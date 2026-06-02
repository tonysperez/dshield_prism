"""E3 sweep — alternative embedding models vs Nomic baseline.

For each candidate model:
  * Generate per-command embeddings under production's embed_context
    (`[intent, tactics, techniques, description]`, cooc=false — the
    E2.1 winner now in production) using the model.
  * Pool to session embeddings via IDF-weighted mean (the E2.2-confirmed
    production pool).
  * Re-cluster with the production HDBSCAN config, score on the merged
    v1+v2 eval, including ``divergent_pair_resolution_rate``.

Plan E3 model list:

  * nomic_baseline    — current production via LM Studio (q8_0 quant).
                        Numbers sourced from the refreshed JSONLs
                        directly; no re-embedding needed.
  * all-MiniLM-L6-v2  — sentence-transformers, 384-dim. Small, fast,
                        trained on different corpora.
  * jina-v2-code      — jinaai/jina-embeddings-v2-base-code, 768-dim.
                        Code/shell-specific training.
  * bge-base-en-v1.5  — BAAI strong general embedder, 768-dim,
                        different architecture from Nomic.

Models load via the ``sentence-transformers`` library. First run
downloads ~1.2GB across the three alternatives. CPU inference on the
167 unique commands in the merged eval set takes 30s–3min per model
depending on size.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_embedding_model.py
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.config import load_config
from enrich.llm.schemas import CommandEnrichment
from enrich.sources.cowrie.commands import _build_embed_text
from enrich.sources.cowrie.sessions import _idf_pool_weight, _mean_pool

from eval_clustering import (  # type: ignore
    _cluster,
    _divergent_pair_metrics,
    _load_labels,
    _per_label_breakdown,
    _extract_session_features,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModelConfig:
    name:           str
    hf_id:          str | None     # None = source numbers from JSONL (baseline)
    trust_remote:   bool = False   # Jina v2 code needs this
    note:           str = ""


MODELS: tuple[ModelConfig, ...] = (
    ModelConfig(
        "nomic_baseline",
        None,
        note="LM Studio q8_0; numbers from refreshed JSONL session embeddings",
    ),
    ModelConfig(
        "all-MiniLM-L6-v2",
        "sentence-transformers/all-MiniLM-L6-v2",
        note="384-d, small/fast, different training corpus",
    ),
    ModelConfig(
        "jina-v2-code",
        "jinaai/jina-embeddings-v2-base-code",
        trust_remote=True,
        note="code-specific training, 768-d",
    ),
    ModelConfig(
        "bge-base-en-v1.5",
        "BAAI/bge-base-en-v1.5",
        note="strong general embedder, 768-d, different architecture",
    ),
    # E9.1 — code-trained OOD candidate. Microsoft UniXcoder is the
    # first model in the plan's fallback list that imports cleanly on
    # transformers 5.9 (Salesforce/codet5p-110m-embedding fails with
    # `is_decoder` config attribute, nomic-ai/CodeRankEmbed needs
    # einops + custom modeling). Training corpus is ~6M repos
    # across Python/Java/Go/PHP/Ruby/JavaScript — closer in
    # distribution to shell commands than the general-purpose
    # embedders E3 tested.
    ModelConfig(
        "unixcoder-base",
        "microsoft/unixcoder-base",
        note="Microsoft code-trained encoder, 768-d, OOD candidate (E9)",
    ),
)


# ---------------------------------------------------------------------------
# Eval-set ingestion
# ---------------------------------------------------------------------------

def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _ce_to_model(ce_doc: dict) -> CommandEnrichment | None:
    enr = (((ce_doc.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
    threat = ce_doc.get("threat") or {}
    description = (ce_doc.get("event") or {}).get("reason") or ""
    intent = enr.get("intent") or "unknown"
    tactics = ((threat.get("tactic") or {}).get("id")) or []
    techniques = ((threat.get("technique") or {}).get("id")) or []
    confidence = enr.get("confidence") or 1
    if not description and intent == "unknown" and not tactics and not techniques:
        return None
    try:
        return CommandEnrichment(
            description=description, intent=intent,
            tactics=list(tactics), techniques=list(techniques),
            confidence=int(confidence),
        )
    except Exception:
        return None


@dataclass
class SessionFacts:
    session_id: str
    label:      str
    scalars:    dict
    is_v2:      bool
    # Per-unique-command entries: (command_text, parsed, occurrence_count,
    # baseline_embedding). The baseline embedding is the persisted
    # production vector — used for the nomic_baseline row.
    commands:   list[tuple[str, CommandEnrichment, int, list[float]]]
    # Persisted session embedding (production Nomic, post-E2.1) — used
    # only for the nomic_baseline row.
    baseline_session_embedding: list[float]


def _extract_scalars(rec: dict) -> dict | None:
    feats = _extract_session_features(rec)
    if feats is None:
        return None
    _, scalars = feats
    return scalars


def _baseline_session_embedding(rec: dict) -> list[float] | None:
    enr = (
        (((rec.get("rollup_doc") or {}).get("dshield") or {}).get("cowrie") or {})
        .get("enrichment") or {}
    ).get("session") or {}
    emb = enr.get("embedding")
    return emb if isinstance(emb, list) and emb else None


def _ingest_sessions(
    v1_labels: dict[str, dict], v2_labels: dict[str, dict],
    v1_jsonl: Path | None, v2_jsonl: Path | None,
) -> list[SessionFacts]:
    label_blocks = {**v1_labels, **v2_labels}
    sessions: list[SessionFacts] = []
    seen_sids: set[str] = set()

    def _ingest_one(rec: dict, is_v2: bool) -> None:
        sid = rec.get("session_id")
        if not isinstance(sid, str) or sid in seen_sids:
            return
        if sid not in label_blocks:
            return
        scalars = _extract_scalars(rec)
        if scalars is None:
            return
        baseline_emb = _baseline_session_embedding(rec)
        if baseline_emb is None:
            return
        commands: list[tuple[str, CommandEnrichment, int, list[float]]] = []
        for ce in rec.get("command_enrichments") or []:
            cmd = ((ce.get("process") or {}).get("command_line")) or ""
            if not cmd:
                continue
            parsed = _ce_to_model(ce)
            if parsed is None:
                continue
            enr = (((ce.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
            occ = int(enr.get("occurrence_count") or 1)
            persisted_emb = enr.get("embedding") or []
            commands.append((cmd, parsed, occ, persisted_emb))
        if not commands:
            return
        seen_sids.add(sid)
        sessions.append(SessionFacts(
            session_id=sid,
            label=label_blocks[sid]["playbook_label"],
            scalars=scalars,
            is_v2=is_v2 or sid in v2_labels,
            commands=commands,
            baseline_session_embedding=baseline_emb,
        ))

    if v1_jsonl is not None and v1_jsonl.exists():
        for rec in _iter_jsonl(v1_jsonl):
            _ingest_one(rec, is_v2=False)
    if v2_jsonl is not None and v2_jsonl.exists():
        for rec in _iter_jsonl(v2_jsonl):
            _ingest_one(rec, is_v2=True)
    return sessions


# ---------------------------------------------------------------------------
# Embedding via sentence-transformers
# ---------------------------------------------------------------------------

def _embed_with_st(
    model_cfg: ModelConfig, embed_texts: list[str],
) -> list[list[float]]:
    """Lazy-import sentence-transformers and encode all texts in one batch.
    Returns a list of vectors aligned with the input order."""
    from sentence_transformers import SentenceTransformer
    log.info("loading model %s (hf_id=%s)", model_cfg.name, model_cfg.hf_id)
    t0 = time.time()
    model = SentenceTransformer(
        model_cfg.hf_id, device="cpu",
        trust_remote_code=model_cfg.trust_remote,
    )
    # Cap input length at whatever the model says it supports. UniXcoder
    # ships with max_position_embeddings=1024 + 2 special tokens, but
    # SentenceTransformer's default max_seq_length defaults to a higher
    # tokenizer ceiling and crashes on overflow when the model itself
    # can't take the longer sequence. Reading the underlying transformer's
    # config keeps this generic across models (BGE = 512, MiniLM = 256,
    # UniXcoder = 1024) — pick the minimum so we never overshoot.
    try:
        underlying = model._first_module().auto_model.config
        model_max = int(getattr(underlying, "max_position_embeddings", 512))
        # Reserve 2 tokens for CLS+SEP.
        safe_max = max(8, model_max - 2)
        if model.max_seq_length > safe_max:
            log.info("  clamping max_seq_length: %d → %d (model limit)",
                     model.max_seq_length, safe_max)
            model.max_seq_length = safe_max
    except Exception as e:
        log.warning("  could not introspect model max_position_embeddings: %s", e)
    log.info("  loaded in %.1fs; dim=%d max_seq_length=%d",
             time.time() - t0, model.get_sentence_embedding_dimension(),
             model.max_seq_length)
    t0 = time.time()
    vectors = model.encode(
        embed_texts, batch_size=32, show_progress_bar=False,
        normalize_embeddings=True,
    )
    log.info("  encoded %d texts in %.1fs", len(embed_texts), time.time() - t0)
    return [list(map(float, v)) for v in vectors]


# ---------------------------------------------------------------------------
# Per-model pooling + scoring
# ---------------------------------------------------------------------------

def _build_session_embeddings_for_model(
    sessions: list[SessionFacts],
    model_cfg: ModelConfig,
    embed_context: tuple[str, ...],
) -> list[list[float]]:
    """For ``nomic_baseline``, return the persisted session embeddings
    verbatim. For every other model, build per-command embed_texts under
    the production embed_context, encode in one batch, then pool with
    the production IDF-weighted mean."""
    if model_cfg.hf_id is None:
        return [s.baseline_session_embedding for s in sessions]

    # Build the unique-command pool keyed by command text so a command
    # appearing in many sessions only gets encoded once.
    unique_keys: dict[str, str] = {}  # key (cmd text) -> embed_text
    cmd_parsed: dict[str, CommandEnrichment] = {}
    for s in sessions:
        for cmd, parsed, _occ, _emb in s.commands:
            if cmd in unique_keys:
                continue
            unique_keys[cmd] = _build_embed_text(
                cmd, parsed, list(embed_context),
                cooccurring=None, embed_cooccurrence=False,
            )
            cmd_parsed[cmd] = parsed
    keys = list(unique_keys.keys())
    embed_texts = [unique_keys[k] for k in keys]
    log.info("  unique commands to embed: %d", len(keys))
    vectors = _embed_with_st(model_cfg, embed_texts)
    cmd_vec = dict(zip(keys, vectors))

    pooled: list[list[float]] = []
    for s in sessions:
        embs = []
        weights = []
        for cmd, _parsed, occ, _persisted in s.commands:
            v = cmd_vec.get(cmd)
            if v is None:
                continue
            embs.append(v)
            weights.append(_idf_pool_weight(occ))
        pooled.append(_mean_pool(embs, weights) if embs else [])
    return pooled


def _score(
    sessions: list[SessionFacts], session_embeddings: list[list[float]],
    cfg, v2_labels: dict[str, dict],
) -> dict:
    session_ids = [s.session_id for s in sessions]
    labels = [s.label for s in sessions]
    scalars = [s.scalars for s in sessions]
    cluster_pred = _cluster(
        session_embeddings, scalars,
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        scalar_weight=cfg.session.cluster_scalar_weight,
    )
    metrics = {
        "ari":          round(float(adjusted_rand_score(labels, cluster_pred)), 4),
        "nmi":          round(float(normalized_mutual_info_score(labels, cluster_pred)), 4),
        "homogeneity":  round(float(homogeneity_score(labels, cluster_pred)), 4),
        "completeness": round(float(completeness_score(labels, cluster_pred)), 4),
        "v_measure":    round(float(v_measure_score(labels, cluster_pred)), 4),
    }
    pair_to_sessions: dict[str, list[str]] = {}
    for sid, block in v2_labels.items():
        pid = block.get("divergent_pair_id")
        if isinstance(pid, str) and pid:
            pair_to_sessions.setdefault(pid, []).append(sid)
    pair_outcomes: list[dict] = []
    if pair_to_sessions:
        v2_metrics, pair_outcomes = _divergent_pair_metrics(
            session_ids, cluster_pred, labels, pair_to_sessions,
        )
        metrics.update(v2_metrics)
    n_clusters = len({int(c) for c in cluster_pred if c >= 0})
    n_outliers = int(sum(1 for c in cluster_pred if c == -1))
    return {
        "metrics":       metrics,
        "n_clusters":    n_clusters,
        "n_outliers":    n_outliers,
        "per_label":     _per_label_breakdown(session_ids, labels, cluster_pred),
        "pair_outcomes": pair_outcomes,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_METRIC_ORDER = (
    "ari", "completeness", "homogeneity", "nmi", "v_measure",
    "divergent_pair_resolution_rate",
)


def _render_markdown(rows: list[dict], n_sessions: int) -> str:
    out: list[str] = []
    out.append("# E3 — embedding model sweep")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append(
        f"Sorted by ARI descending. {len(rows)} models swept against the "
        f"merged v1+v2 eval set ({n_sessions} sessions). All non-baseline "
        f"models loaded via sentence-transformers on CPU. embed_context "
        f"= production (`[intent, tactics, techniques, description]`, "
        f"cooc=false). Pool = production IDF-weighted mean."
    )
    out.append("")
    headers = ["model", "embedding_dim"] + list(_METRIC_ORDER) \
              + ["n_clusters", "n_outliers"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        cells = [
            r["model"]["name"],
            str(r.get("embedding_dim", "?")),
        ]
        for m in _METRIC_ORDER:
            v = r["metrics"].get(m)
            cells.append(f"{v:.4f}" if isinstance(v, float) else str(v or "—"))
        cells.append(str(r["n_clusters"]))
        cells.append(str(r["n_outliers"]))
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    out.append("Notes per model:")
    out.append("")
    for r in rows:
        if r["model"].get("note"):
            out.append(f"- **{r['model']['name']}**: {r['model']['note']}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels-v1", type=Path,
                    default=Path("eval/labels-v1.yaml"))
    ap.add_argument("--jsonl-v1", type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"))
    ap.add_argument("--labels-v2", type=Path,
                    default=Path("eval/labels-v2.yaml"))
    ap.add_argument("--jsonl-v2", type=Path,
                    default=Path("eval/sessions-v2.unlabeled.jsonl"))
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--only", type=str, default=None,
                    help=(
                        "Comma-separated model names to run (subset of the "
                        "registry). Default = all 4. Use this to iterate on "
                        "a single candidate without re-running the others."
                    ))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config()
    v1_labels = _load_labels(args.labels_v1)
    v2_labels = _load_labels(args.labels_v2) if args.labels_v2.exists() else {}

    sessions = _ingest_sessions(
        v1_labels, v2_labels, args.jsonl_v1, args.jsonl_v2,
    )
    if not sessions:
        print("[ERROR] no sessions ingested", file=sys.stderr)
        return 1
    log.info("ingested %d sessions (%d v2); labels: %s",
             len(sessions), sum(1 for s in sessions if s.is_v2),
             dict(Counter(s.label for s in sessions).most_common()))

    only = set(args.only.split(",")) if args.only else None
    embed_context = tuple(cfg.llm.embed_context or [])

    rows: list[dict] = []
    for mc in MODELS:
        if only is not None and mc.name not in only:
            continue
        log.info("=" * 60)
        log.info("MODEL: %s (%s)", mc.name, mc.hf_id or "PERSISTED")
        try:
            session_embs = _build_session_embeddings_for_model(
                sessions, mc, embed_context,
            )
        except Exception as e:
            log.error("model %s failed: %s", mc.name, e)
            continue
        emb_dim = len(session_embs[0]) if session_embs and session_embs[0] else 0
        scored = _score(sessions, session_embs, cfg, v2_labels)
        rows.append({
            "model":         dataclasses.asdict(mc),
            "embedding_dim": emb_dim,
            **scored,
        })
        log.info("  → metrics: %s", scored["metrics"])

    rows.sort(key=lambda r: -r["metrics"].get("ari", 0.0))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"embed-model-sweep-{ts}.md"
    json_path = args.output_dir / f"embed-model-sweep-{ts}.json"
    md_text = _render_markdown(rows, len(sessions))
    md_path.write_text(md_text, encoding="utf-8")
    json_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_sessions":   len(sessions),
        "rows":         rows,
    }, indent=2), encoding="utf-8")
    print(f"\nwrote {md_path}")
    print(f"wrote {json_path}\n")
    print(md_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
