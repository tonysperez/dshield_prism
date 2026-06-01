"""E2.1 sweep — embed_context combinations against the merged v1+v2 eval set.

For each configuration in the embedding-quality plan E2.1's sweep table:

  1. bare              embed_context=[]                       cooc=false
  2. intent_only       [intent]                               cooc=false
  3. description_only  [description]                          cooc=false
  4. intent_desc       [intent, description]                  cooc=false
  5. mitre_only        [tactics, techniques]                  cooc=false
  6. production        [intent, tactics, techniques, desc]    cooc=false
  7. intent_desc_cooc  [intent, description]                  cooc=true
  8. bare_cooc         []                                     cooc=true

…regenerate per-command embeddings under that configuration by calling
``llm.embed()`` directly (no ES write), pool into session embeddings
using the same IDF-weighted mean pool production runs, re-cluster with
HDBSCAN, and score on the merged v1+v2 corpus including the v2
``divergent_pair_resolution_rate`` metric.

Output: a markdown table sorted by ARI desc and a JSON snapshot under
``eval/results/embed-input-sweep-<ts>.{md,json}``.

Cooccurrence siblings come from ES at sweep time (one set of three
``score_cooccurring_siblings`` queries per unique command, cached and
re-used across the two cooccurrence configs). The siblings are exactly
what production runs would inject; only the ``embed_context`` field
list and the ``embed_cooccurrence`` toggle vary across sweep rows.

Cost: ~150 unique commands × 8 configs ≈ 1200 ``llm.embed()`` calls
plus a one-time cooccurrence pre-fetch. Roughly 2-3 minutes against
the local LM Studio + ES setup at the project's default endpoints.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_embed_input.py
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

import numpy as np
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.llm import make_llm_client
from enrich.llm.schemas import CommandEnrichment
from enrich.sources.cowrie.commands import (
    _build_embed_text,
    fetch_cooccurring_commands,
)
from enrich.sources.cowrie.sessions import _idf_pool_weight, _mean_pool

# Sibling-script imports — these helpers already encode the v1+v2 merge
# semantics + the v2-specific metric, so the sweep stays measurement-
# compatible with the baseline gate.
from eval_clustering import (  # type: ignore
    _cluster,
    _divergent_pair_metrics,
    _load_labels,
    _per_label_breakdown,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sweep config table (matches plan E2.1)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SweepConfig:
    name:               str
    embed_context:      tuple[str, ...]
    embed_cooccurrence: bool


SWEEP_CONFIGS: tuple[SweepConfig, ...] = (
    SweepConfig("bare",              (), False),
    SweepConfig("intent_only",       ("intent",), False),
    SweepConfig("description_only",  ("description",), False),
    SweepConfig("intent_desc",       ("intent", "description"), False),
    SweepConfig("mitre_only",        ("tactics", "techniques"), False),
    SweepConfig("production",
                ("intent", "tactics", "techniques", "description"), False),
    SweepConfig("intent_desc_cooc",  ("intent", "description"), True),
    SweepConfig("bare_cooc",         (), True),
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


def _extract_scalars(rec: dict) -> dict | None:
    """Same shape as eval_clustering._extract_session_features's scalar
    block. The sweep doesn't reuse the persisted session embedding —
    only the four augment scalars HDBSCAN appends to the embedding."""
    rollup = rec.get("rollup_doc") or {}
    enr = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    success = enr.get("login_success_count") or 0
    fail = enr.get("login_fail_count") or 0
    total = success + fail
    return {
        "command_count":      enr.get("command_count") or 1,
        "unique_commands":    enr.get("unique_commands") or 1,
        "login_success_rate": success / total if total > 0 else 0.0,
        "mean_novelty_score": enr.get("mean_novelty_score") or 0.0,
    }


def _ce_to_model(ce_doc: dict) -> CommandEnrichment | None:
    """Map a persisted command-enrichment doc back to the in-memory
    CommandEnrichment that ``_build_embed_text`` expects. Mirrors the
    audit script's helper — same field-mapping semantics."""
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
            description=description,
            intent=intent,
            tactics=list(tactics),
            techniques=list(techniques),
            confidence=int(confidence),
        )
    except Exception:
        return None


@dataclass
class SessionFacts:
    """Everything the sweep needs to re-embed and re-pool one session.
    Strictly a sweep-internal structure; production reads the persisted
    session embedding instead of rebuilding it."""
    session_id:      str
    label:           str
    scalars:         dict
    is_v2:           bool
    # Per-unique-command entries: (canonical_hash, occurrence_count).
    # Pool order matches production: iteration over the unique command
    # set, IDF-weighted by occurrence_count.
    command_keys:    list[tuple[str, int]]


def _hash_command(text: str) -> str:
    """Stable hash used as the lookup key into the per-config embedding
    cache. The actual production short-command-hash (sha256[:16] of the
    normalised command) is fine here too, but using the raw command text
    avoids re-deriving the normalisation rules and keeps the cache key
    self-evident from the data we already hold."""
    return text


def _ingest_sessions(
    v1_labels: dict[str, dict],
    v2_labels: dict[str, dict],
    v1_jsonl: Path | None,
    v2_jsonl: Path | None,
) -> tuple[list[SessionFacts], dict[str, dict]]:
    """Build the SessionFacts list and a unique-command dict.

    Returns:
      sessions: list[SessionFacts] in v1-then-v2 order, deduped by
                session_id (the same dedup eval_clustering applies).
      unique_commands: {command_text: {"parsed": CommandEnrichment,
                                       "occurrence_count": int}}
                Keyed by the command text (the sweep cache key); the
                ``occurrence_count`` is whatever the FIRST session
                using that command carries — siblings agree, so it's
                stable.
    """
    sessions: list[SessionFacts] = []
    seen_sids: set[str] = set()
    unique_commands: dict[str, dict] = {}

    label_blocks = {**v1_labels, **v2_labels}

    def _ingest_one(rec: dict, is_v2: bool) -> None:
        sid = rec.get("session_id")
        if not isinstance(sid, str) or sid in seen_sids:
            return
        if sid not in label_blocks:
            return
        scalars = _extract_scalars(rec)
        if scalars is None:
            return

        command_keys: list[tuple[str, int]] = []
        for ce in rec.get("command_enrichments") or []:
            cmd = ((ce.get("process") or {}).get("command_line")) or ""
            if not cmd:
                continue
            parsed = _ce_to_model(ce)
            if parsed is None:
                continue
            enr = (((ce.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
            occ = int(enr.get("occurrence_count") or 1)
            key = _hash_command(cmd)
            if key not in unique_commands:
                unique_commands[key] = {
                    "command":          cmd,
                    "parsed":           parsed,
                    "occurrence_count": occ,
                }
            command_keys.append((key, occ))

        if not command_keys:
            # No commands → no embedding to pool. Skip rather than
            # contribute a zero vector (which would distort the
            # clustering geometry).
            return

        seen_sids.add(sid)
        sessions.append(SessionFacts(
            session_id=sid,
            label=label_blocks[sid]["playbook_label"],
            scalars=scalars,
            is_v2=is_v2 or sid in v2_labels,
            command_keys=command_keys,
        ))

    if v1_jsonl is not None and v1_jsonl.exists():
        for rec in _iter_jsonl(v1_jsonl):
            _ingest_one(rec, is_v2=False)
    if v2_jsonl is not None and v2_jsonl.exists():
        for rec in _iter_jsonl(v2_jsonl):
            _ingest_one(rec, is_v2=True)

    return sessions, unique_commands


# ---------------------------------------------------------------------------
# Cooccurrence pre-fetch
# ---------------------------------------------------------------------------

def _prefetch_cooccurrence(
    es, events_index: str, unique_commands: dict[str, dict], cfg,
) -> dict[str, list[tuple[str, int]]]:
    """Pre-compute the cooccurring-siblings list for every unique command,
    using the SAME production helper (``_score_command_cooccurrence``)
    runtime enrichment uses. Reused across both cooccurrence configs in
    the sweep so we pay the ES roundtrips exactly once."""
    cooc_cfg = cfg.cooccurrence
    if not cooc_cfg.enabled:
        log.info("cooccurrence disabled in cfg.cooccurrence — sweep will treat "
                 "cooc=true rows as effectively cooc=false (no siblings).")
    # The corpus session count is used as the IDF denominator. Match
    # production by querying it from the raw-events index.
    from enrich.sources.cowrie.commands import _fetch_total_session_count
    total_sessions = _fetch_total_session_count(es, events_index)
    log.info("total session count for cooccurrence IDF: %d", total_sessions)

    out: dict[str, list[tuple[str, int]]] = {}
    t0 = time.time()
    for i, (key, cmd_data) in enumerate(unique_commands.items()):
        siblings = fetch_cooccurring_commands(
            es, events_index, cmd_data["command"],
            session_sample_size=cooc_cfg.session_sample_size,
            top_k=cooc_cfg.top_k,
            min_sessions=cooc_cfg.min_sessions,
            total_sessions=total_sessions,
        )
        out[key] = siblings
        if (i + 1) % 20 == 0:
            log.info("cooccurrence pre-fetch: %d/%d (%.1fs)",
                     i + 1, len(unique_commands), time.time() - t0)
    log.info("cooccurrence pre-fetch complete: %d commands in %.1fs",
             len(unique_commands), time.time() - t0)
    return out


# ---------------------------------------------------------------------------
# Per-config evaluation
# ---------------------------------------------------------------------------

def _embed_commands_under_config(
    llm, config: SweepConfig,
    unique_commands: dict[str, dict],
    cooc_siblings: dict[str, list[tuple[str, int]]],
) -> dict[str, list[float]]:
    """Call ``llm.embed()`` once per unique command under ``config``.
    Returns ``{command_key: vector}``."""
    out: dict[str, list[float]] = {}
    t0 = time.time()
    n = len(unique_commands)
    for i, (key, cmd_data) in enumerate(unique_commands.items()):
        embed_text = _build_embed_text(
            cmd_data["command"],
            cmd_data["parsed"],
            list(config.embed_context),
            cooccurring=cooc_siblings.get(key) if config.embed_cooccurrence else None,
            embed_cooccurrence=config.embed_cooccurrence,
        )
        try:
            vec = llm.embed(embed_text)
        except Exception as e:
            log.warning("llm.embed failed for %r under config %s: %s",
                        cmd_data["command"][:60], config.name, e)
            continue
        out[key] = vec
        if (i + 1) % 25 == 0:
            log.info("  %s: embedded %d/%d (%.1fs)",
                     config.name, i + 1, n, time.time() - t0)
    log.info("  %s: %d/%d embeddings in %.1fs",
             config.name, len(out), n, time.time() - t0)
    return out


def _pool_session_embeddings(
    sessions: list[SessionFacts],
    cmd_vectors: dict[str, list[float]],
) -> list[list[float]]:
    """Apply the same IDF-weighted mean pool production uses. Sessions
    whose commands all came up unembedded (LLM call failures) get a
    zero vector — flagged via the metrics but not crashing the sweep."""
    pooled: list[list[float]] = []
    dim = next(iter(cmd_vectors.values()), [0.0])
    dim_size = len(dim) if isinstance(dim, list) else 0
    for s in sessions:
        embs: list[list[float]] = []
        weights: list[float] = []
        for key, occ in s.command_keys:
            vec = cmd_vectors.get(key)
            if vec is None:
                continue
            embs.append(vec)
            weights.append(_idf_pool_weight(occ))
        if not embs:
            log.warning("session %s pooled with zero commands — emitting zero "
                        "vector", s.session_id)
            pooled.append([0.0] * dim_size)
            continue
        pooled.append(_mean_pool(embs, weights))
    return pooled


def _score(
    sessions: list[SessionFacts], embeddings: list[list[float]], cfg,
    v2_labels: dict[str, dict],
) -> dict:
    session_ids = [s.session_id for s in sessions]
    labels = [s.label for s in sessions]
    scalars = [s.scalars for s in sessions]

    cluster_pred = _cluster(
        embeddings, scalars,
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

    # Reconstruct pair_to_sessions from the v2 labels file — same logic
    # the merged evaluator uses.
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
        "metrics":     metrics,
        "n_clusters":  n_clusters,
        "n_outliers":  n_outliers,
        "per_label":   _per_label_breakdown(session_ids, labels, cluster_pred),
        "pair_outcomes": pair_outcomes,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_METRIC_ORDER = (
    "ari", "completeness", "homogeneity", "nmi", "v_measure",
    "divergent_pair_resolution_rate",
)


def _render_markdown(rows: list[dict], baseline_row: dict | None) -> str:
    out: list[str] = []
    out.append("# E2.1 — embed_context sweep")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append(f"Sorted by ARI descending. {len(rows)} configurations swept "
               f"against the merged v1+v2 eval set.")
    out.append("")
    headers = ["config", "embed_context", "cooc"] + list(_METRIC_ORDER) \
              + ["n_clusters", "n_outliers"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        cells = [
            r["config"]["name"],
            "[" + ", ".join(r["config"]["embed_context"]) + "]",
            str(r["config"]["embed_cooccurrence"]),
        ]
        for m in _METRIC_ORDER:
            v = r["metrics"].get(m)
            cells.append(f"{v:.4f}" if isinstance(v, float) else str(v or "—"))
        cells.append(str(r["n_clusters"]))
        cells.append(str(r["n_outliers"]))
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    if baseline_row is not None:
        out.append("Baseline (current production embeddings, no sweep):")
        out.append("")
        cells = [
            "BASELINE",
            "[persisted]",
            "—",
        ]
        for m in _METRIC_ORDER:
            v = baseline_row["metrics"].get(m)
            cells.append(f"{v:.4f}" if isinstance(v, float) else str(v or "—"))
        cells.append(str(baseline_row["n_clusters"]))
        cells.append(str(baseline_row["n_outliers"]))
        out.append("| " + " | ".join(cells) + " |")
        out.append("")
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
    ap.add_argument("--skip-cooccurrence", action="store_true",
                    help=(
                        "Skip the two cooccurrence-using configs. Use when "
                        "ES is unreachable from this workstation; otherwise "
                        "the sweep treats cooc=true rows as cooc=false."
                    ))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config()
    sec = load_secrets()

    v1_labels = _load_labels(args.labels_v1)
    v2_labels = _load_labels(args.labels_v2) if args.labels_v2.exists() else {}

    sessions, unique_commands = _ingest_sessions(
        v1_labels, v2_labels, args.jsonl_v1, args.jsonl_v2,
    )
    log.info("ingested %d sessions (%d v2), %d unique commands",
             len(sessions), sum(1 for s in sessions if s.is_v2),
             len(unique_commands))

    # Distribution sanity check
    log.info("label distribution: %s",
             dict(Counter(s.label for s in sessions).most_common()))

    es = make_client(cfg.elasticsearch, sec)
    events_index = cfg.elasticsearch.indexes.cowrie.sessions_raw

    cooc_siblings: dict[str, list[tuple[str, int]]] = {}
    if not args.skip_cooccurrence:
        cooc_siblings = _prefetch_cooccurrence(es, events_index, unique_commands, cfg)
    else:
        log.info("skipping cooccurrence pre-fetch (--skip-cooccurrence)")

    llm = make_llm_client(cfg.llm)

    rows: list[dict] = []
    sweep_t0 = time.time()
    for i, config in enumerate(SWEEP_CONFIGS, start=1):
        if config.embed_cooccurrence and args.skip_cooccurrence:
            log.info("[%d/%d] %s: SKIPPED (--skip-cooccurrence)",
                     i, len(SWEEP_CONFIGS), config.name)
            continue
        log.info("[%d/%d] %s: embed_context=%s cooc=%s",
                 i, len(SWEEP_CONFIGS), config.name,
                 list(config.embed_context), config.embed_cooccurrence)
        cmd_vectors = _embed_commands_under_config(
            llm, config, unique_commands, cooc_siblings,
        )
        embeddings = _pool_session_embeddings(sessions, cmd_vectors)
        scored = _score(sessions, embeddings, cfg, v2_labels)
        rows.append({
            "config":      dataclasses.asdict(config),
            **scored,
        })
        log.info("  → metrics: %s", scored["metrics"])

    log.info("sweep complete in %.1fs", time.time() - sweep_t0)

    rows.sort(key=lambda r: -r["metrics"].get("ari", 0.0))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"embed-input-sweep-{ts}.md"
    json_path = args.output_dir / f"embed-input-sweep-{ts}.json"

    md_text = _render_markdown(rows, baseline_row=None)
    md_path.write_text(md_text, encoding="utf-8")
    json_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_sessions": len(sessions),
        "n_unique_commands": len(unique_commands),
        "configs_swept": len(rows),
        "rows": rows,
    }, indent=2), encoding="utf-8")

    print(f"\nwrote {md_path}")
    print(f"wrote {json_path}\n")
    print(md_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
