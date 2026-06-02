"""E9.2 — production-scale measurement for one code-trained candidate.

E3's eval-scale model sweep found Nomic, MiniLM, and BGE all converged
on near-identical cluster geometry, declaring "general-purpose
embedders converge on this corpus." The plan's E9 hypothesis is that a
code-trained OOD candidate might break that tie. UniXcoder
(``microsoft/unixcoder-base``) is the first plan-listed fallback that
imports cleanly on transformers 5.9 and successfully encodes the eval
set without position-embedding overflow (clamped to 1022 tokens).

This script measures UniXcoder at production scale, mirroring the
E8.2/E8.3 prod-scale sweep pattern:

  1. Pull every embedded session rollup from production.
  2. mget the per-command enrichment data for every command_set hash.
  3. Encode all 4571 unique commands via UniXcoder on CPU.
  4. IDF-weighted mean-pool into per-session vectors.
  5. Cluster at production HDBSCAN hyperparameters (mcs=5, ms=2,
     scalar_weight=0.05, rescue at 0.96).
  6. Restrict to the eval-labeled subset (108 sessions) and score
     against analyst labels.

Output: ``eval/results/embed-model-prod-scale-<ts>.{md,json}``.

Cost: ~4571 unique commands × ~6 commands/sec UniXcoder CPU encoding
≈ 13 minutes. No production state mutated.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_embedding_model_prod.py
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import adjusted_rand_score, completeness_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.commands import _build_embed_text

# Reuse the prod-scale data plumbing from E8.2 — same rollup iteration,
# same enrichment mget, same pool + cluster + score pipeline.
from sweep_embed_input_order import (  # type: ignore
    _pull_sessions,
    _pull_command_enrichments,
    _pool_sessions,
    _cluster_at_production_scale,
    _score_against_labels,
)
from eval_clustering import _load_labels  # type: ignore

log = logging.getLogger(__name__)


# Candidate ordering — first to import + encode wins. Plan's fallback
# chain at the script level; sweep_embedding_model.py (eval scale)
# carries the same default with the same priority.
_CANDIDATES: tuple[tuple[str, str, bool], ...] = (
    ("unixcoder-base",       "microsoft/unixcoder-base",          False),
    ("codet5p-110m-embed",   "Salesforce/codet5p-110m-embedding", True),
    ("CodeRankEmbed",        "nomic-ai/CodeRankEmbed",            True),
)


def _load_first_working_candidate(verbose: bool):
    """Try the plan's candidate order until one loads. Returns
    ``(name, hf_id, model, max_seq_length)`` for the first success."""
    from sentence_transformers import SentenceTransformer
    for name, hf_id, trust in _CANDIDATES:
        try:
            log.info("trying candidate %s (hf_id=%s, trust_remote=%s)",
                     name, hf_id, trust)
            model = SentenceTransformer(
                hf_id, device="cpu", trust_remote_code=trust,
            )
            # Clamp max_seq_length to the underlying model's actual
            # position-embedding limit (UniXcoder=1024) — sentence-
            # transformers' default tokenizer ceiling overshoots.
            try:
                underlying = model._first_module().auto_model.config
                model_max = int(getattr(underlying, "max_position_embeddings", 512))
                safe_max = max(8, model_max - 2)
                if model.max_seq_length > safe_max:
                    model.max_seq_length = safe_max
            except Exception:
                pass
            log.info("  loaded %s, dim=%d, max_seq_length=%d",
                     name, model.get_sentence_embedding_dimension(),
                     model.max_seq_length)
            # Smoke encode to catch overflow / runtime errors before
            # spending 10+ minutes on the full corpus.
            _ = model.encode(["test"], normalize_embeddings=True)
            return name, hf_id, model, int(model.max_seq_length)
        except Exception as e:
            log.warning("  candidate %s failed: %s: %s",
                        name, type(e).__name__, str(e)[:200])
            continue
    raise SystemExit(
        "No E9 candidate model loaded. Plan's fallback chain exhausted: "
        + ", ".join(c[1] for c in _CANDIDATES)
    )


def _encode_all_commands(
    model, enrichments: dict[str, dict],
    embed_context: tuple[str, ...],
    batch_size: int = 32,
) -> dict[str, list[float]]:
    """Build per-command embed text using the production embed_context,
    then encode all in batches via sentence-transformers."""
    keys: list[str] = []
    texts: list[str] = []
    for h, data in enrichments.items():
        text = _build_embed_text(
            data["command"], data["parsed"], list(embed_context),
            cooccurring=None,
            embed_cooccurrence=False,
            order="prelude_first",
        )
        keys.append(h)
        texts.append(text)
    log.info("encoding %d unique commands ...", len(texts))
    t0 = time.time()
    vectors = model.encode(
        texts, batch_size=batch_size,
        show_progress_bar=False,
        normalize_embeddings=True,
    )
    log.info("  encoded %d commands in %.1fs", len(texts), time.time() - t0)
    return {k: list(map(float, v)) for k, v in zip(keys, vectors)}


_METRIC_ORDER = (
    "ari", "completeness", "homogeneity", "nmi", "v_measure",
    "divergent_pair_resolution_rate",
)


def _render_markdown(
    name: str, hf_id: str, max_seq_length: int,
    candidate_score: dict, baseline_ari: float, baseline_completeness: float,
    started_at: str, rollups: int,
) -> str:
    out: list[str] = []
    out.append(f"# E9.2 — code-trained embedder at production scale ({name})")
    out.append("")
    out.append(f"_Captured {started_at}_")
    out.append("")
    out.append(f"Tested ``{hf_id}`` (max_seq_length={max_seq_length}) against the "
               f"full production corpus (~{rollups} rollups), scored on the "
               "108-session labeled subset.")
    out.append("")
    headers = ["model"] + list(_METRIC_ORDER) + ["n_clusters_total", "n_outliers_total"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    # Baseline row
    cells = ["nomic_baseline"]
    for m in _METRIC_ORDER:
        if m == "ari":
            cells.append(f"{baseline_ari:.4f}")
        elif m == "completeness":
            cells.append(f"{baseline_completeness:.4f}")
        else:
            cells.append("—")  # baseline didn't compute these in this script
    cells.append("—")
    cells.append("—")
    out.append("| " + " | ".join(cells) + " |")
    # Candidate row
    cells = [name]
    for m in _METRIC_ORDER:
        v = candidate_score["metrics"].get(m)
        cells.append(f"{v:.4f}" if isinstance(v, float) else str(v if v is not None else "—"))
    cells.append(str(candidate_score["n_clusters_total"]))
    cells.append(str(candidate_score["n_outliers_total"]))
    out.append("| " + " | ".join(cells) + " |")
    out.append("")
    # Delta
    candidate_ari = candidate_score["metrics"].get("ari") or 0.0
    delta = candidate_ari - baseline_ari
    out.append(f"**Δ ARI vs nomic_baseline = {delta:+.4f}.**")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config-path", type=str, default=None)
    ap.add_argument("--labels", type=Path, default=Path("eval/labels-v1.yaml"))
    ap.add_argument("--labels-v2", type=Path, default=Path("eval/labels-v2.yaml"))
    ap.add_argument("--limit-rollups", type=int, default=None,
                    help="Cap the production pull at N rollups for dev runs.")
    ap.add_argument("--no-rescue", action="store_true")
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(message)s",
    )
    log.setLevel(logging.INFO)

    cfg = load_config(args.config_path)
    secrets = load_secrets(args.config_path)
    scfg = cfg.session
    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands

    sid_to_label: dict[str, str] = {}
    pair_to_sessions: dict[str, list[str]] = {}
    for p in (args.labels, args.labels_v2):
        if not p.exists():
            continue
        block = _load_labels(p)
        sid_to_label.update({sid: b["playbook_label"] for sid, b in block.items()})
        if p == args.labels_v2:
            for sid, b in block.items():
                pid = b.get("divergent_pair_id")
                if isinstance(pid, str) and pid:
                    pair_to_sessions.setdefault(pid, []).append(sid)
    if not sid_to_label:
        raise SystemExit(f"No labels found in {args.labels} or {args.labels_v2}")

    started_at = datetime.now(timezone.utc).isoformat()
    log.info("pulling rollups from %s", sessions_idx)
    sessions = _pull_sessions(es, sessions_idx, scfg.page_size, sid_to_label, args.limit_rollups)
    log.info("pulled %d rollups", len(sessions))

    all_hashes = sorted({h for s in sessions for h in s.command_hashes})
    log.info("pulling enrichments for %d unique command hashes", len(all_hashes))
    enrichments = _pull_command_enrichments(es, commands_idx, all_hashes)

    name, hf_id, model, max_seq = _load_first_working_candidate(args.verbose)

    cmd_vecs = _encode_all_commands(model, enrichments,
                                    tuple(cfg.llm.embed_context))
    kept, pooled = _pool_sessions(sessions, cmd_vecs, enrichments)
    log.info("clustering %d pooled sessions at production hyperparameters", len(kept))
    labels = _cluster_at_production_scale(
        pooled, [s.scalars for s in kept], scfg, rescue=not args.no_rescue,
    )
    score = _score_against_labels(kept, labels, pair_to_sessions)
    log.info("candidate metrics: %s", score["metrics"])

    # Baseline ARI / completeness from eval/baseline-prod-scale.json
    # (= the persisted Nomic production cluster ids on the same eval
    # subset). Keeps the comparison consistent with the E6.2 gate.
    baseline_path = Path("eval/baseline-prod-scale.json")
    if baseline_path.exists():
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline_ari = baseline["metrics"]["ari"]["baseline"]
        baseline_completeness = baseline["metrics"]["completeness"]["baseline"]
    else:
        baseline_ari = float("nan")
        baseline_completeness = float("nan")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"embed-model-prod-scale-{ts}.md"
    json_path = args.output_dir / f"embed-model-prod-scale-{ts}.json"
    md = _render_markdown(
        name, hf_id, max_seq, score, baseline_ari, baseline_completeness,
        started_at, len(sessions),
    )
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps({
        "started_at":         started_at,
        "candidate":          {"name": name, "hf_id": hf_id,
                               "max_seq_length": max_seq},
        "rollups":            len(sessions),
        "score":              score,
        "baseline_ari":       baseline_ari,
        "baseline_completeness": baseline_completeness,
        "config_at_capture": {
            "embed_context":     list(cfg.llm.embed_context),
            "embed_input_order": cfg.llm.embed_input_order,
            "min_cluster_size":  scfg.cluster_min_cluster_size,
            "min_samples":       scfg.cluster_min_samples,
            "scalar_weight":     scfg.cluster_scalar_weight,
            "rescue":            (not args.no_rescue) and scfg.playbook_merge_threshold,
        },
    }, indent=2), encoding="utf-8")

    print(md)
    print(f"\nwrote {md_path}")
    print(f"wrote {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
