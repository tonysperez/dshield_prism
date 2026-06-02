"""E8.3 sweep — MITRE strip-and-measure at production scale.

The original E2.1 sweep tested ``embed_context`` combinations at eval
scale (108 sessions) and found the production
``[intent, tactics, techniques, description]`` config wins overall.
But the E0.3 diagnostic claimed MITRE-IDs were "opaque noise" on this
corpus; the contradiction between those two readings was never resolved
at production scale.

This sweep settles it. Two configs:

  - ``production``       embed_context = [intent, tactics, techniques, description]
  - ``mitre_stripped``   embed_context = [intent, description]

For each, walks the production commands index, rebuilds the per-command
embed text under that config, re-embeds via ``llm.embed()`` (no ES
writes), re-pools every production session via the same IDF-weighted
mean pool the rollup uses, clusters at production HDBSCAN
hyperparameters, restricts to the eval-labeled subset, and scores.

Three outcomes per the plan:
  - MITRE survives (production wins by ≥ 0.02 ARI) → keep production,
    document, mark E0.3's "opaque noise" claim as eval-scale wrong.
  - MITRE doesn't survive (mitre_stripped wins by ≥ 0.02 ARI) → strip
    MITRE from production config (config change + reembed cycle).
  - Within noise (|Δ| < 0.02 ARI) → keep production for stability;
    document.

Output: ``eval/results/mitre-strip-sweep-<ts>.{md,json}``.

Cost: ~4571 unique-command embed calls × 2 configs ≈ 9k LLM calls.
Roughly 2–4 minutes against a local LM Studio @q8_0 endpoint. No
production state mutated.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_mitre_strip.py
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.cluster import HDBSCAN
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.clustering import l2_normalize, rescue_noise_points
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.llm import make_llm_client
from enrich.sources.cowrie.commands import _build_embed_text
from enrich.sources.cowrie.sessions import (
    _idf_pool_weight, _mean_pool, build_session_scalar_block,
)

from eval_clustering import (  # type: ignore
    _load_labels,
    _per_label_breakdown,
    _divergent_pair_metrics,
)

# Reuse the production-data-pull helpers from the order sweep — same
# rollup iteration, same enrichment mget, same labels-merge logic.
from sweep_embed_input_order import (  # type: ignore
    SessionFacts,
    _pull_sessions,
    _pull_command_enrichments,
    _pool_sessions,
    _cluster_at_production_scale,
    _score_against_labels,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sweep configs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SweepConfig:
    name:           str
    embed_context:  tuple[str, ...]


SWEEP_CONFIGS: tuple[SweepConfig, ...] = (
    SweepConfig(
        "production",
        ("intent", "tactics", "techniques", "description"),
    ),
    SweepConfig(
        "mitre_stripped",
        ("intent", "description"),
    ),
)


# Headline ARI tolerance for the within-noise verdict (per plan E8.3).
_NOISE_BAND = 0.02


# ---------------------------------------------------------------------------
# Per-config measurement
# ---------------------------------------------------------------------------

def _embed_all_commands(
    llm, enrichments: dict[str, dict], embed_context: tuple[str, ...],
) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {}
    t0 = time.time()
    n = len(enrichments)
    for i, (h, data) in enumerate(enrichments.items()):
        embed_text = _build_embed_text(
            data["command"], data["parsed"], list(embed_context),
            cooccurring=None,
            embed_cooccurrence=False,
            order="prelude_first",
        )
        try:
            out[h] = llm.embed(embed_text)
        except Exception as e:
            log.warning("llm.embed failed for hash %s under context=%s: %s",
                        h, list(embed_context), e)
            continue
        if (i + 1) % 250 == 0:
            log.info("  embedded %d/%d (%.1fs)", i + 1, n, time.time() - t0)
    log.info("  %d/%d embeddings in %.1fs", len(out), n, time.time() - t0)
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_METRIC_ORDER = (
    "ari", "completeness", "homogeneity", "nmi", "v_measure",
    "divergent_pair_resolution_rate",
)


def _decide_verdict(rows: list[dict]) -> tuple[str, str]:
    """Return (verdict, prose) per the plan's three outcomes."""
    by_name = {r["config"]["name"]: r for r in rows}
    prod = by_name["production"]["score"]["metrics"]["ari"]
    strip = by_name["mitre_stripped"]["score"]["metrics"]["ari"]
    delta = strip - prod  # positive = MITRE-stripped wins
    if abs(delta) < _NOISE_BAND:
        return (
            "within_noise",
            (
                f"|Δ ARI| = |{delta:+.4f}| < ±{_NOISE_BAND:.2f}. The "
                "two configs are within the plan's noise band. **Keep "
                "production** (`[intent, tactics, techniques, description]`) "
                "for stability — there's no signal to justify a config "
                "change. MITRE-IDs neither help nor hurt clustering at "
                "production scale on this corpus; E0.3's eval-scale "
                "\"opaque noise\" claim doesn't generalise. The "
                "production-scale numbers don't crown either config; "
                "the existing one wins on inertia."
            ),
        )
    if delta < 0:
        return (
            "mitre_survives",
            (
                f"Δ ARI = {delta:+.4f} (MITRE-stripped LOSES by "
                f"{abs(delta):.4f}). **Keep production** "
                "(`[intent, tactics, techniques, description]`). MITRE-IDs "
                "contribute real clustering signal at production scale; "
                "E0.3's \"opaque noise\" claim was eval-scale wrong "
                "(small-corpus artifact) and doesn't survive translation "
                "to ~4000 sessions."
            ),
        )
    return (
        "mitre_doesnt_survive",
        (
            f"Δ ARI = {delta:+.4f} (MITRE-stripped WINS by "
            f"{delta:.4f}). **Strip MITRE from production config**: edit "
            "`config/default.yaml` to set `embed_context: [intent, "
            "description]`, then run a full reembed cycle on production "
            "(via E6.3's pattern), refresh "
            "`eval/production-snapshot-v1.jsonl.gz`, and re-capture "
            "`eval/baseline-prod-scale.json` from the new floor. The "
            "E0.3 \"opaque noise\" diagnostic was correct after all."
        ),
    )


def _render_markdown(
    rows: list[dict], baseline_ari: float, started_at: str,
    verdict: str, verdict_prose: str,
) -> str:
    out: list[str] = []
    out.append("# E8.3 — MITRE strip-and-measure (production scale)")
    out.append("")
    out.append(f"_Captured {started_at}_")
    out.append("")
    out.append("Two embed_context configurations swept against the full "
               "production corpus, scored on the labeled eval subset.")
    out.append("")
    headers = ["config", "embed_context"] + list(_METRIC_ORDER) \
              + ["n_clusters_total", "n_outliers_total"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        cells = [
            r["config"]["name"],
            "[" + ", ".join(r["config"]["embed_context"]) + "]",
        ]
        for m in _METRIC_ORDER:
            v = r["score"]["metrics"].get(m)
            cells.append(f"{v:.4f}" if isinstance(v, float) else str(v if v is not None else "—"))
        cells.append(str(r["score"]["n_clusters_total"]))
        cells.append(str(r["score"]["n_outliers_total"]))
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    out.append(f"**Baseline** (persisted production cluster ids, no re-embed): "
               f"ARI {baseline_ari:.4f}.")
    out.append("")
    out.append("## Verdict")
    out.append("")
    out.append(f"**{verdict}**")
    out.append("")
    out.append(verdict_prose)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config-path", type=str, default=None)
    ap.add_argument("--labels", type=Path, default=Path("eval/labels-v1.yaml"))
    ap.add_argument("--labels-v2", type=Path, default=Path("eval/labels-v2.yaml"))
    ap.add_argument("--limit-rollups", type=int, default=None,
                    help="Cap the production pull at N rollups for dev runs.")
    ap.add_argument("--no-rescue", action="store_true",
                    help="Skip the production-faithful noise-rescue pass.")
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
    log.info("pulling enrichments for %d unique command hashes from %s",
             len(all_hashes), commands_idx)
    enrichments = _pull_command_enrichments(es, commands_idx, all_hashes)

    # Baseline ARI from persisted production embeddings — same number
    # as eval/baseline-prod-scale.json's ARI when limit_rollups is None.
    persisted: list[list[float]] = []
    persisted_scalars: list[dict] = []
    persisted_sids: list[str] = []
    for s in sessions:
        emb = None  # ignore; sweep doesn't get persisted embeddings from _pull_sessions
        # Fetch baseline embedding separately via the same iterator
        # eval_production_scale.py uses. Skipped here in favor of a single
        # ES roundtrip below.
    # Lightweight baseline pass: query the persisted embedding for each
    # session we just pulled. Faster than another full search loop.
    sids = [s.session_id for s in sessions]
    sid_to_facts = {s.session_id: s for s in sessions}
    body: dict = {
        "size": scfg.page_size,
        "_source": ["dshield.cowrie.enrichment.session.embedding", "cowrie.session_id"],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    sa = None
    pulled = 0
    while True:
        if sa:
            body["search_after"] = sa
        r = es.search(index=sessions_idx, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            sid = (h["_source"].get("cowrie") or {}).get("session_id", h["_id"])
            facts = sid_to_facts.get(sid)
            if facts is None:
                continue
            emb = (((h["_source"].get("dshield") or {}).get("cowrie") or {})
                   .get("enrichment", {}).get("session", {}).get("embedding"))
            if not emb:
                continue
            persisted.append(emb)
            persisted_scalars.append(facts.scalars)
            persisted_sids.append(sid)
            pulled += 1
            if args.limit_rollups is not None and pulled >= args.limit_rollups:
                break
        else:
            sa = hits[-1]["sort"]
            continue
        break

    baseline_labels = _cluster_at_production_scale(
        persisted, persisted_scalars, scfg, rescue=not args.no_rescue,
    )
    sid_to_baseline_cluster = {sid: int(c) for sid, c in zip(persisted_sids, baseline_labels)}
    bl_eval_labels: list[str] = []
    bl_eval_clusters: list[int] = []
    for sid, lbl in sid_to_label.items():
        if sid in sid_to_baseline_cluster:
            bl_eval_labels.append(lbl)
            bl_eval_clusters.append(sid_to_baseline_cluster[sid])
    baseline_ari = float(adjusted_rand_score(
        bl_eval_labels, np.array(bl_eval_clusters, dtype=np.int64),
    ))

    results: list[dict] = []
    with make_llm_client(cfg.llm) as llm:
        for sc in SWEEP_CONFIGS:
            log.info("=== %s : embed_context=%s ===", sc.name, list(sc.embed_context))
            cmd_vecs = _embed_all_commands(llm, enrichments, sc.embed_context)
            kept, pooled = _pool_sessions(sessions, cmd_vecs, enrichments)
            cluster_labels = _cluster_at_production_scale(
                pooled, [s.scalars for s in kept], scfg, rescue=not args.no_rescue,
            )
            score = _score_against_labels(kept, cluster_labels, pair_to_sessions)
            log.info(
                "  ari=%s  hom=%s  comp=%s  v2pair=%s  n_clusters=%d",
                score["metrics"].get("ari"),
                score["metrics"].get("homogeneity"),
                score["metrics"].get("completeness"),
                score["metrics"].get("divergent_pair_resolution_rate"),
                score["n_clusters_total"],
            )
            results.append({
                "config":  {"name": sc.name, "embed_context": list(sc.embed_context)},
                "score":   score,
                "kept_sessions":     len(kept),
                "embedded_commands": len(cmd_vecs),
            })

    # Preserve plan-spec order for the markdown table (production first,
    # then mitre_stripped) so the verdict prose lines up with the row order.
    verdict, verdict_prose = _decide_verdict(results)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"mitre-strip-sweep-{ts}.md"
    json_path = args.output_dir / f"mitre-strip-sweep-{ts}.json"
    md = _render_markdown(results, baseline_ari, started_at, verdict, verdict_prose)
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps({
        "started_at":   started_at,
        "verdict":      verdict,
        "baseline_ari": round(baseline_ari, 4),
        "rollups":      len(sessions),
        "results":      results,
        "config_at_capture": {
            "embedding_model":   cfg.llm.embedding_model,
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
