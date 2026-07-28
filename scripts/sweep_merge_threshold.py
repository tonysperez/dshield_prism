"""Fragmentation sweep — both directions — at production scale.

Plan F assumed the corpus *under*-fragments (HDBSCAN suppresses small
clusters). The F-phase spike found the opposite at the margin: lowering
mcs floods *density fragments* (size-7 pockets at cosine ≈ 1.0 to a big
playbook centroid). So this tests the actual fragmentation-control knob —
``session.playbook_merge_threshold`` — in **both** directions:

  * **down** (0.90–0.94): more complete-linkage merging → fewer, more
    consolidated playbooks → absorbs density fragments. The (C) direction.
  * **up** (0.98–1.0): less merging → more fragmentation.

Crucially, this is the first measurement that runs the session-layer
``merge_clusters_into_playbooks`` pass. The established eval path
(``eval_clustering.py`` / ``eval_production_scale.py``) scores HDBSCAN +
rescue **pre-merge**, so its cluster counts over-state production
fragmentation. Here the base granularity (HDBSCAN mcs=5,ms=2 + rescue) is
held fixed and only the merge threshold varies, so the table isolates the
merge step's effect — including whether production's current 0.96 already
absorbs the density fragments the pre-merge spike saw.

A clean consolidation win (density fragments absorbed — n_small and
near_large_fraction drop — while ARI holds) confirms over-fragmentation
and ships as a threshold change. If lowering the threshold drops ARI
(real distinct clusters merged away), 0.96 is already right.

Read-only. Run from the repo root via the console venv:
    console/.venv/bin/python scripts/sweep_merge_threshold.py
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.clustering import compute_centroids
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.sessions import merge_clusters_into_playbooks

from eval_production_scale import _load_eval_session_ids_and_labels
from prod_corpus import (
    cluster_hdbscan, normalized_embeddings, pull_session_corpus, score_full,
)

# Both-ways grid centred on the production default (0.96). "none" = skip the
# merge entirely (the pre-merge baseline the spike measured).
_MERGE_GRID = ("none", 1.0, 0.98, 0.96, 0.94, 0.92, 0.90)


def _apply_merge(base_labels: np.ndarray, normalized: np.ndarray,
                 threshold: float) -> np.ndarray:
    """Relabel base HDBSCAN+rescue clusters into merged playbook groups via
    the production ``merge_clusters_into_playbooks`` pass. Outliers (-1)
    pass through untouched."""
    centroids = compute_centroids(normalized, base_labels)  # {int: vec}, no -1
    cmap = {str(int(l)): centroids[l].tolist() for l in centroids}
    groups = merge_clusters_into_playbooks(cmap, threshold)  # {str(lbl): "pgN"}
    pg_to_int: dict[str, int] = {}
    merged = np.empty_like(base_labels)
    for i, l in enumerate(base_labels):
        li = int(l)
        if li < 0:
            merged[i] = -1
            continue
        pg = groups[str(li)]
        if pg not in pg_to_int:
            pg_to_int[pg] = len(pg_to_int)
        merged[i] = pg_to_int[pg]
    return merged


def _render(rows: list[dict], n_sessions: int, n_base: int) -> str:
    out: list[str] = []
    out.append("# Fragmentation sweep — merge threshold (production scale)")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append(f"{n_sessions} sessions · base granularity HDBSCAN(mcs=5,ms=2) "
               f"+ rescue(0.96) → {n_base} clusters, held fixed. Only the "
               "complete-linkage merge threshold varies. `none` = pre-merge "
               "(what the spike measured); `0.96` = current production. "
               "`distinct` = small clusters cos < merge_threshold from every "
               "big playbook; `near_lg` = density-fragment fraction. Down = "
               "less fragmentation; up = more.")
    out.append("")
    headers = ["merge_thr", "clusters", "outliers", "ari", "cmp", "hom", "dpr",
               "n_small", "distinct", "near_lg", "purity", "shard"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---:"] * len(headers)) + "|")
    for r in rows:
        m = r["metrics"]
        def _f(key):
            v = m.get(key)
            return "—" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))
        star = " *" if r["merge_thr"] == "0.96" else ""
        cells = [
            r["merge_thr"], str(r["n_clusters_total"]), str(r["n_outliers_total"]),
            _f("ari"), _f("completeness"), _f("homogeneity"),
            _f("divergent_pair_resolution_rate"),
            str(m.get("n_small_clusters")), str(m.get("n_small_clusters_distinct")),
            _f("small_cluster_near_large_fraction"), _f("small_cluster_purity"),
            _f("small_cluster_shard_fraction"),
        ]
        out.append("| " + " | ".join(cells) + " |" + star)
    out.append("")
    out.append("_* = current production merge threshold._")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    args = ap.parse_args()

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)
    index = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    print(f"pulling corpus from {index} ...", flush=True)
    corpus = pull_session_corpus(es, index, cfg.session.page_size)
    print(f"  {len(corpus)} sessions", flush=True)
    sid_to_label, pair_to_sessions = _load_eval_session_ids_and_labels(
        Path("eval/labels.yaml"), Path("eval/labels-v2.yaml"),
    )
    merge_threshold_default = cfg.session.playbook_merge_threshold

    # Fixed base granularity = production HDBSCAN + rescue.
    base_labels, n_rescued = cluster_hdbscan(
        corpus,
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        scalar_weight=cfg.session.cluster_scalar_weight,
        rescue_threshold=merge_threshold_default,
    )
    normalized = normalized_embeddings(corpus)
    n_base = len({int(c) for c in base_labels if c >= 0})
    print(f"base granularity: {n_base} clusters, {n_rescued} rescued", flush=True)

    rows: list[dict] = []
    for thr in _MERGE_GRID:
        if thr == "none":
            labels = base_labels
            label = "none"
        else:
            labels = _apply_merge(base_labels, normalized, float(thr))
            label = f"{thr:.2f}"
        scored = score_full(
            labels, corpus, sid_to_label, pair_to_sessions,
            merge_threshold=merge_threshold_default,
        )
        scored["merge_thr"] = label
        rows.append(scored)
        m = scored["metrics"]
        print(f"  merge_thr={label:>5} → clusters={scored['n_clusters_total']} "
              f"ari={m['ari']} n_small={m['n_small_clusters']} "
              f"distinct={m['n_small_clusters_distinct']} "
              f"near_lg={m['small_cluster_near_large_fraction']}", flush=True)

    md = _render(rows, len(corpus), n_base)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"merge-threshold-sweep-{ts}.md"
    json_path = args.output_dir / f"merge-threshold-sweep-{ts}.json"
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_sessions": len(corpus), "n_base_clusters": n_base, "rows": rows,
    }, indent=2), encoding="utf-8")
    print("\n" + md)
    print(f"\nwrote {md_path}\nwrote {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
