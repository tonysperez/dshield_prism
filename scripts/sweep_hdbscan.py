"""HDBSCAN hyperparameter sweep against the labeled eval set
(brutal-review phase 3.2).

For each ``(min_cluster_size, min_samples)`` combo in the cross-product
``{2, 3, 5, 8, 13} × {1, 2, 3, 5}`` (20 combos), runs HDBSCAN over the
eval set's embeddings + scalar block (same pipeline as
``scripts/eval_clustering.py``) and reports clustering quality + shape
metrics:

  * ``ari``           — adjusted Rand index vs. analyst labels.
  * ``v_measure``     — harmonic mean of homogeneity + completeness.
  * ``n_clusters``    — distinct non-noise cluster ids.
  * ``n_outliers``    — HDBSCAN -1 noise points.
  * ``outlier_rate``  — n_outliers / total.

Picks the combo with the best ARI as the recommended setting. The
``commit 3.4`` config decision should cite the sweep result (or change
the config and re-baseline).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_hdbscan.py
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from itertools import product
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

# eval_clustering.py is the source of the loading + scalar-building
# helpers; importing it directly keeps the sweep and the baseline eval
# pointed at the same code path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import eval_clustering as ec
from enrich.clustering import l2_normalize
from enrich.config import load_config
from enrich.sources.cowrie.sessions import build_session_scalar_block


# Sweep grid per the brutal-review plan. {2, 3, 5, 8, 13} × {1, 2, 3, 5}
# spans the "fine-grained" (mcs=2) and "noise-aggressive" (mcs=13) ends
# of typical HDBSCAN-on-embeddings practice. min_samples=1 disables
# mutual-reachability density smoothing.
_SWEEP_MIN_CLUSTER_SIZE = (2, 3, 5, 8, 13)
_SWEEP_MIN_SAMPLES      = (1, 2, 3, 5)

# F4.1 production-scale grid (handoff-small-cluster-surfacing-plan). 8 explicit
# (mcs, ms) points; production is (5, 2). Lower-mcs points test whether
# tuning the primary HDBSCAN directly surfaces small clusters without a
# secondary pass — at the risk of shredding big copy/paste playbooks (3b is
# the gate there, not ARI).
_PROD_SWEEP_GRID = ((2, 1), (2, 2), (3, 1), (3, 2), (5, 1), (5, 2), (8, 2), (13, 2))


def _run_one(
    norm_matrix: np.ndarray,
    scalar_block: np.ndarray | None,
    label_truth: list[str],
    *,
    min_cluster_size: int,
    min_samples: int,
) -> dict:
    """Single HDBSCAN run + metric computation. Operates on the
    pre-normalised matrix + pre-built scalar block to keep the sweep
    fast (no re-embedding, no re-normalisation)."""
    if scalar_block is not None:
        cluster_matrix = np.hstack([norm_matrix, scalar_block])
    else:
        cluster_matrix = norm_matrix
    clusterer = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    )
    pred = clusterer.fit_predict(cluster_matrix)
    n = len(pred)
    n_outliers = int(sum(1 for c in pred if c == -1))
    n_clusters = len({int(c) for c in pred if c >= 0})
    return {
        "min_cluster_size": min_cluster_size,
        "min_samples":      min_samples,
        "ari":              round(float(adjusted_rand_score(label_truth, pred)), 4),
        "nmi":              round(float(normalized_mutual_info_score(label_truth, pred)), 4),
        "homogeneity":      round(float(homogeneity_score(label_truth, pred)), 4),
        "completeness":     round(float(completeness_score(label_truth, pred)), 4),
        "v_measure":        round(float(v_measure_score(label_truth, pred)), 4),
        "n_clusters":       n_clusters,
        "n_outliers":       n_outliers,
        "outlier_rate":     round(n_outliers / n, 4) if n else 0.0,
    }


def _load_dataset(labels_path: Path, jsonl_path: Path) -> tuple[
    np.ndarray, np.ndarray | None, list[str], dict,
]:
    """Returns (normalised_embedding_matrix, scalar_block_at_prod_weight,
    label_truth, dataset_meta). Mirrors eval_clustering._evaluate up to
    the point of running HDBSCAN — the sweep replaces only the
    clusterer call."""
    cfg = load_config()
    label_blocks = ec._load_labels(labels_path)
    embeddings: list[list[float]] = []
    scalars: list[dict] = []
    label_truth: list[str] = []
    for rec in ec._iter_jsonl(jsonl_path):
        sid = rec.get("session_id")
        if sid not in label_blocks:
            continue
        feats = ec._extract_session_features(rec)
        if feats is None:
            continue
        emb, sc = feats
        embeddings.append(emb)
        scalars.append(sc)
        label_truth.append(label_blocks[sid]["playbook_label"])
    if len(embeddings) < min(_SWEEP_MIN_CLUSTER_SIZE):
        raise RuntimeError(
            f"only {len(embeddings)} labeled+embedded sessions — need at "
            f"least {min(_SWEEP_MIN_CLUSTER_SIZE)}"
        )
    matrix = np.array(embeddings, dtype=np.float32)
    norm = l2_normalize(matrix)
    scalar_weight = cfg.session.cluster_scalar_weight
    scalar_block = (
        build_session_scalar_block(scalars, scalar_weight)
        if scalar_weight > 0.0 else None
    )
    meta = {
        "labels_path":           str(labels_path),
        "jsonl_path":            str(jsonl_path),
        "labeled_with_embed":    len(embeddings),
        "scalar_weight":         scalar_weight,
        "label_count":           len(set(label_truth)),
    }
    return norm, scalar_block, label_truth, meta


def _render_table(rows: list[dict], best: dict) -> str:
    """Markdown sweep table. Marks the best-ARI combo with an asterisk."""
    out = [
        "| mcs | ms | ARI | NMI | hom | cmp | v_meas | n_clusters | outliers | outlier_rate |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    best_key = (best["min_cluster_size"], best["min_samples"])
    for r in rows:
        star = " *" if (r["min_cluster_size"], r["min_samples"]) == best_key else ""
        out.append(
            f"| {r['min_cluster_size']:>3}{star} | {r['min_samples']:>2} "
            f"| {r['ari']:.4f} | {r['nmi']:.4f} | {r['homogeneity']:.4f} "
            f"| {r['completeness']:.4f} | {r['v_measure']:.4f} "
            f"| {r['n_clusters']:>3} | {r['n_outliers']:>3} "
            f"| {r['outlier_rate']:.4f} |"
        )
    out.append("")
    out.append(
        f"* best-ARI combo: min_cluster_size={best['min_cluster_size']} "
        f"min_samples={best['min_samples']} → ARI {best['ari']:.4f}"
    )
    return "\n".join(out)


_PROD_METRIC_COLS = (
    "ari", "completeness", "homogeneity", "divergent_pair_resolution_rate",
    "outlier_rate", "n_small_clusters", "small_cluster_purity",
    "small_cluster_shard_fraction",
)


def _render_prod_table(rows: list[dict]) -> str:
    """Markdown table for the F4.1 production-scale sweep — the 7 binding
    metrics + small-cluster axis per (mcs, ms)."""
    out: list[str] = []
    out.append("# F4.1 — multi-mcs HDBSCAN sweep (production scale)")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append("All metrics over the full production corpus except ari / "
               "completeness / homogeneity / divergent-pair, which score the "
               "labeled eval subset against the production cluster ids. "
               "Production config is (mcs=5, ms=2). `lbl_in_S` = labeled-eval "
               "members landing in size-∈[3,10] clusters (metric-5 diagnostic).")
    out.append("")
    headers = (["mcs", "ms", "clusters", "outliers", "ari", "cmp", "hom",
                "dpr", "out_rate", "n_small", "distinct", "near_lg", "purity",
                "shard_frac", "lbl_in_S"])
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---:"] * len(headers)) + "|")
    for r in rows:
        m = r["metrics"]
        def _f(key):
            v = m.get(key)
            return "—" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))
        cells = [
            str(r["mcs"]), str(r["ms"]),
            str(r["n_clusters_total"]), str(r["n_outliers_total"]),
            _f("ari"), _f("completeness"), _f("homogeneity"),
            _f("divergent_pair_resolution_rate"), _f("outlier_rate"),
            str(m.get("n_small_clusters")), str(m.get("n_small_clusters_distinct")),
            _f("small_cluster_near_large_fraction"), _f("small_cluster_purity"),
            _f("small_cluster_shard_fraction"), str(r["labeled_in_small"]),
        ]
        prod = " *" if (r["mcs"], r["ms"]) == (5, 2) else ""
        out.append("| " + " | ".join(cells) + " |" + prod)
    out.append("")
    out.append("_* = current production config._")
    return "\n".join(out)


def _run_prod_sweep(output_dir: Path) -> int:
    """F4.1: pull the live corpus once, sweep the 8-point (mcs, ms) grid,
    score each on all 7 binding metrics + the small-cluster axis."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from enrich.config import load_config, load_secrets
    from enrich.es_client import make_client
    from eval_production_scale import _load_eval_session_ids_and_labels
    from prod_corpus import cluster_hdbscan, pull_session_corpus, score_full

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
    merge_threshold = cfg.session.playbook_merge_threshold

    rows: list[dict] = []
    for mcs, ms in _PROD_SWEEP_GRID:
        print(f"  clustering (mcs={mcs}, ms={ms}) ...", flush=True)
        labels, n_rescued = cluster_hdbscan(
            corpus, min_cluster_size=mcs, min_samples=ms,
            scalar_weight=cfg.session.cluster_scalar_weight,
            rescue_threshold=merge_threshold,
        )
        scored = score_full(
            labels, corpus, sid_to_label, pair_to_sessions,
            merge_threshold=merge_threshold,
        )
        scored.update({"mcs": mcs, "ms": ms, "n_rescued": n_rescued})
        rows.append(scored)
        m = scored["metrics"]
        print(f"    ari={m['ari']} out_rate={m['outlier_rate']} "
              f"n_small={m['n_small_clusters']} purity={m['small_cluster_purity']} "
              f"shard={m['small_cluster_shard_fraction']}", flush=True)

    md = _render_prod_table(rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = output_dir / f"hdbscan-prod-sweep-{ts}.md"
    json_path = output_dir / f"hdbscan-prod-sweep-{ts}.json"
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_sessions": len(corpus),
        "grid": [list(p) for p in _PROD_SWEEP_GRID],
        "rows": rows,
    }, indent=2), encoding="utf-8")
    print("\n" + md)
    print(f"\nwrote {md_path}\nwrote {json_path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--prod", action="store_true",
                    help="Run the F4.1 production-scale sweep (live ES, "
                         "8-point (mcs,ms) grid, 7 binding metrics) instead "
                         "of the eval-scale sweep.")
    ap.add_argument("--labels", type=Path,
                    default=Path("eval/labels.yaml"),
                    help="Analyst-labeled YAML")
    ap.add_argument("--jsonl", type=Path,
                    default=Path("eval/sessions.unlabeled.jsonl.gz"),
                    help="Unlabeled eval JSONL")
    ap.add_argument("--output", type=Path,
                    default=Path("eval/results/hdbscan-sweep.json"),
                    help="Where to write the machine-readable JSON")
    ap.add_argument("--output-dir", type=Path,
                    default=Path("eval/results"),
                    help="Output dir for the --prod sweep markdown + JSON")
    ap.add_argument("--no-json", action="store_true",
                    help="Skip the JSON dump (stdout only)")
    args = ap.parse_args()

    if args.prod:
        return _run_prod_sweep(args.output_dir)

    norm, scalar_block, label_truth, meta = _load_dataset(
        args.labels, args.jsonl,
    )

    rows: list[dict] = []
    for mcs, ms in product(_SWEEP_MIN_CLUSTER_SIZE, _SWEEP_MIN_SAMPLES):
        if ms > mcs:
            # HDBSCAN: min_samples > min_cluster_size is degenerate — every
            # point lands in outliers. Skip to keep the table readable.
            continue
        rows.append(_run_one(
            norm, scalar_block, label_truth,
            min_cluster_size=mcs, min_samples=ms,
        ))

    best = max(rows, key=lambda r: r["ari"])
    print(f"input: {meta['labeled_with_embed']} sessions, "
          f"{meta['label_count']} distinct labels, "
          f"scalar_weight={meta['scalar_weight']}")
    print()
    print(_render_table(rows, best))

    if not args.no_json:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input":        meta,
            "sweep_grid": {
                "min_cluster_size": list(_SWEEP_MIN_CLUSTER_SIZE),
                "min_samples":      list(_SWEEP_MIN_SAMPLES),
            },
            "results":      rows,
            "best_ari":     best,
        }
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
