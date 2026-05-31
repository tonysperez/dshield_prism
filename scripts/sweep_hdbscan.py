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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", type=Path,
                    default=Path("eval/labels-v1.yaml"),
                    help="Analyst-labeled YAML")
    ap.add_argument("--jsonl", type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"),
                    help="Unlabeled eval JSONL")
    ap.add_argument("--output", type=Path,
                    default=Path("eval/results/hdbscan-sweep.json"),
                    help="Where to write the machine-readable JSON")
    ap.add_argument("--no-json", action="store_true",
                    help="Skip the JSON dump (stdout only)")
    args = ap.parse_args()

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
