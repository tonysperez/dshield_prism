"""Eval the session-layer clustering against the analyst-labeled ground truth.

Loads ``eval/labels-v1.yaml`` and ``eval/sessions-v1.unlabeled.jsonl``,
joins by ``session_id``, filters to ``is_real: true`` blocks with a
non-null ``playbook_label``, then re-runs the same L2-normalize +
scalar-augment + HDBSCAN pipeline the production session clusterer
uses (``src/enrich/clustering.py``) on the eval set's embeddings.
Reports clustering quality against the analyst labels:

  * ``ari``           — adjusted Rand index (chance-corrected pairwise agreement)
  * ``nmi``           — normalized mutual information
  * ``homogeneity``   — each cluster contains only members of a single label
  * ``completeness``  — all members of a label end up in the same cluster
  * ``v_measure``     — harmonic mean of homogeneity + completeness

This is a pure-function eval: no ES, no writes, no live cluster index
state. The HDBSCAN math + hyperparameters mirror what production runs
(min_cluster_size, min_samples, scalar_weight from ``cfg.session``),
so the score reflects what the deployed pipeline would produce on the
labeled subset.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/eval_clustering.py
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import yaml
from sklearn.cluster import HDBSCAN
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.clustering import l2_normalize
from enrich.config import load_config
from enrich.sources.cowrie.sessions import build_session_scalar_block


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_labels(path: Path) -> dict[str, dict]:
    """Return {session_id: label_block} for every annotated, real block."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, dict] = {}
    for sid, block in data.items():
        if not isinstance(block, dict):
            continue
        if not block.get("annotated"):
            continue
        if not block.get("is_real"):
            continue
        if not block.get("playbook_label"):
            continue
        out[sid] = block
    return out


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _extract_session_features(rec: dict) -> tuple[list[float], dict] | None:
    """Pull the (embedding, scalars) tuple from a JSONL record, mirroring
    `iter_session_docs` in the production clusterer."""
    rollup = rec.get("rollup_doc") or {}
    enr = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    emb = enr.get("embedding")
    if not isinstance(emb, list) or not emb:
        return None
    success = enr.get("login_success_count") or 0
    fail = enr.get("login_fail_count") or 0
    total = success + fail
    scalars = {
        "command_count":      enr.get("command_count") or 1,
        "unique_commands":    enr.get("unique_commands") or 1,
        "login_success_rate": success / total if total > 0 else 0.0,
        "mean_novelty_score": enr.get("mean_novelty_score") or 0.0,
    }
    return emb, scalars


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def _cluster(
    embeddings: list[list[float]],
    scalars: list[dict],
    *,
    min_cluster_size: int,
    min_samples: int,
    scalar_weight: float,
) -> np.ndarray:
    """L2-normalize embeddings, hstack the session scalar block, run HDBSCAN.
    Mirrors `enrich.clustering.run_layer_clustering` minus the side-effects
    (no ES updates, no centroid persist, no reference logic)."""
    matrix = np.array(embeddings, dtype=np.float32)
    normalized = l2_normalize(matrix)
    if scalar_weight > 0.0:
        block = build_session_scalar_block(scalars, scalar_weight)
        cluster_matrix = np.hstack([normalized, block])
    else:
        cluster_matrix = normalized
    clusterer = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    )
    return clusterer.fit_predict(cluster_matrix)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _per_label_breakdown(
    session_ids: list[str],
    label_truth: list[str],
    cluster_pred: np.ndarray,
) -> dict[str, dict]:
    """For each analyst label, compute the cluster id it lands in most
    often and that majority's share. A label that lands in one cluster
    (high share) = the pipeline groups it cleanly. A label split across
    many clusters (low share) = the pipeline is fragmenting that label.

    `cluster_id` of -1 is HDBSCAN's outlier marker; treat it as a real
    cluster in this view so we surface labels whose members the pipeline
    rejected as outliers."""
    by_label: dict[str, list[int]] = {}
    for lbl, c in zip(label_truth, cluster_pred):
        by_label.setdefault(lbl, []).append(int(c))
    out: dict[str, dict] = {}
    for lbl, clusters in sorted(by_label.items()):
        counts = Counter(clusters)
        top_cluster, top_count = counts.most_common(1)[0]
        out[lbl] = {
            "n":                 len(clusters),
            "distinct_clusters": len(counts),
            "majority_cluster":  top_cluster,
            "majority_share":    round(top_count / len(clusters), 3),
            "outlier_share":     round(counts.get(-1, 0) / len(clusters), 3),
        }
    return out


def _evaluate(labels_path: Path, jsonl_path: Path, cfg) -> dict:
    label_blocks = _load_labels(labels_path)
    if not label_blocks:
        raise RuntimeError(
            f"No annotated+real labels with non-null playbook_label "
            f"in {labels_path}"
        )

    session_ids: list[str] = []
    label_truth: list[str] = []
    embeddings: list[list[float]] = []
    scalars: list[dict] = []
    skipped_no_embedding: list[str] = []

    for rec in _iter_jsonl(jsonl_path):
        sid = rec.get("session_id")
        if sid not in label_blocks:
            continue
        feats = _extract_session_features(rec)
        if feats is None:
            skipped_no_embedding.append(sid)
            continue
        emb, sc = feats
        session_ids.append(sid)
        label_truth.append(label_blocks[sid]["playbook_label"])
        embeddings.append(emb)
        scalars.append(sc)

    if len(embeddings) < cfg.session.cluster_min_cluster_size:
        raise RuntimeError(
            f"Too few labeled+embedded sessions ({len(embeddings)}) — "
            f"need at least {cfg.session.cluster_min_cluster_size}."
        )

    cluster_pred = _cluster(
        embeddings, scalars,
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        scalar_weight=cfg.session.cluster_scalar_weight,
    )

    # Standard sklearn metrics. HDBSCAN's -1 (outliers) participates in
    # the metrics as a virtual cluster, which is the right behaviour
    # here: if the pipeline rejects an analyst-confirmed session as an
    # outlier, that's a clustering miss the eval should surface.
    metrics = {
        "ari":          round(float(adjusted_rand_score(label_truth, cluster_pred)), 4),
        "nmi":          round(float(normalized_mutual_info_score(label_truth, cluster_pred)), 4),
        "homogeneity":  round(float(homogeneity_score(label_truth, cluster_pred)), 4),
        "completeness": round(float(completeness_score(label_truth, cluster_pred)), 4),
        "v_measure":    round(float(v_measure_score(label_truth, cluster_pred)), 4),
    }

    n_clusters = len({int(c) for c in cluster_pred if c >= 0})
    n_outliers = int(sum(1 for c in cluster_pred if c == -1))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "min_cluster_size": cfg.session.cluster_min_cluster_size,
            "min_samples":      cfg.session.cluster_min_samples,
            "scalar_weight":    cfg.session.cluster_scalar_weight,
        },
        "input": {
            "labels_path":          str(labels_path),
            "jsonl_path":           str(jsonl_path),
            "labeled_blocks":       len(label_blocks),
            "labeled_with_embed":   len(embeddings),
            "skipped_no_embedding": len(skipped_no_embedding),
            "label_distribution":   dict(Counter(label_truth).most_common()),
        },
        "cluster_output": {
            "n_clusters":     n_clusters,
            "n_outliers":     n_outliers,
            "cluster_sizes":  dict(Counter(int(c) for c in cluster_pred).most_common()),
        },
        "metrics":   metrics,
        "per_label": _per_label_breakdown(session_ids, label_truth, cluster_pred),
    }


def _render_stdout(report: dict) -> str:
    """Human-readable summary for stdout."""
    out: list[str] = []
    out.append("=" * 72)
    out.append("Session-layer clustering eval")
    out.append("=" * 72)
    cfg = report["config"]
    out.append(f"hyperparameters     min_cluster_size={cfg['min_cluster_size']}  "
               f"min_samples={cfg['min_samples']}  "
               f"scalar_weight={cfg['scalar_weight']}")
    inp = report["input"]
    out.append(f"labeled blocks      {inp['labeled_blocks']}")
    out.append(f"with embedding      {inp['labeled_with_embed']}  "
               f"(skipped no-embed: {inp['skipped_no_embedding']})")
    out.append(f"label distribution  {inp['label_distribution']}")
    co = report["cluster_output"]
    out.append(f"cluster output      {co['n_clusters']} clusters + "
               f"{co['n_outliers']} outliers")
    out.append("")
    out.append("Metrics (0..1, higher is better):")
    for k, v in report["metrics"].items():
        out.append(f"  {k:14} {v:.4f}")
    out.append("")
    out.append("Per-label breakdown (analyst label → cluster grouping):")
    out.append(f"  {'label':35} {'n':>4} {'clusters':>9} {'maj.share':>10} {'outlier.share':>14}")
    for lbl, st in sorted(
        report["per_label"].items(),
        key=lambda kv: (-kv[1]["n"], kv[0]),
    ):
        out.append(
            f"  {lbl:35} {st['n']:>4} {st['distinct_clusters']:>9} "
            f"{st['majority_share']:>10.3f} {st['outlier_share']:>14.3f}"
        )
    return "\n".join(out)


def _compare_to_baseline(report: dict, baseline_path: Path) -> tuple[list[dict], bool]:
    """Diff the current metrics against ``eval/baseline.json``.

    Returns (per_metric_rows, ok) where ``ok`` is False when any metric
    has dropped more than its tolerance below the baseline. Each row is
    ``{name, baseline, current, tolerance, delta, status}``.

    Tolerance semantics: absolute drop. A metric fails when
    ``current < baseline - tolerance``. Improvements never fail."""
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    rows: list[dict] = []
    ok = True
    current = report["metrics"]
    for name, spec in baseline["metrics"].items():
        cur = current.get(name)
        base = spec["baseline"]
        tol = spec["tolerance"]
        if cur is None:
            rows.append({"name": name, "baseline": base, "current": None,
                         "tolerance": tol, "delta": None, "status": "MISSING"})
            ok = False
            continue
        delta = cur - base
        status = "PASS" if cur >= base - tol else "FAIL"
        if status == "FAIL":
            ok = False
        rows.append({"name": name, "baseline": base, "current": cur,
                     "tolerance": tol, "delta": round(delta, 4), "status": status})
    return rows, ok


def _render_gate(rows: list[dict], ok: bool) -> str:
    out = ["", "=" * 72, "Regression gate vs baseline", "=" * 72,
           f"  {'metric':14} {'baseline':>10} {'current':>10} "
           f"{'tolerance':>10} {'delta':>10}  status"]
    for r in rows:
        cur = "—" if r["current"] is None else f"{r['current']:.4f}"
        dlt = "—" if r["delta"]   is None else f"{r['delta']:+.4f}"
        out.append(
            f"  {r['name']:14} {r['baseline']:>10.4f} {cur:>10} "
            f"{r['tolerance']:>10.4f} {dlt:>10}  {r['status']}"
        )
    out.append("")
    out.append(f"GATE: {'PASS' if ok else 'FAIL'}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", type=Path,
                    default=Path("eval/labels-v1.yaml"),
                    help="Analyst-labeled YAML")
    ap.add_argument("--jsonl", type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"),
                    help="Unlabeled eval JSONL")
    ap.add_argument("--output-dir", type=Path,
                    default=Path("eval/results"),
                    help="Where to write the machine-readable JSON")
    ap.add_argument("--no-json", action="store_true",
                    help="Skip writing the JSON dump (stdout only)")
    ap.add_argument("--baseline", type=Path, default=None,
                    help=(
                        "Compare metrics to this baseline file and exit "
                        "non-zero on regression. Use to gate PRs."
                    ))
    args = ap.parse_args()

    cfg = load_config()
    report = _evaluate(args.labels, args.jsonl, cfg)
    print(_render_stdout(report))

    if not args.no_json:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = args.output_dir / f"clustering-{ts}.json"
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {out_path}")

    if args.baseline is not None:
        rows, ok = _compare_to_baseline(report, args.baseline)
        print(_render_gate(rows, ok))
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
