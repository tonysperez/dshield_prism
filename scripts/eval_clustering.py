"""Eval the session-layer clustering against the analyst-labeled ground truth.

Loads ``eval/labels.yaml`` (the stratified analyst sample), joins it by
``session_id`` against its unlabeled JSONL, filters to ``is_real: true``
blocks with a non-null ``playbook_label``, then re-runs the same
L2-normalize + SVD-reduce + scalar-augment + HDBSCAN + noise-rescue pipeline
the production session clusterer uses (``src/enrich/clustering.py``) on the
eval set's embeddings. Reports clustering quality against the analyst labels:

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

from enrich.clustering import (
    compute_centroids,
    l2_normalize,
    rescue_noise_points,
    svd_reduce,
)
from enrich.config import load_config
from enrich.sources.cowrie.sessions import build_session_scalar_block


# ---------------------------------------------------------------------------
# F-phase small-cluster + outlier metrics (handoff-small-cluster-surfacing-plan
# F0.1). Shared with eval_production_scale.py + the F3/F4 sweeps so every
# F-phase intervention scores on the same multi-objective axis.
# ---------------------------------------------------------------------------

# Cluster size bands. Small clusters are the surfacing target (metrics 2-3);
# large clusters are the shard reference set the distinctness proxy (3b)
# measures small clusters against. A cluster of size 1-2 falls below the
# small band and counts toward neither — it is effectively residual noise.
SMALL_BAND = (3, 10)        # size ∈ [3, 10]   — the user-stated objective
MEDIUM_BAND = (11, 100)     # size ∈ [11, 100] — context only
LARGE_MIN = 101             # size > 100       — the shard reference set
# Metric 3b textual-homogeneity clause: a small cluster is only a *shard* of a
# big playbook when its members run (near-)identical command sets. 0.8 mirrors
# the `modal_signature_share ≥ 0.8` "copy/paste tight" floor in
# scripts/eval_cluster_purity.py.
SHARD_MODAL_SIGNATURE_FLOOR = 0.8


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


def _modal_share(values: list) -> float | None:
    """Fraction of non-empty ``values`` equal to the modal value. None when
    no non-empty value is present (e.g. a layer/snapshot that doesn't carry
    the field). Used for both the intent-purity (3a) and the
    modal-signature-share (3b) clauses."""
    vals = [v for v in values if v]
    if not vals:
        return None
    _, top_count = Counter(vals).most_common(1)[0]
    return top_count / len(vals)


def small_cluster_metrics(
    cluster_pred: np.ndarray,
    normalized: np.ndarray,
    intents: list,
    signatures: list,
    *,
    merge_threshold: float,
) -> dict:
    """Compute the F-phase small-cluster + outlier axis (plan F0.1).

    Args:
      cluster_pred:  per-row integer cluster label (-1 = HDBSCAN noise).
      normalized:    (n, d) L2-normalized *pure-embedding* matrix — the same
                     geometry ``rescue_noise_points`` + the
                     ``playbook_merge_threshold`` centroid merge use, so the
                     nearest-large-centroid cosine (3b) matches production.
      intents:       per-row ``dominant_intent`` (sessions) / ``intent``
                     (commands), or ``None`` where unavailable. Drives 3a.
      signatures:    per-row ``command_signature`` (or per-layer analog), or
                     ``None`` where unavailable. Drives the 3b modal clause.
      merge_threshold: cosine floor for the shard test (0.96 in production).

    Returns a dict with the scalar metrics (mergeable into ``report['metrics']``)
    plus a per-small-cluster ``small_cluster_detail`` list and two
    ``*_available`` flags so a redacted input (e.g. the embeddings-only
    production snapshot) degrades to ``None`` on 3a/3b rather than silently
    reporting a wrong zero.
    """
    labels = np.asarray(cluster_pred)
    n = int(len(labels))
    n_outliers = int((labels == -1).sum())
    outlier_rate = round(n_outliers / n, 4) if n else 0.0

    sizes = Counter(int(c) for c in labels if c >= 0)
    small_lbls = [l for l, s in sizes.items() if SMALL_BAND[0] <= s <= SMALL_BAND[1]]
    n_small = len(small_lbls)
    n_medium = sum(1 for s in sizes.values() if MEDIUM_BAND[0] <= s <= MEDIUM_BAND[1])
    large_lbls = [l for l, s in sizes.items() if s >= LARGE_MIN]
    n_large = len(large_lbls)

    intent_available = any(bool(i) for i in intents)
    signature_available = any(bool(s) for s in signatures)

    # Centroids in the pure-embedding space; re-unit-normalize for cosine.
    centroids = compute_centroids(normalized, labels)

    def _unit(v: np.ndarray) -> np.ndarray:
        nv = float(np.linalg.norm(v))
        return v / nv if nv > 0.0 else v

    large_centroids = [_unit(centroids[l]) for l in large_lbls if l in centroids]

    details: list[dict] = []
    purities: list[float] = []
    shard_flags: list[bool] = []
    n_near_large = 0       # density-redundant: centroid within threshold of a big playbook
    n_distinct = 0         # genuinely distant from every big playbook
    for l in sorted(small_lbls):
        idx = np.where(labels == l)[0]
        member_intents = [intents[i] for i in idx]
        member_sigs = [signatures[i] for i in idx]
        intent_share = _modal_share(member_intents)
        modal_sig = _modal_share(member_sigs)

        nearest_large_cos: float | None = None
        if l in centroids and large_centroids:
            cu = _unit(centroids[l])
            nearest_large_cos = max(float(np.dot(cu, lc)) for lc in large_centroids)

        # Density-redundancy (broader than the lexical shard test): a small
        # cluster whose centroid is within merge_threshold cosine of a big
        # playbook is the *same behaviour* as that playbook — a density
        # fragment — regardless of textual homogeneity. This catches the
        # gap 3b's modal-signature clause leaves open: textually-diverse
        # fragments hugging a big centroid (cos≈1.0, low modal_sig) that
        # read as "distinct" to 3b but are not new behaviours.
        near_large = nearest_large_cos is not None and nearest_large_cos >= merge_threshold
        if near_large:
            n_near_large += 1
        else:
            n_distinct += 1

        # 3b shard test: within merge_threshold cosine of a big centroid AND
        # textually homogeneous (same copy/paste script). Undeterminable when
        # signatures are absent — leave is_shard None so it's excluded from
        # the fraction rather than counted as "not a shard".
        is_shard: bool | None = None
        if signature_available and modal_sig is not None:
            is_shard = bool(near_large and modal_sig >= SHARD_MODAL_SIGNATURE_FLOOR)
            shard_flags.append(is_shard)

        if intent_share is not None:
            purities.append(intent_share)

        top_intent = None
        if intent_available:
            named = [i for i in member_intents if i]
            if named:
                top_intent = Counter(named).most_common(1)[0][0]

        details.append({
            "cluster_label":         int(l),
            "size":                  int(sizes[l]),
            "dominant_intent":       top_intent,
            "intent_share":          round(intent_share, 4) if intent_share is not None else None,
            "modal_signature_share": round(modal_sig, 4) if modal_sig is not None else None,
            "nearest_large_cosine":  round(nearest_large_cos, 4) if nearest_large_cos is not None else None,
            "is_shard":              is_shard,
            "near_large":            near_large,
        })

    small_cluster_purity = (
        round(sum(purities) / len(purities), 4) if purities else None
    )
    small_cluster_shard_fraction = (
        round(sum(1 for x in shard_flags if x) / len(shard_flags), 4)
        if shard_flags else None
    )
    small_cluster_near_large_fraction = (
        round(n_near_large / n_small, 4) if n_small else None
    )

    return {
        "metrics": {
            "outlier_rate":                 outlier_rate,
            "n_small_clusters":             n_small,
            "n_medium_clusters":            n_medium,
            "n_large_clusters":             n_large,
            "small_cluster_purity":         small_cluster_purity,
            "small_cluster_shard_fraction": small_cluster_shard_fraction,
            # Density-redundancy decomposition of the small-cluster count.
            # n_small_clusters_distinct = genuinely distant from every big
            # playbook (the real surfacing yield); near_large_fraction =
            # share that are density fragments of a big playbook.
            "n_small_clusters_distinct":         n_distinct,
            "small_cluster_near_large_fraction": small_cluster_near_large_fraction,
        },
        "small_cluster_detail":   details,
        "intent_available":       intent_available,
        "signature_available":    signature_available,
        "n_outliers":             n_outliers,
        "n_total":                n,
    }


def render_small_cluster_block(metrics: dict, sc: dict) -> list[str]:
    """Stdout lines for the F-phase small-cluster axis. ``metrics`` is the
    report's merged metric dict; ``sc`` is the report's ``small_cluster``
    block (availability flags + per-cluster detail). Shared by
    eval_clustering.py + eval_production_scale.py."""
    out: list[str] = []
    out.append("Small-cluster + outlier axis (F-phase):")
    out.append(f"  {'outlier_rate':28} {metrics.get('outlier_rate'):.4f}")
    out.append(
        f"  {'clusters S/M/L':28} "
        f"{metrics.get('n_small_clusters')} / "
        f"{metrics.get('n_medium_clusters')} / "
        f"{metrics.get('n_large_clusters')}   "
        f"(small=[3,10], medium=[11,100], large>100)"
    )
    purity = metrics.get("small_cluster_purity")
    shard = metrics.get("small_cluster_shard_fraction")
    intent_ok = sc.get("intent_available")
    sig_ok = sc.get("signature_available")
    out.append(
        f"  {'small_cluster_purity (3a)':28} "
        + (f"{purity:.4f}" if purity is not None
           else ("—  (no small clusters)" if intent_ok else "—  (intent unavailable)"))
    )
    out.append(
        f"  {'small_cluster_shard_frac (3b)':28} "
        + (f"{shard:.4f}" if shard is not None
           else ("—  (no small clusters)" if sig_ok else "—  (signature unavailable)"))
    )
    distinct = metrics.get("n_small_clusters_distinct")
    near = metrics.get("small_cluster_near_large_fraction")
    if distinct is not None:
        out.append(
            f"  {'distinct (cos<thr) / near-big':28} "
            f"{distinct}"
            + (f"  ·  near_large_fraction {near:.4f}" if near is not None else "")
            + "   (distinct = genuine surfacing yield)"
        )
    detail = sc.get("detail") or []
    if detail:
        out.append("  small clusters (label · size · intent · intent_share · "
                   "modal_sig · near_large_cos · shard):")
        for d in detail:
            cos = d["nearest_large_cosine"]
            out.append(
                f"    #{d['cluster_label']:<6} n={d['size']:<3} "
                f"{str(d['dominant_intent'] or '—'):22} "
                f"is={_fmt_opt(d['intent_share'])} "
                f"sig={_fmt_opt(d['modal_signature_share'])} "
                f"cos={'—' if cos is None else f'{cos:.3f}'} "
                f"{'SHARD' if d['is_shard'] else ('ok' if d['is_shard'] is False else '?')}"
            )
    return out


def _fmt_opt(v) -> str:
    return "—" if v is None else f"{v:.2f}"


def _extract_session_intent_signature(rec: dict) -> tuple:
    """Pull ``(dominant_intent, command_signature)`` from a JSONL record's
    rollup doc — the 3a/3b inputs. Either may be ``None`` on a record that
    doesn't carry it (login-only sessions have no commands, hence no
    signature)."""
    enr = (
        (((rec.get("rollup_doc") or {}).get("dshield") or {}).get("cowrie") or {})
        .get("enrichment", {})
        .get("session", {})
    )
    return enr.get("dominant_intent"), enr.get("command_signature")


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
    svd_dim: int,
    merge_threshold: float,
) -> np.ndarray:
    """L2-normalize → SVD-reduce → scalar-augment → HDBSCAN → noise-rescue,
    the SAME pipeline `enrich.clustering.run_layer_clustering` runs (minus
    the ES side-effects, centroid persist, reference logic).

    The SVD reduction and the noise rescue are part of how production
    actually groups, not optional polish: the fit runs in the reduced
    space, then `rescue_noise_points` reassigns HDBSCAN outliers to their
    nearest cluster centroid when cosine ≥ `merge_threshold`, measured in
    FULL-dim pure-embedding space — so the eval's grouping reflects what
    the deployed pipeline produces rather than a raw-HDBSCAN approximation
    with an inflated outlier rate."""
    normalized = l2_normalize(np.array(embeddings, dtype=np.float32))
    reduced, _ = svd_reduce(normalized, svd_dim)
    if scalar_weight > 0.0:
        block = build_session_scalar_block(scalars, scalar_weight)
        cluster_matrix = np.hstack([reduced, block])
    else:
        cluster_matrix = reduced
    labels = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    ).fit_predict(cluster_matrix)
    # Rescue against full-dim pure-embedding space (never the reduced fit
    # space or the scalar block), exactly as run_layer_clustering does.
    # threshold > 1.0 disables, matching playbook_merge_threshold semantics.
    if merge_threshold and merge_threshold <= 1.0:
        labels, _ = rescue_noise_points(normalized, labels, merge_threshold)
    return labels


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _per_label_breakdown(
    session_ids: list[str],
    label_truth: list[str],
    cluster_pred: np.ndarray,
) -> dict[str, dict]:
    """For each analyst label, decompose how HDBSCAN split it. A label
    that lands in one cluster (low fragmentation, high largest_cluster_share)
    = the pipeline groups it cleanly. A label split across many clusters
    (high fragmentation) = the pipeline is fragmenting that label.

    Keys (plan E0.1):
      * ``n_sessions``                 — label support in the eval set.
      * ``n_hdbscan_clusters_assigned`` — distinct cluster ids the label
        members landed in (HDBSCAN ``-1`` counts as one).
      * ``fragmentation_ratio``        — ``n_hdbscan_clusters_assigned /
        n_sessions``. ``1/n`` = perfect grouping; ``1.0`` = every member
        in a different cluster.
      * ``largest_cluster_share``      — share of the label's sessions in
        its dominant cluster.

    Extras retained for cross-referencing from diagnose_embedding_loss.py:
      * ``majority_cluster`` — the dominant cluster id.
      * ``outlier_share``    — share of sessions HDBSCAN tagged as ``-1``.
    """
    by_label: dict[str, list[int]] = {}
    for lbl, c in zip(label_truth, cluster_pred):
        by_label.setdefault(lbl, []).append(int(c))
    out: dict[str, dict] = {}
    for lbl, clusters in sorted(by_label.items()):
        counts = Counter(clusters)
        top_cluster, top_count = counts.most_common(1)[0]
        n = len(clusters)
        n_clusters_assigned = len(counts)
        out[lbl] = {
            "n_sessions":                 n,
            "n_hdbscan_clusters_assigned": n_clusters_assigned,
            "fragmentation_ratio":         round(n_clusters_assigned / n, 3),
            "largest_cluster_share":       round(top_count / n, 3),
            "majority_cluster":            top_cluster,
            "outlier_share":               round(counts.get(-1, 0) / n, 3),
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
    intents: list = []      # per-session dominant_intent (3a input)
    signatures: list = []   # per-session command_signature (3b input)
    skipped_no_embedding: list[str] = []

    seen_sids: set[str] = set()
    for rec in _iter_jsonl(jsonl_path):
        sid = rec.get("session_id")
        if not isinstance(sid, str) or sid in seen_sids:
            continue
        if sid not in label_blocks:
            continue
        feats = _extract_session_features(rec)
        if feats is None:
            skipped_no_embedding.append(sid)
            continue
        emb, sc = feats
        intent, signature = _extract_session_intent_signature(rec)
        seen_sids.add(sid)
        session_ids.append(sid)
        label_truth.append(label_blocks[sid]["playbook_label"])
        embeddings.append(emb)
        scalars.append(sc)
        intents.append(intent)
        signatures.append(signature)

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
        svd_dim=cfg.session.cluster_svd_dim,
        merge_threshold=cfg.session.playbook_merge_threshold,
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

    # F-phase small-cluster + outlier axis (plan F0.1). Computed over the
    # eval-isolated clustering — advisory at this scale (no size>100 clusters
    # exist, so the shard test is near-vacuous); the binding numbers come
    # from eval_production_scale.py (F0.2).
    norm_for_centroids = l2_normalize(np.array(embeddings, dtype=np.float32))
    sc_result = small_cluster_metrics(
        cluster_pred, norm_for_centroids, intents, signatures,
        merge_threshold=cfg.session.playbook_merge_threshold,
    )
    metrics.update(sc_result["metrics"])

    n_clusters = len({int(c) for c in cluster_pred if c >= 0})
    n_outliers = int(sum(1 for c in cluster_pred if c == -1))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "min_cluster_size": cfg.session.cluster_min_cluster_size,
            "min_samples":      cfg.session.cluster_min_samples,
            "scalar_weight":    cfg.session.cluster_scalar_weight,
            "playbook_merge_threshold": cfg.session.playbook_merge_threshold,
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
        "metrics":         metrics,
        "small_cluster": {
            "intent_available":    sc_result["intent_available"],
            "signature_available": sc_result["signature_available"],
            "detail":              sc_result["small_cluster_detail"],
        },
        "per_label":       _per_label_breakdown(session_ids, label_truth, cluster_pred),
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
    for k in ("ari", "nmi", "homogeneity", "completeness", "v_measure"):
        if k in report["metrics"]:
            out.append(f"  {k:14} {report['metrics'][k]:.4f}")
    out.append("")
    out.extend(render_small_cluster_block(report["metrics"], report.get("small_cluster", {})))
    out.append("")
    out.append("Per-label breakdown (analyst label → cluster grouping):")
    out.append(
        f"  {'label':35} {'n':>4} {'clusters':>9} {'fragmentation':>14} "
        f"{'lgst.share':>11} {'outlier.share':>14}"
    )
    for lbl, st in sorted(
        report["per_label"].items(),
        key=lambda kv: (-kv[1]["n_sessions"], kv[0]),
    ):
        out.append(
            f"  {lbl:35} {st['n_sessions']:>4} "
            f"{st['n_hdbscan_clusters_assigned']:>9} "
            f"{st['fragmentation_ratio']:>14.3f} "
            f"{st['largest_cluster_share']:>11.3f} "
            f"{st['outlier_share']:>14.3f}"
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
    out.append("DIAGNOSTIC — not gating. The partition metrics (ARI/NMI/homogeneity/")
    out.append("completeness/v_measure) measure a geometry off the shipped nearest-")
    out.append("prototype assign path; they print for a coarse sanity check but no")
    out.append("longer fail a build. The operational gate is scripts/eval_operational.py.")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", type=Path,
                    default=Path("eval/labels.yaml"),
                    help="v1 analyst-labeled YAML")
    ap.add_argument("--jsonl", type=Path,
                    default=Path("eval/sessions.unlabeled.jsonl"),
                    help="v1 unlabeled eval JSONL")
    ap.add_argument("--output-dir", type=Path,
                    default=Path("eval/results"),
                    help="Where to write the machine-readable JSON")
    ap.add_argument("--no-json", action="store_true",
                    help="Skip writing the JSON dump (stdout only)")
    ap.add_argument("--baseline", type=Path, default=None,
                    help=(
                        "Print a diagnostic delta vs this baseline. Post-Slice-A "
                        "the partition metrics no longer gate (always exits 0); "
                        "the gate is scripts/eval_operational.py."
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
    return 0  # partition metrics are diagnostic post-Slice-A; never fail the build


if __name__ == "__main__":
    sys.exit(main())
