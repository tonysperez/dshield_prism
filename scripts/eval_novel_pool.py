#!/usr/bin/env python
"""Explain corpus-wide assignment novelty with a read-only aggregate τ sweep.

The live path scans the explicitly-public, all-time session window once, then
replays the shared production assignment seam and production-equivalent
HDBSCAN -> noise rescue -> cluster-to-playbook merge for each τ. Output is
aggregate JSON only. It never writes to Elasticsearch or creates an artifact.

Pinned anchor centroids are aggregate but mixed-classification-derived. A live
run therefore requires the explicit ``--confirm-mixed-derived-anchors`` flag:

    console/.venv/bin/python scripts/eval_novel_pool.py \
      --confirm-mixed-derived-anchors
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.cluster import HDBSCAN

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Sibling-script import; path prepended above (precedent: diagnose_unminted_playbook.py).
from eval_assignment_faithful import _band_diagnosis

from enrich.classification import CLASSIFICATION_KEYWORD, PUBLIC, releasable_filter
from enrich.clustering import (
    compute_centroids,
    l2_normalize,
    rescue_noise_points,
    svd_reduce,
)
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.assign_runner import _load_anchors
from enrich.sources.cowrie.assignment import ASSIGNED, NOVEL, compute_assignment_window
from enrich.sources.cowrie.lexical import build_bag_texts, pull_hash_to_cluster
from enrich.sources.cowrie.sessions import (
    build_session_scalar_block,
    effective_novel_pool_min_cluster_size,
    merge_clusters_into_playbooks,
)

DEFAULT_TAUS = (0.88, 0.90, 0.92, 0.94, 0.96, 0.98)
_S = "dshield.cowrie.enrichment.session"
_EMB = f"{_S}.embedding"
_CMDSET = f"{_S}.command_set"
_PB = f"{_S}.playbook_id"
_SOURCE_FIELDS = [
    _EMB,
    _CMDSET,
    f"{_S}.command_count",
    f"{_S}.unique_commands",
    f"{_S}.login_success_count",
    f"{_S}.login_fail_count",
    f"{_S}.mean_novelty_score",
]


@dataclass(frozen=True)
class NovelPoolInputs:
    """Index-aligned in-memory inputs for the aggregate diagnostic."""

    embeddings: np.ndarray
    command_bags: list[str]
    scalars: list[dict]
    anchor_embeddings: np.ndarray
    anchor_ids: list[str]
    anchor_bags: list[str]
    anchor_bag_ids: list[str]
    command_taxonomy_size: int


def _session(src: dict) -> dict:
    return (
        ((src.get("dshield") or {}).get("cowrie") or {})
        .get("enrichment", {})
        .get("session", {})
    )


def _scan(es, index: str, filters: list[dict], fields: list[str], *, page_size: int = 2000):
    body: dict = {
        "size": page_size,
        "_source": fields,
        "query": {"bool": {"filter": filters}},
        "sort": [{"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after is not None:
            body["search_after"] = search_after
        response = es.search(index=index, **body)
        hits = response["hits"]["hits"]
        if not hits:
            return
        yield from hits
        search_after = hits[-1]["sort"]


def _extract_scalars(session: dict) -> dict:
    success = session.get("login_success_count") or 0
    fail = session.get("login_fail_count") or 0
    total = success + fail
    return {
        "command_count": session.get("command_count") or 1,
        "unique_commands": session.get("unique_commands") or 1,
        "login_success_rate": success / total if total > 0 else 0.0,
        "mean_novelty_score": session.get("mean_novelty_score") or 0.0,
    }


def load_public_inputs(es, cfg, *, per_anchor: int = 300) -> NovelPoolInputs:
    """Load one aligned public corpus plus public lexical samples for each anchor.

    The anchor-index read is the explicitly-confirmed mixed-derived input. Every
    query against cowrie session or command documents includes the exact
    fail-closed filter returned by ``releasable_filter(cfg)``.
    """
    if per_anchor <= 0:
        raise ValueError("per_anchor must be positive")
    indexes = cfg.elasticsearch.indexes.cowrie
    public = releasable_filter(cfg)
    explicit_public = {"term": {CLASSIFICATION_KEYWORD: PUBLIC}}
    # The diagnostic is stricter than a deployment's optional fail-open posture:
    # include the configured releasability clause, but always require an explicit
    # public tag as well.
    public_filters = [public] if public == explicit_public else [public, explicit_public]
    anchor_ids, anchor_embeddings, _anchor_predicate_signatures = _load_anchors(
        es, indexes.playbook_anchors,
    )
    if not anchor_ids:
        raise ValueError("no pinned production anchors found")

    embeddings: list[list[float]] = []
    command_sets: list[list[str]] = []
    scalars: list[dict] = []
    window_filter = [*public_filters, {"exists": {"field": _EMB}}]
    for hit in _scan(es, indexes.sessions_rollup, window_filter, _SOURCE_FIELDS):
        session = _session(hit["_source"])
        embedding = session.get("embedding")
        if not embedding:
            continue
        embeddings.append(embedding)
        command_sets.append(list(session.get("command_set") or []))
        scalars.append(_extract_scalars(session))
    if not embeddings:
        raise ValueError("no explicitly-public embedded sessions found")

    anchor_sets: list[list[str]] = []
    anchor_bag_ids: list[str] = []
    for anchor_id in anchor_ids:
        filters = [
            *public_filters,
            {"exists": {"field": _EMB}},
            {"term": {_PB: anchor_id}},
        ]
        for hit in _scan(
            es, indexes.sessions_rollup, filters, [_CMDSET], page_size=min(per_anchor, 2000),
        ):
            anchor_sets.append(list(_session(hit["_source"]).get("command_set") or []))
            anchor_bag_ids.append(anchor_id)
            if anchor_bag_ids.count(anchor_id) >= per_anchor:
                break

    # A public session's bag may only use command-cluster assignments read from
    # explicitly-public command documents. Untagged/confidential commands fail closed.
    hash_to_cluster = pull_hash_to_cluster(es, indexes.commands, filt=public_filters)
    if not hash_to_cluster:
        raise ValueError(
            "public command taxonomy is empty; refusing a degenerate lexical replay "
            "(classify/rebuild the command enrichment index before rerunning)",
        )
    all_bags = build_bag_texts(anchor_sets + command_sets, hash_to_cluster)
    n_anchor_bags = len(anchor_sets)
    matrix = np.asarray(embeddings, dtype=np.float32)
    anchor_matrix = np.asarray(anchor_embeddings, dtype=np.float32)
    if matrix.ndim != 2 or anchor_matrix.ndim != 2:
        raise ValueError("session and anchor embeddings must be two-dimensional")
    if not np.all(np.isfinite(matrix)) or not np.all(np.isfinite(anchor_matrix)):
        raise ValueError("session and anchor embeddings must contain only finite values")
    if matrix.shape[1] != anchor_matrix.shape[1]:
        raise ValueError(
            f"embedding dimension mismatch: sessions={matrix.shape[1]}, "
            f"anchors={anchor_matrix.shape[1]}",
        )
    return NovelPoolInputs(
        embeddings=l2_normalize(matrix),
        command_bags=all_bags[n_anchor_bags:],
        scalars=scalars,
        anchor_embeddings=anchor_matrix,
        anchor_ids=anchor_ids,
        anchor_bags=all_bags[:n_anchor_bags],
        anchor_bag_ids=anchor_bag_ids,
        command_taxonomy_size=len(hash_to_cluster),
    )


def validate_taus(
    values: Iterable[float], *, deployed_tau: float, confident_tau: float,
) -> tuple[float, ...]:
    if not math.isfinite(deployed_tau) or not math.isfinite(confident_tau):
        raise ValueError("deployed and confident τ values must be finite")
    if not 0.0 <= deployed_tau <= confident_tau <= 1.0:
        raise ValueError("deployed/confident τ must satisfy 0 <= deployed <= confident <= 1")
    taus = tuple(float(value) for value in values)
    if not taus:
        raise ValueError("τ grid must not be empty")
    if any(not math.isfinite(value) for value in taus):
        raise ValueError("τ values must be finite")
    if len(set(taus)) != len(taus):
        raise ValueError("τ grid contains duplicate values")
    if any(value < 0.0 or value > confident_tau for value in taus):
        raise ValueError(f"τ values must be within [0, confident_tau={confident_tau}]")
    if not any(math.isclose(value, deployed_tau, abs_tol=1e-12) for value in taus):
        raise ValueError(f"τ grid must include deployed assignment_tau={deployed_tau}")
    return tuple(sorted(taus))


def _distribution(labels: np.ndarray, *, n_total: int) -> dict:
    sizes = sorted(Counter(int(label) for label in labels if int(label) >= 0).values())
    if not sizes:
        return {
            "largest_share": 0.0,
            "top5_share": 0.0,
            "median_size": None,
            "p90_size": None,
        }
    return {
        "largest_share": round(max(sizes) / n_total, 4),
        "top5_share": round(sum(sorted(sizes, reverse=True)[:5]) / n_total, 4),
        "median_size": round(float(np.median(sizes)), 1),
        "p90_size": round(float(np.percentile(sizes, 90)), 1),
    }


def cluster_novel_pool(
    embeddings: np.ndarray,
    scalars: list[dict],
    *,
    min_cluster_size: int,
    min_samples: int,
    scalar_weight: float,
    rescue_threshold: float,
    merge_threshold: float,
    svd_dim: int,
    n_jobs: int,
) -> dict:
    """Run the production session-clustering math and return aggregate shape only."""
    if min_cluster_size < 2:
        raise ValueError("cluster_min_cluster_size must be at least 2")
    if min_samples < 1:
        raise ValueError("cluster_min_samples must be at least 1")
    if not math.isfinite(scalar_weight) or scalar_weight < 0.0:
        raise ValueError("cluster_scalar_weight must be finite and non-negative")
    if (
        not math.isfinite(rescue_threshold)
        or not math.isfinite(merge_threshold)
        or not 0.0 <= rescue_threshold <= 1.0
        or not 0.0 <= merge_threshold <= 1.0
    ):
        raise ValueError("rescue and merge thresholds must be finite and within [0, 1]")
    if svd_dim < 0:
        raise ValueError("cluster_svd_dim must be non-negative")
    if n_jobs == 0:
        raise ValueError("cluster_n_jobs must not be zero")
    matrix = np.asarray(embeddings, dtype=np.float32)
    if matrix.ndim != 2 or matrix.shape[1] == 0:
        raise ValueError("novel-pool embeddings must be a non-empty-width 2-D matrix")
    if not np.all(np.isfinite(matrix)):
        raise ValueError("novel-pool embeddings contain non-finite values")
    if len(scalars) != matrix.shape[0]:
        raise ValueError("novel-pool embeddings and clustering scalars are not aligned")
    n_total = int(matrix.shape[0])
    if n_total < min_cluster_size:
        return {
            "status": "skipped_too_few",
            "raw_clusters": 0,
            "raw_outliers": 0,
            "rescued": 0,
            "residual_outliers": 0,
            "residual_outlier_rate": None,
            "playbook_groups": 0,
            "effective_groups_per_1000": 0.0,
            **_distribution(np.asarray([], dtype=np.int64), n_total=max(n_total, 1)),
        }

    normalized = l2_normalize(matrix)
    scalar_block = (
        build_session_scalar_block(scalars, scalar_weight) if scalar_weight > 0.0 else None
    )
    cluster_matrix = (
        np.hstack([normalized, scalar_block]) if scalar_block is not None else normalized
    )
    reduced, _ = svd_reduce(normalized, svd_dim)
    fit_matrix = (
        np.hstack([reduced, scalar_block])
        if scalar_block is not None and reduced.shape[1] < normalized.shape[1]
        else (reduced if reduced.shape[1] < normalized.shape[1] else cluster_matrix)
    )
    raw_labels = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
        n_jobs=n_jobs,
    ).fit_predict(fit_matrix)
    raw_clusters = len({int(label) for label in raw_labels if int(label) >= 0})
    raw_outliers = int(np.sum(raw_labels == -1))

    labels = np.asarray(raw_labels, dtype=np.int64)
    rescued = 0
    if rescue_threshold > 0.0:
        labels, rescued = rescue_noise_points(normalized, labels, rescue_threshold)
    residual_outliers = int(np.sum(labels == -1))

    centroids = compute_centroids(normalized, labels)
    groups = merge_clusters_into_playbooks(
        {str(label): centroid.tolist() for label, centroid in centroids.items()},
        merge_threshold,
    )
    group_to_int: dict[str, int] = {}
    merged = np.full_like(labels, -1)
    for i, label in enumerate(labels):
        if int(label) < 0:
            continue
        group = groups[str(int(label))]
        group_to_int.setdefault(group, len(group_to_int))
        merged[i] = group_to_int[group]
    n_groups = len(group_to_int)
    return {
        "status": "clustered",
        "raw_clusters": raw_clusters,
        "raw_outliers": raw_outliers,
        "rescued": int(rescued),
        "residual_outliers": residual_outliers,
        "residual_outlier_rate": round(residual_outliers / n_total, 4),
        "playbook_groups": n_groups,
        "effective_groups_per_1000": round(n_groups * 1000.0 / n_total, 2),
        **_distribution(merged, n_total=n_total),
    }


def _band_separation(band_trace: list[dict]) -> dict:
    """Bucket a deployed-τ `band_trace` (item 34) by `confirmed` and reuse
    `eval_assignment_faithful._band_diagnosis` for each bucket's distribution + sweep
    math, so the confirmed/rejected split cannot drift from that reference
    implementation. `_band_diagnosis` already handles an empty bucket (`n: 0`).
    """
    confirmed = [row for row in band_trace if row["confirmed"]]
    rejected = [row for row in band_trace if not row["confirmed"]]
    return {
        "overall": _band_diagnosis(band_trace),
        "confirmed": _band_diagnosis(confirmed),
        "rejected": _band_diagnosis(rejected),
    }


def analyze(inputs: NovelPoolInputs, cfg, taus: Iterable[float]) -> dict:
    """Replay assignment and clustering over one fixed aligned corpus."""
    session_cfg = cfg.session
    if session_cfg.clustering_mode != "hdbscan":
        raise ValueError(
            "exact production-equivalence requires session.clustering_mode='hdbscan'",
        )
    deployed_tau = float(session_cfg.assignment_tau)
    confident_tau = float(session_cfg.assignment_confident_tau)
    tfidf_tau = float(session_cfg.assignment_tfidf_tau)
    rescue_tau = float(getattr(session_cfg, "assignment_rescue_tau", deployed_tau))
    if not math.isfinite(tfidf_tau) or not 0.0 <= tfidf_tau <= 1.0:
        raise ValueError("session.assignment_tfidf_tau must be finite and within [0, 1]")
    if not math.isfinite(rescue_tau):
        raise ValueError("session.assignment_rescue_tau must be finite")
    if not math.isclose(rescue_tau, deployed_tau, abs_tol=1e-12):
        raise ValueError(
            "exact assignment replay requires the structural rescue tier to be disabled "
            "(session.assignment_rescue_tau must equal session.assignment_tau)",
        )
    tau_grid = validate_taus(
        taus, deployed_tau=deployed_tau, confident_tau=confident_tau,
    )
    embeddings = np.asarray(inputs.embeddings, dtype=np.float32)
    anchor_embeddings = np.asarray(inputs.anchor_embeddings, dtype=np.float32)
    if embeddings.ndim != 2 or anchor_embeddings.ndim != 2:
        raise ValueError("session and anchor embeddings must be two-dimensional")
    if embeddings.shape[0] == 0 or embeddings.shape[1] == 0:
        raise ValueError("the fixed session corpus is empty or has zero-width embeddings")
    if anchor_embeddings.shape[0] == 0 or anchor_embeddings.shape[1] == 0:
        raise ValueError("the pinned anchor geometry is empty or zero-width")
    if embeddings.shape[1] != anchor_embeddings.shape[1]:
        raise ValueError(
            f"embedding dimension mismatch: sessions={embeddings.shape[1]}, "
            f"anchors={anchor_embeddings.shape[1]}",
        )
    if not np.all(np.isfinite(embeddings)) or not np.all(np.isfinite(anchor_embeddings)):
        raise ValueError("session and anchor embeddings must contain only finite values")
    n_total = int(embeddings.shape[0])
    if len(inputs.command_bags) != n_total or len(inputs.scalars) != n_total:
        raise ValueError("embeddings, command bags, and clustering scalars are not aligned")
    if not inputs.anchor_ids or anchor_embeddings.shape[0] != len(inputs.anchor_ids):
        raise ValueError("anchor ids and embeddings are empty or not aligned")
    if len(set(inputs.anchor_ids)) != len(inputs.anchor_ids):
        raise ValueError("anchor ids must be unique")
    if len(inputs.anchor_bags) != len(inputs.anchor_bag_ids):
        raise ValueError("anchor bags and anchor bag ids are not aligned")
    known_anchor_ids = set(inputs.anchor_ids)
    if any(anchor_id not in known_anchor_ids for anchor_id in inputs.anchor_bag_ids):
        raise ValueError("anchor bag ids contain an id outside the pinned anchor library")

    rows: list[dict] = []
    novel_pool_min_cluster_size = effective_novel_pool_min_cluster_size(
        session_cfg,
        novel_pool_only=True,
    )
    previous_assigned = n_total + 1
    for tau in tau_grid:
        is_deployed = math.isclose(tau, deployed_tau, abs_tol=1e-12)
        # Capture band_trace (item 34 plumbing) only at the deployed-τ row -- a
        # corpus-scale reproduction of Finding 46 at the shipped operating point,
        # not a new τ×tfidf_tau sweep dimension.
        band_trace: list[dict] | None = [] if is_deployed else None
        result = compute_assignment_window(
            embeddings,
            anchor_embeddings,
            inputs.anchor_ids,
            inputs.anchor_bags,
            inputs.anchor_bag_ids,
            inputs.command_bags,
            tau=tau,
            confident_tau=confident_tau,
            tfidf_tau=tfidf_tau,
            # Keep the declined structural-rescue feature disabled throughout
            # the counterfactual sweep. Its production no-op is rescue_tau ==
            # assignment_tau, so the equivalent value for each swept row is
            # that row's tau rather than the deployed scalar.
            rescue_tau=tau,
            band_trace=band_trace,
        )
        assignments = result.assignments
        assigned = sum(assignment.status == ASSIGNED for assignment in assignments)
        novel_mask = np.asarray(
            [assignment.status == NOVEL for assignment in assignments], dtype=bool,
        )
        novel = int(novel_mask.sum())
        if assigned + novel != n_total:
            raise RuntimeError("assignment counts do not sum to the fixed corpus")
        if assigned > previous_assigned:
            raise RuntimeError("assigned count increased as τ increased; sweep is inconsistent")
        previous_assigned = assigned
        # Consume the shared seam's durable counters rather than reconstructing
        # them from diagnostic trace rows. These counters include every cascade
        # check/rejection and are the same accounting production returns.
        checks = sum(assignment.band_checks for assignment in assignments)
        confirms = sum(bool(assignment.confirmed_in_band) for assignment in assignments)
        rejections = sum(assignment.band_rejections for assignment in assignments)
        tfidf_confirms = checks - rejections
        embedding_fallbacks = confirms - tfidf_confirms
        if tfidf_confirms < 0 or embedding_fallbacks < 0:
            raise RuntimeError(
                "assignment band counters are internally inconsistent "
                f"(checks={checks}, confirms={confirms}, rejections={rejections})",
            )
        shape = cluster_novel_pool(
            embeddings[novel_mask],
            [scalar for scalar, keep in zip(inputs.scalars, novel_mask, strict=False) if keep],
            min_cluster_size=novel_pool_min_cluster_size,
            min_samples=int(session_cfg.cluster_min_samples),
            scalar_weight=float(session_cfg.cluster_scalar_weight),
            rescue_threshold=float(session_cfg.playbook_merge_threshold),
            merge_threshold=float(session_cfg.playbook_merge_threshold),
            svd_dim=int(session_cfg.cluster_svd_dim),
            n_jobs=int(cfg.worker.cluster_n_jobs),
        )
        rows.append({
            "tau": tau,
            "deployed": is_deployed,
            "assigned": assigned,
            "assigned_rate": round(assigned / n_total, 4),
            "novel": novel,
            "novel_rate": round(novel / n_total, 4),
            "band_checks": checks,
            "band_confirms": confirms,
            "band_tfidf_confirms": tfidf_confirms,
            "band_no_tfidf_fallbacks": embedding_fallbacks,
            "band_rejections": rejections,
            "band_tfidf_diagnosis": (
                _band_separation(band_trace) if band_trace is not None else None
            ),
            "tfidf_available": result.tfidf_available,
            "novel_pool_shape": shape,
        })

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "read_only": True,
        "session_classification": "public_only",
        "command_taxonomy_classification": "public_only",
        "anchor_provenance": "pinned_mixed_classification_derived_aggregates",
        "n_sessions": n_total,
        "n_anchors": len(inputs.anchor_ids),
        "n_public_anchor_bags": len(inputs.anchor_bags),
        "n_public_command_taxonomy_docs": inputs.command_taxonomy_size,
        "effective_config": {
            "clustering_mode": session_cfg.clustering_mode,
            "assignment_tau": deployed_tau,
            "assignment_confident_tau": confident_tau,
            "assignment_tfidf_tau": tfidf_tau,
            "assignment_rescue_tau": rescue_tau,
            "cluster_min_cluster_size": int(session_cfg.cluster_min_cluster_size),
            "novel_pool_cluster_min_cluster_size": (
                None
                if getattr(session_cfg, "novel_pool_cluster_min_cluster_size", None) in (None, 0)
                else int(session_cfg.novel_pool_cluster_min_cluster_size)
            ),
            "effective_novel_pool_cluster_min_cluster_size": novel_pool_min_cluster_size,
            "cluster_min_samples": int(session_cfg.cluster_min_samples),
            "cluster_scalar_weight": float(session_cfg.cluster_scalar_weight),
            "cluster_svd_dim": int(session_cfg.cluster_svd_dim),
            "cluster_n_jobs": int(cfg.worker.cluster_n_jobs),
            "noise_rescue_threshold": float(session_cfg.playbook_merge_threshold),
            "playbook_merge_threshold": float(session_cfg.playbook_merge_threshold),
        },
        "rows": rows,
    }


def _parse_taus(raw: str) -> tuple[float, ...]:
    try:
        return tuple(float(part.strip()) for part in raw.split(",") if part.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("τ grid must be comma-separated numbers") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None)
    parser.add_argument("--taus", type=_parse_taus, default=DEFAULT_TAUS)
    parser.add_argument("--per-anchor", type=int, default=300)
    parser.add_argument(
        "--confirm-mixed-derived-anchors",
        action="store_true",
        help="confirm local read-only use of mixed-classification-derived pinned anchors",
    )
    args = parser.parse_args()
    if not args.confirm_mixed_derived_anchors:
        parser.error(
            "live execution requires operator confirmation: "
            "--confirm-mixed-derived-anchors",
        )

    try:
        cfg = load_config(args.config)
        es = make_client(cfg.elasticsearch, load_secrets(args.config))
        inputs = load_public_inputs(es, cfg, per_anchor=args.per_anchor)
        report = analyze(inputs, cfg, args.taus)
    except (RuntimeError, ValueError) as exc:
        print(f"eval_novel_pool: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
