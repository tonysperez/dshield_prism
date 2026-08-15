#!/usr/bin/env python
"""Item 68 recheck — do the 4 anchor-coverage-gap labels still starve/conflate?

Finding 50 found real-anchor macro-F1 capped at 0.41 because 4 of 10 labels have no
anchor that represents them: `account_backdoor_persistence`, `inband_payload_drop`
and `scp_upload` were all HDBSCAN outliers in the novel pool (cause a, "outlier
starvation"); `iot_cli_probe` was assigned but conflated onto the wrong anchor's
modal label (cause b). The leading hypothesis for cause (a) was that a dominant
campaign crowded the rare tail out of the novel pool at `cluster_min_cluster_size=5`.

Finding 51 then shipped item 62 (`assignment_tfidf_tau` 0.80 -> 0.50), which shrank
the novel pool 2,535 -> 77 sessions -- making the hypothesis directly testable and
possibly moot. This script answers that follow-up: replay the live assignment
window at the deployed thresholds, then for each of the 4 target labels report
whether it is still an HDBSCAN outlier in *today's* novel pool (cause a) or, if
assigned, whether its anchor's labelled majority still disagrees with it (cause b).

Read-only and aggregate-only, same posture as items 56/61/65: counts, cosines,
cluster shape and `spb-` anchor ids only -- no `cowrie.session_id`, IP or command
text is ever emitted, and nothing is written to Elasticsearch. Reuses the case's
established reference implementations (`compute_assignment_window`,
`pool_group_labels`, `cluster_novel_pool`, `_anchor_majority_labels`,
`join_labels_to_window`) instead of re-deriving their math, so this script's
verdict cannot silently drift from `eval_novel_pool.py` / `eval_band_labelled.py` /
`diagnose_unminted_playbook.py`.

Pinned anchor centroids are aggregate but mixed-classification-derived, so a live
run needs explicit operator confirmation:

    console/.venv/bin/python scripts/diagnose_anchor_coverage_gap.py \
      --confirm-mixed-derived-anchors
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Sibling-script imports; path prepended above (precedent: diagnose_unminted_playbook.py
# importing from eval_novel_pool, and eval_novel_pool importing from eval_assignment_faithful).
from diagnose_unminted_playbook import pool_group_labels
from eval_band_labelled import (
    _anchor_majority_labels,
    join_labels_to_window,
    load_scorable_labels,
)
from eval_novel_pool import (
    _CMDSET,
    _EMB,
    _PB,
    _SOURCE_FIELDS,
    _extract_scalars,
    _scan,
    _session,
    cluster_novel_pool,
    effective_novel_pool_min_cluster_size,
)

from enrich.classification import CLASSIFICATION_KEYWORD, PUBLIC, releasable_filter
from enrich.clustering import l2_normalize
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.assign_runner import _load_anchors
from enrich.sources.cowrie.assignment import ASSIGNED, NOVEL, compute_assignment_window
from enrich.sources.cowrie.lexical import build_bag_texts, pull_hash_to_cluster

TARGET_LABELS = (
    "account_backdoor_persistence",
    "inband_payload_drop",
    "iot_cli_probe",
    "scp_upload",
)
_SID_FIELD = "cowrie.session_id"
_WINDOW_SOURCE_FIELDS = [_SID_FIELD, *_SOURCE_FIELDS]


@dataclass(frozen=True)
class AnchorCoverageInputs:
    """Index-aligned in-memory inputs for the recheck -- the public window's
    embeddings/command bags/session ids/clustering scalars, plus the anchor
    library's embeddings and public lexical bags."""

    embeddings: np.ndarray
    command_bags: list[str]
    scalars: list[dict]
    session_ids: list[str]
    anchor_embeddings: np.ndarray
    anchor_ids: list[str]
    anchor_bags: list[str]
    anchor_bag_ids: list[str]
    command_taxonomy_size: int


def load_inputs(es, cfg, *, per_anchor: int = 300) -> AnchorCoverageInputs:
    """One aligned scan of the public session window (embedding, command_set,
    session_id, clustering scalars) plus the pinned anchor library and its public
    per-anchor lexical sample. Mirrors `eval_band_labelled.load_inputs`, extended
    with `scalars` (via `eval_novel_pool._extract_scalars`) because `pool_group_labels`
    / `cluster_novel_pool` need the clustering scalar block that `eval_band_labelled`
    itself never uses.
    """
    if per_anchor <= 0:
        raise ValueError("per_anchor must be positive")
    indexes = cfg.elasticsearch.indexes.cowrie
    public = releasable_filter(cfg)
    explicit_public = {"term": {CLASSIFICATION_KEYWORD: PUBLIC}}
    public_filters = [public] if public == explicit_public else [public, explicit_public]
    anchor_ids, anchor_embeddings, _anchor_predicate_signatures = _load_anchors(
        es, indexes.playbook_anchors,
    )
    if not anchor_ids:
        raise ValueError("no pinned production anchors found")

    session_ids: list[str] = []
    embeddings: list[list[float]] = []
    command_sets: list[list[str]] = []
    scalars: list[dict] = []
    window_filter = [*public_filters, {"exists": {"field": _EMB}}]
    for hit in _scan(es, indexes.sessions_rollup, window_filter, _WINDOW_SOURCE_FIELDS):
        session = _session(hit["_source"])
        embedding = session.get("embedding")
        if not embedding:
            continue
        # `cowrie.session_id` is a TOP-LEVEL field on the rollup doc (NOT nested under
        # dshield.cowrie.enrichment.session) -- the label join must key off this field.
        sid = (hit["_source"].get("cowrie") or {}).get("session_id")
        session_ids.append(str(sid) if sid else "")
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
    return AnchorCoverageInputs(
        embeddings=l2_normalize(matrix),
        command_bags=all_bags[n_anchor_bags:],
        scalars=scalars,
        session_ids=session_ids,
        anchor_embeddings=anchor_matrix,
        anchor_ids=anchor_ids,
        anchor_bags=all_bags[:n_anchor_bags],
        anchor_bag_ids=anchor_bag_ids,
        command_taxonomy_size=len(hash_to_cluster),
    )


def _target_label_report(
    label: str,
    indices: list[int],
    assignments: list,
    leave_one_out_majority: dict[int, str | None],
    outlier_status: dict[int, tuple[bool, int]],
) -> dict:
    """One target label's aggregate verdict. `leave_one_out_majority` maps an
    assigned-status window index to the majority label among every OTHER labelled
    row assigned to the same anchor (`None` if no other labelled row is assigned
    there). `outlier_status` maps a novel-status window index to
    (still_outlier, group_size) -- group_size is 0 for an outlier."""
    assigned_detail = {"conflated": 0, "matches_majority": 0, "anchor_unknown": 0}
    novel_detail = {"still_outlier": 0, "now_clustered": 0, "clustered_group_sizes": []}
    status_counts = {"assigned": 0, "novel": 0}
    for i in indices:
        assignment = assignments[i]
        if assignment.status == ASSIGNED:
            status_counts["assigned"] += 1
            majority = leave_one_out_majority[i]
            if majority is None:
                assigned_detail["anchor_unknown"] += 1
            elif majority == label:
                assigned_detail["matches_majority"] += 1
            else:
                assigned_detail["conflated"] += 1
        else:
            status_counts["novel"] += 1
            still_outlier, group_size = outlier_status[i]
            if still_outlier:
                novel_detail["still_outlier"] += 1
            else:
                novel_detail["now_clustered"] += 1
                novel_detail["clustered_group_sizes"].append(group_size)
    return {
        "n_labelled": len(indices),
        "status_counts": status_counts,
        "assigned_detail": assigned_detail,
        "novel_detail": novel_detail,
    }


def analyze(es, cfg, labels_path: Path, *, per_anchor: int = 300) -> dict:
    labels = load_scorable_labels(labels_path)
    inputs = load_inputs(es, cfg, per_anchor=per_anchor)
    resolved, unresolved_reasons = join_labels_to_window(inputs.session_ids, labels)

    scfg = cfg.session
    result = compute_assignment_window(
        inputs.embeddings, inputs.anchor_embeddings, inputs.anchor_ids,
        inputs.anchor_bags, inputs.anchor_bag_ids, inputs.command_bags,
        tau=float(scfg.assignment_tau),
        confident_tau=float(scfg.assignment_confident_tau),
        tfidf_tau=float(scfg.assignment_tfidf_tau),
        rescue_tau=float(scfg.assignment_rescue_tau),
    )
    assignments = result.assignments

    assigned_rows_by_index = {
        i: {"predicted_playbook_id": assignments[i].playbook_id, "true_label": label}
        for i, label in resolved.items()
        if assignments[i].status == ASSIGNED
    }
    # Leave-one-out per target row: a gap label's own vote must not count toward its
    # own anchor's majority, or it would trivially "match" an anchor with zero
    # independent support and `anchor_unknown` could never fire. Excluding only the
    # row under test (not every target-label vote) still lets genuine same-label
    # consensus from a *different* labelled session at the same anchor register as
    # `matches_majority` -- the majority an anchor's *other* labelled members give it
    # is the independent signal Finding 50's "no anchor's modal label matches them"
    # actually measures.
    leave_one_out_majority: dict[int, str | None] = {}
    for i, label in resolved.items():
        if assignments[i].status != ASSIGNED or label not in TARGET_LABELS:
            continue
        loo_rows = [row for j, row in assigned_rows_by_index.items() if j != i]
        leave_one_out_majority[i] = _anchor_majority_labels(loo_rows).get(
            assignments[i].playbook_id,
        )

    novel_mask = np.asarray([a.status == NOVEL for a in assignments], dtype=bool)
    novel_idx = np.flatnonzero(novel_mask)
    merge_threshold = float(scfg.playbook_merge_threshold)
    novel_pool_min_cluster_size = effective_novel_pool_min_cluster_size(
        scfg,
        novel_pool_only=True,
    )
    cluster_kwargs = {
        "min_cluster_size": novel_pool_min_cluster_size,
        "min_samples": int(scfg.cluster_min_samples),
        "scalar_weight": float(scfg.cluster_scalar_weight),
        "rescue_threshold": merge_threshold,
        "merge_threshold": merge_threshold,
        "svd_dim": int(scfg.cluster_svd_dim),
        "n_jobs": int(cfg.worker.cluster_n_jobs),
    }
    novel_pool_shape: dict = {"status": "no_novel_pool"}
    outlier_status: dict[int, tuple[bool, int]] = {}
    if novel_idx.size > 0:
        novel_embeddings = inputs.embeddings[novel_mask]
        novel_scalars = [s for s, keep in zip(inputs.scalars, novel_mask, strict=False) if keep]
        # `cluster_novel_pool` first: it validates every clustering parameter, and
        # `pool_group_labels` (which cannot, being label-producing rather than
        # aggregate) would otherwise run a full HDBSCAN fit on invalid config first.
        novel_pool_shape = cluster_novel_pool(novel_embeddings, novel_scalars, **cluster_kwargs)
        pool_labels = pool_group_labels(novel_embeddings, novel_scalars, **cluster_kwargs)
        sizes = Counter(int(x) for x in pool_labels if int(x) >= 0)
        largest_share = round(max(sizes.values()) / len(pool_labels), 4) if sizes else 0.0
        if (novel_pool_shape.get("playbook_groups") != len(sizes)
                or abs(float(novel_pool_shape.get("largest_share") or 0.0) - largest_share) > 1e-4):
            raise RuntimeError(
                "labelled pool clustering diverged from eval_novel_pool.cluster_novel_pool "
                f"(groups {len(sizes)} vs {novel_pool_shape.get('playbook_groups')}, "
                f"largest_share {largest_share} vs {novel_pool_shape.get('largest_share')})",
            )
        for position, window_index in enumerate(novel_idx):
            group = int(pool_labels[position])
            outlier_status[int(window_index)] = (
                (group < 0, 0) if group < 0 else (False, sizes[group])
            )

    by_label = {}
    for label in TARGET_LABELS:
        indices = [i for i, resolved_label in resolved.items() if resolved_label == label]
        by_label[label] = _target_label_report(
            label, indices, assignments, leave_one_out_majority, outlier_status,
        )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "read_only": True,
        "session_classification": "public_only",
        "anchor_provenance": "pinned_mixed_classification_derived_aggregates",
        "assignment_tau": float(scfg.assignment_tau),
        "assignment_confident_tau": float(scfg.assignment_confident_tau),
        "assignment_tfidf_tau": float(scfg.assignment_tfidf_tau),
        "cluster_min_cluster_size": int(scfg.cluster_min_cluster_size),
        "novel_pool_cluster_min_cluster_size": (
            None
            if getattr(scfg, "novel_pool_cluster_min_cluster_size", None) in (None, 0)
            else int(scfg.novel_pool_cluster_min_cluster_size)
        ),
        "effective_novel_pool_cluster_min_cluster_size": novel_pool_min_cluster_size,
        "n_sessions": int(inputs.embeddings.shape[0]),
        "n_anchors": len(inputs.anchor_ids),
        "novel": int(novel_idx.size),
        "unresolved_label_join_reasons": unresolved_reasons,
        "novel_pool_shape": novel_pool_shape,
        "by_label": by_label,
    }


def summarize(report: dict) -> str:
    lines = [
        (f"sessions={report.get('n_sessions', 0)} anchors={report.get('n_anchors', 0)} "
         f"novel={report.get('novel', 0)} "
         f"(tau={report.get('assignment_tau')}, tfidf_tau={report.get('assignment_tfidf_tau')})"),
    ]
    for label, detail in report.get("by_label", {}).items():
        lines.append(f"  {label}: n={detail['n_labelled']} status={detail['status_counts']}")
        lines.append(f"    assigned={detail['assigned_detail']}")
        lines.append(f"    novel={detail['novel_detail']}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None)
    parser.add_argument("--labels", default="eval/labels.yaml")
    parser.add_argument("--per-anchor", type=int, default=300)
    parser.add_argument("--json", action="store_true", help="emit the full JSON report")
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
        report = analyze(es, cfg, Path(args.labels), per_anchor=args.per_anchor)
    except (RuntimeError, ValueError) as exc:
        print(f"diagnose_anchor_coverage_gap: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        print(summarize(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
