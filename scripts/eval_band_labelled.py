#!/usr/bin/env python
"""Labelled-corpus-scale band check (item 65) — does the TF-IDF band confirm/reject
survive scale, and what does lowering `assignment_tfidf_tau` into Finding 47's 0.2-0.7
valley (item 62) actually do to labelled sessions?

No existing evaluator answers this: `eval_assignment_prod`/`eval_operational` never
exercise the band (`assign_batch` runs with no `tfidf_cos`); `eval_assignment_faithful
--anchors` exercises it but its fixture yields 9 band checks against the corpus's
8,825; `eval_novel_pool` exercises the band at corpus scale but carries no analyst
labels.

This scans the live public session window once, joins it against the 160 labelled
sessions in `eval/labels.yaml` by `cowrie.session_id`, and replays the shared
`compute_assignment_window`/`assign_batch` seam at three `tfidf_tau` arms — 0.80
(deployed), 0.50 (Finding 47's valley), band-disabled — scoring only labelled rows for
anchor-label purity, per-label accuracy, and bootstrapped macro-F1, side by side. Output
is aggregate JSON only: no per-session identifier is ever included. It never writes to
Elasticsearch or creates an artifact.

Pinned anchor centroids are aggregate but mixed-classification-derived (same posture as
`eval_novel_pool.py`). A live run therefore requires the explicit
``--confirm-mixed-derived-anchors`` flag:

    console/.venv/bin/python scripts/eval_band_labelled.py \
      --confirm-mixed-derived-anchors
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eval_assignment_faithful import (
    BOOTSTRAPS,
    SEED,
    _bootstrap_rows,
    _interval,
    _macro_f1,
    _measure,
)

# Sibling-script imports; path prepended above (precedent: eval_novel_pool.py itself
# importing from eval_assignment_faithful, and diagnose_unminted_playbook.py). Reusing
# these rather than re-deriving them means this script's window scan, band-diagnosis
# math, and bootstrap machinery cannot silently drift from the reference scripts'.
from eval_novel_pool import (
    _CMDSET,
    _EMB,
    _PB,
    _SOURCE_FIELDS,
    _band_separation,
    _scan,
    _session,
)
from validate_eval_labels import KNOWN_PLAYBOOK_LABELS

from enrich.classification import CLASSIFICATION_KEYWORD, PUBLIC, releasable_filter
from enrich.clustering import l2_normalize
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.assign_runner import _load_anchors
from enrich.sources.cowrie.assignment import (
    ASSIGNED,
    NOVEL,
    assign_batch,
    compute_assignment_window,
)
from enrich.sources.cowrie.lexical import build_bag_texts, pull_hash_to_cluster

VALLEY_TFIDF_TAU = 0.50  # Finding 47's 0.2-0.7 valley
_SID_FIELD = "cowrie.session_id"
WINDOW_SOURCE_FIELDS = [_SID_FIELD, *_SOURCE_FIELDS]
TARGET_TRACE_LABEL = "inband_payload_drop"


@dataclass(frozen=True)
class BandLabelledInputs:
    """Index-aligned in-memory inputs shared by all three tfidf_tau arms."""

    embeddings: np.ndarray
    command_bags: list[str]
    session_ids: list[str]
    anchor_embeddings: np.ndarray
    anchor_ids: list[str]
    anchor_bags: list[str]
    anchor_bag_ids: list[str]
    command_taxonomy_size: int


def load_scorable_labels(labels_path: Path) -> dict[str, str]:
    """{session_id: playbook_label} for every `eval/labels.yaml` row that is
    `annotated`, not `is_real: false`, carries a `playbook_label`, and that label is a
    member of `KNOWN_PLAYBOOK_LABELS` — mirrors `eval_assignment.load_records_detailed`'s
    `scorable_blocks`/`label_blocks`/`invalid_membership` filter chain exactly, so this
    script's population can never silently drift from the assignment eval gate's (a
    stale/typo'd label is excluded here exactly as it would be excluded there, rather
    than silently entering `true_label` and corrupting purity/macro-F1)."""
    try:
        raw = yaml.safe_load(labels_path.read_text()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"could not read labels file {labels_path}: {exc}") from exc
    annotated_blocks = {
        str(sid): block for sid, block in raw.items()
        if isinstance(block, dict) and block.get("annotated")
    }
    non_real = {
        sid for sid, block in annotated_blocks.items() if block.get("is_real") is False
    }
    scorable_blocks = {
        sid: block for sid, block in annotated_blocks.items() if sid not in non_real
    }
    return {
        sid: str(block["playbook_label"])
        for sid, block in scorable_blocks.items()
        if block.get("playbook_label") in KNOWN_PLAYBOOK_LABELS
    }


def load_inputs(es, cfg, *, per_anchor: int = 300) -> BandLabelledInputs:
    """Scan the public session window once (`cowrie.session_id`, `embedding`,
    `command_set`), load the pinned anchors, and sample a per-anchor public lexical
    bag — the shared corpus every tfidf_tau arm replays against.

    The anchor-index read is the explicitly-confirmed mixed-derived input. Every query
    against cowrie session or command documents includes the exact fail-closed filter
    returned by `releasable_filter(cfg)` (CLAUDE.md's privacy rule).
    """
    if per_anchor <= 0:
        raise ValueError("per_anchor must be positive")
    indexes = cfg.elasticsearch.indexes.cowrie
    public = releasable_filter(cfg)
    explicit_public = {"term": {CLASSIFICATION_KEYWORD: PUBLIC}}
    # Stricter than a deployment's optional fail-open posture: include the configured
    # releasability clause, but always require an explicit public tag as well.
    public_filters = [public] if public == explicit_public else [public, explicit_public]
    anchor_ids, anchor_embeddings, _anchor_predicate_signatures = _load_anchors(
        es, indexes.playbook_anchors,
    )
    if not anchor_ids:
        raise ValueError("no pinned production anchors found")

    session_ids: list[str] = []
    embeddings: list[list[float]] = []
    command_sets: list[list[str]] = []
    window_filter = [*public_filters, {"exists": {"field": _EMB}}]
    for hit in _scan(es, indexes.sessions_rollup, window_filter, WINDOW_SOURCE_FIELDS):
        session = _session(hit["_source"])
        embedding = session.get("embedding")
        if not embedding:
            continue
        # `cowrie.session_id` is a TOP-LEVEL field on the rollup doc (NOT nested under
        # dshield.cowrie.enrichment.session) -- the label join must key off this field,
        # never off the rollup `_id` (see sessions.py's namespacing comment: the `_id`
        # is `<sensor>:<session_id>`, reads go by the field).
        sid = (hit["_source"].get("cowrie") or {}).get("session_id")
        session_ids.append(str(sid) if sid else "")
        embeddings.append(embedding)
        command_sets.append(list(session.get("command_set") or []))
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
    return BandLabelledInputs(
        embeddings=l2_normalize(matrix),
        command_bags=all_bags[n_anchor_bags:],
        session_ids=session_ids,
        anchor_embeddings=anchor_matrix,
        anchor_ids=anchor_ids,
        anchor_bags=all_bags[:n_anchor_bags],
        anchor_bag_ids=anchor_bag_ids,
        command_taxonomy_size=len(hash_to_cluster),
    )


def join_labels_to_window(
    session_ids: list[str], labels: dict[str, str],
) -> tuple[dict[int, str], dict[str, int]]:
    """Resolve each scorable `eval/labels.yaml` row to exactly one public-window row
    index by exact `cowrie.session_id` match. A labelled id that is absent from the
    window, or that occurs more than once in the window (an ambiguous join), is
    excluded from scoring and counted in a named reason bucket instead of being
    silently dropped (item 65's edge-case matrix)."""
    counts = Counter(sid for sid in session_ids if sid)
    first_index: dict[str, int] = {}
    for i, sid in enumerate(session_ids):
        if sid and sid not in first_index:
            first_index[sid] = i
    resolved: dict[int, str] = {}
    reasons: Counter[str] = Counter()
    for sid, label in labels.items():
        occurrences = counts.get(sid, 0)
        if occurrences == 0:
            reasons["unresolved_absent_from_public_window"] += 1
            continue
        if occurrences > 1:
            reasons["unresolved_duplicate_session_id_in_window"] += 1
            continue
        resolved[first_index[sid]] = label
    return resolved, dict(reasons)


def _attribute_band_trace(assignments: list, band_trace: list[dict]) -> list[list[dict]]:
    """Split a flat `band_trace` (`assign_batch` appends strictly in row order, one
    entry per band check actually resolved) into one slice per window row, using each
    `Assignment.band_checks` as that row's slice length. `band_checks` is incremented
    under the exact same condition `band_trace.append(...)` runs
    (`pre == BAND and tc is not None`), so this reconstruction cannot drift from what
    `assign_batch` actually attempted."""
    slices: list[list[dict]] = []
    cursor = 0
    for assignment in assignments:
        n = assignment.band_checks
        slices.append(band_trace[cursor:cursor + n])
        cursor += n
    if cursor != len(band_trace):
        raise RuntimeError("band_trace attribution length mismatch")
    return slices


def _labelled_candidate_trace(
    assignments: list, candidate_trace: list[list[dict]], resolved: dict[int, str],
) -> list[dict]:
    """Candidate-cascade traces for resolved labelled rows only.

    The raw trace is index-aligned to the full public window. The report intentionally
    uses the same synthetic row id as scoring, never the real `cowrie.session_id`.
    """

    if len(candidate_trace) != len(assignments):
        raise RuntimeError("candidate_trace attribution length mismatch")

    def _round_or_none(value) -> float | None:
        return None if value is None else round(float(value), 4)

    return [
        {
            "session_id": str(i),
            "true_label": resolved[i],
            "status": assignments[i].status,
            "assigned_playbook_id": assignments[i].playbook_id,
            "candidates": [
                {
                    **row,
                    "emb_cos": _round_or_none(row.get("emb_cos")),
                    "tfidf_cos": _round_or_none(row.get("tfidf_cos")),
                }
                for row in candidate_trace[i]
            ],
        }
        for i in sorted(resolved)
    ]


def _target_label_candidate_summary(
    assignments: list,
    candidate_trace: list[list[dict]],
    resolved: dict[int, str],
    *,
    target_label: str = TARGET_TRACE_LABEL,
) -> dict:
    """Aggregate item-80 answers for a target analyst label.

    The counters distinguish the three cases the investigation asks about: cascade
    floor stops, no-TF-IDF/thin-anchor decisions, and earlier assigned winners.
    """

    if len(candidate_trace) != len(assignments):
        raise RuntimeError("candidate_trace attribution length mismatch")

    indexes = [i for i in sorted(resolved) if resolved[i] == target_label]
    final_status_counts: Counter[str] = Counter()
    final_assigned_anchor_counts: Counter[str] = Counter()
    decision_counts: Counter[str] = Counter()
    pre_status_counts: Counter[str] = Counter()
    tfidf_none_decisions: Counter[str] = Counter()
    tfidf_numeric_decisions: Counter[str] = Counter()
    assigned_winner_anchor_counts: Counter[str] = Counter()
    assigned_winner_rank_counts: Counter[str] = Counter()
    rows_with_below_floor_stop = 0
    rows_with_band_rejection = 0
    rows_with_tfidf_none_assignment = 0
    rows_with_tfidf_numeric_assignment = 0

    for i in indexes:
        assignment = assignments[i]
        final_status_counts[assignment.status] += 1
        if assignment.playbook_id is not None:
            final_assigned_anchor_counts[assignment.playbook_id] += 1

        row_trace = candidate_trace[i]
        winner_recorded = False
        row_has_below_floor_stop = False
        row_has_band_rejection = False
        row_has_tfidf_none_assignment = False
        row_has_tfidf_numeric_assignment = False
        for candidate in row_trace:
            decision = str(candidate.get("decision"))
            decision_counts[decision] += 1
            pre_status_counts[str(candidate.get("pre_status"))] += 1
            if candidate.get("tfidf_cos") is None:
                tfidf_none_decisions[decision] += 1
            else:
                tfidf_numeric_decisions[decision] += 1
            if decision == "below_floor_stop":
                row_has_below_floor_stop = True
            if decision == "band_rejected":
                row_has_band_rejection = True
            if decision in {
                "assigned", "rescue_assigned", "band_deferred", "band_bypass_assigned",
            }:
                if candidate.get("tfidf_cos") is None:
                    row_has_tfidf_none_assignment = True
                else:
                    row_has_tfidf_numeric_assignment = True
                if not winner_recorded:
                    assigned_winner_anchor_counts[str(candidate.get("anchor_id"))] += 1
                    assigned_winner_rank_counts[str(candidate.get("rank"))] += 1
                    winner_recorded = True

        rows_with_below_floor_stop += int(row_has_below_floor_stop)
        rows_with_band_rejection += int(row_has_band_rejection)
        rows_with_tfidf_none_assignment += int(row_has_tfidf_none_assignment)
        rows_with_tfidf_numeric_assignment += int(row_has_tfidf_numeric_assignment)

    return {
        "label": target_label,
        "n_rows": len(indexes),
        "final_status_counts": dict(sorted(final_status_counts.items())),
        "final_assigned_anchor_counts": dict(sorted(final_assigned_anchor_counts.items())),
        "candidate_decision_counts": dict(sorted(decision_counts.items())),
        "candidate_pre_status_counts": dict(sorted(pre_status_counts.items())),
        "tfidf_none_decision_counts": dict(sorted(tfidf_none_decisions.items())),
        "tfidf_numeric_decision_counts": dict(sorted(tfidf_numeric_decisions.items())),
        "assigned_winner_anchor_counts": dict(sorted(assigned_winner_anchor_counts.items())),
        "assigned_winner_rank_counts": dict(sorted(assigned_winner_rank_counts.items())),
        "rows_with_below_floor_stop": rows_with_below_floor_stop,
        "rows_with_band_rejection": rows_with_band_rejection,
        "rows_with_tfidf_none_assignment": rows_with_tfidf_none_assignment,
        "rows_with_tfidf_numeric_assignment": rows_with_tfidf_numeric_assignment,
    }


def _run_band_arm(
    inputs: BandLabelledInputs, *, tau: float, confident_tau: float,
    tfidf_tau: float, band_bypass_anchor_ids: set[str], rescue_tau: float,
) -> tuple[list, list[dict], list[list[dict]], bool]:
    """A tfidf_tau-varying arm: replays `compute_assignment_window` (fits TF-IDF over
    the anchor + window bags) with `band_trace` captured."""
    band_trace: list[dict] = []
    candidate_trace: list[list[dict]] = []
    result = compute_assignment_window(
        inputs.embeddings, inputs.anchor_embeddings, inputs.anchor_ids,
        inputs.anchor_bags, inputs.anchor_bag_ids, inputs.command_bags,
        tau=tau, confident_tau=confident_tau, tfidf_tau=tfidf_tau,
        band_bypass_anchor_ids=band_bypass_anchor_ids,
        rescue_tau=rescue_tau, band_trace=band_trace, candidate_trace=candidate_trace,
    )
    return result.assignments, band_trace, candidate_trace, result.tfidf_available


def _run_disabled_arm(
    inputs: BandLabelledInputs, *, tau: float, confident_tau: float, rescue_tau: float,
) -> list:
    """The band-disabled floor (Design Notes): `assign_batch` directly with no
    `tfidf_cos` callable at all — never `compute_assignment_window`, so no TF-IDF/SVD
    lexical fit ever runs for this arm. A band anchor then degrades to trusting the
    embedding (`resolve()`'s no-TF-IDF branch, `defer_band=False`) -- that degrade *is*
    the floor."""
    return assign_batch(
        inputs.embeddings, inputs.anchor_embeddings, inputs.anchor_ids,
        tau=tau, confident_tau=confident_tau, tfidf_cos=None, rescue_tau=rescue_tau,
    )


def _anchor_majority_labels(assigned_rows: list[dict]) -> dict[str, str]:
    """Per predicted anchor (`predicted_playbook_id`), the majority true label among
    labelled rows assigned to it -- computed once over the full (unresampled) row set
    and held fixed across purity's bootstrap resamples, the same "prototype held fixed
    across resamples" pattern `eval_assignment_faithful` uses for its fold prototypes."""
    by_anchor: dict[str, Counter] = defaultdict(Counter)
    for row in assigned_rows:
        by_anchor[row["predicted_playbook_id"]][row["true_label"]] += 1
    majority: dict[str, str] = {}
    for anchor, counter in by_anchor.items():
        ranked = counter.most_common(2)
        if len(ranked) == 2 and ranked[0][1] == ranked[1][1]:
            # A tied labelled majority does not establish a familiar analyst label for
            # this aggregate scorer. Omit it rather than letting Counter insertion
            # order decide purity/novelty truth.
            continue
        majority[anchor] = ranked[0][0]
    return majority


def _real_geometry_novelty(
    rows: list[dict], familiar_labels: set[str], *, basis: str,
) -> dict:
    """Novelty metrics in the deployed anchor geometry.

    A true analyst label is familiar when it appears in the supplied basis. Labels
    absent from that basis are real-novel. The precision/recall/false-familiar names
    and denominator semantics intentionally match `eval_operational._pr_from_records`.
    """
    records = [
        (row["true_label"] not in familiar_labels, row["status"] == NOVEL)
        for row in rows
    ]
    tp = sum(1 for truth, pred in records if truth and pred)
    fp = sum(1 for truth, pred in records if not truth and pred)
    fn = sum(1 for truth, pred in records if truth and not pred)
    tn = sum(1 for truth, pred in records if not truth and not pred)
    flagged = tp + fp
    real_novel = tp + fn
    return {
        "basis": basis,
        "familiar_labels": sorted(familiar_labels),
        "novel_precision": round(tp / flagged, 4) if flagged else None,
        "novel_recall": round(tp / real_novel, 4) if real_novel else None,
        "false_familiar": round(fn / real_novel, 4) if real_novel else None,
        "n_flagged_novel": flagged,
        "n_real_novel": real_novel,
        "n_real_familiar": fp + tn,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
    }


def _bootstrap_macro_f1(rows: list[dict], labels: list[str], *, seed_offset: int) -> dict:
    """Bootstrap CI around `_macro_f1` (reused, not reimplemented) via `_bootstrap_rows`
    / `_interval` -- the same BOOTSTRAPS/SEED convention as `eval_assignment_faithful`,
    just assembled here since that script's own `_macro_measure` wrapper is not part of
    the item-65 reuse list (only `_macro_f1` is)."""
    value = _macro_f1(rows, labels)
    samples: list[float] = []
    if rows and labels:
        rng = np.random.default_rng(SEED + seed_offset)
        for _ in range(BOOTSTRAPS):
            sampled = _bootstrap_rows(rows, rng, "session_id")
            samples.append(_macro_f1(sampled, labels))
    return {
        "value": round(value, 4),
        "n": len(rows),
        "n_labels": len(labels),
        "interval": _interval(samples),
        "grouping": "session_id",
    }


def _status_delta(arm_status: dict[int, tuple], deployed_status: dict[int, tuple]) -> dict:
    """Aggregate transition counts between one arm's resolved (status, playbook_id) map
    and the deployed arm's -- keyed only on the internal window index, never a session
    identifier."""
    common = sorted(set(arm_status) & set(deployed_status))
    assigned_to_novel = sum(
        1 for i in common
        if deployed_status[i][0] == ASSIGNED and arm_status[i][0] == NOVEL
    )
    novel_to_assigned = sum(
        1 for i in common
        if deployed_status[i][0] == NOVEL and arm_status[i][0] == ASSIGNED
    )
    label_changed = sum(
        1 for i in common
        if deployed_status[i][0] == ASSIGNED and arm_status[i][0] == ASSIGNED
        and deployed_status[i][1] != arm_status[i][1]
    )
    return {
        "n_compared": len(common),
        "assigned_to_novel": assigned_to_novel,
        "novel_to_assigned": novel_to_assigned,
        "label_changed_while_assigned": label_changed,
    }


def score_arm(
    name: str,
    tfidf_tau: float | None,
    band_enabled: bool,
    assignments: list,
    band_trace: list[dict] | None,
    candidate_trace: list[list[dict]] | None,
    tfidf_available: bool,
    resolved: dict[int, str],
    deployed_index_status: dict[int, tuple] | None,
    seed_base: int,
) -> tuple[dict, dict[int, tuple], dict]:
    """Score exactly the labelled (`resolved`) rows of one arm's replayed
    assignments. Every row dict's "session_id" is a synthetic string built from the
    internal window index -- never the real `cowrie.session_id` -- so no per-session
    identifier is ever held in scoring state, let alone serialized into the report."""
    rows = [
        {
            "session_id": str(i),
            "true_label": resolved[i],
            "predicted_playbook_id": assignments[i].playbook_id,
            "status": assignments[i].status,
        }
        for i in sorted(resolved)
    ]
    index_status = {i: (assignments[i].status, assignments[i].playbook_id) for i in resolved}
    n = len(rows)
    labels_present = sorted({row["true_label"] for row in rows})
    status_counts = Counter(row["status"] for row in rows)
    assigned_rows = [row for row in rows if row["predicted_playbook_id"] is not None]
    majority = _anchor_majority_labels(assigned_rows)
    # Item 66 (Finding 49): `predicted_label` must be the anchor's *majority analyst
    # label*, not the raw `spb-<hex>` playbook id -- per_label_accuracy/macro_f1 compare
    # this against `true_label` (an analyst-label string), the same comparison purity
    # already did correctly via `majority.get(...)`. A NOVEL row's playbook_id is None,
    # for which `majority.get(None)` is safely `None` -- unscored, same as before.
    for row in rows:
        row["predicted_label"] = majority.get(row["predicted_playbook_id"])

    def _purity_num(rs: list[dict]) -> int:
        return sum(
            1 for r in rs
            if r["predicted_playbook_id"] is not None and r["predicted_label"] == r["true_label"]
        )

    def _purity_den(rs: list[dict]) -> int:
        return sum(1 for r in rs if r["predicted_playbook_id"] is not None)

    purity = _measure(
        rows, _purity_num, _purity_den, zero_empty=True,
        seed_offset=seed_base, grouping="session_id",
    )

    per_label_accuracy: dict[str, dict] = {}
    for index, label in enumerate(labels_present):
        def _num(rs: list[dict], label: str = label) -> int:
            return sum(1 for r in rs if r["true_label"] == label and r["predicted_label"] == label)

        def _den(rs: list[dict], label: str = label) -> int:
            return sum(1 for r in rs if r["true_label"] == label)

        per_label_accuracy[label] = _measure(
            rows, _num, _den, zero_empty=True,
            seed_offset=seed_base + 1 + index, grouping="session_id",
        )

    macro_f1 = _bootstrap_macro_f1(
        rows, labels_present, seed_offset=seed_base + 1 + len(labels_present),
    )

    if band_enabled and band_trace is not None:
        band_trace_slices = _attribute_band_trace(assignments, band_trace)
        labelled_band_trace = [row for i in sorted(resolved) for row in band_trace_slices[i]]
    else:
        labelled_band_trace = []
    band = _band_separation(labelled_band_trace)
    labelled_candidate_trace = (
        _labelled_candidate_trace(assignments, candidate_trace, resolved)
        if candidate_trace is not None else []
    )
    target_label_summary = (
        _target_label_candidate_summary(assignments, candidate_trace, resolved)
        if candidate_trace is not None else
        _target_label_candidate_summary(assignments, [[] for _ in assignments], resolved)
    )

    status_delta = (
        _status_delta(index_status, deployed_index_status)
        if deployed_index_status is not None else None
    )

    report = {
        "name": name,
        "tfidf_tau": tfidf_tau,
        "band_enabled": band_enabled,
        "tfidf_available": tfidf_available,
        "n_scored": n,
        "n_true_labels": len(labels_present),
        "status_counts": {
            "assigned": status_counts.get(ASSIGNED, 0),
            "novel": status_counts.get(NOVEL, 0),
        },
        "assigned_rate": round(status_counts.get(ASSIGNED, 0) / n, 4) if n else None,
        "purity": purity,
        "per_label_accuracy": per_label_accuracy,
        "macro_f1": macro_f1,
        "novelty_per_arm": _real_geometry_novelty(
            rows, set(majority.values()), basis="arm_majorities",
        ),
        "band_separation": band,
        "candidate_trace": labelled_candidate_trace,
        "target_label_candidate_summary": target_label_summary,
        "status_delta_vs_deployed": status_delta,
    }
    return report, index_status, {"rows": rows, "majority": majority}


def _attach_comparable_novelty(arms: list[dict], contexts: list[dict]) -> None:
    familiar_labels = {
        label
        for context in contexts
        for label in context["majority"].values()
    }
    for arm, context in zip(arms, contexts, strict=True):
        arm["novelty_comparable"] = _real_geometry_novelty(
            context["rows"], familiar_labels, basis="union_arm_majorities",
        )


def analyze(inputs: BandLabelledInputs, cfg, labels: dict[str, str]) -> dict:
    """Replay the three tfidf_tau arms over one fixed, aligned public corpus and score
    only the labelled rows resolved against it."""
    session_cfg = cfg.session
    tau = float(session_cfg.assignment_tau)
    confident_tau = float(session_cfg.assignment_confident_tau)
    deployed_tfidf_tau = float(session_cfg.assignment_tfidf_tau)
    raw_band_bypass_anchor_ids = getattr(
        session_cfg, "assignment_band_bypass_anchor_ids", [],
    ) or []
    if isinstance(raw_band_bypass_anchor_ids, str):
        raw_band_bypass_anchor_ids = [raw_band_bypass_anchor_ids]
    band_bypass_anchor_ids = {
        normalized
        for anchor_id in raw_band_bypass_anchor_ids
        if (normalized := str(anchor_id).strip())
    }
    rescue_tau = float(getattr(session_cfg, "assignment_rescue_tau", tau))
    if not math.isfinite(tau) or not math.isfinite(confident_tau) or not (
        0.0 <= tau <= confident_tau <= 1.0
    ):
        raise ValueError(
            "assignment_tau/assignment_confident_tau must be finite and satisfy "
            "0 <= tau <= confident_tau <= 1",
        )
    if not math.isfinite(deployed_tfidf_tau) or not 0.0 <= deployed_tfidf_tau <= 1.0:
        raise ValueError("session.assignment_tfidf_tau must be finite and within [0, 1]")
    if not math.isfinite(rescue_tau):
        raise ValueError("session.assignment_rescue_tau must be finite")
    if not math.isclose(rescue_tau, tau, abs_tol=1e-12):
        # Item 65 is scoped to the band/tfidf_tau question (item 62), not the below-tau
        # structural-rescue tier (item 30) -- an active rescue tier would need its own
        # window_predicates/anchor_predicate_signatures plumbing to replay faithfully,
        # which is out of scope here. Fail loudly rather than silently ignore it.
        raise ValueError(
            "exact band replay requires the structural rescue tier to be disabled "
            "(session.assignment_rescue_tau must equal session.assignment_tau)",
        )

    embeddings = np.asarray(inputs.embeddings, dtype=np.float32)
    anchor_embeddings = np.asarray(inputs.anchor_embeddings, dtype=np.float32)
    n_window = int(embeddings.shape[0])
    if n_window == 0 or embeddings.shape[1] == 0:
        raise ValueError("the fixed session window is empty or has zero-width embeddings")
    if len(inputs.command_bags) != n_window or len(inputs.session_ids) != n_window:
        raise ValueError("embeddings, command bags, and session ids are not aligned")
    if anchor_embeddings.shape[0] == 0 or anchor_embeddings.shape[1] == 0:
        raise ValueError("the pinned anchor geometry is empty or zero-width")
    if embeddings.shape[1] != anchor_embeddings.shape[1]:
        raise ValueError(
            f"embedding dimension mismatch: sessions={embeddings.shape[1]}, "
            f"anchors={anchor_embeddings.shape[1]}",
        )
    if not inputs.anchor_ids or anchor_embeddings.shape[0] != len(inputs.anchor_ids):
        raise ValueError("anchor ids and embeddings are empty or not aligned")
    if len(set(inputs.anchor_ids)) != len(inputs.anchor_ids):
        raise ValueError("anchor ids must be unique")
    unknown_band_bypass_anchor_ids = band_bypass_anchor_ids - set(inputs.anchor_ids)
    if unknown_band_bypass_anchor_ids:
        raise ValueError(
            "session.assignment_band_bypass_anchor_ids contains unknown anchor ids: "
            f"{sorted(unknown_band_bypass_anchor_ids)}",
        )
    if len(inputs.anchor_bags) != len(inputs.anchor_bag_ids):
        raise ValueError("anchor bags and anchor bag ids are not aligned")

    resolved, unresolved_reasons = join_labels_to_window(inputs.session_ids, labels)

    arms: list[dict] = []
    arm_contexts: list[dict] = []
    seed_base = 0

    # Arm 1: deployed tfidf_tau (0.80 in production today).
    assignments, band_trace, candidate_trace, tfidf_available = _run_band_arm(
        inputs, tau=tau, confident_tau=confident_tau,
        tfidf_tau=deployed_tfidf_tau, band_bypass_anchor_ids=band_bypass_anchor_ids,
        rescue_tau=rescue_tau,
    )
    deployed_report, deployed_index_status, deployed_context = score_arm(
        "deployed", deployed_tfidf_tau, True, assignments, band_trace, candidate_trace,
        tfidf_available, resolved, None, seed_base,
    )
    deployed_report["status_delta_vs_deployed"] = _status_delta(
        deployed_index_status, deployed_index_status,
    )
    arms.append(deployed_report)
    arm_contexts.append(deployed_context)
    seed_base += 1000

    # Arm 2: Finding 47's valley tfidf_tau.
    assignments, band_trace, candidate_trace, tfidf_available = _run_band_arm(
        inputs, tau=tau, confident_tau=confident_tau,
        tfidf_tau=VALLEY_TFIDF_TAU, band_bypass_anchor_ids=band_bypass_anchor_ids,
        rescue_tau=rescue_tau,
    )
    valley_report, _, valley_context = score_arm(
        "valley", VALLEY_TFIDF_TAU, True, assignments, band_trace, candidate_trace,
        tfidf_available, resolved, deployed_index_status, seed_base,
    )
    arms.append(valley_report)
    arm_contexts.append(valley_context)
    seed_base += 1000

    # Arm 3: band-disabled floor -- assign_batch directly, no lexical fit at all.
    assignments = _run_disabled_arm(
        inputs, tau=tau, confident_tau=confident_tau, rescue_tau=rescue_tau,
    )
    disabled_report, _, disabled_context = score_arm(
        "disabled", None, False, assignments, None, None, False,
        resolved, deployed_index_status, seed_base,
    )
    arms.append(disabled_report)
    arm_contexts.append(disabled_context)

    _attach_comparable_novelty(arms, arm_contexts)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "read_only": True,
        "session_classification": "public_only",
        "command_taxonomy_classification": "public_only",
        "anchor_provenance": "pinned_mixed_classification_derived_aggregates",
        "n_window_sessions": n_window,
        "n_anchors": len(inputs.anchor_ids),
        "n_public_anchor_bags": len(inputs.anchor_bags),
        "n_public_command_taxonomy_docs": inputs.command_taxonomy_size,
        "labels": {
            "scorable_total": len(labels),
            "resolved": len(resolved),
            "unresolved": dict(sorted(unresolved_reasons.items())),
        },
        "effective_config": {
            "assignment_tau": tau,
            "assignment_confident_tau": confident_tau,
            "assignment_rescue_tau": rescue_tau,
            "assignment_band_bypass_anchor_ids": sorted(band_bypass_anchor_ids),
            "deployed_tfidf_tau": deployed_tfidf_tau,
            "valley_tfidf_tau": VALLEY_TFIDF_TAU,
        },
        "arms": arms,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None)
    parser.add_argument("--labels", default="eval/labels.yaml")
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
        labels = load_scorable_labels(Path(args.labels))
        if not labels:
            raise ValueError(f"no scorable labelled rows found in {args.labels}")
        cfg = load_config(args.config)
        es = make_client(cfg.elasticsearch, load_secrets(args.config))
        inputs = load_inputs(es, cfg, per_anchor=args.per_anchor)
        report = analyze(inputs, cfg, labels)
    except (RuntimeError, ValueError) as exc:
        print(f"eval_band_labelled: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
