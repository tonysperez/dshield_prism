#!/usr/bin/env python3
"""Production-path assignment and novelty replay.

This is a temporary diagnostic until the eval corpus contains a representative
snapshot of production anchors. It deliberately uses label-derived prototypes,
but otherwise replays the shared lexical preparation and ``assign_batch`` path.
An explicitly supplied baseline is always fail-closed.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.metadata
import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from capture_anchor_snapshot import predicate_signature as _anchor_predicate_signature
from eval_assignment import EvalRecord, EvidenceLoad, load_records_detailed
from eval_jsonl import resolve as resolve_jsonl
from eval_predicate_falsification import evaluate as evaluate_predicate_separation
from eval_predicate_falsification import load_command_text

from enrich.sources.cowrie.assignment import ASSIGNED, NOVEL, compute_assignment_window

# Private on purpose, imported on purpose: "armed signature" in the item-54 diagnostics must
# mean exactly what `predicate_overlap` means by it — same coercion AND same threshold — so
# reuse the gate's own helper rather than re-deriving one that can drift.
from enrich.sources.cowrie.predicates import (
    ANCHOR_MODAL_THRESHOLD,
    PREDICATE_NAMES,
    _coerce_modal_value,
    command_subsignals,
    fold_session_predicates,
)

TAU = 0.94
CONFIDENT_TAU = 0.98
TFIDF_TAU = 0.50  # was 0.80 — item 62 / Finding 47. Mirrors config.assignment_tfidf_tau;
                  # this script does NOT read config, so it must be kept in step by hand.
SEED = 20260728
MIN_BEHAVIOR_SIZE = 3
MIN_TRIAL_MEMBERS = 10
MIN_LEXICAL_COVERAGE = 1.0
BOOTSTRAPS = 100
PATHS = ("direct", "band_confirm", "cascade_recovery", "band_reject_abstain", "abstain")
THRESHOLD_GRID = (
    {"tau": 0.92, "confident_tau": 0.97, "tfidf_tau": 0.75},
    {"tau": TAU, "confident_tau": CONFIDENT_TAU, "tfidf_tau": TFIDF_TAU},
    {"tau": 0.96, "confident_tau": 0.99, "tfidf_tau": 0.85},
)
REQUIRED_GATES = {
    "familiar_macro_f1": "familiar.macro_f1.value",
    "novelty_recall": "novelty.novelty_recall.value",
    "false_novel_rate": "novelty.false_novel_rate.value",
}


class EvaluationInvalid(ValueError):
    """Controlled evidence/geometry failure."""


def _sha256(path: Path) -> str:
    # Resolve the plain/.gz spelling first: the sessions set is committed
    # gzipped, and capture identity must hash the bytes that were read.
    return hashlib.sha256(resolve_jsonl(path).read_bytes()).hexdigest()


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def _git_revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
        capture_output=True, check=False,
    )
    return result.stdout.strip() or "unknown"


def _dependencies() -> dict[str, str]:
    names = ("numpy", "scikit-learn", "PyYAML")
    return {name: importlib.metadata.version(name) for name in names}


def _interval(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    low, high = np.percentile(values, [2.5, 97.5])
    return {"low": round(float(low), 4), "high": round(float(high), 4)}


def _ratio(numerator: int, denominator: int, *, zero_empty: bool = False) -> float | None:
    if denominator == 0:
        return 0.0 if zero_empty else None
    return numerator / denominator


def _measure(
    outcomes: list[dict[str, Any]],
    numerator: Callable[[list[dict[str, Any]]], int],
    denominator: Callable[[list[dict[str, Any]]], int],
    *,
    zero_empty: bool = False,
    seed_offset: int = 0,
    grouping: str = "session_id",
) -> dict[str, Any]:
    n = numerator(outcomes)
    d = denominator(outcomes)
    value = _ratio(n, d, zero_empty=zero_empty)
    samples: list[float] = []
    if outcomes and value is not None:
        rng = np.random.default_rng(SEED + seed_offset)
        for _ in range(BOOTSTRAPS):
            rows = _bootstrap_rows(outcomes, rng, grouping)
            sampled = _ratio(numerator(rows), denominator(rows), zero_empty=zero_empty)
            if sampled is not None:
                samples.append(sampled)
    return {
        "numerator": n,
        "denominator": d,
        "value": round(value, 4) if value is not None else None,
        "interval": _interval(samples),
        "grouping": grouping,
    }


def _bootstrap_rows(
    outcomes: list[dict[str, Any]],
    rng: np.random.Generator,
    grouping: str,
) -> list[dict[str, Any]]:
    if grouping == "behavior/session_id":
        by_behavior: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in outcomes:
            by_behavior[row["true_label"]].append(row)
        behaviors = sorted(by_behavior)
        picked_behaviors = rng.choice(behaviors, size=len(behaviors), replace=True)
        sampled: list[dict[str, Any]] = []
        for behavior in picked_behaviors:
            by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in by_behavior[str(behavior)]:
                by_session[row["session_id"]].append(row)
            sessions = sorted(by_session)
            picked_sessions = rng.choice(sessions, size=len(sessions), replace=True)
            sampled.extend(row for session in picked_sessions
                           for row in by_session[str(session)])
        return sampled
    by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in outcomes:
        by_session[row["session_id"]].append(row)
    sessions = sorted(by_session)
    picked = rng.choice(sessions, size=len(sessions), replace=True)
    return [row for session in picked for row in by_session[str(session)]]


def _mean_measure(
    outcomes: list[dict[str, Any]], field: str, *, seed_offset: int,
    grouping: str = "session_id",
) -> dict[str, Any]:
    usable = [row for row in outcomes if row.get(field) is not None]
    numerator = float(sum(float(row[field]) for row in usable))
    denominator = len(usable)
    value = numerator / denominator if denominator else None
    samples = []
    if usable:
        rng = np.random.default_rng(SEED + seed_offset)
        for _ in range(BOOTSTRAPS):
            rows = _bootstrap_rows(usable, rng, grouping)
            samples.append(float(np.mean([row[field] for row in rows])))
    return {
        "numerator": round(numerator, 4),
        "denominator": denominator,
        "value": round(value, 4) if value is not None else None,
        "interval": _interval(samples),
        "grouping": grouping,
    }


def _confusion(outcomes: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for true_label in sorted({row["true_label"] for row in outcomes}):
        rows = [row for row in outcomes if row["true_label"] == true_label]
        result[true_label] = dict(sorted(Counter(
            row["predicted_label"] or "__NOVEL__" for row in rows
        ).items()))
    return result


def _margin_report(
    outcomes: list[dict[str, Any]], seed_base: int, *,
    grouping: str = "session_id",
) -> dict[str, Any]:
    return {
        "nearest_cosine": _mean_measure(
            outcomes, "nearest_cosine", seed_offset=seed_base, grouping=grouping,
        ),
        "second_nearest_cosine": _mean_measure(
            outcomes, "second_nearest_cosine", seed_offset=seed_base + 1,
            grouping=grouping,
        ),
        "nearest_margin": _mean_measure(
            outcomes, "nearest_margin", seed_offset=seed_base + 2,
            grouping=grouping,
        ),
    }


def _path_of(assignment: Any, tau: float = TAU) -> str:
    if assignment.status == ASSIGNED:
        if assignment.cascade_rank > 0:
            return "cascade_recovery"
        if assignment.confirmed_in_band:
            return "band_confirm"
        return "direct"
    return "band_reject_abstain" if assignment.cosine >= tau else "abstain"


def _replay(
    anchors: list[EvalRecord],
    windows: list[EvalRecord],
    *,
    novel_labels: set[str],
    tau: float = TAU,
    confident_tau: float = CONFIDENT_TAU,
    tfidf_tau: float = TFIDF_TAU,
    rescue_tau: float | None = None,
    session_predicates: dict[str, dict] | None = None,
    anchor_predicate_signatures: dict[str, dict] | None = None,
) -> list[dict[str, Any]]:
    """`rescue_tau`/`session_predicates`/`anchor_predicate_signatures` (item 30) are the
    replay-side plumbing for the below-tau structural-predicate rescue tier —
    `session_predicates` keys on `EvalRecord.session_id`, `anchor_predicate_signatures`
    keys on `analyst_label` (this replay's stand-in for `playbook_id`). All three default
    to `None`, in which case `compute_assignment_window` gets no rescue arguments at all
    and this function's output is byte-identical to before item 30 (every existing call
    site — the `evaluate()`/baseline gate path — omits them)."""
    anchor_ids = sorted({record.analyst_label for record in anchors})
    embedding_centroids = []
    for anchor_id in anchor_ids:
        rows = np.stack([
            record.embedding for record in anchors if record.analyst_label == anchor_id
        ])
        centroid = rows.mean(axis=0)
        norm = float(np.linalg.norm(centroid))
        if not math.isfinite(norm) or norm == 0.0:
            raise EvaluationInvalid(f"zero/nonfinite embedding centroid:{anchor_id}")
        embedding_centroids.append(centroid / norm)
    anchor_matrix = np.stack(embedding_centroids).astype(np.float32)
    window_predicates = (
        [session_predicates.get(record.session_id) for record in windows]
        if session_predicates is not None else None
    )
    anchor_signatures = (
        [anchor_predicate_signatures.get(anchor_id) for anchor_id in anchor_ids]
        if anchor_predicate_signatures is not None else None
    )
    result = compute_assignment_window(
        np.stack([record.embedding for record in windows]),
        anchor_matrix,
        anchor_ids,
        [record.command_cluster_bag or "" for record in anchors],
        [record.analyst_label for record in anchors],
        [record.command_cluster_bag or "" for record in windows],
        tau=tau,
        confident_tau=confident_tau,
        tfidf_tau=tfidf_tau,
        rescue_tau=rescue_tau,
        window_predicates=window_predicates,
        anchor_predicate_signatures=anchor_signatures,
    )
    assignments = result.assignments
    similarities = np.stack([record.embedding for record in windows]) @ anchor_matrix.T
    ordered = np.sort(similarities, axis=1)[:, ::-1]
    outcomes = []
    for index, (record, assignment) in enumerate(zip(windows, assignments, strict=False)):
        predicted = assignment.playbook_id
        outcomes.append({
            "session_id": record.session_id,
            "true_label": record.analyst_label,
            "predicted_label": predicted,
            "true_novel": record.analyst_label in novel_labels,
            "predicted_novel": assignment.status == NOVEL,
            "correct": predicted == record.analyst_label,
            "path": _path_of(assignment, tau),
            "rescued": assignment.rescued,
            "cascade_rank": assignment.cascade_rank,
            "cosine": assignment.cosine,
            "tfidf_cosine": assignment.tfidf_cosine,
            "band_checks": assignment.band_checks,
            "band_rejections": assignment.band_rejections,
            "band_confirmed": assignment.confirmed_in_band,
            "nearest_cosine": round(float(ordered[index, 0]), 4),
            "second_nearest_cosine": (
                round(float(ordered[index, 1]), 4) if ordered.shape[1] > 1 else None
            ),
            "nearest_margin": (
                round(float(ordered[index, 0] - ordered[index, 1]), 4)
                if ordered.shape[1] > 1 else None
            ),
        })
    return outcomes


def load_anchor_snapshot(
    path: Path,
) -> tuple[list[str], np.ndarray, list[str], list[str], list[dict[str, float] | None]]:
    """Load a committed anchor snapshot (`scripts/capture_anchor_snapshot.py`) for
    `--anchors` replay. Returns (anchor_ids, anchor_matrix, anchor_bags, anchor_bag_ids,
    anchor_signatures): `anchor_ids`/`anchor_matrix` are one L2-normalized centroid row per
    anchor; `anchor_bags`/`anchor_bag_ids` are the flattened per-session command-cluster bags
    used for the TF-IDF band confirm; `anchor_signatures` is the committed
    `predicate_signature` per anchor, aligned to `anchor_ids` (item 54), for the below-tau
    rescue tier. Snapshots written before either field existed degrade gracefully — no bags
    makes `compute_assignment_window` fall back to embedding-only assignment
    (`tfidf_available=False`), and a `None` signature can never rescue anything
    (`predicates.predicate_overlap` is fail-closed). A non-object `predicate_signature` is
    read as `None` for the same reason `_coerce_modal_value` tolerates junk: one malformed
    row must not abort the whole replay."""
    anchor_ids: list[str] = []
    vecs: list[list[float]] = []
    anchor_bags: list[str] = []
    anchor_bag_ids: list[str] = []
    anchor_signatures: list[dict[str, float] | None] = []
    seen_ids: set[str] = set()
    with gzip.open(path, "rt") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            pb, vec = row.get("playbook_id"), row.get("anchor_centroid")
            if not pb or not vec:
                continue
            if pb in seen_ids:
                raise EvaluationInvalid(f"duplicate playbook_id in anchor snapshot: {pb}")
            seen_ids.add(pb)
            anchor_ids.append(pb)
            vecs.append(vec)
            signature = row.get("predicate_signature")
            anchor_signatures.append(signature if isinstance(signature, dict) else None)
            for bag in row.get("command_cluster_bags") or []:
                anchor_bags.append(bag)
                anchor_bag_ids.append(pb)
    if not vecs:
        raise EvaluationInvalid(f"anchor snapshot has no usable rows: {path}")
    dims = {len(vec) for vec in vecs}
    if len(dims) > 1:
        raise EvaluationInvalid(f"anchor snapshot has inconsistent embedding dimensions: {dims}")
    matrix = np.asarray(vecs, dtype=np.float32)
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    return (
        anchor_ids, matrix / np.where(norms == 0.0, 1.0, norms),
        anchor_bags, anchor_bag_ids, anchor_signatures,
    )


def load_background_cohort(path: Path) -> list[str]:
    """Load a committed background cohort (`scripts/capture_anchor_snapshot.py
    --background-out`) for `--background` replay padding: one `command_cluster_bag`
    string per line. Mirrors `load_anchor_snapshot`'s error style — raises
    `EvaluationInvalid` naming `path` on a missing/corrupt/malformed file rather than
    letting a raw `OSError`/`gzip.BadGzipFile`/`json.JSONDecodeError`/`AttributeError`
    escape."""
    bags: list[str] = []
    try:
        with gzip.open(path, "rt") as fh:
            for line in fh:
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise EvaluationInvalid(
                        f"background cohort has a non-object row: {path}",
                    )
                bags.append(row.get("command_cluster_bag") or "")
    except (OSError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
        raise EvaluationInvalid(f"background cohort unreadable: {path}: {exc}") from exc
    if not bags:
        raise EvaluationInvalid(f"background cohort has no usable rows: {path}")
    return bags


TFIDF_TAU_SWEEP_GRID = tuple(round(0.1 * step, 1) for step in range(10))  # 0.0, 0.1, ..., 0.9


def _band_diagnosis(band_trace: list[dict[str, Any]]) -> dict[str, Any]:
    """Post-process a `band_trace` (item 34): the traced `tfidf_cos` distribution plus
    how many of those same checks would confirm at each of a fixed grid of candidate
    `tfidf_tau` values. Pure arithmetic over the already-collected trace — no re-running
    `assign_batch` per grid point, so it cannot drift from what was actually attempted."""
    values = [row["tfidf_cos"] for row in band_trace]
    if not values:
        return {"n": 0, "min": None, "median": None, "mean": None, "max": None, "sweep": []}

    def _round(value: float) -> float:
        rounded = round(float(value), 4)
        return 0.0 if rounded == 0.0 else rounded  # normalize float-noise -0.0 to 0.0

    return {
        "n": len(values),
        "min": _round(np.min(values)),
        "median": _round(np.median(values)),
        "mean": _round(np.mean(values)),
        "max": _round(np.max(values)),
        "sweep": [
            {"tfidf_tau": candidate, "confirms_at_tau": sum(v >= candidate for v in values)}
            for candidate in TFIDF_TAU_SWEEP_GRID
        ],
    }


def _candidate_trace_report(
    scored: list[EvalRecord],
    candidate_trace: list[list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Attach assignment-cascade candidate traces to real-anchor replay diagnostics.

    The raw trace uses full-precision floats so downstream tests can inspect behavior
    precisely. The JSON report rounds them like the rest of this evaluator and leaves
    `tfidf_cos` as `None` when the anchor had no usable TF-IDF centroid or the band was not
    consulted.
    """

    def _round_or_none(value: Any) -> float | None:
        return None if value is None else round(float(value), 4)

    return [
        {
            "session_id": record.session_id,
            "production_playbook_id": record.production_playbook_id,
            "candidates": [
                {
                    **row,
                    "emb_cos": _round_or_none(row.get("emb_cos")),
                    "tfidf_cos": _round_or_none(row.get("tfidf_cos")),
                }
                for row in rows
            ],
        }
        for record, rows in zip(scored, candidate_trace, strict=False)
    ]


def _signature_is_armed(signature: dict[str, float] | None) -> bool:
    """Can this anchor signature ever rescue anything? Deliberately the exact condition
    `predicate_overlap` applies from the anchor side: a *known* predicate name whose coerced
    value clears `ANCHOR_MODAL_THRESHOLD`. A merely-nonzero signature (all 0.25, say) is not
    armed and must not be counted as evidence, nor is one keyed entirely outside
    `PREDICATE_NAMES` — the gate would never look at those keys."""
    if not signature:
        return False
    return any(
        _coerce_modal_value(signature.get(name)) >= ANCHOR_MODAL_THRESHOLD
        for name in PREDICATE_NAMES
    )


def evidence_ceilings(
    scored: list[EvalRecord],
    library: set[str],
    session_predicates: dict[str, dict],
    anchor_signatures: list[dict[str, float] | None] | None,
) -> dict[str, Any]:
    """How much evidence the rescue tier actually had to work with — the numbers that tell
    an inert gate apart from a gate with nothing to read.

    Reported once per sweep from the REAL inputs, never per arm: the `forced_true`/
    `forced_false` arms are handed synthetic vectors and signatures, so computing these from
    an arm's own inputs would describe the substitution rather than the corpus.

    `sessions_with_predicate_evidence` counts sessions with at least one predicate *True* —
    an all-False fold can never rescue, so counting its mere presence would hide exactly the
    missing-evidence case this exists to expose. `anchors_armed` applies
    `_signature_is_armed`, matching what the gate can actually fire on."""
    return {
        "gt_in_library": sum(
            1 for record in scored if record.production_playbook_id in library
        ),
        "sessions_with_predicate_evidence": sum(
            1 for record in scored
            if any((session_predicates.get(record.session_id) or {}).values())
        ),
        "anchors_with_signature": (
            sum(1 for sig in anchor_signatures if sig is not None)
            if anchor_signatures is not None else 0
        ),
        "anchors_armed": (
            sum(1 for sig in anchor_signatures if _signature_is_armed(sig))
            if anchor_signatures is not None else 0
        ),
    }


def _rescue_metrics(
    scored: list[EvalRecord],
    assignments: list[Any],
    library: set[str],
) -> dict[str, Any]:
    """Item 54 rescue-tier accounting for one `_real_anchor_replay` arm. Outcome only —
    evidence ceilings live in `evidence_ceilings`, which is arm-invariant.

    `accuracy_in_library` exists because raw `accuracy` is confounded: a scored session
    whose ground-truth `production_playbook_id` is absent from the snapshot library can
    never be assigned correctly, so it depresses accuracy for a reason that has nothing to
    do with the rescue gate. Its denominator `n_assigned_in_library` is emitted alongside it
    because rescue *moves* that denominator (it assigns sessions that were novel), so the
    ratio is not comparable across arms without it. `n_rescued_gt_in_library` is the same
    guard one level down: a rescue whose ground truth is not in the library is wrong by
    construction, so `n_rescued_correct` is only interpretable next to it."""
    rescued = [(record, a) for record, a in zip(scored, assignments, strict=False) if a.rescued]
    assigned = [(record, a) for record, a in zip(scored, assignments, strict=False) if a.status == ASSIGNED]
    in_library = [
        (record, a) for record, a in assigned if record.production_playbook_id in library
    ]
    accuracy_in_library = (
        sum(record.production_playbook_id == a.playbook_id for record, a in in_library)
        / len(in_library) if in_library else None
    )
    n_assigned = len(assigned)
    return {
        "n_assigned": n_assigned,
        "assigned_rate": round(n_assigned / len(scored), 4) if scored else None,
        "n_rescued": len(rescued),
        "n_rescued_correct": sum(
            record.production_playbook_id == a.playbook_id for record, a in rescued
        ),
        "n_rescued_gt_in_library": sum(
            1 for record, _ in rescued if record.production_playbook_id in library
        ),
        "n_assigned_in_library": len(in_library),
        "accuracy_in_library": (
            round(accuracy_in_library, 4) if accuracy_in_library is not None else None
        ),
    }


def _real_anchor_replay(
    anchor_ids: list[str],
    anchor_matrix: np.ndarray,
    anchor_bags: list[str],
    anchor_bag_ids: list[str],
    records: list[EvalRecord],
    *,
    tau: float = TAU,
    confident_tau: float = CONFIDENT_TAU,
    tfidf_tau: float = TFIDF_TAU,
    background_bags: list[str] | None = None,
    rescue_tau: float | None = None,
    session_predicates: dict[str, dict] | None = None,
    anchor_predicate_signatures: list[dict[str, float] | None] | None = None,
) -> dict[str, Any]:
    """Diagnostic-only replay of the real anchor library against every eval session with
    a known `production_playbook_id` (backlog item 23). Ground truth is the production
    playbook id, not the analyst label — real anchors use production ids, a different
    vocabulary. Not baseline-gated; item 24 decides what, if anything, gets gated.

    `background_bags` (item 38), when given, pads the TF-IDF/SVD fit with a broader
    session sample (`scripts/capture_anchor_snapshot.py --background-out`); omitted
    (`None`, the default), behavior is byte-identical to before.

    `rescue_tau`/`session_predicates`/`anchor_predicate_signatures` (item 54) are the
    real-anchor counterpart of `_replay`'s rescue plumbing: `session_predicates` keys on
    `EvalRecord.session_id`, `anchor_predicate_signatures` is positional and aligned to
    `anchor_ids` (production playbook ids — the real vocabulary, unlike `_replay`'s
    analyst-label stand-in). All three default to `None`, in which case
    `compute_assignment_window` gets no rescue arguments at all and this function's output
    is byte-identical to before item 54."""
    scored = [record for record in records if record.production_playbook_id]
    excluded = len(records) - len(scored)
    library = set(anchor_ids)
    # Positional-alignment validation runs before the empty-corpus shortcut: a malformed
    # snapshot must fail loudly even when the eval set happens to filter down to nothing.
    if anchor_predicate_signatures is not None and (
        len(anchor_predicate_signatures) != len(anchor_ids)
    ):
        raise EvaluationInvalid(
            f"anchor_predicate_signatures has {len(anchor_predicate_signatures)} entries but "
            f"the anchor library has {len(anchor_ids)}"
        )
    if not scored:
        return {
            "n_scored": 0, "excluded_no_production_id": excluded,
            "tfidf_available": False, "status_counts": {}, "accuracy": None, "band": None,
            "band_diagnosis": _band_diagnosis([]),
            **(_rescue_metrics([], [], library) if rescue_tau is not None else {}),
        }
    corpus_dim = scored[0].embedding.shape[0]
    if anchor_matrix.shape[1] != corpus_dim:
        raise EvaluationInvalid(
            f"anchor snapshot embedding dimension {anchor_matrix.shape[1]} does not match "
            f"eval corpus dimension {corpus_dim}"
        )
    window_predicates = (
        [session_predicates.get(record.session_id) for record in scored]
        if session_predicates is not None else None
    )
    band_trace: list[dict[str, Any]] = []
    candidate_trace: list[list[dict[str, Any]]] = []
    result = compute_assignment_window(
        np.stack([record.embedding for record in scored]),
        anchor_matrix, anchor_ids, anchor_bags, anchor_bag_ids,
        [record.command_cluster_bag or "" for record in scored],
        tau=tau, confident_tau=confident_tau, tfidf_tau=tfidf_tau, band_trace=band_trace,
        candidate_trace=candidate_trace,
        background_bags=background_bags,
        rescue_tau=rescue_tau,
        window_predicates=window_predicates,
        anchor_predicate_signatures=anchor_predicate_signatures,
    )
    assignments = result.assignments
    assigned = [(record, a) for record, a in zip(scored, assignments, strict=False) if a.status == ASSIGNED]
    accuracy = (
        sum(record.production_playbook_id == a.playbook_id for record, a in assigned)
        / len(assigned) if assigned else None
    )
    return {
        "n_scored": len(scored),
        "excluded_no_production_id": excluded,
        "tfidf_available": result.tfidf_available,
        "status_counts": dict(Counter(a.status for a in assignments)),
        "accuracy": round(accuracy, 4) if accuracy is not None else None,
        "band": {
            "checks": sum(a.band_checks for a in assignments),
            "rejections": sum(a.band_rejections for a in assignments),
            "confirms": sum(a.confirmed_in_band for a in assignments),
        },
        "band_diagnosis": _band_diagnosis(band_trace),
        # Candidate-level cascade trace is real-anchor-only diagnostics (item 78). The
        # baseline-gated no-`--anchors` evaluator never calls this path.
        "candidate_trace": _candidate_trace_report(scored, candidate_trace),
        # Rescue metrics appear only when the rescue tier is actually armed, so a plain
        # `--anchors` run's rescue shape is byte-identical to before item 54.
        **(_rescue_metrics(scored, assignments, library) if rescue_tau is not None else {}),
    }


def _familiar_folds(records: list[EvalRecord], folds: int = 3) -> list[tuple[list[EvalRecord], list[EvalRecord]]]:
    by_label: dict[str, list[EvalRecord]] = defaultdict(list)
    for record in records:
        by_label[record.analyst_label].append(record)
    fold_of: dict[str, int] = {}
    for label in sorted(by_label):
        rows = sorted(by_label[label], key=lambda row: row.session_id)
        for index, row in enumerate(rows):
            fold_of[row.session_id] = index % folds
    result = []
    for fold in range(folds):
        test = [record for record in records if fold_of[record.session_id] == fold]
        train = [record for record in records if fold_of[record.session_id] != fold]
        learnable = {record.analyst_label for record in train}
        test = [record for record in test if record.analyst_label in learnable]
        if train and test:
            result.append((train, test))
    return result


def novelty_trials(eligible: list[str]) -> list[list[str]]:
    """Pair held-out behaviors, using one final triple when the count is odd."""
    labels = sorted(eligible)
    if len(labels) % 2:
        if len(labels) < 3:
            return []
        pairs = [labels[i:i + 2] for i in range(0, len(labels) - 3, 2)]
        return [*pairs, labels[-3:]]
    return [labels[i:i + 2] for i in range(0, len(labels), 2)]


def _macro_f1(rows: list[dict[str, Any]], labels: list[str]) -> float:
    scores = []
    for label in labels:
        tp = sum(row["true_label"] == label and row["predicted_label"] == label for row in rows)
        fp = sum(row["true_label"] != label and row["predicted_label"] == label for row in rows)
        fn = sum(row["true_label"] == label and row["predicted_label"] != label for row in rows)
        precision = _ratio(tp, tp + fp, zero_empty=True) or 0.0
        recall = _ratio(tp, tp + fn, zero_empty=True) or 0.0
        scores.append(2 * precision * recall / (precision + recall)
                      if precision + recall else 0.0)
    return float(np.mean(scores)) if scores else 0.0


def _macro_measure(outcomes: list[dict[str, Any]], labels: list[str]) -> dict[str, Any]:
    value = _macro_f1(outcomes, labels)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for outcome in outcomes:
        groups[outcome["session_id"]].append(outcome)
    rng = np.random.default_rng(SEED + 91)
    keys = sorted(groups)
    samples = []
    for _ in range(BOOTSTRAPS):
        picked = rng.choice(keys, size=len(keys), replace=True)
        samples.append(_macro_f1(
            [row for key in picked for row in groups[str(key)]], labels,
        ))
    return {
        "numerator": round(sum(
            _macro_f1(outcomes, [label]) for label in labels
        ), 4),
        "denominator": len(labels),
        "value": round(value, 4),
        "interval": _interval(samples),
        "grouping": "session_id",
    }


def _path_metrics(
    outcomes: list[dict[str, Any]], seed_base: int, *,
    grouping: str = "session_id",
) -> dict[str, Any]:
    result = {}
    for index, path in enumerate(PATHS):
        def selected(rows, path=path):
            return [row for row in rows if row["path"] == path]

        result[path] = {
            "share": _measure(
                outcomes, lambda rows: len(selected(rows)), len,
                seed_offset=seed_base + index * 4, grouping=grouping,
            ),
            "accuracy": _measure(
                outcomes, lambda rows: sum(row["correct"] for row in selected(rows)),
                lambda rows: len(selected(rows)), zero_empty=True,
                seed_offset=seed_base + index * 4 + 1, grouping=grouping,
            ),
            "coverage": _measure(
                outcomes,
                lambda rows: sum(not row["predicted_novel"] for row in selected(rows)),
                lambda rows: len(selected(rows)), zero_empty=True,
                seed_offset=seed_base + index * 4 + 2, grouping=grouping,
            ),
            "selective_risk": _measure(
                outcomes,
                lambda rows: sum(not row["predicted_novel"] and not row["correct"]
                                 for row in selected(rows)),
                lambda rows: sum(not row["predicted_novel"] for row in selected(rows)),
                zero_empty=True, seed_offset=seed_base + index * 4 + 3,
                grouping=grouping,
            ),
        }
    return result


def _band_report(
    outcomes: list[dict[str, Any]], seed_base: int, *,
    grouping: str = "session_id",
) -> dict[str, Any]:
    return {
        "checks_per_outcome": _measure(
            outcomes, lambda rows: sum(row["band_checks"] for row in rows),
            len, seed_offset=seed_base, grouping=grouping,
        ),
        "rejections_per_outcome": _measure(
            outcomes, lambda rows: sum(row["band_rejections"] for row in rows),
            len, seed_offset=seed_base + 1, grouping=grouping,
        ),
        "confirmed_share": _measure(
            outcomes, lambda rows: sum(row["band_confirmed"] for row in rows),
            len, seed_offset=seed_base + 2, grouping=grouping,
        ),
        "abstention_share": _measure(
            outcomes, lambda rows: sum(row["predicted_novel"] for row in rows),
            len, seed_offset=seed_base + 3, grouping=grouping,
        ),
        "totals": {
            "checks": sum(row["band_checks"] for row in outcomes),
            "rejections": sum(row["band_rejections"] for row in outcomes),
            "confirms": sum(row["band_confirmed"] for row in outcomes),
            "abstentions": sum(row["predicted_novel"] for row in outcomes),
        },
    }


def _cascade_slices(
    outcomes: list[dict[str, Any]], *, grouping: str = "session_id",
) -> dict[str, Any]:
    cascades = [row for row in outcomes if row["path"] == "cascade_recovery"]
    dimensions: dict[str, list[Any]] = {
        "true_label": sorted({row["true_label"] for row in outcomes}),
        "predicted_label": sorted({
            row["predicted_label"] for row in outcomes if row["predicted_label"] is not None
        }),
        "correctness": [False, True],
        "rank": sorted({row["cascade_rank"] for row in outcomes}),
    }
    field_of = {
        "true_label": "true_label",
        "predicted_label": "predicted_label",
        "correctness": "correct",
        "rank": "cascade_rank",
    }
    result: dict[str, Any] = {}
    for dimension, values in dimensions.items():
        field = field_of[dimension]
        result[dimension] = {
            str(value).lower() if isinstance(value, bool) else str(value): _measure(
                outcomes,
                lambda rows, field=field, value=value: sum(
                    row["path"] == "cascade_recovery" and row[field] == value
                    for row in rows
                ),
                len,
                seed_offset=200 + len(result) * 20 + index,
                grouping=grouping,
            )
            for index, value in enumerate(values)
        }
    result["total"] = _measure(
        outcomes,
        lambda rows: sum(row["path"] == "cascade_recovery" for row in rows),
        len,
        seed_offset=299,
        grouping=grouping,
    )
    result["recovered_outcomes"] = len(cascades)
    return result


def _familiar_report(outcomes: list[dict[str, Any]], eligible: list[str]) -> dict[str, Any]:
    per_label = {}
    for index, label in enumerate(eligible):
        per_label[label] = {
            "precision": _measure(
                outcomes,
                lambda rows, label=label: sum(
                    row["true_label"] == label and row["predicted_label"] == label
                    for row in rows
                ),
                lambda rows, label=label: sum(row["predicted_label"] == label for row in rows),
                zero_empty=True,
                seed_offset=400 + index * 3,
            ),
            "recall": _measure(
                outcomes,
                lambda rows, label=label: sum(
                    row["true_label"] == label and row["predicted_label"] == label
                    for row in rows
                ),
                lambda rows, label=label: sum(row["true_label"] == label for row in rows),
                zero_empty=True,
                seed_offset=401 + index * 3,
            ),
        }
        precision = per_label[label]["precision"]
        recall = per_label[label]["recall"]
        p, r = precision["value"], recall["value"]
        f1_value = 2 * p * r / (p + r) if p + r else 0.0
        # F1 is bootstrapped directly so its interval follows grouped resampling.
        def f1_num(rows: list[dict[str, Any]], label: str = label) -> int:
            tp = sum(row["true_label"] == label and row["predicted_label"] == label for row in rows)
            fp = sum(row["true_label"] != label and row["predicted_label"] == label for row in rows)
            fn = sum(row["true_label"] == label and row["predicted_label"] != label for row in rows)
            pp = _ratio(tp, tp + fp, zero_empty=True) or 0.0
            rr = _ratio(tp, tp + fn, zero_empty=True) or 0.0
            return round(1_000_000 * (2 * pp * rr / (pp + rr) if pp + rr else 0.0))
        f1 = _measure(
            outcomes, f1_num, lambda rows: 1_000_000,
            zero_empty=True, seed_offset=402 + index * 3,
        )
        f1["value"] = round(f1_value, 4)
        per_label[label]["f1"] = f1
    return {
        "n_outcomes": len(outcomes),
        "confusion": _confusion(outcomes),
        "accuracy": _measure(
            outcomes, lambda rows: sum(row["correct"] for row in rows),
            len, seed_offset=11,
        ),
        "macro_f1": _macro_measure(outcomes, eligible),
        "coverage": _measure(
            outcomes, lambda rows: sum(not row["predicted_novel"] for row in rows),
            len, seed_offset=12,
        ),
        "selective_risk": _measure(
            outcomes,
            lambda rows: sum(not row["predicted_novel"] and not row["correct"] for row in rows),
            lambda rows: sum(not row["predicted_novel"] for row in rows),
            zero_empty=True,
            seed_offset=13,
        ),
        "false_novel_rate": _measure(
            outcomes, lambda rows: sum(row["predicted_novel"] for row in rows),
            len, seed_offset=14,
        ),
        "per_label": per_label,
        "paths": _path_metrics(outcomes, 500),
        "cascade": _cascade_slices(outcomes),
        "band": _band_report(outcomes, 525),
        "margins": _margin_report(outcomes, 550),
    }


def _novelty_report(outcomes: list[dict[str, Any]], eligible: list[str]) -> dict[str, Any]:
    per_behavior = {}
    for index, behavior in enumerate(eligible):
        per_behavior[behavior] = {
            "novelty_recall": _measure(
                outcomes,
                lambda rows, behavior=behavior: sum(
                    row["true_label"] == behavior and row["true_novel"]
                    and row["predicted_novel"] for row in rows
                ),
                lambda rows, behavior=behavior: sum(
                    row["true_label"] == behavior and row["true_novel"] for row in rows
                ),
                zero_empty=True,
                seed_offset=600 + index,
                grouping="session_id",
            )
        }
    return {
        "n_outcomes": len(outcomes),
        "confusion": {
            "true_novel_predicted_novel": sum(
                row["true_novel"] and row["predicted_novel"] for row in outcomes
            ),
            "true_novel_predicted_familiar": sum(
                row["true_novel"] and not row["predicted_novel"] for row in outcomes
            ),
            "true_familiar_predicted_novel": sum(
                not row["true_novel"] and row["predicted_novel"] for row in outcomes
            ),
            "true_familiar_predicted_familiar": sum(
                not row["true_novel"] and not row["predicted_novel"] for row in outcomes
            ),
        },
        "novelty_precision": _measure(
            outcomes,
            lambda rows: sum(row["true_novel"] and row["predicted_novel"] for row in rows),
            lambda rows: sum(row["predicted_novel"] for row in rows),
            zero_empty=True,
            seed_offset=21,
            grouping="behavior/session_id",
        ),
        "novelty_recall": _measure(
            outcomes,
            lambda rows: sum(row["true_novel"] and row["predicted_novel"] for row in rows),
            lambda rows: sum(row["true_novel"] for row in rows),
            zero_empty=True,
            seed_offset=22,
            grouping="behavior/session_id",
        ),
        "false_familiar_rate": _measure(
            outcomes,
            lambda rows: sum(row["true_novel"] and not row["predicted_novel"] for row in rows),
            lambda rows: sum(row["true_novel"] for row in rows),
            seed_offset=23,
            grouping="behavior/session_id",
        ),
        "false_novel_rate": _measure(
            outcomes,
            lambda rows: sum(not row["true_novel"] and row["predicted_novel"] for row in rows),
            lambda rows: sum(not row["true_novel"] for row in rows),
            seed_offset=24,
            grouping="behavior/session_id",
        ),
        "familiar_assignment_coverage": _measure(
            outcomes,
            lambda rows: sum(not row["true_novel"] and not row["predicted_novel"] for row in rows),
            lambda rows: sum(not row["true_novel"] for row in rows),
            seed_offset=25,
            grouping="behavior/session_id",
        ),
        "per_behavior": per_behavior,
        "paths": _path_metrics(
            outcomes, 700, grouping="behavior/session_id",
        ),
        "cascade": _cascade_slices(
            outcomes, grouping="behavior/session_id",
        ),
        "band": _band_report(
            outcomes, 725, grouping="behavior/session_id",
        ),
        "margins": _margin_report(
            outcomes, 750, grouping="behavior/session_id",
        ),
    }


def _required_nulls(value: Any, path: str = "report") -> list[str]:
    missing = []
    if isinstance(value, dict):
        if {"numerator", "denominator", "value", "interval"} <= set(value):
            if value["value"] is None or value["interval"] is None:
                missing.append(path)
        else:
            for key, child in value.items():
                missing.extend(_required_nulls(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            missing.extend(_required_nulls(child, f"{path}[{index}]"))
    return missing


def _identity(
    labels_path: Path,
    sessions_path: Path,
    evidence: EvidenceLoad,
    eligible: list[str],
    trials: list[list[str]],
) -> dict[str, Any]:
    capture = evidence.metadata["capture_timestamps"]
    prototype_inputs = [{
        "session_id": record.session_id,
        "label": record.analyst_label,
        "embedding_sha256": hashlib.sha256(record.embedding.tobytes()).hexdigest(),
        "lexical_bag_sha256": hashlib.sha256(
            (record.command_cluster_bag or "").encode()
        ).hexdigest(),
    } for record in sorted(evidence.records, key=lambda item: item.session_id)]
    fold_identity = [{
        "anchor_session_ids": sorted(record.session_id for record in anchors),
        "window_session_ids": sorted(record.session_id for record in windows),
    } for anchors, windows in _familiar_folds(evidence.records)]
    identity = {
        "schema_version": 2,
        "corpus": {
            "labels_path": str(labels_path.resolve()),
            "labels_sha256": _sha256(labels_path),
            "sessions_path": str(resolve_jsonl(sessions_path).resolve()),
            "sessions_sha256": _sha256(sessions_path),
            "accepted_records": len(evidence.records),
        },
        "rubric": {
            "versions": evidence.metadata["rubric_versions"],
            "path": str((ROOT / "eval/RUBRIC.md").resolve()),
            "sha256": _sha256(ROOT / "eval/RUBRIC.md"),
        },
        "sample_design": {
            "familiar_folds": 3,
            "novelty_min_behavior_size": MIN_BEHAVIOR_SIZE,
            "novelty_min_trial_members": MIN_TRIAL_MEMBERS,
            "minimum_lexical_coverage": MIN_LEXICAL_COVERAGE,
            "eligible_behaviors": eligible,
            "novelty_trials": trials,
            "bootstrap_replicates": BOOTSTRAPS,
            "grouping": "session_id",
            "novelty_grouping": "hierarchical behavior/session_id",
            "interval": {"method": "percentile", "confidence": 0.95},
        },
        "representation": {
            "embedding_dimensions": evidence.diagnostics["embedding_dimensions"],
            "embed_versions": evidence.metadata["embed_versions"],
            "embed_config_hashes": evidence.metadata["embed_config_hashes"],
            "normalization": "loader_l2_float32",
            "input_construction": "captured_session_embedding",
            "pooling": "identified_by_embed_config_hash",
            "lexical": "shared_tfidf_svd_label_prototypes",
        },
        "anchors": {
            "geometry": "folded_analyst_label_prototypes",
            "representative_production_snapshot": False,
            "prototype_inputs_sha256": _stable_hash(prototype_inputs),
            "familiar_folds_sha256": _stable_hash(fold_identity),
        },
        "config": {
            "deployed": {
                "tau": TAU, "confident_tau": CONFIDENT_TAU, "tfidf_tau": TFIDF_TAU,
            },
            "fixed_grid": THRESHOLD_GRID,
        },
        "sources": {
            relative: _sha256(ROOT / relative) for relative in (
                "src/enrich/sources/cowrie/assignment.py",
                "src/enrich/clustering.py",
                "src/enrich/sources/cowrie/lexical.py",
                "src/enrich/sources/cowrie/assign_runner.py",
                "scripts/eval_assignment.py",
                "scripts/eval_assignment_faithful.py",
                "scripts/validate_eval_labels.py",
            )
        },
        "git_revision": _git_revision(),
        "dependencies": _dependencies(),
        "seed": SEED,
        "capture_identity": {
            "first": capture[0] if capture else None,
            "last": capture[-1] if capture else None,
            "distinct_timestamps": len(capture),
            "timestamps_sha256": _stable_hash(capture),
        },
        "exclusions": evidence.diagnostics,
    }
    # Canonicalize JSON-sensitive types (integer mapping keys, tuples) so an
    # identity survives a baseline write/read without a false mismatch.
    identity = json.loads(json.dumps(identity, sort_keys=True, allow_nan=False))
    identity["identity_sha256"] = _stable_hash(identity)
    return identity


def evaluate(labels_path: Path, sessions_path: Path) -> dict[str, Any]:
    evidence = load_records_detailed(labels_path, sessions_path)
    counts = Counter(record.analyst_label for record in evidence.records)
    eligible = sorted(label for label, count in counts.items() if count >= MIN_BEHAVIOR_SIZE)
    trials = novelty_trials(eligible)
    invalid = [
        f"loader:{reason}={count}"
        for reason, count in evidence.diagnostics["exclusions"].items() if count
    ]
    if len(evidence.metadata["rubric_versions"]) != 1:
        invalid.append("incompatible rubric metadata")
    if len(evidence.metadata["embed_versions"]) != 1:
        invalid.append("incompatible embedding version metadata")
    if len(evidence.metadata["embed_config_hashes"]) != 1:
        invalid.append("incompatible embedding config metadata")
    if len(evidence.diagnostics["embedding_dimensions"]) != 1:
        invalid.append("incompatible embedding dimensions")
    if evidence.diagnostics["lexical_coverage"] < MIN_LEXICAL_COVERAGE:
        invalid.append(
            "lexical coverage "
            f"{evidence.diagnostics['lexical_coverage']:.4f} below declared minimum "
            f"{MIN_LEXICAL_COVERAGE:.4f}"
        )
    if len(trials) < 2:
        invalid.append("underpowered novelty trial design")
    for index, trial in enumerate(trials):
        support = sum(counts[label] for label in trial)
        if support < MIN_TRIAL_MEMBERS:
            invalid.append(
                f"novelty trial {index} support {support} below {MIN_TRIAL_MEMBERS}"
            )
    familiar_outcomes: list[dict[str, Any]] = []
    novelty_outcomes: list[dict[str, Any]] = []
    operating_curve: list[dict[str, Any]] = []
    if not invalid:
        try:
            for point in THRESHOLD_GRID:
                point_familiar: list[dict[str, Any]] = []
                point_novelty: list[dict[str, Any]] = []
                for anchors, windows in _familiar_folds(evidence.records):
                    point_familiar.extend(_replay(
                        anchors, windows, novel_labels=set(), **point,
                    ))
                for heldout in trials:
                    heldout_set = set(heldout)
                    anchors = [record for record in evidence.records
                               if record.analyst_label not in heldout_set]
                    point_novelty.extend(_replay(
                        anchors, evidence.records, novel_labels=heldout_set, **point,
                    ))
                point_report = {
                    "thresholds": point,
                    "deployed": point == THRESHOLD_GRID[1],
                    "familiar": _familiar_report(point_familiar, eligible),
                    "novelty": _novelty_report(point_novelty, eligible),
                }
                operating_curve.append(point_report)
                if point_report["deployed"]:
                    familiar_outcomes = point_familiar
                    novelty_outcomes = point_novelty
        except EvaluationInvalid as exc:
            invalid.append(str(exc))
            familiar_outcomes = []
            novelty_outcomes = []
            operating_curve = []
    familiar = _familiar_report(familiar_outcomes, eligible) if familiar_outcomes else {}
    novelty = _novelty_report(novelty_outcomes, eligible) if novelty_outcomes else {}
    invalid.extend(_required_nulls({"familiar": familiar, "novelty": novelty}))
    return {
        "schema_version": 2,
        "status": "INVALID" if invalid else "DIAGNOSTIC",
        "authority": "temporary_diagnostic_pending_representative_production_anchors",
        "invalid_reasons": sorted(set(invalid)),
        "identity": _identity(labels_path, sessions_path, evidence, eligible, trials),
        "evidence": evidence.diagnostics,
        "behavior_counts": dict(sorted(counts.items())),
        "eligibility": {
            "minimum_behavior_size": MIN_BEHAVIOR_SIZE,
            "eligible_behaviors": eligible,
            "excluded_behaviors": {
                label: {
                    "count": count,
                    "reason": f"support below {MIN_BEHAVIOR_SIZE}",
                }
                for label, count in sorted(counts.items())
                if label not in eligible
            },
        },
        "familiar": familiar,
        "novelty": novelty,
        "operating_curve": operating_curve,
    }


def _identity_differences(expected: Any, actual: Any, path: str = "identity") -> list[str]:
    if isinstance(expected, dict) and isinstance(actual, dict):
        differences = []
        for key in sorted(set(expected) | set(actual)):
            child = f"{path}.{key}"
            if key not in expected:
                differences.append(f"{child}: unexpected")
            elif key not in actual:
                differences.append(f"{child}: missing")
            else:
                differences.extend(_identity_differences(expected[key], actual[key], child))
        return differences
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return [f"{path}: length {len(expected)} != {len(actual)}"]
        differences = []
        for index, (left, right) in enumerate(zip(expected, actual, strict=False)):
            differences.extend(_identity_differences(left, right, f"{path}[{index}]"))
        return differences
    return [] if expected == actual else [f"{path}: {expected!r} != {actual!r}"]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def apply_baseline(report: dict[str, Any], baseline_path: Path) -> dict[str, Any]:
    reasons: list[str] = []
    try:
        baseline = json.loads(
            baseline_path.read_text(), object_pairs_hook=_unique_object,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        report["status"] = "INVALID"
        report["invalid_reasons"].append(f"baseline unreadable: {exc}")
        return report
    if not isinstance(baseline, dict) or not isinstance(baseline.get("identity"), dict):
        reasons.append("baseline.identity must be an object")
    else:
        reasons.extend(_identity_differences(baseline["identity"], report["identity"]))
    gates = baseline.get("gates") if isinstance(baseline, dict) else None
    if not isinstance(baseline, dict) or baseline.get("schema_version") != 2:
        reasons.append("baseline.schema_version must equal 2")
    if not isinstance(gates, dict) or not gates:
        reasons.append("baseline.gates must be a non-empty object")
    else:
        for missing in sorted(set(REQUIRED_GATES) - set(gates)):
            reasons.append(f"baseline.gates.{missing} is required")
        for name, gate in sorted(gates.items()):
            if not isinstance(gate, dict):
                reasons.append(f"baseline.gates.{name} must be an object")
                continue
            path = gate.get("path")
            if name in REQUIRED_GATES and path != REQUIRED_GATES[name]:
                reasons.append(
                    f"baseline.gates.{name}.path must equal {REQUIRED_GATES[name]}"
                )
            value: Any = report
            for part in str(path or "").split("."):
                value = value.get(part) if isinstance(value, dict) else None
            floor = gate.get("floor")
            ceiling = gate.get("ceiling")
            if floor is None and ceiling is None:
                reasons.append(
                    f"baseline.gates.{name} requires floor or ceiling"
                )
            for field, candidate in (("value", value), ("floor", floor), ("ceiling", ceiling)):
                if candidate is not None and (
                    not isinstance(candidate, (int, float))
                    or isinstance(candidate, bool)
                    or not math.isfinite(float(candidate))
                ):
                    reasons.append(f"baseline.gates.{name}.{field} must be finite numeric")
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                reasons.append(f"baseline.gates.{name}.path is unavailable")
            elif floor is not None and isinstance(floor, (int, float)) and value < floor:
                reasons.append(f"gate {name}: {value} below floor {floor}")
            elif ceiling is not None and isinstance(ceiling, (int, float)) and value > ceiling:
                reasons.append(f"gate {name}: {value} above ceiling {ceiling}")
    report["status"] = "INVALID" if reasons or report["invalid_reasons"] else "PASS"
    report["invalid_reasons"] = sorted(set(report["invalid_reasons"] + reasons))
    report["baseline"] = str(baseline_path.resolve())
    return report


def write_baseline(report: dict[str, Any], baseline_path: Path) -> None:
    gates = {
        "familiar_macro_f1": {
            "path": REQUIRED_GATES["familiar_macro_f1"],
            "floor": report["familiar"]["macro_f1"]["value"],
        },
        "novelty_recall": {
            "path": REQUIRED_GATES["novelty_recall"],
            "floor": report["novelty"]["novelty_recall"]["value"],
        },
        "false_novel_rate": {
            "path": REQUIRED_GATES["false_novel_rate"],
            "ceiling": report["novelty"]["false_novel_rate"]["value"],
        },
    }
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps({
        "schema_version": 2, "identity": report["identity"], "gates": gates,
    }, indent=2, sort_keys=True) + "\n")


def run_rescue_tau_sweep(
    labels_path: Path,
    sessions_path: Path,
    rescue_taus: list[float],
) -> dict[str, Any]:
    """Item 30 A4/A5 — sweep candidate `rescue_tau` values through the same
    label-prototype novelty replay `evaluate()` uses. Rescue only ever affects a session
    the ordinary cascade would already call NOVEL, so only the novelty trials (held-out
    labels replayed as if unfamiliar) can move — the familiar folds are unaffected and
    are not re-run here. Reports `novelty_precision`/`novelty_recall` per swept value —
    NOT a macro-F1 delta (spec-30 constraint: the expected gain is ~4x smaller than the
    operational gate's CI half-width, too small to support a pass/fail macro-F1 claim).
    Also reports the tau-independent structural-predicate per-pair separation accuracy
    (`eval_predicate_falsification.evaluate`, unaffected by `rescue_tau`) for context.

    Diagnostic only — no baseline, no gate. The operator reads this table to pick (or
    decline to pick) a `rescue_tau` to ship; spec-30 marks that choice Ask First.

    Session predicate vectors are computed via the PRODUCTION per-command sub-signal +
    fold path (`predicates.command_subsignals` / `fold_session_predicates`) over the same
    labelled command text `eval_predicate_falsification.load_command_text` loads — this
    exercises the exact code `commands.py`/`lexical.py` run in production, not the
    validated reference implementation directly (that reference is what
    `predicate_separation` below measures, for comparison)."""
    evidence = load_records_detailed(labels_path, sessions_path)
    command_text = load_command_text(labels_path, sessions_path)
    session_predicates = build_session_predicate_vectors(command_text)
    counts = Counter(record.analyst_label for record in evidence.records)
    eligible = sorted(label for label, count in counts.items() if count >= MIN_BEHAVIOR_SIZE)
    trials = novelty_trials(eligible)

    sweep_rows: list[dict[str, Any]] = []
    for rescue_tau in rescue_taus:
        novelty_outcomes: list[dict[str, Any]] = []
        for heldout in trials:
            heldout_set = set(heldout)
            anchors = [record for record in evidence.records
                      if record.analyst_label not in heldout_set]
            by_label: dict[str, list[dict]] = defaultdict(list)
            for record in anchors:
                vector = session_predicates.get(record.session_id)
                if vector is not None:
                    by_label[record.analyst_label].append(vector)
            anchor_signatures = {
                label: _anchor_predicate_signature(vectors)
                for label, vectors in by_label.items()
            }
            novelty_outcomes.extend(_replay(
                anchors, evidence.records, novel_labels=heldout_set,
                rescue_tau=rescue_tau,
                session_predicates=session_predicates,
                anchor_predicate_signatures=anchor_signatures,
            ))
        sweep_rows.append({
            "rescue_tau": rescue_tau,
            "n_rescued": sum(1 for row in novelty_outcomes if row["rescued"]),
            "novelty_precision": _measure(
                novelty_outcomes,
                lambda rows: sum(row["true_novel"] and row["predicted_novel"] for row in rows),
                lambda rows: sum(row["predicted_novel"] for row in rows),
                zero_empty=True, seed_offset=950, grouping="behavior/session_id",
            ),
            "novelty_recall": _measure(
                novelty_outcomes,
                lambda rows: sum(row["true_novel"] and row["predicted_novel"] for row in rows),
                lambda rows: sum(row["true_novel"] for row in rows),
                zero_empty=True, seed_offset=951, grouping="behavior/session_id",
            ),
        })

    predicate_separation = [
        {"pair": f"{row['label_a']} <-> {row['label_b']}",
         "n": row["n"], "accuracy": row["accuracy"]}
        for row in evaluate_predicate_separation(command_text)
    ]
    return {
        "eligible_behaviors": eligible,
        "novelty_trials": trials,
        "rescue_tau_sweep": sweep_rows,
        "predicate_separation": predicate_separation,
    }


RESCUE_ARMS = ("gated", "forced_true", "forced_false")


def build_session_predicate_vectors(
    command_text: dict[str, tuple[str, list[str]]],
) -> dict[str, dict[str, bool]]:
    """session_id -> folded predicate vector, via the PRODUCTION per-command sub-signal +
    fold path (`predicates.command_subsignals` / `fold_session_predicates`) over the
    labelled command text `eval_predicate_falsification.load_command_text` returns. Shared
    by both sweeps so the label-prototype and real-anchor arms cannot diverge on how a
    session vector is built."""
    return {
        sid: fold_session_predicates([command_subsignals(line) for line in lines])
        for sid, (_label, lines) in command_text.items()
    }


def run_real_anchor_rescue_sweep(
    anchor_ids: list[str],
    anchor_matrix: np.ndarray,
    anchor_bags: list[str],
    anchor_bag_ids: list[str],
    anchor_signatures: list[dict[str, float] | None],
    records: list[EvalRecord],
    session_predicates: dict[str, dict[str, bool]],
    rescue_taus: list[float],
    *,
    background_bags: list[str] | None = None,
) -> dict[str, Any]:
    """Item 54 — the three-arm rescue ablation on the REAL anchor library.

    `run_rescue_tau_sweep` answers the same question on label-derived prototypes with
    signatures grouped by analyst label; this one replays against the committed snapshot
    anchors and their committed `predicate_signature`, scoring against
    `production_playbook_id`. Both are reported, because the whole point of item 54 is
    comparing the two geometries — Finding 41(3)'s blocked fraction was measured on the
    label geometry and is expected to fall here.

    The three arms differ only in the predicate inputs, never in the gate code:

    * ``gated`` — real session vectors, real committed anchor signatures. The shipped rule.
    * ``forced_true`` — all-True vectors and all-1.0 signatures. `predicate_overlap` is
      True iff some predicate is True on the session AND modal on the anchor, so this makes
      it unconditionally True: pure tau-lowering with no predicate constraint.
    * ``forced_false`` — real vectors, all-0.0 signatures. Unconditionally False, so the
      rescue tier is inert. The control: it must rescue 0 at every tau.

    Diagnostic only — no baseline, no gate. Offline; reads only committed eval artifacts."""
    forced_true_vectors = {
        record.session_id: dict.fromkeys(PREDICATE_NAMES, True) for record in records
    }
    all_true_signature: dict[str, float] = dict.fromkeys(PREDICATE_NAMES, 1.0)
    all_zero_signature: dict[str, float] = dict.fromkeys(PREDICATE_NAMES, 0.0)
    arm_inputs: dict[str, tuple[dict[str, dict], list[dict[str, float] | None]]] = {
        "gated": (session_predicates, anchor_signatures),
        "forced_true": (forced_true_vectors, [all_true_signature] * len(anchor_ids)),
        "forced_false": (session_predicates, [all_zero_signature] * len(anchor_ids)),
    }

    scored = [record for record in records if record.production_playbook_id]
    ceilings = evidence_ceilings(
        scored, set(anchor_ids), session_predicates, anchor_signatures,
    )
    # With no real evidence on either side the gated arm cannot rescue for reasons that have
    # nothing to do with selectivity, and a blocked_fraction of 1.0 would read as "the gate
    # refuses everything" instead of "the gate was handed nothing".
    have_evidence = bool(
        ceilings["sessions_with_predicate_evidence"] and ceilings["anchors_armed"]
    )

    sweep_rows: list[dict[str, Any]] = []
    for rescue_tau in rescue_taus:
        arms: dict[str, Any] = {}
        for arm in RESCUE_ARMS:
            vectors, signatures = arm_inputs[arm]
            arms[arm] = _real_anchor_replay(
                anchor_ids, anchor_matrix, anchor_bags, anchor_bag_ids, records,
                background_bags=background_bags,
                rescue_tau=rescue_tau,
                session_predicates=vectors,
                anchor_predicate_signatures=signatures,
            )
        ungated = arms["forced_true"]["n_rescued"]
        sweep_rows.append({
            "rescue_tau": rescue_tau,
            "arms": arms,
            # What fraction of the rescues pure tau-lowering would make does the predicate
            # gate refuse? Undefined when tau-lowering rescues nothing, and deliberately
            # withheld when the gate had no evidence to weigh in the first place.
            "blocked_fraction": (
                round((ungated - arms["gated"]["n_rescued"]) / ungated, 4)
                if ungated and have_evidence else None
            ),
        })
    # Key is `rows`, not `rescue_tau_sweep`: the top-level report already has a
    # `rescue_tau_sweep` of a different shape (the label-prototype sweep), and nesting the
    # same name under a different schema makes the JSON hostile to grep.
    return {"arms": list(RESCUE_ARMS), "evidence": ceilings, "rows": sweep_rows}


def _fmt(value: Any, spec: str = ".4f") -> str:
    return "n/a" if value is None else format(value, spec)


def _print_real_anchor_rescue_sweep(sweep: dict[str, Any]) -> None:
    """Item 54 text table. The header states the evidence ceilings because reading rescue
    precision without them invites the conclusion that the gate is bad when the anchor
    library is simply small. `resc_ok` is printed as `correct/reachable` and `acc_in_lib` as
    a ratio over its own denominator — both denominators move as rescue fires, so the bare
    numerators are not comparable down a column."""
    rows = sweep["rows"]
    print("\nreal-anchor rescue_tau sweep (item 54 — DIAGNOSTIC, not gated):")
    if not rows:
        return
    ceilings = sweep["evidence"]
    print(f"  scored={rows[0]['arms']['gated']['n_scored']} "
          f"gt_in_library={ceilings['gt_in_library']} "
          f"sessions_with_evidence={ceilings['sessions_with_predicate_evidence']} "
          f"anchors_signed={ceilings['anchors_with_signature']} "
          f"(armed {ceilings['anchors_armed']})")
    print(f"  {'rescue_tau':>10}  {'arm':<12}  {'rescued':>7}  {'resc_ok':>9}  "
          f"{'assigned':>8}  {'assign_rate':>11}  {'accuracy':>8}  {'acc_in_lib':>16}  "
          f"{'blocked':>7}")
    for row in rows:
        for arm in sweep["arms"]:
            m = row["arms"][arm]
            blocked = _fmt(row["blocked_fraction"]) if arm == "gated" else ""
            resc_ok = f"{m['n_rescued_correct']}/{m['n_rescued_gt_in_library']}"
            acc_lib = f"{_fmt(m['accuracy_in_library'])} (n={m['n_assigned_in_library']})"
            print(f"  {row['rescue_tau']:>10}  {arm:<12}  {m['n_rescued']:>7}  "
                  f"{resc_ok:>9}  {m['n_assigned']:>8}  "
                  f"{_fmt(m['assigned_rate']):>11}  {_fmt(m['accuracy']):>8}  "
                  f"{acc_lib:>16}  {blocked:>7}")


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", type=Path, default=ROOT / "eval/labels.yaml")
    parser.add_argument("--sessions", type=Path, default=ROOT / "eval/sessions.unlabeled.jsonl.gz")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--write-baseline", type=Path)
    parser.add_argument(
        "--anchors", type=Path, default=None,
        help="real anchor snapshot (scripts/capture_anchor_snapshot.py) to replay against "
             "instead of label-derived prototypes; adds report['real_anchor_replay'] "
             "(diagnostic only, not baseline-gated). Combined with --rescue-tau-sweep it "
             "also adds report['real_anchor_rescue_sweep'] (item 54)",
    )
    parser.add_argument(
        "--background", type=Path, default=None,
        help="background cohort (scripts/capture_anchor_snapshot.py --background-out) to "
             "pad the --anchors TF-IDF/SVD fit with a broader session sample; ignored "
             "without --anchors. Omitted (default) is byte-identical to before item 38.",
    )
    parser.add_argument(
        "--rescue-tau-sweep", type=str, default=None,
        help="comma-separated rescue_tau candidates (item 30 A4/A5), each <= tau "
             f"({TAU}), e.g. '0.86,0.88,0.90'; adds report['rescue_tau_sweep'] with "
             "novelty_precision/novelty_recall per candidate plus the tau-independent "
             "predicate separation table. With --anchors it additionally runs the "
             "real-anchor three-arm ablation (item 54) into "
             "report['real_anchor_rescue_sweep'] (diagnostic only, not baseline-gated)",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-json", action="store_false", dest="json")
    args = parser.parse_args()
    # Argument validation runs before `evaluate()` — that call is itself a multi-minute
    # replay, and a typo in --rescue-tau-sweep should cost nothing.
    candidates: list[float] = []
    if args.rescue_tau_sweep:
        try:
            candidates = [float(x) for x in args.rescue_tau_sweep.split(",") if x.strip()]
        except ValueError:
            print(f"invalid --rescue-tau-sweep value: {args.rescue_tau_sweep!r}", file=sys.stderr)
            return 2
        if not candidates:
            print("--rescue-tau-sweep must name at least one value", file=sys.stderr)
            return 2
        if not all(math.isfinite(c) for c in candidates):
            print(f"--rescue-tau-sweep values must all be finite: {candidates}", file=sys.stderr)
            return 2
        # Both ends matter. Above tau `assign_batch` raises; at or below 0.0 the rescue band
        # swallows the entire cosine range, so every arm rescues everything and
        # blocked_fraction stops meaning anything — a silently useless sweep, not a crash.
        out_of_range = [c for c in candidates if not (0.0 < c <= TAU)]
        if out_of_range:
            print(
                f"--rescue-tau-sweep values must all be in (0.0, tau={TAU}]; "
                f"got {out_of_range}",
                file=sys.stderr,
            )
            return 2

    report = evaluate(args.labels, args.sessions)
    if candidates:
        report["rescue_tau_sweep"] = run_rescue_tau_sweep(args.labels, args.sessions, candidates)
    if args.anchors:
        try:
            (
                anchor_ids, anchor_matrix, anchor_bags, anchor_bag_ids, anchor_signatures,
            ) = load_anchor_snapshot(args.anchors)
            background_bags = (
                load_background_cohort(args.background) if args.background else None
            )
            evidence = load_records_detailed(args.labels, args.sessions)
        except (EvaluationInvalid, OSError, json.JSONDecodeError) as exc:
            print(f"invalid anchor snapshot: {exc}", file=sys.stderr)
            return 2
        # Replay failures are attributed separately — a misaligned signature list or a
        # dimension mismatch is not a bad snapshot file, and saying so sends the operator
        # to the wrong place.
        try:
            report["real_anchor_replay"] = _real_anchor_replay(
                anchor_ids, anchor_matrix, anchor_bags, anchor_bag_ids, evidence.records,
                background_bags=background_bags,
            )
            if candidates:
                report["real_anchor_rescue_sweep"] = run_real_anchor_rescue_sweep(
                    anchor_ids, anchor_matrix, anchor_bags, anchor_bag_ids,
                    anchor_signatures, evidence.records,
                    build_session_predicate_vectors(
                        load_command_text(args.labels, args.sessions),
                    ),
                    candidates,
                    background_bags=background_bags,
                )
        except (EvaluationInvalid, ValueError) as exc:
            print(f"real-anchor replay failed: {exc}", file=sys.stderr)
            return 2
    if args.write_baseline:
        if report["status"] == "INVALID":
            print("cannot write baseline from INVALID report", file=sys.stderr)
            return 2
        write_baseline(report, args.write_baseline)
        print(f"wrote {_display_path(args.write_baseline)}", file=sys.stderr)
    if args.baseline:
        report = apply_baseline(report, args.baseline)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    else:
        print(f"assignment faithful: {report['status']}")
        print(f"authority: {report['authority']}")
        if report["invalid_reasons"]:
            for reason in report["invalid_reasons"]:
                print(f"  INVALID {reason}")
        elif report["familiar"]:
            print(f"familiar macro_f1: {report['familiar']['macro_f1']['value']:.4f}")
            print(f"novelty recall: {report['novelty']['novelty_recall']['value']:.4f}")
            print(f"false novel: {report['novelty']['false_novel_rate']['value']:.4f}")
        if report.get("real_anchor_replay"):
            rar = report["real_anchor_replay"]
            print(f"real anchor replay: n_scored={rar['n_scored']} "
                  f"excluded_no_production_id={rar['excluded_no_production_id']} "
                  f"accuracy={rar['accuracy']}")
            bd = rar["band_diagnosis"]
            print(f"band diagnosis: n={bd['n']} min={bd['min']} median={bd['median']} "
                  f"mean={bd['mean']} max={bd['max']}")
        if report.get("rescue_tau_sweep"):
            sweep = report["rescue_tau_sweep"]
            print("\nrescue_tau sweep (item 30 A4/A5 — DIAGNOSTIC, not gated):")
            print(f"  {'rescue_tau':>10}  {'n_rescued':>9}  {'novelty_precision':>18}  "
                  f"{'novelty_recall':>15}")
            for row in sweep["rescue_tau_sweep"]:
                precision = row["novelty_precision"]["value"]
                recall = row["novelty_recall"]["value"]
                print(f"  {row['rescue_tau']:>10}  {row['n_rescued']:>9}  "
                      f"{'n/a' if precision is None else f'{precision:.4f}':>18}  "
                      f"{'n/a' if recall is None else f'{recall:.4f}':>15}")
            print("  predicate separation (tau-independent):")
            for row in sweep["predicate_separation"]:
                acc = row["accuracy"]
                print(f"    {row['pair']:46}n={row['n']:<4} "
                      f"accuracy={'n/a' if acc is None else f'{acc:.4f}'}")
        if report.get("real_anchor_rescue_sweep"):
            _print_real_anchor_rescue_sweep(report["real_anchor_rescue_sweep"])
    return 2 if report["status"] == "INVALID" else 0


if __name__ == "__main__":
    raise SystemExit(main())
