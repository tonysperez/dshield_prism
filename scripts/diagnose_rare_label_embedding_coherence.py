#!/usr/bin/env python
"""Item 70 diagnostic: rare-label embedding coherence.

This read-only diagnostic joins ``eval/labels.yaml`` to the explicitly-public live
session rollup window, then computes within-label pairwise cosine summaries for the
three outlier-starved rare labels. Output is aggregate-only: label names, counts,
cosine statistics, and verdicts. It never emits session ids, IPs, command text, raw
embeddings, or per-pair identifiers, and it never writes to Elasticsearch.

Unlike the anchor-coverage diagnostics, this script reads only public session
embeddings and labels. It does not read pinned/mixed-derived anchors and therefore
does not require ``--confirm-mixed-derived-anchors``.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.classification import CLASSIFICATION_KEYWORD, PUBLIC, releasable_filter
from enrich.clustering import l2_normalize
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

from eval_novel_pool import _EMB, _scan, _session  # noqa: E402
from validate_eval_labels import KNOWN_PLAYBOOK_LABELS  # noqa: E402

TARGET_LABELS = (
    "inband_payload_drop",
    "scp_upload",
    "account_backdoor_persistence",
)
_SID_FIELD = "cowrie.session_id"
_WINDOW_SOURCE_FIELDS = [_SID_FIELD, _EMB]


@dataclass(frozen=True)
class RareLabelInputs:
    embeddings: np.ndarray
    session_ids: list[str]


def load_scorable_labels(labels_path: Path) -> dict[str, str]:
    """Load eval labels using the same scorable-row rules as labelled eval scripts."""
    try:
        raw = yaml.safe_load(labels_path.read_text()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"could not read labels file {labels_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("labels file must be a mapping")
    annotated = {
        str(sid): block
        for sid, block in raw.items()
        if isinstance(block, dict) and block.get("annotated")
    }
    return {
        sid: str(block["playbook_label"])
        for sid, block in annotated.items()
        if block.get("is_real") is not False
        and block.get("playbook_label") in KNOWN_PLAYBOOK_LABELS
    }


def _public_filters(cfg) -> list[dict]:
    public = releasable_filter(cfg)
    explicit_public = {"term": {CLASSIFICATION_KEYWORD: PUBLIC}}
    return [public] if public == explicit_public else [public, explicit_public]


def _matrix_from_embeddings(embeddings: list[list[float]]) -> np.ndarray:
    if not embeddings:
        raise ValueError("no explicitly-public embedded sessions found")
    try:
        matrix = np.asarray(embeddings, dtype=np.float32)
    except (TypeError, ValueError) as exc:
        raise ValueError("session embeddings must be numeric vectors with consistent dimensions") from exc
    if matrix.ndim != 2:
        raise ValueError("session embeddings must be two-dimensional")
    if matrix.shape[0] == 0 or matrix.shape[1] == 0:
        raise ValueError("session embeddings must not be empty or zero-width")
    if not np.all(np.isfinite(matrix)):
        raise ValueError("session embeddings must contain only finite values")
    norms = np.linalg.norm(matrix, axis=1)
    if np.any(norms == 0.0):
        raise ValueError("session embeddings must not contain zero vectors")
    return l2_normalize(matrix)


def load_public_inputs(es, cfg) -> RareLabelInputs:
    """Scan only explicitly-public session rollups with embeddings.

    The query includes the fail-closed public-only classification term regardless of
    the deployment's releasability posture, so untagged/confidential rollups do not
    enter the diagnostic window.
    """
    indexes = cfg.elasticsearch.indexes.cowrie
    filters = [*_public_filters(cfg), {"exists": {"field": _EMB}}]

    session_ids: list[str] = []
    embeddings: list[list[float]] = []
    for hit in _scan(es, indexes.sessions_rollup, filters, _WINDOW_SOURCE_FIELDS):
        src = hit["_source"]
        session = _session(src)
        embedding = session.get("embedding")
        if embedding is None or (
            isinstance(embedding, (list, tuple)) and len(embedding) == 0
        ):
            raise ValueError("session embeddings must not be empty")
        sid = (src.get("cowrie") or {}).get("session_id")
        session_ids.append(str(sid) if sid else "")
        embeddings.append(embedding)
    return RareLabelInputs(embeddings=_matrix_from_embeddings(embeddings), session_ids=session_ids)


def join_labels_to_window(
    session_ids: list[str], labels: dict[str, str],
) -> tuple[dict[str, list[int]], dict[str, int]]:
    counts = Counter(sid for sid in session_ids if sid)
    first_index: dict[str, int] = {}
    for index, sid in enumerate(session_ids):
        if sid and sid not in first_index:
            first_index[sid] = index

    by_label: dict[str, list[int]] = defaultdict(list)
    reasons: Counter[str] = Counter()
    for sid, label in labels.items():
        if label not in TARGET_LABELS:
            continue
        occurrences = counts.get(sid, 0)
        if occurrences == 0:
            reasons["unresolved_absent_from_public_window"] += 1
            continue
        if occurrences > 1:
            reasons["unresolved_duplicate_session_id_in_window"] += 1
            continue
        by_label[label].append(first_index[sid])
    return {label: sorted(indices) for label, indices in by_label.items()}, dict(reasons)


def _cosine_summary(vectors: np.ndarray) -> tuple[int, dict[str, float], dict[str, float]]:
    cosine = vectors @ vectors.T
    rows, cols = np.triu_indices(vectors.shape[0], k=1)
    pairs = cosine[rows, cols]
    if pairs.size == 0:
        return 0, {}, {}
    raw = {
        "min": float(np.min(pairs)),
        "median": float(np.median(pairs)),
        "mean": float(np.mean(pairs)),
        "max": float(np.max(pairs)),
    }
    rounded = {
        "min": round(float(np.min(pairs)), 4),
        "median": round(float(np.median(pairs)), 4),
        "mean": round(float(np.mean(pairs)), 4),
        "max": round(float(np.max(pairs)), 4),
    }
    return int(pairs.size), rounded, raw


def _verdict(pair_count: int, cosine: dict[str, float], *, tau: float) -> str:
    if pair_count == 0:
        return "insufficient_pairs"
    if cosine["min"] >= tau:
        return "embedding_coherent"
    if cosine["median"] < tau:
        return "not_coherent_enough_for_clustering_only_fix"
    return "mixed_coherence"


def analyze(inputs: RareLabelInputs, labels: dict[str, str], *, assignment_tau: float) -> dict:
    if not math.isfinite(assignment_tau) or not 0.0 <= assignment_tau <= 1.0:
        raise ValueError("assignment_tau must be finite and within [0, 1]")
    if inputs.embeddings.ndim != 2 or inputs.embeddings.shape[1] == 0:
        raise ValueError("session embeddings must be two-dimensional and non-zero-width")
    if len(inputs.session_ids) != inputs.embeddings.shape[0]:
        raise ValueError("session ids and embeddings are not aligned")
    if not np.all(np.isfinite(inputs.embeddings)):
        raise ValueError("session embeddings must contain only finite values")

    by_label, unresolved_reasons = join_labels_to_window(inputs.session_ids, labels)
    if not any(by_label.get(label) for label in TARGET_LABELS):
        raise ValueError("no target-label embeddings resolved in the public session window")

    target_reports: dict[str, dict] = {}
    for label in TARGET_LABELS:
        indices = by_label.get(label, [])
        vectors = inputs.embeddings[indices] if indices else np.empty((0, inputs.embeddings.shape[1]))
        pair_count, cosine, raw_cosine = (
            _cosine_summary(vectors) if len(indices) >= 2 else (0, {}, {})
        )
        verdict = (
            "no_resolved_embeddings"
            if not indices else _verdict(pair_count, raw_cosine, tau=assignment_tau)
        )
        target_reports[label] = {
            "n_resolved": len(indices),
            "pair_count": pair_count,
            "cosine": cosine,
            "verdict": verdict,
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "session_classification": "public_only",
        "n_public_embedded_sessions": int(inputs.embeddings.shape[0]),
        "labels": {
            "scorable_total": len(labels),
            "target_resolved": sum(len(indices) for indices in by_label.values()),
            "unresolved": dict(sorted(unresolved_reasons.items())),
        },
        "effective_config": {"assignment_tau": assignment_tau},
        "target_labels": target_reports,
    }


def summarize(report: dict) -> str:
    lines = [
        "rare-label embedding coherence "
        f"(public_sessions={report['n_public_embedded_sessions']}, "
        f"tau={report['effective_config']['assignment_tau']})",
        f"labels={report['labels']}",
    ]
    for label, detail in report["target_labels"].items():
        cosine = detail["cosine"] or {}
        if cosine:
            stats = (
                f"min={cosine['min']} median={cosine['median']} "
                f"mean={cosine['mean']} max={cosine['max']}"
            )
        else:
            stats = "cosine=unmeasured"
        lines.append(
            f"  {label}: n={detail['n_resolved']} pairs={detail['pair_count']} "
            f"{stats} verdict={detail['verdict']}",
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None)
    parser.add_argument("--labels", default="eval/labels.yaml")
    parser.add_argument("--json", action="store_true", help="emit the full JSON report")
    args = parser.parse_args()

    try:
        labels = load_scorable_labels(Path(args.labels))
        if not labels:
            raise ValueError(f"no scorable labelled rows found in {args.labels}")
        cfg = load_config(args.config)
        es = make_client(cfg.elasticsearch, load_secrets(args.config))
        inputs = load_public_inputs(es, cfg)
        report = analyze(
            inputs,
            labels,
            assignment_tau=float(cfg.session.assignment_tau),
        )
    except (RuntimeError, ValueError) as exc:
        print(f"diagnose_rare_label_embedding_coherence: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        print(summarize(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
