"""Upsert findings docs while preserving analyst status.

The miner produces a fresh `evidence` block + score for each finding on
every run; the analyst's `status` / `status_history` / `first_seen_at`
must outlive the re-mine. This module enforces that contract: see
`upsert_finding`.

`finding_id` is content-addressed on `(kind, artifact_kind, artifact_value)`
so the same discovery across runs collapses onto one doc.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

log = logging.getLogger(__name__)


_VALID_STATUSES: frozenset[str] = frozenset({"new", "ack", "confirmed", "rejected"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def finding_id(
    kind: str,
    artifact_kind: str,
    artifact_value: str,
    delta_signature: Optional[str] = None,
) -> str:
    """Deterministic id: `find-<kind3>-<sha16(akind:avalue[:delta])>`.

    Two re-mines that produce the same finding pin to the same doc id,
    so the GET-then-upsert flow naturally preserves the analyst's
    triage state across runs.

    Drift findings pass `delta_signature` so that a *new* delta on the
    same playbook produces a *new* doc id — different drifts on the
    same artifact stay distinct in the inbox. Once a drift is rejected,
    its `delta_signature` lands in the artifact's `drift_suppressions[]`
    and the miner skips re-emitting that exact delta on future runs.
    """
    payload = f"{artifact_kind}:{artifact_value}"
    if delta_signature:
        payload = f"{payload}:{delta_signature}"
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"find-{kind[:3]}-{h}"


def upsert_finding(
    es: Elasticsearch,
    index: str,
    *,
    finding: dict[str, Any],
) -> str:
    """Upsert a single finding, preserving analyst-managed fields.

    `finding` must contain at minimum: kind, artifact{kind,value},
    score, evidence, narrative, run_id. The writer:

    - Computes `finding_id` deterministically and uses it as the doc id.
    - Reads any existing doc to capture `status`, `status_history`,
      and `first_seen_at`. If absent, status defaults to `"new"`,
      history to `[]`, `first_seen_at` to now.
    - Writes the union: miner-owned fields from `finding`,
      analyst-owned fields carried forward from the existing doc.

    Returns the finding_id written.
    """
    kind = finding["kind"]
    artifact = finding["artifact"]
    fid = finding_id(
        kind, artifact["kind"], artifact["value"],
        delta_signature=finding.get("delta_signature"),
    )

    try:
        existing = es.get(index=index, id=fid)
        src = existing.get("_source") or {}
    except Exception:
        src = {}

    status = src.get("status") or "new"
    status_history = src.get("status_history") or []
    first_seen_at = src.get("first_seen_at") or _now_iso()

    doc = {
        "finding_id":      fid,
        "kind":            kind,
        "run_id":          finding.get("run_id"),
        "artifact":        artifact,
        "score":           float(finding.get("score") or 0.0),
        "narrative":       finding.get("narrative") or "",
        "status":          status,
        "status_history":  status_history,
        "first_seen_at":   first_seen_at,
        "last_seen_at":    _now_iso(),
        "evidence":        finding.get("evidence") or {},
        "linked_artifacts": finding.get("linked_artifacts") or [],
    }
    es.index(index=index, id=fid, document=doc, refresh=False)
    return fid


def bulk_upsert_findings(
    es: Elasticsearch,
    index: str,
    findings: Iterable[dict[str, Any]],
    *,
    batch_size: int = 100,
) -> int:
    """Faster path for the miner — bulk-index after a single mget for
    existing analyst state. Returns the count successfully indexed.

    Order:
      1. compute every finding_id
      2. mget the existing docs in one round-trip
      3. merge analyst fields into the new docs
      4. bulk-index in batches

    The per-finding `upsert_finding` is kept for the status-mutation
    code path (the console PATCH endpoint) where bulk isn't needed.
    """
    findings = list(findings)
    if not findings:
        return 0

    ids: list[str] = []
    keyed: list[tuple[str, dict[str, Any]]] = []
    for f in findings:
        kind = f["kind"]
        a = f["artifact"]
        fid = finding_id(
            kind, a["kind"], a["value"],
            delta_signature=f.get("delta_signature"),
        )
        ids.append(fid)
        keyed.append((fid, f))

    existing_by_id: dict[str, dict[str, Any]] = {}
    try:
        resp = es.mget(index=index, ids=ids)
        for d in resp.get("docs") or []:
            if d.get("found"):
                existing_by_id[d["_id"]] = d.get("_source") or {}
    except Exception as exc:
        log.warning("findings: mget for analyst-state preservation failed: %s", exc)

    now = _now_iso()
    actions: list[dict[str, Any]] = []
    for fid, f in keyed:
        src = existing_by_id.get(fid) or {}
        doc = {
            "finding_id":      fid,
            "kind":            f["kind"],
            "run_id":          f.get("run_id"),
            "artifact":        f["artifact"],
            "score":           float(f.get("score") or 0.0),
            "narrative":       f.get("narrative") or "",
            "status":          src.get("status") or "new",
            "status_history":  src.get("status_history") or [],
            "first_seen_at":   src.get("first_seen_at") or now,
            "last_seen_at":    now,
            "evidence":        f.get("evidence") or {},
            "linked_artifacts": f.get("linked_artifacts") or [],
        }
        if f.get("delta_signature"):
            doc["delta_signature"] = f["delta_signature"]
        if f.get("narrative_source"):
            doc["narrative_source"] = f["narrative_source"]
        if f.get("narrative_confidence") is not None:
            doc["narrative_confidence"] = f["narrative_confidence"]
        actions.append({"_op_type": "index", "_index": index, "_id": fid, "_source": doc})

    success = 0
    for i in range(0, len(actions), batch_size):
        chunk = actions[i:i + batch_size]
        try:
            ok, _ = bulk(es, chunk, raise_on_error=False, request_timeout=60)
            success += ok
        except Exception as exc:
            log.warning("findings bulk-index batch failed: %s", exc)
    return success


def mutate_status(
    es: Elasticsearch,
    index: str,
    finding_id_: str,
    *,
    new_status: str,
    note: str = "",
    cfg: Any = None,
) -> dict[str, Any]:
    """Transition a finding's status. Appends a history entry; rejects
    unknown statuses. Returns the updated doc body.

    Called from the console's POST endpoint, not the miner.

    When `cfg` is supplied, Findings v2 step 2 lifecycle side effects fire
    based on (kind classification, transition):

      | Action     | Coverage         | Drift                              |
      |------------|------------------|------------------------------------|
      | → confirmed| append anchor    | append new anchor (rebaseline)     |
      | → rejected | clear anchors    | record drift_suppression           |

    Discovery findings have no lifecycle side effect. `ack` / `new`
    transitions are no-ops on lifecycle state.
    """
    if new_status not in _VALID_STATUSES:
        raise ValueError(f"invalid status: {new_status!r} (valid: {sorted(_VALID_STATUSES)})")
    try:
        resp = es.get(index=index, id=finding_id_)
    except Exception as exc:
        raise LookupError(f"finding not found: {finding_id_}") from exc
    src = resp.get("_source") or {}
    prev = src.get("status") or "new"
    if prev == new_status:
        return src
    history = src.get("status_history") or []
    history.append({
        "ts": _now_iso(),
        "from": prev,
        "to":   new_status,
        "note": note or "",
    })
    src["status"] = new_status
    src["status_history"] = history
    es.index(index=index, id=finding_id_, document=src, refresh="wait_for")

    if cfg is not None:
        try:
            _apply_lifecycle_side_effects(es, cfg, finding=src)
        except Exception as exc:
            log.warning(
                "lifecycle side effect for finding %s (status=%s) failed: %s",
                finding_id_, new_status, exc,
            )
    return src


def add_note(
    es: Elasticsearch,
    index: str,
    finding_id_: str,
    *,
    note: str,
) -> dict[str, Any]:
    """Append a free-text note to a finding without changing its status.

    Records as a status_history entry with `from == to == current_status`
    so the audit trail stays one structured field. Empty notes are
    rejected — there's no useful behaviour for adding a blank entry.

    Drives the inbox drawer's "Add note" path (ROADMAP #17.4 amended).
    """
    if not note or not note.strip():
        raise ValueError("note must be non-empty")
    try:
        resp = es.get(index=index, id=finding_id_)
    except Exception as exc:
        raise LookupError(f"finding not found: {finding_id_}") from exc
    src = resp.get("_source") or {}
    current = src.get("status") or "new"
    history = src.get("status_history") or []
    history.append({
        "ts":   _now_iso(),
        "from": current,
        "to":   current,
        "note": note.strip(),
    })
    src["status_history"] = history
    es.index(index=index, id=finding_id_, document=src, refresh="wait_for")
    return src


def _apply_lifecycle_side_effects(es: Elasticsearch, cfg: Any, *, finding: dict[str, Any]) -> None:
    """Dispatch lifecycle writes triggered by a status change. Routes by
    `(kind_classification, status)` per the Findings v2 design table.

    Coverage findings (`playbook` / `campaign`):
      - confirmed → analyst anchor appended
      - rejected  → all anchors (analyst + provisional) removed

    Drift findings:
      - confirmed → new analyst anchor (rebaseline)
      - rejected  → drift_suppressions[] entry keyed by delta_signature

    Discovery findings (and unknown kinds): no-op.
    """
    from .lifecycle import (
        build_anchor_payload,
        kind_classification,
        record_drift_suppression,
        remove_anchors_by_source,
        write_confirm_anchor,
    )
    kind = finding.get("kind")
    artifact = finding.get("artifact") or {}
    artifact_kind = artifact.get("kind")
    artifact_id = artifact.get("value")
    status = finding.get("status")
    fid = finding.get("finding_id")

    if not kind or not artifact_kind or not artifact_id:
        return
    if artifact_kind not in ("playbook", "campaign"):
        return  # IP / URL / etc. — no lifecycle doc

    classification = kind_classification(kind)
    f_idx = cfg.findings.indexes
    lc_index = (
        f_idx.playbook_lifecycle if artifact_kind == "playbook"
        else f_idx.campaign_lifecycle
    )

    if classification == "coverage":
        if status == "confirmed":
            anchor = build_anchor_payload(
                es, cfg,
                artifact_kind=artifact_kind, artifact_id=artifact_id,
                source="analyst", confirming_finding_id=fid,
            )
            write_confirm_anchor(es, lc_index, artifact_id=artifact_id, anchor=anchor)
        elif status == "rejected":
            # Clear analyst AND provisional anchors. "Reject" means
            # "stop tracking drift on this artifact entirely." A future
            # confirm reinstates a fresh anchor (rebaseline).
            remove_anchors_by_source(es, lc_index, artifact_id=artifact_id, source="analyst")
            remove_anchors_by_source(es, lc_index, artifact_id=artifact_id, source="provisional")
        return

    if classification == "drift":
        if status == "confirmed":
            # Rebaseline: append a fresh analyst anchor that captures
            # the *current* signatures (after the drift the analyst just
            # acknowledged as real).
            anchor = build_anchor_payload(
                es, cfg,
                artifact_kind=artifact_kind, artifact_id=artifact_id,
                source="analyst", confirming_finding_id=fid,
            )
            write_confirm_anchor(es, lc_index, artifact_id=artifact_id, anchor=anchor)
        elif status == "rejected":
            delta_sig = finding.get("delta_signature") or (finding.get("evidence") or {}).get("delta_signature")
            if delta_sig:
                record_drift_suppression(
                    es, lc_index,
                    artifact_id=artifact_id,
                    delta_signature=delta_sig,
                    kind=kind,
                )
            else:
                log.warning(
                    "drift finding %s rejected but no delta_signature on doc; suppression not recorded",
                    fid,
                )
        return
    # discovery / unknown — no lifecycle side effect.


def valid_statuses() -> frozenset[str]:
    return _VALID_STATUSES
