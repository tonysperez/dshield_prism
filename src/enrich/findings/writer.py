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

from .lifecycle import RUN_ID_UNSET

log = logging.getLogger(__name__)


_VALID_STATUSES: frozenset[str] = frozenset({"new", "ack", "confirmed", "rejected"})

#: Max ids per `mget` / actions per `_bulk` on the status-mutation path.
#: Matches `helpers.bulk`'s own default so driving the chunking here changes
#: request shape not at all — it only makes a failure attributable.
_BULK_STATUS_CHUNK = 500


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
    refresh: bool | str = False,
) -> dict[str, Any]:
    """Transition a finding's status. Appends a history entry; rejects
    unknown statuses. Returns the updated doc body.

    Called from the console's POST endpoint, not the miner.

    `refresh` is passed straight to `es.index`. It defaults to `False`:
    the caller owns visibility and issues one `es.indices.refresh()` per
    request instead of paying the index's `refresh_interval` per document.

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
    es.index(index=index, id=finding_id_, document=src, refresh=refresh)

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
    refresh: bool | str = False,
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
    es.index(index=index, id=finding_id_, document=src, refresh=refresh)
    return src


def bulk_mutate_status(
    es: Elasticsearch,
    index: str,
    ids: Iterable[str],
    *,
    new_status: str,
    note: str = "",
    cfg: Any = None,
) -> tuple[int, list[dict[str, Any]]]:
    """Apply one status to many findings in two ES round-trips.

    The per-id `mutate_status` loop cost `2N` round-trips plus `N` blocking
    refreshes; this is one `mget`, one `bulk`, and one `indices.refresh`
    regardless of N. Returns `(n_updated, errors)` where `errors` is a list
    of `{"id", "error"}` — a missing or unwritable id fails only itself.

    Semantics deliberately mirror `mutate_status`:
      - an invalid `new_status` raises `ValueError` **before any ES call**
        (the caller maps it to one HTTP 400 for the whole request)
      - `prev == new_status` writes nothing but still counts as updated
      - lifecycle side effects are per-finding and logged-and-swallowed
      - duplicate ids collapse to one transition
    """
    if new_status not in _VALID_STATUSES:
        raise ValueError(f"invalid status: {new_status!r} (valid: {sorted(_VALID_STATUSES)})")
    ids = list(ids)
    if not ids:
        return 0, []

    errors: list[dict[str, Any]] = []
    existing: dict[str, dict[str, Any]] = {}
    errored: set[str] = set()

    def _fail(fid: str, msg: str) -> None:
        errored.add(fid)
        errors.append({"id": fid, "error": msg})

    # Chunked so one oversized selection can't build a single request that
    # exceeds `http.max_content_length`, and so a transport failure costs
    # its chunk rather than the whole batch.
    for i in range(0, len(ids), _BULK_STATUS_CHUNK):
        chunk_ids = ids[i:i + _BULK_STATUS_CHUNK]
        try:
            resp = es.mget(index=index, ids=chunk_ids)
        except Exception as exc:
            log.warning("findings bulk status mget failed: %s", exc)
            for fid in chunk_ids:
                _fail(fid, f"{exc.__class__.__name__}: {exc}")
            continue
        for d in resp.get("docs") or []:
            if not d.get("found"):
                continue
            src = d.get("_source")
            if not src:
                # An indexed doc with no readable source: writing the
                # computed transition would replace the finding with a
                # two-field stub, erasing kind / artifact / evidence.
                _fail(d["_id"], "empty _source; refusing to overwrite")
                continue
            existing[d["_id"]] = src

    now = _now_iso()
    n_updated = 0
    actions: list[dict[str, Any]] = []
    mutated: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for fid in ids:
        if fid in seen or fid in errored:
            continue
        seen.add(fid)
        src = existing.get(fid)
        if src is None:
            _fail(fid, f"finding not found: {fid}")
            continue
        prev = src.get("status") or "new"
        if prev == new_status:
            n_updated += 1          # no-op: nothing written, still counted
            continue
        history = src.get("status_history") or []
        history.append({
            "ts": now,
            "from": prev,
            "to":   new_status,
            "note": note or "",
        })
        src["status"] = new_status
        src["status_history"] = history
        actions.append({"_op_type": "index", "_index": index, "_id": fid, "_source": src})
        mutated.append((fid, src))

    # `helpers.bulk` chunks internally and re-raises transport errors even
    # under `raise_on_error=False`, so an exception says nothing about the
    # chunks that already committed. Drive the chunking here instead: a
    # failure is then attributable to exactly the ids in its own chunk.
    failed_ids: set[str] = set()
    n_written = 0
    for i in range(0, len(actions), _BULK_STATUS_CHUNK):
        chunk = actions[i:i + _BULK_STATUS_CHUNK]
        try:
            ok, bulk_errs = bulk(
                es, chunk, raise_on_error=False,
                chunk_size=_BULK_STATUS_CHUNK, request_timeout=60,
            )
        except Exception as exc:
            log.warning("findings bulk status write failed: %s", exc)
            for a in chunk:
                failed_ids.add(a["_id"])
                errors.append({"id": a["_id"], "error": f"{exc.__class__.__name__}: {exc}"})
            continue
        n_written += int(ok)
        for e in bulk_errs or []:
            info = (next(iter(e.values()), {}) if isinstance(e, dict) and e else {}) or {}
            efid = info.get("_id")
            msg = str(info.get("error") or "bulk index failed")
            if not efid:
                # Unattributable failure. Fail the whole chunk rather than
                # let a side effect fire on a doc that may not have landed.
                log.warning("findings bulk status error carried no _id: %r", e)
                for a in chunk:
                    failed_ids.add(a["_id"])
                errors.append({"id": "", "error": msg})
                continue
            failed_ids.add(efid)
            errors.append({"id": efid, "error": msg})
    n_updated += n_written

    if actions:
        # One forced refresh for the whole request — the console reloads
        # immediately after and must see every transition. Skipped when
        # nothing was written; there is nothing to make visible.
        try:
            es.indices.refresh(index=index)
        except Exception as exc:
            log.warning("findings refresh after bulk status write failed: %s", exc)

    survivors = [(fid, src) for fid, src in mutated if fid not in failed_ids]
    if cfg is not None and survivors:
        # Batch-invariant, and only the confirm path builds anchors — so
        # resolve it once, there, and pass it down even when it is None.
        # Resolved after `survivors`: a batch that wrote nothing has no
        # anchor to key, so it should not pay the lookup either.
        from .lifecycle import latest_cluster_run_id
        run_id: Any = RUN_ID_UNSET
        if new_status == "confirmed":
            run_id = latest_cluster_run_id(es, cfg)
        for fid, src in survivors:
            try:
                _apply_lifecycle_side_effects(es, cfg, finding=src, confirmed_run_id=run_id)
            except Exception as exc:
                log.warning(
                    "lifecycle side effect for finding %s (status=%s) failed: %s",
                    fid, new_status, exc,
                )
    return n_updated, errors


def _apply_lifecycle_side_effects(
    es: Elasticsearch,
    cfg: Any,
    *,
    finding: dict[str, Any],
    confirmed_run_id: Any = RUN_ID_UNSET,
) -> None:
    """Dispatch lifecycle writes triggered by a status change. Routes by
    `(kind_classification, status)` per the Findings v2 design table.

    `confirmed_run_id` is the batch-invariant latest cluster run. Bulk
    callers resolve it once and pass it in; when None the anchor builder
    resolves it itself (one search per anchor).

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
                confirmed_run_id=confirmed_run_id,
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
                confirmed_run_id=confirmed_run_id,
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
