"""ES heap / circuit-breaker backpressure helpers.

The pipeline runs against Elasticsearch nodes of very different sizes. On a
heap-constrained node a heavy aggregation / scan / bulk can trip the parent
circuit breaker (HTTP 429 ``circuit_breaking_exception``). The client transport
retries those within milliseconds — far too fast for the breaker to drain — and
then raises, hard-failing a pipeline step.

These helpers let every ES call (see ``ResilientClient`` in ``es_client``) ride a
single overload-retry path: on a breaker rejection, poll the node's parent-breaker
ratio, wait for heap to drain, then retry with exponential backoff. The patience
budget is a single shared wall-clock deadline per operation — we'd rather wait a
long time than fail a step.

Everything here is best-effort and ES-version-tolerant: probing never raises, and
overload detection falls back to string matching when client internals differ.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")

# Substrings that mark a response as "node is overloaded, back off and retry"
# rather than a genuine client error. Matched case-insensitively against the
# exception's string form as a version-tolerant fallback to status inspection.
_OVERLOAD_MARKERS = (
    "circuit_breaking_exception",
    "es_rejected_execution_exception",
    "too_many_requests",
    "data too large",
)


def _status_of(exc: BaseException) -> int | None:
    """Best-effort HTTP status extraction across elasticsearch-py versions."""
    for attr in ("status_code", "status"):
        val = getattr(exc, attr, None)
        if isinstance(val, int):
            return val
    meta = getattr(exc, "meta", None)
    status = getattr(meta, "status", None)
    return status if isinstance(status, int) else None


def is_overload_error(exc: BaseException) -> bool:
    """True when ``exc`` is an ES "node is overloaded" signal (429 / parent
    circuit breaker / write-queue rejection) — i.e. retryable after backoff,
    not a genuine client/query error."""
    if _status_of(exc) == 429:
        return True
    text = str(exc).lower()
    return any(marker in text for marker in _OVERLOAD_MARKERS)


def parent_breaker_ratio(es: Any) -> float | None:
    """Return the max over nodes of ``parent.estimated/limit`` from
    ``_nodes/stats/breaker``, or ``None`` if it can't be determined.

    Best-effort: never raises. ``es`` should be the *unwrapped* client (the
    probe must not itself be routed through the retry wrapper)."""
    try:
        resp = es.nodes.stats(metric="breaker")
    except Exception:
        return None
    try:
        nodes = (resp or {}).get("nodes") or {}
        best: float | None = None
        for node in nodes.values():
            parent = ((node or {}).get("breakers") or {}).get("parent") or {}
            limit = parent.get("limit_size_in_bytes")
            used = parent.get("estimated_size_in_bytes")
            if not limit or used is None:
                continue
            ratio = float(used) / float(limit)
            if best is None or ratio > best:
                best = ratio
    except Exception:
        return None
    return best


def _raw(es: Any) -> Any:
    """The unwrapped client to probe with (avoid recursive retry while we're
    trying to measure pressure)."""
    return getattr(es, "_raw", es)


def wait_for_capacity(
    es: Any,
    bp: Any,
    *,
    label: str,
    deadline: float | None = None,
) -> None:
    """Block while the node's parent-breaker ratio is at/above the high
    watermark, until it drains below the resume watermark or the patience
    budget (``deadline``, default ``now + bp.max_wait_s``) elapses.

    No-op when backpressure is disabled or the ratio can't be read."""
    if bp is None or not getattr(bp, "enabled", False):
        return
    if deadline is None:
        deadline = time.monotonic() + bp.max_wait_s
    raw = _raw(es)
    ratio = parent_breaker_ratio(raw)
    if ratio is None or ratio < bp.heap_high_watermark:
        return
    warned = False
    while ratio is not None and ratio >= bp.heap_resume_watermark:
        if time.monotonic() >= deadline:
            log.warning(
                "ES heap still at %.0f%% after waiting; proceeding with %s anyway",
                ratio * 100, label,
            )
            return
        if not warned:
            log.warning(
                "ES heap at %.0f%% (>= %.0f%%); pausing before %s until it drains",
                ratio * 100, bp.heap_high_watermark * 100, label,
            )
            warned = True
        time.sleep(bp.poll_interval_s)
        ratio = parent_breaker_ratio(raw)
    if warned:
        log.info("ES heap recovered (%.0f%%); resuming %s",
                 (ratio or 0.0) * 100, label)


def run_resilient(
    fn: Callable[[], T],
    es: Any,
    bp: Any,
    *,
    label: str,
) -> T:
    """Run ``fn()``; on an ES overload error, wait for heap to drain then retry
    with exponential backoff, until success or the shared ``max_wait_s`` deadline
    (and ``retry_max_attempts`` ceiling) is hit. Non-overload errors propagate
    immediately. When backpressure is disabled, this is a plain ``fn()`` call."""
    if bp is None or not getattr(bp, "enabled", False):
        return fn()
    deadline = time.monotonic() + bp.max_wait_s
    attempt = 0
    while True:
        try:
            return fn()
        except Exception as exc:
            if not is_overload_error(exc):
                raise
            attempt += 1
            remaining = deadline - time.monotonic()
            if attempt >= bp.retry_max_attempts or remaining <= 0:
                log.error(
                    "ES overload on %s persisted after %d attempt(s) / %.0fs; giving up",
                    label, attempt, bp.max_wait_s,
                )
                raise
            log.warning("ES overload on %s (attempt %d): %s", label, attempt, exc)
            wait_for_capacity(es, bp, label=label, deadline=deadline)
            # Exponential backoff, capped and clamped to the remaining budget.
            delay = min(
                bp.retry_max_delay_s,
                bp.retry_base_delay_s * (2 ** (attempt - 1)),
            )
            delay = max(0.0, min(delay, deadline - time.monotonic()))
            if delay:
                time.sleep(delay)
