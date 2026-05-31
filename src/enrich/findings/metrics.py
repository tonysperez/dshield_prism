"""Per-thresholded-quantity percentile-distribution writer
(brutal-review phase 4.1).

Each ``compute_threshold_distributions(es, cfg)`` call queries ES for
the per-run distribution of every registered thresholded quantity,
computes ``{p50, p75, p90, p95, p99, n}``, and returns one metrics doc
per quantity. The dispatcher (``write_threshold_distributions``)
persists the docs into ``cfg.metrics.indexes.default``. Subsequent
phase-4 commits (4.2 / 4.3 / 4.4) replace hardcoded threshold values
in evidence_quality.py / discovery.py with percentile lookups against
the latest doc.

Adding a new quantity is a one-line registration: write a
``(es, cfg) -> list[float]`` function and append it to
``_THRESHOLD_QUANTITIES`` with its kind + layer labels. The writer
shape is the contract; the inventory doc
(``eval/threshold-inventory.md``) catalogs what's pending.

Defensive against missing indices (intel deploys can be partial) —
each computer returns an empty list when its source index doesn't
exist or carries no data, and the writer skips empty distributions.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable

import numpy as np
from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Distribution computers — one per thresholded quantity
# ---------------------------------------------------------------------------

def _last_snapshot_field(es: Elasticsearch, lifecycle_index: str,
                        field: str) -> list[float]:
    """Pull `snapshots[-1].<field>` for every doc in `lifecycle_index`.

    Uses a nested top_hits agg per parent doc to grab the most recent
    snapshot — cheaper than scrolling every doc and extracting the
    last element of `snapshots[]` client-side. Returns an empty list
    when the index doesn't exist or no docs have populated snapshots.
    """
    if not es.indices.exists(index=lifecycle_index):
        return []
    body = {
        "size":  500,
        "_source": False,
        "query": {
            "nested": {
                "path":  "snapshots",
                "query": {"exists": {"field": f"snapshots.{field}"}},
                "inner_hits": {
                    "size":    1,
                    "sort":    [{"snapshots.@timestamp": {"order": "desc"}}],
                    "_source": [f"snapshots.{field}"],
                },
            }
        },
    }
    out: list[float] = []
    try:
        resp = es.search(index=lifecycle_index, **body)
    except Exception as exc:  # noqa: BLE001
        log.warning("threshold-distribution: lifecycle scan on %s failed: %s",
                    lifecycle_index, exc)
        return []
    for h in resp.get("hits", {}).get("hits", []):
        inner = (h.get("inner_hits") or {}).get("snapshots", {})
        inner_hits = (inner.get("hits") or {}).get("hits") or []
        if not inner_hits:
            continue
        # ES strips the nested-path prefix from inner_hits `_source`
        # partial selections — the response shape is `_source:
        # {<field>: <value>}`, not `_source: {snapshots: {<field>: ...}}`.
        src = inner_hits[0].get("_source") or {}
        v = src.get(field)
        if v is None:
            continue
        out.append(float(v))
    return out


def _playbook_session_count_per_run(es: Elasticsearch, cfg) -> list[float]:
    """Distribution of latest-snapshot session counts across every
    playbook lifecycle doc. Feeds 4.2's evidence_quality band migration —
    Strong / Moderate / Single-point bands become percentile lookups."""
    return _last_snapshot_field(
        es, cfg.findings.indexes.playbook_lifecycle, "session_count",
    )


def _playbook_ip_count_per_run(es: Elasticsearch, cfg) -> list[float]:
    """Distribution of latest-snapshot IP counts across every
    playbook lifecycle doc. Feeds the IP-axis half of 4.2's
    evidence_quality band migration."""
    return _last_snapshot_field(
        es, cfg.findings.indexes.playbook_lifecycle, "ip_count",
    )


# ---------------------------------------------------------------------------
# Registry + dispatcher
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _QuantitySpec:
    kind:  str  # discriminator on the metrics doc; consumers filter on this
    layer: str  # which pipeline layer the quantity lives in
    fn:    Callable[[Elasticsearch, object], list[float]]


# Registered quantity computers. Phase 4.1 ships two; 4.2 / 4.3 / 4.4
# each append their own computer alongside their consumer change. The
# inventory doc (eval/threshold-inventory.md) tracks what's pending.
_THRESHOLD_QUANTITIES: tuple[_QuantitySpec, ...] = (
    _QuantitySpec(
        kind="playbook_session_count_per_run",
        layer="playbook_lifecycle",
        fn=_playbook_session_count_per_run,
    ),
    _QuantitySpec(
        kind="playbook_ip_count_per_run",
        layer="playbook_lifecycle",
        fn=_playbook_ip_count_per_run,
    ),
)


def _distribution_doc(*, kind: str, layer: str, values: Iterable[float]) -> dict:
    """Build the canonical metrics doc shape for a value distribution.
    The `prism.metrics` mapping is strict-dynamic with `{run_id,
    generated_at, kind, layer, p50, p75, p90, p95, p99, n}` — this
    function emits exactly that shape."""
    arr = np.array(list(values), dtype=np.float64)
    return {
        "run_id":       str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kind":         kind,
        "layer":        layer,
        "p50":          round(float(np.percentile(arr, 50)), 4),
        "p75":          round(float(np.percentile(arr, 75)), 4),
        "p90":          round(float(np.percentile(arr, 90)), 4),
        "p95":          round(float(np.percentile(arr, 95)), 4),
        "p99":          round(float(np.percentile(arr, 99)), 4),
        "n":            int(arr.size),
    }


def compute_threshold_distributions(es: Elasticsearch, cfg) -> list[dict]:
    """Run every registered quantity computer; produce one metrics doc
    per quantity that had ≥1 value. Empty distributions are dropped
    silently (the operator notices via the count vs. the inventory)."""
    out: list[dict] = []
    for spec in _THRESHOLD_QUANTITIES:
        try:
            values = spec.fn(es, cfg)
        except Exception as exc:  # noqa: BLE001 — best-effort observability
            log.warning("threshold-distribution: %s computer failed: %s",
                        spec.kind, exc)
            continue
        if not values:
            log.info("threshold-distribution: %s produced no values; skip",
                     spec.kind)
            continue
        out.append(_distribution_doc(
            kind=spec.kind, layer=spec.layer, values=values,
        ))
    return out


def write_threshold_distributions(es: Elasticsearch, cfg) -> dict:
    """Compute + persist the distribution docs. Returns
    ``{written, kinds, errors}`` for the CLI to print."""
    metrics_idx = cfg.metrics.indexes.default
    if not es.indices.exists(index=metrics_idx):
        log.warning(
            "threshold-distribution: metrics index %s does not exist; "
            "run `init-indexes --source metrics` first",
            metrics_idx,
        )
        return {"written": 0, "kinds": [], "errors": ["metrics_index_missing"]}
    docs = compute_threshold_distributions(es, cfg)
    written = 0
    errors: list[str] = []
    kinds: list[str] = []
    for doc in docs:
        try:
            es.index(index=metrics_idx, document=doc)
            written += 1
            kinds.append(doc["kind"])
        except Exception as exc:  # noqa: BLE001
            log.warning("threshold-distribution: write failed (%s): %s",
                        doc.get("kind"), exc)
            errors.append(f"{doc.get('kind')}: {type(exc).__name__}")
    return {"written": written, "kinds": kinds, "errors": errors}
