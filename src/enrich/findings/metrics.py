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


def _campaign_convergence_ratio(es: Elasticsearch, cfg) -> list[float]:
    """Distribution of IP-overlap ratios across every (behaviour campaign)
    × (infrastructure campaign) pair whose intersection is non-empty.
    Feeds 4.4's `convergence_min_ip_overlap_ratio` migration — the
    corpus-p75 becomes the new firing cutoff.

    Mirrors `mine_campaign_convergence` exactly: same source index,
    same kind partition, same denominator `min(|bhv|, |inf|)`, same
    non-empty-intersection filter. Pairs with empty intersection are
    skipped (the miner skips them too — they're not convergence
    candidates at all, and including their 0.0 ratio would swamp the
    percentile with a degenerate population).
    """
    cidx = cfg.elasticsearch.indexes.cowrie.campaigns
    if not es.indices.exists(index=cidx):
        return []
    bhv: list[set[str]] = []
    inf: list[set[str]] = []
    body = {
        "size":    500,
        "_source": ["kind", "member_source_ips"],
        "query":   {"term": {"doc_type": "campaign"}},
        "sort":    [{"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=cidx, **body)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "threshold-distribution: campaign scan on %s failed: %s",
                cidx, exc,
            )
            return []
        hits = (resp.get("hits") or {}).get("hits") or []
        if not hits:
            break
        for h in hits:
            src = h.get("_source") or {}
            kind = (src.get("kind") or "").lower()
            ips = src.get("member_source_ips") or []
            if not ips:
                continue
            s = set(ips)
            if kind in ("behaviour", "behavior"):
                bhv.append(s)
            elif kind in ("infrastructure", "infra"):
                inf.append(s)
        search_after = hits[-1].get("sort")
        if not search_after:
            break
    out: list[float] = []
    for b in bhv:
        for i in inf:
            inter = b & i
            if not inter:
                continue
            denom = min(len(b), len(i))
            if denom <= 0:
                continue
            out.append(len(inter) / denom)
    return out


def _ip_behavior_shift_js(es: Elasticsearch, cfg) -> list[float]:
    """Distribution of per-IP JS distance between the latest snapshot's
    ``playbook_distribution`` and the union of prior snapshots — the
    quantity that ``mine_ip_behavior_shift`` thresholds on. Feeds 4.3's
    `ip_shift_js_distance_min` migration: the corpus-p90 of this
    distribution becomes the new firing cutoff.

    Filter mirrors the miner exactly (``runs_observed >= 2``) so the
    percentile reflects the population the threshold actually gates.
    Sources the lifecycle docs in scan order with ``_doc`` tiebreak —
    not a paginated UI surface, so no need to sort by time.
    """
    from .discovery import _jensen_shannon  # reuse the miner's math
    lc_idx = cfg.findings.indexes.source_ip_lifecycle
    if not es.indices.exists(index=lc_idx):
        return []
    body = {
        "_source": ["snapshots"],
        "query":   {"range": {"runs_observed": {"gte": 2}}},
        "size":    500,
        "sort":    [{"_doc": "asc"}],
    }
    out: list[float] = []
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=lc_idx, **body)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "threshold-distribution: ip_behavior_shift_js scan on %s "
                "failed: %s", lc_idx, exc,
            )
            return []
        hits = (resp.get("hits") or {}).get("hits") or []
        if not hits:
            break
        for h in hits:
            src = h.get("_source") or {}
            snaps = src.get("snapshots") or []
            if len(snaps) < 2:
                continue
            curr_dist = snaps[-1].get("playbook_distribution") or {}
            prior_dist: dict[str, float] = {}
            for s in snaps[:-1]:
                for k, v in (s.get("playbook_distribution") or {}).items():
                    prior_dist[k] = prior_dist.get(k, 0.0) + float(v)
            if not curr_dist or not prior_dist:
                continue
            out.append(float(_jensen_shannon(prior_dist, curr_dist)))
        search_after = hits[-1].get("sort")
        if not search_after:
            break
    return out


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
    _QuantitySpec(
        kind="ip_behavior_shift_js",
        layer="source_ip_lifecycle",
        fn=_ip_behavior_shift_js,
    ),
    _QuantitySpec(
        kind="campaign_convergence_ratio",
        layer="campaigns",
        fn=_campaign_convergence_ratio,
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
