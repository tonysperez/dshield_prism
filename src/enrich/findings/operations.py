"""Operations miner (brutal-review phase 7.1).

An "operation" is a merged `cmp-bhv ∪ cmp-inf` pair where the IPs
attributed to the behaviour campaign and the IPs attributed to the
infrastructure campaign overlap enough that they're plausibly the same
actor doing both.

The mining logic is the same shape as
:func:`enrich.findings.discovery.mine_campaign_convergence` — pairwise
compare every bhv against every inf, compute
`|bhv ∩ inf| / min(|bhv|, |inf|)`, gate on the corpus-derived p75 — but
the *output* is different. Convergence emits a `kind=campaign_convergence`
*finding* (an alert). Operations promote the same signal to a
*first-class persisted entity* in `prism.operations` with a stable id
``op-<16hex>`` content-addressed on ``sorted([bhv_id, inf_id])``.

That stability lets downstream code (the graph anchor type 'operation'
in 7.2, the `operation_emergence` finding kind in 7.3, future
attribution joins) reference operations across runs without churn.

Re-mines upsert into the same `_id` so analyst-visible state attached
to an operation (when it lands in 7.2's graph anchor pane) survives
re-mining cleanly.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

from ..es_client import init_index, make_client

log = logging.getLogger(__name__)


_MAPPING_PATH = "setup/es-mappings/cowrie/operations.json"


def _operation_id(bhv_id: str, inf_id: str) -> str:
    """Stable, content-addressed operation id. Two campaigns produce
    the same id regardless of ordering, so re-mines converge."""
    payload = ",".join(sorted([bhv_id, inf_id]))
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"op-{h}"


def _scroll_campaigns(es: Elasticsearch, idx: str):
    """Yield every doc_type=campaign source. Search-after on _doc."""
    body = {
        "size": 500,
        "_source": [
            "campaign_id", "name", "kind", "member_source_ips",
            "first_seen", "last_seen",
        ],
        "query": {"term": {"doc_type": "campaign"}},
        "sort": [{"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=idx, **body)
        except Exception as exc:  # noqa: BLE001
            log.warning("operations: campaign scroll failed: %s", exc)
            return
        hits = (resp.get("hits") or {}).get("hits") or []
        if not hits:
            return
        for h in hits:
            yield h.get("_source") or {}
        search_after = hits[-1].get("sort")
        if not search_after:
            return


def _earliest(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Lexicographic min of ISO timestamps; None-safe."""
    if not a:
        return b
    if not b:
        return a
    return a if a < b else b


def _latest(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if not a:
        return b
    if not b:
        return a
    return a if a > b else b


def run_mine_operations(cfg: Any, secrets: Any, dry_run: bool = False) -> dict[str, Any]:
    """Walk every (bhv, inf) campaign pair, promote those whose IP
    overlap clears the corpus-p75 threshold to operation docs.

    Returns stats: ``{run_id, pairs_evaluated, operations_minted,
    threshold_used, fallback_used, bulk_ok, bulk_errors, dry_run}``.
    """
    from .discovery import _convergence_ratio_cutoff

    es = make_client(cfg.elasticsearch, secrets)
    cidx = cfg.elasticsearch.indexes.cowrie.campaigns
    ops_idx = cfg.elasticsearch.indexes.cowrie.operations

    stats: dict[str, Any] = {
        "run_id":            str(uuid.uuid4()),
        "dry_run":           dry_run,
        "pairs_evaluated":   0,
        "operations_minted": 0,
        "threshold_used":    None,
        "fallback_used":     False,
        "bulk_ok":           0,
        "bulk_errors":       0,
    }
    if not es.indices.exists(index=cidx):
        log.info("operations: campaigns index %s missing; nothing to do", cidx)
        return stats

    # Same threshold logic as `mine_campaign_convergence` (4.4) — the
    # signal is identical; we're persisting it under a different name.
    ratio_fallback = float(getattr(getattr(cfg.findings, "discovery", None),
                                   "convergence_min_ip_overlap_ratio", 0.4))
    ratio_p75 = _convergence_ratio_cutoff(es, cfg)
    stats["fallback_used"] = ratio_p75 is None
    ratio_min = ratio_p75 if ratio_p75 is not None else ratio_fallback
    stats["threshold_used"] = round(float(ratio_min), 6)

    bhv: list[dict] = []
    inf: list[dict] = []
    for src in _scroll_campaigns(es, cidx):
        kind = (src.get("kind") or "").lower()
        ips = src.get("member_source_ips") or []
        if not ips:
            continue
        entry = {
            "id":         src.get("campaign_id"),
            "name":       src.get("name"),
            "ips":        set(ips),
            "first_seen": src.get("first_seen"),
            "last_seen":  src.get("last_seen"),
        }
        if kind in ("behaviour", "behavior"):
            bhv.append(entry)
        elif kind in ("infrastructure", "infra"):
            inf.append(entry)

    now_iso = datetime.now(timezone.utc).isoformat()
    actions: list[dict] = []
    for b in bhv:
        for i in inf:
            stats["pairs_evaluated"] += 1
            inter = b["ips"] & i["ips"]
            if not inter:
                continue
            denom = min(len(b["ips"]), len(i["ips"]))
            ratio = len(inter) / denom if denom > 0 else 0.0
            if ratio < ratio_min:
                continue
            op_id = _operation_id(b["id"], i["id"])
            actions.append({
                "_op_type":  "index",
                "_index":    ops_idx,
                "_id":       op_id,
                "_source": {
                    "@timestamp":         now_iso,
                    "run_id":             stats["run_id"],
                    "operation_id":       op_id,
                    "behaviour_id":       b["id"],
                    "behaviour_name":     b.get("name") or "",
                    "infrastructure_id":  i["id"],
                    "infrastructure_name": i.get("name") or "",
                    "member_source_ips":  sorted(inter),
                    "bhv_ip_count":       len(b["ips"]),
                    "inf_ip_count":       len(i["ips"]),
                    "shared_ip_count":    len(inter),
                    "overlap_ratio":      round(ratio, 6),
                    "overlap_threshold":  stats["threshold_used"],
                    "first_seen":         _earliest(b.get("first_seen"), i.get("first_seen")),
                    "last_seen":          _latest(b.get("last_seen"), i.get("last_seen")),
                },
            })
            stats["operations_minted"] += 1

    if dry_run:
        log.info("operations dry-run: %s", stats)
        return stats

    init_index(es, _MAPPING_PATH, ops_idx)
    if actions:
        try:
            n_ok, errs = bulk(es, actions, raise_on_error=False)
            stats["bulk_ok"] = n_ok
            stats["bulk_errors"] = len(errs) if isinstance(errs, list) else 0
            es.indices.refresh(index=ops_idx)
        except Exception as exc:  # noqa: BLE001
            log.warning("operations: bulk write failed: %s", exc)
            stats["bulk_errors"] = len(actions)
    log.info("operations mined: %s", stats)
    return stats
