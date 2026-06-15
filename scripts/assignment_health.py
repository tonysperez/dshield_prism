"""Cutover health check — read-only summary of the live Option-A assignment state.

After the cutover, run this over a few backward cycles to confirm steady-state health at
a glance: the assigned/novel split, whether the assignment runner is actually firing, the
novel-pool size (the HDBSCAN minting input), null-playbook sessions, and anchor-library
growth/retirements. Surfaces flags for the obvious failure modes (runner idle, novel pool
runaway, novel/null mismatch).

Read-only; aggregates (counts) only. public-only filter BY DEFAULT (0 on the untagged
corpus); `--allow-unclassified` is an OPERATOR decision.

    console/.venv/bin/python scripts/assignment_health.py
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_STATUS = f"{_S}.cluster.assignment_status"
_ASSIGNED_AT = f"{_S}.cluster.assignment_at"
_PB = f"{_S}.playbook_id"
_EMB = f"{_S}.embedding"


def summarize(raw: dict) -> dict:
    """Pure: raw counts → rates + health flags. `raw` keys: total, status_assigned,
    status_novel, has_playbook, assigned_last_day, anchors, retired_anchors,
    anchors_minted_last_week."""
    total = raw["total"]

    def rate(x):
        return round(x / total, 4) if total else None

    novel = raw["status_novel"]
    null_pb = total - raw["has_playbook"]
    flags = []
    nr = rate(novel)
    if nr is not None and nr > 0.10:
        flags.append("novel_rate_high(>10%) — anchors stale or τ too high?")
    if total and raw["assigned_last_day"] == 0:
        flags.append("no assignment writes in 24h — runner idle / not wired into the pipeline?")
    # novels have playbook_id cleared, so null_pb should be >= novel; a large excess means
    # sessions the runner hasn't reached yet (e.g. mid-backfill).
    if novel and null_pb > novel * 2:
        flags.append("null-playbook sessions >> novel — unprocessed sessions (backfill in flight?)")
    return {
        "total_sessions": total,
        "assigned_rate": rate(raw["status_assigned"]),
        "novel_rate": nr,
        "novel_pool_size": novel,
        "null_playbook": null_pb,
        "no_assignment_status": total - raw["status_assigned"] - novel,
        "assigned_last_24h": raw["assigned_last_day"],
        "anchors_active": raw["anchors"],
        "anchors_retired": raw["retired_anchors"],
        "anchors_minted_last_7d": raw["anchors_minted_last_week"],
        "flags": flags or ["ok"],
    }


def _count(es, idx, filt, extra=None):
    q = {"bool": {"filter": filt + ([extra] if extra else [])}}
    return es.count(index=idx, query=q)["count"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--allow-unclassified", action="store_true",
                    help="OPERATOR ONLY: drop the public-only filter. Agent never sets it.")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    anch = cfg.elasticsearch.indexes.cowrie.playbook_anchors

    base = [] if args.allow_unclassified else [releasable_filter(cfg)]
    emb = [{"exists": {"field": _EMB}}]
    filt = base + emb

    raw = {
        "total": _count(es, idx, filt),
        "status_assigned": _count(es, idx, filt, {"term": {_STATUS: "assigned"}}),
        "status_novel": _count(es, idx, filt, {"term": {_STATUS: "novel"}}),
        "has_playbook": _count(es, idx, filt, {"exists": {"field": _PB}}),
        "assigned_last_day": _count(es, idx, filt, {"range": {_ASSIGNED_AT: {"gte": "now-1d"}}}),
        "anchors": es.count(index=anch, query={"exists": {"field": "anchor_centroid"}})["count"],
        "retired_anchors": es.count(index=anch, query={"exists": {"field": "retired_centroid"}})["count"],
        "anchors_minted_last_week": es.count(
            index=anch, query={"range": {"first_seen": {"gte": "now-7d"}}})["count"],
    }
    print(json.dumps(summarize(raw), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
