"""I1.0 — field-presence viability probe for currently-dropped Cowrie events.

Prism's ingest promotes a subset of Cowrie's `cowrie.json` event stream to
ECS and drops the rest. The Phase I plan (`docs/handoff-upstream-
instrumentation-plan.md`) proposes promoting several of those dropped event
kinds — chiefly `direct-tcpip` (honeypot-as-proxy abuse, a behavioural
category that is currently *invisible*) and `command.success`/`failed`
(attacker reaction to a faked failure). Before any ingest-pipeline work, this
measures whether the signal is actually present on this sensor.

Read-only — runs purely off ES aggregations over the raw event index
(`prism.raw.cowrie.session`), no full pull, no writes. Cowrie's `eventid`
lands in `event.action` after ingest (see
`setup/es-pipelines/cowrie-pipeline.yml`), so coverage is the count of
*distinct sessions* carrying at least one event of each kind, over the total
distinct sessions in the window.

Reports the I1.0 decision inputs:
  * full event.action inventory (so we see exactly which kinds this Cowrie
    build emits — a 0 for a probed kind is itself a finding)
  * distinct-session coverage + raw event count per dropped kind of interest
  * the hard-gate inputs: direct-tcpip.request session share and the
    command.success/failed (union) session share

Decision (I1.0, hard gate):
  * direct-tcpip.request coverage < 0.1% of sessions AND command
    success/failed coverage < 5% of sessions  → signal too sparse, STOP.
  * otherwise → PROCEED to I1.1 (note which signal cleared the gate).

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/probe_dropped_cowrie_fields.py
    console/.venv/bin/python scripts/probe_dropped_cowrie_fields.py --days 365
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_ACTION = "event.action"
_SID = "cowrie.session_id"
# cardinality precision ceiling — denominator is ~corpus-scale so this is an
# approximation (a few % error); the rare per-kind subsets count exactly.
_PRECISION = 40000

# Dropped (or only-partially-promoted) event kinds the I1 plan targets, plus
# the per-session markers used as denominators / cross-checks.
_PROBE_KINDS = {
    "direct_tcpip_request": "cowrie.direct-tcpip.request",
    "direct_tcpip_data": "cowrie.direct-tcpip.data",
    "tcpip_forward": "cowrie.tcpip-forward",
    "command_success": "cowrie.command.success",
    "command_failed": "cowrie.command.failed",
    "command_input": "cowrie.command.input",
    "client_size": "cowrie.client.size",
    "client_var": "cowrie.client.var",
    "log_closed": "cowrie.log.closed",
    "connect": "cowrie.session.connect",
}

# Hard-gate thresholds (I1.0).
_DT_GATE = 0.001   # direct-tcpip.request session share floor
_CMD_GATE = 0.05   # command success/failed (union) session share floor


def _sessions(es, idx: str, query: dict, sub_filter: dict | None) -> int:
    """Distinct-session cardinality for `query` AND optional `sub_filter`."""
    must = [query]
    if sub_filter is not None:
        must.append(sub_filter)
    r = es.search(index=idx, size=0, query={"bool": {"filter": must}}, aggs={
        "s": {"cardinality": {"field": _SID, "precision_threshold": _PRECISION}}
    })
    return int(r["aggregations"]["s"]["value"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--days", type=int, default=30,
                    help="look-back window in days (0 = all history)")
    ap.add_argument("--top", type=int, default=50,
                    help="event.action inventory size")
    args = ap.parse_args()

    cfg = load_config()
    es = make_client(cfg.elasticsearch, load_secrets())
    idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    if args.days > 0:
        window = {"range": {"@timestamp": {"gte": f"now-{args.days}d"}}}
        window_desc = f"last {args.days}d"
    else:
        window = {"match_all": {}}
        window_desc = "all history"

    # Total distinct sessions in the window (gate denominator) + connect-event
    # count as an exact per-session cross-check, + the full action inventory.
    base = es.search(index=idx, size=0, query=window, aggs={
        "total_sessions": {
            "cardinality": {"field": _SID, "precision_threshold": _PRECISION}},
        "actions": {"terms": {"field": _ACTION, "size": args.top}},
    })
    total = int(base["aggregations"]["total_sessions"]["value"])
    inventory = base["aggregations"]["actions"]["buckets"]

    # Per-kind: distinct-session coverage + raw event doc_count.
    rows: dict[str, dict] = {}
    for name, action in _PROBE_KINDS.items():
        flt = {"term": {_ACTION: action}}
        sess = _sessions(es, idx, window, flt)
        docs = es.count(index=idx, query={
            "bool": {"filter": [window, flt]}})["count"]
        rows[name] = {"action": action, "sessions": sess, "events": docs,
                      "share": (sess / total if total else 0.0)}

    # Union shares used by the gate (a session can carry both success+failed).
    cmd_union = _sessions(es, idx, window, {"terms": {
        _ACTION: ["cowrie.command.success", "cowrie.command.failed"]}})
    dt_union = _sessions(es, idx, window, {"terms": {
        _ACTION: ["cowrie.direct-tcpip.request", "cowrie.direct-tcpip.data"]}})
    cmd_share = cmd_union / total if total else 0.0
    dt_req_share = rows["direct_tcpip_request"]["share"]

    if dt_req_share < _DT_GATE and cmd_share < _CMD_GATE:
        verdict = (f"STOP — direct-tcpip.request {dt_req_share:.3%} < {_DT_GATE:.1%} "
                   f"AND command success/failed {cmd_share:.2%} < {_CMD_GATE:.0%}; "
                   "signal too sparse to justify the I1 ingest build.")
    else:
        cleared = []
        if dt_req_share >= _DT_GATE:
            cleared.append(f"direct-tcpip.request {dt_req_share:.3%}")
        if cmd_share >= _CMD_GATE:
            cleared.append(f"command success/failed {cmd_share:.2%}")
        verdict = "PROCEED to I1.1 — gate cleared by: " + ", ".join(cleared) + "."

    out = ["# I1.0 — dropped-Cowrie-field presence probe", ""]
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_ · index "
               f"`{idx}` · window **{window_desc}**")
    out.append("")
    out.append(f"- distinct sessions in window: **{total}** "
               f"(connect events: {rows['connect']['events']}, "
               f"~approx, cardinality precision {_PRECISION})")
    out.append("")
    out.append("## Coverage of targeted dropped event kinds")
    out.append("")
    out.append("| field / event kind | event.action | sessions | session share | raw events |")
    out.append("|---|---|---:|---:|---:|")
    # Order the table by the plan's interest, drop the denominators to the end.
    order = ["direct_tcpip_request", "direct_tcpip_data", "tcpip_forward",
             "command_success", "command_failed", "client_size", "client_var",
             "log_closed", "command_input", "connect"]
    for name in order:
        r = rows[name]
        out.append(f"| {name} | `{r['action']}` | {r['sessions']} | "
                   f"{r['share']:.3%} | {r['events']} |")
    out.append("")
    out.append(f"- **direct-tcpip (request∪data) sessions:** {dt_union} "
               f"({dt_union / total if total else 0.0:.3%})")
    out.append(f"- **command success∪failed sessions:** {cmd_union} "
               f"({cmd_share:.2%})")
    out.append("")
    out.append(f"## I1.0 verdict: {verdict}")
    out.append("")
    out.append(f"## Full `event.action` inventory (top {args.top}, window {window_desc})")
    out.append("")
    out.append("| event.action | events |")
    out.append("|---|---:|")
    for b in inventory:
        out.append(f"| `{b['key']}` | {b['doc_count']} |")
    md = "\n".join(out)
    print(md)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    p = args.output_dir / f"I1-field-presence-{ts}.md"
    p.write_text(md, encoding="utf-8")
    print(f"\nwrote {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
