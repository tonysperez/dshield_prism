"""I1.4 — measurement: do the promoted Cowrie fields surface anything new?

Reads the production session rollup (post-deploy) and quantifies the Phase I1
signal:
  * population share of `proxy_request_count > 0` and `command_failure_count > 0`
  * failed-command rate among command-bearing sessions (the I1.0 raw-event
    probe estimated ~87%; this confirms it from the rollup)
  * top proxy targets (nested terms agg over `proxy_attempts.target_ip`)
  * **cluster concentration** — for sessions that attempted a proxy relay, which
    session clusters do they fall in, and where is proxy-use > 50% of a
    cluster's members? Those are candidate *new behavioural categories* the
    command-stream embedding never saw.

Adoption is an analyst go/no-go on the candidate clusters, not a numeric gate
(per the plan): if the proxy clusters are real new behaviour, I1 becomes
load-bearing; if null, the fields stay captured but unread by clustering.

Read-only, live ES. Run from the repo root via the console venv:
    console/.venv/bin/python scripts/measure_I1_effect.py
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_SB = "dshield.cowrie.enrichment.session"
_PROXY = f"{_SB}.proxy_request_count"
_PROXY_DATA = f"{_SB}.proxy_data_count"
_CMD_FAIL = f"{_SB}.command_failure_count"
_CMD_COUNT = f"{_SB}.command_count"
_CLUSTER = f"{_SB}.cluster.id"
_TARGET = f"{_SB}.proxy_attempts.target_ip.keyword"
_PROXY_PATH = f"{_SB}.proxy_attempts"


def _count(es, idx, q) -> int:
    return es.count(index=idx, query=q)["count"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--concentration-floor", type=float, default=0.50,
                    help="cluster proxy-share above which a cluster is a candidate")
    ap.add_argument("--min-proxy-in-cluster", type=int, default=2)
    args = ap.parse_args()

    cfg = load_config()
    es = make_client(cfg.elasticsearch, load_secrets())
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup

    total = _count(es, idx, {"match_all": {}})
    cmd_bearing = _count(es, idx, {"range": {_CMD_COUNT: {"gt": 0}}})
    proxy_pop = _count(es, idx, {"range": {_PROXY: {"gt": 0}}})
    fail_pop = _count(es, idx, {"range": {_CMD_FAIL: {"gt": 0}}})

    out = ["# I1.4 — effect measurement: promoted Cowrie fields", ""]
    out.append(f"_Captured {datetime.now(UTC).isoformat()}_ · index `{idx}`")
    out.append("")
    out.append(f"- total rollup sessions: **{total}**")
    out.append(f"- command-bearing (command_count > 0): **{cmd_bearing}**")

    if proxy_pop == 0 and fail_pop == 0:
        out.append("")
        out.append("## NOT YET POPULATED")
        out.append("")
        out.append("Neither `proxy_request_count` nor `command_failure_count` is "
                   "populated on any rollup doc. Deploy I1.1–I1.3 "
                   "(`init-indexes --update-mapping` first, then the rollup code), "
                   "run one backward cycle, and re-run this script.")
        md = "\n".join(out)
        print(md)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        p = args.output_dir / f"I1-effect-{ts}.md"
        p.write_text(md, encoding="utf-8")
        print(f"\nwrote {p}")
        return 0

    # --- population shares ---
    fail_rate = fail_pop / cmd_bearing if cmd_bearing else 0.0
    out.append(f"- sessions with a proxy relay attempt: **{proxy_pop}** "
               f"({proxy_pop / total if total else 0:.3%} of all)")
    out.append(f"- sessions with ≥1 failed command: **{fail_pop}** "
               f"(**{fail_rate:.1%}** of command-bearing)")
    out.append("")

    # --- top proxy targets (nested agg) ---
    out.append("## Top proxy targets")
    out.append("")
    r = es.search(index=idx, size=0, query={"range": {_PROXY: {"gt": 0}}}, aggs={
        "p": {"nested": {"path": _PROXY_PATH},
              "aggs": {"t": {"terms": {"field": _TARGET, "size": 25}}}}})
    tbuckets = r["aggregations"]["p"]["t"]["buckets"]
    out.append("| target ip | attempts |")
    out.append("|---|---:|")
    for b in tbuckets:
        out.append(f"| `{b['key']}` | {b['doc_count']} |")
    out.append("")

    # --- cluster concentration ---
    out.append("## Cluster concentration of proxy-using sessions")
    out.append("")
    # proxy sessions per cluster
    pr = es.search(index=idx, size=0, query={"range": {_PROXY: {"gt": 0}}}, aggs={
        "c": {"terms": {"field": _CLUSTER, "size": 200}}})
    proxy_by_cluster = {b["key"]: b["doc_count"]
                        for b in pr["aggregations"]["c"]["buckets"]}
    # total members per cluster (need sizes to compute share)
    sizes: dict = {}
    if proxy_by_cluster:
        cr = es.search(index=idx, size=0, query={"exists": {"field": _CLUSTER}}, aggs={
            "c": {"terms": {"field": _CLUSTER,
                            "size": max(1000, len(proxy_by_cluster) * 4)}}})
        sizes = {b["key"]: b["doc_count"] for b in cr["aggregations"]["c"]["buckets"]}

    rows = []
    for cid, pcount in proxy_by_cluster.items():
        size = sizes.get(cid, pcount)
        share = pcount / size if size else 0.0
        rows.append((cid, pcount, size, share))
    rows.sort(key=lambda x: (-x[3], -x[1]))

    candidates = [r for r in rows
                  if r[3] >= args.concentration_floor and r[1] >= args.min_proxy_in_cluster]
    out.append(f"Clusters where proxy-use ≥ {args.concentration_floor:.0%} of members "
               f"AND ≥ {args.min_proxy_in_cluster} proxy sessions — candidate new "
               "behavioural categories for analyst review:")
    out.append("")
    out.append("| cluster id | proxy sessions | cluster size | proxy share |")
    out.append("|---|---:|---:|---:|")
    if candidates:
        for cid, pcount, size, share in candidates:
            out.append(f"| `{cid}` | {pcount} | {size} | {share:.0%} |")
    else:
        out.append("| _(none cleared the floor)_ | | | |")
    out.append("")
    out.append("Full proxy-by-cluster spread (top 15 by proxy count):")
    out.append("")
    out.append("| cluster id | proxy sessions | cluster size | proxy share |")
    out.append("|---|---:|---:|---:|")
    for cid, pcount, size, share in sorted(rows, key=lambda x: -x[1])[:15]:
        out.append(f"| `{cid}` | {pcount} | {size} | {share:.0%} |")
    out.append("")
    out.append("**Decision (analyst go/no-go).** If the candidate clusters are "
               "real proxy-abuse behaviour the command-stream embedding misses, "
               "adopt I1 (the rollup field becomes load-bearing — fold proxy "
               "activity into the session scalar block). If null, the fields stay "
               "captured but unread by clustering. Render candidates via "
               "`scripts/inspect_small_clusters.py`.")

    md = "\n".join(out)
    print(md)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    p = args.output_dir / f"I1-effect-{ts}.md"
    p.write_text(md, encoding="utf-8")
    print(f"\nwrote {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
