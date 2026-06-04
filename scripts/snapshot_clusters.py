"""Snapshot (and diff) the cluster / playbook / campaign analytical layer
(backlog B3.8 — post-hoc audits).

Captures a compact, content-addressed picture of the analytical state to JSON so
two points in time can be diffed: the `spb-` / `cmp-` identity sets (which are
deterministic content hashes, so they *should* reproduce on a rebuild of the
same corpus), session/IP cluster shape, and finding counts. Use it to:

  * snapshot before a `--force` rebuild or backfill, then diff after (did identity
    reproduce? did the cluster shape stay sane?);
  * keep a pre-flip-to-forward audit point for the real backlog.

Read-only against ES. Run from the repo root via the console venv:
    snapshot:  python scripts/snapshot_clusters.py snapshot --out before.json
    diff:      python scripts/snapshot_clusters.py diff before.json after.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client


def _latest_run_summary(es, idx: str) -> dict:
    """`{window_days, n_clusters, total_docs, @timestamp}` of the newest run."""
    try:
        r = es.search(index=idx, size=1,
                      query={"term": {"doc_type": "run_summary"}},
                      sort=[{"@timestamp": {"order": "desc"}}],
                      _source=["@timestamp", "window_days", "n_clusters", "total_docs"])
        h = r["hits"]["hits"]
        return h[0]["_source"] if h else {}
    except Exception:
        return {}


def _count(es, idx, query=None) -> int:
    try:
        return es.count(index=idx, query=query or {"match_all": {}})["count"]
    except Exception:
        return -1


def take_snapshot(cfg, config_path: str) -> dict:
    import datetime as _dt

    es = make_client(cfg.elasticsearch, load_secrets(config_path))
    c = cfg.elasticsearch.indexes.cowrie
    snap: dict = {"captured_at": _dt.datetime.now(_dt.timezone.utc).isoformat()}

    # Playbooks — the spb- identity set (write-once anchors) + session counts.
    anchors = es.search(index=c.playbook_anchors, size=1000,
                        _source=["playbook_id", "playbook_name"],
                        query={"match_all": {}})["hits"]["hits"]
    pb_sessions = es.search(index=c.sessions_rollup, size=0, aggs={
        "pb": {"terms": {"field": "dshield.cowrie.enrichment.session.playbook_id",
                         "size": 1000}}})["aggregations"]["pb"]["buckets"]
    pb_count = {b["key"]: b["doc_count"] for b in pb_sessions}
    snap["playbooks"] = {
        h["_source"]["playbook_id"]: {
            "name": h["_source"].get("playbook_name", ""),
            "sessions": pb_count.get(h["_source"]["playbook_id"], 0),
        }
        for h in anchors
    }

    # Campaigns — cmp- (content-hashed) ids + kind.
    camps = es.search(index=c.campaigns, size=1000, _source=["campaign_id", "kind"],
                      query={"term": {"doc_type": "campaign"}})["hits"]["hits"]
    snap["campaigns"] = {h["_source"]["campaign_id"]: h["_source"].get("kind")
                         for h in camps}

    # Cluster shape (session + IP).
    sc = es.search(index=c.sessions_rollup, size=0, aggs={
        "n": {"cardinality": {"field": "dshield.cowrie.enrichment.session.cluster.id"}}}
    )["aggregations"]["n"]["value"]
    snap["session_clusters"] = {
        "distinct_assigned_ids": sc,
        "latest_run": _latest_run_summary(es, c.session_clusters),
    }
    snap["ip_clusters"] = {
        "embedded_ips": _count(es, c.ips_rollup, {
            "exists": {"field": "dshield.cowrie.enrichment.ip.embedding"}}),
        "latest_run": _latest_run_summary(es, c.ip_clusters),
    }

    # Findings — total + by kind.
    by_kind = es.search(index=cfg.findings.indexes.default, size=0, aggs={
        "k": {"terms": {"field": "kind", "size": 50}}})["aggregations"]["k"]["buckets"]
    snap["findings"] = {
        "total": _count(es, cfg.findings.indexes.default),
        "by_kind": {b["key"]: b["doc_count"] for b in by_kind},
    }
    return snap


def _print_diff(a: dict, b: dict) -> None:
    def _idset(s, key):
        return set((s.get(key) or {}).keys())

    print(f"A captured {a.get('captured_at', '?')}")
    print(f"B captured {b.get('captured_at', '?')}\n")

    for layer in ("playbooks", "campaigns"):
        ka, kb = _idset(a, layer), _idset(b, layer)
        shared, gone, new = ka & kb, ka - kb, kb - ka
        print(f"[{layer}] A={len(ka)} B={len(kb)}  shared={len(shared)} "
              f"gone={len(gone)} new={len(new)}")
        if gone:
            print(f"    gone: {sorted(gone)}")
        if new:
            print(f"    new:  {sorted(new)}")

    sa, sb = a.get("session_clusters", {}), b.get("session_clusters", {})
    print(f"[session_clusters] distinct_assigned_ids "
          f"{sa.get('distinct_assigned_ids')} -> {sb.get('distinct_assigned_ids')} "
          f"| latest_run n_clusters "
          f"{sa.get('latest_run', {}).get('n_clusters')} -> "
          f"{sb.get('latest_run', {}).get('n_clusters')} "
          f"(window_days {sa.get('latest_run', {}).get('window_days')} -> "
          f"{sb.get('latest_run', {}).get('window_days')})")
    ia, ib = a.get("ip_clusters", {}), b.get("ip_clusters", {})
    print(f"[ip_clusters] embedded_ips {ia.get('embedded_ips')} -> "
          f"{ib.get('embedded_ips')}")
    fa, fb = a.get("findings", {}), b.get("findings", {})
    print(f"[findings] total {fa.get('total')} -> {fb.get('total')} "
          f"| by_kind {fa.get('by_kind')} -> {fb.get('by_kind')}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="capture the analytical layer to JSON")
    s.add_argument("--config", default="config/default.yaml")
    s.add_argument("--out", type=Path, default=None,
                   help="write JSON here (default: stdout)")
    d = sub.add_parser("diff", help="diff two snapshot JSON files")
    d.add_argument("a", type=Path)
    d.add_argument("b", type=Path)
    args = ap.parse_args()

    if args.cmd == "snapshot":
        cfg = load_config(args.config)
        snap = take_snapshot(cfg, args.config)
        text = json.dumps(snap, indent=2, sort_keys=True)
        if args.out:
            args.out.write_text(text)
            print(f"wrote {args.out}  "
                  f"({len(snap['playbooks'])} playbooks, "
                  f"{len(snap['campaigns'])} campaigns)")
        else:
            print(text)
        return 0

    _print_diff(json.loads(args.a.read_text()), json.loads(args.b.read_text()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
