"""I3.0 — DShield-firewall corpus-expansion probe (Prism-side cross-reference).

Phase I3 ingests the DShield firewall log (every connection attempt to the
sensor, not just the SSH/telnet ports Cowrie emulates). This measures the
payoff: how many unique source IPs the firewall log carries that are NOT
already in the Cowrie IP corpus (`prism.rollup.cowrie.ip`). That delta is the
plan's corpus-expansion number, and it gates the I3 build (soft gate: < 2×).

The DShield localdshield.log is batched JSON — one line per submission,
`{"type":"firewall","logs":[{time,flags,sip,dip,proto,sport,dport,version},…],
"authheader":…}`. We parse `logs[].sip` and ignore everything else. The
`authheader` is the operator's DShield API credential — this script never reads,
prints, or stores it.

This runs on the workstation with ES access; the operator copies the sensor's
`localdshield.log*` here (or extracts the IP list with
`jq -r '.logs[].sip' localdshield.log* | sort -u`).

    console/.venv/bin/python scripts/probe_dshield_corpus_expansion.py \\
        --dshield-log /path/to/localdshield.log /path/to/localdshield.log.1
    console/.venv/bin/python scripts/probe_dshield_corpus_expansion.py \\
        --ips-file /path/to/unique_sips.txt
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_MGET_BATCH = 1000


def _parse_dshield_logs(paths: list[Path]) -> tuple[set[str], Counter, int]:
    """Return (unique sips, dport distribution, total firewall events).

    Only `logs[].sip` / `logs[].dport` are touched; `authheader` is ignored.
    """
    sips: set[str] = set()
    dports: Counter = Counter()
    events = 0
    for p in paths:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for ev in rec.get("logs") or []:
                    sip = ev.get("sip")
                    if not sip:
                        continue
                    events += 1
                    sips.add(sip)
                    dp = ev.get("dport")
                    if dp is not None:
                        dports[str(dp)] += 1
    return sips, dports, events


def _read_ips_file(path: Path) -> set[str]:
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s:
            out.add(s)
    return out


def _split_public(ips: set[str]) -> tuple[set[str], int]:
    """Drop RFC1918/loopback/etc. — only routable source IPs count as corpus."""
    public: set[str] = set()
    skipped = 0
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            skipped += 1
            continue
        if addr.is_global:
            public.add(ip)
        else:
            skipped += 1
    return public, skipped


def _overlap_with_cowrie(es, idx: str, ips: list[str]) -> int:
    """Count how many `ips` already have a Cowrie IP-rollup doc (id == ip)."""
    found = 0
    for i in range(0, len(ips), _MGET_BATCH):
        batch = ips[i:i + _MGET_BATCH]
        resp = es.mget(index=idx, ids=batch, _source=False)
        found += sum(1 for d in resp["docs"] if d.get("found"))
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dshield-log", type=Path, nargs="*", default=[],
                    help="raw localdshield.log file(s) (batched JSON)")
    ap.add_argument("--ips-file", type=Path, default=None,
                    help="newline-delimited source IPs (alternative to --dshield-log)")
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    args = ap.parse_args()

    if not args.dshield_log and not args.ips_file:
        ap.error("provide --dshield-log <file...> or --ips-file <file>")

    dports: Counter = Counter()
    events = 0
    if args.dshield_log:
        raw_sips, dports, events = _parse_dshield_logs(args.dshield_log)
    else:
        raw_sips = _read_ips_file(args.ips_file)

    public, skipped = _split_public(raw_sips)
    public_list = sorted(public)

    cfg = load_config()
    es = make_client(cfg.elasticsearch, load_secrets())
    ipr = cfg.elasticsearch.indexes.cowrie.ips_rollup
    cowrie_total = es.count(index=ipr)["count"]

    overlap = _overlap_with_cowrie(es, ipr, public_list)
    new = len(public_list) - overlap
    expansion = new / cowrie_total if cowrie_total else 0.0
    combined = cowrie_total + new
    ratio = len(public_list) / cowrie_total if cowrie_total else 0.0

    if expansion >= 2.0:
        verdict = (f"PROCEED — +{new} new IPs = {expansion:.1f}× the Cowrie corpus "
                   f"(≥ 2× gate). Build I3.1.")
    elif expansion >= 1.0:
        verdict = (f"PROCEED (moderate) — +{new} new IPs = {expansion:.1f}× expansion.")
    else:
        verdict = (f"MARGINAL — +{new} new IPs = {expansion:.2f}× (< 2× soft gate); "
                   "escalate to operator before building I3.")

    out = ["# I3.0 — DShield-firewall corpus-expansion probe", ""]
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    src = (", ".join(p.name for p in args.dshield_log)
           if args.dshield_log else args.ips_file.name)
    out.append(f"Source: `{src}`" + (f" · {events} firewall events parsed" if events else ""))
    out.append("")
    out.append(f"- unique source IPs in log: **{len(raw_sips)}** "
               f"(public/routable: {len(public_list)}; dropped non-global: {skipped})")
    out.append(f"- Cowrie IP corpus (`{ipr}`): **{cowrie_total}**")
    out.append(f"- already in Cowrie (overlap): **{overlap}**")
    out.append(f"- **NEW IPs (firewall-only): {new}**")
    out.append(f"- raw ratio (firewall unique / Cowrie): **{ratio:.1f}×**")
    out.append(f"- **corpus-expansion factor (new / Cowrie): {expansion:.1f}×** "
               f"→ combined corpus ≈ {combined}")
    out.append("")
    out.append(f"## I3.0 verdict: {verdict}")
    if dports:
        out.append("")
        out.append("## Top destination ports hit (firewall) — non-2222/23 = beyond Cowrie's view")
        out.append("")
        out.append("| dport | events |")
        out.append("|---|---:|")
        for port, n in dports.most_common(25):
            out.append(f"| {port} | {n} |")
    md = "\n".join(out)
    print(md)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    p = args.output_dir / f"I3-corpus-expansion-{ts}.md"
    p.write_text(md, encoding="utf-8")
    print(f"\nwrote {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
