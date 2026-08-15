"""Smoke test for pure-function bits of the milestone-1 intel providers.

Covers:
  - `feodotracker.parse_feodo_response` — list + dict-wrapped shapes,
    defensive against unknown payloads.
  - `firehol.parse_firehol_netset` — file-format parse: comments,
    CIDRs, bare IPs, IPv6, malformed lines.
  - `firehol.match_firehol` — exact-IP hit, CIDR hit, miss, IPv6
    handling.
  - `isc.parse_isc_response` — list-of-objects + wrapped-dict shapes.
  - `isc.confidence_from_reports` — report count → 1-10 band.

Network paths (Tor exit-list download, FeodoTracker JSON, FireHOL
netset, ISC API) are NOT exercised here — those are integration
concerns validated post-deploy by the `healthcheck --scope intel`
verb.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_providers.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.intel.providers.feodotracker import parse_feodo_response
from enrich.intel.providers.firehol import match_firehol, parse_firehol_netset
from enrich.intel.providers.isc import confidence_from_reports, parse_isc_response

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# -----------------------------------------------------------------------------
# FeodoTracker
# -----------------------------------------------------------------------------

print("[1] FeodoTracker.parse_feodo_response — canonical list shape")
parsed = parse_feodo_response([
    {"ip_address": "1.2.3.4", "port": 443, "status": "online",
     "malware": "Emotet", "first_seen": "2026-04-12 14:23:01"},
    {"ip_address": "5.6.7.8", "port": 8080, "status": "online",
     "malware": "TrickBot"},
])
check("two rows", len(parsed) == 2)
check("keyed by ip", "1.2.3.4" in parsed and "5.6.7.8" in parsed)
check("preserves malware family",
      parsed["1.2.3.4"]["malware"] == "Emotet")
check("preserves port",
      parsed["5.6.7.8"]["port"] == 8080)


print("\n[2] FeodoTracker.parse_feodo_response — wrapped {data:[...]} shape")
parsed = parse_feodo_response({"data": [{"ip_address": "9.9.9.9", "port": 80}]})
check("wrapped data: extracted",
      "9.9.9.9" in parsed and parsed["9.9.9.9"]["port"] == 80)


print("\n[3] FeodoTracker.parse_feodo_response — defensive: bad shapes return empty")
check("string input", parse_feodo_response("bogus") == {})
check("None input", parse_feodo_response(None) == {})
check("rows without ip_address",
      parse_feodo_response([{"port": 443}]) == {})
check("alternate key: `ip`",
      parse_feodo_response([{"ip": "8.8.8.8", "port": 443}]).get("8.8.8.8") is not None)


# -----------------------------------------------------------------------------
# FireHOL
# -----------------------------------------------------------------------------

print("\n[4] FireHOL.parse_firehol_netset — mixed content")
sample = """\
# firehol_level1
#
# (header metadata...)

1.2.3.4
5.6.7.0/24
10.0.0.0/8
# inline comment
not-a-real-line
192.0.2.1
2001:db8::/32
"""
exact_ips, networks = parse_firehol_netset(sample)
check("exact IP collected", "1.2.3.4" in exact_ips)
check("another exact IP collected", "192.0.2.1" in exact_ips)
check("only 2 exact IPs", len(exact_ips) == 2)
check("CIDR count == 3 (incl IPv6 + bogon ranges)",
      len(networks) == 3,
      f"got {len(networks)}: {[str(n) for n in networks]}")
check("malformed lines ignored",
      "not-a-real-line" not in exact_ips)


print("\n[5] FireHOL.match_firehol — exact-IP hit, CIDR hit, miss")
matched, net = match_firehol("1.2.3.4", exact_ips, networks)
check("exact hit: matched", matched is True)
check("exact hit: no network returned", net is None)
matched, net = match_firehol("5.6.7.42", exact_ips, networks)
check("CIDR hit: matched", matched is True)
check("CIDR hit: returns network", net == "5.6.7.0/24")
matched, net = match_firehol("99.99.99.99", exact_ips, networks)
check("miss: not matched", matched is False)
check("miss: no network", net is None)


print("\n[6] FireHOL.match_firehol — IPv6 + bogon (10.0.0.0/8 trap)")
# 10.x is a private range BUT it IS in the sample netset, so the
# matcher should match it. The canonicaliser would have rejected the
# query upstream, but the matcher itself must not pre-judge.
matched, net = match_firehol("10.42.0.1", exact_ips, networks)
check("matcher itself doesn't filter privates",
      matched is True and net == "10.0.0.0/8")
matched, net = match_firehol("2001:db8::dead", exact_ips, networks)
check("ipv6 cidr hit", matched is True and net == "2001:db8::/32")
matched, net = match_firehol("bogus-ip", exact_ips, networks)
check("non-IP input rejected gracefully",
      matched is False and net is None)


print("\n[7] FireHOL.parse_firehol_netset — blanks and empty file")
exact_ips, networks = parse_firehol_netset("")
check("empty file: nothing", len(exact_ips) == 0 and len(networks) == 0)
exact_ips, networks = parse_firehol_netset("\n\n\n# header only\n#\n")
check("comments-only: nothing", len(exact_ips) == 0 and len(networks) == 0)


# -----------------------------------------------------------------------------
# ISC (unchanged — kept for regression coverage)
# -----------------------------------------------------------------------------

print("\n[8] ISC.parse_isc_response — list-of-objects shape")
parsed = parse_isc_response([
    {"source": "1.2.3.4", "reports": 1000, "targets": 50},
    {"source": "5.6.7.8", "reports": 200},
])
check("two rows", len(parsed) == 2)
check("keyed by ip", "1.2.3.4" in parsed and "5.6.7.8" in parsed)
check("row preserves reports",
      parsed["1.2.3.4"]["reports"] == 1000)


print("\n[9] ISC.parse_isc_response — wrapped {data: [...]} shape")
parsed = parse_isc_response({"data": [{"source": "9.9.9.9", "reports": 5}]})
check("wrapped data: extracted",
      "9.9.9.9" in parsed and parsed["9.9.9.9"]["reports"] == 5)


print("\n[10] ISC.parse_isc_response — defensive: bad shapes return empty")
check("string input", parse_isc_response("bogus") == {})
check("None input", parse_isc_response(None) == {})
check("rows without `source`", parse_isc_response([{"foo": "bar"}]) == {})
check("alternate keys: `ip`",
      parse_isc_response([{"ip": "8.8.8.8", "reports": 1}]).get("8.8.8.8") is not None)


print("\n[11] ISC.confidence_from_reports — band mapping")
check("0 reports → 1", confidence_from_reports(0) == 1)
check("1 report → 4 (floor)", confidence_from_reports(1) == 4)
check("100 reports ~ 6",
      confidence_from_reports(100) >= 6 and confidence_from_reports(100) <= 7,
      f"got {confidence_from_reports(100)}")
check("1M reports clamps to 10", confidence_from_reports(1_000_000) == 10)


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
