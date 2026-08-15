"""Smoke test for console-side URL artifact pane helpers (M4).

Covers the pure-function bits of `console/src/console/intel.py`:
  - `_canonical_url` — URL normalization mirror of the pipeline's.
  - `_extract_host_ip` — IP-literal host extraction for the cross-ref.

The ES-talking `fetch_intel_url` orchestration is verified
post-deploy via live API hits.

Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_url_console.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "console" / "src"))

from console.intel import _canonical_url, _extract_host_ip

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
# _canonical_url
# -----------------------------------------------------------------------------

print("[1] _canonical_url — strips default ports, lowercases host, drops query")
check("http with default port",
      _canonical_url("HTTP://Example.com:80/path") == "http://example.com/path")
check("https with default port",
      _canonical_url("https://Example.COM:443/Path") == "https://example.com/Path")
check("non-default port kept",
      _canonical_url("http://example.com:8080/x") == "http://example.com:8080/x")
check("query string dropped",
      _canonical_url("http://example.com/?q=1") == "http://example.com/")
check("fragment dropped",
      _canonical_url("http://example.com/p#frag") == "http://example.com/p")
check("ftp scheme accepted",
      _canonical_url("ftp://example.com/file") == "ftp://example.com/file")


print("\n[2] _canonical_url — rejects malformed / unsupported")
check("file:// rejected", _canonical_url("file:///etc/passwd") is None)
check("empty string", _canonical_url("") is None)
check("None input", _canonical_url(None) is None)
check("no host", _canonical_url("https:///path") is None)


print("\n[3] _canonical_url — matches a real corpus URL")
# From the corpus survey: http://47.242.58.84:60109/linux
out = _canonical_url("http://47.242.58.84:60109/linux")
check("corpus URL canonicalises stable",
      out == "http://47.242.58.84:60109/linux",
      f"got {out!r}")


# -----------------------------------------------------------------------------
# _extract_host_ip
# -----------------------------------------------------------------------------

print("\n[4] _extract_host_ip — IP-literal host returned canonical")
check("ipv4 literal extracted",
      _extract_host_ip("http://47.242.58.84:60109/linux") == "47.242.58.84")
check("ipv4 literal default port",
      _extract_host_ip("http://1.2.3.4/payload.exe") == "1.2.3.4")
check("ipv6 literal extracted (lower)",
      _extract_host_ip("http://[2606:4700:4700::1111]/path") == "2606:4700:4700::1111")


print("\n[5] _extract_host_ip — domain host returns None (passive DNS later)")
check("domain host returns None",
      _extract_host_ip("http://example.com/path") is None)
check("subdomain returns None",
      _extract_host_ip("https://api.example.com:8080/x") is None)


print("\n[6] _extract_host_ip — defensive")
check("empty string", _extract_host_ip("") is None)
check("malformed", _extract_host_ip("not a url") is None)


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
