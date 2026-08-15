"""Smoke test for `enrich.intel.artifact`.

Covers the artifact canonicalisers + the never-query gate. Standalone:
no ES, no LLM, no pytest. Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_artifact.py

Exits non-zero on the first failed assertion. ROADMAP "Research-mode
strategic gaps" section A — milestone 1, IP artifact end-to-end.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.intel.artifact import (
    ARTIFACT_KINDS,
    Artifact,
    canonical_domain,
    canonical_hash,
    canonical_ip,
    canonical_url,
    dedupe_artifacts,
    is_in_cidrs,
    make_artifact,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


print("[1] canonical_ip — public addresses pass, private/reserved are rejected")
check("ipv4 public", canonical_ip("8.8.8.8") == "8.8.8.8")
check("ipv4 with whitespace", canonical_ip("  1.2.3.4  ") == "1.2.3.4")
# Use Cloudflare's public IPv6 resolver — a real public IPv6 that won't
# trip any private/reserved category. `2001:db8::/32` is documentation
# space and IS correctly filtered as reserved, which we exercise below.
check("ipv6 canonicalised lowercase",
      canonical_ip("2606:4700:4700::1111") == "2606:4700:4700::1111")
check("ipv6 uppercase normalised",
      canonical_ip("2606:4700:4700::1111".upper()) == "2606:4700:4700::1111")
# 2001:db8::/32 is documentation-reserved per RFC 3849 and `ipaddress`
# flags it `is_reserved`. The gate must drop it.
check("ipv6 documentation reserved rejected",
      canonical_ip("2001:db8::1") is None)
check("rfc1918 rejected", canonical_ip("192.168.1.1") is None)
check("loopback rejected", canonical_ip("127.0.0.1") is None)
check("link-local rejected", canonical_ip("169.254.1.1") is None)
check("multicast rejected", canonical_ip("224.0.0.1") is None)
check("unspecified rejected", canonical_ip("0.0.0.0") is None)
check("gibberish rejected", canonical_ip("not an ip") is None)
check("empty rejected", canonical_ip("") is None)
check("None rejected", canonical_ip(None) is None)  # type: ignore[arg-type]


print("\n[2] canonical_domain — basic acceptance + rejection")
check("simple domain", canonical_domain("Example.COM") == "example.com")
check("trailing dot stripped", canonical_domain("example.com.") == "example.com")
check("single label rejected", canonical_domain("localhost") is None)
check("with scheme rejected", canonical_domain("http://example.com") is None)
check("with path rejected", canonical_domain("example.com/path") is None)
check("with space rejected", canonical_domain("example .com") is None)
check("leading hyphen rejected", canonical_domain("-foo.com") is None)
check("trailing hyphen rejected", canonical_domain("foo-.com") is None)
check("very long rejected", canonical_domain("x" * 254 + ".com") is None)


print("\n[3] canonical_url — query stripped, host lowered, default port dropped")
check("https default port", canonical_url("HTTPS://Example.com:443/Path?id=1")
      == "https://example.com/Path")
check("http custom port kept", canonical_url("http://example.com:8080/p?x=1")
      == "http://example.com:8080/p")
check("ftp accepted", canonical_url("ftp://files.example.com/x") == "ftp://files.example.com/x")
check("file scheme rejected", canonical_url("file:///etc/passwd") is None)
check("missing host rejected", canonical_url("https:///path") is None)
check("nonsense rejected", canonical_url("not a url") is None)


print("\n[4] canonical_hash — 32/40/64 hex only, case-insensitive")
md5 = "5d41402abc4b2a76b9719d911017c592"
sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
check("md5", canonical_hash(md5) == md5)
check("sha1", canonical_hash(sha1) == sha1)
check("sha256", canonical_hash(sha256) == sha256)
check("md5 uppercase normalised", canonical_hash(md5.upper()) == md5)
check("31-hex rejected", canonical_hash("a" * 31) is None)
check("not hex rejected", canonical_hash("g" * 32) is None)


print("\n[5] make_artifact dispatches by kind")
a = make_artifact("ip", "8.8.8.8")
check("make_artifact ip", a is not None and a.kind == "ip" and a.value == "8.8.8.8")
check("make_artifact private rejected", make_artifact("ip", "10.0.0.1") is None)
check("make_artifact unknown kind", make_artifact("nonsense", "x") is None)


print("\n[6] Artifact dataclass — id format + equality")
a1 = Artifact("ip", "1.1.1.1")
a2 = Artifact("ip", "1.1.1.1")
a3 = Artifact("ip", "1.1.1.2")
check("equality", a1 == a2)
check("inequality", a1 != a3)
check("hashable", len({a1, a2, a3}) == 2)
check("id format", a1.id == "ip:1.1.1.1")

try:
    Artifact("nonsense", "x")
    check("unknown kind raises", False, "no exception")
except ValueError:
    check("unknown kind raises", True)
try:
    Artifact("ip", "")
    check("empty value raises", False, "no exception")
except ValueError:
    check("empty value raises", True)


print("\n[7] dedupe_artifacts — order-preserving")
items = [Artifact("ip", "1.1.1.1"), Artifact("ip", "2.2.2.2"),
         Artifact("ip", "1.1.1.1"), Artifact("ip", "3.3.3.3")]
deduped = dedupe_artifacts(items)
check("dedupe count", len(deduped) == 3)
check("dedupe order preserved",
      [a.value for a in deduped] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"])


print("\n[8] is_in_cidrs — operator's never-query gate")
cidrs = ["10.0.0.0/8", "2001:db8::/32"]
check("ipv4 in cidr", is_in_cidrs("10.5.0.1", cidrs) is True)
check("ipv4 out of cidr", is_in_cidrs("8.8.8.8", cidrs) is False)
check("ipv6 in cidr", is_in_cidrs("2001:db8::1", cidrs) is True)
check("malformed cidr ignored", is_in_cidrs("8.8.8.8", ["not/a/cidr"]) is False)
check("non-ip rejected gracefully", is_in_cidrs("nonsense", cidrs) is False)


print("\n[9] ARTIFACT_KINDS contract")
check("contains ip + url + domain + hash",
      "ip" in ARTIFACT_KINDS and "url" in ARTIFACT_KINDS
      and "domain" in ARTIFACT_KINDS and "hash" in ARTIFACT_KINDS)


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
