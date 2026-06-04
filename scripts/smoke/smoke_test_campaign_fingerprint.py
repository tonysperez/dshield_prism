"""Smoke test for ROADMAP #17: infrastructure campaign fingerprint must be
stable across runs even when artifacts tie on occurrence count.

Before the fix, `sorted(art_counts.items(), key=lambda kv: -kv[1])` relied
on Python's stable sort to break ties — which kept items in their existing
Counter insertion order. Counter insertion is the order in which artifacts
were first seen across `sess_arts` iteration, which in turn depends on
ES-scan order over the session set. So re-running the miner with one
extra session in the component could flip the top-N ordering on ties,
which would flip the fingerprint string, which would rotate the campaign id.

The fix is the secondary sort key `(-count, (kind, value))` — ties resolve
lexicographically on `(kind, value)`, deterministic regardless of input
order.

This test reconstructs the artifact-sort + fingerprint + campaign-id
pipeline against several insertion orderings of the same `art_counts`
data, and asserts the resulting campaign id is identical every time.

Standalone — no ES, no pytest.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_campaign_fingerprint.py
"""
from __future__ import annotations

import itertools
import sys
from collections import OrderedDict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.campaigns import (
    _TOP_ARTIFACTS_PER_CAMPAIGN,
    _campaign_id,
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


# Mirror of the post-#17 sort key. The point of this test is to verify
# that the *result* is stable; the sort itself is one line in
# campaigns.py we can't easily call without the full miner. Replicating
# it here lets us test the property in isolation.
def top_arts_new(art_counts: dict, top_n: int = _TOP_ARTIFACTS_PER_CAMPAIGN) -> list:
    return sorted(art_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]


def top_arts_old(art_counts: dict, top_n: int = _TOP_ARTIFACTS_PER_CAMPAIGN) -> list:
    # Pre-fix behaviour: only `-kv[1]` as the key. Ties resolve by
    # Counter insertion order. Reproduced for the regression contrast.
    return sorted(art_counts.items(), key=lambda kv: -kv[1])[:top_n]


def fingerprint(top_arts: list, top_n_in_id: int = 10) -> str:
    """Mirror of the fingerprint line at campaigns.py:595."""
    return "|".join(f"{k}={v}" for (k, v), _ in top_arts[:top_n_in_id])


# -----------------------------------------------------------------------------
# [1] Headline: same artifacts in different insertion orders → same fingerprint
# and same campaign id, with the fix.
# -----------------------------------------------------------------------------
print("\n[1] tied-count artifacts: campaign id stable across insertion orders")
# Construct artifacts where many tie on count=2 — exactly the case where
# insertion order leaks into the fingerprint under the old code.
items = [
    (("url", "http://b.example/x"), 2),
    (("url", "http://a.example/y"), 2),
    (("hash", "ffaa"),               2),
    (("ssh_key", "AAAA"),            2),
    (("url", "http://c.example/z"), 1),  # tie-breaker outside the tie pack
]

# Generate several permutations of insertion order. With 4 tied entries
# at count=2, ALL their orderings should produce the same fingerprint.
ids_seen: set[str] = set()
fps_seen: set[str] = set()
for perm in itertools.permutations(items):
    d = OrderedDict()
    for k, v in perm:
        d[k] = v
    top = top_arts_new(d)
    fp = fingerprint(top)
    fps_seen.add(fp)
    ids_seen.add(_campaign_id("infrastructure", fp))

check(
    f"new sort key yields exactly one fingerprint across {len(list(itertools.permutations(items)))} orderings",
    len(fps_seen) == 1,
    f"got {len(fps_seen)} distinct fingerprints",
)
check(
    "new sort key yields exactly one campaign id across all orderings",
    len(ids_seen) == 1,
    f"got {len(ids_seen)} distinct ids: {ids_seen}",
)


# -----------------------------------------------------------------------------
# [2] Regression contrast: the OLD sort key would have produced multiple
# fingerprints for the same data — proving this test is actually meaningful
# rather than always passing.
# -----------------------------------------------------------------------------
print("\n[2] contrast: old sort key WOULD have rotated id across orderings")
old_fps: set[str] = set()
for perm in itertools.permutations(items):
    d = OrderedDict()
    for k, v in perm:
        d[k] = v
    top = top_arts_old(d)
    old_fps.add(fingerprint(top))
check(
    "old sort key yields >1 fingerprint (confirms the bug was real)",
    len(old_fps) > 1,
    f"got only {len(old_fps)} fingerprint — test is not exercising the bug",
)


# -----------------------------------------------------------------------------
# [3] Realistic-corpus case: counts strictly distinct → tie-break inactive,
# new and old should agree. Regression guard.
# -----------------------------------------------------------------------------
print("\n[3] strictly-distinct counts: new == old (tie-break doesn't fire)")
items = [
    (("url", "http://a.com"),  5),
    (("hash", "abcd"),         4),
    (("ssh_key", "Z"),         3),
    (("url", "http://b.com"),  2),
    (("hash", "ffff"),         1),
]
d = OrderedDict(items)
top_new = top_arts_new(d)
top_old = top_arts_old(d)
check(
    "result matches on strictly-distinct counts",
    top_new == top_old,
    f"new={top_new} old={top_old}",
)


# -----------------------------------------------------------------------------
# [4] Empty input: doesn't crash; both fingerprint and id are stable.
# -----------------------------------------------------------------------------
print("\n[4] empty input")
top = top_arts_new({})
fp = fingerprint(top)
cid = _campaign_id("infrastructure", fp or "fallback")
check("empty art_counts → empty top_arts", top == [], f"got {top}")
check("empty fingerprint", fp == "", f"got {fp!r}")
check("id falls back to non-empty seed", cid.startswith("cmp-inf-"), f"got {cid}")


# -----------------------------------------------------------------------------
# [5] All-tied counts: still deterministic.
# -----------------------------------------------------------------------------
print("\n[5] all-tied counts → ordering is purely lexical on (kind, value)")
items = [
    (("url", "http://z.com"),  1),
    (("url", "http://a.com"),  1),
    (("ssh_key", "AAAA"),      1),
    (("hash", "deadbeef"),     1),
]
ids_seen = set()
for perm in itertools.permutations(items):
    d = OrderedDict()
    for k, v in perm:
        d[k] = v
    top = top_arts_new(d)
    cid = _campaign_id("infrastructure", fingerprint(top))
    ids_seen.add(cid)
check(
    "single id across all permutations when every count is equal",
    len(ids_seen) == 1,
    f"got {len(ids_seen)} ids",
)
# Order must be lex on (kind, value): ('hash', 'deadbeef') < ('ssh_key', ...) < ('url', 'http://a.com') < ('url', 'http://z.com')
expected_order = [
    ("hash", "deadbeef"),
    ("ssh_key", "AAAA"),
    ("url", "http://a.com"),
    ("url", "http://z.com"),
]
got_order = [k for k, _ in top_arts_new(OrderedDict(items))]
check(
    "all-tied: order is exactly lex on (kind, value)",
    got_order == expected_order,
    f"got {got_order}",
)


# -----------------------------------------------------------------------------
# [6] Cap at _TOP_ARTIFACTS_PER_CAMPAIGN.
# -----------------------------------------------------------------------------
print(f"\n[6] cap at {_TOP_ARTIFACTS_PER_CAMPAIGN}")
big = {(("url", f"http://x{i:03d}.com"), 1) for i in range(_TOP_ARTIFACTS_PER_CAMPAIGN + 20)}
d = OrderedDict(big)
top = top_arts_new(d)
check(
    f"truncated to {_TOP_ARTIFACTS_PER_CAMPAIGN}",
    len(top) == _TOP_ARTIFACTS_PER_CAMPAIGN,
    f"got {len(top)}",
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
