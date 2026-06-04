"""Smoke test for ROADMAP #15: `dominant_intent` resolution must be
deterministic across input orderings, and the rollup doc must now carry
an `intent_distribution` field with top-N counts.

The old code used `Counter(intents).most_common(1)[0][0]` which relies on
Counter insertion order. A 2-command session with one `reconnaissance`
and one `execution` produced a different `dominant_intent` depending on
which hash iterated first. The new helper (`_summarize_intents`) sorts
ties by `(-count, intent_name)` so `execution` wins lexically every time.

Standalone — no ES, no pytest. Pure-function tests of the helper.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_dominant_intent.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import _summarize_intents


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
# [1] Empty input.
# -----------------------------------------------------------------------------
print("\n[1] empty input")
dom, dist = _summarize_intents([])
check("empty list → (None, [])", dom is None and dist == [], f"got ({dom!r}, {dist!r})")


# -----------------------------------------------------------------------------
# [2] Single-intent session.
# -----------------------------------------------------------------------------
print("\n[2] single-element input")
dom, dist = _summarize_intents(["reconnaissance"])
check(
    "single intent → that intent, count=1",
    dom == "reconnaissance" and dist == [{"intent": "reconnaissance", "count": 1}],
    f"got ({dom!r}, {dist!r})",
)


# -----------------------------------------------------------------------------
# [3] The core bug: 1-1 tie must resolve deterministically (the headline).
# -----------------------------------------------------------------------------
print("\n[3] 1-1 tie resolves deterministically regardless of input order")
# Try ALL 2! = 2 permutations of {reconnaissance, execution}.
results = set()
for order in [
    ["reconnaissance", "execution"],
    ["execution", "reconnaissance"],
]:
    dom, _ = _summarize_intents(order)
    results.add(dom)
check(
    "1-1 tie → exactly one dominant_intent regardless of order",
    len(results) == 1,
    f"got results={results} (expected a single-element set)",
)
# Lexical tie-break: "execution" < "reconnaissance" alphabetically.
check(
    "lexical tie-break: 'execution' wins over 'reconnaissance' at 1-1",
    next(iter(results)) == "execution",
    f"got dominant_intent={next(iter(results))!r}",
)


# -----------------------------------------------------------------------------
# [4] 3-way tie also deterministic.
# -----------------------------------------------------------------------------
print("\n[4] 3-way tie at top — distribution and dominant_intent stable")
import itertools
intents = ["execution", "discovery", "collection"]
all_results = set()
for perm in itertools.permutations(intents):
    dom, dist = _summarize_intents(list(perm))
    # tuple-ize distribution for set membership
    dist_t = tuple((d["intent"], d["count"]) for d in dist)
    all_results.add((dom, dist_t))
check(
    "all 3! permutations produce the same (dominant, distribution)",
    len(all_results) == 1,
    f"got {len(all_results)} distinct results: {all_results}",
)
dom, dist_t = next(iter(all_results))
check(
    "3-way 1-1-1 tie picks lexically smallest ('collection')",
    dom == "collection",
    f"got {dom!r}",
)
# Distribution must be sorted by (-count, name) → all three at count=1,
# names alphabetical: collection, discovery, execution.
check(
    "distribution sorted lexically when all counts equal",
    list(dist_t) == [("collection", 1), ("discovery", 1), ("execution", 1)],
    f"got {dist_t}",
)


# -----------------------------------------------------------------------------
# [5] Clear winner — distribution still ordered correctly.
# -----------------------------------------------------------------------------
print("\n[5] clear winner with mixed tail")
dom, dist = _summarize_intents(
    ["execution", "execution", "execution", "discovery", "reconnaissance"]
)
check(
    "majority winner picked",
    dom == "execution",
    f"got {dom!r}",
)
# Tail (discovery=1, reconnaissance=1) is a 1-1 tie → lexical order.
check(
    "tail tie ordered lexically: discovery before reconnaissance",
    dist == [
        {"intent": "execution", "count": 3},
        {"intent": "discovery", "count": 1},
        {"intent": "reconnaissance", "count": 1},
    ],
    f"got {dist}",
)


# -----------------------------------------------------------------------------
# [6] top_n truncates distribution but does not affect dominant_intent.
# -----------------------------------------------------------------------------
print("\n[6] top_n truncation")
dom, dist = _summarize_intents(
    ["a", "a", "b", "c", "d", "e", "f"], top_n=3
)
check(
    "top_n=3 keeps exactly 3 entries",
    len(dist) == 3,
    f"got {len(dist)} entries: {dist}",
)
check(
    "top_n does not change dominant_intent (most common 'a')",
    dom == "a",
    f"got {dom!r}",
)


# -----------------------------------------------------------------------------
# [7] Counts add correctly (regression guard — no off-by-one on duplicates).
# -----------------------------------------------------------------------------
print("\n[7] count arithmetic")
dom, dist = _summarize_intents(["x"] * 7 + ["y"] * 3)
check(
    "7 x's + 3 y's → x:7, y:3",
    dist == [{"intent": "x", "count": 7}, {"intent": "y", "count": 3}],
    f"got {dist}",
)


# -----------------------------------------------------------------------------
# [8] Integration regression — make sure ips.py imports the helper.
# -----------------------------------------------------------------------------
print("\n[8] ips.py imports the helper")
try:
    from enrich.sources.cowrie.ips import _summarize_intents as ip_helper
    check("ips.py exposes _summarize_intents (imported from sessions)",
          ip_helper is _summarize_intents, "function objects differ")
except ImportError as exc:
    check("ips.py imports the helper", False, str(exc))


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
