"""Windowed session clustering query construction (scale-hardening P1.2).

`cluster sessions` can scope to a rolling window of recent sessions instead of
re-clustering the all-time rollup every backward cycle. The window is applied at
the ES query level by `_session_cluster_query(window_days)`, shared by both
session-cluster iterators (`iter_session_docs` and the late-fusion
`iter_session_docs_with_text`). Identity stays stable across windows via the
existing centroid-anchor + reference_centroid mechanisms — this test only
asserts the query is shaped correctly so windowing is actually applied (or
correctly disabled).

Scenarios:
  [1] None / 0 / negative → bare exists query (all-time, current behaviour)
  [2] window_days > 0 → bool.filter with the exists clause AND a
      @timestamp >= now-Nd/d range
  [3] the embedding field the exists clause requires is unchanged
  [4] both iterators emit the same query for the same window

Pure-function test, offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_windowed_clustering.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.sessions import _session_cluster_query

EMB_FIELD = "dshield.cowrie.enrichment.session.embedding"

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
# [1] Off (None / 0 / negative) → bare exists query, no range.
# -----------------------------------------------------------------------------
print("\n[1] windowing off → bare exists query (all-time)")
for label, val in (("None", None), ("0", 0), ("negative", -5)):
    q = _session_cluster_query(val)
    check(
        f"{label} → exists-only",
        q == {"exists": {"field": EMB_FIELD}},
        repr(q),
    )


# -----------------------------------------------------------------------------
# [2] window_days > 0 → bool.filter [exists, range @timestamp gte now-Nd/d].
# -----------------------------------------------------------------------------
print("\n[2] window_days > 0 → bool.filter with exists + @timestamp range")
q90 = _session_cluster_query(90)
flt = (q90.get("bool") or {}).get("filter") or []
check("is a bool query", "bool" in q90, repr(q90))
check("filter has exactly two clauses", len(flt) == 2, repr(flt))
check(
    "exists clause present",
    {"exists": {"field": EMB_FIELD}} in flt,
    repr(flt),
)
ranges = [c for c in flt if "range" in c]
check("exactly one range clause", len(ranges) == 1, repr(flt))
check(
    "range is @timestamp >= now-90d/d",
    ranges == [{"range": {"@timestamp": {"gte": "now-90d/d"}}}],
    repr(ranges),
)


# -----------------------------------------------------------------------------
# [3] int coercion — float-ish / string-ish N still produces an int day count.
# -----------------------------------------------------------------------------
print("\n[3] day count is coerced to int (no float in the date-math string)")
q7 = _session_cluster_query(7)
gte = q7["bool"]["filter"][-1]["range"]["@timestamp"]["gte"]
check("now-7d/d (no decimal)", gte == "now-7d/d", gte)


# -----------------------------------------------------------------------------
# [4] both iterators share the exact same query for a given window.
#     (Guards against the two _source projections drifting in their filter.)
# -----------------------------------------------------------------------------
print("\n[4] same query regardless of which iterator builds it")
check(
    "off matches",
    _session_cluster_query(None) == _session_cluster_query(0),
)
check(
    "on is deterministic",
    _session_cluster_query(30) == _session_cluster_query(30),
)


# -----------------------------------------------------------------------------
# [5] I4d — novel-pool-only scoping (Option A cutover).
# -----------------------------------------------------------------------------
print("\n[5] novel_pool_only adds the assignment_status=novel filter")
_NOVEL = {"term": {"dshield.cowrie.enrichment.session.cluster.assignment_status": "novel"}}
check(
    "default (False) is unchanged — no novel term",
    _session_cluster_query(30) == _session_cluster_query(30, False),
)
qn = _session_cluster_query(0, novel_pool_only=True)
check("novel-only, no window → bool.filter [exists, novel]",
      qn.get("bool", {}).get("filter") == [
          {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}}, _NOVEL],
      str(qn))
qwn = _session_cluster_query(30, novel_pool_only=True)
check("novel-only + window → exists + range + novel (3 filters)",
      len(qwn["bool"]["filter"]) == 3 and qwn["bool"]["filter"][-1] == _NOVEL, str(qwn))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
