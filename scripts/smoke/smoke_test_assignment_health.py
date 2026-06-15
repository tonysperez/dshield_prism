"""Smoke test for the cutover health-check summarizer
(`scripts/assignment_health.py::summarize`). No ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from assignment_health import summarize

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# Healthy steady state: 10000 total, 9700 assigned, 200 novel, runner active.
healthy = summarize({
    "total": 10000, "status_assigned": 9700, "status_novel": 200,
    "has_playbook": 9800, "assigned_last_day": 9700, "anchors": 155,
    "retired_anchors": 2, "anchors_minted_last_week": 3,
})
check("healthy: assigned_rate 0.97", healthy["assigned_rate"] == 0.97, str(healthy["assigned_rate"]))
check("healthy: novel_rate 0.02", healthy["novel_rate"] == 0.02, str(healthy["novel_rate"]))
check("healthy: novel_pool_size 200", healthy["novel_pool_size"] == 200)
check("healthy: null_playbook 200", healthy["null_playbook"] == 200, str(healthy["null_playbook"]))
check("healthy: flags == ok", healthy["flags"] == ["ok"], str(healthy["flags"]))

# Runner idle: no assignment writes in 24h.
idle = summarize({
    "total": 10000, "status_assigned": 9700, "status_novel": 200,
    "has_playbook": 9800, "assigned_last_day": 0, "anchors": 155,
    "retired_anchors": 2, "anchors_minted_last_week": 0,
})
check("idle: flags the idle runner",
      any("runner idle" in f for f in idle["flags"]), str(idle["flags"]))

# Novel runaway: 15% novel.
runaway = summarize({
    "total": 10000, "status_assigned": 8000, "status_novel": 1500,
    "has_playbook": 8500, "assigned_last_day": 8000, "anchors": 155,
    "retired_anchors": 2, "anchors_minted_last_week": 1,
})
check("runaway: flags novel_rate_high",
      any("novel_rate_high" in f for f in runaway["flags"]), str(runaway["flags"]))

# Backfill in flight: many null-playbook sessions vs few novel.
backfill = summarize({
    "total": 10000, "status_assigned": 2000, "status_novel": 50,
    "has_playbook": 2000, "assigned_last_day": 2000, "anchors": 155,
    "retired_anchors": 2, "anchors_minted_last_week": 0,
})
check("backfill: flags null >> novel",
      any("null-playbook sessions >>" in f for f in backfill["flags"]), str(backfill["flags"]))

# Empty corpus: rates are None, no crash.
empty = summarize({
    "total": 0, "status_assigned": 0, "status_novel": 0, "has_playbook": 0,
    "assigned_last_day": 0, "anchors": 0, "retired_anchors": 0, "anchors_minted_last_week": 0,
})
check("empty: rates None, no crash", empty["assigned_rate"] is None and empty["novel_rate"] is None)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
