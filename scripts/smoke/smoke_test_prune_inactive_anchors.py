"""Smoke test for the inactive-anchor prune
(`scripts/prune_inactive_anchors.py`): the pure `select_inactive` selector and the
retire/restore painless (centroid-preserving + idempotent). No ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from prune_inactive_anchors import _RESTORE_SRC, _RETIRE_SRC, select_inactive

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


anchors = ["spb-busy", "spb-dead", "spb-rare", "spb-zero"]
counts = {"spb-busy": 5000, "spb-rare": 3}  # dead + zero are absent (0)

check("min_sessions=1 → only the 0-session anchors (dead, zero)",
      select_inactive(anchors, counts, 1) == ["spb-dead", "spb-zero"],
      str(select_inactive(anchors, counts, 1)))
check("min_sessions=5 → also the barely-used (rare has 3)",
      select_inactive(anchors, counts, 5) == ["spb-dead", "spb-rare", "spb-zero"],
      str(select_inactive(anchors, counts, 5)))
check("busy anchor never selected", "spb-busy" not in select_inactive(anchors, counts, 5))
check("empty library → nothing", select_inactive([], counts, 1) == [])

# retire script: preserves the centroid (reversible) + idempotent noop guard + reason
check("retire preserves centroid under retired_centroid",
      "ctx._source.retired_centroid = ctx._source.anchor_centroid" in _RETIRE_SRC)
check("retire drops anchor_centroid (out of assignment)",
      "ctx._source.remove('anchor_centroid')" in _RETIRE_SRC)
check("retire stamps reason + is idempotent (noop if already retired)",
      "ctx._source.retired_reason = params.reason" in _RETIRE_SRC and "ctx.op = 'noop'" in _RETIRE_SRC)

# restore script: only un-retires the matching reason, fully reverses
check("restore only touches reason-matching docs",
      "ctx._source.retired_reason == params.reason" in _RESTORE_SRC)
check("restore moves the centroid back + clears retirement fields",
      all(t in _RESTORE_SRC for t in (
          "ctx._source.anchor_centroid = ctx._source.retired_centroid",
          "ctx._source.remove('retired_centroid')",
          "ctx._source.remove('retired_reason')")))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
