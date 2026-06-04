"""Late-fusion doc-count ceiling — hard refusal at scale (P1.3).

`clustering_mode=late_fusion` builds an O(N^2) pure-Python pair-distance matrix
(`_disagreement_distance`) plus an n×n float32 matrix, so it must not run
unbounded. `_fusion_over_ceiling` decides, given the doc count and the
configured ceiling, whether to proceed with fusion, fall back to HDBSCAN, or
hard-refuse (raise) — never silently degrade an explicitly-chosen mode.

Scenarios:
  [1] no ceiling (None / 0) → proceed (False)
  [2] within ceiling → proceed (False)
  [3] over ceiling, fallback NOT accepted → RuntimeError (hard refusal)
  [4] over ceiling, --accept-fallback → fall back to HDBSCAN (True)
  [5] exactly at the ceiling → proceed (boundary is inclusive)

Pure-function test, offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_fusion_ceiling.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.clustering import _fusion_over_ceiling


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def _call(n, ceiling, accept):
    return _fusion_over_ceiling(n, ceiling, accept_fallback=accept, layer_label="session")


# -----------------------------------------------------------------------------
# [1] no ceiling → proceed.
# -----------------------------------------------------------------------------
print("\n[1] no ceiling (None / 0) → proceed with fusion")
check("None ceiling → False", _call(10**9, None, False) is False)
check("0 ceiling → False", _call(10**9, 0, False) is False)


# -----------------------------------------------------------------------------
# [2] within ceiling → proceed.
# -----------------------------------------------------------------------------
print("\n[2] within ceiling → proceed")
check("under ceiling → False", _call(4000, 15000, False) is False)


# -----------------------------------------------------------------------------
# [3] over ceiling, no fallback → hard refusal.
# -----------------------------------------------------------------------------
print("\n[3] over ceiling, fallback not accepted → RuntimeError")
raised = False
try:
    _call(50000, 15000, False)
except RuntimeError as exc:
    raised = True
    msg = str(exc)
check("raises RuntimeError", raised)
check("message names the count, ceiling, and the escape hatches",
      raised and "50000" in msg and "15000" in msg and "--accept-fallback" in msg,
      msg if raised else "(did not raise)")


# -----------------------------------------------------------------------------
# [4] over ceiling, fallback accepted → fall back (True), no raise.
# -----------------------------------------------------------------------------
print("\n[4] over ceiling, --accept-fallback → fall back to HDBSCAN")
check("returns True (fall back)", _call(50000, 15000, True) is True)


# -----------------------------------------------------------------------------
# [5] boundary: exactly at ceiling is allowed.
# -----------------------------------------------------------------------------
print("\n[5] exactly at the ceiling → proceed (inclusive boundary)")
check("n == ceiling → False", _call(15000, 15000, False) is False)
# ceiling + 1 must raise (boundary is strictly above the ceiling).
raised2 = False
try:
    _call(15001, 15000, False)
except RuntimeError:
    raised2 = True
check("ceiling + 1 raises", raised2)


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
