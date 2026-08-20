"""Smoke test for the split anchor-match threshold (E8 / Findings 70-71).
Offline: no ES, no network, no LLM.

`playbook_merge_threshold` drove three unrelated comparisons at one value. The
one this splits out is centroid-to-anchor identity reuse: a group clearing it
inherits an existing `playbook_id` and is never minted, while `assignment_tau`
judges each *session* against that same anchor. Live, two groups sat 0.0057 and
0.0085 above the shared 0.94 — they inherited an identity none of their members
could be assigned to, so they re-entered the novel pool every cycle.

Covers `effective_anchor_match_threshold`'s resolution and validation, and the
decision it actually changes in `_assign_playbook_id` at the measured cosines.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from enrich.sources.cowrie.sessions import (
    _assign_playbook_id,
    effective_anchor_match_threshold,
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


def _scfg(merge: float = 0.94, override=None):
    return SimpleNamespace(
        playbook_merge_threshold=merge,
        playbook_anchor_match_threshold=override,
    )


# --- resolution ---------------------------------------------------------------

check("unset override falls back to the merge threshold (no-op default)",
      effective_anchor_match_threshold(_scfg()) == 0.94)
check("an explicit override wins",
      effective_anchor_match_threshold(_scfg(override=0.96)) == 0.96)
check("equal-to-merge is allowed (explicitly pinning the historical value)",
      effective_anchor_match_threshold(_scfg(override=0.94)) == 0.94)
check("a config object without the attribute at all still resolves",
      effective_anchor_match_threshold(
          SimpleNamespace(playbook_merge_threshold=0.94)) == 0.94)

for bad, why in ((1.5, "above 1"), (-0.1, "below 0")):
    try:
        effective_anchor_match_threshold(_scfg(override=bad))
        check(f"an out-of-range override ({why}) raises", False, "no raise")
    except ValueError as exc:
        check(f"an out-of-range override ({why}) raises", "within [0, 1]" in str(exc),
              str(exc))

try:
    # Below the merge cut, two clusters merged into one group could each match a
    # different anchor and identity would depend on iteration order.
    effective_anchor_match_threshold(_scfg(merge=0.94, override=0.90))
    check("an override below the merge threshold raises", False, "no raise")
except ValueError as exc:
    check("an override below the merge threshold raises",
          ">= " in str(exc) and "playbook_merge_threshold" in str(exc), str(exc))


# --- the decision it changes, at the live cosines -----------------------------
# Two unit vectors at a chosen cosine, built in the plane of e0/e1.

def _pair(cos: float) -> tuple[np.ndarray, np.ndarray]:
    a = np.array([1.0, 0.0], dtype=np.float64)
    b = np.array([cos, float(np.sqrt(max(0.0, 1.0 - cos * cos)))], dtype=np.float64)
    return a, b


SEED = "seed-abc"
for cos, at94, at96, label in (
    (0.9457, "reuse", "mint", "cluster_9 — the botnet_loader group"),
    (0.9485, "reuse", "mint", "cluster_7"),
    (0.9629, "reuse", "reuse", "cluster_10 — genuinely close, must keep inheriting"),
    (0.9945, "reuse", "reuse", "cluster_12"),
):
    anchor_vec, group = _pair(cos)
    anchors = [(anchor_vec, "spb-incumbent")]
    got94 = _assign_playbook_id(group, anchors, 0.94, SEED)
    got96 = _assign_playbook_id(group, anchors, 0.96, SEED)
    ok = ((got94 == "spb-incumbent") == (at94 == "reuse")
          and (got96 == "spb-incumbent") == (at96 == "reuse"))
    check(f"cos {cos}: {at94} at 0.94, {at96} at 0.96  [{label}]", ok,
          f"got94={got94} got96={got96}")

# A fresh mint must be deterministic in the seed, not random, or a re-run would
# create a second anchor for the same membership.
anchor_vec, group = _pair(0.9457)
mint_a = _assign_playbook_id(group, [(anchor_vec, "spb-incumbent")], 0.96, SEED)
mint_b = _assign_playbook_id(group, [(anchor_vec, "spb-incumbent")], 0.96, SEED)
check("a fresh mint is deterministic in the membership seed",
      mint_a == mint_b and mint_a != "spb-incumbent", f"{mint_a} vs {mint_b}")

check("an empty anchor library always mints",
      _assign_playbook_id(group, [], 0.96, SEED) == mint_a)

# The nearest anchor decides — a far anchor must not shadow a near one.
near, _ = _pair(0.0)
far = np.array([0.0, 1.0], dtype=np.float64)
group_vec = np.array([1.0, 0.0], dtype=np.float64)
check("the NEAREST anchor is the one tested against the threshold",
      _assign_playbook_id(
          group_vec, [(far, "spb-far"), (group_vec, "spb-near")], 0.96, SEED,
      ) == "spb-near")


print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for name, detail in FAILED:
        print(f"  FAILED: {name} — {detail}")
    raise SystemExit(1)
