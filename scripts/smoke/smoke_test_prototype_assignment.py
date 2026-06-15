"""Smoke test for the prototype-assignment experiment scoring math
(`scripts/exp_prototype_assignment.py::score`).

The live experiment can only run on tagged data; this pins the metric algebra on
a hand-computed synthetic scenario so the numbers are trustworthy before anyone
points it at a real corpus.

Scenario: 2 unit anchors on orthogonal axes (spb-A=e0, spb-B=e1) and 6 sessions
with known cosine-to-nearest and known current playbook:

  id  max_cos  nearest  current_pb   (notes)
  S1   1.00     spb-A    spb-A        agree
  S2   1.00     spb-B    spb-B        agree
  S3   0.95     spb-A    spb-A        agree
  S4   0.99     spb-A    spb-B        DISagree (nearest != current)
  S5   0.50     spb-A    None         current-novel, A-novel @0.9
  S6   0.97     spb-A    None         current-novel, A-known  @0.9

At tau=0.9 the assigned set is {S1,S2,S3,S4,S6} (S5 novel). Every rate below is an
exact integer ratio, robust to float drift since no sample sits within 0.05 of
the threshold.

Standalone — no pytest, no ES.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from exp_prototype_assignment import score

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


def _vec(cos: float, axis: int) -> list[float]:
    """Unit 4-vector with exact cosine `cos` to axis `axis` and 0 to the others
    (orthogonal filler on axis 2)."""
    v = [0.0, 0.0, 0.0, 0.0]
    v[axis] = cos
    v[2] = math.sqrt(max(0.0, 1.0 - cos * cos))
    return v


anchor_ids = ["spb-A", "spb-B"]
anchors = np.array([[1, 0, 0, 0], [0, 1, 0, 0]], dtype=np.float32)

samples = [
    {"emb": _vec(1.00, 0), "current_pb": "spb-A", "is_outlier": False, "novelty": None, "intent": None, "signature": None},
    {"emb": _vec(1.00, 1), "current_pb": "spb-B", "is_outlier": False, "novelty": None, "intent": None, "signature": None},
    {"emb": _vec(0.95, 0), "current_pb": "spb-A", "is_outlier": False, "novelty": None, "intent": None, "signature": None},
    {"emb": _vec(0.99, 0), "current_pb": "spb-B", "is_outlier": False, "novelty": None, "intent": None, "signature": None},
    {"emb": _vec(0.50, 0), "current_pb": None,    "is_outlier": True,  "novelty": None, "intent": None, "signature": None},
    {"emb": _vec(0.97, 0), "current_pb": None,    "is_outlier": False, "novelty": None, "intent": None, "signature": None},
]

rep = score(samples, anchor_ids, anchors, thresholds=[0.9], prod_tau=0.9)

check("n_scored == 6", rep["n_scored"] == 6, str(rep["n_scored"]))
check("n_anchors == 2", rep["n_anchors"] == 2)
check("current_assigned == 4", rep["current_assigned"] == 4, str(rep["current_assigned"]))
check("current_novel == 2", rep["current_novel"] == 2, str(rep["current_novel"]))
check("current_outlier == 1", rep["current_outlier"] == 1, str(rep["current_outlier"]))
check("nearest_eq_current_rate == 0.75 (3/4)",
      rep["nearest_eq_current_rate"] == 0.75, str(rep["nearest_eq_current_rate"]))
check("headline known_rate @0.9 == 0.8333 (5/6)",
      rep["headline_known_rate_at_prod_tau"] == 0.8333,
      str(rep["headline_known_rate_at_prod_tau"]))

s = rep["sweep"][0]
check("sweep known_rate == 0.8333", s["known_rate"] == 0.8333, str(s["known_rate"]))
check("sweep novel_rate == 0.1667", s["novel_rate"] == 0.1667, str(s["novel_rate"]))
check("sweep agreement_on_assigned == 0.75 (3/4)",
      s["agreement_on_assigned"] == 0.75, str(s["agreement_on_assigned"]))
check("sweep current_novel_recall == 0.5 (1/2)",
      s["current_novel_recall"] == 0.5, str(s["current_novel_recall"]))
check("sweep false_novel_rate == 0.0 (0/4)",
      s["false_novel_rate"] == 0.0, str(s["false_novel_rate"]))

# anchor concentration: nn = [A,B,A,A,A,A] → A=5, B=1
conc = rep["anchor_concentration"]
check("both anchors ever-nearest", conc["n_anchors_ever_nearest"] == 2)
check("top10 share == 1.0", conc["top10_share_of_assignments"] == 1.0)

# monotonicity: known_rate is non-increasing in tau
mono = score(samples, anchor_ids, anchors, thresholds=[0.4, 0.96, 0.999], prod_tau=0.9)
kr = [r["known_rate"] for r in mono["sweep"]]
check("known_rate non-increasing in tau", kr[0] >= kr[1] >= kr[2], str(kr))
check("known_rate @0.4 == 1.0 (all assigned)", kr[0] == 1.0, str(kr[0]))
check("known_rate @0.96 == 0.6667 (4/6)", kr[1] == 0.6667, str(kr[1]))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
