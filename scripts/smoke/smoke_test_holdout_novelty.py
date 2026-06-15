"""Smoke test for the held-out-novelty experiment math
(`scripts/exp_holdout_novelty.py::select_family` and `::score_holdout`).

Synthetic scenario (unit 4-vectors):
  anchors: A=e0, Atwin (cos 0.95 to A), B=e1
  family(seed=A, tau=0.94) = {A, Atwin}; retained library = {B}

  held-out A-behaviour sessions (cosine to the only survivor B):
    H1 = e0      → cos 0.00 to B
    H2 (0.97→B)  → cos 0.97 to B
    H3 (0.50→B)  → cos 0.50 to B

  @tau=0.94: novel = H1,H3 (H2 absorbed by B@0.97) → recall 2/3 = 0.6667
  @tau=0.98: all novel (0.97<0.98)               → recall 1.0

Standalone — no pytest, no ES.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from exp_holdout_novelty import score_holdout, select_family

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
    v = [0.0, 0.0, 0.0, 0.0]
    v[axis] = cos
    v[2] = math.sqrt(max(0.0, 1.0 - cos * cos))
    return v


anchors = np.array([
    _vec(1.00, 0),   # A
    _vec(0.95, 0),   # Atwin (cos 0.95 to A)
    [0.0, 1.0, 0.0, 0.0],  # B
], dtype=np.float32)
anchor_ids = ["spb-A", "spb-Atwin", "spb-B"]

# --- select_family ---
fam = select_family(anchors, seed_idx=0, family_tau=0.94)
check("family@0.94 = {A, Atwin}", fam == [0, 1], str(fam))
fam96 = select_family(anchors, seed_idx=0, family_tau=0.96)
check("family@0.96 = {A} only (twin at 0.95 excluded)", fam96 == [0], str(fam96))

# --- score_holdout: retained library = {B} ---
retained_ids = ["spb-B"]
retained = anchors[[2]]
held = [_vec(0.0, 0), _vec(0.97, 1), _vec(0.5, 1)]  # H1,H2,H3 vs B
rep = score_holdout(held, retained_ids, retained, thresholds=[0.94, 0.98], prod_tau=0.94)

check("n_sessions == 3", rep["n_sessions"] == 3, str(rep["n_sessions"]))
check("recall@prod_tau(0.94) == 0.6667 (2/3)",
      rep["novelty_recall_at_prod_tau"] == 0.6667, str(rep["novelty_recall_at_prod_tau"]))
check("sweep recall@0.94 == 0.6667", rep["sweep"][0]["novelty_recall"] == 0.6667,
      str(rep["sweep"][0]))
check("sweep absorbed@0.94 == 0.3333", rep["sweep"][0]["absorbed_rate"] == 0.3333,
      str(rep["sweep"][0]))
check("sweep recall@0.98 == 1.0 (H2 now novel)",
      rep["sweep"][1]["novelty_recall"] == 1.0, str(rep["sweep"][1]))

ab = rep["top_absorbers_at_prod_tau"]
check("one absorber: spb-B ×1 @0.97",
      len(ab) == 1 and ab[0]["anchor"] == "spb-B" and ab[0]["n"] == 1
      and ab[0]["mean_cos"] == 0.97, str(ab))

# nearest-surviving cosine hist: max_cos=[0.0, 0.97, 0.5] → bins0,1,8
check("nearest-surviving hist == [1,1,0,0,0,0,0,0,1,0]",
      rep["nearest_surviving_cos_hist"] == [1, 1, 0, 0, 0, 0, 0, 0, 1, 0],
      str(rep["nearest_surviving_cos_hist"]))

# recall is non-decreasing in tau (stricter tau → more flagged novel)
mono = score_holdout(held, retained_ids, retained,
                     thresholds=[0.4, 0.94, 0.999], prod_tau=0.94)
rc = [s["novelty_recall"] for s in mono["sweep"]]
check("novelty_recall non-decreasing in tau", rc[0] <= rc[1] <= rc[2], str(rc))
# H1 (cos 0 to the only survivor B) is novel even at tau=0.4 → 1/3
check("recall@0.4 == 0.3333 (only the far session H1)", rc[0] == 0.3333, str(rc[0]))
check("recall@0.999 == 1.0 (all novel)", rc[2] == 1.0, str(rc[2]))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
