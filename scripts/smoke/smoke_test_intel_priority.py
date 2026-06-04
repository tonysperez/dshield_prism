"""Smoke test for `enrich.intel.queue.compute_priority`.

Verifies that the priority formula:
  - returns 0 for empty inputs,
  - peaks at 1.0 when every signal saturates,
  - puts novelty above the other signals at default weights,
  - decays recency on the configured half-life.

Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_priority.py
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import IntelPriorityConfig
from enrich.intel.queue import PriorityInputs, compute_priority


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def approx(a: float, b: float, tol: float = 1e-6) -> bool:
    return abs(a - b) <= tol


W = IntelPriorityConfig()


print("[1] all signals None → priority 0")
score = compute_priority(PriorityInputs(), W)
check("empty inputs zero", approx(score, 0.0), f"got {score}")


print("\n[2] all signals saturate → priority equals weight sum (~1.0)")
score = compute_priority(
    PriorityInputs(novelty_score=1.0, confidence=1, centrality_norm=1.0, age_hours=0.0),
    W,
)
expected = W.novelty_w + W.low_conf_w * 0.9 + W.centrality_w + W.recency_w
check("saturated near weight-sum", approx(score, expected),
      f"got {score} expected {expected}")


print("\n[3] novelty dominates: 1.0 novelty alone outranks 1.0 centrality alone")
nov_only = compute_priority(PriorityInputs(novelty_score=1.0), W)
cent_only = compute_priority(PriorityInputs(centrality_norm=1.0), W)
check("novelty > centrality at equal magnitude",
      nov_only > cent_only,
      f"novelty={nov_only} centrality={cent_only}")


print("\n[4] confidence inversion: low confidence increases priority")
low_conf = compute_priority(PriorityInputs(confidence=1), W)
high_conf = compute_priority(PriorityInputs(confidence=10), W)
check("low conf > high conf", low_conf > high_conf,
      f"low={low_conf} high={high_conf}")


print("\n[5] recency half-life decays correctly")
age_zero = compute_priority(PriorityInputs(age_hours=0.0), W)
age_half = compute_priority(PriorityInputs(age_hours=W.recency_half_life_hours), W)
# Recency term alone: 1.0 at age=0, 0.5 at half-life. So score difference
# should equal 0.5 * recency_w.
diff = age_zero - age_half
check("recency half-life decay correct",
      approx(diff, 0.5 * W.recency_w, tol=1e-4),
      f"diff={diff} expected={0.5 * W.recency_w}")


print("\n[6] negative / out-of-range signals are clamped")
score_neg = compute_priority(PriorityInputs(novelty_score=-2.0), W)
score_hi = compute_priority(PriorityInputs(novelty_score=2.0), W)
check("negative novelty clamps to 0", approx(score_neg, 0.0),
      f"got {score_neg}")
check("supra-1 novelty clamps to 1", approx(score_hi, W.novelty_w),
      f"got {score_hi}")


print("\n[7] missing recency_half_life disables term")
W0 = IntelPriorityConfig(recency_half_life_hours=0.0)
score = compute_priority(PriorityInputs(age_hours=0.0), W0)
check("disabled half-life zero", approx(score, 0.0), f"got {score}")


print("\n[8] reordering different signals preserves contribution math")
inputs = PriorityInputs(novelty_score=0.4, confidence=4, centrality_norm=0.2, age_hours=24.0)
score = compute_priority(inputs, W)
parts = (
    W.novelty_w * 0.4,
    W.low_conf_w * 0.6,
    W.centrality_w * 0.2,
    W.recency_w * math.exp(-math.log(2.0) * 24.0 / W.recency_half_life_hours),
)
check("manual decomposition matches",
      approx(score, sum(parts), tol=1e-6),
      f"got {score} expected {sum(parts)}")


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
