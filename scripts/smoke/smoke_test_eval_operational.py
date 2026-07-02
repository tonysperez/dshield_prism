"""Smoke test for the operational-gate pure cores
(`scripts/eval_operational.py`): _pr_from_records, purity_of, novelty_records,
bootstrap_half_width, build_baseline, gate. No ES, no eval files, no network.

Guards the load-bearing properties the gate is built on:
  * false-familiar == 1 - novel recall (same quantity, reported not double-gated).
  * a CI-floor metric below tolerance FAILs; a per-label accuracy below the hard
    floor FAILs (collapse detector); a `diagnostic`-basis metric NEVER FAILs.
  * bootstrap is deterministic (same seed -> identical half-width).
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from eval_operational import (
    _pr_from_records,
    bootstrap_half_width,
    build_baseline,
    gate,
    novelty_records,
    purity_of,
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


def _u(v):
    a = np.array(v, dtype=np.float32)
    return a / np.linalg.norm(a)


# --- _pr_from_records: known confusion --------------------------------------
# (truth_novel, pred_novel): 1 TP, 1 FP, 1 FN, 1 TN
recs = [(True, True), (False, True), (True, False), (False, False)]
pr = _pr_from_records(recs)
check("precision = TP/(TP+FP) = 0.5", pr["novel_precision"] == 0.5, str(pr))
check("recall = TP/(TP+FN) = 0.5", pr["novel_recall"] == 0.5, str(pr))
check("false_familiar == 1 - recall",
      abs(pr["false_familiar"] - (1 - pr["novel_recall"])) < 1e-9, str(pr))
check("n_flagged_novel = TP+FP = 2", pr["n_flagged_novel"] == 2, str(pr))

# --- purity_of: known-pure vs mixed pool ------------------------------------
check("pure pool -> purity 1.0", purity_of([("A", "A"), ("A", "A")]) == 1.0)
check("2/3 mixed pool", purity_of([("A", "A"), ("A", "A"), ("B", "A")]) == 0.6667,
      str(purity_of([("A", "A"), ("A", "A"), ("B", "A")])))
check("empty pool -> None", purity_of([]) is None)

# --- novelty_records: separable labels -> held-out reads novel --------------
A = [_u([1, 0, 0.04, 0]), _u([1, 0.03, 0, 0]), _u([1, -0.03, 0, 0]), _u([1, 0, -0.04, 0])]
B = [_u([0, 1, 0.04, 0]), _u([0, 1, -0.04, 0]), _u([0.03, 1, 0, 0]), _u([-0.03, 1, 0, 0])]
embs = np.array(A + B, dtype=np.float32)
labels = ["A"] * 4 + ["B"] * 4
nrecs = novelty_records(labels, embs, tau=0.94, confident_tau=0.98, min_label_size=4)
held = _pr_from_records(nrecs)
check("orthogonal held-out labels read novel (recall >= 0.9)",
      held["novel_recall"] is not None and held["novel_recall"] >= 0.9, str(held))

# --- bootstrap determinism --------------------------------------------------
vals = [(True, True), (True, False), (False, False)] * 10
hw1 = bootstrap_half_width(vals, lambda s: _pr_from_records(s)["novel_recall"], n=200, seed=0)
hw2 = bootstrap_half_width(vals, lambda s: _pr_from_records(s)["novel_recall"], n=200, seed=0)
check("bootstrap deterministic for a fixed seed", hw1 == hw2, f"{hw1} != {hw2}")
check("bootstrap empty -> 0.0", bootstrap_half_width([], purity_of, n=50) == 0.0)

# --- gate: direction + basis semantics --------------------------------------
baseline = {
    "metrics": {
        "macro_f1": {"baseline": 0.80, "tolerance": 0.05, "direction": "floor", "basis": "ci"},
        "novel_recall": {"baseline": 0.70, "tolerance": 0.05, "direction": "floor", "basis": "ci"},
        "alarm_rate": {"baseline": 0.10, "tolerance": 0.05, "direction": "ceiling", "basis": "ci"},
        "false_familiar": {"baseline": 0.10, "direction": "ceiling", "basis": "diagnostic"},
    },
    "per_label_floor": 0.3,
}


def _report(macro_f1, per_label, *, recall=0.72, alarm=0.10, ff=0.10):
    return {"metrics": {"macro_f1": macro_f1, "novel_recall": recall, "alarm_rate": alarm,
                        "false_familiar": ff, "novel_precision": None,
                        "minted_purity": None, "minted_distinct": None},
            "per_label_accuracy": per_label}


# healthy
_, ok = gate(_report(0.80, {"x": 0.9, "y": 0.8}), baseline)
check("healthy report -> PASS", ok is True)
# macro-F1 below baseline - tol -> FAIL
_, ok = gate(_report(0.70, {"x": 0.9}), baseline)
check("CI floor below tolerance -> FAIL", ok is False)
# per-label collapse below hard floor -> FAIL even if macro holds
_, ok = gate(_report(0.80, {"x": 0.9, "y": 0.10}), baseline)
check("per-label below hard floor -> FAIL (collapse detector)", ok is False)
# gated ceiling metric above baseline + tol -> FAIL
_, ok = gate(_report(0.80, {"x": 0.9}, alarm=0.30), baseline)
check("CI ceiling above tolerance -> FAIL", ok is False)
# gated metric that went None at runtime -> FAIL (collapse, not silent skip)
_, ok = gate(_report(0.80, {"x": 0.9}, recall=None), baseline)
check("gated metric None at runtime -> FAIL (not SKIP)", ok is False)
# diagnostic metric with an absurd value -> still PASS (never gates)
_, ok = gate(_report(0.80, {"x": 0.9}, ff=0.99), baseline)
check("diagnostic false_familiar never fails the build", ok is True)

# --- build_baseline: degenerate novelty -> diagnostic -----------------------
degen_report = {
    "ci_half_width": {"macro_f1": 0.03, "novel_recall": 0.0, "novel_precision": 0.0,
                      "minted_purity": 0.0},
    "metrics": {"macro_f1": 0.8, "novel_precision": 0.0, "novel_recall": 0.0,
                "false_familiar": 1.0, "minted_purity": None, "minted_distinct": None},
    "novelty_degenerate": True, "per_label_floor": 0.3, "tau": 0.94,
    "confident_tau": 0.98, "holdout_k": 2,
}
bl = build_baseline(degen_report, epsilon=0.02)
check("degenerate novelty -> novel_recall basis diagnostic",
      bl["metrics"]["novel_recall"]["basis"] == "diagnostic")
check("non-degenerate would gate: macro_f1 stays ci floor",
      bl["metrics"]["macro_f1"]["basis"] == "ci")

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
