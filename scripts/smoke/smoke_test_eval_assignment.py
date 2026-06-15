"""Smoke test for the assignment-eval pure cores
(`scripts/eval_assignment.py`): build_prototypes, classification_metrics,
_rank_auc, novelty_metrics, stratified_split. No ES, no eval files.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from eval_assignment import (
    _rank_auc,
    build_prototypes,
    classification_metrics,
    novelty_metrics,
    stratified_split,
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


# Two well-separated label clusters on orthogonal axes (4-d).
A = [_u([1, 0, 0.05, 0]), _u([1, 0, -0.05, 0]), _u([1, 0.03, 0, 0]), _u([1, -0.03, 0, 0])]
B = [_u([0, 1, 0.05, 0]), _u([0, 1, -0.05, 0]), _u([0.03, 1, 0, 0]), _u([-0.03, 1, 0, 0])]
embs = np.array(A + B, dtype=np.float32)
labels = ["A"] * 4 + ["B"] * 4

# --- stratified_split: alternating per label ---
tr, te = stratified_split(labels)
check("split covers all, disjoint", sorted(tr + te) == list(range(8)) and not set(tr) & set(te))
check("each label split ~half (2 train / 2 test for A)",
      sum(1 for i in tr if labels[i] == "A") == 2, str(tr))

# --- build_prototypes ---
pids, pmat = build_prototypes(embs, labels)
check("two prototypes A,B", pids == ["A", "B"], str(pids))
check("prototype A ~ e0, B ~ e1",
      pmat[0][0] > 0.99 and pmat[1][1] > 0.99, str(pmat))

# --- classification_metrics: well-separated → perfect ---
cls = classification_metrics(embs, labels, pids, pmat)
check("perfect accuracy on separable labels", cls["accuracy"] == 1.0, str(cls["accuracy"]))
check("macro_f1 == 1.0", cls["macro_f1"] == 1.0, str(cls["macro_f1"]))

# --- _rank_auc: perfectly separated positives above negatives → 1.0 ---
check("rank_auc perfect separation == 1.0",
      _rank_auc(np.array([0.9, 0.8]), np.array([0.1, 0.2])) == 1.0)
check("rank_auc reversed == 0.0",
      _rank_auc(np.array([0.1, 0.2]), np.array([0.9, 0.8])) == 0.0)
check("rank_auc empty → None", _rank_auc(np.array([]), np.array([0.5])) is None)

# --- novelty_metrics: hold out A → A's sessions are far from B (the only survivor) ---
nov = novelty_metrics(embs, labels, min_label_size=4)
check("both labels held out and scored", set(nov["per_label"]) == {"A", "B"}, str(nov["per_label"]))
check("held-out A reads as novel (mean_heldout_cos < mean_indist_cos)",
      nov["per_label"]["A"]["mean_heldout_cos"] < nov["per_label"]["A"]["mean_indist_cos"],
      str(nov["per_label"]["A"]))
check("mean_auc_novel high for orthogonal labels (>=0.9)",
      nov["mean_auc_novel"] >= 0.9, str(nov["mean_auc_novel"]))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
