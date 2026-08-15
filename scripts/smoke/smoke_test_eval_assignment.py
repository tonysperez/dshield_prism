"""Smoke test for the assignment-eval pure cores
(`scripts/eval_assignment.py`): build_prototypes, classification_metrics,
_rank_auc, novelty_metrics, repeated_stratified_kfold. No ES, no eval files.
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
    repeated_stratified_kfold,
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

# --- repeated_stratified_kfold: each fold covers all, disjoint train/test ---
folds = repeated_stratified_kfold(labels, k=2, repeats=2, seed=0)
check("k=2 x repeats=2 -> 4 folds", len(folds) == 4, str(len(folds)))
for tr, te in folds:
    check("fold covers all, disjoint", sorted(tr + te) == list(range(8)) and not set(tr) & set(te),
          str((tr, te)))
    check("each label present in test (k=2, size 4 -> 2 per fold)",
          sum(1 for i in te if labels[i] == "A") == 2
          and sum(1 for i in te if labels[i] == "B") == 2, str(te))
folds_a = repeated_stratified_kfold(labels, k=2, repeats=2, seed=0)
folds_b = repeated_stratified_kfold(labels, k=2, repeats=2, seed=0)
check("deterministic under fixed seed", folds_a == folds_b, str((folds_a, folds_b)))

# --- build_prototypes ---
pids, pmat = build_prototypes(embs, labels)
check("two prototypes A,B", pids == ["A", "B"], str(pids))
check("prototype A ~ e0, B ~ e1",
      pmat[0][0] > 0.99 and pmat[1][1] > 0.99, str(pmat))

# --- classification_metrics: well-separated → perfect ---
cls = classification_metrics(embs, labels, pids, pmat)
check("perfect accuracy on separable labels", cls["accuracy"] == 1.0, str(cls["accuracy"]))
check("macro_f1 == 1.0", cls["macro_f1"] == 1.0, str(cls["macro_f1"]))

# --- classification_metrics: `scoreable` gates the macro mean, not per_label ---
# A third label C that the prototypes cannot possibly predict (no prototype for
# it) stands in for a corpus-singleton: it scores a structural F1 of 0.0. Held
# in the macro mean it drags the score; excluded via `scoreable` it does not,
# but it must still be REPORTED in per_label either way.
_c = np.zeros((1, embs.shape[1]), dtype=np.float32)
_c[0, -1] = 1.0
emb3 = np.vstack([embs, _c])
lab3 = labels + ["C"]
cls_all = classification_metrics(emb3, lab3, pids, pmat)
cls_sub = classification_metrics(emb3, lab3, pids, pmat, scoreable={"A", "B"})
check("unlearnable label scores f1 0.0", cls_all["per_label"]["C"]["f1"] == 0.0,
      str(cls_all["per_label"]["C"]))
check("scoreable=None keeps the old behavior (C drags the mean)",
      cls_all["macro_f1"] < cls_sub["macro_f1"], f"{cls_all['macro_f1']} {cls_sub['macro_f1']}")
_ab = [cls_sub["per_label"][lb]["f1"] for lb in ("A", "B")]
check("excluded macro_f1 is exactly the mean over scoreable labels",
      abs(cls_sub["macro_f1"] - sum(_ab) / 2) < 1e-4, f"{cls_sub['macro_f1']} vs {_ab}")
check("excluding from the mean does NOT erase C's misassignment cost "
      "(its session still hurts A/B precision, so macro_f1 < 1.0)",
      cls_sub["macro_f1"] < 1.0, str(cls_sub["macro_f1"]))
check("per_label still reports the excluded label",
      "C" in cls_sub["per_label"], str(sorted(cls_sub["per_label"])))
check("accuracy is unaffected by scoreable (not a macro average)",
      cls_all["accuracy"] == cls_sub["accuracy"], str((cls_all["accuracy"], cls_sub["accuracy"])))

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
