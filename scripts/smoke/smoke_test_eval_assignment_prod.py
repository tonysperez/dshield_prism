"""Smoke test for the production-scale assignment-eval scoring
(`scripts/eval_assignment_prod.py::score_against_anchors`). No ES, no snapshot file.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from capture_anchor_snapshot import centroid
from eval_assignment_prod import score_against_anchors

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


# Two behaviour-pure anchors (A on e0, B on e1); two sessions per behaviour right on top.
anchors = np.array([[1, 0, 0, 0], [0, 1, 0, 0]], dtype=np.float32)
anchor_ids = ["spb-A", "spb-B"]
embs = np.array([_u([1, 0, 0.02, 0]), _u([1, 0, -0.02, 0]),
                 _u([0, 1, 0.02, 0]), _u([0, 1, -0.02, 0])], dtype=np.float32)
labels = ["recon", "recon", "persist", "persist"]

rep = score_against_anchors(embs, labels, anchor_ids, anchors, tau=0.9, confident_tau=0.98)
check("all assigned (known sessions on their anchors)", rep["assigned_rate"] == 1.0, str(rep))
check("novel_rate 0.0", rep["novel_rate"] == 0.0)
check("homogeneity 1.0 (each anchor is one behaviour)", rep["homogeneity"] == 1.0, str(rep["homogeneity"]))
check("anchor_label_purity 1.0", rep["anchor_label_purity"] == 1.0, str(rep["anchor_label_purity"]))
check("n_assigned == 4", rep["n_assigned"] == 4)

# A session far from every anchor → novel (lowers assigned_rate).
embs2 = np.vstack([embs, _u([0, 0, 1, 0])])  # orthogonal to both anchors
labels2 = labels + ["weird"]
rep2 = score_against_anchors(embs2, labels2, anchor_ids, anchors, tau=0.9, confident_tau=0.98)
check("far session lands novel → assigned_rate 0.8", rep2["assigned_rate"] == 0.8, str(rep2))

# No anchors / nothing assigns → graceful Nones.
empty = score_against_anchors(embs, labels, [], np.zeros((0, 4), dtype=np.float32),
                              tau=0.9, confident_tau=0.98)
check("empty anchors → assigned_rate 0.0, homogeneity None",
      empty["assigned_rate"] == 0.0 and empty["homogeneity"] is None, str(empty))

# --- public-derived centroid math (capture_anchor_snapshot.centroid) ---
import math  # noqa: E402

check("centroid of identical unit vecs == itself", centroid([[1, 0], [1, 0]]) == [1.0, 0.0])
check("centroid normalises the mean",
      abs(centroid([[2, 0], [0, 0]])[0] - 1.0) < 1e-6, str(centroid([[2, 0], [0, 0]])))
c = centroid([[1, 0], [0, 1]])
check("centroid of orthogonal pair ~ [.707,.707]",
      abs(c[0] - math.sqrt(0.5)) < 1e-6 and abs(c[1] - math.sqrt(0.5)) < 1e-6, str(c))
check("zero mean → returned as-is (no div-by-zero)", centroid([[0.0, 0.0]]) == [0.0, 0.0])

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
