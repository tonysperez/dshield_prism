"""Smoke test for the TF-IDF-separation experiment math
(`scripts/exp_tfidf_separation.py`): group_centroids, cross_assign_rate,
pair_report — and the "embedding-close but TF-IDF-far ⇒ conflation" decision.

Standalone — no pytest, no ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from exp_tfidf_separation import cross_assign_rate, group_centroids, pair_report

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# --- group_centroids: L2-normalised mean per group ---
vecs = np.array([[1.0, 0.0], [1.0, 0.0], [0.0, 2.0]], dtype=np.float32)
cents = group_centroids(vecs, ["A", "A", "B"])
check("centroid A == [1,0]", np.allclose(cents["A"], [1.0, 0.0]), str(cents["A"]))
check("centroid B == [0,1] (normalised)", np.allclose(cents["B"], [0.0, 1.0]), str(cents["B"]))

# --- cross_assign_rate: fraction of A nearer B than A ---
va = np.array([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)
rate = cross_assign_rate(va, np.array([1.0, 0.0]), np.array([0.0, 1.0]))
check("cross_assign_rate == 0.5 (one of two crosses)", rate == 0.5, str(rate))
check("cross_assign_rate empty == 0.0",
      cross_assign_rate(np.zeros((0, 2), dtype=np.float32),
                        np.array([1.0, 0.0]), np.array([0.0, 1.0])) == 0.0)

# --- pair_report: the conflation case (emb close, tfidf far) ---
e0 = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
v95 = np.array([0.95, 0.0, 0.31224990, 0.0], dtype=np.float32)  # cos 0.95 to e0
emb_cents = {"A": e0, "B": v95}
tfidf_cents = {"A": np.array([1.0, 0.0], dtype=np.float32),
               "B": np.array([0.0, 1.0], dtype=np.float32)}      # cos 0.0
emb_by_group = {"A": e0.reshape(1, -1), "B": v95.reshape(1, -1)}
tfidf_by_group = {"A": np.array([[1.0, 0.0]], dtype=np.float32),
                  "B": np.array([[0.0, 1.0]], dtype=np.float32)}
rows = pair_report(emb_cents, tfidf_cents, emb_by_group, tfidf_by_group,
                   [("A", "B")], {("A", "B"): 0.95})
r = rows[0]
check("pair: anchor_emb_cos == 0.95", r["anchor_emb_cos"] == 0.95, str(r))
check("pair: sample_emb_cos == 0.95 (embedding-close)", r["sample_emb_cos"] == 0.95, str(r))
check("pair: tfidf_cos == 0.0 (TF-IDF separates)", r["tfidf_cos"] == 0.0, str(r))
check("pair: n_a == n_b == 1", r["n_a"] == 1 and r["n_b"] == 1)

# the decision the headline encodes: emb-close (>=0.94) AND tfidf-far (<0.94) ⇒ conflation
family_tau = 0.94
is_close = r["anchor_emb_cos"] >= family_tau
is_separated = r["tfidf_cos"] < family_tau
check("decision: embedding-close AND TF-IDF-separated ⇒ conflation flagged",
      is_close and is_separated, f"close={is_close} sep={is_separated}")

# control: a genuinely-same pair (both spaces agree it's close) is NOT flagged
tfidf_cents2 = {"A": e0[:2] / np.linalg.norm(e0[:2]),
                "B": v95[:2] / np.linalg.norm(v95[:2])}  # also ~close in tfidf
rows2 = pair_report(emb_cents, tfidf_cents2, emb_by_group,
                    {"A": (e0[:2] / np.linalg.norm(e0[:2])).reshape(1, -1),
                     "B": (v95[:2] / np.linalg.norm(v95[:2])).reshape(1, -1)},
                    [("A", "B")], {("A", "B"): 0.95})
check("control: same behaviour stays TF-IDF-close (not flagged)",
      rows2[0]["tfidf_cos"] >= family_tau, str(rows2[0]["tfidf_cos"]))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
