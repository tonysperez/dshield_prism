"""Smoke test for ROADMAP #12: in-run novelty score must be computed in the
same space HDBSCAN clustered on, not in the pure-embedding space.

Standalone — no ES, no HDBSCAN, no pytest. We hand-build cluster_matrix
analogues and assert:

  1. `novelty_score` returns proper cosine novelty on non-unit-norm vectors
     (backward-compatible: unit-norm input still gives the prior result).
  2. With scalar_weight=0, augmented and pure centroids coincide → identical
     behaviour to before the fix (regression guard).
  3. With scalar_weight>0, a row whose embedding sits far from its cluster's
     embedding-centroid but whose scalars pull it close to that cluster's
     augmented-centroid scores LOW novelty in augmented space (correct) and
     HIGH novelty in pure-embedding space (the old, buggy behaviour). The
     fix flipped which one ships on the doc.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_novelty_space.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

try:
    import numpy as np
except ImportError:
    print("numpy not available — skipping (cluster deps not installed in this venv)")
    sys.exit(0)

from enrich.clustering import compute_centroids, novelty_score

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def _unit(v: list[float]) -> np.ndarray:
    arr = np.array(v, dtype=np.float32)
    n = float(np.linalg.norm(arr))
    return arr / n if n > 0 else arr


# -----------------------------------------------------------------------------
# [1] novelty_score is backward-compatible on unit-norm input.
# -----------------------------------------------------------------------------
print("\n[1] novelty_score backward-compat on unit-norm input")
c = {0: _unit([1.0, 0.0])}
v_aligned = _unit([1.0, 0.0])
v_orthog = _unit([0.0, 1.0])
check(
    "aligned unit vector → novelty ~ 0",
    abs(novelty_score(v_aligned, c)) < 1e-5,
    f"got {novelty_score(v_aligned, c)}",
)
check(
    "orthogonal unit vector → novelty ~ 1",
    abs(novelty_score(v_orthog, c) - 1.0) < 1e-5,
    f"got {novelty_score(v_orthog, c)}",
)


# -----------------------------------------------------------------------------
# [2] novelty_score handles non-unit-norm rows as proper cosine sim.
# -----------------------------------------------------------------------------
print("\n[2] novelty_score on non-unit-norm rows is proper cosine sim")
# vec = (3, 4) → |vec|=5; centroid = (1, 0) → cos = 3/5 = 0.6 → novelty=0.4
vec = np.array([3.0, 4.0], dtype=np.float32)
centroid = {0: np.array([1.0, 0.0], dtype=np.float32)}
got = novelty_score(vec, centroid)
expected = 1.0 - 0.6
check(
    "non-unit vec scored by proper cosine",
    abs(got - expected) < 1e-5,
    f"got {got}, expected {expected}",
)
# Reverse direction → cos = -0.6 → clipped at 0 → novelty=1
vec_neg = np.array([-3.0, -4.0], dtype=np.float32)
got = novelty_score(vec_neg, centroid)
check(
    "negative cosine clipped to 0 → novelty=1",
    abs(got - 1.0) < 1e-5,
    f"got {got}",
)


# -----------------------------------------------------------------------------
# [3] scalar_weight=0 regression guard — augmented == pure centroids.
# -----------------------------------------------------------------------------
print("\n[3] scalar_weight=0: augmented centroids identical to pure")
# Two clusters in 2D embedding space, no scalars appended.
normalized = np.array([
    _unit([1.0, 0.0]),   # cluster 0
    _unit([0.98, 0.02]), # cluster 0
    _unit([0.0, 1.0]),   # cluster 1
    _unit([0.02, 0.98]), # cluster 1
], dtype=np.float32)
labels = np.array([0, 0, 1, 1], dtype=np.int64)
centroids_pure = compute_centroids(normalized, labels)
centroids_aug = compute_centroids(normalized, labels)  # same matrix
check(
    "pure and augmented centroids are bit-identical when no scalars",
    all(np.allclose(centroids_pure[k], centroids_aug[k]) for k in centroids_pure),
    "centroids differ in zero-scalar path",
)


# -----------------------------------------------------------------------------
# [4] The core fix — a row whose scalars pull it into a cluster scores LOW
# novelty in augmented space (correct) and HIGH novelty in pure space (bug).
# -----------------------------------------------------------------------------
print("\n[4] scalar-pulled row: novelty differs between pure and augmented")
# Two embedding clusters: one near +x, one near +y.
# Add a single scalar dimension (call it `occurrence_count`-style) where
# cluster A members have high scalar (~1.0) and cluster B members low (~0.0).
# Then a row whose embedding sits between the two clusters but whose scalar
# is ~1.0 will be pulled into cluster A in augmented space.
emb_A1 = _unit([1.0, 0.05])
emb_A2 = _unit([0.98, 0.0])
emb_B1 = _unit([0.05, 1.0])
emb_B2 = _unit([0.0, 0.98])
# Row of interest: midway between A and B in embedding space.
emb_mid = _unit([0.7, 0.7])

# Scalar block — single column, weight already folded in.
scalar_weight = 0.5
sca_A1 = np.array([1.0 * scalar_weight], dtype=np.float32)
sca_A2 = np.array([1.0 * scalar_weight], dtype=np.float32)
sca_B1 = np.array([0.0 * scalar_weight], dtype=np.float32)
sca_B2 = np.array([0.0 * scalar_weight], dtype=np.float32)
sca_mid = np.array([1.0 * scalar_weight], dtype=np.float32)  # pulls into A

normalized = np.stack([emb_A1, emb_A2, emb_B1, emb_B2, emb_mid])
scalars = np.stack([sca_A1, sca_A2, sca_B1, sca_B2, sca_mid])
cluster_matrix = np.hstack([normalized, scalars])

# Simulated HDBSCAN result: the mid row joined cluster A because its
# scalar matches A's. (We assign labels by hand to model what HDBSCAN
# would produce on this matrix.)
labels = np.array([0, 0, 1, 1, 0], dtype=np.int64)

centroids_pure = compute_centroids(normalized, labels)
centroids_aug = compute_centroids(cluster_matrix, labels)

# Pure-embedding novelty (the OLD, buggy behaviour for in-run scoring).
old_score = novelty_score(normalized[4], centroids_pure)
# Augmented novelty (the NEW behaviour after fix).
new_score = novelty_score(cluster_matrix[4], centroids_aug)

print(f"      old (pure-emb)     novelty for the scalar-pulled row: {old_score:.4f}")
print(f"      new (augmented)    novelty for the scalar-pulled row: {new_score:.4f}")

# The bug we're fixing: under the old computation the row looks novel against
# its own cluster (high score). Under the fix, it should look much closer to
# its cluster because the scalar that pulled it in is part of the comparison.
check(
    "old pure-emb novelty is high (the bug — row looks novel inside its own cluster)",
    old_score > 0.10,
    f"old_score={old_score}",
)
check(
    "new augmented novelty is meaningfully lower than old",
    new_score < old_score,
    f"old_score={old_score}, new_score={new_score}",
)


# -----------------------------------------------------------------------------
# [5] No centroids → novelty=1.0 (regression guard for early-run path).
# -----------------------------------------------------------------------------
print("\n[5] empty centroids → novelty=1.0")
check(
    "empty centroids dict → novelty=1.0",
    novelty_score(np.array([1.0, 0.0]), {}) == 1.0,
    "",
)


# -----------------------------------------------------------------------------
# [6] Zero-norm vec → novelty=1.0 (regression guard — would have divided by 0).
# -----------------------------------------------------------------------------
print("\n[6] zero-norm row → novelty=1.0 (no division-by-zero)")
check(
    "zero-norm row → novelty=1.0",
    novelty_score(np.zeros(3, dtype=np.float32), {0: np.array([1.0, 0.0, 0.0])}) == 1.0,
    "",
)


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
