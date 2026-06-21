"""Smoke test: IP-layer augmented-space noise rescue.

The IP layer clusters on the augmented `[embedding ⊕ scalar]` euclidean space, so
its noise rescue must reassign outliers in THAT space (within a percentile of the
intra-cluster spread) — not the pure-embedding cosine the command/session layers
use. This covers `rescue_noise_points_augmented`:

  * a noise point within the percentile radius of a centroid is rescued to the
    correct (nearest) cluster; one beyond it stays noise (-1).
  * the radius is the requested percentile of the clustered intra-cluster spread,
    so a looser percentile rescues at least as many points.
  * `spread_percentile=0` and "no noise" are no-ops.
  * the pure-cosine `rescue_noise_points` path is left untouched.
  * `IPConfig.rescue_spread_percentile` defaults on (90); command/session layers
    don't set it.

Standalone — no ES, no LLM.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_ip_rescue.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np

from enrich.clustering import rescue_noise_points, rescue_noise_points_augmented
from enrich.config import IPConfig

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name if ok else (name, detail))  # type: ignore[arg-type]
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail and not ok else ""))


def _fixture():
    """Two tight clusters (labels 0,1) in 4-D + three noise points: one well
    inside cluster 0's radius, one well inside cluster 1's, one far between."""
    rng = np.random.default_rng(0)
    c0 = rng.normal(0.0, 0.05, (20, 4)).astype(np.float32)
    c1 = (np.array([10, 0, 0, 0]) + rng.normal(0.0, 0.05, (20, 4))).astype(np.float32)
    labels = np.array([0] * 20 + [1] * 20 + [-1, -1, -1])
    near0 = np.array([[0.02, 0, 0, 0]], np.float32)
    near1 = np.array([[10.0, 0.02, 0, 0]], np.float32)
    far = np.array([[5.0, 5.0, 0, 0]], np.float32)
    M = np.vstack([c0, c1, near0, near1, far]).astype(np.float32)
    return M, labels  # noise rows are indices 40 (near0), 41 (near1), 42 (far)


# ---------------------------------------------------------------------------
print("[1] augmented rescue assigns near-cluster noise to the nearest centroid")
M, labels = _fixture()
new, n, radius = rescue_noise_points_augmented(M, labels, 90)
check("radius is a positive intra-cluster percentile", radius > 0.0, detail=f"radius={radius}")
check("rescued exactly the 2 near points", n == 2, detail=f"n={n}")
check("near-cluster-0 noise -> cluster 0", new[40] == 0, detail=f"got {new[40]}")
check("near-cluster-1 noise -> cluster 1", new[41] == 1, detail=f"got {new[41]}")
check("far noise stays outlier (-1)", new[42] == -1, detail=f"got {new[42]}")
check("clustered labels untouched", (new[:40] == labels[:40]).all())

# ---------------------------------------------------------------------------
print("[2] looser percentile -> larger radius -> rescues at least as many")
_, n50, r50 = rescue_noise_points_augmented(M, labels, 50)
_, n99, r99 = rescue_noise_points_augmented(M, labels, 99)
check("p99 radius >= p50 radius", r99 >= r50, detail=f"{r99} vs {r50}")
check("p99 rescues >= p50 rescues", n99 >= n50, detail=f"{n99} vs {n50}")

# ---------------------------------------------------------------------------
print("[3] no-op guards")
new0, n0, r0 = rescue_noise_points_augmented(M, labels, 0)
check("spread_percentile=0 is a no-op", n0 == 0 and (new0 == labels).all() and r0 == 0.0)
clean = labels[:40]
_, nclean, _ = rescue_noise_points_augmented(M[:40], clean, 90)
check("no noise points -> no-op", nclean == 0)

# ---------------------------------------------------------------------------
print("[4] pure-cosine rescue path is untouched (command/session layers)")
# Unit-norm rows: two clusters on opposite poles + one noise near pole A.
a = np.array([[1.0, 0.0], [0.98, 0.20]], np.float32)
a /= np.linalg.norm(a, axis=1, keepdims=True)
b = np.array([[-1.0, 0.0], [-0.98, 0.20]], np.float32)
b /= np.linalg.norm(b, axis=1, keepdims=True)
noise = np.array([[0.999, 0.045]], np.float32)
noise /= np.linalg.norm(noise, axis=1, keepdims=True)
Mc = np.vstack([a, b, noise]).astype(np.float32)
lc = np.array([0, 0, 1, 1, -1])
newc, nc = rescue_noise_points(Mc, lc, 0.95)
check("pure-cosine rescue still rescues the near-pole noise", nc == 1 and newc[4] == 0,
      detail=f"n={nc} label={newc[4]}")

# ---------------------------------------------------------------------------
print("[5] config default")
check("IPConfig.rescue_spread_percentile defaults to 99", IPConfig().rescue_spread_percentile == 99,
      detail=str(IPConfig().rescue_spread_percentile))

# ---------------------------------------------------------------------------
print()
print(f"{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for name, detail in FAILED:
        print(f"  FAIL  {name}  {detail}")
    sys.exit(1)
print("SMOKE TEST: PASS")
