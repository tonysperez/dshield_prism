"""Smoke test for session-layer HDBSCAN noise rescue (ROADMAP audit).

`rescue_noise_points` reassigns HDBSCAN outliers (-1) to their nearest cluster
centroid when pure-embedding cosine >= threshold — extending the centroid-level
merge (`playbook_merge_threshold`) down to the loose noise points HDBSCAN drops
from a cluster's low-density periphery.

Standalone — no ES/LLM. Skips cleanly if numpy is unavailable.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_noise_rescue.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

try:
    import numpy as np
except ImportError:
    print("numpy unavailable — skipping (cluster extras not installed)")
    sys.exit(0)

from enrich.clustering import rescue_noise_points

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


def unit(v):
    v = np.asarray(v, dtype=np.float32)
    return v / (np.linalg.norm(v) + 1e-12)


# Two well-separated directions in 3-D, L2-normalised "embeddings".
A = unit([1.0, 0.0, 0.0])
B = unit([0.0, 1.0, 0.0])
# Periphery point: cosine ~0.98 to A (between 0.96 and 0.99).
near_A = unit([1.0, 0.2, 0.0])
# Mid point: cosine ~0.71 to both — should NOT be rescued at 0.96.
mid = unit([1.0, 1.0, 0.0])

# -----------------------------------------------------------------------------
print("[1] rescues a near-cluster outlier, leaves a far one as noise")
# rows: 3 in cluster 0 (exactly A), 3 in cluster 1 (exactly B), then 2 noise.
rows = np.vstack([A, A, A, B, B, B, near_A, mid])
labels = np.array([0, 0, 0, 1, 1, 1, -1, -1])
new, n = rescue_noise_points(rows, labels, 0.96)
check("rescued exactly 1 point", n == 1, f"n={n}")
check("near-A noise (cosine ~0.98) joined cluster 0", new[6] == 0, f"label={new[6]}")
check("far (mid) noise stayed outlier", new[7] == -1, f"label={new[7]}")
check("original cluster labels untouched", list(new[:6]) == [0, 0, 0, 1, 1, 1], str(new[:6]))
check("input labels not mutated in place", labels[6] == -1, str(labels[6]))

# -----------------------------------------------------------------------------
print("\n[2] threshold gates the rescue")
new0, n0 = rescue_noise_points(rows, labels, 0.99)
check("threshold above the point's cosine rescues none", n0 == 0, f"n={n0} (near-A ~0.98 < 0.99)")
new_lo, n_lo = rescue_noise_points(rows, labels, 0.5)
check("low threshold rescues both noise points", n_lo == 2, f"n={n_lo}")

# -----------------------------------------------------------------------------
print("\n[3] edge cases")
# No noise → no-op.
nl, nn = rescue_noise_points(rows, np.array([0, 0, 0, 1, 1, 1, 0, 1]), 0.96)
check("no noise points → 0 rescued", nn == 0, f"n={nn}")
# All noise (no centroids) → no-op.
nl2, nn2 = rescue_noise_points(rows, np.full(len(rows), -1), 0.96)
check("no clusters → 0 rescued", nn2 == 0, f"n={nn2}")
# threshold > 1.0 → disabled.
nl3, nn3 = rescue_noise_points(rows, labels, 1.01)
check("threshold > 1.0 disables rescue", nn3 == 0, f"n={nn3}")

# -----------------------------------------------------------------------------
print()
print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
