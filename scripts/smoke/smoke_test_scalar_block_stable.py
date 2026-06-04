"""Smoke test for ROADMAP #14: scalar-block normalization must use a fixed
corpus-scale denominator, not the per-batch max. The same input dict must
produce identical scalar contributions across batches.

Standalone — no ES, no pytest. Imports the three scalar-block builders and
asserts batch-independence at all three layers (command, session, IP).
Numpy is required (the builders use numpy directly); skips with rc=0 if
not available, matching `smoke_test_novelty_space.py`.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_scalar_block_stable.py
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

from enrich.sources.cowrie.sessions import build_session_scalar_block
from enrich.sources.cowrie.ips import _build_behavior_block, build_ip_scalar_block
from enrich.sources.cowrie.commands import build_command_scalar_block


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


W = 0.05


# -----------------------------------------------------------------------------
# [1] command builder — batch-independence + clipping.
# -----------------------------------------------------------------------------
print("\n[1] command scalar block — batch-independence")
# Same canonical row appears in two batches with very different neighbours.
row = {"occurrence_count": 10, "unique_source_ips": 5, "confidence": 7, "session_reuse_rate": 0.5}
small = [row, {"occurrence_count": 1, "unique_source_ips": 1, "confidence": 1, "session_reuse_rate": 0.0}]
huge = [
    row,
    {"occurrence_count": 1, "unique_source_ips": 1, "confidence": 1, "session_reuse_rate": 0.0},
    {"occurrence_count": 99999, "unique_source_ips": 9999, "confidence": 10, "session_reuse_rate": 1.0},
]
b_small = build_command_scalar_block(small, W)
b_huge = build_command_scalar_block(huge, W)
check(
    "command: canonical row identical across batches with different maxes",
    np.allclose(b_small[0], b_huge[0]),
    f"small={b_small[0]} huge={b_huge[0]}",
)
# Output is well below 1 * weight on a typical row (sanity).
check(
    "command: block values within [0, weight]",
    bool(np.all(b_small >= 0.0)) and bool(np.all(b_small <= W + 1e-6)),
    f"min={b_small.min()} max={b_small.max()}",
)


# -----------------------------------------------------------------------------
# [2] command builder — outlier above denominator gets clipped to weight.
# -----------------------------------------------------------------------------
print("\n[2] command scalar block — outliers clipped to [0, 1] * weight")
# Push occurrence_count above the denominator (100000).
extreme = [{"occurrence_count": 10_000_000, "unique_source_ips": 5, "confidence": 5, "session_reuse_rate": 0.0}]
b = build_command_scalar_block(extreme, W)
check(
    "command: occurrence_count above denom clips to weight",
    abs(b[0, 0] - W) < 1e-5,
    f"got {b[0, 0]}, expected {W}",
)


# -----------------------------------------------------------------------------
# [3] session builder — batch-independence.
# -----------------------------------------------------------------------------
print("\n[3] session scalar block — batch-independence")
row = {"command_count": 12, "unique_commands": 8, "login_success_rate": 0.5, "mean_novelty_score": 0.4}
small = [row, {"command_count": 1, "unique_commands": 1, "login_success_rate": 0.0, "mean_novelty_score": 0.0}]
huge = [
    row,
    {"command_count": 1, "unique_commands": 1, "login_success_rate": 0.0, "mean_novelty_score": 0.0},
    {"command_count": 800, "unique_commands": 500, "login_success_rate": 1.0, "mean_novelty_score": 1.0},
]
b_small = build_session_scalar_block(small, W)
b_huge = build_session_scalar_block(huge, W)
check(
    "session: canonical row identical across batches",
    np.allclose(b_small[0], b_huge[0]),
    f"small={b_small[0]} huge={b_huge[0]}",
)


# -----------------------------------------------------------------------------
# [4] session builder — outlier clipping.
# -----------------------------------------------------------------------------
print("\n[4] session scalar block — outlier clipping")
extreme = [{"command_count": 10_000_000, "unique_commands": 10_000_000,
            "login_success_rate": 0.5, "mean_novelty_score": 0.5}]
b = build_session_scalar_block(extreme, W)
check(
    "session: command_count above denom clips to weight",
    abs(b[0, 0] - W) < 1e-5,
    f"got {b[0, 0]}",
)
check(
    "session: unique_commands above denom clips to weight",
    abs(b[0, 1] - W) < 1e-5,
    f"got {b[0, 1]}",
)


# -----------------------------------------------------------------------------
# [5] IP behavior block — batch-independence.
# -----------------------------------------------------------------------------
print("\n[5] IP behavior scalar block — batch-independence")
row = {"total_sessions": 50, "login_success_rate": 0.2,
       "mean_novelty_score": 0.3, "mean_session_duration_s": 60.0}
small = [row, {"total_sessions": 1, "login_success_rate": 0.0,
               "mean_novelty_score": 0.0, "mean_session_duration_s": 1.0}]
huge = [
    row,
    {"total_sessions": 1, "login_success_rate": 0.0,
     "mean_novelty_score": 0.0, "mean_session_duration_s": 1.0},
    {"total_sessions": 50_000, "login_success_rate": 1.0,
     "mean_novelty_score": 1.0, "mean_session_duration_s": 1000.0},
]
b_small = _build_behavior_block(small, W)
b_huge = _build_behavior_block(huge, W)
check(
    "ip-behavior: canonical row identical across batches",
    np.allclose(b_small[0], b_huge[0]),
    f"small={b_small[0]} huge={b_huge[0]}",
)
# Backwards-compat shim mirrors _build_behavior_block.
check(
    "ip: build_ip_scalar_block shim is identical to _build_behavior_block",
    np.allclose(build_ip_scalar_block(small, W), _build_behavior_block(small, W)),
    "",
)


# -----------------------------------------------------------------------------
# [6] IP behavior block — outlier clipping.
# -----------------------------------------------------------------------------
print("\n[6] IP behavior scalar block — outlier clipping")
extreme = [{"total_sessions": 10_000_000, "login_success_rate": 0.5,
            "mean_novelty_score": 0.5, "mean_session_duration_s": 100_000.0}]
b = _build_behavior_block(extreme, W)
check(
    "ip: total_sessions above denom clips to weight",
    abs(b[0, 0] - W) < 1e-5,
    f"got {b[0, 0]}",
)
check(
    "ip: mean_session_duration_s above denom clips to weight",
    abs(b[0, 3] - W) < 1e-5,
    f"got {b[0, 3]}",
)


# -----------------------------------------------------------------------------
# [7] zero/empty inputs don't crash; small inputs map to small outputs.
# -----------------------------------------------------------------------------
print("\n[7] zero inputs stay finite + small")
b_cmd = build_command_scalar_block(
    [{"occurrence_count": 1, "unique_source_ips": 1, "confidence": 1, "session_reuse_rate": 0.0}], W,
)
check(
    "command: minimal row → all values finite + within [0, weight]",
    bool(np.all(np.isfinite(b_cmd))) and bool(np.all(b_cmd >= 0.0)) and bool(np.all(b_cmd <= W + 1e-6)),
    f"got {b_cmd}",
)
b_sess = build_session_scalar_block(
    [{"command_count": 1, "unique_commands": 1, "login_success_rate": 0.0, "mean_novelty_score": 0.0}], W,
)
check(
    "session: minimal row → all values finite + within [0, weight]",
    bool(np.all(np.isfinite(b_sess))) and bool(np.all(b_sess >= 0.0)) and bool(np.all(b_sess <= W + 1e-6)),
    f"got {b_sess}",
)


# -----------------------------------------------------------------------------
# [8] Per-batch max comparison (regression guard).
# Specifically: confirm that under the OLD per-batch max, the canonical
# row's contribution would have differed across `small` and `huge`. This
# guards against accidentally reverting the fix (someone re-introducing
# np.max would make this test pass on the BAD code too unless we assert
# the actual stability property).
# -----------------------------------------------------------------------------
print("\n[8] regression sentinel: changing batch composition does not move row")
# Build a third batch where the canonical row is alongside even more
# extreme values, and verify the canonical row's block is identical.
extreme_batch = [
    row,
    {"total_sessions": 99_999, "login_success_rate": 1.0,
     "mean_novelty_score": 1.0, "mean_session_duration_s": 3500.0},
]
b_extreme = _build_behavior_block(extreme_batch, W)
check(
    "ip-behavior: canonical row stable even with extreme neighbour",
    np.allclose(b_small[0], b_extreme[0]),
    f"small[0]={b_small[0]} extreme[0]={b_extreme[0]}",
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
