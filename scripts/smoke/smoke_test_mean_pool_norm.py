"""Smoke test for ROADMAP #13: `_mean_pool` L2-normalizes each input vector
before averaging AND L2-normalizes its output.

Standalone — no ES, no LLM, no pytest. Imports the pure function and
asserts the documented properties. Exits non-zero on first failure.

What this tests:
  1. Empty input → empty output (regression guard).
  2. Output is unit-norm for non-empty, non-degenerate input.
  3. Per-input normalization removes the larger-norm-dominates bias:
     a 2-input pool where input A is 2× the norm of input B should
     point exactly midway between A's and B's unit directions, NOT
     biased toward A. Without the per-input normalize step the pooled
     vector would lean toward A.
  4. A zero vector among inputs is skipped (would otherwise inject NaN
     via division by its zero norm).
  5. A degenerate pool (all-zero inputs, or antipodal cancellation)
     returns [] — never a zero-magnitude vector, which ES rejects on the
     `cosine` dense_vector rollup field — instead of crashing or NaN-ing.
  6. Idempotent on already-unit-norm inputs (within float tolerance).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_mean_pool_norm.py
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import _mean_pool

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def _norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def _cos(a: list[float], b: list[float]) -> float:
    na, nb = _norm(a), _norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return sum(x * y for x, y in zip(a, b, strict=False)) / (na * nb)


# -----------------------------------------------------------------------------
# [1] Empty input → empty output.
# -----------------------------------------------------------------------------
print("\n[1] empty input")
check("empty list → empty list", _mean_pool([]) == [], "")


# -----------------------------------------------------------------------------
# [2] Output is unit-norm.
# -----------------------------------------------------------------------------
print("\n[2] non-degenerate input → unit-norm output")
out = _mean_pool([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]])
check(
    "pool of [+x, +y] is unit-norm",
    abs(_norm(out) - 1.0) < 1e-6,
    f"got |out|={_norm(out)}",
)
# Should point at the bisector (45°): components equal, z=0.
check(
    "pool of [+x, +y] points at the bisector",
    abs(out[0] - out[1]) < 1e-6 and abs(out[2]) < 1e-6,
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [3] Larger-norm input does NOT dominate (the headline bug).
# -----------------------------------------------------------------------------
print("\n[3] larger-norm input does not bias the pool")
# Input A has norm 2 (points at +x), input B has norm 1 (points at +y).
# Without per-input normalization: result ≈ ((2,0)+(0,1))/2 = (1, 0.5),
# then normalized → cos with +x is 1/sqrt(1.25) ≈ 0.894 (heavy +x bias).
# With per-input normalization: result ≈ ((1,0)+(0,1))/2 = (0.5, 0.5),
# then normalized → cos with +x is 1/sqrt(2) ≈ 0.707 (exactly the bisector).
A = [2.0, 0.0]
B = [0.0, 1.0]
out = _mean_pool([A, B])
cos_x = _cos(out, [1.0, 0.0])
expected = 1.0 / math.sqrt(2.0)
check(
    "pool sits at the bisector regardless of input norm",
    abs(cos_x - expected) < 1e-6,
    f"cos(out, +x) = {cos_x}, expected {expected}",
)
# Sanity: the result is unit-norm.
check(
    "[3] output is unit-norm",
    abs(_norm(out) - 1.0) < 1e-6,
    f"|out|={_norm(out)}",
)


# -----------------------------------------------------------------------------
# [4] Zero-vector input is skipped, not divided by its zero norm.
# -----------------------------------------------------------------------------
print("\n[4] zero-vector input is skipped")
out = _mean_pool([[1.0, 0.0, 0.0], [0.0, 0.0, 0.0], [0.0, 1.0, 0.0]])
check(
    "zero vec skipped → output finite + unit-norm",
    all(math.isfinite(x) for x in out) and abs(_norm(out) - 1.0) < 1e-6,
    f"got {out}, |out|={_norm(out)}",
)
# Same bisector property: equivalent to pooling just [+x, +y].
expected_out = _mean_pool([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]])
check(
    "result equals pool of the non-zero inputs only",
    all(abs(a - b) < 1e-6 for a, b in zip(out, expected_out, strict=False)),
    f"got {out}, expected {expected_out}",
)


# -----------------------------------------------------------------------------
# [5] All-zero input → EMPTY (not a zero vector). A zero-magnitude vector is
# rejected by ES on the `cosine` dense_vector rollup field, which would 400 the
# whole doc; [] signals "no usable embedding" so the caller omits the field.
# -----------------------------------------------------------------------------
print("\n[5] all-zero input → [] (never a zero vector ES rejects)")
out = _mean_pool([[0.0, 0.0, 0.0], [0.0, 0.0, 0.0]])
check(
    "all-zero input → []",
    out == [],
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [6] Idempotent on already-unit-norm inputs (within float tolerance).
# -----------------------------------------------------------------------------
print("\n[6] idempotent on unit-norm inputs")
# Three already-unit vectors. Mean-pool then normalize should give the
# same direction as just normalizing the raw sum.
u1 = [1.0 / math.sqrt(3), 1.0 / math.sqrt(3), 1.0 / math.sqrt(3)]
u2 = [0.0, 1.0, 0.0]
u3 = [1.0, 0.0, 0.0]
out = _mean_pool([u1, u2, u3])
raw_sum = [u1[i] + u2[i] + u3[i] for i in range(3)]
n = _norm(raw_sum)
expected = [v / n for v in raw_sum]
check(
    "unit-norm inputs: out matches normalized raw sum",
    all(abs(a - b) < 1e-6 for a, b in zip(out, expected, strict=False)),
    f"got {out}, expected {expected}",
)
check(
    "[6] output is unit-norm",
    abs(_norm(out) - 1.0) < 1e-6,
    f"|out|={_norm(out)}",
)


# -----------------------------------------------------------------------------
# [7] Two antipodal unit vectors → zero pool, returned as EMPTY (no zero vector,
# no NaN). Same rationale as [5]: never hand ES a zero-magnitude vector.
# -----------------------------------------------------------------------------
print("\n[7] antipodal inputs sum to zero → [] returned")
out = _mean_pool([[1.0, 0.0], [-1.0, 0.0]])
check(
    "antipodal pair → []",
    out == [],
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [8] Single-input pool: direction preserved, output is unit-norm.
# -----------------------------------------------------------------------------
print("\n[8] single-input pool: direction preserved + unit-norm")
out = _mean_pool([[5.0, 0.0, 0.0]])
check(
    "single non-unit input → unit-norm output in same direction",
    abs(_norm(out) - 1.0) < 1e-6 and out[0] > 0.99 and abs(out[1]) < 1e-6,
    f"got {out}",
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
