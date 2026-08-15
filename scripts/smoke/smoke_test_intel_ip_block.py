"""Smoke test for `_build_intel_block` + the full IP scalar builder.

Covers M3.B: external_rarity_score + consensus_malicious as a new
sub-block of the IP cluster matrix. Verifies:
  - Shape / dimensionality is exactly +2 cols over the prior layout.
  - Weight scaling matches the attribution-block convention.
  - Missing intel inputs default to 0 (no effect on clustering).
  - The matrix-stacking order is `behavior | attribution | intel`.
  - Two IPs with identical behavior but different intel verdicts end
    up with measurably different scalar rows (geometric pull-apart).

Pure-function only; no ES.

Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_ip_block.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np

from enrich.sources.cowrie.ips import (
    _build_intel_block,
    make_full_scalar_builder,
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


def _scalars(**kw) -> dict:
    """Sensible defaults; per-test overrides."""
    base = {
        "total_sessions": 10,
        "login_success_rate": 0.0,
        "mean_novelty_score": 0.5,
        "mean_session_duration_s": 30.0,
        "country_iso_code": "US",
        "as_number": 12345,
        "credentials": ["root:root"],
        "external_rarity_score": 0.0,
        "consensus_malicious": False,
    }
    base.update(kw)
    return base


# -----------------------------------------------------------------------------
# _build_intel_block
# -----------------------------------------------------------------------------

print("[1] _build_intel_block — empty input → (0,2) shape")
block = _build_intel_block([], weight=0.10)
check("empty: shape (0, 2)", block.shape == (0, 2))


print("\n[2] _build_intel_block — defaults give all-zero rows")
rows = [_scalars(), _scalars(consensus_malicious=False)]
block = _build_intel_block(rows, weight=0.10)
check("shape (n, 2)", block.shape == (2, 2))
check("default rows all zero", np.allclose(block, 0.0))


print("\n[3] _build_intel_block — rarity column scales by weight")
rows = [
    _scalars(external_rarity_score=0.0),
    _scalars(external_rarity_score=0.5),
    _scalars(external_rarity_score=1.0),
]
block = _build_intel_block(rows, weight=0.10)
check("rarity col 0 = 0.0",  np.isclose(block[0, 0], 0.0))
check("rarity col 0 = 0.05", np.isclose(block[1, 0], 0.05))
check("rarity col 0 = 0.10", np.isclose(block[2, 0], 0.10))


print("\n[4] _build_intel_block — consensus column scales by weight")
rows = [
    _scalars(consensus_malicious=False),
    _scalars(consensus_malicious=True),
]
block = _build_intel_block(rows, weight=0.10)
check("consensus col F = 0.0", np.isclose(block[0, 1], 0.0))
check("consensus col T = 0.10", np.isclose(block[1, 1], 0.10))


print("\n[5] _build_intel_block — clamps rarity to [0, 1]")
rows = [_scalars(external_rarity_score=-0.5),
        _scalars(external_rarity_score=2.0)]
block = _build_intel_block(rows, weight=0.10)
check("rarity -0.5 clamps to 0", np.isclose(block[0, 0], 0.0))
check("rarity  2.0 clamps to 0.10", np.isclose(block[1, 0], 0.10))


# -----------------------------------------------------------------------------
# make_full_scalar_builder — composition order + dimensions
# -----------------------------------------------------------------------------

print("\n[6] make_full_scalar_builder — column count = behavior + attribution + intel")
top_asns = [11111, 22222]
builder = make_full_scalar_builder(
    top_asns=top_asns, attribution_weight=0.10, cred_hash_dim=4,
)
rows = [_scalars(country_iso_code="US", as_number=11111),
        _scalars(country_iso_code="CA", as_number=33333)]
matrix = builder(rows, behavior_weight=0.05)
# 4 behavior + (2 country + 3 ASN + 4 cred) + 2 intel = 15
expected_cols = 4 + 2 + (len(top_asns) + 1) + 4 + 2
check(
    f"matrix has {expected_cols} cols",
    matrix.shape == (2, expected_cols),
    f"got {matrix.shape}",
)
# Behavior is the first 4 cols; intel is the LAST 2.
check("last 2 cols are intel (zero for default rows)",
      np.allclose(matrix[:, -2:], 0.0))


print("\n[7] make_full_scalar_builder — intel block reflects the inputs")
rows = [
    _scalars(consensus_malicious=False, external_rarity_score=0.0),
    _scalars(consensus_malicious=True,  external_rarity_score=0.9),
]
matrix = builder(rows, behavior_weight=0.05)
# Intel cols are the last 2: [rarity, consensus]
intel_cols = matrix[:, -2:]
check("row 0 intel cols zero",
      np.allclose(intel_cols[0], 0.0))
check("row 1 rarity 0.9 * 0.10 = 0.09",
      np.isclose(intel_cols[1, 0], 0.09))
check("row 1 consensus T * 0.10 = 0.10",
      np.isclose(intel_cols[1, 1], 0.10))


print("\n[8] geometric: identical-behavior IPs pulled apart by intel verdict")
# Two IPs with identical behavior + attribution data. Only difference:
# one is intel-clean, one is intel-malicious. Without the intel block,
# their rows would be identical (zero L2 distance). With the intel
# block, they're separated.
behav = _scalars()
clean = {**behav, "consensus_malicious": False, "external_rarity_score": 0.0}
mal   = {**behav, "consensus_malicious": True,  "external_rarity_score": 0.0}
matrix = builder([clean, mal], behavior_weight=0.05)
# L2 distance comes ENTIRELY from the intel block (everything else identical)
diff = matrix[0] - matrix[1]
nonzero = np.count_nonzero(diff)
check("rows differ in exactly 1 column (consensus_malicious only)",
      nonzero == 1,
      f"got {nonzero} non-zero cols, diff={diff[diff!=0]}")
check("L2 distance equals attribution_weight (0.10)",
      np.isclose(np.linalg.norm(diff), 0.10),
      f"got |diff|={np.linalg.norm(diff)}")


print("\n[9] make_full_scalar_builder — empty top_asns still includes intel block")
# Defensive: when _compute_top_asns returns [], the attribution block
# becomes a single 'other' ASN column + country + creds. Intel block
# should still be appended.
builder2 = make_full_scalar_builder(
    top_asns=[], attribution_weight=0.10, cred_hash_dim=4,
)
rows = [_scalars(consensus_malicious=True, external_rarity_score=0.5)]
matrix = builder2(rows, behavior_weight=0.05)
# Intel block is always last 2 cols
check("intel cols still present when top_asns empty",
      matrix.shape[1] >= 2 and matrix[0, -1] > 0,
      f"got matrix shape {matrix.shape}")


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
