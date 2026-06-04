"""Smoke test for ROADMAP #8 — IP cluster attribution features.

Covers the pure-function pieces:
  * `_hash_credential_bin` — stable across processes, in [0, k).
  * `_build_behavior_block` — unchanged 4-col layout at the given weight.
  * `_build_attribution_block` — country one-hot + ASN bucket + credential
    hash; output dimensions match the inputs; only one active column per
    categorical group per row; cred-hash rows sum to ~weight; missing
    fields handled.
  * `make_full_scalar_builder` — combined builder shape matches the sum
    of behavior + attribution widths; attribution width is exactly the
    sum of country vocab + (top_asns+1) + cred_hash_dim.

Standalone — no ES, no LLM. Numpy required (already in console venv).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_ip_attribution.py
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np  # noqa: E402

from enrich.sources.cowrie.ips import (  # noqa: E402
    _build_attribution_block,
    _build_behavior_block,
    _hash_credential_bin,
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


# -------------------------------------------------------------------------
# [1] _hash_credential_bin determinism + range
# -------------------------------------------------------------------------
print("\n[1] _hash_credential_bin")
check("deterministic", _hash_credential_bin("root:admin", 16) == _hash_credential_bin("root:admin", 16))
check("range", all(0 <= _hash_credential_bin(s, 16) < 16 for s in [
    "", "a:b", "root:", ":password", "x" * 200, "spec/ial:!@#$"
]))
check("varies across inputs",
      len({_hash_credential_bin(s, 16) for s in ["root:admin", "admin:123", "user:test", "pi:raspberry"]}) > 1)
check("k=0 is safe (no division by zero)", _hash_credential_bin("anything", 0) == 0)


# -------------------------------------------------------------------------
# [2] Behavior block unchanged
# -------------------------------------------------------------------------
print("\n[2] _build_behavior_block")
scalars = [
    {"total_sessions": 10, "login_success_rate": 0.1,
     "mean_novelty_score": 0.4, "mean_session_duration_s": 30.0},
    {"total_sessions": 1,  "login_success_rate": 0.0,
     "mean_novelty_score": 0.9, "mean_session_duration_s": 1.0},
]
beh = _build_behavior_block(scalars, weight=0.05)
check("shape (n, 4)", beh.shape == (2, 4), f"got {beh.shape}")
check("all in [0, 0.05]", np.all((beh >= 0.0) & (beh <= 0.05 + 1e-6)),
      f"max={float(beh.max())}, min={float(beh.min())}")


# -------------------------------------------------------------------------
# [3] _build_attribution_block — shape + one-active-per-group
# -------------------------------------------------------------------------
print("\n[3] _build_attribution_block — basic shape + activation")
attr_scalars = [
    {"country_iso_code": "US",  "as_number": 64512, "credentials": ["root:admin", "admin:admin"]},
    {"country_iso_code": "CN",  "as_number": 64513, "credentials": ["root:root"]},
    {"country_iso_code": "US",  "as_number": 99999, "credentials": []},                # other ASN, no creds
    {"country_iso_code": "",    "as_number": None,  "credentials": ["pi:raspberry"]},  # missing geo+ASN
]
top_asns = [64512, 64513]                     # arbitrary top-2
cred_hash_dim = 8
weight = 0.10

block = _build_attribution_block(
    attr_scalars, top_asns=top_asns, weight=weight, cred_hash_dim=cred_hash_dim,
)
# country vocab from data = {"", "US", "CN"} = 3 cols
# asn block = top_asns + "other" = 3 cols
# cred = 8 cols
# total = 14 cols
check("shape matches sum of group widths", block.shape == (4, 3 + 3 + 8),
      f"got {block.shape}")
# Each row's country block should sum to weight (one active col at weight).
country_block = block[:, :3]
country_sums = country_block.sum(axis=1)
check("country block: one weight per row",
      np.allclose(country_sums, np.full(4, weight, dtype=np.float32)),
      f"sums={country_sums!r}")
# ASN block columns 3..6: one active per row.
asn_block = block[:, 3:6]
asn_sums = asn_block.sum(axis=1)
check("ASN block: one weight per row",
      np.allclose(asn_sums, np.full(4, weight, dtype=np.float32)),
      f"sums={asn_sums!r}")
# Row 2 (US, ASN 99999) should be in the "other" pool column (last asn col).
check("unknown ASN falls into the 'other' bucket", asn_block[2, 2] == weight)
# Row 3 (no ASN) also other.
check("None ASN falls into 'other'", asn_block[3, 2] == weight)
# Cred block columns 6..14.
cred_block = block[:, 6:]
cred_sums = cred_block.sum(axis=1)
# Rows with creds → sum == weight. Row 2 (no creds) → sum == 0.
check("rows with creds: cred block sums to weight",
      math.isclose(float(cred_sums[0]), weight, abs_tol=1e-6)
      and math.isclose(float(cred_sums[1]), weight, abs_tol=1e-6)
      and math.isclose(float(cred_sums[3]), weight, abs_tol=1e-6),
      f"cred_sums={cred_sums!r}")
check("row with no creds: cred block is zero",
      float(cred_sums[2]) == 0.0, f"got {float(cred_sums[2])}")


# -------------------------------------------------------------------------
# [4] Cred-overlap → cred-block similarity
# Two IPs that tried OVERLAPPING credentials should share active bins,
# while one IP with a disjoint cred set should share fewer.
# -------------------------------------------------------------------------
print("\n[4] credential overlap drives cred-block similarity")
overlap_scalars = [
    {"country_iso_code": "", "as_number": None, "credentials": ["root:admin", "admin:test", "pi:raspberry"]},
    {"country_iso_code": "", "as_number": None, "credentials": ["root:admin", "admin:test", "pi:raspberry"]},
    {"country_iso_code": "", "as_number": None, "credentials": ["entirely:different", "creds:nope"]},
]
b = _build_attribution_block(
    overlap_scalars, top_asns=[], weight=0.10, cred_hash_dim=16,
)
# cred block starts after country (1 col: "") + asn (0 top + 1 other = 1 col) = col 2.
cred = b[:, 2:]
# Cosine between identical-creds rows should be 1; disjoint should be <1.
def _cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))

check("identical cred sets → cosine 1.0",
      math.isclose(_cos(cred[0], cred[1]), 1.0, abs_tol=1e-5),
      f"got {_cos(cred[0], cred[1])}")
check("disjoint cred sets → cosine < identical",
      _cos(cred[0], cred[2]) < _cos(cred[0], cred[1]),
      f"identical={_cos(cred[0], cred[1])}, disjoint={_cos(cred[0], cred[2])}")


# -------------------------------------------------------------------------
# [5] L2 contribution bound matches the design comment
# -------------------------------------------------------------------------
print("\n[5] L2 contribution per row ≤ weight * sqrt(3)")
b = _build_attribution_block(
    [{"country_iso_code": "US", "as_number": 64512, "credentials": ["root:x"]}],
    top_asns=[64512], weight=0.10, cred_hash_dim=8,
)
row_norm = float(np.linalg.norm(b[0]))
# country = 0.10, asn = 0.10, cred = 0.10 (single bin at 1.0 * weight).
# sqrt(3 * 0.01) = sqrt(0.03) ≈ 0.1732.
check("L2 ≈ weight*sqrt(3)",
      math.isclose(row_norm, 0.10 * math.sqrt(3.0), rel_tol=1e-3),
      f"got {row_norm}")


# -------------------------------------------------------------------------
# [6] make_full_scalar_builder — combined matrix shape
# -------------------------------------------------------------------------
print("\n[6] make_full_scalar_builder shape")
builder = make_full_scalar_builder(
    top_asns=[64512, 64513], attribution_weight=0.10, cred_hash_dim=8,
)
combined = builder(attr_scalars, behavior_weight=0.05)
# Behavior 4 + attribution [3 country + 3 asn + 8 cred = 14] + intel 2 (M3.B).
# HASSH block is 0-width here (builder called without hassh args → dim 0).
expected_cols = 4 + 14 + 2
check("combined matrix shape", combined.shape == (4, expected_cols),
      f"got {combined.shape}, want (4, {expected_cols})")
# Behavior part should match _build_behavior_block alone.
beh_alone = _build_behavior_block(attr_scalars, weight=0.05)
check("behavior cols unchanged in combined",
      np.allclose(combined[:, :4], beh_alone))


# -------------------------------------------------------------------------
# [7] Empty inputs
# -------------------------------------------------------------------------
print("\n[7] empty inputs")
empty = _build_attribution_block(
    [], top_asns=[64512], weight=0.10, cred_hash_dim=8,
)
check("empty scalars_list → 0 rows", empty.shape[0] == 0,
      f"got {empty.shape}")


# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
