"""Satellite anchors for write-once anchor drift (item 59).

`_persist_playbook_anchor` pins a playbook's centroid once and never updates
it (prevents transitive id chaining). Measured directly (Finding 45 of the
clustering-quality investigation): 22% of one playbook's own members drift
below `assignment_tau` of their pinned anchor and stay permanently novel even
though `name playbooks` still recognises the group. When enabled
(`anchor_satellite_minting_enabled`), an already-named, drifted group mints an
*additional* anchor doc sharing the incumbent `playbook_id` but a distinct
`_id`, instead of being silently skipped.

Scenarios (all offline — pure helpers, no ES):
  [1] drift fraction: zero members -> 0.0 (fail-closed), normal division
  [2] mint decision: below threshold skips, at/above threshold mints
  [3] satellite id is deterministic per (playbook_id, seed), differs across
      either input, and can never collide with a primary `spb-` id
  [4] `_playbook_anchor_doc` always carries `is_satellite`, defaulting False
      so a primary mint's doc shape is unchanged
  [5] `_persist_playbook_anchor`'s `_id` defaults to `playbook_id` when
      `anchor_id` is omitted (byte-identical to the pre-item-59 call site)

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_anchor_satellite_drift.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.sessions import (
    _anchor_drift_fraction,
    _mint_playbook_id,
    _mint_satellite_anchor_id,
    _persist_playbook_anchor,
    _playbook_anchor_doc,
    _should_mint_satellite,
    _unit_vector,
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


# -----------------------------------------------------------------------------
# [1] drift fraction.
# -----------------------------------------------------------------------------
print("\n[1] _anchor_drift_fraction")
check("zero total -> 0.0 (fail-closed)", _anchor_drift_fraction(0, 0) == 0.0)
check("normal division", abs(_anchor_drift_fraction(1242, 5628) - 0.2207) < 1e-3,
      str(_anchor_drift_fraction(1242, 5628)))
check("no drift -> 0.0", _anchor_drift_fraction(0, 100) == 0.0)
check("all drifted -> 1.0", _anchor_drift_fraction(50, 50) == 1.0)
check("clamped when drifted > total (TOCTOU between the two counts)",
      _anchor_drift_fraction(120, 100) == 1.0, str(_anchor_drift_fraction(120, 100)))


# -----------------------------------------------------------------------------
# [2] mint decision.
# -----------------------------------------------------------------------------
print("\n[2] _should_mint_satellite")
check("below threshold does not mint", _should_mint_satellite(10, 100, 0.15) is False)
check("at threshold mints", _should_mint_satellite(15, 100, 0.15) is True)
check("above threshold mints", _should_mint_satellite(1242, 5628, 0.15) is True)
check("zero total never mints (no evidence)", _should_mint_satellite(0, 0, 0.15) is False)


# -----------------------------------------------------------------------------
# [3] satellite id determinism / uniqueness.
# -----------------------------------------------------------------------------
print("\n[3] _mint_satellite_anchor_id")
sid_a = _mint_satellite_anchor_id("spb-afafb73ec79a60cb", "sescl-deadbeef")
sid_b = _mint_satellite_anchor_id("spb-afafb73ec79a60cb", "sescl-deadbeef")
sid_c = _mint_satellite_anchor_id("spb-afafb73ec79a60cb", "sescl-feedface")
sid_d = _mint_satellite_anchor_id("spb-other0000000000", "sescl-deadbeef")
check("deterministic per (playbook_id, seed)", sid_a == sid_b, f"{sid_a} != {sid_b}")
check("differs across seed", sid_a != sid_c, f"{sid_a} == {sid_c}")
check("differs across incumbent id", sid_a != sid_d, f"{sid_a} == {sid_d}")
check("embeds the incumbent id", sid_a.startswith("spb-afafb73ec79a60cb-sat-"), sid_a)
check("never collides with a primary spb- id",
      sid_a != _mint_playbook_id("sescl-deadbeef")
      and "-sat-" not in _mint_playbook_id("sescl-deadbeef"),
      f"{sid_a} vs {_mint_playbook_id('sescl-deadbeef')}")


# -----------------------------------------------------------------------------
# [4] `_playbook_anchor_doc` always carries `is_satellite`.
# -----------------------------------------------------------------------------
print("\n[4] _playbook_anchor_doc is_satellite field")
unit = _unit_vector([1.0, 0.0, 0.0])
primary_doc = _playbook_anchor_doc("spb-x", unit, "sescl-x", "run-1")
satellite_doc = _playbook_anchor_doc(
    "spb-x", unit, "sescl-x-sat", "run-2", is_satellite=True,
)
check("primary mint defaults is_satellite=False", primary_doc["is_satellite"] is False,
      str(primary_doc))
check("satellite mint carries is_satellite=True", satellite_doc["is_satellite"] is True,
      str(satellite_doc))
check("satellite doc still carries playbook_id = incumbent",
      satellite_doc["playbook_id"] == "spb-x", str(satellite_doc))


# -----------------------------------------------------------------------------
# [5] `_persist_playbook_anchor` — `_id` defaults to `playbook_id`; `anchor_id`
# routes a satellite to its own `_id` while `playbook_id` stays the incumbent.
# -----------------------------------------------------------------------------
print("\n[5] _persist_playbook_anchor _id routing (mocked es.index)")
es_primary = MagicMock()
_persist_playbook_anchor(es_primary, "playbook_anchors", "spb-x", unit, "sescl-x", "run-1")
primary_call = es_primary.index.call_args
check("primary mint: _id == playbook_id",
      primary_call.kwargs["id"] == "spb-x", str(primary_call))
check("primary mint: document.is_satellite == False",
      primary_call.kwargs["document"]["is_satellite"] is False, str(primary_call))

es_satellite = MagicMock()
_persist_playbook_anchor(
    es_satellite, "playbook_anchors", "spb-x", unit, "sescl-x-sat", "run-2",
    anchor_id="spb-x-sat-deadbeef", is_satellite=True,
)
satellite_call = es_satellite.index.call_args
check("satellite mint: _id == anchor_id, NOT playbook_id",
      satellite_call.kwargs["id"] == "spb-x-sat-deadbeef", str(satellite_call))
check("satellite mint: document.playbook_id stays the incumbent id",
      satellite_call.kwargs["document"]["playbook_id"] == "spb-x", str(satellite_call))
check("satellite mint: document.is_satellite == True",
      satellite_call.kwargs["document"]["is_satellite"] is True, str(satellite_call))


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
