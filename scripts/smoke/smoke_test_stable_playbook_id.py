"""Cosine-anchored playbook identity (`spb-<16hex>`).

`playbook_id` is assigned by cosine-matching a playbook's centroid to the
nearest pinned anchor (>= playbook_merge_threshold) and reusing its id,
minting a fresh one only on no-match. Anchors are pinned at first mint and
never updated, so transitive chaining (A~B>=thr, B~C>=thr, A~C<thr) can't
collapse unrelated centroids under one id.

Scenarios (all offline — pure helpers, no ES):
  [1] mint is deterministic per seed, distinct across seeds
  [2] group centroid = size-weighted, L2-normalised mean
  [3] centroid that matches an anchor reuses the anchor id
  [4] centroid with no anchor within threshold mints a fresh id
  [5] empty anchor set mints
  [6] nearest anchor wins when several are above threshold
  [7] membership (seed) changed but centroid still matches a prior anchor
      → id is REUSED, not re-minted
  [8] pinned first-mint anchors block transitive chaining

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_stable_playbook_id.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.predicates import PREDICATE_NAMES
from enrich.sources.cowrie.sessions import (
    _assign_playbook_id,
    _mint_playbook_id,
    _playbook_anchor_doc,
    _playbook_group_centroid,
    _unit_vector,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []
THRESH = 0.96


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASSED.append(name) if cond else FAILED.append((name, detail)))


def _vec(*xs: float) -> np.ndarray:
    return _unit_vector(np.asarray(xs, dtype=np.float32))


# [1] deterministic mint
a = _mint_playbook_id("sescl-deadbeef")
b = _mint_playbook_id("sescl-deadbeef")
c = _mint_playbook_id("sescl-feedface")
check("1a mint stable per seed", a == b, f"{a} != {b}")
check("1b mint differs across seeds", a != c, f"{a} == {c}")
check("1c mint has spb- prefix", a.startswith("spb-"), a)

# [2] size-weighted normalised centroid
m = _playbook_group_centroid([
    {"centroid": [1.0, 0.0, 0.0], "size": 3},
    {"centroid": [0.0, 1.0, 0.0], "size": 1},
])
check("2a centroid is unit length", abs(float(np.linalg.norm(m)) - 1.0) < 1e-5,
      str(m))
check("2b size weighting applied", m[0] > m[1], str(m))
check("2c no-centroid members → None",
      _playbook_group_centroid([{"size": 5}]) is None)

# [3] match reuses anchor id
anchor_vec = _vec(1.0, 0.0, 0.0)
anchors = [(anchor_vec, "spb-anchor01")]
same = _vec(1.0, 0.0, 0.0)
check("3 matching centroid reuses anchor",
      _assign_playbook_id(same, anchors, THRESH, "sescl-x") == "spb-anchor01")

# [4] no match within threshold → mint
orthogonal = _vec(0.0, 1.0, 0.0)
got = _assign_playbook_id(orthogonal, anchors, THRESH, "sescl-x")
check("4 no anchor match mints fresh",
      got == _mint_playbook_id("sescl-x"), got)

# [5] empty anchors → mint
got5 = _assign_playbook_id(same, [], THRESH, "sescl-y")
check("5 empty anchors mints", got5 == _mint_playbook_id("sescl-y"), got5)

# [6] nearest of several above-threshold anchors wins
near = _vec(1.0, 0.05, 0.0)
anchors6 = [
    (_vec(1.0, 0.0, 0.0), "spb-A"),
    (_vec(1.0, 0.30, 0.0), "spb-B"),
]
check("6 nearest anchor wins",
      _assign_playbook_id(near, anchors6, THRESH, "sescl-z") == "spb-A")

# [7] membership/seed changed, centroid still matches → reuse.
anchor_old = (_vec(1.0, 0.0, 0.0), _mint_playbook_id("sescl-OLD"))
drifted = _vec(1.0, 0.02, 0.0)
reused = _assign_playbook_id(drifted, [anchor_old], THRESH, "sescl-NEW")
check("7a id survives membership change",
      reused == anchor_old[1], f"{reused} != {anchor_old[1]}")
check("7b membership hash WOULD have flipped",
      _mint_playbook_id("sescl-OLD") != _mint_playbook_id("sescl-NEW"))

# [8] pinned first-mint anchors block transitive chaining.
THRESH8 = 0.96
a8 = _vec(1.0, 0.00, 0.0)
b8 = _vec(1.0, 0.28, 0.0)
c8 = _vec(1.0, 0.62, 0.0)
check("8 setup: a~b>=thr", float(a8 @ b8) >= THRESH8, f"{float(a8 @ b8):.4f}")
check("8 setup: b~c>=thr", float(b8 @ c8) >= THRESH8, f"{float(b8 @ c8):.4f}")
check("8 setup: a~c<thr", float(a8 @ c8) < THRESH8, f"{float(a8 @ c8):.4f}")

pinned: list = []
known: set = set()
def _assign8(unit, seed):
    sid = _assign_playbook_id(unit, pinned, THRESH8, seed)
    if sid not in known:
        known.add(sid)
        pinned.append((unit, sid))
    return sid

id_a = _assign8(a8, "sescl-A")
id_b = _assign8(b8, "sescl-B")
id_c = _assign8(c8, "sescl-C")
check("8a B reuses A's pinned id", id_b == id_a, f"{id_b} != {id_a}")
check("8b C does NOT chain into A's id (mints fresh)", id_c != id_a,
      f"C chained: {id_c} == {id_a}")

# [9] `_playbook_anchor_doc` (item 51c) — predicate_signature is always
# present, never missing, on the anchor doc shape `_persist_playbook_anchor`
# writes.
doc_no_sig = _playbook_anchor_doc("spb-x", same, "sescl-x", "run-1")
check("9a no predicate_signature given -> all-zero, not missing",
      doc_no_sig.get("predicate_signature") == dict.fromkeys(PREDICATE_NAMES, 0.0),
      str(doc_no_sig.get("predicate_signature")))

given_sig = {**dict.fromkeys(PREDICATE_NAMES, 0.0), "multi_arch_targeting": 0.75}
doc_with_sig = _playbook_anchor_doc("spb-y", same, "sescl-y", "run-1",
                                     predicate_signature=given_sig)
check("9b given predicate_signature is written through unchanged",
      doc_with_sig.get("predicate_signature") == given_sig, str(doc_with_sig))

check("9c doc shape still carries the other fields (playbook_id/centroid/seed/run)",
      doc_no_sig["playbook_id"] == "spb-x"
      and doc_no_sig["seed_playbook_id"] == "sescl-x"
      and doc_no_sig["first_run_id"] == "run-1"
      and len(doc_no_sig["anchor_centroid"]) == len(same),
      str(doc_no_sig))


for n in PASSED:
    print(f"  PASS {n}")
for n, d in FAILED:
    print(f"  FAIL {n}: {d}")
print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
sys.exit(1 if FAILED else 0)
