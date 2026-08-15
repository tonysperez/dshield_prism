"""Smoke test for the `backfill-anchor-signatures` verb (item 51b):
`enrich.sources.cowrie.lexical.build_session_predicate_vectors` +
`enrich.sources.cowrie.predicates.predicate_signature` (the pure fold path
`_sample_predicate_vectors` runs once it has `command_sets`/`hash_to_predicates` in
hand), and the pure `--force`-gated skip decision
(`sessions._anchor_signature_present` / `sessions._should_backfill_anchor_signature`).

No ES (everything here is the pure computation the ES-shaped wiring feeds into); no
live network. Standalone — no pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.lexical import build_session_predicate_vectors
from enrich.sources.cowrie.predicates import PREDICATE_NAMES, command_subsignals, predicate_signature
from enrich.sources.cowrie.sessions import (
    _anchor_signature_present,
    _should_backfill_anchor_signature,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# ---------------------------------------------------------------------------
# The pure fold path `_sample_predicate_vectors` runs after fetching
# command_sets + hash_to_predicates: build_session_predicate_vectors ->
# predicate_signature.
# ---------------------------------------------------------------------------
h_uname = command_subsignals("uname -m")
h_key = command_subsignals("echo key >> ~/.ssh/authorized_keys")
h_immut = command_subsignals("chattr +i .ssh")
hash_to_predicates = {"h_uname": h_uname, "h_key": h_key, "h_immut": h_immut}

# Three sampled sessions: one fires multi_arch_targeting, one fires
# key_write_immutability (split across 2 commands), one has no evidence at all
# (references an unresolvable hash, mirroring a command enriched before item 30).
command_sets = [["h_uname"], ["h_key", "h_immut"], ["unresolvable_hash"]]
vectors = build_session_predicate_vectors(command_sets, hash_to_predicates)
sig = predicate_signature(vectors)

check("signature covers exactly the 7 PREDICATE_NAMES",
      set(sig.keys()) == set(PREDICATE_NAMES), str(sig))
check("every signature value is a frequency in [0, 1]",
      all(0.0 <= v <= 1.0 for v in sig.values()), str(sig))
check("multi_arch_targeting fired by 1 of 3 sampled sessions -> 1/3",
      abs(sig["multi_arch_targeting"] - (1 / 3)) < 1e-9, str(sig))
check("key_write_immutability fired by 1 of 3 sampled sessions -> 1/3",
      abs(sig["key_write_immutability"] - (1 / 3)) < 1e-9, str(sig))
check("a never-fired predicate is exactly 0.0",
      sig["self_spread"] == 0.0, str(sig))

# Empty evidence (no sampled sessions at all, e.g. a playbook_id with zero
# member sessions found) -> all-zero signature, never missing/None.
empty_sig = predicate_signature(build_session_predicate_vectors([], {}))
check("empty command_sets -> all-zero signature",
      empty_sig == dict.fromkeys(PREDICATE_NAMES, 0.0), str(empty_sig))

# A sampled session whose only commands are all unresolvable hashes (no
# predicates.* evidence anywhere) also folds to all-zero, not a crash/None.
no_evidence_sig = predicate_signature(
    build_session_predicate_vectors([["missing_a"], ["missing_b"]], {}),
)
check("all-unresolvable-hash sessions -> all-zero signature (fail-closed)",
      no_evidence_sig == dict.fromkeys(PREDICATE_NAMES, 0.0), str(no_evidence_sig))


# ---------------------------------------------------------------------------
# skip-unless-`--force` decision — pure predicate
# ---------------------------------------------------------------------------
check("no existing signature -> backfill runs (not force)",
      _should_backfill_anchor_signature(None, force=False) is True)
check("empty-dict existing signature -> treated as absent -> backfill runs",
      _should_backfill_anchor_signature({}, force=False) is True)
check("already-signed anchor (all-zero, but present) -> skipped without --force",
      _should_backfill_anchor_signature(dict.fromkeys(PREDICATE_NAMES, 0.0), force=False)
      is False)
check("already-signed anchor (nonzero) -> skipped without --force",
      _should_backfill_anchor_signature({"multi_arch_targeting": 0.5}, force=False) is False)
check("already-signed anchor -> recomputed anyway when --force",
      _should_backfill_anchor_signature({"multi_arch_targeting": 0.5}, force=True) is True)

check("_anchor_signature_present: None -> False", _anchor_signature_present(None) is False)
check("_anchor_signature_present: {} -> False", _anchor_signature_present({}) is False)
check("_anchor_signature_present: all-zero dict -> True (present, just no evidence)",
      _anchor_signature_present(dict.fromkeys(PREDICATE_NAMES, 0.0)) is True)
check("_anchor_signature_present: non-dict (malformed doc) -> False",
      _anchor_signature_present("not-a-dict") is False)  # type: ignore[arg-type]


print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
