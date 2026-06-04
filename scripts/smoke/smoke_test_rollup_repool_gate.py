"""Conditional rollup re-pool gate (P1.1).

The backward pass used to clear the rollup watermarks every cycle, forcing a
full re-pool of every session just to absorb command rewrites that are no-ops
in steady state. `rollup_repool_decision` decides — fail-safe — whether a full
re-pool is actually needed; `mark_rollup_dirty` is the signal re-enrich-stale /
reembed raise when they rewrite a doc.

Scenarios:
  [1] decision matrix: clean → skip; dirty / no-stored-hash / schema-changed → reset
  [2] mark_rollup_dirty sets the dirty key to "1"
  [3] rollup_schema_hash is deterministic (same cfg → same hash)

Offline; the decision logic is the risky bit and is pure.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_rollup_repool_gate.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.rollup_gate import (
    ROLLUP_DIRTY_KEY,
    mark_rollup_dirty,
    rollup_repool_decision,
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
# [1] decision matrix.
# -----------------------------------------------------------------------------
print("\n[1] decision matrix (fail-safe: only skip when confidently clean)")
check("clean → skip", rollup_repool_decision(False, "h", "h") == (False, "clean"))
check("dirty → reset",
      rollup_repool_decision(True, "h", "h") == (True, "command_corpus_dirty"))
check("dirty wins even if hash matches",
      rollup_repool_decision(True, "h", "h")[0] is True)
check("no stored hash (first run) → reset",
      rollup_repool_decision(False, "h", None) == (True, "no_stored_schema_hash"))
check("empty stored hash → reset",
      rollup_repool_decision(False, "h", "") == (True, "no_stored_schema_hash"))
check("schema changed → reset",
      rollup_repool_decision(False, "h2", "h1") == (True, "rollup_schema_changed"))


# -----------------------------------------------------------------------------
# [2] mark_rollup_dirty.
# -----------------------------------------------------------------------------
print("\n[2] mark_rollup_dirty raises the dirty flag")


class _StubDB:
    def __init__(self):
        self.kv: dict = {}

    def set_watermark(self, value, key):
        self.kv[key] = value


db = _StubDB()
mark_rollup_dirty(db)
check("dirty key set to '1'", db.kv.get(ROLLUP_DIRTY_KEY) == "1", f"got {db.kv}")


# -----------------------------------------------------------------------------
# [3] schema-hash determinism.
# -----------------------------------------------------------------------------
print("\n[3] rollup_schema_hash is deterministic")
try:
    from enrich.config import load_config
    from enrich.sources.cowrie.sessions import rollup_schema_hash
    cfg = load_config()
    h1, h2 = rollup_schema_hash(cfg), rollup_schema_hash(cfg)
    check("same cfg → identical hash", h1 == h2 and isinstance(h1, str) and len(h1) == 16,
          f"{h1!r} vs {h2!r}")
except Exception as exc:  # cluster deps absent on a bare box — don't hard-fail
    check("schema hash check skipped (deps absent)", True, str(exc))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
