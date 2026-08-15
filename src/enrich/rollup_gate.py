"""Conditional rollup re-pool gate (P1.1).

The backward pass used to reset the session/IP rollup watermarks every cycle,
forcing a full re-pool of *every* session (240k today → ~21.6M at target) just
to absorb command-level rewrites from ``re-enrich-stale``/``reembed`` — which
are no-ops in steady state. This module decides, conservatively, whether a full
re-pool is actually needed:

  * **dirty flag** — ``re-enrich-stale``/``reembed`` set it whenever they
    rewrite ≥1 command doc, so the next rollup must re-pool to absorb them.
  * **schema hash** — a hash of the rollup builder (`rollup_schema_hash`,
    in sessions.py) so a code/config change to the builder forces a re-pool
    even when no command changed (the case `embed_config_hash` would miss).

Fail-safe by construction: re-pool unless we are *confident* nothing changed
(not dirty AND the stored schema hash matches). And it composes with the
existing watermark semantics — `run_rollup` is untouched: when the gate resets,
it clears the watermark (→ full backfill); a *failed* rollup leaves the
watermark cleared, so the next run re-pools regardless of the gate. The
operator override is the unconditional `reset` verb / `pipeline --force`.
"""
from __future__ import annotations

# StateDB watermark keys (the watermark table doubles as a tiny KV store).
ROLLUP_DIRTY_KEY = "rollup_command_dirty"
ROLLUP_SCHEMA_HASH_KEY = "rollup_schema_hash_applied"


def mark_rollup_dirty(db) -> None:
    """Flag that a command-level rewrite happened, so the next rollup re-pools.
    Called by ``re-enrich-stale``/``reembed`` when they change ≥1 doc. Cleared
    only after a reset fires (see `rollup_repool_decision` callers)."""
    db.set_watermark("1", ROLLUP_DIRTY_KEY)


def rollup_repool_decision(
    dirty: bool,
    current_schema_hash: str,
    stored_schema_hash: str | None,
) -> tuple[bool, str]:
    """Whether to force a full re-pool (reset the rollup watermarks), with a
    reason. Pure — unit-tested directly. Fail-safe: only returns ``False`` (skip
    the re-pool) when we are confident nothing changed.

      * dirty                       → re-pool ("command_corpus_dirty")
      * no stored hash (first run)  → re-pool ("no_stored_schema_hash")
      * stored hash != current      → re-pool ("rollup_schema_changed")
      * else                        → skip   ("clean")
    """
    if dirty:
        return True, "command_corpus_dirty"
    if not stored_schema_hash:
        return True, "no_stored_schema_hash"
    if current_schema_hash != stored_schema_hash:
        return True, "rollup_schema_changed"
    return False, "clean"
