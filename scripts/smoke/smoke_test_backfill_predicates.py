"""Smoke test for the `backfill-predicates` verb (item 51a):
`enrich.sources.cowrie.commands.predicate_backfill_query` (the pure existence-filter
query builder driving `iter_docs_for_predicate_backfill`) and `command_subsignals` on a
representative rescue-tier fixture (`chattr -ia .ssh` + an `authorized_keys` write).

No ES (the query builder is pure); no live network. Standalone — no pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.commands import predicate_backfill_query
from enrich.sources.cowrie.predicates import SUBSIGNAL_NAMES, command_subsignals

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
# predicate_backfill_query — the existence-filter shape
# ---------------------------------------------------------------------------
q = predicate_backfill_query()
filters = q["bool"]["filter"]
must_not = q["bool"]["must_not"]

check("requires process.command_line to exist",
      {"exists": {"field": "process.command_line"}} in filters, str(q))
check("excludes docs that already carry the first predicate sub-signal",
      must_not == [{"exists": {"field": f"dshield.cowrie.enrichment.predicates.{SUBSIGNAL_NAMES[0]}"}}],
      str(q))
check("no other clauses sneak in (idempotent-by-existence-filter, nothing extra)",
      set(q["bool"].keys()) == {"filter", "must_not"}, str(q))

# A doc already carrying predicates would be filtered out by `must_not` on a
# re-run — this is what makes `run_backfill_predicates` a natural no-op the
# second time. Nothing further to assert here without ES; the query shape
# above is the whole contract `iter_docs_for_predicate_backfill` relies on.


# ---------------------------------------------------------------------------
# command_subsignals — the rescue-tier `chattr -ia .ssh` + authorized_keys fixture
# ---------------------------------------------------------------------------
chattr_sub = command_subsignals("chattr -ia .ssh")
check("chattr -ia .ssh -> has_immutability True", chattr_sub["has_immutability"] is True)
check("chattr -ia .ssh -> has_key_write False (no authorized_keys in THIS command)",
      chattr_sub["has_key_write"] is False)
check("chattr -ia .ssh -> not a c2 launch / self-spread / host-recon signal",
      not any([chattr_sub["has_c2_launch"], chattr_sub["has_self_spread"],
               chattr_sub["has_host_recon"]]), str(chattr_sub))

key_sub = command_subsignals("echo ssh-rsa AAAAB3 attacker@evil >> ~/.ssh/authorized_keys")
check("authorized_keys write -> has_key_write True", key_sub["has_key_write"] is True)
check("authorized_keys write -> has_immutability False (no chattr in THIS command)",
      key_sub["has_immutability"] is False)

check("both sub-signal dicts carry the full SUBSIGNAL_NAMES key set",
      set(chattr_sub.keys()) == set(SUBSIGNAL_NAMES) and set(key_sub.keys()) == set(SUBSIGNAL_NAMES))


print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
