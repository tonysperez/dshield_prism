"""Smoke test for the operations miner (brutal-review phase 7.1).

Covers:
  * `_operation_id` is stable + commutative on (bhv, inf) pair.
  * Pairs with overlap below the threshold don't mint.
  * Pairs with non-empty intersection above the threshold mint exactly
    one operation doc per pair, content-addressed by the stable id.
  * Multiple bhv × multiple inf produces N×M evaluations.
  * `first_seen` / `last_seen` come from the campaign extremes.
  * Empty / missing campaigns index returns cleanly.

Pure-function offline (stubs ES + the convergence-ratio cutoff lookup).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_operations.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.findings import operations as ops_mod  # noqa: E402

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# ---------------------------------------------------------------------------
# [1] _operation_id — stable + commutative.
# ---------------------------------------------------------------------------
print("[1] _operation_id")

id1 = ops_mod._operation_id("cmp-bhv-aaa", "cmp-inf-bbb")
id2 = ops_mod._operation_id("cmp-inf-bbb", "cmp-bhv-aaa")
check("op id format is 'op-<16hex>'",
      id1.startswith("op-") and len(id1) == 19 and all(c in "0123456789abcdef" for c in id1[3:]))
check("op id is commutative on argument order", id1 == id2, f"{id1} vs {id2}")
check("op id changes when one input changes",
      ops_mod._operation_id("cmp-bhv-aaa", "cmp-inf-ccc") != id1)


# ---------------------------------------------------------------------------
# [2] _earliest / _latest helpers — None-safe.
# ---------------------------------------------------------------------------
print("\n[2] timestamp helpers")
check("earliest(None, X) == X", ops_mod._earliest(None, "2026-05-01") == "2026-05-01")
check("earliest(X, None) == X", ops_mod._earliest("2026-05-01", None) == "2026-05-01")
check("earliest picks the lexicographically smaller ISO ts",
      ops_mod._earliest("2026-06-01", "2026-04-01") == "2026-04-01")
check("latest picks the lexicographically larger ISO ts",
      ops_mod._latest("2026-06-01", "2026-04-01") == "2026-06-01")
check("both None -> None",
      ops_mod._earliest(None, None) is None)


# ---------------------------------------------------------------------------
# [3] Miner — synthetic bhv + inf with known overlap.
# ---------------------------------------------------------------------------
print("\n[3] run_mine_operations — synthetic corpus")

_BULK_CALLS: list[list[dict]] = []

class _StubIndices:
    def __init__(self, present: bool = True) -> None:
        self.present = present
    def exists(self, *, index: str) -> bool:
        return self.present
    def refresh(self, *, index: str):
        return {}


class _StubES:
    """Returns canned campaign docs in scroll order; captures bulk writes."""
    def __init__(self, *, campaigns: list[dict], present: bool = True) -> None:
        self.campaigns = campaigns
        self.indices = _StubIndices(present=present)
        self._delivered = False
    def search(self, **kwargs):
        if self._delivered:
            return {"hits": {"hits": []}}
        self._delivered = True
        hits = [
            {"_source": c, "sort": [i]}
            for i, c in enumerate(self.campaigns)
        ]
        return {"hits": {"hits": hits}}


class _Cfg:
    class elasticsearch:
        class indexes:
            class cowrie:
                campaigns  = "campaigns-test"
                operations = "operations-test"
    class findings:
        class discovery:
            convergence_min_ip_overlap_ratio = 0.4


# Monkey-patch the writer so we can capture without hitting ES.
_orig_bulk = ops_mod.bulk
_orig_init = ops_mod.init_index
_orig_make = ops_mod.make_client


def _stub_bulk(es, actions, **kw):
    actions_list = list(actions)
    _BULK_CALLS.append(actions_list)
    return len(actions_list), []


def _stub_init(es, mapping, index):
    return {"created": False, "stub": True}


_es_used: dict[str, _StubES] = {"es": None}  # type: ignore[assignment]


def _stub_make(esconf, secrets):
    return _es_used["es"]


def _stub_cutoff(es, cfg):
    # Pin the threshold so the test doesn't depend on a metrics index.
    return 0.5


ops_mod.bulk = _stub_bulk
ops_mod.init_index = _stub_init
ops_mod.make_client = _stub_make

# Patch the cutoff so the test is self-contained.
from enrich.findings import discovery as disc_mod  # noqa: E402
_orig_cutoff = disc_mod._convergence_ratio_cutoff
disc_mod._convergence_ratio_cutoff = _stub_cutoff


def _reset_bulk():
    _BULK_CALLS.clear()


# Scenario: two bhv, two inf. One pair overlaps strongly, one doesn't.
campaigns = [
    {"campaign_id": "cmp-bhv-A", "kind": "behaviour", "name": "Behaviour A",
     "member_source_ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
     "first_seen": "2026-04-01T00:00:00Z", "last_seen": "2026-05-15T00:00:00Z"},
    {"campaign_id": "cmp-bhv-B", "kind": "behaviour", "name": "Behaviour B",
     "member_source_ips": ["10.0.0.1", "10.0.0.2"],
     "first_seen": "2026-05-01T00:00:00Z", "last_seen": "2026-05-10T00:00:00Z"},
    {"campaign_id": "cmp-inf-X", "kind": "infrastructure", "name": "Infra X",
     "member_source_ips": ["1.1.1.1", "2.2.2.2", "5.5.5.5"],
     "first_seen": "2026-03-15T00:00:00Z", "last_seen": "2026-05-20T00:00:00Z"},
    {"campaign_id": "cmp-inf-Y", "kind": "infrastructure", "name": "Infra Y",
     "member_source_ips": ["99.99.99.99"],
     "first_seen": "2026-05-12T00:00:00Z", "last_seen": "2026-05-15T00:00:00Z"},
]
_es_used["es"] = _StubES(campaigns=campaigns)
_reset_bulk()

stats = ops_mod.run_mine_operations(_Cfg, secrets=None, dry_run=False)
check("pairs_evaluated counts all bhv × inf",
      stats["pairs_evaluated"] == 4, str(stats["pairs_evaluated"]))
check("operations_minted == 1 (only A×X passes 0.5 threshold)",
      stats["operations_minted"] == 1, str(stats["operations_minted"]))
check("threshold_used reflects stub cutoff (0.5)",
      stats["threshold_used"] == 0.5)
check("fallback_used = False when cutoff function returns a value",
      stats["fallback_used"] is False)

# Inspect the minted op
op_actions = [a for batch in _BULK_CALLS for a in batch]
check("exactly one operation bulk-indexed",
      len(op_actions) == 1, f"got {len(op_actions)}")
src = op_actions[0]["_source"]
check("operation_id is content-addressed on the pair",
      src["operation_id"] == ops_mod._operation_id("cmp-bhv-A", "cmp-inf-X"))
check("behaviour_id + infrastructure_id present",
      src["behaviour_id"] == "cmp-bhv-A" and src["infrastructure_id"] == "cmp-inf-X")
check("member_source_ips is the intersection, sorted",
      src["member_source_ips"] == ["1.1.1.1", "2.2.2.2"])
check("counts: bhv=4 inf=3 shared=2",
      src["bhv_ip_count"] == 4
      and src["inf_ip_count"] == 3
      and src["shared_ip_count"] == 2)
check("overlap_ratio = 2 / min(4,3) = 0.666...",
      abs(src["overlap_ratio"] - (2/3)) < 1e-6,
      str(src["overlap_ratio"]))
check("first_seen = earlier of the pair (2026-03-15)",
      src["first_seen"].startswith("2026-03-15"))
check("last_seen = later of the pair (2026-05-20)",
      src["last_seen"].startswith("2026-05-20"))


# ---------------------------------------------------------------------------
# [4] Re-mine upserts under the same id (stability invariant).
# ---------------------------------------------------------------------------
print("\n[4] re-mine stability")

_es_used["es"] = _StubES(campaigns=campaigns)
_reset_bulk()
stats2 = ops_mod.run_mine_operations(_Cfg, secrets=None, dry_run=False)
op_actions2 = [a for batch in _BULK_CALLS for a in batch]
check("second mine produces the same id",
      op_actions2[0]["_id"] == op_actions[0]["_id"])
check("operations_minted is still 1 (same pair, no duplicates)",
      stats2["operations_minted"] == 1)


# ---------------------------------------------------------------------------
# [5] Missing campaigns index → graceful no-op.
# ---------------------------------------------------------------------------
print("\n[5] missing campaigns index")
_es_used["es"] = _StubES(campaigns=[], present=False)
_reset_bulk()
stats3 = ops_mod.run_mine_operations(_Cfg, secrets=None, dry_run=False)
check("operations_minted == 0", stats3["operations_minted"] == 0)
check("pairs_evaluated == 0",   stats3["pairs_evaluated"] == 0)


# ---------------------------------------------------------------------------
# [6] Dry-run skips writes.
# ---------------------------------------------------------------------------
print("\n[6] dry-run")
_es_used["es"] = _StubES(campaigns=campaigns)
_reset_bulk()
stats4 = ops_mod.run_mine_operations(_Cfg, secrets=None, dry_run=True)
check("dry-run still evaluates pairs",
      stats4["pairs_evaluated"] == 4)
check("dry-run still counts mints",
      stats4["operations_minted"] == 1)
check("dry-run skips bulk writes",
      not _BULK_CALLS)


# Restore patches.
ops_mod.bulk = _orig_bulk
ops_mod.init_index = _orig_init
ops_mod.make_client = _orig_make
disc_mod._convergence_ratio_cutoff = _orig_cutoff


# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
