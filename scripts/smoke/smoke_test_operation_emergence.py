"""Smoke test for the operation_emergence miner (brutal-review 7.3).

Covers:
  * First sighting of an op emits `event=formed`.
  * Re-mine on the same op produces nothing (prior finding exists).
  * Op that grew ≥ 1.5x its prior shared_ip_count emits `event=grew`
    with delta_signature='grew_<new_count>'.
  * Op below the growth ratio doesn't emit.
  * Missing ops index returns cleanly.
  * Evidence carries every analyst-relevant field.

Stubs ES; no network.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_operation_emergence.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.findings.discovery import (
    _OPERATION_GROWTH_RATIO,
    mine_operation_emergence,
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


class _StubIndices:
    def __init__(self, *, present_map=None):
        self.present_map = present_map or {}
    def exists(self, *, index):
        return self.present_map.get(index, True)


class _StubES:
    """Returns the seeded ops on the ops-index `search`, and a synthetic
    aggregation on the findings-index `search` derived from `prior_max`."""
    def __init__(self, *, ops_index, findings_index, ops, prior_max):
        self.ops_index = ops_index
        self.findings_index = findings_index
        self.ops = ops
        self.prior_max = prior_max
        self.indices = _StubIndices()

    def search(self, *, index, **kwargs):
        if index == self.ops_index:
            hits = [{"_source": o} for o in self.ops]
            return {"hits": {"hits": hits}}
        if index == self.findings_index:
            # Return the prior-max aggregation shape.
            buckets = []
            for op_id, m in (self.prior_max or {}).items():
                buckets.append({
                    "key": op_id,
                    "doc_count": 1,
                    "max_shared": {"value": m},
                })
            return {"hits": {"hits": []}, "aggregations": {
                "by_op": {"buckets": buckets},
            }}
        return {"hits": {"hits": []}}


class _Cfg:
    class elasticsearch:
        class indexes:
            class cowrie:
                operations = "ops-test"
    class findings:
        class indexes:
            default = "findings-test"


def _op(opid, shared, **kw):
    base = {
        "operation_id":         opid,
        "behaviour_id":         "cmp-bhv-A",
        "behaviour_name":       "BhvA",
        "infrastructure_id":    "cmp-inf-X",
        "infrastructure_name":  "InfX",
        "shared_ip_count":      shared,
        "bhv_ip_count":         shared + 5,
        "inf_ip_count":         shared + 3,
        "overlap_ratio":        0.6,
        "first_seen":           "2026-05-15T00:00:00Z",
        "last_seen":            "2026-05-31T00:00:00Z",
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# [1] First-sighting: no prior findings → formed.
# ---------------------------------------------------------------------------
print("[1] formed: no prior findings → one 'formed' per op")

es = _StubES(
    ops_index="ops-test", findings_index="findings-test",
    ops=[_op("op-aaa", 50), _op("op-bbb", 20)],
    prior_max={},
)
findings = mine_operation_emergence(es, _Cfg, run_id="r1")
check("two findings emitted, one per op",
      len(findings) == 2, str(len(findings)))
events = sorted((f["evidence"]["event"], f["artifact"]["value"]) for f in findings)
check("both events == 'formed'",
      events == [("formed", "op-aaa"), ("formed", "op-bbb")])
check("delta_signature == 'formed' for both",
      all(f["delta_signature"] == "formed" for f in findings))


# ---------------------------------------------------------------------------
# [2] Re-mine: prior 'formed' exists, op unchanged → no new finding.
# ---------------------------------------------------------------------------
print("\n[2] re-mine on unchanged op produces no new finding")

es = _StubES(
    ops_index="ops-test", findings_index="findings-test",
    ops=[_op("op-aaa", 50)],
    prior_max={"op-aaa": 50},
)
findings = mine_operation_emergence(es, _Cfg, run_id="r2")
check("zero new findings on unchanged op",
      len(findings) == 0)


# ---------------------------------------------------------------------------
# [3] Growth: shared_ip_count exceeds prior × 1.5.
# ---------------------------------------------------------------------------
print("\n[3] grew: shared count >= prior × growth ratio")

# 50 * 1.5 = 75; current 80 should fire.
es = _StubES(
    ops_index="ops-test", findings_index="findings-test",
    ops=[_op("op-aaa", 80)],
    prior_max={"op-aaa": 50},
)
findings = mine_operation_emergence(es, _Cfg, run_id="r3")
check("one finding emitted on growth",
      len(findings) == 1, str(len(findings)))
f = findings[0]
check("event == 'grew'", f["evidence"]["event"] == "grew")
check("delta_signature == 'grew_<new_count>'",
      f["delta_signature"] == "grew_80", f["delta_signature"])
check("evidence prior + current populated",
      f["evidence"]["shared_ip_count_prior"] == 50
      and f["evidence"]["shared_ip_count"] == 80)


# ---------------------------------------------------------------------------
# [4] Below growth ratio: 50 → 60 (1.2×, below 1.5) → no finding.
# ---------------------------------------------------------------------------
print("\n[4] sub-threshold growth produces nothing")

es = _StubES(
    ops_index="ops-test", findings_index="findings-test",
    ops=[_op("op-aaa", 60)],
    prior_max={"op-aaa": 50},
)
findings = mine_operation_emergence(es, _Cfg, run_id="r4")
check("zero findings on 1.2× growth (below ratio)",
      len(findings) == 0)


# ---------------------------------------------------------------------------
# [5] Re-mine on growth event: prior is now the new max, so re-running
# with the same shared count produces no new finding. Tests the
# bucket-by-count idempotency.
# ---------------------------------------------------------------------------
print("\n[5] re-mine after growth is idempotent")

# After the growth event in [3], prior_max would be 80 (since the agg
# picks the max over all prior findings).
es = _StubES(
    ops_index="ops-test", findings_index="findings-test",
    ops=[_op("op-aaa", 80)],
    prior_max={"op-aaa": 80},
)
findings = mine_operation_emergence(es, _Cfg, run_id="r5")
check("zero findings when re-mining at same shared count after growth",
      len(findings) == 0)


# ---------------------------------------------------------------------------
# [6] Missing ops index: graceful no-op.
# ---------------------------------------------------------------------------
print("\n[6] missing ops index returns empty")

es = _StubES(
    ops_index="ops-test", findings_index="findings-test",
    ops=[], prior_max={},
)
es.indices = _StubIndices(present_map={"ops-test": False})
findings = mine_operation_emergence(es, _Cfg, run_id="r6")
check("empty findings when ops index missing", findings == [])


# ---------------------------------------------------------------------------
# [7] Evidence shape — every analyst-relevant field present.
# ---------------------------------------------------------------------------
print("\n[7] evidence carries every documented field")

es = _StubES(
    ops_index="ops-test", findings_index="findings-test",
    ops=[_op("op-aaa", 50)], prior_max={},
)
findings = mine_operation_emergence(es, _Cfg, run_id="r7")
ev = findings[0]["evidence"]
required = {
    "operation_id", "event", "behaviour_id", "behaviour_name",
    "infrastructure_id", "infrastructure_name",
    "shared_ip_count", "shared_ip_count_prior",
    "bhv_ip_count", "inf_ip_count", "overlap_ratio",
    "first_seen", "last_seen",
}
missing = required - set(ev)
check("every required evidence field present",
      not missing, f"missing={sorted(missing)}")


# ---------------------------------------------------------------------------
# [8] Growth ratio constant is what we documented.
# ---------------------------------------------------------------------------
print("\n[8] growth ratio constant sanity")
check(f"_OPERATION_GROWTH_RATIO == 1.5 (got {_OPERATION_GROWTH_RATIO})",
      _OPERATION_GROWTH_RATIO == 1.5)


# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
