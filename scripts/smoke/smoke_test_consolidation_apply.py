"""Smoke test for the consolidation apply pure core
(`scripts/consolidation_apply.py`): plan_to_operations, build_repoint_request,
build_retire_request. No ES, no writes.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from consolidation_apply import (
    build_repoint_request,
    build_retire_request,
    plan_to_operations,
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


# --- plan_to_operations ---
report = {
    "merge_groups": [
        {"canonical": "spb-C", "members": ["spb-A1", "spb-A2", "spb-C"]},
        {"canonical": "spb-D", "members": ["spb-D", "spb-B1"]},
    ]
}
ops = plan_to_operations(report)
check("3 ops from 2 groups (2+1 aliases)", len(ops) == 3, str(ops))
check("canonical excluded from aliases",
      {o["alias"] for o in ops} == {"spb-A1", "spb-A2", "spb-B1"}, str(ops))
check("each alias maps to its group's canonical",
      {o["alias"]: o["canonical"] for o in ops}
      == {"spb-A1": "spb-C", "spb-A2": "spb-C", "spb-B1": "spb-D"}, str(ops))
check("empty plan → no ops", plan_to_operations({}) == [])
check("plan with only singletons → no ops",
      plan_to_operations({"merge_groups": [{"canonical": "spb-X", "members": ["spb-X"]}]}) == [])

# --- build_repoint_request ---
rq = build_repoint_request("idx.sessions", "spb-A1", "spb-C", "C-name", "2026-06-14T00:00:00Z")
check("repoint targets the alias by playbook_id",
      rq["query"] == {"term": {"dshield.cowrie.enrichment.session.playbook_id": "spb-A1"}}, str(rq["query"]))
check("repoint conflicts=proceed + refresh", rq["conflicts"] == "proceed" and rq["refresh"] is True)
prm = rq["script"]["params"]
check("repoint params carry canonical id/name, alias, now",
      prm["canonical_id"] == "spb-C" and prm["canonical_name"] == "C-name"
      and prm["alias_id"] == "spb-A1" and prm["now"] == "2026-06-14T00:00:00Z", str(prm))
src = rq["script"]["source"]
check("repoint sets playbook_id/name/merged_from/named_at",
      all(t in src for t in ("s.playbook_id = params.canonical_id",
                             "s.playbook_name = params.canonical_name",
                             "s.playbook_merged_from = params.alias_id",
                             "s.playbook_named_at = params.now")), src)

# --- build_retire_request ---
rt = build_retire_request("idx.anchors", "spb-A1", "spb-C", "2026-06-14T00:00:00Z")
check("retire targets the alias anchor by id", rt["id"] == "spb-A1")
check("retire params carry canonical + now",
      rt["script"]["params"] == {"canonical": "spb-C", "now": "2026-06-14T00:00:00Z"}, str(rt["script"]["params"]))
rsrc = rt["script"]["source"]
check("retire preserves centroid + sets merged_into/retired_at + is idempotent (noop guard)",
      all(t in rsrc for t in ("ctx._source.retired_centroid = ctx._source.anchor_centroid",
                              "ctx._source.remove('anchor_centroid')",
                              "ctx._source.merged_into = params.canonical",
                              "ctx._source.retired_at = params.now",
                              "ctx.op = 'noop'")), rsrc)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
