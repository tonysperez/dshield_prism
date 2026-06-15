"""Smoke test for the I3c shadow-write action builder
(`scripts/assign_shadow_write.py::shadow_action`) and the I3a config knobs.
No ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from assign_shadow_write import shadow_action
from enrich.sources.cowrie.assignment import Assignment

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# --- assigned session → shadow action ---
a = Assignment(playbook_id="spb-X", cosine=0.97, status="assigned",
               tfidf_cosine=0.85, confirmed_in_band=True, cascade_rank=1)
act = shadow_action("sensor:sess-1", a, "2026-06-14T00:00:00Z")
check("update op on the right doc id",
      act["_op_type"] == "update" and act["_id"] == "sensor:sess-1", str(act))
cluster = act["doc"]["dshield"]["cowrie"]["enrichment"]["session"]["cluster"]
check("writes assigned_playbook_id", cluster["assigned_playbook_id"] == "spb-X", str(cluster))
check("writes status/cosine/cascade/at",
      cluster["assignment_status"] == "assigned" and cluster["assignment_cosine"] == 0.97
      and cluster["assignment_cascade_rank"] == 1
      and cluster["assignment_at"] == "2026-06-14T00:00:00Z", str(cluster))
check("does NOT touch playbook_id / playbook_name",
      "playbook_id" not in cluster and "playbook_name" not in cluster
      and "playbook_id" not in act["doc"]["dshield"]["cowrie"]["enrichment"]["session"],
      str(act["doc"]))

# --- novel session → null playbook id, status novel ---
nov = Assignment(playbook_id=None, cosine=0.80, status="novel")
nact = shadow_action("sensor:sess-2", nov, "2026-06-14T00:00:00Z")
ncluster = nact["doc"]["dshield"]["cowrie"]["enrichment"]["session"]["cluster"]
check("novel: assigned_playbook_id is None + status novel",
      ncluster["assigned_playbook_id"] is None and ncluster["assignment_status"] == "novel",
      str(ncluster))

# --- I3a config knobs exist with the validated defaults ---
from enrich.config import SessionConfig  # noqa: E402

sc = SessionConfig()
check("assignment_tau default 0.94", sc.assignment_tau == 0.94, str(sc.assignment_tau))
check("assignment_confident_tau default 0.98", sc.assignment_confident_tau == 0.98)
check("assignment_tfidf_tau default 0.80", sc.assignment_tfidf_tau == 0.80)
check("assignment_shadow_enabled default False", sc.assignment_shadow_enabled is False)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
