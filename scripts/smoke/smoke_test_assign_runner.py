"""Smoke test for the authoritative assignment write cores
(`enrich.sources.cowrie.assign_runner`: assignment_action, build_actions) and the
I4b config flag. No ES.

The critical safety property: shadow mode NEVER touches playbook_id; authoritative mode
sets it for assigned, clears it for novel, and always writes the shadow fields.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.assign_runner import assignment_action, build_actions
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


NOW = "2026-06-14T00:00:00Z"


def _session(act):
    return act["doc"]["dshield"]["cowrie"]["enrichment"]["session"]


assigned = Assignment(playbook_id="spb-X", cosine=0.99, status="assigned", cascade_rank=0)
novel = Assignment(playbook_id=None, cosine=0.80, status="novel")

# --- shadow mode: never touches playbook_id ---
sa = _session(assignment_action("s1", assigned, NOW, authoritative=False, playbook_name="X"))
check("shadow: writes cluster.assigned_playbook_id",
      sa["cluster"]["assigned_playbook_id"] == "spb-X", str(sa))
check("shadow: status + cosine + cascade + at written",
      sa["cluster"]["assignment_status"] == "assigned" and sa["cluster"]["assignment_cosine"] == 0.99
      and sa["cluster"]["assignment_cascade_rank"] == 0 and sa["cluster"]["assignment_at"] == NOW)
check("shadow: does NOT set playbook_id / playbook_name / playbook_named_at",
      "playbook_id" not in sa and "playbook_name" not in sa and "playbook_named_at" not in sa,
      str(sa))

# --- authoritative assigned: sets playbook_id/name + bumps named_at ---
aa = _session(assignment_action("s2", assigned, NOW, authoritative=True, playbook_name="X-name"))
check("authoritative assigned: playbook_id set", aa.get("playbook_id") == "spb-X", str(aa))
check("authoritative assigned: playbook_name set", aa.get("playbook_name") == "X-name")
check("authoritative assigned: playbook_named_at bumped (IP rollups self-heal)",
      aa.get("playbook_named_at") == NOW)
check("authoritative assigned: shadow fields still written",
      aa["cluster"]["assigned_playbook_id"] == "spb-X")

# --- authoritative novel: clears playbook_id/name ---
an = _session(assignment_action("s3", novel, NOW, authoritative=True))
check("authoritative novel: playbook_id cleared to None",
      "playbook_id" in an and an["playbook_id"] is None, str(an))
check("authoritative novel: playbook_name cleared to None", an["playbook_name"] is None)
check("authoritative novel: shadow status novel",
      an["cluster"]["assignment_status"] == "novel" and an["cluster"]["assigned_playbook_id"] is None)

# --- band (post-resolve shouldn't occur) leaves playbook_id untouched in authoritative ---
band = Assignment(playbook_id="spb-Y", cosine=0.96, status="band", cascade_rank=0)
ab = _session(assignment_action("s4", band, NOW, authoritative=True, playbook_name="Y"))
check("authoritative band: playbook_id left untouched (not set/cleared)",
      "playbook_id" not in ab, str(ab))

# --- build_actions wires ids + names ---
acts = build_actions(["s1", "s2"], [assigned, novel], {"spb-X": "X-name"}, NOW, authoritative=True)
check("build_actions: one action per id, right ids",
      [a["_id"] for a in acts] == ["s1", "s2"], str([a["_id"] for a in acts]))
check("build_actions: resolved name applied to assigned",
      _session(acts[0]).get("playbook_name") == "X-name")

# --- I4b flag default ---
from enrich.config import SessionConfig  # noqa: E402

check("assignment_authoritative default True (operator request)",
      SessionConfig().assignment_authoritative is True)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
