"""Smoke test for ROADMAP #10 — playbook-name collision detection.

The detection helper (`_detect_name_collisions`) is the pure function
that decides whether pass-2 disambiguation needs to fire and which
clusters need renaming. Pass 2's LLM call and ES writes aren't covered
here — those need a live LLM and are exercised end-to-end in the
backward pipeline run.

Covers:
  * No collisions → empty result.
  * Within-run collision (two new playbooks share a name).
  * Cross-run collision (one new playbook collides with a frozen one).
  * Case-insensitive + trim normalisation.
  * Frozen-only collision is NOT returned (nothing to rename).
  * Empty / falsy names ignored.

Standalone — no ES, no LLM.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_playbook_disambiguate.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import _detect_name_collisions

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def _pb(pid: str, name: str) -> dict:
    return {
        "playbook_id": pid,
        "name": name,
        "member_cids": [f"cluster_{pid[-1]}"],
        "sample_session_ids": [f"s{pid[-1]}_a", f"s{pid[-1]}_b"],
        "unique_commands": [f"cmd-from-{pid}"],
        "group_id": f"pg{pid[-1]}",
        "size": 5,
    }


# -------------------------------------------------------------------------
# [1] No collisions — every name unique.
# -------------------------------------------------------------------------
print("\n[1] no collisions")
out = _detect_name_collisions(
    pass1_named=[_pb("p1", "Mirai Variant"), _pb("p2", "XMRig Dropper")],
    existing_playbooks={
        "p_old1": {"playbook_id": "p_old1", "name": "Telegram Recon",
                   "sample_session_ids": ["x"], "cluster_ids": ["co1"]},
    },
)
check("no collisions → empty list", out == [], f"got {out!r}")


# -------------------------------------------------------------------------
# [2] Within-run collision: 2 new playbooks share a name.
# -------------------------------------------------------------------------
print("\n[2] within-run collision")
out = _detect_name_collisions(
    pass1_named=[
        _pb("p1", "curl Pipe Bash Dropper"),
        _pb("p2", "curl Pipe Bash Dropper"),
        _pb("p3", "Mirai Variant"),
    ],
    existing_playbooks={},
)
check("one collision group returned", len(out) == 1, f"got {len(out)} groups")
g = out[0]
check("both renamable", len(g["renamable"]) == 2 and len(g["frozen"]) == 0)
check("group carries the colliding name",
      g["name"] == "curl Pipe Bash Dropper", f"got {g['name']!r}")
pids = {pb["playbook_id"] for pb in g["renamable"]}
check("renamable contains p1 and p2", pids == {"p1", "p2"}, f"got {pids!r}")


# -------------------------------------------------------------------------
# [3] Cross-run collision: 1 new playbook collides with a frozen one.
# -------------------------------------------------------------------------
print("\n[3] cross-run collision")
out = _detect_name_collisions(
    pass1_named=[_pb("p1", "Mirai Variant")],
    existing_playbooks={
        "p_old": {"playbook_id": "p_old", "name": "Mirai Variant",
                  "sample_session_ids": ["sid_old"], "cluster_ids": ["co1"]},
    },
)
check("one collision group", len(out) == 1, f"got {len(out)} groups")
g = out[0]
check("renamable=1, frozen=1",
      len(g["renamable"]) == 1 and len(g["frozen"]) == 1)
check("renamable is p1", g["renamable"][0]["playbook_id"] == "p1")
check("frozen is p_old", g["frozen"][0]["playbook_id"] == "p_old")


# -------------------------------------------------------------------------
# [4] Case-insensitive + trim normalisation.
# -------------------------------------------------------------------------
print("\n[4] case + whitespace")
out = _detect_name_collisions(
    pass1_named=[
        _pb("p1", "  Mirai Variant  "),
        _pb("p2", "mirai variant"),
    ],
    existing_playbooks={},
)
check("trims and lowercases names when comparing",
      len(out) == 1 and len(out[0]["renamable"]) == 2,
      f"got {out!r}")


# -------------------------------------------------------------------------
# [5] Frozen-only collisions are NOT returned (nothing to rename).
# Two existing playbooks share a name. With no new playbook to rename,
# we don't disturb the existing ones.
# -------------------------------------------------------------------------
print("\n[5] frozen-only collisions are skipped")
out = _detect_name_collisions(
    pass1_named=[_pb("p1", "Telegram Recon")],
    existing_playbooks={
        "p_old1": {"playbook_id": "p_old1", "name": "curl Pipe Bash Dropper",
                   "sample_session_ids": ["x"], "cluster_ids": ["co1"]},
        "p_old2": {"playbook_id": "p_old2", "name": "curl Pipe Bash Dropper",
                   "sample_session_ids": ["y"], "cluster_ids": ["co2"]},
    },
)
check("frozen-vs-frozen collision returns no group",
      out == [], f"got {out!r}")


# -------------------------------------------------------------------------
# [6] Empty / falsy names ignored on both sides.
# -------------------------------------------------------------------------
print("\n[6] empty names")
out = _detect_name_collisions(
    pass1_named=[
        _pb("p1", ""),
        _pb("p2", ""),
        _pb("p3", None),  # type: ignore[arg-type]
    ],
    existing_playbooks={
        "p_old": {"playbook_id": "p_old", "name": "",
                  "sample_session_ids": [], "cluster_ids": []},
    },
)
check("empty/None names produce no collisions", out == [], f"got {out!r}")


# -------------------------------------------------------------------------
# [7] Mixed: multi-way within-run + frozen colliders on the same name.
# -------------------------------------------------------------------------
print("\n[7] multi-way collision with frozen")
out = _detect_name_collisions(
    pass1_named=[
        _pb("p1", "uname Reconnaissance"),
        _pb("p2", "uname Reconnaissance"),
        _pb("p3", "uname Reconnaissance"),
        _pb("p4", "Mirai Variant"),
    ],
    existing_playbooks={
        "p_old": {"playbook_id": "p_old", "name": "uname Reconnaissance",
                  "sample_session_ids": ["sid_old"], "cluster_ids": ["co1"]},
    },
)
check("one collision returned", len(out) == 1)
g = out[0]
check("3 renamable + 1 frozen", len(g["renamable"]) == 3 and len(g["frozen"]) == 1,
      f"renamable={len(g['renamable'])}, frozen={len(g['frozen'])}")


# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
