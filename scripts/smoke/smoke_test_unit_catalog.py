"""Console unit catalog vs the real systemd units — drift gate.

The /health "Pipeline & schedule" panel reads run state from ES (the `unit`
field `enrich.ops` stamps from `PRISM_SYSTEMD_UNIT=%n`), but the human
description behind each unit's tooltip and its timer cadence are static data in
`console.queries._UNIT_CATALOG` — ES cannot supply them.

Static data rots silently, so this test is the guard: add or remove a
`systemd/*.service` without touching the catalog and the build fails naming the
unit. It also checks that every unit file actually sets the env var the
attribution depends on — a unit missing it writes unattributed ops docs and
would quietly show up as "manual / ad-hoc" forever.

Scenarios:
  [1] catalog keys == systemd/*.service filenames (no missing, no extra)
  [2] every unit file sets Environment=PRISM_SYSTEMD_UNIT=%n, after its
      EnvironmentFile= so it wins
  [3] every catalog entry has a non-empty description and cadence
  [4] units with a matching *.timer advertise a cadence that isn't "manual"

Offline: reads repo files only. No ES, no LLM, no network.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_unit_catalog.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))

from console.queries import _UNIT_CATALOG

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


UNIT_DIR = REPO / "systemd"
SERVICES = sorted(p.name for p in UNIT_DIR.glob("*.service"))
TIMERS = {p.name for p in UNIT_DIR.glob("*.timer")}


# -----------------------------------------------------------------------------
# [1] The catalog covers exactly the units that exist.
# -----------------------------------------------------------------------------
print("\n[1] _UNIT_CATALOG keys match systemd/*.service exactly")
check("systemd/*.service found", bool(SERVICES), str(UNIT_DIR))

missing = [s for s in SERVICES if s not in _UNIT_CATALOG]
extra = [k for k in _UNIT_CATALOG if k not in SERVICES]
check("no unit missing from the catalog", not missing,
      f"add to console.queries._UNIT_CATALOG: {missing}")
check("no stale catalog entry", not extra,
      f"remove from console.queries._UNIT_CATALOG: {extra}")


# -----------------------------------------------------------------------------
# [2] Every unit stamps its own name, after the EnvironmentFile.
# -----------------------------------------------------------------------------
print("\n[2] every unit sets Environment=PRISM_SYSTEMD_UNIT=%n")
for name in SERVICES:
    text = (UNIT_DIR / name).read_text()
    lines = [ln.strip() for ln in text.splitlines()]
    stamp = "Environment=PRISM_SYSTEMD_UNIT=%n"
    has = stamp in lines
    check(f"{name} stamps its unit name", has,
          "ops docs from this unit would be unattributed")
    if has and any(ln.startswith("EnvironmentFile=") for ln in lines):
        # Compare last-to-last: systemd applies these in file order, so the
        # stamp must follow every EnvironmentFile= to be certain it wins.
        env_file_at = max(i for i, ln in enumerate(lines)
                          if ln.startswith("EnvironmentFile="))
        check(f"{name} sets it after EnvironmentFile",
              max(i for i, ln in enumerate(lines) if ln == stamp) > env_file_at,
              "EnvironmentFile would override the stamp")


# -----------------------------------------------------------------------------
# [3] Catalog entries are actually usable as a tooltip.
# -----------------------------------------------------------------------------
print("\n[3] catalog entries carry a description + cadence")
for name, meta in sorted(_UNIT_CATALOG.items()):
    check(f"{name} has a description",
          bool((meta.get("description") or "").strip()), str(meta))
    check(f"{name} has a cadence",
          bool((meta.get("cadence") or "").strip()), str(meta))


# -----------------------------------------------------------------------------
# [4] Cadence must be the timer's own OnCalendar string, verbatim. Prose would
#     be a second source of truth for a schedule systemd owns; comparing the
#     literal means changing a timer fails the build instead of quietly making
#     the console lie.
# -----------------------------------------------------------------------------
print("\n[4] cadence == the timer's OnCalendar string")
for name in SERVICES:
    timer = UNIT_DIR / name.replace(".service", ".timer")
    cadence = (_UNIT_CATALOG.get(name, {}).get("cadence") or "")
    if timer.name not in TIMERS:
        check(f"{name} (no timer) advertises no schedule",
              "*" not in cadence, cadence)
        continue
    on_cal = [ln.strip().split("=", 1)[1] for ln in timer.read_text().splitlines()
              if ln.strip().startswith("OnCalendar=")]
    check(f"{name} cadence matches its timer's OnCalendar",
          cadence in on_cal, f"catalog={cadence!r} timer={on_cal!r}")


# -----------------------------------------------------------------------------
# [5] The mapping the whole feature rests on. Without `unit` on `prism.ops`,
#     attribution is dead and every run lands in "manual / ad-hoc" — a state the
#     other checks here would happily report as green.
# -----------------------------------------------------------------------------
print("\n[5] prism.ops mapping still declares `unit`")
mapping = json.loads((REPO / "setup/es-mappings/ops/default.json").read_text())
props = mapping.get("mappings", {}).get("properties", {})
unit_map = props.get("unit", {})
check("`unit` present in the ops mapping", bool(unit_map), str(sorted(props)))
check("`unit` is a text+keyword multifield, not bare keyword",
      unit_map.get("type") == "text"
      and unit_map.get("fields", {}).get("keyword", {}).get("type") == "keyword",
      str(unit_map))
# The console aggregates on `unit.keyword`; a bare keyword field would break the
# project's own mapping-update rule and the agg's field path.
check("mapping stays strict-dynamic (the ordering constraint's premise)",
      mapping.get("mappings", {}).get("dynamic") == "strict",
      str(mapping.get("mappings", {}).get("dynamic")))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
