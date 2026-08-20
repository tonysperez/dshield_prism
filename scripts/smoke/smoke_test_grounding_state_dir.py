"""Command-grounding denylist state-dir override (release-readiness P1-5).

Under systemd, the installed source tree is read-only (`ProtectSystem=strict`),
so `command_grounding.py`'s denylist write (the Tune page's block/unblock
buttons) needs to land somewhere inside the unit's `ReadWritePaths`. It now
reads `PRISM_STATE_DIR` (set identically by every systemd unit in
`systemd/*.service` that imports this module) and redirects both the read and
the write there — critical that it's *both*: if only the write moved, the
pipeline would keep reading the stale package-relative copy while the console
edited a different file, silently splitting the two.

`_DENYLIST_PATH` is computed at module import time from the env var, so this
spawns fresh subprocesses (one per scenario) rather than re-importing in
process — a `reload()` wouldn't reliably reset a module-level constant read
from `os.environ` at import time, and a real deploy always sees the env var
before the process (and thus the import) even starts.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_grounding_state_dir.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def _denylist_path(env_overrides: dict[str, str]) -> str:
    env = dict(os.environ)
    env.pop("PRISM_STATE_DIR", None)
    env.update(env_overrides)
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from enrich.command_grounding import _DENYLIST_PATH; "
        "print(_DENYLIST_PATH)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code, str(SRC)],
        env=env, capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


# -----------------------------------------------------------------------------
# [1] Unset PRISM_STATE_DIR -> falls back to the package-relative path
# (dev/workstation checkout, no systemd env).
# -----------------------------------------------------------------------------
print("\n[1] PRISM_STATE_DIR unset -> package-relative denylist path")
path_unset = _denylist_path({})
expected_pkg = str(SRC / "enrich" / "data" / "commands" / "denylist.yaml")
check("resolves under src/enrich/data/commands", path_unset == expected_pkg,
      f"got {path_unset!r}, want {expected_pkg!r}")


# -----------------------------------------------------------------------------
# [2] PRISM_STATE_DIR set -> redirects under <state_dir>/command_grounding/,
# matching what every systemd unit sets (PRISM_STATE_DIR=/var/lib/dshield_prism).
# -----------------------------------------------------------------------------
print("\n[2] PRISM_STATE_DIR set -> redirected under <state_dir>/command_grounding/")
path_set = _denylist_path({"PRISM_STATE_DIR": "/var/lib/dshield_prism"})
expected_state = "/var/lib/dshield_prism/command_grounding/denylist.yaml"
check("resolves under the state dir", path_set == expected_state,
      f"got {path_set!r}, want {expected_state!r}")
check("does NOT fall back to the package path when set", path_set != path_unset)


# -----------------------------------------------------------------------------
# [3] Every systemd unit that imports command_grounding sets PRISM_STATE_DIR
# to the SAME value — a mismatch would split-brain the denylist between
# whichever unit writes it (console) and whichever reads it (the pipeline
# units), which is worse than not fixing this at all.
# -----------------------------------------------------------------------------
print("\n[3] every systemd unit sets PRISM_STATE_DIR consistently")
systemd_dir = REPO / "systemd"
service_files = sorted(systemd_dir.glob("*.service"))
check("found systemd unit files", len(service_files) > 0, str(systemd_dir))
values: dict[str, str] = {}
for f in service_files:
    text = f.read_text(encoding="utf-8")
    line = next((ln for ln in text.splitlines() if ln.startswith("Environment=PRISM_STATE_DIR=")), None)
    if line:
        values[f.name] = line.split("=", 2)[2]
check("every unit sets PRISM_STATE_DIR (none silently omitted)",
      len(values) == len(service_files),
      f"missing from: {sorted({f.name for f in service_files} - set(values))}")
check("every unit sets the SAME value", len(set(values.values())) == 1, str(values))
if values:
    check("value matches the state dir the fallback path check expects",
          next(iter(values.values())) == "/var/lib/dshield_prism", str(values))


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
