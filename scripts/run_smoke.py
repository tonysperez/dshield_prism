#!/usr/bin/env python
"""Run the offline-safe smoke tests — the CI smoke gate (ROADMAP #8).

The ~88 `scripts/smoke/smoke_test_*.py` scripts are standalone (they mock/avoid
ES, the LLM, and the network), so they run in an isolated CI box with **no live
Elasticsearch**. This runner executes them in subprocesses and fails the build
if any non-skipped test fails.

Verified 2026-06-04 by running every smoke test with ES pointed at a dead
endpoint: 81 passed, 0 needed ES. The `SKIP` set below is the 7 that fail for
reasons UNRELATED to ES — pre-existing rot/bugs (exactly the "tests nobody runs,
so they rot" #8 warns about). Fix them and remove from SKIP. **Do not add a test
to SKIP because it needs ES** — none do; if one starts needing ES, mock it.

Run from the repo root:  python scripts/run_smoke.py [--list]
CI installs `enrich` (`.[cluster]`) + the console package, then runs this.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SMOKE_DIR = REPO / "scripts" / "smoke"
PER_TEST_TIMEOUT_S = 300


def _safe_env() -> dict:
    """Subprocess env that guarantees the smoke tests never touch a real ES or
    an unwritable state dir: point ES at a dead endpoint and redirect SQLite to
    a temp file (via a PRISM_LOCAL_CONFIG override). A caller-set
    PRISM_LOCAL_CONFIG (e.g. CI) wins — we only fill it in when unset."""
    env = dict(os.environ)
    if "PRISM_LOCAL_CONFIG" not in env:
        override = Path(tempfile.gettempdir()) / "run_smoke_local.yaml"
        override.write_text(
            'elasticsearch:\n  hosts: ["http://127.0.0.1:9"]\n'
            f'worker:\n  state_db: "{Path(tempfile.gettempdir()) / "run_smoke_state.sqlite"}"\n'
        )
        env["PRISM_LOCAL_CONFIG"] = str(override)
    return env

# name -> reason. Empty: the whole suite is green. NOT for ES-needing tests
# (none need ES) — only add a test here if it has a genuine pre-existing failure
# you can't fix immediately, with the reason. The 7 that were here (rot/path
# bugs the gate surfaced on first run) are all fixed.
SKIP: dict[str, str] = {}


def main() -> int:
    tests = sorted(SMOKE_DIR.glob("smoke_test_*.py"))
    if "--list" in sys.argv:
        for t in tests:
            mark = f"SKIP ({SKIP[t.name]})" if t.name in SKIP else "run"
            print(f"  {mark:6}  {t.name}" if t.name not in SKIP else f"  {mark}  {t.name}")
        return 0

    env = _safe_env()
    passed, failed, skipped = [], [], []
    for t in tests:
        if t.name in SKIP:
            skipped.append(t.name)
            continue
        try:
            r = subprocess.run(
                [sys.executable, str(t)], cwd=REPO, env=env, check=False,
                capture_output=True, text=True, timeout=PER_TEST_TIMEOUT_S,
            )
            ok = r.returncode == 0
            tail = (r.stdout + r.stderr)
        except subprocess.TimeoutExpired:
            ok, tail = False, f"TIMEOUT after {PER_TEST_TIMEOUT_S}s"
        if ok:
            passed.append(t.name)
            print(f"  PASS  {t.name}")
        else:
            failed.append(t.name)
            print(f"  FAIL  {t.name}")
            for line in tail.splitlines()[-15:]:
                print(f"        {line}")

    print(f"\n=== {len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped ===")
    if skipped:
        print("skipped (known pre-existing failures — NOT ES-related; see SKIP):")
        for s in skipped:
            print(f"  - {s}: {SKIP[s]}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
