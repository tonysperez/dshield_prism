"""Session-rollup id namespacing — cross-sensor collision avoidance (P6.2/D3).

Cowrie session ids are instance-local short tokens; across multiple sensors two
sessions can share an id and collide on the rollup `_id`, silently corrupting
derived state on upsert. `_session_uid` namespaces the `_id` as
`<sensor>:<session_id>`.

Scenarios:
  [1] format is <sensor>:<session_id>
  [2] missing / empty sensor falls back to the default token
  [3] same raw session id on two sensors → distinct uids (the collision the
      change exists to prevent); same sensor+id is stable (idempotent upsert)

Pure-function test, offline. Note: reads never parse the uid back — they query
the raw `cowrie.session_id` field — so only the write-side invariant is tested.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_session_uid.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.sessions import _DEFAULT_SENSOR, _session_uid


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# -----------------------------------------------------------------------------
# [1] format.
# -----------------------------------------------------------------------------
print("\n[1] uid format is <sensor>:<session_id>")
check("named sensor", _session_uid("honey-eu-1", "abcd1234") == "honey-eu-1:abcd1234")


# -----------------------------------------------------------------------------
# [2] default fallback when sensor unset.
# -----------------------------------------------------------------------------
print("\n[2] missing/empty sensor → default token")
check("None sensor → default", _session_uid(None, "abcd1234") == f"{_DEFAULT_SENSOR}:abcd1234")
check("empty sensor → default", _session_uid("", "abcd1234") == f"{_DEFAULT_SENSOR}:abcd1234")


# -----------------------------------------------------------------------------
# [3] cross-sensor collision avoidance + same-sensor stability.
# -----------------------------------------------------------------------------
print("\n[3] same raw id on two sensors → distinct uids; same sensor → stable")
raw = "deadbeefcafe"
a = _session_uid("sensor-a", raw)
b = _session_uid("sensor-b", raw)
check("two sensors, same raw id → distinct uids (no upsert collision)", a != b, f"{a} vs {b}")
check("same sensor+id is stable (idempotent upsert)",
      _session_uid("sensor-a", raw) == a)
check("a single-sensor deploy keeps a stable default-namespaced id",
      _session_uid(None, raw) == _session_uid("", raw))


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
