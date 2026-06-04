"""Session rollup always stamps observer.name (multi-sensor P6.1).

The session rollup `_id` is namespaced `<sensor>:<session_id>` (D3/P6.2) using
`observer.name` (or `_DEFAULT_SENSOR` when unset). But the doc only stored an
`observer` block when the raw events carried one — so single-sensor deploys
(whose Cowrie events have no `observer.name`) got an `_id` prefixed `default:`
while the doc had **no** `observer.name` field. A cross-sensor read that filters
on the `observer.name` field would then miss those docs.

P6.1 fix: `_build_session_doc` always stamps `observer.name` (defaulting to
`_DEFAULT_SENSOR`) so the doc's sensor identity matches its namespaced `_id`,
making the field reliably present for cross-sensor read disambiguation.

Scenarios:
  [1] events with no observer → observer.name == _DEFAULT_SENSOR, and the
      _session_uid built from it matches the `default:` _id namespace
  [2] events with an observer.name → preserved verbatim (+ other observer
      fields like type kept), _id namespaced to it

Offline; builds a doc from synthetic events.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_observer_name.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from enrich.config import load_config
from enrich.sources.cowrie.sessions import (
    _DEFAULT_SENSOR,
    _build_session_doc,
    _session_uid,
)

CFG = load_config(str(REPO / "config" / "default.yaml"))

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def _events(observer=None):
    sid = "abc123"
    conn = {"@timestamp": "2026-06-03T00:00:00Z",
            "event": {"action": "cowrie.session.connect"},
            "source": {"ip": "1.2.3.4"}, "cowrie": {"session_id": sid}}
    close = {"@timestamp": "2026-06-03T00:01:00Z",
             "event": {"action": "cowrie.session.closed"},
             "cowrie": {"session_id": sid}}
    if observer:
        conn["observer"] = observer
        close["observer"] = observer
    return [conn, close]


# -----------------------------------------------------------------------------
# [1] no observer on events → default, consistent with the _id namespace.
# -----------------------------------------------------------------------------
print("\n[1] events with no observer → observer.name == _DEFAULT_SENSOR")
d1 = _build_session_doc("abc123", _events(), {}, CFG)
on1 = (d1.get("observer") or {}).get("name")
check("observer block present", isinstance(d1.get("observer"), dict), str(d1.get("observer")))
check("observer.name == _DEFAULT_SENSOR", on1 == _DEFAULT_SENSOR, repr(on1))
check("_id namespace built from observer.name matches the `default:` prefix",
      _session_uid(on1, "abc123") == f"{_DEFAULT_SENSOR}:abc123",
      _session_uid(on1, "abc123"))


# -----------------------------------------------------------------------------
# [2] observer.name present → preserved verbatim, other fields kept.
# -----------------------------------------------------------------------------
print("\n[2] events with observer.name → preserved + namespaced _id")
d2 = _build_session_doc("abc123", _events({"name": "sensor-east", "type": "honeypot"}), {}, CFG)
obs2 = d2.get("observer") or {}
check("observer.name preserved", obs2.get("name") == "sensor-east", repr(obs2.get("name")))
check("other observer fields kept (type)", obs2.get("type") == "honeypot", repr(obs2.get("type")))
check("_id namespaced to the sensor", _session_uid(obs2.get("name"), "abc123") == "sensor-east:abc123",
      _session_uid(obs2.get("name"), "abc123"))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
