"""Console /health observability lane (health-observability spec).

The status strip adds two best-effort signals to /health, each a PURE classifier
(no ES) so every I/O-matrix row is unit-testable offline, wrapped by an ES fetch
that must degrade to a neutral state on any error:

  * ES pressure — `_derive_pressure_state(ratio, high_wm, resume_wm)` →
    ok / warn / crit / unknown; `es_pressure(es, cfg)` reads the parent-breaker
    ratio and must return `unknown` when the probe is unavailable / denied.
  * Per-sensor freshness — `_sensor_freshness_rows(buckets, now, stale_min)` →
    one `{sensor, last_ts, state}` per bucket (ok|stale); `sensor_freshness`
    aggregates the sessions rollup and must return `{rows: []}` on any ES error.

Offline; the pure helpers need no ES, and the wrappers use tiny stubs.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_health_observability.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))  # noqa: E402
sys.path.insert(0, str(REPO / "src"))  # noqa: E402

from console import queries  # noqa: E402
from console._config import load_config  # noqa: E402
from console.queries import (  # noqa: E402
    _derive_pressure_state,
    _sensor_freshness_rows,
    es_pressure,
    sensor_freshness,
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


HIGH = 0.85
RESUME = 0.70


# -----------------------------------------------------------------------------
# [1] _derive_pressure_state — every I/O-matrix row.
# -----------------------------------------------------------------------------
print("\n[1] _derive_pressure_state: healthy / elevated / critical / unknown")

ok = _derive_pressure_state(0.50, HIGH, RESUME)
check("below resume → ok", ok["state"] == "ok", str(ok))
check("ok carries ratio", ok["ratio"] == 0.50, str(ok))
check("ok detail shows percent", "50%" in (ok["detail"] or ""), str(ok))

warn = _derive_pressure_state(0.75, HIGH, RESUME)
check("resume <= ratio < high → warn", warn["state"] == "warn", str(warn))

crit = _derive_pressure_state(0.90, HIGH, RESUME)
check("ratio >= high → crit", crit["state"] == "crit", str(crit))

# Boundary: exactly at a watermark is inclusive of the higher state.
check("ratio == resume → warn", _derive_pressure_state(RESUME, HIGH, RESUME)["state"] == "warn")
check("ratio == high → crit", _derive_pressure_state(HIGH, HIGH, RESUME)["state"] == "crit")

unk = _derive_pressure_state(None, HIGH, RESUME)
check("ratio None → unknown", unk["state"] == "unknown", str(unk))
check("unknown ratio is None", unk["ratio"] is None, str(unk))
check("unknown full shape", set(unk.keys()) == {"state", "ratio", "detail"}, str(unk.keys()))


# -----------------------------------------------------------------------------
# [2] es_pressure — wires parent_breaker_ratio; degrades to unknown.
# -----------------------------------------------------------------------------
print("\n[2] es_pressure: stubbed nodes.stats → derived; denied/absent → unknown")


class _Nodes:
    def __init__(self, resp, raises=False):
        self._resp = resp
        self._raises = raises

    def stats(self, *, metric):
        if self._raises:
            raise RuntimeError("nodes.stats denied")
        return self._resp


class _PressES:
    def __init__(self, resp, raises=False):
        self.nodes = _Nodes(resp, raises)


# 90% of the parent breaker → crit.
resp = {"nodes": {"n1": {"breakers": {"parent": {
    "limit_size_in_bytes": 100, "estimated_size_in_bytes": 90}}}}}
out = es_pressure(_PressES(resp), CFG)
check("healthy stats → crit at 90%", out["state"] == "crit", str(out))

# nodes.stats denied → parent_breaker_ratio returns None → unknown, no raise.
out_denied = es_pressure(_PressES(None, raises=True), CFG)
check("denied nodes.stats → unknown", out_denied["state"] == "unknown", str(out_denied))

# Import unavailable (console-only install) → unknown without touching ES.
_saved = queries._ES_HEALTH_AVAILABLE
try:
    queries._ES_HEALTH_AVAILABLE = False
    out_noimp = es_pressure(_PressES(None, raises=True), CFG)
    check("es_health unavailable → unknown", out_noimp["state"] == "unknown", str(out_noimp))
finally:
    queries._ES_HEALTH_AVAILABLE = _saved


# -----------------------------------------------------------------------------
# [3] _sensor_freshness_rows — every I/O-matrix row (incl. synthetic N-sensor).
# -----------------------------------------------------------------------------
print("\n[3] _sensor_freshness_rows: one / multi / quiet / no-data")

NOW = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
STALE_MIN = 120


def _bucket(name, delta_min):
    ts = (NOW - timedelta(minutes=delta_min)).isoformat()
    return {"key": name, "last_ts": {"value_as_string": ts}}


# One sensor, fresh → single ok row.
one = _sensor_freshness_rows([_bucket("default", 10)], NOW, STALE_MIN)
check("one sensor → 1 row", len(one) == 1, str(one))
check("fresh single sensor → ok", one[0]["state"] == "ok", str(one))
check("row carries sensor name", one[0]["sensor"] == "default", str(one))

# Synthetic multi-sensor: two buckets, one older than stale_min → 2 rows, the
# old one flagged stale. (Covers the N-sensor branch without live multi-sensor
# data — the whole point of the pure helper.)
multi = _sensor_freshness_rows([_bucket("sensor-a", 5), _bucket("sensor-b", 200)],
                               NOW, STALE_MIN)
check("multi-sensor → 2 rows", len(multi) == 2, str(multi))
by_name = {r["sensor"]: r for r in multi}
check("fresh sensor → ok", by_name["sensor-a"]["state"] == "ok", str(multi))
check("quiet sensor (>stale_min) → stale", by_name["sensor-b"]["state"] == "stale", str(multi))

# Boundary: exactly at stale_min is NOT stale (strictly greater flips it).
edge = _sensor_freshness_rows([_bucket("edge", STALE_MIN)], NOW, STALE_MIN)
check("age == stale_min → ok (strict >)", edge[0]["state"] == "ok", str(edge))

# No data: zero buckets → empty list (caller renders empty-state, not an error).
check("no buckets → []", _sensor_freshness_rows([], NOW, STALE_MIN) == [])
check("None buckets → []", _sensor_freshness_rows(None, NOW, STALE_MIN) == [])

# Robustness: a bucket with a missing/garbage ts must not raise and fails safe
# to `stale` (we can't confirm it is fresh).
bad = _sensor_freshness_rows(
    [{"key": "no_ts"}, {"key": "junk", "last_ts": {"value_as_string": "not-a-ts"}}],
    NOW, STALE_MIN,
)
check("missing ts → stale, no raise", bad[0]["state"] == "stale", str(bad))
check("unparseable ts → stale, no raise", bad[1]["state"] == "stale", str(bad))


# -----------------------------------------------------------------------------
# [4] sensor_freshness — wires the by_sensor agg; ES error → {rows: []}.
# -----------------------------------------------------------------------------
print("\n[4] sensor_freshness: stubbed agg → rows; ES error → empty")

_real_now = datetime.now(timezone.utc)


class _StubES:
    def __init__(self, buckets=None, raises=False):
        self._buckets = buckets or []
        self._raises = raises

    def search(self, **kw):
        if self._raises:
            raise RuntimeError("es down")
        return {"aggregations": {"by_sensor": {"buckets": self._buckets}}}


fresh_ts = (_real_now - timedelta(minutes=1)).isoformat()
old_ts = (_real_now - timedelta(minutes=999)).isoformat()
stub = _StubES(buckets=[
    {"key": "default", "last_ts": {"value_as_string": fresh_ts}},
    {"key": "quiet", "last_ts": {"value_as_string": old_ts}},
])
out = sensor_freshness(stub, CFG)
check("agg → 2 rows", len(out["rows"]) == 2, str(out))
states = {r["sensor"]: r["state"] for r in out["rows"]}
check("fresh sensor ok / quiet sensor stale",
      states.get("default") == "ok" and states.get("quiet") == "stale", str(states))

out_err = sensor_freshness(_StubES(raises=True), CFG)
check("ES error → {rows: []}", out_err == {"rows": []}, str(out_err))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
