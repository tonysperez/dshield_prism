"""Console run-status from prism.ops (scale-hardening P4.3).

`health_runs` only surfaces the 3 cluster `run_summary` docs. `health_ops_runs`
widens the /health "pipeline activity" panel to the P4.2 `prism.ops` telemetry:
the latest run per verb (newest doc in each `verb` terms bucket) plus the
in-progress heartbeat (`status=started` docs not yet patched to
finished/failed). The index is optional, so an absent / erroring `prism.ops`
must degrade to empty lists, never raise into the endpoint.

Scenarios:
  [1] latest-per-verb rows extracted from the terms+top_hits agg, sorted
      newest-first; running list from the status=started query
  [2] missing prism.ops index → {rows: [], running: []} (no telemetry yet)
  [3] a failing search degrades to empty rows but still returns the dict shape

Offline; stub ES + the real config (for cfg.ops.indexes.default).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_health_ops_runs.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))
sys.path.insert(0, str(REPO / "src"))

from console.queries import health_ops_runs, pipeline_running, _current_burst_start
# Use the CONSOLE's slim AppConfig (console._config), NOT enrich.config — the
# console runs on its own config class, and `cfg.ops` must resolve there too.
from console._config import load_config

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


def _doc(verb, status, dur, rc, started):
    return {"_source": {
        "verb": verb, "status": status, "host": "h1",
        "started_at": started, "finished_at": "x", "duration_s": dur, "rc": rc,
    }}


class _Idx:
    def __init__(self, exists): self._exists = exists
    def exists(self, *, index): return self._exists


class _StubES:
    """Serves the terms+top_hits agg (when `aggs` given) and the running
    query (otherwise). `fail` makes every search raise; `exists` toggles the
    index-presence guard."""

    def __init__(self, *, exists=True, fail=False):
        self.indices = _Idx(exists)
        self._fail = fail

    def search(self, *, index, size, query, aggs=None, sort=None, _source=None):
        if self._fail:
            raise RuntimeError("es down")
        if aggs:
            return {"aggregations": {"by_verb": {"buckets": [
                # deliberately NOT in time order — health_ops_runs must sort.
                {"key": "enrich",   "latest": {"hits": {"hits": [
                    _doc("enrich", "finished", 996.8, 0, "2026-06-03T15:02:00")]}}},
                {"key": "escalate", "latest": {"hits": {"hits": [
                    _doc("escalate", "failed", 0.1, 1, "2026-06-03T15:29:44")]}}},
                {"key": "rollup",   "latest": {"hits": {"hits": [
                    _doc("rollup", "finished", 157.4, 0, "2026-06-03T15:24:31")]}}},
            ]}}}
        return {"hits": {"hits": [
            {"_source": {"verb": "cluster", "host": "h1", "started_at": "2026-06-03T15:40:00"}},
        ]}}


# -----------------------------------------------------------------------------
# [1] happy path — latest per verb, newest-first; running heartbeat.
# -----------------------------------------------------------------------------
print("\n[1] latest run per verb (sorted newest-first) + in-progress heartbeat")
out = health_ops_runs(_StubES(), CFG)
verbs = [r["verb"] for r in out["rows"]]
check("one row per verb bucket", len(out["rows"]) == 3, str(verbs))
check("rows sorted by started_at desc",
      verbs == ["escalate", "rollup", "enrich"], str(verbs))
check("rows carry status + duration", out["rows"][0].get("status") == "failed"
      and out["rows"][2].get("duration_s") == 996.8, str(out["rows"][0]))
check("running heartbeat surfaced", [r["verb"] for r in out["running"]] == ["cluster"],
      str(out["running"]))


# -----------------------------------------------------------------------------
# [2] missing index → empty lists, no raise.
# -----------------------------------------------------------------------------
print("\n[2] absent prism.ops → empty lists (telemetry not enabled)")
out2 = health_ops_runs(_StubES(exists=False), CFG)
check("rows empty", out2["rows"] == [])
check("running empty", out2["running"] == [])


# -----------------------------------------------------------------------------
# [3] search failure → degrades to empty, still returns the dict shape.
# -----------------------------------------------------------------------------
print("\n[3] failing search → empty rows, no raise into the endpoint")
out3 = health_ops_runs(_StubES(fail=True), CFG)
check("returns the {rows, running} shape", set(out3.keys()) == {"rows", "running"}, str(out3.keys()))
check("rows empty on failure", out3["rows"] == [] and out3["running"] == [])


# -----------------------------------------------------------------------------
# [4] pipeline_running — the site-wide running-banner heartbeat.
# -----------------------------------------------------------------------------
print("\n[4] pipeline_running drives the global running banner")


class _RunningES:
    """Serves the running query with the given started docs (the age `range`
    clause is ES-side; the stub just returns what it's given)."""

    def __init__(self, started, *, exists=True):
        self.indices = _Idx(exists)
        self._started = started

    def search(self, *, index, size, query, sort=None, _source=None):
        return {"hits": {"hits": [{"_source": s} for s in self._started]}}


pr = pipeline_running(_RunningES([
    {"verb": "cluster", "host": "h1", "started_at": "2026-06-03T16:10:00"},
    {"verb": "rollup",  "host": "h1", "started_at": "2026-06-03T16:09:00"},
]), CFG)
check("active when a verb is in-flight", pr["active"] is True, str(pr))
check("running list populated", len(pr["running"]) == 2)
check("since = earliest started_at", pr["since"] == "2026-06-03T16:09:00", str(pr["since"]))

pr_idle = pipeline_running(_RunningES([]), CFG)
check("idle → active False, since None", pr_idle["active"] is False and pr_idle["since"] is None, str(pr_idle))

pr_off = pipeline_running(_RunningES([{"verb": "x", "started_at": "t"}], exists=False), CFG)
check("absent prism.ops → inactive (no banner)", pr_off == {"running": [], "active": False, "since": None}, str(pr_off))


# -----------------------------------------------------------------------------
# [5] burst-start = stable run start (survives reload): a long step must NOT
#     split the burst (gap is finished->started, not started->started), and a
#     prior cycle far back MUST split.
# -----------------------------------------------------------------------------
print("\n[5] _current_burst_start is the stable run start (not the current step)")

# started_at desc. d0 = current step (running, no finished); d1/d2 contiguous
# (d2 = a 19s enrich whose duration would falsely split a started->started gap
# walk); d3 = a prior cycle 30 min back that MUST split.
_BURST_DOCS = [
    {"started_at": "2026-06-03T16:00:35+00:00"},
    {"started_at": "2026-06-03T16:00:20+00:00", "finished_at": "2026-06-03T16:00:34+00:00"},
    {"started_at": "2026-06-03T16:00:00+00:00", "finished_at": "2026-06-03T16:00:19+00:00"},
    {"started_at": "2026-06-03T15:30:00+00:00", "finished_at": "2026-06-03T15:30:05+00:00"},
]


class _BurstES:
    """Distinguishes the running query (status=started) from the burst scan."""

    def __init__(self):
        self.indices = _Idx(True)

    def search(self, *, index, size, query, sort=None, _source=None):
        must = (query.get("bool") or {}).get("must") or []
        is_running = any((m.get("term") or {}).get("status") == "started" for m in must)
        if is_running:
            return {"hits": {"hits": [
                {"_source": {"verb": "cluster", "host": "h", "started_at": _BURST_DOCS[0]["started_at"]}},
            ]}}
        return {"hits": {"hits": [{"_source": d} for d in _BURST_DOCS]}}


burst = _current_burst_start(_BurstES(), "prism.ops")
check("burst start = earliest contiguous step (not split by a long step)",
      burst == "2026-06-03T16:00:00+00:00", str(burst))
prb = pipeline_running(_BurstES(), CFG)
check("pipeline_running.since = burst start, not the current step",
      prb["since"] == "2026-06-03T16:00:00+00:00", str(prb["since"]))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
