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
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))
sys.path.insert(0, str(REPO / "src"))

from console.queries import (  # noqa: E402
    health_ops_runs, pipeline_running, _current_burst_start, _unit_rows,
)
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


def _doc(verb, status, dur, rc, started, unit=None):
    src = {
        "verb": verb, "status": status, "host": "h1",
        "started_at": started, "finished_at": "x", "duration_s": dur, "rc": rc,
    }
    if unit:
        src["unit"] = unit
    return {"_source": src}


AGG_SEEN: dict = {}


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
        if aggs and "by_unit" in aggs:
            # Assert the agg SHAPE, not just serve a canned reply — otherwise a
            # regression to a bare `unit` field (fails on a text field), a
            # dropped `missing` (silently loses every manual run), or a lost
            # time bound would pass the whole suite.
            bu = aggs["by_unit"]["terms"]
            AGG_SEEN["field"] = bu.get("field")
            AGG_SEEN["missing"] = bu.get("missing")
            AGG_SEEN["failures"] = "failures" in aggs["by_unit"]["aggs"]
            AGG_SEEN["range"] = any(
                "range" in c for c in query.get("bool", {}).get("filter", [])
            )
            # Unit-then-verb agg backing the "Pipeline & schedule" panel.
            # `rollup` appears under TWO units — the case a verb-only agg
            # cannot represent.
            return {"aggregations": {"by_unit": {"buckets": [
                {"key": "dshield_prism-forward.service", "by_verb": {"buckets": [
                    {"key": "enrich", "latest": {"hits": {"hits": [_doc(
                        "enrich", "finished", 996.8, 0, "2026-06-03T15:02:00",
                        "dshield_prism-forward.service")]}}},
                    {"key": "rollup", "latest": {"hits": {"hits": [_doc(
                        "rollup", "finished", 157.4, 0, "2026-06-03T15:24:31",
                        "dshield_prism-forward.service")]}}},
                ]}},
                {"key": "dshield_prism-backward.service", "by_verb": {"buckets": [
                    {"key": "escalate", "latest": {"hits": {"hits": [_doc(
                        "escalate", "failed", 0.1, 1, "2026-06-03T15:29:44",
                        "dshield_prism-backward.service")]}}},
                    {"key": "rollup", "latest": {"hits": {"hits": [_doc(
                        "rollup", "finished", 12.0, 0, "2026-06-03T12:10:00",
                        "dshield_prism-backward.service")]}}},
                ]}},
                # Manual CLI runs: no `unit`, bucketed by the agg's `missing`.
                {"key": "manual / ad-hoc", "by_verb": {"buckets": [
                    {"key": "reembed", "latest": {"hits": {"hits": [_doc(
                        "reembed", "finished", 3.0, 0, "2026-06-02T09:00:00")]}}},
                ]}},
            ]}}}
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
check("aggregates on unit.keyword (a text field would reject `unit`)",
      AGG_SEEN.get("field") == "unit.keyword", str(AGG_SEEN))
check("missing-bucket keeps manual runs",
      AGG_SEEN.get("missing") == "manual / ad-hoc", str(AGG_SEEN))
check("windowed so a retired verb can't pin a unit forever",
      AGG_SEEN.get("range") is True, str(AGG_SEEN))
check("carries the failure filter that un-masks collapsed verbs",
      AGG_SEEN.get("failures") is True, str(AGG_SEEN))


# -----------------------------------------------------------------------------
# [2] missing index → empty lists, no raise. `units` MUST be empty too: the JS
#     renders its "no telemetry" placeholder on !units.length, so populating
#     catalog rows here would silently delete that placeholder.
# -----------------------------------------------------------------------------
print("\n[2] absent prism.ops → empty lists (telemetry not enabled)")
out2 = health_ops_runs(_StubES(exists=False), CFG)
check("rows empty", out2["rows"] == [])
check("running empty", out2["running"] == [])
check("units empty (keeps the JS placeholder)", out2["units"] == [], str(out2["units"]))


# -----------------------------------------------------------------------------
# [3] search failure → degrades to empty, still returns the dict shape.
# -----------------------------------------------------------------------------
print("\n[3] failing search → empty rows, no raise into the endpoint")
out3 = health_ops_runs(_StubES(fail=True), CFG)
check("returns the {rows, running, units} shape",
      set(out3.keys()) == {"rows", "running", "units"}, str(out3.keys()))
check("rows empty on failure", out3["rows"] == [] and out3["running"] == [])
# The agg failed, so no run docs — but every catalogued unit must still render
# (as "never") rather than the panel collapsing to nothing.
check("units fall back to catalog-only rows",
      bool(out3["units"]) and all(u["state"] == "never" for u in out3["units"]),
      str([(u["unit"], u["state"]) for u in out3["units"]]))


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
# [6] _unit_rows — the "Pipeline & schedule" panel's pure grouping. Covers every
#     row of the spec's I/O matrix. No ES.
# -----------------------------------------------------------------------------
print("\n[6] _unit_rows groups run docs by owning systemd unit")

NOW = datetime(2026, 6, 3, 16, 0, tzinfo=timezone.utc)
FWD = "dshield_prism-forward.service"
BWD = "dshield_prism-backward.service"
CAT = {
    FWD: {"description": "forward pass", "cadence": "every 30 min"},
    BWD: {"description": "backward pass", "cadence": "4×/day"},
    "dshield_prism-console.service": {"description": "the UI", "cadence": "continuous"},
}


def _row(verb, unit, status, started, rc=0, dur=1.0):
    d = {"verb": verb, "status": status, "started_at": started,
         "duration_s": dur, "rc": rc, "host": "h1"}
    if unit:
        d["unit"] = unit
    return d


def _by_unit(rows):
    return {u["unit"]: u for u in rows}


# Healthy scheduled unit + a unit that has never run + an unrun catalog entry.
u = _by_unit(_unit_rows(
    [_row("enrich", FWD, "finished", "2026-06-03T15:02:00"),
     _row("rollup", FWD, "finished", "2026-06-03T15:24:31")],
    [], CAT,
))
check("healthy unit → state ok", u[FWD]["state"] == "ok", str(u[FWD]["state"]))
check("last_run = max started_at, normalised to UTC",
      u[FWD]["last_run"] == "2026-06-03T15:24:31+00:00", str(u[FWD]["last_run"]))
check("child verb rows attached", len(u[FWD]["verbs"]) == 2, str(u[FWD]["verbs"]))
check("catalog description + cadence surfaced for the tooltip",
      u[FWD]["description"] == "forward pass" and u[FWD]["cadence"] == "every 30 min",
      str(u[FWD]))
check("never-run catalog unit still rendered",
      u[BWD]["state"] == "never" and u[BWD]["last_run"] is None, str(u[BWD]))

# Running: matched on (unit, verb), not verb alone.
u = _by_unit(_unit_rows(
    [_row("rollup", FWD, "started", "2026-06-03T16:00:00"),
     _row("rollup", BWD, "finished", "2026-06-03T12:00:00")],
    [{"verb": "rollup", "unit": FWD, "started_at": "2026-06-03T16:00:00"}], CAT,
))
check("in-flight unit → state running", u[FWD]["state"] == "running", str(u[FWD]["state"]))
check("same verb under another unit is NOT marked running",
      u[BWD]["state"] == "ok", str(u[BWD]["state"]))

# Failure, by status and by non-zero rc.
u = _by_unit(_unit_rows([_row("escalate", BWD, "failed", "t1", rc=1)], [], CAT))
check("failed status → state failed", u[BWD]["state"] == "failed", str(u[BWD]["state"]))
u = _by_unit(_unit_rows([_row("escalate", BWD, "finished", "t1", rc=2)], [], CAT))
check("non-zero rc → state failed", u[BWD]["state"] == "failed", str(u[BWD]["state"]))

# Manual runs and unknown units.
u = _by_unit(_unit_rows(
    [_row("reembed", None, "finished", "t1"),
     _row("x", "", "finished", "t1"),
     _row("y", "some-other.service", "finished", "t1")],
    [], CAT,
))
check("unstamped + empty-string unit → manual / ad-hoc bucket",
      len(u["manual / ad-hoc"]["verbs"]) == 2, str(u.get("manual / ad-hoc")))
check("unknown unit kept, with no tooltip",
      u["some-other.service"]["description"] is None, str(u.get("some-other.service")))

# Pre-migration corpus: docs exist, none carry `unit`.
rows = _unit_rows([_row("enrich", None, "finished", "t1")], [], CAT)
u = _by_unit(rows)
check("pre-migration → everything ad-hoc, catalog units 'never'",
      u["manual / ad-hoc"]["state"] == "ok"
      and all(u[k]["state"] == "never" for k in CAT), str([(r["unit"], r["state"]) for r in rows]))

# Empty input still yields the catalog.
rows = _unit_rows([], [], CAT)
check("no telemetry → one 'never' row per catalog unit",
      len(rows) == len(CAT) and all(r["state"] == "never" for r in rows), str(len(rows)))

# Sort: running, then failed, then ok, then never; ad-hoc last within rank.
rows = _unit_rows(
    [_row("a", FWD, "finished", "t1"),
     _row("b", BWD, "failed", "t1", rc=1),
     _row("c", None, "started", (NOW - timedelta(minutes=1)).isoformat())],
    [], CAT, NOW,
)
check("actionable states sort first",
      [r["unit"] for r in rows][:3] == ["manual / ad-hoc", BWD, FWD],
      str([(r["unit"], r["state"]) for r in rows]))


# -----------------------------------------------------------------------------
# [7] The masking case. `prism.ops.verb` is the TOP-LEVEL verb only, so
#     backward's four `mine` steps share one bucket: a failed `mine findings`
#     followed by a successful `mine hunts` leaves the newest doc `finished`.
#     Without the windowed failure filter the unit reads green and the failure
#     is never rendered — the exact thing this panel exists to catch.
# -----------------------------------------------------------------------------
print("\n[7] a collapsed sibling's failure still turns the unit red")

latest_ok = [_row("mine", BWD, "finished", "2026-06-03T15:30:00")]
u = _by_unit(_unit_rows(latest_ok, [], CAT, NOW))
check("without failure evidence the collapse reads ok",
      u[BWD]["state"] == "ok", str(u[BWD]["state"]))

u = _by_unit(_unit_rows(latest_ok, [], CAT, NOW, failed_verbs={BWD: ["mine"]}))
check("failure filter un-masks the overwritten sibling",
      u[BWD]["state"] == "failed", str(u[BWD]["state"]))
check("the failing verb is named for the UI",
      u[BWD]["failed_verbs"] == ["mine"], str(u[BWD]["failed_verbs"]))
check("the child row is marked failed, not ok",
      u[BWD]["verbs"][0]["state"] == "failed", str(u[BWD]["verbs"]))

# A unit known only from the failure filter must still appear.
u = _by_unit(_unit_rows([], [], {}, NOW, failed_verbs={"orphan.service": ["mine"]}))
check("a unit seen only in the failure filter still renders",
      u["orphan.service"]["state"] == "failed", str(list(u)))


# -----------------------------------------------------------------------------
# [8] Ghost runs. An OOM-killed process leaves `status=started` unpatched. Past
#     the heartbeat window that is a corpse, not a run — and since `running`
#     outranks `failed`, treating it as live would mask a real failure.
# -----------------------------------------------------------------------------
print("\n[8] a stale `started` doc is a ghost, not a running unit")

fresh = (NOW - timedelta(minutes=5)).isoformat()
stale = (NOW - timedelta(minutes=180)).isoformat()

u = _by_unit(_unit_rows([_row("enrich", FWD, "started", fresh)], [], CAT, NOW))
check("a recent started doc is running", u[FWD]["state"] == "running", str(u[FWD]["state"]))

u = _by_unit(_unit_rows([_row("enrich", FWD, "started", stale)], [], CAT, NOW))
check("a started doc past the window is NOT running",
      u[FWD]["state"] != "running", str(u[FWD]["state"]))

# The masking scenario: ghost + a real failure elsewhere in the same unit.
u = _by_unit(_unit_rows(
    [_row("enrich", FWD, "started", stale), _row("rollup", FWD, "failed", stale, rc=1)],
    [], CAT, NOW,
))
check("a ghost no longer hides a real failure",
      u[FWD]["state"] == "failed", str(u[FWD]["state"]))

# An explicitly-running doc always wins, however old the agg's copy looks.
u = _by_unit(_unit_rows(
    [_row("enrich", FWD, "finished", stale)],
    [{"verb": "enrich", "unit": FWD, "started_at": fresh}], CAT, NOW,
))
check("the windowed running list still marks the unit running",
      u[FWD]["state"] == "running", str(u[FWD]["state"]))

# A unit in flight that the agg never returned must not read "never".
u = _by_unit(_unit_rows(
    [], [{"verb": "enrich", "unit": "brand-new.service", "started_at": fresh}], {}, NOW,
))
check("an in-flight unit absent from the agg still renders as running",
      u["brand-new.service"]["state"] == "running", str(list(u)))


# -----------------------------------------------------------------------------
# [9] Aggregates on the unit row: honest duration and host.
# -----------------------------------------------------------------------------
print("\n[9] unit rows aggregate duration and host honestly")
u = _by_unit(_unit_rows(
    [_row("enrich", FWD, "finished", "2026-06-03T15:00:00", dur=10.0),
     _row("rollup", FWD, "finished", "2026-06-03T15:10:00", dur=2.5)],
    [], CAT, NOW,
))
check("duration is the unit's total, not a placeholder",
      u[FWD]["duration_s"] == 12.5, str(u[FWD]["duration_s"]))
check("a single host is named", u[FWD]["host"] == "h1", str(u[FWD]["host"]))

rows_mh = [_row("enrich", FWD, "finished", "t1"), _row("rollup", FWD, "finished", "t2")]
rows_mh[1]["host"] = "h2"
u = _by_unit(_unit_rows(rows_mh, [], CAT, NOW))
check("multiple hosts are not misreported as one",
      u[FWD]["host"] == "2 hosts", str(u[FWD]["host"]))

# Unparseable/missing timestamps must not raise or win the sort.
u = _by_unit(_unit_rows(
    [_row("a", FWD, "finished", None), _row("b", FWD, "finished", "not-a-date"),
     _row("c", FWD, "finished", "2026-06-03T15:00:00+00:00")],
    [], CAT, NOW,
))
check("a bad timestamp neither raises nor becomes last_run",
      u[FWD]["last_run"] == "2026-06-03T15:00:00+00:00", str(u[FWD]["last_run"]))
check("rows with no usable timestamp sort last",
      u[FWD]["verbs"][0]["verb"] == "c", str([v["verb"] for v in u[FWD]["verbs"]]))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
