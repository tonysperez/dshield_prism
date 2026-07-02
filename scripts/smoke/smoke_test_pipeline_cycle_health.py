"""Console Health-badge cycle-state derivation (health-badge-door spec).

The topbar badge carries two signals: ingestion freshness (rollup @timestamp)
and pipeline-CYCLE health inferred from `prism.ops` verb-run telemetry. The
cycle classifier is a PURE function `_derive_cycle_state(rows, running, now_ts,
stale_min)` (no ES) so every I/O-matrix row is unit-testable offline; the ES
fetch lives in `pipeline_cycle_health` and must degrade to `{state: unknown}`
on an absent index or any query error.

Covers every row of the spec's I/O matrix:
  [1] Healthy    — all latest rows finished, newest within stale_min → ok
  [2] Failed     — any latest row status=failed → warn (+ failed verb names)
  [3] Behind     — newest ts older than stale_min, none running → behind
  [4] Running    — a verb in-flight → ok (recent activity, not behind)
  [5] No telemetry — zero verb_run rows → unknown (neutral dot)
  [6] ES error   — the prism.ops query raises / index absent → unknown

Offline; the pure helper needs no ES, and the ES-fetch cases use a tiny stub.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_pipeline_cycle_health.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))  # noqa: E402
sys.path.insert(0, str(REPO / "src"))  # noqa: E402

from console._config import load_config  # noqa: E402
from console.queries import _derive_cycle_state, pipeline_cycle_health  # noqa: E402

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


NOW = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
STALE_MIN = 120


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _row(verb, status, finished_delta_min=None, started_delta_min=None):
    """Build a latest-verb-run row. Deltas are minutes-before-NOW."""
    r = {"verb": verb, "status": status}
    if started_delta_min is not None:
        r["started_at"] = _iso(NOW - timedelta(minutes=started_delta_min))
    if finished_delta_min is not None:
        r["finished_at"] = _iso(NOW - timedelta(minutes=finished_delta_min))
    return r


# -----------------------------------------------------------------------------
# [1] Healthy — all finished, newest within stale_min.
# -----------------------------------------------------------------------------
print("\n[1] all latest runs finished + newest within stale_min → ok")
rows = [
    _row("rollup", "finished", finished_delta_min=10, started_delta_min=13),
    _row("cluster", "finished", finished_delta_min=30, started_delta_min=45),
]
out = _derive_cycle_state(rows, [], NOW, STALE_MIN)
check("state ok", out["state"] == "ok", str(out))
check("no failed verbs", out["failed_verbs"] == [], str(out))
check("newest_ts is the freshest finish", out["newest_ts"] == rows[0]["finished_at"], str(out))


# -----------------------------------------------------------------------------
# [2] Failed cycle — any latest row status=failed.
# -----------------------------------------------------------------------------
print("\n[2] any latest run status=failed → warn (+ failed verb names)")
rows = [
    _row("rollup", "finished", finished_delta_min=10, started_delta_min=13),
    _row("escalate", "failed", finished_delta_min=5, started_delta_min=6),
]
out = _derive_cycle_state(rows, [], NOW, STALE_MIN)
check("state warn", out["state"] == "warn", str(out))
check("failed verb named in list", out["failed_verbs"] == ["escalate"], str(out))
check("detail names the failed verb", "escalate" in (out["detail"] or ""), str(out))

# A failed verb wins even if another verb is in-flight (correctness signal beats
# recency).
out_fr = _derive_cycle_state(rows, [{"verb": "cluster"}], NOW, STALE_MIN)
check("failed beats running", out_fr["state"] == "warn", str(out_fr))


# -----------------------------------------------------------------------------
# [3] Behind — newest finished ts older than stale_min, none running.
# -----------------------------------------------------------------------------
print("\n[3] newest run older than stale_min, none running → behind")
rows = [
    _row("rollup", "finished", finished_delta_min=200, started_delta_min=205),
    _row("cluster", "finished", finished_delta_min=240, started_delta_min=250),
]
out = _derive_cycle_state(rows, [], NOW, STALE_MIN)
check("state behind", out["state"] == "behind", str(out))
check("no failed verbs", out["failed_verbs"] == [], str(out))


# -----------------------------------------------------------------------------
# [4] Running now — a verb in-flight → ok, even if the newest finish is stale.
# -----------------------------------------------------------------------------
print("\n[4] a verb in-flight → ok (recent activity, not behind)")
rows = [
    _row("rollup", "finished", finished_delta_min=200, started_delta_min=205),
]
out = _derive_cycle_state(rows, [{"verb": "cluster", "started_at": _iso(NOW)}], NOW, STALE_MIN)
check("running overrides stale → ok", out["state"] == "ok", str(out))
check("detail mentions running verb", "cluster" in (out["detail"] or ""), str(out))


# -----------------------------------------------------------------------------
# [5] No telemetry — zero verb_run rows → unknown.
# -----------------------------------------------------------------------------
print("\n[5] zero verb_run rows → unknown (neutral dot)")
out = _derive_cycle_state([], [], NOW, STALE_MIN)
check("state unknown", out["state"] == "unknown", str(out))
check("newest_ts None", out["newest_ts"] is None, str(out))


# -----------------------------------------------------------------------------
# [6] ES error / absent index → unknown, swallowed (no raise into the endpoint).
# -----------------------------------------------------------------------------
print("\n[6] ES query raises / index absent → unknown, no raise")


class _Idx:
    def __init__(self, exists): self._exists = exists
    def exists(self, *, index): return self._exists


class _RaisingES:
    """Index exists, but the search raises — must be swallowed to unknown."""
    def __init__(self): self.indices = _Idx(True)
    def search(self, **kw): raise RuntimeError("es down")


class _AbsentES:
    """prism.ops absent → unknown without ever searching."""
    def __init__(self): self.indices = _Idx(False)
    def search(self, **kw): raise AssertionError("should not search when index absent")


out_err = pipeline_cycle_health(_RaisingES(), CFG)
check("search failure → unknown", out_err["state"] == "unknown", str(out_err))
check("failure returns the full shape",
      set(out_err.keys()) == {"state", "detail", "newest_ts", "failed_verbs"}, str(out_err.keys()))

out_absent = pipeline_cycle_health(_AbsentES(), CFG)
check("absent index → unknown", out_absent["state"] == "unknown", str(out_absent))


# -----------------------------------------------------------------------------
# [7] pipeline_cycle_health end-to-end over a stubbed by_verb agg → ok.
# -----------------------------------------------------------------------------
print("\n[7] pipeline_cycle_health wires the agg + running fetch → derived state")


class _StubES:
    """Serves the by_verb terms+top_hits agg (aggs given) and the running query
    (otherwise)."""

    def __init__(self, rows, running):
        self.indices = _Idx(True)
        self._rows = rows
        self._running = running

    def search(self, *, index, size, query, aggs=None, sort=None, _source=None):
        if aggs:
            return {"aggregations": {"by_verb": {"buckets": [
                {"key": r["verb"], "latest": {"hits": {"hits": [{"_source": r}]}}}
                for r in self._rows
            ]}}}
        return {"hits": {"hits": [{"_source": s} for s in self._running]}}


# pipeline_cycle_health uses the REAL utcnow, so build these rows relative to it
# (not the frozen NOW the pure-helper cases use).
_real_now = datetime.now(timezone.utc)


def _live_row(verb, status, finished_delta_min):
    return {
        "verb": verb, "status": status,
        "finished_at": (_real_now - timedelta(minutes=finished_delta_min)).isoformat(),
        "started_at": (_real_now - timedelta(minutes=finished_delta_min + 2)).isoformat(),
    }


stub = _StubES(
    rows=[_live_row("rollup", "finished", 5)],
    running=[],
)
out7 = pipeline_cycle_health(stub, CFG)
check("healthy agg → ok", out7["state"] == "ok", str(out7))

stub_fail = _StubES(
    rows=[_live_row("escalate", "failed", 5)],
    running=[],
)
out7b = pipeline_cycle_health(stub_fail, CFG)
check("failed agg → warn with verb", out7b["state"] == "warn"
      and out7b["failed_verbs"] == ["escalate"], str(out7b))


# -----------------------------------------------------------------------------
# [8] Robustness — the pure classifier must stay TOTAL on malformed timestamps
# (review hardening): a tz-naive ts must not raise, and an unparseable
# finished_at must fall back to a valid started_at rather than dropping the row.
# -----------------------------------------------------------------------------
print("\n[8] malformed timestamps: naive ts is UTC-normalised; bad finished_at falls back")

# Naive ISO (no Z / no offset) — must be treated as UTC, not raise TypeError.
naive_rows = [{"verb": "rollup", "status": "finished",
               "finished_at": "2026-07-01T11:50:00",   # 10m before NOW, naive
               "started_at": "2026-07-01T11:47:00"}]
try:
    out8 = _derive_cycle_state(naive_rows, [], NOW, STALE_MIN)
    check("naive ts does not raise → ok", out8["state"] == "ok", str(out8))
except TypeError as exc:  # pragma: no cover -- the bug this guards against
    check("naive ts does not raise → ok", False, f"raised {exc!r}")

# finished_at present but garbage; started_at valid & fresh → use started_at,
# not drop the row into 'no run timestamps'.
bad_fin_rows = [{"verb": "cluster", "status": "finished",
                 "finished_at": "not-a-timestamp",
                 "started_at": _iso(NOW - timedelta(minutes=5))}]
out8b = _derive_cycle_state(bad_fin_rows, [], NOW, STALE_MIN)
check("unparseable finished_at falls back to started_at → ok",
      out8b["state"] == "ok", str(out8b))
check("newest_ts is the valid started_at",
      out8b["newest_ts"] == bad_fin_rows[0]["started_at"], str(out8b))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
