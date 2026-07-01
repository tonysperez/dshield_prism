"""History longitudinal lifecycle — pure scoring logic.

The reworked History page is a one-row-per-playbook longitudinal list ranked by a
composite `interest` score. This locks the pure helpers that drive it:
  * `_pick_interval`  — adaptive shared-axis bucket by corpus span.
  * `_history_rows`   — terms buckets → display rows with an aligned `band`.
  * `_band_recurs`    — dormant→active re-activation count (⟳ badge + recurring filter).
  * `_score_history`  — per-row signals + normalized 0–100 interest + state/trend.
  * `_sort_history`   — the analyst's sort lens.

Asserts the I/O-matrix properties: band alignment, recurrence detection, live/dead
state, trend direction, interest bounds + mass monotonicity, and the sort lens.
Standalone — no ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))

from console.queries import (  # noqa: E402
    _band_episodes,
    _band_recurs,
    _history_rows,
    _pick_interval,
    _score_history,
    _sort_history,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED.append(name) if ok else FAILED.append((name, detail)))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  {detail}"))


def bkt(pid, band, ips=1, nov=0.5, sessions=None):
    return {
        "key": pid,
        "doc_count": sum(band) if sessions is None else sessions,
        "band": {"buckets": [{"doc_count": v} for v in band]},
        "ips": {"value": ips},
        "novelty": {"value": nov},
        "first": {"value_as_string": "2024-01-01T00:00:00Z"},
        "last": {"value_as_string": "2024-03-01T00:00:00Z"},
    }


print("\n[1] _pick_interval — adaptive bucket by span")
check("30d → day", _pick_interval(30) == ("1d", "day"))
check("90d window still day (<=92)", _pick_interval(90) == ("1d", "day"))
check("180d → week", _pick_interval(180) == ("7d", "week"))
check("~2y → week boundary", _pick_interval(700) == ("7d", "week"))
check("~3y → month", _pick_interval(1000) == ("30d", "month"))
check("decade+ → quarter", _pick_interval(4000) == ("90d", "quarter"))

print("\n[2] _band_recurs — re-activation after a dormant gap")
check("continuous episode → 0", _band_recurs([1, 1, 1, 1], 2) == 0)
check("two episodes split by gap>=2 → 1", _band_recurs([1, 1, 0, 0, 0, 1, 1], 2) == 1)
check("gap too short → 0", _band_recurs([1, 0, 1], 2) == 0)
check("leading zeros (pre-birth) don't count", _band_recurs([0, 0, 1, 1], 2) == 0)
check("three episodes → 2", _band_recurs([1, 0, 0, 1, 0, 0, 1], 2) == 2)

print("\n[3] _history_rows — buckets → aligned band rows")
rows = _history_rows([bkt("pb-A", [1, 2, 3]), bkt("pb-B", [0, 5, 0]), {"key": None}], {"pb-A": "alpha"})
check("keyless bucket dropped", len(rows) == 2)
check("bands are equal-length (aligned)", len(rows[0]["band"]) == len(rows[1]["band"]) == 3)
check("name maps on", rows[0]["name"] == "alpha")
check("band carries integer counts", rows[0]["band"] == [1, 2, 3])
check("kind defaults to playbook", rows[0]["kind"] == "playbook")
# session-cluster path: name_map=None → name from the bucket's modal `name` sub-agg
scb = _history_rows([{
    "key": "sc1", "doc_count": 2,
    "band": {"buckets": [{"doc_count": 2}]},
    "ips": {"value": 1}, "novelty": {"value": 0.3},
    "first": {"value_as_string": "2024-01-01T00:00:00Z"},
    "last": {"value_as_string": "2024-02-01T00:00:00Z"},
    "name": {"buckets": [{"key": "ssh recon"}]},
}], None, kind="session_cluster")
check("modal name resolves when name_map is None", scb[0]["name"] == "ssh recon")
check("kind propagates", scb[0]["kind"] == "session_cluster")

print("\n[4] _score_history — signals, state, trend, interest bounds")
rise = _history_rows([bkt("rise", [0, 0, 1, 2, 4, 8], nov=0.9, ips=50)], {})
fall = _history_rows([bkt("fall", [8, 4, 2, 1, 0, 0], nov=0.1, ips=3)], {})
recur = _history_rows([bkt("recur", [3, 0, 0, 0, 3, 0], nov=0.4)], {})
pool = rise + fall + recur
_score_history(pool, gap=2, dead_tail=1)
by = {r["id"]: r for r in pool}
check("rising band → trend up", by["rise"]["trend_dir"] == "up", by["rise"]["trend_dir"])
check("rising band → live (tail active)", by["rise"]["state"] == "live")
check("falling band → trend down", by["fall"]["trend_dir"] == "down", by["fall"]["trend_dir"])
check("falling band → dead (silent tail)", by["fall"]["state"] == "dead")
check("gapped band → recurs>=1", by["recur"]["recurs"] >= 1, str(by["recur"]["recurs"]))
check("interest within 0..100", all(0 <= r["interest"] <= 100 for r in pool))
check("scratch signals stripped", not any(k.startswith("_") for r in pool for k in r))
check("terms carry the five normalized signals",
      set(by["rise"]["terms"]) == {"liveness", "trend", "recurrence", "mass", "escalation"})

print("\n[5] mass monotonicity + sort lens")
big = _history_rows([bkt("big", [50, 50, 50])], {})
small = _history_rows([bkt("small", [1, 1, 1])], {})
mpool = big + small
_score_history(mpool, gap=2, dead_tail=1)
mby = {r["id"]: r for r in mpool}
check("bigger volume → higher mass term",
      mby["big"]["terms"]["mass"] >= mby["small"]["terms"]["mass"])
_sort_history(mpool, "mass")
check("sort=mass puts the big playbook first", mpool[0]["id"] == "big")
_sort_history(mpool, "bogus")
check("unknown sort falls back to interest (no crash)", len(mpool) == 2)

print("\n[6] degenerate pools (review hardening)")
solo = _history_rows([bkt("solo", [1, 2, 3, 2, 1], nov=0.5)], {})
_score_history(solo, gap=2, dead_tail=1)
check("single-row pool scores > 0 (neutral norm, not a spurious 0)",
      solo[0]["interest"] > 0, str(solo[0]["interest"]))
sb = _history_rows([bkt("sb", [5])], {})
_score_history(sb, gap=2, dead_tail=1)
check("single-bucket band → trend flat (not spurious up)",
      sb[0]["trend_dir"] == "flat", sb[0]["trend_dir"])

print("\n[7] _band_episodes — alive spans for the live-period strip")
check("two episodes → two spans", _band_episodes([1, 1, 0, 0, 0, 1, 1], 2) == [[0, 1], [5, 6]])
check("continuous → one span", _band_episodes([1, 1, 1, 1], 2) == [[0, 3]])
check("short gap bridges → one span", _band_episodes([1, 0, 1], 2) == [[0, 2]])
check("leading zeros excluded", _band_episodes([0, 0, 1, 1], 2) == [[2, 3]])
ep_rows = _history_rows([bkt("ep", [1, 1, 0, 0, 0, 1, 1])], {})
_score_history(ep_rows, gap=2, dead_tail=1)
check("scored row carries episodes", ep_rows[0]["episodes"] == [[0, 1], [5, 6]])
check("recurs == len(episodes) - 1",
      ep_rows[0]["recurs"] == len(ep_rows[0]["episodes"]) - 1)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
