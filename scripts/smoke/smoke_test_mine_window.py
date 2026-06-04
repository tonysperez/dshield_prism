"""Smoke test for ROADMAP #21: campaign miners now window-scope by time.

Pre-#21 both `_iter_session_rollups` and `_iter_command_input_events`
ran with `match_all` queries — every session / every command event
ever indexed was pulled into memory. IO and working-set scaled
linearly with corpus age, and (correctness-wise) IPs that hit the
honeypot months apart could co-support an itemset that no real operator
ever assembled.

The fix introduces `_build_window_query(field, window_days)` and adds
`window_days: Optional[int] = _DEFAULT_MINE_WINDOW_DAYS` to both
iterators, `_build_ip_to_playbooks`, `run_mine_behaviour`,
`run_mine_infrastructure`, and the top-level `run_mine`. `window_days=0`
or `None` keeps the legacy unbounded behaviour for backfills.

This test uses a stub ES client that records every query body, then
asserts:
  1. `_build_window_query` returns match_all for None/0/negative and
     a proper range filter for positive ints.
  2. `_iter_session_rollups` query body includes the range filter on
     `event.start` when window_days is set, and is match_all otherwise.
  3. `_iter_command_input_events` includes the range filter on `@timestamp`.
  4. The miners' default is `_DEFAULT_MINE_WINDOW_DAYS`.
  5. `run_mine(window_days=N)` propagates N to both miners.

Standalone — no real ES, no pytest.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_mine_window.py
"""
from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.campaigns import (
    _DEFAULT_MINE_WINDOW_DAYS,
    _build_window_query,
    _iter_command_input_events,
    _iter_session_rollups,
    run_mine_behaviour,
    run_mine_infrastructure,
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


# -----------------------------------------------------------------------------
# [1] _build_window_query unit tests.
# -----------------------------------------------------------------------------
print("\n[1] _build_window_query — windowing math")
check(
    "None → match_all",
    _build_window_query("event.start", None) == {"match_all": {}},
    f"got {_build_window_query('event.start', None)}",
)
check(
    "0 → match_all (legacy unbounded behaviour)",
    _build_window_query("event.start", 0) == {"match_all": {}},
    f"got {_build_window_query('event.start', 0)}",
)
check(
    "negative → match_all (defensive)",
    _build_window_query("event.start", -5) == {"match_all": {}},
    f"got {_build_window_query('event.start', -5)}",
)
q = _build_window_query("event.start", 30)
check(
    "30 → range filter on event.start with gte=now-30d/d",
    q == {"range": {"event.start": {"gte": "now-30d/d"}}},
    f"got {q}",
)
q = _build_window_query("@timestamp", 7)
check(
    "7 on @timestamp → range filter with gte=now-7d/d",
    q == {"range": {"@timestamp": {"gte": "now-7d/d"}}},
    f"got {q}",
)


# -----------------------------------------------------------------------------
# [2] Iterator behaviour — records the actual query body issued.
# -----------------------------------------------------------------------------
print("\n[2] _iter_session_rollups query body")


class _StubES:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        # Pretend the response is empty so the iterator exits cleanly.
        return {"hits": {"hits": []}}


# Default (no override): module default applies → range filter on event.start.
es = _StubES()
list(_iter_session_rollups(es, "rollup-test"))
q = es.calls[0]["query"]
check(
    "session iter at default window → range on event.start",
    q == {"range": {"event.start": {"gte": f"now-{_DEFAULT_MINE_WINDOW_DAYS}d/d"}}},
    f"got {json.dumps(q)}",
)

# Explicit override to 0 — disables window, falls back to match_all.
es = _StubES()
list(_iter_session_rollups(es, "rollup-test", window_days=0))
q = es.calls[0]["query"]
check(
    "session iter with window_days=0 → match_all (legacy)",
    q == {"match_all": {}},
    f"got {json.dumps(q)}",
)

# Explicit override to 7 — narrower window.
es = _StubES()
list(_iter_session_rollups(es, "rollup-test", window_days=7))
q = es.calls[0]["query"]
check(
    "session iter with window_days=7 → range gte=now-7d/d",
    q == {"range": {"event.start": {"gte": "now-7d/d"}}},
    f"got {json.dumps(q)}",
)


# -----------------------------------------------------------------------------
# [3] _iter_command_input_events query body — needs to AND the window with
# the existing event.action filter.
# -----------------------------------------------------------------------------
print("\n[3] _iter_command_input_events query body")

es = _StubES()
list(_iter_command_input_events(es, "raw-test"))
q = es.calls[0]["query"]
# Expect bool.must with both the event.action term filter and the range filter.
must = q.get("bool", {}).get("must", [])
has_action = any(m.get("term", {}).get("event.action") == "cowrie.command.input" for m in must)
has_range = any(
    m.get("range", {}).get("@timestamp", {}).get("gte") == f"now-{_DEFAULT_MINE_WINDOW_DAYS}d/d"
    for m in must
)
check(
    "command iter at default window → bool.must has event.action filter",
    has_action,
    f"got {json.dumps(q)}",
)
check(
    "command iter at default window → bool.must has range on @timestamp",
    has_range,
    f"got {json.dumps(q)}",
)

# window_days=0 → range filter dropped, only event.action remains.
es = _StubES()
list(_iter_command_input_events(es, "raw-test", window_days=0))
q = es.calls[0]["query"]
must = q.get("bool", {}).get("must", [])
check(
    "command iter with window_days=0 → only event.action filter (no range)",
    len(must) == 1 and must[0].get("term", {}).get("event.action") == "cowrie.command.input",
    f"got {json.dumps(q)}",
)


# -----------------------------------------------------------------------------
# [4] Miner defaults match the module-level constant.
# -----------------------------------------------------------------------------
print("\n[4] miner defaults match _DEFAULT_MINE_WINDOW_DAYS")
sig_b = inspect.signature(run_mine_behaviour)
check(
    f"run_mine_behaviour default window_days == {_DEFAULT_MINE_WINDOW_DAYS}",
    sig_b.parameters["window_days"].default == _DEFAULT_MINE_WINDOW_DAYS,
    f"got {sig_b.parameters['window_days'].default}",
)
sig_i = inspect.signature(run_mine_infrastructure)
check(
    f"run_mine_infrastructure default window_days == {_DEFAULT_MINE_WINDOW_DAYS}",
    sig_i.parameters["window_days"].default == _DEFAULT_MINE_WINDOW_DAYS,
    f"got {sig_i.parameters['window_days'].default}",
)
check(
    "module constant value matches expected default (30)",
    _DEFAULT_MINE_WINDOW_DAYS == 30,
    f"got {_DEFAULT_MINE_WINDOW_DAYS}",
)


# -----------------------------------------------------------------------------
# [5] run_mine plumbing — when caller passes window_days, both miners get it.
# -----------------------------------------------------------------------------
print("\n[5] run_mine forwards window_days to both miners")

from enrich.sources.cowrie import campaigns as campaigns_mod

captured: list[tuple[str, dict]] = []

def _fake_behaviour(cfg, secrets, **kwargs):
    captured.append(("behaviour", dict(kwargs)))
    return {"stub": True}

def _fake_infra(cfg, secrets, **kwargs):
    captured.append(("infrastructure", dict(kwargs)))
    return {"stub": True}

orig_b = campaigns_mod.run_mine_behaviour
orig_i = campaigns_mod.run_mine_infrastructure
campaigns_mod.run_mine_behaviour = _fake_behaviour
campaigns_mod.run_mine_infrastructure = _fake_infra
try:
    # Caller passes None → both miners get NO window_days kwarg → they
    # use their own default (30).
    captured.clear()
    campaigns_mod.run_mine(None, None, kind="all", dry_run=True, window_days=None)
    behaviour_kwargs = next(k for n, k in captured if n == "behaviour")
    infra_kwargs = next(k for n, k in captured if n == "infrastructure")
    check(
        "window_days=None → behaviour miner called without explicit window_days kwarg",
        "window_days" not in behaviour_kwargs,
        f"got kwargs={behaviour_kwargs}",
    )
    check(
        "window_days=None → infra miner called without explicit window_days kwarg",
        "window_days" not in infra_kwargs,
        f"got kwargs={infra_kwargs}",
    )

    # Caller passes 7 → both miners receive window_days=7.
    captured.clear()
    campaigns_mod.run_mine(None, None, kind="all", dry_run=True, window_days=7)
    behaviour_kwargs = next(k for n, k in captured if n == "behaviour")
    infra_kwargs = next(k for n, k in captured if n == "infrastructure")
    check(
        "window_days=7 → behaviour miner receives 7",
        behaviour_kwargs.get("window_days") == 7,
        f"got {behaviour_kwargs}",
    )
    check(
        "window_days=7 → infra miner receives 7",
        infra_kwargs.get("window_days") == 7,
        f"got {infra_kwargs}",
    )

    # Caller passes 0 → forwarded as 0 (legacy unbounded opt-in).
    captured.clear()
    campaigns_mod.run_mine(None, None, kind="all", dry_run=True, window_days=0)
    behaviour_kwargs = next(k for n, k in captured if n == "behaviour")
    infra_kwargs = next(k for n, k in captured if n == "infrastructure")
    check(
        "window_days=0 (explicit unbounded) forwarded as 0",
        behaviour_kwargs.get("window_days") == 0 and infra_kwargs.get("window_days") == 0,
        f"got b={behaviour_kwargs} i={infra_kwargs}",
    )

    # kind='behaviour' alone → infra miner not called at all.
    captured.clear()
    campaigns_mod.run_mine(None, None, kind="behaviour", dry_run=True, window_days=14)
    check(
        "kind=behaviour → only behaviour miner called",
        len(captured) == 1 and captured[0][0] == "behaviour" and captured[0][1].get("window_days") == 14,
        f"got captured={captured}",
    )
finally:
    campaigns_mod.run_mine_behaviour = orig_b
    campaigns_mod.run_mine_infrastructure = orig_i


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
