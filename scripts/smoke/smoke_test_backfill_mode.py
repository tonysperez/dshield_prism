"""`pipeline --backfill` step-plan transform (backlog B2 / problem #1).

Historical backfill must not run the temporally-corrupting steps (`track
lifecycles`, `mine findings`) — they'd stamp backfill wall-clock onto 2-year-old
activity and flood the inbox — and must cluster sessions over the FULL corpus
(`--window-days 0`), not the 30d window. `_apply_backfill_mode` encodes that.

Asserts: the two skip steps are dropped; `cluster sessions` → full-corpus
callable, `reset rollup watermarks` → force callable, and `enrich` → full-rescan
callable are each swapped (so a backfill re-enriches + re-pools the full history
instead of silently skipping everything older than the watermarks); every other
step is preserved in order with its original fn; the skip-set constant matches.

Standalone — no real ES. Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_backfill_mode.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from enrich.cli import (
    _BACKFILL_SKIP_STEPS,
    _apply_backfill_mode,
    _backfill_session_plan,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED.append(name) if ok else FAILED.append((name, detail)))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  {detail}"))


# A miniature stand-in for the real pipeline step list (name, fn, optional).
def _mk(tag):
    return lambda: tag


normal = [
    ("enrich", _mk("enrich"), False),
    ("reset rollup watermarks", _mk("reset_gated"), True),
    ("cluster commands", _mk("ccmd"), False),
    ("cluster sessions", _mk("csess_windowed"), False),
    ("name playbooks", _mk("name"), True),
    ("cluster ips", _mk("cips"), False),
    ("mine campaigns", _mk("camp"), True),
    ("track lifecycles", _mk("life"), True),
    ("intel refresh", _mk("intel"), True),
    ("mine findings", _mk("find"), True),
]

FULL = lambda: "csess_FULL"
FULL_RESET = lambda: "reset_FORCED"
ENRICH_FULL = lambda: "enrich_FULL"
out = _apply_backfill_mode(normal, {
    "cluster sessions": FULL,
    "reset rollup watermarks": FULL_RESET,
    "enrich": ENRICH_FULL,
})
names = [n for n, _f, _o in out]

print("\n[1] skip-set constant")
check("skip set is exactly the two corrupting steps",
      _BACKFILL_SKIP_STEPS == ("track lifecycles", "mine findings"),
      str(_BACKFILL_SKIP_STEPS))

print("\n[2] dropped + preserved")
check("track lifecycles dropped", "track lifecycles" not in names)
check("mine findings dropped", "mine findings" not in names)
check("count = 10 - 2 = 8", len(out) == 8, str(len(out)))
check("order preserved for kept steps",
      names == ["enrich", "reset rollup watermarks", "cluster commands",
                "cluster sessions", "name playbooks", "cluster ips",
                "mine campaigns", "intel refresh"],
      str(names))

print("\n[3] enrich + watermark reset + cluster sessions forced for the full corpus")
csess_fn = next(f for n, f, _o in out if n == "cluster sessions")
check("cluster sessions fn replaced with the full-corpus callable",
      csess_fn() == "csess_FULL", csess_fn())
reset_fn = next(f for n, f, _o in out if n == "reset rollup watermarks")
check("reset rollup watermarks fn replaced with the force variant",
      reset_fn() == "reset_FORCED", reset_fn())
enrich_fn = next(f for n, f, _o in out if n == "enrich")
check("enrich fn replaced with the full-rescan variant",
      enrich_fn() == "enrich_FULL", enrich_fn())
others_intact = all(
    f() == orig_fn()
    for (n, f, _o), (_on, orig_fn, _oo) in zip(out, [s for s in normal if s[0] not in _BACKFILL_SKIP_STEPS], strict=False)
    if n not in ("cluster sessions", "reset rollup watermarks", "enrich")
)
check("other steps keep their original fn", others_intact)

print("\n[4] Option A cutover — backfill session-labelling plan")
check("authoritative + anchors → assign_then_novel",
      _backfill_session_plan(True, True) == "assign_then_novel")
check("authoritative + NO anchors → legacy_full (bootstrap first library)",
      _backfill_session_plan(True, False) == "legacy_full")
check("not authoritative → legacy_full",
      _backfill_session_plan(False, True) == "legacy_full"
      and _backfill_session_plan(False, False) == "legacy_full")

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
