"""Per-item degradation log-flood cap (scale-hardening P4.1).

Per-item graceful-degradation fallbacks (e.g. a co-occurrence agg query failing
for ONE command) used to log a `warning` each. At corpus scale a degraded ES
would flood the journal with hundreds of thousands of identical lines —
exactly the "logs too much noise" risk this slice of P4.1 addresses.

`_note_degraded(key, msg, *args)` now warns ONCE per run per failure-type (the
operator signal), then counts + logs the rest at `debug`.
`flush_degraded_fallbacks()` returns + resets the per-run totals so the dominant
`enrich` path can surface the aggregate once. Each verb runs as its own
process, so the module-level counters are naturally per-run.

Scenarios:
  [1] first occurrence per key → one WARNING; subsequent → DEBUG (flood capped)
  [2] distinct keys each get their own one-warning
  [3] flush returns the accumulated counts and resets to empty

Offline; captures the commands logger.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_degraded_fallbacks.py
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie import commands as C

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


_RECORDS: list[tuple[str, str]] = []


class _Capture(logging.Handler):
    def emit(self, r):
        _RECORDS.append((r.levelname, r.getMessage()))


C.log.addHandler(_Capture())
C.log.setLevel(logging.DEBUG)


def _levels():
    return [lvl for lvl, _ in _RECORDS]


# Clean slate (in case an import warmed the counters).
C.flush_degraded_fallbacks()
_RECORDS.clear()

# -----------------------------------------------------------------------------
# [1] one warning on first occurrence, debug thereafter.
# -----------------------------------------------------------------------------
print("\n[1] per-item flood is capped: 1 warning then debug")
for i in range(5):
    C._note_degraded("k1", "k1 failed for %r: %s", f"cmd{i}", "boom")
warns = [m for lvl, m in _RECORDS if lvl == "WARNING"]
debugs = [lvl for lvl in _levels() if lvl == "DEBUG"]
check("exactly 1 WARNING for 5 occurrences", len(warns) == 1, str(len(warns)))
check("the other 4 are DEBUG", len(debugs) == 4, str(len(debugs)))
check("first warning carries the per-item-fallback marker",
      "per-item fallback" in warns[0], warns[0])


# -----------------------------------------------------------------------------
# [2] a distinct key gets its own single warning.
# -----------------------------------------------------------------------------
print("\n[2] distinct failure-types each warn once")
_RECORDS.clear()
C._note_degraded("k2", "k2 failed: %s", "x")
C._note_degraded("k2", "k2 failed: %s", "y")
warns2 = [m for lvl, m in _RECORDS if lvl == "WARNING"]
check("new key warns once", len(warns2) == 1, str(len(warns2)))


# -----------------------------------------------------------------------------
# [3] flush returns the accumulated counts and resets.
# -----------------------------------------------------------------------------
print("\n[3] flush returns per-run totals and resets")
snap = C.flush_degraded_fallbacks()
check("counts reflect every occurrence (k1=5, k2=2)",
      snap.get("k1") == 5 and snap.get("k2") == 2, str(snap))
check("flush resets to empty", C.flush_degraded_fallbacks() == {})
# After a reset, the next occurrence warns again (new run semantics).
_RECORDS.clear()
C._note_degraded("k1", "k1 failed: %s", "z")
check("first occurrence after flush warns again",
      [lvl for lvl, _ in _RECORDS] == ["WARNING"], str(_RECORDS))


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
