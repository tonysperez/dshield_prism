"""Smoke test: ES heap / circuit-breaker backpressure.

Covers `enrich.es_health` (overload detection, breaker probe, capacity wait,
resilient retry) and the `ResilientClient` wrapper in `enrich.es_client`:

  * `is_overload_error` classifies 429 / circuit_breaker / write-queue
    rejections as retryable, and genuine errors (404, ValueError) as not.
  * `parent_breaker_ratio` parses `_nodes/stats/breaker` into a max ratio and
    returns None on malformed / raising stats.
  * `wait_for_capacity` no-ops when disabled or under the resume watermark,
    loops while the stubbed ratio stays high, and bails at the deadline.
  * `run_resilient` retries an overload-then-success, re-raises after the
    max_wait deadline, and does NOT retry a non-overload error.
  * `ResilientClient` routes direct + namespaced calls through `run_resilient`,
    returns non-API attrs raw, re-wraps `options()`, and exposes `._raw`.

Standalone — no ES. A fake clock makes `time.monotonic`/`time.sleep`
deterministic, so retries/waits don't actually sleep.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_es_backpressure.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich import es_health
from enrich.config import ESBackpressureConfig
from enrich.es_client import ResilientClient

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name if ok else (name, detail))  # type: ignore[arg-type]
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail and not ok else ""))


class _FakeClock:
    """Deterministic monotonic clock; `sleep` advances it instead of blocking."""
    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


def _install_clock() -> _FakeClock:
    clk = _FakeClock()
    es_health.time = clk  # type: ignore[assignment]
    return clk


def _bp(**over) -> ESBackpressureConfig:
    base = dict(
        enabled=True, heap_high_watermark=0.85, heap_resume_watermark=0.70,
        poll_interval_s=1.0, max_wait_s=10.0,
        retry_max_attempts=200, retry_base_delay_s=1.0, retry_max_delay_s=4.0,
    )
    base.update(over)
    return ESBackpressureConfig(**base)


class _Err(Exception):
    def __init__(self, msg: str, status: int | None = None) -> None:
        super().__init__(msg)
        if status is not None:
            self.status_code = status


# ---------------------------------------------------------------------------
print("[1] is_overload_error")
check("429 by status", es_health.is_overload_error(_Err("nope", status=429)))
check("circuit_breaking_exception text",
      es_health.is_overload_error(_Err("... circuit_breaking_exception: data too large")))
check("es_rejected_execution_exception text",
      es_health.is_overload_error(_Err("es_rejected_execution_exception")))
check("404 is not overload", not es_health.is_overload_error(_Err("missing", status=404)))
check("plain error is not overload", not es_health.is_overload_error(ValueError("bad query")))


# ---------------------------------------------------------------------------
print("[2] parent_breaker_ratio")
class _Nodes:
    def __init__(self, resp, raise_=False):
        self._resp = resp
        self._raise = raise_
    def stats(self, **k):
        if self._raise:
            raise RuntimeError("boom")
        return self._resp
class _ProbeES:
    def __init__(self, resp, raise_=False):
        self.nodes = _Nodes(resp, raise_)

good = {"nodes": {
    "a": {"breakers": {"parent": {"limit_size_in_bytes": 100, "estimated_size_in_bytes": 60}}},
    "b": {"breakers": {"parent": {"limit_size_in_bytes": 100, "estimated_size_in_bytes": 90}}},
}}
check("max ratio across nodes", es_health.parent_breaker_ratio(_ProbeES(good)) == 0.9)
check("raising stats -> None", es_health.parent_breaker_ratio(_ProbeES(None, raise_=True)) is None)
check("malformed stats -> None", es_health.parent_breaker_ratio(_ProbeES({"nodes": {"a": {}}})) is None)


# ---------------------------------------------------------------------------
print("[3] wait_for_capacity")
_install_clock()

check("disabled -> no-op",
      es_health.wait_for_capacity(_ProbeES(good), _bp(enabled=False), label="x") is None)

# Ratio under the high watermark -> returns immediately (no looping).
es_health.parent_breaker_ratio = lambda raw: 0.50  # type: ignore[assignment]
clk = _install_clock()
es_health.wait_for_capacity(object(), _bp(), label="under-watermark")
check("under high watermark returns immediately (no sleep)", clk.t == 0.0)

# Ratio high, then drains below the resume watermark after 2 probes.
seq = iter([0.90, 0.88, 0.60])
es_health.parent_breaker_ratio = lambda raw: next(seq, 0.60)  # type: ignore[assignment]
clk = _install_clock()
es_health.wait_for_capacity(object(), _bp(poll_interval_s=1.0), label="drain")
check("loops while high then returns (slept ~2x)", clk.t == 2.0, detail=f"t={clk.t}")

# Ratio stuck high -> bails at the max_wait deadline (warn + proceed).
es_health.parent_breaker_ratio = lambda raw: 0.95  # type: ignore[assignment]
clk = _install_clock()
es_health.wait_for_capacity(object(), _bp(poll_interval_s=1.0, max_wait_s=3.0), label="stuck")
check("bails at max_wait deadline", clk.t >= 3.0, detail=f"t={clk.t}")


# ---------------------------------------------------------------------------
print("[4] run_resilient")
es_health.parent_breaker_ratio = lambda raw: 0.10  # always healthy -> waits return fast
_install_clock()

# Overload once, then succeed.
state = {"n": 0}
def _flaky():
    state["n"] += 1
    if state["n"] == 1:
        raise _Err("circuit_breaking_exception")
    return "ok"
check("retries overload then returns result",
      es_health.run_resilient(_flaky, object(), _bp(), label="flaky") == "ok" and state["n"] == 2)

# Non-overload error -> raised immediately, fn called exactly once.
state2 = {"n": 0}
def _bad():
    state2["n"] += 1
    raise ValueError("genuine error")
raised = False
try:
    es_health.run_resilient(_bad, object(), _bp(), label="bad")
except ValueError:
    raised = True
check("non-overload error re-raised immediately", raised and state2["n"] == 1)

# Always overload -> re-raises after the max_wait deadline.
_install_clock()
def _always():
    raise _Err("data too large", status=429)
gave_up = False
try:
    es_health.run_resilient(_always, object(), _bp(max_wait_s=5.0, retry_base_delay_s=1.0,
                                                   retry_max_delay_s=2.0), label="always")
except _Err:
    gave_up = True
check("gives up (re-raises) after max_wait deadline", gave_up)

# Disabled backpressure -> plain passthrough.
check("disabled -> plain fn() call",
      es_health.run_resilient(lambda: "raw", object(), _bp(enabled=False), label="off") == "raw")


# ---------------------------------------------------------------------------
print("[5] ResilientClient wrapper")
es_health.parent_breaker_ratio = lambda raw: 0.10  # type: ignore[assignment]
_install_clock()

class _FakeIndicesClient:           # type-name ends in 'Client' -> namespace
    def refresh(self, **k):
        return "refreshed"
class _FakeRaw:
    not_a_method = 123              # non-API attribute returned raw
    def __init__(self):
        self.indices = _FakeIndicesClient()
        self._search_calls = 0
    def search(self, **k):
        self._search_calls += 1
        if self._search_calls == 1:
            raise _Err("circuit_breaking_exception")
        return {"hits": "ok"}
    def options(self, **k):
        return self

raw = _FakeRaw()
c = ResilientClient(raw, _bp())
check("direct method retries overload then succeeds", c.search(index="x") == {"hits": "ok"})
check("namespaced method routes through wrapper", c.indices.refresh(index="x") == "refreshed")
check("non-API attribute returned raw", c.not_a_method == 123)
check("options() returns a re-wrapped client", type(c.options()).__name__ == "ResilientClient")
check("_raw exposes the unwrapped client", c._raw is raw)
# helpers-style mutation lands on the underlying client (slots-safe).
opt = c.options()
opt._client_meta = (("h", "bp"),)
check("attribute set forwards to raw client", getattr(raw, "_client_meta", None) == (("h", "bp"),))


# ---------------------------------------------------------------------------
print()
print(f"{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for name, detail in FAILED:
        print(f"  FAIL  {name}  {detail}")
    sys.exit(1)
print("SMOKE TEST: PASS")
