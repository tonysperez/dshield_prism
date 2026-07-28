"""prism.ops run telemetry — per-verb started→finished/failed docs (P4.2).

Each tracked CLI verb writes a `started` doc on entry and patches it to
`finished`/`failed` on exit. The writer is best-effort: a telemetry failure (or
a missing index) must never break the verb it observes.

Scenarios:
  [1] run_start writes a started doc (verb, run_id, host, status=started)
  [2] run_finish patches to finished with duration_s + rc
  [3] run_finish patches to failed with an error string
  [4] index absent → run_start returns None; run_finish(None) is a safe no-op
  [5] ES client construction blows up → run_start returns None, never raises
  [6] a write exception inside run_start/run_finish is swallowed

Offline: patches enrich.es_client.make_client with a stub.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_ops_telemetry.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import enrich.es_client as esc
from enrich import ops
from enrich.config import load_config, load_secrets

CFG = load_config()
SEC = load_secrets()

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _StubIndices:
    def __init__(self, exists):
        self._exists = exists

    def exists(self, *, index):
        return self._exists


class _StubES:
    def __init__(self, *, exists=True, fail=frozenset()):
        self.indices = _StubIndices(exists)
        self.indexed: list[dict] = []
        self.updated: list[dict] = []
        self._fail = fail

    def index(self, *, index, id, document):
        if "index" in self._fail:
            raise RuntimeError("boom-index")
        self.indexed.append({"index": index, "id": id, "document": document})

    def update(self, *, index, id, doc):
        if "update" in self._fail:
            raise RuntimeError("boom-update")
        self.updated.append({"index": index, "id": id, "doc": doc})


def _patch(stub_or_exc):
    def _mk(*_a, **_k):
        if isinstance(stub_or_exc, Exception):
            raise stub_or_exc
        return stub_or_exc
    esc.make_client = _mk


# -----------------------------------------------------------------------------
# [1] + [2] start then finish (finished).
# -----------------------------------------------------------------------------
print("\n[1/2] start writes 'started'; finish patches to 'finished'")
es = _StubES(exists=True)
_patch(es)
h = ops.run_start(CFG, SEC, "rollup")
check("handle returned", h is not None)
check("one started doc indexed", len(es.indexed) == 1, f"got {len(es.indexed)}")
d = es.indexed[0]["document"]
check("status=started, verb=rollup, has run_id + host + started_at",
      d["status"] == "started" and d["verb"] == "rollup"
      and d.get("run_id") and d.get("host") and d.get("started_at"))
check("doc _id == run_id", es.indexed[0]["id"] == d["run_id"])
ops.run_finish(CFG, SEC, h, status="finished", rc=0)
check("one update issued", len(es.updated) == 1)
u = es.updated[0]["doc"]
check("status=finished, rc=0, has duration_s + finished_at",
      u["status"] == "finished" and u["rc"] == 0
      and "duration_s" in u and "finished_at" in u)
check("update targets the same _id", es.updated[0]["id"] == d["run_id"])


# -----------------------------------------------------------------------------
# [3] finish (failed) carries the error.
# -----------------------------------------------------------------------------
print("\n[3] finish 'failed' carries error + rc")
es = _StubES(exists=True)
_patch(es)
h = ops.run_start(CFG, SEC, "cluster")
ops.run_finish(CFG, SEC, h, status="failed", rc=1, error="kaboom")
u = es.updated[0]["doc"]
check("status=failed, rc=1, error captured",
      u["status"] == "failed" and u["rc"] == 1 and u["error"] == "kaboom")


# -----------------------------------------------------------------------------
# [4] index absent → no-op start, safe finish(None).
# -----------------------------------------------------------------------------
print("\n[4] absent index → no doc written; finish(None) is a no-op")
es = _StubES(exists=False)
_patch(es)
h = ops.run_start(CFG, SEC, "enrich")
check("handle is None when index absent", h is None)
check("nothing indexed", es.indexed == [])
ops.run_finish(CFG, SEC, h, status="finished", rc=0)  # must not raise
check("finish(None) did nothing", es.updated == [])


# -----------------------------------------------------------------------------
# [5] make_client raises → run_start returns None, never raises.
# -----------------------------------------------------------------------------
print("\n[5] ES construction failure is swallowed")
_patch(RuntimeError("no ES"))
h = ops.run_start(CFG, SEC, "mine")
check("run_start returned None on connect failure", h is None)


# -----------------------------------------------------------------------------
# [6] write exceptions inside start/finish are swallowed.
# -----------------------------------------------------------------------------
print("\n[6] index/update write exceptions are swallowed")
es = _StubES(exists=True, fail={"index"})
_patch(es)
check("run_start swallows an index() error", ops.run_start(CFG, SEC, "rollup") is None)
es = _StubES(exists=True)
_patch(es)
h = ops.run_start(CFG, SEC, "rollup")
es._fail = {"update"}
ops.run_finish(CFG, SEC, h, status="finished", rc=0)  # must not raise
check("run_finish swallows an update() error", True)


# -----------------------------------------------------------------------------
# [7] owning systemd unit stamped from PRISM_SYSTEMD_UNIT (each unit file sets
#     it to `%n`). Absent for a manual CLI run — the console buckets those as
#     "manual / ad-hoc", so the key must be OMITTED, not written as null:
#     `prism.ops` is `dynamic: strict` and a null groups on nothing.
# -----------------------------------------------------------------------------
print("\n[7] unit stamp from PRISM_SYSTEMD_UNIT; omitted for manual runs")
import os  # noqa: E402

_prev = os.environ.pop("PRISM_SYSTEMD_UNIT", None)
try:
    es = _StubES(exists=True)
    _patch(es)
    ops.run_start(CFG, SEC, "rollup")
    check("no env var → `unit` key omitted entirely",
          "unit" not in es.indexed[0]["document"], str(es.indexed[0]["document"]))

    os.environ["PRISM_SYSTEMD_UNIT"] = "dshield_prism-forward.service"
    es = _StubES(exists=True)
    _patch(es)
    ops.run_start(CFG, SEC, "rollup")
    check("env var set → `unit` stamped on the doc",
          es.indexed[0]["document"].get("unit") == "dshield_prism-forward.service",
          str(es.indexed[0]["document"]))

    os.environ["PRISM_SYSTEMD_UNIT"] = "   "
    es = _StubES(exists=True)
    _patch(es)
    ops.run_start(CFG, SEC, "rollup")
    check("blank/whitespace env var treated as unset",
          "unit" not in es.indexed[0]["document"], str(es.indexed[0]["document"]))

    # A stray export of the console's own bucket label must not merge real unit
    # runs into the manual bucket.
    os.environ["PRISM_SYSTEMD_UNIT"] = "manual / ad-hoc"
    es = _StubES(exists=True)
    _patch(es)
    ops.run_start(CFG, SEC, "rollup")
    check("the ad-hoc bucket label is rejected as a unit name",
          "unit" not in es.indexed[0]["document"], str(es.indexed[0]["document"]))

    # [8] strict-mapping fallback: if the ops mapping hasn't been updated yet,
    # ES rejects the `unit` field. Retry once without it so telemetry degrades
    # to pre-`unit` behaviour rather than disappearing entirely.
    print("\n[8] strict-mapping rejection falls back to an unstamped doc")
    os.environ["PRISM_SYSTEMD_UNIT"] = "dshield_prism-forward.service"

    class _StrictES(_StubES):
        """Rejects any doc carrying `unit`, like a strict mapping would."""

        def index(self, *, index, id, document):
            if "unit" in document:
                raise RuntimeError("strict_dynamic_mapping_exception: [unit]")
            super().index(index=index, id=id, document=document)

    es = _StrictES(exists=True)
    _patch(es)
    h = ops.run_start(CFG, SEC, "rollup")
    check("run_start still returns a usable handle", h is not None)
    check("the doc lands without `unit`",
          len(es.indexed) == 1 and "unit" not in es.indexed[0]["document"],
          str(es.indexed))
    ops.run_finish(CFG, SEC, h, status="finished", rc=0)
    check("the run still finishes normally", len(es.updated) == 1, str(es.updated))
finally:
    os.environ.pop("PRISM_SYSTEMD_UNIT", None)
    if _prev is not None:
        os.environ["PRISM_SYSTEMD_UNIT"] = _prev


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
