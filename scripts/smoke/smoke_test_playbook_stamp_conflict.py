"""Playbook stamping survives a stale-read version conflict.

`update_by_query` searches first, then writes each hit conditioned on the
`seq_no` search returned. Search sees only refreshed segments and both stamped
indices run `refresh_interval: 30s`, so the same centroid doc stamped twice in
one run (pass-1 name → pass-2 merge/rename) 409s on the second write. ES's
default `conflicts=abort` throws that as a ConflictError and drops the whole
request, leaving the centroid unnamed while its member sessions carry the id.

`_update_by_query_resilient` is the recovery: `conflicts=proceed` (so one bad
doc can't drop the batch), then refresh + re-run while conflicts remain.

The call *shape* matters as much as the retry: elasticsearch-py counts
`conflicts` among `update_by_query`'s body fields, so `body=` + `conflicts=`
raises "Received multiple values for 'conflicts'" and every write is lost.
(`delete_by_query` is exempt — `conflicts` is a plain query param there.) The
fake client below enforces both rules against the *real* client signature.

Scenarios:
  [1] clean first call → one UBQ, no recovery refresh
  [2] stale read, then clean → refresh + re-run, zero residual conflicts
  [3] a genuinely concurrent writer → retries exhaust, response still returned
      (no exception) with version_conflicts set for the caller to report
  [4] `_apply_playbook_name` end to end over a fake ES: centroid write asks for
      a post-write refresh, a persistent conflict is counted not raised, and the
      session write still runs
  [5] every conflict-tolerant UBQ in the pipeline passes query/script as keyword
      args (`increment_silent_runs` shares the failure mode)

Pure-function test, offline — the ES client is a local fake.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_playbook_stamp_conflict.py
"""
from __future__ import annotations

import inspect
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from elasticsearch import Elasticsearch

from enrich.findings.lifecycle import increment_silent_runs
from enrich.sources.cowrie.sessions import (
    _apply_playbook_name,
    _update_by_query_resilient,
)

# elasticsearch-py sends these as body fields, so a raw `body=` alongside any of
# them is rejected by the client. Kept explicit so the fake fails the same way.
_UBQ_BODY_FIELDS = ("conflicts", "max_docs", "query", "script", "slice")

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _FakeIndices:
    def __init__(self, calls: list[tuple]) -> None:
        self._calls = calls

    def refresh(self, index: str) -> dict:
        self._calls.append(("refresh", index))
        return {"_shards": {"failed": 0}}


    def exists(self, index: str) -> bool:      # es.indices.exists
        return True


class FakeES:
    """Minimal stand-in: replays a scripted list of UBQ responses (the last one
    repeats once exhausted) and records every call in order. Rejects any call
    the real 8.x client would reject."""

    def __init__(self, responses: list[dict]) -> None:
        self.calls: list[tuple] = []
        self._responses = list(responses)
        self.indices = _FakeIndices(self.calls)

    def update_by_query(self, *, index, conflicts=None, refresh=False, **kwargs):
        if "body" in kwargs and (
            conflicts is not None or any(f in kwargs for f in _UBQ_BODY_FIELDS)
        ):
            raise TypeError(
                "Received multiple values for 'conflicts', specify parameters "
                "using either body or parameters, not both."
            )
        # The real client's signature is the contract — a renamed/unknown
        # parameter must fail here, offline, not in production.
        inspect.signature(Elasticsearch.update_by_query).bind_partial(
            None, index=index, conflicts=conflicts, refresh=refresh, **kwargs,
        )
        self.calls.append(("ubq", index, conflicts, refresh))
        resp = self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]
        return dict(resp)


OK = {"updated": 3, "version_conflicts": 0}
CONFLICT = {"updated": 0, "version_conflicts": 1}


# -----------------------------------------------------------------------------
# [1] no conflict → single call, no recovery refresh.
# -----------------------------------------------------------------------------
print("\n[1] clean write → one UBQ, no recovery refresh")
es = FakeES([OK])
resp = _update_by_query_resilient(es, "idx", {"match_all": {}}, {"source": "noop"})
check("returns the UBQ response", resp["updated"] == 3, str(resp))
check("issues exactly one UBQ", [c[0] for c in es.calls] == ["ubq"], str(es.calls))
check("always passes conflicts=proceed", es.calls[0][2] == "proceed", str(es.calls[0]))


# -----------------------------------------------------------------------------
# [2] stale read then clean → refresh + re-run lands the write.
# -----------------------------------------------------------------------------
print("\n[2] stale-read conflict → refresh, re-run, write lands")
es = FakeES([CONFLICT, OK])
resp = _update_by_query_resilient(es, "idx", {"match_all": {}}, {"source": "noop"})
check("no residual conflicts", int(resp["version_conflicts"]) == 0, str(resp))
check("the retried write updated docs", resp["updated"] == 3, str(resp))
check("refreshed between attempts",
      [c[0] for c in es.calls] == ["ubq", "refresh", "ubq"], str(es.calls))


# -----------------------------------------------------------------------------
# [3] a real concurrent writer → bounded retries, conflict reported not raised.
# -----------------------------------------------------------------------------
print("\n[3] persistent conflict → bounded retry, no exception")
es = FakeES([CONFLICT])
resp = _update_by_query_resilient(es, "idx", {"match_all": {}}, {"source": "noop"})
check("residual conflict surfaced to the caller",
      int(resp["version_conflicts"]) == 1, str(resp))
check("retries are bounded (1 by default)",
      [c[0] for c in es.calls] == ["ubq", "refresh", "ubq"], str(es.calls))

es = FakeES([CONFLICT])
resp = _update_by_query_resilient(es, "idx", {"match_all": {}}, {"source": "noop"},
                                  retries=0)
check("retries=0 disables the recovery pass",
      [c[0] for c in es.calls] == ["ubq"], str(es.calls))


# -----------------------------------------------------------------------------
# [4] _apply_playbook_name end to end.
# -----------------------------------------------------------------------------
print("\n[4] _apply_playbook_name over a fake ES")
es = FakeES([OK])
stats: dict = defaultdict(int)
_apply_playbook_name(es, "clusters", "sessions", "run-1", ["c1", "c2"],
                     "spb-deadbeef", "SSH Key Dropper", stats)
ubqs = [c for c in es.calls if c[0] == "ubq"]
check("stamps centroids then sessions",
      [c[1] for c in ubqs] == ["clusters", "sessions"], str(ubqs))
check("centroid write refreshes (re-read by pass 2 in the same run)",
      ubqs[0][3] is True, str(ubqs[0]))
check("session write does not refresh (large index, refreshed once at the end)",
      ubqs[1][3] is False, str(ubqs[1]))
check("clean run records no conflict counters",
      not stats["centroid_update_conflicts"] and not stats["session_update_conflicts"],
      str(dict(stats)))

es = FakeES([CONFLICT])
stats = defaultdict(int)
_apply_playbook_name(es, "clusters", "sessions", "run-1", ["c1"],
                     "spb-deadbeef", "SSH Key Dropper", stats, log_prefix="merge")
check("persistent conflict counted, not raised",
      stats["centroid_update_conflicts"] == 1 and stats["session_update_conflicts"] == 1,
      str(dict(stats)))
check("conflict is not miscounted as an error",
      not stats["centroid_update_errors"] and not stats["session_update_errors"],
      str(dict(stats)))
check("session stamping still runs after a centroid conflict",
      [c[1] for c in es.calls if c[0] == "ubq"].count("sessions") == 2, str(es.calls))


# -----------------------------------------------------------------------------
# [5] the same failure mode elsewhere: lifecycle's silent-run bump.
# -----------------------------------------------------------------------------
print("\n[5] increment_silent_runs uses the accepted call shape")
es = FakeES([{"updated": 7, "version_conflicts": 0}])
n = increment_silent_runs(es, "prism.lifecycle", current_run_id="run-1")
check("bump lands (body= would have raised)", n == 7, str(n))
check("it asks for conflicts=proceed", es.calls[0][2] == "proceed", str(es.calls))

# The guard above is only worth having if it rejects the shape that broke
# production: body= alongside conflicts=.
rejected = False
try:
    FakeES([OK]).update_by_query(
        index="idx", body={"query": {"match_all": {}}}, conflicts="proceed",
    )
except TypeError:
    rejected = True
check("the fake rejects body= + conflicts= (the production failure)", rejected)


print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
