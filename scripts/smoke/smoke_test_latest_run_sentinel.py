"""Latest-run readers resolve via the run_summary sentinel (scale-hardening P3.1).

P3.3 made the clustering writer emit the `run_summary` doc LAST, so its presence
means the run's writes finished. P3.1 finishes the job: every reader that
resolves "the latest cluster run" now gates on `doc_type=run_summary` instead of
the newest `doc_type=cluster` doc, so a half-built run (centroids written, but
the process died before the run_summary) is invisible — readers fall back to the
previous *complete* run instead of aggregating half-applied state.

Readers unified (all the same query shape): `clustering.load_centroids`
(fallback), `explain._latest_run_id`, `name playbooks` (sessions.py),
`build_anchor_payload` (lifecycle.py), `name ip-clusters` (ips.py). The
findings miner, console `RunCache`, and the lifecycle `_latest_cluster_run`
already gated on the sentinel.

This exercises `explain._latest_run_id` as the representative (the others use the
identical pattern):
  [1] picks the run from the newest run_summary
  [2] ignores a newer cluster-only (half-built) run with no run_summary —
      returns the previous complete run
  [3] no run_summary at all → None (don't anchor on a half-built run)

Offline; stub ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_latest_run_sentinel.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.explain import _latest_run_id

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _StubES:
    """Serves `doc_type=run_summary` and `doc_type=cluster` searches from two
    separate stores, and records which doc_type each query asked for."""

    def __init__(self, run_summary_runs, cluster_runs):
        # newest-first lists of run_ids
        self._by_doctype = {"run_summary": run_summary_runs, "cluster": cluster_runs}
        self.asked: list[str] = []

    def search(self, *, index, size, query, sort=None, _source=None):
        dt = (query.get("term") or {}).get("doc_type")
        self.asked.append(dt)
        runs = self._by_doctype.get(dt, [])
        hits = [{"_source": {"run_id": runs[0]}}] if runs else []
        return {"hits": {"hits": hits}}


# -----------------------------------------------------------------------------
# [1] resolves the newest run_summary's run.
# -----------------------------------------------------------------------------
print("\n[1] _latest_run_id resolves via the run_summary sentinel")
es = _StubES(run_summary_runs=["run-complete"], cluster_runs=["run-complete"])
rid = _latest_run_id(es, "clusters-idx")
check("queried doc_type=run_summary (not cluster)", es.asked == ["run_summary"], str(es.asked))
check("returned the run_summary run", rid == "run-complete", str(rid))


# -----------------------------------------------------------------------------
# [2] a newer cluster-only run (no run_summary) is IGNORED — fall back to the
#     last complete run.
# -----------------------------------------------------------------------------
print("\n[2] half-built run (cluster docs, no run_summary) is ignored")
# run_summary store still points at the older complete run; cluster store has a
# newer half-built run that must NOT be picked.
es2 = _StubES(run_summary_runs=["run-OLD-complete"], cluster_runs=["run-NEW-halfbuilt"])
rid2 = _latest_run_id(es2, "clusters-idx")
check("returns the previous COMPLETE run, not the half-built one",
      rid2 == "run-OLD-complete", str(rid2))


# -----------------------------------------------------------------------------
# [3] no run_summary at all → None (never anchor on a half-built run).
# -----------------------------------------------------------------------------
print("\n[3] no run_summary → None")
es3 = _StubES(run_summary_runs=[], cluster_runs=["run-NEW-halfbuilt"])
check("None despite a cluster-only run present", _latest_run_id(es3, "clusters-idx") is None)


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
