"""Cluster-run prune — dead per-run centroid garbage collection (P2.1).

Each cluster run appends a fresh `cluster` centroid set + a `run_summary`
doc and never prunes; only the latest run is ever read, so the cluster
indices accumulate dead state forever. `prune_cluster_runs` keeps the
newest `keep_runs` runs and deletes the rest — but must NEVER touch
`reference_centroid` docs (the cross-run novelty anchors).

Scenarios:
  [1] keeps newest K run_ids; delete query targets only cluster/run_summary
      and excludes those run_ids — reference_centroid structurally out of scope
  [2] missing index → skip (no search, no delete)
  [3] no run_summary docs → skip (can't tell newest → never a blind delete)
  [4] dry-run → counts, never deletes
  [5] _select_keep_run_ids ranks by @timestamp desc, dedups, floors keep at 1

Stubs ES so the test is offline (same pattern as smoke_test_findings_tombstone).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_prune_cluster_runs.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.clustering import _select_keep_run_ids, prune_cluster_runs

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
    def __init__(self, exists: bool):
        self._exists = exists
    def exists(self, *, index):
        return self._exists


class _StubES:
    """Records search / delete_by_query / count so we can introspect what
    the prune would do. `run_summary_ids` is the newest-first run_id list
    ES would return for the size=keep_runs, sort=@timestamp-desc query."""
    def __init__(self, *, exists=True, run_summary_ids=None, deleted=0, count=0):
        self.indices = _StubIndices(exists)
        self._ids = list(run_summary_ids or [])
        self._deleted = deleted
        self._count = count
        self.searches: list[dict] = []
        self.deletes: list[dict] = []
        self.counts: list[dict] = []

    def search(self, *, index, size=10, query=None, sort=None, _source=None):
        self.searches.append({"index": index, "size": size, "query": query})
        hits = [{"_source": {"run_id": rid}} for rid in self._ids[:size]]
        return {"hits": {"hits": hits}}

    def delete_by_query(self, *, index, body, conflicts="proceed", refresh=False):
        self.deletes.append({"index": index, "body": body})
        return {"deleted": self._deleted}

    def count(self, *, index, query=None):
        self.counts.append({"index": index, "query": query})
        return {"count": self._count}


# -----------------------------------------------------------------------------
# [1] keep newest K; delete query correct + reference_centroid never targeted.
# -----------------------------------------------------------------------------
print("\n[1] keeps newest run_ids; delete excludes them and spares reference_centroid")
es = _StubES(run_summary_ids=["run-new", "run-mid", "run-old"], deleted=42)
res = prune_cluster_runs(es, "prism.cluster.cowrie.ip", keep_runs=2, layer_label="ip")
check("status ok", res.get("status") == "ok", f"got {res}")
check("reported deleted count", res.get("deleted") == 42, f"got {res}")
check("one delete_by_query issued", len(es.deletes) == 1, f"got {len(es.deletes)}")
q = es.deletes[0]["body"]["query"]["bool"]
doc_types = set(q["must"][0]["terms"]["doc_type"])
check("delete targets only cluster + run_summary",
      doc_types == {"cluster", "run_summary"}, f"got {doc_types}")
check("reference_centroid is NOT in the delete scope",
      "reference_centroid" not in doc_types)
kept = set(q["must_not"][0]["terms"]["run_id"])
# size=2 honored by the stub → newest two run_ids retained.
check("must_not keeps exactly the newest --keep-runs run_ids",
      kept == {"run-new", "run-mid"}, f"got {kept}")
check("the old run is therefore deletable (not in keep set)",
      "run-old" not in kept)


# -----------------------------------------------------------------------------
# [2] missing index → skip entirely.
# -----------------------------------------------------------------------------
print("\n[2] missing index → skip (no search, no delete)")
es = _StubES(exists=False)
res = prune_cluster_runs(es, "prism.cluster.cowrie.session", keep_runs=5, layer_label="session")
check("status missing", res.get("status") == "missing", f"got {res}")
check("no search issued", es.searches == [])
check("no delete issued", es.deletes == [])


# -----------------------------------------------------------------------------
# [3] no run_summary docs → safety skip (never a blind delete).
# -----------------------------------------------------------------------------
print("\n[3] no run_summary docs → skip, no delete")
es = _StubES(run_summary_ids=[], deleted=999)
res = prune_cluster_runs(es, "prism.cluster.cowrie.command", keep_runs=5, layer_label="command")
check("status no_run_summaries", res.get("status") == "no_run_summaries", f"got {res}")
check("searched for run_summary but issued no delete", es.searches and es.deletes == [])


# -----------------------------------------------------------------------------
# [4] dry-run → counts, never deletes.
# -----------------------------------------------------------------------------
print("\n[4] dry-run counts but never deletes")
es = _StubES(run_summary_ids=["a", "b", "c"], count=17, deleted=17)
res = prune_cluster_runs(es, "prism.cluster.cowrie.ip", keep_runs=1, dry_run=True, layer_label="ip")
check("status dry_run", res.get("status") == "dry_run", f"got {res}")
check("would_delete from count()", res.get("would_delete") == 17, f"got {res}")
check("count() called once", len(es.counts) == 1)
check("no delete_by_query issued in dry-run", es.deletes == [])


# -----------------------------------------------------------------------------
# [5] _select_keep_run_ids: newest by @timestamp, dedup, keep floor.
# -----------------------------------------------------------------------------
print("\n[5] _select_keep_run_ids ranks by @timestamp desc, dedups, floors at 1")
summaries = [
    {"run_id": "r1", "@timestamp": "2026-06-01T00:00:00Z"},
    {"run_id": "r2", "@timestamp": "2026-06-03T00:00:00Z"},
    {"run_id": "r3", "@timestamp": "2026-06-02T00:00:00Z"},
    {"run_id": "r2", "@timestamp": "2026-06-03T00:00:00Z"},  # dup id
    {"@timestamp": "2026-06-09T00:00:00Z"},                  # no run_id → ignored
]
keep = _select_keep_run_ids(summaries, 2)
check("newest two distinct runs, newest first", keep == ["r2", "r3"], f"got {keep}")
check("keep_runs<1 is floored to 1",
      _select_keep_run_ids(summaries, 0) == ["r2"], f"got {_select_keep_run_ids(summaries, 0)}")
check("docs without run_id are skipped",
      "" not in keep and None not in keep)


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
