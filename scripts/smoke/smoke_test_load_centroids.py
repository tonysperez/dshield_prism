"""Regression guard for ROADMAP #18 + ROADMAP P1 + scale-hardening P3.1.

P3.1: `load_centroids`' cluster fallback resolves the latest run via the
`doc_type=run_summary` completion sentinel (written LAST, P3.3) — so a
half-built run is never read — then loads that run's centroids filtered on
`doc_type=cluster` + `run_id`. (This supersedes the original #18 framing where
*both* searches filtered `doc_type=cluster`; the #18 intent — never mix
cluster and run_summary docs — is preserved by the explicit per-search
doc_type filters.)

P1: `load_centroids` must prefer the `doc_type=reference_centroid` set when
present (highest `reference_generation`). Only when no reference exists does
it fall back to the run_summary-resolved latest run.

Standalone — no real ES, no pytest.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_load_centroids.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.clustering import load_centroids


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _StubIndicesClient:
    def __init__(self, *, exists: bool = True) -> None:
        self.exists_val = exists
        self.exists_calls: list[str] = []

    def exists(self, *, index: str) -> bool:
        self.exists_calls.append(index)
        return self.exists_val


def _query_targets_doctype(query: dict, doc_type_value: str) -> bool:
    """Walk a query dict looking for `{"term": {"doc_type": <value>}}`."""
    if isinstance(query, dict):
        if query.get("term", {}).get("doc_type") == doc_type_value:
            return True
        for v in query.values():
            if _query_targets_doctype(v, doc_type_value):
                return True
    if isinstance(query, list):
        for v in query:
            if _query_targets_doctype(v, doc_type_value):
                return True
    return False


class _StubES:
    """Records every search body. Routes by `doc_type` in the query:
    `reference_centroid` → `ref_*_hits` (gen lookup, then fetch); `run_summary`
    → `run_summary_hits` (P3.1 latest-run resolution); `cluster` →
    `cluster_hits` (the per-run centroid fetch).

    `cluster_first_hits` is accepted as a back-compat alias for
    `run_summary_hits` (the run-id resolution) and `cluster_second_hits` for
    `cluster_hits` (the centroid fetch), so older call sites keep working.
    """

    def __init__(
        self,
        *,
        ref_first_hits: list[dict] | None = None,
        ref_second_hits: list[dict] | None = None,
        run_summary_hits: list[dict] | None = None,
        cluster_hits: list[dict] | None = None,
        cluster_first_hits: list[dict] | None = None,
        cluster_second_hits: list[dict] | None = None,
        exists: bool = True,
    ) -> None:
        self.indices = _StubIndicesClient(exists=exists)
        self.ref_first_hits = ref_first_hits or []
        self.ref_second_hits = ref_second_hits or []
        # run-id resolution now comes from the run_summary sentinel (P3.1).
        self.run_summary_hits = run_summary_hits or cluster_first_hits or []
        self.cluster_hits = cluster_hits or cluster_second_hits or []
        self.calls: list[dict] = []
        self._ref_n = 0

    def search(self, **kwargs):
        self.calls.append(kwargs)
        q = kwargs.get("query") or {}
        if _query_targets_doctype(q, "reference_centroid"):
            self._ref_n += 1
            return {"hits": {"hits": self.ref_first_hits if self._ref_n == 1 else self.ref_second_hits}}
        if _query_targets_doctype(q, "run_summary"):
            return {"hits": {"hits": self.run_summary_hits}}
        if _query_targets_doctype(q, "cluster"):
            return {"hits": {"hits": self.cluster_hits}}
        return {"hits": {"hits": []}}

    def run_summary_calls(self) -> list[dict]:
        return [c for c in self.calls if _query_targets_doctype(c.get("query") or {}, "run_summary")]

    def cluster_calls(self) -> list[dict]:
        return [c for c in self.calls if _query_targets_doctype(c.get("query") or {}, "cluster")]

    def ref_calls(self) -> list[dict]:
        return [c for c in self.calls if _query_targets_doctype(c.get("query") or {}, "reference_centroid")]


# -----------------------------------------------------------------------------
# [1] Both CLUSTER searches carry the doc_type=cluster filter (#18 guard).
# Reference is absent (no ref docs) so load_centroids falls back to cluster.
# -----------------------------------------------------------------------------
print("\n[1] no reference -> resolve run via run_summary sentinel, fetch centroids via cluster")
es = _StubES(
    ref_first_hits=[],  # no reference docs
    run_summary_hits=[{"_source": {"run_id": "run-xyz"}}],
    cluster_hits=[
        {"_source": {"centroid": [1.0, 0.0, 0.0]}},
        {"_source": {"centroid": [0.0, 1.0, 0.0]}},
    ],
)
out = load_centroids(es, "clusters-test")

check(
    "function returned the 2 cluster centroids",
    out == [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]],
    f"got {out}",
)
check(
    "run resolved via exactly 1 run_summary search (P3.1)",
    len(es.run_summary_calls()) == 1,
    f"got {len(es.run_summary_calls())} run_summary searches",
)
check(
    "centroids fetched via exactly 1 cluster-doctype search",
    len(es.cluster_calls()) == 1,
    f"got {len(es.cluster_calls())} cluster searches",
)
_cluster_q = es.cluster_calls()[0].get("query") or {}
check(
    "the centroid fetch is scoped to doc_type=cluster + the resolved run_id",
    _query_targets_doctype(_cluster_q, "cluster") and "run-xyz" in json.dumps(_cluster_q),
    f"cluster query: {json.dumps(_cluster_q)}",
)


# -----------------------------------------------------------------------------
# [2] The run-resolution (run_summary) search uses @timestamp desc sort.
# -----------------------------------------------------------------------------
print("\n[2] the run_summary resolution search sorts by @timestamp desc")
first_sort = es.run_summary_calls()[0].get("sort")
check(
    "run_summary search sorts by @timestamp desc",
    first_sort == [{"@timestamp": "desc"}],
    f"got sort={first_sort}",
)


# -----------------------------------------------------------------------------
# [3] Non-existent index → [] without throwing, no searches at all.
# -----------------------------------------------------------------------------
print("\n[3] non-existent cluster index returns [] cleanly")
es_nx = _StubES(exists=False)
out = load_centroids(es_nx, "clusters-missing")
check("missing index → []", out == [], f"got {out}")
check(
    "no search issued when index missing",
    es_nx.calls == [],
    f"got {len(es_nx.calls)} unexpected searches",
)


# -----------------------------------------------------------------------------
# [4] Empty cluster index (no cluster docs, no ref docs) → [] cleanly.
# -----------------------------------------------------------------------------
print("\n[4] empty cluster index returns [] cleanly")
es_empty = _StubES()
out = load_centroids(es_empty, "clusters-empty")
check("empty index → []", out == [], f"got {out}")


# -----------------------------------------------------------------------------
# [5] First cluster hit without run_id → [] cleanly.
# -----------------------------------------------------------------------------
print("\n[5] first cluster hit without run_id returns [] cleanly")
es_no_run = _StubES(
    cluster_first_hits=[{"_source": {"something_else": True}}],
    cluster_second_hits=[],
)
out = load_centroids(es_no_run, "clusters-norunid")
check("missing run_id → []", out == [], f"got {out}")


# -----------------------------------------------------------------------------
# [6] Centroid-less hits filtered out of cluster fallback path.
# -----------------------------------------------------------------------------
print("\n[6] cluster-fallback hits without centroid are filtered out")
es_mixed = _StubES(
    cluster_first_hits=[{"_source": {"run_id": "run-xyz"}}],
    cluster_second_hits=[
        {"_source": {"centroid": [1.0, 0.0, 0.0]}},
        {"_source": {}},
        {"_source": {"centroid": [0.0, 1.0, 0.0]}},
    ],
)
out = load_centroids(es_mixed, "clusters-mixed")
check(
    "centroid-less hits dropped",
    out == [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]],
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [7] ES exception → [] (defensive).
# -----------------------------------------------------------------------------
print("\n[7] ES exception → [] (defensive)")
class _BoomES:
    indices = _StubIndicesClient(exists=True)
    def search(self, **kwargs):
        raise RuntimeError("boom")
out = load_centroids(_BoomES(), "clusters-boom")
check("ES exception → []", out == [], f"got {out}")


# -----------------------------------------------------------------------------
# [8] ROADMAP P1: reference centroids present -> returned without touching the
# cluster doc_type path. Verifies preference order.
# -----------------------------------------------------------------------------
print("\n[8] reference_centroid set present is preferred over cluster docs")
es_ref = _StubES(
    ref_first_hits=[{"_source": {"reference_generation": 3}}],
    ref_second_hits=[
        {"_source": {
            "centroid": [0.1, 0.2, 0.3],
            "reference_minted_at": "2026-01-01T00:00:00+00:00",
            "embedding_dims": 3,
        }},
        {"_source": {
            "centroid": [0.4, 0.5, 0.6],
            "reference_minted_at": "2026-01-01T00:00:00+00:00",
            "embedding_dims": 3,
        }},
    ],
    # Cluster-fallback responses are set but should never be consumed.
    cluster_first_hits=[{"_source": {"run_id": "ignored-run"}}],
    cluster_second_hits=[{"_source": {"centroid": [9.9, 9.9, 9.9]}}],
)
out = load_centroids(es_ref, "clusters-with-ref")
check(
    "returned reference centroids, not cluster fallback",
    out == [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]],
    f"got {out}",
)
check(
    "no cluster-doctype searches issued when reference is present",
    es_ref.cluster_calls() == [],
    f"got {len(es_ref.cluster_calls())} unexpected cluster searches",
)
check(
    "2 reference-doctype searches issued (gen lookup + fetch)",
    len(es_ref.ref_calls()) == 2,
    f"got {len(es_ref.ref_calls())} reference searches",
)


# -----------------------------------------------------------------------------
# [9] ROADMAP P1: reference gen lookup that returns a hit lacking
# `reference_generation` falls through to cluster path (defensive).
# -----------------------------------------------------------------------------
print("\n[9] reference hit without generation falls back to cluster path")
es_bad_ref = _StubES(
    ref_first_hits=[{"_source": {}}],
    cluster_first_hits=[{"_source": {"run_id": "fallback-run"}}],
    cluster_second_hits=[{"_source": {"centroid": [7.0, 7.0]}}],
)
out = load_centroids(es_bad_ref, "clusters-bad-ref")
check(
    "fell back to cluster centroids",
    out == [[7.0, 7.0]],
    f"got {out}",
)


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
