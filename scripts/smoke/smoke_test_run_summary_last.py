"""run_summary written LAST as the completion sentinel (scale-hardening P3.3).

The clustering writer used to emit the `run_summary` doc in the SAME bulk as the
centroids, *before* the per-doc `cluster.id` patches. A crash between the two
left a `run_summary` implying a run that was only partially applied, and any
reader resolving "latest run" off it would aggregate half-written membership.

The fix: write order is (1) centroids/reference_centroids → (2) per-doc patches
→ (3) `run_summary` LAST, stamped with the actual write-error counts. Readers
that gate on the run_summary sentinel (lifecycle, prune, miner) therefore fall
back to the previous complete run instead of a half-applied one.

Scenarios:
  [1] writer ordering — run_summary is the LAST captured write, after the
      per-doc updates, and on the clusters index; it carries
      cluster_doc_errors / update_errors / write_errors / runtime_seconds.
  [2] write-error surfacing — when the per-doc update bulk reports errors, the
      run_summary still gets written and its update_errors / write_errors
      reflect them (a clean run reports 0).
  [3] reader gating — lifecycle `_latest_cluster_run` resolves "latest run" via
      the run_summary sentinel and returns (None, 0) when none exists, so
      `_iter_current_playbooks` yields nothing for a run with no sentinel.

Offline; uses the cluster extras (numpy + hdbscan), like the sibling
clustering smokes.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_run_summary_last.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np

from enrich import clustering
from enrich.findings import lifecycle as lc

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
# Harness: two tight clusters of 3 docs each (dim 4); capture every bulk write
# in call order; route searches to "no reference docs present".
# -----------------------------------------------------------------------------
EMB_DIM = 4
DIR_A = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
DIR_B = np.array([0.0, 1.0, 0.0, 0.0], dtype=np.float32)


def _make_doc_iter():
    rng = np.random.default_rng(seed=7)
    docs = []
    for i in range(3):
        docs.append((f"a{i}", (DIR_A + rng.normal(0, 0.01, EMB_DIM)).astype(np.float32).tolist(), f"la{i}", {"f": 0.5}))
    for i in range(3):
        docs.append((f"b{i}", (DIR_B + rng.normal(0, 0.01, EMB_DIM)).astype(np.float32).tolist(), f"lb{i}", {"f": 0.5}))
    return iter(docs)


def _zero_scalar_block(scalars_list, weight):
    return np.zeros((len(scalars_list), 0), dtype=np.float32)


class _Indices:
    def exists(self, *, index): return True
    def refresh(self, *, index): return {}


class _StubES:
    def __init__(self): self.indices = _Indices()
    def search(self, **kwargs): return {"hits": {"hits": []}}  # no reference docs


CAPTURED: list[tuple[str, list[dict]]] = []
ERR_INDEX: str | None = None  # when set, bulk writes to this index report 1 error


def _stub_bulk_write(es, index, actions):
    acts = list(actions)
    CAPTURED.append((index, acts))
    if ERR_INDEX is not None and index == ERR_INDEX and acts:
        return len(acts) - 1, [{"index": {"error": "simulated"}}]
    return len(acts), []


clustering.bulk_write = _stub_bulk_write
clustering.init_index = lambda es, mapping_path, index_name: {"stub": True}

DOCS_IDX = "docs-test"
CLUSTERS_IDX = "clusters-test"


def _run():
    CAPTURED.clear()
    return clustering.run_layer_clustering(
        es=_StubES(), docs_iter=_make_doc_iter(),
        docs_index=DOCS_IDX, clusters_index=CLUSTERS_IDX,
        mapping_path="/dev/null",
        update_script="ctx._source.x = params.novelty_score",
        scalar_block_builder=_zero_scalar_block,
        min_cluster_size=3, min_samples=2, scalar_weight=0.0,
        batch_size=100, sample_size=5, centroid_sample_field="sample_x",
        dry_run=False, layer_label="test.layer", use_reference=False,
        window_days=30,
    )


def _summary_call_index():
    """(call_idx, source) of the run_summary write, or (None, None)."""
    for i, (idx, acts) in enumerate(CAPTURED):
        for a in acts:
            if (a.get("_source") or {}).get("doc_type") == "run_summary":
                return i, a["_source"]
    return None, None


def _last_update_call_index():
    """Highest call_idx that wrote per-doc `update` ops to the docs index."""
    last = -1
    for i, (idx, acts) in enumerate(CAPTURED):
        if idx == DOCS_IDX and any(a.get("_op_type") == "update" for a in acts):
            last = i
    return last


# -----------------------------------------------------------------------------
# [1] ordering — run_summary is the last write, after the per-doc updates.
# -----------------------------------------------------------------------------
print("\n[1] run_summary is written LAST, after the per-doc updates")
stats = _run()
s_idx, s_src = _summary_call_index()
u_idx = _last_update_call_index()
check("a run_summary was written", s_idx is not None)
check("per-doc updates were written", u_idx >= 0)
check("run_summary write comes AFTER the per-doc updates",
      s_idx is not None and u_idx >= 0 and s_idx > u_idx, f"summary@{s_idx} updates@{u_idx}")
check("run_summary is the LAST captured write",
      s_idx == len(CAPTURED) - 1, f"summary@{s_idx} of {len(CAPTURED)}")
check("run_summary written to the clusters index",
      s_idx is not None and CAPTURED[s_idx][0] == CLUSTERS_IDX, CAPTURED[s_idx][0] if s_idx is not None else "-")
check("run_summary carries window_days (30)", (s_src or {}).get("window_days") == 30, str((s_src or {}).get("window_days")))
check("run_summary carries write-error fields + runtime",
      all(k in (s_src or {}) for k in ("cluster_doc_errors", "update_errors", "write_errors", "runtime_seconds")),
      str(sorted((s_src or {}).keys())))
check("clean run → write_errors == 0", (s_src or {}).get("write_errors") == 0, str((s_src or {}).get("write_errors")))
check("stats expose run_summary_written", stats.get("run_summary_written") == 1, str(stats.get("run_summary_written")))


# -----------------------------------------------------------------------------
# [2] error surfacing — per-doc update failures land on the run_summary.
# -----------------------------------------------------------------------------
print("\n[2] per-doc update errors are surfaced on the run_summary")
ERR_INDEX = DOCS_IDX
try:
    _run()
finally:
    ERR_INDEX = None
_, s_src2 = _summary_call_index()
check("run_summary still written despite update errors", s_src2 is not None)
check("update_errors > 0", (s_src2 or {}).get("update_errors", 0) > 0, str((s_src2 or {}).get("update_errors")))
check("write_errors >= update_errors", (s_src2 or {}).get("write_errors", 0) >= (s_src2 or {}).get("update_errors", 0))


# -----------------------------------------------------------------------------
# [3] reader gating — latest run resolved via the run_summary sentinel.
# -----------------------------------------------------------------------------
print("\n[3] lifecycle resolves 'latest run' via the run_summary sentinel")


class _SentinelES:
    """Returns one run_summary hit (or none) and records the resolution query."""

    def __init__(self, summary):  # summary: dict | None
        self._summary = summary
        self.queried_doctypes: list[str] = []
        self.indices = type("_I", (), {"exists": staticmethod(lambda index: True)})()

    def search(self, **kwargs):
        dt = (kwargs.get("query") or {}).get("term", {}).get("doc_type")
        self.queried_doctypes.append(dt)
        if dt == "run_summary" and self._summary is not None:
            return {"hits": {"hits": [{"_source": self._summary}]}}
        return {"hits": {"hits": []}}


es_ok = _SentinelES({"run_id": "run-prev", "window_days": 0})
rid, wd = lc._latest_cluster_run(es_ok, "ix")
check("_latest_cluster_run resolves via run_summary doc_type",
      es_ok.queried_doctypes == ["run_summary"], str(es_ok.queried_doctypes))
check("returns (run_id, window_days) from the sentinel", (rid, wd) == ("run-prev", 0), f"{(rid, wd)}")

es_none = _SentinelES(None)
check("no run_summary → (None, 0) (fall back, don't read a half-run)",
      lc._latest_cluster_run(es_none, "ix") == (None, 0))
# _iter_current_playbooks must yield nothing when there's no sentinel, even
# though a crashed run could have left cluster docs behind.
check("_iter_current_playbooks yields nothing without a run_summary",
      list(lc._iter_current_playbooks(_SentinelES(None), "cix", "six")) == [])


# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
