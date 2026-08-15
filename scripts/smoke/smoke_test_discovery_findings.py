"""Findings v2 step 3 — stream B (discovery) miner correctness.

Covers the four discovery kinds that shipped in step 3:
  - mine_new_playbook
  - mine_intel_verdict_flip
  - mine_ip_behavior_shift
  - mine_unattributed_active_ip

Plus:
  - _jensen_shannon math sanity
  - _is_meaningful_flip transition classification
  - stream_for_kind console-side routing helper

Stubs the ES + lifecycle-doc inputs so the test is offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_discovery_findings.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "console" / "src"))

from datetime import UTC, datetime, timedelta

from console.findings import _DISCOVERY_KINDS, _DRIFT_KINDS, stream_for_kind

from enrich.findings.discovery import (
    DISCOVERY_MINERS,
    _is_meaningful_flip,
    _jensen_shannon,
    mine_campaign_convergence,
    mine_intel_verdict_flip,
    mine_ip_behavior_shift,
    mine_new_playbook,
    mine_outlier_burst,
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


class _StubIndices:
    def exists(self, *, index: str) -> bool:
        return True


class _StubES:
    """Returns the seeded lifecycle docs in pages, via a scroll-style search."""

    def __init__(self, *, docs: list[dict]):
        self.indices = _StubIndices()
        self.docs = docs
        self._delivered = False

    def search(self, **kwargs):
        if self._delivered:
            return {"hits": {"hits": []}}
        self._delivered = True
        # Apply query.term / range filter if present (only what miners use).
        query = kwargs.get("query") or {}
        docs = list(self.docs)
        if "term" in query:
            term = query["term"]
            field, val = next(iter(term.items()))
            docs = [d for d in docs if d.get(field) == val]
        if "range" in query:
            rng = query["range"]
            field, conds = next(iter(rng.items()))
            if "gte" in conds:
                docs = [d for d in docs if int(d.get(field, 0)) >= conds["gte"]]
        hits = [{"_source": d, "sort": [i]} for i, d in enumerate(docs)]
        return {"hits": {"hits": hits}}


class _Cfg:
    class findings:
        class indexes:
            default = "prism.finding"
            playbook_lifecycle = "lc-pb"
            campaign_lifecycle = "lc-cmp"
            source_ip_lifecycle = "lc-ip"

        class discovery:
            intel_flip_recent_session_days = 7
            ip_shift_js_distance_min = 0.3
            ip_shift_min_sessions = 5
            unattributed_min_sessions = 5
            outlier_burst_window_hours = 24
            outlier_burst_min_sessions = 5
            convergence_min_ip_overlap_ratio = 0.4

    class elasticsearch:
        class indexes:
            class cowrie:
                sessions_rollup = "rollup-sess"
                campaigns = "camp"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _ago(days: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


# -----------------------------------------------------------------------------
# [1] mine_new_playbook — runs_observed == 1 triggers exactly once.
# -----------------------------------------------------------------------------
print("\n[1] new_playbook fires once on first observation")
docs = [
    {"playbook_id": "sescl-fresh",  "playbook_name": "Fresh Dropper", "runs_observed": 1,
     "first_seen_ever": _now(),
     "snapshots": [{"session_count": 3, "ip_count": 2}]},
    {"playbook_id": "sescl-known",  "playbook_name": "Known", "runs_observed": 12,
     "first_seen_ever": _ago(30),
     "snapshots": [{"session_count": 50, "ip_count": 12}]},
]
findings = mine_new_playbook(_StubES(docs=docs), _Cfg, run_id="run-1")
check("1 finding emitted", len(findings) == 1, f"got {len(findings)}")
check("artifact.value is the fresh playbook id",
      findings[0]["artifact"] == {"kind": "playbook", "value": "sescl-fresh"})
check("kind == new_playbook", findings[0]["kind"] == "new_playbook")
check("narrative names the playbook", "Fresh Dropper" in findings[0]["narrative"])


# -----------------------------------------------------------------------------
# [2] _is_meaningful_flip — transition classification.
# -----------------------------------------------------------------------------
print("\n[2] verdict-flip transition classifier")
check("clean → malicious fires",      _is_meaningful_flip("clean", "malicious") is True)
check("malicious → clean fires",      _is_meaningful_flip("malicious", "clean") is True)
check("no_data → malicious fires",    _is_meaningful_flip("no_data", "malicious") is True)
check("None → malicious fires",       _is_meaningful_flip(None, "malicious") is True)
check("same verdict does not fire",   _is_meaningful_flip("malicious", "malicious") is False)
check("anything → no_data does not fire", _is_meaningful_flip("clean", "no_data") is False)
check("None curr does not fire",      _is_meaningful_flip("clean", None) is False)


# -----------------------------------------------------------------------------
# [3] mine_intel_verdict_flip — recent corpus session gate.
# -----------------------------------------------------------------------------
print("\n[3] intel_verdict_flip fires only with a recent session")
docs = [
    {"source_ip": "1.1.1.1", "runs_observed": 3, "last_seen": _ago(1),
     "snapshots": [
         {"intel_verdict": "no_data",   "intel_consensus_score": 0.0},
         {"intel_verdict": "clean",     "intel_consensus_score": 0.0},
         {"intel_verdict": "malicious", "intel_consensus_score": 0.85,
          "asn": 12345, "geo_country": "RU"},
     ]},
    # IP last seen long ago — gate filters out
    {"source_ip": "2.2.2.2", "runs_observed": 2, "last_seen": _ago(40),
     "snapshots": [
         {"intel_verdict": "clean"},
         {"intel_verdict": "malicious", "intel_consensus_score": 0.9},
     ]},
    # IP with same verdict on both snapshots — no flip
    {"source_ip": "3.3.3.3", "runs_observed": 2, "last_seen": _ago(1),
     "snapshots": [{"intel_verdict": "clean"}, {"intel_verdict": "clean"}]},
]
findings = mine_intel_verdict_flip(_StubES(docs=docs), _Cfg, run_id="run-1")
ips_fired = [f["artifact"]["value"] for f in findings]
check("only the recent + flipped IP fires", ips_fired == ["1.1.1.1"], f"got {ips_fired}")
check("evidence carries prev + curr verdict",
      findings[0]["evidence"]["verdict_prev"] == "clean"
      and findings[0]["evidence"]["verdict_curr"] == "malicious")
check("evidence carries asn / country",
      findings[0]["evidence"]["asn"] == 12345
      and findings[0]["evidence"]["geo_country"] == "RU")


# -----------------------------------------------------------------------------
# [4] _jensen_shannon math sanity.
# -----------------------------------------------------------------------------
print("\n[4] jensen-shannon distance")
check("identical distributions → 0",
      abs(_jensen_shannon({"a": 1.0}, {"a": 1.0})) < 1e-6)
check("disjoint distributions → 1",
      abs(_jensen_shannon({"a": 1.0}, {"b": 1.0}) - 1.0) < 1e-6)
check("empty + empty → 0",
      _jensen_shannon({}, {}) == 0.0)
check("one empty → 1",
      _jensen_shannon({"a": 1.0}, {}) == 1.0)
# Mid-range: 50/50 vs 100/0 should be intermediate
mid = _jensen_shannon({"a": 1.0, "b": 1.0}, {"a": 1.0})
check("partial overlap → 0 < d < 1", 0.0 < mid < 1.0, f"got {mid}")


# -----------------------------------------------------------------------------
# [5] mine_ip_behavior_shift — modal flip + JS distance gates.
# -----------------------------------------------------------------------------
print("\n[5] ip_behavior_shift fires on modal flip or JS distance")
docs = [
    # Modal flip: was sescl-A, now sescl-B
    {"source_ip": "10.0.0.1", "runs_observed": 3,
     "snapshots": [
         {"session_count": 6, "dominant_playbook_id": "sescl-A",
          "playbook_distribution": {"sescl-A": 5, "sescl-B": 1}},
         {"session_count": 6, "dominant_playbook_id": "sescl-A",
          "playbook_distribution": {"sescl-A": 5, "sescl-B": 1}},
         {"session_count": 6, "dominant_playbook_id": "sescl-B",
          "playbook_distribution": {"sescl-A": 1, "sescl-B": 5}},
     ]},
    # Stable IP — same modal across history. Should NOT fire.
    {"source_ip": "10.0.0.2", "runs_observed": 3,
     "snapshots": [
         {"session_count": 6, "dominant_playbook_id": "sescl-X",
          "playbook_distribution": {"sescl-X": 6}},
         {"session_count": 6, "dominant_playbook_id": "sescl-X",
          "playbook_distribution": {"sescl-X": 6}},
         {"session_count": 6, "dominant_playbook_id": "sescl-X",
          "playbook_distribution": {"sescl-X": 6}},
     ]},
    # Modal flip BUT session_count < threshold — should NOT fire.
    {"source_ip": "10.0.0.3", "runs_observed": 2,
     "snapshots": [
         {"session_count": 4, "dominant_playbook_id": "sescl-A",
          "playbook_distribution": {"sescl-A": 4}},
         {"session_count": 3, "dominant_playbook_id": "sescl-B",
          "playbook_distribution": {"sescl-B": 3}},
     ]},
]
findings = mine_ip_behavior_shift(_StubES(docs=docs), _Cfg, run_id="run-1")
ips = sorted([f["artifact"]["value"] for f in findings])
check("only the flipped + active IP fires", ips == ["10.0.0.1"], f"got {ips}")
ev = findings[0]["evidence"]
check("modal_flip evidence True", ev["modal_flip"] is True)
check("modal_prev=A, modal_curr=B",
      ev["modal_prev"] == "sescl-A" and ev["modal_curr"] == "sescl-B")
check("snapshots_compared == 3", ev["snapshots_compared"] == 3)


# -----------------------------------------------------------------------------
# [6] unattributed_active_ip retired — DISCOVERY_MINERS does not include it.
# -----------------------------------------------------------------------------
print("\n[6] unattributed_active_ip kind retired from active miners")
check("'unattributed_active_ip' not in DISCOVERY_MINERS",
      "unattributed_active_ip" not in DISCOVERY_MINERS,
      f"got: {sorted(DISCOVERY_MINERS.keys())}")
check("6 active discovery miners",  # post-P1b
      len(DISCOVERY_MINERS) == 6, f"got {len(DISCOVERY_MINERS)}")


# -----------------------------------------------------------------------------
# [7a] mine_outlier_burst — shared-artifact bucket gates on min_sessions.
# -----------------------------------------------------------------------------
print("\n[7a] outlier_burst — shared-artifact bucket")


class _ESAgg:
    """One-shot ES stub for a single search returning a canned aggregation."""

    def __init__(self, *, aggregations, exists=True):
        self.aggregations = aggregations
        self._exists = exists
    class _Idx:
        def __init__(self, ok): self.ok = ok
        def exists(self, *, index): return self.ok

    @property
    def indices(self): return _ESAgg._Idx(self._exists)
    def search(self, **kw):
        return {"hits": {"hits": []}, "aggregations": self.aggregations}


outlier_aggs = {"by_artifact": {"buckets": [
    {"key": "url:hxxp://drop/",  "doc_count": 8,
     "unique_ips": {"value": 5},
     "sample": {"hits": {"hits": [
         {"_source": {"source": {"ip": "1.1.1.1"}, "cowrie": {"session_id": "s1"}}},
         {"_source": {"source": {"ip": "2.2.2.2"}, "cowrie": {"session_id": "s2"}}},
     ]}}},
    {"key": "hash:deadbeef",     "doc_count": 5,
     "unique_ips": {"value": 5},
     "sample": {"hits": {"hits": [
         {"_source": {"source": {"ip": "3.3.3.3"}}},
     ]}}},
]}}
findings = mine_outlier_burst(_ESAgg(aggregations=outlier_aggs), _Cfg, run_id="r1")
check("2 outlier_burst findings emitted", len(findings) == 2, f"got {len(findings)}")
check("artifact kind is shared_artifact",
      findings[0]["artifact"]["kind"] == "shared_artifact")
check("shared artifact carried as artifact.value",
      sorted(f["artifact"]["value"] for f in findings) ==
      ["hash:deadbeef", "url:hxxp://drop/"])
check("evidence carries session+ip counts + sample ips",
      findings[0]["evidence"]["session_count"] in (5, 8)
      and findings[0]["evidence"]["ip_count"] == 5
      and len(findings[0]["evidence"]["sample_ips"]) <= 5)

# No outliers above min_sessions → no findings
empty = mine_outlier_burst(_ESAgg(aggregations={"by_artifact": {"buckets": []}}),
                           _Cfg, run_id="r1")
check("no findings when no qualifying buckets", empty == [])

# Missing rollup index → no findings, no error
gone = mine_outlier_burst(_ESAgg(aggregations={}, exists=False), _Cfg, run_id="r1")
check("missing rollup index → []", gone == [])


# -----------------------------------------------------------------------------
# [7c] mine_campaign_convergence — pairwise IP overlap >= threshold.
# -----------------------------------------------------------------------------
print("\n[7c] campaign_convergence — pairwise IP overlap")


class _CampaignES:
    class _Idx:
        def exists(self, *, index): return True
    indices = _Idx()

    def __init__(self, *, docs):
        self.docs = docs
        self._delivered = False

    def search(self, **kw):
        if self._delivered:
            return {"hits": {"hits": []}}
        self._delivered = True
        hits = [{"_source": d, "sort": [i]} for i, d in enumerate(self.docs)]
        return {"hits": {"hits": hits}}


campaigns = [
    {"campaign_id": "cmp-bhv-A", "name": "Drop A", "kind": "behaviour",
     "member_source_ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]},
    {"campaign_id": "cmp-inf-A", "name": "Infra A", "kind": "infrastructure",
     "member_source_ips": ["1.1.1.1", "2.2.2.2", "5.5.5.5"]},
    {"campaign_id": "cmp-inf-B", "name": "Infra B", "kind": "infrastructure",
     "member_source_ips": ["7.7.7.7", "8.8.8.8"]},
]
findings = mine_campaign_convergence(_CampaignES(docs=campaigns), _Cfg, run_id="r1")
# A↔A: |{1.1.1.1, 2.2.2.2}| / min(4,3) = 2/3 = 0.67 → fires (>=0.4)
# A↔B: 0 shared → no fire
check("1 convergence finding (A↔A)", len(findings) == 1, f"got {len(findings)}")
ev = findings[0]["evidence"]
check("overlap_ratio ~ 2/3 (rounded to 4dp)", abs(ev["overlap_ratio"] - 2/3) < 1e-4)
check("shared_ip_count == 2", ev["shared_ip_count"] == 2)
check("artifact pair correct",
      findings[0]["artifact"]["value"] == "cmp-bhv-A+cmp-inf-A")

# No overlap that clears threshold → no findings
weak = [
    {"campaign_id": "cmp-bhv-Z", "name": "Z", "kind": "behaviour",
     "member_source_ips": ["1", "2", "3", "4", "5"]},
    {"campaign_id": "cmp-inf-Z", "name": "Z", "kind": "infrastructure",
     "member_source_ips": ["1", "9", "10"]},  # 1 shared / min(5,3)=3 = 0.33 < 0.4
]
findings = mine_campaign_convergence(_CampaignES(docs=weak), _Cfg, run_id="r1")
check("no findings when ratio below threshold", findings == [])


# -----------------------------------------------------------------------------
# [7] stream_for_kind console routing.
# -----------------------------------------------------------------------------
print("\n[7] stream_for_kind routing across all kinds")
check("'playbook' → coverage", stream_for_kind("playbook") == "coverage")
check("'campaign' → coverage", stream_for_kind("campaign") == "coverage")
check("'new_playbook' → discovery", stream_for_kind("new_playbook") == "discovery")
check("'intel_verdict_flip' → discovery", stream_for_kind("intel_verdict_flip") == "discovery")
check("'ip_behavior_shift' → discovery", stream_for_kind("ip_behavior_shift") == "discovery")
check("'playbook_command_drift' → drift", stream_for_kind("playbook_command_drift") == "drift")
check("'campaign_growth' → drift", stream_for_kind("campaign_growth") == "drift")
check("unknown kind → 'unknown'", stream_for_kind("zzzz") == "unknown")
check("DISCOVERY_KINDS has 8", len(_DISCOVERY_KINDS) == 8)
check("DRIFT_KINDS has 7", len(_DRIFT_KINDS) == 7)


# -----------------------------------------------------------------------------
# [8] _ip_shift_js_cutoff — fallback + n-gate + value-floor + cache.
# -----------------------------------------------------------------------------
print("\n[8] ip_shift_js_cutoff lookup paths")

from enrich.findings.discovery import (
    _CONVERGENCE_CUTOFF_CACHE,
    _CONVERGENCE_CUTOFF_MIN_N,
    _CONVERGENCE_CUTOFF_MIN_VALUE,
    _JS_CUTOFF_CACHE,
    _JS_CUTOFF_MIN_N,
    _JS_CUTOFF_MIN_VALUE,
    _convergence_ratio_cutoff,
    _ip_shift_js_cutoff,
)


class _MetricsIndices:
    def __init__(self, present): self.present = present
    def exists(self, *, index): return self.present


class _MetricsES:
    """Stand-in for the metrics-index lookup only. `doc` is the
    `_source` of the most-recent ip_behavior_shift_js doc, or None to
    simulate no docs.
    """
    def __init__(self, *, present=True, doc=None):
        self.indices = _MetricsIndices(present)
        self.doc = doc
    def search(self, *, index, size, sort, query, _source):
        if self.doc is None:
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [{"_source": {
            k: self.doc[k] for k in _source if k in self.doc
        }}]}}


class _MetricsCfg:
    class metrics:
        class indexes:
            default = "smoke.metrics.idx"


# (a) Missing metrics index -> fallback (None)
_JS_CUTOFF_CACHE.clear()
out = _ip_shift_js_cutoff(_MetricsES(present=False), _MetricsCfg())
check("missing metrics index -> None", out is None, str(out))

# (b) Index present, no doc -> fallback (None)
_JS_CUTOFF_CACHE.clear()
out = _ip_shift_js_cutoff(_MetricsES(present=True, doc=None), _MetricsCfg())
check("no metrics doc -> None", out is None, str(out))

# (c) n below the min-sample gate -> None
_JS_CUTOFF_CACHE.clear()
out = _ip_shift_js_cutoff(
    _MetricsES(present=True, doc={"n": _JS_CUTOFF_MIN_N - 1, "p90": 0.5}),
    _MetricsCfg(),
)
check("n below min-sample gate -> None", out is None, str(out))

# (d) p90 below the min-value floor -> None (bimodal-stable corpus)
_JS_CUTOFF_CACHE.clear()
out = _ip_shift_js_cutoff(
    _MetricsES(present=True, doc={"n": 2046, "p90": 0.0}),
    _MetricsCfg(),
)
check("p90 below floor -> None (bimodal-stable)", out is None, str(out))

_JS_CUTOFF_CACHE.clear()
out = _ip_shift_js_cutoff(
    _MetricsES(present=True, doc={"n": 2046,
                                  "p90": _JS_CUTOFF_MIN_VALUE - 0.0001}),
    _MetricsCfg(),
)
check("p90 just under floor -> None", out is None, str(out))

# (e) Healthy: n above gate AND p90 above floor -> returns the value
_JS_CUTOFF_CACHE.clear()
out = _ip_shift_js_cutoff(
    _MetricsES(present=True, doc={"n": 2046, "p90": 0.42}),
    _MetricsCfg(),
)
check("healthy p90 returned as-is", out == 0.42, str(out))

# (f) Boundary: p90 exactly at the floor -> returned (>= is inclusive)
_JS_CUTOFF_CACHE.clear()
out = _ip_shift_js_cutoff(
    _MetricsES(present=True, doc={"n": _JS_CUTOFF_MIN_N,
                                  "p90": _JS_CUTOFF_MIN_VALUE}),
    _MetricsCfg(),
)
check("p90 == floor -> returned", out == _JS_CUTOFF_MIN_VALUE, str(out))

# (g) Cache stickiness: second call with swapped doc returns cached value.
_JS_CUTOFF_CACHE.clear()
es1 = _MetricsES(present=True, doc={"n": 100, "p90": 0.35})
_ip_shift_js_cutoff(es1, _MetricsCfg())
es2 = _MetricsES(present=True, doc={"n": 100, "p90": 0.99})
out = _ip_shift_js_cutoff(es2, _MetricsCfg())
check("cache returns first call's value within TTL",
      out == 0.35, str(out))


# -----------------------------------------------------------------------------
# [9] _convergence_ratio_cutoff — same gates as 4.3, different percentile.
# -----------------------------------------------------------------------------
print("\n[9] convergence_ratio_cutoff lookup paths")

# (a) Missing metrics index -> None
_CONVERGENCE_CUTOFF_CACHE.clear()
out = _convergence_ratio_cutoff(_MetricsES(present=False), _MetricsCfg())
check("conv: missing metrics index -> None", out is None, str(out))

# (b) No doc -> None
_CONVERGENCE_CUTOFF_CACHE.clear()
out = _convergence_ratio_cutoff(_MetricsES(present=True, doc=None), _MetricsCfg())
check("conv: no metrics doc -> None", out is None, str(out))

# (c) n below sample gate -> None
_CONVERGENCE_CUTOFF_CACHE.clear()
out = _convergence_ratio_cutoff(
    _MetricsES(present=True,
               doc={"n": _CONVERGENCE_CUTOFF_MIN_N - 1, "p75": 0.5}),
    _MetricsCfg(),
)
check("conv: n below sample gate -> None", out is None, str(out))

# (d) p75 below the 0.2 value floor -> None (incidental-overlap noise)
_CONVERGENCE_CUTOFF_CACHE.clear()
out = _convergence_ratio_cutoff(
    _MetricsES(present=True, doc={"n": 50, "p75": 0.15}),
    _MetricsCfg(),
)
check("conv: p75 below floor -> None", out is None, str(out))

# (e) Healthy case -> returns value
_CONVERGENCE_CUTOFF_CACHE.clear()
out = _convergence_ratio_cutoff(
    _MetricsES(present=True, doc={"n": 50, "p75": 0.55}),
    _MetricsCfg(),
)
check("conv: healthy p75 returned as-is", out == 0.55, str(out))

# (f) Boundary: p75 exactly at floor -> returned
_CONVERGENCE_CUTOFF_CACHE.clear()
out = _convergence_ratio_cutoff(
    _MetricsES(present=True,
               doc={"n": _CONVERGENCE_CUTOFF_MIN_N,
                    "p75": _CONVERGENCE_CUTOFF_MIN_VALUE}),
    _MetricsCfg(),
)
check("conv: p75 == floor -> returned",
      out == _CONVERGENCE_CUTOFF_MIN_VALUE, str(out))

# (g) Caches separately from JS cutoff
_CONVERGENCE_CUTOFF_CACHE.clear()
_JS_CUTOFF_CACHE.clear()
es_js = _MetricsES(present=True, doc={"n": 100, "p90": 0.42})
es_conv = _MetricsES(present=True, doc={"n": 100, "p75": 0.55})
v1 = _ip_shift_js_cutoff(es_js, _MetricsCfg())
v2 = _convergence_ratio_cutoff(es_conv, _MetricsCfg())
check("conv + js caches are independent",
      v1 == 0.42 and v2 == 0.55, f"js={v1} conv={v2}")


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
