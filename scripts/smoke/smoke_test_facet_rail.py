"""Findings v2 P1c — left facet rail.

Covers:
  - `_facet_filters` translates {dim: bucket_name} into ES must clauses
  - score / age / ip bands map to correct ranges
  - intent + intel_verdict map to term/should clauses
  - `facet_counts` issues one ES search per dimension and returns
    `{dim: [{key, count}, ...]}`
  - `list_findings(facets=...)` appends the facet filter to the query
  - `_kinds_for_stream` returns the right kind sets for each stream
  - empty / unknown facet inputs degrade gracefully

Stubs ES so the test is offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_facet_rail.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "console" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from console.findings import (
    _facet_filters,
    _kinds_for_stream,
    facet_counts,
    list_findings,
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


# -----------------------------------------------------------------------------
# [1] _facet_filters translation
# -----------------------------------------------------------------------------
print("\n[1] _facet_filters translation")
check("empty facets → no clauses",
      _facet_filters({}) == [] and _facet_filters({"score_band": ""}) == [])

clauses = _facet_filters({"score_band": "high"})
check("score_band=high → range>=1.5",
      len(clauses) == 1
      and clauses[0]["range"]["score"]["gte"] == 1.5)

clauses = _facet_filters({"age_band": "today"})
check("age_band=today → range first_seen_at>=now-24h",
      len(clauses) == 1
      and clauses[0]["range"]["first_seen_at"].get("gte") == "now-24h")

clauses = _facet_filters({"ip_band": "large"})
check("ip_band=large → bool[should] over ip_count + member_ips",
      len(clauses) == 1
      and "bool" in clauses[0]
      and len(clauses[0]["bool"]["should"]) == 2)

clauses = _facet_filters({"intent": "execution"})
check("intent → term on evidence.dominant_intent",
      len(clauses) == 1
      and clauses[0]["term"]["evidence.dominant_intent"] == "execution")

clauses = _facet_filters({"intel_verdict": "malicious"})
check("intel_verdict → bool[should] over verdict_curr + consensus_label",
      len(clauses) == 1
      and len(clauses[0]["bool"]["should"]) == 2)

clauses = _facet_filters({"unknown_dim": "x"})
check("unknown dim → silently ignored",
      clauses == [])

clauses = _facet_filters({"score_band": "high", "age_band": "today"})
check("multiple facets → multiple clauses",
      len(clauses) == 2)


# -----------------------------------------------------------------------------
# [2] _kinds_for_stream
# -----------------------------------------------------------------------------
print("\n[2] _kinds_for_stream")
check("coverage → playbook + campaign",
      _kinds_for_stream("coverage") == frozenset({"playbook", "campaign"}))
check("drift → 7 kinds",   len(_kinds_for_stream("drift")) == 7)
check("discovery → 8 kinds", len(_kinds_for_stream("discovery")) == 8)
check("unknown → empty",  _kinds_for_stream("foo") == frozenset())


# -----------------------------------------------------------------------------
# [3] facet_counts: one search per dimension, returns counts
# -----------------------------------------------------------------------------
print("\n[3] facet_counts issues per-dim searches + returns counts")


class _StubIdx:
    def exists(self, *, index): return True


class _StubES:
    """Returns canned aggregation shapes based on the aggs requested."""

    indices = _StubIdx()

    def __init__(self):
        self.search_calls: list[dict] = []

    def search(self, **kw):
        self.search_calls.append(kw)
        aggs = kw.get("aggs") or {}
        agg_keys = sorted(aggs.keys())
        # ip_band uses two range aggs (ip_count + member_ips)
        if agg_keys == ["ip_count", "member_ips"]:
            return {"hits": {"hits": []}, "aggregations": {
                "ip_count": {"buckets": [
                    {"key": "small", "doc_count": 1},
                    {"key": "medium", "doc_count": 2},
                    {"key": "large", "doc_count": 3},
                ]},
                "member_ips": {"buckets": [
                    {"key": "small", "doc_count": 4},
                    {"key": "medium", "doc_count": 5},
                    {"key": "large", "doc_count": 6},
                ]},
            }}
        # intel_verdict uses two terms aggs (v + c)
        if agg_keys == ["c", "v"]:
            return {"hits": {"hits": []}, "aggregations": {
                "v": {"buckets": [{"key": "malicious", "doc_count": 7}]},
                "c": {"buckets": [{"key": "clean",     "doc_count": 9}]},
            }}
        # single-agg facets (score_band / age_band / intent) all use "f"
        if "f" in aggs:
            agg = aggs["f"]
            if "range" in agg:
                # Use the ranges' keys to fabricate counts
                return {"hits": {"hits": []}, "aggregations": {"f": {"buckets": [
                    {"key": r["key"], "doc_count": 10 * (i + 1)}
                    for i, r in enumerate(agg["range"]["ranges"])
                ]}}}
            return {"hits": {"hits": []}, "aggregations": {"f": {"buckets": [
                {"key": "execute_payload", "doc_count": 5},
                {"key": "host_recon", "doc_count": 3},
            ]}}}
        return {"hits": {"hits": []}, "aggregations": {}}


class _Cfg:
    class findings:
        class indexes:
            default = "prism.finding"


es = _StubES()
result = facet_counts(es, _Cfg, status=["new"])
check("facet_counts returns all 5 dimensions",
      sorted(result.keys()) == sorted(["score_band", "age_band", "ip_band",
                                       "intent", "intel_verdict"]),
      f"got {sorted(result.keys())}")
check("score_band has 3 buckets in expected order",
      [b["key"] for b in result["score_band"]] == ["low", "medium", "high"])
check("ip_band merged ip_count + member_ips per bucket",
      [b["count"] for b in result["ip_band"]] == [5, 7, 9],  # 1+4, 2+5, 3+6
      f"got {[b['count'] for b in result['ip_band']]}")
check("intel_verdict merged from two aggs",
      sorted(b["key"] for b in result["intel_verdict"]) == ["clean", "malicious"])
check("intent populates terms agg",
      sorted(b["key"] for b in result["intent"]) == ["execute_payload", "host_recon"])


# -----------------------------------------------------------------------------
# [4] Active-facet exclusion: counting score_band must NOT filter on score_band
# -----------------------------------------------------------------------------
print("\n[4] facet_counts: counting a dim excludes that dim's filter from must")
es = _StubES()
facet_counts(es, _Cfg, status=["new"],
             facets={"score_band": "high", "age_band": "today"})

# Find the search call whose first agg is for `f` (single-agg) and whose
# ranges field is `score` — that's the score_band counting query.
score_call = None
for c in es.search_calls:
    aggs = c.get("aggs") or {}
    f = aggs.get("f")
    if not f or "range" not in f:
        continue
    if f["range"]["field"] == "score":
        score_call = c
        break
assert score_call is not None
must = (((score_call.get("query") or {}).get("bool")) or {}).get("must") or []
# Should contain age_band filter (range on first_seen_at) but NOT score_band
has_age = any("range" in m and "first_seen_at" in m.get("range", {}) for m in must)
has_score = any("range" in m and "score" in m.get("range", {}) for m in must)
check("score_band query keeps age_band filter", has_age)
check("score_band query excludes the score_band filter being counted",
      not has_score)


# -----------------------------------------------------------------------------
# [5] list_findings appends facet filter to the search must
# -----------------------------------------------------------------------------
print("\n[5] list_findings appends facet filter")


class _ListES:
    indices = _StubIdx()
    def __init__(self): self.calls = []
    def search(self, **kw):
        self.calls.append(kw)
        return {"hits": {"hits": [], "total": {"value": 0}}}


es = _ListES()
list_findings(es, _Cfg, status=["new"], facets={"intent": "execution"})
must = (((es.calls[0].get("query") or {}).get("bool")) or {}).get("must") or []
has_intent = any(
    m.get("term", {}).get("evidence.dominant_intent") == "execution"
    for m in must
)
check("list_findings: facet filter present in query", has_intent,
      f"got must={must}")


# -----------------------------------------------------------------------------
# [6] facet_counts: missing index → {}
# -----------------------------------------------------------------------------
print("\n[6] facet_counts: missing index returns {}")


class _MissingES:
    class indices:
        def exists(self, *, index): return False
    indices = indices()


out = facet_counts(_MissingES(), _Cfg)
check("missing index → empty dict", out == {})


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
