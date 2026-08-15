"""Findings v2 step 4 — stream A (drift) miner correctness.

Covers the 7 drift kinds:
  - playbook_command_drift     — signature mode flip
  - playbook_sequence_drift    — bigram Jaccard, mutex with command_drift
  - playbook_artifact_drift    — artifact set Jaccard distance
  - playbook_geo_drift         — ASN cosine distance
  - playbook_size_drift        — relative + absolute growth gates
  - playbook_resurgence        — timestamp gap proxy
  - campaign_growth            — same gates as size_drift on campaigns

Plus:
  - run_drift orchestration + drift_suppressions[] dedup
  - delta_signature stability (same delta → same id across runs)
  - finding_id incorporates delta_signature

Stubs ES + lifecycle docs so the test is offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_drift_findings.py
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.drift import (
    _cosine_dict,
    _delta_sig,
    _f_artifact_drift,
    _f_command_drift,
    _f_geo_drift,
    _f_resurgence,
    _f_sequence_drift,
    _f_size_drift,
    _jaccard,
    run_drift,
)
from enrich.findings.writer import finding_id

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _Cfg:
    class findings:
        class indexes:
            default = "prism.finding"
            playbook_lifecycle = "lc-pb"
            campaign_lifecycle = "lc-cmp"
            source_ip_lifecycle = "lc-ip"

        class drift:
            command_jaccard_threshold = 0.5
            bigram_jaccard_threshold = 0.4
            artifact_set_drift_min = 0.5
            asn_cosine_drift_min = 0.4
            size_growth_pct_min = 0.75
            size_growth_min_delta_ips = 3
            resurgence_silent_runs = 8
            campaign_growth_pct_min = 0.75
            campaign_growth_min_delta_ips = 3

    class elasticsearch:
        class indexes:
            class cowrie:
                sessions_rollup = "rollup-sess"


# -----------------------------------------------------------------------------
# [1] Pure helpers.
# -----------------------------------------------------------------------------
print("\n[1] jaccard / cosine helpers")
check("jaccard identical sets == 1", _jaccard(["a", "b"], ["a", "b"]) == 1.0)
check("jaccard disjoint sets == 0", _jaccard(["a"], ["b"]) == 0.0)
check("jaccard half-overlap == 1/3", abs(_jaccard(["a", "b"], ["b", "c"]) - 1/3) < 1e-6)
check("jaccard two empties == 1", _jaccard([], []) == 1.0)
check("cosine identical == 1", abs(_cosine_dict({"a": 3}, {"a": 6}) - 1.0) < 1e-6)
check("cosine disjoint == 0", _cosine_dict({"a": 1}, {"b": 1}) == 0.0)
check("delta_sig stable", _delta_sig("x", "y") == _delta_sig("x", "y"))


# -----------------------------------------------------------------------------
# [2] command_drift — Jaccard primary path + signature-equality fallback.
# -----------------------------------------------------------------------------
print("\n[2] playbook_command_drift (Jaccard primary, signature fallback)")
# Disjoint sets → Jaccard=0 < 0.5 → fire
f = _f_command_drift(_Cfg, "r", lc={},
                     anchor={"command_set": ["a", "b", "c"], "command_signature": "S-A"},
                     curr={"command_set":   ["x", "y", "z"], "command_signature": "S-C",
                           "session_count": 4})
check("fires on disjoint command_sets (Jaccard=0)",
      f is not None and f["kind"] == "playbook_command_drift")
check("evidence carries command_jaccard", "command_jaccard" in f["evidence"],
      f"got {f['evidence']}")
check("evidence carries added + removed",
      sorted(f["evidence"]["added"]) == ["x", "y", "z"]
      and sorted(f["evidence"]["removed"]) == ["a", "b", "c"])

# Identical sets → Jaccard=1 ≥ 0.5 → no fire even with differing sigs
nf = _f_command_drift(_Cfg, "r", lc={},
                      anchor={"command_set": ["a", "b"], "command_signature": "S-A"},
                      curr={"command_set":   ["a", "b"], "command_signature": "S-B"})
check("no fire on identical command_sets even with differing signatures", nf is None)

# Above threshold (Jaccard 0.6) → no fire
above = _f_command_drift(_Cfg, "r", lc={},
                         anchor={"command_set": ["a", "b", "c"]},
                         curr={"command_set":   ["a", "b", "c", "d", "e"]})
# Jaccard = 3/5 = 0.6, threshold = 0.5 → no fire
check("no fire when Jaccard above threshold", above is None,
      f"got {above['evidence'] if above else None}")

# Below threshold → fire
below = _f_command_drift(_Cfg, "r", lc={},
                         anchor={"command_set": ["a", "b", "c", "d"]},
                         curr={"command_set":   ["a", "e", "f", "g"]})
# Jaccard = 1/7 ≈ 0.143 < 0.5 → fire
check("fires when Jaccard below threshold", below is not None)

# Legacy fallback: no command_set on either side, but signatures differ → fire
legacy_fire = _f_command_drift(_Cfg, "r", lc={},
                               anchor={"command_signature": "AAA"},
                               curr={"command_signature": "BBB", "session_count": 4})
check("legacy fallback: fires on signature mismatch when command_set missing",
      legacy_fire is not None
      and legacy_fire["evidence"].get("fallback", "").startswith("signature"))

# Legacy fallback: signatures match → no fire
legacy_nofire = _f_command_drift(_Cfg, "r", lc={},
                                 anchor={"command_signature": "AAA"},
                                 curr={"command_signature": "AAA"})
check("legacy fallback: no fire on matching sigs", legacy_nofire is None)

# No data at all → no fire
nf2 = _f_command_drift(_Cfg, "r", lc={}, anchor={}, curr={"command_signature": "BBB"})
check("no fire when neither command_set nor anchor sig present", nf2 is None)


# -----------------------------------------------------------------------------
# [3] sequence_drift — bigram Jaccard + command_drift mutex.
# -----------------------------------------------------------------------------
print("\n[3] playbook_sequence_drift")
anchor = {"command_bigram_set": ["a|b", "b|c", "c|d", "d|e"],
          "command_bigram_signature": "ANC"}
curr_low = {"command_bigram_set": ["x|y", "y|z"],
            "command_bigram_signature": "CUR"}
f = _f_sequence_drift(_Cfg, "r", lc={}, anchor=anchor, curr=curr_low, command_fired=False)
check("fires when Jaccard < threshold and command did NOT fire",
      f is not None and f["kind"] == "playbook_sequence_drift",
      f"got {f}")
check("evidence carries jaccard score < threshold",
      f["evidence"]["bigram_jaccard"] < _Cfg.findings.drift.bigram_jaccard_threshold)

nf = _f_sequence_drift(_Cfg, "r", lc={}, anchor=anchor, curr=curr_low, command_fired=True)
check("MUTEX: no fire when command_drift already fired", nf is None)

high_overlap = {"command_bigram_set": ["a|b", "b|c", "c|d", "d|e"],
                "command_bigram_signature": "SAME"}
nf2 = _f_sequence_drift(_Cfg, "r", lc={}, anchor=anchor, curr=high_overlap, command_fired=False)
check("no fire when bigram sets identical", nf2 is None)


# -----------------------------------------------------------------------------
# [4] artifact_drift — set distance.
# -----------------------------------------------------------------------------
print("\n[4] playbook_artifact_drift")
f = _f_artifact_drift(_Cfg, "r", lc={},
                      anchor={"artifact_set": ["url:hxxp://a", "hash:111"]},
                      curr={"artifact_set":   ["url:hxxp://b", "hash:222"]})
check("fires on fully-disjoint artifact sets (distance=1)",
      f is not None and f["kind"] == "playbook_artifact_drift")
check("evidence carries added + removed",
      sorted(f["evidence"]["added"]) == ["hash:222", "url:hxxp://b"]
      and sorted(f["evidence"]["removed"]) == ["hash:111", "url:hxxp://a"])

nf = _f_artifact_drift(_Cfg, "r", lc={},
                       anchor={"artifact_set": ["a", "b", "c", "d"]},
                       curr={"artifact_set":   ["a", "b", "c", "e"]})
# Jaccard=3/5=0.6, distance=0.4 < 0.5 → no fire
check("no fire when distance below threshold", nf is None)


# -----------------------------------------------------------------------------
# [5] geo_drift — ASN cosine distance.
# -----------------------------------------------------------------------------
print("\n[5] playbook_geo_drift")
f = _f_geo_drift(_Cfg, "r", lc={},
                 anchor={"asn_distribution": {"100": 10}},
                 curr={"asn_distribution":   {"200": 10}})
check("fires when ASN sets fully disjoint (distance=1)",
      f is not None and f["kind"] == "playbook_geo_drift")
check("cosine distance == 1.0", f["evidence"]["asn_cosine_distance"] == 1.0)

nf = _f_geo_drift(_Cfg, "r", lc={},
                  anchor={"asn_distribution": {"100": 5, "200": 5}},
                  curr={"asn_distribution":   {"100": 5, "200": 4}})
check("no fire when ASN distributions ~identical", nf is None)


# -----------------------------------------------------------------------------
# [6] size_drift — pct + absolute gates.
# -----------------------------------------------------------------------------
print("\n[6] playbook_size_drift")
# 4 → 10 IPs: +6 (>= 3), +150% (>= 75%) → fires
f = _f_size_drift(_Cfg, "r", lc={}, anchor={"ip_count": 4}, curr={"ip_count": 10})
check("fires on +150% growth (4 → 10)", f is not None)
check("delta_ips == 6", f["evidence"]["delta_ips"] == 6)
check("growth_pct == 1.5", abs(f["evidence"]["growth_pct"] - 1.5) < 1e-6)

# 4 → 5 IPs: +1 < min_delta_ips → no fire
nf = _f_size_drift(_Cfg, "r", lc={}, anchor={"ip_count": 4}, curr={"ip_count": 5})
check("no fire when delta below min_delta_ips", nf is None)

# 100 → 120: +20 OK, +20% < 75% → no fire
nf2 = _f_size_drift(_Cfg, "r", lc={}, anchor={"ip_count": 100}, curr={"ip_count": 120})
check("no fire when growth pct below threshold", nf2 is None)

# 0 → 10: growth from zero (delta>=3) → fires with pct=None
f0 = _f_size_drift(_Cfg, "r", lc={}, anchor={"ip_count": 0}, curr={"ip_count": 10})
check("fires on growth from zero", f0 is not None)
check("growth_pct null for div-by-zero case", f0["evidence"]["growth_pct"] is None)


# -----------------------------------------------------------------------------
# [7] resurgence — timestamp gap proxy.
# -----------------------------------------------------------------------------
print("\n[7] playbook_resurgence")
def _snap(ts: datetime, run_id: str = "rX"):
    return {"@timestamp": ts.isoformat(), "run_id": run_id, "session_count": 3}

now = datetime.now(UTC)
# Gap of 60 hours between first 2 snaps → 60h >= 8 * 6 = 48h threshold → fires
big_gap = {
    "silent_runs_current": 0,
    "runs_observed": 5,
    "snapshots": [
        _snap(now - timedelta(days=10)),
        _snap(now - timedelta(days=10) + timedelta(hours=60)),
        _snap(now),
    ],
}
f = _f_resurgence(_Cfg, "r", lc=big_gap, anchor={}, curr={"session_count": 3})
check("fires on >=48h gap in snapshot timestamps", f is not None,
      f"got {f}")

# Small gap (< 48h) → no fire
small_gap = {
    "silent_runs_current": 0,
    "runs_observed": 5,
    "snapshots": [
        _snap(now - timedelta(hours=12)),
        _snap(now - timedelta(hours=6)),
        _snap(now),
    ],
}
nf = _f_resurgence(_Cfg, "r", lc=small_gap, anchor={}, curr={})
check("no fire when no big gap", nf is None)

# silent_runs_current > 0 → no fire (we didn't touch the artifact this run)
busy = dict(big_gap, silent_runs_current=2)
nf2 = _f_resurgence(_Cfg, "r", lc=busy, anchor={}, curr={})
check("no fire when silent_runs_current > 0", nf2 is None)


# -----------------------------------------------------------------------------
# [8] delta_signature stability + finding_id incorporates it.
# -----------------------------------------------------------------------------
print("\n[8] delta_signature stable across runs; finding_id changes per delta")
f1 = _f_command_drift(_Cfg, "r1", lc={}, anchor={"command_signature": "AAA"},
                      curr={"command_signature": "BBB"})
f2 = _f_command_drift(_Cfg, "r2", lc={}, anchor={"command_signature": "AAA"},
                      curr={"command_signature": "BBB"})
check("same delta → same delta_signature across runs",
      f1["delta_signature"] == f2["delta_signature"])

f3 = _f_command_drift(_Cfg, "r3", lc={}, anchor={"command_signature": "AAA"},
                      curr={"command_signature": "CCC"})  # different "now"
check("different delta → different delta_signature",
      f1["delta_signature"] != f3["delta_signature"])

# finding_id changes when delta_signature changes (drift findings stay distinct)
fid_1 = finding_id("playbook_command_drift", "playbook", "sescl-X", f1["delta_signature"])
fid_3 = finding_id("playbook_command_drift", "playbook", "sescl-X", f3["delta_signature"])
fid_legacy = finding_id("playbook", "playbook", "sescl-X")  # coverage finding, no delta
check("finding_id differs by delta_signature on same artifact",
      fid_1 != fid_3, f"{fid_1} == {fid_3}")
check("legacy finding_id (no delta) is distinct from drift ids",
      fid_legacy != fid_1 and fid_legacy != fid_3)


# -----------------------------------------------------------------------------
# [9] run_drift orchestration + drift_suppressions dedup.
# -----------------------------------------------------------------------------
print("\n[9] run_drift end-to-end with suppression")


class _OrchES:
    """Returns a single anchored playbook lifecycle doc; current-state agg
    returns a different command_signature (drift expected)."""

    class _Idx:
        def exists(self, *, index): return index in ("lc-pb", "lc-cmp", "rollup-sess")

    def __init__(self, *, suppressed_sig=None):
        self.indices = _OrchES._Idx()
        self.suppressed_sig = suppressed_sig
        self._delivered: set[str] = set()

    def search(self, **kwargs):
        index = kwargs.get("index")
        # _scroll drives this with search_after; deliver hits once per index.
        is_scroll = "sort" in kwargs and "size" in kwargs and "aggs" not in kwargs
        if is_scroll:
            if index in self._delivered:
                return {"hits": {"hits": []}}
            self._delivered.add(index)
        if index == "lc-pb":
            sups = []
            if self.suppressed_sig:
                sups.append({"kind": "playbook_command_drift",
                             "delta_signature": self.suppressed_sig})
            return {"hits": {"hits": [{
                "_source": {
                    "playbook_id": "sescl-orch",
                    "playbook_name": "Orchestrator Test",
                    "silent_runs_current": 0,
                    "runs_observed": 5,
                    "snapshots": [{"@timestamp": "2026-05-22T00:00:00+00:00",
                                   "run_id": "rL", "session_count": 4}],
                    "confirm_anchors": [{
                        "ts": "2026-05-21T00:00:00+00:00",
                        "source": "analyst",
                        "command_signature": "ANCHOR-SIG",
                        "command_bigram_set": ["a|b"],
                        "command_bigram_signature": "AB-SIG",
                        "artifact_set": ["url:hxxp://x"],
                        "asn_distribution": {"100": 1},
                        "ip_count": 2,
                    }],
                    "drift_suppressions": sups,
                },
                "sort": [1],
            }]}}
        if index == "rollup-sess":
            # aggregation response — current playbook state
            return {"aggregations": {
                "session_count":   {"value": 5},
                "ip_count":        {"value": 3},
                "cmd_sig":         {"buckets": [{"key": "CURRENT-SIG", "doc_count": 5}]},
                "bigram_sig":      {"buckets": [{"key": "CB-SIG",      "doc_count": 5}]},
                "bigram_set":      {"buckets": [{"key": "a|b", "doc_count": 4}]},
                "artifact_set":    {"buckets": [{"key": "url:hxxp://x", "doc_count": 4}]},
                "asn":             {"buckets": [{"key": 100, "doc_count": 3}]},
                "dominant_intent": {"buckets": [{"key": "exec", "doc_count": 5}]},
            }, "hits": {"hits": []}}
        if index == "lc-cmp":
            return {"hits": {"hits": []}}
        return {"hits": {"hits": []}}


# Without suppression — command_drift should fire.
out = run_drift(_OrchES(), _Cfg, run_id="run-orch-1")
cmd_findings = out.get("playbook_command_drift") or []
check("orchestrator emits command_drift", len(cmd_findings) == 1, f"got {len(cmd_findings)}")
check("artifact pinned to playbook id",
      cmd_findings[0]["artifact"] == {"kind": "playbook", "value": "sescl-orch"})
check("score defaulted to 1.0", cmd_findings[0]["score"] == 1.0)
check("narrative carries playbook name",
      "Orchestrator Test" in cmd_findings[0]["narrative"])

# With the same delta_signature suppressed → no command_drift finding
expected_sig = _delta_sig("cmd", "ANCHOR-SIG", "CURRENT-SIG")
out_sup = run_drift(_OrchES(suppressed_sig=expected_sig), _Cfg, run_id="run-orch-2")
cmd_sup = out_sup.get("playbook_command_drift") or []
check("suppression dedup — drop the matched-signature finding",
      cmd_sup == [], f"got {cmd_sup}")
# Other kinds (size, sequence, etc.) still considered — but everything else
# matches anchor in this fixture, so none should fire.
non_empty = {k: v for k, v in out_sup.items() if v}
check("no other drift kinds spuriously fire on identical-to-anchor state",
      non_empty == {}, f"got {list(non_empty.keys())}")


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
