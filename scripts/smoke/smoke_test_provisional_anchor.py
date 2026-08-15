"""Findings v2 step 2 — provisional anchor sweep.

`_sweep_provisional_anchors` writes a `source: "provisional"` anchor on
every lifecycle doc that:
  - has `runs_observed >= provisional_stable_runs`
  - has `silent_runs_current == 0`
  - has `confirm_anchors[] == []`

Scenarios:
  [1] Three docs — only the eligible one gets a provisional anchor.
  [2] Eligible doc already has an analyst anchor → skipped (don't
      shadow analyst with provisional).
  [3] An analyst confirm AFTER provisional appends on top (history
      preserved).
  [4] An analyst reject AFTER provisional clears the provisional.

Standalone — no real ES, no pytest.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_provisional_anchor.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.lifecycle import _sweep_provisional_anchors
from enrich.findings.writer import _apply_lifecycle_side_effects

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

    def refresh(self, *, index: str):
        return {}


class _StubES:
    """In-memory store with the minimum ES API the sweep + anchor build use."""

    def __init__(self):
        self.indices = _StubIndices()
        self.store: dict[str, dict[str, dict]] = {}

    def get(self, *, index: str, id: str):
        if index in self.store and id in self.store[index]:
            return {"_source": dict(self.store[index][id])}
        raise KeyError(id)

    def index(self, *, index: str, id: str, document: dict, refresh=False):
        self.store.setdefault(index, {})[id] = dict(document)

    def search(self, **kwargs):
        index = kwargs.get("index")
        query = kwargs.get("query") or {}
        # The sweep query: bool.must[range(runs_observed), term(silent=0)]
        must = ((query.get("bool") or {}).get("must")) or []
        is_sweep = any("range" in c and "runs_observed" in (c.get("range") or {}) for c in must)
        if is_sweep:
            stable_min = must[0]["range"]["runs_observed"]["gte"]
            hits = []
            for doc_id, src in (self.store.get(index) or {}).items():
                if int(src.get("runs_observed", 0)) >= stable_min and int(src.get("silent_runs_current", 0)) == 0:
                    hits.append({"_id": doc_id, "_source": dict(src)})
            return {"hits": {"hits": hits}}
        # The anchor builder: latest cluster run_id lookup + per-playbook agg
        if "term" in query and (query.get("term") or {}).get("doc_type") == "cluster":
            return {"hits": {"hits": [{"_source": {"run_id": "run-cluster-now"}}]}}
        # Anchor session aggs
        if "aggs" in kwargs:
            return {"hits": {"hits": []}, "aggregations": {
                "cmd_sig":    {"buckets": [{"key": "csig-abc", "doc_count": 5}]},
                "bigram_sig": {"buckets": [{"key": "bsig-def", "doc_count": 5}]},
                "artifacts":  {"buckets": [
                    {"key": "url:hxxp://x", "doc_count": 3},
                    {"key": "hash:deadbeef", "doc_count": 2},
                ]},
            }}
        return {"hits": {"hits": []}}


class _Cfg:
    class findings:
        class indexes:
            default = "prism.finding"
            playbook_lifecycle = "lifecycle-pb"
            campaign_lifecycle = "lifecycle-cmp"
            source_ip_lifecycle = "lifecycle-ip"

        class lifecycle:
            snapshot_cap = 30
            provisional_stable_runs = 8

    class elasticsearch:
        class indexes:
            class cowrie:
                commands = "x"
                command_clusters = "x"
                sessions_rollup = "rollup-sess"
                session_clusters = "clusters-sess"
                ips_rollup = "x"
                ip_clusters = "x"
                campaigns = "x"


def _seed_pb(es, doc_id, *, runs_observed, silent, anchors=None):
    es.store.setdefault("lifecycle-pb", {})[doc_id] = {
        "playbook_id": doc_id,
        "playbook_name": "p-" + doc_id,
        "first_seen_ever": "2026-05-15T00:00:00+00:00",
        "last_seen": "2026-05-22T00:00:00+00:00",
        "first_run_id": "run-a",
        "last_run_id": "run-current",
        "runs_observed": runs_observed,
        "silent_runs_current": silent,
        "snapshots": [{
            "run_id": "run-current",
            "@timestamp": "2026-05-22T00:00:00+00:00",
            "session_count": 5, "ip_count": 2, "mean_novelty": 0.5,
            "dominant_intent": "execute_payload",
            "asn_top": "12345", "asn_distribution": {"12345": 2},
        }],
        "confirm_anchors": anchors or [],
        "drift_suppressions": [],
    }


# -----------------------------------------------------------------------------
# [1] Three docs, only one eligible.
# -----------------------------------------------------------------------------
print("\n[1] sweep writes a provisional only on the eligible doc")
es = _StubES()
_seed_pb(es, "sescl-elig",      runs_observed=10, silent=0)               # eligible
_seed_pb(es, "sescl-young",     runs_observed=4,  silent=0)               # too young
_seed_pb(es, "sescl-silent",    runs_observed=10, silent=3)               # currently silent
written = _sweep_provisional_anchors(
    es, _Cfg,
    lifecycle_index="lifecycle-pb", artifact_kind="playbook", key_field="playbook_id",
    stable_min=8, run_id="run-current",
)
check("1 provisional written", written == 1, f"got {written}")
elig_anchors = es.store["lifecycle-pb"]["sescl-elig"]["confirm_anchors"]
check("eligible doc got 1 anchor", len(elig_anchors) == 1)
check("anchor source == provisional", elig_anchors[0]["source"] == "provisional")
check("anchor confirming_finding_id is null",
      elig_anchors[0]["confirming_finding_id"] is None)
check("anchor carried snapshot session_count",
      elig_anchors[0]["session_count"] == 5)
check("anchor carried command_signature from agg",
      elig_anchors[0]["command_signature"] == "csig-abc")
check("anchor carried artifact_set from agg (2 entries)",
      len(elig_anchors[0]["artifact_set"]) == 2)
check("young doc untouched",
      es.store["lifecycle-pb"]["sescl-young"]["confirm_anchors"] == [])
check("silent doc untouched",
      es.store["lifecycle-pb"]["sescl-silent"]["confirm_anchors"] == [])


# -----------------------------------------------------------------------------
# [2] Eligible doc already has anchor → sweep skips it.
# -----------------------------------------------------------------------------
print("\n[2] sweep skips a doc that already has any anchor")
es = _StubES()
_seed_pb(es, "sescl-prior", runs_observed=10, silent=0,
         anchors=[{"ts": "t0", "source": "analyst"}])
written = _sweep_provisional_anchors(
    es, _Cfg,
    lifecycle_index="lifecycle-pb", artifact_kind="playbook", key_field="playbook_id",
    stable_min=8, run_id="run-current",
)
check("no provisional written when anchor pre-exists", written == 0, f"got {written}")
check("existing anchor still single",
      len(es.store["lifecycle-pb"]["sescl-prior"]["confirm_anchors"]) == 1)


# -----------------------------------------------------------------------------
# [3] Provisional → analyst confirm: both anchors present (history preserved).
# -----------------------------------------------------------------------------
print("\n[3] provisional then analyst confirm — both anchors stack")
es = _StubES()
_seed_pb(es, "sescl-stack", runs_observed=10, silent=0)
_sweep_provisional_anchors(
    es, _Cfg,
    lifecycle_index="lifecycle-pb", artifact_kind="playbook", key_field="playbook_id",
    stable_min=8, run_id="run-current",
)
# Analyst hits "confirm" on the coverage finding for this playbook.
_apply_lifecycle_side_effects(es, _Cfg, finding={
    "finding_id": "find-pla-stack",
    "kind": "playbook",
    "artifact": {"kind": "playbook", "value": "sescl-stack"},
    "status": "confirmed",
})
anchors = es.store["lifecycle-pb"]["sescl-stack"]["confirm_anchors"]
check("2 anchors after analyst confirm", len(anchors) == 2, f"got {len(anchors)}")
check("ordering: provisional first, analyst second",
      [a["source"] for a in anchors] == ["provisional", "analyst"])


# -----------------------------------------------------------------------------
# [4] Provisional → analyst reject: provisional is removed (full clear).
# -----------------------------------------------------------------------------
print("\n[4] provisional then analyst reject — provisional removed")
es = _StubES()
_seed_pb(es, "sescl-rej", runs_observed=10, silent=0)
_sweep_provisional_anchors(
    es, _Cfg,
    lifecycle_index="lifecycle-pb", artifact_kind="playbook", key_field="playbook_id",
    stable_min=8, run_id="run-current",
)
# Reject the coverage finding for this playbook.
_apply_lifecycle_side_effects(es, _Cfg, finding={
    "finding_id": "find-pla-rej",
    "kind": "playbook",
    "artifact": {"kind": "playbook", "value": "sescl-rej"},
    "status": "rejected",
})
remaining = es.store["lifecycle-pb"]["sescl-rej"]["confirm_anchors"]
check("anchors empty after analyst reject", remaining == [], f"got {remaining}")


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
