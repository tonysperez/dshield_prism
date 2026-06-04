"""Findings v2 step 2 — confirm-anchor + drift-suppression side effects.

Verifies:
  - write_confirm_anchor / write_provisional_anchor appends to
    confirm_anchors[] with the right `source`.
  - remove_anchors_by_source filters out exactly one source class.
  - record_drift_suppression appends to drift_suppressions[].
  - kind_classification routes the three streams correctly.
  - mutate_status dispatches lifecycle side effects per the design table:
      coverage confirmed  → analyst anchor appended
      coverage rejected   → all anchors (analyst + provisional) cleared
      drift confirmed     → fresh analyst anchor (rebaseline)
      drift rejected      → drift_suppressions[] entry keyed by delta_sig
      discovery / unknown → no lifecycle write

Standalone — no real ES, no pytest.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_confirm_anchor.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.lifecycle import (
    DRIFT_KINDS,
    COVERAGE_KINDS,
    kind_classification,
    record_drift_suppression,
    remove_anchors_by_source,
    write_confirm_anchor,
    write_provisional_anchor,
)
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
    def __init__(self):
        self.refreshed: list[str] = []

    def exists(self, *, index: str) -> bool:
        return True

    def refresh(self, *, index: str):
        self.refreshed.append(index)
        return {}


class _StubES:
    def __init__(self, *, search_response=None):
        self.indices = _StubIndices()
        self.store: dict[str, dict[str, dict]] = {}
        self.search_response = search_response or {"hits": {"hits": []}, "aggregations": {}}
        self.searches: list[dict] = []

    def get(self, *, index: str, id: str):
        if index in self.store and id in self.store[index]:
            return {"_source": dict(self.store[index][id])}
        raise KeyError(id)

    def index(self, *, index: str, id: str, document: dict, refresh=False):
        self.store.setdefault(index, {})[id] = dict(document)

    def search(self, **kwargs):
        self.searches.append(kwargs)
        return dict(self.search_response)


class _Cfg:
    """Bare config object exposing only what _apply_lifecycle_side_effects needs."""
    class findings:
        class indexes:
            default = "prism.finding"
            playbook_lifecycle = "lifecycle-pb"
            campaign_lifecycle = "lifecycle-cmp"
            source_ip_lifecycle = "lifecycle-ip"

    class elasticsearch:
        class indexes:
            class cowrie:
                commands = "x"
                command_clusters = "x"
                sessions_rollup = "x"
                session_clusters = "x"
                ips_rollup = "x"
                ip_clusters = "x"
                campaigns = "x"


# Bare lifecycle doc helper
def _seed(es, index, doc_id, *, runs_observed=2, silent=0, anchors=None, source_ip=False):
    base = {
        ("source_ip" if source_ip else "playbook_id"): doc_id,
        "first_seen_ever": "2026-05-20T00:00:00+00:00",
        "last_seen": "2026-05-22T00:00:00+00:00",
        "first_run_id": "run-a",
        "last_run_id": "run-current",
        "runs_observed": runs_observed,
        "silent_runs_current": silent,
        "snapshots": [{
            "run_id": "run-current",
            "@timestamp": "2026-05-22T00:00:00+00:00",
            "session_count": 4, "ip_count": 2, "mean_novelty": 0.6,
            "dominant_intent": "execution",
            "asn_top": "12345", "asn_distribution": {"12345": 2},
        }],
        "confirm_anchors": anchors or [],
        "drift_suppressions": [],
    }
    es.store.setdefault(index, {})[doc_id] = base


# -----------------------------------------------------------------------------
# [1] write_confirm_anchor / write_provisional_anchor — appending behaviour.
# -----------------------------------------------------------------------------
print("\n[1] anchor append + provisional source forcing")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-aaaa")
write_confirm_anchor(es, "lifecycle-pb", artifact_id="sescl-aaaa",
                     anchor={"ts": "t0", "source": "analyst", "confirmed_run_id": "r1"})
write_provisional_anchor(es, "lifecycle-pb", artifact_id="sescl-aaaa",
                         anchor={"ts": "t1", "source": "ignored",
                                 "confirmed_run_id": "r1"})  # source overridden
anchors = es.store["lifecycle-pb"]["sescl-aaaa"]["confirm_anchors"]
check("2 anchors appended", len(anchors) == 2, f"got {len(anchors)}")
check("first anchor is analyst", anchors[0]["source"] == "analyst")
check("second anchor forced to provisional", anchors[1]["source"] == "provisional")


# -----------------------------------------------------------------------------
# [2] remove_anchors_by_source — drops only the targeted source.
# -----------------------------------------------------------------------------
print("\n[2] remove_anchors_by_source")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-bbbb", anchors=[
    {"ts": "t0", "source": "provisional"},
    {"ts": "t1", "source": "analyst"},
    {"ts": "t2", "source": "provisional"},
])
removed = remove_anchors_by_source(es, "lifecycle-pb", artifact_id="sescl-bbbb", source="provisional")
remaining = es.store["lifecycle-pb"]["sescl-bbbb"]["confirm_anchors"]
check("removed count == 2", removed == 2, f"got {removed}")
check("only analyst anchor remains", len(remaining) == 1 and remaining[0]["source"] == "analyst")


# -----------------------------------------------------------------------------
# [3] record_drift_suppression — appends.
# -----------------------------------------------------------------------------
print("\n[3] record_drift_suppression")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-cccc")
record_drift_suppression(es, "lifecycle-pb", artifact_id="sescl-cccc",
                         delta_signature="dlt-abc", kind="playbook_command_drift")
sup = es.store["lifecycle-pb"]["sescl-cccc"]["drift_suppressions"]
check("1 suppression appended", len(sup) == 1)
check("delta_signature carried", sup[0]["delta_signature"] == "dlt-abc")
check("kind carried", sup[0]["kind"] == "playbook_command_drift")


# -----------------------------------------------------------------------------
# [4] kind_classification routing.
# -----------------------------------------------------------------------------
print("\n[4] kind_classification routing")
check("'playbook' → coverage", kind_classification("playbook") == "coverage")
check("'campaign' → coverage", kind_classification("campaign") == "coverage")
check("'playbook_command_drift' → drift", kind_classification("playbook_command_drift") == "drift")
check("'campaign_growth' → drift", kind_classification("campaign_growth") == "drift")
check("'new_playbook' → discovery", kind_classification("new_playbook") == "discovery")
check("'outlier_burst' → discovery", kind_classification("outlier_burst") == "discovery")
check("DRIFT_KINDS covers 7 kinds", len(DRIFT_KINDS) == 7, f"got {len(DRIFT_KINDS)}")
check("COVERAGE_KINDS == {playbook, campaign}", COVERAGE_KINDS == frozenset({"playbook", "campaign"}))


# -----------------------------------------------------------------------------
# [5] mutate_status side effect — coverage confirmed → analyst anchor.
# -----------------------------------------------------------------------------
print("\n[5] coverage finding confirmed → analyst anchor appended")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-dddd")
finding = {
    "finding_id": "find-pla-xxxxx",
    "kind": "playbook",
    "artifact": {"kind": "playbook", "value": "sescl-dddd"},
    "status": "confirmed",
}
_apply_lifecycle_side_effects(es, _Cfg, finding=finding)
anchors = es.store["lifecycle-pb"]["sescl-dddd"]["confirm_anchors"]
check("1 anchor after confirm", len(anchors) == 1, f"got {len(anchors)}")
check("source == analyst", anchors[0]["source"] == "analyst")
check("confirming_finding_id carried", anchors[0]["confirming_finding_id"] == "find-pla-xxxxx")
check("snapshot fields copied (session_count)", anchors[0]["session_count"] == 4)
check("snapshot fields copied (dominant_intent)", anchors[0]["dominant_intent"] == "execution")


# -----------------------------------------------------------------------------
# [6] mutate_status side effect — coverage rejected → all anchors cleared.
# -----------------------------------------------------------------------------
print("\n[6] coverage finding rejected → analyst AND provisional anchors cleared")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-eeee", anchors=[
    {"ts": "t0", "source": "provisional"},
    {"ts": "t1", "source": "analyst"},
])
finding = {
    "finding_id": "find-pla-yyyyy",
    "kind": "playbook",
    "artifact": {"kind": "playbook", "value": "sescl-eeee"},
    "status": "rejected",
}
_apply_lifecycle_side_effects(es, _Cfg, finding=finding)
remaining = es.store["lifecycle-pb"]["sescl-eeee"]["confirm_anchors"]
check("all anchors removed on reject", remaining == [], f"got {remaining}")


# -----------------------------------------------------------------------------
# [7] mutate_status side effect — drift confirmed → fresh anchor (rebaseline).
# -----------------------------------------------------------------------------
print("\n[7] drift finding confirmed → rebaseline anchor")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-ffff", anchors=[
    {"ts": "t0", "source": "analyst", "session_count": 1},
])
finding = {
    "finding_id": "find-pla-zzzzz",
    "kind": "playbook_command_drift",
    "artifact": {"kind": "playbook", "value": "sescl-ffff"},
    "status": "confirmed",
    "delta_signature": "dlt-rebaseline",
}
_apply_lifecycle_side_effects(es, _Cfg, finding=finding)
anchors = es.store["lifecycle-pb"]["sescl-ffff"]["confirm_anchors"]
check("now 2 anchors (history preserved + new one)", len(anchors) == 2, f"got {len(anchors)}")
check("newest is analyst", anchors[-1]["source"] == "analyst")
check("newest carries the drift finding id",
      anchors[-1]["confirming_finding_id"] == "find-pla-zzzzz")


# -----------------------------------------------------------------------------
# [8] mutate_status side effect — drift rejected → suppression appended.
# -----------------------------------------------------------------------------
print("\n[8] drift finding rejected → drift_suppressions[] entry")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-gggg")
finding = {
    "finding_id": "find-pla-wwwww",
    "kind": "playbook_artifact_drift",
    "artifact": {"kind": "playbook", "value": "sescl-gggg"},
    "status": "rejected",
    "delta_signature": "dlt-noise",
}
_apply_lifecycle_side_effects(es, _Cfg, finding=finding)
doc = es.store["lifecycle-pb"]["sescl-gggg"]
check("anchors untouched on drift reject", doc["confirm_anchors"] == [])
check("1 suppression appended", len(doc["drift_suppressions"]) == 1)
check("suppression delta_signature matches",
      doc["drift_suppressions"][0]["delta_signature"] == "dlt-noise")
check("suppression kind matches",
      doc["drift_suppressions"][0]["kind"] == "playbook_artifact_drift")


# -----------------------------------------------------------------------------
# [9] mutate_status side effect — drift rejected without delta_signature
# does NOT crash and does NOT record a suppression.
# -----------------------------------------------------------------------------
print("\n[9] drift rejected without delta_signature — defensive no-op")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-hhhh")
finding = {
    "finding_id": "find-pla-vvvvv",
    "kind": "playbook_command_drift",
    "artifact": {"kind": "playbook", "value": "sescl-hhhh"},
    "status": "rejected",
    # no delta_signature
}
_apply_lifecycle_side_effects(es, _Cfg, finding=finding)
sup = es.store["lifecycle-pb"]["sescl-hhhh"]["drift_suppressions"]
check("no suppression recorded", sup == [], f"got {sup}")


# -----------------------------------------------------------------------------
# [10] discovery / non-playbook artifact_kind — no lifecycle side effect.
# -----------------------------------------------------------------------------
print("\n[10] discovery + unknown artifact_kind → no-op")
es = _StubES()
_seed(es, "lifecycle-pb", "sescl-iiii")
finding_disc = {
    "finding_id": "find-new-aaaaa",
    "kind": "new_playbook",
    "artifact": {"kind": "playbook", "value": "sescl-iiii"},
    "status": "confirmed",
}
_apply_lifecycle_side_effects(es, _Cfg, finding=finding_disc)
check("discovery confirm — no anchor written",
      es.store["lifecycle-pb"]["sescl-iiii"]["confirm_anchors"] == [])

finding_ip = {
    "finding_id": "find-axi-bbbbb",
    "kind": "playbook",  # coverage
    "artifact": {"kind": "ip", "value": "203.0.113.5"},  # not a playbook lifecycle
    "status": "confirmed",
}
_apply_lifecycle_side_effects(es, _Cfg, finding=finding_ip)
check("non-playbook/campaign artifact_kind — no lifecycle write",
      "203.0.113.5" not in (es.store.get("lifecycle-pb") or {}))


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
