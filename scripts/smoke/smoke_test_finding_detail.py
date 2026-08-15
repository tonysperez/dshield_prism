"""Findings v2 step 6 — detail drawer backend joins.

`get_finding_detail(es, cfg, finding_id)` enriches a base finding with:
  - `lifecycle`             — the matching lifecycle doc
  - `top_commands`          — playbook artifact: top-3 by novelty
  - `top_ips`               — playbook artifact: top-5 by session count + intel
  - `convergent_campaigns`  — playbook artifact: campaigns referencing it

This test exercises:
  - playbook-artifact path (all joins fire)
  - ip-artifact path (only lifecycle join)
  - campaign-artifact path (only lifecycle join)
  - missing base finding → None
  - per-join failure does not crash the drawer (returns empty list)

Stubs ES so the test is offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_finding_detail.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "console" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from console.findings import get_finding_detail

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

    class elasticsearch:
        class indexes:
            class cowrie:
                commands = "cmds-idx"
                sessions_rollup = "rollup-sess"
                campaigns = "campaigns-idx"


class _StubIndices:
    def __init__(self, *, existing_indices=None):
        self.existing = set(existing_indices or [])
    def exists(self, *, index: str) -> bool:
        return index in self.existing


class _StubES:
    """Returns canned docs by (index, id) and canned search responses by
    index + characteristic query shape."""

    def __init__(self, *, docs, searches, existing_indices=None):
        # docs: {(index, id): _source}
        # searches: {index: response_dict} — naive routing; assumes one
        # search shape per index in this test
        self.docs = docs
        self.search_responses = searches
        self.indices = _StubIndices(existing_indices=existing_indices)

    def get(self, *, index: str, id: str):
        key = (index, id)
        if key not in self.docs:
            raise KeyError(key)
        return {"_source": self.docs[key], "_id": id}

    def search(self, **kwargs):
        index = kwargs.get("index")
        return self.search_responses.get(index, {"hits": {"hits": []}, "aggregations": {}})


# -----------------------------------------------------------------------------
# [1] playbook artifact: all joins fire and shape is well-formed.
# -----------------------------------------------------------------------------
print("\n[1] playbook artifact — all joins fire")
FIND_ID = "find-pla-AAAA"
PB_ID = "sescl-AAAA"

base_finding = {
    "finding_id": FIND_ID, "kind": "playbook",
    "artifact": {"kind": "playbook", "value": PB_ID},
    "status": "new", "score": 1.7,
    "narrative": "playbook narrative",
}

lifecycle_doc = {
    "playbook_id": PB_ID,
    "playbook_name": "Drop Test",
    "runs_observed": 5,
    "silent_runs_current": 0,
    "snapshots": [
        {"@timestamp": "2026-05-20T00:00:00+00:00", "session_count": 3, "ip_count": 2},
        {"@timestamp": "2026-05-21T00:00:00+00:00", "session_count": 7, "ip_count": 4},
    ],
    "confirm_anchors": [{"source": "analyst", "ts": "2026-05-21T01:00:00+00:00"}],
    "drift_suppressions": [],
}

es = _StubES(
    existing_indices=["lc-pb"],
    docs={
        ("prism.finding", FIND_ID): base_finding,
        ("lc-pb", PB_ID): lifecycle_doc,
    },
    searches={
        # _top_commands_for_playbook step 1: member sessions
        "rollup-sess": {
            "hits": {"hits": [
                {"_source": {"cowrie": {"session_id": "sess-1"}}},
                {"_source": {"cowrie": {"session_id": "sess-2"}}},
            ]},
            # Will also be returned for _top_ips_for_playbook;
            # extending payload below picks the right aggregation.
            "aggregations": {
                "by_ip": {"buckets": [
                    {"key": "1.1.1.1", "doc_count": 6,
                     "intel": {"hits": {"hits": [{"_source": {
                         "dshield": {"cowrie": {"enrichment": {"session": {
                             "source_ip_intel": {"consensus_label": "malicious"}
                         }}}}
                     }}]}}},
                    {"key": "2.2.2.2", "doc_count": 3,
                     "intel": {"hits": {"hits": []}}},
                ]},
            },
        },
        # _top_commands_for_playbook step 2: command aggregation
        "cmds-idx": {
            "hits": {"hits": []},
            "aggregations": {"top": {"buckets": [
                {"key": "cmd-h1",
                 "avg_novelty": {"value": 0.91},
                 "sample": {"hits": {"hits": [{"_source": {
                     "process": {"command_line": "wget hxxp://x/a"},
                     "dshield": {"cowrie": {"enrichment": {"description": "fetch payload"}}},
                 }}]}}},
                {"key": "cmd-h2",
                 "avg_novelty": {"value": 0.75},
                 "sample": {"hits": {"hits": [{"_source": {
                     "process": {"command_line": "chmod +x ./mal"},
                 }}]}}},
            ]}},
        },
        # _convergent_campaigns
        "campaigns-idx": {
            "hits": {"hits": [
                {"_source": {"campaign_id": "cmp-bhv-1", "name": "drops-2026",
                             "kind": "behaviour", "ip_count": 12}},
            ]},
        },
    },
)

out = get_finding_detail(es, _Cfg, FIND_ID)
check("base finding present", out is not None and out.get("kind") == "playbook")
check("lifecycle joined", out and out["lifecycle"].get("runs_observed") == 5)
check("snapshots carried", out and len(out["lifecycle"]["snapshots"]) == 2)
check("top_commands joined (2 entries)", len(out.get("top_commands") or []) == 2)
check("top_commands[0] command text",
      out["top_commands"][0]["command"] == "wget hxxp://x/a")
check("top_commands[0] novelty rounded",
      out["top_commands"][0]["novelty"] == 0.91)
check("top_ips joined (2 entries)", len(out.get("top_ips") or []) == 2)
check("top_ips intel verdict captured",
      out["top_ips"][0]["intel_verdict"] == "malicious")
check("top_ips fallback when no intel hit",
      out["top_ips"][1]["intel_verdict"] is None)
check("convergent_campaigns joined", len(out.get("convergent_campaigns") or []) == 1)
check("convergent_campaigns name + kind",
      out["convergent_campaigns"][0]["campaign_name"] == "drops-2026"
      and out["convergent_campaigns"][0]["kind"] == "behaviour")


# -----------------------------------------------------------------------------
# [2] ip artifact — only lifecycle join (no commands/ips/campaigns).
# -----------------------------------------------------------------------------
print("\n[2] ip artifact — lifecycle only")
es = _StubES(
    existing_indices=["lc-ip"],
    docs={
        ("prism.finding", "find-iv-1"): {
            "finding_id": "find-iv-1", "kind": "intel_verdict_flip",
            "artifact": {"kind": "ip", "value": "1.1.1.1"},
            "status": "new",
        },
        ("lc-ip", "1.1.1.1"): {
            "source_ip": "1.1.1.1",
            "runs_observed": 4,
            "snapshots": [{"@timestamp": "2026-05-22T00:00:00+00:00", "session_count": 5}],
        },
    },
    searches={},
)
out = get_finding_detail(es, _Cfg, "find-iv-1")
check("ip-artifact base finding loaded", out is not None and out["kind"] == "intel_verdict_flip")
check("ip lifecycle joined", out["lifecycle"]["source_ip"] == "1.1.1.1")
check("no top_commands key for ip artifact", "top_commands" not in out)
check("no top_ips key for ip artifact", "top_ips" not in out)
check("no convergent_campaigns key for ip artifact", "convergent_campaigns" not in out)


# -----------------------------------------------------------------------------
# [3] campaign artifact — only lifecycle join.
# -----------------------------------------------------------------------------
print("\n[3] campaign artifact — lifecycle only")
es = _StubES(
    existing_indices=["lc-cmp"],
    docs={
        ("prism.finding", "find-cmp-1"): {
            "finding_id": "find-cmp-1", "kind": "campaign",
            "artifact": {"kind": "campaign", "value": "cmp-bhv-1"},
            "status": "new",
        },
        ("lc-cmp", "cmp-bhv-1"): {
            "campaign_id": "cmp-bhv-1", "runs_observed": 3, "snapshots": [],
        },
    },
    searches={},
)
out = get_finding_detail(es, _Cfg, "find-cmp-1")
check("campaign-artifact base loaded", out is not None and out["kind"] == "campaign")
check("campaign lifecycle joined",
      out["lifecycle"]["campaign_id"] == "cmp-bhv-1")
check("no top_commands for campaign artifact", "top_commands" not in out)


# -----------------------------------------------------------------------------
# [4] missing base finding → None
# -----------------------------------------------------------------------------
print("\n[4] missing base finding → None")
es = _StubES(docs={}, searches={})
check("missing finding returns None",
      get_finding_detail(es, _Cfg, "find-missing") is None)


# -----------------------------------------------------------------------------
# [5] join failure does not crash; returns empty lists.
# -----------------------------------------------------------------------------
print("\n[5] join failure → empty lists, base finding still returned")


class _ExplodingES(_StubES):
    def search(self, **kwargs):
        raise RuntimeError("simulated downstream failure")


es = _ExplodingES(
    existing_indices=["lc-pb"],
    docs={
        ("prism.finding", FIND_ID): base_finding,
        ("lc-pb", PB_ID): lifecycle_doc,
    },
    searches={},
)
out = get_finding_detail(es, _Cfg, FIND_ID)
check("base finding still present despite join failures", out is not None)
check("lifecycle still joined (get is separate from search)",
      out["lifecycle"].get("runs_observed") == 5)
check("top_commands defaults to empty list", out["top_commands"] == [])
check("top_ips defaults to empty list", out["top_ips"] == [])
check("convergent_campaigns defaults to empty list", out["convergent_campaigns"] == [])


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
