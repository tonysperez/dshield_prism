"""Findings v2 step 1 — lifecycle snapshot append + silent-run bump.

Verifies the unit functions in `enrich.findings.lifecycle`:

  - update_playbook_lifecycle    — read-modify-write upsert
  - update_campaign_lifecycle    — same, keyed by campaign_id
  - update_source_ip_lifecycle   — same, no confirm_anchors/drift_suppressions
  - increment_silent_runs        — bumps silent counter on stale docs

Scenarios:
  [1] 3-run sequence on the same playbook → snapshots grow, runs_observed
      increments, silent_runs_current stays 0.
  [2] Snapshot cap rotation — push N+5 snapshots, only last N kept.
  [3] increment_silent_runs targets docs whose last_run_id != current.
  [4] Campaign upsert sets campaign_kind / campaign_name on first write
      and updates them on later writes.
  [5] Source-IP upsert produces a doc WITHOUT confirm_anchors[] /
      drift_suppressions[] (strict-dynamic mapping forbids those).

Standalone — no real ES, no pytest.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_lifecycle_snapshot.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.lifecycle import (
    increment_silent_runs,
    update_campaign_lifecycle,
    update_playbook_lifecycle,
    update_source_ip_lifecycle,
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
    def __init__(self, *, exists: bool = True):
        self.exists_val = exists

    def exists(self, *, index: str) -> bool:
        return self.exists_val


class _StubES:
    """In-memory dict of {index: {doc_id: source}} with the minimum ES API."""

    def __init__(self, *, exists: bool = True):
        self.indices = _StubIndices(exists=exists)
        self.store: dict[str, dict[str, dict]] = {}
        self.update_by_query_calls: list[dict] = []

    def get(self, *, index: str, id: str):
        idx = self.store.get(index) or {}
        if id not in idx:
            raise KeyError(id)
        return {"_source": dict(idx[id])}

    def index(self, *, index: str, id: str, document: dict, refresh=False):
        self.store.setdefault(index, {})[id] = dict(document)
        return {"result": "indexed"}

    def update_by_query(self, *, index: str, body: dict, refresh=True, conflicts="proceed"):
        # Naive implementation: parse must_not -> last_run_id != X, bump
        # silent_runs_current on the remaining docs.
        self.update_by_query_calls.append({"index": index, "body": body})
        must_not = ((body.get("query") or {}).get("bool") or {}).get("must_not") or []
        exclude_run = None
        for clause in must_not:
            term = clause.get("term") or {}
            if "last_run_id" in term:
                exclude_run = term["last_run_id"]
        idx = self.store.get(index) or {}
        updated = 0
        for src in idx.values():
            if exclude_run is not None and src.get("last_run_id") == exclude_run:
                continue
            src["silent_runs_current"] = int(src.get("silent_runs_current", 0)) + 1
            updated += 1
        return {"updated": updated}


def _snap(run_id: str, ts: str, sc: int = 5, ic: int = 2) -> dict:
    return {
        "run_id": run_id,
        "@timestamp": ts,
        "session_count": sc,
        "ip_count": ic,
        "mean_novelty": 0.5,
        "dominant_intent": "exec",
        "asn_top": "12345",
        "asn_distribution": {"12345": ic},
    }


# -----------------------------------------------------------------------------
# [1] 3-run sequence on same playbook → snapshots accumulate, counters move.
# -----------------------------------------------------------------------------
print("\n[1] 3-run snapshot accumulation on a single playbook")
es = _StubES()
PB = "sescl-0000aaaa"
IDX = "lifecycle-dshield.cowrie.playbook-default"

update_playbook_lifecycle(es, IDX, playbook_id=PB, playbook_name="dropper-a",
                          run_id="run-1", snapshot=_snap("run-1", "2026-05-20T00:00:00+00:00"))
update_playbook_lifecycle(es, IDX, playbook_id=PB, playbook_name="dropper-a",
                          run_id="run-2", snapshot=_snap("run-2", "2026-05-20T06:00:00+00:00", sc=7))
update_playbook_lifecycle(es, IDX, playbook_id=PB, playbook_name="dropper-a-v2",
                          run_id="run-3", snapshot=_snap("run-3", "2026-05-20T12:00:00+00:00", sc=4))

doc = es.store[IDX][PB]
check("3 snapshots accumulated", len(doc["snapshots"]) == 3, f"got {len(doc['snapshots'])}")
check("first_seen_ever == first run ts", doc["first_seen_ever"] == "2026-05-20T00:00:00+00:00")
check("last_seen == third run ts", doc["last_seen"] == "2026-05-20T12:00:00+00:00")
check("first_run_id pinned", doc["first_run_id"] == "run-1")
check("last_run_id moves", doc["last_run_id"] == "run-3")
check("runs_observed == 3", doc["runs_observed"] == 3, f"got {doc['runs_observed']}")
check("silent_runs_current == 0 after touching", doc["silent_runs_current"] == 0)
check("snapshot order preserved", [s["run_id"] for s in doc["snapshots"]] == ["run-1", "run-2", "run-3"])
check("playbook_name refreshed on each write", doc["playbook_name"] == "dropper-a-v2",
      f"got {doc['playbook_name']!r}")


# -----------------------------------------------------------------------------
# [2] Snapshot rotation: cap=5, push 8 → keep last 5 only.
# -----------------------------------------------------------------------------
print("\n[2] snapshot cap rotation")
es = _StubES()
for i in range(1, 9):
    update_playbook_lifecycle(es, IDX, playbook_id=PB, playbook_name="x",
                              run_id=f"run-{i}",
                              snapshot=_snap(f"run-{i}", f"2026-05-20T{i:02d}:00:00+00:00"),
                              snapshot_cap=5)
doc = es.store[IDX][PB]
ids = [s["run_id"] for s in doc["snapshots"]]
check("5 snapshots kept after cap", len(doc["snapshots"]) == 5, f"got {len(doc['snapshots'])}")
check("oldest 3 dropped", ids == ["run-4", "run-5", "run-6", "run-7", "run-8"], f"got {ids}")
check("runs_observed counts all 8 writes", doc["runs_observed"] == 8, f"got {doc['runs_observed']}")


# -----------------------------------------------------------------------------
# [3] silent-run bump: touch PB-A this run, leave PB-B stale.
# -----------------------------------------------------------------------------
print("\n[3] increment_silent_runs only bumps stale docs")
es = _StubES()
update_playbook_lifecycle(es, IDX, playbook_id="sescl-aaaa", playbook_name="a",
                          run_id="run-X", snapshot=_snap("run-X", "2026-05-20T00:00:00+00:00"))
update_playbook_lifecycle(es, IDX, playbook_id="sescl-bbbb", playbook_name="b",
                          run_id="run-X", snapshot=_snap("run-X", "2026-05-20T00:00:00+00:00"))
# Next "run" — only A is touched
update_playbook_lifecycle(es, IDX, playbook_id="sescl-aaaa", playbook_name="a",
                          run_id="run-Y", snapshot=_snap("run-Y", "2026-05-20T06:00:00+00:00"))

updated = increment_silent_runs(es, IDX, current_run_id="run-Y")
check("1 doc bumped (sescl-bbbb)", updated == 1, f"got {updated}")
check("sescl-bbbb silent_runs_current == 1",
      es.store[IDX]["sescl-bbbb"]["silent_runs_current"] == 1)
check("sescl-aaaa silent_runs_current still 0",
      es.store[IDX]["sescl-aaaa"]["silent_runs_current"] == 0)

# Another silent pass without touching B again → counter goes to 2
updated2 = increment_silent_runs(es, IDX, current_run_id="run-Z")
check("both stale on run-Z (A also no-touch) → 2 docs bumped", updated2 == 2,
      f"got {updated2}")
check("sescl-bbbb silent_runs_current == 2 now",
      es.store[IDX]["sescl-bbbb"]["silent_runs_current"] == 2)


# -----------------------------------------------------------------------------
# [4] Campaign upsert: campaign_kind / campaign_name carried + refreshed.
# -----------------------------------------------------------------------------
print("\n[4] campaign lifecycle upsert")
es = _StubES()
CIDX = "lifecycle-dshield.cowrie.campaign-default"
CID = "cmp-bhv-cafe1234"
update_campaign_lifecycle(es, CIDX, campaign_id=CID,
                          campaign_name="droppers-2026q2",
                          campaign_kind="behaviour",
                          run_id="run-1",
                          snapshot=_snap("run-1", "2026-05-20T00:00:00+00:00"))
update_campaign_lifecycle(es, CIDX, campaign_id=CID,
                          campaign_name="droppers-2026q2-rev",
                          campaign_kind="behaviour",
                          run_id="run-2",
                          snapshot=_snap("run-2", "2026-05-20T06:00:00+00:00"))
doc = es.store[CIDX][CID]
check("campaign_name refreshed", doc["campaign_name"] == "droppers-2026q2-rev")
check("campaign_kind preserved", doc["campaign_kind"] == "behaviour")
check("2 campaign snapshots", len(doc["snapshots"]) == 2)
check("campaign confirm_anchors[] initialised empty", doc.get("confirm_anchors") == [])


# -----------------------------------------------------------------------------
# [5] Source-IP upsert: NO confirm_anchors[], NO drift_suppressions[].
# -----------------------------------------------------------------------------
print("\n[5] source-IP lifecycle has no anchor/suppression fields")
es = _StubES()
IIDX = "lifecycle-dshield.cowrie.source_ip-default"
IP = "203.0.113.5"
update_source_ip_lifecycle(es, IIDX, source_ip=IP,
                           run_id="run-1",
                           snapshot={
                               "run_id": "run-1",
                               "@timestamp": "2026-05-20T00:00:00+00:00",
                               "session_count": 3,
                               "dominant_playbook_id": "sescl-aaaa",
                               "playbook_distribution": {"sescl-aaaa": 3},
                               "intel_verdict": "no_data",
                               "intel_consensus_score": 0.0,
                               "asn": 12345,
                               "geo_country": "US",
                           })
doc = es.store[IIDX][IP]
check("source_ip key set", doc["source_ip"] == IP)
check("no confirm_anchors field", "confirm_anchors" not in doc, f"got keys: {list(doc.keys())}")
check("no drift_suppressions field", "drift_suppressions" not in doc)
check("snapshot has playbook_distribution",
      doc["snapshots"][0]["playbook_distribution"] == {"sescl-aaaa": 3})


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
