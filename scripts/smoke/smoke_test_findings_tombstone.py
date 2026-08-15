"""Findings tombstone sweep — orphan finding garbage collection.

Content-addressed playbook_id / campaign_id values shift across
clustering passes (membership re-forms → new content hash). The miner
preserves analyst state on living artifacts, but findings whose
underlying artifact has vanished pile up and cause Findings/Insights
divergence. `_tombstone_orphan_findings` deletes them on every
`mine findings` pass.

Scenarios:
  [1] orphan campaign finding deleted; live one preserved
  [2] empty live set → skip (defends against degraded mining run)
  [3] mixed kinds — only the targeted artifact_kinds are touched
  [4] no orphans → 0 deletions

Stubs ES so the test is offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_findings_tombstone.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.miner import _tombstone_orphan_findings

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _StubES:
    """Records every delete_by_query payload so we can introspect what
    would have been deleted."""
    def __init__(self, *, deleted_per_call: list[int] | None = None):
        self.calls: list[dict] = []
        self.deleted_per_call = deleted_per_call or []
        self._idx = 0
    def delete_by_query(self, *, index, body, conflicts="proceed", refresh=False):
        self.calls.append({"index": index, "body": body})
        n = self.deleted_per_call[self._idx] if self._idx < len(self.deleted_per_call) else 0
        self._idx += 1
        return {"deleted": n}


def _f(kind: str, akind: str, avalue: str) -> dict:
    return {"kind": kind, "artifact": {"kind": akind, "value": avalue}}


# -----------------------------------------------------------------------------
# [1] orphan campaign deleted; live campaign preserved.
# -----------------------------------------------------------------------------
print("\n[1] orphan campaign tombstoned, live one survives")
es = _StubES(deleted_per_call=[3])  # ES reports 3 orphans deleted
this_run = [
    _f("campaign", "campaign", "cmp-live-1"),
    _f("campaign", "campaign", "cmp-live-2"),
    _f("playbook", "playbook", "sescl-live-A"),
]
deleted = _tombstone_orphan_findings(
    es, "prism.finding", this_run, artifact_kinds=("playbook", "campaign"),
)
check("returned the delete count", deleted == 3, f"got {deleted}")
check("2 delete_by_query calls issued (one per artifact_kind)",
      len(es.calls) == 2, f"got {len(es.calls)}")
# Verify the campaign-kind delete excludes the live ids.
cmp_call = next(c for c in es.calls
                if c["body"]["query"]["bool"]["must"][0]["term"]["artifact.kind"] == "campaign")
excluded = set(cmp_call["body"]["query"]["bool"]["must_not"][0]["terms"]["artifact.value"])
check("campaign delete excludes both live campaign ids",
      excluded == {"cmp-live-1", "cmp-live-2"})
pb_call = next(c for c in es.calls
               if c["body"]["query"]["bool"]["must"][0]["term"]["artifact.kind"] == "playbook")
pb_excluded = set(pb_call["body"]["query"]["bool"]["must_not"][0]["terms"]["artifact.value"])
check("playbook delete excludes the live playbook id",
      pb_excluded == {"sescl-live-A"})


# -----------------------------------------------------------------------------
# [2] empty live set → safety skip (don't wipe everything on a degraded run).
# -----------------------------------------------------------------------------
print("\n[2] empty live set → no delete_by_query issued")
es = _StubES(deleted_per_call=[])
this_run: list = []  # nothing mined this run
deleted = _tombstone_orphan_findings(
    es, "prism.finding", this_run, artifact_kinds=("playbook", "campaign"),
)
check("nothing deleted", deleted == 0)
check("no delete_by_query call issued for either kind",
      es.calls == [], f"got {es.calls}")


# -----------------------------------------------------------------------------
# [3] partial live — playbook has live, campaign empty → only playbook scanned.
# -----------------------------------------------------------------------------
print("\n[3] partial live: only the kinds with live members are scanned")
es = _StubES(deleted_per_call=[1])
this_run = [_f("playbook", "playbook", "sescl-only")]
deleted = _tombstone_orphan_findings(
    es, "prism.finding", this_run, artifact_kinds=("playbook", "campaign"),
)
check("1 delete (playbook scan only)", deleted == 1)
check("only 1 delete_by_query call issued", len(es.calls) == 1)
check("call was for playbook artifact_kind",
      es.calls[0]["body"]["query"]["bool"]["must"][0]["term"]["artifact.kind"] == "playbook")


# -----------------------------------------------------------------------------
# [4] no orphans (ES reports 0 deleted) → still safe.
# -----------------------------------------------------------------------------
print("\n[4] no orphans → total deleted == 0")
es = _StubES(deleted_per_call=[0, 0])
this_run = [
    _f("playbook", "playbook", "sescl-A"),
    _f("campaign", "campaign", "cmp-A"),
]
deleted = _tombstone_orphan_findings(
    es, "prism.finding", this_run, artifact_kinds=("playbook", "campaign"),
)
check("0 deleted reported", deleted == 0)
check("both kind scans still issued (proves we checked, found nothing)",
      len(es.calls) == 2)


# -----------------------------------------------------------------------------
# [5] artifact_kinds restricts scope — ip-keyed findings never tombstoned.
# -----------------------------------------------------------------------------
print("\n[5] artifact_kinds=('campaign',) leaves playbook + ip docs alone")
es = _StubES(deleted_per_call=[2])
this_run = [
    _f("campaign", "campaign", "cmp-X"),
    _f("intel_verdict_flip", "ip", "1.1.1.1"),
    _f("playbook", "playbook", "sescl-Z"),
]
deleted = _tombstone_orphan_findings(
    es, "prism.finding", this_run, artifact_kinds=("campaign",),
)
check("only 1 delete_by_query issued (campaign only)", len(es.calls) == 1)
check("call was for campaign artifact_kind",
      es.calls[0]["body"]["query"]["bool"]["must"][0]["term"]["artifact.kind"] == "campaign")


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
