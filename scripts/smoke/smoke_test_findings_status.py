"""Smoke test for `enrich.findings.writer.mutate_status` — analyst-state
preservation across re-mines and the status workflow.

Uses an in-memory fake ES client so this can run anywhere.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_findings_status.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.writer import (  # noqa: E402
    bulk_upsert_findings, finding_id, mutate_status,
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


class FakeIndices:
    def __init__(self, store):
        self._store = store

    def exists(self, index):
        return True

    def refresh(self, index):
        pass


class FakeES:
    """Minimal in-memory ES stand-in. Implements the surface the writer
    actually touches: get, index, mget, and helpers.bulk via a side door."""

    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.indices = FakeIndices(self.docs)

    def get(self, index, id):
        if id not in self.docs:
            raise LookupError(f"not found: {id}")
        return {"_id": id, "_index": index, "_source": dict(self.docs[id])}

    def index(self, index, id, document, refresh=False):
        self.docs[id] = dict(document)
        return {"_id": id, "result": "indexed"}

    def mget(self, index, ids, _source=None):
        out = []
        for i in ids:
            if i in self.docs:
                out.append({"_id": i, "found": True, "_source": dict(self.docs[i])})
            else:
                out.append({"_id": i, "found": False})
        return {"docs": out}


# Patch the elasticsearch helpers.bulk used by writer.bulk_upsert_findings.
import enrich.findings.writer as writer_mod  # noqa: E402


def _fake_bulk(es, actions, raise_on_error=True, request_timeout=60):
    n = 0
    for a in actions:
        if a.get("_op_type") == "index":
            es.docs[a["_id"]] = dict(a["_source"])
            n += 1
    return (n, [])


writer_mod.bulk = _fake_bulk  # type: ignore[assignment]


print("[1] bulk_upsert creates fresh docs with status=new")
es = FakeES()
findings = [
    {
        "kind": "playbook",
        "run_id": "r-1",
        "artifact": {"kind": "playbook", "value": "sescl-0123456789abcdef"},
        "score": 1.40,
        "narrative": "Mirai-style — 42 sessions",
        "evidence": {"member_sessions": 42, "mean_novelty": 0.31},
    },
    {
        "kind": "campaign",
        "run_id": "r-1",
        "artifact": {"kind": "campaign", "value": "cmp-beh-0123456789abcdef"},
        "score": 6.0,
        "narrative": "behaviour — 30 sessions across 12 IPs",
        "evidence": {"member_sessions": 30, "member_ips": 12},
    },
]
n = bulk_upsert_findings(es, "findings-idx", findings)
check("bulk indexed two docs", n == 2, f"n={n}")
fid_pb = finding_id("playbook", "playbook", "sescl-0123456789abcdef")
fid_cmp = finding_id("campaign", "campaign", "cmp-beh-0123456789abcdef")
check("playbook finding stored", fid_pb in es.docs)
check("campaign finding stored", fid_cmp in es.docs)
check("fresh status is 'new'", es.docs[fid_pb]["status"] == "new")
check("fresh status_history is empty", es.docs[fid_pb]["status_history"] == [])
check("first_seen_at set", bool(es.docs[fid_pb]["first_seen_at"]))


print("\n[2] mutate_status records a history entry")
updated = mutate_status(es, "findings-idx", fid_pb, new_status="ack", note="reviewing")
check("status mutated", updated["status"] == "ack")
check("history length 1", len(updated["status_history"]) == 1)
entry = updated["status_history"][0]
check("history.from = new", entry["from"] == "new")
check("history.to = ack", entry["to"] == "ack")
check("history.note carried", entry["note"] == "reviewing")
check("history.ts present", bool(entry.get("ts")))


print("\n[3] re-mine after status change does NOT overwrite status")
first_seen = es.docs[fid_pb]["first_seen_at"]
findings_remine = [
    {
        "kind": "playbook",
        "run_id": "r-2",
        "artifact": {"kind": "playbook", "value": "sescl-0123456789abcdef"},
        "score": 1.82,   # fresh score
        "narrative": "Mirai-style — 80 sessions",
        "evidence": {"member_sessions": 80, "mean_novelty": 0.42},
    },
]
bulk_upsert_findings(es, "findings-idx", findings_remine)
doc = es.docs[fid_pb]
check("status preserved across re-mine", doc["status"] == "ack")
check("history preserved across re-mine", len(doc["status_history"]) == 1)
check("first_seen_at preserved", doc["first_seen_at"] == first_seen)
check("score updated by re-mine", abs(doc["score"] - 1.82) < 1e-6)
check("narrative updated by re-mine", doc["narrative"] == "Mirai-style — 80 sessions")
check("evidence updated by re-mine",
      doc["evidence"]["member_sessions"] == 80)


print("\n[4] mutate_status rejects invalid statuses")
try:
    mutate_status(es, "findings-idx", fid_pb, new_status="bogus")
    check("invalid status raises", False, "no exception")
except ValueError:
    check("invalid status raises", True)


print("\n[5] mutate_status on missing finding raises LookupError")
try:
    mutate_status(es, "findings-idx", "find-nonexistent", new_status="ack")
    check("missing finding raises", False, "no exception")
except LookupError:
    check("missing finding raises", True)


print("\n[6] same-status no-op does not append a history entry")
prev_history_len = len(es.docs[fid_pb]["status_history"])
mutate_status(es, "findings-idx", fid_pb, new_status="ack")  # already ack
check("history unchanged on same-status",
      len(es.docs[fid_pb]["status_history"]) == prev_history_len)


print(f"\n--- {len(PASSED)} passed, {len(FAILED)} failed ---")
if FAILED:
    for name, detail in FAILED:
        print(f"  FAILED  {name}  {detail}")
    sys.exit(1)
