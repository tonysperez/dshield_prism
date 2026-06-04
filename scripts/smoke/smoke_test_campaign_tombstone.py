"""Campaign replace — orphan-tombstone instead of delete-all-then-bulk (P3.2).

`mine campaigns` used to `delete_by_query` every `kind` doc, THEN bulk the
new run — a crash between the two empties the campaigns index until the next
6 h cycle (the console reads "no campaigns"). `_replace_campaign_docs`
upserts the current run FIRST, then tombstones only the `campaign_id`s absent
from this run (the findings-miner pattern) — so there is never an empty
window.

Scenarios:
  [1] orphan tombstoned, live preserved; upsert happens BEFORE delete; the
      delete excludes the current ids (so the just-written docs survive)
  [2] empty run → no-op (no bulk, no delete) — never wipe on a degraded run
  [3] kind scoping — infrastructure replace only sweeps kind=infrastructure
  [4] docs without an _id are excluded from the keep set

Stubs ES offline: monkeypatches the module-level `bulk` (so helpers.bulk is
intercepted) and a stub `delete_by_query`. Same approach family as
smoke_test_findings_tombstone.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_campaign_tombstone.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import enrich.sources.cowrie.campaigns as camp


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


EVENTS: list[str] = []
BULK_CALLS: list[dict] = []


def _fake_bulk(es, docs, **kw):
    """Intercept helpers.bulk used inside campaigns.py."""
    EVENTS.append("bulk")
    BULK_CALLS.append({"docs": list(docs), "refresh": kw.get("refresh")})
    return (len(BULK_CALLS[-1]["docs"]), [])


camp.bulk = _fake_bulk


class _StubES:
    def __init__(self, *, deleted=0):
        self.deletes: list[dict] = []
        self._deleted = deleted

    def delete_by_query(self, *, index, body, refresh=False, conflicts="proceed"):
        EVENTS.append("delete")
        self.deletes.append({"index": index, "body": body})
        return {"deleted": self._deleted}


def _doc(cid: str, kind: str) -> dict:
    return {
        "_index": "prism.campaign.cowrie",
        "_id":    cid,
        "_source": {"doc_type": "campaign", "campaign_id": cid, "kind": kind},
    }


def _reset() -> None:
    EVENTS.clear()
    BULK_CALLS.clear()


# -----------------------------------------------------------------------------
# [1] orphan tombstoned, live preserved, upsert BEFORE delete.
# -----------------------------------------------------------------------------
print("\n[1] orphan tombstoned; live preserved; upsert precedes delete")
_reset()
es = _StubES(deleted=1)  # ES reports 1 orphan removed (the vanished campaign)
docs = [_doc("cmp-bhv-A", "behaviour"), _doc("cmp-bhv-B", "behaviour")]
res = camp._replace_campaign_docs(es, "prism.campaign.cowrie", "behaviour", docs,
                                  label="mine behaviour")
check("upserted count", res["upserted"] == 2, f"got {res}")
check("orphans_deleted count", res["orphans_deleted"] == 1, f"got {res}")
check("upsert happens BEFORE delete (no empty window)",
      EVENTS == ["bulk", "delete"], f"got {EVENTS}")
check("upsert refreshed so current docs are visible",
      BULK_CALLS[0]["refresh"] is True)
q = es.deletes[0]["body"]["query"]["bool"]
musts = {tuple(t["term"].items())[0] for t in q["must"]}
check("delete is scoped to doc_type=campaign + kind=behaviour",
      ("doc_type", "campaign") in musts and ("kind", "behaviour") in musts, f"got {musts}")
kept = set(q["must_not"][0]["terms"]["campaign_id"])
check("delete excludes the current ids (live campaigns survive)",
      kept == {"cmp-bhv-A", "cmp-bhv-B"}, f"got {kept}")


# -----------------------------------------------------------------------------
# [2] empty run → no bulk, no delete (degraded-run safety).
# -----------------------------------------------------------------------------
print("\n[2] empty run → no-op (never wipe on a degraded run)")
_reset()
es = _StubES(deleted=999)
res = camp._replace_campaign_docs(es, "prism.campaign.cowrie", "behaviour", [],
                                  label="mine behaviour")
check("nothing upserted/deleted", res == {"upserted": 0, "orphans_deleted": 0}, f"got {res}")
check("no bulk and no delete issued", EVENTS == [], f"got {EVENTS}")
check("stub recorded no delete_by_query", es.deletes == [])


# -----------------------------------------------------------------------------
# [3] infrastructure kind scoping.
# -----------------------------------------------------------------------------
print("\n[3] infrastructure replace sweeps only kind=infrastructure")
_reset()
es = _StubES(deleted=0)
res = camp._replace_campaign_docs(
    es, "prism.campaign.cowrie", "infrastructure",
    [_doc("cmp-inf-1", "infrastructure")], label="mine infra")
q = es.deletes[0]["body"]["query"]["bool"]
kind_term = next(t["term"]["kind"] for t in q["must"] if "kind" in t["term"])
check("kind term is infrastructure", kind_term == "infrastructure", f"got {kind_term}")
check("returns upserted=1", res["upserted"] == 1, f"got {res}")


# -----------------------------------------------------------------------------
# [4] docs lacking an _id are excluded from the keep set.
# -----------------------------------------------------------------------------
print("\n[4] malformed doc without _id is excluded from the keep set")
_reset()
es = _StubES(deleted=0)
docs = [_doc("cmp-bhv-A", "behaviour"),
        {"_index": "prism.campaign.cowrie",
         "_source": {"doc_type": "campaign", "kind": "behaviour"}}]  # no _id
res = camp._replace_campaign_docs(es, "prism.campaign.cowrie", "behaviour", docs,
                                  label="mine behaviour")
kept = set(es.deletes[0]["body"]["query"]["bool"]["must_not"][0]["terms"]["campaign_id"])
check("only the doc with an _id is in the keep set", kept == {"cmp-bhv-A"}, f"got {kept}")
check("upserted counts only ided docs", res["upserted"] == 1, f"got {res}")


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
