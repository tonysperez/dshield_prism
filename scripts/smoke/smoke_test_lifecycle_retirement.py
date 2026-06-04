"""Lifecycle retirement sweep — hard-deletes docs past the silent-run
threshold.

Long-silent lifecycle docs accumulate forever in the source-IP index
(every IP that ever appeared) and gradually in the playbook/campaign
indices (anything retired). `retire_silent_lifecycles` is the
delete-by-query that bounds that growth: any doc whose
`silent_runs_current` reaches the per-layer threshold is hard-deleted; a
re-emergence mints a fresh doc through the normal path.

Scenarios:
  [1] docs below threshold survive; docs at/above threshold are deleted
  [2] threshold=0 disables the sweep (no deletes regardless of state)
  [3] missing index returns 0, no exception
  [4] stats counter matches actual deletes

Standalone — no real ES, no pytest.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.lifecycle import retire_silent_lifecycles

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
    def __init__(self, exists: bool = True):
        self._exists = exists

    def exists(self, *, index: str) -> bool:
        return self._exists


class _StubES:
    """In-memory dict of {index: {doc_id: source}} supporting
    delete_by_query on a `range` clause over `silent_runs_current`."""

    def __init__(self, exists: bool = True):
        self.indices = _StubIndices(exists)
        self.store: dict[str, dict[str, dict]] = {}

    def delete_by_query(self, *, index: str, body: dict, conflicts="proceed", refresh=True):
        rng = ((body.get("query") or {}).get("range") or {}).get("silent_runs_current") or {}
        gte = rng.get("gte")
        if gte is None:
            return {"deleted": 0}
        idx = self.store.get(index) or {}
        to_delete = [did for did, src in idx.items()
                     if int(src.get("silent_runs_current") or 0) >= int(gte)]
        for did in to_delete:
            del idx[did]
        return {"deleted": len(to_delete)}


IDX = "lifecycle-dshield.cowrie.playbook-default"


# [1] Threshold partition.
print("\n[1] Docs at/above threshold are deleted; below survive")
es = _StubES()
es.store[IDX] = {
    "spb-active":     {"silent_runs_current": 0},
    "spb-warm":       {"silent_runs_current": 50},
    "spb-borderline": {"silent_runs_current": 119},
    "spb-stale-a":    {"silent_runs_current": 120},
    "spb-stale-b":    {"silent_runs_current": 240},
    "spb-no-field":   {},
}
deleted = retire_silent_lifecycles(es, IDX, threshold=120)
check("returns deleted count", deleted == 2, f"got {deleted}")
remaining = set(es.store[IDX].keys())
check("active doc survives", "spb-active" in remaining)
check("warm doc survives", "spb-warm" in remaining)
check("borderline (just below) survives", "spb-borderline" in remaining)
check("at-threshold deleted", "spb-stale-a" not in remaining)
check("above-threshold deleted", "spb-stale-b" not in remaining)
check("missing-field doc survives (treated as 0)", "spb-no-field" in remaining)

# [2] threshold=0 disables.
print("\n[2] threshold=0 disables the sweep")
es = _StubES()
es.store[IDX] = {
    "spb-stale": {"silent_runs_current": 9999},
}
deleted = retire_silent_lifecycles(es, IDX, threshold=0)
check("zero threshold returns 0", deleted == 0, f"got {deleted}")
check("nothing deleted on threshold=0", "spb-stale" in es.store[IDX])

# [3] Missing index → 0, no exception.
print("\n[3] Missing index returns 0")
es = _StubES(exists=False)
deleted = retire_silent_lifecycles(es, IDX, threshold=10)
check("missing index returns 0", deleted == 0, f"got {deleted}")

# [4] Stats counter parity.
print("\n[4] Returned count matches store delta")
es = _StubES()
es.store[IDX] = {f"spb-{i:04d}": {"silent_runs_current": 200} for i in range(7)}
before = len(es.store[IDX])
deleted = retire_silent_lifecycles(es, IDX, threshold=120)
after = len(es.store[IDX])
check("delta matches return", before - after == deleted == 7, f"before={before} after={after} ret={deleted}")


print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
sys.exit(1 if FAILED else 0)
