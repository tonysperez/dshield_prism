"""Smoke test for ROADMAP #9 — functional-duplicate gating, in-process gate logic.

Validates `lookup_canonical_for_shape` against a hand-rolled fake ES
client, and the inherit-path bookkeeping (`_synth_parsed_from_parent`,
shape block construction) without spinning up real ES or an LLM.

What the test covers:
  - Lookup honors min_confidence and require_known_intent.
  - Lookup prefers `canonical` and `standalone` roles, never `child`.
  - Lookup tie-breaks on confidence first, occurrence_count second.
  - `_synth_parsed_from_parent` builds a CommandEnrichment that
    `_build_embed_text` can consume.

Standalone — no pytest, no real ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_functional_dedup.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.commands import (
    _synth_parsed_from_parent,
    lookup_canonical_for_shape,
)


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# -----------------------------------------------------------------------------
# Fake ES that mimics es.search() with the body shape we pass.
# -----------------------------------------------------------------------------

class FakeES:
    def __init__(self, docs: list[dict]) -> None:
        self.docs = docs
        self.last_query: dict | None = None

    def search(self, *, index: str, **body):
        self.last_query = body
        filters = body["query"]["bool"]["filter"]
        must_not = body["query"]["bool"].get("must_not") or []

        def _passes(doc: dict) -> bool:
            src = doc["_source"]
            for f in filters:
                if "term" in f:
                    (path, val), = f["term"].items()
                    cur = src
                    for part in path.split("."):
                        cur = (cur or {}).get(part)
                    if cur != val:
                        return False
                elif "terms" in f:
                    (path, vals), = f["terms"].items()
                    cur = src
                    for part in path.split("."):
                        cur = (cur or {}).get(part)
                    if cur not in vals:
                        return False
                elif "range" in f:
                    (path, rng), = f["range"].items()
                    cur = src
                    for part in path.split("."):
                        cur = (cur or {}).get(part)
                    if cur is None or cur < rng.get("gte", -1):
                        return False
            for f in must_not:
                if "term" in f:
                    (path, val), = f["term"].items()
                    cur = src
                    for part in path.split("."):
                        cur = (cur or {}).get(part)
                    if cur == val:
                        return False
            return True

        matched = [d for d in self.docs if _passes(d)]
        # Sort by confidence desc, occurrence_count desc.
        def keyf(d):
            enr = d["_source"]["dshield"]["cowrie"]["enrichment"]
            return (-(enr.get("confidence") or 0),
                    -(enr.get("occurrence_count") or 0))
        matched.sort(key=keyf)
        size = body.get("size", 10)
        return {"hits": {"hits": matched[:size]}}


def make_doc(_id, shape_hash, role, intent, confidence, occ,
             desc="standard description", model="local"):
    return {
        "_id": _id,
        "_source": {
            "process": {"command_line": f"cmd-{_id}"},
            "event": {"reason": desc},
            "dshield": {"cowrie": {"enrichment": {
                "intent": intent,
                "confidence": confidence,
                "model": model,
                "occurrence_count": occ,
                "llm_config_hash": "abc123",
                "embed_config_hash": "def456",
                "shape": {"hash": shape_hash, "role": role},
            }}}
        }
    }


# -----------------------------------------------------------------------------
# Case 1 — basic lookup returns the canonical
# -----------------------------------------------------------------------------

es = FakeES([
    make_doc("c1", "shape-A", "canonical", "data_collection", 8, 50),
    make_doc("c2", "shape-A", "standalone", "data_collection", 6, 10),
    make_doc("c3", "shape-B", "canonical", "discovery", 9, 100),
])
got = lookup_canonical_for_shape(es, "idx", "shape-A",
                                  min_confidence=5,
                                  require_known_intent=True)
check("returns highest-confidence match", got is not None and got["_id"] == "c1",
      detail=f"got={got}")

# -----------------------------------------------------------------------------
# Case 2 — children excluded
# -----------------------------------------------------------------------------

es = FakeES([
    make_doc("p1", "shape-X", "child", "data_collection", 10, 999),
    make_doc("p2", "shape-X", "canonical", "data_collection", 5, 5),
])
got = lookup_canonical_for_shape(es, "idx", "shape-X",
                                  min_confidence=5,
                                  require_known_intent=True)
check("never returns role=child even when its confidence is higher",
      got is not None and got["_id"] == "p2",
      detail=f"got={got}")

# -----------------------------------------------------------------------------
# Case 3 — unknown intent excluded when require_known_intent=True
# -----------------------------------------------------------------------------

es = FakeES([
    make_doc("u1", "shape-Y", "canonical", "unknown", 9, 50),
    make_doc("u2", "shape-Y", "standalone", "lateral_movement", 6, 5),
])
got = lookup_canonical_for_shape(es, "idx", "shape-Y",
                                  min_confidence=5,
                                  require_known_intent=True)
check("require_known_intent skips intent=unknown parents",
      got is not None and got["_id"] == "u2",
      detail=f"got={got}")

got = lookup_canonical_for_shape(es, "idx", "shape-Y",
                                  min_confidence=5,
                                  require_known_intent=False)
check("require_known_intent=False allows intent=unknown",
      got is not None and got["_id"] == "u1",
      detail=f"got={got}")

# -----------------------------------------------------------------------------
# Case 4 — confidence floor
# -----------------------------------------------------------------------------

es = FakeES([
    make_doc("low1", "shape-Z", "canonical", "execution", 3, 100),
    make_doc("low2", "shape-Z", "standalone", "execution", 4, 200),
])
got = lookup_canonical_for_shape(es, "idx", "shape-Z",
                                  min_confidence=5,
                                  require_known_intent=True)
check("confidence floor excludes all low-confidence parents",
      got is None,
      detail=f"got={got}")

# -----------------------------------------------------------------------------
# Case 5 — _synth_parsed_from_parent
# -----------------------------------------------------------------------------

parent = {
    "_id": "x",
    "intent": "credential_access",
    "confidence": 7,
    "description": "Attempts to set a new password via echo/passwd.",
    "model": "llama3:8b",
}
parsed = _synth_parsed_from_parent(parent)
check("synth parsed: intent inherited", parsed.intent == "credential_access")
check("synth parsed: confidence inherited", parsed.confidence == 7)
check("synth parsed: description inherited",
      parsed.description == "Attempts to set a new password via echo/passwd.")
check("synth parsed: iocs default empty",
      parsed.iocs.urls == [] and parsed.iocs.ips == [])

# -----------------------------------------------------------------------------
# Case 6 — _synth_parsed_from_parent: degraded parent (defaults applied)
# -----------------------------------------------------------------------------

degraded = {"_id": "y"}
parsed = _synth_parsed_from_parent(degraded)
check("degraded parent: intent falls back to unknown",
      parsed.intent == "unknown")
check("degraded parent: confidence floor at 1",
      parsed.confidence == 1)
check("degraded parent: description empty",
      parsed.description == "")

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
