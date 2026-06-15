"""Smoke test for the consolidation engine's pure core
(`scripts/consolidation_engine.py`): nearest_other, compute_absorption (full
target distribution), propose_edges, tfidf_gate, select_merges, resolve_components.

Scenario (every number hand-computed):
  A's 10 sessions: 4 absorb into B (0.96), 3 into Z (0.95), 3 stay (0.50).
    → A targets B@0.4, Z@0.3 ; absorption_rate 0.7
  B → A @1.0 ; C → D @1.0 ; D → C @1.0
  TF-IDF: A↔B close (0.90 → confirm), A↔Z far (0.60 → conflation), C↔D far (reject)

  Expected: merge {A,B} (via strong B→A; canonical A = larger); A→B@0.4 is partial
  overlap (TF-IDF-close but < merge_min); A→Z surfaces as a *secondary* conflation
  (the gap the old dominant-only engine missed); C↔D rejected.

Standalone — no pytest, no ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from consolidation_engine import (
    compute_absorption,
    nearest_other,
    propose_edges,
    resolve_components,
    select_merges,
    tfidf_gate,
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


# --- nearest_other: exclude the session's own source anchor ---
sims = np.array([[0.90, 0.96, 0.30],
                 [0.95, 0.90, 0.20]], dtype=np.float32)
oi, oc = nearest_other(sims, np.array([0, 1]))
check("nearest_other idx == [1,0]", list(oi) == [1, 0], str(oi))
check("nearest_other cos == [0.96,0.95]", np.allclose(oc, [0.96, 0.95]), str(oc))

# --- absorption with full target distribution ---
source_ids = ["A"] * 10 + ["B"] * 10 + ["C"] * 10 + ["D"] * 10
target_ids = (["B"] * 4 + ["Z"] * 3 + ["Q"] * 3) + ["A"] * 10 + ["D"] * 10 + ["C"] * 10
target_cos = ([0.96] * 4 + [0.95] * 3 + [0.50] * 3) + [0.95] * 10 + [0.97] * 10 + [0.97] * 10

absorption = compute_absorption(source_ids, target_ids, target_cos,
                                tau=0.94, min_sessions=5, min_edge=0.15)
check("A absorption_rate == 0.7", absorption["A"]["absorption_rate"] == 0.7, str(absorption["A"]))
check("A targets == [B@0.4, Z@0.3] (secondary target kept)",
      absorption["A"]["targets"] == [{"target": "B", "rate": 0.4}, {"target": "Z", "rate": 0.3}],
      str(absorption["A"]["targets"]))

small = compute_absorption(["E"] * 3, ["F"] * 3, [0.99] * 3, tau=0.94, min_sessions=5, min_edge=0.15)
check("anchor below min_sessions flagged small", small["E"]["small"] is True, str(small["E"]))

# --- edges → gate → split ---
edges = propose_edges(absorption)
check("5 candidate edges (incl A's secondary)", len(edges) == 5, str(edges))
check("A→Z secondary edge present", ("A", "Z", 0.3) in edges, str(edges))

tcos_map = {("A", "B"): 0.90, ("B", "A"): 0.90, ("A", "Z"): 0.60,
            ("C", "D"): 0.60, ("D", "C"): 0.60}
confirmed, rejected = tfidf_gate(edges, lambda a, b: tcos_map.get((a, b)), threshold=0.80)
check("confirmed == {A↔B}", {(e["x"], e["y"]) for e in confirmed} == {("A", "B"), ("B", "A")},
      str(confirmed))
check("A→Z surfaces as a (secondary) conflation",
      any(r["x"] == "A" and r["y"] == "Z" for r in rejected), str(rejected))
check("C↔D rejected as conflation", {("C", "D"), ("D", "C")} <= {(r["x"], r["y"]) for r in rejected})

merges, partial = select_merges(confirmed, merge_min=0.5)
check("only strong B→A drives the merge", [(e["x"], e["y"]) for e in merges] == [("B", "A")],
      str(merges))
check("weak A→B@0.4 is partial overlap (not a merge)",
      [(e["x"], e["y"]) for e in partial] == [("A", "B")], str(partial))

sizes = {"A": 1000, "B": 100, "C": 500, "D": 50}
groups = resolve_components(merges, sizes)
check("exactly one merge group", len(groups) == 1, str(groups))
check("canonical == A (largest)", groups[0]["canonical"] == "A", str(groups[0]))
check("members == [A,B]", groups[0]["members"] == ["A", "B"], str(groups[0]))
check("Z,C,D NOT merged",
      all(set(g["members"]).isdisjoint({"Z", "C", "D"}) for g in groups))

# canonical follows size, and transitive chains collapse
check("canonical flips to B when B is larger",
      resolve_components([{"x": "A", "y": "B"}], {"A": 100, "B": 1000})[0]["canonical"] == "B")
g3 = resolve_components([{"x": "A", "y": "B"}, {"x": "B", "y": "C"}], {"A": 5, "B": 9, "C": 1})
check("transitive chain A-B-C → one group of 3, canonical B",
      len(g3) == 1 and g3[0]["n_merged"] == 3 and g3[0]["canonical"] == "B", str(g3))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
