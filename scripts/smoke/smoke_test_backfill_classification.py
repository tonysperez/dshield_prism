"""Smoke test for the classification-backfill query builder
(`scripts/backfill_classification.py::build_backfill_query`). The stickiness rules are the
safety property: `public` only ever tags untagged docs; `confidential` never matches an
already-confidential doc. No ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from backfill_classification import build_backfill_query

KW = "dshield.classification.keyword"
PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# --- public: only untagged docs (never downgrade) ---
q = build_backfill_query("public", sensor=None, has_observer=False)
filters = q["bool"]["filter"]
check("public: matches only docs with no classification (must_not exists)",
      filters[0] == {"bool": {"must_not": {"exists": {"field": KW}}}}, str(filters))
check("public, no sensor → single filter (no observer term)", len(filters) == 1, str(filters))

# --- confidential: anything not already confidential ---
qc = build_backfill_query("confidential", sensor=None, has_observer=False)
check("confidential: matches docs not already confidential (must_not term)",
      qc["bool"]["filter"][0] == {"bool": {"must_not": {"term": {KW: "confidential"}}}},
      str(qc))

# --- sensor scoping only when the index carries observer.name ---
qs = build_backfill_query("public", sensor="sensor-A", has_observer=True)
check("sensor + has_observer → adds observer.name term",
      {"term": {"observer.name": "sensor-A"}} in qs["bool"]["filter"], str(qs))
qns = build_backfill_query("public", sensor="sensor-A", has_observer=False)
check("sensor but NO observer → no observer term (IP-rollup case)",
      all("term" not in f for f in qns["bool"]["filter"]), str(qns))
check("whole-corpus (sensor=None) never scopes by observer",
      len(build_backfill_query("public", sensor=None, has_observer=True)["bool"]["filter"]) == 1)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
