"""ROADMAP #4 — cluster specificity scoring (offline).

`specificity_scores(df_by_key, total_clusters)` assigns each IP / command an
IDF-shape distinctiveness score in [0, 1]: a key in one cluster ≈ 1.0, a key
spanning ~every cluster ≈ 0. Persisted per centroid doc as ip_specificity /
command_specificity and read by the console drawer + /distinctive pivot.

Scenarios (pure helper, no ES):
  [1] ubiquitous key (df = C) scores exactly 0
  [2] singleton key (df = 1) scores exactly 1.0 regardless of corpus size
  [3] strictly monotonic: smaller df → higher score
  [4] all scores stay within [0, 1]
  [5] degenerate inputs (C <= 1) don't blow up — return zeros

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_cluster_specificity.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import specificity_scores

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASSED.append(name) if cond else FAILED.append((name, detail)))


# [1] ubiquitous key → 0
s = specificity_scores({"x": 30}, 30)
check("1 ubiquitous key scores 0", s["x"] == 0.0, str(s))

# [2] singleton = 1.0 regardless of C (this is the fix — Laplace smoothing
#     used to cap singletons at ~0.8, which didn't match the intuition that
#     "appears only in this cluster" IS the maximum signal).
s20 = specificity_scores({"x": 1}, 20)["x"]
s200 = specificity_scores({"x": 1}, 200)["x"]
check("2a singleton scores 1.0 at C=20", s20 == 1.0, f"{s20}")
check("2b singleton scores 1.0 at C=200 (no C-dependence)", s200 == 1.0, f"{s200}")

# [3] strictly monotonic decreasing in df
C = 100
scored = specificity_scores({"a": 1, "b": 5, "c": 25, "d": 100}, C)
order = [scored["a"], scored["b"], scored["c"], scored["d"]]
check("3 monotonic decreasing in df", order == sorted(order, reverse=True), str(order))

# [4] bounds
allv = list(specificity_scores({f"k{i}": i for i in range(1, 51)}, 50).values())
check("4 all scores within [0,1]", all(0.0 <= v <= 1.0 for v in allv), str(allv[:5]))

# [5] degenerate: one cluster (or none) ⇒ "distinctive" is meaningless;
#     every key scores 0 rather than NaN.
check("5a C<=0 returns zeros", specificity_scores({"x": 1}, 0) == {"x": 0.0})
check("5b C==1 returns zeros", specificity_scores({"x": 1}, 1) == {"x": 0.0})


for n in PASSED:
    print(f"  PASS {n}")
for n, d in FAILED:
    print(f"  FAIL {n}: {d}")
print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
sys.exit(1 if FAILED else 0)
