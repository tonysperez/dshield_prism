"""Smoke test for ROADMAP #11 — playbook naming distinctiveness + merge gate.

Validates the pure functions that drive pass-2 collision resolution, with no
ES/LLM:

  - `_combined_coverage_map` merges command + IOC coverage into fractions.
  - `_distinctive_features` returns features present in one cluster and absent
    in its siblings (at the floor), sorted by coverage.
  - `_indistinguishable` is true iff no feature separates two clusters.
  - `_partition_mergeable` groups mutually-indistinguishable clusters and keeps
    genuinely-distinct ones apart.
  - `_format_coverage_lines` renders coverage with session counts + percent.

Standalone — no pytest, no real ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_playbook_distinctiveness.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import (
    _combined_coverage_map,
    _distinctive_features,
    _format_coverage_lines,
    _indistinguishable,
    _partition_mergeable,
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


# ---------------------------------------------------------------------------
# [1] _combined_coverage_map
# ---------------------------------------------------------------------------
print("[1] _combined_coverage_map")
m = _combined_coverage_map([("uname -m", 8), ("w", 2)], [("ip:1.2.3.4", 4)], total_sessions=10)
check("command prefixed cmd:", m.get("cmd:uname -m") == 0.8, str(m))
check("ioc keeps native prefix", m.get("ip:1.2.3.4") == 0.4, str(m))
check("low-coverage cmd kept as fraction", m.get("cmd:w") == 0.2, str(m))
check("zero total → empty map", _combined_coverage_map([("x", 1)], [], 0) == {})


# ---------------------------------------------------------------------------
# [2] _distinctive_features
# ---------------------------------------------------------------------------
print("[2] _distinctive_features")
# A and B share a recon command; A additionally runs chattr (distinctive),
# B additionally hits a C2 IP (distinctive). Floor 0.5.
cov = {
    "A": {"cmd:uname -m": 0.9, "cmd:chattr +i": 0.8, "cmd:w": 0.1},
    "B": {"cmd:uname -m": 0.9, "ip:9.9.9.9": 0.7},
}
dist = _distinctive_features(cov, floor=0.5)
a_feats = {f for f, _ in dist["A"]}
b_feats = {f for f, _ in dist["B"]}
check("A distinctive = chattr only", a_feats == {"cmd:chattr +i"}, str(a_feats))
check("B distinctive = C2 ip only", b_feats == {"ip:9.9.9.9"}, str(b_feats))
check("shared command not distinctive to anyone",
      "cmd:uname -m" not in a_feats and "cmd:uname -m" not in b_feats)
check("below-floor feature excluded", "cmd:w" not in a_feats)
# Sorted by coverage desc.
cov2 = {"A": {"cmd:x": 0.9, "cmd:y": 0.6}, "B": {}}
ranked = [f for f, _ in _distinctive_features(cov2, 0.5)["A"]]
check("distinctive sorted by coverage desc", ranked == ["cmd:x", "cmd:y"], str(ranked))


# ---------------------------------------------------------------------------
# [3] _indistinguishable
# ---------------------------------------------------------------------------
print("[3] _indistinguishable")
same_a = {"cmd:uname -m": 0.9, "cmd:w": 0.8}
same_b = {"cmd:uname -m": 0.85, "cmd:w": 0.7}
check("identical prevalent sets → indistinguishable",
      _indistinguishable(same_a, same_b, 0.5) is True)
diff_a = {"cmd:uname -m": 0.9, "cmd:chattr +i": 0.8}
diff_b = {"cmd:uname -m": 0.9}
check("one has a distinctive prevalent feature → distinguishable",
      _indistinguishable(diff_a, diff_b, 0.5) is False)
# A separating feature below the floor in BOTH does not distinguish.
low_a = {"cmd:uname -m": 0.9, "cmd:rare": 0.2}
low_b = {"cmd:uname -m": 0.9}
check("sub-floor difference does not distinguish",
      _indistinguishable(low_a, low_b, 0.5) is True)
# Conservative floor: a weakly-prevalent (25%) separating feature blocks merge.
weak_a = {"cmd:uname -m": 0.9, "cmd:chattr +i": 0.3}
weak_b = {"cmd:uname -m": 0.9}
check("25% feature blocks merge at floor 0.25",
      _indistinguishable(weak_a, weak_b, 0.25) is False)


# ---------------------------------------------------------------------------
# [4] _partition_mergeable
# ---------------------------------------------------------------------------
print("[4] _partition_mergeable")
# A~B (same), C distinct (has chattr).
cov3 = {
    "A": {"cmd:uname -m": 0.9, "cmd:w": 0.7},
    "B": {"cmd:uname -m": 0.9, "cmd:w": 0.7},
    "C": {"cmd:uname -m": 0.9, "cmd:chattr +i": 0.8},
}
groups = _partition_mergeable(cov3, 0.5)
check("A+B merge, C separate", groups == [["A", "B"], ["C"]], str(groups))
# All distinct → all singletons.
cov4 = {
    "A": {"cmd:a": 0.9},
    "B": {"cmd:b": 0.9},
    "C": {"cmd:c": 0.9},
}
groups4 = _partition_mergeable(cov4, 0.5)
check("all distinct → singletons", groups4 == [["A"], ["B"], ["C"]], str(groups4))
# All identical → one group.
cov5 = {k: {"cmd:uname -m": 0.9} for k in ("A", "B", "C")}
groups5 = _partition_mergeable(cov5, 0.5)
check("all identical → one merged group", groups5 == [["A", "B", "C"]], str(groups5))
check("deterministic member + group ordering",
      all(m == sorted(m) for m in groups5) and groups == sorted(groups, key=lambda g: g[0]))


# ---------------------------------------------------------------------------
# [5] _format_coverage_lines
# ---------------------------------------------------------------------------
print("[5] _format_coverage_lines")
out = _format_coverage_lines([("uname -m", 8)], 10)
check("renders count and percent", "8/10" in out and "80%" in out, out)
out2 = _format_coverage_lines([("cmd:chattr", 5)], 10, strip_cmd_prefix=True)
check("strips cmd: prefix when asked", "chattr" in out2 and "cmd:chattr" not in out2, out2)
check("empty ranked → (none)", _format_coverage_lines([], 10).strip() == "(none)")


# ---------------------------------------------------------------------------
print()
print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
