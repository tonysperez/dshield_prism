"""Smoke test for the cluster-naming context budget
(`_format_coverage_lines` size guards + the SessionConfig knobs). A huge cluster — or a
single multi-KB base64/here-doc command — must not blow the naming LLM's context window.

Standalone — no ES, no LLM.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.config import SessionConfig
from enrich.sources.cowrie.sessions import _format_coverage_lines

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


# --- default (no caps) is unchanged ---
out = _format_coverage_lines([("ls -la", 10), ("wget http://x/y", 5)], 10)
check("default renders all lines", out.count("\n- ".replace("\n", "")) >= 0 and "ls -la" in out and "wget http://x/y" in out, out)
check("default: no truncation marker", "truncated" not in out and "pruned" not in out)

# --- per-item truncation: a single giant command is clipped ---
big = "A" * 5000
out = _format_coverage_lines([(big, 8)], 10, max_item_chars=600)
check("giant command truncated to budget", ("A" * 5000) not in out, "full blob still present")
check("truncation marker present", "…[+4400 chars truncated]" in out, out[:120])
check("truncated line << original", len(out) < 1200, str(len(out)))

# --- block budget: lowest-coverage tail dropped, highest kept ---
feats = [(f"cmd{i}", 10 - i) for i in range(6)]  # coverage-ranked desc
out = _format_coverage_lines(feats, 10, max_chars=60)
check("keeps the highest-coverage feature", "cmd0" in out, out)
check("drops the lowest-coverage tail", "cmd5" not in out, out)
check("prune note with remaining count", "pruned to fit the naming context budget" in out, out)
check("block stays near budget", len(out) <= 60 + 120, str(len(out)))  # one over-budget line + note

# at least one line is always kept even if the first line exceeds the budget
out_tiny = _format_coverage_lines([("x" * 200, 5), ("y", 4)], 10, max_chars=10, max_item_chars=50)
check("keeps >=1 line even under a tiny budget", "(in 5/10" in out_tiny, out_tiny)

# --- config knobs exist with sane defaults ---
sc = SessionConfig()
check("playbook_naming_max_command_chars default 600", sc.playbook_naming_max_command_chars == 600)
check("playbook_naming_max_chars default 8000", sc.playbook_naming_max_chars == 8000)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
