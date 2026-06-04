"""Playbook name-by-id reuse — stop re-LLM'ing every playbook every cycle (P5.1).

`cluster sessions` writes fresh, name-less centroid docs each backward cycle, so
without reuse every anchor-stable `spb-` id gets re-named by the LLM every run
(name churn under a stable id). `_should_reuse_playbook_name` is the per-id
decision: reuse the prior-run name (skip the LLM) or mint a fresh one.

Scenarios:
  [1] prior name + steady state → reuse (skip the LLM)
  [2] prior name + --force → re-name (operator override re-LLMs)
  [3] no prior entry / empty prior name → mint fresh
  [4] over a realistic prior-name map (the _load_other_playbook_names shape):
      known non-empty ids reuse; empty/unknown ids mint; --force overrides

Pure-function test, offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_playbook_name_reuse.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.sessions import _should_reuse_playbook_name


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# -----------------------------------------------------------------------------
# [1] prior name + steady state → reuse.
# -----------------------------------------------------------------------------
print("\n[1] prior name, no --force → reuse (skip the LLM)")
check("reuses a non-empty prior name",
      _should_reuse_playbook_name("SSH Key Dropper", force=False) is True)


# -----------------------------------------------------------------------------
# [2] prior name + --force → re-name.
# -----------------------------------------------------------------------------
print("\n[2] prior name + --force → re-name (operator override)")
check("--force re-LLMs even with a prior name",
      _should_reuse_playbook_name("SSH Key Dropper", force=True) is False)


# -----------------------------------------------------------------------------
# [3] no/empty prior name → mint fresh.
# -----------------------------------------------------------------------------
print("\n[3] no prior name → mint fresh")
check("None prior name → no reuse", _should_reuse_playbook_name(None, force=False) is False)
check("empty prior name → no reuse", _should_reuse_playbook_name("", force=False) is False)


# -----------------------------------------------------------------------------
# [4] realistic prior-name map (the _load_other_playbook_names shape).
# -----------------------------------------------------------------------------
print("\n[4] decision over a prior-name map keyed by playbook_id")
prior_named = {
    "spb-aaaaaaaaaaaaaaaa": {"name": "Recon Sweep", "cluster_ids": ["cluster_3"]},
    "spb-bbbbbbbbbbbbbbbb": {"name": "", "cluster_ids": ["cluster_9"]},  # named-but-empty
}


def _reuse(pid: str, force: bool = False) -> bool:
    # Mirrors the extraction in run_name_playbooks: prior_name then the helper.
    prior_name = (prior_named.get(pid) or {}).get("name")
    return _should_reuse_playbook_name(prior_name, force=force)


check("known id with a name → reuse", _reuse("spb-aaaaaaaaaaaaaaaa") is True)
check("known id with empty name → mint", _reuse("spb-bbbbbbbbbbbbbbbb") is False)
check("unknown id → mint", _reuse("spb-zzzzzzzzzzzzzzzz") is False)
check("--force overrides a reusable id", _reuse("spb-aaaaaaaaaaaaaaaa", force=True) is False)


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
