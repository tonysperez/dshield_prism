"""Smoke test for `enrich.findings` — the M5 miner that emits one
finding per playbook and one per campaign.

Covers (pure-function only, no ES):
  - `finding_id` is deterministic and content-addressed.
  - `valid_statuses` exposes the expected workflow transitions.

The miner itself reads from ES; integration coverage lives in the
manual `dshield_prism mine findings --dry-run` invocation against a
live cluster.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_findings_miner.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.writer import finding_id, valid_statuses  # noqa: E402


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


print("[1] finding_id determinism + content-addressing")
fid_a = finding_id("playbook", "playbook", "sescl-0123456789abcdef")
fid_a2 = finding_id("playbook", "playbook", "sescl-0123456789abcdef")
fid_b = finding_id("playbook", "playbook", "sescl-fedcba9876543210")
fid_c = finding_id("campaign", "campaign", "cmp-beh-0123456789abcdef")
check("same inputs → same id", fid_a == fid_a2, f"{fid_a} vs {fid_a2}")
check("different value → different id", fid_a != fid_b)
check("different kind → different prefix", fid_c.startswith("find-cam-"))
check("playbook prefix", fid_a.startswith("find-pla-"))
check("id length is bounded", len(fid_a) < 40, f"len={len(fid_a)}")


print("\n[2] valid_statuses contract")
vs = valid_statuses()
for s in ("new", "ack", "confirmed", "rejected"):
    check(f"status {s!r} accepted", s in vs)
check("invalid status excluded", "deleted" not in vs)


print(f"\n--- {len(PASSED)} passed, {len(FAILED)} failed ---")
if FAILED:
    for name, detail in FAILED:
        print(f"  FAILED  {name}  {detail}")
    sys.exit(1)
