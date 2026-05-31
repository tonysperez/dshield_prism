"""Smoke test: per-technique MITRE application counter (phase 2.3).

Asserts:
  * `_validate_mitre_ids` bumps the application counter on every
    accepted technique ID, leaves it alone on invalid IDs and on
    tactic IDs (tactics are intentionally excluded — they're coarse-
    grained buckets not subject to the over-application failure mode
    this metric is meant to surface).
  * `mitre_application_counts()` returns an accurate snapshot.
  * `reset_mitre_application_counts()` clears the counter.

Run standalone from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_mitre_application_counter.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.llm.schemas import (
    MITRE_TACTIC_IDS,
    MITRE_TECHNIQUE_IDS,
    _validate_mitre_ids,
    mitre_application_counts,
    reset_mitre_application_counts,
)


def _ensure_known(*ids: str, valid: frozenset[str]) -> None:
    missing = [i for i in ids if i not in valid]
    assert not missing, (
        f"Vendored ATT&CK set missing expected ids: {missing} "
        "(refresh src/enrich/data/mitre/attack.json or rewrite this test)"
    )


def main() -> int:
    # Pick a few stable techniques the vendored corpus carries.
    techs = ("T1059", "T1059.004", "T1078")
    tactics = ("TA0001", "TA0002")
    _ensure_known(*techs,   valid=MITRE_TECHNIQUE_IDS)
    _ensure_known(*tactics, valid=MITRE_TACTIC_IDS)

    reset_mitre_application_counts()
    assert mitre_application_counts() == {}, "counter should be empty after reset"

    # 3 calls applying T1059, 2 applying T1059.004, 1 applying T1078, plus
    # a junk id we expect to be dropped (and NOT count).
    for _ in range(3):
        _validate_mitre_ids(["T1059"], MITRE_TECHNIQUE_IDS, "techniques")
    for _ in range(2):
        _validate_mitre_ids(["T1059.004"], MITRE_TECHNIQUE_IDS, "techniques")
    _validate_mitre_ids(["T1078"], MITRE_TECHNIQUE_IDS, "techniques")
    _validate_mitre_ids(["T9999"], MITRE_TECHNIQUE_IDS, "techniques")  # invalid

    # Tactics MUST NOT bump the technique counter.
    for _ in range(5):
        _validate_mitre_ids(["TA0001"], MITRE_TACTIC_IDS, "tactics")

    snap = mitre_application_counts()
    assert snap == {"T1059": 3, "T1059.004": 2, "T1078": 1}, (
        f"unexpected snapshot: {dict(snap)}"
    )

    # Reset clears everything.
    reset_mitre_application_counts()
    assert mitre_application_counts() == {}, "counter should be empty after reset"

    # Caller's snapshot is a COPY — mutating it doesn't affect the live counter.
    _validate_mitre_ids(["T1059"], MITRE_TECHNIQUE_IDS, "techniques")
    s1 = mitre_application_counts()
    s1["T1059"] = 999
    s2 = mitre_application_counts()
    assert s2["T1059"] == 1, (
        "external mutation should not affect the live counter; "
        f"got {dict(s2)}"
    )

    print("mitre application counter smoke OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
