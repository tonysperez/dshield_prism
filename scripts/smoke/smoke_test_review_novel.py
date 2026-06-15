"""Smoke test for the novel-pool review grouping
(`scripts/review_novel.py`: categorize, group_novel). No ES, no command text.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from review_novel import categorize, group_novel

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


C = dict(tau=0.94, confident_tau=0.98)
check("cos 0.90 → below_tau", categorize(0.90, **C) == "below_tau")
check("cos 0.96 → band_conflation", categorize(0.96, **C) == "band_conflation")
check("cos exactly tau 0.94 → band_conflation", categorize(0.94, **C) == "band_conflation")
check("cos None → below_tau", categorize(None, **C) == "below_tau")

rows = [
    # 3 sessions share sig-A, all below tau (genuinely far)
    {"signature": "sig-A", "intent": "recon", "current_pb": "spb-1", "current_name": "Recon", "cosine": 0.80, "text": "x"},
    {"signature": "sig-A", "intent": "recon", "current_pb": "spb-1", "current_name": "Recon", "cosine": 0.85, "text": "x"},
    {"signature": "sig-A", "intent": "exec", "current_pb": "spb-1", "current_name": "Recon", "cosine": 0.78, "text": "x"},
    # 2 sessions share sig-B, band conflations
    {"signature": "sig-B", "intent": "persist", "current_pb": "spb-2", "current_name": "Persist", "cosine": 0.95, "text": "y"},
    {"signature": "sig-B", "intent": "persist", "current_pb": "spb-2", "current_name": "Persist", "cosine": 0.965, "text": "y"},
]
groups = group_novel(rows, **C)

check("2 distinct signature groups", len(groups) == 2, str([g["signature"] for g in groups]))
check("sorted by count desc (sig-A first, ×3)",
      groups[0]["signature"] == "sig-A" and groups[0]["count"] == 3, str(groups[0]))
check("sig-A categorized below_tau", groups[0]["category"] == "below_tau", str(groups[0]))
check("sig-A intents deduped + sorted", groups[0]["intents"] == ["exec", "recon"], str(groups[0]))
check("sig-A cosine range 0.78–0.85",
      groups[0]["cosine_min"] == 0.78 and groups[0]["cosine_max"] == 0.85, str(groups[0]))
check("sig-A current playbook surfaced (HDBSCAN's label)",
      groups[0]["current_playbooks"] == ["Recon"], str(groups[0]))
check("sig-B categorized band_conflation + ×2",
      groups[1]["category"] == "band_conflation" and groups[1]["count"] == 2, str(groups[1]))

# empty signature collapses to a single ∅ bucket
g2 = group_novel([{"signature": None, "intent": None, "current_pb": None,
                   "current_name": None, "cosine": 0.5, "text": ""}], **C)
check("missing signature → ∅ bucket", len(g2) == 1 and g2[0]["signature"] == "∅", str(g2))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
