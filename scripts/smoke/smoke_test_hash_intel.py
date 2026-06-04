"""Smoke test for ROADMAP #2 — hash intel pure logic.

Covers (no network/ES): MalwareBazaar + VirusTotal classifiers, the hash
priority tiering (`_hash_drop_boost` + `base_boost` in `compute_priority`), and
the tool-gated command hash regex (`extract_iocs_regex`).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_hash_intel.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.command_shape import extract_iocs_regex
from enrich.config import IntelPriorityConfig
from enrich.intel.providers.malwarebazaar import classify_malwarebazaar
from enrich.intel.providers.virustotal_public import classify_virustotal
from enrich.intel.queue import (
    _HASH_TIER1_DROP_BOOST,
    _HASH_TIER1_WRITE_BOOST,
    PriorityInputs,
    _hash_drop_boost,
    compute_priority,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name, cond, detail=""):
    (PASSED if cond else FAILED).append(name if cond else (name, detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f"  ({detail})"))


SHA = "a" * 64
TRIVIAL = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# -----------------------------------------------------------------------------
print("[1] MalwareBazaar classifier")
mal, label, conf, tags, ac, ed = classify_malwarebazaar([{"signature": "Mirai", "file_type": "elf", "tags": ["mirai", "elf"]}])
check("hit → malicious + evidence_direct", mal is True and ed is True, f"{mal},{ed}")
check("hit → family in label/tags", "mirai" in label and "mirai" in tags, f"{label},{tags}")
check("hit → high confidence", conf == 9, str(conf))
mal2, *_ = classify_malwarebazaar([])
check("miss → no opinion", mal2 is None)

# -----------------------------------------------------------------------------
print("\n[2] VirusTotal classifier")
mal, label, conf, tags, ac, ed = classify_virustotal({"last_analysis_stats": {"malicious": 12}, "popular_threat_classification": {"suggested_threat_label": "trojan.mirai"}})
check("≥3 engines → malicious, aggregator (not direct)", mal is True and ed is False, f"{mal},{ed}")
check("label carries suggested family", "trojan.mirai" in label, label)
mlow, llow, *_ = classify_virustotal({"last_analysis_stats": {"malicious": 1}})
check("<3 engines → no malicious vote", mlow is None, str(mlow))
mabs, *_ = classify_virustotal({})
check("no stats → no malicious vote", mabs is None)

# -----------------------------------------------------------------------------
print("\n[3] _hash_drop_boost (within tier-1: drops > content-writes)")
check("url-fetched → drop boost", _hash_drop_boost(SHA, None, True) == _HASH_TIER1_DROP_BOOST)
check("binary filename, no url → drop", _hash_drop_boost(SHA, "redtail.x86_64", False) == _HASH_TIER1_DROP_BOOST)
check("authorized_keys → content-write", _hash_drop_boost(SHA, "/root/.ssh/authorized_keys", False) == _HASH_TIER1_WRITE_BOOST)
check("hosts.deny → content-write", _hash_drop_boost(SHA, "/etc/hosts.deny", False) == _HASH_TIER1_WRITE_BOOST)
check("trivial hash → content-write even if binary name", _hash_drop_boost(TRIVIAL, "redtail.arm7", False) == _HASH_TIER1_WRITE_BOOST)

# -----------------------------------------------------------------------------
print("\n[4] compute_priority base_boost tiers hashes (drop > write > command)")
w = IntelPriorityConfig()
ci = dict(centrality_norm=0.5)
p_drop = compute_priority(PriorityInputs(base_boost=_HASH_TIER1_DROP_BOOST, **ci), w)
p_write = compute_priority(PriorityInputs(base_boost=_HASH_TIER1_WRITE_BOOST, **ci), w)
p_cmd = compute_priority(PriorityInputs(base_boost=0.0, **ci), w)
check("tier1-drop > tier1-write > tier2", p_drop > p_write > p_cmd, f"{p_drop},{p_write},{p_cmd}")
check("base_boost default 0 leaves ip/url math unchanged",
      compute_priority(PriorityInputs(novelty_score=0.4), w) == w.novelty_w * 0.4)

# -----------------------------------------------------------------------------
print("\n[5] extract_iocs_regex hash gating (prefix always; bare hex tool-gated)")
check("sha256: prefix extracted", SHA in extract_iocs_regex(f"verify sha256:{SHA}")["hashes"])
check("bare hex WITH tool extracted", SHA in extract_iocs_regex(f"sha256sum payload; {SHA}")["hashes"])
check("bare hex WITHOUT tool NOT extracted", extract_iocs_regex(f"echo {SHA} > x")["hashes"] == [])
check("non-canonical length NOT extracted", extract_iocs_regex(f"sha256sum x; {'a'*50}")["hashes"] == [])

# -----------------------------------------------------------------------------
print()
print(f"PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
if FAILED:
    for f in FAILED:
        print("  -", f)
    sys.exit(1)
sys.exit(0)
