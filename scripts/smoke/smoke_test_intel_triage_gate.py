"""Smoke test for `triage.intel_skip_reason` and `IntelSummary.from_doc`.

Covers M3.A: the intel-aware cloud-escalation gate. Pure-function only;
the ES-talking `IntelLookup.get_many` orchestration is exercised
post-deploy via the live pipeline run.

Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_triage_gate.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import CloudConfig, CloudTriageConfig
from enrich.intel.lookup import IntelSummary
from enrich.triage import intel_skip_reason, _reasons_are_gateable


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def _summary(**kw) -> IntelSummary:
    """Build an IntelSummary with sensible defaults — override individual fields."""
    defaults = dict(
        consensus_malicious=False,
        consensus_label="unknown",
        override_applied="",
        external_rarity_score=0.0,
        malicious_provider_count=0,
        clean_provider_count=0,
        confidence_max=None,
        tags=(),
    )
    defaults.update(kw)
    return IntelSummary(**defaults)


def _cfg(intel_aware: bool = True) -> CloudConfig:
    return CloudConfig(triage=CloudTriageConfig(intel_aware=intel_aware))


# -----------------------------------------------------------------------------
# IntelSummary.from_doc — reading an ES doc body
# -----------------------------------------------------------------------------

print("[1] IntelSummary.from_doc — well-formed doc")
doc = {
    "derived": {
        "consensus_malicious": True,
        "consensus_label": "abuseipdb_high",
        "override_applied": "",
        "external_rarity_score": 0.25,
        "malicious_provider_count": 2,
        "clean_provider_count": 0,
        "confidence_max": 9,
        "tags": ["abuseipdb_score_95", "firehol_level1"],
    }
}
s = IntelSummary.from_doc(doc)
check("populates consensus_malicious", s is not None and s.consensus_malicious is True)
check("populates label",             s.consensus_label == "abuseipdb_high")
check("populates rollups",
      s.malicious_provider_count == 2 and s.confidence_max == 9)
check("tags as tuple",               s.tags == ("abuseipdb_score_95", "firehol_level1"))


print("\n[2] IntelSummary.from_doc — missing derived block / malformed")
check("None body", IntelSummary.from_doc(None) is None)  # type: ignore[arg-type]
check("empty body", IntelSummary.from_doc({}) is None)
check("missing derived", IntelSummary.from_doc({"providers": {}}) is None)
check("derived missing consensus_malicious",
      IntelSummary.from_doc({"derived": {}}) is None)


print("\n[3] IntelSummary.from_doc — pre-M2 doc without rollup fields")
# Old docs (before the M2 rollup additions) only had consensus_malicious /
# consensus_label / override_applied. Defensive defaults should keep
# downstream code working.
old = {"derived": {"consensus_malicious": False, "consensus_label": "tor_exit"}}
s = IntelSummary.from_doc(old)
check("pre-M2 doc parses",       s is not None)
check("pre-M2 defaults rollups",
      s.malicious_provider_count == 0 and s.clean_provider_count == 0
      and s.confidence_max is None and s.tags == ())


# -----------------------------------------------------------------------------
# _reasons_are_gateable
# -----------------------------------------------------------------------------

print("\n[4] _reasons_are_gateable — recognises LLM-uncertainty reasons")
check("empty list → not gateable", _reasons_are_gateable([]) is False)
check("low_confidence prefix",
      _reasons_are_gateable(["low_confidence<=4"]) is True)
check("novel_embedding",         _reasons_are_gateable(["novel_embedding"]) is True)
check("sample",                  _reasons_are_gateable(["sample"]) is True)
check("multiple gateable",
      _reasons_are_gateable(["low_confidence<=4", "novel_embedding"]) is True)


print("\n[5] _reasons_are_gateable — command-shape reasons make it non-gateable")
check("base64_blob blocks gate",
      _reasons_are_gateable(["base64_blob"]) is False)
check("ip_literal blocks gate",
      _reasons_are_gateable(["ip_literal"]) is False)
check("rare_tld blocks gate",
      _reasons_are_gateable(["rare_tld"]) is False)
check("any non-gateable taints the list",
      _reasons_are_gateable(["low_confidence<=4", "base64_blob"]) is False)


# -----------------------------------------------------------------------------
# intel_skip_reason — the rule
# -----------------------------------------------------------------------------

print("\n[6] intel_skip_reason — no IP summaries → no opinion (None)")
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4"],
    ip_summaries=[],
    cfg=_cfg(),
)
check("empty IP list returns None", r is None)


print("\n[7] intel_skip_reason — disabled toggle → None even when rule would fire")
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4"],
    ip_summaries=[_summary(override_applied="authoritative_clean")],
    cfg=_cfg(intel_aware=False),
)
check("intel_aware=False short-circuits", r is None)


print("\n[8] intel_skip_reason — rule 1: every IP authoritative_clean")
# ShadowServer-class scenario: all source IPs are GN-RIOT or AbuseIPDB-
# whitelisted.
ipsums = [
    _summary(override_applied="authoritative_clean",
             consensus_label="greynoise_benign"),
    _summary(override_applied="authoritative_clean",
             consensus_label="abuseipdb_whitelisted"),
]
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4"],
    ip_summaries=ipsums, cfg=_cfg(),
)
check("rule 1 fires", r == "intel_skip_authoritative_clean")


print("\n[8a] rule 1 with mixed override_applied → no skip (one IP isn't authoritative)")
mixed = [
    _summary(override_applied="authoritative_clean"),
    _summary(override_applied="", consensus_malicious=False),    # silent
]
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4"],
    ip_summaries=mixed, cfg=_cfg(),
)
check("rule 1 refuses on mixed", r is None)


print("\n[9] intel_skip_reason — rule 2: commodity_consensus + gateable reasons")
# All IPs have ≥2 INDEPENDENT malicious providers, only LLM-uncertainty
# reasons → skip. (Independence guard, brutal-review 2.1: the rule checks
# max_independent_set(malicious_providers) >= 2, not a bare provider count —
# abuseipdb + greynoise have disjoint upstreams, so they count as 2 sources.)
commodity = [
    _summary(consensus_malicious=True,
             malicious_providers=frozenset({"abuseipdb", "greynoise"})),
    _summary(consensus_malicious=True,
             malicious_providers=frozenset({"abuseipdb", "greynoise"})),
    _summary(consensus_malicious=True,
             malicious_providers=frozenset({"abuseipdb", "greynoise"})),
]
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4"], ip_summaries=commodity, cfg=_cfg(),
)
check("rule 2 fires on commodity + gateable",
      r == "intel_skip_commodity_consensus")


print("\n[9a] rule 2 — single-provider-flag IP shouldn't be enough")
# A single INDEPENDENT provider is not "strong consensus." Require ≥2.
weak = [
    _summary(consensus_malicious=True,
             malicious_providers=frozenset({"abuseipdb"})),
    _summary(consensus_malicious=True,
             malicious_providers=frozenset({"abuseipdb", "greynoise"})),
]
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4"], ip_summaries=weak, cfg=_cfg(),
)
check("rule 2 refuses on single-provider IP", r is None)


print("\n[9b] rule 2 — command-shape reason taints the list, no skip")
# An IP that's strong-commodity-consensus running a base64-evasion
# command: don't skip. The command shape is its own signal.
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4", "base64_blob"],
    ip_summaries=commodity, cfg=_cfg(),
)
check("rule 2 refuses when base64_blob fires", r is None)


print("\n[9c] rule 2 — ip_literal in reasons taints the list")
r = intel_skip_reason(
    triage_reasons=["ip_literal"],
    ip_summaries=commodity, cfg=_cfg(),
)
check("rule 2 refuses when ip_literal fires", r is None)


print("\n[10] intel_skip_reason — rule 1 takes priority over rule 2")
# An IP can be authoritative_clean AND have a non-empty triage_reasons
# (e.g. low_confidence). Rule 1 should fire regardless of which gateable
# reason is present.
clean = [_summary(override_applied="authoritative_clean")]
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4", "base64_blob"],
    ip_summaries=clean, cfg=_cfg(),
)
# Note: rule 1 doesn't gate on command-shape reasons. The override is
# authoritative — ShadowServer running base64 is still ShadowServer.
check("rule 1 fires even with base64_blob in reasons",
      r == "intel_skip_authoritative_clean")


print("\n[11] intel_skip_reason — no flags → no skip (default fallthrough)")
silent = [_summary(consensus_malicious=False, malicious_provider_count=0)]
r = intel_skip_reason(
    triage_reasons=["low_confidence<=4"], ip_summaries=silent, cfg=_cfg(),
)
check("no intel signal: defer to existing rules", r is None)


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
