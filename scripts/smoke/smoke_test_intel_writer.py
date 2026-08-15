"""Smoke test for `enrich.intel.writer`.

Covers:
  - `compute_derived` — the any-positive consensus rule + tag union.
  - `build_intel_doc` — provider merge with prior doc, derived block
    recomputation, `first_observed_locally` preservation.

Pure-function only. No ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_writer.py
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.intel.artifact import Artifact
from enrich.intel.providers.base import DerivedSignals, ProviderResult
from enrich.intel.writer import build_intel_doc, compute_derived

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


print("[1] compute_derived — empty provider set")
d = compute_derived([])
check("empty: not malicious", d["consensus_malicious"] is False)
check("empty: unknown label", d["consensus_label"] == "unknown")
check("empty: rarity 1.0", d["external_rarity_score"] == 1.0)
check("empty: providers_with_data == 0", d["providers_with_data"] == 0)
check("empty: no override", d["override_applied"] == "")


print("\n[2] compute_derived — single malicious provider flips consensus")
d = compute_derived([
    DerivedSignals(malicious=True, confidence=9, label="botnet", tags=("mirai",)),
])
check("single mal: True", d["consensus_malicious"] is True)
check("single mal: label", d["consensus_label"] == "botnet")
check("single mal: tags", d["tags"] == ["mirai"])
check("single mal: rarity 0", d["external_rarity_score"] == 0.0)
check("single mal aggregate: no override", d["override_applied"] == "")


print("\n[3] compute_derived — any-positive: one malicious among silent providers")
d = compute_derived([
    DerivedSignals(malicious=None),                          # no opinion
    DerivedSignals(malicious=True, confidence=8, label="scanner", tags=("scan",)),
    DerivedSignals(malicious=None),
])
check("any-positive flips consensus", d["consensus_malicious"] is True)
check("label from malicious provider", d["consensus_label"] == "scanner")
# rarity = (3 total - 1 with_data) / 3 = 0.6666...
check("rarity reflects silence",
      abs(d["external_rarity_score"] - 0.6667) < 1e-3,
      f"got {d['external_rarity_score']}")


print("\n[4] compute_derived — picks first malicious provider's label")
d = compute_derived([
    DerivedSignals(malicious=True, confidence=5, label="low_conf_label", tags=("a",)),
    DerivedSignals(malicious=True, confidence=10, label="HIGH_CONF", tags=("b",)),
])
# Spec says: first non-None label among malicious providers. We don't
# require highest-confidence; the test guards the documented behaviour.
check("label is first malicious provider's label",
      d["consensus_label"] == "low_conf_label",
      f"got {d['consensus_label']}")
# Tags union both:
check("tags union both", set(d["tags"]) == {"a", "b"})


print("\n[5] compute_derived — all-benign / informational only")
d = compute_derived([
    DerivedSignals(malicious=None, label="tor_exit", tags=("tor_exit",)),
])
check("informational not flagged malicious", d["consensus_malicious"] is False)
check("informational label surfaces", d["consensus_label"] == "tor_exit")


# -------------------------------------------------------------------------
# Consensus refinement (2026-05-17): authoritative_clean + evidence_direct
# -------------------------------------------------------------------------

print("\n[5a] ShadowServer case — GN benign overrides AbuseIPDB false-positive")
# Canonical case: AbuseIPDB scored 100 on a known-good scanner; GreyNoise
# authoritative_clean rescues it.
d = compute_derived([
    DerivedSignals(  # AbuseIPDB — aggregator vote, no direct evidence
        malicious=True, confidence=10, label="abuseipdb_high",
        tags=("abuseipdb_score_100",),
        evidence_direct=False,
    ),
    DerivedSignals(  # GreyNoise benign — authoritative clean
        malicious=False, confidence=8, label="greynoise_benign",
        tags=("greynoise_benign", "shadowserver.org"),
        authoritative_clean=True,
    ),
])
check("override flips consensus to clean", d["consensus_malicious"] is False)
check("override applied is authoritative_clean",
      d["override_applied"] == "authoritative_clean")
check("override picks GN benign label",
      d["consensus_label"] == "greynoise_benign")


print("\n[5b] RIOT override — same semantics as benign")
d = compute_derived([
    DerivedSignals(malicious=True, label="firehol_level1", evidence_direct=False),
    DerivedSignals(malicious=False, label="greynoise_riot",
                   authoritative_clean=True),
])
check("RIOT also flips", d["consensus_malicious"] is False)
check("override applied", d["override_applied"] == "authoritative_clean")


print("\n[5c] Direct malicious survives authoritative_clean")
# Pathological but possible: FeodoTracker says active C2, GreyNoise says
# benign somehow. Direct evidence wins.
d = compute_derived([
    DerivedSignals(  # FeodoTracker — direct C2 observation
        malicious=True, confidence=9, label="feodo_c2",
        tags=("feodo_c2", "emotet"),
        evidence_direct=True,
    ),
    DerivedSignals(  # GreyNoise benign
        malicious=False, label="greynoise_benign",
        authoritative_clean=True,
    ),
])
check("direct malicious wins", d["consensus_malicious"] is True)
check("override is direct_malicious",
      d["override_applied"] == "direct_malicious")
check("label from FeodoTracker (the direct signal)",
      d["consensus_label"] == "feodo_c2")


print("\n[5d] GN classification=malicious (direct) defeats other clean signal")
# Hypothetical: a future provider sets authoritative_clean but GN itself
# directly flags as malicious. Direct wins.
d = compute_derived([
    DerivedSignals(  # GN classification=malicious
        malicious=True, confidence=9, label="greynoise_malicious",
        evidence_direct=True,
    ),
    DerivedSignals(
        malicious=False, label="some_clean_signal",
        authoritative_clean=True,
    ),
])
check("GN direct mal beats other clean", d["consensus_malicious"] is True)
check("override is direct_malicious",
      d["override_applied"] == "direct_malicious")


print("\n[5e] Aggregator-only malicious without clean signal — any-positive applies")
# Regression guard: without authoritative_clean in the mix, aggregator
# votes still flip consensus to malicious (the original any-positive).
d = compute_derived([
    DerivedSignals(  # AbuseIPDB
        malicious=True, label="abuseipdb_high",
        evidence_direct=False,
    ),
    DerivedSignals(  # FireHOL
        malicious=True, label="firehol_level1",
        evidence_direct=False,
    ),
])
check("aggregator-only still flips consensus to malicious",
      d["consensus_malicious"] is True)
check("override_applied is empty (no special rule fired)",
      d["override_applied"] == "")


print("\n[5f] authoritative_clean alone with no malicious votes — consensus clean")
d = compute_derived([
    DerivedSignals(  # GN benign with nothing else
        malicious=False, label="greynoise_benign",
        authoritative_clean=True,
    ),
    DerivedSignals(malicious=None),                        # silent provider
])
check("clean alone: consensus clean",
      d["consensus_malicious"] is False)
check("override applied (clean was the only signal)",
      d["override_applied"] == "authoritative_clean")


# -------------------------------------------------------------------------
# Derived rollups (2026-05-17): malicious_provider_count, clean_provider_count,
# confidence_max — precomputed inputs for M3.A triage gate + M5 findings.
# -------------------------------------------------------------------------

print("\n[6] derived rollups — empty signal set")
d = compute_derived([])
check("empty: malicious_provider_count = 0",
      d["malicious_provider_count"] == 0)
check("empty: clean_provider_count = 0",
      d["clean_provider_count"] == 0)
check("empty: confidence_max None", d["confidence_max"] is None)


print("\n[7] derived rollups — single malicious provider")
d = compute_derived([
    DerivedSignals(malicious=True, confidence=8, label="x"),
])
check("single mal: malicious_provider_count = 1",
      d["malicious_provider_count"] == 1)
check("single mal: clean_provider_count = 0",
      d["clean_provider_count"] == 0)
check("single mal: confidence_max = 8", d["confidence_max"] == 8)


print("\n[8] derived rollups — three malicious + one clean")
d = compute_derived([
    DerivedSignals(malicious=True, confidence=6, label="a"),
    DerivedSignals(malicious=True, confidence=9, label="b"),    # highest
    DerivedSignals(malicious=True, confidence=8, label="c"),
    DerivedSignals(malicious=False, label="d", authoritative_clean=True),
])
check("3+1: malicious_provider_count = 3",
      d["malicious_provider_count"] == 3)
check("3+1: clean_provider_count = 1",
      d["clean_provider_count"] == 1)
# confidence_max picks the highest among malicious-voting providers.
# Note: even though authoritative_clean fires, this rollup reflects
# the *vote* count for M3.A — gate can still compare against malicious
# votes from aggregators.
check("3+1: confidence_max = 9 (max among malicious)",
      d["confidence_max"] == 9)


print("\n[9] derived rollups — malicious with None confidence handled")
# Some providers (Tor) don't carry confidence; their None values
# shouldn't crash the max() reduction.
d = compute_derived([
    DerivedSignals(malicious=True, confidence=None, label="a"),
    DerivedSignals(malicious=True, confidence=7, label="b"),
])
check("conf=None ignored in max",
      d["confidence_max"] == 7,
      f"got {d['confidence_max']}")


print("\n[10] derived rollups — clean signal doesn't count in malicious_count")
d = compute_derived([
    DerivedSignals(malicious=False, label="clean1", authoritative_clean=True),
    DerivedSignals(malicious=False, label="clean2"),
    DerivedSignals(malicious=None, label="silent"),
])
check("no malicious: count = 0",
      d["malicious_provider_count"] == 0)
check("two clean: clean_count = 2",
      d["clean_provider_count"] == 2)
check("no malicious: confidence_max None",
      d["confidence_max"] is None)


print("\n[6] build_intel_doc — merges prior providers with new results")
artifact = Artifact("ip", "203.0.113.5")
now = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)
prior = {
    "artifact": {"kind": "ip", "value": "203.0.113.5",
                 "first_observed_locally": "2026-04-01T00:00:00+00:00"},
    "providers": {
        "tor": {
            "fetched_at": "2026-05-15T00:00:00+00:00",
            "ttl_expires_at": "2026-05-16T00:00:00+00:00",
            "malicious": None, "confidence": None,
            "label": "tor_exit", "tags": ["tor_exit"],
            "structured": {"is_exit": True}, "raw": {},
        },
    },
    "derived": {"consensus_malicious": False, "consensus_label": "tor_exit",
                "tags": ["tor_exit"], "providers_with_data": 0, "providers_total": 1,
                "external_rarity_score": 1.0},
    "last_refreshed": "2026-05-15T00:00:00+00:00",
}
new_result = ProviderResult.make(
    provider="spamhaus",
    artifact=artifact,
    structured={"listed": True, "codes": ["127.0.0.2"]},
    raw={"codes": ["127.0.0.2"]},
    derived=DerivedSignals(malicious=True, confidence=9,
                           label="spamhaus_sbl", tags=("spamhaus_sbl",)),
    ttl=timedelta(days=1),
    now=now,
)
new_doc = build_intel_doc(artifact, [new_result], prior, now=now)

check("first_observed_locally preserved",
      new_doc["artifact"]["first_observed_locally"] == "2026-04-01T00:00:00+00:00")
check("tor preserved", "tor" in new_doc["providers"])
check("spamhaus added", "spamhaus" in new_doc["providers"])
check("last_refreshed updated to now",
      new_doc["last_refreshed"] == now.isoformat())
check("derived now flags malicious", new_doc["derived"]["consensus_malicious"] is True)
# Tags is union — tor_exit + spamhaus_sbl
check("derived tags union",
      set(new_doc["derived"]["tags"]) == {"tor_exit", "spamhaus_sbl"})


print("\n[7] build_intel_doc — no prior doc")
fresh = build_intel_doc(artifact, [new_result], None, now=now)
check("no prior: first_observed = now",
      fresh["artifact"]["first_observed_locally"] == now.isoformat())
check("no prior: providers populated",
      "spamhaus" in fresh["providers"])
check("no prior: derived computed", fresh["derived"]["consensus_malicious"] is True)


print("\n[8] build_intel_doc — re-running same provider overwrites entry")
older = ProviderResult.make(
    provider="spamhaus",
    artifact=artifact,
    structured={"listed": False, "codes": []},  # different structured
    raw={"codes": []},
    derived=DerivedSignals(malicious=None, label=None, tags=()),
    ttl=timedelta(days=1),
    now=now - timedelta(days=2),
)
# First write the older, then the newer.
doc1 = build_intel_doc(artifact, [older], None, now=now - timedelta(days=2))
doc2 = build_intel_doc(artifact, [new_result], doc1, now=now)
check("provider entry overwritten by newer result",
      doc2["providers"]["spamhaus"]["malicious"] is True)
check("derived reflects newer signal",
      doc2["derived"]["consensus_malicious"] is True)


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
