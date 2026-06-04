"""Smoke test for `_attach_source_ip_intel` — the M3.C doc mutator.

Verifies the helper that copies an `IntelSummary` onto the session
rollup doc body at `dshield.cowrie.enrichment.session.source_ip_intel`.

Pure-function only; no ES.

Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_session_block.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.intel.lookup import IntelSummary
from enrich.sources.cowrie.sessions import _attach_source_ip_intel


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


def _intel_block(doc):
    return (
        doc.get("dshield", {}).get("cowrie", {}).get("enrichment", {})
        .get("session", {}).get("source_ip_intel")
    )


print("[1] _attach_source_ip_intel — None summary is a no-op")
doc = {"dshield": {"cowrie": {"enrichment": {"session": {}}}}}
_attach_source_ip_intel(doc, None)
check("no source_ip_intel block written", _intel_block(doc) is None)


print("\n[2] _attach_source_ip_intel — populates the block correctly")
doc = {"dshield": {"cowrie": {"enrichment": {"session": {"command_count": 5}}}}}
_attach_source_ip_intel(doc, _summary(
    consensus_malicious=True,
    consensus_label="abuseipdb_high",
    override_applied="",
    external_rarity_score=0.25,
    malicious_provider_count=2,
    clean_provider_count=0,
    confidence_max=9,
))
intel = _intel_block(doc)
check("block exists",                  intel is not None)
check("consensus_malicious carried",   intel["consensus_malicious"] is True)
check("consensus_label carried",       intel["consensus_label"] == "abuseipdb_high")
check("override_applied carried",      intel["override_applied"] == "")
check("external_rarity_score carried", intel["external_rarity_score"] == 0.25)
check("malicious_provider_count carried", intel["malicious_provider_count"] == 2)
check("clean_provider_count carried",  intel["clean_provider_count"] == 0)
check("confidence_max carried (int)",  intel["confidence_max"] == 9)


print("\n[3] _attach_source_ip_intel — does not clobber existing session block")
doc = {"dshield": {"cowrie": {"enrichment": {"session": {
    "command_count": 5,
    "dominant_intent": "execution",
}}}}}
_attach_source_ip_intel(doc, _summary(consensus_malicious=True))
session = doc["dshield"]["cowrie"]["enrichment"]["session"]
check("command_count preserved", session.get("command_count") == 5)
check("dominant_intent preserved", session.get("dominant_intent") == "execution")
check("source_ip_intel added",   "source_ip_intel" in session)


print("\n[4] _attach_source_ip_intel — confidence_max=None field omitted")
# ES rejects null integers in some strict configs; we omit the field
# rather than write null.
doc = {"dshield": {"cowrie": {"enrichment": {"session": {}}}}}
_attach_source_ip_intel(doc, _summary(confidence_max=None))
intel = _intel_block(doc)
check("confidence_max omitted from doc",
      "confidence_max" not in intel,
      f"got intel={intel}")
# But the rest of the block is still there:
check("rest of block present",
      "consensus_malicious" in intel and "consensus_label" in intel)


print("\n[5] _attach_source_ip_intel — bootstraps missing parents")
# Doc with no dshield path at all (e.g. a freshly-built doc that's
# missing the nested structure). Should auto-create.
doc = {}
_attach_source_ip_intel(doc, _summary(consensus_malicious=True))
intel = _intel_block(doc)
check("parents auto-created", intel is not None and intel["consensus_malicious"] is True)


print("\n[6] _attach_source_ip_intel — authoritative_clean override carried")
doc = {"dshield": {"cowrie": {"enrichment": {"session": {}}}}}
_attach_source_ip_intel(doc, _summary(
    consensus_malicious=False,
    consensus_label="greynoise_benign",
    override_applied="authoritative_clean",
    confidence_max=8,
))
intel = _intel_block(doc)
check("override_applied=authoritative_clean carried",
      intel["override_applied"] == "authoritative_clean")
check("consensus_label carried",
      intel["consensus_label"] == "greynoise_benign")


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
