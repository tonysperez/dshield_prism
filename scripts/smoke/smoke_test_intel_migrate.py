"""Smoke test for `enrich.intel.migrate`.

Covers the pure-function half: per-provider reclassifier + `rebuild_doc`.
The orchestrator `run_reapply_rules` (which talks to ES) is verified
post-deploy by the operator running `intel reapply-rules --dry-run`.

The headline case is the ShadowServer-style fix that motivated the
2026-05-17 consensus refinement: an existing doc where
`providers.greynoise.malicious` is None and `authoritative_clean` is
absent should, after reclassification, carry `malicious=False` and
`authoritative_clean=True`, flipping the doc's `consensus_malicious`
from True (under the old aggregator-only votes) to False (under the
override rule).

Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_migrate.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.intel.migrate import (
    rebuild_doc,
    reclassify_abuseipdb,
    reclassify_feodotracker,
    reclassify_greynoise,
    reclassify_passthrough,
)


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
# GreyNoise reclassification — the headline case
# -----------------------------------------------------------------------------

print("[1] GreyNoise reclassify: legacy benign-classification block → authoritative_clean")
# Legacy persisted block from pre-2026-05-17 — ShadowServer-shaped.
legacy_benign = {
    "fetched_at": "2026-05-16T00:00:00+00:00",
    "ttl_expires_at": "2026-05-23T00:00:00+00:00",
    "malicious": None,                          # old contract: no vote
    "confidence": 8,
    "label": "greynoise_benign",                # tag was set under old contract
    "tags": ["greynoise_benign", "ShadowServer.org"],
    "structured": {
        "in_greynoise": True,
        "classification": "benign",
        "name": "ShadowServer.org",
        "noise": True,
        "riot": False,
        "last_seen": "2026-05-15",
        "link": "https://viz.greynoise.io/ip/216.218.206.67",
    },
    "raw": {},
    # No authoritative_clean field at all — pre-migration.
}

updated = reclassify_greynoise(legacy_benign)
check("malicious flipped to False",          updated["malicious"] is False)
check("authoritative_clean True",            updated["authoritative_clean"] is True)
check("evidence_direct False",               updated["evidence_direct"] is False)
check("label preserved as greynoise_benign", updated["label"] == "greynoise_benign")
check("structured unchanged",                updated["structured"] is legacy_benign["structured"])
check("fetched_at preserved",                updated["fetched_at"] == legacy_benign["fetched_at"])


print("\n[2] GreyNoise reclassify: legacy malicious-classification block → evidence_direct")
legacy_mal = {
    "malicious": True, "confidence": 9, "label": "greynoise_malicious",
    "tags": ["greynoise_malicious", "Mirai"],
    "structured": {"in_greynoise": True, "classification": "malicious",
                   "name": "Mirai", "noise": True, "riot": False,
                   "last_seen": "2026-05-15"},
    "raw": {}, "fetched_at": "2026-05-16T00:00:00+00:00",
    "ttl_expires_at": "2026-05-23T00:00:00+00:00",
}
updated = reclassify_greynoise(legacy_mal)
check("malicious still True", updated["malicious"] is True)
check("evidence_direct=True (GN's own observation)", updated["evidence_direct"] is True)
check("authoritative_clean=False on malicious", updated["authoritative_clean"] is False)


print("\n[3] GreyNoise reclassify: RIOT-only block → authoritative_clean")
legacy_riot = {
    "malicious": None, "label": "greynoise_riot",
    "tags": ["greynoise_riot", "Google Public DNS"],
    "structured": {"in_greynoise": True, "classification": None,
                   "name": "Google Public DNS", "noise": False, "riot": True},
    "raw": {}, "fetched_at": "2026-05-16T00:00:00+00:00",
    "ttl_expires_at": "2026-05-23T00:00:00+00:00",
}
updated = reclassify_greynoise(legacy_riot)
check("RIOT: malicious=False",               updated["malicious"] is False)
check("RIOT: authoritative_clean=True",      updated["authoritative_clean"] is True)
check("RIOT: label preserved",               updated["label"] == "greynoise_riot")


print("\n[4] GreyNoise reclassify is idempotent")
once = reclassify_greynoise(legacy_benign)
twice = reclassify_greynoise(once)
check("idempotent",
      twice["malicious"] == once["malicious"]
      and twice["authoritative_clean"] == once["authoritative_clean"]
      and twice["label"] == once["label"])


print("\n[4a] GreyNoise reclassify: 'suspicious' classification over RIOT")
# 130.131.195.135 shape: MS Azure RIOT-listed + GN classified suspicious.
# Old classifier returned (None, "greynoise_riot", ..., authoritative_clean=True).
# Fixed classifier returns informational greynoise_suspicious; no clean override.
ms_azure_legacy = {
    "malicious": False,                         # under the buggy interim
    "confidence": 8,
    "label": "greynoise_riot",                  # buggy interim picked riot
    "tags": ["greynoise_riot", "unknown"],
    "authoritative_clean": True,                # the bug
    "evidence_direct": False,
    "structured": {"in_greynoise": True,
                   "classification": "suspicious",
                   "name": "unknown",
                   "noise": True, "riot": True},
    "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
}
updated = reclassify_greynoise(ms_azure_legacy)
check("MS Azure case: label flips to suspicious",
      updated["label"] == "greynoise_suspicious",
      f"got {updated['label']}")
check("MS Azure case: authoritative_clean revoked",
      updated["authoritative_clean"] is False)
check("MS Azure case: malicious None (no vote)",
      updated["malicious"] is None)
check("MS Azure case: evidence_direct False",
      updated["evidence_direct"] is False)


print("\n[4b] rebuild_doc on MS Azure case: AbuseIPDB regains the consensus")
# Now exercise the full path: a doc with GN suspicious + AbuseIPDB 97
# should end up consensus_malicious=true (AbuseIPDB wins via any-positive
# rule with no clean override).
ms_doc = {
    "artifact": {"kind": "ip", "value": "130.131.195.135",
                 "first_observed_locally": "2026-05-17T00:00:00+00:00"},
    "providers": {
        "abuseipdb": {
            "malicious": True, "confidence": 9, "label": "abuseipdb_high",
            "tags": ["abuseipdb_score_97"],
            "structured": {"abuse_confidence_score": 97,
                           "total_reports": 200},
            "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
        },
        "greynoise": ms_azure_legacy,
    },
    "derived": {  # under the buggy interim
        "consensus_malicious": False,
        "consensus_label": "greynoise_riot",
        "override_applied": "authoritative_clean",
        "tags": ["abuseipdb_score_97", "greynoise_riot", "unknown"],
        "providers_with_data": 2,
        "providers_total": 2,
        "external_rarity_score": 0.0,
    },
    "last_refreshed": "...",
}
rebuilt = rebuild_doc(ms_doc)
check("MS Azure rebuild: consensus_malicious flips back to True",
      rebuilt["derived"]["consensus_malicious"] is True)
check("MS Azure rebuild: override_applied is empty (any-positive)",
      rebuilt["derived"]["override_applied"] == "")
check("MS Azure rebuild: consensus_label from AbuseIPDB",
      rebuilt["derived"]["consensus_label"] == "abuseipdb_high")


print("\n[5] GreyNoise reclassify: 404-shaped block (in_greynoise=False)")
legacy_404 = {
    "malicious": None, "label": None, "tags": [],
    "structured": {"in_greynoise": False},
    "raw": {"status": 404}, "fetched_at": "2026-05-16T00:00:00+00:00",
    "ttl_expires_at": "2026-05-23T00:00:00+00:00",
}
updated = reclassify_greynoise(legacy_404)
check("404 block: no opinion preserved",
      updated["malicious"] is None and updated["label"] is None
      and updated["authoritative_clean"] is False)


# -----------------------------------------------------------------------------
# FeodoTracker reclassification — direct evidence backfill
# -----------------------------------------------------------------------------

print("\n[6] FeodoTracker reclassify: active C2 block → evidence_direct=True")
feodo_hit = {
    "malicious": True, "confidence": 9, "label": "feodo_c2",
    "tags": ["feodo_c2", "emotet"],
    "structured": {"is_active_c2": True, "malware_family": "Emotet",
                   "port": 443, "first_seen": "2026-04-12 14:23:01",
                   "list_size": 423},
    "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
}
updated = reclassify_feodotracker(feodo_hit)
check("feodo hit: malicious True preserved", updated["malicious"] is True)
check("feodo hit: evidence_direct=True set", updated["evidence_direct"] is True)
check("feodo hit: authoritative_clean=False", updated["authoritative_clean"] is False)
check("feodo hit: label preserved",          updated["label"] == "feodo_c2")


print("\n[7] FeodoTracker reclassify: miss block → no flags set")
feodo_miss = {
    "malicious": None, "label": None, "tags": [],
    "structured": {"is_active_c2": False, "list_size": 423},
    "raw": {"row": None}, "fetched_at": "...", "ttl_expires_at": "...",
}
updated = reclassify_feodotracker(feodo_miss)
check("feodo miss: malicious None", updated["malicious"] is None)
check("feodo miss: no flags",
      updated["evidence_direct"] is False
      and updated["authoritative_clean"] is False)


# -----------------------------------------------------------------------------
# Passthrough — aggregator providers retain shape, gain default fields
# -----------------------------------------------------------------------------

print("\n[7a] AbuseIPDB reclassify: pre-fix doc (no is_whitelisted) reclassifies idempotent")
# Pre-2026-05-17 AbuseIPDB block had no `is_whitelisted` in structured.
# Reclassification should produce the same verdict as the original
# score-only logic (defensive default False).
pre_fix_abuse = {
    "malicious": True, "confidence": 9, "label": "abuseipdb_high",
    "tags": ["abuseipdb_score_85"],
    "structured": {
        "abuse_confidence_score": 85,
        "total_reports": 200,
        "num_distinct_users": 45,
        "country_code": "CN",
        "isp": "Some ISP",
        "usage_type": "Data Center/Web Hosting/Transit",
        "last_reported_at": "...",
        # NO is_whitelisted field — pre-fix shape
    },
    "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
}
updated = reclassify_abuseipdb(pre_fix_abuse)
check("pre-fix abuse: malicious True preserved",
      updated["malicious"] is True)
check("pre-fix abuse: label",
      updated["label"] == "abuseipdb_high")
check("pre-fix abuse: NOT authoritative_clean (no isWhitelisted info)",
      updated["authoritative_clean"] is False)
check("pre-fix abuse: NOT evidence_direct (aggregator)",
      updated["evidence_direct"] is False)
twice = reclassify_abuseipdb(updated)
check("pre-fix abuse: idempotent",
      twice["authoritative_clean"] is False and twice["malicious"] is True)


print("\n[7b] AbuseIPDB reclassify: post-fix whitelisted doc → authoritative_clean")
# A doc fetched AFTER the field-capture fix lands. is_whitelisted=True
# even though score is high — the canonical override case.
whitelisted_abuse = {
    "malicious": True, "confidence": 9, "label": "abuseipdb_high",  # under old rule
    "tags": ["abuseipdb_score_72"],
    "structured": {
        "abuse_confidence_score": 72,
        "total_reports": 30,
        "is_whitelisted": True,                    # the new field
        "hostnames": ["resolver.example.com"],
        "domain": "example.com",
        "is_tor": False,
        "country_code": "US",
        "isp": "Hurricane Electric LLC",
        "usage_type": "Data Center/Web Hosting/Transit",
        "last_reported_at": "...",
    },
    "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
}
updated = reclassify_abuseipdb(whitelisted_abuse)
check("whitelisted abuse: malicious flips to False",
      updated["malicious"] is False)
check("whitelisted abuse: authoritative_clean=True",
      updated["authoritative_clean"] is True)
check("whitelisted abuse: label flips",
      updated["label"] == "abuseipdb_whitelisted")
check("whitelisted abuse: score branch did NOT fire",
      "abuseipdb_high" not in updated["label"])


print("\n[7c] AbuseIPDB reclassify: structured preserved unchanged")
# Only the derived fields change; structured (hostnames / domain / etc.)
# must round-trip identically.
assert updated["structured"] is whitelisted_abuse["structured"]
check("structured object identity preserved",
      updated["structured"] is whitelisted_abuse["structured"])


print("\n[8] Passthrough reclassifier: no rule change, new fields default to False")
abuse_legacy = {
    "malicious": True, "confidence": 10, "label": "abuseipdb_high",
    "tags": ["abuseipdb_score_100"],
    "structured": {"abuse_confidence_score": 100, "total_reports": 412},
    "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
}
updated = reclassify_passthrough(abuse_legacy)
check("passthrough: malicious unchanged", updated["malicious"] is True)
check("passthrough: gains authoritative_clean=False",
      updated["authoritative_clean"] is False)
check("passthrough: gains evidence_direct=False",
      updated["evidence_direct"] is False)
check("passthrough: doesn't override existing values",
      reclassify_passthrough({**abuse_legacy, "authoritative_clean": True,
                              "evidence_direct": True})["authoritative_clean"] is True)


# -----------------------------------------------------------------------------
# rebuild_doc — full doc rewrite with new consensus
# -----------------------------------------------------------------------------

print("\n[9] rebuild_doc: ShadowServer doc flips consensus to clean")
# A doc with AbuseIPDB (aggregator, malicious=true) + GreyNoise (benign).
# Under the old contract: consensus=true.
# Under the new contract after rebuild: consensus=false, override=authoritative_clean.
shadowserver_doc = {
    "artifact": {"kind": "ip", "value": "216.218.206.67",
                 "first_observed_locally": "2026-05-16T00:00:00+00:00"},
    "providers": {
        "abuseipdb": {
            "malicious": True, "confidence": 10, "label": "abuseipdb_high",
            "tags": ["abuseipdb_score_100"],
            "structured": {"abuse_confidence_score": 100,
                           "total_reports": 412},
            "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
        },
        "greynoise": legacy_benign,                  # see test [1]
        "firehol": {
            "malicious": None, "label": None, "tags": [],
            "structured": {"matched": False, "matched_net": None,
                           "list_size_ips": 1, "list_size_nets": 4500},
            "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
        },
    },
    "derived": {
        # Old consensus — what we're migrating away from.
        "consensus_malicious": True,
        "consensus_label": "abuseipdb_high",
        "tags": ["abuseipdb_score_100", "greynoise_benign", "ShadowServer.org"],
        "providers_with_data": 1,
        "providers_total": 3,
        "external_rarity_score": 0.6667,
    },
    "last_refreshed": "2026-05-16T00:00:00+00:00",
}
rebuilt = rebuild_doc(shadowserver_doc)
check("ShadowServer: consensus flipped to clean",
      rebuilt["derived"]["consensus_malicious"] is False)
check("ShadowServer: override_applied=authoritative_clean",
      rebuilt["derived"]["override_applied"] == "authoritative_clean")
check("ShadowServer: label from GN",
      rebuilt["derived"]["consensus_label"] == "greynoise_benign")
check("ShadowServer: artifact preserved",
      rebuilt["artifact"]["value"] == "216.218.206.67")
check("ShadowServer: providers preserved",
      set(rebuilt["providers"].keys()) == {"abuseipdb", "greynoise", "firehol"})
# GN block has the new flags now
check("ShadowServer: GN block updated",
      rebuilt["providers"]["greynoise"]["authoritative_clean"] is True)
# AbuseIPDB block is passthrough — same data, no new flags lit
check("ShadowServer: AbuseIPDB block unchanged in semantics",
      rebuilt["providers"]["abuseipdb"]["malicious"] is True
      and rebuilt["providers"]["abuseipdb"]["evidence_direct"] is False)


print("\n[10] rebuild_doc: no-greynoise doc — consensus unchanged, fields added")
no_gn_doc = {
    "artifact": {"kind": "ip", "value": "1.2.3.4",
                 "first_observed_locally": "..."},
    "providers": {
        "abuseipdb": {
            "malicious": True, "label": "abuseipdb_high", "tags": [],
            "structured": {"abuse_confidence_score": 85},
            "raw": {}, "fetched_at": "...", "ttl_expires_at": "...",
        },
    },
    "derived": {"consensus_malicious": True, "consensus_label": "abuseipdb_high",
                "tags": [], "providers_with_data": 1, "providers_total": 1,
                "external_rarity_score": 0.0},
    "last_refreshed": "...",
}
rebuilt = rebuild_doc(no_gn_doc)
check("no-gn doc: still malicious",
      rebuilt["derived"]["consensus_malicious"] is True)
check("no-gn doc: override_applied empty",
      rebuilt["derived"]["override_applied"] == "")
check("no-gn doc: AbuseIPDB gains the default fields",
      rebuilt["providers"]["abuseipdb"]["authoritative_clean"] is False
      and rebuilt["providers"]["abuseipdb"]["evidence_direct"] is False)


print("\n[11] rebuild_doc is idempotent")
once = rebuild_doc(shadowserver_doc)
twice = rebuild_doc(once)
check("idempotent: same consensus",
      twice["derived"]["consensus_malicious"]
      == once["derived"]["consensus_malicious"])
check("idempotent: same override",
      twice["derived"]["override_applied"]
      == once["derived"]["override_applied"])


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
