"""Smoke test for the M2 intel providers — GreyNoise + AbuseIPDB.

Exercises the pure-function verdict mappers (`classify_greynoise`,
`classify_abuseipdb`) so the smoke suite covers the verdict logic
without an HTTP call. Live HTTP paths are validated post-deploy by
`healthcheck --scope intel`.

Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_m2.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.intel.providers.abuseipdb import classify_abuseipdb
from enrich.intel.providers.greynoise import classify_greynoise


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
# GreyNoise classification mapping
# -----------------------------------------------------------------------------

print("[1] GreyNoise classify_greynoise — 'malicious' classification flips consensus")
mal, label, conf, tags, auth_clean, evid_direct = classify_greynoise(
    classification="malicious", is_noise=True, is_riot=False, name="Mirai",
)
check("malicious: True", mal is True)
check("malicious: label", label == "greynoise_malicious")
check("malicious: confidence 9", conf == 9)
check("malicious: name folded into tags",
      "Mirai" in tags or "mirai" in [t.lower() for t in tags])
check("malicious: evidence_direct=True (GN's own observation)", evid_direct is True)
check("malicious: authoritative_clean=False", auth_clean is False)


print("\n[2] 'benign' classification — flips authoritative_clean")
mal, label, conf, tags, auth_clean, evid_direct = classify_greynoise(
    classification="benign", is_noise=False, is_riot=True, name="Cloudflare DNS",
)
check("benign: malicious=False (override signal)", mal is False)
check("benign: label", label == "greynoise_benign")
check("benign: authoritative_clean=True", auth_clean is True)
check("benign: evidence_direct=False", evid_direct is False)


print("\n[3] RIOT (known-good infra) — authoritative_clean too")
mal, label, conf, tags, auth_clean, evid_direct = classify_greynoise(
    classification=None, is_noise=False, is_riot=True, name="Google Public DNS",
)
check("riot: malicious=False", mal is False)
check("riot: label riot", label == "greynoise_riot")
check("riot: authoritative_clean=True", auth_clean is True)


print("\n[3a] 'suspicious' classification — informational, NOT a clean override")
# This is the 130.131.195.135 fix: GreyNoise saying "we have concerns"
# should not be drowned out by RIOT-listing.
mal, label, conf, tags, auth_clean, evid_direct = classify_greynoise(
    classification="suspicious", is_noise=True, is_riot=True, name="unknown",
)
check("suspicious: malicious None (no vote)", mal is None)
check("suspicious: label greynoise_suspicious",
      label == "greynoise_suspicious")
check("suspicious: NOT authoritative_clean (does NOT override AbuseIPDB)",
      auth_clean is False)
check("suspicious: NOT evidence_direct (not a malicious vote)",
      evid_direct is False)
check("suspicious: takes priority over RIOT",
      auth_clean is False,
      "RIOT was True in the input but the suspicious branch fired first")


print("\n[4] noise=true unclassified — informational, NO clean override")
mal, label, conf, tags, auth_clean, evid_direct = classify_greynoise(
    classification="unknown", is_noise=True, is_riot=False, name="Shodan",
)
check("noise: malicious None (not flagged)", mal is None)
check("noise: label noise", label == "greynoise_noise")
check("noise: confidence band 6", conf == 6)
check("noise: NOT authoritative_clean (mass scanner ≠ confirmed-good)",
      auth_clean is False)
check("noise: name in tags",
      any("shodan" in t.lower() for t in tags),
      f"tags={tags}")


print("\n[5] unknown + no noise + no riot — no opinion")
mal, label, conf, tags, auth_clean, evid_direct = classify_greynoise(
    classification="unknown", is_noise=False, is_riot=False, name=None,
)
check("unknown: malicious None", mal is None)
check("unknown: no label", label is None)
check("unknown: no tags", tags == ())
check("unknown: no flags set", auth_clean is False and evid_direct is False)


print("\n[6] empty / None classification handled gracefully")
mal, label, conf, tags, auth_clean, evid_direct = classify_greynoise(
    classification=None, is_noise=False, is_riot=False, name=None,
)
check("None classification: all None / False",
      mal is None and label is None and tags == ()
      and auth_clean is False and evid_direct is False)


# -----------------------------------------------------------------------------
# AbuseIPDB classification mapping
# -----------------------------------------------------------------------------

print("\n[7] AbuseIPDB — score >= 50 flips malicious=True (aggregator, NOT direct)")
mal, label, conf, tags, ac, ed = classify_abuseipdb(
    abuse_score=95, total_reports=412,
    usage_type="Data Center/Web Hosting/Transit",
)
check("score 95: malicious True", mal is True)
check("score 95: label high", label == "abuseipdb_high")
check("score 95: confidence in upper band",
      conf is not None and conf >= 9,
      f"got {conf}")
check("score 95: NOT evidence_direct (aggregated reports)", ed is False)
check("score 95: NOT authoritative_clean", ac is False)
check("usage_type folded as a tag",
      any("data_center" in t.lower() or "abuseipdb_usage" in t for t in tags),
      f"got tags={tags}")
check("score embedded in tags",
      any("95" in t for t in tags),
      f"got tags={tags}")


print("\n[7a] AbuseIPDB isWhitelisted=True flips authoritative_clean (override)")
# Canonical override case: AbuseIPDB's own whitelist says this is good
# infrastructure (Cloudflare/Google/well-known-scanner-class). Should
# override aggregator-only malicious votes from FireHOL / ISC / etc.
mal, label, conf, tags, ac, ed = classify_abuseipdb(
    abuse_score=95,                              # would otherwise flip malicious
    total_reports=200,
    usage_type=None,
    is_whitelisted=True,
)
check("whitelisted: malicious=False", mal is False)
check("whitelisted: label", label == "abuseipdb_whitelisted")
check("whitelisted: authoritative_clean=True", ac is True)
check("whitelisted: evidence_direct=False", ed is False)
check("whitelisted: tag present",
      "abuseipdb_whitelisted" in tags,
      f"got {tags}")
check("whitelisted: score branch did NOT fire",
      "abuseipdb_high" not in label,
      f"label={label}")


print("\n[8] AbuseIPDB — score 50 exactly is the cutoff (no whitelist)")
mal, _, conf, _, ac, ed = classify_abuseipdb(
    abuse_score=50, total_reports=2, usage_type=None,
)
check("score 50: malicious True (boundary inclusive)", mal is True)
check("score 50: confidence 5", conf == 5)
check("score 50: NOT evidence_direct", ed is False)


print("\n[9] AbuseIPDB — score below 50 is informational only")
mal, label, conf, _, ac, _ = classify_abuseipdb(
    abuse_score=25, total_reports=1, usage_type=None,
)
check("score 25: malicious None (informational)", mal is None)
check("score 25: label low", label == "abuseipdb_low")
check("score 25: confidence None", conf is None)
check("score 25: NOT authoritative_clean (low score ≠ benign vote)", ac is False)


print("\n[10] AbuseIPDB — score 0 with no reports = no opinion")
mal, label, _, _, ac, _ = classify_abuseipdb(
    abuse_score=0, total_reports=0, usage_type=None,
)
check("score 0 / 0 reports: malicious None", mal is None)
check("score 0 / 0 reports: no label", label is None)
check("score 0 / 0 reports: no flags", ac is False)


print("\n[11] AbuseIPDB — None score handled")
mal, label, conf, tags, ac, ed = classify_abuseipdb(
    abuse_score=None, total_reports=None, usage_type=None,
)
check("None score: all None",
      mal is None and label is None and tags == ()
      and ac is False and ed is False)


print("\n[11a] AbuseIPDB — None score + whitelisted should still no-op")
# Defensive: if the API returns isWhitelisted=true but no score (rare /
# error case), we don't want to fire the clean override on bad input.
mal, label, conf, tags, ac, ed = classify_abuseipdb(
    abuse_score=None, total_reports=None, usage_type=None,
    is_whitelisted=True,
)
check("None score + whitelisted: no opinion (defensive)",
      mal is None and ac is False)


print("\n[12] AbuseIPDB — confidence monotonicity in 50-100 band")
prev = -1
for score in (50, 60, 70, 80, 90, 100):
    _, _, c, _, _, _ = classify_abuseipdb(
        abuse_score=score, total_reports=10, usage_type=None,
    )
    check(f"score {score}: conf monotonic (got {c})",
          c is not None and c >= prev, f"prev={prev}, c={c}")
    if c is not None:
        prev = c


print("\n[13] AbuseIPDB whitelist beats score across boundary")
# Sweep: whitelisted IPs at every score level should all be authoritative_clean.
for score in (0, 25, 50, 75, 100):
    mal, _, _, _, ac, _ = classify_abuseipdb(
        abuse_score=score, total_reports=10, usage_type=None,
        is_whitelisted=True,
    )
    check(f"whitelisted at score={score}: clean",
          mal is False and ac is True,
          f"got mal={mal} ac={ac}")


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
