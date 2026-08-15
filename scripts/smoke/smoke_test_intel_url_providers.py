"""Smoke test for M4 URL-kind providers.

Covers pure-function classifiers + parsers for URLhaus and ThreatFox.
The network paths are exercised post-deploy by `healthcheck --scope
intel` and the first `intel refresh` run.

Run from the repo root via the console venv:

    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_url_providers.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.intel.providers.threatfox import classify_threatfox
from enrich.intel.providers.urlhaus import classify_urlhaus, parse_urlhaus_csv

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
# URLhaus parse_urlhaus_csv
# -----------------------------------------------------------------------------

print("[1] parse_urlhaus_csv — REAL upstream format: `#`-prefixed header")
# Canonical URLhaus csv_online shape: preamble lines + an empty `#`
# line + the header (ALSO `#`-prefixed) + data rows.
real_shape = '''################################################################
# abuse.ch URLhaus Database Dump (CSV - online URLs only)      #
# Last updated: 2026-05-17 22:17:15 (UTC)                      #
#                                                              #
# Terms Of Use: https://urlhaus.abuse.ch/api/                  #
# For questions please contact urlhaus [at] abuse.ch           #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"42","2026-05-01 12:34:56","http://1.2.3.4/payload.exe","online","2026-05-15","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/42/","reporter1"
"43","2026-05-02 11:22:33","http://5.6.7.8/x.sh","online","2026-05-15","malware_download","sh,gafgyt","https://urlhaus.abuse.ch/url/43/","reporter2"
'''
parsed = parse_urlhaus_csv(real_shape)
check("two rows parsed", len(parsed) == 2)
check("keyed by url",
      "http://1.2.3.4/payload.exe" in parsed
      and "http://5.6.7.8/x.sh" in parsed)
check("threat field carried",
      parsed["http://1.2.3.4/payload.exe"]["threat"] == "malware_download")
check("tags carried",
      parsed["http://1.2.3.4/payload.exe"]["tags"] == "elf,mirai")


print("\n[1a] parse_urlhaus_csv — documentation-line-with-commas does NOT match as header")
# Regression guard: a `# Format: id,dateadded,url,...` documentation
# line contains `url` and commas but the first column "Format: id"
# isn't an identifier. Must not be mistaken for a header.
tricky = '''# Description
# Format: id, dateadded, url, url_status — see below
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"42","2026-05-01","http://x.com/a","online","2026-05-15","malware_download","tag1","link","reporter"
'''
parsed = parse_urlhaus_csv(tricky)
check("strict header detection skips documentation",
      len(parsed) == 1)
check("real header found, row keyed correctly",
      "http://x.com/a" in parsed
      and parsed["http://x.com/a"]["threat"] == "malware_download")


print("\n[2] parse_urlhaus_csv — defensive: empty / malformed input")
check("empty string → empty dict", parse_urlhaus_csv("") == {})
check("only comments → empty dict",
      parse_urlhaus_csv("# comment\n# another\n") == {})
check("no header → empty dict",
      parse_urlhaus_csv("just,some,random,values\n") == {})


print("\n[3] parse_urlhaus_csv — rows with column-count mismatch skipped")
mismatch = '''# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"42","2026-05-01","http://x.com/a","online"
"43","2026-05-02","http://y.com/b","online","2026-05-15","malware_download","tag1","link","reporter"
'''
parsed = parse_urlhaus_csv(mismatch)
check("mismatched-column row dropped", len(parsed) == 1)
check("well-formed row kept",
      "http://y.com/b" in parsed)


# -----------------------------------------------------------------------------
# URLhaus classify_urlhaus
# -----------------------------------------------------------------------------

print("\n[4] classify_urlhaus — miss returns no-opinion")
mal, label, conf, tags, ac, ed = classify_urlhaus(
    in_urlhaus=False, threat=None, tags=(),
)
check("miss: malicious None",      mal is None)
check("miss: label None",          label is None)
check("miss: tags empty",          tags == ())
check("miss: no flags",            ac is False and ed is False)


print("\n[5] classify_urlhaus — hit flips malicious + tags")
mal, label, conf, tags, ac, ed = classify_urlhaus(
    in_urlhaus=True, threat="malware_download", tags=("elf", "mirai"),
)
check("hit: malicious True",          mal is True)
check("hit: label includes threat",   label == "urlhaus_malware_download")
check("hit: confidence 9",            conf == 9)
check("hit: tags include match",      "urlhaus_match" in tags)
check("hit: tags include threat tag", "urlhaus_threat_malware_download" in tags)
check("hit: source tags carried",     "elf" in tags and "mirai" in tags)
check("hit: NOT evidence_direct (aggregator)", ed is False)


print("\n[6] classify_urlhaus — hit with no threat label")
mal, label, conf, tags, _, _ = classify_urlhaus(
    in_urlhaus=True, threat=None, tags=(),
)
check("no-threat hit: still malicious", mal is True)
check("no-threat hit: label uses 'unknown'", label == "urlhaus_unknown")
check("no-threat hit: urlhaus_match tag", "urlhaus_match" in tags)


print("\n[6a] classify_urlhaus — strips URLhaus 'None'/'null' sentinel tags")
# URLhaus uses the string `None` for empty cells; without filtering
# we'd carry it through as a junk 'none' tag and 'urlhaus_threat_none'
# label. This is a real-data regression observed on the live deploy.
mal, label, conf, tags, _, _ = classify_urlhaus(
    in_urlhaus=True, threat="None", tags=("None",),
)
check("threat='None' treated as unknown",
      label == "urlhaus_unknown",
      f"got {label!r}")
check("'None' sentinel filtered from tags",
      "none" not in tags and "None" not in tags,
      f"got {tags}")
check("urlhaus_match still present",
      "urlhaus_match" in tags)

# Mixed real + sentinel tags: keep the real ones, drop the sentinel
mal, label, conf, tags, _, _ = classify_urlhaus(
    in_urlhaus=True, threat="malware_download",
    tags=("elf", "None", "mirai", "null", ""),
)
check("mixed tags: real ones kept",
      "elf" in tags and "mirai" in tags)
check("mixed tags: sentinels dropped",
      "none" not in tags and "null" not in tags and "" not in tags)


# -----------------------------------------------------------------------------
# ThreatFox classify_threatfox
# -----------------------------------------------------------------------------

print("\n[7] classify_threatfox — empty data → no opinion")
mal, label, conf, tags, ac, ed = classify_threatfox([])
check("empty: all None / False",
      mal is None and label is None and tags == ()
      and ac is False and ed is False)


print("\n[8] classify_threatfox — single high-confidence entry")
entries = [{
    "threat_type": "botnet_cc",
    "malware": "Mirai",
    "confidence_level": 90,
}]
mal, label, conf, tags, ac, ed = classify_threatfox(entries)
check("high-conf: malicious True", mal is True)
check("high-conf: label includes threat_type",
      "botnet_cc" in (label or ""), f"got {label!r}")
check("high-conf: confidence 9", conf == 9)
check("high-conf: malware in tags", "mirai" in tags)
check("high-conf: threatfox_match tag", "threatfox_match" in tags)
check("high-conf: NOT evidence_direct (aggregator)", ed is False)


print("\n[9] classify_threatfox — multiple entries, picks highest-confidence")
entries = [
    {"threat_type": "payload_delivery", "malware": "X", "confidence_level": 60},
    {"threat_type": "botnet_cc",        "malware": "Y", "confidence_level": 90},
    {"threat_type": "spam",             "malware": "Z", "confidence_level": 75},
]
mal, label, conf, tags, _, _ = classify_threatfox(entries)
check("picks highest-confidence label",
      label and "botnet_cc" in label, f"got {label!r}")
check("confidence is from highest entry (90→9)", conf == 9)
# Documented behaviour: tags reflect ONLY the highest-confidence
# entry's malware (plus malware_alias). Lower-confidence entries
# don't contribute. This keeps the tag set focused; the full data
# is preserved in `structured.raw` for analyst inspection.
check("only highest-conf entry's malware in tags",
      "y" in tags and "x" not in tags and "z" not in tags,
      f"tags={tags}")


print("\n[10] classify_threatfox — entry with malware_alias deduplicated")
entries = [{
    "threat_type": "botnet_cc",
    "malware": "Mirai",
    "malware_alias": "Mirai",
    "confidence_level": 80,
}]
_, _, _, tags, _, _ = classify_threatfox(entries)
# 'mirai' should appear once despite being both malware and malware_alias.
mirai_count = sum(1 for t in tags if t == "mirai")
check("malware == alias deduplicated", mirai_count == 1,
      f"tags={tags}")


print("\n[11] classify_threatfox — entry with malware_alias differing")
entries = [{
    "threat_type": "botnet_cc",
    "malware": "Mirai",
    "malware_alias": "Linux/Mirai",
    "confidence_level": 80,
}]
_, _, _, tags, _, _ = classify_threatfox(entries)
check("both malware and alias present",
      "mirai" in tags and "linux/mirai" in tags,
      f"tags={tags}")


print("\n[12] classify_threatfox — confidence_level < 50 → informational only")
entries = [{
    "threat_type": "payload_delivery",
    "malware": "TestFamily",
    "confidence_level": 40,
}]
mal, label, conf, tags, _, _ = classify_threatfox(entries)
check("low-conf: malicious None",          mal is None)
check("low-conf: label threatfox_low",     label == "threatfox_low")
check("low-conf: malware in tags",         "testfamily" in tags)
check("low-conf: threatfox_low_confidence tag",
      "threatfox_low_confidence" in tags)


print("\n[13] classify_threatfox — confidence monotonicity in 50-100 band")
prev = -1
for conf_level in (50, 60, 70, 80, 90, 100):
    entries = [{"threat_type": "x", "malware": "y", "confidence_level": conf_level}]
    _, _, c, _, _, _ = classify_threatfox(entries)
    check(f"confidence_level={conf_level}: c={c} monotonic",
          c is not None and c >= prev,
          f"prev={prev}, c={c}")
    prev = c


print(f"\n— {len(PASSED)} pass, {len(FAILED)} fail —")
if FAILED:
    for n, d in FAILED:
        print(f"  ✗ {n}: {d}")
    sys.exit(1)
sys.exit(0)
