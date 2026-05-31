"""Two-pass narrative incident write-up — Item #2 of the analyst-first
UX push.

The Report modal already assembles paste-ready raw material across 11
categories. The analyst's actual deliverable — a SANS ISC diary entry,
a SOC writeup, the README's `cmp-beh-…` paragraph — is *prose*, not a
CSV. This module produces that prose via a two-pass pipeline:

  Pass 1 EXTRACT  : Heavy context → strict JSON brief (structured
                    analytical judgments + cite-able identifiers).
                    Always local LLM.
  Verify          : Server-side cite-check — every key_identifier
                    value in the brief must appear verbatim in the
                    source context. Strips ones that don't.
  Pass 2 NARRATE  : Brief only (small) → 3-4 paragraphs of plain prose.
                    Local LLM by default; cloud opt-in (cloud only ever
                    sees the small validated brief, never the raw
                    context).
  Cite-check      : Regex sweep of the prose for sha256/IPv4/URL/MITRE
                    /ASN. Any concrete identifier not in the brief or
                    the source context → strip the containing sentence
                    with an inline footnote.

This means by the time the analyst sees prose, every concrete
identifier in it has been validated twice (once via the brief schema,
once via the regex sweep). The brief itself is exposed in the UI as a
collapsible structured fallback.

Reuses:
  - The cluster-pair-explanation prompt-from-template + structured-JSON
    pattern (see `src/enrich/sources/cowrie/explain.py`).
  - The narrative module's cloud-LLM client builder pattern
    (`src/enrich/findings/narrative._make_client`).
  - The fencing module for attacker-controlled command text in Pass 1
    (`src/enrich/llm/fencing.py`). Pass 2 sees only the validated brief.
"""
from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from enrich.llm.fencing import FENCE_NOTICE, fence, make_nonce

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt loading + rendering
# ---------------------------------------------------------------------------

_PROMPT_DIR = Path(__file__).resolve().parents[3] / "config" / "prompts"
_EXTRACT_PATH = _PROMPT_DIR / "writeup_extract.txt"
_NARRATE_PATH = _PROMPT_DIR / "writeup_narrate.txt"


def load_extract_template() -> str:
    return _EXTRACT_PATH.read_text(encoding="utf-8")


def load_narrate_template() -> str:
    return _NARRATE_PATH.read_text(encoding="utf-8")


def _safe_str(v: Any, max_len: int = 200) -> str:
    s = "" if v is None else str(v)
    return s[:max_len]


# ---------------------------------------------------------------------------
# Scope rendering for Pass 1
# ---------------------------------------------------------------------------

def _format_scope_summary(scope: dict, nonce: str) -> str:
    """Render the in-view artifact aggregates as the SCOPE_SUMMARY block.

    Carries every category the Report modal collates: IPs (with country
    + ASN + HASSH + intel verdict), commands (text + intent + MITRE),
    sessions, credentials, URLs, file hashes (with filename + dropping
    command), analyst artifacts, lifecycle notes, HASSH aggregate, and
    session sequences.

    Attacker-controlled fields (command lines, URLs, filenames, session
    ids, credentials) get nonce-fenced. Counts and analyst-trusted
    aggregates do not.
    """
    lines: list[str] = []

    # --- IPs --------------------------------------------------------------
    ips = scope.get("ips") or []
    if ips:
        country_buckets: dict[str, int] = {}
        asn_buckets: dict[str, int] = {}
        intel_buckets: dict[str, int] = {}
        hassh_buckets: dict[str, int] = {}
        for e in ips:
            if not isinstance(e, dict):
                continue
            if e.get("country"): country_buckets[e["country"]] = country_buckets.get(e["country"], 0) + 1
            if e.get("asn"):     asn_buckets[str(e["asn"])] = asn_buckets.get(str(e["asn"]), 0) + 1
            v = (e.get("intel_verdict") or "").lower()
            if v: intel_buckets[v] = intel_buckets.get(v, 0) + 1
            if e.get("hassh"):   hassh_buckets[str(e["hassh"])[:16]] = hassh_buckets.get(str(e["hassh"])[:16], 0) + 1
        lines.append(f"IPs ({len(ips)} total)")
        if country_buckets:
            top = sorted(country_buckets.items(), key=lambda kv: -kv[1])[:10]
            lines.append("  countries: " + ", ".join(f"{k}({v})" for k, v in top))
        if asn_buckets:
            top = sorted(asn_buckets.items(), key=lambda kv: -kv[1])[:10]
            lines.append("  ASNs: " + ", ".join(f"AS{k}({v})" for k, v in top))
        if intel_buckets:
            lines.append("  intel verdicts: " + ", ".join(f"{k}={v}" for k, v in sorted(intel_buckets.items(), key=lambda kv: -kv[1])))
        if hassh_buckets:
            lines.append("  HASSH fingerprints: " + ", ".join(f"{k}…({v})" for k, v in sorted(hassh_buckets.items(), key=lambda kv: -kv[1])[:5]))
        sample_ips = [
            _safe_str(e.get("ip") if isinstance(e, dict) else e, 60)
            for e in ips[:15]
        ]
        sample_ips = [ip for ip in sample_ips if ip]
        if sample_ips:
            lines.append("  sample IPs (literals — cite by exact value): " + ", ".join(sample_ips))

    # --- Commands ---------------------------------------------------------
    commands = scope.get("commands") or []
    if commands:
        intent_buckets: dict[str, int] = {}
        for c in commands:
            if isinstance(c, dict) and c.get("intent"):
                intent_buckets[c["intent"]] = intent_buckets.get(c["intent"], 0) + 1
        lines.append(f"Commands ({len(commands)} total)")
        if intent_buckets:
            top = sorted(intent_buckets.items(), key=lambda kv: -kv[1])[:8]
            lines.append("  intents: " + ", ".join(f"{k}({v})" for k, v in top))
        cmd_lines: list[str] = []
        for c in commands[:30]:
            if not isinstance(c, dict):
                continue
            txt = _safe_str(c.get("command_line") or c.get("text"), 200)
            if not txt:
                continue
            sha = _safe_str(c.get("sha256"), 16)
            intent = _safe_str(c.get("intent"), 40)
            tail = []
            if sha:    tail.append(f"sha={sha}")
            if intent: tail.append(f"intent={intent}")
            cmd_lines.append(f"  - {txt}" + (f"   [{', '.join(tail)}]" if tail else ""))
        if cmd_lines:
            lines.append(fence("commands", "\n".join(cmd_lines), nonce))

    # --- Sessions ---------------------------------------------------------
    sessions = scope.get("sessions") or []
    if sessions:
        lines.append(f"Sessions ({len(sessions)} total)")
        sids = [_safe_str(s.get("session_id") if isinstance(s, dict) else s, 32)
                for s in sessions[:10]]
        sids = [s for s in sids if s]
        if sids:
            lines.append(fence("session_ids", "  sample: " + ", ".join(sids), nonce))

    # --- Credentials ------------------------------------------------------
    creds = scope.get("credentials") or []
    if creds:
        lines.append(f"Credentials observed ({len(creds)} unique user:pass pairs)")
        cred_lines = ["  - " + _safe_str(c, 80) for c in creds[:15]]
        if cred_lines:
            lines.append(fence("credentials", "\n".join(cred_lines), nonce))

    # --- URLs -------------------------------------------------------------
    urls = scope.get("urls") or []
    if urls:
        url_lines = []
        host_buckets: dict[str, int] = {}
        for u in urls[:30]:
            url_str = u.get("url") if isinstance(u, dict) else u
            url_str = _safe_str(url_str, 250)
            if not url_str:
                continue
            url_lines.append("  - " + url_str)
            # Cheap host extraction for the aggregate.
            try:
                from urllib.parse import urlparse
                host = urlparse(url_str).hostname or ""
                if host:
                    host_buckets[host] = host_buckets.get(host, 0) + 1
            except Exception:
                pass
        lines.append(f"URLs ({len(urls)} total) — literals, cite hosts by exact value:")
        if host_buckets:
            top = sorted(host_buckets.items(), key=lambda kv: -kv[1])[:8]
            lines.append("  top hosts: " + ", ".join(f"{k}({v})" for k, v in top))
        if url_lines:
            lines.append(fence("urls", "\n".join(url_lines), nonce))

    # --- File hashes ------------------------------------------------------
    hashes = scope.get("hashes") or []
    if hashes:
        lines.append(f"File hashes ({len(hashes)} total) — literals, cite by exact value or sha256 prefix:")
        hash_lines = []
        for h in hashes[:20]:
            if isinstance(h, dict):
                sha = _safe_str(h.get("sha256") or h.get("hash"), 100)
                fn = _safe_str(h.get("filename"), 80)
                drop = _safe_str(h.get("dropping_cmd"), 100)
                attr = _safe_str(h.get("attribution"), 40)
                intel = _safe_str(h.get("intel_verdict"), 40)
                tail = []
                if fn:    tail.append(f"file={fn}")
                if drop:  tail.append(f"dropped_by={drop}")
                if attr:  tail.append(f"attr={attr}")
                if intel: tail.append(f"intel={intel}")
                hash_lines.append(f"  - {sha}" + (f"   [{', '.join(tail)}]" if tail else ""))
            else:
                hash_lines.append("  - " + _safe_str(h, 100))
        lines.append(fence("hashes", "\n".join(hash_lines), nonce))

    # --- Analyst artifacts ------------------------------------------------
    artifacts = scope.get("analyst_artifacts") or []
    if artifacts:
        lines.append(f"Analyst-defined artifacts ({len(artifacts)} hits) — analyst-trusted tags on the data:")
        for a in artifacts[:15]:
            if isinstance(a, dict):
                k = _safe_str(a.get("kind"), 40)
                v = _safe_str(a.get("value"), 120)
                note = _safe_str(a.get("notes") or a.get("rule_notes"), 200)
                lines.append(f"  - {k}: {v}" + (f"   [analyst note: {note}]" if note else ""))

    # --- Lifecycle notes --------------------------------------------------
    notes = scope.get("lifecycle_notes") or []
    if notes:
        lines.append(f"Analyst-authored lifecycle notes ({len(notes)}) — prior analyst observations on these artifacts:")
        for n in notes[:8]:
            if isinstance(n, dict):
                anchor = _safe_str(n.get("anchor_label") or n.get("artifact_value"), 80)
                txt    = _safe_str(n.get("text") or n.get("note"), 300)
                lines.append(f"  - on {anchor}: {txt}")

    # --- Session sequences ------------------------------------------------
    seqs = scope.get("session_sequences") or []
    if seqs:
        lines.append(f"Session command sequences ({len(seqs)} sessions, ordered):")
        seq_lines = []
        for s in seqs[:5]:
            if not isinstance(s, dict):
                continue
            sid = _safe_str(s.get("session_id"), 32)
            steps = s.get("commands") or s.get("steps") or []
            if not isinstance(steps, list):
                continue
            seq_lines.append(f"  session {sid}:")
            for i, step in enumerate(steps[:20], 1):
                seq_lines.append(f"    {i}. " + _safe_str(step, 180))
        if seq_lines:
            lines.append(fence("session_sequences", "\n".join(seq_lines), nonce))

    # --- Playbooks / campaigns identity -----------------------------------
    pbs = scope.get("playbooks") or []
    if pbs:
        names = ", ".join(
            _safe_str(p.get("name") if isinstance(p, dict) else p, 80)
            for p in pbs[:10]
        )
        lines.append(f"Playbooks ({len(pbs)}): {names}")

    cmps = scope.get("campaigns") or []
    if cmps:
        names = ", ".join(
            _safe_str(c.get("name") if isinstance(c, dict) else c, 80)
            for c in cmps[:10]
        )
        lines.append(f"Campaigns ({len(cmps)}): {names}")

    return "\n".join(lines) if lines else "(no in-view scope provided)"


def _format_mitre_chain(mitre: list) -> str:
    if not mitre:
        return "(no MITRE techniques identified across in-view commands)"
    # Accept either the agg-rows shape [{tactic_id, technique_id, command_count}, ...]
    # or the raw aggregate row [id, type, count] from buildMitreAggregate.
    by_kind: dict[str, list[tuple[str, int]]] = {"tactic": [], "technique": []}
    for e in mitre:
        if isinstance(e, dict):
            tid = e.get("tactic_id") or ""
            tech = e.get("technique_id") or ""
            cnt = int(e.get("command_count") or 0)
            # An entry may carry both — record each in its own bucket so
            # neither dimension is silently dropped.
            if tech:
                by_kind["technique"].append((tech, cnt))
            if tid:
                by_kind["tactic"].append((tid, cnt))
        elif isinstance(e, (list, tuple)) and len(e) >= 3:
            ident, kind, cnt = e[0], e[1], int(e[2] or 0)
            if kind in by_kind:
                by_kind[kind].append((str(ident), cnt))
    lines = []
    if by_kind["tactic"]:
        top = sorted(by_kind["tactic"], key=lambda kv: -kv[1])
        lines.append("  tactics: " + ", ".join(f"{k}({v})" for k, v in top))
    if by_kind["technique"]:
        top = sorted(by_kind["technique"], key=lambda kv: -kv[1])
        lines.append("  techniques: " + ", ".join(f"{k}({v})" for k, v in top))
    return "\n".join(lines) if lines else "(no MITRE techniques identified across in-view commands)"


def _format_intel_summary(intel: dict) -> str:
    if not intel:
        return "(no intel verdicts provided)"
    parts = []
    for kind in ("ip", "url", "hash"):
        verdicts = intel.get(kind) or {}
        cleaned = {k: v for k, v in verdicts.items() if v}
        if cleaned:
            parts.append(f"  {kind}: " + ", ".join(f"{k}={v}" for k, v in cleaned.items()))
    return "\n".join(parts) if parts else "(no intel verdicts provided)"


def build_extract_prompt(
    anchor: dict, scope: dict, evidence_quality: str, nonce: str,
) -> str:
    """Substitute the Pass 1 extract prompt template's placeholders."""
    tmpl = load_extract_template()
    repl = {
        "<<<ANCHOR_KIND>>>":      _safe_str(anchor.get("kind"), 64),
        "<<<ANCHOR_NAME>>>":      _safe_str(anchor.get("name"), 200),
        "<<<ANCHOR_EVIDENCE>>>":  _safe_str(anchor.get("evidence"), 400),
        "<<<ANCHOR_WINDOW>>>":    _safe_str(anchor.get("window"), 100),
        "<<<SCOPE_SUMMARY>>>":    _format_scope_summary(scope, nonce),
        "<<<MITRE_CHAIN>>>":      _format_mitre_chain(scope.get("mitre") or []),
        "<<<INTEL_SUMMARY>>>":    _format_intel_summary(scope.get("intel") or {}),
        "<<<EVIDENCE_QUALITY>>>": _safe_str(evidence_quality, 200) or "(no verdict)",
    }
    for k, v in repl.items():
        tmpl = tmpl.replace(k, v)
    return tmpl


def build_narrate_prompt(brief: dict) -> str:
    """Substitute the Pass 2 narrate prompt template's only placeholder."""
    tmpl = load_narrate_template()
    return tmpl.replace("<<<BRIEF_JSON>>>", json.dumps(brief, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Brief schema + parsing
# ---------------------------------------------------------------------------

_BRIEF_KEYS: tuple[str, ...] = (
    "timeframe_phrase",
    "scale_phrase",
    "what_they_did",
    "what_they_wanted",
    "actor_model",
    "viability_assessment",
    "key_identifiers",
    "concerning_signals",
    "evidence_gaps",
    "confidence_band",
    "confidence_reasoning",
    "defensive_angle",
)

_VALID_CONFIDENCE_BANDS = {"high", "moderate", "single-point"}


# Small models routinely wrap JSON in prose; walk the response to find
# the first balanced {...} object (respecting string literals + escapes).
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)
# Reasoning models (Qwen3, DeepSeek-R1, gpt-oss) emit a <think>…</think>
# trace alongside their final output. Strip it before the cite-check —
# the analyst doesn't want chain-of-thought in their writeup, and the
# trace contains identifiers we wouldn't want the cite-check to inspect.
_THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL | re.IGNORECASE)
# Some models leak the closing tag without an opening one when the
# trace exceeds context — strip dangling closers too.
_THINK_TAIL_RE = re.compile(r"^.*?</think>\s*", re.DOTALL | re.IGNORECASE)


def _clean_model_artifacts(text: str) -> str:
    """Strip code-fence wrapping + <think>…</think> reasoning traces.

    Run on Pass 2 output before cite-check so the analyst-facing prose
    is just the prose, not the model's chain-of-thought. Cite-check
    needs this too — a hash mentioned in the reasoning trace shouldn't
    "verify" a hallucinated hash in the final answer.
    """
    s = (text or "").strip()
    # Reasoning trace blocks
    s = _THINK_RE.sub("", s)
    # If a `</think>` survived (orphaned opening tag truncated), drop
    # everything up to and including it.
    if "</think>" in s.lower():
        s = _THINK_TAIL_RE.sub("", s)
    # Code fence wrapping
    if s.startswith("```"):
        s = _FENCE_RE.sub("", s, count=2)
    return s.strip()


def _extract_first_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def parse_brief_response(text: str) -> Optional[dict]:
    """Parse the Pass 1 LLM response into the brief shape.

    Lenient: handles reasoning-model <think> traces, code-fenced JSON,
    prose around the JSON, and backfills missing keys with empty
    strings / lists so the schema is always complete. Returns None
    only on hard parse failure.
    """
    if not text:
        return None
    # Strip reasoning traces FIRST so they don't pollute the JSON walk.
    s = _clean_model_artifacts(text)
    data = None
    try:
        data = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        cand = _extract_first_json_object(s)
        if cand:
            try:
                data = json.loads(cand)
            except (json.JSONDecodeError, ValueError):
                data = None
    if not isinstance(data, dict):
        return None

    def _as_str(v: Any) -> str:
        if isinstance(v, str):
            return v.strip()
        return str(v or "").strip()

    def _as_list_of_str(v: Any) -> list[str]:
        if isinstance(v, list):
            return [str(x).strip() for x in v if x]
        if isinstance(v, str) and v.strip():
            return [v.strip()]
        return []

    def _as_identifiers(v: Any) -> list[dict]:
        out: list[dict] = []
        if not isinstance(v, list):
            return out
        for e in v:
            if not isinstance(e, dict):
                continue
            value = _as_str(e.get("value"))
            if not value:
                continue
            out.append({
                "label":          _as_str(e.get("label")) or "identifier",
                "value":          value,
                "why_it_matters": _as_str(e.get("why_it_matters")),
            })
        return out

    band = _as_str(data.get("confidence_band")).lower()
    if band not in _VALID_CONFIDENCE_BANDS:
        band = "moderate"  # default — never error on a free-form band string

    return {
        "timeframe_phrase":     _as_str(data.get("timeframe_phrase")),
        "scale_phrase":         _as_str(data.get("scale_phrase")),
        "what_they_did":        _as_str(data.get("what_they_did")),
        "what_they_wanted":     _as_str(data.get("what_they_wanted")),
        "actor_model":          _as_str(data.get("actor_model")),
        "viability_assessment": _as_str(data.get("viability_assessment")),
        "key_identifiers":      _as_identifiers(data.get("key_identifiers")),
        "concerning_signals":   _as_list_of_str(data.get("concerning_signals")),
        "evidence_gaps":        _as_list_of_str(data.get("evidence_gaps")),
        "confidence_band":      band,
        "confidence_reasoning": _as_str(data.get("confidence_reasoning")),
        "defensive_angle":      _as_str(data.get("defensive_angle")),
    }


# ---------------------------------------------------------------------------
# Brief cite-check — strip key_identifiers not present verbatim in source
# ---------------------------------------------------------------------------

def verify_brief_against_source(brief: dict, source_text: str) -> tuple[dict, list[str]]:
    """Strip key_identifiers whose value doesn't appear in the source.

    Returns (cleaned_brief, dropped_values). The Pass 2 narrate stage
    can then only cite identifiers we've already proven came from the
    data — the model can't smuggle a hallucinated sha256 through.
    """
    if not brief or not isinstance(brief.get("key_identifiers"), list):
        return brief, []
    src_lower = (source_text or "").lower()
    kept: list[dict] = []
    dropped: list[str] = []
    for ident in brief["key_identifiers"]:
        value = (ident.get("value") or "").strip()
        if not value:
            continue
        # Verbatim presence — case-insensitive (hex hashes are sometimes
        # rendered upper case in source). Substring is correct here: a
        # short sha256 prefix may legitimately appear inside a longer one.
        if value.lower() in src_lower:
            kept.append(ident)
        else:
            dropped.append(value)
    cleaned = dict(brief)
    cleaned["key_identifiers"] = kept
    return cleaned, dropped


# ---------------------------------------------------------------------------
# Pass 2 cite-check — strip prose sentences citing unverified identifiers
# ---------------------------------------------------------------------------

# Patterns the cite-check looks for in the prose. Any match that's NOT
# in the brief's key_identifiers or the source context is treated as a
# hallucinated citation.
_CITE_PATTERNS = (
    # sha256 (with or without the "sha256:" prefix; 12+ hex chars to
    # avoid matching short hex chunks inside words). Matches full 64-char
    # hashes and the truncated "sha256:c2c1…" form the narrate prompt
    # encourages.
    ("sha256",          re.compile(r"\b(?:sha256:)?([0-9a-f]{12,64})\b", re.IGNORECASE)),
    # IPv4 (with simple octet-range validation in the post-filter).
    ("ipv4",            re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")),
    # URL — capture host portion so we can match it against the brief's
    # values even when the brief carries just the hostname.
    ("url",             re.compile(r"\bhttps?://([^\s<>\"',)]+)", re.IGNORECASE)),
    # MITRE techniques (T1234 / T1234.005)
    ("mitre_technique", re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")),
    # MITRE tactics (TA0001 …)
    ("mitre_tactic",    re.compile(r"\b(TA\d{4})\b")),
    # ASN — capture digits only
    ("asn",             re.compile(r"\bAS(\d{1,7})\b")),
)


def _normalize_for_compare(s: str) -> str:
    return (s or "").lower().strip()


def _identifier_appears_in(value: str, haystacks: tuple[str, ...]) -> bool:
    v = _normalize_for_compare(value)
    if not v:
        return False
    return any(v in h for h in haystacks)


def _looks_like_valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _split_into_sentences(prose: str) -> list[str]:
    """Best-effort sentence split. Keeps trailing punctuation per
    sentence and preserves paragraph breaks as their own elements so
    rejoining doesn't collapse layout.
    """
    out: list[str] = []
    for para in prose.split("\n\n"):
        # Crude: split on sentence-ending punctuation followed by space + cap.
        # Keep the delimiter on the preceding sentence.
        parts = re.split(r"(?<=[.!?])\s+(?=[A-Z(\"'])", para.strip())
        for p in parts:
            p = p.strip()
            if p:
                out.append(p)
        out.append("\n\n")  # paragraph separator marker
    if out and out[-1] == "\n\n":
        out.pop()
    return out


def cite_check_prose(prose: str, brief: dict, source_text: str) -> tuple[str, list[dict]]:
    """Strip sentences citing identifiers not in the brief or source.

    Returns (cleaned_prose, redactions). Each redaction is
    `{sentence, identifier, kind}` — the UI uses these for inline
    footnotes.
    """
    if not prose:
        return prose, []
    # Build the verified-identifier haystack (case-insensitive).
    src_lower = _normalize_for_compare(source_text)
    brief_lower_blobs: list[str] = []
    for ident in (brief.get("key_identifiers") or []):
        v = ident.get("value") or ""
        if v:
            brief_lower_blobs.append(_normalize_for_compare(v))
    haystacks = (src_lower, *brief_lower_blobs)

    sentences = _split_into_sentences(prose)
    cleaned_pieces: list[str] = []
    redactions: list[dict] = []
    seen_redacted_idents: set[str] = set()

    for s in sentences:
        if s == "\n\n":
            cleaned_pieces.append(s)
            continue
        offending: Optional[tuple[str, str]] = None  # (kind, identifier)
        for kind, pat in _CITE_PATTERNS:
            for m in pat.finditer(s):
                ident = m.group(1) if m.lastindex else m.group(0)
                # Domain-specific filtering — false positives that
                # aren't actually citations of attacker artifacts.
                if kind == "ipv4" and not _looks_like_valid_ipv4(ident):
                    continue
                if kind == "sha256" and len(ident) < 12:
                    continue
                if not _identifier_appears_in(ident, haystacks):
                    offending = (kind, ident)
                    break
            if offending:
                break
        if offending is None:
            cleaned_pieces.append(s)
            continue
        # Strip the sentence; emit an inline footnote in its place. Each
        # unverified identifier is only flagged once even if it appears
        # in multiple sentences.
        kind, ident = offending
        dup_key = f"{kind}:{ident.lower()}"
        if dup_key not in seen_redacted_idents:
            redactions.append({
                "sentence":   s,
                "identifier": ident,
                "kind":       kind,
            })
            seen_redacted_idents.add(dup_key)
        cleaned_pieces.append(
            f"_(sentence removed: cited unverified {kind} «{ident}»)_"
        )

    # Re-glue. Insert single spaces between consecutive sentences and
    # preserve the paragraph markers.
    out_parts: list[str] = []
    last_was_para = False
    for piece in cleaned_pieces:
        if piece == "\n\n":
            out_parts.append("\n\n")
            last_was_para = True
            continue
        if out_parts and not last_was_para:
            out_parts.append(" ")
        out_parts.append(piece)
        last_was_para = False
    cleaned = "".join(out_parts).strip()
    return cleaned, redactions


# ---------------------------------------------------------------------------
# Local LLM call (mirrors /api/ask pattern)
# ---------------------------------------------------------------------------

def call_local(
    llm_cfg: Any, prompt: str, system_prompt: str, *, max_tokens: int = 2048,
) -> tuple[str, int, int]:
    headers = {"Content-Type": "application/json"}
    if llm_cfg.api_key:
        headers["Authorization"] = f"Bearer {llm_cfg.api_key}"
    base = llm_cfg.base_url.rstrip("/").removesuffix("/v1")
    payload = {
        "model": llm_cfg.generation_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": max_tokens,
        "stream": False,
    }
    r = httpx.post(
        f"{base}/v1/chat/completions",
        json=payload,
        headers=headers,
        timeout=llm_cfg.request_timeout,
    )
    r.raise_for_status()
    data = r.json()
    text = data["choices"][0]["message"]["content"] or ""
    usage = data.get("usage") or {}
    return text, int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)


# ---------------------------------------------------------------------------
# Cloud LLM call + budget gate (writeup-specific bucket)
# ---------------------------------------------------------------------------

def _utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def writeup_budget_remaining_usd(db: Any, cfg: Any) -> float:
    cap = float(getattr(cfg.cloud, "writeup_daily_budget_usd", 0.0) or 0.0)
    if cap <= 0.0:
        return 0.0
    spent = db.get_writeup_spend(_utc_today())["cost_usd"]
    return max(0.0, cap - spent)


def writeup_budget_status(db: Any, cfg: Any) -> dict:
    cap = float(getattr(cfg.cloud, "writeup_daily_budget_usd", 0.0) or 0.0)
    spent = db.get_writeup_spend(_utc_today())["cost_usd"] if cap > 0.0 else 0.0
    remaining = max(0.0, cap - spent) if cap > 0.0 else 0.0
    return {
        "cap_usd":       cap,
        "spent_usd":     round(spent, 4),
        "remaining_usd": round(remaining, 4),
        "enabled":       cap > 0.0,
        "available":     cap > 0.0 and remaining > 0.0,
        "cloud_enabled": bool(cfg.cloud.enabled),
    }


def call_cloud(
    cfg: Any, secrets: Any, db: Any,
    prompt: str, system_prompt: str, *, max_tokens: int = 2048,
) -> tuple[str, int, int, float]:
    if not cfg.cloud.enabled:
        raise RuntimeError("cloud LLM disabled in config")
    if cfg.cloud.provider != "anthropic":
        raise RuntimeError(f"cloud.provider={cfg.cloud.provider} unsupported for writeup")
    cap = float(getattr(cfg.cloud, "writeup_daily_budget_usd", 0.0) or 0.0)
    if cap <= 0.0:
        raise RuntimeError("cloud.writeup_daily_budget_usd is 0 — cloud escalation disabled")
    if writeup_budget_remaining_usd(db, cfg) <= 0.0:
        raise RuntimeError(f"writeup cloud budget exhausted for today (cap=${cap:.2f})")
    api_key = (
        getattr(secrets, "anthropic_api_key", None)
        or getattr(secrets, "cloud_api_key", None)
    )
    if not api_key:
        raise RuntimeError("anthropic_api_key not set in secrets")

    from enrich.llm.anthropic import AnthropicClient
    client = AnthropicClient(
        api_key=api_key,
        model=cfg.cloud.model,
        max_tokens=max_tokens,
        base_url=cfg.cloud.base_url,
        timeout=cfg.cloud.request_timeout,
    )
    try:
        text, in_tok, out_tok = client.generate_with_usage(
            prompt, system=system_prompt, max_tokens=max_tokens,
        )
    finally:
        try:
            client.close()
        except Exception:
            pass

    pricing = cfg.cloud.pricing
    cost = (
        (in_tok  / 1_000_000.0) * float(pricing.input_per_mtok) +
        (out_tok / 1_000_000.0) * float(pricing.output_per_mtok)
    )
    db.add_writeup_spend(_utc_today(), in_tok, out_tok, cost)
    return text, int(in_tok), int(out_tok), float(cost)


# ---------------------------------------------------------------------------
# Top-level entrypoint — chains Pass 1 → verify → Pass 2 → cite-check
# ---------------------------------------------------------------------------

EXTRACT_SYSTEM_PROMPT = (
    "You are a security analyst performing structured extraction from honeypot data. "
    + FENCE_NOTICE
    + " Respond strictly in the requested JSON shape; no markdown fences, no commentary."
)

NARRATE_SYSTEM_PROMPT = (
    "You are a security analyst writing a narrative threat assessment. "
    "You will only see a structured 'brief' produced from validated extraction; "
    "you do not have access to the raw honeypot data. Cite only the identifiers "
    "the brief gave you. Plain prose only."
)


def generate_writeup(
    *,
    cfg: Any, secrets: Any, db: Any, llm_cfg: Any,
    anchor: dict, scope: dict, evidence_quality: str,
    escalate: bool = False,
    extract_max_tokens: int = 1536,
    narrate_max_tokens: int = 1024,
) -> dict:
    """Run the two-pass pipeline and return the analyst-facing result.

    Pass 1 is always local — heavy attacker-controlled context never
    leaves the network. Pass 2 may escalate to cloud (the brief is small
    and analyst-reviewable before any prose is generated).

    Returns (always):
      {
        "narrative":   "<prose, may include inline footnotes>",
        "brief":       {<validated brief dict>},
        "redactions":  [{sentence, identifier, kind}, ...],
        "stages":      [
          {"name": "extract", "model": "<X>", "ms": <int>,
           "input_tokens": <int>, "output_tokens": <int>, "cost_usd": 0.0},
          {"name": "narrate", "model": "<X>", "ms": <int>,
           "input_tokens": <int>, "output_tokens": <int>, "cost_usd": <float>}
        ],
        "escalated":      <bool>,           # narrate stage hit cloud?
        "total_cost_usd": <float>,
        "brief_dropped_identifiers": ["<value>", ...],  # verify stage strips
      }

    Raises RuntimeError on hard failure (LLM down, parse failure,
    budget exhausted when escalation was requested).
    """
    if not llm_cfg:
        raise RuntimeError("local LLM not configured — Pass 1 needs the local LLM")
    if escalate and (cfg is None or db is None):
        raise RuntimeError("cloud escalation needs the pipeline state DB")

    nonce = make_nonce()
    extract_prompt = build_extract_prompt(anchor, scope, evidence_quality, nonce)

    # --- Pass 1: extract --------------------------------------------------
    t0 = time.perf_counter()
    try:
        ex_text, ex_in, ex_out = call_local(
            llm_cfg, extract_prompt, EXTRACT_SYSTEM_PROMPT, max_tokens=extract_max_tokens,
        )
    except Exception as exc:
        log.exception("writeup extract: LLM call failed")
        raise RuntimeError(f"extract LLM call failed: {exc}")
    ex_ms = int((time.perf_counter() - t0) * 1000)

    brief = parse_brief_response(ex_text)
    if brief is None:
        log.warning("writeup extract: unparseable response head=%r", ex_text[:400])
        raise RuntimeError(
            "extract stage returned unparseable JSON; "
            f"raw head: {ex_text[:300]!r}"
        )

    # --- Verify pass: cite-check brief against source --------------------
    brief, dropped = verify_brief_against_source(brief, extract_prompt)
    if dropped:
        log.info("writeup extract: dropped %d unverified identifier(s): %s",
                 len(dropped), dropped)

    # --- Pass 2: narrate --------------------------------------------------
    narrate_prompt = build_narrate_prompt(brief)
    t1 = time.perf_counter()
    nr_cost = 0.0
    nr_model = ""
    if escalate:
        try:
            nr_text, nr_in, nr_out, nr_cost = call_cloud(
                cfg, secrets, db, narrate_prompt, NARRATE_SYSTEM_PROMPT,
                max_tokens=narrate_max_tokens,
            )
            nr_model = cfg.cloud.model
        except RuntimeError:
            # Budget/credential issues bubble up — analyst sees actionable error.
            raise
        except Exception as exc:
            log.exception("writeup narrate (cloud): failed")
            raise RuntimeError(f"narrate cloud LLM call failed: {exc}")
    else:
        try:
            nr_text, nr_in, nr_out = call_local(
                llm_cfg, narrate_prompt, NARRATE_SYSTEM_PROMPT,
                max_tokens=narrate_max_tokens,
            )
            nr_model = llm_cfg.generation_model
        except Exception as exc:
            log.exception("writeup narrate (local): failed")
            raise RuntimeError(f"narrate local LLM call failed: {exc}")
    nr_ms = int((time.perf_counter() - t1) * 1000)

    if not nr_text or not nr_text.strip():
        raise RuntimeError("narrate stage returned empty output")

    prose = _clean_model_artifacts(nr_text)
    if not prose:
        raise RuntimeError("narrate stage produced only artifacts (no prose)")

    # --- Pass 2 cite-check ------------------------------------------------
    prose, redactions = cite_check_prose(prose, brief, extract_prompt)

    return {
        "narrative":   prose,
        "brief":       brief,
        "redactions":  redactions,
        "stages": [
            {"name": "extract", "model": llm_cfg.generation_model,
             "ms": ex_ms, "input_tokens": ex_in, "output_tokens": ex_out,
             "cost_usd": 0.0},
            {"name": "narrate", "model": nr_model,
             "ms": nr_ms, "input_tokens": nr_in, "output_tokens": nr_out,
             "cost_usd": round(nr_cost, 4)},
        ],
        "escalated":      bool(escalate),
        "total_cost_usd": round(nr_cost, 4),
        "brief_dropped_identifiers": dropped,
    }
