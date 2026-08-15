"""Functional-duplicate gating: shape signature + IOC regex extraction.

Two responsibilities (ROADMAP #9):

1. `normalize_to_shape` + `compute_shape_hash` — produce a placeholder
   string + 16-hex hash that collapses commands which differ only in
   literal values (credentials, IPs, URLs, paths, numbers). Same shape
   hash → one LLM call covers them all; subsequent variants inherit.

2. `extract_iocs_regex` — pull IPs / URLs / domains / files / hashes
   from a raw command via regex. Used on the inherit path because the
   LLM-produced `parsed.iocs` is the per-command-unique part that must
   re-run even when the structural enrichment (intent/description/
   tactics/techniques) is inherited from a canonical sibling.

The shape signature deliberately biases toward false-negative
(re-enrich a near-duplicate) over false-positive (mislink semantically
different commands). The placeholder pack is "minimal": only tokens
that clearly look like values become placeholders. Command names,
flags, and shell separators are preserved as-is.
"""
from __future__ import annotations

import hashlib
import re
import shlex

# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------

# Shell operators we segment on. Matches `_split_shell_segments` in
# command_grounding.py but driven by shlex's punctuation_chars so that
# unspaced forms (`cmd1|cmd2`, `cmd;cmd`) parse correctly.
_SEPARATORS = frozenset({";", "|", "||", "&", "&&", ">", ">>", "<", "<<", "\n"})

# Recognises a flag token — short (`-x`) or long (`--no-check-certificate`).
# Same regex as command_grounding.
_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z][\w\-]*$")

# Strict whitelist for command names. Same regex as command_grounding so
# the same parser noise filter applies. Tokens like `}'`, `accept-encoding:`,
# or bare numbers don't qualify as a segment's command — they get treated as
# values and substituted.
_VALID_CMD_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

# Same as command_grounding._MULTICALL_BINARIES.
_MULTICALL_BINARIES = frozenset({"busybox"})


def _tokenize(line: str) -> list[str]:
    """Quote-aware token split that ALSO breaks on unspaced operators.

    Uses shlex.shlex with `punctuation_chars=True` so `cmd|other` splits
    to `["cmd", "|", "other"]` rather than concatenating into a single
    `cmd|other` token (which is what plain `shlex.split` does and what
    bites the segmenter in `command_grounding._split_shell_segments`).

    Falls back to whitespace split on unbalanced quotes / other lex
    failure so attacker weirdness doesn't crash the caller.
    """
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return [t for t in lex if t]
    except ValueError:
        return line.split()


def _split_segments(line: str) -> tuple[list[list[str]], list[str]]:
    """Tokenize + split into segments at shell-separator tokens.

    Returns `(segments, seps)`. `seps[i]` is the separator token that
    preceded `segments[i+1]` — they're threaded back between segments
    during signature assembly so `cmd1; cmd2` and `cmd1 && cmd2`
    produce different signatures.
    """
    tokens = _tokenize(line)
    segments: list[list[str]] = []
    seps: list[str] = []
    current: list[str] = []
    for tok in tokens:
        if tok in _SEPARATORS:
            segments.append(current)
            seps.append(tok)
            current = []
        else:
            current.append(tok)
    segments.append(current)
    return segments, seps


# ---------------------------------------------------------------------------
# Token classification → placeholder
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
# Loose IPv6 — anything with 2+ colons and only hex/colon chars, length-bounded.
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]{0,15}://")
# Path-like: starts with /, ./, ../, ~/, or ~. Length-bounded to avoid
# matching arbitrary tokens with a single slash in the middle.
_PATH_RE = re.compile(r"^(?:/|\./|\.\./|~/|~$)")
_INT_RE = re.compile(r"^\d+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
# Base64-ish: at least 16 chars from the b64 alphabet, with 2+ character
# classes present (so pure-digit and pure-letter don't get mislabeled).
_B64_CHARS = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _has_multiple_classes(s: str) -> bool:
    has_l = any(c.islower() for c in s)
    has_u = any(c.isupper() for c in s)
    has_d = any(c.isdigit() for c in s)
    has_p = any(c in "+/=_-" for c in s)
    return (int(has_l) + int(has_u) + int(has_d) + int(has_p)) >= 2


def _is_ipv6(tok: str) -> bool:
    # IPv6 must contain at least two colons AND only hex/colon chars.
    return tok.count(":") >= 2 and bool(_IPV6_RE.match(tok))


def _classify_value(tok: str) -> str:
    """Return placeholder string for a value-position token.

    Order matters — checks go from most-specific (URL) to most-general
    (`<ARG>`). Each rule is conservative; ambiguous tokens fall through
    to `<ARG>` rather than getting force-cast to a specific placeholder.
    """
    if _ENV_RE.match(tok):
        return "<ENV>"
    if _URL_RE.match(tok):
        return "<URL>"
    if _IPV4_RE.match(tok):
        return "<IP>"
    if _is_ipv6(tok):
        return "<IP>"
    if _PATH_RE.match(tok):
        return "<PATH>"
    if _INT_RE.match(tok):
        return "<INT>"
    if _HEX_RE.match(tok):
        return "<HEX>"
    if _B64_CHARS.match(tok) and _has_multiple_classes(tok):
        return "<B64>"
    return "<ARG>"


def _command_name_from_token(token: str) -> str:
    """Strip path prefix + leading dot, return cmd name or "" if invalid.

    Mirror of command_grounding._command_name_from_token. Lowercases and
    validates against `_VALID_CMD_NAME_RE`. Returning "" signals "this
    isn't a real command name; treat the token as a value."
    """
    raw = token.rsplit("/", 1)[-1].lstrip(".").lower()
    return raw if _VALID_CMD_NAME_RE.match(raw) else ""


# ---------------------------------------------------------------------------
# Signature assembly
# ---------------------------------------------------------------------------

def normalize_to_shape(cmd: str) -> str:
    """Return the placeholder string for `cmd`.

    Empty string signals "shape signature is degenerate; don't dedup."
    This happens when no segment yields a valid command name — i.e. the
    line is parser noise that wouldn't produce a useful LLM enrichment
    in the first place.
    """
    if not cmd or not cmd.strip():
        return ""

    segments, seps = _split_segments(cmd)
    seen_valid = False
    rendered_segments: list[str] = []

    for seg in segments:
        if not seg:
            rendered_segments.append("")
            continue

        # Skip leading env-var assignments (`KEY=value cmd ...`).
        i = 0
        env_tokens: list[str] = []
        while i < len(seg) and _ENV_RE.match(seg[i]):
            env_tokens.append("<ENV>")
            i += 1
        if i >= len(seg):
            # Pure env assignment, no command — emit env placeholders only.
            rendered_segments.append(" ".join(env_tokens))
            continue

        cmd_name = _command_name_from_token(seg[i])
        if not cmd_name:
            # No valid command in this segment — classify every remaining
            # token as a value. Segment contributes to the signature but
            # doesn't count toward `seen_valid`.
            rest = [_classify_value(t) for t in seg[i:]]
            rendered_segments.append(" ".join(env_tokens + rest))
            continue

        seen_valid = True
        out_tokens = [*env_tokens, cmd_name]
        j = i + 1

        # Multi-call binaries (`busybox <sub> ...`) — keep the next
        # non-flag, non-assignment token as a literal subcommand name.
        if cmd_name in _MULTICALL_BINARIES:
            k = j
            while k < len(seg) and (_FLAG_RE.match(seg[k]) or _ENV_RE.match(seg[k])):
                # Flags before subcommand: keep as-is.
                out_tokens.append(seg[k])
                k += 1
            if k < len(seg):
                sub = _command_name_from_token(seg[k])
                if sub:
                    out_tokens.append(sub)
                    j = k + 1
                else:
                    out_tokens.append(_classify_value(seg[k]))
                    j = k + 1

        for tok in seg[j:]:
            if _FLAG_RE.match(tok):
                out_tokens.append(tok)
            else:
                out_tokens.append(_classify_value(tok))

        rendered_segments.append(" ".join(out_tokens))

    if not seen_valid:
        # Every segment was parser noise. Refuse to emit a signature so
        # the gate falls back to the standalone path (full LLM enrich).
        return ""

    # Thread separators back between segments. `seps[i]` is the operator
    # that PRECEDED segment[i+1].
    out: list[str] = []
    for idx, rendered in enumerate(rendered_segments):
        if idx > 0:
            sep = seps[idx - 1] if idx - 1 < len(seps) else ";"
            out.append(sep)
        out.append(rendered)
    return " ".join(p for p in out if p)


def compute_shape_hash(cmd: str) -> str:
    """Return 16-hex shape hash, or "" if the signature is degenerate.

    16 hex = 64 bits = ~1.8e19 buckets; collision risk is negligible for
    the corpus sizes we care about (millions of unique commands at
    most).
    """
    sig = normalize_to_shape(cmd)
    if not sig:
        return ""
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Per-command IOC extraction (regex-only — used on the inherit path)
# ---------------------------------------------------------------------------

# Reuses the same regex family as the placeholder classifier but operates
# over the raw command text rather than tokens. Goal: when a child
# inherits intent/description/etc. from a canonical, the per-command
# literal IOCs (its specific URL, IP, hash) still land on the child doc.

_IOC_URL_RE = re.compile(
    r"(?:https?|hxxps?|ftp|tftp|smb|file)://[^\s\"'<>|;`]+",
    re.IGNORECASE,
)
_IOC_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Hash extraction (#2) — mirror the campaign miner's gated shape so bare hex
# only counts as a hash with tool context. Exact md5/sha1/sha256 lengths.
_HEX_LEN = r"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})"
# Always trusted: an explicit `sha256:HEX` / `sha1=HEX` / `md5:HEX` prefix.
_IOC_HASH_PREFIX_RE = re.compile(rf"\b(?:sha256|sha1|md5)[:=]({_HEX_LEN})\b", re.IGNORECASE)
# Bare hex only counts when a hash-producing tool appears in the same command.
_IOC_HASH_TOOL_RE = re.compile(
    r"\b(?:sha256sum|sha512sum|sha384sum|sha224sum|sha1sum|md5sum|"
    r"shasum|certutil|openssl\s+dgst|gpg\s+--print-md)\b",
    re.IGNORECASE,
)
_IOC_HEX_RE = re.compile(rf"\b{_HEX_LEN}\b")
_IOC_PATH_RE = re.compile(r"(?:^|[\s|;&`(])(/[\w./\-]{2,})")
# A loose domain: 2+ dot-separated labels, last is a TLD-like 2-24 alpha.
_IOC_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)


def _looks_like_ipv4(s: str) -> bool:
    return bool(_IPV4_RE.match(s))


def extract_iocs_regex(cmd: str) -> dict[str, list[str]]:
    """Return `{ips, domains, urls, files, hashes}` for `cmd`.

    Output shape matches `CommandEnrichment.iocs.model_dump()` so the
    inherit path can feed it straight into `_build_indicators` without
    further translation.

    Conservative on domains — only pulls them from URL hosts and a
    secondary line scan. Bare-token hostname guesses would generate
    false positives for non-URL-shaped tokens like `linux-headers-5.4`.
    """
    if not cmd:
        return {"ips": [], "domains": [], "urls": [], "files": [], "hashes": []}

    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    hashes: list[str] = []
    files: list[str] = []
    seen: set[tuple[str, str]] = set()

    for m in _IOC_URL_RE.finditer(cmd):
        url = m.group(0).rstrip(".,;:)]}'\"")
        key = ("url", url)
        if key not in seen:
            seen.add(key)
            urls.append(url)
        # Pull host out of the URL for the domain list, unless host is an IP.
        try:
            host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        except IndexError:
            host = ""
        if host:
            if _looks_like_ipv4(host):
                if ("ip", host) not in seen:
                    seen.add(("ip", host))
                    ips.append(host)
            elif "." in host and ("domain", host.lower()) not in seen:
                seen.add(("domain", host.lower()))
                domains.append(host.lower())

    for m in _IOC_IPV4_RE.finditer(cmd):
        ip = m.group(0)
        if ("ip", ip) not in seen:
            seen.add(("ip", ip))
            ips.append(ip)

    # Prefixed hashes (`sha256:HEX`) are always trusted; bare hex only when a
    # hash-producing tool is in the command (tool-context gate, mirrors the
    # campaign miner). Avoids treating arbitrary 32/40/64-hex tokens (request
    # ids, cowrie fakefs hashes, base16 blobs) as file hashes.
    for m in _IOC_HASH_PREFIX_RE.finditer(cmd):
        h = m.group(1).lower()
        if ("hash", h) not in seen:
            seen.add(("hash", h))
            hashes.append(h)
    if _IOC_HASH_TOOL_RE.search(cmd):
        for m in _IOC_HEX_RE.finditer(cmd):
            h = m.group(0).lower()
            if ("hash", h) not in seen:
                seen.add(("hash", h))
                hashes.append(h)

    for m in _IOC_PATH_RE.finditer(cmd):
        p = m.group(1)
        # Heuristic: paths shorter than 3 chars or that look like flags
        # leak through; gate on minimum length + presence of a path char.
        if len(p) >= 3 and "/" in p:
            key = ("file", p)
            if key not in seen:
                seen.add(key)
                files.append(p)

    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "files": files,
        "hashes": hashes,
    }


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = (
    "compute_shape_hash",
    "extract_iocs_regex",
    "normalize_to_shape",
)
