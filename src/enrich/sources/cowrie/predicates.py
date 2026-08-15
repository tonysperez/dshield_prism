"""Structural predicates — the production port of `eval_predicate_falsification.py`'s
7 validated structural predicates (backlog item 29) into the assignment path (item 30).

`eval_predicate_falsification.py` computes its 7 booleans over an entire session's
joined command text in one regex pass. At enrichment time (`commands.py`) only one
command doc exists at a time, so this module splits that computation in two:

  * `command_subsignals(command_line)` — the constituent regex sub-signals for ONE
    command, computed once at enrichment write time and stored on the command doc
    (`dshield.cowrie.enrichment.predicates.*`). Cheap, versioned, and keeps assignment
    off the raw `process.command_line` path (constraint: `assign_runner` reads only
    these booleans/token lists, never command text).
  * `fold_session_predicates(subsignals)` — recomposes the 7 composed predicates from a
    session's list of per-command sub-signal dicts (as pulled off command docs by
    `lexical.pull_hash_to_predicates` / `lexical.build_session_predicate_vectors`).

Four of the seven predicates (`c2_launch_arg`, `self_spread`, `host_info_gather`, plus
the two constituent conditions of `key_write_immutability`/`hetero_target_fallback`) are
simple presence checks: OR-ing the per-command booleans across a session is equivalent
to `re.search` over the joined session text UNLESS a match would only appear by two
adjacent commands' text landing next to each other across the join boundary — an
accepted, documented approximation inherent to precomputing per command (the
falsification script's own patterns are written to match within one shell command, so
this is expected to be rare-to-never in practice).

`appliance_menu_only` is an AND-fold over every command in the session (vacuously False
for an empty session, matching the original `if not lines: return False`).

`multi_arch_targeting` needs exact cross-command pooling of the *distinct* architecture
tokens found (not just a per-command "any token" flag), so `command_subsignals` stores
the actual matched token set per command; the fold takes the union before applying the
original three-way OR (uname -m single-command hit; OR case-keyword-anywhere AND at
least one pooled token; OR at least two distinct pooled tokens). Because `\\b`-bounded
regex token identity does not depend on where a whitespace-joined string is split, this
union-of-per-command-token-sets is numerically identical to running the original regex
over the joined text.

`hetero_target_fallback` / `key_write_immutability` OR-pool each of their two
constituent conditions independently across commands, then AND the two pooled results —
this is the exact fold named in the spec's Design Notes.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Regexes — ported verbatim from scripts/eval_predicate_falsification.py.
# Do not diverge: this module's whole purpose is identical semantics, just
# decomposed to run one command at a time.
# ---------------------------------------------------------------------------

_ARCH_TOKENS = (
    "x86_64", "x86", "i386", "i686", "aarch64", "arm64",
    "arm5", "arm6", "arm7", "armv4", "armv5", "armv6", "armv7",
    "mipsel", "mips64", "mips", "powerpc", "ppc", "sparc", "sh4", "m68k",
)
_APPLIANCE_MENU_VERBS = {"sh", "shell", "enable", "system", "linuxshell", "help", "busybox"}
_HOST_RECON_RE = re.compile(
    r"\buname\b|/proc/cpuinfo|\bhostname\b|\bwhoami\b|\bnetstat\b|\bfree\b|\blscpu\b"
    r"|\bls\s+/|\bw\b|\bid\b",
    re.IGNORECASE,
)
_ARCH_CASE_RE = re.compile(r"\bcase\b", re.IGNORECASE)
_UNAME_M_RE = re.compile(r"uname\s+-m", re.IGNORECASE)
_IP = r"\d{1,3}(?:\[?\.\]?\d{1,3}){3}"
_C2_LAUNCH_RE = re.compile(rf"(?:\./|/)\S+\s+{_IP}[\s:]+\d{{2,5}}\b")
_SELF_SPREAD_RE = re.compile(
    r"telnetd\s+[^&\n]*-l|\bnc\s+[^&\n]*-l|\bsh\s+-s\s+(?:telnet|ssh)\b",
    re.IGNORECASE,
)
_MULTI_DIR_RE = re.compile(r"cd\s+\S+\s*\|\|\s*cd\s+\S+\s*\|\|\s*cd\s+", re.IGNORECASE)
_MULTI_TOOL_RE = re.compile(r"busybox\s+wget|wget[^|]*\|\||curl[^|]*\|\|", re.IGNORECASE)
_KEY_WRITE_RE = re.compile(r"authorized_keys", re.IGNORECASE)
_IMMUTABILITY_RE = re.compile(r"chattr\s+[+-]?ia?\b|\blockr\s+-ia\b", re.IGNORECASE)

# The 7 composed predicate names, in the fixed order used everywhere a
# predicate vector/signature is represented positionally.
PREDICATE_NAMES: tuple[str, ...] = (
    "multi_arch_targeting",
    "c2_launch_arg",
    "self_spread",
    "appliance_menu_only",
    "host_info_gather",
    "key_write_immutability",
    "hetero_target_fallback",
)

# The per-command sub-signal field names written to
# `dshield.cowrie.enrichment.predicates.*` (see setup/es-mappings/cowrie/commands.json).
SUBSIGNAL_NAMES: tuple[str, ...] = (
    "has_uname_m",
    "arch_tokens",
    "has_case_token",
    "has_c2_launch",
    "has_self_spread",
    "is_appliance_verb",
    "has_host_recon",
    "has_key_write",
    "has_immutability",
    "has_multi_dir_cd",
    "has_multi_tool_fallback",
)


def command_subsignals(command_line: str) -> dict:
    """Per-command constituent regex sub-signals for one `process.command_line`.

    Computed once at enrichment write time (`commands.py`) and stored verbatim on the
    command doc; `fold_session_predicates` recomposes the 7 composed predicates from a
    session's list of these dicts. `arch_tokens` is the only non-boolean field — the
    sorted list of distinct architecture tokens this command matched, needed so the
    session-level fold can pool *distinct* tokens across commands exactly like the
    falsification script's joined-text regex does.
    """
    text = command_line or ""
    found_arch = sorted(
        tok for tok in _ARCH_TOKENS
        if re.search(rf"\b{re.escape(tok)}\b", text, re.IGNORECASE)
    )
    return {
        "has_uname_m": bool(_UNAME_M_RE.search(text)),
        "arch_tokens": found_arch,
        "has_case_token": bool(_ARCH_CASE_RE.search(text)),
        "has_c2_launch": bool(_C2_LAUNCH_RE.search(text)),
        "has_self_spread": bool(_SELF_SPREAD_RE.search(text)),
        "is_appliance_verb": text.strip().lower() in _APPLIANCE_MENU_VERBS,
        "has_host_recon": bool(_HOST_RECON_RE.search(text)),
        "has_key_write": bool(_KEY_WRITE_RE.search(text)),
        "has_immutability": bool(_IMMUTABILITY_RE.search(text)),
        "has_multi_dir_cd": bool(_MULTI_DIR_RE.search(text)),
        "has_multi_tool_fallback": bool(_MULTI_TOOL_RE.search(text)),
    }


def _all_false() -> dict[str, bool]:
    return dict.fromkeys(PREDICATE_NAMES, False)


def fold_session_predicates(subsignals: list[dict]) -> dict[str, bool]:
    """Recompose the 7 composed predicates from a session's per-command sub-signal
    dicts, applying each predicate's correct fold (see module docstring). A missing
    sub-signal key on any row is treated as falsy/empty (fail-closed, matching
    `lexical.build_session_predicate_vectors`'s handling of commands that predate this
    feature). An empty `subsignals` list (no resolvable commands) folds to all-False,
    matching `eval_predicate_falsification.appliance_menu_only`'s `if not lines: return
    False` for the empty-session case.
    """
    if not subsignals:
        return _all_false()

    any_uname_m = any(s.get("has_uname_m") for s in subsignals)
    pooled_arch_tokens = {tok for s in subsignals for tok in (s.get("arch_tokens") or [])}
    any_case_token = any(s.get("has_case_token") for s in subsignals)
    multi_arch_targeting = (
        any_uname_m
        or (any_case_token and bool(pooled_arch_tokens))
        or len(pooled_arch_tokens) >= 2
    )

    c2_launch_arg = any(s.get("has_c2_launch") for s in subsignals)
    self_spread = any(s.get("has_self_spread") for s in subsignals)
    appliance_menu_only = all(s.get("is_appliance_verb") for s in subsignals)
    host_info_gather = any(s.get("has_host_recon") for s in subsignals)

    any_key_write = any(s.get("has_key_write") for s in subsignals)
    any_immutability = any(s.get("has_immutability") for s in subsignals)
    key_write_immutability = any_key_write and any_immutability

    any_multi_dir = any(s.get("has_multi_dir_cd") for s in subsignals)
    any_multi_tool = any(s.get("has_multi_tool_fallback") for s in subsignals)
    hetero_target_fallback = any_multi_dir and any_multi_tool

    return {
        "multi_arch_targeting": multi_arch_targeting,
        "c2_launch_arg": c2_launch_arg,
        "self_spread": self_spread,
        "appliance_menu_only": appliance_menu_only,
        "host_info_gather": host_info_gather,
        "key_write_immutability": key_write_immutability,
        "hetero_target_fallback": hetero_target_fallback,
    }


# Modal threshold: an anchor predicate signature entry (a member-session frequency in
# [0, 1], see scripts/capture_anchor_snapshot.py:predicate_signature) counts as the
# anchor "firing" that predicate when at least half its sampled member sessions fired
# it — the majority/modal value, not merely "occurred at least once". A single
# incidental member hit must not open every unrelated below-tau session sharing that
# one predicate to a rescue.
ANCHOR_MODAL_THRESHOLD = 0.5


def predicate_overlap(
    session_predicates: dict[str, bool] | None,
    anchor_signature: dict[str, float] | None,
    *,
    modal_threshold: float = ANCHOR_MODAL_THRESHOLD,
) -> bool:
    """Evidence-gated overlap test for the below-tau rescue tier.

    True iff at least one predicate is True on the session vector AND that same
    predicate is modal (>= `modal_threshold`) on the anchor's signature. An all-False
    (or missing/None) session vector, or a missing/None/all-zero anchor signature,
    naturally returns False here without any special-case — this is the "never rescue
    on an all-false match on either side" evidence gate (spec constraint 2).
    """
    if not session_predicates or not anchor_signature:
        return False
    return any(
        bool(fires) and _coerce_modal_value(anchor_signature.get(name)) >= modal_threshold
        for name, fires in session_predicates.items()
    )


def predicate_signature(vectors: list[dict[str, bool]]) -> dict[str, float]:
    """Modal/frequency vector over an anchor's member sessions' predicate vectors (item
    30) — the fraction of sampled sessions where each of the 7 structural predicates
    (`PREDICATE_NAMES`) fired. Mirrors `capture_anchor_snapshot.centroid()`'s "aggregate
    over member sessions" role, but for predicate evidence: a plain per-predicate
    frequency in [0, 1] (frequencies are already bounded/comparable as-is, unlike the
    embedding mean, so no normalisation step is needed). Empty `vectors` -> all-zero (no
    evidence), matching `predicate_overlap`'s fail-closed all-false handling — an anchor
    with no evidence can never rescue a session into itself.

    Single source of truth (item 51): moved here from `scripts/capture_anchor_snapshot.py`
    (which now imports it), and reused verbatim by `sessions._sample_predicate_vectors`
    for both the anchor-signature backfill and the mint-time anchor write."""
    if not vectors:
        return dict.fromkeys(PREDICATE_NAMES, 0.0)
    n = len(vectors)
    return {name: sum(bool(v.get(name)) for v in vectors) / n for name in PREDICATE_NAMES}


def _coerce_modal_value(value: object) -> float:
    """Safe float coercion for an anchor `predicate_signature` entry. The ES field is
    `index: false`/unvalidated, so a malformed doc (`None`, a string, etc.) is possible;
    treat anything non-numeric as "predicate not present" (0.0) rather than raising and
    aborting the whole assignment batch over one bad anchor."""
    try:
        return float(value) if value is not None else 0.0
    except (TypeError, ValueError):
        return 0.0
