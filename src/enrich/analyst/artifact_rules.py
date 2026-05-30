"""Analyst-authored artifact-rule store + matching engine.

The rule subsystem (ROADMAP #5) lets an analyst declare "this is an
artifact, find every other session that contains it" — a per-deploy
addition to the fixed `url|ip|domain|file|hash` extraction set.

Each rule is one doc in `cfg.analyst.indexes.artifact_rules` keyed on
`rule_id` (`arule-<16hex>`). Soft-delete via `active=false` so historical
match attribution stays valid. The forward-application path
(`run_enrich` / `run_reenrich_stale` / `run_escalate`) loads active rules
once per worker run via `load_active_rules` and calls `apply_rules` per
command. The retroactive scan verb `apply-artifact-rules` walks the
commands index and stamps `analyst_artifacts` blocks on existing docs.

Rules support three `match_type`s:
  - **literal**   — word-boundary match of an exact string (case-(in)sensitive
                    per the rule). `value` is the pattern.
  - **substring** — plain "contained anywhere in text" check. `value` is the
                    pattern.
  - **regex**     — Python `re.search` with the rule's pattern. `value` is
                    the matched span (group 0).

Regex safety: at create time the pattern is compiled in-process (Python's
`re` has no native timeout, but compile-time pathologies are rare), then
sample-tested against `cfg.analyst.regex_sample_size` recent commands.
A pattern that matches more than half the sample is rejected as
catastrophic (proxy for `.*`-style runaway patterns).
"""
from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

MATCH_TYPES = ("literal", "substring", "regex")
_ID_PREFIX = "arule-"


# ---------------------------------------------------------------------------
# Compiled rule + matching
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    kind: str
    match_type: str
    pattern: str
    case_sensitive: bool
    _re: Optional[re.Pattern]  # compiled matcher; None for substring/literal-fallback

    def find(self, text: str) -> list[str]:
        """Return distinct matched spans from `text`.

        For literal/substring, the matched value is the pattern itself (the
        text contains the pattern as a span). For regex, group 0 of each
        match is returned.
        """
        if not text:
            return []
        if self.match_type == "regex":
            assert self._re is not None
            out: list[str] = []
            seen: set[str] = set()
            for m in self._re.finditer(text):
                v = m.group(0)
                if v and v not in seen:
                    seen.add(v)
                    out.append(v)
            return out
        if self.match_type == "literal":
            # Word-boundary match of an exact string.
            assert self._re is not None
            return [self.pattern] if self._re.search(text) else []
        if self.match_type == "substring":
            hay = text if self.case_sensitive else text.lower()
            ndl = self.pattern if self.case_sensitive else self.pattern.lower()
            return [self.pattern] if ndl in hay else []
        return []


def compile_rule(rule: dict) -> CompiledRule:
    """Build a `CompiledRule` from a stored rule dict. Raises `ValueError`
    on invalid `match_type` or unparseable regex.
    """
    match_type = rule.get("match_type")
    if match_type not in MATCH_TYPES:
        raise ValueError(f"unknown match_type: {match_type!r}")
    pattern = rule.get("pattern") or ""
    if not pattern:
        raise ValueError("pattern is empty")
    case_sensitive = bool(rule.get("case_sensitive", False))
    flags = 0 if case_sensitive else re.IGNORECASE

    compiled: Optional[re.Pattern] = None
    if match_type == "regex":
        compiled = re.compile(pattern, flags)
    elif match_type == "literal":
        # Whitespace/string-boundary match — `\b` fails on tokens that start
        # with non-word chars (paths like `/tmp/x`), which is exactly the
        # case analysts want this kind for.
        compiled = re.compile(
            r"(?<!\S)" + re.escape(pattern) + r"(?!\S)", flags,
        )
    # substring: no precompile; the `find` path does a plain `in` check.
    return CompiledRule(
        rule_id=rule["rule_id"],
        kind=rule.get("kind") or "",
        match_type=match_type,
        pattern=pattern,
        case_sensitive=case_sensitive,
        _re=compiled,
    )


def apply_rules(
    command_text: str, rules: list[CompiledRule], *, cap: int
) -> list[dict]:
    """Run every rule against `command_text`, dedup, cap.

    Returns a list of `{rule_id, kind, value, match_type}` dicts, ordered
    by rule then by first occurrence in the command. Total entries are
    capped at `cap` so a pathological command can't blow up the doc.
    """
    if not command_text or not rules:
        return []
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        for value in rule.find(command_text):
            key = (rule.rule_id, value)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "rule_id": rule.rule_id,
                "kind": rule.kind,
                "value": value,
                "match_type": rule.match_type,
            })
            if len(out) >= cap:
                return out
    return out


def artifact_set_strings(hits: list[dict]) -> list[str]:
    """Render `apply_rules` output as `artifact_set` keyword strings.

    Format: `analyst:<kind>:<value>`. Kinds and values pass through as-is
    (the session-rollup builder is responsible for deduping the union).
    """
    return [f"analyst:{h.get('kind') or ''}:{h.get('value') or ''}" for h in hits]


# ---------------------------------------------------------------------------
# Rule store (ES)
# ---------------------------------------------------------------------------

def _index(cfg) -> str:
    return cfg.analyst.indexes.artifact_rules


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mint_rule_id() -> str:
    return _ID_PREFIX + secrets.token_hex(8)


def create_rule(
    es, cfg, *,
    kind: str,
    match_type: str,
    pattern: str,
    case_sensitive: bool = False,
    notes: str = "",
    created_by: str = "",
) -> dict:
    """Validate, store, and return a new rule. Raises `ValueError` on bad
    input. Catastrophic-pattern probe is the caller's job (it requires the
    ES commands index for a sample query); do it before calling here.
    """
    kind = (kind or "").strip()
    pattern = (pattern or "").strip()
    if not kind:
        raise ValueError("kind is required")
    if match_type not in MATCH_TYPES:
        raise ValueError(f"match_type must be one of {MATCH_TYPES}, got {match_type!r}")
    if not pattern:
        raise ValueError("pattern is required")
    # Compile to fail-fast on regex syntax errors.
    compile_rule({
        "rule_id": "preflight",
        "kind": kind,
        "match_type": match_type,
        "pattern": pattern,
        "case_sensitive": case_sensitive,
    })

    rule_id = _mint_rule_id()
    doc = {
        "rule_id": rule_id,
        "kind": kind,
        "match_type": match_type,
        "pattern": pattern,
        "case_sensitive": case_sensitive,
        "created_by": created_by or "",
        "created_at": _now(),
        "notes": notes or "",
        "active": True,
        "match_count_estimate": 0,
        "last_scanned_at": None,
    }
    es.index(index=_index(cfg), id=rule_id, document=doc, refresh="wait_for")
    return doc


def get_rule(es, cfg, rule_id: str) -> Optional[dict]:
    try:
        r = es.get(index=_index(cfg), id=rule_id)
    except Exception:
        return None
    if not r.get("found"):
        return None
    return r["_source"]


def list_rules(
    es, cfg, *,
    active: Optional[bool] = None,
    kind: Optional[str] = None,
    created_by: Optional[str] = None,
    size: int = 100,
    frm: int = 0,
) -> dict:
    must: list[dict] = []
    if active is not None:
        must.append({"term": {"active": bool(active)}})
    if kind:
        must.append({"term": {"kind.keyword": kind}})
    if created_by:
        must.append({"term": {"created_by": created_by}})
    body: dict = {"size": size, "from": frm, "sort": [{"created_at": "desc"}]}
    if must:
        body["query"] = {"bool": {"filter": must}}
    try:
        r = es.search(index=_index(cfg), **body)
    except Exception as exc:
        log.warning("list_rules failed: %s", exc)
        return {"total": 0, "rules": [], "from": frm, "size": size}
    rules = [h["_source"] for h in r["hits"]["hits"]]
    total = r["hits"]["total"]["value"] if isinstance(r["hits"]["total"], dict) else r["hits"]["total"]
    return {"total": total, "rules": rules, "from": frm, "size": size}


def set_active(es, cfg, rule_id: str, active: bool) -> dict:
    rule = get_rule(es, cfg, rule_id)
    if rule is None:
        raise LookupError(f"rule not found: {rule_id}")
    es.update(
        index=_index(cfg), id=rule_id,
        doc={"active": bool(active)}, refresh="wait_for",
    )
    rule["active"] = bool(active)
    return rule


def stamp_scan_result(
    es, cfg, rule_id: str, *, match_count: int, scanned_at: Optional[str] = None,
) -> None:
    """Update a rule's `match_count_estimate` and `last_scanned_at` after a
    retroactive scan completes. Best-effort; failure is logged."""
    try:
        es.update(
            index=_index(cfg), id=rule_id,
            doc={
                "match_count_estimate": int(match_count),
                "last_scanned_at": scanned_at or _now(),
            },
            refresh=False,
        )
    except Exception as exc:
        log.warning("stamp_scan_result(%s) failed: %s", rule_id, exc)


def load_active_rules(es, cfg) -> list[CompiledRule]:
    """Load + compile every active rule. One ES query per worker run.

    Returns `[]` cleanly when the subsystem is disabled, no rules exist, or
    the index isn't initialised yet — the forward-application caller can
    treat the empty list as the zero-cost path.
    """
    if not cfg.analyst.enabled:
        return []
    try:
        r = es.search(
            index=_index(cfg), size=500,
            query={"bool": {"filter": [{"term": {"active": True}}]}},
        )
    except Exception as exc:
        # Most common cause: index hasn't been created yet on this deploy.
        log.debug("load_active_rules: %s; treating as no rules", exc)
        return []
    out: list[CompiledRule] = []
    for h in r["hits"]["hits"]:
        try:
            out.append(compile_rule(h["_source"]))
        except Exception as exc:
            log.warning(
                "skipping rule %s: compile failed (%s)",
                h.get("_id"), exc,
            )
    return out


# ---------------------------------------------------------------------------
# Regex safety / sample probe
# ---------------------------------------------------------------------------

_REJECT_RATIO = 0.5  # >50% sample matches → reject as catastrophic


def sample_probe(
    es, cfg, *, rule_dict: dict,
) -> tuple[int, int]:
    """Run a candidate rule against a sample of recent commands. Returns
    `(sample_size, match_count)`. Used by the POST handler to reject
    catastrophic patterns before storage.

    The sample is `cfg.analyst.regex_sample_size` most-recent commands by
    @timestamp. Empty (no corpus yet) returns `(0, 0)` — the rule is allowed
    through; the retroactive scan will run later anyway.
    """
    size = max(1, int(cfg.analyst.regex_sample_size))
    try:
        compiled = compile_rule({**rule_dict, "rule_id": "probe"})
    except (ValueError, re.error) as exc:
        # Surface as ValueError so callers can return a 400.
        raise ValueError(f"pattern invalid: {exc}") from exc
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands
    try:
        r = es.search(
            index=cmd_idx,
            size=size,
            sort=[{"@timestamp": "desc"}],
            _source=["process.command_line"],
            query={"exists": {"field": "process.command_line"}},
        )
    except Exception:
        return (0, 0)
    hits = r["hits"]["hits"]
    if not hits:
        return (0, 0)
    matched = 0
    for h in hits:
        cmd = (((h.get("_source") or {}).get("process") or {}).get("command_line")) or ""
        if compiled.find(cmd):
            matched += 1
    return (len(hits), matched)


def is_catastrophic(sample_size: int, match_count: int) -> bool:
    """`True` when the candidate matches more than `_REJECT_RATIO` of the
    sample — proxy for runaway patterns like `.*`. A 0-sample (empty
    corpus) is never catastrophic.
    """
    if sample_size <= 0:
        return False
    return (match_count / sample_size) > _REJECT_RATIO


def estimate_affected(es, cfg, rule_dict: dict) -> int:
    """Best-effort estimate of how many command docs the rule would touch
    across the full corpus. Used by the sync-cap-then-queue threshold.

    For `substring`/`literal` patterns we use an ES `match_phrase` count
    (cheap and accurate enough). For `regex` we scale the sample probe up
    by the corpus size — coarse, but adequate as a routing signal.
    """
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands
    match_type = rule_dict.get("match_type")
    pattern = rule_dict.get("pattern") or ""
    try:
        total_r = es.count(index=cmd_idx, query={"exists": {"field": "process.command_line"}})
        total = int(total_r.get("count") or 0)
    except Exception:
        total = 0
    if total == 0:
        return 0
    if match_type in ("literal", "substring"):
        try:
            r = es.count(
                index=cmd_idx,
                query={"match_phrase": {"process.command_line": pattern}},
            )
            return int(r.get("count") or 0)
        except Exception:
            return total  # be pessimistic on failure
    # regex: scale the sample probe.
    sample_size, matched = sample_probe(es, cfg, rule_dict=rule_dict)
    if sample_size == 0:
        return 0
    return int(round(matched / sample_size * total))
