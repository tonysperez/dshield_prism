"""Retroactive scan for analyst-authored artifact rules (ROADMAP #5).

Walks the cowrie commands index, applies the given rules to each
`process.command_line`, and stamps the
`dshield.cowrie.enrichment.analyst_artifacts` block via a partial update.
Then refreshes session rollup `artifact_set` strings for any session whose
member commands changed.

Used by:
  * the CLI verb `apply-artifact-rules [--rule-id ID]` (one-shot admin),
  * the console POST handler when `affected_estimate <
    cfg.analyst.sync_scan_doc_threshold` (sync-cap path).

Idempotent: re-running on already-tagged docs is cheap. A doc whose
existing `analyst_artifacts` entries for the targeted rule already match
the freshly computed set is skipped.
"""
from __future__ import annotations

import logging

from ..es_client import bulk_write, make_client
from . import artifact_rules as rules_mod

log = logging.getLogger(__name__)


# Painless: stamp the `analyst_artifacts` array on the enrichment block.
# Replaces the whole array — callers compute the full set per doc.
_STAMP_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "ctx._source.dshield.cowrie.enrichment.analyst_artifacts = params.analyst_artifacts;"
)


def _existing_hits(doc_src: dict) -> list[dict]:
    en = ((doc_src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
    return en.get("analyst_artifacts") or []


def _same_hits(a: list[dict], b: list[dict]) -> bool:
    """Set-equality on `(rule_id, value)` pairs — kind/match_type are
    derived from the rule and unchanged for a given (rule_id, value)."""
    def key(h): return (h.get("rule_id"), h.get("value"))
    return {key(h) for h in a} == {key(h) for h in b}


def run_apply_artifact_rules(
    cfg,
    secrets,
    *,
    rule_ids: list[str] | None = None,
    dry_run: bool = False,
) -> dict:
    """Walk the commands index and stamp `analyst_artifacts`.

    When `rule_ids` is given, only those rules are evaluated (and the
    stamp computes the FULL combined set — other already-stamped rules
    on the doc are NOT preserved unless they're in the active set; this
    is intentional, the scan is the source of truth for what should be
    stamped). When `rule_ids` is None, every active rule is applied.

    `dry_run=True` counts matches but writes nothing.
    """
    es = make_client(cfg.elasticsearch, secrets)
    if not cfg.analyst.enabled:
        return {"skipped_reason": "analyst.enabled is false"}

    # Load the rules we'll evaluate. When rule_ids is specified, allow
    # inactive rules too so a freshly-created rule that hasn't been seen
    # by `load_active_rules` yet (e.g. caller passed rule_id at POST time)
    # is still applied.
    all_active = rules_mod.load_active_rules(es, cfg)
    if rule_ids:
        wanted: set[str] = set(rule_ids)
        rules = [r for r in all_active if r.rule_id in wanted]
        # Missing wanted rules — fetch + compile from the rule index too.
        missing = wanted - {r.rule_id for r in rules}
        for rid in missing:
            rdoc = rules_mod.get_rule(es, cfg, rid)
            if rdoc is None:
                log.warning("rule not found: %s", rid)
                continue
            try:
                rules.append(rules_mod.compile_rule(rdoc))
            except Exception as exc:
                log.warning("rule %s: compile failed: %s", rid, exc)
    else:
        rules = all_active
    if not rules:
        return {"skipped_reason": "no rules to apply", "rule_ids": rule_ids or []}

    cap = cfg.analyst.max_match_per_doc
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands
    batch_size = max(10, int(cfg.analyst.scan_batch_size))

    stats = {
        "scanned": 0,
        "matched_docs": 0,
        "unchanged": 0,
        "updated": 0,
        "bulk_errors": 0,
        "per_rule_match_count": {r.rule_id: 0 for r in rules},
        "touched_session_ids": [],  # filled below for rollup refresh
    }
    touched_sessions: set[str] = set()
    actions: list[dict] = []

    # Pagination over commands. We need command_line + the existing
    # enrichment block (so we can skip docs whose stamp is already current).
    search_after = None
    src_fields = [
        "process.command_line",
        "dshield.cowrie.enrichment.analyst_artifacts",
    ]
    body = {
        "size": batch_size,
        "query": {"exists": {"field": "process.command_line"}},
        # `_id` as a tiebreaker requires fielddata (disabled in modern ES) and
        # 400s the whole search. `_doc` is the Lucene-internal doc id, fast
        # and cheap; the project's other backfill verbs use the same shape.
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
        "_source": src_fields,
    }
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=cmd_idx, **body)
        except Exception as exc:
            log.error("scan: ES search failed: %s; aborting", exc)
            stats["error"] = str(exc)
            break
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            stats["scanned"] += 1
            src = h.get("_source") or {}
            cmd = ((src.get("process") or {}).get("command_line")) or ""
            if not cmd:
                continue
            new_hits = rules_mod.apply_rules(cmd, rules, cap=cap)
            if not new_hits:
                continue
            stats["matched_docs"] += 1
            for entry in new_hits:
                rid = entry.get("rule_id")
                if rid in stats["per_rule_match_count"]:
                    stats["per_rule_match_count"][rid] += 1
            existing = _existing_hits(src)
            if _same_hits(existing, new_hits):
                stats["unchanged"] += 1
                continue
            if dry_run:
                continue
            actions.append({
                "_op_type": "update",
                "_id": h["_id"],
                "script": {
                    "source": _STAMP_SCRIPT,
                    "params": {"analyst_artifacts": new_hits},
                },
            })
            if len(actions) >= 50:
                ok, errs = bulk_write(es, cmd_idx, actions)
                stats["updated"] += ok
                stats["bulk_errors"] += len(errs)
                if errs:
                    log.warning("scan bulk errors (%d): %s", len(errs), errs[:2])
                actions = []
        search_after = hits[-1]["sort"]

    if actions and not dry_run:
        ok, errs = bulk_write(es, cmd_idx, actions)
        stats["updated"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("scan bulk errors (%d): %s", len(errs), errs[:2])

    # Per-rule scan-result stamp (best-effort). Skip stamping when the
    # iteration aborted before scanning anything — otherwise a 400 on the
    # first ES query falsely advertises "scanned 0 == match_count 0", which
    # is indistinguishable from a clean no-hit result.
    if not dry_run and "error" not in stats and stats["scanned"] > 0:
        for rid, cnt in stats["per_rule_match_count"].items():
            # Honour the configured ceiling on what we report as the
            # estimate — the doc still got stamped, but the rule's
            # estimate is bounded.
            rules_mod.stamp_scan_result(
                es, cfg, rid,
                match_count=min(cnt, int(cfg.analyst.max_match_count_per_rule)),
            )

    # Note: we deliberately do NOT refresh session rollup `artifact_set`
    # here — the next `rollup sessions` pass picks up the new
    # `analyst_artifacts` field via the existing aggregation (forward
    # application is wired in `_build_session_doc`). For a scan kicked off
    # from POST, the operator's next backward cycle reconciles.
    stats["touched_session_ids"] = sorted(touched_sessions)
    stats["rules_applied"] = [r.rule_id for r in rules]
    stats["dry_run"] = dry_run
    return stats
