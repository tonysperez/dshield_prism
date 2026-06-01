"""Findings v2 step 6 — hypothesis-driven hunts (brutal-review phase 6.1).

A "hunt" is an analyst-authored YAML query against the session rollup
index that emits ``kind=analyst_hunt`` findings into ``prism.findings``.
The execution shape is deliberately small: a hunt is a list of
**filters** (AND-combined) plus a name and id; matching sessions
produce one finding per (hunt, session) pair.

The point is the *workflow*: analysts pursue hypotheses ("show me
sessions that touched these persistence vectors in the last 7 days")
without writing Elasticsearch queries by hand. The seed library in
``config/hunts/`` (commit 6.2) covers the standing-question cases;
the in-console authoring UI (commit 6.4) lets analysts express
new hypotheses without touching YAML.

Hunt findings differ from discovery / drift findings in two ways:

1. **Anchor on the session, not the playbook**. A session matching
   a hunt is the unit of analyst review — the playbook the session
   belongs to is incidental.
2. **The hunt is the delta signature**. Two hunts firing on the same
   session produce two distinct findings (one per hunt). The
   writer's ``delta_signature`` slot carries the ``hunt_id``.

Hunt YAML schema:

    id: persistence-touched
    name: "Persistence vectors touched"
    description: "Sessions that touched any standard Linux persistence vector"
    filters:
      - kind: artifact_set_contains_any
        values: [crontab, authorized_keys, systemctl, "chattr +i"]
      - kind: window
        last_days: 7
    enabled: true   # optional; default true

Supported filter kinds:

    artifact_set_contains_any   values: list[str]
    artifact_set_contains_all   values: list[str]
    intent_in                   values: list[str]
    command_count_gte           threshold: int
    login_fail_count_gte        threshold: int
    external_match_cosine_gte   threshold: float  (uses 5.9's per-session field)
    window                      last_days: int    (event.start >= now - N days)
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml
from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)


# Field paths on `prism.rollup.cowrie.session` — kept in one place so
# the hunt loader doesn't have to know where each value lives.
_F_ARTIFACT_SET   = "dshield.cowrie.enrichment.session.artifact_set.keyword"
_F_INTENT         = "dshield.cowrie.enrichment.session.dominant_intent"
_F_COMMAND_COUNT  = "dshield.cowrie.enrichment.session.command_count"
_F_LOGIN_FAILS    = "dshield.cowrie.enrichment.session.login_fail_count"
_F_EXT_COSINE     = "dshield.cowrie.enrichment.session.cluster.external_match_cosine"
_F_TS             = "event.start"

# Bounded by ES default max — hunts that match more than this many
# sessions per run silently truncate. Operator sees the number in the
# stats dict and can refine.
_MAX_FINDINGS_PER_HUNT = 500


def _validate_filter(f: dict, *, hunt_id: str, idx: int) -> None:
    """Raise ValueError when a filter clause is malformed. Catches typos
    early — a hunt with one bad filter shouldn't half-run silently."""
    if not isinstance(f, dict):
        raise ValueError(f"hunt {hunt_id!r} filter[{idx}]: not a mapping")
    kind = f.get("kind")
    if kind == "artifact_set_contains_any" or kind == "artifact_set_contains_all":
        if not isinstance(f.get("values"), list) or not f["values"]:
            raise ValueError(
                f"hunt {hunt_id!r} filter[{idx}] ({kind}): `values` must "
                "be a non-empty list of strings"
            )
    elif kind == "intent_in":
        if not isinstance(f.get("values"), list) or not f["values"]:
            raise ValueError(
                f"hunt {hunt_id!r} filter[{idx}] ({kind}): `values` required"
            )
    elif kind in ("command_count_gte", "login_fail_count_gte"):
        t = f.get("threshold")
        if not isinstance(t, int) or t < 0:
            raise ValueError(
                f"hunt {hunt_id!r} filter[{idx}] ({kind}): `threshold` "
                "must be a non-negative int"
            )
    elif kind == "external_match_cosine_gte":
        t = f.get("threshold")
        if not isinstance(t, (int, float)) or not (0.0 <= float(t) <= 1.0):
            raise ValueError(
                f"hunt {hunt_id!r} filter[{idx}] ({kind}): `threshold` "
                "must be a float in [0, 1]"
            )
    elif kind == "window":
        d = f.get("last_days")
        if not isinstance(d, int) or d <= 0:
            raise ValueError(
                f"hunt {hunt_id!r} filter[{idx}] ({kind}): `last_days` "
                "must be a positive int"
            )
    else:
        raise ValueError(
            f"hunt {hunt_id!r} filter[{idx}]: unknown filter kind {kind!r}"
        )


def load_hunts(hunts_dir: str) -> list[dict[str, Any]]:
    """Walk ``hunts_dir`` for ``*.yaml`` / ``*.yml`` files. Returns the
    enabled hunts in id-sorted order. A malformed file aborts the
    entire load — better than silently skipping a broken hunt and
    leaving the analyst wondering why nothing fired.
    """
    p = Path(hunts_dir)
    if not p.is_dir():
        log.info("hunts: directory %s does not exist; nothing to run", hunts_dir)
        return []
    hunts: list[dict[str, Any]] = []
    for f in sorted(p.iterdir()):
        if f.suffix not in (".yaml", ".yml"):
            continue
        try:
            with f.open(encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"hunts: failed to parse {f}: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError(f"hunts: {f} is not a YAML mapping")
        hunt_id = doc.get("id")
        if not isinstance(hunt_id, str) or not hunt_id:
            raise ValueError(f"hunts: {f} missing required `id`")
        if not isinstance(doc.get("name"), str):
            raise ValueError(f"hunt {hunt_id!r}: missing required `name`")
        filters = doc.get("filters") or []
        if not isinstance(filters, list) or not filters:
            raise ValueError(f"hunt {hunt_id!r}: `filters` must be a non-empty list")
        for i, flt in enumerate(filters):
            _validate_filter(flt, hunt_id=hunt_id, idx=i)
        if doc.get("enabled", True):
            hunts.append(doc)
        else:
            log.info("hunts: %s loaded but disabled (enabled: false)", hunt_id)
    return hunts


def _filter_to_es_clause(f: dict) -> dict:
    """Translate one validated filter clause into an ES query fragment.
    Combined with sibling filters under a bool.must to form the hunt's
    full query. Field paths kept off the caller — this function owns
    the schema-to-field-path mapping."""
    kind = f["kind"]
    if kind == "artifact_set_contains_any":
        return {"terms": {_F_ARTIFACT_SET: list(f["values"])}}
    if kind == "artifact_set_contains_all":
        # ES has no "terms_set with minimum_should_match=ALL" shortcut
        # outside terms_set queries — easier to AND a series of term
        # clauses.
        return {"bool": {"must": [
            {"term": {_F_ARTIFACT_SET: v}} for v in f["values"]
        ]}}
    if kind == "intent_in":
        return {"terms": {_F_INTENT: list(f["values"])}}
    if kind == "command_count_gte":
        return {"range": {_F_COMMAND_COUNT: {"gte": int(f["threshold"])}}}
    if kind == "login_fail_count_gte":
        return {"range": {_F_LOGIN_FAILS: {"gte": int(f["threshold"])}}}
    if kind == "external_match_cosine_gte":
        return {"range": {_F_EXT_COSINE: {"gte": float(f["threshold"])}}}
    if kind == "window":
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(f["last_days"]))
        return {"range": {_F_TS: {"gte": cutoff.isoformat()}}}
    # `_validate_filter` already gated this; reaching here is a bug.
    raise ValueError(f"hunts: unsupported filter kind {kind!r}")


def _run_one_hunt(
    es: Elasticsearch, sessions_idx: str,
    hunt: dict, *, run_id: str, max_findings: int,
) -> list[dict[str, Any]]:
    """Execute one hunt's query against the session rollup. Returns a
    list of finding dicts ready for ``bulk_upsert_findings``. Empty
    list when no sessions match."""
    must = [_filter_to_es_clause(f) for f in hunt["filters"]]
    body = {
        "size": max_findings,
        "_source": [
            "cowrie.session_id",
            "source.ip",
            _F_TS,
            "event.end",
            _F_COMMAND_COUNT,
            _F_INTENT,
            "dshield.cowrie.enrichment.session.playbook_id",
            "dshield.cowrie.enrichment.session.playbook_name",
            "dshield.cowrie.enrichment.session.cluster.external_match_id",
            "dshield.cowrie.enrichment.session.cluster.external_match_cosine",
        ],
        "query": {"bool": {"must": must}},
        "sort": [{_F_TS: {"order": "desc"}}],
    }
    try:
        resp = es.search(index=sessions_idx, **body)
    except Exception as exc:  # noqa: BLE001
        log.warning("hunts: %s execution failed: %s", hunt["id"], exc)
        return []
    out: list[dict[str, Any]] = []
    for h in (resp.get("hits") or {}).get("hits") or []:
        s = h["_source"]
        sid = ((s.get("cowrie") or {}).get("session_id")) or h["_id"]
        sess_enr = ((s.get("dshield") or {}).get("cowrie", {})
                    .get("enrichment", {}).get("session", {})) or {}
        cluster = sess_enr.get("cluster") or {}
        out.append({
            "kind":     "analyst_hunt",
            "run_id":   run_id,
            "artifact": {"kind": "session", "value": sid},
            "score":    1.0,
            # `delta_signature` carries the hunt id so two different
            # hunts on the same session produce two distinct findings
            # (the writer hashes (kind, artifact_kind, artifact_value,
            # delta_signature) into the finding_id).
            "delta_signature": f"hunt:{hunt['id']}",
            "narrative": (
                f"Session {sid} matches hunt '{hunt['name']}' "
                f"({len(must)} filter{'s' if len(must) > 1 else ''})."
            ),
            "evidence": {
                "hunt_id":          hunt["id"],
                "hunt_name":        hunt["name"],
                "hunt_description": hunt.get("description") or "",
                "session_id":       sid,
                "source_ip":        (s.get("source") or {}).get("ip"),
                "first_seen":       s.get("event", {}).get("start"),
                "last_seen":        s.get("event", {}).get("end"),
                "command_count":    sess_enr.get("command_count"),
                "dominant_intent":  sess_enr.get("dominant_intent"),
                "playbook_id":      sess_enr.get("playbook_id"),
                "playbook_name":    sess_enr.get("playbook_name"),
                "external_match_id":     cluster.get("external_match_id"),
                "external_match_cosine": cluster.get("external_match_cosine"),
            },
        })
    return out


def run_hunts(es: Elasticsearch, cfg: Any, run_id: str) -> dict[str, Any]:
    """Load every YAML in `cfg.findings.hunts.config_dir`, execute each
    one against the session rollup, and return:

        {
          "loaded":   n_hunts,
          "by_hunt":  {hunt_id: [finding, ...]},
          "skipped":  ["disabled_id", ...],
          "errors":   [{"hunt_id": ..., "error": ...}],
        }

    The caller (``run_mine`` in miner.py) writes the per-hunt finding
    lists via ``bulk_upsert_findings``.
    """
    hunts_dir = getattr(getattr(cfg.findings, "hunts", None),
                        "config_dir", "config/hunts")
    max_per_hunt = int(getattr(getattr(cfg.findings, "hunts", None),
                               "max_findings_per_hunt",
                               _MAX_FINDINGS_PER_HUNT))
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup

    out: dict[str, Any] = {
        "loaded":  0, "by_hunt": {}, "errors": [],
    }
    try:
        hunts = load_hunts(hunts_dir)
    except Exception as exc:  # noqa: BLE001
        log.warning("hunts: load failed: %s", exc)
        out["errors"].append({"hunt_id": None, "error": str(exc)})
        return out
    out["loaded"] = len(hunts)
    if not hunts:
        return out

    if not es.indices.exists(index=sessions_idx):
        log.info("hunts: sessions rollup %s does not exist; skipping all",
                 sessions_idx)
        return out

    for hunt in hunts:
        try:
            findings = _run_one_hunt(
                es, sessions_idx, hunt,
                run_id=run_id, max_findings=max_per_hunt,
            )
            out["by_hunt"][hunt["id"]] = findings
        except Exception as exc:  # noqa: BLE001
            log.warning("hunts: %s failed: %s", hunt["id"], exc)
            out["errors"].append({"hunt_id": hunt["id"], "error": str(exc)})
    return out
