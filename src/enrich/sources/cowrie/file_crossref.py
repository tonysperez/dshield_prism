"""Cross-session file -> command attribution (brutal-review 7.6).

Joins each per-session `file_events` entry to subsequent command lines run
by the same source.ip across sessions. Output: one doc per
`(sha256, source.ip)` in `prism.crossref.file_command` capturing:

  * `first_seen`     — earliest session this IP dropped (download/upload)
                       the hash. Carries the in-session command attribution
                       (from session_rollup `file_events[].command_hash`)
                       when available.
  * `first_executed` — earliest session this IP ran a command whose line
                       references the file's basename, that is later than
                       (or equal to) `first_seen.ts`. Same-session
                       drop+exec collapses into both pointers; truly
                       cross-session drop -> exec is what the
                       `cross_session=true` flag highlights.

Run via `mine file-crossref` (CLI verb) — invoked by the backward chain
after `mine campaigns` so the session rollup is fresh.

Re-runs converge: doc `_id = "fcx-<sha16(sha256:ip)>"` is content-addressed.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime

from elasticsearch import Elasticsearch

from ...config import AppConfig, Secrets
from ...es_client import bulk_write, init_index, make_client

log = logging.getLogger(__name__)

_MAPPING = "setup/es-mappings/cowrie/file_command_crossref.json"

# Cap so a single hash dropped on thousands of unique IPs doesn't blow up
# the working set. Tail beyond the cap stays un-crossref'd; the analyst
# can pivot on the in-corpus droppers list which is uncapped.
_MAX_PAIRS_PER_RUN = 50000

# Cap how many distinct candidate-execution sessions we scan per pair.
# Most files exec on their first or second appearance; deep tails are
# rarely informative for this surface.
_MAX_CANDIDATE_SESSIONS_PER_PAIR = 200

_PAGE_SIZE = 1000

# Word-boundary regex compile cache. Bounded — the working set of distinct
# filenames per run is small (~ thousands).
_FILENAME_PAT_CACHE: dict[str, re.Pattern] = {}


def _crossref_id(sha256: str, ip: str) -> str:
    """Content-addressed id stable across re-mines."""
    digest = hashlib.sha256(f"{sha256}:{ip}".encode()).hexdigest()[:16]
    return f"fcx-{digest}"


def _filename_is_specific(basename: str) -> bool:
    """Same guard as sessions.py — a basename is specific enough to risk
    a `command_line` substring match only if it has a real extension
    or is at least 5 chars. Rejects `sshd`, `a`, `x`. Empty -> not
    specific. Duplicated here to avoid pulling the sessions module's
    import chain into this miner."""
    if not basename:
        return False
    if re.search(r"\.[A-Za-z0-9]{1,6}$", basename):
        return True
    return len(basename) >= 5


def _filename_pat(basename: str) -> re.Pattern:
    """Word-boundary regex matching `basename` as a whole token in a
    command line. Cached per process — caller must filter through
    `_filename_is_specific` first."""
    pat = _FILENAME_PAT_CACHE.get(basename)
    if pat is None:
        pat = re.compile(r"(?<![\w.\-])" + re.escape(basename) + r"(?![\w.\-])")
        _FILENAME_PAT_CACHE[basename] = pat
    return pat


def _iter_session_file_events(
    es: Elasticsearch, sessions_idx: str,
) -> list[tuple[str, str, str, list[dict], list[str]]]:
    """Scroll the session rollup yielding tuples of
    `(session_id, source_ip, event_start, file_events, command_set)`
    for every session that touched at least one file.

    Returned as a list (not a generator) because the caller groups by
    `(sha256, ip)` before the second pass — there's no streaming win
    and a materialised list lets us cap working-set explicitly.
    """
    out: list[tuple[str, str, str, list[dict], list[str]]] = []
    body: dict = {
        "size": _PAGE_SIZE,
        "_source": [
            "cowrie.session_id",
            "source.ip",
            "event.start",
            "dshield.cowrie.enrichment.session.file_events",
            "dshield.cowrie.enrichment.session.command_set",
        ],
        "query": {"nested": {
            "path": "dshield.cowrie.enrichment.session.file_events",
            "query": {"exists": {"field":
                "dshield.cowrie.enrichment.session.file_events.sha256"}},
        }},
        "sort": [{"event.start": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=sessions_idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return out
        for h in hits:
            src = h.get("_source") or {}
            sid = ((src.get("cowrie") or {}).get("session_id")) or h["_id"]
            ip = ((src.get("source") or {}).get("ip"))
            ts = (src.get("event") or {}).get("start")
            sess = (((src.get("dshield") or {}).get("cowrie") or {})
                    .get("enrichment", {}).get("session", {}))
            fe = sess.get("file_events") or []
            cmd_set = sess.get("command_set") or []
            if ip and ts and fe:
                out.append((sid, ip, ts, fe, cmd_set))
        search_after = hits[-1]["sort"]


def _resolve_first_executed(
    es: Elasticsearch,
    cfg: AppConfig,
    *,
    sha256: str,
    ip: str,
    first_seen_ts: str,
    filenames: set[str],
    first_seen_session: str,
    first_seen_attr: str | None,
) -> dict | None:
    """Find the earliest session by `ip` (at or after `first_seen_ts`)
    where any command's `process.command_line` contains one of
    `filenames` as a whole-token match.

    If the first_seen session itself carries a same-session command
    attribution (url_match / destfile_match), it counts as the
    first_executed unless an earlier-timestamped execution-only session
    is found.

    Returns `{session_id, ts, command_hash, command_line}` or None.
    """
    # 1. Build a filename match query against the commands enrichment
    #    index, intersected with same-IP sessions whose event.start >=
    #    first_seen_ts. We pull hashes; resolving the command line happens
    #    in step 2.
    specific = [f for f in filenames if _filename_is_specific(f)]
    if not specific:
        # Without a specific filename to anchor on, we can't go further.
        # The first_seen session's own attribution still applies if any.
        if first_seen_attr in ("url_match", "destfile_match"):
            return _same_session_first_executed(
                es, cfg, ip=ip, session_id=first_seen_session,
                ts=first_seen_ts, filenames=filenames,
            )
        return None

    # Match any of the specific filenames in process.command_line.
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands
    try:
        should = [
            {"match_phrase": {"process.command_line": fn}}
            for fn in specific
        ]
        cmd_resp = es.search(
            index=cmd_idx, size=200,
            query={"bool": {"should": should, "minimum_should_match": 1}},
            _source=["process.command_line", "process.hash.sha256"],
        )
    except Exception as exc:
        log.warning("[crossref] command match query failed for sha=%s ip=%s: %s",
                    sha256[:12], ip, exc)
        return None

    # Map command_hash -> command_line for the verification step.
    cmd_hash_to_line: dict[str, str] = {}
    for ch in cmd_resp.get("hits", {}).get("hits", []):
        s = ch.get("_source") or {}
        line = (s.get("process") or {}).get("command_line") or ""
        cmd_hash = (((s.get("process") or {}).get("hash") or {}).get("sha256")) or ch["_id"]
        if not cmd_hash:
            continue
        # Verify the whole-token match in-process to suppress false-positive
        # nibbles (ES match_phrase tokenises against the default analyzer
        # and can be lax around punctuation in shell commands).
        if any(_filename_pat(fn).search(line) for fn in specific):
            cmd_hash_to_line[cmd_hash] = line
    if not cmd_hash_to_line:
        if first_seen_attr in ("url_match", "destfile_match"):
            return _same_session_first_executed(
                es, cfg, ip=ip, session_id=first_seen_session,
                ts=first_seen_ts, filenames=filenames,
            )
        return None

    # 2. Find the earliest session by this IP, at-or-after first_seen_ts,
    #    that contains any of the matching command hashes.
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        sess_resp = es.search(
            index=sessions_idx,
            size=_MAX_CANDIDATE_SESSIONS_PER_PAIR,
            query={"bool": {"must": [
                {"term": {"source.ip": ip}},
                {"range": {"event.start": {"gte": first_seen_ts}}},
                {"terms": {
                    "dshield.cowrie.enrichment.session.command_set":
                        list(cmd_hash_to_line.keys()),
                }},
            ]}},
            _source=[
                "cowrie.session_id", "event.start",
                "dshield.cowrie.enrichment.session.command_set",
            ],
            sort=[{"event.start": "asc"}, {"_doc": "asc"}],
        )
    except Exception as exc:
        log.warning("[crossref] session lookup failed for sha=%s ip=%s: %s",
                    sha256[:12], ip, exc)
        return None

    for sh in sess_resp.get("hits", {}).get("hits", []):
        s = sh.get("_source") or {}
        sid = ((s.get("cowrie") or {}).get("session_id")) or sh["_id"]
        ts = (s.get("event") or {}).get("start")
        cmd_set = (((s.get("dshield") or {}).get("cowrie") or {})
                   .get("enrichment", {}).get("session", {})).get("command_set") or []
        for ch in cmd_set:
            if ch in cmd_hash_to_line:
                return {
                    "session_id":   sid,
                    "ts":           ts,
                    "command_hash": ch,
                    "command_line": cmd_hash_to_line[ch],
                }
    return None


def _same_session_first_executed(
    es: Elasticsearch,
    cfg: AppConfig,
    *,
    ip: str, session_id: str, ts: str,
    filenames: set[str],
) -> dict | None:
    """Fallback when the same-session drop+exec is the only attribution
    available — read the command's line out of the commands enrichment
    index so the surface can render it. Used when filename-specificity
    rejection wiped out the cross-session lookup but `command_attribution`
    on the file_events record still pointed at an in-session command."""
    # We don't carry the per-session command line here; the caller has
    # only command_hash. Skip — let the caller leave first_executed null
    # rather than half-populate. The console can still derive the link
    # from the session_rollup's file_events when needed.
    return None


def _build_doc(
    sha256: str, ip: str,
    timeline: list[dict],
    first_executed: dict | None,
    run_id: str,
    now_iso: str,
) -> dict:
    """Compose the crossref doc for one (sha256, ip) pair. `timeline` is
    every (file_events entry + session metadata) for this pair, ordered
    by ts asc."""
    head = timeline[0]
    first_seen_block = {
        "session_id":          head["session_id"],
        "ts":                  head["ts"],
        "action":              head["action"],
    }
    if head.get("filename"):
        first_seen_block["filename"] = head["filename"]
    if head.get("command_hash"):
        first_seen_block["command_hash"] = head["command_hash"]
    if head.get("command_attribution"):
        first_seen_block["command_attribution"] = head["command_attribution"]

    n_sessions_dropped = len({t["session_id"] for t in timeline})

    cross_session = False
    n_sessions_executed = 0
    fexec_block: dict | None = None
    if first_executed:
        fexec_block = {
            "session_id":   first_executed["session_id"],
            "command_hash": first_executed["command_hash"],
        }
        if first_executed.get("ts"):
            fexec_block["ts"] = first_executed["ts"]
        if first_executed.get("command_line"):
            fexec_block["command_line"] = first_executed["command_line"]
        n_sessions_executed = 1  # at least one — we found one
        cross_session = first_executed["session_id"] != head["session_id"]

    doc: dict = {
        "@timestamp":          now_iso,
        "crossref_id":         _crossref_id(sha256, ip),
        "sha256":               sha256,
        "source":               {"ip": ip},
        "first_seen":           first_seen_block,
        "n_sessions_dropped":   n_sessions_dropped,
        "n_sessions_executed":  n_sessions_executed,
        "cross_session":        cross_session,
        "run_id":               run_id,
        "generated_at":         now_iso,
    }
    if fexec_block is not None:
        doc["first_executed"] = fexec_block
    return doc


def run_mine_file_crossref(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """Cross-session file -> command attribution miner.

    Stats: `{pairs_seen, pairs_written, cross_session, dry_run, ...}`.
    """
    t0 = time.time()
    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    out_idx = cfg.elasticsearch.indexes.cowrie.file_command_crossref

    if not es.indices.exists(index=sessions_idx):
        return {
            "pairs_seen": 0, "pairs_written": 0, "cross_session": 0,
            "dry_run": dry_run, "reason": f"sessions index missing: {sessions_idx}",
        }

    timeline: list = _iter_session_file_events(es, sessions_idx)
    by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for sid, ip, ts, fe_list, cmd_set in timeline:
        for fe in fe_list:
            sha = fe.get("sha256")
            if not sha:
                continue
            by_pair[(sha, ip)].append({
                "session_id":          sid,
                "ts":                  fe.get("ts") or ts,
                "action":              fe.get("action"),
                "filename":            fe.get("filename"),
                "command_hash":        fe.get("command_hash"),
                "command_attribution": fe.get("command_attribution"),
                "_command_set":        cmd_set,
            })
        if len(by_pair) >= _MAX_PAIRS_PER_RUN:
            log.warning("[crossref] working-set cap reached at %d pairs; tail skipped",
                        _MAX_PAIRS_PER_RUN)
            break

    if not by_pair:
        return {
            "pairs_seen": 0, "pairs_written": 0, "cross_session": 0,
            "dry_run": dry_run, "runtime_seconds": round(time.time() - t0, 2),
        }

    init_index(es, _MAPPING, out_idx)
    run_id = str(uuid.uuid4())
    now_iso = datetime.now(UTC).isoformat()
    pairs_written = 0
    cross_session_count = 0
    actions: list[dict] = []
    BATCH = 200

    for (sha, ip), records in by_pair.items():
        records.sort(key=lambda r: r["ts"])
        filenames = {r["filename"] for r in records if r.get("filename")}
        first_seen = records[0]

        first_executed = _resolve_first_executed(
            es, cfg,
            sha256=sha, ip=ip,
            first_seen_ts=first_seen["ts"],
            filenames=filenames,
            first_seen_session=first_seen["session_id"],
            first_seen_attr=first_seen.get("command_attribution"),
        )
        # When the first_seen record itself attributes to an in-session
        # command, the same session counts as first_executed (cross_session
        # = False). Only override when nothing cross-session was found.
        if first_executed is None and first_seen.get("command_hash") and \
                first_seen.get("command_attribution") in ("url_match", "destfile_match"):
            first_executed = {
                "session_id":   first_seen["session_id"],
                "ts":           first_seen["ts"],
                "command_hash": first_seen["command_hash"],
                "command_line": None,  # not surfaced when same-session
            }

        doc = _build_doc(sha, ip, records, first_executed, run_id, now_iso)
        if doc["cross_session"]:
            cross_session_count += 1
        actions.append({
            "_op_type": "index",
            "_id":      doc["crossref_id"],
            "_source":  doc,
        })
        pairs_written += 1

        if not dry_run and len(actions) >= BATCH:
            _ok, errs = bulk_write(es, out_idx, actions)
            if errs:
                log.warning("[crossref] bulk errors (%d): %s", len(errs), errs[:2])
            actions = []

    if not dry_run and actions:
        _ok, errs = bulk_write(es, out_idx, actions)
        if errs:
            log.warning("[crossref] bulk errors (%d): %s", len(errs), errs[:2])

    try:
        if not dry_run:
            es.indices.refresh(index=out_idx)
    except Exception as exc:
        log.warning("[crossref] post-write refresh failed: %s", exc)

    return {
        "pairs_seen":      len(by_pair),
        "pairs_written":   pairs_written if not dry_run else 0,
        "cross_session":   cross_session_count,
        "dry_run":         dry_run,
        "run_id":          run_id,
        "runtime_seconds": round(time.time() - t0, 2),
    }
