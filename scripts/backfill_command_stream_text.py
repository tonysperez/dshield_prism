"""Backfill ``command_stream_text`` on existing session rollups.

When the E4.4 late-fusion adoption ships, the session rollup schema
grows a new ``command_stream_text`` field. Rollups built after the
deploy populate it automatically (rollup builder concatenates the
session's raw command_line stream as part of normal processing).
Rollups built before the deploy lack the field — this script walks
those, fetches their raw events from ``prism.raw.cowrie.session``,
rebuilds the text, and patches the rollup in place.

The script is idempotent: rollups already carrying
``command_stream_text`` are skipped. Rollups whose
``session.command_set`` is empty (login-only sessions, no shell
activity) are also skipped — the lexical view has nothing meaningful
for them.

Wall cost: paginate-by-1000 over rollups + one terms query per page
to fetch raw events + one bulk update per page. Scales linearly with
the number of un-backfilled sessions.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/backfill_command_stream_text.py
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import bulk_write, make_client

log = logging.getLogger(__name__)

_BASE = "dshield.cowrie.enrichment.session"
_WS_RE = re.compile(r"\s+")


def _iter_rollups_needing_backfill(
    es, rollup_index: str, page_size: int,
):
    """Stream session rollup _ids + session_ids for rollups that have a
    populated command_set but do NOT yet have command_stream_text."""
    body = {
        "size": page_size,
        "_source": ["cowrie.session_id"],
        "query": {"bool": {
            "must": [
                {"exists": {"field": f"{_BASE}.command_set"}},
            ],
            "must_not": [
                {"exists": {"field": f"{_BASE}.command_stream_text"}},
            ],
        }},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after is not None:
            body["search_after"] = search_after
        resp = es.search(index=rollup_index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            sid = (h["_source"].get("cowrie") or {}).get("session_id")
            if isinstance(sid, str) and sid:
                yield h["_id"], sid
        search_after = hits[-1].get("sort")
        if search_after is None:
            return


def _fetch_command_streams(
    es, raw_index: str, session_ids: list[str],
) -> dict[str, str]:
    """Return {session_id: concatenated_command_stream_text} from raw
    events. Order is chronological (asc by @timestamp), matching the
    rollup builder's behaviour. Empty stream → omitted (rollup will
    keep its missing field, matching the "skip if no commands" rule)."""
    if not session_ids:
        return {}
    body = {
        "size": 5000,
        "_source": [
            "cowrie.session_id",
            "process.command_line",
            "@timestamp",
        ],
        "query": {"bool": {"must": [
            {"term": {"event.action": "cowrie.command.input"}},
            {"terms": {"cowrie.session_id": session_ids}},
        ]}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    per_session: dict[str, list[str]] = {}
    search_after = None
    while True:
        if search_after is not None:
            body["search_after"] = search_after
        resp = es.search(index=raw_index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            src = h["_source"]
            sid = (src.get("cowrie") or {}).get("session_id")
            cmd = (src.get("process") or {}).get("command_line")
            if isinstance(sid, str) and isinstance(cmd, str) and cmd:
                per_session.setdefault(sid, []).append(cmd)
        if len(hits) < body["size"]:
            break
        search_after = hits[-1].get("sort")
        if search_after is None:
            break
    return {sid: " ".join(cmds) for sid, cmds in per_session.items() if cmds}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--page-size", type=int, default=1000)
    ap.add_argument("--max-pages", type=int, default=None,
                    help="Cap on rollup pages processed. Useful for "
                         "smoke-testing the script before a full run.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Compute the text but don't write back.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)
    rollup_index = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    raw_index    = cfg.elasticsearch.indexes.cowrie.sessions_raw
    log.info("rollup index: %s", rollup_index)
    log.info("raw index:    %s", raw_index)

    page_count = 0
    total_pages_processed = 0
    total_rollups_updated = 0
    total_skipped_no_commands = 0
    t0 = time.time()

    page_ids: list[tuple[str, str]] = []  # (rollup_doc_id, session_id)
    for doc_id, sid in _iter_rollups_needing_backfill(
        es, rollup_index, args.page_size,
    ):
        page_ids.append((doc_id, sid))
        if len(page_ids) < args.page_size:
            continue
        # Process this page
        sids = [s for _, s in page_ids]
        streams = _fetch_command_streams(es, raw_index, sids)
        actions: list[dict] = []
        for doc_id, sid in page_ids:
            text = streams.get(sid)
            if not text:
                total_skipped_no_commands += 1
                continue
            actions.append({
                "_op_type": "update",
                "_id":      doc_id,
                "doc": {
                    "dshield": {"cowrie": {"enrichment": {"session": {
                        "command_stream_text": text,
                    }}}}
                },
            })
        if actions and not args.dry_run:
            ok, errs = bulk_write(es, rollup_index, actions)
            if errs:
                log.warning("page %d: %d bulk errors", page_count, len(errs))
            total_rollups_updated += ok
        elif args.dry_run:
            total_rollups_updated += len(actions)
        page_count += 1
        total_pages_processed += 1
        if page_count % 5 == 0:
            log.info("processed %d pages, updated %d rollups so far (%.1fs)",
                     page_count, total_rollups_updated, time.time() - t0)
        if args.max_pages is not None and page_count >= args.max_pages:
            break
        page_ids = []

    # Final partial page
    if page_ids and (args.max_pages is None or page_count < args.max_pages):
        sids = [s for _, s in page_ids]
        streams = _fetch_command_streams(es, raw_index, sids)
        actions: list[dict] = []
        for doc_id, sid in page_ids:
            text = streams.get(sid)
            if not text:
                total_skipped_no_commands += 1
                continue
            actions.append({
                "_op_type": "update",
                "_id":      doc_id,
                "doc": {
                    "dshield": {"cowrie": {"enrichment": {"session": {
                        "command_stream_text": text,
                    }}}}
                },
            })
        if actions and not args.dry_run:
            ok, errs = bulk_write(es, rollup_index, actions)
            if errs:
                log.warning("final page: %d bulk errors", len(errs))
            total_rollups_updated += ok
        elif args.dry_run:
            total_rollups_updated += len(actions)
        total_pages_processed += 1

    log.info("done: %d pages, %d rollups updated, %d skipped (no commands), %.1fs",
             total_pages_processed, total_rollups_updated,
             total_skipped_no_commands, time.time() - t0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
