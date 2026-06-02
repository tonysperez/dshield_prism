"""Refresh persisted session embeddings in the eval JSONLs from live ES.

Surgical companion to ``build_eval_set.py`` — when production runs
``reembed`` (after a config change that flipped ``embed_config_hash``),
the v1+v2 unlabeled JSONLs go stale: their persisted session embeddings
still encode the old config. This script does the minimum work needed
to verify the new production state on the eval set:

  * Reads each session_id from the JSONL (the labeled set is fixed —
    we never change the SET of sessions, only their embedding vectors).
  * Queries live ES for the current session-rollup ``embedding`` field.
  * Replaces just that field in-place; every other field (raw_events,
    command_enrichments, intel, stratum, divergent_pair_id, …) is left
    untouched so the redaction work and labeling join points stay
    valid.

After this script runs, ``eval_clustering.py`` reflects whatever the
production embedding pipeline currently produces.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/refresh_eval_embeddings.py
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

log = logging.getLogger(__name__)

_SESSION_ENRICHMENT_PATH = ("dshield", "cowrie", "enrichment", "session")
_COMMAND_ENRICHMENT_PATH = ("dshield", "cowrie", "enrichment")


def _dig(d: dict, *path: str) -> dict | None:
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur if isinstance(cur, dict) else None


def _fetch_session_embeddings(
    es, sessions_index: str, session_ids: list[str],
) -> dict[str, list[float]]:
    """Return {session_id: embedding} via a single terms search."""
    if not session_ids:
        return {}
    body = {
        "size": len(session_ids),
        "_source": [
            "cowrie.session_id",
            "dshield.cowrie.enrichment.session.embedding",
        ],
        "query": {"terms": {"cowrie.session_id": session_ids}},
    }
    resp = es.search(index=sessions_index, **body)
    out: dict[str, list[float]] = {}
    for h in resp["hits"]["hits"]:
        src = h["_source"]
        sid = (src.get("cowrie") or {}).get("session_id")
        emb = (_dig(src, *_SESSION_ENRICHMENT_PATH) or {}).get("embedding")
        if isinstance(sid, str) and isinstance(emb, list):
            out[sid] = emb
    return out


def _fetch_command_embeddings(
    es, commands_index: str, command_hashes: list[str],
) -> dict[str, list[float]]:
    """Return {hash: embedding} via mget. command-enrichment doc _ids
    are the 16-hex normalized-command hash."""
    if not command_hashes:
        return {}
    out: dict[str, list[float]] = {}
    batch_size = 512
    for i in range(0, len(command_hashes), batch_size):
        batch = command_hashes[i : i + batch_size]
        resp = es.mget(
            index=commands_index, body={"ids": batch},
            _source=["dshield.cowrie.enrichment.embedding"],
        )
        for doc in resp.get("docs") or []:
            if not doc.get("found"):
                continue
            src = doc.get("_source") or {}
            enr = _dig(src, *_COMMAND_ENRICHMENT_PATH) or {}
            emb = enr.get("embedding")
            if isinstance(emb, list):
                out[doc["_id"]] = emb
    return out


def _refresh_one(
    es, sessions_index: str, commands_index: str, jsonl_path: Path,
) -> dict:
    """Walk the JSONL, refresh session + per-command embeddings, write
    back. Stats returned so the caller can sanity-check yield rate."""
    if not jsonl_path.exists():
        log.warning("missing JSONL: %s — skipping", jsonl_path)
        return {"skipped": 0, "refreshed_sessions": 0, "missing": 0}

    records: list[dict] = []
    session_ids: list[str] = []
    command_hashes: set[str] = set()
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            records.append(rec)
            sid = rec.get("session_id")
            if isinstance(sid, str):
                session_ids.append(sid)
            for ce in rec.get("command_enrichments") or []:
                # Persisted command_enrichment docs typically carry
                # `process.hash.sha256` (full) but the index _id is the
                # 16-hex prefix. We bypass by walking `event.id` which
                # _build_ecs_doc stamps to the short hash.
                ev = (ce.get("event") or {})
                short = ev.get("id")
                if isinstance(short, str):
                    command_hashes.add(short)

    log.info("%s: %d sessions, %d unique command-enrichment hashes",
             jsonl_path.name, len(session_ids), len(command_hashes))

    sess_embeds = _fetch_session_embeddings(es, sessions_index, session_ids)
    cmd_embeds = _fetch_command_embeddings(
        es, commands_index, sorted(command_hashes),
    )
    log.info("  resolved %d/%d session embeddings, %d/%d command embeddings",
             len(sess_embeds), len(session_ids),
             len(cmd_embeds), len(command_hashes))

    refreshed = 0
    missing = 0
    for rec in records:
        sid = rec.get("session_id")
        rollup = rec.get("rollup_doc") or {}
        enr = _dig(rollup, *_SESSION_ENRICHMENT_PATH)
        if enr is None or sid not in sess_embeds:
            missing += 1
            continue
        enr["embedding"] = sess_embeds[sid]
        # Also refresh per-command embeddings so any downstream consumer
        # that pools from per-command vectors (e.g. the E2.1 sweep, the
        # E0.3 audit) sees fresh data.
        for ce in rec.get("command_enrichments") or []:
            short = (ce.get("event") or {}).get("id")
            if not isinstance(short, str) or short not in cmd_embeds:
                continue
            ce_enr = _dig(ce, *_COMMAND_ENRICHMENT_PATH)
            if ce_enr is not None:
                ce_enr["embedding"] = cmd_embeds[short]
        refreshed += 1

    with jsonl_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, default=str) + "\n")

    log.info("%s: refreshed %d session embeddings (%d missing)",
             jsonl_path.name, refreshed, missing)
    return {
        "refreshed_sessions": refreshed,
        "missing":            missing,
        "command_embeddings_resolved": len(cmd_embeds),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jsonls", type=Path, nargs="+",
                    default=[
                        Path("eval/sessions-v1.unlabeled.jsonl"),
                        Path("eval/sessions-v2.unlabeled.jsonl"),
                    ],
                    help="One or more JSONL files to refresh in place.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)
    sessions_index = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    commands_index = cfg.elasticsearch.indexes.cowrie.commands

    total_refreshed = 0
    for p in args.jsonls:
        stats = _refresh_one(es, sessions_index, commands_index, p)
        total_refreshed += stats.get("refreshed_sessions", 0)
    log.info("total session embeddings refreshed across all JSONLs: %d",
             total_refreshed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
