"""Refresh persisted session embeddings in the eval JSONLs from live ES.

Surgical companion to ``build_eval_set.py`` — when production runs
``reembed`` (after a config change that flipped ``embed_config_hash``),
the unlabeled JSONL goes stale: its persisted session embeddings still
encode the old config. This script does the minimum work needed to
verify the new production state on the eval set:

  * Reads each session_id from the JSONL (the labeled set is fixed —
    we never change the SET of sessions, only their embedding vectors).
  * Queries live ES for the current session-rollup ``embedding`` field.
  * Replaces just that field in-place; every other field (raw_events,
    command_enrichments, intel, stratum, divergent_pair_id, …) is left
    untouched so the redaction work and labeling join points stay
    valid. Per-command embeddings are not persisted — see `_refresh_one`.

The set is committed gzipped (``eval/sessions.unlabeled.jsonl.gz``); either
spelling may be passed to ``--jsonls`` and is resolved to what exists.

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
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from eval_jsonl import open_jsonl
from eval_jsonl import resolve as resolve_jsonl

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

log = logging.getLogger(__name__)

_SESSION_ENRICHMENT_PATH = ("dshield", "cowrie", "enrichment", "session")


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


def _refresh_one(es, sessions_index: str, jsonl_path: Path) -> dict:
    """Walk the JSONL, refresh session embeddings, write back. Stats
    returned so the caller can sanity-check yield rate."""
    jsonl_path = resolve_jsonl(jsonl_path)
    if not jsonl_path.exists():
        log.warning("missing JSONL: %s — skipping", jsonl_path)
        return {"skipped": 0, "refreshed_sessions": 0, "missing": 0}

    records: list[dict] = []
    session_ids: list[str] = []
    with open_jsonl(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            records.append(rec)
            sid = rec.get("session_id")
            if isinstance(sid, str):
                session_ids.append(sid)

    log.info("%s: %d sessions", jsonl_path.name, len(session_ids))

    sess_embeds = _fetch_session_embeddings(es, sessions_index, session_ids)
    log.info("  resolved %d/%d session embeddings",
             len(sess_embeds), len(session_ids))

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
        # Per-command embeddings are deliberately NOT written back. They were
        # 147 MB of the 186 MB set (79%) and no consumer reads them from the
        # JSONL: the sweeps that pool per-command vectors
        # (`sweep_embed_input_order.py`, `sweep_embedding_model_prod.py`)
        # fetch them from live ES via `_pull_command_enrichments`. Persisting
        # them pushed the artifact past GitHub's 100 MB blob ceiling.
        refreshed += 1

    suffix = ".tmp.gz" if jsonl_path.name.endswith(".gz") else ".tmp"
    tmp_path = jsonl_path.parent / (jsonl_path.name + suffix)
    with open_jsonl(tmp_path, "wt") as f:
        for rec in records:
            f.write(json.dumps(rec, default=str) + "\n")
    os.replace(tmp_path, jsonl_path)

    log.info("%s: refreshed %d session embeddings (%d missing)",
             jsonl_path.name, refreshed, missing)
    return {
        "refreshed_sessions": refreshed,
        "missing":            missing,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jsonls", type=Path, nargs="+",
                    default=[Path("eval/sessions.unlabeled.jsonl.gz")],
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

    total_refreshed = 0
    for p in args.jsonls:
        stats = _refresh_one(es, sessions_index, p)
        total_refreshed += stats.get("refreshed_sessions", 0)
    log.info("total session embeddings refreshed across all JSONLs: %d",
             total_refreshed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
