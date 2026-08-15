"""Refresh command-cluster taxonomy tokens in the eval JSONLs from live ES.

Surgical companion to ``refresh_eval_embeddings.py`` — where that script
refreshes the persisted *embedding* vectors after a re-embed, this one
refreshes the persisted *command-cluster-id* tokens
(``dshield.cowrie.enrichment.cluster``) after a clustering/taxonomy
re-run. Without this, the eval set's TF-IDF bag vocabulary drifts out of
sync with the live anchor snapshot's vocabulary (item 46 — the eval set's
dominant token can end up entirely absent from the current taxonomy,
making any TF-IDF-dependent replay measure vocabulary skew rather than
the assignment mechanism).

  * Reads each command hash referenced by ``command_enrichments`` (the
    labeled set is fixed — we never change the SET of sessions or their
    commands, only the cluster id each command currently resolves to).
  * Pulls the current, public-only ``{hash: cluster_id}`` map via
    ``lexical.pull_hash_to_cluster`` (the same call
    ``capture_anchor_snapshot.py`` uses) — never an unfiltered `mget`, since
    a command doc's classification is an aggregate over its *current*
    contributing sessions and can have flipped to confidential since this
    fixture was captured.
  * For each command whose hash resolves in that map, overwrites just its
    ``cluster`` sub-object. A hash that no longer resolves publicly (or at
    all) has its stale ``cluster`` block cleared, which makes it fall back
    to the outlier token downstream — the same fail-safe default
    ``build_bag_texts``/``_command_cluster_bag`` already use for any
    unresolved hash.
  * Every other field (embedding, raw_events, hash_intel, url_intel,
    stratum, …) is left untouched.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/refresh_eval_taxonomy.py
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.lexical import pull_hash_to_cluster

from eval_jsonl import open_jsonl
from eval_jsonl import resolve as resolve_jsonl

log = logging.getLogger(__name__)


def _collect_hashes(records: list[dict]) -> set[str]:
    hashes: set[str] = set()
    for rec in records:
        for ce in rec.get("command_enrichments") or []:
            short = ((ce.get("event") or {}).get("id"))
            if isinstance(short, str):
                hashes.add(short)
    return hashes


def _refresh_cluster_tokens(
    command_enrichments: list[dict], hash_to_cluster: dict[str, str],
) -> dict:
    """Mutate each enrichment's ``cluster`` sub-object in place from the fresh
    public-only taxonomy. A hash not in ``hash_to_cluster`` (non-public now,
    or absent from the live corpus) gets its stale ``cluster`` block cleared
    rather than left stale — downstream bag-building already treats a
    missing/absent ``cluster.id`` as the outlier token, so clearing is a
    fail-safe no-op there, not a special case. Returns
    ``{refreshed, cleared, missing_hash}`` counts."""
    stats = {"refreshed": 0, "cleared": 0, "missing_hash": 0}
    for ce in command_enrichments:
        short = ((ce.get("event") or {}).get("id"))
        if not isinstance(short, str):
            stats["missing_hash"] += 1
            continue
        dshield = ce.get("dshield")
        if not isinstance(dshield, dict):
            dshield = ce["dshield"] = {}
        cowrie = dshield.get("cowrie")
        if not isinstance(cowrie, dict):
            cowrie = dshield["cowrie"] = {}
        enrichment = cowrie.get("enrichment")
        if not isinstance(enrichment, dict):
            enrichment = cowrie["enrichment"] = {}
        value = hash_to_cluster.get(short)
        if value is None:
            enrichment.pop("cluster", None)
            stats["cleared"] += 1
            continue
        enrichment["cluster"] = {
            "id": value,
            "is_outlier": value == "cluster_outlier",
        }
        stats["refreshed"] += 1
    return stats


def _refresh_one(es, commands_index: str, jsonl_path: Path, *, filt: list[dict]) -> dict:
    """Walk the JSONL, refresh every command's cluster token, write back.
    Stats returned so the caller can sanity-check yield rate."""
    jsonl_path = resolve_jsonl(jsonl_path)
    if not jsonl_path.exists():
        log.warning("missing JSONL: %s — skipping", jsonl_path)
        return {"refreshed": 0, "cleared": 0, "missing_hash": 0}

    records: list[dict] = []
    with open_jsonl(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))

    hashes = _collect_hashes(records)
    log.info("%s: %d sessions, %d unique command hashes",
             jsonl_path.name, len(records), len(hashes))

    hash_to_cluster = pull_hash_to_cluster(es, commands_index, filt=filt)
    log.info("  live public-only taxonomy: %d command hashes", len(hash_to_cluster))

    # An empty taxonomy against a non-empty hash set almost always means the
    # ES query itself failed to find anything (wrong index, auth, connectivity,
    # a broken filter) rather than every referenced command having genuinely
    # gone confidential/vanished. Refuse to write in that case rather than
    # silently clearing every cluster token in the fixture.
    if hashes and not hash_to_cluster:
        log.error(
            "%s: live taxonomy fetch returned 0 hashes against %d referenced "
            "in the fixture — refusing to write (check ES connectivity/index/filter)",
            jsonl_path.name, len(hashes),
        )
        return {"refreshed": 0, "cleared": 0, "missing_hash": 0, "aborted": 1}

    totals = {"refreshed": 0, "cleared": 0, "missing_hash": 0}
    for rec in records:
        stats = _refresh_cluster_tokens(
            rec.get("command_enrichments") or [], hash_to_cluster,
        )
        for k, v in stats.items():
            totals[k] += v

    # Keep ``.gz`` last so the writer still gzips the temp file; a plain
    # ``.gz.tmp`` would silently write plaintext under a gzip name.
    suffix = ".tmp.gz" if jsonl_path.name.endswith(".gz") else ".tmp"
    tmp_path = jsonl_path.parent / (jsonl_path.name + suffix)
    with open_jsonl(tmp_path, "wt") as f:
        for rec in records:
            f.write(json.dumps(rec, default=str) + "\n")
    os.replace(tmp_path, jsonl_path)

    log.info("%s: refreshed %d, cleared %d, missing_hash %d",
              jsonl_path.name, totals["refreshed"], totals["cleared"],
              totals["missing_hash"])
    return totals


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
    commands_index = cfg.elasticsearch.indexes.cowrie.commands
    # pull_hash_to_cluster's `filt` is a list of bool.filter clauses spliced
    # onto its base query (`[{"exists": ...}] + list(filt or [])`);
    # releasable_filter returns a single clause dict, so it must be wrapped —
    # passing the bare dict would have `list()` iterate its keys instead.
    filt = [releasable_filter(cfg)]

    total_refreshed = 0
    for p in args.jsonls:
        stats = _refresh_one(es, commands_index, p, filt=filt)
        total_refreshed += stats.get("refreshed", 0)
    log.info("total command tokens refreshed across all JSONLs: %d",
              total_refreshed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
