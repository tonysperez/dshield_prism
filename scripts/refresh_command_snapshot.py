"""Refresh the command-layer regression gate's snapshot.

Pulls every embedded command from the production enriched-command index
with the fields the command clusterer consumes (embedding + the four
scalar-block inputs) plus ``intent`` (for the self-consistency
intent-purity metric), and writes a gzipped JSONL to
``eval/command-snapshot-v1.jsonl.gz`` (committed so CI can score the
command layer offline — there is no analyst label set for commands, so
the gate is self-consistency only: outlier rate, cluster count, rescue
count, intent purity).

Snapshot layout mirrors the session snapshot:
  * Line 1: ``{"_metadata": true, "captured_at": "...", ...}``.
  * Lines 2..N: ``{"_id": "...", "_source": {...}}`` one per command.

Run from the repo root via the production venv (or the workstation venv
with ES creds):
    sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \\
      scripts/refresh_command_snapshot.py
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

# Exactly the fields the command clusterer reads (iter_enriched_docs) plus
# intent for the purity metric. No command_line — the gate scores cluster
# shape, not text, so we keep the snapshot lean and leak-free.
_SOURCE_FIELDS = [
    "dshield.cowrie.enrichment.embedding",
    "dshield.cowrie.enrichment.occurrence_count",
    "dshield.cowrie.enrichment.unique_sessions",
    "dshield.cowrie.enrichment.unique_source_ips",
    "dshield.cowrie.enrichment.confidence",
    "dshield.cowrie.enrichment.intent",
]


def _iter_embedded(es, index: str, page_size: int):
    body: dict = {
        "size": page_size,
        "_source": _SOURCE_FIELDS,
        "query": {"exists": {"field": "dshield.cowrie.enrichment.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h["_id"], h["_source"]
        search_after = hits[-1]["sort"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config-path", type=str, default=None)
    ap.add_argument("--output", type=Path,
                    default=Path("eval/command-snapshot-v1.jsonl.gz"))
    ap.add_argument("--page-size", type=int, default=1000)
    ap.add_argument("--label", type=str, default=None)
    args = ap.parse_args()

    cfg = load_config(args.config_path)
    secrets = load_secrets(args.config_path)
    es = make_client(cfg.elasticsearch, secrets)
    idx = cfg.elasticsearch.indexes.cowrie.commands
    if not es.indices.exists(index=idx):
        raise SystemExit(f"Commands index '{idx}' not found.")

    ccfg = cfg.command_cluster
    metadata = {
        "_metadata": True,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "commands_index": idx,
        "label": args.label,
        "command_cluster_config_at_capture": {
            "min_cluster_size": ccfg.min_cluster_size,
            "min_samples": ccfg.min_samples,
            "scalar_weight": ccfg.scalar_weight,
            "rescue_threshold": ccfg.rescue_threshold,
        },
        "schema_version": 1,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_suffix(args.output.suffix + ".tmp")
    n = 0
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        f.write(json.dumps(metadata) + "\n")
        for doc_id, src in _iter_embedded(es, idx, args.page_size):
            f.write(json.dumps({"_id": doc_id, "_source": src},
                                separators=(",", ":")) + "\n")
            n += 1
            if n % 1000 == 0:
                print(f"  wrote {n} commands...", flush=True)
    tmp.replace(args.output)
    mb = args.output.stat().st_size / (1024 * 1024)
    print(f"\nwrote {args.output} — {n} commands, {mb:.2f} MB gzipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
