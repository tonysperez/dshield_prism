"""Refresh the production-scale gate's session-rollup snapshot.

Pulls every embedded session rollup from the production ES index, runs
each ``_source`` through the same ``_redact_event`` the eval-set
build pipeline uses, and writes a gzipped JSONL to
``eval/production-snapshot-v1.jsonl.gz`` (committed to the repo so CI
can score offline).

Snapshot layout:
  * Line 1: ``{"_metadata": true, "captured_at": "...", ...}`` with
    provenance fields the CI gate reads for the staleness check.
  * Lines 2..N: ``{"_id": "...", "_source": {...redacted rollup...}}``
    one per session rollup, sorted by @timestamp ascending.

Cadence (per the plan): refresh roughly quarterly. The CI gate warns
at >90d, hard-fails at >180d.

Run from the repo root via the production venv (the workstation venv
can also do it if it has ES creds):

    sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \\
      scripts/refresh_production_snapshot.py
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_eval_set import _redact_event  # type: ignore

from enrich.classification import explicit_public_filters
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

# Source fields the snapshot needs: the clustering inputs (embedding +
# scalars + session_id) mirrored from iter_session_docs, plus the two
# fields the F-phase small-cluster axis scores on — dominant_intent
# (3a intent purity) and command_signature (3b modal-signature share).
# A snapshot captured before these two were added degrades gracefully:
# eval_production_scale reports None on 3a/3b rather than a wrong zero.
_SNAPSHOT_SOURCE_FIELDS = [
    "dshield.cowrie.enrichment.session.embedding",
    "dshield.cowrie.enrichment.session.command_count",
    "dshield.cowrie.enrichment.session.unique_commands",
    "dshield.cowrie.enrichment.session.login_success_count",
    "dshield.cowrie.enrichment.session.login_fail_count",
    "dshield.cowrie.enrichment.session.mean_novelty_score",
    "dshield.cowrie.enrichment.session.dominant_intent",
    "dshield.cowrie.enrichment.session.command_signature",
    "cowrie.session_id",
]


_EMBEDDING_EXISTS = {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}}


def _iter_embedded_rollups(es, index: str, page_size: int, cfg):
    # Committed artifact — only explicit-public docs, regardless of the
    # configurable releasability posture (release-readiness P1-3; mirrors
    # capture_anchor_snapshot.py).
    body: dict = {
        "size": page_size,
        "_source": _SNAPSHOT_SOURCE_FIELDS,
        "query": {"bool": {
            "must": [_EMBEDDING_EXISTS],
            "filter": explicit_public_filters(cfg),
        }},
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


def _count_non_public_skipped(es, index: str, cfg) -> int:
    """How many embedded rollups were excluded by the public filter — an
    audit signal, not a gate input."""
    total = es.count(index=index, query=_EMBEDDING_EXISTS)["count"]
    public = es.count(index=index, query={"bool": {
        "must": [_EMBEDDING_EXISTS],
        "filter": explicit_public_filters(cfg),
    }})["count"]
    return max(0, total - public)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config-path", type=str, default=None)
    ap.add_argument("--output", type=Path,
                    default=Path("eval/production-snapshot-v1.jsonl.gz"),
                    help="Where to write the gzipped snapshot.")
    ap.add_argument("--page-size", type=int, default=1000,
                    help="ES search-after page size. Default matches the "
                         "production session iterator.")
    ap.add_argument("--label", type=str, default=None,
                    help="Optional short label written into the snapshot "
                         "metadata (e.g. quarter / refresh reason).")
    args = ap.parse_args()

    cfg = load_config(args.config_path)
    secrets = load_secrets(args.config_path)
    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup

    if not es.indices.exists(index=sessions_idx):
        raise SystemExit(
            f"Sessions rollup index '{sessions_idx}' not found. "
            f"Check elasticsearch.indexes.cowrie.sessions_rollup."
        )

    n_skipped_non_public = _count_non_public_skipped(es, sessions_idx, cfg)
    if n_skipped_non_public:
        print(
            f"skipping {n_skipped_non_public} embedded rollup(s) that are not "
            f"explicit-public (confidential or untagged) — committed snapshots "
            f"are public-only.",
            flush=True,
        )

    captured_at = datetime.now(UTC).isoformat()
    metadata = {
        "_metadata":        True,
        "captured_at":      captured_at,
        "sessions_index":   sessions_idx,
        "label":            args.label,
        "embedding_pipeline_at_capture": (
            f"embed_context={list(cfg.llm.embed_context)} "
            f"cooccurrence.embed_cooccurrence={cfg.cooccurrence.embed_cooccurrence}"
        ),
        "session_cluster_config_at_capture": {
            "min_cluster_size":    cfg.session.cluster_min_cluster_size,
            "min_samples":         cfg.session.cluster_min_samples,
            "scalar_weight":       cfg.session.cluster_scalar_weight,
            "playbook_merge_threshold": cfg.session.playbook_merge_threshold,
            "clustering_mode":     cfg.session.clustering_mode,
        },
        "redaction":        "build_eval_set._redact_event",
        # v2 adds dominant_intent + command_signature for the F-phase
        # small-cluster axis (3a/3b). v1 snapshots lack them and degrade.
        "schema_version":   2,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = args.output.with_suffix(args.output.suffix + ".tmp")
    n_written = 0
    n_seen = 0
    with gzip.open(tmp_out, "wt", encoding="utf-8") as f:
        f.write(json.dumps(metadata) + "\n")
        for doc_id, src in _iter_embedded_rollups(
            es, sessions_idx, args.page_size, cfg,
        ):
            n_seen += 1
            redacted = _redact_event(src)
            rec = {"_id": doc_id, "_source": redacted}
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
            n_written += 1
            if n_written % 1000 == 0:
                print(f"  wrote {n_written} rollups...", flush=True)
    if n_written == 0:
        tmp_out.unlink(missing_ok=True)
        raise SystemExit(
            "refusing to write an empty snapshot: 0 explicit-public embedded "
            "rollups found. Do NOT leave a committable empty snapshot — "
            "re-ingest sensors with dshield.classification tags first."
        )
    # Atomic swap so a partial dump can't be picked up by the gate.
    tmp_out.replace(args.output)
    size_mb = args.output.stat().st_size / (1024 * 1024)
    print(
        f"\nwrote {args.output} — {n_written} rollups, "
        f"{size_mb:.2f} MB gzipped, captured_at={captured_at}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
