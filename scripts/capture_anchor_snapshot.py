"""Capture a PUBLIC anchor snapshot for the offline prod-scale assignment eval
(`scripts/eval_assignment_prod.py`). The output is committed to VCS, so it must contain
ONLY public data.

The production `playbook_anchors.anchor_centroid` is pinned from MIXED-classification
sessions, so it cannot be committed. Instead this **recomputes** each playbook's centroid
from its **public** sessions only (`releasable_filter` — fail-safe: explicit
`dshield.classification: public`), so every vector in the snapshot is public-derived.
There is deliberately NO `--allow-unclassified`: a committed artifact is public or it does
not exist.

On the current untagged corpus the public filter returns 0, so the snapshot is **empty** —
that is the correct, safe outcome. Re-ingest sensors with `dshield.classification` tags
first, then re-capture. One gzipped-JSONL line per playbook:
`{playbook_id, anchor_centroid, n_public_sessions}`.

    console/.venv/bin/python scripts/capture_anchor_snapshot.py \
        --out eval/anchor-snapshot-v1.jsonl.gz
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_PB = f"{_S}.playbook_id"
_EMB = f"{_S}.embedding"


def centroid(embs: list[list[float]]) -> list[float]:
    """L2-normalised mean of the (public) session embeddings — the public-derived anchor."""
    import numpy as np
    m = np.asarray(embs, dtype=np.float32).mean(axis=0)
    n = float(np.linalg.norm(m))
    return (m / n).tolist() if n > 0 else m.tolist()


def _public_playbook_ids(es, idx, filt, size) -> list[tuple[str, int]]:
    r = es.search(index=idx, size=0, query={"bool": {"filter": filt}},
                  aggs={"pb": {"terms": {"field": _PB, "size": size}}})
    return [(b["key"], b["doc_count"]) for b in r["aggregations"]["pb"]["buckets"]]


def _sample_embeddings(es, idx, filt, pb, n):
    r = es.search(index=idx, size=min(n, 10000), _source=[_EMB],
                  query={"bool": {"filter": filt + [{"term": {_PB: pb}}]}})
    out = []
    for h in r["hits"]["hits"]:
        s = (((h["_source"].get("dshield") or {}).get("cowrie") or {})
             .get("enrichment", {}).get("session", {}))
        if s.get("embedding"):
            out.append(s["embedding"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--out", default="eval/anchor-snapshot-v1.jsonl.gz")
    ap.add_argument("--per-anchor", type=int, default=500, help="public sessions averaged per playbook")
    ap.add_argument("--min-public", type=int, default=5, help="skip playbooks with fewer public sessions")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    # PUBLIC ONLY — committed to VCS. No override.
    filt = [releasable_filter(cfg), {"exists": {"field": _EMB}}]

    pbs = _public_playbook_ids(es, idx, filt, size=5000)
    rows: list[str] = []
    for pb, count in pbs:
        if not pb or count < args.min_public:
            continue
        embs = _sample_embeddings(es, idx, filt, pb, args.per_anchor)
        if len(embs) < args.min_public:
            continue
        rows.append(json.dumps({"playbook_id": pb, "anchor_centroid": centroid(embs),
                                "n_public_sessions": len(embs)}))

    if not rows:
        # Do NOT leave a committable empty snapshot — there's no public data to capture.
        print("0 public playbooks — the corpus has no `dshield.classification:public` "
              "sessions yet. Retro-tag your public sensor with "
              "scripts/backfill_classification.py, then re-capture. No snapshot written.",
              file=sys.stderr)
        return 0
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, "wt") as fh:
        fh.write("\n".join(rows) + "\n")
    print(f"wrote {len(rows)} public-derived anchors → {out}")
    print("Next: baseline + commit — `python scripts/eval_assignment_prod.py --write-baseline`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
