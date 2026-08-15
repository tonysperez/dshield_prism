"""Sweep TruncatedSVD dimensionality for the command-layer HDBSCAN.

HDBSCAN's nearest-neighbour phase degrades to ~O(n²) on 768-d euclidean
embeddings (spatial trees collapse in high dimensions), so `cluster commands`
takes hours at hundreds-of-thousands scale. Reducing the embedding to a few
dozen dimensions first makes it tractable — but it can over-merge clusters
separated only in the discarded directions. This sweep quantifies the
trade-off: at each SVD dim it reports the SAME metrics the `command-scale`
gate uses, plus the variance retained and the HDBSCAN wall-clock.

`dim=0` is the full-dim (current production) baseline; compare the rest to it.

Data source:
  --snapshot PATH    committed labeled snapshot (default; repo data, no ES)
  --live --limit N   first-N commands (index order) from live ES — run this on
                     the OPERATOR's box: it reads the operator's own corpus, and
                     the output is metrics only (no command content), so it's
                     safe to share back.

Usage:
  console/.venv/bin/python scripts/sweep_command_svd.py
  console/.venv/bin/python scripts/sweep_command_svd.py --dims 0,64,96,128,192
  console/.venv/bin/python scripts/sweep_command_svd.py --live --limit 40000
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.cluster import HDBSCAN

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.clustering import (
    l2_normalize,
    rescue_noise_points,
    svd_reduce,
)
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.commands import build_command_scalar_block

_BASE = "dshield.cowrie.enrichment"


def _scalars_from_source(src: dict):
    en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment", {})
    emb = en.get("embedding")
    if not emb:
        return None, {}, None
    occ = en.get("occurrence_count") or 1
    scalars = {
        "occurrence_count":   occ,
        "unique_sessions":    en.get("unique_sessions") or 1,
        "unique_source_ips":  en.get("unique_source_ips") or 1,
        "confidence":         en.get("confidence") or 5,
        "session_reuse_rate": min((en.get("unique_sessions") or 1) / occ, 1.0),
    }
    return emb, scalars, en.get("intent")


def _load_snapshot(path: Path):
    embs, scalars, intents = [], [], []
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if i == 0 and rec.get("_metadata"):
                continue
            emb, sc, intent = _scalars_from_source(rec.get("_source") or {})
            if emb is not None:
                embs.append(emb)
                scalars.append(sc)
                intents.append(intent)
    return embs, scalars, intents


def _load_live(cfg, secrets, limit: int):
    es = make_client(cfg.elasticsearch, secrets)
    idx = cfg.elasticsearch.indexes.cowrie.commands
    embs, scalars, intents = [], [], []
    body = {
        "size": min(limit, cfg.command_cluster.page_size),
        "_source": [f"{_BASE}.embedding", f"{_BASE}.occurrence_count",
                    f"{_BASE}.unique_sessions", f"{_BASE}.unique_source_ips",
                    f"{_BASE}.confidence", f"{_BASE}.intent"],
        "query": {"exists": {"field": f"{_BASE}.embedding"}},
        "sort": [{"_doc": "asc"}],  # index order — a cross-section, not time-biased
    }
    sa = None
    while len(embs) < limit:
        if sa:
            body["search_after"] = sa
        r = es.search(index=idx, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            emb, sc, intent = _scalars_from_source(h["_source"])
            if emb is not None:
                embs.append(emb)
                scalars.append(sc)
                intents.append(intent)
                if len(embs) >= limit:
                    break
        sa = hits[-1]["sort"]
    return embs, scalars, intents


def _metrics(labels, intents, n_rescued):
    n = len(labels)
    n_outliers = int((labels == -1).sum())
    n_clusters = len({int(c) for c in labels if c >= 0})
    byc: dict = defaultdict(list)
    for lbl, it in zip(labels, intents, strict=False):
        if lbl >= 0:
            byc[int(lbl)].append(it or "")
    purities = []
    for members in byc.values():
        named = [m for m in members if m]
        if named:
            purities.append(Counter(named).most_common(1)[0][1] / len(named))
    purity = round(sum(purities) / len(purities), 4) if purities else None
    return {
        "outlier_rate": round(n_outliers / n, 4) if n else 0.0,
        "n_rescued": n_rescued,
        "n_clusters": n_clusters,
        "purity": purity,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", default="eval/command-snapshot-v1.jsonl.gz")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--limit", type=int, default=40000)
    ap.add_argument("--dims", default="0,50,100,150,200")
    ap.add_argument("--config", default="config/default.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    ccfg = cfg.command_cluster
    dims = [int(d) for d in args.dims.split(",") if d.strip()]

    if args.live:
        print(f"loading up to {args.limit} live commands (index order)...")
        embs, scalars, intents = _load_live(cfg, load_secrets(args.config), args.limit)
    else:
        print(f"loading snapshot {args.snapshot}...")
        embs, scalars, intents = _load_snapshot(Path(args.snapshot))

    n = len(embs)
    print(f"loaded {n} commands; ambient dim={len(embs[0]) if n else 0}")
    print(f"config: mcs={ccfg.min_cluster_size} ms={ccfg.min_samples} "
          f"scalar_weight={ccfg.scalar_weight} rescue={ccfg.rescue_threshold} "
          f"n_jobs={cfg.worker.cluster_n_jobs}\n")

    normalized = l2_normalize(np.array(embs, dtype=np.float32))
    block = (build_command_scalar_block(scalars, ccfg.scalar_weight)
             if ccfg.scalar_weight > 0.0 else None)

    print(f"{'dim':>5} {'expl.var':>9} {'clusters':>9} {'purity':>8} "
          f"{'outlier%':>9} {'rescued':>8} {'fit_s':>8}")
    print("-" * 62)
    rows = []
    for dim in dims:
        reduced, explained = svd_reduce(normalized, dim)
        matrix = np.hstack([reduced, block]) if block is not None else reduced
        t0 = time.time()
        labels = HDBSCAN(
            min_cluster_size=ccfg.min_cluster_size,
            min_samples=ccfg.min_samples,
            metric="euclidean",
            n_jobs=cfg.worker.cluster_n_jobs,
        ).fit_predict(matrix)
        n_rescued = 0
        if ccfg.rescue_threshold and ccfg.rescue_threshold > 0.0:
            labels, n_rescued = rescue_noise_points(reduced, labels, ccfg.rescue_threshold)
        dt = time.time() - t0
        m = _metrics(labels, intents, n_rescued)
        rows.append((dim, explained, m, dt))
        label = "full" if dim <= 0 or dim >= normalized.shape[1] else str(dim)
        print(f"{label:>5} {explained:>9.4f} {m['n_clusters']:>9} "
              f"{(m['purity'] or 0):>8.4f} {m['outlier_rate'] * 100:>8.2f}% "
              f"{m['n_rescued']:>8} {dt:>8.2f}")

    base = next((r for r in rows if r[0] <= 0), rows[0])
    bp = base[2]["purity"] or 0
    print("\nvs full-dim baseline:")
    for dim, _expl, m, dt in rows:
        if dim <= 0:
            continue
        dp = (m["purity"] or 0) - bp
        speed = base[3] / dt if dt else float("inf")
        print(f"  dim={dim:<4} purity {dp:+.4f}  clusters {m['n_clusters'] - base[2]['n_clusters']:+d}"
              f"  speed {speed:.1f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
