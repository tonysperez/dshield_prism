"""Sweep TruncatedSVD dimensionality for the session-layer HDBSCAN.

HDBSCAN's nearest-neighbour phase degrades to ~O(n^2) on 768-d euclidean
embeddings (spatial trees collapse in high dimensions), so a full-corpus
`cluster sessions --window-days 0` run (`pipeline --backfill` and the weekly
`dshield_prism-recluster-full` timer) takes HOURS at hundreds-of-thousands
scale. Reducing the embedding to a few dozen dimensions first makes it
tractable — but it can over-merge clusters separated only in the discarded
directions. This sweep quantifies the trade-off: at each SVD dim it reports the
same shape the `prod-scale` gate cares about (clusters / purity / outlier rate),
plus variance retained and HDBSCAN wall-clock, so you can pick the lowest dim
that still holds quality on YOUR corpus before trusting `session.cluster_svd_dim`.

This is the session-layer sibling of `scripts/sweep_command_svd.py`. The SVD is
fit-only: production reduces the embedding for the HDBSCAN label assignment ONLY
— noise rescue, persisted centroids, novelty, and the cross-run reference all
stay full-dim — so this sweep mirrors that (rescue runs in full-dim space).

`dim=0` is the full-dim (legacy) baseline; compare the rest to it.

Data source:
  --snapshot PATH    committed labeled session snapshot (default; repo data,
                     no ES). NOTE: ~4k sessions — good for the QUALITY delta,
                     too small to show the wall-clock win. Use --live at scale.
  --live --limit N   first-N session rollups (index order) from live ES — run
                     this on the OPERATOR's box at real scale: it reads the
                     operator's own corpus, and the output is metrics only (no
                     session content), so it's safe to share back.

Usage:
  console/.venv/bin/python scripts/sweep_session_svd.py
  console/.venv/bin/python scripts/sweep_session_svd.py --dims 0,64,96,128,192
  console/.venv/bin/python scripts/sweep_session_svd.py --live --limit 60000
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
from enrich.sources.cowrie.sessions import build_session_scalar_block


def _parse_session(src: dict):
    """(embedding, scalars, dominant_intent) from a session rollup _source.

    Mirrors `eval_production_scale._iter_rollup_source` so the sweep sees the
    same four clustering scalars production does. Returns (None, {}, None) when
    the rollup carries no embedding (the `iter_session_docs` filter)."""
    s = (
        ((src.get("dshield") or {}).get("cowrie") or {})
        .get("enrichment", {})
        .get("session", {})
    )
    emb = s.get("embedding")
    if not emb:
        return None, {}, None
    success = s.get("login_success_count") or 0
    fail = s.get("login_fail_count") or 0
    total = success + fail
    scalars = {
        "command_count":      s.get("command_count") or 1,
        "unique_commands":    s.get("unique_commands") or 1,
        "login_success_rate": success / total if total > 0 else 0.0,
        "mean_novelty_score": s.get("mean_novelty_score") or 0.0,
    }
    return emb, scalars, s.get("dominant_intent")


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
            emb, sc, intent = _parse_session(rec.get("_source") or {})
            if emb is not None:
                embs.append(emb)
                scalars.append(sc)
                intents.append(intent)
    return embs, scalars, intents


def _load_live(cfg, secrets, limit: int):
    es = make_client(cfg.elasticsearch, secrets)
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    base = "dshield.cowrie.enrichment.session"
    embs, scalars, intents = [], [], []
    body = {
        "size": min(limit, cfg.session.page_size),
        "_source": [
            f"{base}.embedding", f"{base}.command_count", f"{base}.unique_commands",
            f"{base}.login_success_count", f"{base}.login_fail_count",
            f"{base}.mean_novelty_score", f"{base}.dominant_intent",
        ],
        "query": {"exists": {"field": f"{base}.embedding"}},
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
            emb, sc, intent = _parse_session(h["_source"])
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
    ap.add_argument("--snapshot", default="eval/production-snapshot-v1.jsonl.gz")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--limit", type=int, default=60000)
    ap.add_argument("--dims", default="0,64,96,128,192")
    ap.add_argument("--config", default="config/default.yaml")
    args = ap.parse_args()

    cfg = load_config(args.config)
    scfg = cfg.session
    dims = [int(d) for d in args.dims.split(",") if d.strip()]

    if args.live:
        print(f"loading up to {args.limit} live sessions (index order)...")
        embs, scalars, intents = _load_live(cfg, load_secrets(args.config), args.limit)
    else:
        print(f"loading snapshot {args.snapshot}...")
        embs, scalars, intents = _load_snapshot(Path(args.snapshot))

    n = len(embs)
    print(f"loaded {n} sessions; ambient dim={len(embs[0]) if n else 0}")
    print(f"config: mcs={scfg.cluster_min_cluster_size} ms={scfg.cluster_min_samples} "
          f"scalar_weight={scfg.cluster_scalar_weight} "
          f"rescue={scfg.playbook_merge_threshold} "
          f"n_jobs={cfg.worker.cluster_n_jobs}\n")

    normalized = l2_normalize(np.array(embs, dtype=np.float32))
    block = (build_session_scalar_block(scalars, scfg.cluster_scalar_weight)
             if scfg.cluster_scalar_weight > 0.0 else None)

    print(f"{'dim':>5} {'expl.var':>9} {'clusters':>9} {'purity':>8} "
          f"{'outlier%':>9} {'rescued':>8} {'fit_s':>8}")
    print("-" * 62)
    rows = []
    for dim in dims:
        reduced, explained = svd_reduce(normalized, dim)
        matrix = np.hstack([reduced, block]) if block is not None else reduced
        t0 = time.time()
        labels = HDBSCAN(
            min_cluster_size=scfg.cluster_min_cluster_size,
            min_samples=scfg.cluster_min_samples,
            metric="euclidean",
            n_jobs=cfg.worker.cluster_n_jobs,
        ).fit_predict(matrix)
        # Rescue in FULL-dim pure-embedding space, exactly as production does
        # (run_layer_clustering rescues against `normalized`, never the reduced
        # fit space). 1.0 disables, matching `playbook_merge_threshold` semantics.
        n_rescued = 0
        if scfg.playbook_merge_threshold and scfg.playbook_merge_threshold <= 1.0:
            labels, n_rescued = rescue_noise_points(
                normalized, labels, scfg.playbook_merge_threshold,
            )
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
