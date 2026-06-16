"""Health check for HDBSCAN outliers across the three clustering layers.

For each layer (commands, sessions, IPs):
  - Total docs + outlier count + % of clustered docs
  - Recent `run_summary` history (clusters / outliers / rescued)
  - For each outlier carrying an embedding: max cosine to the nearest
    centroid in the latest run, with a histogram and the would-be-rescue
    count at each candidate threshold

Tracks the "noise rescue for command + IP layers" open audit item in
[ROADMAP.md](../docs/roadmap.md). When that ships, the would-be-rescue
counts for those two layers should drop to single digits — this script
is the metric to confirm it.

Read-only. Always exits 0. Run from the repo root via the console venv:
    console/.venv/bin/python scripts/diagnose_outlier_health.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np  # noqa: E402

from enrich.config import load_config, load_secrets  # noqa: E402
from enrich.es_client import make_client  # noqa: E402


def _latest_run_id(es, idx: str) -> str:
    if not es.indices.exists(index=idx):
        return ""
    r = es.search(
        index=idx, size=1,
        query={"term": {"doc_type": "cluster"}},
        sort=[{"@timestamp": "desc"}],
        _source=["run_id"],
    )
    hits = r["hits"]["hits"]
    return hits[0]["_source"]["run_id"] if hits else ""


def _centroids(es, cluster_idx: str, run_id: str) -> np.ndarray:
    r = es.search(
        index=cluster_idx, size=1000,
        query={"bool": {"must": [
            {"term": {"doc_type": "cluster"}},
            {"term": {"run_id": run_id}},
        ]}},
        _source=["centroid"],
    )
    rows = [h["_source"]["centroid"] for h in r["hits"]["hits"]
            if h["_source"].get("centroid")]
    if not rows:
        return np.empty((0, 0), dtype=np.float32)
    M = np.array(rows, dtype=np.float32)
    norms = np.linalg.norm(M, axis=1, keepdims=True)
    norms = np.where(norms == 0.0, 1.0, norms)
    return M / norms


def _scan_outlier_embs(es, docs_idx: str, cluster_field: str, emb_field: str,
                       page_size: int = 500):
    body = {
        "size": page_size,
        "_source": [emb_field],
        "query": {"bool": {"must": [
            {"term": {cluster_field: "outlier"}},
            {"exists": {"field": emb_field}},
        ]}},
        "sort": [{"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        r = es.search(index=docs_idx, **body)
        hits = r["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            for k in emb_field.split("."):
                src = (src or {}).get(k)
                if src is None:
                    break
            if src:
                yield np.array(src, dtype=np.float32)
        search_after = hits[-1]["sort"]


def _print_run_history(es, cluster_idx: str, label: str, n: int = 5) -> None:
    if not es.indices.exists(index=cluster_idx):
        return
    r = es.search(
        index=cluster_idx, size=n,
        query={"term": {"doc_type": "run_summary"}},
        sort=[{"@timestamp": "desc"}],
        _source=["@timestamp", "total_docs", "n_clusters", "n_outliers",
                 "n_rescued", "runtime_seconds"],
    )
    if not r["hits"]["hits"]:
        return
    print(f"  recent {label} run_summary:")
    for h in r["hits"]["hits"]:
        s = h["_source"]
        rescued = s.get("n_rescued")
        rescued_part = f" rescued={rescued}" if rescued is not None else ""
        print(f"    {s.get('@timestamp')}  total={s.get('total_docs')}  "
              f"clusters={s.get('n_clusters')}  outliers={s.get('n_outliers')}"
              f"{rescued_part}  rt={s.get('runtime_seconds')}s")


def _audit_outliers(es, label: str, docs_idx: str, cluster_idx: str,
                    cluster_field: str, emb_field: str) -> None:
    print("=" * 64)
    print(label)
    print("=" * 64)

    total = es.count(index=docs_idx)["count"]
    outliers = es.count(
        index=docs_idx,
        query={"term": {cluster_field: "outlier"}},
    )["count"]
    pct = (100.0 * outliers / total) if total else 0.0
    print(f"  total docs:  {total}")
    print(f"  outliers:    {outliers}  ({pct:.1f}% of total)")

    # Sessions sometimes write partial docs (no embedding); print that too.
    if label.startswith("SESSIONS"):
        with_emb = es.count(
            index=docs_idx,
            query={"exists": {"field": emb_field}},
        )["count"]
        pct_emb = (100.0 * outliers / with_emb) if with_emb else 0.0
        print(f"  with embedding: {with_emb}  ({pct_emb:.1f}% of these are outliers)")

    print()
    _print_run_history(es, cluster_idx, label.lower())
    print()

    run_id = _latest_run_id(es, cluster_idx)
    if not run_id:
        print("  no cluster run yet — nothing to score against.")
        print()
        return
    C = _centroids(es, cluster_idx, run_id)
    if C.size == 0:
        print(f"  cluster run {run_id} has no centroids — skip.")
        print()
        return

    sims: list[float] = []
    for emb in _scan_outlier_embs(es, docs_idx, cluster_field, emb_field):
        e = emb / (np.linalg.norm(emb) + 1e-12)
        sims.append(float((e @ C.T).max()))
    if not sims:
        print("  no outliers carry an embedding — nothing to score.")
        print()
        return

    arr = np.array(sims)
    print(f"  outliers w/ embedding:   {len(sims)}")
    print("  max-cosine-to-nearest-centroid:")
    print(f"    median: {float(np.median(arr)):.4f}   p25: {float(np.percentile(arr,25)):.4f}"
          f"   p75: {float(np.percentile(arr,75)):.4f}   p90: {float(np.percentile(arr,90)):.4f}"
          f"   max: {float(arr.max()):.4f}")
    print()
    print("  histogram of max-cosine-to-nearest-centroid:")
    bands = [0.0, 0.5, 0.7, 0.8, 0.85, 0.90, 0.92, 0.94, 0.96, 0.98, 1.0001]
    for lo, hi in zip(bands[:-1], bands[1:]):
        c = int(((arr >= lo) & (arr < hi)).sum())
        bar = "#" * min(60, c)
        print(f"    [{lo:.2f}, {hi:.2f}):  {c:5d}  {bar}")
    print()
    print("  would-be-rescue count at threshold τ "
          "(if `rescue_threshold` were enabled for this layer):")
    for tau in (0.85, 0.90, 0.92, 0.94, 0.96):
        n = int((arr >= tau).sum())
        pctw = (100.0 * n / len(arr)) if len(arr) else 0.0
        print(f"    τ={tau:.2f}:  {n:5d}  ({pctw:.1f}% of outliers w/ embedding)")
    print()


def main() -> int:
    cfg = load_config()
    secrets = load_secrets()
    es = make_client(cfg.elasticsearch, secrets)
    idxs = cfg.elasticsearch.indexes.cowrie

    _audit_outliers(
        es, "COMMANDS",
        idxs.commands, idxs.command_clusters,
        cluster_field="dshield.cowrie.enrichment.cluster.id",
        emb_field="dshield.cowrie.enrichment.embedding",
    )
    _audit_outliers(
        es, "SESSIONS",
        idxs.sessions_rollup, idxs.session_clusters,
        cluster_field="dshield.cowrie.enrichment.session.cluster.id",
        emb_field="dshield.cowrie.enrichment.session.embedding",
    )
    _audit_outliers(
        es, "IPs",
        idxs.ips_rollup, idxs.ip_clusters,
        cluster_field="dshield.cowrie.enrichment.ip.cluster.id",
        emb_field="dshield.cowrie.enrichment.ip.embedding",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
