"""F3.1 — late-fusion sweep at PRODUCTION scale on the 7 binding metrics.

The user observed informally that the E4.4 late fusion "clustered better"
qualitatively — pulled out small distinct clusters HDBSCAN suppressed.
E4.4 was reverted on ARI grounds with no way to credit the qualitative
win. This re-measures it at production scale under the F-phase
multi-objective metric set (F0), including the 3b shard fraction +
density-redundancy decomposition.

Mechanism (same as scripts/sweep_late_fusion.py, scaled up):
  1. Base clusterer A: production HDBSCAN over embedding + scalar block.
  2. Base clusterer B: HDBSCAN over a TF-IDF + truncated-SVD lexical
     block, min_cluster_size = ``lex_mcs``.
  3. Pair-disagreement distance: ``d(i,j) = (2 - agree)/2`` where
     ``agree`` counts how many of the two base clusterers put i,j in the
     same non-noise cluster. Vectorized (the eval-scale double loop does
     not scale to ~4000 sessions).
  4. ``AgglomerativeClustering(n_clusters=k, metric='precomputed',
     linkage=...)`` at each ``n_clusters`` — forces exactly k clusters,
     matching the eval-scale ``scripts/sweep_late_fusion.py``. (A
     ``fcluster(maxclust)`` cut collapses to 1 cluster on this matrix's
     3-valued {0, 0.5, 1.0} ties, so it is not used.)

Caveat the reader must keep in mind: agglomerative output has **no noise
label**, so ``outlier_rate`` is structurally 0 for every fusion config —
metric 1 is trivially "met" and is not informative here. The deciding
measurements are 3b (shard fraction) + the density-redundancy split +
the ARI floor, exactly as the F3 phase doc says.

Read-only. Run from the repo root via the console venv:
    console/.venv/bin/python scripts/sweep_late_fusion_prod.py
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eval_production_scale import _load_eval_session_ids_and_labels
from prod_corpus import normalized_embeddings, pull_session_corpus, score_full

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.sessions import build_session_scalar_block

# Plan F3.1 grid. lex_mcs is the lexical HDBSCAN min_cluster_size. The
# distance matrix is built once per lex_mcs; AgglomerativeClustering then
# forces exactly k clusters at each n_clusters. "auto" = the embedding
# base's cluster count. Higher n_clusters is the interesting region (the
# fusion's whole pitch is "more small clusters"), so the grid leans high.
_LEX_MCS = (5, 15, 25)
_N_CLUSTERS = ("auto", 40, 60, 93)


def _cluster_embedding(corpus, cfg) -> np.ndarray:
    from sklearn.cluster import HDBSCAN
    normalized = normalized_embeddings(corpus)
    if cfg.session.cluster_scalar_weight > 0.0:
        block = build_session_scalar_block(corpus.scalars, cfg.session.cluster_scalar_weight)
        matrix = np.hstack([normalized, block])
    else:
        matrix = normalized
    return HDBSCAN(
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        metric="euclidean",
    ).fit_predict(matrix)


def _cluster_lexical(corpus, lex_mcs: int, svd_dim: int) -> np.ndarray:
    from sklearn.cluster import HDBSCAN
    from sklearn.decomposition import TruncatedSVD
    from sklearn.feature_extraction.text import TfidfVectorizer
    vec = TfidfVectorizer(max_features=5000, ngram_range=(1, 2),
                          sublinear_tf=True, norm="l2")
    tfidf = vec.fit_transform(corpus.texts)
    n_comp = min(svd_dim, tfidf.shape[1], tfidf.shape[0] - 1)
    reduced = TruncatedSVD(n_components=n_comp, random_state=20260601) \
        .fit_transform(tfidf).astype(np.float32)
    return HDBSCAN(min_cluster_size=lex_mcs, min_samples=1,
                   metric="euclidean").fit_predict(reduced)


def _disagreement_full(labels_emb: np.ndarray, labels_lex: np.ndarray) -> np.ndarray:
    """Vectorized pair-disagreement distance, full n×n (for
    AgglomerativeClustering(metric='precomputed'))."""
    e = labels_emb
    x = labels_lex
    emb_eq = (e[:, None] == e[None, :]) & (e[:, None] != -1)
    lex_eq = (x[:, None] == x[None, :]) & (x[:, None] != -1)
    agreement = emb_eq.astype(np.int8) + lex_eq.astype(np.int8)  # 0,1,2
    dist = (2 - agreement).astype(np.float64) / 2.0
    np.fill_diagonal(dist, 0.0)
    return dist


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--svd-dim", type=int, default=100)
    ap.add_argument("--linkage", default="average",
                    choices=["average", "complete", "single"])
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    args = ap.parse_args()

    from sklearn.cluster import AgglomerativeClustering

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)
    index = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    print(f"pulling corpus from {index} ...", flush=True)
    corpus = pull_session_corpus(es, index, cfg.session.page_size)
    print(f"  {len(corpus)} sessions", flush=True)
    sid_to_label, pair_to_sessions = _load_eval_session_ids_and_labels(
        Path("eval/labels.yaml"), Path("eval/labels-v2.yaml"),
    )
    merge_threshold = cfg.session.playbook_merge_threshold

    print("base clusterer: embedding HDBSCAN ...", flush=True)
    labels_emb = _cluster_embedding(corpus, cfg)
    n_emb = len({int(c) for c in labels_emb if c >= 0})
    print(f"  embedding base: {n_emb} clusters", flush=True)

    rows: list[dict] = []
    for lex_mcs in _LEX_MCS:
        print(f"lexical HDBSCAN (lex_mcs={lex_mcs}) ...", flush=True)
        labels_lex = _cluster_lexical(corpus, lex_mcs, args.svd_dim)
        n_lex = len({int(c) for c in labels_lex if c >= 0})
        print(f"  lexical base: {n_lex} clusters; building distance matrix ...",
              flush=True)
        dist = _disagreement_full(labels_emb, labels_lex)
        for nc in _N_CLUSTERS:
            k = n_emb if nc == "auto" else int(nc)
            fused = AgglomerativeClustering(
                n_clusters=k, metric="precomputed", linkage=args.linkage,
            ).fit_predict(dist)
            scored = score_full(
                fused, corpus, sid_to_label, pair_to_sessions,
                merge_threshold=merge_threshold,
            )
            scored.update({"lex_mcs": lex_mcs, "n_clusters_req": nc,
                           "n_lex_base": n_lex})
            rows.append(scored)
            m = scored["metrics"]
            print(f"  n_clusters={nc:>4} → ari={m['ari']} "
                  f"n_small={m['n_small_clusters']} "
                  f"distinct={m['n_small_clusters_distinct']} "
                  f"shard={m['small_cluster_shard_fraction']} "
                  f"near_large={m['small_cluster_near_large_fraction']}", flush=True)

    md = _render(rows, len(corpus), n_emb, args.linkage)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"late-fusion-prod-sweep-{ts}.md"
    json_path = args.output_dir / f"late-fusion-prod-sweep-{ts}.json"
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps({
        "generated_at": datetime.now(UTC).isoformat(),
        "n_sessions": len(corpus), "linkage": args.linkage,
        "svd_dim": args.svd_dim, "emb_base_clusters": n_emb, "rows": rows,
    }, indent=2), encoding="utf-8")
    print("\n" + md)
    print(f"\nwrote {md_path}\nwrote {json_path}")
    return 0


def _render(rows: list[dict], n_sessions: int, n_emb: int, linkage: str) -> str:
    out: list[str] = []
    out.append("# F3.1 — late-fusion sweep (production scale)")
    out.append("")
    out.append(f"_Captured {datetime.now(UTC).isoformat()}_")
    out.append("")
    out.append(f"{n_sessions} sessions · embedding base {n_emb} clusters · "
               f"linkage={linkage}. ARI / completeness / homogeneity / dpr "
               "score the labeled eval subset; the small-cluster axis is "
               "corpus-wide. **outlier_rate is structurally 0** (agglomerative "
               "has no noise label) — ignore it here. `distinct` = small "
               "clusters with centroid cos < merge_threshold to every big "
               "playbook (the genuine surfacing yield); `near_lg` = density-"
               "fragment fraction.")
    out.append("")
    headers = ["lex_mcs", "n_clusters", "clusters", "ari", "cmp", "hom",
               "dpr", "n_small", "distinct", "purity", "shard", "near_lg",
               "lbl_in_S"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---:"] * len(headers)) + "|")
    for r in rows:
        m = r["metrics"]
        def _f(key, m=m):
            v = m.get(key)
            return "—" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))
        cells = [
            str(r["lex_mcs"]), str(r["n_clusters_req"]),
            str(r["n_clusters_total"]),
            _f("ari"), _f("completeness"), _f("homogeneity"),
            _f("divergent_pair_resolution_rate"),
            str(m.get("n_small_clusters")), str(m.get("n_small_clusters_distinct")),
            _f("small_cluster_purity"), _f("small_cluster_shard_fraction"),
            _f("small_cluster_near_large_fraction"), str(r["labeled_in_small"]),
        ]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
