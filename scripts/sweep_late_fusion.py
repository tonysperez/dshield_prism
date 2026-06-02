"""E4.4 — late-fusion variant (contingent on E4.2 null).

E4.2's concat sweep produced no winner: the lexical block is either
absorbed (low weight) or overrides the better embedding signal (high
weight). Per plan, the contingent next test is *late fusion* — combine
the two clusterers' decisions rather than their features.

Strategy:

  1. Cluster sessions on the production embedding alone (production
     HDBSCAN config). Call the assignment ``labels_emb``.
  2. Cluster sessions on the TF-IDF + truncated-SVD lexical block
     alone (no embedding, no scalar augment). Call this ``labels_lex``.
  3. Build a per-pair agreement matrix:
        A[i, j] = 2  if labels_emb[i]==labels_emb[j] AND
                       labels_lex[i]==labels_lex[j]
                = 1  if exactly one clusterer agrees on the pair
                = 0  if both disagree
        D[i, j] = (2 - A[i, j]) / 2  (distance, range [0, 1])
     HDBSCAN noise (-1) is treated as "not in any cluster" — pairs
     involving a noise session never satisfy the "same cluster"
     predicate on the side that produced the -1.
  4. Re-cluster sessions via sklearn's AgglomerativeClustering with
     ``metric='precomputed'`` on D, sweeping ``n_clusters`` ∈ a small
     set around the analyst label count.

The plan says "agglomerative on disagreement distance" without nailing
``n_clusters`` — this sweep walks a small range so the table shows
whether late fusion has any sweet spot vs the embedding-only baseline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_late_fusion.py
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.cluster import AgglomerativeClustering, HDBSCAN
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.clustering import l2_normalize
from enrich.config import load_config
from enrich.sources.cowrie.sessions import build_session_scalar_block

from eval_clustering import (  # type: ignore
    _divergent_pair_metrics,
    _extract_session_features,
    _extract_session_text,
    _load_labels,
    _per_label_breakdown,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


@dataclass
class Session:
    session_id: str
    label:      str
    embedding:  list[float]
    scalars:    dict
    text:       str
    is_v2:      bool


def _ingest(
    v1_labels: dict, v2_labels: dict,
    v1_jsonl: Path, v2_jsonl: Path,
) -> list[Session]:
    label_blocks = {**v1_labels, **v2_labels}
    seen_sids: set[str] = set()
    out: list[Session] = []
    def _ingest_one(rec: dict, is_v2: bool) -> None:
        sid = rec.get("session_id")
        if not isinstance(sid, str) or sid in seen_sids:
            return
        if sid not in label_blocks:
            return
        feats = _extract_session_features(rec)
        if feats is None:
            return
        emb, sc = feats
        text = _extract_session_text(rec)
        if text is None:
            return
        seen_sids.add(sid)
        out.append(Session(
            session_id=sid,
            label=label_blocks[sid]["playbook_label"],
            embedding=emb, scalars=sc, text=text,
            is_v2=is_v2 or sid in v2_labels,
        ))
    for jl, v2 in ((v1_jsonl, False), (v2_jsonl, True)):
        if jl is not None and jl.exists():
            for rec in _iter_jsonl(jl):
                _ingest_one(rec, is_v2=v2)
    return out


# ---------------------------------------------------------------------------
# Two base clusterers + late-fusion distance matrix
# ---------------------------------------------------------------------------

def _cluster_embedding(sessions: list[Session], cfg) -> np.ndarray:
    """Production-equivalent: embedding + scalar block, HDBSCAN with
    production hyperparams."""
    embs = np.array([s.embedding for s in sessions], dtype=np.float32)
    normalized = l2_normalize(embs)
    if cfg.session.cluster_scalar_weight > 0.0:
        block = build_session_scalar_block(
            [s.scalars for s in sessions], cfg.session.cluster_scalar_weight,
        )
        cluster_matrix = np.hstack([normalized, block])
    else:
        cluster_matrix = normalized
    return HDBSCAN(
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        metric="euclidean",
    ).fit_predict(cluster_matrix)


def _cluster_lexical(sessions: list[Session], svd_dim: int, cfg) -> np.ndarray:
    """TF-IDF + SVD only — no embedding, no scalar augment. Mirrors the
    E0.2 ablation's setup but with HDBSCAN (same density-based math the
    production clusterer uses, just on a different feature set)."""
    vectorizer = TfidfVectorizer(
        max_features=5000, ngram_range=(1, 2),
        sublinear_tf=True, norm="l2",
    )
    tfidf = vectorizer.fit_transform(s.text for s in sessions)
    n_components = min(svd_dim, tfidf.shape[1], tfidf.shape[0] - 1)
    svd = TruncatedSVD(n_components=n_components, random_state=20260601)
    reduced = svd.fit_transform(tfidf).astype(np.float32)
    return HDBSCAN(
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        metric="euclidean",
    ).fit_predict(reduced)


def _disagreement_distance(
    labels_emb: np.ndarray, labels_lex: np.ndarray,
) -> np.ndarray:
    """Build the n×n pair-disagreement distance matrix.

    For each pair (i, j):
      * agree_emb = labels_emb[i] == labels_emb[j] and labels_emb[i] != -1
      * agree_lex = labels_lex[i] == labels_lex[j] and labels_lex[i] != -1
      * agreement = int(agree_emb) + int(agree_lex)   (0, 1, or 2)
      * distance  = (2 - agreement) / 2               (range [0, 1])

    HDBSCAN noise (-1) counts as "not in any cluster", so a pair where
    both members are noise doesn't get credited as "same cluster" — they
    correctly enter the distance matrix as disagreeing.
    """
    n = len(labels_emb)
    dist = np.zeros((n, n), dtype=np.float32)
    for i in range(n):
        for j in range(i + 1, n):
            a_emb = (labels_emb[i] == labels_emb[j]) and labels_emb[i] != -1
            a_lex = (labels_lex[i] == labels_lex[j]) and labels_lex[i] != -1
            agreement = int(a_emb) + int(a_lex)
            d = (2 - agreement) / 2.0
            dist[i, j] = d
            dist[j, i] = d
    return dist


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score(
    sessions: list[Session], cluster_pred: np.ndarray, v2_labels: dict,
) -> dict:
    session_ids = [s.session_id for s in sessions]
    labels = [s.label for s in sessions]
    metrics = {
        "ari":          round(float(adjusted_rand_score(labels, cluster_pred)), 4),
        "nmi":          round(float(normalized_mutual_info_score(labels, cluster_pred)), 4),
        "homogeneity":  round(float(homogeneity_score(labels, cluster_pred)), 4),
        "completeness": round(float(completeness_score(labels, cluster_pred)), 4),
        "v_measure":    round(float(v_measure_score(labels, cluster_pred)), 4),
    }
    pair_to_sessions: dict[str, list[str]] = {}
    for sid, block in v2_labels.items():
        pid = block.get("divergent_pair_id")
        if isinstance(pid, str) and pid:
            pair_to_sessions.setdefault(pid, []).append(sid)
    pair_outcomes: list[dict] = []
    if pair_to_sessions:
        v2_metrics, pair_outcomes = _divergent_pair_metrics(
            session_ids, cluster_pred, labels, pair_to_sessions,
        )
        metrics.update(v2_metrics)
    n_clusters = len({int(c) for c in cluster_pred if c >= 0})
    n_outliers = int(sum(1 for c in cluster_pred if c == -1))
    return {
        "metrics":     metrics,
        "n_clusters":  n_clusters,
        "n_outliers":  n_outliers,
        "per_label":   _per_label_breakdown(session_ids, labels, cluster_pred),
        "pair_outcomes": pair_outcomes,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_METRIC_ORDER = (
    "ari", "completeness", "homogeneity", "nmi", "v_measure",
    "divergent_pair_resolution_rate",
)


def _render_markdown(rows: list[dict], n_sessions: int, n_lex_clusters: int) -> str:
    out: list[str] = []
    out.append("# E4.4 — late-fusion sweep")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append(
        f"Sorted by ARI descending. {len(rows)} agglomerative-fusion "
        f"configurations swept against the merged v1+v2 eval set "
        f"({n_sessions} sessions). The embedding clusterer is "
        f"production HDBSCAN; the lexical clusterer is HDBSCAN over a "
        f"TF-IDF + SVD block ({n_lex_clusters} clusters found). Late "
        f"fusion = agglomerative clustering on the pair-disagreement "
        f"distance matrix."
    )
    out.append("")
    out.append(
        "Anchor rows: the two base clusterers' standalone metrics for "
        "reference."
    )
    out.append("")
    headers = ["row"] + list(_METRIC_ORDER) + ["n_clusters", "n_outliers"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        cells = [r["name"]]
        for m in _METRIC_ORDER:
            v = r["metrics"].get(m)
            cells.append(f"{v:.4f}" if isinstance(v, float) else str(v or "—"))
        cells.append(str(r["n_clusters"]))
        cells.append(str(r["n_outliers"]))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

# A handful of agglomerative target-cluster counts around the analyst
# label cardinality. The merged v1+v2 set has 6 distinct labels; we
# sweep a window around that to surface any sweet spot.
SWEEP_N_CLUSTERS: tuple[int, ...] = (5, 6, 7, 8, 10, 12)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels-v1", type=Path, default=Path("eval/labels-v1.yaml"))
    ap.add_argument("--jsonl-v1",  type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"))
    ap.add_argument("--labels-v2", type=Path, default=Path("eval/labels-v2.yaml"))
    ap.add_argument("--jsonl-v2",  type=Path,
                    default=Path("eval/sessions-v2.unlabeled.jsonl"))
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--svd-dim", type=int, default=100,
                    help="Truncated-SVD output dim for the lexical clusterer.")
    ap.add_argument("--linkage", type=str, default="average",
                    choices=["average", "single", "complete"],
                    help="Agglomerative linkage on the disagreement distance.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config()
    v1_labels = _load_labels(args.labels_v1)
    v2_labels = _load_labels(args.labels_v2) if args.labels_v2.exists() else {}
    sessions = _ingest(v1_labels, v2_labels, args.jsonl_v1, args.jsonl_v2)
    if not sessions:
        print("[ERROR] no sessions ingested", file=sys.stderr)
        return 1
    log.info("ingested %d sessions; labels: %s",
             len(sessions),
             dict(Counter(s.label for s in sessions).most_common()))

    log.info("base clusterer 1: embedding-only (production HDBSCAN)")
    labels_emb = _cluster_embedding(sessions, cfg)
    n_emb = len({int(c) for c in labels_emb if c >= 0})
    log.info("  %d non-noise clusters, %d outliers",
             n_emb, int(sum(1 for c in labels_emb if c == -1)))

    log.info("base clusterer 2: TF-IDF + SVD (lexical-only HDBSCAN)")
    labels_lex = _cluster_lexical(sessions, args.svd_dim, cfg)
    n_lex = len({int(c) for c in labels_lex if c >= 0})
    log.info("  %d non-noise clusters, %d outliers",
             n_lex, int(sum(1 for c in labels_lex if c == -1)))

    log.info("building disagreement distance matrix (%d×%d)",
             len(sessions), len(sessions))
    dist = _disagreement_distance(labels_emb, labels_lex)

    rows: list[dict] = []

    # Anchor rows: standalone base clusterers
    rows.append({"name": "embedding-only (anchor)", **_score(sessions, labels_emb, v2_labels)})
    rows.append({"name": "lexical-only (anchor)",   **_score(sessions, labels_lex, v2_labels)})

    # Fusion sweep
    for k in SWEEP_N_CLUSTERS:
        log.info("agglomerative fusion (linkage=%s, n_clusters=%d)", args.linkage, k)
        agg = AgglomerativeClustering(
            n_clusters=k, metric="precomputed", linkage=args.linkage,
        )
        fused = agg.fit_predict(dist)
        scored = _score(sessions, fused, v2_labels)
        rows.append({
            "name": f"fusion (n_clusters={k}, linkage={args.linkage})",
            **scored,
        })
        log.info("  → metrics: %s", scored["metrics"])

    rows.sort(key=lambda r: -r["metrics"].get("ari", 0.0))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"late-fusion-sweep-{ts}.md"
    json_path = args.output_dir / f"late-fusion-sweep-{ts}.json"
    md_text = _render_markdown(rows, len(sessions), n_lex)
    md_path.write_text(md_text, encoding="utf-8")
    json_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_sessions":   len(sessions),
        "linkage":      args.linkage,
        "svd_dim":      args.svd_dim,
        "base":         {"emb_clusters": n_emb, "lex_clusters": n_lex},
        "rows":         rows,
    }, indent=2), encoding="utf-8")
    print(f"\nwrote {md_path}")
    print(f"wrote {json_path}\n")
    print(md_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
