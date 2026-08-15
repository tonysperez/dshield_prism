"""Shared production-corpus puller for the F-phase spike scripts.

Used by ``inspect_small_clusters.py`` (F2.0 render harness),
``sweep_hdbscan.py --prod`` (F4.1 mcs sweep), and
``sweep_late_fusion_prod.py`` (F3.1) so the live-ES pull + the
session-layer clustering math live in exactly one place.

Pulls every embedded session rollup from the configured production
sessions index with the fields the small-cluster axis (3a intent
purity, 3b modal-signature share) and the analyst eyeball
(command-stream samples) need.

Read-only: a single ``search_after`` scan, no writes.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.clustering import l2_normalize, rescue_noise_points
from enrich.sources.cowrie.sessions import build_session_scalar_block

# Everything the spike needs per session: the four clustering scalars +
# embedding (clustering), dominant_intent + command_signature (3a/3b),
# command_stream_text (the eyeball sample), session_id (joins).
_SOURCE_FIELDS = [
    "dshield.cowrie.enrichment.session.embedding",
    "dshield.cowrie.enrichment.session.command_count",
    "dshield.cowrie.enrichment.session.unique_commands",
    "dshield.cowrie.enrichment.session.login_success_count",
    "dshield.cowrie.enrichment.session.login_fail_count",
    "dshield.cowrie.enrichment.session.mean_novelty_score",
    "dshield.cowrie.enrichment.session.dominant_intent",
    "dshield.cowrie.enrichment.session.command_signature",
    "dshield.cowrie.enrichment.session.command_stream_text",
    # command_set = the session's unique command hashes; the G1 Arm B
    # cluster_bag representation maps these to command-cluster ids.
    "dshield.cowrie.enrichment.session.command_set",
    "cowrie.session_id",
]


@dataclass
class SessionCorpus:
    """Column-oriented production session corpus. All lists are index-aligned."""
    doc_ids:     list[str] = field(default_factory=list)
    session_ids: list[str] = field(default_factory=list)
    embeddings:  list[list[float]] = field(default_factory=list)
    scalars:     list[dict] = field(default_factory=list)
    intents:     list = field(default_factory=list)
    signatures:  list = field(default_factory=list)
    texts:       list[str] = field(default_factory=list)
    command_sets: list[list[str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.doc_ids)


def pull_session_corpus(
    es, index: str, page_size: int = 1000, limit: int | None = None,
) -> SessionCorpus:
    """Stream every embedded session rollup into a SessionCorpus."""
    body: dict = {
        "size": page_size,
        "_source": _SOURCE_FIELDS,
        "query": {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    corpus = SessionCorpus()
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            src = h["_source"]
            s = (
                ((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {})
                .get("session", {})
            )
            emb = s.get("embedding")
            if not emb:
                continue
            sid = (src.get("cowrie") or {}).get("session_id") or h["_id"]
            success = s.get("login_success_count") or 0
            fail = s.get("login_fail_count") or 0
            total = success + fail
            corpus.doc_ids.append(h["_id"])
            corpus.session_ids.append(sid)
            corpus.embeddings.append(emb)
            corpus.scalars.append({
                "command_count":      s.get("command_count") or 1,
                "unique_commands":    s.get("unique_commands") or 1,
                "login_success_rate": success / total if total > 0 else 0.0,
                "mean_novelty_score": s.get("mean_novelty_score") or 0.0,
            })
            corpus.intents.append(s.get("dominant_intent"))
            corpus.signatures.append(s.get("command_signature"))
            corpus.texts.append(s.get("command_stream_text") or "")
            corpus.command_sets.append(list(s.get("command_set") or []))
            if limit is not None and len(corpus) >= limit:
                return corpus
        search_after = hits[-1]["sort"]
    return corpus


def normalized_embeddings(corpus: SessionCorpus) -> np.ndarray:
    """(n, d) L2-normalized pure-embedding matrix — the geometry the shard
    test (3b) + rescue use."""
    return l2_normalize(np.array(corpus.embeddings, dtype=np.float32))


def score_full(
    labels: np.ndarray,
    corpus: SessionCorpus,
    sid_to_label: dict[str, str],
    pair_to_sessions: dict[str, list[str]] | None = None,
    *,
    merge_threshold: float,
) -> dict:
    """Score a production-scale labeling on the F-phase binding metrics.

    Metrics 4-7 (ari/nmi/homogeneity/completeness/v_measure) are computed
    on the labeled eval subset; metrics 1-3 (outlier_rate, small-cluster
    count/purity/shard-fraction) are computed corpus-wide. Shared by F3.1 +
    F4.1 so every prod-scale sweep scores identically. ``labels`` is
    index-aligned with ``corpus``. (``pair_to_sessions`` is accepted for
    back-compat with older callers but no longer scored — the divergent-pair
    metric was retired with the semantic-clustering claim; see
    eval/archive/semantic-clustering-claim/.)
    """
    del pair_to_sessions  # retired; accepted for caller back-compat only
    from eval_clustering import small_cluster_metrics  # local import
    from sklearn.metrics import (
        adjusted_rand_score,
        completeness_score,
        homogeneity_score,
        normalized_mutual_info_score,
        v_measure_score,
    )

    sid_to_cluster = {sid: int(c) for sid, c in zip(corpus.session_ids, labels, strict=False)}
    eval_sids: list[str] = []
    truth: list[str] = []
    pred: list[int] = []
    for sid, lbl in sid_to_label.items():
        if sid in sid_to_cluster:
            eval_sids.append(sid)
            truth.append(lbl)
            pred.append(sid_to_cluster[sid])
    pred_arr = np.array(pred, dtype=np.int64)

    metrics: dict = {
        "ari":          round(float(adjusted_rand_score(truth, pred_arr)), 4),
        "nmi":          round(float(normalized_mutual_info_score(truth, pred_arr)), 4),
        "homogeneity":  round(float(homogeneity_score(truth, pred_arr)), 4),
        "completeness": round(float(completeness_score(truth, pred_arr)), 4),
        "v_measure":    round(float(v_measure_score(truth, pred_arr)), 4),
    }

    norm = normalized_embeddings(corpus)
    sc = small_cluster_metrics(
        labels, norm, corpus.intents, corpus.signatures,
        merge_threshold=merge_threshold,
    )
    metrics.update(sc["metrics"])

    n = len(labels)
    return {
        "metrics":             metrics,
        "small_cluster_detail": sc["small_cluster_detail"],
        "n_clusters_total":    len({int(c) for c in labels if c >= 0}),
        "n_outliers_total":    int((np.asarray(labels) == -1).sum()),
        "eval_sessions_found": len(eval_sids),
        # how many size-∈[3,10] members are labeled-eval sessions — makes a
        # metric-5 trip diagnosable (the unlabeled-tail constraint).
        "labeled_in_small":    _labeled_in_small_clusters(
            labels, corpus.session_ids, sid_to_label, sc["small_cluster_detail"],
        ),
        "n_total":             n,
    }


def _labeled_in_small_clusters(
    labels: np.ndarray,
    session_ids: list[str],
    sid_to_label: dict[str, str],
    detail: list[dict],
) -> int:
    small_lbls = {d["cluster_label"] for d in detail}
    return sum(
        1 for sid, c in zip(session_ids, labels, strict=False)
        if int(c) in small_lbls and sid in sid_to_label
    )


def cluster_hdbscan(
    corpus: SessionCorpus,
    *,
    min_cluster_size: int,
    min_samples: int,
    scalar_weight: float,
    rescue_threshold: float | None,
) -> tuple[np.ndarray, int]:
    """Production-equivalent session clustering: L2-normalize, optional
    weighted scalar block, HDBSCAN, optional noise rescue. Returns
    ``(labels, n_rescued)``. Mirrors ``run_layer_clustering`` minus I/O."""
    from sklearn.cluster import HDBSCAN

    normalized = normalized_embeddings(corpus)
    if scalar_weight > 0.0:
        block = build_session_scalar_block(corpus.scalars, scalar_weight)
        cluster_matrix = np.hstack([normalized, block])
    else:
        cluster_matrix = normalized
    labels = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    ).fit_predict(cluster_matrix)
    n_rescued = 0
    if rescue_threshold is not None and rescue_threshold > 0.0:
        labels, n_rescued = rescue_noise_points(normalized, labels, rescue_threshold)
    return labels, n_rescued
