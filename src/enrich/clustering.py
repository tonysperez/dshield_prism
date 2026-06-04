"""Shared HDBSCAN core. Layer-agnostic — used by every per-source clusterer.

Each source module (sources/<source>/<layer>.py) supplies:
- iter docs from its index, yielding (doc_id, embedding, label, scalars)
- a scalar-block builder (n × k normalized features)
- an ES update script + centroid sample-field name

This module owns the math: L2-normalize, scalar augmentation, HDBSCAN call,
centroid + novelty score computation.
"""
from __future__ import annotations

import logging
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Iterator, Optional

from elasticsearch import Elasticsearch

from .es_client import bulk_write, init_index

log = logging.getLogger(__name__)

# Tolerance on scalar_weight equality when validating a reference centroid set.
# A reference minted at weight=0.05 is invalid for scoring at weight=0.10 — the
# augmented-space geometry changes — so we require an exact match within float
# noise.
_REFERENCE_SCALAR_WEIGHT_TOL = 1e-6

try:
    import numpy as np
    from sklearn.cluster import HDBSCAN as _HDBSCAN
    _CLUSTER_DEPS = True
except ImportError:
    _CLUSTER_DEPS = False
    np = None  # type: ignore[assignment]
    _HDBSCAN = None  # type: ignore[assignment]


def cluster_deps_available() -> bool:
    return _CLUSTER_DEPS


def require_cluster_deps() -> None:
    if not _CLUSTER_DEPS:
        raise ImportError(
            "Cluster deps not installed. Run: pip install -e '.[cluster]'"
        )


def l2_normalize(matrix: "np.ndarray") -> "np.ndarray":
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms = np.where(norms == 0.0, 1.0, norms)
    return matrix / norms


def compute_centroids(
    matrix: "np.ndarray", labels: "np.ndarray"
) -> dict[int, "np.ndarray"]:
    centroids: dict[int, "np.ndarray"] = {}
    for lbl in np.unique(labels):
        if lbl < 0:
            continue
        mask = labels == lbl
        centroids[int(lbl)] = matrix[mask].mean(axis=0)
    return centroids


def rescue_noise_points(
    normalized: "np.ndarray",
    labels: "np.ndarray",
    threshold: float,
) -> tuple["np.ndarray", int]:
    """Reassign HDBSCAN noise points (-1) to their nearest cluster centroid when
    pure-embedding cosine similarity >= `threshold`. Returns (new_labels,
    n_rescued). Pure — no I/O.

    HDBSCAN's density model drops sessions in low-density periphery as noise
    even when they are behaviourally near-identical to a cluster (cosine ~1.0
    to its centroid). The existing centroid-level merge (`playbook_merge_
    threshold`) can't see them — they never become a centroid. This closes
    that gap by extending the same cosine-merge rule down to the loose noise
    points: an outlier within `threshold` cosine of a cluster centroid joins
    that cluster. Centroids here are means of the L2-normalised member
    embeddings, normalised for the cosine comparison — the same pure-embedding
    geometry the centroid merge uses. Points below `threshold` stay noise.
    """
    new_labels = labels.copy()
    noise_idx = np.where(labels == -1)[0]
    if len(noise_idx) == 0 or threshold > 1.0:
        return new_labels, 0
    centroids = compute_centroids(normalized, labels)
    if not centroids:
        return new_labels, 0
    cluster_lbls = sorted(centroids)
    C = np.array([centroids[l] for l in cluster_lbls], dtype=np.float32)
    C = C / (np.linalg.norm(C, axis=1, keepdims=True) + 1e-12)
    sims = normalized[noise_idx] @ C.T            # (m, k) — rows already unit-norm
    best = sims.argmax(axis=1)
    best_sim = sims.max(axis=1)
    rescued = 0
    for r, i in enumerate(noise_idx):
        if best_sim[r] >= threshold:
            new_labels[i] = cluster_lbls[best[r]]
            rescued += 1
    return new_labels, rescued


def novelty_score(vec: "np.ndarray", centroids: dict[int, "np.ndarray"]) -> float:
    """1 - max cosine_sim to any centroid. Vec need not be unit-norm.

    Proper cosine sim — divides by `|vec| * |c|`. Backward compatible for the
    L2-normalized embedding case (|vec|=1 → identical to the prior formula),
    but also correct on the scalar-augmented rows used at clustering time
    (ROADMAP #12: in-run novelty is scored in the same space HDBSCAN saw).
    """
    if not centroids:
        return 1.0
    norm_v = float(np.linalg.norm(vec))
    if norm_v == 0.0:
        return 1.0
    best = -1.0
    for c in centroids.values():
        norm_c = float(np.linalg.norm(c))
        if norm_c == 0.0:
            continue
        sim = float(np.dot(vec, c)) / (norm_v * norm_c)
        if sim > best:
            best = sim
    return float(1.0 - max(0.0, best))


def novelty_score_from_lists(
    embedding: list[float],
    centroids: list[list[float]],
) -> float:
    """Pure-Python novelty score for triage (no numpy dependency)."""
    if not centroids:
        return 1.0
    best = -1.0
    for c in centroids:
        dot = sum(a * b for a, b in zip(embedding, c))
        norm_c = math.sqrt(sum(b * b for b in c))
        if norm_c == 0.0:
            continue
        sim = dot / norm_c
        if sim > best:
            best = sim
    return float(1.0 - max(0.0, best))


# ---------------------------------------------------------------------------
# Late-fusion clustering (E4.4 adoption)
# ---------------------------------------------------------------------------
#
# Late fusion combines two HDBSCAN passes (one over the embedding +
# scalar augmentation, one over a per-session TF-IDF + truncated-SVD
# lexical view) via Agglomerative clustering on the per-pair
# disagreement-distance matrix. Adopted for the session layer per
# eval/results/E4-verdict.md — +0.085 ARI on the merged v1+v2 eval vs
# the embedding-only HDBSCAN baseline, with homogeneity preserved above
# the 0.80 binding rule.
#
# Outlier semantics are preserved: ``embedding_outlier_flags`` (the
# embedding-only HDBSCAN's ``label == -1`` mask) is returned alongside
# the fusion labels so callers can populate ``cluster.is_outlier`` from
# the original HDBSCAN pass. Downstream consumers (novelty / rescue /
# outlier_burst) see the same noise concept they do today; only the
# cluster id assignment changes.
#
# These helpers are layer-agnostic by design (operate on prepared
# numpy blocks) — the session caller composes them. Command + IP
# layers don't currently have a meaningful lexical view, so they stay
# on the single-pass run_layer_clustering path.


def compute_lexical_features(
    texts: list[str], n_components: int = 100,
) -> "np.ndarray":
    """Fit TF-IDF + truncated SVD on the corpus and return per-row
    L2-normalized features (n_texts × n_components).

    Hyperparameters mirror the E0.2 ablation and every E4 sweep:
    max_features 5000, (1,2) ngrams, sublinear_tf, l2 norm. Refit on
    every cluster run — the vocabulary is corpus-state-dependent and
    persisting the vectorizer adds a versioning footgun we don't yet
    need. Cost at production scale is single-digit seconds for tens of
    thousands of sessions.

    Empty / single-text corpora return a zero block of shape
    ``(len(texts), 1)`` so downstream callers don't have to special-
    case shape.
    """
    require_cluster_deps()
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD

    if not texts:
        return np.zeros((0, 1), dtype=np.float32)

    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        norm="l2",
    )
    try:
        tfidf = vectorizer.fit_transform(texts)
    except ValueError:
        # Empty vocabulary (e.g. all texts are punctuation-only).
        return np.zeros((len(texts), 1), dtype=np.float32)

    k = min(n_components, tfidf.shape[1], max(tfidf.shape[0] - 1, 1))
    if k < 2:
        return np.zeros((len(texts), 1), dtype=np.float32)
    svd = TruncatedSVD(n_components=k, random_state=20260601)
    reduced = svd.fit_transform(tfidf).astype(np.float32)
    norms = np.linalg.norm(reduced, axis=1, keepdims=True)
    norms[norms == 0.0] = 1.0
    return (reduced / norms).astype(np.float32)


def cluster_bag_labels(
    bag_texts: list[str], *,
    min_cluster_size: int, min_samples: int, n_components: int = 64,
) -> tuple["np.ndarray", "np.ndarray"]:
    """G1 Arm B — cluster sessions on a TF-IDF bag of *command-cluster ids*.

    ``bag_texts`` is per-session space-joined command-cluster-id tokens with
    multiplicity (e.g. ``"cluster_20 cluster_20 cluster_7"``). Reuses
    ``compute_lexical_features`` — the tokenizer treats each cluster-id as
    one token, and the vocabulary is bounded by the command-cluster count,
    so the SVD geometry stays stable across corpus scales (the property raw
    command tokens lack — they proliferate, which is why E4.4 fragmented to
    72). Returns ``(labels, lexical_block)``; the per-row-normalized lexical
    block is also the geometry to rescue noise points in.
    """
    require_cluster_deps()
    block = compute_lexical_features(bag_texts, n_components=n_components)
    labels = _HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    ).fit_predict(block)
    return labels, block


def _disagreement_distance(
    labels_a: "np.ndarray", labels_b: "np.ndarray",
) -> "np.ndarray":
    """Build the n × n pair-disagreement distance matrix used as the
    fusion clusterer's input.

    For each pair (i, j):
      * agree_a = labels_a[i] == labels_a[j] AND labels_a[i] != -1
      * agree_b = labels_b[i] == labels_b[j] AND labels_b[i] != -1
      * agreement = int(agree_a) + int(agree_b)   (∈ {0, 1, 2})
      * distance  = (2 - agreement) / 2           (∈ [0, 1])

    HDBSCAN noise (-1) is never treated as "same cluster" — two noise
    sessions enter the matrix as disagreeing, which lets the
    Agglomerative pass place them on the periphery rather than fusing
    them into a spurious common cluster.
    """
    n = len(labels_a)
    if n == 0:
        return np.zeros((0, 0), dtype=np.float32)
    dist = np.zeros((n, n), dtype=np.float32)
    for i in range(n):
        a_i = int(labels_a[i])
        b_i = int(labels_b[i])
        for j in range(i + 1, n):
            agree_a = (a_i == int(labels_a[j])) and a_i != -1
            agree_b = (b_i == int(labels_b[j])) and b_i != -1
            d = (2 - int(agree_a) - int(agree_b)) / 2.0
            dist[i, j] = d
            dist[j, i] = d
    return dist


def fusion_cluster_labels(
    embedding_cluster_matrix: "np.ndarray",
    lexical_block: "np.ndarray",
    *,
    min_cluster_size: int,
    min_samples: int,
    n_clusters: int | None = None,
) -> tuple["np.ndarray", "np.ndarray", int, int]:
    """Run the late-fusion clustering math on prepared inputs.

    Args:
        embedding_cluster_matrix: the matrix the production HDBSCAN
            would consume — embedding + (optional) weighted scalar
            block, already L2-normalized. Shape: (n_docs, embedding_dim
            + scalar_dim).
        lexical_block: the TF-IDF + SVD per-row-normalized lexical
            features from ``compute_lexical_features``. Shape:
            (n_docs, lexical_dim).
        min_cluster_size: HDBSCAN parameter — applied to BOTH the
            embedding and lexical clusterers identically.
        min_samples: HDBSCAN min_samples — same as above.
        n_clusters: target cluster count for the Agglomerative fusion
            step. When None, defaults to
            ``max(n_emb_clusters, n_lex_clusters)`` — the empirically-
            tested rule from the E4.4 sweep that lands within 0.015 ARI
            of the hand-tuned optimum on the eval set.

    Returns:
        ``(fusion_labels, embedding_outlier_flags, n_emb_clusters, n_lex_clusters)``:
          * fusion_labels: per-doc cluster id from the Agglomerative
            fusion (0..n_clusters-1; never -1).
          * embedding_outlier_flags: bool array where True means the
            embedding-only HDBSCAN tagged this doc as noise. Callers
            populate ``cluster.is_outlier`` from this — preserves the
            production outlier concept for novelty / rescue /
            outlier_burst downstream.
          * n_emb_clusters / n_lex_clusters: number of non-noise
            clusters each base HDBSCAN found. Stats-only — useful for
            logging and the default n_clusters rule above.
    """
    require_cluster_deps()
    from sklearn.cluster import AgglomerativeClustering

    n_docs = int(embedding_cluster_matrix.shape[0])
    if n_docs < min_cluster_size:
        # Too few docs for HDBSCAN. Return one cluster + no outliers.
        return (
            np.zeros(n_docs, dtype=np.int32),
            np.zeros(n_docs, dtype=bool),
            0, 0,
        )

    emb_clusterer = _HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    )
    labels_emb = emb_clusterer.fit_predict(embedding_cluster_matrix)
    n_emb = int(len({int(l) for l in labels_emb if l >= 0}))

    lex_clusterer = _HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    )
    labels_lex = lex_clusterer.fit_predict(lexical_block)
    n_lex = int(len({int(l) for l in labels_lex if l >= 0}))

    if n_clusters is None:
        # E4.4 self-tuning rule. Bound below at 2 so Agglomerative has
        # something to do even when both base clusterers produced a
        # single cluster.
        n_clusters = max(2, n_emb, n_lex)
    n_clusters = max(2, min(n_clusters, n_docs))

    dist = _disagreement_distance(labels_emb, labels_lex)
    agg = AgglomerativeClustering(
        n_clusters=n_clusters,
        metric="precomputed",
        linkage="average",
    )
    fusion_labels = agg.fit_predict(dist.astype(float)).astype(np.int32)
    embedding_outlier_flags = (labels_emb == -1)
    return fusion_labels, embedding_outlier_flags, n_emb, n_lex


def _fusion_over_ceiling(
    n_docs: int,
    fusion_max_docs: Optional[int],
    *,
    accept_fallback: bool,
    layer_label: str,
) -> bool:
    """Decide what to do when the late-fusion path is selected at `n_docs`.

    Returns ``False`` (proceed with fusion) when there is no ceiling or the
    count is within it. Returns ``True`` (fall back to HDBSCAN) when over the
    ceiling AND `accept_fallback` is set. **Raises** ``RuntimeError`` when over
    the ceiling and fallback was not explicitly accepted — a hard refusal, not
    a silent degradation, because the operator chose `late_fusion` deliberately.
    P1.3. Pure (apart from a warning log); unit-tested directly.
    """
    if not fusion_max_docs or n_docs <= fusion_max_docs:
        return False
    if accept_fallback:
        log.warning(
            "[%s] late_fusion over ceiling (%d > %d) — falling back to HDBSCAN "
            "(--accept-fallback)", layer_label, n_docs, fusion_max_docs,
        )
        return True
    raise RuntimeError(
        f"[{layer_label}] late_fusion refused: {n_docs} docs exceeds "
        f"session.fusion_max_docs={fusion_max_docs}. The fusion path builds an "
        f"O(N^2) pure-Python pair-distance matrix and an n×n float32 matrix, so "
        f"it would hang at this size. Reduce the doc count (windowed clustering, "
        f"P1.2), raise session.fusion_max_docs, or pass --accept-fallback to "
        f"cluster with plain HDBSCAN instead."
    )


def load_centroids(
    es: Elasticsearch, clusters_index: str,
    *, reference_source: Optional[str] = None,
) -> list[list[float]]:
    """Load pure-embedding centroid vectors. Used by triage's novel_embedding rule.

    Prefers `doc_type=reference_centroid` (highest `reference_generation`
    for the requested `reference_source`) for stable across-run novelty
    scores; falls back to the latest `doc_type=cluster` run when no
    reference exists (fresh deploy, pre-bootstrap) AND the in-corpus
    path is requested. When `reference_source` is explicit (e.g.
    `"external"`), no in-run fallback is attempted — if no external
    reference centroids exist for that source, return [].

    Returns [] on missing index, no data, or any query failure.
    """
    try:
        if not es.indices.exists(index=clusters_index):
            return []

        ref = load_reference_centroids(
            es, clusters_index, reference_source=reference_source,
        )
        if ref and ref.get("pure"):
            return ref["pure"]

        # No in-run fallback when an explicit reference_source was
        # requested — the caller is asking specifically "do we have
        # an external reference?" and the honest answer is "no".
        if reference_source is not None:
            return []

        # P3.1 — resolve "latest run" via the run_summary completion sentinel
        # (written LAST, P3.3), so a half-built run (centroids written, crashed
        # before run_summary) is never read; fall back to the last complete run.
        resp = es.search(
            index=clusters_index,
            **{
                "size": 1,
                "query": {"term": {"doc_type": "run_summary"}},
                "sort": [{"@timestamp": "desc"}],
                "_source": ["run_id"],
            },
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return []
        run_id = hits[0]["_source"].get("run_id")
        if not run_id:
            return []

        resp2 = es.search(
            index=clusters_index,
            **{
                "size": 1000,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"doc_type": "cluster"}},
                            {"term": {"run_id": run_id}},
                        ]
                    }
                },
                "_source": ["centroid"],
            },
        )
        return [
            h["_source"]["centroid"]
            for h in resp2["hits"]["hits"]
            if h["_source"].get("centroid")
        ]
    except Exception as exc:
        log.warning("Could not load centroids from %s: %s", clusters_index, exc)
        return []


def load_run_centroids(
    es: Elasticsearch, clusters_index: str,
) -> dict:
    """Load ``{cluster_id: pure-embedding centroid}`` from the latest COMPLETE
    cluster run.

    Resolves "latest run" via the ``run_summary`` completion sentinel (written
    LAST — P3.1/P3.3 — so a half-built run whose centroids were indexed before a
    crash is never read). The ``outlier`` pseudo-cluster has no centroid doc and
    is therefore absent. Returns ``{}`` on missing index, no complete run, or any
    query failure.

    Used by the IP-layer incremental assign (backlog B0.5 Option B) to place new
    IPs on the nearest existing cluster centroid without re-running HDBSCAN.
    """
    try:
        if not es.indices.exists(index=clusters_index):
            return {}
        resp = es.search(
            index=clusters_index,
            **{
                "size": 1,
                "query": {"term": {"doc_type": "run_summary"}},
                "sort": [{"@timestamp": "desc"}],
                "_source": ["run_id"],
            },
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return {}
        run_id = hits[0]["_source"].get("run_id")
        if not run_id:
            return {}
        resp2 = es.search(
            index=clusters_index,
            **{
                "size": 1000,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"doc_type": "cluster"}},
                            {"term": {"run_id": run_id}},
                        ]
                    }
                },
                "_source": ["cluster_id", "centroid"],
            },
        )
        out: dict = {}
        for h in resp2["hits"]["hits"]:
            src = h["_source"]
            cid = src.get("cluster_id")
            centroid = src.get("centroid")
            if cid and centroid:
                out[cid] = centroid
        return out
    except Exception as exc:
        log.warning("Could not load run centroids from %s: %s", clusters_index, exc)
        return {}


def load_reference_centroids(
    es: Elasticsearch, clusters_index: str,
    *, reference_source: Optional[str] = None,
) -> dict:
    """Load the active `reference_centroid` set (max `reference_generation`).

    Returns `{}` if the index is missing, no reference docs exist, or the
    query fails. Otherwise returns:

        {
          "pure":              list[list[float]],   # always present
          "augmented":         list[list[float]],   # absent for IP-layer refs
          "generation":        int,
          "source_run_id":     str | None,
          "embedding_dims":    int | None,
          "augmented_dims":    int | None,
          "scalar_weight":     float | None,
          "minted_at":         str | None,          # ISO timestamp
          "age_days":          float | None,
          "reference_source":  str | None,          # echo of the filter
        }

    ``reference_source`` filter (brutal-review phase 5.4):
      - ``None`` (default) — match only docs WITHOUT a ``reference_source``
        field. This is the in-corpus centroid set: every centroid that
        existed before phase 5.4 lacks the field, so the default path
        preserves the historical "load the latest in-corpus ref" behavior.
      - explicit string (e.g. ``"external"``) — match docs whose
        ``reference_source`` equals that value. Phase 5.4 mints centroids
        with ``reference_source="external"`` from the Atomic Red Team
        corpus; phase 5.5 reads them via this filter to populate
        ``novelty_score_external`` alongside the in-corpus
        ``novelty_score``.

    Generation numbering is per-source: each ``reference_source`` value
    has its own monotonic counter, so bootstrapping a new external
    generation doesn't perturb the in-corpus counter.

    The caller is responsible for staleness checks (dim mismatch, scalar_weight
    delta, age). This loader only fetches.
    """
    # Centroid-source filter — appended to every query against the
    # reference_centroid set in this loader.
    if reference_source is None:
        source_filter = {
            "bool": {"must_not": {"exists": {"field": "reference_source"}}}
        }
    else:
        source_filter = {"term": {"reference_source.keyword": reference_source}}

    try:
        if not es.indices.exists(index=clusters_index):
            return {}

        # Find max generation FOR THIS SOURCE. `reference_generation` is a
        # `long` and sorts cleanly. Per-source generation means an
        # external bootstrap doesn't bump the in-corpus counter (and
        # vice versa).
        resp = es.search(
            index=clusters_index,
            **{
                "size": 1,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"doc_type": "reference_centroid"}},
                            source_filter,
                        ]
                    }
                },
                "sort": [{"reference_generation": "desc"}, {"@timestamp": "desc"}],
                "_source": ["reference_generation"],
            },
        )
        hits = resp["hits"]["hits"]
        if not hits:
            return {}
        gen = hits[0]["_source"].get("reference_generation")
        if gen is None:
            return {}

        resp2 = es.search(
            index=clusters_index,
            **{
                "size": 1000,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"doc_type": "reference_centroid"}},
                            {"term": {"reference_generation": gen}},
                            source_filter,
                        ]
                    }
                },
                "_source": [
                    "centroid", "centroid_augmented",
                    "source_run_id", "embedding_dims", "augmented_dims",
                    "scalar_weight", "reference_minted_at",
                ],
            },
        )
        ref_hits = resp2["hits"]["hits"]
        if not ref_hits:
            return {}

        pure: list[list[float]] = []
        aug: list[list[float]] = []
        meta_src = ref_hits[0]["_source"]
        for h in ref_hits:
            src = h["_source"]
            if src.get("centroid"):
                pure.append(src["centroid"])
            if src.get("centroid_augmented"):
                aug.append(src["centroid_augmented"])

        if not pure:
            return {}

        minted_at = meta_src.get("reference_minted_at")
        age_days = None
        if minted_at:
            try:
                mt = datetime.fromisoformat(minted_at.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - mt).total_seconds() / 86400.0
            except (ValueError, AttributeError):
                pass

        return {
            "pure": pure,
            "augmented": aug,
            "generation": int(gen),
            "source_run_id": meta_src.get("source_run_id"),
            "embedding_dims": meta_src.get("embedding_dims"),
            "augmented_dims": meta_src.get("augmented_dims"),
            "scalar_weight": meta_src.get("scalar_weight"),
            "minted_at": minted_at,
            "age_days": age_days,
            "reference_source": reference_source,
        }
    except Exception as exc:
        log.warning(
            "Could not load reference centroids from %s: %s", clusters_index, exc
        )
        return {}


def _validate_reference(
    ref: dict,
    *,
    current_embedding_dims: int,
    current_augmented_dims: int,
    current_scalar_weight: float,
    expects_augmented: bool,
) -> str:
    """Return '' if the reference is usable, else a short reason string.

    Reasons: 'dim_mismatch_pure', 'dim_mismatch_augmented',
    'missing_augmented', 'scalar_weight_mismatch'. The caller logs + decides
    fallback behavior; this function does no logging.
    """
    if ref.get("embedding_dims") not in (None, current_embedding_dims):
        return "dim_mismatch_pure"
    if expects_augmented:
        if not ref.get("augmented"):
            return "missing_augmented"
        if ref.get("augmented_dims") not in (None, current_augmented_dims):
            return "dim_mismatch_augmented"
        ref_w = ref.get("scalar_weight")
        if ref_w is not None and abs(float(ref_w) - current_scalar_weight) > _REFERENCE_SCALAR_WEIGHT_TOL:
            return "scalar_weight_mismatch"
    return ""


# ---------------------------------------------------------------------------
# Cluster-run retention (scale-hardening P2.1)
# ---------------------------------------------------------------------------
#
# Each cluster run appends a fresh `cluster` centroid set + one `run_summary`
# doc and never prunes, so the cluster indices accumulate dead per-run state
# forever — only the *latest* run is ever read (see `load_centroids` and the
# console's run-cache, which resolve the newest run_id then filter to it).
# `prune_cluster_runs` caps each index by keeping only the newest `keep_runs`
# runs' `cluster` + `run_summary` docs.
#
# `reference_centroid` docs are NEVER touched: they are read across runs (the
# stable across-run novelty anchors) and deleting any generation breaks
# novelty scoring. The delete query is scoped to `doc_type in {cluster,
# run_summary}`, which structurally excludes `reference_centroid`.


def _select_keep_run_ids(run_summaries: list[dict], keep_runs: int) -> list[str]:
    """The `run_id`s of the newest `keep_runs` runs.

    `run_summaries` is a list of dicts each with at least `run_id` and
    `@timestamp`. Sorted by `@timestamp` desc (ties broken by run_id for
    determinism); the first `keep_runs` distinct run_ids are returned. Pure —
    no ES, so the retention rule is unit-tested directly.
    """
    keep_runs = max(1, keep_runs)
    ordered = sorted(
        (rs for rs in run_summaries if rs.get("run_id")),
        key=lambda rs: (rs.get("@timestamp") or "", rs.get("run_id") or ""),
        reverse=True,
    )
    keep: list[str] = []
    for rs in ordered:
        rid = rs["run_id"]
        if rid not in keep:
            keep.append(rid)
        if len(keep) >= keep_runs:
            break
    return keep


def prune_cluster_runs(
    es: Elasticsearch,
    clusters_index: str,
    *,
    keep_runs: int = 5,
    dry_run: bool = False,
    layer_label: str = "",
) -> dict:
    """Delete `cluster` + `run_summary` docs older than the newest `keep_runs`
    runs from one cluster index. Keeps every `reference_centroid` generation.

    Safety: if the index is missing, or no `run_summary` doc exists (we can't
    tell which run is newest), the prune is SKIPPED — never a blind delete
    (mirrors the findings-tombstone empty-live-set guard).
    """
    label = layer_label or clusters_index
    try:
        if not es.indices.exists(index=clusters_index):
            return {"index": clusters_index, "status": "missing", "deleted": 0}
    except Exception as exc:
        log.warning("[prune %s] exists() failed: %s", label, exc)
        return {"index": clusters_index, "status": "error", "deleted": 0, "error": str(exc)}

    # Newest `keep_runs` run_ids, straight from the run_summary docs. Bounded
    # by `keep_runs` (small), so this stays cheap even before the first prune.
    try:
        resp = es.search(
            index=clusters_index,
            size=max(1, keep_runs),
            query={"term": {"doc_type": "run_summary"}},
            sort=[{"@timestamp": "desc"}],
            _source=["run_id"],
        )
        keep = _select_keep_run_ids(
            [h.get("_source", {}) for h in resp["hits"]["hits"]], keep_runs,
        )
    except Exception as exc:
        log.warning("[prune %s] could not read run_summary docs: %s", label, exc)
        return {"index": clusters_index, "status": "error", "deleted": 0, "error": str(exc)}

    if not keep:
        # No run_summary docs → can't establish a keep set → do nothing.
        return {"index": clusters_index, "status": "no_run_summaries", "deleted": 0}

    # Delete the per-run state of every OTHER run. The `doc_type` filter keeps
    # reference_centroid docs structurally out of scope.
    del_query = {
        "bool": {
            "must":     [{"terms": {"doc_type": ["cluster", "run_summary"]}}],
            "must_not": [{"terms": {"run_id": keep}}],
        }
    }

    if dry_run:
        try:
            n = int(es.count(index=clusters_index, query=del_query)["count"])
        except Exception as exc:
            log.warning("[prune %s] dry-run count failed: %s", label, exc)
            n = -1
        return {"index": clusters_index, "status": "dry_run",
                "kept_runs": len(keep), "would_delete": n}

    try:
        resp = es.delete_by_query(
            index=clusters_index, body={"query": del_query},
            conflicts="proceed", refresh=False,
        )
        deleted = int(resp.get("deleted") or 0)
    except Exception as exc:
        log.warning("[prune %s] delete_by_query failed: %s", label, exc)
        return {"index": clusters_index, "status": "error", "deleted": 0, "error": str(exc)}

    if deleted:
        log.info(
            "[prune %s] kept newest %d run(s); deleted %d dead cluster/run_summary doc(s)",
            label, len(keep), deleted,
        )
    return {"index": clusters_index, "status": "ok", "kept_runs": len(keep), "deleted": deleted}


def run_layer_clustering(
    *,
    es: Elasticsearch,
    docs_iter: Iterator[tuple[str, list[float], str, dict]],
    docs_index: str,
    clusters_index: str,
    mapping_path: str,
    update_script: str,
    scalar_block_builder: Callable[[list[dict], float], "np.ndarray"],
    min_cluster_size: int,
    min_samples: int,
    scalar_weight: float,
    batch_size: int,
    sample_size: int,
    centroid_sample_field: str,
    dry_run: bool,
    layer_label: str,
    refresh_reference: bool = False,
    use_reference: bool = True,
    reference_max_age_days: int = 45,
    rescue_threshold: float | None = None,
    reference_source: Optional[str] = None,
    bootstrap_reference_now: bool = False,
    cluster_fn: Optional[Callable[..., tuple["np.ndarray", Optional["np.ndarray"]]]] = None,
    fusion_max_docs: Optional[int] = None,
    accept_fallback: bool = False,
    window_days: Optional[int] = None,
) -> dict:
    """Generic HDBSCAN pipeline for one layer (commands / sessions / IPs / future).

    Steps:
      1. Pull all (doc_id, embedding, label, scalars) from docs_iter.
      2. L2-normalize embeddings -> n×D matrix.
      3. Optionally hstack a weighted scalar block.
      4. Run HDBSCAN.
      5. Compute centroids in BOTH spaces (pure + augmented when scalar_weight>0).
      6. Resolve scoring centroids (reference if available + valid, else this run).
      7. Score per-doc novelty against the scoring centroids.
      8. Persist pure-embedding centroids (+ reference_centroids) to clusters_index.
      9. Bulk-update doc cluster fields via update_script.
     10. Write the run_summary sentinel LAST (P3.3), stamped with write-error
         counts, so its presence means the run's writes finished.
     11. Auto-bootstrap or refresh the reference_centroid set if asked / needed.

    Why two centroid sets (ROADMAP #12): HDBSCAN labels come from
    `cluster_matrix` (pure embedding + weighted scalar block). Scoring a row's
    novelty against pure-embedding centroids would let a row that was pulled
    into cluster X by its scalars score high novelty against X — the
    "in-cluster doc escalated as novel" Heisenbug. So the per-doc
    `novelty_score` is computed in the same augmented space.

    The *persisted* per-run centroid stays pure-embedding because
    `load_centroids` + triage compare it against a fresh command's bare
    embedding — triage has no way to materialise that command's scalars
    (occurrence_count, etc. are corpus-derived, not known at first-touch time).

    Reference centroids (ROADMAP P1): if `use_reference=True` and a valid
    `doc_type=reference_centroid` set exists, per-doc novelty is scored against
    that frozen reference instead of this run's centroids. This makes scores
    comparable across runs — an outlier in run N no longer becomes a member in
    run N+1 just because the centroid set shifted. The reference is auto-
    bootstrapped from the current run when no reference exists, and refreshed
    in-place when `refresh_reference=True`. Stale references (dim mismatch or
    scalar_weight delta) fall back to in-run scoring with a logged warning.

    IP-layer caveat: the IP-layer scalar block is variable-width (country and
    ASN vocabularies vary per run), so reference docs carry the pure-embedding
    centroid only. Per-doc novelty for the IP layer therefore scores against
    pure references — the across-run Heisenbug risk for IPs is documented and
    accepted.
    """
    require_cluster_deps()

    t_start = time.monotonic()

    doc_ids: list[str] = []
    embeddings_list: list[list[float]] = []
    labels_list: list[str] = []  # human-readable label per doc (e.g. command text, session_id)
    scalars_list: list[dict] = []

    for doc_id, emb, label, scalars in docs_iter:
        doc_ids.append(doc_id)
        embeddings_list.append(emb)
        labels_list.append(label)
        scalars_list.append(scalars)

    n_docs = len(doc_ids)
    log.info("[%s] Fetched %d docs with embeddings", layer_label, n_docs)

    if n_docs < min_cluster_size:
        log.warning(
            "[%s] Too few docs (%d) for clustering (min_cluster_size=%d); skipping",
            layer_label, n_docs, min_cluster_size,
        )
        return {
            "docs_fetched": n_docs, "status": "skipped_too_few",
            "window_days": int(window_days or 0), "dry_run": dry_run,
        }

    matrix = np.array(embeddings_list, dtype=np.float32)
    del embeddings_list
    normalized = l2_normalize(matrix)
    del matrix

    cluster_matrix = normalized
    if scalar_weight > 0.0:
        scalar_block = scalar_block_builder(scalars_list, scalar_weight)
        cluster_matrix = np.hstack([normalized, scalar_block])
        log.info(
            "[%s] scalar augmentation: weight=%.3f matrix shape=%s",
            layer_label, scalar_weight, cluster_matrix.shape,
        )
    del scalars_list

    # ``cluster_fn`` hook (E4.4 late-fusion adoption): when provided,
    # the caller supplies the clusterer instead of the default HDBSCAN
    # pass. The hook returns ``(cluster_labels_arr,
    # outlier_flags_override)``:
    #   * cluster_labels_arr — per-doc cluster ids. May or may not use
    #     -1 as a noise marker depending on the algorithm (Agglomerative
    #     fusion never does; the embedding HDBSCAN inside fusion still
    #     does, but its result is surfaced via outlier_flags_override).
    #   * outlier_flags_override — optional bool array (length n_docs).
    #     When set, takes precedence over ``labels == -1`` for the
    #     ``cluster.is_outlier`` output and the ``n_outliers`` stat.
    #     Lets fusion mode preserve the embedding-HDBSCAN's noise
    #     concept for downstream (novelty / rescue / outlier_burst)
    #     without changing the production cluster.id semantics that
    #     non-noise sessions enjoy.
    outlier_flags_override: Optional["np.ndarray"] = None
    # P1.3 — refuse (or fall back) before the O(N^2) late-fusion path runs at a
    # size that would hang. No-op for HDBSCAN (cluster_fn is None) or no ceiling.
    if cluster_fn is not None and _fusion_over_ceiling(
        n_docs, fusion_max_docs, accept_fallback=accept_fallback,
        layer_label=layer_label,
    ):
        cluster_fn = None
    if cluster_fn is None:
        log.info(
            "[%s] Running HDBSCAN (min_cluster_size=%d, min_samples=%d) on %d docs ...",
            layer_label, min_cluster_size, min_samples, n_docs,
        )
        clusterer = _HDBSCAN(
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
            metric="euclidean",
        )
        cluster_labels_arr = clusterer.fit_predict(cluster_matrix)
    else:
        log.info(
            "[%s] Running provided cluster_fn on %d docs (HDBSCAN replaced)",
            layer_label, n_docs,
        )
        cluster_labels_arr, outlier_flags_override = cluster_fn(
            cluster_matrix=cluster_matrix,
            normalized=normalized,
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
        )

    # Optional noise rescue (session layer): reassign outliers within
    # `rescue_threshold` pure-embedding cosine of a cluster centroid. Closes the
    # blind spot in the centroid-level merge, which never sees noise points.
    # Runs before centroid/size/novelty computation so all downstream data
    # reflects the rescued membership. Default off → command/IP layers unchanged.
    #
    # Rescue is skipped in cluster_fn mode (e.g. fusion) — the override
    # already encodes which sessions count as outliers, and reassigning
    # them to the nearest centroid would silently mutate that
    # contract. Fusion mode's "every session gets a cluster_id"
    # property makes the rescue irrelevant by construction.
    n_rescued = 0
    if rescue_threshold is not None and rescue_threshold > 0.0 and cluster_fn is None:
        cluster_labels_arr, n_rescued = rescue_noise_points(
            normalized, cluster_labels_arr, rescue_threshold,
        )
        if n_rescued:
            log.info(
                "[%s] noise rescue: reassigned %d outlier(s) to nearest centroid "
                "(cosine >= %.3f)", layer_label, n_rescued, rescue_threshold,
            )
    elif rescue_threshold is not None and rescue_threshold > 0.0:
        log.info(
            "[%s] noise rescue: skipped (cluster_fn override present)",
            layer_label,
        )

    unique_labels = [int(l) for l in np.unique(cluster_labels_arr)]
    valid_cluster_ids = [l for l in unique_labels if l >= 0]
    n_clusters = len(valid_cluster_ids)
    if outlier_flags_override is not None:
        n_outliers = int(np.asarray(outlier_flags_override, dtype=bool).sum())
    else:
        n_outliers = int(np.sum(cluster_labels_arr == -1))
    log.info(
        "[%s] %s: %d clusters, %d outliers",
        layer_label, "HDBSCAN" if cluster_fn is None else "cluster_fn",
        n_clusters, n_outliers,
    )

    # Pure-embedding centroids — persisted to ES for triage / external use.
    centroids = compute_centroids(normalized, cluster_labels_arr)
    # Augmented-space centroids — used for in-run novelty scoring so the
    # score reflects the same geometry HDBSCAN clustered on. When
    # scalar_weight==0 the two are identical; share the dict to save the
    # extra pass over the matrix.
    if scalar_weight > 0.0:
        centroids_for_novelty = compute_centroids(cluster_matrix, cluster_labels_arr)
    else:
        centroids_for_novelty = centroids

    # Resolve reference centroids. The "scoring centroids" determine whether
    # per-doc novelty is comparable across runs.
    #   - score_in_augmented: True → score cluster_matrix[i]; False → normalized[i].
    #   - score_centroids:    dict[int, np.ndarray]; values are what novelty_score iterates.
    #   - bootstrap_reference: True → write this run's centroids as the new ref.
    persist_augmented = scalar_weight > 0.0
    embedding_dims = int(normalized.shape[1])
    augmented_dims = int(cluster_matrix.shape[1]) if persist_augmented else embedding_dims

    reference_status = "disabled"
    reference_generation: int | None = None
    reference_age_days: float | None = None
    bootstrap_reference = False
    score_in_augmented = persist_augmented
    score_centroids = centroids_for_novelty

    if bootstrap_reference_now:
        # Explicit operator request: mint a new ref generation for this
        # `reference_source` regardless of what already exists for it.
        # In-run scoring uses this run's own centroids — the external
        # ref doesn't make sense as a novelty target for itself.
        reference_status = "bootstrap"
        bootstrap_reference = True
    elif use_reference:
        ref = load_reference_centroids(
            es, clusters_index, reference_source=reference_source,
        ) if not dry_run else {}
        if not ref:
            reference_status = "bootstrap"
            bootstrap_reference = True
        else:
            reason = _validate_reference(
                ref,
                current_embedding_dims=embedding_dims,
                current_augmented_dims=augmented_dims,
                current_scalar_weight=scalar_weight,
                expects_augmented=persist_augmented,
            )
            if reason:
                log.warning(
                    "[%s] reference_centroid set (generation=%s) invalid (%s); "
                    "falling back to in-run scoring. Run `cluster %s --refresh-reference` to refresh.",
                    layer_label, ref.get("generation"), reason, layer_label,
                )
                reference_status = f"stale_{reason}"
                reference_generation = ref.get("generation")
            else:
                # Build np-array centroid dict matching the space we'll score in.
                if persist_augmented and ref.get("augmented"):
                    score_centroids = {
                        i: np.asarray(v, dtype=np.float32)
                        for i, v in enumerate(ref["augmented"])
                    }
                    score_in_augmented = True
                else:
                    score_centroids = {
                        i: np.asarray(v, dtype=np.float32)
                        for i, v in enumerate(ref["pure"])
                    }
                    score_in_augmented = False
                reference_status = "active"
                reference_generation = ref.get("generation")
                reference_age_days = ref.get("age_days")
                if reference_age_days is not None and reference_age_days > reference_max_age_days:
                    log.warning(
                        "[%s] reference_centroid age %.1fd exceeds max_age %dd; "
                        "consider `cluster %s --refresh-reference`.",
                        layer_label, reference_age_days, reference_max_age_days, layer_label,
                    )

    if refresh_reference:
        # Operator forced a refresh — write this run's centroids as the new
        # reference AND score this run against them (identical scores because
        # ref==current). Overrides bootstrap/active.
        bootstrap_reference = True
        reference_status = "refreshed"
        score_centroids = centroids_for_novelty
        score_in_augmented = persist_augmented

    # Dual novelty (brutal-review 5.5) — alongside the in-corpus
    # `novelty_score`, score each doc against the external reference set
    # (if one exists for this layer) and emit `novelty_score_external`.
    # Only attempted on regular live-data runs; skipped during external
    # bootstrap (self-scoring the corpus against itself is meaningless)
    # and during dry-runs.
    score_centroids_external: dict | None = None
    score_external_in_augmented = False
    reference_external_status = "disabled"
    reference_external_generation: int | None = None
    if (
        use_reference
        and not bootstrap_reference_now
        and not dry_run
    ):
        ref_ext = load_reference_centroids(
            es, clusters_index, reference_source="external",
        )
        if ref_ext:
            reason_ext = _validate_reference(
                ref_ext,
                current_embedding_dims=embedding_dims,
                current_augmented_dims=augmented_dims,
                current_scalar_weight=scalar_weight,
                expects_augmented=persist_augmented,
            )
            if reason_ext:
                log.warning(
                    "[%s] external reference (gen=%s) invalid (%s); "
                    "novelty_score_external will be omitted this run",
                    layer_label, ref_ext.get("generation"), reason_ext,
                )
                reference_external_status = f"stale_{reason_ext}"
                reference_external_generation = ref_ext.get("generation")
            else:
                if persist_augmented and ref_ext.get("augmented"):
                    score_centroids_external = {
                        i: np.asarray(v, dtype=np.float32)
                        for i, v in enumerate(ref_ext["augmented"])
                    }
                    score_external_in_augmented = True
                else:
                    score_centroids_external = {
                        i: np.asarray(v, dtype=np.float32)
                        for i, v in enumerate(ref_ext["pure"])
                    }
                    score_external_in_augmented = False
                reference_external_status = "active"
                reference_external_generation = ref_ext.get("generation")
                log.info(
                    "[%s] dual novelty active: external ref gen=%d, %d centroids",
                    layer_label, reference_external_generation,
                    len(score_centroids_external),
                )

    sample_map: dict[int, list[str]] = {lbl: [] for lbl in valid_cluster_ids}
    for lbl, label_text in zip(cluster_labels_arr, labels_list):
        lbl = int(lbl)
        if lbl >= 0 and len(sample_map[lbl]) < sample_size:
            sample_map[lbl].append(label_text)

    now_str = datetime.now(timezone.utc).isoformat()
    run_id = str(uuid.uuid4())

    update_actions: list[dict] = []
    for i, (doc_id, lbl) in enumerate(zip(doc_ids, cluster_labels_arr)):
        lbl = int(lbl)
        if outlier_flags_override is not None:
            # Fusion / cluster_fn mode: outliers are decided by the
            # override (sourced from the embedding-only HDBSCAN inside
            # fusion), independent of the fused cluster_labels_arr.
            # Every session still gets a cluster_id from the fusion
            # result; outliers don't get the legacy "outlier" sentinel
            # — downstream consumers should filter on cluster.is_outlier
            # instead of pattern-matching the id string.
            is_outlier = bool(outlier_flags_override[i])
            cluster_id = f"cluster_{lbl}"
            doc_vec = cluster_matrix[i] if score_in_augmented else normalized[i]
            score = novelty_score(doc_vec, score_centroids)
        else:
            is_outlier = lbl < 0
            cluster_id = "outlier" if is_outlier else f"cluster_{lbl}"
            if is_outlier:
                score = 1.0
            else:
                doc_vec = cluster_matrix[i] if score_in_augmented else normalized[i]
                score = novelty_score(doc_vec, score_centroids)
        params: dict = {
            "cluster_id":    cluster_id,
            "novelty_score": round(score, 6),
            "is_outlier":    is_outlier,
            "scored_at":     now_str,
        }
        # Dual novelty (5.5): when an external reference is loaded, score
        # every doc against it too. Outliers get max novelty (1.0) against
        # both refs by convention — HDBSCAN already said "nothing in this
        # corpus claims you".
        # External-match attribution (5.9): also record WHICH external
        # centroid was the closest match + the raw cosine. Outliers
        # carry no match (they don't claim any centroid).
        if score_centroids_external is not None:
            if is_outlier:
                ext_score = 1.0
                ext_match_idx = None
                ext_match_cos = None
            else:
                ext_vec = (
                    cluster_matrix[i] if score_external_in_augmented
                    else normalized[i]
                )
                # Find the nearest external centroid in one pass — same
                # math as `novelty_score`, but we keep the index of the
                # winning centroid alongside its cosine.
                norm_v = float(np.linalg.norm(ext_vec))
                best_idx = None
                best_sim = -1.0
                if norm_v > 0.0:
                    for idx, c_vec in score_centroids_external.items():
                        norm_c = float(np.linalg.norm(c_vec))
                        if norm_c == 0.0:
                            continue
                        sim = float(np.dot(ext_vec, c_vec)) / (norm_v * norm_c)
                        if sim > best_sim:
                            best_sim = sim
                            best_idx = idx
                ext_score = float(1.0 - max(0.0, best_sim))
                ext_match_idx = best_idx
                ext_match_cos = best_sim if best_idx is not None else None
            params["novelty_score_external"] = round(ext_score, 6)
            if ext_match_idx is not None:
                params["external_match_id"] = f"cluster_{ext_match_idx}"
                params["external_match_cosine"] = round(float(ext_match_cos), 6)
        update_actions.append({
            "_op_type": "update",
            "_id":      doc_id,
            "script": {
                "source": update_script,
                "params": params,
            },
        })
    del cluster_matrix

    cluster_docs: list[dict] = []
    for lbl, centroid_vec in centroids.items():
        cluster_docs.append({
            "_op_type": "index",
            "_source": {
                "@timestamp": now_str,
                "run_id": run_id,
                "doc_type": "cluster",
                "cluster_id": f"cluster_{lbl}",
                "size": int(np.sum(cluster_labels_arr == lbl)),
                "centroid": centroid_vec.tolist(),
                centroid_sample_field: sample_map.get(lbl, []),
            },
        })
    # P3.3 — the run_summary is the run-complete sentinel and is written LAST
    # (after the per-doc cluster.id updates below), not here, so its existence
    # always means "this run's writes finished". Build its body now (all the
    # values are in hand); the final-write block appends the actual write-error
    # counts and the true end-to-end runtime before indexing it.
    run_summary_source: dict = {
        "@timestamp": now_str,
        "run_id": run_id,
        "doc_type": "run_summary",
        "total_docs": n_docs,
        "n_clusters": n_clusters,
        "n_outliers": n_outliers,
        "n_rescued": n_rescued,
        # P1.2 — 0 = all-time (full corpus); >0 = the run only saw sessions
        # from the last N days. The lifecycle tracker reads this off the
        # latest run_summary to decide whether a playbook's absence means
        # "gone from the corpus" (full run) or just "no recent sessions"
        # (windowed run) — only the former advances silent-run accounting.
        "window_days": int(window_days or 0),
        # Effective clustering config this run used — lets a deploy be
        # verified from ES alone (e.g. "did the latest command run cluster
        # with rescue_threshold=0.94?") without shell access to the box.
        # Mappings are dynamic, so these auto-map.
        "clustering_config": {
            "min_cluster_size": min_cluster_size,
            "min_samples": min_samples,
            "scalar_weight": scalar_weight,
            "rescue_threshold": rescue_threshold,
        },
    }

    if bootstrap_reference and not dry_run:
        # Find current max generation FOR THIS SOURCE so the new ref docs
        # sort above existing generations of the same source on read.
        # History is preserved (no delete) — emergency rollback is just
        # `delete by query reference_generation=<new> AND reference_source=<source>`.
        if reference_source is None:
            prev_source_filter = {
                "bool": {"must_not": {"exists": {"field": "reference_source"}}}
            }
        else:
            prev_source_filter = {"term": {"reference_source.keyword": reference_source}}
        try:
            prev_resp = es.search(
                index=clusters_index,
                **{
                    "size": 1,
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"doc_type": "reference_centroid"}},
                                prev_source_filter,
                            ]
                        }
                    },
                    "sort": [{"reference_generation": "desc"}],
                    "_source": ["reference_generation"],
                },
            )
            prev_hits = prev_resp["hits"]["hits"]
            prev_gen = int(prev_hits[0]["_source"].get("reference_generation", 0)) if prev_hits else 0
        except Exception as exc:
            log.warning(
                "[%s] could not read previous reference_generation (%s); starting at 0",
                layer_label, exc,
            )
            prev_gen = 0
        new_gen = prev_gen + 1
        for lbl, centroid_vec in centroids.items():
            ref_src: dict = {
                "@timestamp": now_str,
                "run_id": run_id,
                "doc_type": "reference_centroid",
                "cluster_id": f"cluster_{lbl}",
                "size": int(np.sum(cluster_labels_arr == lbl)),
                "centroid": centroid_vec.tolist(),
                centroid_sample_field: sample_map.get(lbl, []),
                "reference_generation": new_gen,
                "source_run_id": run_id,
                "embedding_dims": embedding_dims,
                "scalar_weight": float(scalar_weight),
                "reference_minted_at": now_str,
            }
            if reference_source is not None:
                ref_src["reference_source"] = reference_source
            if persist_augmented:
                ref_src["centroid_augmented"] = centroids_for_novelty[lbl].tolist()
                ref_src["augmented_dims"] = augmented_dims
            cluster_docs.append({"_op_type": "index", "_source": ref_src})
        reference_generation = new_gen
        log.info(
            "[%s] reference_centroid %s (source=%s): generation=%d, n_clusters=%d, embedding_dims=%d%s",
            layer_label,
            "refresh" if reference_status == "refreshed" else "bootstrap",
            reference_source or "in-corpus",
            new_gen, len(centroids), embedding_dims,
            f", augmented_dims={augmented_dims}" if persist_augmented else "",
        )

    stats: dict = {
        "run_id": run_id,
        "docs_fetched": n_docs,
        "n_clusters": n_clusters,
        "n_outliers": n_outliers,
        "n_rescued": n_rescued,
        "window_days": int(window_days or 0),
        "dry_run": dry_run,
        "reference_status": reference_status,
        "reference_generation": reference_generation,
        "reference_age_days": (
            round(reference_age_days, 2) if reference_age_days is not None else None
        ),
        # Dual novelty (5.5) — null when no external ref is loaded.
        "reference_external_status": reference_external_status,
        "reference_external_generation": reference_external_generation,
    }

    if dry_run:
        log.info("[%s] dry-run: skipping all ES writes", layer_label)
        stats["status"] = "dry_run"
        return stats

    init_index(es, mapping_path, clusters_index)

    # P3.3 — write order makes the run_summary a trustworthy completion sentinel:
    #   1. centroid + reference_centroid docs   (clusters_index)
    #   2. per-doc cluster.id patches            (docs_index)
    #   3. run_summary LAST                      (clusters_index)
    # A crash before step 3 leaves NO run_summary, so a reader that resolves
    # "latest run" via the run_summary (lifecycle, prune, miner) falls back to
    # the previous complete run instead of a half-applied one.
    ok, errs = bulk_write(es, clusters_index, cluster_docs)
    stats["cluster_docs_written"] = ok
    stats["cluster_doc_errors"] = len(errs)
    if errs:
        log.warning("[%s] cluster index bulk errors (%d): %s", layer_label, len(errs), errs[:2])

    bulk_ok = 0
    bulk_errors = 0
    for start in range(0, len(update_actions), batch_size):
        chunk = update_actions[start: start + batch_size]
        ok, errs = bulk_write(es, docs_index, chunk)
        bulk_ok += ok
        bulk_errors += len(errs)
        if errs:
            log.warning("[%s] update errors (%d): %s", layer_label, len(errs), errs[:2])
        log.debug("[%s] Updated %d/%d docs", layer_label, start + len(chunk), n_docs)

    # Step 3 — the run_summary sentinel, written last and stamped with the
    # actual write-error counts (P3.3 + P4 bulk-error surfacing) and the true
    # end-to-end runtime. `write_errors > 0` on the latest run_summary tells a
    # reader the run completed but some docs didn't land, without shell access.
    run_summary_source["cluster_doc_errors"] = stats["cluster_doc_errors"]
    run_summary_source["update_errors"] = bulk_errors
    run_summary_source["write_errors"] = stats["cluster_doc_errors"] + bulk_errors
    run_summary_source["runtime_seconds"] = round(time.monotonic() - t_start, 2)
    rs_ok, rs_errs = bulk_write(
        es, clusters_index, [{"_op_type": "index", "_source": run_summary_source}],
    )
    if rs_errs:
        # The sentinel itself failed to write — better to surface loudly than to
        # leave readers resolving a stale run with no signal that this one ran.
        log.warning("[%s] run_summary write failed (%d): %s", layer_label, len(rs_errs), rs_errs[:1])
    stats["run_summary_written"] = rs_ok

    # Explicit refresh on both indexes we just wrote to. The mapping default
    # is refresh_interval=30s, which would otherwise leave a window where
    # the next pipeline step starts before ES has made the writes visible
    # — silently breaking the chain:
    #   cluster sessions -> name playbooks would find 0 centroids
    #   cluster commands -> escalate would find 0 commands with novelty
    #   cluster ips      -> any reader would see stale cluster.id values
    try:
        es.indices.refresh(index=f"{clusters_index},{docs_index}")
    except Exception as exc:
        log.warning("[%s] post-cluster refresh failed (continuing): %s", layer_label, exc)

    stats["docs_updated"] = bulk_ok
    stats["bulk_errors"] = bulk_errors
    stats["runtime_seconds"] = round(time.monotonic() - t_start, 2)
    stats["docs_index"] = docs_index
    stats["clusters_index"] = clusters_index
    return stats
