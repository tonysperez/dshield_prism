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
from typing import Callable, Iterator

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


def load_centroids(es: Elasticsearch, clusters_index: str) -> list[list[float]]:
    """Load pure-embedding centroid vectors. Used by triage's novel_embedding rule.

    Prefers `doc_type=reference_centroid` (highest `reference_generation`) for
    stable across-run novelty scores; falls back to the latest `doc_type=cluster`
    run when no reference exists (fresh deploy, pre-bootstrap).

    Returns [] on missing index, no data, or any query failure.
    """
    try:
        if not es.indices.exists(index=clusters_index):
            return []

        ref = load_reference_centroids(es, clusters_index)
        if ref and ref.get("pure"):
            return ref["pure"]

        resp = es.search(
            index=clusters_index,
            **{
                "size": 1,
                "query": {"term": {"doc_type": "cluster"}},
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


def load_reference_centroids(
    es: Elasticsearch, clusters_index: str
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
        }

    The caller is responsible for staleness checks (dim mismatch, scalar_weight
    delta, age). This loader only fetches.
    """
    try:
        if not es.indices.exists(index=clusters_index):
            return {}

        # Find max generation. `reference_generation` is a `long` and sorts cleanly.
        resp = es.search(
            index=clusters_index,
            **{
                "size": 1,
                "query": {"term": {"doc_type": "reference_centroid"}},
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
      8. Bulk-update doc cluster fields via update_script.
      9. Persist pure-embedding centroids + run_summary docs to clusters_index.
     10. Auto-bootstrap or refresh the reference_centroid set if asked / needed.

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
        return {"docs_fetched": n_docs, "status": "skipped_too_few", "dry_run": dry_run}

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

    unique_labels = [int(l) for l in np.unique(cluster_labels_arr)]
    valid_cluster_ids = [l for l in unique_labels if l >= 0]
    n_clusters = len(valid_cluster_ids)
    n_outliers = int(np.sum(cluster_labels_arr == -1))
    log.info("[%s] HDBSCAN: %d clusters, %d outliers", layer_label, n_clusters, n_outliers)

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

    if use_reference:
        ref = load_reference_centroids(es, clusters_index) if not dry_run else {}
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
        is_outlier = lbl < 0
        cluster_id = "outlier" if is_outlier else f"cluster_{lbl}"
        if is_outlier:
            score = 1.0
        else:
            doc_vec = cluster_matrix[i] if score_in_augmented else normalized[i]
            score = novelty_score(doc_vec, score_centroids)
        update_actions.append({
            "_op_type": "update",
            "_id": doc_id,
            "script": {
                "source": update_script,
                "params": {
                    "cluster_id": cluster_id,
                    "novelty_score": round(score, 6),
                    "is_outlier": is_outlier,
                    "scored_at": now_str,
                },
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
    cluster_docs.append({
        "_op_type": "index",
        "_source": {
            "@timestamp": now_str,
            "run_id": run_id,
            "doc_type": "run_summary",
            "total_docs": n_docs,
            "n_clusters": n_clusters,
            "n_outliers": n_outliers,
            "runtime_seconds": round(time.monotonic() - t_start, 2),
        },
    })

    if bootstrap_reference and not dry_run:
        # Find current max generation so the new ref docs sort above existing
        # generations on read. History is preserved (no delete) — emergency
        # rollback is just `delete by query reference_generation=<new>`.
        try:
            prev_resp = es.search(
                index=clusters_index,
                **{
                    "size": 1,
                    "query": {"term": {"doc_type": "reference_centroid"}},
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
            if persist_augmented:
                ref_src["centroid_augmented"] = centroids_for_novelty[lbl].tolist()
                ref_src["augmented_dims"] = augmented_dims
            cluster_docs.append({"_op_type": "index", "_source": ref_src})
        reference_generation = new_gen
        log.info(
            "[%s] reference_centroid %s: generation=%d, n_clusters=%d, embedding_dims=%d%s",
            layer_label,
            "refresh" if reference_status == "refreshed" else "bootstrap",
            new_gen, len(centroids), embedding_dims,
            f", augmented_dims={augmented_dims}" if persist_augmented else "",
        )

    stats: dict = {
        "run_id": run_id,
        "docs_fetched": n_docs,
        "n_clusters": n_clusters,
        "n_outliers": n_outliers,
        "dry_run": dry_run,
        "reference_status": reference_status,
        "reference_generation": reference_generation,
        "reference_age_days": (
            round(reference_age_days, 2) if reference_age_days is not None else None
        ),
    }

    if dry_run:
        log.info("[%s] dry-run: skipping all ES writes", layer_label)
        stats["status"] = "dry_run"
        return stats

    init_index(es, mapping_path, clusters_index)

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
