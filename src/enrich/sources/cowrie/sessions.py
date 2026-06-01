"""Cowrie session layer: rollup, clustering, and playbook naming.

rollup-sessions: aggregate events per cowrie.session.closed into one session doc.
cluster-sessions: HDBSCAN over session embeddings (delegates to clustering core).
name-playbooks:   local LLM names each session cluster (a "playbook").
"""
from __future__ import annotations

import hashlib
import logging
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Iterator, Optional

if TYPE_CHECKING:
    import numpy as np

from elasticsearch import Elasticsearch

from ...cache import StateDB
from ...config import AppConfig, Secrets, SessionConfig
from ...es_client import bulk_write, make_client
from ...llm.schemas import (
    PLAYBOOK_DISAMBIGUATE_JSON_SCHEMA,
    PLAYBOOK_NAME_JSON_SCHEMA,
    PlaybookDisambiguation,
    PlaybookName,
)
from .commands import hash_command, normalize

log = logging.getLogger(__name__)

_SESSION_WATERMARK_KEY = "session_last_processed_at"
_SESSIONS_MAPPING = "setup/es-mappings/cowrie/sessions.json"
_SESSION_CLUSTERS_MAPPING = "setup/es-mappings/cowrie/session_clusters.json"

# Fixed corpus-scale denominators for the log1p-normalized scalar block,
# replacing the previous per-batch `np.max(...)` (ROADMAP #14). Per-batch
# normalization meant the same session yielded different scalar contributions
# across re-runs purely because a bigger neighbour appeared. These constants
# are chosen well above the long-term P99.9 observed in production
# (command_count P99.9 ≈ 10 today, max ≈ 20 — 1000 leaves headroom for
# unusually-long future sessions). The block output is clipped to [0, 1]
# so a future outlier above the denominator doesn't blow the normalization.
_SCALAR_DENOM_COMMAND_COUNT = 1000.0
_SCALAR_DENOM_UNIQUE_COMMANDS = 1000.0

_SESSION_CLUSTER_UPDATE_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment.session == null) { ctx._source.dshield.cowrie.enrichment.session = [:]; }"
    "def s = ctx._source.dshield.cowrie.enrichment.session;"
    "if (s.cluster == null) { s.cluster = [:]; }"
    "s.cluster.id = params.cluster_id;"
    "s.cluster.novelty_score = params.novelty_score;"
    "s.cluster.is_outlier = params.is_outlier;"
    "s.cluster.scored_at = params.scored_at;"
    # Re-clustering invalidates any playbook label on this session — the old
    # name was attached to a different clustering run. Clear so downstream
    # readers see "no playbook" until `name playbooks` reruns and refills
    # both fields from the new centroid. Otherwise session.playbook_id
    # would point at a stale playbook whose membership no longer matches
    # the new session.cluster.id.
    "s.remove('playbook_id');"
    "s.remove('playbook_name');"
)

_SESSION_PLAYBOOK_NAME_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment.session == null) { ctx._source.dshield.cowrie.enrichment.session = [:]; }"
    "ctx._source.dshield.cowrie.enrichment.session.playbook_id = params.playbook_id;"
    "ctx._source.dshield.cowrie.enrichment.session.playbook_name = params.playbook_name;"
    # Watermark signal for the per-IP rollup. `@timestamp` is the session's
    # real event time and must not move; this is a side-channel "the playbook
    # attribution on this doc was (re)written at" timestamp that
    # `_iter_updated_session_ips` ORs against to pick up newly-named sessions.
    "ctx._source.dshield.cowrie.enrichment.session.playbook_named_at = params.now;"
)


_PLAYBOOK_ID_HASH_LEN = 16


def _compute_seed_id(member_session_ids: Iterable[str]) -> str:
    """Reproducible internal seed for anchor assignment. Format: `sescl-<16-hex>`.

    SHA-256 of the playbook's member session ids, sorted and joined with
    newline. Used only to feed `_mint_playbook_id` when a centroid has no
    anchor match — two runs with identical membership and no prior anchor
    yield the same fresh id. The seed is also stored on the anchor doc as
    `seed_playbook_id` for audit ("this anchor was first minted from this
    exact membership"); nothing else reads it.

    Empty membership raises — outlier clusters are filtered upstream.
    """
    sids = sorted(set(s for s in member_session_ids if s))
    if not sids:
        raise ValueError("_compute_seed_id requires at least one session id")
    digest = hashlib.sha256("\n".join(sids).encode("utf-8")).hexdigest()
    return f"sescl-{digest[:_PLAYBOOK_ID_HASH_LEN]}"


# ===========================================================================
# Playbook identity — cosine-anchored
#
# Each playbook's `playbook_id` (`spb-<16hex>`) is assigned by matching the
# playbook's mean-centroid against pinned anchors in the write-once
# `playbook_anchors` index. A match (cosine >= playbook_merge_threshold)
# reuses the anchor's id; a miss mints a fresh id from the membership seed
# and pins a new anchor.
#
# Matching against a FIXED reference (not a walking centroid) is what keeps
# the id stable across membership changes — a walking anchor lets transitive
# chains form (A~B>=thr, B~C>=thr, A~C<thr collapsing under one id). The
# pass-2 name-merge does NOT touch the id: naming is a display concern,
# cosine identity is a separate axis.
# ===========================================================================

_PLAYBOOK_ID_PREFIX = "spb-"


def _mint_playbook_id(seed_id: str) -> str:
    """Mint a fresh `spb-<16hex>` id from a membership seed. Deterministic:
    re-running the same membership through `_compute_seed_id` yields the
    same `spb-` id, so re-pinning an anchor after a purge produces the same
    canonical id when membership is identical."""
    digest = hashlib.sha256(seed_id.encode("utf-8")).hexdigest()
    return f"{_PLAYBOOK_ID_PREFIX}{digest[:_PLAYBOOK_ID_HASH_LEN]}"


def _unit_vector(vec) -> "np.ndarray":
    import numpy as np
    arr = np.asarray(vec, dtype=np.float32)
    norm = float(np.linalg.norm(arr))
    return arr if norm == 0.0 else arr / norm


def _playbook_group_centroid(member_docs: list[dict]) -> Optional["np.ndarray"]:
    """Size-weighted mean of the member clusters' centroids, L2-normalised.
    Returns None when no member carries a usable centroid."""
    import numpy as np
    vecs, weights = [], []
    for c in member_docs:
        cen = c.get("centroid")
        if isinstance(cen, list) and cen:
            vecs.append(np.asarray(cen, dtype=np.float32))
            weights.append(float(c.get("size") or 1))
    if not vecs:
        return None
    mean = np.average(np.vstack(vecs), axis=0, weights=weights)
    return _unit_vector(mean)


# ===========================================================================
# Cluster specificity (ROADMAP #4)
#
# How distinctive is an IP / command to a behaviour cluster vs the rest of the
# corpus? An IDF-shape score: a key that appears in only one cluster scores
# ~1.0; one that spans ~every cluster scores ~0. Persisted per centroid doc as
# `ip_specificity` / `command_specificity` flattened maps so the console drawer
# + `/distinctive` pivot read it directly (no per-open aggregation).
# ===========================================================================

_SESSION_CLUSTER_ID_FIELD = "dshield.cowrie.enrichment.session.cluster.id"
_SESSION_COMMAND_SET_FIELD = "dshield.cowrie.enrichment.session.command_set.keyword"


def specificity_scores(
    df_by_key: dict[str, int], total_clusters: int,
) -> dict[str, float]:
    """Normalized IDF specificity in [0, 1] for each key, given how many
    clusters it appears in (`df`) and the total cluster count.

    `score = ln(C/df) / ln(C)` — a key in one cluster scores exactly 1.0, a
    key spanning every cluster scores 0. No `+1` smoothing: the "df=1 →
    almost-1" ceiling produced by Laplace smoothing didn't match the
    intuition that *appears in only this cluster* IS the maximum signal.
    Degenerate `C <= 1` returns zeros (one cluster ⇒ nothing distinctive).
    Pure/offline (reused by ROADMAP #5)."""
    import math
    if total_clusters <= 1 or not df_by_key:
        return {k: 0.0 for k in df_by_key}
    denom = math.log(total_clusters)
    out: dict[str, float] = {}
    for k, df in df_by_key.items():
        d = max(1, int(df))
        score = math.log(total_clusters / d) / denom
        out[k] = round(max(0.0, min(1.0, score)), 3)
    return out


def _persist_cluster_specificity(
    es: Elasticsearch, sessions_idx: str, clusters_idx: str,
    run_id: str, cap: int,
) -> dict:
    """Compute per-cluster `ip_specificity` / `command_specificity` for this
    run and write the maps onto every `doc_type=cluster` centroid doc.

    One aggregation pass with three siblings:
      - corpus `df_ip`, `df_cmd`  — how many distinct clusters each IP /
        command appears in. MUST be top-level: putting the `cardinality`
        sub-agg under the per-cluster terms bucket scopes it to that single
        cluster and returns 1 for every key.
      - per-cluster `by_cluster` — the member IPs and commands of each
        cluster, taken straight from the rollup; we look up each member's
        corpus-wide df from the sibling aggs to compute the score."""
    stats = {"clusters_scored": 0, "centroids_updated": 0}
    base = {"bool": {
        "must": [{"exists": {"field": _SESSION_CLUSTER_ID_FIELD}}],
        "must_not": [{"term": {_SESSION_CLUSTER_ID_FIELD: "outlier"}}],
    }}
    try:
        resp = es.search(
            index=sessions_idx, size=0, query=base,
            aggs={
                "total_clusters": {"cardinality": {"field": _SESSION_CLUSTER_ID_FIELD}},
                "df_ip": {
                    "terms": {"field": "source.ip", "size": 100000},
                    "aggs": {"dfc": {"cardinality": {"field": _SESSION_CLUSTER_ID_FIELD}}},
                },
                "df_cmd": {
                    "terms": {"field": _SESSION_COMMAND_SET_FIELD, "size": 100000},
                    "aggs": {"dfc": {"cardinality": {"field": _SESSION_CLUSTER_ID_FIELD}}},
                },
                "by_cluster": {
                    "terms": {"field": _SESSION_CLUSTER_ID_FIELD, "size": 20000},
                    "aggs": {
                        "ips":  {"terms": {"field": "source.ip", "size": cap}},
                        "cmds": {"terms": {"field": _SESSION_COMMAND_SET_FIELD, "size": cap}},
                    },
                },
            },
        )
    except Exception as exc:  # noqa: BLE001 — specificity is best-effort
        log.warning("specificity: aggregation failed (continuing): %s", exc)
        return stats

    aggs = resp.get("aggregations", {})
    total_clusters = int(aggs.get("total_clusters", {}).get("value", 0) or 0)
    df_ip = {b["key"]: int(b["dfc"]["value"])
             for b in aggs.get("df_ip", {}).get("buckets", [])}
    df_cmd = {b["key"]: int(b["dfc"]["value"])
              for b in aggs.get("df_cmd", {}).get("buckets", [])}

    spec_by_cid: dict[str, tuple[dict, dict]] = {}
    for b in aggs.get("by_cluster", {}).get("buckets", []):
        cid = b["key"]
        # Members of THIS cluster, scored against corpus-wide df.
        ip_df = {x["key"]: df_ip.get(x["key"], 1) for x in b["ips"]["buckets"]}
        cmd_df = {x["key"]: df_cmd.get(x["key"], 1) for x in b["cmds"]["buckets"]}
        spec_by_cid[cid] = (
            specificity_scores(ip_df, total_clusters),
            specificity_scores(cmd_df, total_clusters),
        )
        stats["clusters_scored"] += 1
    if not spec_by_cid:
        return stats

    # Map cluster_id -> centroid doc _id(s) for this run, then bulk-update.
    actions: list[dict] = []
    try:
        cresp = es.search(
            index=clusters_idx, size=10000,
            _source=["cluster_id"],
            query={"bool": {"must": [
                {"term": {"doc_type": "cluster"}},
                {"term": {"run_id": run_id}},
            ]}},
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("specificity: centroid scan failed (continuing): %s", exc)
        return stats
    for h in cresp["hits"]["hits"]:
        cid = h["_source"].get("cluster_id")
        spec = spec_by_cid.get(cid)
        if not spec:
            continue
        actions.append({
            "_op_type": "update",
            "_id": h["_id"],
            "doc": {"ip_specificity": spec[0], "command_specificity": spec[1]},
        })
    if actions:
        ok, errs = bulk_write(es, clusters_idx, actions)
        stats["centroids_updated"] = ok
        if errs:
            log.warning("specificity: %d centroid update errors: %s", len(errs), errs[:2])
    return stats


def _load_playbook_anchors(
    es: Elasticsearch, anchor_idx: str,
) -> list[tuple["np.ndarray", str]]:
    """Load every pinned anchor from the write-once `playbook_anchors`
    index — one `(centroid, playbook_id)` pair per known id. The naming
    pass needs the full set in memory to match each playbook's centroid
    against every prior anchor. Raises on query failure: the anchors are
    load-bearing, silent fallback would mint duplicate ids."""
    resp = es.search(
        index=anchor_idx,
        size=10000,
        query={"exists": {"field": "anchor_centroid"}},
        _source=["playbook_id", "anchor_centroid"],
    )
    anchors: list[tuple["np.ndarray", str]] = []
    for h in resp.get("hits", {}).get("hits", []):
        s = h["_source"]
        cen = s.get("anchor_centroid")
        pid = s.get("playbook_id") or h.get("_id")
        if isinstance(cen, list) and cen and pid:
            anchors.append((_unit_vector(cen), pid))
    return anchors


def _persist_playbook_anchor(
    es: Elasticsearch, anchor_idx: str, playbook_id: str,
    unit: "np.ndarray", seed_id: str, run_id: str,
) -> None:
    """Pin the centroid of a freshly-minted playbook id. Idempotent on
    `_id = playbook_id`: re-running the same membership through a clean
    anchor index overwrites with the same centroid rather than
    duplicating. Called only on a mint (no anchor matched), never on
    reuse — the anchor stays fixed for the id's lifetime."""
    from datetime import datetime, timezone
    es.index(
        index=anchor_idx,
        id=playbook_id,
        document={
            "playbook_id": playbook_id,
            "anchor_centroid": [float(x) for x in unit],
            "seed_playbook_id": seed_id,
            "first_run_id": run_id,
            "first_seen": datetime.now(timezone.utc).isoformat(),
        },
    )


def _assign_playbook_id(
    group_unit: "np.ndarray",
    anchors: list[tuple["np.ndarray", str]],
    threshold: float,
    seed_id: str,
) -> str:
    """Reuse the nearest anchor's id when cosine >= threshold; otherwise
    mint a fresh id from the membership seed. `group_unit` and anchor
    vectors are unit-normalised, so the dot product is cosine similarity."""
    import numpy as np
    if anchors:
        sims = np.array([float(a @ group_unit) for a, _ in anchors])
        j = int(np.argmax(sims))
        if float(sims[j]) >= threshold:
            return anchors[j][1]
    return _mint_playbook_id(seed_id)


def merge_clusters_into_playbooks(
    centroids: dict[str, list[float]],
    threshold: float,
) -> dict[str, str]:
    """Group HDBSCAN cluster centroids into playbooks via complete-linkage
    hierarchical clustering on cosine distance.

    L2-normalises each centroid, runs agglomerative clustering with
    `method='complete'` over the pairwise cosine-distance matrix, and cuts
    the dendrogram at distance `1 - threshold`. A group forms only when
    *every* pairwise sim among its members clears the threshold, so a
    chain of borderline edges (A~B, B~C at threshold but A~C far below)
    cannot bridge unrelated centroids into one playbook — the failure
    mode that the previous single-linkage + post-validation guard tried
    to patch all-or-nothing.

    Returns `{cluster_id -> group_id}` where group_id is `pg<N>`, with
    groups numbered deterministically by their lex-smallest member.

    `threshold = 1.0` only merges centroids that are bit-identical (cutoff
    distance = 0). Empty input → empty dict; a single centroid → one
    `pg0`. Outliers must be filtered upstream — they have no centroid.
    """
    import numpy as np
    from scipy.cluster.hierarchy import fcluster, linkage
    from scipy.spatial.distance import squareform

    if not centroids:
        return {}

    cluster_ids = sorted(centroids.keys())
    n = len(cluster_ids)

    if n == 1:
        return {cluster_ids[0]: "pg0"}

    M = np.array([centroids[cid] for cid in cluster_ids], dtype=np.float32)
    norms = np.linalg.norm(M, axis=1, keepdims=True)
    norms = np.where(norms == 0.0, 1.0, norms)
    Mn = M / norms
    sim = Mn @ Mn.T
    dist = np.clip(1.0 - sim, 0.0, 2.0)
    np.fill_diagonal(dist, 0.0)
    condensed = squareform(dist, checks=False)

    Z = linkage(condensed, method="complete")
    cutoff = max(0.0, 1.0 - float(threshold))
    labels = fcluster(Z, t=cutoff, criterion="distance")

    by_label: dict[int, list[str]] = {}
    for cid, lbl in zip(cluster_ids, labels):
        by_label.setdefault(int(lbl), []).append(cid)

    # Members are already lex-sorted (input was sorted). Number groups by
    # lex-smallest member for stable cross-run ids.
    groups = sorted(by_label.values(), key=lambda members: members[0])

    out: dict[str, str] = {}
    for gidx, members in enumerate(groups):
        gid = f"pg{gidx}"
        for cid in members:
            out[cid] = gid
    return out


_SESSION_CLUSTER_SAMPLE_SIZE = 5


# ---------------------------------------------------------------------------
# Rollup: collect events + build session doc
# ---------------------------------------------------------------------------

def _iter_closed_sessions(
    es: Elasticsearch,
    index: str,
    since: Optional[str],
    page_size: int = 1000,
) -> Iterator[tuple[str, str]]:
    """Yield (session_id, closed_at) for cowrie.session.closed events after `since`."""
    must: list[dict] = [{"term": {"event.action": "cowrie.session.closed"}}]
    if since:
        must.append({"range": {"@timestamp": {"gt": since}}})

    body: dict = {
        "size": page_size,
        "_source": ["cowrie.session_id", "@timestamp"],
        "query": {"bool": {"must": must}},
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
            src = h["_source"]
            session_id = (src.get("cowrie") or {}).get("session_id")
            ts = src.get("@timestamp")
            if session_id and ts:
                yield session_id, ts
        search_after = hits[-1]["sort"]


def _fetch_session_events(
    es: Elasticsearch,
    index: str,
    session_ids: list[str],
    page_size: int = 1000,
) -> dict[str, list[dict]]:
    """Fetch all events for the given session_ids. Returns {session_id: [event_sources]}."""
    result: dict[str, list[dict]] = {sid: [] for sid in session_ids}

    body: dict = {
        "size": page_size,
        "_source": [
            "@timestamp", "event.action", "event.duration", "event.outcome",
            "source.ip", "source.port", "source.geo", "source.as",
            "destination.ip", "destination.port",
            "network.protocol", "network.type",
            "user.name", "user_agent.original",
            "cowrie.session_id", "cowrie.password", "cowrie.hassh_algorithms",
            "cowrie.hassh",
            "process.command_line",
            # File-event hashes (ROADMAP #3). The ingest pipeline already
            # structures the cowrie shasum at `file.hash.sha256`; `destfile`
            # (download dest) / `filename` (upload name) give the attacker-
            # facing name; `url.original` is present only for wget-style fetches.
            "file.hash.sha256", "url.original",
            "cowrie.destfile", "cowrie.filename",
        ],
        "query": {"terms": {"cowrie.session_id": session_ids}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }

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
            sid = (src.get("cowrie") or {}).get("session_id")
            if sid and sid in result:
                result[sid].append(src)
        search_after = hits[-1]["sort"]

    return result


def _mget_enrichment(
    es: Elasticsearch,
    index: str,
    hashes: list[str],
) -> dict[str, dict]:
    """Batch-fetch enrichment docs by command hash. Returns {hash: source}."""
    if not hashes:
        return {}
    resp = es.mget(index=index, ids=hashes)
    return {doc["_id"]: doc["_source"] for doc in resp["docs"] if doc.get("found")}


def _summarize_intents(
    intents: list[str], top_n: int = 3
) -> tuple[Optional[str], list[dict]]:
    """Return `(dominant_intent, intent_distribution)` from a list of intent
    labels. The distribution is the top-N `(intent, count)` pairs sorted by
    `(-count, intent)` so ties resolve lexically — deterministic across runs.

    The previous code used `Counter(intents).most_common(1)[0][0]`, which
    relies on Counter insertion order to break ties. A 2-command session with
    one `reconnaissance` and one `execution` produced a different
    `dominant_intent` depending on whichever order the unique-hash iteration
    happened to surface them in — ROADMAP #15.

    Empty input → `(None, [])`. Used by both session and IP rollups; the IP
    layer composes per-IP intents from per-session `dominant_intent` values
    so this helper fixes both layers in one place.
    """
    if not intents:
        return None, []
    counter = Counter(intents)
    # Lexical tie-break: sort by (-count, name). Counter.most_common is
    # stable but ordering depends on insertion — explicit sort makes ties
    # deterministic regardless of how the input was enumerated.
    pairs = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    distribution = [{"intent": name, "count": count} for name, count in pairs[:top_n]]
    return pairs[0][0], distribution


def _command_entropy(counts: dict[str, int]) -> float:
    """Shannon entropy (bits) of the command frequency distribution."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


# Fixed corpus-scale denominator for the IDF-style pool weight (ROADMAP #19).
# Mirrors `_SCALAR_DENOM_OCCURRENCE_COUNT` from the command-cluster scalar
# block (#14) — chosen well above the long-term P99 of command
# occurrence_count so the weight is stable run-to-run and a future outlier
# above the denominator just clamps to a small positive weight rather than
# going negative.
_POOL_IDF_N = 100000.0


def _idf_pool_weight(occurrence_count: int | float | None) -> float:
    """log((N+1)/(occ+1)) with `occ` clamped to [1, N]. Rare commands get
    big weights; boilerplate gets small. Always positive (>= ~0)."""
    if occurrence_count is None or occurrence_count < 1:
        occurrence_count = 1
    # Clamp the input so a misconfigured corpus that pushed `occ` above N
    # doesn't make the log negative. The output minimum is then 0.
    occ = min(float(occurrence_count), _POOL_IDF_N)
    return math.log((_POOL_IDF_N + 1.0) / (occ + 1.0))


def _mean_pool(
    embeddings: list[list[float]],
    weights: list[float] | None = None,
) -> list[float]:
    """Weighted mean-pool of equal-length float vectors, then L2-normalize.

    Each input is L2-normalized before summing so commands with slightly
    larger embedding norms don't dominate the pooled vector (ROADMAP #13).
    The pooled output is also L2-normalized so direct cosine comparisons
    downstream (kNN, cluster diagnostics, explain page) don't need a "did
    this caller remember to normalize?" footgun.

    When `weights` is supplied, each input's L2-normalized vector is
    multiplied by its weight before summing — rare commands count more,
    boilerplate counts less (ROADMAP #19, option (a)). Weight signs are
    expected non-negative; pass `None` for uniform weighting.

    Pure Python — no numpy required.
    """
    if not embeddings:
        return []
    if weights is not None and len(weights) != len(embeddings):
        raise ValueError(
            f"weights/embeddings length mismatch: {len(weights)} vs {len(embeddings)}"
        )
    dims = len(embeddings[0])
    result = [0.0] * dims
    n_contributing = 0
    for idx, emb in enumerate(embeddings):
        norm = math.sqrt(sum(v * v for v in emb))
        if norm == 0.0:
            continue
        w = 1.0 if weights is None else float(weights[idx])
        if w == 0.0:
            continue
        scale = w / norm
        for i, v in enumerate(emb):
            result[i] += v * scale
        n_contributing += 1
    if n_contributing == 0:
        # Every input had zero norm OR zero weight — pathological but possible.
        # Return a zero vector of correct dim rather than an empty list so
        # downstream callers (which already gate `if embeddings else None`)
        # don't have to special-case a sudden change in shape.
        return [0.0] * dims
    out_norm = math.sqrt(sum(v * v for v in result))
    if out_norm == 0.0:
        # Antipodal vectors summed to zero. Vanishingly unlikely on a 768-d
        # embedding model; return a zero vector rather than NaN-ing the doc.
        return [0.0] * dims
    inv_out = 1.0 / out_norm
    return [v * inv_out for v in result]


_MAX_CREDENTIALS_PER_SESSION = 200
# Findings v2 step 1: bounded sequence + artifact set per session so the
# rollup doc stays small. 64 bigrams covers ~65 commands of ordered context;
# 200 artifacts covers even the most prolific dropper chains.
_MAX_BIGRAMS_PER_SESSION = 64
_MAX_ARTIFACTS_PER_SESSION = 200
# Cap on per-session cowrie file-event records (ROADMAP #3). A single session
# rarely drops/uploads more than a handful of files; 50 bounds the rollup doc
# against a pathological dropper loop while keeping every real chain intact.
_MAX_FILE_EVENTS_PER_SESSION = 50
# P1a follow-up: literal unique-command hash list per session, so the
# playbook-level union (terms agg across member sessions) can be Jaccard'd
# against an anchor's command_set for drift detection. 128 covers the
# 99.9th percentile session — most have <20 unique commands.
_MAX_COMMAND_SET_PER_SESSION = 128


def _record_credential(credentials_set: set[str], ev: dict) -> None:
    """Add the `(user.name, cowrie.password)` tuple from a login event to the
    session's credential set. Either part may be empty — empty user OR
    empty password both still contribute a tuple, since credential-spray
    scanners frequently use one of the two and the empty-string position
    is itself a fingerprint (matches the IP-layer convention at #8).
    """
    user = ((ev.get("user") or {}).get("name") or "")
    password = ((ev.get("cowrie") or {}).get("password") or "")
    if user or password:
        credentials_set.add(f"{user}:{password}")


def _compute_hassh(algorithms: str) -> str:
    """HASSH = md5 of the SSH client's `kex;enc;mac;comp` algorithm string.

    cowrie's `hassh_algorithms` is already that semicolon-joined string, so this
    reproduces cowrie's own `hassh` md5 for events that lack the precomputed
    value (older cowrie builds / custom forks). ROADMAP attribution scaffolding."""
    return hashlib.md5(algorithms.encode("utf-8")).hexdigest()


def _filename_is_specific(basename: str) -> bool:
    """Guard against false-positive filename links (ROADMAP #3). A name is
    specific enough to match against command text only if it has a real
    extension (`.sh`, `.arm7`, …) OR is at least 5 chars. Rejects short/common
    basenames like `sshd`, `a`, `x` that would mislink to unrelated commands
    (`service sshd restart`). Empty → not specific."""
    if not basename:
        return False
    if re.search(r"\.[A-Za-z0-9]{1,6}$", basename):
        return True
    return len(basename) >= 5


def _filename_match_command(
    filename: str,
    session_commands: list[tuple[str, str]],
) -> Optional[str]:
    """Best-effort file→command link by filename (ROADMAP #3): the hash of the
    first session command that references the (specific-enough) basename as a
    **whole token** — bounded by non-filename chars so a substring can't
    mislink (`/usr/sbin/sshd` won't match `sshd`, and `sshd` is rejected by the
    specificity guard anyway). Returns the command hash or None. Used as a
    fallback for file_events with no stronger (url/destfile/preceding) link —
    e.g. an SFTP upload later run by `sh setup.sh`."""
    base = (filename or "").rsplit("/", 1)[-1]
    if not _filename_is_specific(base):
        return None
    pat = re.compile(r"(?<![\w.\-])" + re.escape(base) + r"(?![\w.\-])")
    for cmd_hash, cmd_line in session_commands:
        if pat.search(cmd_line):
            return cmd_hash
    return None


def _record_file_event(
    file_events: list[dict],
    ev: dict,
    action: str,
    last_command: Optional[tuple[str, str]] = None,
) -> None:
    """Append a cowrie file-event record (ROADMAP #3) when it carries a hash.

    The ingest pipeline structures cowrie's `shasum` at `file.hash.sha256`. The
    attacker-facing name is `cowrie.destfile` (download destination) or
    `cowrie.filename` (upload name); `url.original` is present only for
    wget-style fetches. Events without a hash (e.g. failed downloads) are
    skipped — there's nothing to pivot on. Capped by the caller's check so the
    rollup doc stays bounded.

    `last_command` is the nearest-preceding `(command_hash, command_line)` in
    the session (events are @timestamp-ordered). When present, the record links
    file→command (`command_hash`) so the console can trace IP→Session→Command→
    File. `command_attribution` records the confidence basis: `url_match` /
    `destfile_match` when the file's url/destfile appears in that command line,
    else `preceding_command`. No prior command (e.g. SFTP upload) → no link.
    """
    if len(file_events) >= _MAX_FILE_EVENTS_PER_SESSION:
        return
    sha256 = ((ev.get("file") or {}).get("hash") or {}).get("sha256")
    if not sha256:
        return
    cowrie = ev.get("cowrie") or {}
    filename = cowrie.get("destfile") if action == "download" else cowrie.get("filename")
    url = (ev.get("url") or {}).get("original")
    rec: dict = {"action": action, "sha256": sha256}
    if filename:
        rec["filename"] = filename
    if url:
        rec["url"] = url
    ts = ev.get("@timestamp")
    if ts:
        rec["ts"] = ts
    if last_command is not None:
        cmd_hash, cmd_line = last_command
        rec["command_hash"] = cmd_hash
        # Match the basename (incl extension), not the full destination path —
        # cowrie's destfile is an absolute path (`/root/x.sh`) while the command
        # references the bare name (`wget …/x.sh`), so the paths rarely match.
        base = (filename or "").rsplit("/", 1)[-1]
        if url and url in cmd_line:
            rec["command_attribution"] = "url_match"
        elif base and base in cmd_line:
            rec["command_attribution"] = "destfile_match"
        else:
            rec["command_attribution"] = "preceding_command"
    file_events.append(rec)


def _attach_source_ip_intel(doc: dict, summary) -> None:
    """Mutate `doc` to add `dshield.cowrie.enrichment.session.source_ip_intel`.

    `summary` is an `IntelSummary` (or None). When None, no field is
    added — the absence carries meaning ("no intel data for this IP")
    distinct from `consensus_malicious=False`. ROADMAP M3.C.

    Pure function on the dict input — no ES, no other side effects.
    Smoke-testable in `scripts/smoke_test_intel_session_block.py`.
    """
    if summary is None:
        return
    session = (
        doc.setdefault("dshield", {})
        .setdefault("cowrie", {})
        .setdefault("enrichment", {})
        .setdefault("session", {})
    )
    session["source_ip_intel"] = {
        "consensus_malicious":      bool(summary.consensus_malicious),
        "consensus_label":          summary.consensus_label,
        "override_applied":         summary.override_applied,
        "external_rarity_score":    summary.external_rarity_score,
        "malicious_provider_count": summary.malicious_provider_count,
        "clean_provider_count":     summary.clean_provider_count,
        # ES rejects null integers in some strict configs; only emit
        # the field when the intel actually carries a value.
        **(
            {"confidence_max": summary.confidence_max}
            if summary.confidence_max is not None else {}
        ),
    }


def _build_session_doc(
    session_id: str,
    events: list[dict],
    enrichment_by_hash: dict[str, dict],
    cfg: AppConfig,
) -> dict:
    """Build a session rollup doc from raw events + pre-fetched enrichment data."""
    connect_event: Optional[dict] = None
    closed_event: Optional[dict] = None
    login_success_count = 0
    login_fail_count = 0
    file_download_count = 0
    file_upload_count = 0
    # ROADMAP #3: cowrie-computed file hashes (structured at `file.hash.sha256`
    # by the ingest pipeline). One record per download/upload that carries a
    # hash; capped at `_MAX_FILE_EVENTS_PER_SESSION`.
    file_events: list[dict] = []
    # Nearest-preceding command for file→command attribution (ROADMAP #3). Events
    # arrive @timestamp-ordered, so when a file event fires this holds the
    # command that triggered the drop. `(hash, command_line)` or None.
    last_command: Optional[tuple[str, str]] = None
    # All `(command_hash, command_line)` this session, for the post-loop
    # filename-match fallback (an SFTP upload is run by a *later* command).
    session_commands: list[tuple[str, str]] = []
    command_hashes: list[str] = []
    unique_hashes: set[str] = set()
    # Every (user, password) pair attempted in this session, deduped. The
    # legacy top-level cowrie.password / user.name fields keep first-seen
    # for compatibility, but credential-spray bots can fire 50+ unique
    # pairs in one session and the IP-layer attribution feature (ROADMAP
    # #8) needs all of them — ROADMAP #16.
    credentials_set: set[str] = set()

    for ev in events:
        action = (ev.get("event") or {}).get("action", "")
        if action == "cowrie.session.connect":
            connect_event = ev
        elif action == "cowrie.session.closed":
            closed_event = ev
        elif action == "cowrie.login.success":
            login_success_count += 1
            _record_credential(credentials_set, ev)
        elif action == "cowrie.login.failed":
            login_fail_count += 1
            _record_credential(credentials_set, ev)
        elif action == "cowrie.session.file_download":
            file_download_count += 1
            _record_file_event(file_events, ev, "download", last_command)
        elif action == "cowrie.session.file_upload":
            file_upload_count += 1
            _record_file_event(file_events, ev, "upload", last_command)
        elif action == "cowrie.command.input":
            cmd = (ev.get("process") or {}).get("command_line")
            if cmd:
                norm, _ = normalize(cmd, cfg.worker.command_max_chars)
                if norm:
                    h = hash_command(norm)
                    command_hashes.append(h)
                    unique_hashes.add(h)
                    last_command = (h, cmd)
                    session_commands.append((h, cmd))

    # ROADMAP #3 filename-match fallback: link file_events that have no
    # stronger (url/destfile/preceding) command link by scanning the whole
    # session for a command that references the filename as a guarded whole
    # token — catches SFTP uploads run by a later `sh <file>`. Anything still
    # unlinked is the cross-session backlog (ROADMAP open audit item).
    for fe in file_events:
        if fe.get("command_hash") or not fe.get("filename"):
            continue
        match = _filename_match_command(fe["filename"], session_commands)
        if match:
            fe["command_hash"] = match
            fe["command_attribution"] = "filename_match"

    start_ts = (connect_event or {}).get("@timestamp") or (events[0].get("@timestamp") if events else None)
    end_ts = (closed_event or {}).get("@timestamp")
    anchor_ts = end_ts or start_ts
    duration_ns = ((closed_event.get("event") or {}).get("duration") if closed_event else None)

    source_info: dict = {}
    dest_info: dict = {}
    network_info: dict = {}
    user_info: dict = {}
    ua_info: dict = {}
    cowrie_extra: dict = {}

    for ev in events:
        if not source_info.get("ip") and (ev.get("source") or {}).get("ip"):
            source_info = ev["source"]
        if not dest_info.get("ip") and (ev.get("destination") or {}).get("ip"):
            dest_info = ev["destination"]
        if not network_info.get("protocol") and (ev.get("network") or {}).get("protocol"):
            network_info = ev["network"]
        if not user_info.get("name") and (ev.get("user") or {}).get("name"):
            user_info = ev["user"]
        if not ua_info.get("original") and (ev.get("user_agent") or {}).get("original"):
            ua_info = ev["user_agent"]
        cowrie = ev.get("cowrie") or {}
        if not cowrie_extra.get("password") and cowrie.get("password"):
            cowrie_extra["password"] = cowrie["password"]
        if not cowrie_extra.get("hassh_algorithms") and cowrie.get("hassh_algorithms"):
            cowrie_extra["hassh_algorithms"] = cowrie["hassh_algorithms"]
        if not cowrie_extra.get("hassh") and cowrie.get("hassh"):
            cowrie_extra["hassh"] = cowrie["hassh"]

    # HASSH md5 fallback (ROADMAP attribution scaffolding): when cowrie didn't
    # emit its precomputed `hassh` but did emit the algorithm string, derive it
    # locally so every SSH session carries a fingerprint to cluster on.
    if not cowrie_extra.get("hassh") and cowrie_extra.get("hassh_algorithms"):
        cowrie_extra["hassh"] = _compute_hassh(cowrie_extra["hassh_algorithms"])

    embeddings: list[list[float]] = []
    # Per-command IDF weight for the pool — boilerplate (high occurrence)
    # gets small weight, rare/distinctive commands dominate. ROADMAP #19.
    embedding_weights: list[float] = []
    intents: list[str] = []
    novelty_scores: list[float] = []
    confidences: list[float] = []

    for h in unique_hashes:
        enrich_doc = enrichment_by_hash.get(h)
        if not enrich_doc:
            continue
        en = ((enrich_doc.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
        emb = en.get("embedding")
        if emb:
            embeddings.append(emb)
            embedding_weights.append(_idf_pool_weight(en.get("occurrence_count")))
        if en.get("intent"):
            intents.append(en["intent"])
        cluster = en.get("cluster") or {}
        ns = cluster.get("novelty_score")
        if ns is not None:
            novelty_scores.append(float(ns))
        c = en.get("confidence")
        if c is not None:
            confidences.append(float(c))

    embedding = _mean_pool(embeddings, embedding_weights) if embeddings else None

    dominant_intent, intent_distribution = _summarize_intents(intents)

    hash_counts = Counter(command_hashes)
    entropy = _command_entropy(dict(hash_counts))

    # Findings v2 step 1: stable signatures + sequence + artifact set for the
    # drift detectors (step 4) to diff against confirm anchors (step 2).
    # `command_signature` collapses the unique-command set to one keyword;
    # `command_bigram_set` carries the first _MAX_BIGRAMS ordered pairs so
    # `playbook_sequence_drift` can fire on re-orderings within the same
    # vocabulary; `artifact_set` carries every IOC seen across the session's
    # commands so artifact-drift kinds have a session-level input.
    sorted_unique = sorted(unique_hashes)
    command_signature = (
        hashlib.sha256("|".join(sorted_unique).encode("utf-8")).hexdigest()[:32]
        if sorted_unique else None
    )
    bigrams: list[str] = []
    for i in range(len(command_hashes) - 1):
        if len(bigrams) >= _MAX_BIGRAMS_PER_SESSION:
            break
        bigrams.append(f"{command_hashes[i]}|{command_hashes[i + 1]}")
    command_bigram_signature = (
        hashlib.sha256("|".join(sorted(bigrams)).encode("utf-8")).hexdigest()[:32]
        if bigrams else None
    )
    artifact_values: set[str] = set()
    for h in unique_hashes:
        ed = enrichment_by_hash.get(h)
        if not ed:
            continue
        for ind in ((ed.get("threat") or {}).get("indicator") or []):
            kind = ind.get("type")
            if kind in ("ipv4-addr", "ipv6-addr") and ind.get("ip"):
                artifact_values.add(f"ip:{ind['ip']}")
            elif kind == "domain-name" and ind.get("domain"):
                artifact_values.add(f"domain:{ind['domain']}")
            elif kind == "url":
                u = (ind.get("url") or {}).get("full")
                if u:
                    artifact_values.add(f"url:{u}")
            elif kind == "file":
                f_obj = ind.get("file") or {}
                sha = (f_obj.get("hash") or {}).get("sha256")
                if sha:
                    artifact_values.add(f"hash:{sha}")
                elif f_obj.get("name"):
                    artifact_values.add(f"file:{f_obj['name']}")
        # ROADMAP #5: analyst-authored rule matches. Namespaced with an
        # `analyst:` prefix so the existing playbook/campaign artifact
        # aggregations pick them up without code changes.
        for hit in ((ed.get("dshield") or {}).get("cowrie", {}).get("enrichment") or {}).get("analyst_artifacts") or []:
            k = (hit.get("kind") or "").strip()
            v = (hit.get("value") or "").strip()
            if k and v:
                artifact_values.add(f"analyst:{k}:{v}")

    # ROADMAP #3: promote cowrie-computed file hashes into the same artifact_set
    # (`hash:` prefix) so campaign infra-mining, playbook_artifact_drift, and
    # discovery shared-artifact findings pick them up with no extra plumbing.
    for fe in file_events:
        artifact_values.add(f"hash:{fe['sha256']}")

    session_block: dict = {
        "command_count": len(command_hashes),
        "unique_commands": len(unique_hashes),
        "login_success_count": login_success_count,
        "login_fail_count": login_fail_count,
        "file_download_count": file_download_count,
        "file_upload_count": file_upload_count,
        "command_entropy": round(entropy, 4),
        "embed_version": cfg.session.embed_version,
    }
    if command_signature:
        session_block["command_signature"] = command_signature
        # P1a follow-up: store the literal unique-command hash list (capped)
        # so `playbook_command_drift` can compute full Jaccard at the
        # playbook level (union across member sessions).
        session_block["command_set"] = sorted_unique[:_MAX_COMMAND_SET_PER_SESSION]
    if bigrams:
        session_block["command_bigram_set"] = bigrams
        session_block["command_bigram_signature"] = command_bigram_signature
    if artifact_values:
        session_block["artifact_set"] = sorted(artifact_values)[:_MAX_ARTIFACTS_PER_SESSION]
    if file_events:
        session_block["file_events"] = file_events
    if dominant_intent:
        session_block["dominant_intent"] = dominant_intent
    if intent_distribution:
        session_block["intent_distribution"] = intent_distribution
    if credentials_set:
        # Sorted + capped so the doc is bounded and idempotent across runs.
        # Cap matches the IP-layer cap pattern from issue #8.
        session_block["credentials"] = sorted(credentials_set)[:_MAX_CREDENTIALS_PER_SESSION]
    if novelty_scores:
        session_block["mean_novelty_score"] = round(sum(novelty_scores) / len(novelty_scores), 4)
        session_block["max_novelty_score"] = round(max(novelty_scores), 4)
    if confidences:
        session_block["mean_confidence"] = round(sum(confidences) / len(confidences), 2)
    if embedding:
        session_block["embedding"] = embedding

    # ROADMAP #3: session-level ECS file indicators, one per distinct hash,
    # so the rollup is threat.indicator-queryable and feeds #2's intel queue.
    # First filename seen for a hash wins (display only).
    file_indicators: list[dict] = []
    seen_hashes: set[str] = set()
    for fe in file_events:
        sha = fe["sha256"]
        if sha in seen_hashes:
            continue
        seen_hashes.add(sha)
        ind: dict = {"type": "file", "file": {"hash": {"sha256": sha}}}
        if fe.get("filename"):
            ind["file"]["name"] = fe["filename"]
        file_indicators.append(ind)

    doc: dict = {
        "@timestamp": anchor_ts,
        "event": {
            "kind": "enrichment",
            "category": ["network"],
            "dataset": "dshield.cowrie.enrichment.session",
        },
        "cowrie": {"session_id": session_id, **cowrie_extra},
        "dshield": {
            "cowrie": {
                "enrichment": {
                    "session": session_block,
                }
            }
        },
    }
    if start_ts:
        doc["event"]["start"] = start_ts
    if end_ts:
        doc["event"]["end"] = end_ts
    if duration_ns is not None:
        doc["event"]["duration"] = duration_ns
    if source_info:
        doc["source"] = source_info
    if dest_info:
        doc["destination"] = dest_info
    if network_info:
        doc["network"] = network_info
    if user_info:
        doc["user"] = user_info
    if ua_info:
        doc["user_agent"] = ua_info
    if file_indicators:
        doc["threat"] = {"indicator": file_indicators}

    return doc


def run_rollup(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """Build/update session rollup docs from the events index."""
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)

    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands

    since = db.get_watermark(_SESSION_WATERMARK_KEY)
    log.info("Session watermark: %s", since or "(none, full backfill)")

    closed: list[tuple[str, str]] = list(
        _iter_closed_sessions(es, events_idx, since, cfg.session.page_size)
    )
    log.info("Found %d closed sessions since watermark", len(closed))

    if not closed:
        db.close()
        return {"closed_sessions_found": 0, "dry_run": dry_run}

    max_ts = max(ts for _, ts in closed)

    if dry_run:
        db.close()
        return {"closed_sessions_found": len(closed), "max_ts": max_ts, "dry_run": True}

    stats: dict = defaultdict(int)

    from ...es_client import init_index
    init_index(es, _SESSIONS_MAPPING, sessions_idx)

    # M3.C: bulk source-IP intel lookups per batch. Each session's
    # source IP is denormalised onto its rollup doc so downstream
    # pivots ("show me playbooks whose member sessions are all
    # intel-clean") become single-index queries instead of
    # cross-index joins.
    intel_lookup = None
    if cfg.intel.enabled:
        from ...intel.lookup import IntelLookup
        intel_lookup = IntelLookup(es, cfg)
        log.info("session rollup: source-IP-intel persistence enabled")

    session_ids_all = [sid for sid, _ in closed]
    page = cfg.session.page_size

    for batch_start in range(0, len(session_ids_all), page):
        batch_ids = session_ids_all[batch_start: batch_start + page]

        events_by_session = _fetch_session_events(es, events_idx, batch_ids)

        all_hashes: set[str] = set()
        for sid in batch_ids:
            for ev in events_by_session.get(sid, []):
                if (ev.get("event") or {}).get("action") == "cowrie.command.input":
                    cmd = (ev.get("process") or {}).get("command_line")
                    if cmd:
                        norm, _ = normalize(cmd, cfg.worker.command_max_chars)
                        if norm:
                            all_hashes.add(hash_command(norm))

        enrichment_by_hash = _mget_enrichment(es, commands_idx, list(all_hashes))
        stats["command_hashes_fetched"] += len(enrichment_by_hash)

        # Phase 1: build the session docs without intel.
        built: list[tuple[str, dict]] = []
        for sid in batch_ids:
            events = events_by_session.get(sid, [])
            if not events:
                stats["sessions_no_events"] += 1
                continue
            doc = _build_session_doc(sid, events, enrichment_by_hash, cfg)
            session_block = (
                doc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session", {})
            )
            if session_block.get("embedding"):
                stats["sessions_with_embedding"] += 1
            built.append((sid, doc))
            stats["sessions_built"] += 1

        # Phase 2: bulk intel lookup over the batch's source IPs,
        # then mutate each doc to attach the source_ip_intel block.
        # No-op when intel disabled or when the doc has no source.ip.
        if intel_lookup is not None and built:
            batch_ips = sorted({
                (doc.get("source") or {}).get("ip")
                for _, doc in built
                if (doc.get("source") or {}).get("ip")
            })
            if batch_ips:
                intel_lookup.get_many("ip", batch_ips)
                for _, doc in built:
                    ip = (doc.get("source") or {}).get("ip")
                    if not ip:
                        continue
                    summary = intel_lookup.get_one("ip", ip)
                    if summary is not None:
                        _attach_source_ip_intel(doc, summary)
                        stats["sessions_with_intel"] += 1

        actions: list[dict] = [
            {"_op_type": "index", "_id": sid, "_source": doc}
            for sid, doc in built
        ]

        if actions:
            ok, errs = bulk_write(es, sessions_idx, actions)
            stats["bulk_ok"] += ok
            stats["bulk_errors"] += len(errs)
            if errs:
                log.warning("rollup-sessions bulk errors (%d): %s", len(errs), errs[:2])

        log.info(
            "Processed batch %d/%d (%d sessions)",
            batch_start + len(batch_ids), len(session_ids_all), len(batch_ids),
        )

    # Explicit refresh so the next pipeline step (`cluster sessions`) and the
    # later `rollup ips` see every session doc we just wrote. The mapping
    # uses refresh_interval=30s, which otherwise leaves a race where the
    # downstream iterator misses the trailing batches.
    try:
        es.indices.refresh(index=sessions_idx)
    except Exception as exc:
        log.warning("rollup-sessions refresh failed (continuing): %s", exc)

    db.set_watermark(max_ts, _SESSION_WATERMARK_KEY)
    log.info("Session watermark advanced to %s", max_ts)
    db.close()

    return dict(
        stats,
        closed_sessions_found=len(closed),
        max_ts=max_ts,
        sessions_index=sessions_idx,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Cluster sessions
# ---------------------------------------------------------------------------

def iter_session_docs(
    es: Elasticsearch,
    index: str,
    page_size: int = 1000,
) -> Iterator[tuple[str, list[float], str, dict]]:
    """Yield (doc_id, embedding, session_id, scalars)."""
    body: dict = {
        "size": page_size,
        "_source": [
            "dshield.cowrie.enrichment.session.embedding",
            "dshield.cowrie.enrichment.session.command_count",
            "dshield.cowrie.enrichment.session.unique_commands",
            "dshield.cowrie.enrichment.session.login_success_count",
            "dshield.cowrie.enrichment.session.login_fail_count",
            "dshield.cowrie.enrichment.session.mean_novelty_score",
            "cowrie.session_id",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}},
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
            src = h["_source"]
            s = (
                ((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {})
                .get("session", {})
            )
            emb = s.get("embedding")
            if not emb:
                continue
            session_id = (src.get("cowrie") or {}).get("session_id", h["_id"])
            success = s.get("login_success_count") or 0
            fail = s.get("login_fail_count") or 0
            total_logins = success + fail
            scalars = {
                "command_count": s.get("command_count") or 1,
                "unique_commands": s.get("unique_commands") or 1,
                "login_success_rate": success / total_logins if total_logins > 0 else 0.0,
                "mean_novelty_score": s.get("mean_novelty_score") or 0.0,
            }
            yield h["_id"], emb, session_id, scalars
        search_after = hits[-1]["sort"]


def build_session_scalar_block(scalars_list: list[dict], weight: float) -> "np.ndarray":
    """(n, 4) weighted scalar matrix for session-level HDBSCAN.

    log1p-normalized fields use fixed corpus-scale denominators (ROADMAP #14)
    so the same session yields identical scalar contributions across re-runs,
    regardless of who else is in the batch. Output clipped to [0, 1].
    """
    import numpy as np
    counts = np.array([s.get("command_count") or 1 for s in scalars_list], dtype=np.float32)
    unique = np.array([s.get("unique_commands") or 1 for s in scalars_list], dtype=np.float32)
    success_rate = np.array([s.get("login_success_rate", 0.0) for s in scalars_list], dtype=np.float32)
    novelty = np.array([s.get("mean_novelty_score", 0.0) for s in scalars_list], dtype=np.float32)

    denom_count = float(np.log1p(_SCALAR_DENOM_COMMAND_COUNT))
    denom_unique = float(np.log1p(_SCALAR_DENOM_UNIQUE_COMMANDS))

    block = np.zeros((len(scalars_list), 4), dtype=np.float32)
    block[:, 0] = np.clip(np.log1p(counts) / denom_count, 0.0, 1.0) * weight
    block[:, 1] = np.clip(np.log1p(unique) / denom_unique, 0.0, 1.0) * weight
    block[:, 2] = np.clip(success_rate, 0.0, 1.0) * weight
    block[:, 3] = np.clip(novelty, 0.0, 1.0) * weight
    return block


def populate_reference_session_embeddings(
    cfg: AppConfig, secrets: Secrets,
    *, dry_run: bool = False,
) -> dict:
    """Mean-pool per-command embeddings into each reference rollup
    session's ``dshield.cowrie.enrichment.session.embedding`` field
    (brutal-review phase 5.4).

    The reference-corpus rollup (`prism.reference.cowrie.session`)
    carries `command_set` (unique command hashes per session) from the
    5.2 importer. Phase 5.3's `enrich --reference` populates
    `prism.enriched.cowrie.command` for those hashes. This helper
    closes the loop: for every reference session, fetch the enriched
    command embeddings by hash, mean-pool, and write the result back
    to the reference rollup. After this the reference rollup looks
    identical-shape to a live session rollup, and the existing
    clustering iterators consume it without modification.

    Skips sessions whose commands aren't all enriched yet (re-run
    `enrich --reference` with a higher budget to enrich more).
    Returns stats `{visited, embedded, skipped_unenriched,
    skipped_no_commands}`.
    """
    import numpy as np
    from elasticsearch.helpers import bulk

    es = make_client(cfg.elasticsearch, secrets)
    ref_idx = cfg.elasticsearch.indexes.cowrie.reference_sessions
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands

    stats = {
        "visited":              0,
        "embedded":             0,
        "skipped_unenriched":   0,
        "skipped_no_commands":  0,
    }
    actions: list[dict] = []
    search_after = None
    while True:
        body: dict = {
            "size": 200,
            "_source": [
                "cowrie.session_id",
                "dshield.cowrie.enrichment.session.command_set",
            ],
            "query": {"match_all": {}},
            "sort":  [{"_doc": "asc"}],
        }
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=ref_idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            stats["visited"] += 1
            src = h["_source"]
            sid = (src.get("cowrie") or {}).get("session_id") or h["_id"]
            s = ((src.get("dshield") or {}).get("cowrie", {})
                 .get("enrichment", {}).get("session", {}))
            command_set = s.get("command_set") or []
            if not command_set:
                stats["skipped_no_commands"] += 1
                continue
            # Bulk-mget the per-command enrichment docs by hash. Embeddings
            # live at `dshield.cowrie.enrichment.embedding`.
            mget_resp = es.mget(
                index=cmd_idx, ids=command_set,
                _source=["dshield.cowrie.enrichment.embedding"],
            )
            vectors: list[list[float]] = []
            for doc in mget_resp.get("docs") or []:
                if not doc.get("found"):
                    continue
                src_d = doc.get("_source") or {}
                emb = ((src_d.get("dshield") or {}).get("cowrie", {})
                       .get("enrichment", {}).get("embedding"))
                if emb:
                    vectors.append(emb)
            if len(vectors) < len(command_set):
                # Not all commands are enriched yet — skip and tell
                # the operator to re-run enrich --reference.
                stats["skipped_unenriched"] += 1
                continue
            arr = np.array(vectors, dtype=np.float32)
            pooled = arr.mean(axis=0).tolist()
            actions.append({
                "_op_type": "update",
                "_index":   ref_idx,
                "_id":      h["_id"],
                "script": {
                    "source": (
                        "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
                        "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
                        "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
                        "if (ctx._source.dshield.cowrie.enrichment.session == null) { ctx._source.dshield.cowrie.enrichment.session = [:]; }"
                        "ctx._source.dshield.cowrie.enrichment.session.embedding = params.emb;"
                    ),
                    "params": {"emb": pooled},
                },
            })
            stats["embedded"] += 1
        search_after = hits[-1].get("sort")
        if not search_after:
            break

    if dry_run:
        log.info("reference-embedding dry-run: %s", stats)
        return dict(stats, dry_run=True)
    if actions:
        n_ok, errs = bulk(es, actions, raise_on_error=False)
        stats["bulk_ok"] = n_ok
        stats["bulk_errors"] = len(errs) if isinstance(errs, list) else 0
        es.indices.refresh(index=ref_idx)
    log.info("reference session embeddings populated: %s", stats)
    return dict(stats)


def run_cluster(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
    refresh_reference: bool = False,
    use_reference: bool = True,
    bootstrap_from: Optional[str] = None,
) -> dict:
    """HDBSCAN over session embeddings. Delegates to clustering core.

    ``bootstrap_from="external"`` (brutal-review phase 5.4) reads from
    the reference-corpus rollup instead of the live rollup, runs the
    same clustering, and writes the resulting centroids as a new
    external reference generation tagged ``reference_source="external"``.
    The 5.5 dual-novelty writer reads those centroids alongside the
    in-corpus ref to populate ``novelty_score_external``.
    """
    from ...clustering import run_layer_clustering
    es = make_client(cfg.elasticsearch, secrets)

    # External bootstrap (5.4): swap source index, mint a new external
    # reference generation, skip the live-corpus specificity pass.
    is_external_bootstrap = bootstrap_from == "external"
    if is_external_bootstrap:
        sessions_idx = cfg.elasticsearch.indexes.cowrie.reference_sessions
        layer_label = "cowrie.sessions.reference[external]"
        reference_source = "external"
    else:
        sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
        layer_label = "cowrie.sessions"
        reference_source = None
    clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    scfg: SessionConfig = cfg.session

    if not es.indices.exists(index=sessions_idx):
        if is_external_bootstrap:
            raise RuntimeError(
                f"Reference sessions index '{sessions_idx}' not found. "
                "Run `import_reference_corpus.py` (5.2) then `enrich --reference` (5.3) first."
            )
        raise RuntimeError(
            f"Sessions index '{sessions_idx}' not found. "
            "Run 'rollup sessions' first, or check elasticsearch.indexes.cowrie.sessions_rollup in config."
        )

    # External path: compute reference session embeddings first (one
    # mget per session, mean-pool against the shared enrichment index).
    # Live path: rollup already populated this field.
    if is_external_bootstrap:
        emb_stats = populate_reference_session_embeddings(cfg, secrets, dry_run=dry_run)
        log.info("[%s] reference embeddings: %s", layer_label, emb_stats)
        if not dry_run and emb_stats.get("embedded", 0) == 0:
            raise RuntimeError(
                "No reference sessions could be embedded. Did `enrich --reference` "
                "run to completion? Check `skipped_unenriched` in the embedding stats."
            )

    result = run_layer_clustering(
        es=es,
        docs_iter=iter_session_docs(es, sessions_idx, scfg.page_size),
        docs_index=sessions_idx,
        clusters_index=clusters_idx,
        mapping_path=_SESSION_CLUSTERS_MAPPING,
        update_script=_SESSION_CLUSTER_UPDATE_SCRIPT,
        scalar_block_builder=build_session_scalar_block,
        min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
        scalar_weight=scfg.cluster_scalar_weight,
        batch_size=scfg.batch_size,
        sample_size=_SESSION_CLUSTER_SAMPLE_SIZE,
        centroid_sample_field="sample_session_ids",
        dry_run=dry_run,
        layer_label=layer_label,
        refresh_reference=refresh_reference,
        # External path forces a fresh ref bootstrap, doesn't score
        # against an existing one — the per-session "novelty against
        # myself" output isn't useful.
        use_reference=False if is_external_bootstrap else use_reference,
        bootstrap_reference_now=is_external_bootstrap,
        reference_source=reference_source,
        reference_max_age_days=scfg.reference_max_age_days,
        # Rescue HDBSCAN noise sessions that are within the same cosine
        # threshold the centroid-level merge uses — closes the merge's blind
        # spot for loose periphery sessions. Session layer only; command/IP
        # clusterers omit this and are unaffected. Set
        # playbook_merge_threshold=1.0 to disable (also disables centroid merge).
        rescue_threshold=scfg.playbook_merge_threshold,
    )

    # ROADMAP #4: per-cluster IP/command specificity, persisted on the centroid
    # docs the core just wrote (+ refreshed). Best-effort — a failure here
    # never fails the clustering run. Session docs already carry this run's
    # cluster.id, so the aggregations see the fresh membership.
    #
    # Skipped on external bootstrap: the reference rollup has no `source.ip`
    # field (synthetic sessions don't have real source IPs) and the
    # specificity aggregator joins on IP. The external centroids stand on
    # their own as embedding-space anchors; per-cluster IP/command
    # distinctiveness is a live-corpus property anyway.
    run_id = result.get("run_id")
    if (not is_external_bootstrap
            and not dry_run and run_id
            and result.get("cluster_docs_written")):
        result["specificity"] = _persist_cluster_specificity(
            es, sessions_idx, clusters_idx, run_id, scfg.specificity_store_cap,
        )
    return result


# ---------------------------------------------------------------------------
# Name playbooks (each session cluster gets a short LLM-generated label).
# ---------------------------------------------------------------------------

def _fetch_member_session_ids(
    es: Elasticsearch,
    sessions_idx: str,
    cluster_ids: list[str],
    page_size: int = 1000,
) -> dict[str, set[str]]:
    """Pull `{cluster_id → set[session_id]}` for the named cluster ids.

    Reads the session rollup index, scoped to docs whose
    `dshield.cowrie.enrichment.session.cluster.id` matches one of the
    requested cluster_ids (i.e. members of the current run — `cluster
    sessions` overwrites this field for every session, so by the time
    `name playbooks` calls us the field reflects the latest run only).

    Returns an empty map if `cluster_ids` is empty. Missing cluster ids
    return as keys with empty sets (caller chooses how to react).
    """
    out: dict[str, set[str]] = {cid: set() for cid in cluster_ids}
    if not cluster_ids:
        return out

    cluster_field = "dshield.cowrie.enrichment.session.cluster.id"
    body: dict = {
        "size": page_size,
        "_source": ["cowrie.session_id", cluster_field],
        "query": {"terms": {cluster_field: cluster_ids}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=sessions_idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return out
        for h in hits:
            src = h["_source"]
            sid = (src.get("cowrie") or {}).get("session_id") or h["_id"]
            cid = (
                ((src.get("dshield") or {}).get("cowrie") or {})
                .get("enrichment", {}).get("session", {}).get("cluster", {}).get("id")
            )
            if cid and cid in out and sid:
                out[cid].add(sid)
        search_after = hits[-1]["sort"]


def _load_other_playbook_names(
    es: Elasticsearch,
    session_clusters_idx: str,
    exclude_run_id: str,
) -> dict[str, dict]:
    """Load already-named playbooks from `session_clusters`, *excluding*
    centroids written in the current run.

    Returns `{playbook_id: {"name": str, "sample_session_ids": list[str],
    "cluster_ids": list[str]}}`. A single playbook can span multiple
    centroid docs (HDBSCAN clusters merged at name time share one
    `playbook_id`); we collapse those into one entry per playbook.

    Used by pass-2 disambiguation (ROADMAP #10) to find collisions
    against playbooks named in any prior run.
    """
    by_pid: dict[str, dict] = {}
    try:
        body: dict = {
            "size": 1000,
            "_source": ["playbook_id", "playbook_name", "sample_session_ids",
                        "cluster_id", "run_id"],
            "query": {"bool": {"must": [
                {"term": {"doc_type": "cluster"}},
                {"exists": {"field": "playbook_id"}},
                {"exists": {"field": "playbook_name"}},
            ]}},
            "sort": [{"@timestamp": "desc"}, {"_doc": "asc"}],
        }
        search_after = None
        while True:
            if search_after:
                body["search_after"] = search_after
            resp = es.search(index=session_clusters_idx, **body)
            hits = resp["hits"]["hits"]
            if not hits:
                break
            for h in hits:
                src = h["_source"]
                if src.get("run_id") == exclude_run_id:
                    continue
                pid = src.get("playbook_id")
                if not pid:
                    continue
                entry = by_pid.setdefault(pid, {
                    "playbook_id": pid,
                    "name": src.get("playbook_name") or "",
                    "sample_session_ids": [],
                    "cluster_ids": [],
                })
                # Newest doc wins for name (centroid rewrites land first).
                if not entry["name"] and src.get("playbook_name"):
                    entry["name"] = src["playbook_name"]
                for sid in (src.get("sample_session_ids") or []):
                    if sid not in entry["sample_session_ids"]:
                        entry["sample_session_ids"].append(sid)
                cid = src.get("cluster_id")
                if cid and cid not in entry["cluster_ids"]:
                    entry["cluster_ids"].append(cid)
            search_after = hits[-1]["sort"]
    except Exception as exc:
        log.warning("could not load existing playbook names (continuing): %s", exc)
    return by_pid


def _detect_name_collisions(
    pass1_named: list[dict],
    existing_playbooks: dict[str, dict],
) -> list[dict]:
    """Pure function — group playbooks by case-insensitive trimmed name.

    `pass1_named` is the list of playbooks named in the current run (each
    dict has `playbook_id`, `name`, plus pass-2 context fields). Entries
    with empty names are silently skipped.

    `existing_playbooks` is the output of `_load_other_playbook_names` —
    playbooks named in any prior run. Entries are folded into a
    collision group only if their name matches a name produced this run.
    We never disturb an existing playbook's name in pass 2; existing
    colliders are listed as "frozen" so the LLM can differentiate the
    new ones from them.

    Returns one entry per collision group with at least one renamable
    member AND at least 2 total members (renamable + frozen). Groups
    with a single playbook (no collision) are omitted.
    """
    by_name: dict[str, dict] = {}
    def _key(n: str) -> str:
        return (n or "").strip().lower()
    for pb in pass1_named:
        k = _key(pb.get("name"))
        if not k:
            continue
        g = by_name.setdefault(k, {"name": pb["name"], "renamable": [], "frozen": []})
        g["renamable"].append(pb)
    for pb in existing_playbooks.values():
        k = _key(pb.get("name"))
        if not k:
            continue
        if k in by_name:
            by_name[k]["frozen"].append(pb)
    return [
        g for g in by_name.values()
        if g["renamable"] and (len(g["renamable"]) + len(g["frozen"])) > 1
    ]


def _format_cluster_block(pb: dict, commands: list[str]) -> str:
    """Render one cluster's context (playbook id, sample sids, sample commands)
    as a textual block for inclusion in the pass-2 disambiguation prompt."""
    sids = pb.get("sample_session_ids") or []
    cids = pb.get("cluster_ids") or []
    lines = [
        f"  Playbook id: {pb.get('playbook_id', '?')}",
        f"  Cluster ids: {', '.join(cids) if cids else '(unknown)'}",
        f"  Sample session ids: {', '.join(sids[:5]) if sids else '(none)'}",
        "  Commands executed (sampled, deduplicated):",
    ]
    if commands:
        lines.extend(f"    - {c}" for c in commands[:15])
    else:
        lines.append("    (no commands available)")
    return "\n".join(lines)


def _format_renamable_block(
    pb: dict,
    distinctive_feats: list[tuple[str, float]],
    floor: float,
) -> str:
    """Rich pass-2 context for one renamable cluster (ROADMAP #11): commands
    and IOCs ranked by session coverage, IOCs prevalence-gated at `floor` so a
    one-off C2 IP can't be anchored on, and the explicit distinctive set
    (features present here but absent in every sibling)."""
    total = pb.get("coverage_total") or 0
    cmd_cov = pb.get("cmd_coverage") or []
    ioc_cov = [
        (i, n) for i, n in (pb.get("ioc_coverage") or [])
        if total and (n / total) >= floor
    ]
    lines = [
        f"  Playbook id: {pb.get('playbook_id', '?')}",
        f"  Cluster ids: {', '.join(pb.get('member_cids') or []) or '(unknown)'}",
        f"  Sessions sampled: {total}",
        "  Commands by session coverage:",
        _format_coverage_lines(cmd_cov, total, indent="    "),
        f"  Prevalent IOCs (>= {floor:.0%} of sessions):",
        _format_coverage_lines(ioc_cov, total, indent="    "),
    ]
    d_cmds = [(f[len("cmd:"):], c) for f, c in distinctive_feats if f.startswith("cmd:")]
    d_iocs = [(f, c) for f, c in distinctive_feats if not f.startswith("cmd:")]
    lines.append("  DISTINCTIVE to this cluster (present here, absent in the others) — anchor the name here:")
    if d_cmds or d_iocs:
        lines.extend(f"    - command: {f}   ({c:.0%} of sessions)" for f, c in d_cmds)
        lines.extend(f"    - ioc: {f}   ({c:.0%} of sessions)" for f, c in d_iocs)
    else:
        lines.append("    (none — no prevalent feature separates this cluster from its siblings)")
    return "\n".join(lines)


def _apply_playbook_name(
    es: Elasticsearch,
    session_clusters_idx: str,
    sessions_idx: str,
    run_id: str,
    member_cids: list[str],
    playbook_id: str,
    name: str,
    stats: dict,
    *,
    log_prefix: str = "playbook",
) -> None:
    """Write playbook_id + playbook_name onto the centroid docs and onto
    every member session via update_by_query. Shared by pass-1 initial
    naming and pass-2 disambiguation rename."""
    script = (
        "ctx._source.playbook_id = params.playbook_id;"
        "ctx._source.playbook_name = params.name;"
    )
    params = {"playbook_id": playbook_id, "name": name}
    try:
        es.update_by_query(
            index=session_clusters_idx,
            body={
                "query": {"bool": {"must": [
                    {"term": {"run_id": run_id}},
                    {"term": {"doc_type": "cluster"}},
                    {"terms": {"cluster_id": member_cids}},
                ]}},
                "script": {"source": script, "params": params},
            },
        )
    except Exception as exc:
        log.warning("Failed to update centroids for %s %s: %s", log_prefix, playbook_id, exc)
        stats["centroid_update_errors"] += 1
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        es.update_by_query(
            index=sessions_idx,
            body={
                "query": {"terms": {
                    "dshield.cowrie.enrichment.session.cluster.id": member_cids,
                }},
                "script": {
                    "source": _SESSION_PLAYBOOK_NAME_SCRIPT,
                    "params": {
                        "playbook_id": playbook_id,
                        "playbook_name": name,
                        "now": now_iso,
                    },
                },
            },
        )
    except Exception as exc:
        log.warning("Failed to update session docs for %s %s: %s", log_prefix, playbook_id, exc)
        stats["session_update_errors"] += 1


def _run_disambiguation_pass(
    *,
    es: Elasticsearch,
    llm,                                            # open llm client
    prompt_template: str,
    group: dict,                                    # output of _detect_name_collisions
    run_id: str,
    session_clusters_idx: str,
    sessions_idx: str,
    events_idx: str,
    cfg: AppConfig,
    stats: dict,
) -> None:
    """Resolve one name-collision group via a single LLM call.

    Builds the pass-2 prompt with each renamable cluster's rich context
    plus any frozen colliders (already-named playbooks from prior runs
    that share the name — for context only, never renamed). Calls the
    LLM, validates the response, and applies the renames via
    `_apply_playbook_name`.

    Soft-fails on any LLM error / invalid JSON / collision in the
    response — original pass-1 names stay. ROADMAP #11 (was #10): each
    renamable block now carries cluster-wide command/IOC coverage and the
    *distinctive* feature set (present here, absent in siblings) so the LLM
    anchors the new name on a genuinely separating, prevalent signal rather
    than eyeballing independent samples.
    """
    name = group["name"]
    renamable = group["renamable"]
    frozen = group["frozen"]
    floor = cfg.session.playbook_merge_distinctiveness_floor

    # Compute what actually separates each renamable cluster from its
    # siblings, so the prompt can hand the LLM the distinctive set instead of
    # asking it to spot the difference unaided.
    cov_by_pid = {
        pb["playbook_id"]: _combined_coverage_map(
            pb.get("cmd_coverage") or [], pb.get("ioc_coverage") or [],
            pb.get("coverage_total") or 0,
        )
        for pb in renamable
    }
    distinctive = _distinctive_features(cov_by_pid, floor)

    renamable_blocks: list[str] = []
    for pb in renamable:
        renamable_blocks.append(
            _format_renamable_block(pb, distinctive.get(pb["playbook_id"], []), floor)
        )

    frozen_blocks: list[str] = []
    for pb in frozen:
        sids = pb.get("sample_session_ids") or []
        cmds = _fetch_session_sample_commands(
            es, events_idx, sids[:5],
            max_commands=cfg.session.playbook_sample_commands,
        ) if sids else []
        frozen_blocks.append(
            f"  Name: \"{pb.get('name', '?')}\"\n" + _format_cluster_block(pb, cmds)
        )

    frozen_section = (
        "FROZEN (already-named in a prior run; do NOT rename, listed for differentiation):\n"
        + "\n\n".join(frozen_blocks)
    ) if frozen_blocks else (
        "FROZEN (already-named in a prior run; do NOT rename, listed for differentiation):\n"
        "  (none — this is a within-run collision only)"
    )

    from ...llm.fencing import SYSTEM_PROMPT, fence, make_nonce
    # The renamable/frozen blocks embed attacker-controlled command text and
    # extracted IOCs — fence them. `<<<NAME>>>` is the short collision label.
    nonce = make_nonce()
    prompt = (
        prompt_template
        .replace("<<<NAME>>>", name)
        .replace("<<<RENAMABLE_BLOCK>>>",
                 fence("renamable_clusters", "\n\n".join(renamable_blocks), nonce))
        .replace("<<<FROZEN_BLOCK>>>", fence("frozen_clusters", frozen_section, nonce))
    )

    try:
        raw = llm.generate_json(
            prompt,
            schema=PLAYBOOK_DISAMBIGUATE_JSON_SCHEMA,
            schema_name="playbook_disambiguate",
            options={"max_tokens": 1024},
            system=SYSTEM_PROMPT,
        )
        parsed = PlaybookDisambiguation.model_validate_json(raw)
    except Exception as exc:
        log.warning(
            "Pass-2 LLM call failed for name '%s' (%d renamable, %d frozen): %s",
            name, len(renamable), len(frozen), exc,
        )
        stats["disambiguate_failed"] += 1
        return

    # Build a {playbook_id: PlaybookRename} map. The LLM is told to use
    # cluster ids; we tolerate either playbook_id or any of the member
    # cluster ids as the key (LLMs occasionally confuse them).
    by_pid: dict[str, str] = {pb["playbook_id"]: pb["playbook_id"] for pb in renamable}
    by_cid: dict[str, str] = {}
    for pb in renamable:
        for cid in pb["member_cids"]:
            by_cid[cid] = pb["playbook_id"]
    resolved: dict[str, str] = {}
    for r in parsed.renames:
        if r.cluster_id in by_pid:
            resolved[r.cluster_id] = r.new_name
        elif r.cluster_id in by_cid:
            resolved[by_cid[r.cluster_id]] = r.new_name

    if len(resolved) < len(renamable):
        log.warning(
            "Pass-2 LLM omitted renames for %d cluster(s) under '%s'; "
            "keeping pass-1 names for those",
            len(renamable) - len(resolved), name,
        )

    # Final-distinctness gate: every new name must be distinct from the
    # others in this group AND from all frozen names. Otherwise drop the
    # offending one — pass-1 name stays.
    frozen_names_lc = {(pb.get("name") or "").strip().lower() for pb in frozen}
    seen_new_lc: set[str] = set()
    final_renames: dict[str, str] = {}
    for pid, new_name in resolved.items():
        nlc = new_name.strip().lower()
        if not nlc or nlc in frozen_names_lc or nlc in seen_new_lc:
            log.warning(
                "Pass-2 rename rejected (collides with frozen or another new name): "
                "pid=%s new_name=%r", pid, new_name,
            )
            continue
        seen_new_lc.add(nlc)
        final_renames[pid] = new_name

    # Apply.
    for pb in renamable:
        new_name = final_renames.get(pb["playbook_id"])
        if not new_name:
            continue
        log.info(
            "Pass-2 rename: %s '%s' → '%s'",
            pb["playbook_id"], pb["name"], new_name,
        )
        _apply_playbook_name(
            es, session_clusters_idx, sessions_idx,
            run_id, pb["member_cids"], pb["playbook_id"], new_name, stats,
            log_prefix="disambig",
        )
        stats["clusters_renamed"] += 1


def _merge_collision_subgroups(
    *,
    es: Elasticsearch,
    group: dict,
    members_by_cid: dict[str, set[str]],
    run_id: str,
    session_clusters_idx: str,
    sessions_idx: str,
    events_idx: str,
    cfg: AppConfig,
    stats: dict,
) -> list[dict]:
    """Merge mutually-indistinguishable renamable playbooks within one
    collision group into single playbooks (ROADMAP #11). Returns the
    post-merge renamable list (same dict shape as a named_in_run entry) for the
    caller to feed into the rename pass. Pure-distinctiveness gated — the LLM
    never decides a merge.

    When two (or more) colliding playbooks share every prevalent feature and
    differ on none (at `playbook_merge_distinctiveness_floor`), forcing distinct
    names fabricates a difference. Instead we collapse them under one id: the
    lex-smallest of the merging spbs wins (deterministic, no centroid math).
    The losing spbs remain pinned in the anchor index (write-once) but no
    cluster doc references them after the merge; they age out via the
    lifecycle retirement sweep.
    """
    renamable = group["renamable"]
    if len(renamable) < 2:
        return renamable

    floor = cfg.session.playbook_merge_distinctiveness_floor
    pb_by_pid = {pb["playbook_id"]: pb for pb in renamable}
    cov_by_pid = {
        pid: _combined_coverage_map(
            pb.get("cmd_coverage") or [], pb.get("ioc_coverage") or [],
            pb.get("coverage_total") or 0,
        )
        for pid, pb in pb_by_pid.items()
    }
    subgroups = _partition_mergeable(cov_by_pid, floor)

    out: list[dict] = []
    for sub in subgroups:
        if len(sub) < 2:
            out.append(pb_by_pid[sub[0]])
            continue

        merged_pbs = [pb_by_pid[pid] for pid in sub]
        merged_cids = sorted({cid for pb in merged_pbs for cid in pb["member_cids"]})
        merged_sids: set[str] = set()
        for pb in merged_pbs:
            merged_sids |= set(pb.get("member_sids_union") or set())
            for cid in pb["member_cids"]:
                merged_sids |= members_by_cid.get(cid, set())
        if not merged_sids:
            out.extend(merged_pbs)  # defensive — shouldn't happen
            continue

        new_pid = min(sub)  # lex-smallest winning spb id
        name = group["name"]  # the shared pass-1 name survives the merge

        log.info(
            "Pass-2 merge: %d playbooks %s → %s '%s' (no distinguishing feature "
            "at floor %.2f)", len(sub), sub, new_pid, name, floor,
        )
        _apply_playbook_name(
            es, session_clusters_idx, sessions_idx, run_id,
            merged_cids, new_pid, name, stats,
            log_prefix="merge",
        )
        stats["collisions_merged"] += 1
        stats["playbooks_merged_away"] += len(sub) - 1

        # Refresh coverage over the merged membership for any later rename step
        # (the merged playbook may still collide with a frozen prior-run name).
        cov_sids = _subsample_sids(merged_sids, cfg.session.playbook_naming_session_cap)
        cov_total = len(cov_sids)
        cmd_cov = _fetch_command_coverage(
            es, events_idx, cov_sids, cfg.session.playbook_sample_commands,
        )
        ioc_cov = _fetch_ioc_coverage(
            es, sessions_idx, cov_sids, cfg.session.playbook_sample_commands,
        )
        out.append({
            "playbook_id": new_pid,
            "name": name,
            "member_cids": merged_cids,
            "sample_session_ids": merged_pbs[0].get("sample_session_ids") or [],
            "unique_commands": [c for c, _ in cmd_cov],
            "cmd_coverage": cmd_cov,
            "ioc_coverage": ioc_cov,
            "coverage_total": cov_total,
            "member_sids_union": merged_sids,
            "group_id": merged_pbs[0].get("group_id"),
            "size": sum(int(pb.get("size") or 0) for pb in merged_pbs),
        })

    return out


def _fetch_session_sample_commands(
    es: Elasticsearch,
    events_index: str,
    session_ids: list[str],
    max_commands: int = 15,
) -> list[str]:
    """Top unique commands from given session IDs via events index aggregation."""
    try:
        resp = es.search(
            index=events_index,
            size=0,
            query={"bool": {"must": [
                {"terms": {"cowrie.session_id": session_ids}},
                {"term": {"event.action": "cowrie.command.input"}},
            ]}},
            aggs={"top_commands": {"terms": {"field": "process.command_line", "size": max_commands}}},
        )
        buckets = resp.get("aggregations", {}).get("top_commands", {}).get("buckets", [])
        return [b["key"] for b in buckets if b.get("key")]
    except Exception as exc:
        log.warning("Could not fetch session commands: %s", exc)
        return []


# ===========================================================================
# Cluster-wide coverage sampling + distinctiveness (ROADMAP #11)
#
# A playbook name is only as good as the commands/IOCs the LLM sees. The old
# path sampled the first 5 session ids off the centroid doc, so the cluster's
# defining behaviour could be missing from the sample. These helpers instead
# rank features by *session coverage* (fraction of the cluster's sessions
# carrying the feature) over a representative random subsample of the full
# membership, and compute which features actually separate colliding clusters.
# ===========================================================================


def _subsample_sids(session_ids: Iterable[str], cap: int) -> list[str]:
    """De-duplicated session ids, randomly down-sampled to `cap` for a bounded,
    representative coverage aggregation. Deterministic only up to RNG state —
    coverage fractions are stable in expectation, which is what naming needs."""
    sids = list(dict.fromkeys(s for s in session_ids if s))
    if cap > 0 and len(sids) > cap:
        sids = random.sample(sids, cap)
    return sids


def _fetch_command_coverage(
    es: Elasticsearch,
    events_index: str,
    session_ids: list[str],
    max_commands: int = 15,
) -> list[tuple[str, int]]:
    """Cluster-wide command coverage: [(command, sessions_running_it)] sorted by
    coverage desc, capped at `max_commands`. Ranks by *distinct sessions* (the
    behaviour most sessions share), not raw occurrence (which one chatty
    session can dominate). Over-fetches the terms agg, then re-ranks by the
    per-command session cardinality. Caller supplies an already-subsampled id
    list so the denominator (`len(session_ids)`) is shared with IOC coverage."""
    if not session_ids:
        return []
    try:
        resp = es.search(
            index=events_index,
            size=0,
            query={"bool": {"must": [
                {"terms": {"cowrie.session_id": session_ids}},
                {"term": {"event.action": "cowrie.command.input"}},
            ]}},
            aggs={"by_cmd": {
                "terms": {"field": "process.command_line", "size": max(max_commands * 5, 50)},
                "aggs": {"sessions": {"cardinality": {"field": "cowrie.session_id"}}},
            }},
        )
    except Exception as exc:
        log.warning("Could not fetch command coverage: %s", exc)
        return []
    buckets = resp.get("aggregations", {}).get("by_cmd", {}).get("buckets", [])
    ranked = [
        (b["key"], int((b.get("sessions") or {}).get("value") or 0))
        for b in buckets if b.get("key")
    ]
    ranked.sort(key=lambda x: (-x[1], x[0]))
    return ranked[:max_commands]


def _fetch_ioc_coverage(
    es: Elasticsearch,
    sessions_index: str,
    session_ids: list[str],
    max_iocs: int = 15,
) -> list[tuple[str, int]]:
    """Cluster-wide IOC coverage from the session-rollup `artifact_set`:
    [(artifact, sessions_carrying_it)] sorted by coverage desc, capped at
    `max_iocs`. The rollup is one doc per session keyed by session id, so a
    terms-agg bucket's `doc_count` over `artifact_set.keyword` is exactly the
    number of sampled sessions carrying that artifact. Artifacts are already
    kind-prefixed (`ip:` / `domain:` / `url:` / `hash:` / `file:`)."""
    if not session_ids:
        return []
    field = "dshield.cowrie.enrichment.session.artifact_set.keyword"
    try:
        resp = es.search(
            index=sessions_index,
            size=0,
            query={"ids": {"values": session_ids}},
            aggs={"by_ioc": {"terms": {"field": field, "size": max(max_iocs * 5, 50)}}},
        )
    except Exception as exc:
        log.warning("Could not fetch IOC coverage: %s", exc)
        return []
    buckets = resp.get("aggregations", {}).get("by_ioc", {}).get("buckets", [])
    ranked = [(b["key"], int(b.get("doc_count") or 0)) for b in buckets if b.get("key")]
    ranked.sort(key=lambda x: (-x[1], x[0]))
    return ranked[:max_iocs]


def _format_coverage_lines(
    ranked: list[tuple[str, int]],
    total: int,
    *,
    strip_cmd_prefix: bool = False,
    indent: str = "  ",
) -> str:
    """Render coverage-ranked features as prompt lines with explicit session
    coverage, so the LLM can tell a defining behaviour (high coverage) from a
    one-off (low coverage). ROADMAP #11."""
    lines: list[str] = []
    for feat, n in ranked:
        if strip_cmd_prefix and feat.startswith("cmd:"):
            feat = feat[len("cmd:"):]
        pct = f"{(100 * n / total):.0f}%" if total else "?"
        lines.append(f"{indent}- {feat}   (in {n}/{total} sessions, {pct})")
    return "\n".join(lines) if lines else f"{indent}(none)"


def _combined_coverage_map(
    cmd_ranked: list[tuple[str, int]],
    ioc_ranked: list[tuple[str, int]],
    total_sessions: int,
) -> dict[str, float]:
    """Merge command + IOC coverage into one `{feature: fraction}` map for the
    distinctiveness/merge logic. Commands are prefixed `cmd:`; IOCs keep their
    native kind prefix. Fractions are coverage / total sampled sessions."""
    if total_sessions <= 0:
        return {}
    out: dict[str, float] = {}
    for cmd, n in cmd_ranked:
        out[f"cmd:{cmd}"] = n / total_sessions
    for ioc, n in ioc_ranked:
        out[ioc] = n / total_sessions
    return out


def _distinctive_features(
    coverage_by_key: dict[str, dict[str, float]],
    floor: float,
) -> dict[str, list[tuple[str, float]]]:
    """For each cluster key, the features distinctive to it: coverage >= floor
    in this cluster AND < floor in every sibling. Sorted by coverage desc.
    Pure — no I/O. ROADMAP #11."""
    keys = list(coverage_by_key.keys())
    out: dict[str, list[tuple[str, float]]] = {k: [] for k in keys}
    for k in keys:
        for feat, cov in coverage_by_key[k].items():
            if cov < floor:
                continue
            if all(coverage_by_key[o].get(feat, 0.0) < floor for o in keys if o != k):
                out[k].append((feat, cov))
        out[k].sort(key=lambda x: (-x[1], x[0]))
    return out


def _indistinguishable(a: dict[str, float], b: dict[str, float], floor: float) -> bool:
    """Two clusters are indistinguishable at `floor` when no feature is present
    (coverage >= floor) in one and absent (< floor) in the other — i.e. they
    share every prevalent feature and differ on none. Pure."""
    for feat in set(a) | set(b):
        if (a.get(feat, 0.0) >= floor) != (b.get(feat, 0.0) >= floor):
            return False
    return True


def _partition_mergeable(
    coverage_by_key: dict[str, dict[str, float]],
    floor: float,
) -> list[list[str]]:
    """Union-find over the mutually-indistinguishable relation. Returns groups
    of cluster keys (singletons as 1-element lists), each group's members
    sorted lexicographically, groups ordered by their lex-smallest member.
    A group of size >= 2 is a merge candidate. Pure. ROADMAP #11.

    Note the relation is not transitive in general (A~B and B~C does not force
    A~C); single-linkage union-find still groups a chain, which is the
    intended conservative behaviour here — if A merges with B and B with C
    they collapse to one playbook only when each pairwise step found no
    separating feature."""
    keys = sorted(coverage_by_key.keys())
    parent = {k: k for k in keys}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = keys[i], keys[j]
            if _indistinguishable(coverage_by_key[a], coverage_by_key[b], floor):
                ra, rb = find(a), find(b)
                if ra != rb:
                    parent[ra] = rb

    groups: dict[str, list[str]] = defaultdict(list)
    for k in keys:
        groups[find(k)].append(k)
    out = [sorted(members) for members in groups.values()]
    out.sort(key=lambda members: members[0])
    return out


def run_name_playbooks(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
    force: bool = False,
) -> dict:
    """Generate playbook names for each non-outlier session cluster (local LLM, never cloud)."""
    if not cfg.prompts.playbook_name:
        raise RuntimeError("prompts.playbook_name is unset in config.")

    prompt_template = Path(cfg.prompts.playbook_name).read_text()

    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    session_clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    clusters: list[dict] = []
    try:
        if not es.indices.exists(index=session_clusters_idx):
            raise RuntimeError(
                f"Session clusters index '{session_clusters_idx}' not found. "
                "Run 'cluster sessions' first."
            )
        resp = es.search(
            index=session_clusters_idx,
            size=1,
            query={"term": {"doc_type": "cluster"}},
            sort=[{"@timestamp": "desc"}],
            _source=["run_id"],
        )
        hits = resp["hits"]["hits"]
        if not hits:
            raise RuntimeError("No cluster docs found. Run 'cluster sessions' first.")
        run_id = hits[0]["_source"]["run_id"]
        resp2 = es.search(
            index=session_clusters_idx,
            size=1000,
            query={"bool": {"must": [
                {"term": {"doc_type": "cluster"}},
                {"term": {"run_id": run_id}},
            ]}},
            _source=["cluster_id", "size", "sample_session_ids", "playbook_name",
                     "run_id", "centroid"],
        )
        clusters = [h["_source"] for h in resp2["hits"]["hits"]]
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Could not load session clusters: {exc}") from exc

    log.info("Loaded %d session cluster centroid docs", len(clusters))

    # Filter outliers out before merging — they have no centroid and aren't
    # a behaviour group. Then collapse near-duplicate clusters into playbook
    # groups via cosine-similarity union-find. Threshold of 1.0 effectively
    # disables merging (1 cluster = 1 playbook). See
    # `merge_clusters_into_playbooks` and config.SessionConfig.playbook_merge_threshold.
    nameable = [
        c for c in clusters
        if c.get("cluster_id") and c.get("cluster_id") != "outlier" and c.get("centroid")
    ]
    centroids_by_cid = {c["cluster_id"]: c["centroid"] for c in nameable}
    cluster_to_group = merge_clusters_into_playbooks(
        centroids_by_cid, cfg.session.playbook_merge_threshold,
    )

    # Pull the *full* member session-id set per cluster from the rollup
    # index — the centroid doc only carries 5 samples, but the membership
    # seed (which feeds anchor mints) is content-hashed over the entire
    # membership so identical runs yield identical seeds.
    members_by_cid = _fetch_member_session_ids(
        es, sessions_idx, list(centroids_by_cid.keys()), cfg.session.page_size,
    )

    # Bucket cluster docs by their assigned playbook group.
    docs_by_group: dict[str, list[dict]] = defaultdict(list)
    for c in nameable:
        docs_by_group[cluster_to_group[c["cluster_id"]]].append(c)

    n_groups = len(docs_by_group)
    n_merged_groups = sum(1 for members in docs_by_group.values() if len(members) > 1)
    log.info(
        "Playbook merge: %d nameable clusters → %d playbook groups (%d merged) "
        "at threshold %.3f",
        len(nameable), n_groups, n_merged_groups,
        cfg.session.playbook_merge_threshold,
    )

    from ...llm import make_llm_client
    llm = make_llm_client(cfg.llm).__enter__()
    log.info("Playbook naming: using local LLM (%s)", cfg.llm.generation_model)

    stats: dict = defaultdict(int)
    # Outliers don't appear in `nameable` — record them here for parity with
    # the old per-cluster stats.
    stats["skipped_outlier"] = sum(1 for c in clusters if c.get("cluster_id") == "outlier")
    # Pass-1 named playbooks (carries pass-2 disambiguation context).
    # ROADMAP issue #10.
    named_in_run: list[dict] = []

    # Playbook identity: each playbook's centroid is matched against the
    # pinned anchors in the write-once `playbook_anchors` index. A match
    # reuses the anchor's id; a miss mints a fresh id and pins a new
    # anchor in the same call. Ids minted THIS run are appended to the
    # in-memory anchor set so two same-run groups on one lineage stay
    # consistent.
    anchor_idx = cfg.elasticsearch.indexes.cowrie.playbook_anchors
    if not es.indices.exists(index=anchor_idx):
        raise RuntimeError(
            f"playbook anchor index {anchor_idx!r} is missing — run "
            f"`init-indexes --source cowrie` before naming playbooks. "
            f"The anchor index is load-bearing; assignment cannot proceed."
        )
    anchors = _load_playbook_anchors(es, anchor_idx)
    # Ids already pinned (loaded + minted this run). A returned id not in
    # this set is a fresh mint → persist its anchor.
    known_anchor_ids: set[str] = {pid for _, pid in anchors}

    try:
        for group_id in sorted(docs_by_group.keys()):
            members = docs_by_group[group_id]
            member_cids = sorted(c["cluster_id"] for c in members)
            total_size = sum(int(c.get("size") or 0) for c in members)

            # Skip if every member is already named and not forcing. Mixed
            # state (some named, some not) → re-process so the whole group
            # ends up consistent.
            if not force and members and all(c.get("playbook_name") for c in members):
                stats["skipped_already_named"] += 1
                continue

            # A handful of illustrative session ids for the prompt's
            # SAMPLE_IDS slot (display only — naming evidence comes from
            # cluster-wide coverage below, not these).
            sample_sids: list[str] = []
            seen_sids: set[str] = set()
            for c in members:
                for sid in (c.get("sample_session_ids") or []):
                    if sid and sid not in seen_sids:
                        seen_sids.add(sid)
                        sample_sids.append(sid)
            sample_sids = sample_sids[:5]

            # Full membership across every constituent cluster. Drives both the
            # content-addressed playbook id and the coverage sampling below.
            # Empty membership is impossible here (`nameable` filtered outliers,
            # and clusters with zero member docs couldn't anchor a centroid) —
            # but be defensive anyway.
            member_sids_union: set[str] = set()
            for cid in member_cids:
                member_sids_union.update(members_by_cid.get(cid, set()))
            if not member_sids_union:
                stats["skipped_no_members"] += 1
                log.warning(
                    "Playbook group %s (clusters %s) has zero member sessions"
                    " in the rollup index — skipping naming",
                    group_id, member_cids,
                )
                continue

            # ROADMAP #11: rank commands + IOCs by session coverage (fraction of
            # the cluster's sessions carrying them) over a representative random
            # subsample of the *full* membership — not the first 5 sample
            # sessions. The cluster's defining behaviour is what most of its
            # sessions share. Coverage is stashed on the named_in_run entry so
            # pass-2 distinctiveness reuses it without re-querying.
            cov_sids = _subsample_sids(
                member_sids_union, cfg.session.playbook_naming_session_cap,
            )
            cov_total = len(cov_sids)
            cmd_coverage = _fetch_command_coverage(
                es, events_idx, cov_sids, cfg.session.playbook_sample_commands,
            )
            ioc_coverage = _fetch_ioc_coverage(
                es, sessions_idx, cov_sids, cfg.session.playbook_sample_commands,
            )

            if not cmd_coverage:
                stats["skipped_no_commands"] += 1
                log.debug("No commands found for playbook group %s (clusters %s)",
                          group_id, member_cids)
                continue

            stats["clusters_processed"] += len(members)
            stats["groups_processed"] += 1

            if dry_run:
                log.info(
                    "[dry-run] playbook %s (clusters=%s, %d sessions): would name from "
                    "%d commands over %d sampled sessions",
                    group_id, member_cids, total_size, len(cmd_coverage), cov_total,
                )
                continue

            # Membership seed: SHA-256 over the union of member session ids.
            # Reproducible across runs with identical membership, used only
            # to feed `_assign_playbook_id` when no anchor matches (and to
            # record the seed on the resulting anchor doc as audit trail).
            seed_id = _compute_seed_id(member_sids_union)

            # Assign the canonical `spb-` id: match the playbook's centroid
            # against pinned anchors, else mint fresh + pin. The anchor is
            # PINNED on mint and never updated, so a walking-centroid chain
            # (A~B>=thr, B~C>=thr, A~C<thr) can't collapse unrelated
            # playbooks under one id.
            group_unit = _playbook_group_centroid(members)
            if group_unit is not None:
                playbook_id = _assign_playbook_id(
                    group_unit, anchors,
                    cfg.session.playbook_merge_threshold, seed_id,
                )
                if playbook_id not in known_anchor_ids:
                    known_anchor_ids.add(playbook_id)
                    anchors.append((group_unit, playbook_id))
                    _persist_playbook_anchor(
                        es, anchor_idx, playbook_id,
                        group_unit, seed_id, run_id,
                    )
                    stats["id_minted"] += 1
                else:
                    stats["id_reused"] += 1
            else:
                # No usable member centroid (rare — every member would have
                # to lack a `centroid` field). Fall back to a pure-seed mint
                # so the playbook still has an id; no anchor pinned because
                # we have no centroid to match against later.
                playbook_id = _mint_playbook_id(seed_id)
                stats["id_no_centroid"] += 1
            stats["id_assigned"] += 1

            cluster_id_for_prompt = (
                member_cids[0] if len(member_cids) == 1
                else f"{playbook_id} (clusters: {', '.join(member_cids)})"
            )
            from ...llm.fencing import SYSTEM_PROMPT, fence, make_nonce
            # The coverage-ranked command list is raw attacker command text —
            # fence it. Cluster/session ids + size are system-generated.
            nonce = make_nonce()
            prompt = (
                prompt_template
                .replace("<<<CLUSTER_ID>>>", cluster_id_for_prompt)
                .replace("<<<SIZE>>>", str(total_size))
                .replace("<<<SAMPLE_IDS>>>", ", ".join(sample_sids))
                .replace("<<<COMMANDS>>>",
                         fence("commands", _format_coverage_lines(cmd_coverage, cov_total), nonce))
            )

            try:
                raw = llm.generate_json(
                    prompt,
                    schema=PLAYBOOK_NAME_JSON_SCHEMA,
                    schema_name="playbook_name",
                    options={"max_tokens": 512},
                    system=SYSTEM_PROMPT,
                )
                parsed = PlaybookName.model_validate_json(raw)
                name = parsed.playbook_name
                if not name:
                    raise ValueError("empty playbook_name")
            except Exception as exc:
                log.warning("LLM failed for playbook group %s (clusters %s): %s",
                            group_id, member_cids, exc)
                stats["llm_failed"] += 1
                continue

            log.info(
                "Playbook %s (clusters=%s, %d sessions) → '%s' (%s)",
                group_id, member_cids, total_size, name, parsed.rationale or "no rationale",
            )
            stats["named"] += 1
            named_in_run.append({
                "playbook_id": playbook_id,
                "name": name,
                "member_cids": member_cids,
                "sample_session_ids": sample_sids,
                "unique_commands": [c for c, _ in cmd_coverage],
                # ROADMAP #11: coverage stashed for pass-2 distinctiveness.
                "cmd_coverage": cmd_coverage,
                "ioc_coverage": ioc_coverage,
                "coverage_total": cov_total,
                "member_sids_union": member_sids_union,
                "group_id": group_id,
                "size": total_size,
            })

            _apply_playbook_name(
                es, session_clusters_idx, sessions_idx,
                run_id, member_cids, playbook_id, name, stats,
                log_prefix="playbook",
            )

        # -------------------------------------------------------------------
        # Pass 2 — resolve naming collisions (ROADMAP #11). For each collision
        # group: first merge any mutually-indistinguishable playbooks into one
        # (deterministic, distinctiveness-gated), then ask the LLM to rename
        # whatever genuinely-distinct playbooks remain — anchoring on the
        # computed distinctive feature set.
        # -------------------------------------------------------------------
        if cfg.prompts.playbook_disambiguate and named_in_run:
            existing = _load_other_playbook_names(
                es, session_clusters_idx, exclude_run_id=run_id,
            )
            collisions = _detect_name_collisions(named_in_run, existing)
            stats["collisions_detected"] = len(collisions)
            if collisions:
                disamb_prompt_template = Path(cfg.prompts.playbook_disambiguate).read_text()
                log.info(
                    "Pass-2 disambiguation: %d name collision group(s) "
                    "(in-run renamables: %d; frozen colliders: %d)",
                    len(collisions),
                    sum(len(g["renamable"]) for g in collisions),
                    sum(len(g["frozen"]) for g in collisions),
                )
                for group in collisions:
                    # Merge step: collapse playbooks with no distinguishing
                    # feature; returns the post-merge renamable set.
                    post_merge = _merge_collision_subgroups(
                        es=es,
                        group=group,
                        members_by_cid=members_by_cid,
                        run_id=run_id,
                        session_clusters_idx=session_clusters_idx,
                        sessions_idx=sessions_idx,
                        events_idx=events_idx,
                        cfg=cfg,
                        stats=stats,
                    )
                    # Rename step only when a real collision survives the merge
                    # (more than one distinct name-holder for this name).
                    if len(post_merge) + len(group["frozen"]) < 2 or not post_merge:
                        continue
                    stats["collisions_renamed"] += 1
                    _run_disambiguation_pass(
                        es=es,
                        llm=llm,
                        prompt_template=disamb_prompt_template,
                        group={"name": group["name"], "renamable": post_merge,
                               "frozen": group["frozen"]},
                        run_id=run_id,
                        session_clusters_idx=session_clusters_idx,
                        sessions_idx=sessions_idx,
                        events_idx=events_idx,
                        cfg=cfg,
                        stats=stats,
                    )

    finally:
        llm.__exit__(None, None, None)

    # Refresh both indexes so `mine campaigns` (next pipeline step) sees the
    # playbook_id values we just wrote onto every member session. Without
    # this the miner reads a partial snapshot and the behaviour itemsets
    # come up empty even when the data supports them.
    try:
        es.indices.refresh(index=f"{session_clusters_idx},{sessions_idx}")
    except Exception as exc:
        log.warning("name-playbooks refresh failed (continuing): %s", exc)

    return dict(
        stats,
        total_clusters=len(clusters),
        total_groups=n_groups,
        merged_groups=n_merged_groups,
        merge_threshold=cfg.session.playbook_merge_threshold,
        dry_run=dry_run,
        force=force,
    )
