#!/usr/bin/env python
"""Item 56 — why has the large novel behaviour never been minted as an anchor?

Finding 43 measured that ~95.7% of the novel pool forms one coherent group that
HDBSCAN resolves cleanly, yet none of the pinned anchors covers it. This script
answers *which gate* in ``sessions.run_name_playbooks`` suppresses the mint, by
walking that pool's sessions through the real mint path in production order and
attributing every eliminated session to a gate:

    G0 run_scope            the naming run never saw the session (window/scope)
    G1 cluster_truncation   its cluster fell outside the unpaged size=1000 load
    G2 outlier              no centroid -> not in `nameable`
    G3 merge_absorb         folded into a playbook group with incumbents (descriptive)
    G4 pre_mint_skips       skipped_already_named / _no_members / _no_commands
    G5 id_reused            the group centroid matched an anchor -> no mint
    G6 centroid_vs_member   the mismatch measurement (descriptive)

Gate order is the point: reporting only the outcome ("no anchor exists") repeats
what Finding 43 already knows. Every gate reports sessions-in and eliminated, and
eliminations plus survivors always equal the pool size.

Read-only and aggregate-only: counts, cosines, cluster ids and ``spb-`` ids. No
session ids, IPs or command text are ever emitted, and nothing is written to
Elasticsearch. Pinned anchor centroids are aggregate but mixed-classification-
derived, so a live run needs explicit operator confirmation:

    console/.venv/bin/python scripts/diagnose_unminted_playbook.py \
      --confirm-mixed-derived-anchors

Membership truth is the *live* clustering run's cluster docs plus each session's
rollup ``cluster.id`` — production state, not a re-simulation (Findings 31/33/40/42).
The one HDBSCAN run here defines "the ~1,904-session behaviour" exactly as Finding
43 did, because production never clustered this pool in the first place; its shape
is cross-checked against `eval_novel_pool.cluster_novel_pool` so the two cannot drift.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
from sklearn.cluster import HDBSCAN

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eval_novel_pool import (
    NovelPoolInputs,
    _extract_scalars,
    _scan,
    _session,
    cluster_novel_pool,
)

from enrich.classification import CLASSIFICATION_KEYWORD, PUBLIC, releasable_filter
from enrich.clustering import (
    compute_centroids,
    l2_normalize,
    rescue_noise_points,
    svd_reduce,
)
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.assign_runner import _load_anchors
from enrich.sources.cowrie.assignment import NOVEL, compute_assignment_window
from enrich.sources.cowrie.lexical import build_bag_texts, pull_hash_to_cluster
from enrich.sources.cowrie.sessions import (
    _assign_playbook_id,
    _compute_seed_id,
    _load_playbook_anchors,
    _playbook_group_centroid,
    build_session_scalar_block,
    merge_clusters_into_playbooks,
)

_S = "dshield.cowrie.enrichment.session"
_EMB = f"{_S}.embedding"
_CMDSET = f"{_S}.command_set"
_PB = f"{_S}.playbook_id"
_CID = f"{_S}.cluster.id"
_ASTATUS = f"{_S}.cluster.assignment_status"
_SOURCE_FIELDS = [
    "@timestamp",
    "cowrie.session_id",
    _EMB,
    _CMDSET,
    _CID,
    _ASTATUS,
    f"{_S}.command_count",
    f"{_S}.unique_commands",
    f"{_S}.login_success_count",
    f"{_S}.login_fail_count",
    f"{_S}.mean_novelty_score",
]

# `run_name_playbooks` loads this run's cluster docs with a single unpaged
# search. Mirrored exactly so G1 measures the truncation production would hit,
# rather than a guess at which clusters a `size=1000` cut would drop.
NAMING_CLUSTER_LOAD_SIZE = 1000

GATE_ORDER = (
    "G0_run_scope",
    "G1_cluster_not_visible",
    "G2_outlier",
    "G3_merge_absorb",
    "G4_pre_mint_skips",
    "G5_id_reused",
    "G6_centroid_vs_member",
)


# ---------------------------------------------------------------------------
# Loading (ES-facing)
# ---------------------------------------------------------------------------

def public_filters(cfg) -> list[dict]:
    """The fail-closed public-only clause, plus an always-explicit public term.

    Same posture as `eval_novel_pool.load_public_inputs`: a diagnostic is stricter
    than a deployment's optional fail-open configuration.
    """
    configured = releasable_filter(cfg)
    explicit = {"term": {CLASSIFICATION_KEYWORD: PUBLIC}}
    return [configured] if configured == explicit else [configured, explicit]


def load_pool_inputs(es, cfg, *, per_anchor: int = 300):
    """One public-only pass over the session rollup, carrying identity alongside geometry.

    Returns ``(NovelPoolInputs, rows)`` where ``rows`` is index-aligned with the
    embeddings and holds ``session_id`` / ``cluster_id`` / ``@timestamp`` /
    ``assignment_status``. `eval_novel_pool.load_public_inputs` drops identity by
    design (it only ever reports aggregates); the gate ladder needs to follow
    individual sessions into the live clustering run, so the scan is repeated here
    rather than re-ordered across two calls, whose `_doc` sort is not stable.
    """
    if per_anchor <= 0:
        raise ValueError("per_anchor must be positive")
    indexes = cfg.elasticsearch.indexes.cowrie
    filters = public_filters(cfg)
    anchor_ids, anchor_embeddings, _sigs = _load_anchors(es, indexes.playbook_anchors)

    embeddings: list[list[float]] = []
    command_sets: list[list[str]] = []
    scalars: list[dict] = []
    rows: list[dict] = []
    window_filter = [*filters, {"exists": {"field": _EMB}}]
    for hit in _scan(es, indexes.sessions_rollup, window_filter, _SOURCE_FIELDS):
        src = hit["_source"]
        session = _session(src)
        embedding = session.get("embedding")
        if not embedding:
            continue
        embeddings.append(embedding)
        command_sets.append(list(session.get("command_set") or []))
        scalars.append(_extract_scalars(session))
        cluster = session.get("cluster") or {}
        rows.append({
            "session_id": (src.get("cowrie") or {}).get("session_id") or hit["_id"],
            "cluster_id": cluster.get("id"),
            "assignment_status": cluster.get("assignment_status"),
            "timestamp": src.get("@timestamp"),
        })
    if not embeddings:
        raise ValueError("no explicitly-public embedded sessions found")

    if not anchor_ids:
        # Not an error: with no anchor library every group would mint. The gate
        # ladder short-circuits on this and says so.
        return None, rows

    anchor_sets: list[list[str]] = []
    anchor_bag_ids: list[str] = []
    for anchor_id in anchor_ids:
        anchor_filters = [*filters, {"exists": {"field": _EMB}}, {"term": {_PB: anchor_id}}]
        for hit in _scan(
            es, indexes.sessions_rollup, anchor_filters, [_CMDSET],
            page_size=min(per_anchor, 2000),
        ):
            anchor_sets.append(list(_session(hit["_source"]).get("command_set") or []))
            anchor_bag_ids.append(anchor_id)
            if anchor_bag_ids.count(anchor_id) >= per_anchor:
                break

    hash_to_cluster = pull_hash_to_cluster(es, indexes.commands, filt=filters)
    if not hash_to_cluster:
        raise ValueError(
            "public command taxonomy is empty; refusing a degenerate lexical replay "
            "(classify/rebuild the command enrichment index before rerunning)",
        )
    all_bags = build_bag_texts(anchor_sets + command_sets, hash_to_cluster)
    n_anchor_bags = len(anchor_sets)
    matrix = np.asarray(embeddings, dtype=np.float32)
    anchor_matrix = np.asarray(anchor_embeddings, dtype=np.float32)
    # Same input validation `load_public_inputs` performs. Without it a scalar or
    # ragged embedding field reaches `.shape[1]` as an IndexError, which `main`
    # does not catch, and the operator gets a traceback instead of exit 2.
    if matrix.ndim != 2 or anchor_matrix.ndim != 2:
        raise ValueError("session and anchor embeddings must be two-dimensional")
    if not np.all(np.isfinite(matrix)) or not np.all(np.isfinite(anchor_matrix)):
        raise ValueError("session and anchor embeddings must contain only finite values")
    if matrix.shape[1] != anchor_matrix.shape[1]:
        raise ValueError(
            f"embedding dimension mismatch: sessions={matrix.shape[1]}, "
            f"anchors={anchor_matrix.shape[1]}",
        )
    inputs = NovelPoolInputs(
        embeddings=l2_normalize(matrix),
        command_bags=all_bags[n_anchor_bags:],
        scalars=scalars,
        anchor_embeddings=anchor_matrix,
        anchor_ids=anchor_ids,
        anchor_bags=all_bags[:n_anchor_bags],
        anchor_bag_ids=anchor_bag_ids,
        command_taxonomy_size=len(hash_to_cluster),
    )
    return inputs, rows


def load_latest_run(es, session_clusters_idx: str) -> dict:
    """The run `name playbooks` would name: newest `run_summary` completion sentinel."""
    resp = es.search(
        index=session_clusters_idx, size=1,
        query={"term": {"doc_type": "run_summary"}},
        sort=[{"@timestamp": "desc"}],
        # `@timestamp` is load-bearing, not decoration: production evaluates its
        # `now-Nd/d` window at RUN time, so the scope gate has to be anchored to
        # when the run executed, never to when this diagnostic happens to run.
        _source=["run_id", "@timestamp", "window_days", "total_docs", "n_clusters",
                 "n_outliers", "n_rescued", "clustering_config"],
    )
    hits = resp["hits"]["hits"]
    if not hits:
        raise RuntimeError(
            "no completed cluster run found — run `cluster sessions` first",
        )
    run = hits[0]["_source"]
    if not run.get("run_id"):
        raise RuntimeError("latest run_summary carries no run_id; the run is unusable")
    return run


def load_naming_clusters(es, session_clusters_idx: str, run_id: str):
    """Reproduce `run_name_playbooks`' cluster load byte-for-byte, plus the true count.

    The production query is a single unpaged `size=1000` search, so issuing the
    identical query yields the same *shape* of cluster set naming can see — which
    is what G1 needs, since a `size` cut's victims are not otherwise derivable.
    Neither query sorts, so when the run genuinely exceeds the cut this draw is a
    different arbitrary sample than the one naming took; G1 reports that caveat
    rather than pretending to name the exact victims.
    """
    query = {"bool": {"must": [
        {"term": {"doc_type": "cluster"}},
        {"term": {"run_id": run_id}},
    ]}}
    resp = es.search(
        index=session_clusters_idx, size=NAMING_CLUSTER_LOAD_SIZE, query=query,
        _source=["cluster_id", "size", "sample_session_ids", "playbook_name",
                 "run_id", "centroid"],
    )
    visible = [h["_source"] for h in resp["hits"]["hits"]]
    total = int(es.count(index=session_clusters_idx, query=query)["count"])
    return visible, total


def group_has_public_commands(es, events_idx: str, session_ids: list[str],
                              filters: list[dict]) -> bool:
    """Does this group have any public command evidence at all?

    Production's `_fetch_command_coverage` ranks `process.command_line` text and
    carries no classification filter. This asks only the yes/no question the
    `skipped_no_commands` gate turns on, over explicitly-public events, and never
    pulls the command strings. Being a strict subset of what production sees, a
    True here is conclusive (the gate cannot fire); a False is conservative.
    """
    if not session_ids:
        return False
    resp = es.count(
        index=events_idx,
        query={"bool": {"filter": [
            *filters,
            {"terms": {"cowrie.session_id": session_ids}},
            {"term": {"event.action": "cowrie.command.input"}},
        ]}},
    )
    return int(resp["count"]) > 0


# ---------------------------------------------------------------------------
# Pool identification (pure)
# ---------------------------------------------------------------------------

def pool_group_labels(embeddings, scalars: list[dict], *, min_cluster_size: int,
                      min_samples: int, scalar_weight: float, rescue_threshold: float,
                      merge_threshold: float, svd_dim: int, n_jobs: int):
    """Per-row playbook-group labels for the novel pool (-1 = residual outlier).

    Runs the identical pipeline as `eval_novel_pool.cluster_novel_pool`, which
    returns aggregates only; the caller cross-checks the two agree.
    """
    matrix = np.asarray(embeddings, dtype=np.float32)
    n_total = int(matrix.shape[0])
    if n_total < min_cluster_size:
        return np.full(n_total, -1, dtype=np.int64)
    normalized = l2_normalize(matrix)
    scalar_block = (
        build_session_scalar_block(scalars, scalar_weight) if scalar_weight > 0.0 else None
    )
    cluster_matrix = (
        np.hstack([normalized, scalar_block]) if scalar_block is not None else normalized
    )
    reduced, _ = svd_reduce(normalized, svd_dim)
    fit_matrix = (
        np.hstack([reduced, scalar_block])
        if scalar_block is not None and reduced.shape[1] < normalized.shape[1]
        else (reduced if reduced.shape[1] < normalized.shape[1] else cluster_matrix)
    )
    labels = np.asarray(
        HDBSCAN(min_cluster_size=min_cluster_size, min_samples=min_samples,
                metric="euclidean", n_jobs=n_jobs).fit_predict(fit_matrix),
        dtype=np.int64,
    )
    if rescue_threshold > 0.0:
        labels, _ = rescue_noise_points(normalized, labels, rescue_threshold)
    centroids = compute_centroids(normalized, labels)
    groups = merge_clusters_into_playbooks(
        {str(label): centroid.tolist() for label, centroid in centroids.items()},
        merge_threshold,
    )
    group_to_int: dict[str, int] = {}
    merged = np.full(n_total, -1, dtype=np.int64)
    for i, label in enumerate(labels):
        if int(label) < 0:
            continue
        group = groups[str(int(label))]
        group_to_int.setdefault(group, len(group_to_int))
        merged[i] = group_to_int[group]
    return merged


def cosine_summary(values, tau: float) -> dict:
    """Distribution of member cosines against one anchor — the G6 measurement."""
    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 0:
        return {"n": 0}
    return {
        "n": int(arr.size),
        "min": round(float(arr.min()), 4),
        "p25": round(float(np.percentile(arr, 25)), 4),
        "median": round(float(np.median(arr)), 4),
        "p75": round(float(np.percentile(arr, 75)), 4),
        "max": round(float(arr.max()), 4),
        "fraction_ge_tau": round(float(np.mean(arr >= tau)), 4),
    }


# ---------------------------------------------------------------------------
# The gate ladder (pure)
# ---------------------------------------------------------------------------

def _gate(name: str, sessions_in: int, eliminated: int, detail: dict) -> dict:
    return {
        "gate": name,
        "sessions_in": sessions_in,
        "eliminated": eliminated,
        "detail": detail,
    }


def evaluate_gates(pool: list[dict], run: dict, visible_clusters: list[dict],
                   clusters_in_run: int, anchors: list, *, merge_threshold: float,
                   assignment_tau: float, commands_probe) -> list[dict]:
    """Walk the pool through `run_name_playbooks`' gates in production order.

    `pool` rows carry `session_id`, `cluster_id`, `in_window` and `embedding` (unit).
    `commands_probe(session_ids) -> bool` answers the `skipped_no_commands` question.
    Every gate reports sessions-in and eliminated; the two always reconcile with the
    pool size, so no session can go unaccounted for.
    """
    gates: list[dict] = []
    alive = list(pool)

    # G0 — the naming run's scope. A windowed run (`cluster_window_days`, default
    # 30) never saw older sessions, so they cannot enter the mint path at all.
    window_days = int(run.get("window_days") or 0)
    out_of_window = [r for r in alive if not r["in_window"]]
    # The run_summary persists no novel-pool flag, so scope can only be inferred.
    # Production's own novelty verdict is on the session docs: if the run was
    # novel-pool-scoped it only saw docs whose `assignment_status` was "novel"
    # at the time. Report the distribution and the disagreement with this run's
    # recomputed novelty — a strong hint, deliberately not an elimination.
    persisted = Counter(r.get("assignment_status") or "absent" for r in alive)
    detail0 = {
        "window_days": window_days,
        "run_started": run.get("@timestamp"),
        "run_total_docs": run.get("total_docs"),
        "run_n_clusters": run.get("n_clusters"),
        "run_n_outliers": run.get("n_outliers"),
        "pool_in_window": len(alive) - len(out_of_window),
        "scope_hint": "windowed" if window_days > 0 else "all_time",
        "persisted_assignment_status": dict(persisted),
        # Every row here is novel by this run's recompute; any that production
        # last recorded as assigned means the two disagree about the pool.
        "disagrees_with_persisted_novelty": sum(
            n for status, n in persisted.items() if status not in (NOVEL, "absent")
        ),
    }
    gates.append(_gate(GATE_ORDER[0], len(alive), len(out_of_window), detail0))
    alive = [r for r in alive if r["in_window"]]

    # G1 — the session's cluster is not among the ones naming can see. Two very
    # different causes share this outcome and must not be conflated: the unpaged
    # size=1000 cluster load genuinely cutting clusters off, versus a rollup
    # `cluster.id` left over from an EARLIER run (cluster ids are `cluster_<int>`
    # and are not run-scoped, so a session the latest run never re-clustered keeps
    # its stale id). Calling the second one "truncation" sends the operator after
    # a paging bug that never fired.
    visible_ids = {c.get("cluster_id") for c in visible_clusters if c.get("cluster_id")}
    truncated = clusters_in_run > NAMING_CLUSTER_LOAD_SIZE
    dropped = [
        r for r in alive
        if r["cluster_id"] and r["cluster_id"] != "outlier"
        and r["cluster_id"] not in visible_ids
    ]
    detail1 = {
        "clusters_in_run": clusters_in_run,
        "clusters_visible_to_naming": len(visible_clusters),
        "naming_load_size": NAMING_CLUSTER_LOAD_SIZE,
        "truncated": truncated,
        "cause": "size_1000_truncation" if truncated else "stale_or_absent_cluster_id",
        # A stale id that happens to COLLIDE with a current-run id cannot be
        # detected from `cluster.id` alone — such a session is silently attributed
        # to an unrelated cluster and pollutes G3/G5/G6. Flag the exposure.
        "stale_id_collision_risk": window_days > 0 or clusters_in_run < (
            int(run.get("n_clusters") or 0) or clusters_in_run
        ),
        "unsorted_draw_caveat": (
            "neither production's load nor this one sorts, so the truncated victims "
            "are a different arbitrary draw than naming's"
        ) if truncated else None,
    }
    gates.append(_gate(GATE_ORDER[1], len(alive), len(dropped), detail1))
    dropped_ids = {id(r) for r in dropped}
    alive = [r for r in alive if id(r) not in dropped_ids]

    # G2 — `nameable` keeps only clustered docs that carry a centroid. An outlier
    # (or a session with no cluster assignment) has no centroid and never mints.
    by_cid = {c["cluster_id"]: c for c in visible_clusters if c.get("cluster_id")}
    def _nameable(row) -> bool:
        cid = row["cluster_id"]
        if not cid or cid == "outlier":
            return False
        doc = by_cid.get(cid)
        return bool(doc and doc.get("centroid"))
    unnameable = [r for r in alive if not _nameable(r)]
    detail2 = {
        "no_cluster_assignment": sum(1 for r in alive if not r["cluster_id"]),
        "outlier": sum(1 for r in alive if r["cluster_id"] == "outlier"),
        "cluster_without_centroid": sum(
            1 for r in alive
            if r["cluster_id"] and r["cluster_id"] != "outlier"
            and not (by_cid.get(r["cluster_id"]) or {}).get("centroid")
        ),
    }
    gates.append(_gate(GATE_ORDER[2], len(alive), len(unnameable), detail2))
    alive = [r for r in alive if _nameable(r)]

    # G3 — cluster-to-playbook merge. Descriptive: it eliminates nobody on its
    # own, but it decides whose centroid the mint test is applied to, and folding
    # the pool in with a large incumbent is what makes G5/G6 possible.
    nameable_docs = [c for c in visible_clusters if c.get("cluster_id")
                     and c["cluster_id"] != "outlier" and c.get("centroid")]
    centroids_by_cid = {c["cluster_id"]: c["centroid"] for c in nameable_docs}
    cluster_to_group = (
        merge_clusters_into_playbooks(centroids_by_cid, merge_threshold)
        if centroids_by_cid else {}
    )
    pool_by_cid = Counter(r["cluster_id"] for r in alive)
    rows_by_group: dict[str, list[dict]] = defaultdict(list)
    for r in alive:
        rows_by_group[cluster_to_group[r["cluster_id"]]].append(r)
    docs_by_group: dict[str, list[dict]] = defaultdict(list)
    for c in nameable_docs:
        docs_by_group[cluster_to_group[c["cluster_id"]]].append(c)
    detail3 = {
        "merge_threshold": merge_threshold,
        "nameable_clusters": len(nameable_docs),
        "playbook_groups": len(docs_by_group),
        "groups_holding_pool": len(rows_by_group),
        "groups": sorted(
            (
                {
                    "group": gid,
                    "pool_sessions": len(rows),
                    "member_clusters": sorted(c["cluster_id"] for c in docs_by_group[gid]),
                    "member_cluster_sizes": {
                        c["cluster_id"]: int(c.get("size") or 0) for c in docs_by_group[gid]
                    },
                    "pool_sessions_by_cluster": {
                        cid: pool_by_cid[cid] for cid in
                        sorted(c["cluster_id"] for c in docs_by_group[gid])
                        if pool_by_cid.get(cid)
                    },
                    "absorbed_with_incumbents": any(
                        not pool_by_cid.get(c["cluster_id"]) for c in docs_by_group[gid]
                    ),
                }
                for gid, rows in rows_by_group.items()
            ),
            key=lambda g: -g["pool_sessions"],
        ),
    }
    gates.append(_gate(GATE_ORDER[3], len(alive), 0, detail3))

    # G4 — the three `continue`s that fire BEFORE the mint block.
    skipped: dict[str, list[str]] = {"already_named": [], "no_members": [], "no_commands": []}
    for gid, rows in rows_by_group.items():
        docs = docs_by_group[gid]
        if docs and all(d.get("playbook_name") for d in docs):
            skipped["already_named"].append(gid)
            continue
        sids = [r["session_id"] for r in rows]
        if not sids:
            skipped["no_members"].append(gid)
            continue
        if not commands_probe(sids):
            skipped["no_commands"].append(gid)
    skipped_groups = {g for group_ids in skipped.values() for g in group_ids}
    eliminated4 = sum(len(rows_by_group[g]) for g in skipped_groups)
    detail4 = {
        "skipped_already_named": sorted(skipped["already_named"]),
        "skipped_no_members": sorted(skipped["no_members"]),
        "skipped_no_commands": sorted(skipped["no_commands"]),
        "no_commands_probe": "public_only_conservative",
        # Every group here holds pool sessions by construction, so production's
        # empty-membership guard cannot fire; reported for completeness.
        "no_members_reachable": False,
    }
    gates.append(_gate(GATE_ORDER[4], len(alive), eliminated4, detail4))
    for gid in skipped_groups:
        rows_by_group.pop(gid, None)
    alive = [r for rows in rows_by_group.values() for r in rows]

    # G5 — the mint test itself: match the group centroid against the pinned
    # anchors. A match reuses the incumbent id, so the behaviour never gets one.
    # Production appends each freshly-minted anchor to its in-memory set inside
    # the group loop, so a later group on the same lineage reuses the id minted
    # earlier in the SAME run. Evaluating every group against a static library
    # would report that second group as `would_mint` and can manufacture a
    # spurious "no gate fires" verdict. Mirror the accumulation, and iterate in
    # production's `sorted(docs_by_group)` order so the accumulation matches too.
    working = list(anchors)
    known_ids = {pid for _, pid in working}
    reused_groups: dict[str, dict] = {}
    no_centroid_groups: list[str] = []
    group_reports: list[dict] = []
    for gid in sorted(rows_by_group):
        rows = rows_by_group[gid]
        docs = docs_by_group[gid]
        centroid = _playbook_group_centroid(docs)
        if centroid is None:
            # Production's `else` branch mints a pure-seed id and pins NO anchor
            # (`id_no_centroid`), so the behaviour gets an id and still never gets
            # an anchor. That is a mint suppression in its own right, not a case
            # to drop silently from the ladder.
            no_centroid_groups.append(gid)
            group_reports.append({
                "group": gid, "pool_sessions": len(rows),
                "outcome": "no_centroid_no_anchor_pinned",
                "matched_anchor": None, "matched_cosine": None,
                "top3_anchor_cosines": [],
            })
            continue
        seed = _compute_seed_id(r["session_id"] for r in rows)
        assigned = _assign_playbook_id(centroid, working, merge_threshold, seed)
        # Mirror `_assign_playbook_id`'s own argmax rather than an independent
        # sort, so the reported cosine always belongs to the reported anchor
        # (a sort on (cosine, id) tuples breaks ties differently from argmax).
        matched_cosine = None
        if working:
            sims_arr = np.array([float(vec @ centroid) for vec, _ in working])
            matched_cosine = round(float(sims_arr[int(np.argmax(sims_arr))]), 4)
        ranked = sorted(
            ((round(float(vec @ centroid), 4), pid) for vec, pid in working), reverse=True,
        )
        reused = assigned in known_ids
        group_reports.append({
            "group": gid,
            "pool_sessions": len(rows),
            "outcome": "id_reused" if reused else "would_mint",
            "matched_anchor": assigned if reused else None,
            "matched_cosine": matched_cosine,
            "top3_anchor_cosines": [
                {"playbook_id": pid, "cosine": cos} for cos, pid in ranked[:3]
            ],
        })
        if reused:
            reused_groups[gid] = {"anchor": assigned, "centroid": centroid,
                                  "cosine": matched_cosine}
        else:
            known_ids.add(assigned)
            working.append((centroid, assigned))
    eliminated5 = sum(
        len(rows_by_group[g]) for g in (*reused_groups, *no_centroid_groups)
    )
    detail5 = {
        "n_anchors": len(anchors),
        "anchors_minted_in_run": len(working) - len(anchors),
        "no_centroid_groups": sorted(no_centroid_groups),
        "groups": sorted(group_reports, key=lambda g: -g["pool_sessions"]),
    }
    gates.append(_gate(GATE_ORDER[5], len(alive), eliminated5, detail5))

    # G6 — the item 56 hypothesis. Descriptive: for the largest group the mint
    # test folded into an incumbent, compare the group centroid's cosine to that
    # anchor against the pool members' own cosines. A mismatch means the centroid
    # is inside the anchor's radius while its members are not.
    detail6: dict = {"measured": False}
    if reused_groups:
        gid = max(reused_groups, key=lambda g: len(rows_by_group[g]))
        info = reused_groups[gid]
        # Look the anchor up in `working`, not `anchors`: the match may be an id
        # minted earlier in this same run, which the pinned library does not hold.
        anchor_vec = next(vec for vec, pid in working if pid == info["anchor"])
        members = np.asarray(
            [r["embedding"] for r in rows_by_group[gid]], dtype=np.float32,
        )
        member_cosines = members @ anchor_vec
        summary = cosine_summary(member_cosines, assignment_tau)
        detail6 = {
            "measured": True,
            "group": gid,
            "anchor": info["anchor"],
            "assignment_tau": assignment_tau,
            "centroid_cosine": info["cosine"],
            "member_cosines": summary,
            "mismatch": bool(
                info["cosine"] is not None
                and info["cosine"] >= merge_threshold
                and summary.get("fraction_ge_tau", 1.0) < 0.5
            ),
        }
    # `sessions_in` here is the population G5 eliminated — the group this gate
    # exists to explain — not the survivors, which by definition need no diagnosis.
    gates.append(_gate(GATE_ORDER[6], eliminated5, 0, detail6))
    return gates


def _g6_clause(gates: list[dict]) -> str:
    """The centroid-vs-member result, if it was measured at all.

    Appended whichever gate fired first: an earlier gate eliminating some sessions
    does not make the mismatch measurement on the rest less interesting — it is the
    reason the script exists, and burying it behind `--json` wastes the run.
    """
    g6 = next((g for g in gates if g["gate"] == GATE_ORDER[6]), None)
    detail = (g6 or {}).get("detail") or {}
    if not detail.get("measured"):
        return ""
    mc = detail["member_cosines"]
    return (
        f" Centroid-vs-member: group centroid matched {detail['anchor']} at "
        f"{detail['centroid_cosine']}, members' median cosine {mc.get('median')}, "
        f"{mc.get('fraction_ge_tau', 0.0):.1%} clear tau={detail['assignment_tau']} "
        f"— mismatch {'CONFIRMED' if detail['mismatch'] else 'NOT confirmed'}."
    )


def verdict(gates: list[dict], pool_size: int) -> str:
    """First gate that eliminated pool sessions, with its count and the G6 result."""
    if pool_size == 0:
        return "no_novel_pool — the deployed τ leaves no novel sessions to explain"
    for gate in gates:
        if gate["eliminated"] > 0:
            share = gate["eliminated"] / pool_size
            return (
                f"{gate['gate']} — {gate['eliminated']}/{pool_size} "
                f"({share:.1%}) pool sessions eliminated here."
                + _g6_clause(gates)
            )
    return (
        "no_gate_fires — every pool session reaches the mint block; look elsewhere."
        + _g6_clause(gates)
    )


def zeroed_gates() -> list[dict]:
    """All seven gates at zero — the shape the early-return paths must still emit,
    so a consumer never has to special-case an absent `gates` list."""
    return [_gate(name, 0, 0, {"evaluated": False}) for name in GATE_ORDER]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _parse_ts(timestamp):
    """Lenient ISO-8601 parse, normalised to UTC. None when undatable."""
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(str(timestamp))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def window_cutoff(window_days: int, run_started):
    """The `now-Nd/d` boundary the naming run's clustering query actually used.

    Production evaluates the range filter when the run executes and floors it to
    a day boundary (`/d`). Anchoring to *this* script's clock instead would move
    the boundary by however long ago the run was, misclassifying a whole band of
    sessions in both directions — and G0 is the first gate, so that lands
    straight in the verdict. None means "no window" (all-time run).
    """
    if window_days <= 0:
        return None
    anchor = _parse_ts(run_started) or datetime.now(UTC)
    day_start = anchor.replace(hour=0, minute=0, second=0, microsecond=0)
    return day_start - timedelta(days=window_days)


def _in_window(timestamp, cutoff) -> bool:
    """Was this session inside the naming run's clustering window?

    `cutoff` of None means an all-time run: everything is in scope. An unparseable
    or missing timestamp counts as in-window — the gate must never blame scope for
    a session it simply could not date.
    """
    if cutoff is None:
        return True
    parsed = _parse_ts(timestamp)
    return True if parsed is None else parsed >= cutoff


def diagnose(es, cfg, *, per_anchor: int = 300) -> dict:
    scfg = cfg.session
    assignment_tau = float(scfg.assignment_tau)
    merge_threshold = float(scfg.playbook_merge_threshold)
    rescue_tau = float(getattr(scfg, "assignment_rescue_tau", assignment_tau))
    # Same guard `eval_novel_pool.analyze` enforces. With a rescue tier actually
    # configured, replaying the pool as if it were disabled silently produces a
    # LARGER novel pool than production has — and then all seven gates describe a
    # population that does not exist. Refuse rather than measure the wrong thing.
    if abs(rescue_tau - assignment_tau) > 1e-12:
        raise ValueError(
            "exact assignment replay requires the structural rescue tier to be "
            "disabled (session.assignment_rescue_tau must equal session.assignment_tau; "
            f"got {rescue_tau} vs {assignment_tau})",
        )
    naming_cap = int(scfg.playbook_naming_session_cap)
    if naming_cap <= 0:
        raise ValueError("session.playbook_naming_session_cap must be positive")
    indexes = cfg.elasticsearch.indexes.cowrie
    # Production raises on a missing anchor index for exactly this reason: silent
    # fallback mints duplicate ids. Here a missing index would surface as a raw
    # NotFoundError traceback instead of the actionable exit 2.
    for label, idx in (("session cluster", indexes.session_clusters),
                       ("playbook anchor", indexes.playbook_anchors)):
        if not es.indices.exists(index=idx):
            raise RuntimeError(
                f"{label} index {idx!r} is missing — run `init-indexes --source cowrie` "
                f"and `cluster sessions` before diagnosing",
            )
    generated = {
        "generated_at": datetime.now(UTC).isoformat(),
        "read_only": True,
        "session_classification": "public_only",
        "anchor_provenance": "pinned_mixed_classification_derived_aggregates",
        "assignment_tau": assignment_tau,
        "playbook_merge_threshold": merge_threshold,
    }

    inputs, rows = load_pool_inputs(es, cfg, per_anchor=per_anchor)
    if inputs is None:
        return {**generated, "n_sessions": len(rows), "n_anchors": 0, "pool_size": 0,
                "gates": zeroed_gates(),
                "survivors_reaching_mint": 0,
                "verdict": "no_anchor_library — nothing to match against, "
                           "every playbook group would mint"}

    result = compute_assignment_window(
        inputs.embeddings, inputs.anchor_embeddings, inputs.anchor_ids,
        inputs.anchor_bags, inputs.anchor_bag_ids, inputs.command_bags,
        tau=assignment_tau,
        confident_tau=float(scfg.assignment_confident_tau),
        tfidf_tau=float(scfg.assignment_tfidf_tau),
        # Guarded equal to `assignment_tau` above: the declined rescue tier
        # (Finding 42) stays the no-op production runs it as.
        rescue_tau=rescue_tau,
    )
    novel_mask = np.asarray(
        [a.status == NOVEL for a in result.assignments], dtype=bool,
    )
    novel_idx = np.flatnonzero(novel_mask)
    generated |= {
        "n_sessions": int(inputs.embeddings.shape[0]),
        "n_anchors": len(inputs.anchor_ids),
        "novel": int(novel_idx.size),
        "novel_rate": round(float(novel_idx.size) / float(inputs.embeddings.shape[0]), 4),
    }
    if novel_idx.size == 0:
        return {**generated, "pool_size": 0, "gates": zeroed_gates(),
                "survivors_reaching_mint": 0, "verdict": verdict([], 0)}

    novel_embeddings = inputs.embeddings[novel_mask]
    novel_scalars = [s for s, keep in zip(inputs.scalars, novel_mask, strict=False) if keep]
    cluster_kwargs = {
        "min_cluster_size": int(scfg.cluster_min_cluster_size),
        "min_samples": int(scfg.cluster_min_samples),
        "scalar_weight": float(scfg.cluster_scalar_weight),
        "rescue_threshold": merge_threshold,
        "merge_threshold": merge_threshold,
        "svd_dim": int(scfg.cluster_svd_dim),
        "n_jobs": int(cfg.worker.cluster_n_jobs),
    }
    # `cluster_novel_pool` first: it validates every clustering parameter, and
    # `pool_group_labels` (which cannot, being label-producing rather than
    # aggregate) would otherwise run a full HDBSCAN fit on invalid config first.
    shape = cluster_novel_pool(novel_embeddings, novel_scalars, **cluster_kwargs)
    labels = pool_group_labels(novel_embeddings, novel_scalars, **cluster_kwargs)
    sizes = Counter(int(x) for x in labels if int(x) >= 0)
    # Cross-check both the group count and the largest share — two different
    # partitions can share a count, and the labels drive every downstream gate.
    largest_share = round(max(sizes.values()) / len(labels), 4) if sizes else 0.0
    if (shape.get("playbook_groups") != len(sizes)
            or abs(float(shape.get("largest_share") or 0.0) - largest_share) > 1e-4):
        raise RuntimeError(
            "labelled pool clustering diverged from eval_novel_pool.cluster_novel_pool "
            f"(groups {len(sizes)} vs {shape.get('playbook_groups')}, largest_share "
            f"{largest_share} vs {shape.get('largest_share')})",
        )
    if not sizes:
        return {**generated, "pool_size": 0, "novel_pool_shape": shape,
                "gates": zeroed_gates(), "survivors_reaching_mint": 0,
                "verdict": "no_novel_pool — the novel pool resolves to no coherent group"}

    largest_label, largest_size = sizes.most_common(1)[0]
    keep = labels == largest_label
    run = load_latest_run(es, indexes.session_clusters)
    cutoff = window_cutoff(int(run.get("window_days") or 0), run.get("@timestamp"))
    pool = [
        {
            "session_id": rows[int(i)]["session_id"],
            "cluster_id": rows[int(i)]["cluster_id"],
            "assignment_status": rows[int(i)]["assignment_status"],
            "in_window": _in_window(rows[int(i)]["timestamp"], cutoff),
            "embedding": novel_embeddings[j],
        }
        for j, i in enumerate(novel_idx) if keep[j]
    ]
    visible, clusters_in_run = load_naming_clusters(es, indexes.session_clusters,
                                                    run["run_id"])
    anchors = _load_playbook_anchors(es, indexes.playbook_anchors)
    filters = public_filters(cfg)

    def probe(session_ids: list[str]) -> bool:
        return group_has_public_commands(
            es, indexes.sessions_raw, session_ids[:naming_cap], filters,
        )

    gates = evaluate_gates(
        pool, run, visible, clusters_in_run, anchors,
        merge_threshold=merge_threshold, assignment_tau=assignment_tau,
        commands_probe=probe,
    )
    survivors = len(pool) - sum(g["eliminated"] for g in gates)
    if survivors < 0:
        raise RuntimeError("gate ladder eliminated more sessions than the pool holds")
    return {
        **generated,
        "pool_size": len(pool),
        "pool_share_of_novel": round(largest_size / float(novel_idx.size), 4),
        "novel_pool_shape": shape,
        "naming_run": {k: run.get(k) for k in
                       ("run_id", "@timestamp", "window_days", "total_docs",
                        "n_clusters", "n_outliers", "n_rescued", "clustering_config")},
        "gates": gates,
        "survivors_reaching_mint": survivors,
        "verdict": verdict(gates, len(pool)),
    }


def summarize(report: dict) -> str:
    lines = [
        (f"pool={report.get('pool_size', 0)} of novel={report.get('novel', 0)} "
         f"(sessions={report.get('n_sessions', 0)}, anchors={report.get('n_anchors', 0)}, "
         f"tau={report.get('assignment_tau')})"),
    ]
    for gate in report.get("gates", []):
        # G6 is a diagnosis of what G5 removed, not the next step in the ladder;
        # its `in=` would otherwise read as a population that grew after G5.
        note = "  (diagnoses G5's eliminations)" if gate["gate"] == GATE_ORDER[6] else ""
        lines.append(
            f"  {gate['gate']:<24} in={gate['sessions_in']:>6} "
            f"eliminated={gate['eliminated']:>6}{note}",
        )
    if "survivors_reaching_mint" in report:
        lines.append(
            f"  {'survivors_reaching_mint':<24} {report['survivors_reaching_mint']:>17}",
        )
    lines.append(f"verdict: {report.get('verdict', 'none')}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None)
    parser.add_argument("--per-anchor", type=int, default=300)
    parser.add_argument("--json", action="store_true", help="emit the full JSON report")
    parser.add_argument(
        "--confirm-mixed-derived-anchors",
        action="store_true",
        help="confirm local read-only use of mixed-classification-derived pinned anchors",
    )
    args = parser.parse_args()
    if not args.confirm_mixed_derived_anchors:
        parser.error(
            "live execution requires operator confirmation: "
            "--confirm-mixed-derived-anchors",
        )

    try:
        cfg = load_config(args.config)
        es = make_client(cfg.elasticsearch, load_secrets(args.config))
        report = diagnose(es, cfg, per_anchor=args.per_anchor)
    except (RuntimeError, ValueError) as exc:
        print(f"diagnose_unminted_playbook: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        print(summarize(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
