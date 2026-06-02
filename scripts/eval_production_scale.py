"""Eval session-layer clustering at PRODUCTION SCALE on the labeled subset.

Bridges the gap the E4 postmortem identified: eval-isolated metrics
(``scripts/eval_clustering.py``) cluster on the 108 labeled sessions
only, but production HDBSCAN runs on ~4000+ sessions where the corpus
geometry is different. The same labeled subset typically scores 0.067
ARI lower at production scale, and a "win" at eval scale doesn't
necessarily survive at production scale (cf. E4.4 late-fusion).

This script:
  1. Pulls every session rollup with an embedding from the configured
     production sessions index (typically ``prism.rollup.cowrie.session``).
  2. Runs the production HDBSCAN math locally (L2-normalize, scalar
     augment, HDBSCAN, optional noise rescue) — same hyperparameters as
     ``run_session_clustering``, but no ES writes.
  3. Filters the resulting cluster assignment to the session_ids
     present in ``eval/sessions-v{1,2}.unlabeled.jsonl`` (the analyst-
     labeled subset).
  4. Scores ARI / NMI / homogeneity / completeness /
     ``divergent_pair_resolution_rate`` against analyst labels.
  5. Emits the per-label fragmentation table (E0.1 logic — catches
     "ARI up but one label collapsed" regressions).
  6. Writes ``eval/results/prod-scale-<ts>.json``.

Run from the repo root via the venv that has the production config /
ES creds in reach. On the workstation:

    ./console/.venv/bin/python scripts/eval_production_scale.py \\
      --config-path config/local.yaml

On the production box, typically:

    sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python \\
      scripts/eval_production_scale.py
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.cluster import HDBSCAN
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.clustering import compute_centroids, l2_normalize, rescue_noise_points
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.sessions import (
    build_session_scalar_block,
    merge_clusters_into_playbooks,
)

from eval_clustering import (  # type: ignore
    _load_labels,
    _per_label_breakdown,
    _divergent_pair_metrics,
    render_small_cluster_block,
    small_cluster_metrics,
)

# Source fields the production-scale small-cluster axis (F0.2) needs on top of
# the four clustering scalars: dominant_intent drives 3a (intent purity),
# command_signature drives the 3b modal-signature-share clause. The
# embeddings-only snapshot predates these; the metric degrades to None there.
_PROD_EVAL_SOURCE_FIELDS = [
    "dshield.cowrie.enrichment.session.embedding",
    "dshield.cowrie.enrichment.session.command_count",
    "dshield.cowrie.enrichment.session.unique_commands",
    "dshield.cowrie.enrichment.session.login_success_count",
    "dshield.cowrie.enrichment.session.login_fail_count",
    "dshield.cowrie.enrichment.session.mean_novelty_score",
    "dshield.cowrie.enrichment.session.dominant_intent",
    "dshield.cowrie.enrichment.session.command_signature",
    "cowrie.session_id",
]

# Snapshot freshness thresholds (E6.2). Mirrors the plan's cadence: a
# warning when the snapshot is older than 90 days lets the operator
# notice drift; a hard-fail at 180 days forces a refresh before any
# clustering-touching PR can merge. The captured_at timestamp lives in
# line 1 of the snapshot file.
_SNAPSHOT_STALE_WARN_DAYS = 90
_SNAPSHOT_STALE_FAIL_DAYS = 180


def _load_eval_session_ids_and_labels(
    labels_v1: Path, labels_v2: Path,
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Return ``({session_id: playbook_label}, {pair_id: [sid_a, sid_b]})``.

    Joins v1 + v2 by session_id and extracts divergent-pair groupings
    from the v2 label blocks (mirrors ``eval_clustering._evaluate``).
    """
    blocks: dict[str, dict] = {}
    if labels_v1.exists():
        blocks.update(_load_labels(labels_v1))
    pair_to_sessions: dict[str, list[str]] = {}
    if labels_v2.exists():
        v2_blocks = _load_labels(labels_v2)
        blocks.update(v2_blocks)
        for sid, b in v2_blocks.items():
            pid = b.get("divergent_pair_id")
            if isinstance(pid, str) and pid:
                pair_to_sessions.setdefault(pid, []).append(sid)
    sid_to_label = {sid: b["playbook_label"] for sid, b in blocks.items()}
    return sid_to_label, pair_to_sessions


def _cluster_at_production_scale(
    embeddings: list[list[float]],
    scalars_list: list[dict],
    *,
    min_cluster_size: int,
    min_samples: int,
    scalar_weight: float,
    rescue_threshold: float | None,
) -> tuple[np.ndarray, int]:
    """Mirror ``run_layer_clustering`` cluster-assignment math, no ES.

    Steps in order:
      1. L2-normalize the embedding matrix.
      2. Optionally hstack the weighted scalar block (matches the
         production session config — ``cluster_scalar_weight=0.05`` by
         default).
      3. Run HDBSCAN at the supplied hyperparameters.
      4. Optionally rescue noise points within ``rescue_threshold``
         pure-embedding cosine of a cluster centroid (production
         default ``playbook_merge_threshold=0.96``).

    Returns ``(labels, n_rescued)``. Labels match the cluster_id integer
    namespace HDBSCAN emits (-1 = noise unless rescued).
    """
    matrix = np.array(embeddings, dtype=np.float32)
    normalized = l2_normalize(matrix)
    if scalar_weight > 0.0:
        block = build_session_scalar_block(scalars_list, scalar_weight)
        cluster_matrix = np.hstack([normalized, block])
    else:
        cluster_matrix = normalized
    clusterer = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    )
    labels = clusterer.fit_predict(cluster_matrix)
    n_rescued = 0
    if rescue_threshold is not None and rescue_threshold > 0.0:
        labels, n_rescued = rescue_noise_points(normalized, labels, rescue_threshold)
    return labels, n_rescued


def _apply_session_merge(
    labels: np.ndarray, embeddings: list[list[float]], threshold: float,
) -> tuple[np.ndarray, int]:
    """Run the production cluster→playbook merge (``merge_clusters_into_playbooks``,
    complete-linkage cosine ≥ threshold) on HDBSCAN+rescue labels, the step the
    session pipeline runs but the pre-merge eval historically skipped. Returns
    ``(merged_labels, n_playbook_groups)``. Outliers (-1) pass through; the
    merged labels are a fresh dense integer namespace."""
    normalized = l2_normalize(np.array(embeddings, dtype=np.float32))
    centroids = compute_centroids(normalized, labels)  # {int: vec}, excludes -1
    cmap = {str(int(l)): centroids[l].tolist() for l in centroids}
    groups = merge_clusters_into_playbooks(cmap, threshold)  # {str(lbl): "pgN"}
    pg_to_int: dict[str, int] = {}
    merged = np.empty_like(labels)
    for i, l in enumerate(labels):
        li = int(l)
        if li < 0:
            merged[i] = -1
            continue
        pg = groups[str(li)]
        if pg not in pg_to_int:
            pg_to_int[pg] = len(pg_to_int)
        merged[i] = pg_to_int[pg]
    return merged, len(pg_to_int)


def _iter_rollup_source(
    src: dict,
) -> tuple[list[float] | None, str | None, dict, str | None, str | None] | None:
    """Extract (embedding, session_id, scalars, dominant_intent,
    command_signature) from a rollup ES _source.

    Returns None when the rollup carries no embedding (mirrors the
    ``iter_session_docs`` filter). Used by both the ES streaming path
    and the snapshot-replay path so the math sees identical inputs. The
    two trailing fields are None on a redacted snapshot that predates the
    F0.2 field additions — the small-cluster metric degrades to None on
    3a/3b rather than reporting a wrong zero.
    """
    s = (
        ((src.get("dshield") or {}).get("cowrie") or {})
        .get("enrichment", {})
        .get("session", {})
    )
    emb = s.get("embedding")
    if not emb:
        return None
    sid = (src.get("cowrie") or {}).get("session_id")
    success = s.get("login_success_count") or 0
    fail = s.get("login_fail_count") or 0
    total = success + fail
    scalars = {
        "command_count":      s.get("command_count") or 1,
        "unique_commands":    s.get("unique_commands") or 1,
        "login_success_rate": success / total if total > 0 else 0.0,
        "mean_novelty_score": s.get("mean_novelty_score") or 0.0,
    }
    return emb, sid, scalars, s.get("dominant_intent"), s.get("command_signature")


def _iter_live_rollups(es, index: str, page_size: int):
    """Stream (doc_id, embedding, session_id, scalars, intent, signature)
    from live ES. Like ``iter_session_docs`` but additionally pulls the
    two fields the F0.2 small-cluster axis needs (dominant_intent,
    command_signature) — kept local so the production clusterer's
    iterator stays lean."""
    body: dict = {
        "size": page_size,
        "_source": _PROD_EVAL_SOURCE_FIELDS,
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
            parsed = _iter_rollup_source(h["_source"])
            if parsed is None:
                continue
            emb, sid, scalars, intent, signature = parsed
            yield h["_id"], emb, (sid or h["_id"]), scalars, intent, signature
        search_after = hits[-1]["sort"]


def _iter_from_snapshot(
    snapshot_path: Path,
) -> tuple[list[str], list[list[float]], list[str], list[dict], list, list, dict]:
    """Read every rollup from a gzipped snapshot JSONL.

    Snapshot file layout:
      * Line 1: a metadata record ``{"_metadata": true, "captured_at":
        "...", ...}`` describing how/when the snapshot was minted.
      * Lines 2..N: ES-style ``{"_id": "...", "_source": {...}}``
        records, one per session rollup, already redacted.

    Returns ``(doc_ids, embeddings, session_ids, scalars, intents,
    signatures, metadata)``. ``intents`` / ``signatures`` are None-filled
    on a pre-F0.2 snapshot that didn't capture those fields; the
    small-cluster metric degrades to None on 3a/3b accordingly. The
    metadata dict feeds the staleness check + provenance fields.
    """
    doc_ids: list[str] = []
    embeddings: list[list[float]] = []
    session_ids: list[str] = []
    scalars_list: list[dict] = []
    intents: list = []
    signatures: list = []
    metadata: dict = {}
    if not snapshot_path.exists():
        raise RuntimeError(f"Snapshot not found: {snapshot_path}")
    opener = gzip.open if str(snapshot_path).endswith(".gz") else open
    with opener(snapshot_path, "rt", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if i == 0 and rec.get("_metadata"):
                metadata = rec
                continue
            src = rec.get("_source") or {}
            parsed = _iter_rollup_source(src)
            if parsed is None:
                continue
            emb, sid, scalars, intent, signature = parsed
            if sid is None:
                sid = rec.get("_id", "")
            doc_ids.append(rec.get("_id", sid))
            embeddings.append(emb)
            session_ids.append(sid)
            scalars_list.append(scalars)
            intents.append(intent)
            signatures.append(signature)
    if not metadata:
        raise RuntimeError(
            f"Snapshot {snapshot_path} has no line-1 metadata record. "
            "Regenerate via scripts/refresh_production_snapshot.py."
        )
    return doc_ids, embeddings, session_ids, scalars_list, intents, signatures, metadata


def _evaluate(
    *,
    cfg,
    secrets,
    labels_v1: Path,
    labels_v2: Path,
    rescue: bool,
    merge: bool,
    limit_rollups: int | None,
    run_label: str | None,
    snapshot_path: Path | None,
    dump_assignments: bool = False,
) -> dict:
    sid_to_label, pair_to_sessions = _load_eval_session_ids_and_labels(
        labels_v1, labels_v2,
    )
    if not sid_to_label:
        raise RuntimeError(
            f"No analyst labels found in {labels_v1} / {labels_v2}"
        )

    scfg = cfg.session
    sessions_idx: str
    snapshot_metadata: dict = {}

    if snapshot_path is not None:
        # Snapshot-replay path (CI / air-gapped). No ES connection.
        sessions_idx = f"snapshot:{snapshot_path.name}"
        (
            doc_ids, embeddings, session_ids, scalars_list,
            intents, signatures, snapshot_metadata,
        ) = _iter_from_snapshot(snapshot_path)
        if limit_rollups is not None:
            doc_ids = doc_ids[:limit_rollups]
            embeddings = embeddings[:limit_rollups]
            session_ids = session_ids[:limit_rollups]
            scalars_list = scalars_list[:limit_rollups]
            intents = intents[:limit_rollups]
            signatures = signatures[:limit_rollups]
    else:
        es = make_client(cfg.elasticsearch, secrets)
        sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
        if not es.indices.exists(index=sessions_idx):
            raise RuntimeError(
                f"Sessions rollup index '{sessions_idx}' not found. "
                f"Check elasticsearch.indexes.cowrie.sessions_rollup in config."
            )
        doc_ids = []
        embeddings = []
        session_ids = []
        scalars_list = []
        intents = []
        signatures = []
        for doc_id, emb, sid, scalars, intent, signature in _iter_live_rollups(
            es, sessions_idx, scfg.page_size,
        ):
            doc_ids.append(doc_id)
            embeddings.append(emb)
            session_ids.append(sid)
            scalars_list.append(scalars)
            intents.append(intent)
            signatures.append(signature)
            if limit_rollups is not None and len(doc_ids) >= limit_rollups:
                break

    n_pulled = len(doc_ids)
    if n_pulled < scfg.cluster_min_cluster_size:
        raise RuntimeError(
            f"Pulled only {n_pulled} rollups from {sessions_idx} — "
            f"need at least {scfg.cluster_min_cluster_size} for HDBSCAN. "
            f"Has `rollup sessions` + `embed sessions` run?"
        )

    rescue_threshold = scfg.playbook_merge_threshold if rescue else None
    labels, n_rescued = _cluster_at_production_scale(
        embeddings, scalars_list,
        min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
        scalar_weight=scfg.cluster_scalar_weight,
        rescue_threshold=rescue_threshold,
    )

    # Cluster→playbook merge — the production session pipeline runs this
    # (sessions.py:2635) but the historical pre-merge eval skipped it,
    # understating real production ARI by ~0.025. On by default so the gate
    # measures the full pipeline; --no-merge reproduces the pre-merge numbers.
    n_playbook_groups: int | None = None
    merge_threshold = scfg.playbook_merge_threshold
    if merge:
        labels, n_playbook_groups = _apply_session_merge(
            labels, embeddings, merge_threshold,
        )

    # Restrict to the labeled eval subset.
    sid_to_cluster: dict[str, int] = {
        sid: int(c) for sid, c in zip(session_ids, labels)
    }
    eval_sids_found: list[str] = []
    eval_label_truth: list[str] = []
    eval_cluster_pred: list[int] = []
    missing_eval_sids: list[str] = []
    for sid, lbl in sid_to_label.items():
        if sid in sid_to_cluster:
            eval_sids_found.append(sid)
            eval_label_truth.append(lbl)
            eval_cluster_pred.append(sid_to_cluster[sid])
        else:
            # Eval-set session that production hasn't ingested (or has
            # ingested but the embedding hasn't been written yet).
            # Surfaces a real corpus desync — flagged in the JSON.
            missing_eval_sids.append(sid)

    if not eval_sids_found:
        raise RuntimeError(
            f"None of the {len(sid_to_label)} labeled eval sessions were "
            f"found in {sessions_idx}. Has the embedding pipeline run "
            "against the eval set's session_ids?"
        )

    eval_cluster_pred_arr = np.array(eval_cluster_pred, dtype=np.int64)
    metrics = {
        "ari":          round(float(adjusted_rand_score(eval_label_truth, eval_cluster_pred_arr)), 4),
        "nmi":          round(float(normalized_mutual_info_score(eval_label_truth, eval_cluster_pred_arr)), 4),
        "homogeneity":  round(float(homogeneity_score(eval_label_truth, eval_cluster_pred_arr)), 4),
        "completeness": round(float(completeness_score(eval_label_truth, eval_cluster_pred_arr)), 4),
        "v_measure":    round(float(v_measure_score(eval_label_truth, eval_cluster_pred_arr)), 4),
    }
    pair_outcomes: list[dict] = []
    if pair_to_sessions:
        v2_metrics, pair_outcomes = _divergent_pair_metrics(
            eval_sids_found, eval_cluster_pred_arr,
            eval_label_truth, pair_to_sessions,
        )
        metrics.update(v2_metrics)

    n_clusters_total = len({int(c) for c in labels if c >= 0})
    n_outliers_total = int(sum(1 for c in labels if c == -1))
    n_clusters_on_eval = len({c for c in eval_cluster_pred if c >= 0})

    # F-phase small-cluster + outlier axis (plan F0.2). Computed over the
    # FULL production corpus, NOT the labeled eval subset — the ~108
    # analyst labels are too few and corpus-specific to translate to the
    # ~4000-session production geometry, so metrics 1-3 are deliberately
    # corpus-wide while the ARI/completeness axis (4-7) stays on the
    # labeled subset. These are the *binding* small-cluster numbers per the
    # plan's scale-binding note.
    norm_full = l2_normalize(np.array(embeddings, dtype=np.float32))
    sc_result = small_cluster_metrics(
        labels, norm_full, intents, signatures,
        merge_threshold=scfg.playbook_merge_threshold,
    )
    metrics.update(sc_result["metrics"])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_label": run_label,
        "scale": "production",
        "config": {
            "min_cluster_size":  scfg.cluster_min_cluster_size,
            "min_samples":       scfg.cluster_min_samples,
            "scalar_weight":     scfg.cluster_scalar_weight,
            "rescue_threshold":  rescue_threshold,
            "merge_threshold":   merge_threshold if merge else None,
            "merged":            merge,
            "cooccurrence_embedded": cfg.cooccurrence.embed_cooccurrence,
            "embed_context":     list(cfg.llm.embed_context),
            "clustering_mode":   scfg.clustering_mode,
        },
        "input": {
            "sessions_index":         sessions_idx,
            "rollups_pulled":         n_pulled,
            "rollups_limit_applied":  limit_rollups,
            "labels_path":            str(labels_v1),
            "v2_labels_path":         str(labels_v2),
            "eval_sessions_total":    len(sid_to_label),
            "eval_sessions_found":    len(eval_sids_found),
            "eval_sessions_missing":  len(missing_eval_sids),
            "missing_eval_sids":      missing_eval_sids,
            "v2_pairs_in_eval":       len(pair_to_sessions),
            "snapshot_path":          str(snapshot_path) if snapshot_path else None,
            "snapshot_metadata":      snapshot_metadata or None,
        },
        "cluster_output": {
            "n_clusters_total":     n_clusters_total,
            "n_outliers_total":     n_outliers_total,
            "n_rescued":            n_rescued,
            "n_playbook_groups":    n_playbook_groups,
            "n_clusters_on_eval":   n_clusters_on_eval,
        },
        "metrics":         metrics,
        "small_cluster": {
            "scope":               "full_corpus",
            "intent_available":    sc_result["intent_available"],
            "signature_available": sc_result["signature_available"],
            "detail":              sc_result["small_cluster_detail"],
        },
        "per_label":       _per_label_breakdown(
            eval_sids_found, eval_label_truth, eval_cluster_pred_arr,
        ),
        "divergent_pairs": pair_outcomes,
        # Full-corpus {session_id: cluster_id} — the input the G-phase
        # cross-arm comparison (compare_clusterings.py) reads. Gated because
        # it adds ~4k entries the gate doesn't need; the G capture runs ask
        # for it. Post-merge labels when merge ran.
        "assignments": (
            {sid: int(c) for sid, c in zip(session_ids, labels)}
            if dump_assignments else None
        ),
    }


def _snapshot_staleness(metadata: dict) -> tuple[float | None, str]:
    """Return ``(age_days, status)`` for the snapshot's captured_at.

    Status is one of ``"fresh" / "warn" / "fail" / "unknown"``. The
    thresholds match the plan (E6.2): >90d warn, >180d fail.
    """
    captured_at = metadata.get("captured_at")
    if not captured_at:
        return None, "unknown"
    try:
        ts = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None, "unknown"
    age = (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0
    if age > _SNAPSHOT_STALE_FAIL_DAYS:
        return age, "fail"
    if age > _SNAPSHOT_STALE_WARN_DAYS:
        return age, "warn"
    return age, "fresh"


def _compare_to_baseline(
    report: dict, baseline_path: Path,
) -> tuple[list[dict], list[dict], bool]:
    """Diff current metrics + per-label fragmentation against a baseline.

    The baseline file shape mirrors ``eval/baseline.json`` but adds a
    ``per_label`` block. A regression on either side fails the gate:

      * Metric drops more than ``tolerance`` below ``baseline``.
      * A label's ``n_hdbscan_clusters_assigned`` grows by more than 1
        vs the recorded baseline count (the "max −1 cluster on any
        analyst label" rule from the plan).

    Returns ``(metric_rows, per_label_rows, ok)``.
    """
    base = json.loads(baseline_path.read_text(encoding="utf-8"))
    rows: list[dict] = []
    ok = True
    current = report["metrics"]
    for name, spec in base.get("metrics", {}).items():
        cur = current.get(name)
        b = spec["baseline"]
        tol = spec["tolerance"]
        if cur is None:
            rows.append({"name": name, "baseline": b, "current": None,
                         "tolerance": tol, "delta": None, "status": "MISSING"})
            ok = False
            continue
        delta = cur - b
        status = "PASS" if cur >= b - tol else "FAIL"
        if status == "FAIL":
            ok = False
        rows.append({"name": name, "baseline": b, "current": cur,
                     "tolerance": tol, "delta": round(delta, 4), "status": status})

    per_label_rows: list[dict] = []
    cur_labels = report.get("per_label", {})
    for lbl, lbl_spec in base.get("per_label", {}).items():
        b_clusters = lbl_spec.get("n_hdbscan_clusters_assigned")
        cur_st = cur_labels.get(lbl)
        if cur_st is None:
            per_label_rows.append({
                "label": lbl, "baseline_clusters": b_clusters,
                "current_clusters": None, "delta": None, "status": "MISSING",
            })
            ok = False
            continue
        cur_clusters = cur_st.get("n_hdbscan_clusters_assigned")
        delta = cur_clusters - b_clusters
        # Plan rule: "no analyst label regresses by more than 1 cluster"
        # — i.e. cluster count grows by no more than +1. Drops (label
        # consolidates into fewer clusters) are always fine.
        status = "PASS" if delta <= 1 else "FAIL"
        if status == "FAIL":
            ok = False
        per_label_rows.append({
            "label": lbl, "baseline_clusters": b_clusters,
            "current_clusters": cur_clusters, "delta": delta, "status": status,
        })

    return rows, per_label_rows, ok


def _render_gate(
    metric_rows: list[dict], per_label_rows: list[dict], ok: bool,
    snapshot_status: str | None, snapshot_age_days: float | None,
) -> str:
    out = ["", "=" * 72, "Production-scale regression gate", "=" * 72]
    if snapshot_status:
        if snapshot_status == "fresh":
            label = f"snapshot age      {snapshot_age_days:.1f}d (fresh)"
        elif snapshot_status == "warn":
            label = (
                f"snapshot age      {snapshot_age_days:.1f}d (WARN: refresh "
                f"recommended; >180d hard-fails)"
            )
        elif snapshot_status == "fail":
            label = (
                f"snapshot age      {snapshot_age_days:.1f}d (FAIL: "
                f"exceeds {_SNAPSHOT_STALE_FAIL_DAYS}d limit)"
            )
        else:
            label = "snapshot age      unknown (no captured_at in metadata)"
        out.append(label)
    out.append("")
    out.append(
        f"  {'metric':33} {'baseline':>10} {'current':>10} "
        f"{'tolerance':>10} {'delta':>10}  status"
    )
    for r in metric_rows:
        cur = "—" if r["current"] is None else f"{r['current']:.4f}"
        dlt = "—" if r["delta"]   is None else f"{r['delta']:+.4f}"
        out.append(
            f"  {r['name']:33} {r['baseline']:>10.4f} {cur:>10} "
            f"{r['tolerance']:>10.4f} {dlt:>10}  {r['status']}"
        )
    if per_label_rows:
        out.append("")
        out.append("Per-label cluster-count check (max +1 cluster regression):")
        out.append(
            f"  {'label':35} {'baseline':>10} {'current':>10} "
            f"{'delta':>10}  status"
        )
        for r in per_label_rows:
            cur = "—" if r["current_clusters"] is None else str(r["current_clusters"])
            dlt = "—" if r["delta"] is None else f"{r['delta']:+d}"
            out.append(
                f"  {r['label']:35} {r['baseline_clusters']:>10} {cur:>10} "
                f"{dlt:>10}  {r['status']}"
            )
    out.append("")
    out.append(f"GATE: {'PASS' if ok else 'FAIL'}")
    return "\n".join(out)


def _render_stdout(report: dict) -> str:
    out: list[str] = []
    out.append("=" * 72)
    out.append("Production-scale session clustering eval")
    out.append("=" * 72)
    cfg = report["config"]
    out.append(
        f"hyperparameters   min_cluster_size={cfg['min_cluster_size']}  "
        f"min_samples={cfg['min_samples']}  scalar_weight={cfg['scalar_weight']}  "
        f"rescue={cfg['rescue_threshold']}  "
        f"merge={cfg.get('merge_threshold') if cfg.get('merged') else 'off'}"
    )
    out.append(
        f"embedding config  cooccurrence={cfg['cooccurrence_embedded']}  "
        f"context={cfg['embed_context']}  clustering_mode={cfg['clustering_mode']}"
    )
    inp = report["input"]
    out.append(f"sessions index    {inp['sessions_index']}")
    out.append(
        f"rollups pulled    {inp['rollups_pulled']}"
        + (f" (limit applied: {inp['rollups_limit_applied']})"
           if inp.get("rollups_limit_applied") else "")
    )
    out.append(
        f"eval coverage     {inp['eval_sessions_found']}/{inp['eval_sessions_total']} "
        f"labeled sessions matched in production"
        + (f"  (MISSING: {inp['eval_sessions_missing']})"
           if inp["eval_sessions_missing"] else "")
    )
    co = report["cluster_output"]
    out.append(
        f"clusters          total={co['n_clusters_total']}  "
        f"outliers={co['n_outliers_total']}  rescued={co['n_rescued']}  "
        + (f"playbook_groups={co['n_playbook_groups']}  "
           if co.get("n_playbook_groups") is not None else "")
        + f"on eval subset={co['n_clusters_on_eval']}"
    )
    out.append("")
    out.append("Metrics (eval subset against production cluster ids):")
    for k in ("ari", "nmi", "homogeneity", "completeness", "v_measure"):
        if k in report["metrics"]:
            out.append(f"  {k:14} {report['metrics'][k]:.4f}")

    if "divergent_pair_resolution_rate" in report["metrics"]:
        m = report["metrics"]
        out.append("")
        out.append("Divergent-pair (v2) metric:")
        out.append(
            f"  divergent_pair_resolution_rate    "
            f"{m['divergent_pair_resolution_rate']:.4f}"
        )
        pos_t = m.get("divergent_pair_positive_total", 0)
        pos_r = m.get("divergent_pair_positive_resolved", 0)
        neg_t = m.get("divergent_pair_negative_total", 0)
        neg_s = m.get("divergent_pair_negative_separated", 0)
        skipped = m.get("divergent_pair_skipped", 0)
        out.append(f"    positive: {pos_r}/{pos_t} same-label pairs clustered together")
        out.append(f"    negative: {neg_s}/{neg_t} different-label pairs separated")
        if skipped:
            out.append(f"    skipped:  {skipped} (member missing in production)")

    out.append("")
    out.append("(small-cluster axis below is corpus-wide; ARI axis above is "
               "the labeled subset)")
    out.extend(render_small_cluster_block(report["metrics"], report.get("small_cluster", {})))

    out.append("")
    out.append("Per-label breakdown (analyst label → production cluster grouping):")
    out.append(
        f"  {'label':35} {'n':>4} {'clusters':>9} {'fragmentation':>14} "
        f"{'lgst.share':>11} {'outlier.share':>14}"
    )
    for lbl, st in sorted(
        report["per_label"].items(),
        key=lambda kv: (-kv[1]["n_sessions"], kv[0]),
    ):
        out.append(
            f"  {lbl:35} {st['n_sessions']:>4} "
            f"{st['n_hdbscan_clusters_assigned']:>9} "
            f"{st['fragmentation_ratio']:>14.3f} "
            f"{st['largest_cluster_share']:>11.3f} "
            f"{st['outlier_share']:>14.3f}"
        )
    return "\n".join(out)


# Gated metrics + their tolerances (absolute drop below baseline that fails
# the gate). Matches the long-standing prod-scale baseline. The new
# small-cluster metrics (outlier_rate, shard_fraction, …) are lower-better /
# need different gate semantics (deferred F0.3), so they are recorded
# informationally, not gated.
_BASELINE_TOLERANCES = {
    "ari":                            0.05,
    "nmi":                            0.05,
    "homogeneity":                    0.05,
    "completeness":                   0.05,
    "v_measure":                      0.05,
    "divergent_pair_resolution_rate": 0.17,
}


def _write_baseline(report: dict, path: Path) -> None:
    """Emit a baseline-prod-scale.json from a run report. Reproducible
    re-basing — replaces the previously-manual hand-edit of the JSON."""
    cfg = report["config"]
    inp = report["input"]
    metrics = report["metrics"]
    baseline_metrics = {
        name: {"baseline": metrics[name], "tolerance": tol}
        for name, tol in _BASELINE_TOLERANCES.items()
        if name in metrics
    }
    per_label = {
        lbl: {
            "n_sessions": st["n_sessions"],
            "n_hdbscan_clusters_assigned": st["n_hdbscan_clusters_assigned"],
        }
        for lbl, st in report["per_label"].items()
    }
    # Informational (non-gated) snapshot of the small-cluster axis.
    small = {
        k: metrics.get(k) for k in (
            "outlier_rate", "n_small_clusters", "n_small_clusters_distinct",
            "small_cluster_purity", "small_cluster_shard_fraction",
            "small_cluster_near_large_fraction",
        )
    }
    doc = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "captured_from": "scripts/eval_production_scale.py --write-baseline",
        "snapshot_at_capture": inp.get("snapshot_path"),
        "snapshot_metadata": inp.get("snapshot_metadata"),
        "config_at_capture": cfg,
        "rollups_at_capture": inp.get("rollups_pulled"),
        "eval_sessions_at_capture": inp.get("eval_sessions_found"),
        "embedding_pipeline_at_capture": (
            f"embed_context={cfg.get('embed_context')} "
            f"cooccurrence.embed_cooccurrence={cfg.get('cooccurrence_embedded')} "
            f"merge_threshold={cfg.get('merge_threshold')} merged={cfg.get('merged')}"
        ),
        "tolerance_semantic": (
            "Each gated metric fails when current < baseline - tolerance. "
            "Per-label table fails when a label's cluster count exceeds "
            "baseline by more than 1. small_cluster_* are informational only."
        ),
        "metrics": baseline_metrics,
        "per_label": per_label,
        "small_cluster_informational": small,
    }
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config-path", type=str, default=None,
                    help="Path to the AppConfig YAML (defaults to "
                         "ENRICH_CONFIG / config/default.yaml).")
    ap.add_argument("--labels", type=Path,
                    default=Path("eval/labels-v1.yaml"),
                    help="v1 analyst-labeled YAML")
    ap.add_argument("--labels-v2", type=Path,
                    default=Path("eval/labels-v2.yaml"),
                    help="v2 (divergent-pair) analyst-labeled YAML")
    ap.add_argument("--snapshot", type=Path, default=None,
                    help=(
                        "Read rollups from a gzipped snapshot file "
                        "(captured via scripts/refresh_production_snapshot.py) "
                        "instead of live ES. Use in CI / air-gapped runs."
                    ))
    ap.add_argument("--no-rescue", action="store_true",
                    help=(
                        "Skip the noise-rescue pass. Use to reproduce the "
                        "E4 postmortem's HDBSCAN-on-embedding-only numbers "
                        "(ARI ≈ 0.334). Production runs with rescue "
                        "enabled, so by default this script does too."
                    ))
    ap.add_argument("--no-merge", action="store_true",
                    help=(
                        "Skip the cluster→playbook merge pass. Production "
                        "runs the merge (sessions.py), so it is ON by default "
                        "and the gate measures the full pipeline. Use this to "
                        "reproduce the pre-merge eval numbers."
                    ))
    ap.add_argument("--write-baseline", type=Path, default=None,
                    help=(
                        "Write a baseline-prod-scale.json from this run "
                        "(reproducible re-basing). Gates the established "
                        "higher-better metrics at default tolerances; the "
                        "new small-cluster metrics are recorded informationally."
                    ))
    ap.add_argument("--limit-rollups", type=int, default=None,
                    help=(
                        "Cap the production pull at N rollups. Dev tool — "
                        "production runs leave this unset."
                    ))
    ap.add_argument("--label", type=str, default=None,
                    help="Short label persisted in the output JSON. "
                         "Use to mark experimental runs (e.g. 'cooc-on-revalidate').")
    ap.add_argument("--baseline", type=Path, default=None,
                    help=(
                        "Compare metrics + per-label cluster counts to this "
                        "baseline file and exit non-zero on regression. Use "
                        "to gate PRs (CI). Typical: --baseline "
                        "eval/baseline-prod-scale.json"
                    ))
    ap.add_argument("--output-dir", type=Path,
                    default=Path("eval/results"),
                    help="Where to write the machine-readable JSON.")
    ap.add_argument("--no-json", action="store_true",
                    help="Skip writing the JSON dump (stdout only).")
    ap.add_argument("--dump-assignments", action="store_true",
                    help="Include the full-corpus {session_id: cluster_id} map "
                         "in the JSON, for G-phase cross-arm comparison "
                         "(scripts/compare_clusterings.py).")
    args = ap.parse_args()

    cfg = load_config(args.config_path)
    secrets = load_secrets(args.config_path) if args.snapshot is None else None

    report = _evaluate(
        cfg=cfg,
        secrets=secrets,
        labels_v1=args.labels,
        labels_v2=args.labels_v2,
        rescue=not args.no_rescue,
        merge=not args.no_merge,
        dump_assignments=args.dump_assignments,
        limit_rollups=args.limit_rollups,
        run_label=args.label,
        snapshot_path=args.snapshot,
    )

    print(_render_stdout(report))

    if args.write_baseline is not None:
        _write_baseline(report, args.write_baseline)
        print(f"\nwrote baseline {args.write_baseline}")

    if not args.no_json:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = args.output_dir / f"prod-scale-{ts}.json"
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {out_path}")

    exit_code = 0
    if args.baseline is not None:
        snapshot_status: str | None = None
        snapshot_age: float | None = None
        if args.snapshot is not None:
            snapshot_age, snapshot_status = _snapshot_staleness(
                report["input"].get("snapshot_metadata") or {}
            )
        metric_rows, per_label_rows, gate_ok = _compare_to_baseline(
            report, args.baseline,
        )
        if snapshot_status == "fail":
            gate_ok = False
        print(_render_gate(
            metric_rows, per_label_rows, gate_ok,
            snapshot_status, snapshot_age,
        ))
        exit_code = 0 if gate_ok else 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
