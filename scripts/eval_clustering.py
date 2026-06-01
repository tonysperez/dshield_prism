"""Eval the session-layer clustering against the analyst-labeled ground truth.

Loads ``eval/labels-v1.yaml`` (the general stratified sample) and, when
present, ``eval/labels-v2.yaml`` (the divergent-pair stress test), joins
each by ``session_id`` against its unlabeled JSONL, filters to
``is_real: true`` blocks with a non-null ``playbook_label``, then re-runs
the same L2-normalize + scalar-augment + HDBSCAN pipeline the production
session clusterer uses (``src/enrich/clustering.py``) on the merged eval
set's embeddings. Reports clustering quality against the analyst labels:

  * ``ari``           — adjusted Rand index (chance-corrected pairwise agreement)
  * ``nmi``           — normalized mutual information
  * ``homogeneity``   — each cluster contains only members of a single label
  * ``completeness``  — all members of a label end up in the same cluster
  * ``v_measure``     — harmonic mean of homogeneity + completeness

And, when the v2 set is loaded, the v2-specific metric:

  * ``divergent_pair_resolution_rate`` — fraction of v2 pairs where the
    clustering's same-cluster / different-cluster call agrees with the
    analyst's same-label / different-label call. Direct measure of the
    embedding's "behavior-not-text" claim: positive-case pairs (same
    label, textually divergent commands) should land in the same
    cluster; negative-case pairs (different label, sharing only a
    coarse intent) should split. HDBSCAN outliers (-1) never count as
    "same cluster" — pairs whose members both land in noise count as
    "split" against the metric.

This is a pure-function eval: no ES, no writes, no live cluster index
state. The HDBSCAN math + hyperparameters mirror what production runs
(min_cluster_size, min_samples, scalar_weight from ``cfg.session``),
so the score reflects what the deployed pipeline would produce on the
labeled subset.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/eval_clustering.py
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import yaml
from sklearn.cluster import HDBSCAN
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.clustering import l2_normalize
from enrich.config import load_config
from enrich.sources.cowrie.sessions import build_session_scalar_block


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_labels(path: Path) -> dict[str, dict]:
    """Return {session_id: label_block} for every annotated, real block."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, dict] = {}
    for sid, block in data.items():
        if not isinstance(block, dict):
            continue
        if not block.get("annotated"):
            continue
        if not block.get("is_real"):
            continue
        if not block.get("playbook_label"):
            continue
        out[sid] = block
    return out


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _extract_session_features(rec: dict) -> tuple[list[float], dict] | None:
    """Pull the (embedding, scalars) tuple from a JSONL record, mirroring
    `iter_session_docs` in the production clusterer."""
    rollup = rec.get("rollup_doc") or {}
    enr = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    emb = enr.get("embedding")
    if not isinstance(emb, list) or not emb:
        return None
    success = enr.get("login_success_count") or 0
    fail = enr.get("login_fail_count") or 0
    total = success + fail
    scalars = {
        "command_count":      enr.get("command_count") or 1,
        "unique_commands":    enr.get("unique_commands") or 1,
        "login_success_rate": success / total if total > 0 else 0.0,
        "mean_novelty_score": enr.get("mean_novelty_score") or 0.0,
    }
    return emb, scalars


def _extract_session_text(rec: dict) -> str | None:
    """Concatenate the session's cowrie.command.input / .failed
    command-line strings in chronological order. Used by the TF-IDF
    baseline embedder (--embedding-source tfidf-svd) so the ablation
    grades a model-free comparator on the same labels."""
    raw_events = rec.get("raw_events") or []
    parts: list[str] = []
    for ev in raw_events:
        action = (ev.get("event") or {}).get("action")
        if action not in ("cowrie.command.input", "cowrie.command.failed"):
            continue
        cmd = (ev.get("process") or {}).get("command_line")
        if isinstance(cmd, str) and cmd:
            parts.append(cmd)
    return " ".join(parts) if parts else None


def _tfidf_svd_embed(texts: list[str], *, n_components: int = 100) -> list[list[float]]:
    """Fit a TF-IDF + truncated-SVD baseline embedder on the eval set
    and return per-session vectors. Used as a model-free comparator for
    the brutal-review embedding ablation (phase 3.3).

    Why TF-IDF: it's the simplest text representation that captures
    "which commands occur" without learned semantics. If the
    embedding-based clustering does meaningfully better than this
    baseline on the eval set, the embedding-sees-through-text thesis
    holds; if TF-IDF ties or wins, the thesis weakens on this corpus.

    Why n_components=100: TF-IDF + SVD at ~50-200 dims is the
    standard "topic" reduction. 100 lands in the middle; on a
    100-session eval set with O(1000) unique tokens, this captures
    most of the explained variance without overfitting to noise.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        # Default token pattern is `\b\w\w+\b` — keep it; commands tokenise
        # cleanly on whitespace + punctuation for our corpus. Pipes,
        # semicolons, slashes already act as word separators.
        sublinear_tf=True,
        norm="l2",
    )
    matrix = vectorizer.fit_transform(texts)
    n_components = min(n_components, matrix.shape[1], matrix.shape[0] - 1)
    if n_components < 2:
        # Pathologically tiny corpus — surface as a degenerate run.
        return [[0.0] for _ in texts]
    svd = TruncatedSVD(n_components=n_components, random_state=20260531)
    reduced = svd.fit_transform(matrix)
    return reduced.tolist()


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def _cluster(
    embeddings: list[list[float]],
    scalars: list[dict],
    *,
    min_cluster_size: int,
    min_samples: int,
    scalar_weight: float,
) -> np.ndarray:
    """L2-normalize embeddings, hstack the session scalar block, run HDBSCAN.
    Mirrors `enrich.clustering.run_layer_clustering` minus the side-effects
    (no ES updates, no centroid persist, no reference logic)."""
    matrix = np.array(embeddings, dtype=np.float32)
    normalized = l2_normalize(matrix)
    if scalar_weight > 0.0:
        block = build_session_scalar_block(scalars, scalar_weight)
        cluster_matrix = np.hstack([normalized, block])
    else:
        cluster_matrix = normalized
    clusterer = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    )
    return clusterer.fit_predict(cluster_matrix)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _per_label_breakdown(
    session_ids: list[str],
    label_truth: list[str],
    cluster_pred: np.ndarray,
) -> dict[str, dict]:
    """For each analyst label, decompose how HDBSCAN split it. A label
    that lands in one cluster (low fragmentation, high largest_cluster_share)
    = the pipeline groups it cleanly. A label split across many clusters
    (high fragmentation) = the pipeline is fragmenting that label.

    Keys (plan E0.1):
      * ``n_sessions``                 — label support in the eval set.
      * ``n_hdbscan_clusters_assigned`` — distinct cluster ids the label
        members landed in (HDBSCAN ``-1`` counts as one).
      * ``fragmentation_ratio``        — ``n_hdbscan_clusters_assigned /
        n_sessions``. ``1/n`` = perfect grouping; ``1.0`` = every member
        in a different cluster.
      * ``largest_cluster_share``      — share of the label's sessions in
        its dominant cluster.

    Extras retained for cross-referencing from diagnose_embedding_loss.py:
      * ``majority_cluster`` — the dominant cluster id.
      * ``outlier_share``    — share of sessions HDBSCAN tagged as ``-1``.
    """
    by_label: dict[str, list[int]] = {}
    for lbl, c in zip(label_truth, cluster_pred):
        by_label.setdefault(lbl, []).append(int(c))
    out: dict[str, dict] = {}
    for lbl, clusters in sorted(by_label.items()):
        counts = Counter(clusters)
        top_cluster, top_count = counts.most_common(1)[0]
        n = len(clusters)
        n_clusters_assigned = len(counts)
        out[lbl] = {
            "n_sessions":                 n,
            "n_hdbscan_clusters_assigned": n_clusters_assigned,
            "fragmentation_ratio":         round(n_clusters_assigned / n, 3),
            "largest_cluster_share":       round(top_count / n, 3),
            "majority_cluster":            top_cluster,
            "outlier_share":               round(counts.get(-1, 0) / n, 3),
        }
    return out


def _divergent_pair_metrics(
    session_ids: list[str],
    cluster_pred: np.ndarray,
    label_truth: list[str],
    pair_to_sessions: dict[str, list[str]],
) -> tuple[dict, list[dict]]:
    """Compute the v2-specific per-pair metric.

    For each ``divergent_pair_id`` whose two members both ended up in
    the clustering:

      * positive-case pair (analyst gave both the same playbook_label)
        — counted as "resolved" iff the embedding put both in the same
        non-outlier cluster.
      * negative-case pair (analyst gave different labels) — counted
        as "resolved" iff the embedding put the members in different
        clusters (HDBSCAN outliers also count as "different" against
        any non-outlier).

    ``divergent_pair_resolution_rate`` is the fraction of pairs where
    the embedding's clustering call agrees with the analyst's label
    call. Same metric for positive and negative cases — that's the
    point of the v2 set: positives test the embedding's
    "behavior-not-text" claim, negatives keep the metric honest
    against trivial baselines (all-singletons scores ~67% on this
    corpus' negative-heavy distribution; the embedding has to beat
    that on the positives to clear).

    Pairs whose members didn't survive the embedding-bearing filter
    upstream (no embedding, etc.) are skipped — they're a no-op for
    the metric, surfaced via ``n_pairs_skipped``.
    """
    sid_to_cluster: dict[str, int] = {
        sid: int(c) for sid, c in zip(session_ids, cluster_pred)
    }
    sid_to_label: dict[str, str] = {
        sid: lbl for sid, lbl in zip(session_ids, label_truth)
    }

    pos_total = pos_resolved = neg_total = neg_separated = 0
    n_pairs_skipped = 0
    pair_outcomes: list[dict] = []
    for pid, members in pair_to_sessions.items():
        if len(members) != 2:
            n_pairs_skipped += 1
            continue
        sid_a, sid_b = members
        if sid_a not in sid_to_cluster or sid_b not in sid_to_cluster:
            n_pairs_skipped += 1
            continue
        cluster_a = sid_to_cluster[sid_a]
        cluster_b = sid_to_cluster[sid_b]
        labels_match = sid_to_label[sid_a] == sid_to_label[sid_b]
        # HDBSCAN -1 is noise, not a real cluster. Two outliers don't
        # constitute "same cluster" — they're separately not-in-any-
        # cluster, which against the metric counts as "different."
        clusters_match = cluster_a == cluster_b and cluster_a != -1

        if labels_match:
            pos_total += 1
            if clusters_match:
                pos_resolved += 1
        else:
            neg_total += 1
            if not clusters_match:
                neg_separated += 1
        pair_outcomes.append({
            "pair_id":       pid,
            "sessions":      [sid_a, sid_b],
            "labels":        [sid_to_label[sid_a], sid_to_label[sid_b]],
            "clusters":      [cluster_a, cluster_b],
            "labels_match":  labels_match,
            "clusters_match": clusters_match,
            "resolved":      (labels_match == clusters_match),
        })

    n_pairs = pos_total + neg_total
    n_correct = pos_resolved + neg_separated
    rate = (n_correct / n_pairs) if n_pairs else 0.0

    metrics = {
        "divergent_pair_resolution_rate": round(rate, 4),
        "divergent_pair_positive_total":     pos_total,
        "divergent_pair_positive_resolved":  pos_resolved,
        "divergent_pair_negative_total":     neg_total,
        "divergent_pair_negative_separated": neg_separated,
        "divergent_pair_skipped":            n_pairs_skipped,
    }
    return metrics, pair_outcomes


def _evaluate(
    labels_path: Path, jsonl_path: Path, cfg,
    *,
    v2_labels_path: Path | None = None,
    v2_jsonl_path: Path | None = None,
    embedding_source: str = "model",
) -> dict:
    label_blocks = _load_labels(labels_path)
    if not label_blocks:
        raise RuntimeError(
            f"No annotated+real labels with non-null playbook_label "
            f"in {labels_path}"
        )

    # Auto-merge v2 when its labels file exists and a JSONL is reachable.
    # The plan's E1.3 step calls for both sets to feed the same clustering
    # run — that's the corpus every E2+ experiment will measure against.
    v2_label_blocks: dict[str, dict] = {}
    pair_to_sessions: dict[str, list[str]] = {}
    if v2_labels_path is not None and v2_labels_path.exists() \
            and v2_jsonl_path is not None and v2_jsonl_path.exists():
        v2_label_blocks = _load_labels(v2_labels_path)
        for sid, block in v2_label_blocks.items():
            pid = block.get("divergent_pair_id")
            if isinstance(pid, str) and pid:
                pair_to_sessions.setdefault(pid, []).append(sid)
        # Merge into the joint label_blocks. Sessions are partitioned
        # by build: a v2 session_id appearing in v1 would be a bug
        # caught upstream by the build/validate steps.
        label_blocks = {**label_blocks, **v2_label_blocks}

    session_ids: list[str] = []
    label_truth: list[str] = []
    embeddings: list[list[float]] = []
    scalars: list[dict] = []
    skipped_no_embedding: list[str] = []
    session_texts: list[str] = []  # populated only when embedding_source=tfidf-svd
    v2_session_ids: set[str] = set()

    # Iterate v1 first, then v2 (when present). Order doesn't affect the
    # clustering math but keeps the merged label_distribution histogram
    # predictable, and v1-first means overlap sessions (sampled in both
    # sets) load their embedding from v1 — the rollup doc is the same
    # in both JSONLs, so the choice is cosmetic.
    seen_sids: set[str] = set()
    for src_jsonl in (jsonl_path, v2_jsonl_path):
        if src_jsonl is None or not src_jsonl.exists():
            continue
        is_v2 = (src_jsonl == v2_jsonl_path)
        for rec in _iter_jsonl(src_jsonl):
            sid = rec.get("session_id")
            if not isinstance(sid, str) or sid in seen_sids:
                # Dedupe by session_id — when the same session is sampled
                # into both v1 and v2 (the build pipelines don't enforce
                # disjointness), double-clustering it would silently bias
                # the metrics toward the overlap set.
                continue
            if sid not in label_blocks:
                continue
            feats = _extract_session_features(rec)
            if feats is None:
                skipped_no_embedding.append(sid)
                continue
            emb, sc = feats
            if embedding_source == "tfidf-svd":
                text = _extract_session_text(rec)
                if text is None:
                    # Session has an embedding but no command text — shouldn't
                    # happen on the v1 set (build_eval_set ES-filters login-
                    # only), but skip defensively rather than fit TF-IDF on
                    # an empty document.
                    skipped_no_embedding.append(sid)
                    continue
                session_texts.append(text)
            seen_sids.add(sid)
            session_ids.append(sid)
            label_truth.append(label_blocks[sid]["playbook_label"])
            embeddings.append(emb)
            scalars.append(sc)
            if is_v2 or sid in v2_label_blocks:
                # A session loaded via v1 but ALSO carrying a v2 label
                # still counts toward v2 for the divergent-pair lookup —
                # its pair_id is in pair_to_sessions.
                v2_session_ids.add(sid)

    if len(embeddings) < cfg.session.cluster_min_cluster_size:
        raise RuntimeError(
            f"Too few labeled+embedded sessions ({len(embeddings)}) — "
            f"need at least {cfg.session.cluster_min_cluster_size}."
        )

    if embedding_source == "tfidf-svd":
        # Replace the LLM embeddings with the TF-IDF baseline. Scalars
        # stay; the rest of the pipeline (L2-normalize + scalar augment +
        # HDBSCAN) is unchanged so the only varying input is the vector
        # source.
        embeddings = _tfidf_svd_embed(session_texts)

    cluster_pred = _cluster(
        embeddings, scalars,
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        scalar_weight=cfg.session.cluster_scalar_weight,
    )

    # Standard sklearn metrics. HDBSCAN's -1 (outliers) participates in
    # the metrics as a virtual cluster, which is the right behaviour
    # here: if the pipeline rejects an analyst-confirmed session as an
    # outlier, that's a clustering miss the eval should surface.
    metrics = {
        "ari":          round(float(adjusted_rand_score(label_truth, cluster_pred)), 4),
        "nmi":          round(float(normalized_mutual_info_score(label_truth, cluster_pred)), 4),
        "homogeneity":  round(float(homogeneity_score(label_truth, cluster_pred)), 4),
        "completeness": round(float(completeness_score(label_truth, cluster_pred)), 4),
        "v_measure":    round(float(v_measure_score(label_truth, cluster_pred)), 4),
    }

    pair_outcomes: list[dict] = []
    if pair_to_sessions:
        v2_metrics, pair_outcomes = _divergent_pair_metrics(
            session_ids, cluster_pred, label_truth, pair_to_sessions,
        )
        metrics.update(v2_metrics)

    n_clusters = len({int(c) for c in cluster_pred if c >= 0})
    n_outliers = int(sum(1 for c in cluster_pred if c == -1))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "embedding_source": embedding_source,
        "config": {
            "min_cluster_size": cfg.session.cluster_min_cluster_size,
            "min_samples":      cfg.session.cluster_min_samples,
            "scalar_weight":    cfg.session.cluster_scalar_weight,
        },
        "input": {
            "labels_path":          str(labels_path),
            "jsonl_path":           str(jsonl_path),
            "v2_labels_path":       str(v2_labels_path) if v2_labels_path else None,
            "v2_jsonl_path":        str(v2_jsonl_path) if v2_jsonl_path else None,
            "labeled_blocks":       len(label_blocks),
            "labeled_with_embed":   len(embeddings),
            "v2_sessions_in_eval":  len(v2_session_ids),
            "v2_pairs_in_eval":     len(pair_to_sessions),
            "skipped_no_embedding": len(skipped_no_embedding),
            "label_distribution":   dict(Counter(label_truth).most_common()),
        },
        "cluster_output": {
            "n_clusters":     n_clusters,
            "n_outliers":     n_outliers,
            "cluster_sizes":  dict(Counter(int(c) for c in cluster_pred).most_common()),
        },
        "metrics":         metrics,
        "per_label":       _per_label_breakdown(session_ids, label_truth, cluster_pred),
        "divergent_pairs": pair_outcomes,
    }


def _render_stdout(report: dict) -> str:
    """Human-readable summary for stdout."""
    out: list[str] = []
    out.append("=" * 72)
    out.append("Session-layer clustering eval")
    out.append("=" * 72)
    cfg = report["config"]
    out.append(f"hyperparameters     min_cluster_size={cfg['min_cluster_size']}  "
               f"min_samples={cfg['min_samples']}  "
               f"scalar_weight={cfg['scalar_weight']}")
    inp = report["input"]
    out.append(f"labeled blocks      {inp['labeled_blocks']}")
    out.append(f"with embedding      {inp['labeled_with_embed']}  "
               f"(skipped no-embed: {inp['skipped_no_embedding']})")
    v2_n = inp.get("v2_sessions_in_eval") or 0
    if v2_n:
        out.append(
            f"v2 contribution     {v2_n} sessions across "
            f"{inp.get('v2_pairs_in_eval', 0)} divergent pairs"
        )
    out.append(f"label distribution  {inp['label_distribution']}")
    co = report["cluster_output"]
    out.append(f"cluster output      {co['n_clusters']} clusters + "
               f"{co['n_outliers']} outliers")
    out.append("")
    out.append("Metrics (0..1, higher is better):")
    # Split clustering-quality metrics from the integer divergent-pair
    # counters so the stdout table doesn't try to print bare ints as
    # floats. The clustering metrics are all floats; the v2 breakdown
    # has both a rate (float) and supporting counts (ints).
    _CLUSTERING_METRICS = (
        "ari", "nmi", "homogeneity", "completeness", "v_measure",
    )
    _V2_RATE_METRIC = "divergent_pair_resolution_rate"
    _V2_COUNT_METRICS = (
        "divergent_pair_positive_total", "divergent_pair_positive_resolved",
        "divergent_pair_negative_total", "divergent_pair_negative_separated",
        "divergent_pair_skipped",
    )
    for k in _CLUSTERING_METRICS:
        if k in report["metrics"]:
            out.append(f"  {k:14} {report['metrics'][k]:.4f}")
    if _V2_RATE_METRIC in report["metrics"]:
        out.append("")
        out.append("Divergent-pair (v2) metric:")
        out.append(f"  {_V2_RATE_METRIC:33} {report['metrics'][_V2_RATE_METRIC]:.4f}")
        out.append("  per-outcome breakdown:")
        m = report["metrics"]
        pos_t = m.get("divergent_pair_positive_total", 0)
        pos_r = m.get("divergent_pair_positive_resolved", 0)
        neg_t = m.get("divergent_pair_negative_total", 0)
        neg_s = m.get("divergent_pair_negative_separated", 0)
        skipped = m.get("divergent_pair_skipped", 0)
        pos_pct = (pos_r / pos_t) if pos_t else 0.0
        neg_pct = (neg_s / neg_t) if neg_t else 0.0
        out.append(
            f"    positive (same-label):       {pos_r}/{pos_t} "
            f"clustered together ({pos_pct:.2%})"
        )
        out.append(
            f"    negative (different-label):  {neg_s}/{neg_t} "
            f"correctly separated ({neg_pct:.2%})"
        )
        if skipped:
            out.append(f"    skipped (member missing):    {skipped}")
    out.append("")
    out.append("Per-label breakdown (analyst label → cluster grouping):")
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


def _compare_to_baseline(report: dict, baseline_path: Path) -> tuple[list[dict], bool]:
    """Diff the current metrics against ``eval/baseline.json``.

    Returns (per_metric_rows, ok) where ``ok`` is False when any metric
    has dropped more than its tolerance below the baseline. Each row is
    ``{name, baseline, current, tolerance, delta, status}``.

    Tolerance semantics: absolute drop. A metric fails when
    ``current < baseline - tolerance``. Improvements never fail."""
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    rows: list[dict] = []
    ok = True
    current = report["metrics"]
    for name, spec in baseline["metrics"].items():
        cur = current.get(name)
        base = spec["baseline"]
        tol = spec["tolerance"]
        if cur is None:
            rows.append({"name": name, "baseline": base, "current": None,
                         "tolerance": tol, "delta": None, "status": "MISSING"})
            ok = False
            continue
        delta = cur - base
        status = "PASS" if cur >= base - tol else "FAIL"
        if status == "FAIL":
            ok = False
        rows.append({"name": name, "baseline": base, "current": cur,
                     "tolerance": tol, "delta": round(delta, 4), "status": status})
    return rows, ok


def _render_gate(rows: list[dict], ok: bool) -> str:
    out = ["", "=" * 72, "Regression gate vs baseline", "=" * 72,
           f"  {'metric':14} {'baseline':>10} {'current':>10} "
           f"{'tolerance':>10} {'delta':>10}  status"]
    for r in rows:
        cur = "—" if r["current"] is None else f"{r['current']:.4f}"
        dlt = "—" if r["delta"]   is None else f"{r['delta']:+.4f}"
        out.append(
            f"  {r['name']:14} {r['baseline']:>10.4f} {cur:>10} "
            f"{r['tolerance']:>10.4f} {dlt:>10}  {r['status']}"
        )
    out.append("")
    out.append(f"GATE: {'PASS' if ok else 'FAIL'}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", type=Path,
                    default=Path("eval/labels-v1.yaml"),
                    help="v1 analyst-labeled YAML")
    ap.add_argument("--jsonl", type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"),
                    help="v1 unlabeled eval JSONL")
    ap.add_argument("--labels-v2", type=Path,
                    default=Path("eval/labels-v2.yaml"),
                    help=(
                        "v2 (divergent-pair) analyst-labeled YAML. "
                        "When both this and --jsonl-v2 exist, the "
                        "evaluator merges v1+v2 into a single clustering "
                        "run and emits the divergent_pair_resolution_rate "
                        "metric on top of the standard clustering scores. "
                        "Point at a non-existent path to opt out and run "
                        "v1-only (e.g. --labels-v2 /dev/null)."
                    ))
    ap.add_argument("--jsonl-v2", type=Path,
                    default=Path("eval/sessions-v2.unlabeled.jsonl"),
                    help="v2 unlabeled eval JSONL (paired with --labels-v2)")
    ap.add_argument("--output-dir", type=Path,
                    default=Path("eval/results"),
                    help="Where to write the machine-readable JSON")
    ap.add_argument("--no-json", action="store_true",
                    help="Skip writing the JSON dump (stdout only)")
    ap.add_argument("--baseline", type=Path, default=None,
                    help=(
                        "Compare metrics to this baseline file and exit "
                        "non-zero on regression. Use to gate PRs."
                    ))
    ap.add_argument("--embedding-source",
                    choices=["model", "tfidf-svd"],
                    default="model",
                    help=(
                        "Vector source for clustering. `model` uses the "
                        "LLM embeddings persisted on each rollup doc "
                        "(production). `tfidf-svd` fits a baseline "
                        "TF-IDF + truncated-SVD on session command text "
                        "as a model-free comparator (brutal-review "
                        "phase 3.3 embedding ablation)."
                    ))
    args = ap.parse_args()

    cfg = load_config()
    report = _evaluate(
        args.labels, args.jsonl, cfg,
        v2_labels_path=args.labels_v2,
        v2_jsonl_path=args.jsonl_v2,
        embedding_source=args.embedding_source,
    )
    print(_render_stdout(report))

    if not args.no_json:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = args.output_dir / f"clustering-{ts}.json"
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {out_path}")

    if args.baseline is not None:
        rows, ok = _compare_to_baseline(report, args.baseline)
        print(_render_gate(rows, ok))
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
