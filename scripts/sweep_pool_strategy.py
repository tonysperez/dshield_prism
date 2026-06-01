"""E2.2 sweep — session-layer pool-strategy combinations.

Reuses the per-command embeddings already persisted in the v1+v2
JSONLs (those came from the live production embedder, post-E2.1
adoption of ``cooccurrence.embed_cooccurrence=false``). For each
strategy below, re-pool each session's per-command vectors into a
session vector, re-cluster with the production HDBSCAN config, score
on the merged corpus including ``divergent_pair_resolution_rate``.

Strategies (matches plan E2.2):

  * mean              IDF-weighted mean, L2-norm in/out (production)
  * mean_unweighted   uniform-weight mean (drops IDF)
  * max               element-wise max of L2-normed inputs, L2-norm
  * concat_top_3      concat the IDF-top-3 commands; pad with zeros
  * concat_top_5      same, k=5
  * concat_top_10     same, k=10
  * attention_pool    weighted mean using per-command novelty score

The sweep performs NO ``llm.embed()`` calls and NO ES queries — just
arithmetic on the persisted vectors. Wall time is dominated by HDBSCAN
re-fits at higher dimensions (the concat_top_10 variant is 7680-dim
before scalar augmentation).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_pool_strategy.py
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import math
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    v_measure_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.config import load_config
from enrich.sources.cowrie.sessions import _idf_pool_weight, _mean_pool

from eval_clustering import (  # type: ignore
    _cluster,
    _divergent_pair_metrics,
    _load_labels,
    _per_label_breakdown,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pool strategies
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PoolStrategy:
    name:  str
    kind:  str            # one of: mean, mean_unweighted, max, concat_top_k, attention
    k:     int | None = None
    output_dim_for: callable | None = None


def _l2_normalize(vec: list[float]) -> list[float]:
    n = math.sqrt(sum(v * v for v in vec))
    if n == 0.0:
        return [0.0] * len(vec)
    inv = 1.0 / n
    return [v * inv for v in vec]


def _pool_max(per_command_vectors: list[list[float]]) -> list[float]:
    """Element-wise max of L2-normalized inputs, then L2-normalize the
    result. Captures the strongest signal in each dimension across the
    session's commands."""
    if not per_command_vectors:
        return []
    dim = len(per_command_vectors[0])
    normed = [_l2_normalize(v) for v in per_command_vectors]
    out = [max(v[i] for v in normed) for i in range(dim)]
    return _l2_normalize(out)


def _pool_concat_top_k(
    per_command_vectors: list[list[float]],
    weights: list[float],
    k: int,
    base_dim: int,
) -> list[float]:
    """Concatenate the top-k commands by IDF weight. Pads with zeros
    when the session has fewer than k commands — the resulting vector
    is sparse but still embeddable in the fixed k*base_dim space the
    sweep needs for HDBSCAN to consume a single matrix."""
    pairs = sorted(zip(weights, per_command_vectors), key=lambda p: -p[0])
    top = pairs[:k]
    out: list[float] = []
    for _, vec in top:
        out.extend(vec)
    target_dim = k * base_dim
    if len(out) < target_dim:
        out.extend([0.0] * (target_dim - len(out)))
    # L2-normalize the concatenated vector so downstream HDBSCAN's
    # L2-norm pass is a no-op and the geometry matches what other
    # strategies feed.
    return _l2_normalize(out)


def _pool_one(
    strategy: PoolStrategy,
    per_command_vectors: list[list[float]],
    idf_weights: list[float],
    novelty_scores: list[float],
    base_dim: int,
) -> list[float]:
    """Dispatcher. Returns the pooled session embedding."""
    if not per_command_vectors:
        return [0.0] * base_dim
    if strategy.kind == "mean":
        return _mean_pool(per_command_vectors, idf_weights)
    if strategy.kind == "mean_unweighted":
        return _mean_pool(per_command_vectors, None)
    if strategy.kind == "max":
        return _pool_max(per_command_vectors)
    if strategy.kind == "concat_top_k":
        assert strategy.k is not None
        return _pool_concat_top_k(per_command_vectors, idf_weights, strategy.k, base_dim)
    if strategy.kind == "attention":
        # Per-command novelty as weight. Fall back to uniform when a
        # command lacks a novelty score (novel commands score high; a
        # missing score means the command never crossed a cluster pass,
        # which we treat as low-importance).
        weights = [n if n is not None else 0.0 for n in novelty_scores]
        # _mean_pool drops zero-weight entries; if every weight is
        # zero (e.g. session with no clustering history) the function
        # returns a zero vector. Fall back to uniform pooling in that
        # case so the sweep doesn't drop the session.
        if not any(w > 0.0 for w in weights):
            return _mean_pool(per_command_vectors, None)
        return _mean_pool(per_command_vectors, weights)
    raise ValueError(f"unknown pool kind {strategy.kind!r}")


SWEEP_STRATEGIES: tuple[PoolStrategy, ...] = (
    PoolStrategy("mean",              "mean"),
    PoolStrategy("mean_unweighted",   "mean_unweighted"),
    PoolStrategy("max",               "max"),
    PoolStrategy("concat_top_3",      "concat_top_k", k=3),
    PoolStrategy("concat_top_5",      "concat_top_k", k=5),
    PoolStrategy("concat_top_10",     "concat_top_k", k=10),
    PoolStrategy("attention_pool",    "attention"),
)


# ---------------------------------------------------------------------------
# Eval-set ingestion (per-command vectors persisted on the JSONL)
# ---------------------------------------------------------------------------

@dataclass
class SessionFacts:
    session_id:    str
    label:         str
    scalars:       dict
    is_v2:         bool
    # Per-unique-command entries, in JSONL order. Each entry:
    # (embedding_vector, idf_weight, novelty_score)
    commands:      list[tuple[list[float], float, float]]


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _extract_scalars(rec: dict) -> dict | None:
    """Mirror eval_clustering._extract_session_features's scalar block."""
    rollup = rec.get("rollup_doc") or {}
    enr = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    success = enr.get("login_success_count") or 0
    fail = enr.get("login_fail_count") or 0
    total = success + fail
    return {
        "command_count":      enr.get("command_count") or 1,
        "unique_commands":    enr.get("unique_commands") or 1,
        "login_success_rate": success / total if total > 0 else 0.0,
        "mean_novelty_score": enr.get("mean_novelty_score") or 0.0,
    }


def _ingest_sessions(
    v1_labels: dict[str, dict],
    v2_labels: dict[str, dict],
    v1_jsonl: Path | None,
    v2_jsonl: Path | None,
) -> tuple[list[SessionFacts], int]:
    """Build the SessionFacts list. Returns (sessions, base_dim) where
    base_dim is the per-command embedding dimensionality."""
    label_blocks = {**v1_labels, **v2_labels}
    sessions: list[SessionFacts] = []
    seen_sids: set[str] = set()
    base_dim = 0

    def _ingest_one(rec: dict, is_v2: bool) -> None:
        nonlocal base_dim
        sid = rec.get("session_id")
        if not isinstance(sid, str) or sid in seen_sids:
            return
        if sid not in label_blocks:
            return
        scalars = _extract_scalars(rec)
        if scalars is None:
            return
        commands: list[tuple[list[float], float, float]] = []
        for ce in rec.get("command_enrichments") or []:
            enr = (((ce.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
            emb = enr.get("embedding")
            if not isinstance(emb, list) or not emb:
                continue
            if base_dim == 0:
                base_dim = len(emb)
            occ = int(enr.get("occurrence_count") or 1)
            idf = _idf_pool_weight(occ)
            novelty = (enr.get("cluster") or {}).get("novelty_score")
            try:
                novelty = float(novelty) if novelty is not None else 0.0
            except (TypeError, ValueError):
                novelty = 0.0
            commands.append((emb, idf, novelty))
        if not commands:
            return
        seen_sids.add(sid)
        sessions.append(SessionFacts(
            session_id=sid,
            label=label_blocks[sid]["playbook_label"],
            scalars=scalars,
            is_v2=is_v2 or sid in v2_labels,
            commands=commands,
        ))

    if v1_jsonl is not None and v1_jsonl.exists():
        for rec in _iter_jsonl(v1_jsonl):
            _ingest_one(rec, is_v2=False)
    if v2_jsonl is not None and v2_jsonl.exists():
        for rec in _iter_jsonl(v2_jsonl):
            _ingest_one(rec, is_v2=True)
    return sessions, base_dim


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score(
    sessions: list[SessionFacts],
    session_embeddings: list[list[float]],
    cfg,
    v2_labels: dict[str, dict],
) -> dict:
    session_ids = [s.session_id for s in sessions]
    labels = [s.label for s in sessions]
    scalars = [s.scalars for s in sessions]

    cluster_pred = _cluster(
        session_embeddings, scalars,
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        scalar_weight=cfg.session.cluster_scalar_weight,
    )
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
        "metrics":       metrics,
        "n_clusters":    n_clusters,
        "n_outliers":    n_outliers,
        "per_label":     _per_label_breakdown(session_ids, labels, cluster_pred),
        "pair_outcomes": pair_outcomes,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_METRIC_ORDER = (
    "ari", "completeness", "homogeneity", "nmi", "v_measure",
    "divergent_pair_resolution_rate",
)


def _render_markdown(rows: list[dict], n_sessions: int, base_dim: int) -> str:
    out: list[str] = []
    out.append("# E2.2 — pool strategy sweep")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append(
        f"Sorted by ARI descending. {len(rows)} pool strategies swept against "
        f"the merged v1+v2 eval set ({n_sessions} sessions). Per-command "
        f"vectors come from the persisted JSONL embeddings (base_dim={base_dim}); "
        f"no LLM calls."
    )
    out.append("")
    headers = ["strategy", "embedding_dim"] + list(_METRIC_ORDER) \
              + ["n_clusters", "n_outliers"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        cells = [
            r["strategy"]["name"],
            str(r["embedding_dim"]),
        ]
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

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels-v1", type=Path,
                    default=Path("eval/labels-v1.yaml"))
    ap.add_argument("--jsonl-v1", type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"))
    ap.add_argument("--labels-v2", type=Path,
                    default=Path("eval/labels-v2.yaml"))
    ap.add_argument("--jsonl-v2", type=Path,
                    default=Path("eval/sessions-v2.unlabeled.jsonl"))
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config()
    v1_labels = _load_labels(args.labels_v1)
    v2_labels = _load_labels(args.labels_v2) if args.labels_v2.exists() else {}

    sessions, base_dim = _ingest_sessions(
        v1_labels, v2_labels, args.jsonl_v1, args.jsonl_v2,
    )
    if base_dim == 0:
        print("[ERROR] no per-command embeddings found in JSONLs — did you "
              "refresh them after the last reembed? "
              "(scripts/refresh_eval_embeddings.py)", file=sys.stderr)
        return 1
    log.info("ingested %d sessions (%d v2), base_dim=%d, labels: %s",
             len(sessions), sum(1 for s in sessions if s.is_v2), base_dim,
             dict(Counter(s.label for s in sessions).most_common()))

    rows: list[dict] = []
    for strategy in SWEEP_STRATEGIES:
        log.info("strategy: %s", strategy.name)
        session_embeddings: list[list[float]] = []
        for s in sessions:
            per_cmd = [e for e, _, _ in s.commands]
            idfs    = [w for _, w, _ in s.commands]
            novs    = [n for _, _, n in s.commands]
            pooled = _pool_one(strategy, per_cmd, idfs, novs, base_dim)
            session_embeddings.append(pooled)
        # Embedding dim for the cluster matrix — bookkeeping for the
        # output table; HDBSCAN takes whatever we give it.
        emb_dim = len(session_embeddings[0]) if session_embeddings else 0
        scored = _score(sessions, session_embeddings, cfg, v2_labels)
        rows.append({
            "strategy":      dataclasses.asdict(strategy),
            "embedding_dim": emb_dim,
            **scored,
        })
        log.info("  → metrics: %s", scored["metrics"])

    rows.sort(key=lambda r: -r["metrics"].get("ari", 0.0))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"pool-strategy-sweep-{ts}.md"
    json_path = args.output_dir / f"pool-strategy-sweep-{ts}.json"
    md_text = _render_markdown(rows, len(sessions), base_dim)
    md_path.write_text(md_text, encoding="utf-8")
    json_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_sessions":   len(sessions),
        "base_dim":     base_dim,
        "rows":         rows,
    }, indent=2), encoding="utf-8")
    print(f"\nwrote {md_path}")
    print(f"wrote {json_path}\n")
    print(md_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
