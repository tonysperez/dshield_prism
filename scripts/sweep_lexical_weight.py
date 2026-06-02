"""E4.2 sweep — TF-IDF + SVD lexical block weight against the eval set.

Phase E2 + E3 established that the general-purpose embedder ceiling on
this corpus is ARI 0.4447 / completeness 0.6040 (Nomic and BGE tied
exactly; smaller model lost; code-specific candidate DNF). The only
remaining knob short of fine-tuning is hybrid features: hand the
HDBSCAN clusterer a parallel block of explicit lexical structure
alongside the embedding so the clusterer can exploit information the
embedding alone misses.

This sweep concatenates a per-session TF-IDF + truncated-SVD lexical
block (100-d, mirroring the E0.2 ablation script's setup) onto the
production cluster matrix at each of:

    weight ∈ {0.0, 0.05, 0.10, 0.20, 0.40, 0.80}

weight=0.0 is the production baseline (embedding + scalar block only)
and serves as the sweep's anchor row — a sanity check that the
mechanic doesn't regress when the lexical block is zeroed.

No production code is touched — the cluster-matrix assembly is inlined
in this script. If a non-zero weight wins, E4.3 lifts the assembly
into ``src/enrich/clustering.py`` behind a ``cluster_lexical_weight``
config knob (default 0.0 keeps production unchanged).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/sweep_lexical_weight.py
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
from sklearn.cluster import HDBSCAN
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
# Ingestion (mirrors eval_clustering's session collection)
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
    v1_jsonl: Path | None, v2_jsonl: Path | None,
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
            embedding=emb,
            scalars=sc,
            text=text,
            is_v2=is_v2 or sid in v2_labels,
        ))

    if v1_jsonl is not None and v1_jsonl.exists():
        for rec in _iter_jsonl(v1_jsonl):
            _ingest_one(rec, is_v2=False)
    if v2_jsonl is not None and v2_jsonl.exists():
        for rec in _iter_jsonl(v2_jsonl):
            _ingest_one(rec, is_v2=True)
    return out


# ---------------------------------------------------------------------------
# Lexical block
# ---------------------------------------------------------------------------

def _tfidf_svd_block(
    texts: list[str], n_components: int = 100,
) -> np.ndarray:
    """Fit TF-IDF + truncated SVD on the corpus once. Same hyperparams
    as the E0.2 ablation: max_features 5000, (1,2) ngrams, sublinear_tf,
    l2 norm. Returns an (n_sessions, n_components) matrix."""
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        norm="l2",
    )
    tfidf = vectorizer.fit_transform(texts)
    n_components = min(n_components, tfidf.shape[1], tfidf.shape[0] - 1)
    if n_components < 2:
        log.warning("corpus too small for SVD — returning zero block")
        return np.zeros((tfidf.shape[0], 1), dtype=np.float32)
    svd = TruncatedSVD(n_components=n_components, random_state=20260601)
    reduced = svd.fit_transform(tfidf).astype(np.float32)
    # L2-normalize each row so the block contributes consistently when
    # scaled by the sweep's weight, regardless of session command volume.
    norms = np.linalg.norm(reduced, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return (reduced / norms).astype(np.float32)


# ---------------------------------------------------------------------------
# Hybrid clustering + scoring
# ---------------------------------------------------------------------------

def _cluster_hybrid(
    embeddings: list[list[float]],
    scalars: list[dict],
    lexical_block: np.ndarray,
    *,
    min_cluster_size: int,
    min_samples: int,
    scalar_weight: float,
    lexical_weight: float,
) -> np.ndarray:
    """Same shape as eval_clustering._cluster, with a third block: the
    weighted lexical features hstacked after the scalar block."""
    matrix = np.array(embeddings, dtype=np.float32)
    normalized = l2_normalize(matrix)
    parts = [normalized]
    if scalar_weight > 0.0:
        parts.append(build_session_scalar_block(scalars, scalar_weight))
    if lexical_weight > 0.0 and lexical_block.size > 0:
        parts.append(lexical_block * lexical_weight)
    cluster_matrix = np.hstack(parts)
    clusterer = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
    )
    return clusterer.fit_predict(cluster_matrix)


def _score(
    sessions: list[Session], lexical_block: np.ndarray, cfg,
    v2_labels: dict, lexical_weight: float,
) -> dict:
    session_ids = [s.session_id for s in sessions]
    labels = [s.label for s in sessions]
    cluster_pred = _cluster_hybrid(
        [s.embedding for s in sessions],
        [s.scalars for s in sessions],
        lexical_block,
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        scalar_weight=cfg.session.cluster_scalar_weight,
        lexical_weight=lexical_weight,
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


def _render_markdown(rows: list[dict], n_sessions: int) -> str:
    out: list[str] = []
    out.append("# E4.2 — lexical-weight sweep")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append(
        f"Sorted by ARI descending. {len(rows)} weights swept against the "
        f"merged v1+v2 eval set ({n_sessions} sessions). "
        f"Lexical block = per-session TF-IDF (max_features 5000, (1,2) "
        f"ngrams, sublinear_tf, l2 norm) + truncated SVD to 100 dims, "
        f"L2-normalized per row. Stacked alongside the embedding + "
        f"scalar block at the specified weight before HDBSCAN."
    )
    out.append("")
    out.append("Anchor: `lexical_weight=0.0` reproduces the production baseline.")
    out.append("")
    headers = ["lexical_weight"] + list(_METRIC_ORDER) + ["n_clusters", "n_outliers"]
    out.append("| " + " | ".join(headers) + " |")
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        cells = [f"{r['lexical_weight']:.2f}"]
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

# Plan E4.2 weight sweep, plus an explicit 0.0 anchor.
SWEEP_WEIGHTS: tuple[float, ...] = (0.0, 0.05, 0.10, 0.20, 0.40, 0.80)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels-v1", type=Path, default=Path("eval/labels-v1.yaml"))
    ap.add_argument("--jsonl-v1",  type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"))
    ap.add_argument("--labels-v2", type=Path, default=Path("eval/labels-v2.yaml"))
    ap.add_argument("--jsonl-v2",  type=Path,
                    default=Path("eval/sessions-v2.unlabeled.jsonl"))
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--weights", type=str, default=None,
                    help=(
                        "Comma-separated weights to sweep, e.g. "
                        "`0.0,0.05,0.10,0.20,0.40,0.80`. Default = the "
                        "plan E4.2 list."
                    ))
    ap.add_argument("--svd-dim", type=int, default=100,
                    help="Truncated-SVD output dim for the lexical block.")
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
    log.info("ingested %d sessions (%d v2); labels: %s",
             len(sessions), sum(1 for s in sessions if s.is_v2),
             dict(Counter(s.label for s in sessions).most_common()))

    lexical = _tfidf_svd_block([s.text for s in sessions], n_components=args.svd_dim)
    log.info("lexical block: shape=%s", lexical.shape)

    weights = (
        [float(w) for w in args.weights.split(",")] if args.weights
        else list(SWEEP_WEIGHTS)
    )

    rows: list[dict] = []
    for w in weights:
        log.info("lexical_weight=%.2f", w)
        scored = _score(sessions, lexical, cfg, v2_labels, w)
        rows.append({"lexical_weight": w, **scored})
        log.info("  → metrics: %s", scored["metrics"])

    rows.sort(key=lambda r: -r["metrics"].get("ari", 0.0))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = args.output_dir / f"lexical-weight-sweep-{ts}.md"
    json_path = args.output_dir / f"lexical-weight-sweep-{ts}.json"
    md_text = _render_markdown(rows, len(sessions))
    md_path.write_text(md_text, encoding="utf-8")
    json_path.write_text(json.dumps({
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "n_sessions":    len(sessions),
        "lexical_shape": list(lexical.shape),
        "rows":          rows,
    }, indent=2), encoding="utf-8")
    print(f"\nwrote {md_path}")
    print(f"wrote {json_path}\n")
    print(md_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
