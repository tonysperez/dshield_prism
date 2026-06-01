"""Diagnose where the embedding wins and loses against TF-IDF on the eval set.

Per the embedding-quality plan E0.2: for every analyst label, run the
session clusterer twice — once with the production LLM embedding,
once with the TF-IDF + truncated-SVD baseline — and surface the pairs
where the two disagree.

Two disagreement sets per label:

  * **embedding wins** — pairs the embedding puts in the same cluster
    that TF-IDF splits. These are the cases where the
    "behaviour-not-text" thesis is doing real work.
  * **embedding loses** — pairs TF-IDF puts in the same cluster that
    the embedding splits. These are the cases where surface text was
    a better signal than the embedding picked up.

For each disagreement set, the script samples up to ``--sample-pairs``
session pairs and prints both session ids plus a one-line command
preview, so a human can eyeball *why* the embedding agreed (or
disagreed) without round-tripping to ES.

HDBSCAN ``-1`` (outlier) is treated as "not in any cluster" — pairs
involving an outlier are never counted as "grouped together."

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/diagnose_embedding_loss.py
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.config import load_config

# Reuse the eval-clustering loaders so the two scripts always agree on
# which sessions land in the eval set.
from eval_clustering import (  # type: ignore
    _cluster,
    _extract_session_features,
    _extract_session_text,
    _iter_jsonl,
    _load_labels,
    _tfidf_svd_embed,
)


def _command_preview(rec: dict, max_chars: int = 120) -> str:
    """One-line preview of the session's first few commands. Used only
    in the human report — never fed back into clustering."""
    text = _extract_session_text(rec) or ""
    text = text.replace("\n", " ⏎ ")
    if len(text) > max_chars:
        text = text[: max_chars - 1] + "…"
    return text or "(no command events)"


def _pair_grouped(cluster_pred: np.ndarray, i: int, j: int) -> bool:
    """True iff sessions i and j land in the same non-outlier cluster.

    HDBSCAN ``-1`` means "noise"; two noise sessions are not grouped
    even though their label id matches numerically."""
    ci = int(cluster_pred[i])
    cj = int(cluster_pred[j])
    return ci == cj and ci != -1


def _diff_label(
    indices: list[int],
    emb_pred: np.ndarray,
    tfidf_pred: np.ndarray,
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Return (embedding_wins, embedding_loses) pair-index lists for the
    sessions inside one analyst label.

    ``embedding_wins`` = grouped by embedding, split by TF-IDF.
    ``embedding_loses`` = grouped by TF-IDF, split by embedding.
    """
    wins: list[tuple[int, int]] = []
    loses: list[tuple[int, int]] = []
    for a in range(len(indices)):
        for b in range(a + 1, len(indices)):
            i, j = indices[a], indices[b]
            emb_together = _pair_grouped(emb_pred, i, j)
            tfidf_together = _pair_grouped(tfidf_pred, i, j)
            if emb_together and not tfidf_together:
                wins.append((i, j))
            elif tfidf_together and not emb_together:
                loses.append((i, j))
    return wins, loses


def _sample(rng: random.Random, pairs: list[tuple[int, int]], k: int) -> list[tuple[int, int]]:
    if len(pairs) <= k:
        return pairs
    return rng.sample(pairs, k)


def _render(report: dict) -> str:
    out: list[str] = []
    out.append("=" * 78)
    out.append("Embedding-vs-TF-IDF per-label disagreement diagnostic")
    out.append("=" * 78)
    inp = report["input"]
    out.append(f"eval sessions       {inp['labeled_with_embed']}")
    out.append(f"labels              {inp['n_labels']}")
    cfg = report["config"]
    out.append(f"hyperparameters     min_cluster_size={cfg['min_cluster_size']}  "
               f"min_samples={cfg['min_samples']}  "
               f"scalar_weight={cfg['scalar_weight']}")
    out.append("")
    out.append("Per-label disagreement (HDBSCAN -1 outliers never counted as grouped):")
    out.append(
        f"  {'label':35} {'n':>4} {'pairs':>6} {'emb_wins':>9} {'emb_loses':>10}"
    )
    for lbl, st in sorted(
        report["per_label"].items(),
        key=lambda kv: (-kv[1]["n_sessions"], kv[0]),
    ):
        out.append(
            f"  {lbl:35} {st['n_sessions']:>4} "
            f"{st['total_possible_pairs']:>6} "
            f"{st['n_embedding_wins']:>9} {st['n_embedding_loses']:>10}"
        )
    out.append("")
    out.append("-" * 78)
    out.append("Sampled pairs (one line per session: <session_id>  <command preview>)")
    out.append("-" * 78)
    for lbl, st in sorted(
        report["per_label"].items(),
        key=lambda kv: (-kv[1]["n_embedding_wins"] - kv[1]["n_embedding_loses"], kv[0]),
    ):
        if not (st["sampled_wins"] or st["sampled_loses"]):
            continue
        out.append("")
        out.append(f"## {lbl}  (n={st['n_sessions']}, "
                   f"wins={st['n_embedding_wins']}, loses={st['n_embedding_loses']})")
        if st["sampled_wins"]:
            out.append("  embedding wins (grouped by embed, split by TF-IDF):")
            for pair in st["sampled_wins"]:
                a, b = pair["sessions"]
                out.append(f"    A {a['sid']}  {a['preview']}")
                out.append(f"    B {b['sid']}  {b['preview']}")
                out.append("")
        if st["sampled_loses"]:
            out.append("  embedding loses (grouped by TF-IDF, split by embed):")
            for pair in st["sampled_loses"]:
                a, b = pair["sessions"]
                out.append(f"    A {a['sid']}  {a['preview']}")
                out.append(f"    B {b['sid']}  {b['preview']}")
                out.append("")
    return "\n".join(out)


def _build(args, cfg) -> dict:
    label_blocks = _load_labels(args.labels)
    if not label_blocks:
        raise RuntimeError(f"No annotated labels found in {args.labels}")

    rng = random.Random(args.seed)

    session_ids: list[str] = []
    label_truth: list[str] = []
    embeddings: list[list[float]] = []
    scalars: list[dict] = []
    texts: list[str] = []
    previews: list[str] = []

    for rec in _iter_jsonl(args.jsonl):
        sid = rec.get("session_id")
        if sid not in label_blocks:
            continue
        feats = _extract_session_features(rec)
        if feats is None:
            continue
        emb, sc = feats
        text = _extract_session_text(rec)
        if text is None:
            # No command events to ground the TF-IDF run; skip rather
            # than fit on an empty string.
            continue
        session_ids.append(sid)
        label_truth.append(label_blocks[sid]["playbook_label"])
        embeddings.append(emb)
        scalars.append(sc)
        texts.append(text)
        previews.append(_command_preview(rec))

    if len(embeddings) < cfg.session.cluster_min_cluster_size:
        raise RuntimeError(
            f"Too few labeled+embedded sessions ({len(embeddings)}) — "
            f"need at least {cfg.session.cluster_min_cluster_size}."
        )

    emb_pred = _cluster(
        embeddings, scalars,
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        scalar_weight=cfg.session.cluster_scalar_weight,
    )
    tfidf_vecs = _tfidf_svd_embed(texts)
    tfidf_pred = _cluster(
        tfidf_vecs, scalars,
        min_cluster_size=cfg.session.cluster_min_cluster_size,
        min_samples=cfg.session.cluster_min_samples,
        scalar_weight=cfg.session.cluster_scalar_weight,
    )

    # Group indices by analyst label.
    label_to_indices: dict[str, list[int]] = defaultdict(list)
    for idx, lbl in enumerate(label_truth):
        label_to_indices[lbl].append(idx)

    per_label: dict[str, dict] = {}
    for lbl, indices in sorted(label_to_indices.items()):
        wins, loses = _diff_label(indices, emb_pred, tfidf_pred)
        sampled_wins = _sample(rng, wins, args.sample_pairs)
        sampled_loses = _sample(rng, loses, args.sample_pairs)
        per_label[lbl] = {
            "n_sessions": len(indices),
            "total_possible_pairs": len(indices) * (len(indices) - 1) // 2,
            "n_embedding_wins": len(wins),
            "n_embedding_loses": len(loses),
            "sampled_wins": [
                {"sessions": [
                    {"sid": session_ids[i], "preview": previews[i]},
                    {"sid": session_ids[j], "preview": previews[j]},
                ]}
                for i, j in sampled_wins
            ],
            "sampled_loses": [
                {"sessions": [
                    {"sid": session_ids[i], "preview": previews[i]},
                    {"sid": session_ids[j], "preview": previews[j]},
                ]}
                for i, j in sampled_loses
            ],
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "min_cluster_size": cfg.session.cluster_min_cluster_size,
            "min_samples":      cfg.session.cluster_min_samples,
            "scalar_weight":    cfg.session.cluster_scalar_weight,
            "tfidf_svd_n_components": 100,
            "sample_pairs":     args.sample_pairs,
            "seed":             args.seed,
        },
        "input": {
            "labels_path":        str(args.labels),
            "jsonl_path":         str(args.jsonl),
            "labeled_blocks":     len(label_blocks),
            "labeled_with_embed": len(embeddings),
            "n_labels":           len(per_label),
            "label_distribution": dict(Counter(label_truth).most_common()),
        },
        "cluster_summary": {
            "embedding": {
                "n_clusters": len({int(c) for c in emb_pred if c >= 0}),
                "n_outliers": int(sum(1 for c in emb_pred if c == -1)),
            },
            "tfidf_svd": {
                "n_clusters": len({int(c) for c in tfidf_pred if c >= 0}),
                "n_outliers": int(sum(1 for c in tfidf_pred if c == -1)),
            },
        },
        "per_label": per_label,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", type=Path, default=Path("eval/labels-v1.yaml"))
    ap.add_argument("--jsonl",  type=Path, default=Path("eval/sessions-v1.unlabeled.jsonl"))
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--no-json", action="store_true")
    ap.add_argument("--sample-pairs", type=int, default=3,
                    help="Sample this many disagreement pairs per label per side.")
    # 2026-06-01: fixed seed for reproducibility. Pin to the plan's E0
    # commit date so sampled pairs are stable across re-runs (lets a
    # reviewer cite specific pair ids in commit messages).
    ap.add_argument("--seed", type=int, default=20260601)
    args = ap.parse_args()

    cfg = load_config()
    report = _build(args, cfg)
    print(_render(report))

    if not args.no_json:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = args.output_dir / f"embedding-loss-{ts}.json"
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
