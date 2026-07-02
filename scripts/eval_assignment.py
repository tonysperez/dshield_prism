"""Offline eval gate for the Option-A assignment algorithm (the post-cutover
counterpart to eval_clustering.py, which now covers only the novel-pool HDBSCAN).

Validates `enrich.sources.cowrie.assignment.assign_batch` against the analyst labels
(`eval/labels-v1.yaml` + `eval/sessions-v1.unlabeled.jsonl`) — no live ES, so it runs in
CI. Builds per-label prototypes from the labelled embeddings (a stand-in for the live
anchors — a production-scale anchor snapshot is a follow-up) and measures the two things
the assignment era cares about:

  * **classification** — stratified train/test split: prototypes from train, 1-NN
    nearest-prototype assignment of test. Reports overall accuracy + macro-F1 + per-label
    precision/recall. Threshold-free (the metric of record), since label-prototypes are
    coarser than the 155 fine anchors so absolute cosines differ from production τ.
  * **novelty (OOD)** — Exp-2 offline: hold out one label's prototype, assign that label's
    sessions against the rest, and check their nearest-surviving cosine is *lower* than
    in-distribution sessions' nearest cosine. Reports a rank-AUC of "held-out reads as
    novel" (threshold-free) + the mean-cosine gap.

DIAGNOSTIC ONLY (post quality-metrics Slice A): assignment quality now gates in
scripts/eval_operational.py with variance-justified thresholds. This script still
prints accuracy / macro-F1 / mean_auc_novel for visibility but never fails a build;
mean_auc_novel is threshold-free (the pipeline ships one fixed cosine point).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.assignment import assign_batch


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
def load_labeled(labels_path: Path, jsonl_path: Path) -> tuple[list[str], np.ndarray]:
    """(labels, embeddings) for every annotated, non-null labelled session that has an
    embedding. Index-aligned."""
    raw = yaml.safe_load(labels_path.read_text()) or {}
    label_of = {sid: b.get("playbook_label") for sid, b in raw.items()
                if isinstance(b, dict) and b.get("annotated") and b.get("playbook_label")}
    labels, embs = [], []
    for line in jsonl_path.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        sid = rec.get("session_id")
        if sid not in label_of:
            continue
        enr = ((((rec.get("rollup_doc") or {}).get("dshield") or {}).get("cowrie") or {})
               .get("enrichment", {}).get("session", {}))
        emb = enr.get("embedding")
        if isinstance(emb, list) and emb:
            labels.append(label_of[sid])
            embs.append(emb)
    return labels, _l2(np.array(embs, dtype=np.float32))


def _l2(m: np.ndarray) -> np.ndarray:
    n = np.linalg.norm(m, axis=1, keepdims=True)
    return m / np.where(n == 0.0, 1.0, n)


def stratified_split(labels: list[str], seed: int = 0) -> tuple[list[int], list[int]]:
    """Deterministic per-label split: alternating members → (train, test)."""
    by = defaultdict(list)
    for i, lb in enumerate(labels):
        by[lb].append(i)
    train, test = [], []
    for lb in sorted(by):
        members = by[lb]
        for k, i in enumerate(members):
            (train if k % 2 == 0 else test).append(i)
    return sorted(train), sorted(test)


# ---------------------------------------------------------------------------
# Pure metric cores (smoke-tested)
# ---------------------------------------------------------------------------
def build_prototypes(embs: np.ndarray, labels: list[str]) -> tuple[list[str], np.ndarray]:
    """L2-normalised mean embedding per label."""
    by = defaultdict(list)
    for i, lb in enumerate(labels):
        by[lb].append(i)
    ids = sorted(by)
    mat = np.array([embs[by[lb]].mean(axis=0) for lb in ids], dtype=np.float32)
    return ids, _l2(mat)


def classification_metrics(test_embs, test_labels, proto_ids, proto_mat) -> dict:
    """1-NN nearest-prototype assignment (τ-free: assign everything, take nearest)."""
    res = assign_batch(test_embs, proto_mat, proto_ids, tau=0.0, confident_tau=0.0)
    pred = [r.playbook_id for r in res]
    correct = sum(1 for p, t in zip(pred, test_labels) if p == t)
    # macro precision/recall over labels present in the test set
    per: dict[str, dict] = {}
    for lb in sorted(set(test_labels)):
        tp = sum(1 for p, t in zip(pred, test_labels) if p == lb and t == lb)
        fp = sum(1 for p, t in zip(pred, test_labels) if p == lb and t != lb)
        fn = sum(1 for p, t in zip(pred, test_labels) if p != lb and t == lb)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        per[lb] = {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)}
    macro_f1 = float(np.mean([m["f1"] for m in per.values()])) if per else 0.0
    return {
        "n_test": len(test_labels),
        "accuracy": round(correct / len(test_labels), 4) if test_labels else None,
        "macro_f1": round(macro_f1, 4),
        "per_label": per,
    }


def _rank_auc(pos: np.ndarray, neg: np.ndarray) -> float:
    """AUC = P(pos ranks above neg). Here 'positive' = held-out session correctly reads
    as MORE novel, i.e. its nearest-surviving cosine is LOWER than an in-dist session's.
    So we score 1 - cosine and AUC over (held-out vs in-dist)."""
    if len(pos) == 0 or len(neg) == 0:
        return None
    order = np.argsort(np.concatenate([pos, neg]))
    ranks = np.empty(len(order), dtype=np.float64)
    ranks[order] = np.arange(1, len(order) + 1)
    r_pos = ranks[:len(pos)].sum()
    auc = (r_pos - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))
    return round(float(auc), 4)


def novelty_metrics(embs: np.ndarray, labels: list[str], min_label_size: int = 4) -> dict:
    """Per held-out label: its sessions assigned against the OTHER labels' prototypes
    should have lower nearest cosine than in-distribution sessions. Rank-AUC of that."""
    by = defaultdict(list)
    for i, lb in enumerate(labels):
        by[lb].append(i)
    per = {}
    aucs, gaps = [], []
    for lb in sorted(by):
        held_idx = by[lb]
        if len(held_idx) < min_label_size:
            continue
        keep_mask = np.array([labels[i] != lb for i in range(len(labels))])
        proto_ids, proto_mat = build_prototypes(embs[keep_mask], [labels[i] for i in range(len(labels)) if keep_mask[i]])
        held = embs[held_idx]
        held_cos = (held @ proto_mat.T).max(axis=1)            # nearest surviving (should be low)
        indist = embs[keep_mask]
        indist_cos = (indist @ proto_mat.T).max(axis=1)        # nearest own-ish (should be high)
        # positives = held-out novelty score (1-cos); AUC that held-out > in-dist on novelty
        auc = _rank_auc(1.0 - held_cos, 1.0 - indist_cos)
        gap = round(float(indist_cos.mean() - held_cos.mean()), 4)
        per[lb] = {"n_held": len(held_idx), "auc_novel": auc,
                   "mean_heldout_cos": round(float(held_cos.mean()), 4),
                   "mean_indist_cos": round(float(indist_cos.mean()), 4), "cos_gap": gap}
        if auc is not None:
            aucs.append(auc)
            gaps.append(gap)
    return {
        "mean_auc_novel": round(float(np.mean(aucs)), 4) if aucs else None,
        "mean_cos_gap": round(float(np.mean(gaps)), 4) if gaps else None,
        "per_label": per,
    }


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------
_GATED = {"accuracy": "classification", "macro_f1": "classification",
          "mean_auc_novel": "novelty"}


def evaluate(labels: list[str], embs: np.ndarray) -> dict:
    train, test = stratified_split(labels)
    proto_ids, proto_mat = build_prototypes(embs[train], [labels[i] for i in train])
    cls = classification_metrics(embs[test], [labels[i] for i in test], proto_ids, proto_mat)
    nov = novelty_metrics(embs, labels)
    return {
        "n_labeled": len(labels), "n_train": len(train), "n_test": len(test),
        "n_labels": len(set(labels)),
        "metrics": {"accuracy": cls["accuracy"], "macro_f1": cls["macro_f1"],
                    "mean_auc_novel": nov["mean_auc_novel"]},
        "classification": cls, "novelty": nov,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", default="eval/labels-v1.yaml")
    ap.add_argument("--unlabeled", default="eval/sessions-v1.unlabeled.jsonl")
    ap.add_argument("--baseline", default="eval/baseline-assignment.json")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--tolerance", type=float, default=0.05)
    ap.add_argument("--no-json", action="store_true")
    args = ap.parse_args()

    labels, embs = load_labeled(Path(args.labels), Path(args.unlabeled))
    if not labels:
        print("No labelled sessions with embeddings found.", file=sys.stderr)
        return 1
    report = evaluate(labels, embs)

    if args.write_baseline:
        Path(args.baseline).write_text(json.dumps(
            {"metrics": report["metrics"], "tolerance": args.tolerance,
             "captured_from": "eval_assignment.py --write-baseline"}, indent=2))
        print(f"wrote baseline {args.baseline}")
        return 0

    if not args.no_json:
        print(json.dumps(report, indent=2))

    # DIAGNOSTIC ONLY. The operational gate is scripts/eval_operational.py; the
    # assignment macro-F1 / per-label accuracy / novelty numbers now gate there
    # (variance-justified thresholds). This script prints the same metrics for
    # visibility but never fails a build — mean_auc_novel is a threshold-free
    # diagnostic (the pipeline ships one fixed cosine point, not an AUC).
    base = json.loads(Path(args.baseline).read_text()) if Path(args.baseline).exists() else None
    print(f"\n  {'metric':18}{'baseline':>10}{'current':>10}{'delta':>9}")
    for m in _GATED:
        cur = report["metrics"].get(m)
        if base is None:
            print(f"  {m:18}{'(none)':>10}{cur!s:>10}")
            continue
        bl = base["metrics"].get(m)
        if cur is None or bl is None:
            print(f"  {m:18}{bl!s:>10}{cur!s:>10}")
            continue
        print(f"  {m:18}{bl:>10.4f}{cur:>10.4f}{cur - bl:>+9.4f}")
    print("\nDIAGNOSTIC — not gating (operational gate: scripts/eval_operational.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
