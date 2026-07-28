"""Offline eval gate for the Option-A assignment algorithm (the post-cutover
counterpart to eval_clustering.py, which now covers only the novel-pool HDBSCAN).

Validates `enrich.sources.cowrie.assignment.assign_batch` against the analyst labels
(`eval/labels.yaml` + `eval/sessions.unlabeled.jsonl`) — no live ES, so it runs in
CI. Builds per-label prototypes from the labelled embeddings (a stand-in for the live
anchors — a production-scale anchor snapshot is a follow-up) and measures the two things
the assignment era cares about:

  * **classification** — deterministic repeated stratified k-fold (CAP-8 / A2):
    prototypes from each fold's train split, 1-NN nearest-prototype assignment of its
    test split. Point estimate = mean accuracy/macro-F1/per-label recall over all folds;
    CI = the across-fold spread. Threshold-free (the metric of record), since
    label-prototypes are coarser than the 155 fine anchors so absolute cosines differ
    from production τ.
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


def _fold_assignment(labels: list[str], k: int, seed: int, rotation: int) -> list[int]:
    """Deterministic per-label round-robin fold index for one repeat. Each
    label's members are shuffled (seeded) then assigned folds
    `(index + rotation) % k` in rotation, so a label with fewer members than
    `k` still lands each member in a distinct fold, and a size-1 label always
    lands in exactly one fold — which one varies across repeats via
    `rotation`, rather than being pinned to the same fold forever."""
    rng = np.random.default_rng(seed)
    by = defaultdict(list)
    for i, lb in enumerate(labels):
        by[lb].append(i)
    fold_of = [-1] * len(labels)
    for lb in sorted(by):
        order = list(by[lb])
        rng.shuffle(order)
        for j, i in enumerate(order):
            fold_of[i] = (j + rotation) % k
    return fold_of


def repeated_stratified_kfold(
    labels: list[str], *, k: int = 5, repeats: int = 3, seed: int = 0,
) -> list[tuple[list[int], list[int]]]:
    """Deterministic repeated stratified k-fold (CAP-8 / A2), replacing the
    single alternating 50/50 split (`stratified_split`, retired). That split
    had three coupled defects: singleton labels went train-only and vanished
    from macro-F1 and the per-label floor; size-2 labels trained a
    1-example prototype tested on 1 example; and its bootstrap resampled one
    fixed test half with prototypes frozen, so the reported CI captured only
    test-resampling noise, not split variance.

    Every label with >=1 member reaches a test fold at least once per
    repeat (`_fold_assignment`'s rotation) — including singletons, which a
    plain scikit `StratifiedKFold` would reject outright (it requires
    `n_splits <= smallest class size`). Returns one `(train_idx, test_idx)`
    pair per (repeat, fold); the caller's point estimate is the mean over all
    of them, and the CI is the across-fold/repeat spread — which, unlike the
    retired split's bootstrap, actually captures split variance. Deterministic
    under a fixed `seed`: same seed -> bit-identical folds.
    """
    n = len(labels)
    folds: list[tuple[list[int], list[int]]] = []
    for r in range(repeats):
        fold_of = _fold_assignment(labels, k, seed=seed + r, rotation=r % k)
        for f in range(k):
            test = [i for i in range(n) if fold_of[i] == f]
            if not test:
                continue
            train = [i for i in range(n) if fold_of[i] != f]
            folds.append((train, test))
    return folds


def fold_ci_half_width(values: list[float]) -> float:
    """Half-width of the 95% percentile spread of a per-fold metric list —
    the across-fold/repeat variance CAP-8 makes visible (vs. the retired
    split's single-test-half bootstrap). 0.0 when too few folds exist to form
    a spread."""
    if len(values) < 2:
        return 0.0
    lo, hi = np.percentile(values, [2.5, 97.5])
    return round(float(hi - lo) / 2.0, 4)


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


_DEFAULT_K, _DEFAULT_REPEATS = 5, 3


def evaluate(labels: list[str], embs: np.ndarray, *,
             k: int = _DEFAULT_K, repeats: int = _DEFAULT_REPEATS, seed: int = 0) -> dict:
    folds = repeated_stratified_kfold(labels, k=k, repeats=repeats, seed=seed)
    fold_acc, fold_f1 = [], []
    per_label_recall: dict[str, list[float]] = defaultdict(list)
    for train, test in folds:
        proto_ids, proto_mat = build_prototypes(embs[train], [labels[i] for i in train])
        cls = classification_metrics(embs[test], [labels[i] for i in test], proto_ids, proto_mat)
        if cls["accuracy"] is not None:
            fold_acc.append(cls["accuracy"])
        fold_f1.append(cls["macro_f1"])
        for lb, m in cls["per_label"].items():
            per_label_recall[lb].append(m["recall"])
    accuracy = round(float(np.mean(fold_acc)), 4) if fold_acc else None
    macro_f1 = round(float(np.mean(fold_f1)), 4) if fold_f1 else 0.0
    per_label = {lb: {"recall_mean": round(float(np.mean(v)), 4), "n_folds": len(v)}
                 for lb, v in sorted(per_label_recall.items())}
    nov = novelty_metrics(embs, labels)
    return {
        "n_labeled": len(labels), "n_folds": k, "n_repeats": repeats, "n_folds_run": len(folds),
        "n_labels": len(set(labels)),
        "metrics": {"accuracy": accuracy, "macro_f1": macro_f1,
                    "mean_auc_novel": nov["mean_auc_novel"]},
        "ci_half_width": {"accuracy": fold_ci_half_width(fold_acc),
                          "macro_f1": fold_ci_half_width(fold_f1)},
        "classification": {"per_label": per_label},
        "novelty": nov,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", default="eval/labels.yaml")
    ap.add_argument("--unlabeled", default="eval/sessions.unlabeled.jsonl")
    ap.add_argument("--baseline", default="eval/baseline-assignment.json")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--tolerance", type=float, default=0.05)
    ap.add_argument("--k-folds", type=int, default=_DEFAULT_K,
                    help="repeated stratified k-fold: folds per repeat (CAP-8)")
    ap.add_argument("--repeats", type=int, default=_DEFAULT_REPEATS,
                    help="repeated stratified k-fold: number of repeats (CAP-8)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-json", action="store_true")
    args = ap.parse_args()

    labels, embs = load_labeled(Path(args.labels), Path(args.unlabeled))
    if not labels:
        print("No labelled sessions with embeddings found.", file=sys.stderr)
        return 1
    report = evaluate(labels, embs, k=args.k_folds, repeats=args.repeats, seed=args.seed)

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
