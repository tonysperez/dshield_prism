"""Operational quality gate — the post-partition CI gate (quality-metrics Slice A).

Grades the operator jobs on the committed eval geometry (`eval/labels.yaml` +
`eval/sessions.unlabeled.jsonl.gz`), offline and deterministic — no live ES:

  * **assign**       — macro-F1 + per-label accuracy (nearest-prototype).
  * **mint-novel**   — novel precision/recall + false-familiar via a whole-label
                       (leave-one-label-out) holdout scored through
                       `assign_batch` at the shipped tau; minted-playbook purity
                       + genuinely-distinct count by clustering the novel pool.

Every gated threshold is variance-justified — a bootstrap-CI half-width for
metrics with real n (macro-F1, minted purity/distinct), or a hard absolute floor
for per-label accuracy (a collapse detector; n is too small there for a CI). No
flat uniform absolute drop — that was the old gate's hole.

Novelty is gated **only if the generated baseline shows it non-degenerate** at
tau in this (label-mean) geometry — label-mean prototypes run hotter than
production's fine anchors, so tau=0.94 can pin novel-recall at ~0, and a metric
that cannot move is not a gate. Otherwise novelty (and false-familiar, which is
1 - novel recall) print as diagnostics; honest novelty gating lands with the real
anchors in Slice E. See docs/decisions.md.

Gate direction per metric: floors fail when current < baseline - tolerance;
the `diagnostic` basis never fails a build.

**Two strata.** `eval/labels.yaml` mixes the original variety-first draw with rows added
by a targeted pass (`scripts/select_eval_candidates.py`), marked by `selection_channel`.
Label-weighted metrics (macro-F1, per-label accuracy) run on everything; session-weighted
ones (novel precision/recall, false-familiar, minted purity/distinct) scope to the
variety-first rows, or they would report the deliberate over-sampling of a rare label as
a system change. `report["scope"]` records which rows each family saw. See
`variety_first_mask`.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from eval_assignment import (
    MIN_MACRO_SUPPORT,
    build_prototypes,
    classification_metrics,
    fold_ci_half_width,
    load_labeled,
    repeated_stratified_kfold,
)

from enrich.clustering import cluster_deps_available, l2_normalize
from enrich.sources.cowrie.assignment import NOVEL, assign_batch


def variety_first_mask(channels: list[str | None]) -> list[int]:
    """Row indices belonging to the ORIGINAL variety-first draw — the rows whose
    `selection_channel` is absent.

    Pure. `eval/labels.yaml` grew by a targeted pass (`select_eval_candidates.py`) that
    draws rare-label candidates deliberately, so the set is now two strata. Which
    metrics that breaks depends on how each is weighted:

      * `macro_f1` and per-label accuracy weight LABELS, not sessions. Adding examples
        of a thin label changes which sessions represent it, not the label's weight, so
        both run on the full set.
      * `novel_precision`, `novel_recall` and `minted_purity` are SESSION-weighted, so
        they read the label mix directly. Over a set where `scp_upload` was deliberately
        made ten times more prevalent than the corpus, they measure the draw. Worse,
        they would move the first time an analyst finishes labelling and be read as a
        system change — the exact fixture-shift misreading this project has hit before.

    So the session-weighted metrics scope here and stay comparable to every baseline
    committed before the growth pass. An all-targeted set (no original rows) returns
    every index rather than an empty scope: a caller with nothing else to fall back on
    should get an honest wide number, not a division by zero.
    """
    original = [i for i, c in enumerate(channels) if not c]
    return original or list(range(len(channels)))


# Degeneracy floor: if measured novel-recall is at/below this at write-baseline
# time, novelty is marked diagnostic rather than gated (geometry pinned it).
_DEGENERATE_RECALL = 0.05
# Minimum novel-pool size worth clustering for minted purity.
_MINTED_MIN_POOL = 10
_MINT_MIN_CLUSTER_SIZE = 5
_MINT_MIN_SAMPLES = 2


# ---------------------------------------------------------------------------
# Assignment block — macro-F1 + per-label accuracy
# ---------------------------------------------------------------------------
def _macro_f1_from(pred: list[str], truth: list[str]) -> float:
    per = []
    for lb in sorted(set(truth)):
        tp = sum(1 for p, t in zip(pred, truth, strict=False) if p == lb and t == lb)
        fp = sum(1 for p, t in zip(pred, truth, strict=False) if p == lb and t != lb)
        fn = sum(1 for p, t in zip(pred, truth, strict=False) if p != lb and t == lb)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        per.append(2 * prec * rec / (prec + rec) if (prec + rec) else 0.0)
    return float(np.mean(per)) if per else 0.0


# ---------------------------------------------------------------------------
# Novelty block — leave-one-label-out holdout scored at the shipped tau
# ---------------------------------------------------------------------------
def _normalize_vec(v: np.ndarray) -> np.ndarray:
    n = np.linalg.norm(v)
    return v if n == 0.0 else v / n


def novelty_records(labels: list[str], embs: np.ndarray, *, tau: float,
                    confident_tau: float, min_label_size: int = 4) -> list[tuple[bool, bool]]:
    """One (truth_novel, pred_novel) record per session, each session counted once
    per role — so precision's base rate is honest and the records are independent
    for the bootstrap:

      * negatives (should-read-familiar): every session assigned against a
        prototype set where its OWN label's prototype is leave-one-out — the
        mean of that label's *other* members, excluding itself (CAP-7 / A1).
        Without this, every session sits inside its own label-mean and its
        nearest cosine is inflated by a 1/label_size self-contribution,
        suppressing false alarms. Other-label prototypes are untouched (they
        were already leakage-free). A size-1 label has no LOO prototype — that
        session is excluded from the negative base rather than forced into a
        synthetic self-comparison. A novel flag here is a false alarm (FP).
      * positives (should-read-novel): leave-one-label-out — each eligible
        label's sessions assigned against the prototypes with THAT label
        withheld, so the behavior genuinely has no home. Already leakage-free
        (unchanged by CAP-7). A novel flag is a true positive.
    """
    by = defaultdict(list)
    for i, lb in enumerate(labels):
        by[lb].append(i)
    records: list[tuple[bool, bool]] = []
    # negatives: leave-one-out own-label prototype, other labels unchanged.
    all_ids, all_mat = build_prototypes(embs, labels)
    label_row = {lb: idx for idx, lb in enumerate(all_ids)}
    for lb, idxs in by.items():
        n = len(idxs)
        if n < 2:
            continue  # size-1 label: no LOO prototype exists, excluded
        lb_sum = embs[idxs].sum(axis=0)
        for i in idxs:
            loo_proto = all_mat.copy()
            loo_proto[label_row[lb]] = _normalize_vec((lb_sum - embs[i]) / (n - 1))
            res = assign_batch(embs[i:i + 1], loo_proto, all_ids,
                               tau=tau, confident_tau=confident_tau)
            records.append((False, res[0].status == NOVEL))
    # positives: leave-one-label-out.
    for held in sorted(by):
        if len(by[held]) < min_label_size:
            continue
        keep_mask = np.array([labels[i] != held for i in range(len(labels))])
        keep_labels = [labels[i] for i in range(len(labels)) if keep_mask[i]]
        proto_ids, proto_mat = build_prototypes(embs[keep_mask], keep_labels)
        pos = assign_batch(embs[by[held]], proto_mat, proto_ids,
                           tau=tau, confident_tau=confident_tau)
        records.extend((True, a.status == NOVEL) for a in pos)
    return records


def _pr_from_records(records: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for truth, pred in records if truth and pred)
    fp = sum(1 for truth, pred in records if not truth and pred)
    fn = sum(1 for truth, pred in records if truth and not pred)
    precision = round(tp / (tp + fp), 4) if (tp + fp) else None
    recall = round(tp / (tp + fn), 4) if (tp + fn) else None
    false_familiar = round(fn / (tp + fn), 4) if (tp + fn) else None  # = 1 - recall
    return {"novel_precision": precision, "novel_recall": recall,
            "false_familiar": false_familiar, "n_flagged_novel": tp + fp}


# ---------------------------------------------------------------------------
# Minted-playbook block — cluster the novel pool, purity vs true labels
# ---------------------------------------------------------------------------
def purity_of(records: list[tuple[str, str]]) -> float | None:
    """Session-weighted modal-label purity: fraction of members whose true label
    equals their cluster's modal label. `records` is (member_true_label, modal)."""
    if not records:
        return None
    return round(sum(1 for t, m in records if t == m) / len(records), 4)


def minted_block(labels: list[str], embs: np.ndarray, *, holdout_k: int) -> dict:
    """Withhold the `holdout_k` rarest labels together, cluster their pooled
    sessions, and measure purity (session-weighted modal-true-label share over
    non-noise clusters) + the count of distinct modal true-labels the minted
    clusters cover. The rarest labels are picked with a stable `(count, label)`
    key so the pool is independent of the input JSONL order."""
    if not cluster_deps_available():
        return {"minted_purity": None, "minted_distinct": None, "records": [], "skip": "no cluster deps"}
    from sklearn.cluster import HDBSCAN

    sizes = Counter(labels)
    rarest = [lb for lb, _ in sorted(sizes.items(), key=lambda kv: (kv[1], kv[0]))[:holdout_k]]
    pool_idx = [i for i, lb in enumerate(labels) if lb in rarest]
    if len(pool_idx) < _MINTED_MIN_POOL:
        return {"minted_purity": None, "minted_distinct": None, "records": [], "skip": "pool too small"}
    pool_embs = l2_normalize(embs[pool_idx])
    pool_labels = [labels[i] for i in pool_idx]
    pred = HDBSCAN(min_cluster_size=_MINT_MIN_CLUSTER_SIZE, min_samples=_MINT_MIN_SAMPLES,
                   metric="euclidean", copy=True).fit_predict(pool_embs)
    # per non-noise cluster: modal true label + member records for purity
    modal_labels: dict[int, str] = {}
    records: list[tuple[str, str]] = []  # (member_true_label, cluster_modal_label)
    for c in sorted({int(x) for x in pred} - {-1}):
        members = [pool_labels[i] for i in range(len(pred)) if pred[i] == c]
        modal = Counter(members).most_common(1)[0][0]
        modal_labels[c] = modal
        records.extend((m, modal) for m in members)
    distinct = len(set(modal_labels.values()))
    return {"minted_purity": purity_of(records),
            "minted_distinct": distinct if records else None, "records": records}


# ---------------------------------------------------------------------------
# Bootstrap CI (deterministic)
# ---------------------------------------------------------------------------
def bootstrap_half_width(values: list[float], stat, *, n: int, seed: int = 0) -> float:
    """Half-width of the 95% percentile CI of `stat` over resamples of `values`.
    Deterministic (seeded). `values` is the per-unit record list; `stat` maps a
    resampled list → a scalar (or None, skipped)."""
    if not values:
        return 0.0
    rng = np.random.default_rng(seed)
    # 1-D object array so each element stays the original record (a plain
    # np.array(list_of_tuples) would build a 2-D (n,2) array and reshape records).
    arr = np.empty(len(values), dtype=object)
    for i, v in enumerate(values):
        arr[i] = v
    dist = []
    for _ in range(n):
        pick = rng.integers(0, len(arr), size=len(arr))
        s = stat([arr[j] for j in pick])
        if s is not None:
            dist.append(s)
    if not dist:
        return 0.0
    lo, hi = np.percentile(dist, [2.5, 97.5])
    return round(float(hi - lo) / 2.0, 4)


# ---------------------------------------------------------------------------
# Evaluate
# ---------------------------------------------------------------------------
def evaluate(labels: list[str], embs: np.ndarray, *, tau: float, confident_tau: float,
             holdout_k: int, bootstrap: int, per_label_floor: float,
             k_folds: int = 5, repeats: int = 3, seed: int = 0,
             channels: list[str | None] | None = None) -> dict:
    # Repeated stratified k-fold (CAP-8 / A2), replacing the single alternating
    # 50/50 split: every label with >=1 member reaches a test fold, and the CI
    # is the across-fold spread (captures split variance, not just
    # test-resampling noise). Point estimate = mean over folds.
    # Low-support labels leave the macro mean but stay fully reported — see
    # `eval_assignment.MIN_MACRO_SUPPORT` for what measurement drove the threshold.
    label_counts = Counter(labels)
    scoreable = {lb for lb, n in label_counts.items() if n >= MIN_MACRO_SUPPORT}
    folds = repeated_stratified_kfold(labels, k=k_folds, repeats=repeats, seed=seed)
    fold_f1: list[float] = []
    per_label_recall: dict[str, list[float]] = defaultdict(list)
    n_test_total = 0
    for train, test in folds:
        proto_ids, proto_mat = build_prototypes(embs[train], [labels[i] for i in train])
        test_embs, test_truth = embs[test], [labels[i] for i in test]
        cls = classification_metrics(test_embs, test_truth, proto_ids, proto_mat,
                                     scoreable=scoreable)
        fold_f1.append(cls["macro_f1"])
        n_test_total += cls["n_test"]
        for lb, m in cls["per_label"].items():
            per_label_recall[lb].append(m["recall"])
    macro_f1 = round(float(np.mean(fold_f1)), 4) if fold_f1 else 0.0
    per_label_acc = {lb: round(float(np.mean(v)), 4) for lb, v in per_label_recall.items()}
    f1_hw = fold_ci_half_width(fold_f1)

    # Session-weighted metrics run on the variety-first stratum only; the
    # label-weighted ones above already ran on everything. See `variety_first_mask`.
    chans = channels if channels is not None else [None] * len(labels)
    scope = variety_first_mask(chans)
    scoped_labels = [labels[i] for i in scope]
    scoped_embs = embs[scope] if len(embs) else embs
    nov_records = novelty_records(scoped_labels, scoped_embs,
                                  tau=tau, confident_tau=confident_tau)
    nov = _pr_from_records(nov_records)
    mint = minted_block(scoped_labels, scoped_embs, holdout_k=holdout_k)

    # Novelty/minted CIs are unrelated to CAP-8 (not split-derived) — unchanged
    # deterministic bootstrap over their own record lists.
    rec_hw = bootstrap_half_width(nov_records, lambda s: _pr_from_records(s)["novel_recall"], n=bootstrap)
    prec_hw = bootstrap_half_width(nov_records, lambda s: _pr_from_records(s)["novel_precision"], n=bootstrap)
    pur_hw = bootstrap_half_width(mint["records"], purity_of, n=bootstrap)

    return {
        "n_labeled": len(labels), "n_labels": len(set(labels)),
        "n_test": n_test_total, "n_folds": k_folds, "n_repeats": repeats,
        "n_folds_run": len(folds),
        # Which rows each metric family saw, so a number is never read against the
        # wrong denominator.
        "macro_f1_support": {
            "min_support": MIN_MACRO_SUPPORT,
            "in_mean": sorted(scoreable),
            "excluded": {lb: label_counts[lb] for lb in sorted(set(label_counts) - scoreable)},
        },
        "scope": {
            "label_weighted_n": len(labels),
            "session_weighted_n": len(scope),
            "selection_channels": dict(Counter(c or "variety-first" for c in chans)),
            "session_weighted_metrics": [
                "novel_precision", "novel_recall", "false_familiar", "minted_purity",
                "minted_distinct",
            ],
        },
        "tau": tau, "confident_tau": confident_tau, "holdout_k": holdout_k,
        "metrics": {
            "macro_f1": macro_f1,
            "novel_precision": nov["novel_precision"],
            "novel_recall": nov["novel_recall"],
            "false_familiar": nov["false_familiar"],
            "minted_purity": mint["minted_purity"],
            "minted_distinct": mint["minted_distinct"],
        },
        "ci_half_width": {"macro_f1": f1_hw, "novel_recall": rec_hw,
                          "novel_precision": prec_hw, "minted_purity": pur_hw},
        "per_label_accuracy": per_label_acc,
        "per_label_floor": per_label_floor,
        "label_counts": dict(Counter(labels)),
        "novelty_degenerate": (nov["novel_recall"] is None or nov["novel_recall"] <= _DEGENERATE_RECALL),
        "n_flagged_novel": nov["n_flagged_novel"],
        "minted_skip": mint.get("skip"),
    }


# ---------------------------------------------------------------------------
# Baseline + gate
# ---------------------------------------------------------------------------
def build_baseline(report: dict, *, epsilon: float) -> dict:
    """Per-metric {baseline, tolerance, direction, basis}. macro-F1 / minted purity /
    novelty → CI floor (novelty unless degenerate); per-label → hard floor; minted-
    distinct + false-familiar → diagnostic."""
    hw = report["ci_half_width"]
    m = report["metrics"]
    degen = report["novelty_degenerate"]

    def ci(name):
        return {"baseline": m[name], "tolerance": max(hw.get(name, 0.0), epsilon),
                "direction": "floor", "basis": "ci"}

    metrics = {
        "macro_f1": ci("macro_f1"),
        "minted_purity": (ci("minted_purity") if m["minted_purity"] is not None
                          else {"baseline": None, "direction": "floor", "basis": "diagnostic"}),
        # minted_distinct is an integer HDBSCAN cluster count over a small pool —
        # a tol-0 floor would flake red on cross-BLAS MST tie-breaks, so it is
        # reported, not gated. minted_purity (a ratio) carries the mint signal.
        "minted_distinct": {"baseline": m["minted_distinct"], "direction": "floor",
                            "basis": "diagnostic"},
        "novel_precision": ({"baseline": None, "direction": "floor", "basis": "diagnostic"}
                            if degen else ci("novel_precision")),
        "novel_recall": ({"baseline": None, "direction": "floor", "basis": "diagnostic"}
                         if degen else ci("novel_recall")),
        "false_familiar": {"baseline": m["false_familiar"], "direction": "ceiling",
                           "basis": "diagnostic"},
    }
    note = ("Per-metric thresholds: macro-F1 / minted purity / novelty use a bootstrap-CI "
            "floor (baseline - half-width); per-label accuracy uses a hard absolute floor "
            "(collapse detector), except singleton labels (n<2), which are reported but "
            "excluded from the floor — no k-fold prototype is possible for them, so a "
            "0.0 there is structural, not a regression; minted-distinct + false-familiar "
            "are diagnostics; novelty is "
            + ("DIAGNOSTIC (label-mean geometry pinned novel-recall <= "
               f"{_DEGENERATE_RECALL} at tau — honest gating deferred to Slice E's "
               "real anchors)" if degen else "a CI floor (non-degenerate at tau)")
            + "; false-familiar (= 1 - novel recall) is always reported, never gated.")
    return {
        "metrics": metrics,
        "per_label_floor": report["per_label_floor"],
        "tau": report["tau"], "confident_tau": report["confident_tau"],
        "holdout_k": report["holdout_k"],
        "captured_from": "eval_operational.py --write-baseline",
        "tolerance_semantic": note,
    }


def gate(report: dict, baseline: dict) -> tuple[list[str], bool]:
    lines, ok = [], True
    lines.append(f"  {'metric':18}{'basis':>11}{'baseline':>10}{'current':>10}{'tol':>8}  status")
    for name, spec in baseline["metrics"].items():
        cur = report["metrics"].get(name)
        basis = spec.get("basis", "ci")
        bl = spec.get("baseline")
        if basis == "diagnostic" or bl is None:
            lines.append(f"  {name:18}{'diagnostic':>11}{bl!s:>10}{cur!s:>10}      —  (info)")
            continue
        tol = spec.get("tolerance", 0)
        if cur is None:
            # A GATED metric that went None at runtime is a collapse (e.g. novelty
            # stopped producing any signal) — fail, never silently skip.
            ok = False
            lines.append(f"  {name:18}{basis:>11}{bl!s:>10}{'None':>10}      —  FAIL")
            continue
        passed = cur <= bl + tol if spec["direction"] == "ceiling" else cur >= bl - tol
        ok = ok and passed
        lines.append(f"  {name:18}{basis:>11}{bl:>10.4f}{cur:>10.4f}{tol:>8.3f}  "
                     f"{'PASS' if passed else 'FAIL'}")
    # per-label accuracy: hard absolute floor — catches a single label collapsing.
    # Singleton labels (n<2, matching CAP-7's LOO threshold — a size-1 label has
    # no held-out prototype either) can never train a k-fold prototype, so they
    # score 0.0 by construction, not by regression. Reported for visibility but
    # excluded from the hard floor — the label stays in the eval set (real,
    # rare behavior is exactly the signal novelty detection cares about), it's
    # just not held to a floor that no amount of prototype quality could clear.
    floor = baseline["per_label_floor"]
    counts = report.get("label_counts", {})
    worst = None
    for lb, acc in sorted(report["per_label_accuracy"].items()):
        n = counts.get(lb)
        if n is not None and n < 2:
            lines.append(f"  {('per_label:' + lb):18}{'floor':>11}{floor:>10.3f}{acc:>10.4f}"
                         f"{'':>8}  (info, n=1 — no k-fold prototype)")
            continue
        passed = acc >= floor
        ok = ok and passed
        if worst is None or acc < worst[1]:
            worst = (lb, acc)
        lines.append(f"  {('per_label:' + lb):18}{'floor':>11}{floor:>10.3f}{acc:>10.4f}"
                     f"{'':>8}  {'PASS' if passed else 'FAIL'}")
    return lines, ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", default="eval/labels.yaml")
    ap.add_argument("--unlabeled", default="eval/sessions.unlabeled.jsonl.gz")
    ap.add_argument("--baseline", default="eval/baseline-operational.json")
    ap.add_argument("--tau", type=float, default=0.94)
    ap.add_argument("--confident-tau", type=float, default=0.98)
    ap.add_argument("--holdout-k", type=int, default=2)
    ap.add_argument("--per-label-floor", type=float, default=0.3)
    ap.add_argument("--bootstrap", type=int, default=1000)
    ap.add_argument("--epsilon", type=float, default=0.02)
    ap.add_argument("--k-folds", type=int, default=5,
                    help="repeated stratified k-fold: folds per repeat (CAP-8)")
    ap.add_argument("--repeats", type=int, default=3,
                    help="repeated stratified k-fold: number of repeats (CAP-8)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--no-json", action="store_true")
    args = ap.parse_args()

    labels, embs, channels = load_labeled(
        Path(args.labels), Path(args.unlabeled), with_channels=True,
    )
    if not labels:
        print("No labelled sessions with embeddings found.", file=sys.stderr)
        return 1
    report = evaluate(labels, embs, tau=args.tau, confident_tau=args.confident_tau,
                      holdout_k=args.holdout_k, bootstrap=args.bootstrap,
                      per_label_floor=args.per_label_floor,
                      k_folds=args.k_folds, repeats=args.repeats, seed=args.seed,
                      channels=channels)

    if args.write_baseline:
        baseline = build_baseline(report, epsilon=args.epsilon)
        Path(args.baseline).write_text(json.dumps(baseline, indent=2) + "\n")
        print(f"wrote baseline {args.baseline}")
        print(f"  novelty: {'DIAGNOSTIC (degenerate)' if report['novelty_degenerate'] else 'GATED'} "
              f"(novel_recall={report['metrics']['novel_recall']}, "
              f"flagged_novel={report['n_flagged_novel']})")
        return 0

    if not args.no_json:
        print(json.dumps(report, indent=2))

    if not Path(args.baseline).exists():
        print(f"\nNo baseline at {args.baseline} — printing metrics only, no gate.")
        return 0
    baseline = json.loads(Path(args.baseline).read_text())
    lines, ok = gate(report, baseline)
    print()
    for ln in lines:
        print(ln)
    print(f"\nGATE: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
