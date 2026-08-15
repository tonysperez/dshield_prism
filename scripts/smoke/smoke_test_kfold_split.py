"""Smoke test for repeated stratified k-fold (CAP-8 / A2).

The single alternating 50/50 split (`eval_assignment.stratified_split`,
retired) had three coupled defects: singleton labels went train-only and
vanished from macro-F1 and the per-label floor; size-2 labels trained a
1-example prototype tested on 1 example; and its bootstrap resampled one
fixed test half with prototypes frozen, so the reported CI captured only
test-resampling noise, not split variance. `repeated_stratified_kfold` +
`fold_ci_half_width` (`scripts/eval_assignment.py`) replace it.

Covers, all with synthetic embeddings (no ES/LLM/network):
  * A singleton label lands in a test fold at least once.
  * Determinism: same seed -> bit-identical folds across two calls.
  * CI half-width: on a fixture engineered so fold difficulty varies (some
    folds' small training prototypes misclassify boundary members, others
    don't), the across-fold spread is strictly wider than the retired
    split's single-fixed-test-half bootstrap on the same data — the
    "variance-justified tolerance" claim now actually captures split
    variance instead of just resampling noise.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_kfold_split.py
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import eval_operational as eo
from eval_assignment import (
    build_prototypes,
    classification_metrics,
    fold_ci_half_width,
    repeated_stratified_kfold,
)

from enrich.sources.cowrie.assignment import assign_batch


def _unit(v) -> np.ndarray:
    a = np.array(v, dtype=np.float32)
    return a / np.linalg.norm(a)


def _make_label(rng: np.random.Generator, center_deg: float, n: int, spread_deg: float) -> list[np.ndarray]:
    out = []
    for _ in range(n):
        d = center_deg + rng.uniform(-spread_deg, spread_deg)
        r = np.deg2rad(d)
        out.append(np.array([np.cos(r), np.sin(r)], dtype=np.float32))
    return out


def test_singleton_reaches_a_test_fold() -> None:
    labels = ["A"] * 4 + ["B"] * 3 + ["C"] * 1  # C is a singleton
    c_idx = labels.index("C")
    folds = repeated_stratified_kfold(labels, k=3, repeats=4, seed=0)
    assert any(c_idx in test for _, test in folds), folds
    print("  ok: singleton label lands in a test fold at least once")


def test_deterministic_under_fixed_seed() -> None:
    labels = ["A"] * 5 + ["B"] * 5 + ["C"] * 2
    folds_a = repeated_stratified_kfold(labels, k=3, repeats=3, seed=7)
    folds_b = repeated_stratified_kfold(labels, k=3, repeats=3, seed=7)
    assert folds_a == folds_b, (folds_a, folds_b)
    print("  ok: same seed -> bit-identical folds")


def _old_stratified_split(labels: list[str]) -> tuple[list[int], list[int]]:
    """The retired single alternating 50/50 split, reimplemented here only as
    a reference oracle for the CI-half-width regression check below."""
    by = defaultdict(list)
    for i, lb in enumerate(labels):
        by[lb].append(i)
    train, test = [], []
    for lb in sorted(by):
        for k, i in enumerate(by[lb]):
            (train if k % 2 == 0 else test).append(i)
    return sorted(train), sorted(test)


def _kfold_fixture() -> tuple[list[str], np.ndarray]:
    """3 labels with enough internal angular spread that different fold
    compositions land different prototypes — some folds' small training
    subsets misclassify boundary members, others don't. Engineered (seed=2)
    so the retired split's bootstrap reads a perfectly-classified fixed test
    half (CI half-width 0.0) while genuinely different folds do not."""
    rng = np.random.default_rng(2)
    labels: list[str] = []
    vecs: list[np.ndarray] = []
    for lb, center, n, spread in (("A", 0, 10, 40), ("B", 45, 10, 25), ("C", 200, 8, 15)):
        for v in _make_label(rng, center, n, spread):
            labels.append(lb)
            vecs.append(v)
    return labels, np.stack(vecs)


def test_ci_half_width_ge_old_single_split() -> None:
    labels, embs = _kfold_fixture()

    train, test = _old_stratified_split(labels)
    proto_ids, proto_mat = build_prototypes(embs[train], [labels[i] for i in train])
    test_embs, test_truth = embs[test], [labels[i] for i in test]
    test_pred = [r.playbook_id for r in
                 assign_batch(test_embs, proto_mat, proto_ids, tau=0.0, confident_tau=0.0)]
    paired = list(zip(test_pred, test_truth, strict=False))
    old_hw = eo.bootstrap_half_width(
        paired, lambda s: eo._macro_f1_from([p for p, _ in s], [t for _, t in s]),
        n=1000, seed=0)

    folds = repeated_stratified_kfold(labels, k=3, repeats=5, seed=0)
    fold_f1 = []
    for tr, te in folds:
        pids, pmat = build_prototypes(embs[tr], [labels[i] for i in tr])
        cls = classification_metrics(embs[te], [labels[i] for i in te], pids, pmat)
        fold_f1.append(cls["macro_f1"])
    new_hw = fold_ci_half_width(fold_f1)

    assert old_hw == 0.0, old_hw  # fixed test half happens to classify perfectly every resample
    assert new_hw > old_hw, (new_hw, old_hw, fold_f1)
    print(f"  ok: k-fold CI half-width ({new_hw}) > retired single-split bootstrap ({old_hw})")


def main() -> int:
    print("smoke_test_kfold_split:")
    test_singleton_reaches_a_test_fold()
    test_deterministic_under_fixed_seed()
    test_ci_half_width_ge_old_single_split()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
