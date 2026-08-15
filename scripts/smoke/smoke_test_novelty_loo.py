"""Smoke test for leave-one-out novelty negatives (CAP-7 / A1).

`scripts/eval_operational.py::novelty_records`'s negative pass used to score
every session against a prototype that included itself, inflating its nearest
cosine by a 1/label_size self-contribution and suppressing false alarms —
worst on exactly the small labels where false-familiars actually occur. CAP-7
fixes this: the negative pass now uses each session's own-label prototype
recomputed leave-one-out (mean of that label's *other* members).

Covers, all with synthetic 2D unit-vector embeddings (no ES/LLM/network):
  * A size-2 label's LOO prototype for one member is exactly the other member
    (the only "other" there is).
  * `novel_precision` on the same synthetic set is LOWER (or equal) under LOO
    than under the naive self-inclusive prototype — the bias is one-sided
    (removing self can only lower or hold precision, never raise it).
  * A size-1 label is excluded from the negative base entirely (no LOO
    prototype exists), rather than forced into a synthetic self-comparison.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_novelty_loo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import eval_operational as eo

from enrich.sources.cowrie.assignment import NOVEL, assign_batch

TAU, CONFIDENT_TAU = 0.94, 0.98


def _unit(deg: float) -> np.ndarray:
    r = np.deg2rad(deg)
    return np.array([np.cos(r), np.sin(r)], dtype=np.float32)


def test_size2_label_loo_prototype_is_the_other_member() -> None:
    v1, v2 = _unit(0), _unit(30)
    embs = np.stack([v1, v2])
    lb_sum = embs.sum(axis=0)
    loo_for_v1 = eo._normalize_vec((lb_sum - embs[0]) / 1)
    assert np.allclose(loo_for_v1, v2 / np.linalg.norm(v2), atol=1e-6), loo_for_v1
    print("  ok: size-2 label LOO prototype for one member is exactly the other")


def _synthetic_set() -> tuple[list[str], np.ndarray]:
    """3 size-2 labels (A/B/C, 30 deg internal spread, >=90 deg apart from each
    other) whose bisector reads ASSIGNED under the naive self-inclusive
    prototype but NOVEL under LOO (the other member alone) — plus a size-4
    label D, tightly clustered (<=4 deg spread) so its own negatives are
    unaffected by LOO either way, far enough from A/B/C (30-60+ deg) that its
    leave-one-label-out positives correctly read novel."""
    labels: list[str] = []
    vecs: list[np.ndarray] = []
    for lb, angles in (("A", (0, 30)), ("B", (120, 150)), ("C", (240, 270))):
        for a in angles:
            labels.append(lb)
            vecs.append(_unit(a))
    for a in (58, 59, 61, 62):
        labels.append("D")
        vecs.append(_unit(a))
    return labels, np.stack(vecs)


def test_loo_novel_precision_le_naive() -> None:
    labels, embs = _synthetic_set()
    records_loo = eo.novelty_records(labels, embs, tau=TAU, confident_tau=CONFIDENT_TAU)
    positives = [r for r in records_loo if r[0] is True]
    assert len(positives) == 4, positives  # only D (size 4) qualifies (min_label_size=4)
    assert all(pred is True for _, pred in positives), positives  # D correctly reads novel

    all_ids, all_mat = eo.build_prototypes(embs, labels)
    naive_neg = assign_batch(embs, all_mat, all_ids, tau=TAU, confident_tau=CONFIDENT_TAU)
    naive_records = [(False, a.status == NOVEL) for a in naive_neg] + positives

    loo_pr = eo._pr_from_records(records_loo)
    naive_pr = eo._pr_from_records(naive_records)
    assert naive_pr["novel_precision"] == 1.0, naive_pr  # A/B/C bisectors all read ASSIGNED
    assert loo_pr["novel_precision"] == 0.4, loo_pr        # A/B/C LOO-others all read NOVEL
    assert loo_pr["novel_precision"] <= naive_pr["novel_precision"], (loo_pr, naive_pr)
    print("  ok: LOO novel_precision (0.4) <= naive novel_precision (1.0) on the same data")


def test_size1_label_excluded_from_negative_base() -> None:
    labels, embs = _synthetic_set()
    labels = [*labels, "solo"]
    embs = np.vstack([embs, _unit(200)])
    records = eo.novelty_records(labels, embs, tau=TAU, confident_tau=CONFIDENT_TAU)
    negatives = [r for r in records if r[0] is False]
    # Every size>=2 label contributes one negative per member: A(2)+B(2)+C(2)+D(4)
    # = 10. "solo" (size 1) has no LOO prototype, so it contributes zero.
    assert len(negatives) == 10, negatives
    print("  ok: size-1 label contributes zero negatives (no LOO prototype)")


def main() -> int:
    print("smoke_test_novelty_loo:")
    test_size2_label_loo_prototype_is_the_other_member()
    test_loo_novel_precision_le_naive()
    test_size1_label_excluded_from_negative_base()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
