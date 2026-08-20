"""Smoke test: how `scripts/eval_operational.py::gate` treats low-support labels.

Only n<2 is exempt, from the per-label HARD FLOOR: a singleton scores 0.0 by
construction, so failing it would be a false alarm. Everything at n>=2 is gated
normally AND stays in the macro-F1 mean — `MIN_MACRO_SUPPORT` is 2, and the test
below pins that, because raising it was proposed once and reverted (see the
constant's own comment and `docs/decisions.md`).

A size-1 label can never train a k-fold prototype (every fold it's in is a
test fold — CAP-8's own rotation guarantees that), so it always scores 0.0.
That's structural, not a regression, so it must not fail the gate — but it
still needs to be visible in the output, not silently dropped. Mirrors the
same n<2 threshold CAP-7 already uses for leave-one-out novelty negatives
(`novelty_records`, `scripts/eval_operational.py:75`).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_operational_singleton_floor.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

import eval_operational as eo


def test_singleton_excluded_from_hard_floor() -> None:
    report = {
        "metrics": {},
        "per_label_accuracy": {"real_label": 1.0, "singleton": 0.0},
        "label_counts": {"real_label": 5, "singleton": 1},
    }
    baseline = {"metrics": {}, "per_label_floor": 0.3}
    lines, ok = eo.gate(report, baseline)
    assert ok is True, "a size-1 label's 0.0 must not fail the gate"
    singleton_line = next(line for line in lines if "singleton" in line)
    assert "info" in singleton_line and "n=1" in singleton_line, singleton_line
    print("  ok: singleton (n=1) label excluded from the hard floor, reported as info")


def test_non_singleton_below_floor_still_fails() -> None:
    report = {
        "metrics": {},
        "per_label_accuracy": {"real_label": 1.0, "collapsed": 0.1},
        "label_counts": {"real_label": 5, "collapsed": 4},
    }
    baseline = {"metrics": {}, "per_label_floor": 0.3}
    lines, ok = eo.gate(report, baseline)
    assert ok is False, "a genuine (n>=2) collapse below the floor must still fail"
    collapsed_line = next(line for line in lines if "collapsed" in line)
    assert "FAIL" in collapsed_line, collapsed_line
    print("  ok: a non-singleton label below the floor still fails the gate")


def test_missing_label_count_defaults_to_gated() -> None:
    # No `label_counts` entry for a label -> not excluded (fails closed, not open).
    report = {
        "metrics": {},
        "per_label_accuracy": {"unknown_count": 0.0},
        "label_counts": {},
    }
    baseline = {"metrics": {}, "per_label_floor": 0.3}
    _lines, ok = eo.gate(report, baseline)
    assert ok is False, "an unknown label count must not be silently excluded"
    print("  ok: missing label_counts entry fails closed (still gated)")


def test_rare_labels_stay_in_the_macro_mean() -> None:
    """`MIN_MACRO_SUPPORT` is 2: only singletons leave the mean.

    Pins a decision, not an implementation detail. Raising this to 5 was built and
    reverted — rare labels are stabilisers, and pruning them WIDENS the macro-F1 CI
    (0.1594 at n>=2 -> 0.1661 at n>=5) rather than tightening it. See
    `docs/decisions.md`, "Macro-F1 excludes labels a held-out split cannot learn".
    """
    from eval_assignment import MIN_MACRO_SUPPORT

    assert MIN_MACRO_SUPPORT == 2, (
        "raising MIN_MACRO_SUPPORT prunes rare labels from the macro mean, which "
        "docs/decisions.md declines on measured evidence — change the decision first"
    )

    report = {
        "metrics": {},
        "per_label_accuracy": {"real_label": 1.0, "rare": 1.0},
        "label_counts": {"real_label": 50, "rare": 3},
    }
    baseline = {"metrics": {}, "per_label_floor": 0.3}
    lines, ok = eo.gate(report, baseline)
    assert ok is True
    rare_line = next(line for line in lines if "rare" in line)
    assert "info" not in rare_line, rare_line
    assert "excluded" not in rare_line, rare_line
    print("  ok: an n=3 label is gated normally and stays in the macro mean")

    report["per_label_accuracy"]["rare"] = 0.0
    _lines, ok = eo.gate(report, baseline)
    assert ok is False, "a rare label collapsing below the floor must still fail"
    print("  ok: a rare label below the floor still fails the gate")


def main() -> int:
    print("smoke_test_operational_singleton_floor:")
    test_singleton_excluded_from_hard_floor()
    test_rare_labels_stay_in_the_macro_mean()
    test_non_singleton_below_floor_still_fails()
    test_missing_label_count_defaults_to_gated()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
