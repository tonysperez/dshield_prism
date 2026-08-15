"""Smoke test for label-schema v2 — required-if-annotated provenance
(CAP-2) + optional rare-class boost.

Covers the four label-block fields (`annotator`, `labeled_at`,
`rubric_version`, `boost_weight`) added to `eval/labels.yaml`:
  * `annotator` / `labeled_at` / `rubric_version` are required-if-annotated
    (CAP-2): missing/null on an `annotated: true` block fails closed, one
    error per missing field, naming the field.
  * `annotated: false` blocks skip the whole schema, including provenance —
    not-yet-labeled skeletons stay valid.
  * A well-typed provenance block validates clean.
  * Every bad value errors: `boost_weight` of 0 / negative / inf / nan /
    True / non-number; `labeled_at` that isn't a real ISO date; empty or
    non-string `annotator` / `rubric_version`.
  * The renderer's `_EMPTY_LABEL_BLOCK` skeleton carries the four keys at
    their defaults, so the merge's skeleton-key projection round-trips
    them onto existing blocks instead of stripping them.

Standalone — no ES, no LLM, no network.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_eval_label_schema.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# scripts/ on the path so the top-level render/validate modules import.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import render_eval_set as render
import validate_eval_labels as val


def _errors_for(block: dict) -> list[str]:
    """Run one annotated block through _check_block, return its errors."""
    errors: list[str] = []
    val._check_block("sid", block, errors)
    return errors


def _base_block(**overrides) -> dict:
    """A minimal valid annotated is_real=true block, plus overrides."""
    block = {
        "annotated":         True,
        "is_real":           True,
        "playbook_label":    "ssh_key_chattr_persistence",
        "expected_findings": [],
        "notes":             "ok",
    }
    block.update(overrides)
    return block


def test_annotated_block_missing_provenance_fails() -> None:
    # CAP-2: an annotated block with none of the three required provenance
    # fields fails closed, one error per missing field, naming it.
    errors = _errors_for(_base_block())
    for f in ("annotator", "labeled_at", "rubric_version"):
        assert any(f in e for e in errors), (f, errors)
    print("  ok: annotated block missing provenance fails, one error per field")


def test_not_annotated_block_skips_provenance() -> None:
    errors = _errors_for(_base_block(annotated=False, is_real=False))
    assert errors == [], errors
    print("  ok: annotated:false block skips provenance entirely")


def test_well_typed_provenance_passes() -> None:
    errors = _errors_for(_base_block(
        annotator="ts",
        labeled_at="2026-07-03",
        rubric_version="v1",
        boost_weight=2.0,
    ))
    assert errors == [], errors
    print("  ok: well-typed provenance validates clean")


def test_null_provenance_fails() -> None:
    # Explicit nulls (the skeleton defaults) are treated the same as absent —
    # still required-if-annotated. boost_weight alone stays optional.
    errors = _errors_for(_base_block(
        annotator=None, labeled_at=None, rubric_version=None, boost_weight=1.0,
    ))
    for f in ("annotator", "labeled_at", "rubric_version"):
        assert any(f in e for e in errors), (f, errors)
    print("  ok: explicit-null provenance fails same as absent")


def test_boost_weight_bad_values_error() -> None:
    for bad in (0, -1, -0.5, float("inf"), float("nan"), True, "heavy"):
        errors = _errors_for(_base_block(boost_weight=bad))
        assert any("boost_weight" in e for e in errors), (bad, errors)
    print("  ok: boost_weight rejects 0 / negative / inf / nan / bool / non-number")


def test_boost_weight_huge_int_ok_not_crash() -> None:
    # A 400-digit YAML int must not crash the validator (math.isfinite would
    # OverflowError on the float cast) — no upper bound, so it validates clean.
    # Valid provenance alongside it isolates this assertion to boost_weight.
    errors = _errors_for(_base_block(
        boost_weight=10 ** 400,
        annotator="ts", labeled_at="2026-07-03", rubric_version="v1",
    ))
    assert errors == [], errors
    print("  ok: boost_weight huge int validates without OverflowError")


def test_labeled_at_bad_dates_error() -> None:
    # Includes the ISO forms `date.fromisoformat` accepts but YYYY-MM-DD must
    # NOT: week date (2026-W27-3), compact (20260703), non-zero-padded
    # (2026-1-3); plus impossible dates, garbage, empty, and non-string.
    for bad in ("banana", "2026-13-40", "2026-02-30", "07/03/2026", "",
                "2026-W27-3", "20260703", "2026-1-3", "2026-07-03 ", 20260703):
        errors = _errors_for(_base_block(labeled_at=bad))
        assert any("labeled_at" in e for e in errors), (bad, errors)
    print("  ok: labeled_at rejects week/compact/unpadded/impossible/non-string")


def test_provenance_strings_bad_error() -> None:
    for field in ("annotator", "rubric_version"):
        for bad in ("", "   ", "\t\n", 123, []):
            errors = _errors_for(_base_block(**{field: bad}))
            assert any(field in e for e in errors), (field, bad, errors)
    print("  ok: annotator / rubric_version reject empty / whitespace / non-string")


def test_skeleton_carries_provenance_keys() -> None:
    skel = render._EMPTY_LABEL_BLOCK
    for k in ("annotator", "labeled_at", "rubric_version", "boost_weight"):
        assert k in skel, f"{k!r} missing from _EMPTY_LABEL_BLOCK — merge would strip it"
    assert skel["boost_weight"] == 1.0, skel["boost_weight"]
    assert skel["annotator"] is None
    assert skel["labeled_at"] is None
    assert skel["rubric_version"] is None
    # The v2 per-record skeleton copies the same defaults.
    per_rec = render._skeleton_for_record({"session_id": "x"})
    for k in ("annotator", "labeled_at", "rubric_version", "boost_weight"):
        assert k in per_rec, f"{k!r} missing from _skeleton_for_record"
    print("  ok: renderer skeleton round-trips the four provenance keys")


def main() -> int:
    print("smoke_test_eval_label_schema:")
    test_annotated_block_missing_provenance_fails()
    test_not_annotated_block_skips_provenance()
    test_well_typed_provenance_passes()
    test_null_provenance_fails()
    test_boost_weight_bad_values_error()
    test_boost_weight_huge_int_ok_not_crash()
    test_labeled_at_bad_dates_error()
    test_provenance_strings_bad_error()
    test_skeleton_carries_provenance_keys()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
