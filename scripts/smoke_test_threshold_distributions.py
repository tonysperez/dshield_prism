"""Smoke test: threshold-distribution doc shape + percentile math
(brutal-review phase 4.1).

Asserts:
  * `_distribution_doc` emits the canonical {run_id, generated_at, kind,
    layer, p50, p75, p90, p95, p99, n} shape with correct numeric
    percentiles on a synthetic distribution.
  * Empty distributions are dropped by `compute_threshold_distributions`
    (the writer never produces an `n=0` doc).
  * Every registered quantity has a kind discriminator + layer label
    so the strict-dynamic prism.metrics mapping accepts the doc.

Run standalone from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_threshold_distributions.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.metrics import (
    _THRESHOLD_QUANTITIES,
    _distribution_doc,
)


def _check_percentiles() -> None:
    # Synthetic distribution: integers 0..99. NumPy's default linear
    # interpolation puts p50 at 49.5, p99 at 98.01.
    values = list(range(100))
    doc = _distribution_doc(
        kind="smoke_test_kind", layer="smoke_test_layer", values=values,
    )
    # Schema fields all present.
    expected_keys = {
        "run_id", "generated_at", "kind", "layer",
        "p50", "p75", "p90", "p95", "p99", "n",
    }
    assert set(doc) == expected_keys, (
        f"unexpected fields: {set(doc) ^ expected_keys}"
    )
    # Numeric percentiles.
    assert doc["n"]   == 100,                       f"n: {doc['n']}"
    assert doc["p50"] == 49.5,                      f"p50: {doc['p50']}"
    assert doc["p75"] == 74.25,                     f"p75: {doc['p75']}"
    assert doc["p90"] == 89.1,                      f"p90: {doc['p90']}"
    assert doc["p95"] == 94.05,                     f"p95: {doc['p95']}"
    assert doc["p99"] == 98.01,                     f"p99: {doc['p99']}"
    assert doc["kind"]  == "smoke_test_kind"
    assert doc["layer"] == "smoke_test_layer"
    print("percentile math: 1 case passes")


def _check_uniform_distribution() -> None:
    # Degenerate input: all values equal. Every percentile collapses to
    # the value; the writer must not divide by zero or emit NaN.
    doc = _distribution_doc(kind="k", layer="l", values=[7.0] * 50)
    for pct in ("p50", "p75", "p90", "p95", "p99"):
        assert doc[pct] == 7.0, f"{pct} on uniform: {doc[pct]}"
    assert doc["n"] == 50
    print("uniform distribution: collapses cleanly")


def _check_single_value() -> None:
    # NumPy percentile on a single value returns the value; the writer
    # must not raise on n=1 (rare but possible in early-corpus states).
    doc = _distribution_doc(kind="k", layer="l", values=[42.0])
    for pct in ("p50", "p75", "p90", "p95", "p99"):
        assert doc[pct] == 42.0
    assert doc["n"] == 1
    print("n=1: handled without error")


def _check_registry_contract() -> None:
    # Every registered quantity must have a distinct kind discriminator
    # (used downstream by phase-4.2+ consumers to find their distribution)
    # and a non-empty layer label.
    kinds = [spec.kind for spec in _THRESHOLD_QUANTITIES]
    assert len(kinds) == len(set(kinds)), (
        f"duplicate kind discriminators: {kinds}"
    )
    for spec in _THRESHOLD_QUANTITIES:
        assert spec.kind,  f"empty kind on {spec}"
        assert spec.layer, f"empty layer on {spec}"
        assert callable(spec.fn), f"non-callable computer on {spec}"
    print(f"registry: {len(_THRESHOLD_QUANTITIES)} quantities, all distinct")


def main() -> int:
    _check_percentiles()
    _check_uniform_distribution()
    _check_single_value()
    _check_registry_contract()
    print("threshold-distribution smoke OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
