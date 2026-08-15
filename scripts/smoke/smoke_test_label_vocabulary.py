"""Smoke test for the rubric-v2 closed label vocabulary and the
vocabulary-alignment diagnostic.

Two coupled changes, both aimed at the same failure: an open label vocabulary
let two labeling passes over the same 160 sessions (both compliant with
`rubric_version: v1`) produce 11 and 12 categories with only 5 shared. Because
`eval_agreement.py` compares label *strings*, a pure rename scored as total
disagreement — raw agreement 0.4813 against 0.5813 once the vocabularies were
aligned 1:1.

  * `scripts/validate_eval_labels.py` now enforces a closed `playbook_label`
    vocabulary, with an actionable message for the retired synonyms.
  * `scripts/eval_agreement.py::vocabulary_alignment` reports agreement under
    the best 1:1 renaming, with categories present in BOTH vocabularies locked
    to themselves — those are genuine disagreement, not naming.

Covers (no ES/LLM/network):
  * A canonical label validates; an unknown one and a retired synonym both
    fail, and the synonym's message names its replacement.
  * A pure renaming recovers to 1.0 aligned agreement.
  * A category in both vocabularies is NEVER remapped, even when remapping
    would score higher — that is the property separating naming from
    disagreement.
  * Identical vocabularies leave aligned == raw (the diagnostic is inert when
    there is no drift).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_label_vocabulary.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import eval_agreement as ea
import validate_eval_labels as vel


def _block(label: str) -> dict:
    return {
        "annotated": True, "is_real": True, "playbook_label": label,
        "expected_findings": [], "notes": "",
        "annotator": "smoke", "labeled_at": "2026-07-28", "rubric_version": "v2",
    }


def test_canonical_label_validates() -> None:
    errors: list[str] = []
    filled, pb = vel._check_block("s1", _block("host_recon"), errors)
    assert filled and pb == "host_recon", (filled, pb)
    assert errors == [], errors
    print("  ok: canonical playbook_label validates clean")


def test_unknown_label_rejected() -> None:
    errors: list[str] = []
    vel._check_block("s2", _block("totally_new_thing"), errors)
    assert len(errors) == 1, errors
    assert "closed vocabulary" in errors[0], errors[0]
    print("  ok: unknown playbook_label rejected as out-of-vocabulary")


def test_retired_alias_names_its_replacement() -> None:
    errors: list[str] = []
    vel._check_block("s3", _block("uploaded_payload_staging"), errors)
    assert len(errors) == 1, errors
    assert "retired" in errors[0] and "scp_upload" in errors[0], errors[0]
    # Every alias must resolve to something the operator can act on.
    for retired, replacement in vel.RETIRED_LABEL_ALIASES.items():
        assert retired not in vel.KNOWN_PLAYBOOK_LABELS, retired
        assert isinstance(replacement, str) and replacement, retired
    print("  ok: retired synonym rejected, message names the canonical label")


def test_pure_rename_fully_recovers() -> None:
    # A calls it `scp_upload`, B calls it `uploaded_payload_staging`. Same
    # behavior, different string: raw agreement 0, aligned 1.0.
    pairs = [("scp_upload", "uploaded_payload_staging")] * 5
    raw = ea.percent_agreement(pairs)
    va = ea.vocabulary_alignment(pairs)
    assert raw == 0.0, raw
    assert va["aligned_percent_agreement"] == 1.0, va
    assert va["alignment"] == [
        {"a": "scp_upload", "b": "uploaded_payload_staging", "count": 5}], va
    print("  ok: pure rename scores raw 0.0 / aligned 1.0")


def test_shared_category_never_remapped() -> None:
    """The load-bearing constraint. `host_recon` is in both vocabularies, and
    remapping A's `host_recon` onto B's `probe` would score higher (3 > 1) —
    but both annotators knew the term `host_recon` and chose differently, so
    that is disagreement, not naming. It must stay locked to itself."""
    pairs = (
        [("host_recon", "probe")] * 3
        + [("host_recon", "host_recon")] * 1
        + [("probe", "probe")] * 1
    )
    va = ea.vocabulary_alignment(pairs)
    mapped = {r["a"]: r["b"] for r in va["alignment"]}
    assert "host_recon" not in mapped, va["alignment"]
    # Only the identity matches count: host_recon(1) + probe(1) = 2 of 5.
    assert abs(va["aligned_percent_agreement"] - 2 / 5) < 1e-12, va
    print("  ok: category shared by both vocabularies is never remapped")


def test_no_drift_is_inert() -> None:
    pairs = [("host_recon", "host_recon")] * 4 + [("host_recon", "scp_upload")] * 2
    raw = ea.percent_agreement(pairs)
    va = ea.vocabulary_alignment(pairs)
    assert va["aligned_percent_agreement"] == raw, (raw, va)
    assert va["alignment"] == [], va
    print("  ok: aligned == raw when there is no vocabulary drift")


def test_empty_overlap() -> None:
    va = ea.vocabulary_alignment([])
    assert va["aligned_percent_agreement"] is None, va
    assert va["alignment"] == [], va
    print("  ok: empty overlap returns None rather than raising")


def main() -> int:
    print("smoke_test_label_vocabulary:")
    test_canonical_label_validates()
    test_unknown_label_rejected()
    test_retired_alias_names_its_replacement()
    test_pure_rename_fully_recovers()
    test_shared_category_never_remapped()
    test_no_drift_is_inert()
    test_empty_overlap()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
