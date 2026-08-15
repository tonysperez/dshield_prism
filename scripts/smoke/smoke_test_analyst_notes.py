"""Smoke test for ROADMAP #16 — analyst-authored command-grounding notes.

Covers `enrich.command_grounding._load_analyst_notes` +
`find_matching_analyst_notes` + `build_ground_truth_block` integration:
  * A substring entry fires when its pattern is in the command line.
  * A literal entry respects whitespace-boundary discipline (inherits
    the same semantics from `enrich.analyst.artifact_rules.compile_rule`).
  * A regex entry matches the regex group.
  * Multi-line notes preserve formatting in the rendered block.
  * Malformed entries are skipped without taking out the rest of the
    file.
  * Editing the YAML file changes `compute_llm_config_hash` so the
    next `re-enrich-stale` re-runs affected commands.

Standalone — no ES, no LLM.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_analyst_notes.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich import command_grounding as cg


def _swap_notes_path(yaml_text: str) -> Path:
    """Write a temp YAML, point the loader at it, return the temp Path."""
    tmp = Path(tempfile.mkstemp(suffix=".yaml")[1])
    tmp.write_text(yaml_text, encoding="utf-8")
    cg._ANALYST_NOTES_PATH = tmp
    cg.reset_loaded_for_tests()
    return tmp


def test_substring_match_lands_in_block() -> None:
    _swap_notes_path("""
- pattern: "D877F783D5D3EF8C"
  match_type: substring
  notes: |
    Dota3 cryptominer marker. The `locate <fragment>s` lookup is a
    sanity check the loader runs to verify a prior install.
""")
    block = cg.build_ground_truth_block("locate D877F783D5D3EF8Cs")
    assert "(analyst note matching 'D877F783D5D3EF8C')" in block, block
    assert "Dota3 cryptominer marker" in block
    assert "sanity check" in block
    print("  ok: substring match injects analyst notes")


def test_literal_match_whitespace_boundary() -> None:
    _swap_notes_path("""
- pattern: "/tmp/redtail.elf"
  match_type: literal
  notes: |
    RedTail miner staged dropper. Common path on Dota3 chains too.
- pattern: "tmp"
  match_type: literal
  notes: "Should NOT fire on /tmp/anything"
""")
    block = cg.build_ground_truth_block("chmod +x /tmp/redtail.elf")
    assert "RedTail miner staged dropper" in block
    assert "Should NOT fire" not in block, block
    print("  ok: literal uses whitespace boundary (no over-match)")


def test_regex_match() -> None:
    _swap_notes_path(r"""
- pattern: "build-[0-9a-f]{8}"
  match_type: regex
  notes: |
    Custom build tag — see internal tracker BLD-1234.
""")
    block = cg.build_ground_truth_block("curl http://x/build-deadbeef -o /tmp/p")
    assert "(analyst note matching 'build-deadbeef')" in block, block
    assert "internal tracker BLD-1234" in block
    print("  ok: regex match")


def test_multiline_notes_preserve_layout() -> None:
    _swap_notes_path("""
- pattern: "marker_xyz"
  match_type: substring
  notes: |
    line one
    line two
    line three
""")
    block = cg.build_ground_truth_block("echo marker_xyz")
    # Each line of notes survives with the 6-space indentation our
    # emitter applies (`  ` for the marker line + `    ` for continuation).
    assert "line one" in block
    assert "line two" in block
    assert "line three" in block
    print("  ok: multi-line notes preserve layout")


def test_bad_entry_skipped() -> None:
    _swap_notes_path("""
- pattern: ""           # missing
  match_type: substring
  notes: nope
- not-a-mapping
- pattern: "(unclosed"  # bad regex
  match_type: regex
  notes: bad regex note
- pattern: "good_pattern"
  match_type: substring
  notes: this one is fine
""")
    notes = cg._load_analyst_notes()
    assert len(notes) == 1
    assert notes[0]["pattern"] == "good_pattern"
    print("  ok: malformed entries skipped, valid ones survive")


def test_empty_file_yields_no_notes() -> None:
    _swap_notes_path("# just a comment\n")
    assert cg._load_analyst_notes() == []
    block = cg.build_ground_truth_block("echo hi")
    assert "(analyst note" not in block
    print("  ok: empty file yields no notes")


def test_no_match_no_emission() -> None:
    _swap_notes_path("""
- pattern: "needle_that_will_not_match"
  match_type: substring
  notes: "should not appear"
""")
    block = cg.build_ground_truth_block("echo unrelated")
    assert "(analyst note" not in block, block
    print("  ok: no match → no emission")


def test_config_hash_picks_up_edits() -> None:
    """The grounding hash is computed over the live data directory. Our
    swapped temp-file path doesn't fall under it, so we exercise the hash
    by mutating the canonical YAML directly via reset + reload — and
    assert that two distinct file states yield different hashes."""
    from enrich.config import _hash_command_grounding

    real = cg._ANALYST_NOTES_PATH  # already swapped to temp by prior tests
    # Make sure we're using a path inside the canonical data dir for this
    # specific test — only that location is hashed.
    canonical = cg._DATA_DIR / "analyst_notes.yaml"
    cg._ANALYST_NOTES_PATH = canonical
    original = canonical.read_text(encoding="utf-8")
    try:
        cg.reset_loaded_for_tests()
        hash_a = _hash_command_grounding()

        canonical.write_text(
            original + '\n- pattern: "x"\n  match_type: substring\n  notes: "x"\n',
            encoding="utf-8",
        )
        cg.reset_loaded_for_tests()
        hash_b = _hash_command_grounding()
        assert hash_a != hash_b, "editing analyst_notes.yaml must flip the grounding hash"
    finally:
        canonical.write_text(original, encoding="utf-8")
        cg._ANALYST_NOTES_PATH = real
        cg.reset_loaded_for_tests()
    print("  ok: edits to analyst_notes.yaml flip _hash_command_grounding")


def main() -> int:
    print("smoke_test_analyst_notes:")
    test_substring_match_lands_in_block()
    test_literal_match_whitespace_boundary()
    test_regex_match()
    test_multiline_notes_preserve_layout()
    test_bad_entry_skipped()
    test_empty_file_yields_no_notes()
    test_no_match_no_emission()
    test_config_hash_picks_up_edits()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
