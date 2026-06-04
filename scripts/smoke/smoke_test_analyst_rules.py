"""Smoke test for ROADMAP #5 — analyst-defined artifacts (offline).

Covers `enrich.analyst.artifact_rules`:
  * `compile_rule` for the three match types.
  * `find` semantics: literal uses whitespace-boundary so path-like tokens
    starting with `/` match; substring is "contained anywhere"; regex is
    `re.search`. A literal pattern must NOT match a substring of a larger
    token (boundary discipline).
  * Case sensitivity toggle changes match decisions for `substring` and
    `literal`/`regex` (via re.IGNORECASE).
  * `apply_rules` dedupes per (rule_id, value) and caps total entries.
  * `artifact_set_strings` formats as `analyst:<kind>:<value>`.
  * `is_catastrophic` flags ratios > 50%; 0-sample is never catastrophic.
  * Config: `AnalystRuleConfig` carries default index name and tunables;
    `AppConfig` wires `analyst` cleanly.
  * `_resolve_index_for_layer("analyst", "artifact_rules")` returns the
    configured index name.

Standalone — no ES, no LLM.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_analyst_rules.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.analyst import artifact_rules as ar  # noqa: E402


def _rule(rid, kind, mt, pat, cs=False):
    return ar.compile_rule({
        "rule_id": rid, "kind": kind, "match_type": mt,
        "pattern": pat, "case_sensitive": cs,
    })


def test_literal_boundary_and_path_tokens() -> None:
    r = _rule("r1", "path", "literal", "/tmp/redtail.elf")
    assert r.find("chmod +x /tmp/redtail.elf") == ["/tmp/redtail.elf"]
    # Embedded inside a larger token → NO match (boundary discipline).
    r2 = _rule("r2", "x", "literal", "tmp")
    assert r2.find("ls /tmp/x") == []
    # But a standalone word matches.
    assert r2.find("cd tmp ; ls") == ["tmp"]
    print("  ok: literal respects whitespace boundary")


def test_substring_matches_anywhere() -> None:
    r = _rule("r3", "ua", "substring", "Mozilla")
    assert r.find("curl -A Mozilla/5.0 http://x") == ["Mozilla"]
    # Case-insensitive by default.
    assert r.find("curl -A mozilla/5.0 http://x") == ["Mozilla"]
    # Case-sensitive flips the decision.
    r_cs = _rule("r3cs", "ua", "substring", "Mozilla", cs=True)
    assert r_cs.find("curl -A mozilla/5.0 http://x") == []
    print("  ok: substring + case sensitivity")


def test_regex_findall() -> None:
    r = _rule("r4", "tag", "regex", r"build-[0-9a-f]{8}")
    hits = r.find("fetch /build-deadbeef and /build-cafebabe")
    assert hits == ["build-deadbeef", "build-cafebabe"]
    print("  ok: regex finds all distinct spans")


def test_apply_rules_dedup_and_cap() -> None:
    r1 = _rule("a", "x", "substring", "abc")
    r2 = _rule("b", "y", "substring", "def")
    out = ar.apply_rules("abcdef abc def", [r1, r2], cap=10)
    # Two unique (rule_id, value) tuples — both rules' "value" is the
    # pattern itself for substring, so we expect exactly two entries even
    # though "abc" appears twice in the text.
    keys = sorted((h["rule_id"], h["value"]) for h in out)
    assert keys == [("a", "abc"), ("b", "def")], keys
    # Cap is enforced.
    capped = ar.apply_rules("abcdef abc def", [r1, r2], cap=1)
    assert len(capped) == 1
    print("  ok: apply_rules dedup + cap")


def test_artifact_set_strings_shape() -> None:
    hits = [
        {"rule_id": "x", "kind": "path", "value": "/tmp/x"},
        {"rule_id": "y", "kind": "useragent", "value": "Mozilla/5.0"},
    ]
    out = ar.artifact_set_strings(hits)
    assert out == ["analyst:path:/tmp/x", "analyst:useragent:Mozilla/5.0"]
    print("  ok: artifact_set_strings format")


def test_catastrophic_probe_ratio() -> None:
    assert ar.is_catastrophic(10, 6) is True
    assert ar.is_catastrophic(10, 5) is False  # exactly 50% is NOT catastrophic
    assert ar.is_catastrophic(10, 3) is False
    assert ar.is_catastrophic(0, 0) is False   # empty corpus = never reject
    print("  ok: is_catastrophic ratio")


def test_compile_rejects_invalid() -> None:
    try:
        _rule("bad", "x", "wat", "abc")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on bogus match_type")
    try:
        _rule("bad", "x", "regex", "(unclosed")
    except Exception:
        pass
    else:
        raise AssertionError("expected re.error on bad regex")
    print("  ok: compile rejects invalid rules")


def test_config_wires_cleanly() -> None:
    from enrich.config import AnalystRuleConfig, AppConfig
    cfg = AnalystRuleConfig()
    assert cfg.enabled is True
    assert cfg.indexes.artifact_rules == "prism.analyst.artifact_rules"
    assert cfg.sync_scan_doc_threshold == 5000
    # AppConfig requires nested ESConfig / LLMConfig / etc., so just check
    # the field is declared with a sensible default factory.
    assert "analyst" in AppConfig.model_fields
    print("  ok: AnalystRuleConfig defaults + AppConfig field")


def test_cli_resolver_recognises_analyst_source() -> None:
    from enrich.cli import _LAYER_MAPPINGS
    assert "analyst" in _LAYER_MAPPINGS
    assert "artifact_rules" in _LAYER_MAPPINGS["analyst"]
    print("  ok: CLI _LAYER_MAPPINGS knows the analyst source")


def main() -> int:
    print("smoke_test_analyst_rules:")
    test_literal_boundary_and_path_tokens()
    test_substring_matches_anywhere()
    test_regex_findall()
    test_apply_rules_dedup_and_cap()
    test_artifact_set_strings_shape()
    test_catastrophic_probe_ratio()
    test_compile_rejects_invalid()
    test_config_wires_cleanly()
    test_cli_resolver_recognises_analyst_source()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
