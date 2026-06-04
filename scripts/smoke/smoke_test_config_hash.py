"""Smoke test for ROADMAP #7 — two auto-derived cache hashes.

Covers:
  * `compute_llm_config_hash` and `compute_embed_config_hash` are
    deterministic.
  * Each hash is independent — prompt-file or LLM-side cooccurrence
    edits flip only the LLM hash; embed_context / embedding_model /
    embed_cooccurrence edits flip only the embed hash.
  * Missing prompt files don't crash the LLM hash function (and fold
    the path into the digest so two typos don't collide).
  * `StateDB.is_cached` requires BOTH hashes to match.
  * `mark_embed_cached` updates only the embed hash, preserving the
    LLM hash — so a stale LLM output can't be silently blessed.
  * Legacy rows (missing either hash) are flagged by
    `legacy_cache_row_count` and stamped by `bless_legacy_cache_rows`.

Standalone — no ES, no LLM. Uses a tmp SQLite DB and tmp prompt files.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_config_hash.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.cache import StateDB
from enrich.config import (
    AppConfig,
    compute_embed_config_hash,
    compute_llm_config_hash,
)


def _mk_cfg(
    tmp: Path, *,
    prompt_body: str = "BASE",
    cooc_top_k: int = 8,
    embed_context: list[str] | None = None,
    embedding_model: str = "nomic-embed-text",
    embed_cooccurrence: bool = True,
) -> AppConfig:
    """Build a minimum-viable AppConfig anchored on tmp filesystem."""
    tmp.mkdir(parents=True, exist_ok=True)
    pp = tmp / "command_enrichment.txt"
    pp.write_text(prompt_body)
    db_path = tmp / "state.sqlite"
    return AppConfig.model_validate({
        "elasticsearch": {
            "hosts": ["http://x"],
            "indexes": {"cowrie": {
                "sessions_raw": "raw",
                "commands": "cmds",
                "command_clusters": "cmd_clusters",
                "sessions_rollup": "sess_rollup",
                "session_clusters": "sess_clusters",
                "ips_rollup": "ips_rollup",
                "ip_clusters": "ip_clusters",
                "campaigns": "campaigns",
            }},
        },
        "llm": {
            "base_url": "http://l",
            "generation_model": "gen-m",
            "embedding_model": embedding_model,
            "embed_context": embed_context if embed_context is not None
            else ["intent", "tactics", "description"],
        },
        "worker": {"state_db": str(db_path)},
        "prompts": {"command_enrichment": str(pp)},
        "cooccurrence": {
            "top_k": cooc_top_k,
            "embed_cooccurrence": embed_cooccurrence,
        },
    })


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def hashes(cfg):
    return compute_llm_config_hash(cfg), compute_embed_config_hash(cfg)


with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)

    # -------------------------------------------------------------------
    # [1] Both hashes deterministic
    # -------------------------------------------------------------------
    print("\n[1] determinism")
    cfg_a = _mk_cfg(tmp / "a")
    l1, e1 = hashes(cfg_a)
    l2, e2 = hashes(cfg_a)
    check("llm hash deterministic", l1 == l2, f"{l1!r} vs {l2!r}")
    check("embed hash deterministic", e1 == e2, f"{e1!r} vs {e2!r}")
    check("llm hash format 16-hex",
          len(l1) == 16 and all(c in "0123456789abcdef" for c in l1))
    check("embed hash format 16-hex",
          len(e1) == 16 and all(c in "0123456789abcdef" for c in e1))
    check("llm and embed hashes are distinct values", l1 != e1,
          f"{l1!r} == {e1!r} — independent inputs should differ")

    # -------------------------------------------------------------------
    # [2] Hashes are INDEPENDENT — LLM-side edits don't flip embed hash
    # -------------------------------------------------------------------
    print("\n[2] LLM-side edits flip only LLM hash")
    # Prompt-file content change.
    base_dir = tmp / "b_base"
    cfg_b = _mk_cfg(base_dir)
    bl, be = hashes(cfg_b)
    (base_dir / "command_enrichment.txt").write_text("DIFFERENT")
    al, ae = hashes(cfg_b)
    check("prompt edit → llm hash changes", bl != al)
    check("prompt edit → embed hash unchanged", be == ae,
          f"{be!r} vs {ae!r}")

    # LLM-side cooccurrence field (top_k).
    cfg_c1 = _mk_cfg(tmp / "c1", cooc_top_k=8)
    cfg_c2 = _mk_cfg(tmp / "c2", cooc_top_k=12)
    (tmp / "c1" / "command_enrichment.txt").write_text("SAME")
    (tmp / "c2" / "command_enrichment.txt").write_text("SAME")
    l_c1, e_c1 = hashes(cfg_c1)
    l_c2, e_c2 = hashes(cfg_c2)
    check("cooc top_k edit → llm hash changes", l_c1 != l_c2)
    check("cooc top_k edit → embed hash unchanged", e_c1 == e_c2,
          f"{e_c1!r} vs {e_c2!r}")

    # -------------------------------------------------------------------
    # [3] Hashes are INDEPENDENT — embed-side edits don't flip LLM hash
    # -------------------------------------------------------------------
    print("\n[3] embed-side edits flip only embed hash")
    # embed_context list.
    cfg_d1 = _mk_cfg(tmp / "d1", embed_context=["intent", "description"])
    cfg_d2 = _mk_cfg(tmp / "d2", embed_context=["intent", "tactics", "description"])
    (tmp / "d1" / "command_enrichment.txt").write_text("SAME")
    (tmp / "d2" / "command_enrichment.txt").write_text("SAME")
    l_d1, e_d1 = hashes(cfg_d1)
    l_d2, e_d2 = hashes(cfg_d2)
    check("embed_context edit → embed hash changes", e_d1 != e_d2)
    check("embed_context edit → llm hash unchanged", l_d1 == l_d2,
          f"{l_d1!r} vs {l_d2!r}")

    # embedding_model.
    cfg_m1 = _mk_cfg(tmp / "m1", embedding_model="nomic-embed-text")
    cfg_m2 = _mk_cfg(tmp / "m2", embedding_model="mxbai-embed-large")
    (tmp / "m1" / "command_enrichment.txt").write_text("SAME")
    (tmp / "m2" / "command_enrichment.txt").write_text("SAME")
    l_m1, e_m1 = hashes(cfg_m1)
    l_m2, e_m2 = hashes(cfg_m2)
    check("embedding_model edit → embed hash changes", e_m1 != e_m2)
    check("embedding_model edit → llm hash unchanged", l_m1 == l_m2,
          f"{l_m1!r} vs {l_m2!r}")

    # cooccurrence.embed_cooccurrence toggle.
    cfg_t1 = _mk_cfg(tmp / "t1", embed_cooccurrence=True)
    cfg_t2 = _mk_cfg(tmp / "t2", embed_cooccurrence=False)
    (tmp / "t1" / "command_enrichment.txt").write_text("SAME")
    (tmp / "t2" / "command_enrichment.txt").write_text("SAME")
    l_t1, e_t1 = hashes(cfg_t1)
    l_t2, e_t2 = hashes(cfg_t2)
    check("embed_cooccurrence toggle → embed hash changes", e_t1 != e_t2)
    check("embed_cooccurrence toggle → llm hash unchanged", l_t1 == l_t2,
          f"{l_t1!r} vs {l_t2!r}")

    # embed_context list order should NOT matter (sorted internally).
    cfg_o1 = _mk_cfg(tmp / "o1", embed_context=["intent", "tactics"])
    cfg_o2 = _mk_cfg(tmp / "o2", embed_context=["tactics", "intent"])
    (tmp / "o1" / "command_enrichment.txt").write_text("SAME")
    (tmp / "o2" / "command_enrichment.txt").write_text("SAME")
    check("embed_context order doesn't matter (sorted)",
          compute_embed_config_hash(cfg_o1) == compute_embed_config_hash(cfg_o2))

    # -------------------------------------------------------------------
    # [4] Missing prompt file: graceful, path differentiates
    # -------------------------------------------------------------------
    print("\n[4] missing prompt file: graceful, path differentiates")
    cfg_x = _mk_cfg(tmp / "x")
    cfg_x.prompts.command_enrichment = str(tmp / "x" / "missing.txt")
    cfg_y = _mk_cfg(tmp / "y")
    cfg_y.prompts.command_enrichment = str(tmp / "y" / "also_missing.txt")
    lx, _ = hashes(cfg_x)
    ly, _ = hashes(cfg_y)
    check("missing file: llm hash computed without raising", len(lx) == 16)
    check("missing file: different paths differentiate", lx != ly)

    # -------------------------------------------------------------------
    # [5] is_cached requires BOTH hashes; mark_cached stamps both
    # -------------------------------------------------------------------
    print("\n[5] is_cached needs both hashes")
    cfg_db = _mk_cfg(tmp / "db")
    db = StateDB(cfg_db.worker.state_db)
    L, E = hashes(cfg_db)
    db.mark_cached("cmd1", "gen-m", L, E, "2026-01-01")
    check("hit when both match", db.is_cached("cmd1", "gen-m", L, E))
    check("miss when llm hash differs",
          not db.is_cached("cmd1", "gen-m", "deadbeef00000000", E))
    check("miss when embed hash differs",
          not db.is_cached("cmd1", "gen-m", L, "cafebabe00000000"))
    check("miss when both empty",
          not db.is_cached("cmd1", "gen-m", "", ""))

    # -------------------------------------------------------------------
    # [6] mark_embed_cached: updates embed hash only, preserves llm hash
    # -------------------------------------------------------------------
    print("\n[6] mark_embed_cached preserves llm hash")
    NEW_EMBED = "feedface00000000"
    db.mark_embed_cached("cmd1", NEW_EMBED, "2026-01-02")
    check("post-reembed: still hits under (old llm, new embed)",
          db.is_cached("cmd1", "gen-m", L, NEW_EMBED))
    check("post-reembed: does NOT hit under (new llm, new embed)",
          not db.is_cached("cmd1", "gen-m", "newllmhash000000", NEW_EMBED),
          "reembed should not bless a stale LLM output")

    # mark_embed_cached on a non-existent row is a no-op (no insert).
    db.mark_embed_cached("ghost_cmd", NEW_EMBED, "2026-01-02")
    check("mark_embed_cached doesn't insert for unknown command",
          not db.is_cached("ghost_cmd", "gen-m", "x" * 16, NEW_EMBED))

    # -------------------------------------------------------------------
    # [7] Legacy rows: count + bless
    # -------------------------------------------------------------------
    print("\n[7] legacy rows + bless")
    # Simulate a pre-#7 row (no auto hashes).
    db.conn.execute(
        "INSERT INTO enrichment_cache(command_hash, model, prompt_version,"
        " embed_version, config_hash, llm_config_hash, embed_config_hash,"
        " enriched_at) VALUES (?,?,?,?,?,?,?,?)",
        ("legacy1", "gen-m", "v1", "v1", "", "", "", "2025-12-01"),
    )
    # Simulate a row from #7 v1 (single config_hash present, two-hash empty).
    db.conn.execute(
        "INSERT INTO enrichment_cache(command_hash, model, prompt_version,"
        " embed_version, config_hash, llm_config_hash, embed_config_hash,"
        " enriched_at) VALUES (?,?,?,?,?,?,?,?)",
        ("legacy2", "gen-m", "v1", "v1", "abcdef0123456789", "", "", "2025-12-15"),
    )
    legacy_count = db.legacy_cache_row_count()
    check("two legacy rows counted", legacy_count == 2,
          f"got {legacy_count}")
    stamped = db.bless_legacy_cache_rows(L, E)
    check("bless stamps both legacy rows", stamped == 2, f"stamped={stamped}")
    check("post-bless: legacy1 hits under live hashes",
          db.is_cached("legacy1", "gen-m", L, E))
    check("post-bless: legacy2 hits under live hashes",
          db.is_cached("legacy2", "gen-m", L, E))
    check("post-bless: legacy count = 0",
          db.legacy_cache_row_count() == 0)

    # -------------------------------------------------------------------
    # [8] Bulk hash readers (used by reembed skip-if-fresh and
    # re-enrich-stale to find drift cheaply, without re-reading ES).
    # -------------------------------------------------------------------
    print("\n[8] bulk hash readers")
    embed_map = db.get_cached_embed_hashes()
    llm_map   = db.get_cached_llm_hashes()
    # Every command we stamped above should appear in both maps.
    expected_cmds = {"cmd1", "legacy1", "legacy2"}
    check("get_cached_embed_hashes returns all rows",
          expected_cmds.issubset(set(embed_map)),
          f"missing {expected_cmds - set(embed_map)}")
    check("get_cached_llm_hashes returns all rows",
          expected_cmds.issubset(set(llm_map)),
          f"missing {expected_cmds - set(llm_map)}")
    # cmd1 was reembedded with NEW_EMBED via mark_embed_cached.
    check("embed_map reflects mark_embed_cached's update",
          embed_map["cmd1"] == NEW_EMBED,
          f"got {embed_map['cmd1']!r}")
    # cmd1's llm hash was NOT touched by mark_embed_cached.
    check("llm_map untouched by mark_embed_cached",
          llm_map["cmd1"] == L,
          f"got {llm_map['cmd1']!r}, expected {L!r}")

    # -------------------------------------------------------------------
    # [9] clear_watermark(key) — surgical, not all-or-nothing.
    # -------------------------------------------------------------------
    print("\n[9] clear_watermark(key) surgical delete")
    db.set_watermark("2026-01-01", "last_processed_at")
    db.set_watermark("2026-01-02", "session_last_processed_at")
    db.set_watermark("2026-01-03", "ip_rollup_last_processed_at")
    deleted = db.clear_watermark("session_last_processed_at")
    check("clear_watermark(specific) deletes exactly one row",
          deleted == 1, f"got {deleted}")
    check("non-targeted command watermark still present",
          db.get_watermark("last_processed_at") == "2026-01-01")
    check("non-targeted IP watermark still present",
          db.get_watermark("ip_rollup_last_processed_at") == "2026-01-03")
    check("targeted session watermark gone",
          db.get_watermark("session_last_processed_at") is None)
    # Default (no key) clears everything that's left.
    deleted_all = db.clear_watermark()
    check("clear_watermark() with no key clears the remaining rows",
          deleted_all == 2, f"got {deleted_all}")

    db.close()

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
