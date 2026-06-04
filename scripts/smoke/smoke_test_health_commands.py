"""Smoke test for ROADMAP #11.5 — Health page command-coverage classifier.

Verifies `console.health.health_commands` classification logic by
mocking ES + the grounding data:

  - A command with no entry → `needs_def`.
  - A command with tldr-only → `tldr_only`.
  - A command with curated → counted in `stats.curated`, NOT in list.
  - Aggregate counts weight by `occurrence_count`.
  - Sample command lines captured per token (deduped, capped at 3).
  - Lists ranked by count desc.

Standalone — no live ES, no LLM.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_health_commands.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

# Need both the pipeline package (for command_grounding) AND the console
# package on sys.path. The console venv has both editable-installed.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "console" / "src"))

from console import health as console_health


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def _fake_es_with(hits: list[dict]):
    """Build a minimal ES mock that returns the given hits once, then []."""
    es = MagicMock()
    pages = [
        {"hits": {"hits": [
            {"_source": h, "sort": [str(i)]} for i, h in enumerate(hits)
        ]}},
        {"hits": {"hits": []}},
    ]
    es.search.side_effect = pages
    return es


def _fake_cfg():
    cfg = MagicMock()
    cfg.elasticsearch.indexes.cowrie.commands = "test-commands"
    return cfg


def _mk_hit(cmd_line: str, occurrence: int = 1) -> dict:
    return {
        "process": {"command_line": cmd_line},
        "dshield": {"cowrie": {"enrichment": {"occurrence_count": occurrence}}},
    }


# Patch the grounding data into a known fixed map for deterministic tests.
# `wget` is curated (has flags). `cat` is tldr-only (no curated description).
# `nopedoesntexist` doesn't appear in the data at all.
_FIXED_DATA = {
    "wget": {
        "curated_description": "fetch files",
        "flags": {"-q": "quiet", "-O": "output"},
        "tldr_by_os": {"common": "tldr/common wget summary"},
        "source": "both",
    },
    "cat": {
        "curated_description": "",
        "flags": {},
        "tldr_by_os": {
            "common": "tldr/common cat summary",
            "linux": "tldr/linux cat summary",
        },
        "source": "tldr",
    },
}
# Patch on console.health — that module imported the helpers as bound
# names at import time, so patching the grounding module wouldn't reach
# them. We patch both the data loader AND the denylist accessor.
_orig_load = console_health._load_command_data
console_health._load_command_data = lambda: _FIXED_DATA  # type: ignore[assignment]
_orig_denylist = console_health.list_denied_commands
console_health.list_denied_commands = lambda: {            # type: ignore[assignment]
    "satori": "Mirai variant identifier, not a command",
}


# -------------------------------------------------------------------------
# [1] needs_def captures unknown commands ranked by occurrence-weighted count
# -------------------------------------------------------------------------
print("\n[1] needs_def list")
hits = [
    _mk_hit("nopedoesntexist arg",              occurrence=10),
    _mk_hit("alsoabsent foo",                   occurrence=3),
    _mk_hit("nopedoesntexist another arg",      occurrence=2),
]
es = _fake_es_with(hits)
cfg = _fake_cfg()
out = console_health.health_commands(es, cfg)
check("response shape: available=True", out["available"] is True)
check("needs_def includes nopedoesntexist and alsoabsent",
      {x["name"] for x in out["needs_def"]} == {"nopedoesntexist", "alsoabsent"})
# nopedoesntexist count = 10 + 2 = 12; alsoabsent = 3.
counts = {x["name"]: x["count"] for x in out["needs_def"]}
check("occurrence_count weights aggregate", counts == {"nopedoesntexist": 12, "alsoabsent": 3},
      f"got {counts!r}")
check("needs_def sorted by count desc",
      [x["name"] for x in out["needs_def"]] == ["nopedoesntexist", "alsoabsent"])


# -------------------------------------------------------------------------
# [2] curated commands counted but omitted from the list
# -------------------------------------------------------------------------
print("\n[2] curated counted but not listed")
hits = [_mk_hit("wget -q http://x", occurrence=5)]
es = _fake_es_with(hits)
out = console_health.health_commands(es, cfg)
check("wget appears in stats.curated count",
      out["stats"]["curated"] == 1, f"got curated={out['stats']['curated']}")
check("wget NOT in needs_def list",
      not any(x["name"] == "wget" for x in out["needs_def"]))
check("wget NOT in tldr_only list",
      not any(x["name"] == "wget" for x in out["tldr_only"]))


# -------------------------------------------------------------------------
# [3] tldr-only commands captured in tldr_only list
# -------------------------------------------------------------------------
print("\n[3] tldr_only list")
hits = [
    _mk_hit("cat /etc/passwd",      occurrence=7),
    _mk_hit("cat /proc/cpuinfo",    occurrence=4),
]
es = _fake_es_with(hits)
out = console_health.health_commands(es, cfg)
check("cat in tldr_only with weighted count",
      any(x["name"] == "cat" and x["count"] == 11 for x in out["tldr_only"]),
      f"got tldr_only={out['tldr_only']!r}")
check("stats.tldr_only count matches",
      out["stats"]["tldr_only"] == 1)


# -------------------------------------------------------------------------
# [4] Samples are deduped per command and capped
# -------------------------------------------------------------------------
print("\n[4] samples dedup + cap")
hits = [
    _mk_hit("unknowncmd a"),
    _mk_hit("unknowncmd a"),         # exact duplicate — should NOT be kept twice
    _mk_hit("unknowncmd b"),
    _mk_hit("unknowncmd c"),
    _mk_hit("unknowncmd d"),         # 4th distinct — beyond cap of 3
]
es = _fake_es_with(hits)
out = console_health.health_commands(es, cfg, sample_limit=3)
entry = next(x for x in out["needs_def"] if x["name"] == "unknowncmd")
check("samples deduped",
      "unknowncmd a" in entry["samples"]
      and entry["samples"].count("unknowncmd a") == 1)
check("samples capped at 3", len(entry["samples"]) == 3,
      f"got {len(entry['samples'])}")


# -------------------------------------------------------------------------
# [5] stats: total counts + total_corpus_occurrences
# -------------------------------------------------------------------------
print("\n[5] stats roll-up")
hits = [
    _mk_hit("wget -q http://x",       occurrence=5),
    _mk_hit("cat /etc/passwd",        occurrence=7),
    _mk_hit("nopedoesntexist arg",    occurrence=10),
]
es = _fake_es_with(hits)
out = console_health.health_commands(es, cfg)
check("total_unique_cmds = 3 (wget, cat, nope)",
      out["stats"]["total_unique_cmds"] == 3,
      f"got {out['stats']['total_unique_cmds']}")
check("total_corpus_occurrences = 5+7+10 = 22",
      out["stats"]["total_corpus_occurrences"] == 22,
      f"got {out['stats']['total_corpus_occurrences']}")


# -------------------------------------------------------------------------
# [6] Denylisted tokens go to the `denied` bucket, not `needs_def`.
# -------------------------------------------------------------------------
print("\n[6] denylist routes tokens to `denied` bucket")
hits = [
    _mk_hit("./satori",                occurrence=5),
    _mk_hit("/bin/busybox SATORI",     occurrence=3),
    _mk_hit("nopedoesntexist arg",     occurrence=2),
]
es = _fake_es_with(hits)
out = console_health.health_commands(es, cfg)
# satori is denied → in `denied`, NOT in `needs_def`.
denied_names = {x["name"] for x in out["denied"]}
needs_def_names = {x["name"] for x in out["needs_def"]}
check("satori in denied bucket", "satori" in denied_names,
      f"got denied={denied_names!r}, needs_def={needs_def_names!r}")
check("satori NOT in needs_def", "satori" not in needs_def_names)
check("nopedoesntexist still in needs_def", "nopedoesntexist" in needs_def_names)
check("denied rationale carried through",
      next((x["rationale"] for x in out["denied"] if x["name"] == "satori"), "")
      == "Mirai variant identifier, not a command")
check("stats.denied populated",
      out["stats"]["denied"] == 1, f"got {out['stats']['denied']}")
check("denied counts aggregated (./satori + busybox SATORI = 5+3 = 8)",
      next((x["count"] for x in out["denied"] if x["name"] == "satori"), 0) == 8,
      f"got {[x for x in out['denied'] if x['name'] == 'satori']!r}")


# -------------------------------------------------------------------------
# [7] Empty corpus: clean zero-state response.
# -------------------------------------------------------------------------
print("\n[7] empty corpus")
es = _fake_es_with([])
out = console_health.health_commands(es, cfg)
check("empty corpus: total_unique_cmds = 0",
      out["stats"]["total_unique_cmds"] == 0)
check("empty corpus: needs_def is []", out["needs_def"] == [])
check("empty corpus: tldr_only is []", out["tldr_only"] == [])


# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------
console_health._load_command_data = _orig_load  # type: ignore[assignment]
console_health.list_denied_commands = _orig_denylist  # type: ignore[assignment]


print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
