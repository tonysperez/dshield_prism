"""Smoke test for spec-grounding-precompute — the `track grounding-coverage`
pipeline job (`enrich.grounding_coverage_job`).

Verifies, fully offline (mocked ES, no network, no LLM):

  - A command with no entry -> `needs_def`.
  - A command with tldr-only -> `tldr_only`.
  - A command with curated -> counted in `stats.curated`, NOT listed.
  - Denylisted tokens -> `denied`, not `needs_def`.
  - Aggregate `count` weights by `occurrence_count` and includes EVERY
    classification (public, confidential, untagged) — the coverage stats
    are corpus-wide.
  - `samples` are gated to public-only: a confidential or untagged doc's
    command line never appears in `samples`, even though it counted.
  - `write_grounding_coverage` writes a single doc at the configured
    fixed id, and no-ops cleanly when the target index doesn't exist yet.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_grounding_coverage_job.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))  # noqa: E402

from enrich import grounding_coverage_job as gcj  # noqa: E402

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
    """Minimal ES mock: one page of `hits`, then an empty page."""
    es = MagicMock()
    pages = [
        {"hits": {"hits": [
            {"_source": h, "sort": [str(i)]} for i, h in enumerate(hits)
        ]}},
        {"hits": {"hits": []}},
    ]
    es.search.side_effect = pages
    return es


def _fake_es_pages(pages: list[list[dict]]):
    """ES mock where each page is a list of RAW hit dicts (caller builds
    `_source`/`sort` directly, so it can construct malformed hits) followed
    by an implicit empty terminal page. `es.search.side_effect` may have
    unused trailing items if the scan ends earlier than the terminal page
    (e.g. Fix 1/Fix 2 tests that expect the scan to stop early)."""
    es = MagicMock()
    es.search.side_effect = (
        [{"hits": {"hits": p}} for p in pages] + [{"hits": {"hits": []}}]
    )
    return es


def _fake_cfg():
    return SimpleNamespace(
        elasticsearch=SimpleNamespace(
            indexes=SimpleNamespace(cowrie=SimpleNamespace(commands="test-commands")),
        ),
        grounding_coverage=SimpleNamespace(
            indexes=SimpleNamespace(default="prism.metrics.grounding_coverage"),
            doc_id="latest",
            samples_per_entry=3,
            max_list_len=200,
            scan_batch_size=1000,
        ),
        # Explicit fail-safe posture (production default): only an explicit
        # `public` classification is releasable.
        classification=SimpleNamespace(unclassified_is_confidential=True),
    )


def _mk_hit(cmd_line: str, occurrence: int = 1, classification: str | None = None) -> dict:
    doc: dict = {
        "process": {"command_line": cmd_line},
        "dshield": {"cowrie": {"enrichment": {"occurrence_count": occurrence}}},
    }
    if classification is not None:
        doc["dshield"]["classification"] = classification
    return doc


# Fixed grounding data: `wget` is curated (has flags). `cat` is tldr-only.
# `nopedoesntexist` isn't in the data at all.
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

_orig_load = gcj._load_command_data
_orig_denylist = gcj.list_denied_commands
gcj._load_command_data = lambda: _FIXED_DATA  # type: ignore[assignment]
gcj.list_denied_commands = lambda: {  # type: ignore[assignment]
    "satori": "Mirai variant identifier, not a command",
}


# -------------------------------------------------------------------------
# [1] needs_def captures unknown commands, ranked by occurrence-weighted count
# -------------------------------------------------------------------------
print("\n[1] needs_def bucketing + occurrence weighting")
hits = [
    _mk_hit("nopedoesntexist arg",         occurrence=10, classification="public"),
    _mk_hit("alsoabsent foo",              occurrence=3,  classification="public"),
    _mk_hit("nopedoesntexist another arg", occurrence=2,  classification="public"),
]
es = _fake_es_with(hits)
cfg = _fake_cfg()
out = gcj.compute_grounding_coverage(es, cfg)
check("needs_def includes nopedoesntexist and alsoabsent",
      {x["name"] for x in out["needs_def"]} == {"nopedoesntexist", "alsoabsent"})
counts = {x["name"]: x["count"] for x in out["needs_def"]}
check("occurrence_count weights aggregate", counts == {"nopedoesntexist": 12, "alsoabsent": 3},
      f"got {counts!r}")
check("needs_def sorted by count desc",
      [x["name"] for x in out["needs_def"]] == ["nopedoesntexist", "alsoabsent"])


# -------------------------------------------------------------------------
# [2] curated commands counted but omitted from the list
# -------------------------------------------------------------------------
print("\n[2] curated counted but not listed")
hits = [_mk_hit("wget -q http://x", occurrence=5, classification="public")]
es = _fake_es_with(hits)
out = gcj.compute_grounding_coverage(es, cfg)
check("wget appears in stats.curated count",
      out["stats"]["curated"] == 1, f"got curated={out['stats']['curated']}")
check("wget NOT in needs_def", not any(x["name"] == "wget" for x in out["needs_def"]))
check("wget NOT in tldr_only", not any(x["name"] == "wget" for x in out["tldr_only"]))


# -------------------------------------------------------------------------
# [3] tldr-only commands captured
# -------------------------------------------------------------------------
print("\n[3] tldr_only bucketing")
hits = [
    _mk_hit("cat /etc/passwd",   occurrence=7, classification="public"),
    _mk_hit("cat /proc/cpuinfo", occurrence=4, classification="public"),
]
es = _fake_es_with(hits)
out = gcj.compute_grounding_coverage(es, cfg)
check("cat in tldr_only with weighted count",
      any(x["name"] == "cat" and x["count"] == 11 for x in out["tldr_only"]),
      f"got tldr_only={out['tldr_only']!r}")
check("stats.tldr_only count matches", out["stats"]["tldr_only"] == 1)


# -------------------------------------------------------------------------
# [4] denylisted tokens route to `denied`, not `needs_def`
# -------------------------------------------------------------------------
print("\n[4] denylist routing")
hits = [
    _mk_hit("./satori",             occurrence=5, classification="public"),
    _mk_hit("/bin/busybox SATORI",  occurrence=3, classification="public"),
    _mk_hit("nopedoesntexist arg",  occurrence=2, classification="public"),
]
es = _fake_es_with(hits)
out = gcj.compute_grounding_coverage(es, cfg)
denied_names = {x["name"] for x in out["denied"]}
needs_def_names = {x["name"] for x in out["needs_def"]}
check("satori in denied bucket", "satori" in denied_names, f"got denied={denied_names!r}")
check("satori NOT in needs_def", "satori" not in needs_def_names)
check("denied rationale carried through",
      next((x["rationale"] for x in out["denied"] if x["name"] == "satori"), "")
      == "Mirai variant identifier, not a command")
check("denied counts aggregated (5+3=8)",
      next((x["count"] for x in out["denied"] if x["name"] == "satori"), 0) == 8)


# -------------------------------------------------------------------------
# [5] privacy gate — samples are public-only; counts aggregate everything
# -------------------------------------------------------------------------
print("\n[5] samples gated to public-only (load-bearing privacy rule)")
hits = [
    _mk_hit("nopedoesntexist --from-public",  occurrence=1, classification="public"),
    _mk_hit("nopedoesntexist --from-confidential", occurrence=1, classification="confidential"),
    _mk_hit("nopedoesntexist --from-untagged", occurrence=1, classification=None),
]
es = _fake_es_with(hits)
out = gcj.compute_grounding_coverage(es, cfg)
entry = next(x for x in out["needs_def"] if x["name"] == "nopedoesntexist")
check("count aggregates all three classifications", entry["count"] == 3,
      f"got {entry['count']}")
check("samples contain ONLY the public command line",
      entry["samples"] == ["nopedoesntexist --from-public"],
      f"got {entry['samples']!r}")
check("confidential command line never appears in samples",
      "nopedoesntexist --from-confidential" not in entry["samples"])
check("untagged command line never appears in samples (fail-safe)",
      "nopedoesntexist --from-untagged" not in entry["samples"])


# -------------------------------------------------------------------------
# [6] samples deduped + capped at samples_per_entry
# -------------------------------------------------------------------------
print("\n[6] samples dedup + cap")
hits = [
    _mk_hit("unknowncmd a", classification="public"),
    _mk_hit("unknowncmd a", classification="public"),  # exact dup — not kept twice
    _mk_hit("unknowncmd b", classification="public"),
    _mk_hit("unknowncmd c", classification="public"),
    _mk_hit("unknowncmd d", classification="public"),  # 4th distinct — beyond cap
]
es = _fake_es_with(hits)
out = gcj.compute_grounding_coverage(es, cfg)
entry = next(x for x in out["needs_def"] if x["name"] == "unknowncmd")
check("samples deduped",
      entry["samples"].count("unknowncmd a") == 1)
check("samples capped at samples_per_entry (3)", len(entry["samples"]) == 3,
      f"got {len(entry['samples'])}")


# -------------------------------------------------------------------------
# [7] empty corpus -> clean zero-state
# -------------------------------------------------------------------------
print("\n[7] empty corpus")
es = _fake_es_with([])
out = gcj.compute_grounding_coverage(es, cfg)
check("empty corpus: total_unique_cmds = 0", out["stats"]["total_unique_cmds"] == 0)
check("empty corpus: needs_def is []", out["needs_def"] == [])
check("empty corpus: doc carries generated_at", bool(out.get("generated_at")))


# -------------------------------------------------------------------------
# [8] write_grounding_coverage — single-doc write shape
# -------------------------------------------------------------------------
print("\n[8] write_grounding_coverage writes one doc at the fixed id")
es = _fake_es_with([_mk_hit("cat /etc/passwd", occurrence=1, classification="public")])
es.indices.exists.return_value = True
result = gcj.write_grounding_coverage(es, cfg)
check("write reports written=True", result.get("written") is True, str(result))
check("es.index called once", es.index.call_count == 1, f"got {es.index.call_count}")
_, kwargs = es.index.call_args
check("write targets configured index",
      kwargs.get("index") == "prism.metrics.grounding_coverage", str(kwargs.get("index")))
check("write uses the fixed doc id", kwargs.get("id") == "latest", str(kwargs.get("id")))
check("written document carries stats + buckets",
      set(kwargs.get("document", {}).keys())
      >= {"generated_at", "stats", "needs_def", "tldr_only", "denied"},
      str(kwargs.get("document", {}).keys()))


# -------------------------------------------------------------------------
# [9] write_grounding_coverage no-ops when the index doesn't exist yet
# -------------------------------------------------------------------------
print("\n[9] write_grounding_coverage — index missing")
es = MagicMock()
es.indices.exists.return_value = False
result = gcj.write_grounding_coverage(es, cfg)
check("written=False when index missing", result.get("written") is False, str(result))
check("error reason surfaced", result.get("error") == "grounding_coverage_index_missing",
      str(result))
check("no search/index call attempted", es.search.call_count == 0 and es.index.call_count == 0)


# -------------------------------------------------------------------------
# [10] Fix 4 — sample dedup compares the TRUNCATED (stored) string, not the
# full untruncated command line. Two lines sharing the same 200-char prefix
# but differing after it must not both get appended as if they were
# distinct samples.
# -------------------------------------------------------------------------
print("\n[10] Fix 4: sample dedup compares the truncated (200-char) string")
long_prefix = "cmdtrunctest " + ("x" * 250)  # > 200 chars, shared by both lines
hits = [
    _mk_hit(long_prefix + " AAA", occurrence=1, classification="public"),
    _mk_hit(long_prefix + " BBB", occurrence=1, classification="public"),
]
es = _fake_es_with(hits)
out = gcj.compute_grounding_coverage(es, cfg)
entry = next(x for x in out["needs_def"] if x["name"] == "cmdtrunctest")
check("two lines sharing a 200-char truncated prefix dedup to ONE sample",
      len(entry["samples"]) == 1,
      f"got {len(entry['samples'])} samples: {entry['samples']!r}")
check("stored sample is truncated to 200 chars",
      len(entry["samples"][0]) == 200, f"got len={len(entry['samples'][0])}")


# -------------------------------------------------------------------------
# [11] Fix 3 — total_corpus_occurrences weights once per SOURCE RECORD, not
# once per parsed sub-command. A compound line (`&&`) yields two
# (cmd, flags) tuples from parse_shell_line for the SAME record.
# -------------------------------------------------------------------------
print("\n[11] Fix 3: total_corpus_occurrences not inflated by compound commands")
hits = [_mk_hit("wget x && cat y", occurrence=5, classification="public")]
es = _fake_es_with(hits)
out = gcj.compute_grounding_coverage(es, cfg)
check("per-command counts still see the full weight (each distinct command "
      "occurring in the line counts)",
      next(x["count"] for x in out["tldr_only"] if x["name"] == "cat") == 5)
check("total_corpus_occurrences reflects ONE record's weight (5), not "
      "2x for the two sub-commands parsed out of the single line",
      out["stats"]["total_corpus_occurrences"] == 5,
      f"got {out['stats']['total_corpus_occurrences']}")


# -------------------------------------------------------------------------
# [12] Fix 2 — malformed documents are skipped, not fatal: the scan keeps
# going past a hit missing `_source`, a non-string command_line, and a
# malformed occurrence_count. Also verifies the occurrence_count edge cases:
# genuinely-absent -> defaults to 1; present-but-malformed -> skip (not
# coerced); present-and-0 -> kept as a real 0 (not silently coerced to 1).
# -------------------------------------------------------------------------
print("\n[12] Fix 2: malformed hits are skipped, scan continues past them")
raw_hits = [
    {"_source": _mk_hit("nopedoesntexist ok1", occurrence=2, classification="public"),
     "sort": ["0"]},
    {"sort": ["1"]},  # missing `_source` entirely
    {"_source": {"process": {"command_line": 12345},
                 "dshield": {"classification": "public"}},
     "sort": ["2"]},  # command_line is not a string
    {"_source": {
        "process": {"command_line": "nopedoesntexist badocc"},
        "dshield": {"cowrie": {"enrichment": {"occurrence_count": "not-a-number"}},
                    "classification": "public"},
    }, "sort": ["3"]},  # malformed occurrence_count -> skip this hit's contribution
    {"_source": {
        "process": {"command_line": "nopedoesntexist zerocount"},
        "dshield": {"cowrie": {"enrichment": {"occurrence_count": 0}},
                    "classification": "public"},
    }, "sort": ["4"]},  # occurrence_count present and genuinely 0 -> kept as 0
    {"_source": {
        "process": {"command_line": "nopedoesntexist noocc"},
        "dshield": {"classification": "public"},
    }, "sort": ["5"]},  # occurrence_count genuinely absent -> defaults to 1
    {"_source": _mk_hit("nopedoesntexist ok2", occurrence=3, classification="public"),
     "sort": ["6"]},
]
es = _fake_es_pages([raw_hits])
out = gcj.compute_grounding_coverage(es, cfg)
entry = next(x for x in out["needs_def"] if x["name"] == "nopedoesntexist")
# ok1(2) + badocc(skipped, contributes 0) + zerocount(0) + noocc(defaults to 1) + ok2(3) = 6
check("scan survives missing-_source/non-string-command_line/malformed-occurrence "
      "hits and keeps counting the valid ones",
      entry["count"] == 6, f"got {entry['count']}")
check("total_corpus_occurrences matches the same per-record weighting",
      out["stats"]["total_corpus_occurrences"] == 6,
      f"got {out['stats']['total_corpus_occurrences']}")


# -------------------------------------------------------------------------
# [13] Fix 2 — a page whose last hit is missing the `sort` cursor ends the
# scan cleanly (treated as end-of-scan) instead of raising KeyError.
# -------------------------------------------------------------------------
print("\n[13] Fix 2: missing `sort` cursor on the last hit ends the scan, not KeyError")
page_missing_sort = [
    {"_source": _mk_hit("nopedoesntexist onlyhit", occurrence=1, classification="public")},
    # no "sort" key on this hit at all
]
es = _fake_es_pages([page_missing_sort])
raised_keyerror = False
out = None
try:
    out = gcj.compute_grounding_coverage(es, cfg)
except KeyError:
    raised_keyerror = True
check("no KeyError when the last hit lacks a sort cursor", not raised_keyerror)
check("scan stops after the page missing a cursor (search called once, no infinite loop)",
      es.search.call_count == 1, f"got {es.search.call_count}")
if out is not None:
    entry = next((x for x in out["needs_def"] if x["name"] == "nopedoesntexist"), None)
    check("the page's own hit is still processed before the scan ends",
          entry is not None and entry["count"] == 1, f"got {entry!r}")


# -------------------------------------------------------------------------
# [14] Fix 1 — a scan failure (e.g. transient ES error partway through a
# multi-page scan) must propagate as a hard failure: compute_grounding_
# coverage raises, and write_grounding_coverage must NOT call es.index()
# (the last-good report doc is left untouched) and must report failure.
# -------------------------------------------------------------------------
print("\n[14] Fix 1: scan failure propagates; write does not overwrite the last-good doc")
page1 = [
    {"_source": _mk_hit("nopedoesntexist page1", occurrence=1, classification="public"),
     "sort": ["0"]},
]

es = MagicMock()
es.search.side_effect = [{"hits": {"hits": page1}}, RuntimeError("simulated ES timeout")]
raised = False
try:
    gcj.compute_grounding_coverage(es, cfg)
except RuntimeError:
    raised = True
except Exception as exc:  # pragma: no cover -- would indicate a regression
    check("compute_grounding_coverage propagates the ORIGINAL exception type", False,
          f"got {type(exc).__name__}: {exc}")
check("compute_grounding_coverage propagates a scan failure (page 1 ok, page 2 raises) "
      "instead of silently truncating the run", raised)

es2 = MagicMock()
es2.indices.exists.return_value = True
es2.search.side_effect = [{"hits": {"hits": page1}}, RuntimeError("simulated ES timeout")]
result = gcj.write_grounding_coverage(es2, cfg)
check("write_grounding_coverage reports failure (non-empty error) instead of success",
      bool(result.get("error")), str(result))
check("write_grounding_coverage signals written=False on scan failure",
      result.get("written") is False, str(result))
check("write_grounding_coverage never calls es.index() when the scan fails — "
      "the last-good report doc at the fixed id is left untouched",
      es2.index.call_count == 0, f"got {es2.index.call_count} index() call(s)")


# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------
gcj._load_command_data = _orig_load  # type: ignore[assignment]
gcj.list_denied_commands = _orig_denylist  # type: ignore[assignment]


print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
