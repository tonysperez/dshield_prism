"""Smoke test for the refresh-eval-taxonomy script (`scripts/refresh_eval_taxonomy.py`):
`_collect_hashes`, `_refresh_cluster_tokens`, and `_refresh_one` (with
`pull_hash_to_cluster` monkeypatched — real ES/`es` argument is never touched).
No live ES, no real eval files.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

import refresh_eval_taxonomy
from refresh_eval_taxonomy import _collect_hashes, _refresh_cluster_tokens, _refresh_one

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


def _ce(short_hash: str) -> dict:
    return {"event": {"id": short_hash}, "dshield": {"cowrie": {"enrichment": {
        "cluster": {"id": "stale_cluster_id", "is_outlier": False},
    }}}}


# --- _collect_hashes ---
records = [
    {"command_enrichments": [_ce("aaaa"), _ce("bbbb")]},
    {"command_enrichments": [_ce("bbbb"), {"event": {}}]},
    {"command_enrichments": []},
    {},
]
check("collect_hashes dedupes across records and ignores missing event.id",
      _collect_hashes(records) == {"aaaa", "bbbb"}, str(_collect_hashes(records)))
check("collect_hashes on no records is empty", _collect_hashes([]) == set())

# --- _refresh_cluster_tokens: hash resolves to a live cluster ---
ces = [_ce("aaaa")]
stats = _refresh_cluster_tokens(ces, {"aaaa": "17"})
cluster = ces[0]["dshield"]["cowrie"]["enrichment"]["cluster"]
check("resolved hash gets fresh cluster id", cluster["id"] == "17", str(cluster))
check("resolved hash is_outlier False", cluster["is_outlier"] is False, str(cluster))
check("resolved hash counted as refreshed", stats == {"refreshed": 1, "cleared": 0, "missing_hash": 0}, str(stats))

# --- hash currently an outlier ---
ces = [_ce("aaaa")]
stats = _refresh_cluster_tokens(ces, {"aaaa": "cluster_outlier"})
cluster = ces[0]["dshield"]["cowrie"]["enrichment"]["cluster"]
check("outlier hash gets cluster_outlier id", cluster["id"] == "cluster_outlier", str(cluster))
check("outlier hash is_outlier True", cluster["is_outlier"] is True, str(cluster))

# --- hash not in the public-only map: stale cluster block is cleared, not left stale ---
ces = [_ce("aaaa")]
stats = _refresh_cluster_tokens(ces, {})
enrichment = ces[0]["dshield"]["cowrie"]["enrichment"]
check("unresolved hash clears the stale cluster block", "cluster" not in enrichment, str(enrichment))
check("unresolved hash counted as cleared", stats == {"refreshed": 0, "cleared": 1, "missing_hash": 0}, str(stats))

# --- command-enrichment record with no event.id: left untouched, counted as missing_hash ---
malformed = {"event": {}, "dshield": {"cowrie": {"enrichment": {
    "cluster": {"id": "stale_cluster_id", "is_outlier": False},
}}}}
ces = [malformed]
stats = _refresh_cluster_tokens(ces, {"aaaa": "17"})
cluster = ces[0]["dshield"]["cowrie"]["enrichment"]["cluster"]
check("malformed record's stale cluster block is left untouched",
      cluster == {"id": "stale_cluster_id", "is_outlier": False}, str(cluster))
check("malformed record counted as missing_hash",
      stats == {"refreshed": 0, "cleared": 0, "missing_hash": 1}, str(stats))

# --- mixed batch: every other field on a resolved record stays untouched ---
mixed = _ce("aaaa")
mixed["process"] = {"command_line": "cd ~"}
stats = _refresh_cluster_tokens([mixed], {"aaaa": "9"})
check("unrelated fields on the enrichment survive the refresh",
      mixed["process"] == {"command_line": "cd ~"}, str(mixed))

# --- non-dict nested enrichment shape doesn't crash setdefault-style access ---
corrupt = {"event": {"id": "aaaa"}, "dshield": "not-a-dict"}
stats = _refresh_cluster_tokens([corrupt], {"aaaa": "9"})
check("non-dict dshield value is replaced rather than raising",
      corrupt["dshield"]["cowrie"]["enrichment"]["cluster"]["id"] == "9", str(corrupt))
check("non-dict dshield value still counts as refreshed",
      stats == {"refreshed": 1, "cleared": 0, "missing_hash": 0}, str(stats))


def _write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


# --- _refresh_one: missing JSONL path is a no-op, not an error ---
with tempfile.TemporaryDirectory() as tmp:
    missing = Path(tmp) / "does-not-exist.jsonl"
    stats = _refresh_one(object(), "commands-idx", missing, filt=[])
    check("missing JSONL path returns zero stats",
          stats == {"refreshed": 0, "cleared": 0, "missing_hash": 0}, str(stats))
    check("missing JSONL path is not created", not missing.exists())

# --- _refresh_one: taxonomy fetch returns empty against a non-empty hash set
# --- refuses to write rather than silently clearing every command's cluster ---
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / "sessions.jsonl"
    original = [{"session_id": "s1", "command_enrichments": [_ce("aaaa")]}]
    _write_jsonl(path, original)
    before = path.read_text()
    refresh_eval_taxonomy.pull_hash_to_cluster = lambda *a, **k: {}
    try:
        stats = _refresh_one(object(), "commands-idx", path, filt=[])
    finally:
        del refresh_eval_taxonomy.pull_hash_to_cluster
    check("empty taxonomy against non-empty hashes aborts (refreshed=0)",
          stats.get("refreshed") == 0 and stats.get("aborted") == 1, str(stats))
    check("aborted refresh leaves the fixture byte-identical",
          path.read_text() == before, "file was modified despite abort")

# --- _refresh_one: normal path resolves + clears + writes back atomically ---
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / "sessions.jsonl"
    original = [
        {"session_id": "s1", "command_enrichments": [_ce("aaaa")]},
        {"session_id": "s2", "command_enrichments": [_ce("bbbb")]},
    ]
    _write_jsonl(path, original)
    refresh_eval_taxonomy.pull_hash_to_cluster = lambda *a, **k: {"aaaa": "17"}
    try:
        stats = _refresh_one(object(), "commands-idx", path, filt=[{"term": {}}])
    finally:
        del refresh_eval_taxonomy.pull_hash_to_cluster
    check("normal run refreshes the resolved hash and clears the unresolved one",
          stats == {"refreshed": 1, "cleared": 1, "missing_hash": 0}, str(stats))
    written = [json.loads(line) for line in path.read_text().splitlines()]
    written_ce0 = written[0]["command_enrichments"][0]
    written_ce1 = written[1]["command_enrichments"][0]
    check("write-back persists the refreshed id",
          written_ce0["dshield"]["cowrie"]["enrichment"]["cluster"]["id"] == "17",
          str(written_ce0))
    check("write-back persists the cleared block's removal",
          "cluster" not in written_ce1["dshield"]["cowrie"]["enrichment"],
          str(written_ce1))
    check("no leftover .tmp file after a successful write",
          not path.with_suffix(path.suffix + ".tmp").exists())

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
