"""Smoke test for E3's targeted eval-set build (`scripts/build_eval_set.py`).

Covers the candidate-file parser, the append-dedupe guard, and the channel plumbing
onto the emitted record. No live ES, no network.
"""
from __future__ import annotations

import gzip
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from build_eval_set import (
    _fetch_rollups_by_ids,
    existing_session_ids,
    read_session_id_channels,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


print("--- read_session_id_channels ---")
with tempfile.TemporaryDirectory() as d:
    p = Path(d) / "cands.txt"
    p.write_text(
        "# rare-label candidates\n"
        "aaa\tpredicate\n"
        "bbb\tevent\n"
        "\n"
        "   ccc   \n"
        "ddd\t\n"
        "  # indented comment\n",
    )
    got = read_session_id_channels(p)
    check("tab-separated channel is parsed",
          got.get("aaa") == "predicate" and got.get("bbb") == "event", str(got))
    check("a bare id defaults to 'unspecified', it is not dropped",
          got.get("ccc") == "unspecified", str(got))
    check("an empty channel field also defaults", got.get("ddd") == "unspecified", str(got))
    check("comments and blank lines are skipped", len(got) == 4, str(got))
    check("surrounding whitespace is stripped", "ccc" in got, str(got.keys()))

    empty = Path(d) / "empty.txt"
    empty.write_text("")
    check("an empty file yields no candidates", read_session_id_channels(empty) == {})

print("\n--- existing_session_ids (the --append join guard) ---")
with tempfile.TemporaryDirectory() as d:
    out = Path(d) / "sessions.jsonl.gz"
    check("a missing set is empty, not an error", existing_session_ids(out) == set())
    with gzip.open(out, "wt") as fh:
        fh.write(json.dumps({"session_id": "aaa"}) + "\n")
        fh.write("\n")  # blank line tolerated
        fh.write(json.dumps({"session_id": "bbb"}) + "\n")
        fh.write(json.dumps({"no_session_id": 1}) + "\n")
    check("existing ids are read back", existing_session_ids(out) == {"aaa", "bbb"},
          str(existing_session_ids(out)))

    plain = Path(d) / "sessions.jsonl"
    plain.write_text(json.dumps({"session_id": "ccc"}) + "\n")
    check("the plain (non-gz) spelling is also read",
          existing_session_ids(plain) == {"ccc"}, str(existing_session_ids(plain)))

print("\n--- _fetch_rollups_by_ids ---")


class FakeES:
    def __init__(self) -> None:
        self.queries: list[dict] = []

    def search(self, index=None, size=None, query=None):
        self.queries.append(query)
        ids = query["bool"]["filter"][0]["terms"]["cowrie.session_id"]
        # 'ghost' is requested but does not exist in the index
        return {"hits": {"hits": [
            {"_source": {"cowrie": {"session_id": i}}} for i in ids if i != "ghost"
        ]}}


es = FakeES()
rows = _fetch_rollups_by_ids(es, "rollup", ["aaa", "ghost", "bbb"])
check("returns a rollup per found id", len(rows) == 2, str(rows))
check("a missing id is silently absent, not an exception",
      {r["cowrie"]["session_id"] for r in rows} == {"aaa", "bbb"}, str(rows))
check("reads by the cowrie.session_id FIELD, never the namespaced _id",
      "cowrie.session_id" in es.queries[0]["bool"]["filter"][0]["terms"], str(es.queries[0]))
check("an empty id list makes no query",
      _fetch_rollups_by_ids(FakeES(), "rollup", []) == [])
check("blank ids are filtered out before querying",
      _fetch_rollups_by_ids(FakeES(), "rollup", ["", None]) == [])

es2 = FakeES()
_fetch_rollups_by_ids(es2, "rollup", [f"s{i}" for i in range(2500)], page=1000)
check("pages large id lists rather than one oversized terms query",
      len(es2.queries) == 3, f"{len(es2.queries)} queries")

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
