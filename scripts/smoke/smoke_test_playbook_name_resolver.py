"""Smoke test for the playbook-name bucket parser
(`console.queries._names_from_pb_buckets`) — the pure half of the post-cutover name
resolver that reads `playbook_name` from the session rollup instead of the (now sparse)
session-cluster centroids.

Standalone — no ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))

from console.queries import _names_from_pb_buckets

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


def _bucket(pid, name):
    b = {"key": pid}
    if name is not None:
        b["name"] = {"buckets": [{"key": name, "doc_count": 9}]}
    return b


# modal playbook_name per playbook_id bucket
out = _names_from_pb_buckets([_bucket("spb-A", "Mirai Loader"), _bucket("spb-B", "SSH Key Persist")])
check("maps each playbook_id to its modal name",
      out == {"spb-A": "Mirai Loader", "spb-B": "SSH Key Persist"}, str(out))

# a playbook whose sessions have no name (all novel/null) → dropped, not ""
out2 = _names_from_pb_buckets([_bucket("spb-A", "Mirai Loader"), _bucket("spb-novel", None)])
check("playbook with no named session is omitted (not blank)",
      out2 == {"spb-A": "Mirai Loader"}, str(out2))

# empty name sub-agg bucket list → omitted
out3 = _names_from_pb_buckets([{"key": "spb-X", "name": {"buckets": []}}])
check("empty name sub-agg → omitted", out3 == {}, str(out3))

# empty / no key
check("empty input → {}", _names_from_pb_buckets([]) == {})
check("bucket without key → skipped", _names_from_pb_buckets([{"name": {"buckets": [{"key": "x"}]}}]) == {})

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
