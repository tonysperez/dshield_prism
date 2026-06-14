"""History 'Standout' ranking lens — pure `_rank_standout` logic.

The History page surfaces *salient* (not high-volume) behaviours, and the analyst
flips between two lenses:
  * `novel`       — by novelty alone; the anomalous one-off ranks highest.
  * `novel_reach` — by novelty x log1p(distinct_ips); a slightly-less-novel but
    far more widespread behaviour outranks the one-off.

Asserts the lens actually flips the order, that reach is driven by distinct-IPs
(not session count), the limit truncates, names map on, and keyless buckets are
dropped. Standalone — no ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))

from console.queries import _rank_standout

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED.append(name) if ok else FAILED.append((name, detail)))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  {detail}"))


def _bucket(pid, novelty, ips, sessions=1):
    return {
        "key": pid, "doc_count": sessions,
        "novelty": {"value": novelty}, "ips": {"value": ips},
        "first": {"value_as_string": "2023-01-01T00:00:00Z"},
        "last": {"value_as_string": "2023-06-01T00:00:00Z"},
    }


# A: very novel one-off; B: slightly less novel but widespread; C: midrange.
buckets = [
    _bucket("spb-A", 0.95, 1, sessions=2),
    _bucket("spb-B", 0.80, 500, sessions=1800),
    _bucket("spb-C", 0.50, 10, sessions=40),
]
names = {"spb-A": "weird one-off", "spb-B": "widespread botnet", "spb-C": "midrange"}

print("\n[1] novel lens — novelty alone")
nov = _rank_standout(buckets, "novel", names, 12)
check("most-novel one-off ranks first", nov[0]["playbook_id"] == "spb-A",
      str([r["playbook_id"] for r in nov]))
check("order is A,B,C by novelty",
      [r["playbook_id"] for r in nov] == ["spb-A", "spb-B", "spb-C"])

print("\n[2] novel_reach lens — novelty x log1p(distinct_ips)")
reach = _rank_standout(buckets, "novel_reach", names, 12)
check("widespread B outranks the one-off A", reach[0]["playbook_id"] == "spb-B",
      str([r["playbook_id"] for r in reach]))
check("the lens flips the top result vs novel",
      reach[0]["playbook_id"] != nov[0]["playbook_id"])

print("\n[3] reach is distinct-IPs, not session count")
b2 = [_bucket("spb-noisy", 0.7, 1, sessions=9999),
      _bucket("spb-spread", 0.7, 300, sessions=300)]
r2 = _rank_standout(b2, "novel_reach", {}, 12)
check("spread (many IPs) beats noisy (one IP, many sessions)",
      r2[0]["playbook_id"] == "spb-spread", str([r["playbook_id"] for r in r2]))

print("\n[4] hygiene")
check("limit truncates", len(_rank_standout(buckets, "novel", names, 2)) == 2)
check("name maps onto rows", nov[0]["name"] == "weird one-off")
check("keyless / empty buckets dropped",
      len(_rank_standout([{"key": None}, {"novelty": {"value": 1}}], "novel", {}, 12)) == 0)
check("unknown sort falls back to a valid ranking (no crash)",
      len(_rank_standout(buckets, "bogus", names, 12)) == 3)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
