"""Smoke test for `hassh_cluster_id` (brutal-review 7.4).

Covers the pure id-derivation in isolation:
  * Same dominant + same seen set → same id (counts irrelevant).
  * Different dominant on same seen set → different id.
  * New HASSH appearing in the distribution → different id (re-keys).
  * Single-fingerprint IPs grouping correctly.
  * `_build_ip_doc` stamps the field when HASSH was seen, and omits it
    when no HASSH was observed.
  * Id format is `hcl-<16hex>`.

Stubs nothing — the helper + builder are pure functions.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_hassh_cluster.py
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.ips import (
    _build_ip_doc,
    _hassh_cluster_id,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _Cfg:
    class ip:
        embed_version = "test-v1"


def _session(hassh: str | None = None) -> dict:
    """Minimal session-rollup doc shape `_build_ip_doc` consumes."""
    doc: dict = {
        "event": {"start": "2026-05-30T00:00:00Z", "end": "2026-05-30T00:01:00Z"},
        "dshield": {"cowrie": {"enrichment": {"session": {
            "command_count": 1, "login_success_count": 0,
        }}}},
    }
    if hassh:
        doc["cowrie"] = {"hassh": hassh}
    return doc


# ---------------------------------------------------------------------------
# [1] Counts don't change the id when the set is unchanged.
# ---------------------------------------------------------------------------
print("[1] counts don't affect id when seen-set is unchanged")
a = _hassh_cluster_id(Counter({"H1": 1}))
b = _hassh_cluster_id(Counter({"H1": 50}))
check("same dominant + same set → same id (regardless of count)",
      a == b, f"a={a} b={b}")

c = _hassh_cluster_id(Counter({"H1": 3, "H2": 1}))
d = _hassh_cluster_id(Counter({"H1": 10, "H2": 2}))
check("counts scale but set/dominant stable → same id",
      c == d, f"c={c} d={d}")


# ---------------------------------------------------------------------------
# [2] New HASSH appearing in the distribution re-keys.
# ---------------------------------------------------------------------------
print("\n[2] new HASSH in the seen set re-keys")
e = _hassh_cluster_id(Counter({"H1": 5}))
f = _hassh_cluster_id(Counter({"H1": 5, "H2": 1}))
check("adding a never-seen HASSH changes the id",
      e != f, f"e={e} f={f}")


# ---------------------------------------------------------------------------
# [3] Dominant shift re-keys even on same seen-set.
# ---------------------------------------------------------------------------
print("\n[3] dominant shift on the same seen-set re-keys")
g = _hassh_cluster_id(Counter({"H1": 10, "H2": 3}))   # dom = H1
h = _hassh_cluster_id(Counter({"H1": 3,  "H2": 10}))  # dom = H2
check("flipping which HASSH is modal changes the id",
      g != h, f"g={g} h={h}")


# ---------------------------------------------------------------------------
# [4] Single-fingerprint IPs sharing a HASSH cluster.
# ---------------------------------------------------------------------------
print("\n[4] single-fingerprint IPs sharing a HASSH cluster together")
ip_a = _hassh_cluster_id(Counter({"H1": 4}))
ip_b = _hassh_cluster_id(Counter({"H1": 1}))
ip_c = _hassh_cluster_id(Counter({"H2": 7}))
check("two single-HASSH IPs sharing the fingerprint → same id", ip_a == ip_b)
check("different single HASSH → different id", ip_a != ip_c)


# ---------------------------------------------------------------------------
# [5] Id format check.
# ---------------------------------------------------------------------------
print("\n[5] id format is hcl-<16hex>")
pattern = re.compile(r"^hcl-[0-9a-f]{16}$")
check("id matches hcl-<16hex>", bool(pattern.match(ip_a)), ip_a)


# ---------------------------------------------------------------------------
# [6] `_build_ip_doc` writes the field when HASSH was seen.
# ---------------------------------------------------------------------------
print("\n[6] _build_ip_doc stamps hassh_cluster_id when HASSH was seen")
doc = _build_ip_doc("203.0.113.1", [_session("H1"), _session("H1"), _session("H2")], _Cfg)
ip_block = doc["dshield"]["cowrie"]["enrichment"]["ip"]
check("ip_block has hassh_cluster_id", "hassh_cluster_id" in ip_block)
check("hassh_cluster_id matches the helper output",
      ip_block["hassh_cluster_id"] == _hassh_cluster_id(Counter({"H1": 2, "H2": 1})),
      ip_block.get("hassh_cluster_id"))


# ---------------------------------------------------------------------------
# [7] `_build_ip_doc` omits the field when no HASSH was observed.
# ---------------------------------------------------------------------------
print("\n[7] _build_ip_doc omits hassh_cluster_id on HASSH-less IPs")
doc = _build_ip_doc("203.0.113.2", [_session(), _session()], _Cfg)
ip_block = doc["dshield"]["cowrie"]["enrichment"]["ip"]
check("ip_block has no hassh_cluster_id when no HASSH",
      "hassh_cluster_id" not in ip_block)
check("ip_block has no hassh when no HASSH",
      "hassh" not in ip_block)


# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
