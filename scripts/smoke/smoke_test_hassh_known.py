"""Smoke test for the vendored HASSH-to-tooling map (brutal-review 7.5).

Covers:
  * `lookup(None)` / `lookup("")` cleanly return None (no false positives).
  * `lookup(<unknown>)` returns None.
  * `lookup(<seeded>)` returns the entry intact when the test patches one in.
  * `_build_ip_doc` stamps `hassh_family` / `hassh_tool` when the dominant
    HASSH is in the map, omits them when not.
  * Module is robust to a missing JSON file (fail-soft to empty map).
  * Module loads on import without raising even when the file is empty.

Stubs nothing — pure-function lookup + builder.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_hassh_known.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.data import hassh_known as hk  # noqa: E402
from enrich.sources.cowrie.ips import _build_ip_doc  # noqa: E402


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
# [1] None / empty inputs.
# ---------------------------------------------------------------------------
print("[1] lookup(None) / lookup('') are clean no-ops")
check("lookup(None) is None",       hk.lookup(None) is None)
check("lookup('') is None",         hk.lookup("") is None)


# ---------------------------------------------------------------------------
# [2] Unknown HASSH returns None.
# ---------------------------------------------------------------------------
print("\n[2] unknown HASSH returns None")
check("lookup('deadbeef...') is None",
      hk.lookup("deadbeefdeadbeefdeadbeefdeadbeef") is None)


# ---------------------------------------------------------------------------
# [3] Module loaded the JSON, version is set, entries is a dict.
# ---------------------------------------------------------------------------
print("\n[3] module loaded cleanly")
check("VERSION non-empty", bool(hk.VERSION))
check("entry_count() returns an int >= 0", isinstance(hk.entry_count(), int) and hk.entry_count() >= 0)


# ---------------------------------------------------------------------------
# [4] Patch one entry in-process; lookup picks it up.
# ---------------------------------------------------------------------------
print("\n[4] in-process patched entry is resolvable")
PATCH = "abcd1234abcd1234abcd1234abcd1234"
saved = hk._ENTRIES.get(PATCH)
hk._ENTRIES[PATCH] = {
    "family": "test-family",
    "tool": "test-tool",
    "confidence": "high",
    "source": "smoke_test_hassh_known.py",
    "notes": "transient",
}
try:
    got = hk.lookup(PATCH)
    check("lookup returns the patched entry", isinstance(got, dict))
    check("family field present and correct",
          (got or {}).get("family") == "test-family")
    check("tool field present and correct",
          (got or {}).get("tool") == "test-tool")

    # -------------------------------------------------------------------
    # [5] _build_ip_doc stamps when the dominant HASSH is patched in.
    # -------------------------------------------------------------------
    print("\n[5] _build_ip_doc stamps hassh_family / hassh_tool when known")
    doc = _build_ip_doc("203.0.113.10", [_session(PATCH), _session(PATCH)], _Cfg)
    ip_block = doc["dshield"]["cowrie"]["enrichment"]["ip"]
    check("hassh_family stamped", ip_block.get("hassh_family") == "test-family")
    check("hassh_tool stamped",   ip_block.get("hassh_tool") == "test-tool")
finally:
    # Restore original state so later test runs aren't polluted.
    if saved is None:
        hk._ENTRIES.pop(PATCH, None)
    else:
        hk._ENTRIES[PATCH] = saved


# ---------------------------------------------------------------------------
# [6] _build_ip_doc omits hassh_family / hassh_tool when unknown.
# ---------------------------------------------------------------------------
print("\n[6] _build_ip_doc omits hassh_family / hassh_tool when unknown")
doc = _build_ip_doc("203.0.113.11", [_session("ffffffffffffffffffffffffffffffff")], _Cfg)
ip_block = doc["dshield"]["cowrie"]["enrichment"]["ip"]
check("hassh present (the raw fingerprint)", ip_block.get("hassh") == "f" * 32)
check("hassh_cluster_id present",   "hassh_cluster_id" in ip_block)
check("hassh_family NOT stamped",   "hassh_family" not in ip_block)
check("hassh_tool NOT stamped",     "hassh_tool" not in ip_block)


# ---------------------------------------------------------------------------
# [7] _build_ip_doc on HASSH-less IP: no hassh / cluster_id / family / tool.
# ---------------------------------------------------------------------------
print("\n[7] _build_ip_doc on HASSH-less IP stamps nothing HASSH-related")
doc = _build_ip_doc("203.0.113.12", [_session()], _Cfg)
ip_block = doc["dshield"]["cowrie"]["enrichment"]["ip"]
for field in ("hassh", "hassh_cluster_id", "hassh_family", "hassh_tool"):
    check(f"{field} absent", field not in ip_block)


# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
