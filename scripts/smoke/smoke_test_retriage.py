"""Smoke test for ROADMAP #23 follow-on: `re-triage --backward`.

`re-enrich-stale` doesn't pick up triage-rule changes because `triage.py`
lives outside `llm_config_hash`. So after #23 tightened the `base64_blob`
gate, historical docs kept their stale `base64_blob` entries. `re-triage`
closes that gap: walks the enriched-commands index, re-runs
`reasons_to_escalate` with current rules using a deterministic rng, and
rewrites `triage_reasons` while preserving non-reproducible runtime
reasons (budget_exhausted / cloud_failed / cloud_parse_failed / sample).

Standalone — no real ES, no pytest. Stubs the ES client and exercises
the diff semantics + bulk update shape.

What this asserts:
  1. Rule-only diff: a stored `base64_blob` reason on a doc whose command
     contains only a hex digest (post-#23) gets removed.
  2. Real base64 keeps `base64_blob`.
  3. Runtime-only reasons (budget_exhausted, cloud_failed, sample) are
     PRESERVED across re-triage even though current rules wouldn't
     reproduce them.
  4. The deterministic rng suppresses the random `sample` rule on
     re-runs (so re-triage is idempotent).
  5. Empty result removes the `triage_reasons` field entirely (via the
     RETRIAGE_SCRIPT's null/empty branch).
  6. Window filter passes through to the iterator query.
  7. Dry-run path doesn't issue bulk writes.
  8. `_strip_rule_reasons` filters by both exact match and the
     `low_confidence<=N` prefix.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_retriage.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.commands import (
    _RETRIAGE_SCRIPT,
    _RULE_DERIVED_REASONS,
    _RUNTIME_ONLY_REASONS,
    _strip_rule_reasons,
    run_retriage,
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
# [1] _strip_rule_reasons — drops rule-derived, keeps runtime-only.
# -----------------------------------------------------------------------------
print("\n[1] _strip_rule_reasons unit tests")
check(
    "drops base64_blob",
    _strip_rule_reasons(["base64_blob"]) == [],
    "",
)
check(
    "drops low_confidence<=4 (prefix match)",
    _strip_rule_reasons(["low_confidence<=4"]) == [],
    "",
)
check(
    "preserves budget_exhausted",
    _strip_rule_reasons(["budget_exhausted"]) == ["budget_exhausted"],
    "",
)
check(
    "preserves sample",
    _strip_rule_reasons(["sample"]) == ["sample"],
    "",
)
check(
    "mixed: keeps runtime, drops rules",
    sorted(_strip_rule_reasons([
        "base64_blob", "budget_exhausted", "low_confidence<=4",
        "sample", "ip_literal", "cloud_failed",
    ])) == sorted(["budget_exhausted", "sample", "cloud_failed"]),
    "",
)
check(
    "rule and runtime constants don't overlap",
    set(_RULE_DERIVED_REASONS) & set(_RUNTIME_ONLY_REASONS) == set(),
    "",
)


# -----------------------------------------------------------------------------
# Stub infrastructure for [2]+ end-to-end runs of run_retriage.
# -----------------------------------------------------------------------------
class _StubIndices:
    def __init__(self) -> None:
        self.refreshes: list[str] = []
    def exists(self, *, index: str) -> bool:
        return True
    def refresh(self, *, index: str) -> None:
        self.refreshes.append(index)


class _StubES:
    """Minimal ES double. `search` pages a fixed list of synthetic docs;
    `bulk` (called via elasticsearch.helpers.bulk_write) is intercepted by
    monkey-patching that helper. mget is a noop because run_retriage
    doesn't call it."""
    def __init__(self, docs: list[dict]) -> None:
        self.indices = _StubIndices()
        self._docs = docs
        self.searches: list[dict] = []
        self._yielded = 0

    def search(self, **kwargs):
        self.searches.append(kwargs)
        # First call: return everything; subsequent: empty (terminate loop).
        if self._yielded >= len(self._docs):
            return {"hits": {"hits": []}}
        hits = [
            {"_id": d["_id"], "_source": d["_source"], "sort": [d["_id"]]}
            for d in self._docs
        ]
        self._yielded = len(self._docs)
        return {"hits": {"hits": hits}}


def _build_cfg():
    """Minimal AppConfig that satisfies run_retriage's needs."""
    from enrich.config import AppConfig
    return AppConfig.model_validate({
        "elasticsearch": {
            "hosts": ["http://stub"],
            "indexes": {
                "cowrie": {
                    "sessions_raw":     "raw",
                    "commands":         "cmds",
                    "command_clusters": "clusters",
                    "sessions_rollup":  "sess",
                    "session_clusters": "sclusters",
                    "ips_rollup":       "ips",
                    "ip_clusters":      "iclusters",
                    "campaigns":        "campaigns",
                },
            },
        },
        "worker": {"state_db": "/tmp/_retriage_test_state.sqlite"},
        "llm": {"base_url": "http://stub", "generation_model": "x", "embedding_model": "y"},
        "prompts": {"command_enrichment": "config/prompts/command_enrichment.txt"},
        "cloud": {"api_key_env": "FOO"},
    })


def _doc(doc_id: str, cmd: str, confidence: int,
         triage_reasons: list[str] | None = None,
         embedding: list[float] | None = None,
         intent: str = "execution") -> dict:
    src = {
        "process": {"command_line": cmd},
        "dshield": {"cowrie": {"enrichment": {
            "confidence": confidence,
            "intent": intent,
        }}},
    }
    en = src["dshield"]["cowrie"]["enrichment"]
    if triage_reasons is not None:
        en["triage_reasons"] = triage_reasons
    if embedding is not None:
        en["embedding"] = embedding
    return {"_id": doc_id, "_source": src}


# -----------------------------------------------------------------------------
# Intercept bulk_write and make_client + load_centroids so the function runs
# end-to-end without ES.
# -----------------------------------------------------------------------------
import enrich.sources.cowrie.commands as commands_mod
import enrich.clustering as clustering_mod

_captured_bulk: list[dict] = []
_orig_bulk_write = commands_mod.bulk_write
_orig_make_client = commands_mod.make_client
_orig_load_centroids = clustering_mod.load_centroids


def _stub_bulk_write(es, index, actions):
    _captured_bulk.extend(actions)
    return len(actions), []


def _stub_load_centroids(es, idx, *, reference_source=None):
    return []


# -----------------------------------------------------------------------------
# [2] base64_blob with hex-only command → reason gets removed.
# -----------------------------------------------------------------------------
print("\n[2] hex digest tagged as base64_blob → removed by re-triage")
HEX_200 = ("abcdef0123456789" * 13)[:200]  # 200 chars, no uppercase
stub_docs = [_doc("d1", f"sha256: {HEX_200}", confidence=7,
                  triage_reasons=["base64_blob"])]
es_stub = _StubES(stub_docs)
commands_mod.bulk_write = _stub_bulk_write
commands_mod.make_client = lambda *a, **kw: es_stub
clustering_mod.load_centroids = _stub_load_centroids
_captured_bulk.clear()
try:
    stats = run_retriage(_build_cfg(), None, dry_run=False)
finally:
    commands_mod.bulk_write = _orig_bulk_write
    commands_mod.make_client = _orig_make_client
    clustering_mod.load_centroids = _orig_load_centroids

check(
    "scanned=1 changed=1 unchanged=0",
    stats["scanned"] == 1 and stats["changed"] == 1 and stats["unchanged"] == 0,
    f"got {stats}",
)
check(
    "base64_blob counted in removed_by_rule",
    stats["removed_by_rule"].get("base64_blob") == 1,
    f"got {stats['removed_by_rule']}",
)
check(
    "1 bulk update queued",
    len(_captured_bulk) == 1,
    f"got {_captured_bulk}",
)
check(
    "update script is _RETRIAGE_SCRIPT",
    _captured_bulk[0]["script"]["source"] == _RETRIAGE_SCRIPT,
    "",
)
check(
    "update params: triage_reasons is empty list (script removes field)",
    _captured_bulk[0]["script"]["params"]["triage_reasons"] == [],
    f"got {_captured_bulk[0]['script']['params']}",
)


# -----------------------------------------------------------------------------
# [3] Real base64 keeps base64_blob — no change.
# -----------------------------------------------------------------------------
print("\n[3] real base64 keeps base64_blob → unchanged")
real_b64 = "Aa9" + ("ABCdef012345" * 17)  # 207 chars, mixed
stub_docs = [_doc("d2", f"echo {real_b64} | base64 -d", confidence=7,
                  triage_reasons=["base64_blob"])]
es_stub = _StubES(stub_docs)
commands_mod.bulk_write = _stub_bulk_write
commands_mod.make_client = lambda *a, **kw: es_stub
clustering_mod.load_centroids = _stub_load_centroids
_captured_bulk.clear()
try:
    stats = run_retriage(_build_cfg(), None, dry_run=False)
finally:
    commands_mod.bulk_write = _orig_bulk_write
    commands_mod.make_client = _orig_make_client
    clustering_mod.load_centroids = _orig_load_centroids

check(
    "unchanged=1, no update queued",
    stats["unchanged"] == 1 and stats["changed"] == 0 and _captured_bulk == [],
    f"got {stats} captured={_captured_bulk}",
)


# -----------------------------------------------------------------------------
# [4] Runtime-only reasons preserved.
# -----------------------------------------------------------------------------
print("\n[4] runtime-only reasons preserved across re-triage")
# A doc with base64_blob (stale — hex command) + budget_exhausted + sample.
# After re-triage: base64_blob dropped; budget_exhausted + sample preserved.
stub_docs = [_doc("d3", f"sha256: {HEX_200}", confidence=7,
                  triage_reasons=["base64_blob", "budget_exhausted", "sample"])]
es_stub = _StubES(stub_docs)
commands_mod.bulk_write = _stub_bulk_write
commands_mod.make_client = lambda *a, **kw: es_stub
clustering_mod.load_centroids = _stub_load_centroids
_captured_bulk.clear()
try:
    stats = run_retriage(_build_cfg(), None, dry_run=False)
finally:
    commands_mod.bulk_write = _orig_bulk_write
    commands_mod.make_client = _orig_make_client
    clustering_mod.load_centroids = _orig_load_centroids

reasons = _captured_bulk[0]["script"]["params"]["triage_reasons"]
check(
    "merged list contains budget_exhausted",
    "budget_exhausted" in reasons,
    f"got {reasons}",
)
check(
    "merged list contains sample (runtime-only, preserved)",
    "sample" in reasons,
    f"got {reasons}",
)
check(
    "merged list does NOT contain base64_blob (rule-only, removed)",
    "base64_blob" not in reasons,
    f"got {reasons}",
)
check(
    "removed_by_rule counts base64_blob",
    stats["removed_by_rule"].get("base64_blob") == 1,
    f"got {stats['removed_by_rule']}",
)


# -----------------------------------------------------------------------------
# [5] Deterministic re-runs (no `sample` re-introduced by random firing).
# -----------------------------------------------------------------------------
print("\n[5] deterministic rng suppresses the random `sample` rule")
# Doc with no stored triage_reasons. Even if cloud.triage.sample_rate > 0,
# re-triage must not produce `sample` for a benign command. We test by
# running twice and asserting idempotent behaviour.
stub_docs = [_doc("d4", "ls -la", confidence=7, triage_reasons=[])]
results = []
for _ in range(2):
    es_stub = _StubES([dict(d) for d in stub_docs])
    commands_mod.bulk_write = _stub_bulk_write
    commands_mod.make_client = lambda *a, **kw: es_stub
    clustering_mod.load_centroids = _stub_load_centroids
    _captured_bulk.clear()
    try:
        s = run_retriage(_build_cfg(), None, dry_run=False)
        results.append((s["scanned"], s["changed"], s["unchanged"]))
    finally:
        commands_mod.bulk_write = _orig_bulk_write
        commands_mod.make_client = _orig_make_client
        clustering_mod.load_centroids = _orig_load_centroids
check(
    "two consecutive re-triage runs produce identical scanned/changed/unchanged",
    results[0] == results[1],
    f"got {results}",
)


# -----------------------------------------------------------------------------
# [6] Window filter passes into the iterator query.
# -----------------------------------------------------------------------------
print("\n[6] window_days plumbed into the iterator query")
stub_docs = [_doc("d5", "ls", confidence=7)]
es_stub = _StubES(stub_docs)
commands_mod.bulk_write = _stub_bulk_write
commands_mod.make_client = lambda *a, **kw: es_stub
clustering_mod.load_centroids = _stub_load_centroids
_captured_bulk.clear()
try:
    run_retriage(_build_cfg(), None, dry_run=True, window_days=7)
finally:
    commands_mod.bulk_write = _orig_bulk_write
    commands_mod.make_client = _orig_make_client
    clustering_mod.load_centroids = _orig_load_centroids

# Walk the captured search query for the range filter.
query = es_stub.searches[0]["query"]
must = query.get("bool", {}).get("must", [])
has_range_7d = any(
    m.get("range", {}).get("@timestamp", {}).get("gte") == "now-7d/d"
    for m in must
)
check(
    "search query carries gte=now-7d/d",
    has_range_7d,
    f"got {json.dumps(query)}",
)


# -----------------------------------------------------------------------------
# [7] Dry-run doesn't write.
# -----------------------------------------------------------------------------
print("\n[7] dry-run path doesn't issue bulk writes")
stub_docs = [_doc("d6", f"sha256: {HEX_200}", confidence=7,
                  triage_reasons=["base64_blob"])]
es_stub = _StubES(stub_docs)
commands_mod.bulk_write = _stub_bulk_write
commands_mod.make_client = lambda *a, **kw: es_stub
clustering_mod.load_centroids = _stub_load_centroids
_captured_bulk.clear()
try:
    stats = run_retriage(_build_cfg(), None, dry_run=True)
finally:
    commands_mod.bulk_write = _orig_bulk_write
    commands_mod.make_client = _orig_make_client
    clustering_mod.load_centroids = _orig_load_centroids

check(
    "dry_run: changed counted but no bulk_write called",
    stats["changed"] == 1 and stats.get("status") == "dry_run" and _captured_bulk == [],
    f"got stats={stats} captured={_captured_bulk}",
)


# -----------------------------------------------------------------------------
# [8] RETRIAGE_SCRIPT shape sanity: empty triage_reasons removes the field.
# Pure-Python structural check — we can't run painless locally, but verifying
# the source carries the conditional removal branch is enough to lock in
# the contract (and humans reading the script know what it does).
# -----------------------------------------------------------------------------
print("\n[8] _RETRIAGE_SCRIPT contains conditional removal branch")
check(
    "script removes field on empty / null params",
    "en.remove('triage_reasons')" in _RETRIAGE_SCRIPT,
    "",
)
check(
    "script assigns on non-empty params",
    "en.triage_reasons = params.triage_reasons" in _RETRIAGE_SCRIPT,
    "",
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
