"""Findings v2 step 5 — drift narrative generator.

Covers:
  - parse_narrative_response strict-JSON guard.
  - generate_delta_narrative skips when cloud disabled / kind in skip set.
  - attach_drift_narratives reuses existing LLM narratives by
    delta_signature (cache hit).
  - attach_drift_narratives respects the budget floor.
  - Invalid JSON from the LLM → finding's narrative falls back to the
    structured template set by the drift miner.

Stubs the LLM client + StateDB + ES so the test is offline.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_drift_narrative.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings import narrative as nar_mod
from enrich.findings.narrative import (
    _KINDS_SKIPPED,
    attach_drift_narratives,
    generate_delta_narrative,
    parse_narrative_response,
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
# [1] parse_narrative_response — strict JSON acceptance.
# -----------------------------------------------------------------------------
print("\n[1] parse_narrative_response")
ok = parse_narrative_response('{"summary": "Bigram set Jaccard 0.31 vs anchor.", "confidence": 0.8}')
check("clean JSON accepted", ok is not None and ok["summary"].startswith("Bigram"))
check("confidence parsed", ok["confidence"] == 0.8)

fenced = parse_narrative_response('```json\n{"summary": "X", "confidence": 0.5}\n```')
check("code-fenced JSON accepted", fenced is not None and fenced["summary"] == "X")

check("invalid JSON → None", parse_narrative_response("not even json") is None)
check("non-dict JSON → None", parse_narrative_response('["x", "y"]') is None)
check("missing summary → None",
      parse_narrative_response('{"confidence": 0.8}') is None)
check("empty summary → None",
      parse_narrative_response('{"summary": "", "confidence": 0.5}') is None)
check("non-string summary → None",
      parse_narrative_response('{"summary": 12, "confidence": 0.5}') is None)
clamp = parse_narrative_response('{"summary": "x", "confidence": "1.5"}')
check("confidence clamped to [0,1]", clamp is not None and clamp["confidence"] == 1.0)
nocf = parse_narrative_response('{"summary": "x"}')
check("missing confidence defaults to 0",
      nocf is not None and nocf["confidence"] == 0.0)
long_sum = "y" * 500
truncated = parse_narrative_response(f'{{"summary": "{long_sum}", "confidence": 0.5}}')
check("summary truncated at 200 chars",
      truncated is not None and len(truncated["summary"]) == 200)


# -----------------------------------------------------------------------------
# [2] generate_delta_narrative skip paths.
# -----------------------------------------------------------------------------
print("\n[2] generate_delta_narrative skips")


class _Cfg:
    class cloud:
        enabled = True
        provider = "anthropic"
        base_url = None
        model = "claude-x"
        request_timeout = 1
        daily_budget_usd = 5.0
        class pricing:
            input_per_mtok = 3.0
            output_per_mtok = 15.0

    class findings:
        class indexes:
            default = "prism.finding"

        class narrative:
            enabled = True
            budget_floor_usd = 0.05
            max_tokens = 160


class _Secrets:
    cloud_api_key = "stub-key"


check("kind in _KINDS_SKIPPED → None",
      generate_delta_narrative(_Cfg, _Secrets,
                               {"kind": "intel_verdict_flip", "evidence": {}}) is None)


class _CfgCloudOff:
    class cloud:
        enabled = False
        provider = "anthropic"
    class findings:
        class indexes: default = "x"
        class narrative: enabled = True; budget_floor_usd = 0.05; max_tokens = 160


check("cloud disabled → None",
      generate_delta_narrative(_CfgCloudOff, _Secrets,
                               {"kind": "playbook_command_drift", "evidence": {},
                                "_classification": "public"}) is None)


class _SecretsNoKey:
    pass


check("no api key → None",
      generate_delta_narrative(_Cfg, _SecretsNoKey,
                               {"kind": "playbook_command_drift", "evidence": {},
                                "_classification": "public"}) is None)


# -----------------------------------------------------------------------------
# [3] LLM-call path — monkey-patch _make_client to return a stub client.
# -----------------------------------------------------------------------------
print("\n[3] LLM-call path")


class _StubClient:
    def __init__(self, text):
        self.text = text
        self.closed = False
    def generate_with_usage(self, prompt, *, max_tokens=160):
        return self.text, 50, 30
    def close(self):
        self.closed = True


# Patch _make_client to return our stub.
_orig_make = nar_mod._make_client


def _patch_client(text):
    nar_mod._make_client = lambda cfg, secrets: _StubClient(text)


def _restore_client():
    nar_mod._make_client = _orig_make


# Valid JSON response → narrative produced
_patch_client('{"summary": "Bigram Jaccard 0.18 vs anchor (sequence changed).", "confidence": 0.85}')
out = generate_delta_narrative(_Cfg, _Secrets, {
    "kind": "playbook_sequence_drift",
    "evidence": {"bigram_jaccard": 0.18},
    "_classification": "public",
})
check("valid JSON → narrative produced", out is not None)
check("summary text correct",
      out and out["summary"].startswith("Bigram"))
check("input/output tokens captured",
      out and out["input_tokens"] == 50 and out["output_tokens"] == 30)

# Invalid JSON → None (caller falls back)
_patch_client("Sure! The bigrams changed dramatically.")
out = generate_delta_narrative(_Cfg, _Secrets, {
    "kind": "playbook_sequence_drift",
    "evidence": {},
    "_classification": "public",
})
check("invalid JSON response → None", out is None)
_restore_client()


# -----------------------------------------------------------------------------
# [4] attach_drift_narratives — cache hit reuses existing.
# -----------------------------------------------------------------------------
print("\n[4] attach_drift_narratives cache reuse")


class _StubDB:
    def __init__(self, spent=0.0):
        self.spent = spent
        self.spend_calls: list[tuple[int, int, float]] = []
    def add_spend(self, day, in_tok, out_tok, cost):
        self.spend_calls.append((in_tok, out_tok, cost))
        self.spent += cost
    def get_spend(self, day):
        return {"cost_usd": self.spent}


class _StubES:
    def __init__(self, existing: dict):
        self.existing = existing
    def mget(self, *, index, ids):
        return {"docs": [
            ({"found": True, "_id": fid, "_source": self.existing[fid]}
             if fid in self.existing else
             {"found": False, "_id": fid})
            for fid in ids
        ]}


from enrich.findings.writer import finding_id

f = {
    "kind": "playbook_sequence_drift",
    "run_id": "r1",
    "artifact": {"kind": "playbook", "value": "sescl-A"},
    "delta_signature": "dlt-AAA",
    "narrative": "structured fallback",
    "evidence": {},
    "_classification": "public",
}
fid = finding_id(f["kind"], f["artifact"]["kind"], f["artifact"]["value"], f["delta_signature"])
existing = {fid: {
    "kind": "playbook_sequence_drift",
    "delta_signature": "dlt-AAA",
    "narrative_source": "llm",
    "narrative": "Cached LLM summary — bigrams reordered.",
    "narrative_confidence": 0.77,
}}
db = _StubDB()
stats = attach_drift_narratives(_StubES(existing), _Cfg, _Secrets, db, "prism.finding", [f])
check("cache hit recorded", stats["cached"] == 1 and stats["generated"] == 0)
check("finding narrative replaced by cached LLM one",
      f["narrative"] == "Cached LLM summary — bigrams reordered.")
check("no spend recorded on cache hit", db.spend_calls == [])


# -----------------------------------------------------------------------------
# [5] attach_drift_narratives — cache miss + budget floor → skip.
# -----------------------------------------------------------------------------
print("\n[5] budget floor skips LLM call when insufficient")


class _CfgBroke(_Cfg):
    class cloud(_Cfg.cloud):
        enabled = True
        daily_budget_usd = 0.01  # tiny budget

    class findings(_Cfg.findings):
        class narrative(_Cfg.findings.narrative):
            budget_floor_usd = 1.0  # require $1 floor


f = {
    "kind": "playbook_sequence_drift",
    "artifact": {"kind": "playbook", "value": "sescl-B"},
    "delta_signature": "dlt-BBB",
    "narrative": "structured fallback B",
    "evidence": {},
    "_classification": "public",
}
db = _StubDB(spent=0.0)   # remaining = 0.01, < floor=1.0
stats = attach_drift_narratives(_StubES({}), _CfgBroke, _Secrets, db, "prism.finding", [f])
check("budget_skipped == 1", stats["budget_skipped"] == 1, f"got {stats}")
check("structured narrative preserved on budget skip",
      f["narrative"] == "structured fallback B")


# -----------------------------------------------------------------------------
# [6] attach_drift_narratives — cache miss + invalid LLM JSON → failed, fallback preserved.
# -----------------------------------------------------------------------------
print("\n[6] invalid LLM response → fallback preserved")
_patch_client("not json")
f = {
    "kind": "playbook_command_drift",
    "artifact": {"kind": "playbook", "value": "sescl-C"},
    "delta_signature": "dlt-CCC",
    "narrative": "structured fallback C",
    "evidence": {"signature_anchor": "AAA", "signature_current": "BBB"},
    "_classification": "public",
}
db = _StubDB()
stats = attach_drift_narratives(_StubES({}), _Cfg, _Secrets, db, "prism.finding", [f])
_restore_client()
check("failed == 1", stats["failed"] == 1, f"got {stats}")
check("structured narrative preserved on parse failure",
      f["narrative"] == "structured fallback C")
check("no spend recorded on failure", db.spend_calls == [])


# -----------------------------------------------------------------------------
# [7] attach_drift_narratives — valid LLM JSON → summary attached + spend recorded.
# -----------------------------------------------------------------------------
print("\n[7] valid LLM response → summary attached + spend recorded")
_patch_client('{"summary": "Signatures changed; new payload.", "confidence": 0.9}')
f = {
    "kind": "playbook_command_drift",
    "artifact": {"kind": "playbook", "value": "sescl-D"},
    "delta_signature": "dlt-DDD",
    "narrative": "structured fallback D",
    "evidence": {"signature_anchor": "AAA", "signature_current": "BBB"},
    "_classification": "public",
}
db = _StubDB()
stats = attach_drift_narratives(_StubES({}), _Cfg, _Secrets, db, "prism.finding", [f])
_restore_client()
check("generated == 1", stats["generated"] == 1, f"got {stats}")
check("LLM summary attached to finding",
      f["narrative"] == "Signatures changed; new payload.")
check("narrative_source == 'llm'", f["narrative_source"] == "llm")
check("narrative_confidence == 0.9", f["narrative_confidence"] == 0.9)
check("spend recorded (50 in / 30 out)",
      len(db.spend_calls) == 1 and db.spend_calls[0][:2] == (50, 30))


# -----------------------------------------------------------------------------
# [8] _KINDS_SKIPPED — design table fidelity.
# -----------------------------------------------------------------------------
print("\n[8] skip set")
check("intel_verdict_flip skipped", "intel_verdict_flip" in _KINDS_SKIPPED)
check("playbook_size_drift skipped", "playbook_size_drift" in _KINDS_SKIPPED)
check("playbook_resurgence skipped", "playbook_resurgence" in _KINDS_SKIPPED)
check("campaign_growth skipped", "campaign_growth" in _KINDS_SKIPPED)
check("playbook_command_drift NOT skipped (LLM target)",
      "playbook_command_drift" not in _KINDS_SKIPPED)
check("playbook_sequence_drift NOT skipped",
      "playbook_sequence_drift" not in _KINDS_SKIPPED)


# -----------------------------------------------------------------------------
# [9] classification privacy gate — confidential / untagged is never narrated.
# A drift finding carries `_classification` (stamped by the drift miner from the
# playbook's member sessions). The cloud narration must be skipped for anything
# not releasable, even when valid JSON is on offer.
# -----------------------------------------------------------------------------
print("\n[9] classification gate skips confidential + untagged findings")
_patch_client('{"summary": "MUST NOT be sent to the cloud", "confidence": 0.9}')
for label, tag in [("confidential", "confidential"), ("untagged (fail-safe)", None)]:
    gf = {
        "kind": "playbook_command_drift",
        "artifact": {"kind": "playbook", "value": f"sescl-G{label[:3]}"},
        "delta_signature": f"dlt-G{label[:3]}",
        "narrative": "structured fallback G",
        "evidence": {"signature_anchor": "A", "signature_current": "B"},
    }
    if tag is not None:
        gf["_classification"] = tag
    gdb = _StubDB()
    gstats = attach_drift_narratives(_StubES({}), _Cfg, _Secrets, gdb, "prism.finding", [gf])
    check(f"{label} → skipped_confidential",
          gstats["skipped_confidential"] == 1 and gstats["generated"] == 0, f"got {gstats}")
    check(f"{label} → no cloud spend", gdb.spend_calls == [])
    check(f"{label} → structured narrative preserved",
          gf["narrative"] == "structured fallback G" and gf.get("narrative_source") != "llm")
# Direct generate_delta_narrative also refuses a confidential finding.
out = generate_delta_narrative(_Cfg, _Secrets, {
    "kind": "playbook_command_drift", "evidence": {}, "_classification": "confidential",
})
check("generate_delta_narrative refuses confidential", out is None)
_restore_client()


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
