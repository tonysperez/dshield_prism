"""Data-classification privacy gate (public | confidential).

Confidential sensor data must never be escalated to the cloud LLM or queried
against CTI feeds. This verifies — fully offline, no live ES — the gate logic
and the propagation onto rollup docs:

  [1] is_releasable matrix (public/confidential/absent x fail-safe/fail-open).
  [2] aggregate — "most restrictive source wins".
  [3] stickier — never downgrades a deduped command back to public.
  [4] releasable_filter — the ES clause that excludes confidential docs.
  [5] IP rollup propagation (_build_ip_doc): any confidential session taints
      the IP; public only if every session is public; else unset (gated).
  [6] command-group aggregation (the cloud-escalation gate input).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_classification.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from enrich import classification as cl
from enrich.config import load_config
from enrich.findings.drift import _playbook_classification
from enrich.sources.cowrie.ips import _build_ip_doc

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED.append(name) if ok else FAILED.append((name, detail)))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  {detail}"))


cfg = load_config(str(REPO / "config" / "default.yaml"))


class _Cfg:
    """Tiny cfg shim carrying just the classification knob."""
    def __init__(self, unclassified_is_confidential):
        self.classification = type(
            "C", (), {"unclassified_is_confidential": unclassified_is_confidential})()


SAFE = _Cfg(True)   # fail-safe (default / the operator's choice)
OPEN = _Cfg(False)  # fail-open

print("\n[1] is_releasable — only explicit public leaves the box (fail-safe)")
check("public is releasable (safe)", cl.is_releasable("public", SAFE) is True)
check("confidential never releasable (safe)", cl.is_releasable("confidential", SAFE) is False)
check("absent NOT releasable (safe = fail-safe)", cl.is_releasable(None, SAFE) is False)
check("unknown value NOT releasable (safe)", cl.is_releasable("secret?", SAFE) is False)
check("confidential never releasable (open)", cl.is_releasable("confidential", OPEN) is False)
check("absent IS releasable (fail-open)", cl.is_releasable(None, OPEN) is True)
check("default config is fail-safe", cfg.classification.unclassified_is_confidential is True)
check("the live default gates absent", cl.is_releasable(None, cfg) is False)

print("\n[2] aggregate — most restrictive source wins")
check("all public -> public", cl.aggregate(["public", "public"]) == "public")
check("any confidential -> confidential", cl.aggregate(["public", "confidential"]) == "confidential")
check("public + absent -> None (gated under fail-safe)", cl.aggregate(["public", None]) is None)
check("empty -> None", cl.aggregate([]) is None)
check("only confidential -> confidential", cl.aggregate(["confidential"]) == "confidential")

print("\n[3] stickier — a deduped command never downgrades to public")
check("public then confidential -> confidential", cl.stickier("public", "confidential") == "confidential")
check("confidential then public -> confidential", cl.stickier("confidential", "public") == "confidential")
check("public then public -> public", cl.stickier("public", "public") == "public")
check("None then public -> public", cl.stickier(None, "public") == "public")
check("confidential then None -> confidential", cl.stickier("confidential", None) == "confidential")

print("\n[4] releasable_filter — query clause excludes confidential docs")
f_safe = cl.releasable_filter(SAFE)
check("fail-safe filter = term classification.keyword:public",
      f_safe == {"term": {"dshield.classification.keyword": "public"}}, str(f_safe))
f_open = cl.releasable_filter(OPEN)
check("fail-open filter = must_not confidential",
      f_open.get("bool", {}).get("must_not", {}).get("term", {})
      == {"dshield.classification.keyword": "confidential"}, str(f_open))


def _sess(classification):
    """Minimal session-rollup doc carrying a classification."""
    d = {"event": {}, "dshield": {"cowrie": {"enrichment": {"session": {}}}}}
    if classification is not None:
        d["dshield"]["classification"] = classification
    return d


def _ip_class(session_classes):
    doc = _build_ip_doc("203.0.113.7", [_sess(c) for c in session_classes], cfg)
    return (doc.get("dshield") or {}).get("classification")


print("\n[5] IP rollup propagation (_build_ip_doc aggregates its sessions)")
check("all-public sessions -> IP public", _ip_class(["public", "public"]) == "public")
check("any confidential session -> IP confidential",
      _ip_class(["public", "confidential"]) == "confidential")
check("public + untagged session -> IP unset (gated)",
      _ip_class(["public", None]) is None)
check("all-untagged -> IP unset (gated under fail-safe)", _ip_class([None, None]) is None)

print("\n[6] command-group aggregation feeds the cloud-escalation gate")
# A content-deduped command's class_set is the set of its source events' tags.
for class_set, expect_releasable in [
    ({"public"}, True),
    ({"public", "confidential"}, False),
    ({"public", None}, False),     # mixed with untagged -> gated (fail-safe)
    ({None}, False),
]:
    agg = cl.aggregate(class_set)
    rel = cl.is_releasable(agg, cfg)
    check(f"class_set={class_set} -> releasable={rel}", rel is expect_releasable, f"agg={agg}")


def _bk(items):  # ES terms-agg buckets: [(key, doc_count), ...]
    return [{"key": k, "doc_count": n} for k, n in items]


print("\n[7] drift-finding narrative gate (playbook tag drives cloud narration)")
# _playbook_classification turns the session-rollup terms-agg buckets into the
# playbook's tag; the narrative step only narrates a releasable playbook.
cases = [
    ("all 4 sessions public", _bk([("public", 4)]), 4, "public", True),
    ("any confidential session", _bk([("public", 3), ("confidential", 1)]), 4, "confidential", False),
    ("3 tagged public, 1 untagged", _bk([("public", 3)]), 4, None, False),  # fail-safe taint
    ("no session tagged", _bk([]), 4, None, False),
]
for label, buckets, sc, expect_tag, expect_rel in cases:
    tag = _playbook_classification(buckets, sc)
    rel = cl.is_releasable(tag, cfg)
    check(f"{label} -> tag={tag}, narrate={rel}",
          tag == expect_tag and rel is expect_rel, f"tag={tag} rel={rel}")

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
