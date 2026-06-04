"""Smoke test for the hunts subsystem (brutal-review phase 6.1).

Covers:
  * YAML loader rejects malformed hunt files.
  * Per-filter validation catches typos before execution.
  * Each supported filter kind translates to the right ES query fragment.
  * The executor walks a stubbed ES, builds finding dicts of the expected
    shape, and stamps `delta_signature=hunt:<id>` so the writer's
    finding_id is hunt-distinguishable.

Pure-function offline (no ES, no LLM).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_hunts.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.findings.hunts import (  # noqa: E402
    _filter_to_es_clause, _run_one_hunt, _validate_filter, load_hunts,
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


def expect_raises(name: str, fn, *args, exc_type=Exception, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
        check(name, False, "no exception raised")
    except exc_type as e:
        check(name, True, f"got {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# [1] Filter validation — typos / wrong shapes are rejected.
# ---------------------------------------------------------------------------
print("[1] _validate_filter — rejects malformed clauses")

expect_raises(
    "unknown filter kind",
    _validate_filter, {"kind": "nonsense_filter"}, hunt_id="h", idx=0,
    exc_type=ValueError,
)
expect_raises(
    "artifact_set_contains_any without values",
    _validate_filter, {"kind": "artifact_set_contains_any"}, hunt_id="h", idx=0,
    exc_type=ValueError,
)
expect_raises(
    "artifact_set_contains_any with empty list",
    _validate_filter, {"kind": "artifact_set_contains_any", "values": []},
    hunt_id="h", idx=0, exc_type=ValueError,
)
expect_raises(
    "window with non-positive days",
    _validate_filter, {"kind": "window", "last_days": 0},
    hunt_id="h", idx=0, exc_type=ValueError,
)
expect_raises(
    "external_match_cosine_gte with threshold > 1",
    _validate_filter,
    {"kind": "external_match_cosine_gte", "threshold": 1.5},
    hunt_id="h", idx=0, exc_type=ValueError,
)
expect_raises(
    "command_count_gte with non-int threshold",
    _validate_filter,
    {"kind": "command_count_gte", "threshold": "five"},
    hunt_id="h", idx=0, exc_type=ValueError,
)

# Happy path — every supported filter validates cleanly.
for f in [
    {"kind": "artifact_set_contains_any", "values": ["crontab"]},
    {"kind": "artifact_set_contains_all", "values": ["a", "b"]},
    {"kind": "intent_in",                 "values": ["persistence"]},
    {"kind": "command_count_gte",         "threshold": 10},
    {"kind": "login_fail_count_gte",      "threshold": 50},
    {"kind": "external_match_cosine_gte", "threshold": 0.5},
    {"kind": "window",                    "last_days": 7},
]:
    try:
        _validate_filter(f, hunt_id="t", idx=0)
        check(f"valid filter: {f['kind']}", True)
    except Exception as e:
        check(f"valid filter: {f['kind']}", False, str(e))


# ---------------------------------------------------------------------------
# [2] Filter → ES clause translation.
# ---------------------------------------------------------------------------
print("\n[2] _filter_to_es_clause — schema-to-ES mapping is correct")

clause = _filter_to_es_clause(
    {"kind": "artifact_set_contains_any", "values": ["crontab", "systemctl"]},
)
check("artifact_set_contains_any → terms on artifact_set.keyword",
      "terms" in clause
      and "artifact_set.keyword" in str(clause["terms"]),
      str(clause))

clause = _filter_to_es_clause(
    {"kind": "artifact_set_contains_all", "values": ["crontab", "systemctl"]},
)
check("artifact_set_contains_all → bool.must with one term each",
      isinstance(clause, dict)
      and "bool" in clause
      and len(clause["bool"]["must"]) == 2,
      str(clause))

clause = _filter_to_es_clause({"kind": "external_match_cosine_gte", "threshold": 0.5})
check("external_match_cosine_gte → range with gte=0.5",
      "range" in clause
      and "external_match_cosine" in str(clause["range"])
      and clause["range"][next(iter(clause["range"]))]["gte"] == 0.5,
      str(clause))

clause = _filter_to_es_clause({"kind": "window", "last_days": 7})
check("window → range on event.start with gte timestamp",
      "range" in clause
      and "event.start" in str(clause["range"])
      and "gte" in clause["range"]["event.start"],
      str(clause))


# ---------------------------------------------------------------------------
# [3] YAML loader — round-trips a valid file; rejects malformed.
# ---------------------------------------------------------------------------
print("\n[3] load_hunts — directory walk + validation")

with tempfile.TemporaryDirectory() as td:
    # Valid hunt.
    (Path(td) / "ok.yaml").write_text(
        "id: ok-hunt\n"
        "name: OK Hunt\n"
        "filters:\n"
        "  - {kind: window, last_days: 7}\n"
        "  - {kind: intent_in, values: [persistence, execution]}\n"
    )
    # Disabled hunt — loaded but excluded.
    (Path(td) / "off.yaml").write_text(
        "id: off-hunt\n"
        "name: Off Hunt\n"
        "enabled: false\n"
        "filters:\n"
        "  - {kind: window, last_days: 7}\n"
    )
    # Non-YAML file — ignored.
    (Path(td) / "readme.txt").write_text("not yaml")
    hunts = load_hunts(td)
    ids = [h["id"] for h in hunts]
    check("loads enabled hunt only",
          ids == ["ok-hunt"], f"got ids={ids}")

# Missing dir is a no-op (returns []).
with tempfile.TemporaryDirectory() as td:
    check("missing directory returns empty list",
          load_hunts(str(Path(td) / "no-such")) == [])

# Malformed YAML aborts the load.
with tempfile.TemporaryDirectory() as td:
    (Path(td) / "bad.yaml").write_text(
        "id: bad-hunt\n"
        "name: Bad Hunt\n"
        "filters:\n"
        "  - {kind: nonsense}\n"
    )
    expect_raises(
        "malformed filter aborts load",
        load_hunts, td, exc_type=ValueError,
    )

# Missing required `id` aborts.
with tempfile.TemporaryDirectory() as td:
    (Path(td) / "noid.yaml").write_text(
        "name: No ID\n"
        "filters:\n"
        "  - {kind: window, last_days: 7}\n"
    )
    expect_raises(
        "missing id aborts load",
        load_hunts, td, exc_type=ValueError,
    )


# ---------------------------------------------------------------------------
# [4] Executor — builds finding dicts of the expected shape.
# ---------------------------------------------------------------------------
print("\n[4] _run_one_hunt — finding shape + delta_signature")


class _StubES:
    """Returns the seeded session-rollup hits; doesn't actually evaluate
    the query (smoke tests filter translation in section [2])."""
    def __init__(self, *, hits):
        self.hits = hits
        self.indices = type("I", (), {"exists": lambda self, **kw: True})()
    def search(self, **kwargs):
        return {"hits": {"hits": self.hits}}


sample_hits = [
    {
        "_id": "sess-1",
        "_source": {
            "cowrie":  {"session_id": "sess-1"},
            "source":  {"ip": "1.2.3.4"},
            "event":   {"start": "2026-05-31T00:00:00+00:00",
                        "end":   "2026-05-31T00:05:00+00:00"},
            "dshield": {"cowrie": {"enrichment": {"session": {
                "command_count":    12,
                "dominant_intent":  "persistence",
                "playbook_id":      "spb-abc",
                "playbook_name":    "Some Playbook",
                "cluster": {
                    "external_match_id":     "cluster_0",
                    "external_match_cosine": 0.91,
                },
            }}}},
        },
    },
]
hunt = {
    "id":     "persistence-touched",
    "name":   "Persistence touched",
    "filters": [
        {"kind": "artifact_set_contains_any",
         "values": ["crontab", "authorized_keys"]},
        {"kind": "window", "last_days": 7},
    ],
}
findings = _run_one_hunt(
    _StubES(hits=sample_hits), "sessions-idx", hunt,
    run_id="run-1", max_findings=100,
)
check("one finding per matching session",
      len(findings) == 1, f"got {len(findings)}")
f = findings[0]
check("kind=analyst_hunt", f["kind"] == "analyst_hunt", f["kind"])
check("artifact.kind=session",
      f["artifact"]["kind"] == "session", str(f["artifact"]))
check("artifact.value is the session id",
      f["artifact"]["value"] == "sess-1", str(f["artifact"]))
check("delta_signature carries hunt:<id>",
      f["delta_signature"] == "hunt:persistence-touched",
      f["delta_signature"])
ev = f["evidence"]
check("evidence carries hunt_id + hunt_name",
      ev["hunt_id"] == "persistence-touched"
      and ev["hunt_name"] == "Persistence touched")
check("evidence carries source_ip + command_count",
      ev["source_ip"] == "1.2.3.4" and ev["command_count"] == 12)
check("evidence carries external_match_id + cosine when present",
      ev["external_match_id"] == "cluster_0"
      and ev["external_match_cosine"] == 0.91)

# Empty hits → empty findings.
findings_empty = _run_one_hunt(
    _StubES(hits=[]), "sessions-idx", hunt,
    run_id="run-1", max_findings=100,
)
check("empty hits → empty findings", findings_empty == [])


# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
