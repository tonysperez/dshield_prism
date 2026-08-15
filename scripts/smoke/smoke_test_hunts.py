"""Smoke test for the hunts subsystem.

Covers:
  * YAML loader rejects malformed hunt files.
  * Per-filter validation catches typos before execution.
  * Each supported filter kind translates to the right ES query fragment.
  * The executor walks a stubbed ES, builds finding dicts of the expected
    shape, and stamps `delta_signature=hunt:<id>` so the writer's
    finding_id is hunt-distinguishable.
  * `enabled` gates *writing*, not loading — disabled hunts still load and
    still preview, `run_hunts` skips them, `--include-disabled` overrides.
  * `set_hunt_enabled` rewrites exactly one line, leaving description
    blocks and inline comments byte-identical.
  * `preview_hunt` returns projected sessions and creates no findings.
  * `write_hunt` / `delete_hunt` — the console's authoring path: ids are
    sanitised, the target stays inside the hunts dir, the candidate is
    validated before it replaces anything, and file modes survive the
    atomic swap.
  * The console's create / edit / delete routes, driven through a
    `TestClient` against a temp hunts dir: status codes, conflict
    detection, and that no failure hands back an absolute path.

Pure-function offline (no ES, no LLM) — the route section stubs the ES
client factory and SKIPs when fastapi / console aren't installed.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_hunts.py
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.findings.hunts import (  # noqa: E402
    HUNT_ID_RE, _filter_to_es_clause, _run_one_hunt, _validate_filter,
    delete_hunt, enabled_hunts, load_hunts, preview_hunt, run_hunts,
    set_hunt_enabled, validate_hunt_doc, write_hunt,
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
# `isinstance(True, int)` is True, so an unguarded check reads
# `last_days: true` as 1 day and `threshold: true` as 1.
for bad_bool in (
    {"kind": "window", "last_days": True},
    {"kind": "command_count_gte", "threshold": True},
    {"kind": "login_fail_count_gte", "threshold": True},
    {"kind": "external_match_cosine_gte", "threshold": True},
):
    expect_raises(
        f"{bad_bool['kind']} rejects a bool where a number belongs",
        _validate_filter, bad_bool, hunt_id="h", idx=0, exc_type=ValueError,
    )
# A non-string `values` member validates fine but blows up at ES time.
for bad_values in ([{"a": 1}], [None], [7], ["ok", ""], ["ok", 7]):
    expect_raises(
        f"intent_in rejects values={bad_values!r}",
        _validate_filter, {"kind": "intent_in", "values": bad_values},
        hunt_id="h", idx=0, exc_type=ValueError,
    )
expect_raises(
    "artifact_set_contains_any rejects a non-string values member",
    _validate_filter,
    {"kind": "artifact_set_contains_any", "values": ["crontab", 3]},
    hunt_id="h", idx=0, exc_type=ValueError,
)
# Unbounded `last_days` overflows `timedelta` inside _filter_to_es_clause,
# which is outside preview's try block — the page 500s forever after.
expect_raises(
    "window rejects an out-of-range last_days",
    _validate_filter, {"kind": "window", "last_days": 10 ** 12},
    hunt_id="h", idx=0, exc_type=ValueError,
)
check("window accepts the 3650-day ceiling",
      _validate_filter({"kind": "window", "last_days": 3650},
                       hunt_id="h", idx=0) is None)

# Happy path — every supported filter validates cleanly.
for f in [
    {"kind": "artifact_set_contains_any", "values": ["crontab"]},
    {"kind": "artifact_set_contains_all", "values": ["a", "b"]},
    {"kind": "intent_in",                 "values": ["install_persistence"]},
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
        "  - {kind: intent_in, values: [install_persistence, execute_payload]}\n"
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
    # `enabled` gates WRITING, not loading — a disabled hunt must still
    # come back or the console can never list it to switch it on again.
    check("loads disabled hunts too",
          ids == ["off-hunt", "ok-hunt"], f"got ids={ids}")
    by_id = {h["id"]: h for h in hunts}
    check("absent `enabled` key defaults to True",
          by_id["ok-hunt"]["enabled"] is True,
          repr(by_id["ok-hunt"].get("enabled")))
    check("`enabled: false` normalizes to bool False",
          by_id["off-hunt"]["enabled"] is False,
          repr(by_id["off-hunt"].get("enabled")))
    check("each hunt carries _source_path to its own file",
          Path(by_id["off-hunt"]["_source_path"]).name == "off.yaml",
          by_id["off-hunt"].get("_source_path"))
    check("enabled_hunts() filters to the write set",
          [h["id"] for h in enabled_hunts(hunts)] == ["ok-hunt"])

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
    the query (smoke tests filter translation in section [2]). `total`
    lets a test make _count disagree with the returned page, which is how
    preview detects truncation."""
    def __init__(self, *, hits, total=None):
        self.hits = hits
        self.total = len(hits) if total is None else total
        self.indices = type("I", (), {"exists": lambda self, **kw: True})()
    def search(self, **kwargs):
        size = kwargs.get("size")
        hits = self.hits if size is None else self.hits[:size]
        return {"hits": {"hits": hits}}
    def count(self, **kwargs):
        return {"count": self.total}


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
                "dominant_intent":  "install_persistence",
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
# [5] set_hunt_enabled — surgical YAML rewrite preserves everything else.
# ---------------------------------------------------------------------------
print("\n[5] set_hunt_enabled — single-line rewrite")

# A file shaped like the shipped seeds: block description, inline
# comments, and an existing `enabled` line with a trailing comment.
SEED_YAML = (
    "id: seedy\n"
    "name: \"Seedy Hunt\"\n"
    "description: |\n"
    "  Multi-paragraph description with an em-dash — and a `backtick`.\n"
    "\n"
    "  Second paragraph that a yaml round-trip would flatten.\n"
    "filters:\n"
    "  - kind: login_fail_count_gte\n"
    "    threshold: 20   # tune me\n"
    "\n"
    "# Ships disabled.\n"
    "enabled: false  # flipped from the console\n"
)

with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "seedy.yaml"
    p.write_text(SEED_YAML)
    original = p.read_text()
    h = load_hunts(td)[0]
    check("seed loads disabled", h["enabled"] is False)

    set_hunt_enabled(h, True)
    after_on = p.read_text()
    check("in-memory hunt reflects the flip", h["enabled"] is True)
    check("reloads as enabled", load_hunts(td)[0]["enabled"] is True)
    # The whole point of the surgical rewrite: only `enabled` moves.
    diff = [(a, b) for a, b in zip(original.splitlines(),
                                   after_on.splitlines()) if a != b]
    check("exactly one line changed", len(diff) == 1, repr(diff))
    check("the changed line is `enabled`",
          diff and diff[0][1].startswith("enabled: true"), repr(diff))
    check("trailing comment on the enabled line survives",
          "# flipped from the console" in after_on)
    check("description block survives verbatim",
          "Second paragraph that a yaml round-trip would flatten." in after_on)
    check("filter inline comment survives", "# tune me" in after_on)

    # Flipping back must restore the file byte-for-byte.
    set_hunt_enabled(h, False)
    check("flip back restores original bytes",
          p.read_text() == original,
          repr(p.read_text()[-80:]))

# No `enabled:` key at all → append it.
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "nokey.yaml"
    p.write_text(
        "id: nokey\n"
        "name: No Key\n"
        "filters:\n"
        "  - {kind: window, last_days: 7}\n"
    )
    h = load_hunts(td)[0]
    check("absent key loads as enabled", h["enabled"] is True)
    set_hunt_enabled(h, False)
    check("appended key parses back", load_hunts(td)[0]["enabled"] is False)
    check("appended as a top-level line",
          p.read_text().rstrip().endswith("enabled: false"),
          repr(p.read_text()))

# A file with no trailing newline still gets a well-formed append.
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "nonl.yaml"
    p.write_text(
        "id: nonl\n"
        "name: No Newline\n"
        "filters:\n"
        "  - {kind: window, last_days: 7}"
    )
    h = load_hunts(td)[0]
    set_hunt_enabled(h, False)
    check("append survives a missing trailing newline",
          load_hunts(td)[0]["enabled"] is False)

# A hunt dict that never went through load_hunts has no _source_path.
expect_raises(
    "set_hunt_enabled without _source_path raises",
    set_hunt_enabled, {"id": "orphan"}, True, exc_type=ValueError,
)

# A quoted key is the SAME key to PyYAML — replace it, never append a
# second one, or the file ends up with two contradictory declarations.
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "quoted.yaml"
    p.write_text(
        "id: quoted\nname: Quoted Key\n"
        '"enabled": true\n'
        "filters:\n  - {kind: window, last_days: 7}\n"
    )
    h = load_hunts(td)[0]
    set_hunt_enabled(h, False)
    body = p.read_text()
    check("quoted `enabled` key is replaced, not duplicated",
          body.count("enabled") == 1 and load_hunts(td)[0]["enabled"] is False,
          repr(body))

# CRLF files must not come back mixed-EOL.
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "crlf.yaml"
    p.write_bytes(
        b"id: crlf\r\nname: CRLF\r\nenabled: true\r\n"
        b"filters:\r\n  - {kind: window, last_days: 7}\r\n"
    )
    h = load_hunts(td)[0]
    set_hunt_enabled(h, False)
    raw = p.read_bytes()
    check("CRLF line endings survive the rewrite",
          b"enabled: false\r\n" in raw and b"enabled: false\n" not in
          raw.replace(b"\r\n", b"\r\n "), repr(raw))

# The write is atomic: no stray temp files left in the hunts dir.
with tempfile.TemporaryDirectory() as td:
    (Path(td) / "a.yaml").write_text(
        "id: a\nname: A\nfilters:\n  - {kind: window, last_days: 7}\n"
    )
    h = load_hunts(td)[0]
    set_hunt_enabled(h, False)
    leftovers = [f.name for f in Path(td).iterdir() if f.name != "a.yaml"]
    check("atomic swap leaves no temp files behind",
          leftovers == [], str(leftovers))


# ---------------------------------------------------------------------------
# [5b] Loader hardening — ambiguous `enabled`, duplicate ids, symlink escape.
# ---------------------------------------------------------------------------
print("\n[5b] load_hunts — hardening")


def _one_hunt_dir(td, body):
    (Path(td) / "h.yaml").write_text(
        "id: h\nname: H\n" + body
        + "filters:\n  - {kind: window, last_days: 7}\n"
    )
    return load_hunts(td)[0]


# `bool("false")` is True — a naive coercion runs a hunt the operator
# switched off, which is exactly what the CLI guard exists to prevent.
with tempfile.TemporaryDirectory() as td:
    check('quoted "false" resolves to disabled, not enabled',
          _one_hunt_dir(td, 'enabled: "false"\n')["enabled"] is False)
with tempfile.TemporaryDirectory() as td:
    check('quoted "no" resolves to disabled',
          _one_hunt_dir(td, 'enabled: "no"\n')["enabled"] is False)
with tempfile.TemporaryDirectory() as td:
    check('quoted "true" resolves to enabled',
          _one_hunt_dir(td, 'enabled: "true"\n')["enabled"] is True)
with tempfile.TemporaryDirectory() as td:
    # A bare `enabled:` parses to None — treat as absent, don't abort.
    check("valueless `enabled:` defaults to enabled",
          _one_hunt_dir(td, "enabled:\n")["enabled"] is True)
with tempfile.TemporaryDirectory() as td:
    (Path(td) / "junk.yaml").write_text(
        "id: junk\nname: Junk\nenabled: [1, 2]\n"
        "filters:\n  - {kind: window, last_days: 7}\n"
    )
    expect_raises("uninterpretable `enabled` aborts the load",
                  load_hunts, td, exc_type=ValueError)

# Two files claiming one id: `by_hunt` would collide and the console
# would toggle whichever sorted first while the other kept writing.
with tempfile.TemporaryDirectory() as td:
    for n in ("a.yaml", "b.yaml"):
        (Path(td) / n).write_text(
            "id: dupe\nname: Dupe\nfilters:\n  - {kind: window, last_days: 7}\n"
        )
    expect_raises("duplicate hunt id aborts the load",
                  load_hunts, td, exc_type=ValueError)

# `_source_path` is what the toggle rewrites, so a symlink out of the
# hunts dir would turn "flip this hunt" into "rewrite that file".
with tempfile.TemporaryDirectory() as td:
    outside = Path(td) / "outside"
    outside.mkdir()
    target = outside / "evil.yaml"
    target.write_text(
        "id: evil\nname: Evil\nfilters:\n  - {kind: window, last_days: 7}\n"
    )
    hunts_dir = Path(td) / "hunts"
    hunts_dir.mkdir()
    try:
        (hunts_dir / "link.yaml").symlink_to(target)
    except (OSError, NotImplementedError):
        check("symlink escaping the hunts dir is refused", True,
              "skipped: symlinks unsupported here")
    else:
        expect_raises("symlink escaping the hunts dir is refused",
                      load_hunts, str(hunts_dir), exc_type=ValueError)


# ---------------------------------------------------------------------------
# [6] run_hunts — writes for enabled hunts only; reports the rest.
# ---------------------------------------------------------------------------
print("\n[6] run_hunts — enabled gates the write path")


class _Cfg:
    """Minimal duck-typed stand-in for the pydantic config tree."""
    def __init__(self, hunts_dir):
        self.findings = type("F", (), {
            "hunts": type("H", (), {
                "config_dir": hunts_dir, "max_findings_per_hunt": 50,
            })(),
        })()
        self.elasticsearch = type("E", (), {
            "indexes": type("I", (), {
                "cowrie": type("C", (), {"sessions_rollup": "sessions-idx"})(),
            })(),
        })()


def _mixed_dir(td):
    (Path(td) / "on.yaml").write_text(
        "id: on-hunt\nname: \"On\"\nenabled: true\n"
        "filters:\n  - {kind: window, last_days: 7}\n"
    )
    (Path(td) / "off.yaml").write_text(
        "id: off-hunt\nname: \"Off\"\nenabled: false\n"
        "filters:\n  - {kind: window, last_days: 7}\n"
    )


with tempfile.TemporaryDirectory() as td:
    _mixed_dir(td)
    es = _StubES(hits=sample_hits)
    res = run_hunts(es, _Cfg(td), "run-2")
    check("loaded counts every hunt on disk, not just the run ones",
          res["loaded"] == 2, str(res["loaded"]))
    check("only the enabled hunt produced findings",
          list(res["by_hunt"]) == ["on-hunt"], str(list(res["by_hunt"])))
    check("disabled hunt reported under skipped",
          res["skipped"] == ["off-hunt"], str(res["skipped"]))

    # --include-disabled (CLI gates this behind --dry-run) runs both.
    res_all = run_hunts(es, _Cfg(td), "run-3", include_disabled=True)
    check("include_disabled runs disabled hunts too",
          sorted(res_all["by_hunt"]) == ["off-hunt", "on-hunt"],
          str(sorted(res_all["by_hunt"])))
    check("include_disabled reports nothing skipped",
          res_all["skipped"] == [], str(res_all["skipped"]))

# Everything off → no findings at all, but still a clean result.
with tempfile.TemporaryDirectory() as td:
    (Path(td) / "off.yaml").write_text(
        "id: off-hunt\nname: \"Off\"\nenabled: false\n"
        "filters:\n  - {kind: window, last_days: 7}\n"
    )
    res = run_hunts(_StubES(hits=sample_hits), _Cfg(td), "run-4")
    check("all-disabled dir writes nothing",
          res["by_hunt"] == {} and res["errors"] == [], str(res))
    check("all-disabled dir still reports loaded + skipped",
          res["loaded"] == 1 and res["skipped"] == ["off-hunt"], str(res))


# ---------------------------------------------------------------------------
# [7] preview_hunt — executes, projects sessions, writes nothing.
# ---------------------------------------------------------------------------
print("\n[7] preview_hunt — no findings, no writes")


class _NoIndexES(_StubES):
    """Session rollup absent — preview must degrade, not raise."""
    def __init__(self):
        super().__init__(hits=[])
        self.indices = type("I", (), {"exists": lambda self, **kw: False})()
    def search(self, **kwargs):
        raise AssertionError("preview must not search a missing index")


with tempfile.TemporaryDirectory() as td:
    _mixed_dir(td)
    cfg = _Cfg(td)
    off = {h["id"]: h for h in load_hunts(td)}["off-hunt"]
    pv = preview_hunt(_StubES(hits=sample_hits), cfg, off)
    check("previews a DISABLED hunt", pv["enabled"] is False)
    check("total comes from _count, shown from the page",
          pv["total"] == 1 and pv["shown"] == 1, str(pv))
    check("returns projected session rows, not findings",
          "session_id" in pv["sessions"][0]
          and "delta_signature" not in pv["sessions"][0]
          and "kind" not in pv["sessions"][0],
          str(pv["sessions"][0]))
    check("session row carries the display fields",
          pv["sessions"][0]["source_ip"] == "1.2.3.4"
          and pv["sessions"][0]["command_count"] == 12
          and pv["sessions"][0]["playbook_name"] == "Some Playbook",
          str(pv["sessions"][0]))
    check("no _source_path in a projected row",
          "_source_path" not in pv["sessions"][0])
    check("exact-fit result set is NOT flagged truncated",
          pv["truncated"] is False, str(pv))
    check("preview carries no run_id", "run_id" not in pv)

    # total > page => genuinely truncated. This is the number that tells
    # the analyst how many findings enabling the hunt would write.
    pv_trunc = preview_hunt(_StubES(hits=sample_hits, total=4000), cfg, off,
                            limit=1)
    check("truncation is total-vs-page, not page-vs-cap",
          pv_trunc["truncated"] is True and pv_trunc["total"] == 4000
          and pv_trunc["shown"] == 1, str(pv_trunc))

    # limit=0 must not silently mean "the config maximum".
    pv_zero = preview_hunt(_StubES(hits=sample_hits), cfg, off, limit=0)
    check("limit=0 clamps to 1, not the cfg default",
          pv_zero["shown"] == 1, str(pv_zero))

    # A search that errors returns [] from _run_one_hunt; without the
    # note the analyst reads "no matches" and drops a live hypothesis.
    class _BrokenSearchES(_StubES):
        def search(self, **kwargs):
            raise RuntimeError("shard failure")
    pv_err = preview_hunt(_BrokenSearchES(hits=sample_hits, total=7), cfg, off)
    check("counted matches but zero rows surfaces a note",
          pv_err["shown"] == 0 and pv_err["total"] == 7
          and bool(pv_err.get("note")), str(pv_err))

    # Missing rollup index degrades to total=0 + a note.
    pv_none = preview_hunt(_NoIndexES(), cfg, off)
    check("missing rollup index → total 0 + note",
          pv_none["total"] == 0 and bool(pv_none.get("note")), str(pv_none))

    # The load-bearing guarantee: preview never touched the toggle or
    # the YAML on disk.
    check("preview leaves `enabled` untouched",
          load_hunts(td)[0]["enabled"] is False)


# ---------------------------------------------------------------------------
# [8] write_hunt / delete_hunt — the console's authoring path.
# ---------------------------------------------------------------------------
print("\n[8] write_hunt / delete_hunt — validated, contained, atomic")


def _leftovers(td, *expected):
    return sorted(f.name for f in Path(td).iterdir()
                  if f.name not in expected)


def _doc(hunt_id="new-hunt", **over):
    d = {
        "id": hunt_id,
        "name": "New Hunt",
        "description": "Hypothesis authored from the console.",
        "enabled": False,
        "filters": [{"kind": "window", "last_days": 3}],
    }
    d.update(over)
    return d


# `validate_hunt_doc` is per-document: the loader's file-level rules, and
# NOT the cross-file duplicate-id check, which is directory state.
check("validate_hunt_doc returns the hunt id",
      validate_hunt_doc(_doc()) == "new-hunt")
check("validate_hunt_doc is per-document, not directory state — the same "
      "id validates twice",
      validate_hunt_doc(_doc("dupe")) == validate_hunt_doc(_doc("dupe")))
expect_raises("validate_hunt_doc rejects a missing name",
              validate_hunt_doc, {"id": "x", "filters": [
                  {"kind": "window", "last_days": 1}]},
              exc_type=ValueError)
expect_raises("validate_hunt_doc rejects an empty filter list",
              validate_hunt_doc, {"id": "x", "name": "X", "filters": []},
              exc_type=ValueError)

# Create: round-trips through the loader, disabled, seed-shaped.
with tempfile.TemporaryDirectory() as td:
    written = write_hunt(td, _doc(**{"_source_path": "/etc/passwd"}))
    check("write_hunt targets <hunts_dir>/<id>.yaml",
          Path(written) == Path(td).resolve() / "new-hunt.yaml", written)
    body = Path(written).read_text()
    check("`_source_path` is never serialised into the file",
          "_source_path" not in body, body)
    top = [ln.split(":")[0] for ln in body.splitlines()
           if ln[:1] not in (" ", "-", "")]
    check("key order reads like the hand-written seeds",
          top == ["id", "name", "description", "enabled", "filters"], str(top))
    hunts = load_hunts(td)
    check("a console-written hunt round-trips through load_hunts",
          [h["id"] for h in hunts] == ["new-hunt"], str(hunts))
    check("console-created hunts are written disabled",
          hunts[0]["enabled"] is False, repr(hunts[0].get("enabled")))
    check("filters survive the round-trip verbatim",
          hunts[0]["filters"] == [{"kind": "window", "last_days": 3}],
          str(hunts[0]["filters"]))
    check("atomic swap leaves no temp file behind",
          _leftovers(td, "new-hunt.yaml") == [], str(_leftovers(td)))
    # Fresh files must be readable by the pipeline user, not 0600 —
    # mkstemp's mode would otherwise ride through os.replace.
    umask = os.umask(0)
    os.umask(umask)
    check("a created file gets 0o644 & ~umask, not mkstemp's 0600",
          (os.stat(written).st_mode & 0o777) == (0o644 & ~umask),
          oct(os.stat(written).st_mode & 0o777))

# An id from HTTP becomes a filename — it must never traverse.
BAD_IDS = ["../../etc/x", "A_b", "", "x" * 65, "-leading",
           "with/slash", "with space", "dot.dot", "..", "UPPER"]
with tempfile.TemporaryDirectory() as td:
    for bad in BAD_IDS:
        expect_raises(f"write_hunt refuses id {bad!r}",
                      write_hunt, td, _doc(bad), exc_type=ValueError)
    check("a rejected id writes nothing at all",
          _leftovers(td) == [], str(_leftovers(td)))

# A hand-written legacy id (`My_Hunt`) loads and lists fine, so the editor
# must be able to save it back. The regex gates only the case where the id
# *becomes* the filename; with an explicit `path=` the safety property is
# containment, which is checked either way.
with tempfile.TemporaryDirectory() as td:
    legacy = Path(td) / "legacy.yaml"
    legacy.write_text(
        "id: My_Hunt\nname: Legacy\n"
        "filters:\n  - {kind: window, last_days: 7}\n"
    )
    h = load_hunts(td)[0]
    write_hunt(td, {
        "id": "My_Hunt", "name": "Legacy renamed", "description": "",
        "enabled": h["enabled"],
        "filters": [{"kind": "window", "last_days": 9}],
    }, path=h["_source_path"])
    after = load_hunts(td)[0]
    check("a legacy id at an existing path stays editable",
          after["name"] == "Legacy renamed"
          and after["filters"] == [{"kind": "window", "last_days": 9}],
          str(after))
    expect_raises("a legacy id still cannot NAME a new file",
                  write_hunt, td, _doc("My_Hunt"), exc_type=ValueError)
    check("the refused create left only the original file",
          _leftovers(td, "legacy.yaml") == [], str(_leftovers(td)))

check("HUNT_ID_RE accepts the shipped seed-style ids",
      all(HUNT_ID_RE.match(i) for i in
          ("persistence-touched", "a", "0", "x" * 64)))
check("HUNT_ID_RE rejects 65 chars", not HUNT_ID_RE.match("x" * 65))

# `path=` is how an edit writes back to the hunt's own file; it must not
# become a way to write anywhere on the box.
with tempfile.TemporaryDirectory() as td:
    hd = Path(td) / "hunts"
    hd.mkdir()
    outside = Path(td) / "outside.yaml"
    expect_raises("write_hunt refuses a path= outside the hunts dir",
                  write_hunt, str(hd), _doc(), path=str(outside),
                  exc_type=ValueError)
    check("the out-of-tree path was not created", not outside.exists())
    # The console 400s with this text — it must not hand the operator's
    # filesystem layout back over HTTP.
    try:
        write_hunt(str(hd), _doc(), path=str(outside))
        msg = ""
    except ValueError as exc:
        msg = str(exc)
    check("the containment error quotes no absolute path",
          bool(msg) and str(td) not in msg, repr(msg))

# A bad filter must refuse the write *before* it replaces anything —
# one unparseable YAML aborts the whole directory load.
with tempfile.TemporaryDirectory() as td:
    good = write_hunt(td, _doc("keeper"))
    before = Path(good).read_text()
    for bad_doc in (
        _doc("keeper", filters=[{"kind": "window", "last_days": 0}]),
        _doc("keeper", filters=[{"kind": "nonsense"}]),
        _doc("keeper", filters=[]),
    ):
        expect_raises("a malformed filter refuses the write",
                      write_hunt, td, bad_doc, path=good, exc_type=ValueError)
    check("the existing file is untouched after a refused write",
          Path(good).read_text() == before)
    check("a refused write leaves no .tmp file behind",
          _leftovers(td, "keeper.yaml") == [], str(_leftovers(td)))
    check("the directory still loads after a refused write",
          [h["id"] for h in load_hunts(td)] == ["keeper"])

# Edit: writes back to the hunt's own file (a `.yml`, named off-id),
# never a second one, and carries `enabled` through untouched.
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "not-the-id.yml"
    p.write_text(
        "id: keeper\nname: Keeper\nenabled: true\n"
        "filters:\n  - {kind: window, last_days: 7}\n"
    )
    os.chmod(p, 0o640)
    h = load_hunts(td)[0]
    write_hunt(td, {
        "id": "keeper", "name": "Keeper renamed", "description": "",
        "enabled": h["enabled"],
        "filters": [{"kind": "command_count_gte", "threshold": 5}],
    }, path=h["_source_path"])
    check("an edit rewrites the hunt's own file, never a second one",
          sorted(f.name for f in Path(td).iterdir()) == ["not-the-id.yml"],
          str(_leftovers(td)))
    after = load_hunts(td)[0]
    check("an edit preserves `enabled: true`",
          after["enabled"] is True, repr(after.get("enabled")))
    check("an edit replaces name + filters",
          after["name"] == "Keeper renamed"
          and after["filters"] == [{"kind": "command_count_gte",
                                    "threshold": 5}], str(after))
    # os.replace keeps the TEMP file's mode; without the chmod every
    # saved hunt would silently come back owner-only.
    check("the existing file's mode survives the atomic swap",
          (os.stat(p).st_mode & 0o777) == 0o640,
          oct(os.stat(p).st_mode & 0o777))

# Delete: the file goes, siblings and findings do not.
with tempfile.TemporaryDirectory() as td:
    write_hunt(td, _doc("goner"))
    write_hunt(td, _doc("stayer"))
    by_id = {h["id"]: h for h in load_hunts(td)}
    delete_hunt(by_id["goner"], hunts_dir=td)
    check("delete_hunt unlinks the hunt's file",
          not (Path(td) / "goner.yaml").exists())
    check("delete_hunt leaves the rest of the directory loadable",
          [h["id"] for h in load_hunts(td)] == ["stayer"])

expect_raises("delete_hunt without _source_path raises",
              delete_hunt, {"id": "orphan"}, exc_type=ValueError)

with tempfile.TemporaryDirectory() as td:
    hd = Path(td) / "hunts"
    hd.mkdir()
    write_hunt(str(hd), _doc("inside"))
    victim = Path(td) / "victim.yaml"
    victim.write_text("id: victim\nname: V\n")
    expect_raises(
        "delete_hunt refuses a _source_path outside the hunts dir",
        delete_hunt, {"id": "inside", "_source_path": str(victim)},
        hunts_dir=str(hd), exc_type=ValueError)
    check("the out-of-tree file survives the refused delete",
          victim.exists())


# ---------------------------------------------------------------------------
# [9] console routes (create/edit/delete) — the rows that live only in the
#     HTTP layer: status codes, conflict detection, and the promise that a
#     failure never hands the operator's filesystem layout back to a client.
# ---------------------------------------------------------------------------
print("\n[9] console routes — create / edit / delete over HTTP")

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))

try:
    import asyncio
    import httpx
    from console import server as console_server  # noqa: E402
except ImportError as exc:
    print(f"  SKIP  console routes — {exc} "
          "(fastapi/console not installed in this venv)")
    console_server = None

if console_server is not None:
    import fastapi.routing as fastapi_routing

    async def _run_sync_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    fastapi_routing.run_in_threadpool = _run_sync_inline

    class ASGIClient:
        """Synchronous facade over httpx's async in-process ASGI transport."""
        def __init__(self, app):
            self.app = app

        def request(self, method, path, **kwargs):
            async def send():
                transport = httpx.ASGITransport(app=self.app)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://testserver",
                ) as client:
                    return await client.request(method, path, **kwargs)
            return asyncio.run(send())

        def post(self, path, **kwargs):
            return self.request("POST", path, **kwargs)

        def put(self, path, **kwargs):
            return self.request("PUT", path, **kwargs)

        def delete(self, path, **kwargs):
            return self.request("DELETE", path, **kwargs)

    # The routes log.exception() on the deliberate failures below; the
    # tracebacks are expected, so keep them out of the smoke output.
    logging.getLogger(console_server.__name__).setLevel(logging.CRITICAL)

    with tempfile.TemporaryDirectory() as td:
        # `build_app` constructs an ES client and reads the shipped config;
        # stub the client factory so it builds offline, and point the hunts
        # dir at the temp tree so no real YAML is ever touched.
        console_server.make_client = lambda *a, **k: object()
        _real_load_config = console_server.load_config

        def _cfg_with_temp_hunts(path=None, _real=_real_load_config, _dir=td):
            cfg = _real(path)
            cfg.findings.hunts.config_dir = _dir
            return cfg

        console_server.load_config = _cfg_with_temp_hunts
        try:
            app = console_server.build_app(str(REPO / "config" / "default.yaml"))
        finally:
            console_server.load_config = _real_load_config
        client = ASGIClient(app)

        GOOD = {
            "id": "created-hunt",
            "name": "Created Hunt",
            "description": "authored from the console",
            "filters": [{"kind": "window", "last_days": 3}],
        }

        # --- create ----------------------------------------------------
        r = client.post("/api/hunts", json=GOOD)
        check("POST /api/hunts → 201", r.status_code == 201, r.text)
        j = r.json() if r.status_code == 201 else {}
        check("the create response carries the created hunt",
              j.get("id") == "created-hunt"
              and j.get("name") == "Created Hunt"
              and j.get("filters") == GOOD["filters"], r.text)
        check("`_source_path` never crosses the wire",
              "_source_path" not in r.text, r.text)
        # A hunt from a half-formed hypothesis must not start writing
        # findings before the analyst has previewed it.
        check("the created file is on disk disabled",
              load_hunts(td)[0]["enabled"] is False, str(load_hunts(td)))

        r = client.post("/api/hunts", json=GOOD)
        check("re-creating an already-loaded id → 409",
              r.status_code == 409, r.text)

        # A file can exist without being loaded under that id — it may
        # declare a different one inside. Creating would clobber it.
        squatter = Path(td) / "squatter.yaml"
        squatter.write_text(
            "id: other-id\nname: Other\n"
            "filters:\n  - {kind: window, last_days: 1}\n")
        r = client.post("/api/hunts", json={**GOOD, "id": "squatter"})
        check("creating over an existing <id>.yaml → 409",
              r.status_code == 409, r.text)
        check("the file that was in the way is untouched",
              "id: other-id" in squatter.read_text())

        # An id from HTTP becomes a filename — it must never traverse.
        for bad_id in ("../../etc/x", "A_b", "", "x" * 65):
            r = client.post("/api/hunts", json={**GOOD, "id": bad_id})
            check(f"create with id {bad_id!r} → 400",
                  r.status_code == 400, f"{r.status_code} {r.text}")

        before = sorted(f.name for f in Path(td).iterdir())
        r = client.post("/api/hunts", json={
            **GOOD, "id": "bad-filter",
            "filters": [{"kind": "window", "last_days": 0}]})
        check("create with a bad filter → 400", r.status_code == 400, r.text)
        check("the validator's own message reaches the client",
              "last_days" in r.text, r.text)
        check("a refused create writes nothing",
              sorted(f.name for f in Path(td).iterdir()) == before,
              str(sorted(f.name for f in Path(td).iterdir())))

        # `body: dict` would make FastAPI 422 a non-object body before the
        # handler runs, leaving the hand-validated 400 unreachable.
        r = client.post("/api/hunts", json=["not", "an", "object"])
        check("a non-object create body → 400, not 422",
              r.status_code == 400, f"{r.status_code} {r.text}")

        # --- edit ------------------------------------------------------
        (Path(td) / "on.yaml").write_text(
            # `name: On` would parse as the YAML 1.1 boolean; quote it.
            "id: on-hunt\nname: \"On\"\nenabled: true\nowner: opsec\n"
            "filters:\n  - {kind: window, last_days: 7}\n")
        r = client.put("/api/hunts/on-hunt", json={
            "id": "on-hunt", "name": "On renamed", "description": "",
            "filters": [{"kind": "command_count_gte", "threshold": 5}]})
        check("PUT /api/hunts/{id} → 200", r.status_code == 200, r.text)
        edited = {h["id"]: h for h in load_hunts(td)}["on-hunt"]
        check("an edit preserves `enabled: true` through the route",
              r.json().get("enabled") is True and edited["enabled"] is True,
              r.text)
        check("an edit replaces name + filters",
              edited["name"] == "On renamed"
              and edited["filters"] == [{"kind": "command_count_gte",
                                         "threshold": 5}], str(edited))
        # An operator's own top-level keys are not the console's to drop.
        check("an edit keeps unknown top-level keys",
              edited.get("owner") == "opsec", str(edited))

        on_before = (Path(td) / "on.yaml").read_text()
        r = client.put("/api/hunts/on-hunt", json={
            "id": "on-hunt", "name": "On renamed", "description": "",
            "filters": [{"kind": "nonsense"}]})
        check("edit with a bad filter → 400", r.status_code == 400, r.text)
        check("a refused edit leaves the file byte-identical",
              (Path(td) / "on.yaml").read_text() == on_before)

        r = client.put("/api/hunts/on-hunt", json="not an object")
        check("a non-object edit body → 400, not 422",
              r.status_code == 400, f"{r.status_code} {r.text}")

        r = client.put("/api/hunts/no-such-hunt",
                       json={**GOOD, "id": "no-such-hunt"})
        check("PUT an unknown id → 404", r.status_code == 404, r.text)

        # --- delete ----------------------------------------------------
        r = client.delete("/api/hunts/no-such-hunt")
        check("DELETE an unknown id → 404", r.status_code == 404, r.text)

        r = client.delete("/api/hunts/created-hunt")
        check("DELETE → 200 and the YAML file is gone",
              r.status_code == 200
              and not (Path(td) / "created-hunt.yaml").exists(), r.text)

        # --- unloadable directory --------------------------------------
        # One malformed file aborts the whole load, and the loader's error
        # text names an absolute path. Every route must degrade to a 500
        # that says nothing about the operator's filesystem layout.
        (Path(td) / "broken.yaml").write_text(
            "id: broken\nname: Broken\n"
            "filters:\n  - {kind: nonsense}\n")
        for verb, resp in (
            ("create", client.post("/api/hunts",
                                   json={**GOOD, "id": "after-break"})),
            ("edit",   client.put("/api/hunts/on-hunt",
                                  json={**GOOD, "id": "on-hunt"})),
            ("delete", client.delete("/api/hunts/on-hunt")),
        ):
            check(f"{verb} on an unloadable directory → 500",
                  resp.status_code == 500, f"{resp.status_code} {resp.text}")
            check(f"the {verb} 500 quotes no absolute path",
                  td not in resp.text, resp.text)


# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
