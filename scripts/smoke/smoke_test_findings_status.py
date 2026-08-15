"""Smoke test for `enrich.findings.writer.mutate_status` — analyst-state
preservation across re-mines and the status workflow.

Uses an in-memory fake ES client so this can run anywhere.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_findings_status.py
"""
from __future__ import annotations

import logging
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.writer import (  # noqa: E402
    add_note, bulk_mutate_status, bulk_upsert_findings, finding_id, mutate_status,
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


#: Sentinel default for `FakeES.index(refresh=...)`. If the fake defaulted to
#: `False` the "never uses wait_for / defaults to False" assertions would be
#: tautologies — they'd pass even if the writer stopped passing `refresh` at
#: all. Recording a sentinel makes them prove the writer supplied the value.
UNSET_REFRESH = "<unset>"


class FakeIndices:
    def __init__(self, store):
        self._store = store
        self.refresh_calls: list[str] = []

    def exists(self, index):
        return True

    def refresh(self, index):
        self.refresh_calls.append(index)


class FakeES:
    """Minimal in-memory ES stand-in. Implements the surface the writer
    actually touches: get, index, mget, search, and helpers.bulk via a
    side door. Records call counts so the tests can assert the mutation
    path costs a fixed number of round-trips regardless of batch size.

    Every read hands back a deep copy and every write stores one. Real ES
    round-trips through JSON, so a caller can never mutate stored state by
    holding onto a returned `_source`. A shallow copy would leave nested
    values (notably `status_history`) aliased to the stored doc, and the
    history assertions below would then pass without any write happening.
    """

    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.indices = FakeIndices(self.docs)
        self.index_calls: list[dict] = []
        self.mget_calls = 0
        self.search_calls = 0
        self.search_hits: list[dict] = []
        #: ids the next bulk should report as item-level failures.
        self.bulk_item_failures: set[str] = set()
        #: when set, the next bulk raises this instead of writing.
        self.bulk_raises: Exception | None = None
        #: when true, the next bulk emits one error entry carrying no `_id`.
        self.bulk_error_without_id = False
        #: ids whose mget entry comes back found-but-sourceless.
        self.sourceless: set[str] = set()

    def get(self, index, id):
        if id not in self.docs:
            raise LookupError(f"not found: {id}")
        return {"_id": id, "_index": index, "_source": deepcopy(self.docs[id])}

    def index(self, index, id, document, refresh=UNSET_REFRESH):
        self.index_calls.append({"id": id, "refresh": refresh})
        self.docs[id] = deepcopy(document)
        return {"_id": id, "result": "indexed"}

    def mget(self, index, ids, _source=None):
        self.mget_calls += 1
        out = []
        for i in ids:
            if i in self.sourceless:
                out.append({"_id": i, "found": True})
            elif i in self.docs:
                out.append({"_id": i, "found": True, "_source": deepcopy(self.docs[i])})
            else:
                out.append({"_id": i, "found": False})
        return {"docs": out}

    def search(self, **kwargs):
        self.search_calls += 1
        return {"hits": {"hits": list(self.search_hits)}}


# Patch the elasticsearch helpers.bulk used by writer.bulk_upsert_findings.
import enrich.findings.writer as writer_mod  # noqa: E402


BULK_CALLS: list[int] = []


def _fake_bulk(es, actions, stats_only=False, ignore_status=(), *args, **kwargs):
    """Mirrors `elasticsearch.helpers.bulk`'s real signature — `raise_on_error`,
    `chunk_size` and `request_timeout` all arrive as **kwargs there, so a fake
    that named them positionally would reject calls the real client accepts.

    Failure injection is driven off the client so the error branches of
    `bulk_mutate_status` are reachable: the real helper re-raises transport
    errors even under `raise_on_error=False`, and reports item-level failures
    as `{op_type: {"_id": ..., "error": ...}}` entries.
    """
    actions = list(actions)
    BULK_CALLS.append(len(actions))
    if es.bulk_raises is not None:
        raise es.bulk_raises
    n = 0
    errs: list[dict] = []
    if es.bulk_error_without_id:
        errs.append({"index": {"error": {"type": "unattributable"}}})
    for a in actions:
        if a["_id"] in es.bulk_item_failures:
            errs.append({"index": {"_id": a["_id"],
                                   "error": {"type": "version_conflict_engine_exception"}}})
            continue
        if a.get("_op_type") == "index":
            es.docs[a["_id"]] = deepcopy(a["_source"])
            n += 1
    return (n, errs)


writer_mod.bulk = _fake_bulk  # type: ignore[assignment]


print("[1] bulk_upsert creates fresh docs with status=new")
es = FakeES()
findings = [
    {
        "kind": "playbook",
        "run_id": "r-1",
        "artifact": {"kind": "playbook", "value": "sescl-0123456789abcdef"},
        "score": 1.40,
        "narrative": "Mirai-style — 42 sessions",
        "evidence": {"member_sessions": 42, "mean_novelty": 0.31},
    },
    {
        "kind": "campaign",
        "run_id": "r-1",
        "artifact": {"kind": "campaign", "value": "cmp-beh-0123456789abcdef"},
        "score": 6.0,
        "narrative": "behaviour — 30 sessions across 12 IPs",
        "evidence": {"member_sessions": 30, "member_ips": 12},
    },
]
n = bulk_upsert_findings(es, "findings-idx", findings)
check("bulk indexed two docs", n == 2, f"n={n}")
fid_pb = finding_id("playbook", "playbook", "sescl-0123456789abcdef")
fid_cmp = finding_id("campaign", "campaign", "cmp-beh-0123456789abcdef")
check("playbook finding stored", fid_pb in es.docs)
check("campaign finding stored", fid_cmp in es.docs)
check("fresh status is 'new'", es.docs[fid_pb]["status"] == "new")
check("fresh status_history is empty", es.docs[fid_pb]["status_history"] == [])
check("first_seen_at set", bool(es.docs[fid_pb]["first_seen_at"]))


print("\n[2] mutate_status records a history entry")
updated = mutate_status(es, "findings-idx", fid_pb, new_status="ack", note="reviewing")
check("status mutated", updated["status"] == "ack")
check("history length 1", len(updated["status_history"]) == 1)
entry = updated["status_history"][0]
check("history.from = new", entry["from"] == "new")
check("history.to = ack", entry["to"] == "ack")
check("history.note carried", entry["note"] == "reviewing")
check("history.ts present", bool(entry.get("ts")))


print("\n[3] re-mine after status change does NOT overwrite status")
first_seen = es.docs[fid_pb]["first_seen_at"]
findings_remine = [
    {
        "kind": "playbook",
        "run_id": "r-2",
        "artifact": {"kind": "playbook", "value": "sescl-0123456789abcdef"},
        "score": 1.82,   # fresh score
        "narrative": "Mirai-style — 80 sessions",
        "evidence": {"member_sessions": 80, "mean_novelty": 0.42},
    },
]
bulk_upsert_findings(es, "findings-idx", findings_remine)
doc = es.docs[fid_pb]
check("status preserved across re-mine", doc["status"] == "ack")
check("history preserved across re-mine", len(doc["status_history"]) == 1)
check("first_seen_at preserved", doc["first_seen_at"] == first_seen)
check("score updated by re-mine", abs(doc["score"] - 1.82) < 1e-6)
check("narrative updated by re-mine", doc["narrative"] == "Mirai-style — 80 sessions")
check("evidence updated by re-mine",
      doc["evidence"]["member_sessions"] == 80)


print("\n[4] mutate_status rejects invalid statuses")
try:
    mutate_status(es, "findings-idx", fid_pb, new_status="bogus")
    check("invalid status raises", False, "no exception")
except ValueError:
    check("invalid status raises", True)


print("\n[5] mutate_status on missing finding raises LookupError")
try:
    mutate_status(es, "findings-idx", "find-nonexistent", new_status="ack")
    check("missing finding raises", False, "no exception")
except LookupError:
    check("missing finding raises", True)


print("\n[6] same-status no-op does not append a history entry")
prev_history_len = len(es.docs[fid_pb]["status_history"])
mutate_status(es, "findings-idx", fid_pb, new_status="ack")  # already ack
check("history unchanged on same-status",
      len(es.docs[fid_pb]["status_history"]) == prev_history_len)


print("\n[7] single-doc writes never block on the index refresh_interval")
check("no mutation used refresh='wait_for'",
      all(c["refresh"] != "wait_for" for c in es.index_calls),
      f"calls={es.index_calls}")
check("mutate_status defaults to refresh=False",
      all(c["refresh"] is False for c in es.index_calls),
      f"calls={es.index_calls}")

check("every write actually passed a refresh value",
      all(c["refresh"] is not UNSET_REFRESH for c in es.index_calls),
      f"calls={es.index_calls}")

before_note = len(es.index_calls)
add_note(es, "findings-idx", fid_pb, note="a note")
check("add_note issued a write", len(es.index_calls) > before_note,
      f"calls={es.index_calls}")
check("add_note defaults to refresh=False",
      len(es.index_calls) > before_note
      and es.index_calls[before_note]["refresh"] is False,
      f"calls={es.index_calls[before_note:]}")


def _seed_bulk_es(n: int, status: str = "new") -> tuple[FakeES, list[str]]:
    """Fresh fake with `n` findings, all at `status`. Counters start clean."""
    fake = FakeES()
    ids: list[str] = []
    for i in range(n):
        fid = f"find-pbk-{i:016x}"
        ids.append(fid)
        fake.docs[fid] = {
            "finding_id":     fid,
            "kind":           "playbook",
            "status":         status,
            "status_history": [],
            "artifact":       {"kind": "playbook", "value": f"sescl-{i:016x}"},
        }
    BULK_CALLS.clear()
    return fake, ids


print("\n[8] bulk happy path — 2 round-trips regardless of N")
es_b, ids_b = _seed_bulk_es(31)
n_upd, errs = bulk_mutate_status(es_b, "findings-idx", ids_b, new_status="ack")
check("all 31 counted", n_upd == 31, f"n_updated={n_upd}")
check("no errors", errs == [], f"errors={errs}")
check("exactly one mget", es_b.mget_calls == 1, f"mget_calls={es_b.mget_calls}")
check("exactly one bulk", len(BULK_CALLS) == 1, f"bulk_calls={BULK_CALLS}")
check("one bulk carried all 31 actions", BULK_CALLS == [31], f"bulk_calls={BULK_CALLS}")
check("exactly one refresh", len(es_b.indices.refresh_calls) == 1,
      f"refresh_calls={es_b.indices.refresh_calls}")
check("no per-doc es.index calls", es_b.index_calls == [], f"calls={es_b.index_calls}")
check("status applied to every doc",
      all(es_b.docs[i]["status"] == "ack" for i in ids_b))
check("one history entry per doc",
      all(len(es_b.docs[i]["status_history"]) == 1 for i in ids_b))


print("\n[9] bulk no-ops write nothing but still count")
es_n, ids_n = _seed_bulk_es(5, status="ack")
n_upd, errs = bulk_mutate_status(es_n, "findings-idx", ids_n, new_status="ack")
check("no-ops counted as updated", n_upd == 5, f"n_updated={n_upd}")
check("no bulk write emitted", BULK_CALLS == [], f"bulk_calls={BULK_CALLS}")
check("no history appended",
      all(es_n.docs[i]["status_history"] == [] for i in ids_n))
check("no errors on no-op", errs == [], f"errors={errs}")
check("no refresh when nothing was written",
      es_n.indices.refresh_calls == [], f"refresh={es_n.indices.refresh_calls}")


print("\n[10] bulk missing id fails only that id")
es_m, ids_m = _seed_bulk_es(3)
n_upd, errs = bulk_mutate_status(
    es_m, "findings-idx", ids_m + ["find-nonexistent"], new_status="confirmed",
)
check("survivors updated", n_upd == 3, f"n_updated={n_upd}")
check("one error reported", len(errs) == 1, f"errors={errs}")
check("error names the missing id", errs and errs[0]["id"] == "find-nonexistent")
check("error message matches mutate_status wording",
      errs and errs[0]["error"] == "finding not found: find-nonexistent",
      f"errors={errs}")
check("still exactly one bulk", len(BULK_CALLS) == 1, f"bulk_calls={BULK_CALLS}")


print("\n[11] bulk invalid status is rejected before any ES call")
es_i, ids_i = _seed_bulk_es(3)
try:
    bulk_mutate_status(es_i, "findings-idx", ids_i, new_status="bogus")
    check("invalid status raises ValueError", False, "no exception")
except ValueError:
    check("invalid status raises ValueError", True)
check("no mget issued for invalid status", es_i.mget_calls == 0)
check("no bulk issued for invalid status", BULK_CALLS == [], f"bulk_calls={BULK_CALLS}")
check("no refresh issued for invalid status", es_i.indices.refresh_calls == [])


print("\n[12] bulk with empty ids is a no-op")
es_e, _ = _seed_bulk_es(2)
n_upd, errs = bulk_mutate_status(es_e, "findings-idx", [], new_status="ack")
check("empty ids returns (0, [])", (n_upd, errs) == (0, []), f"got=({n_upd}, {errs})")
check("empty ids touches no ES", es_e.mget_calls == 0 and BULK_CALLS == [])


print("\n[13] duplicate ids collapse to one transition")
es_d, ids_d = _seed_bulk_es(2)
n_upd, errs = bulk_mutate_status(
    es_d, "findings-idx", ids_d + ids_d, new_status="ack",
)
check("duplicates counted once", n_upd == 2, f"n_updated={n_upd}")
check("one history entry despite duplicate id",
      all(len(es_d.docs[i]["status_history"]) == 1 for i in ids_d))


print("\n[14] a bulk confirm resolves the cluster run once and threads it to"
      " every anchor")
# The real `_apply_lifecycle_side_effects` runs here on purpose. Stubbing the
# dispatcher would make `search_calls == 1` provable while the value it
# resolved never reached `build_anchor_payload` — the half of the contract
# that actually keeps every anchor in a batch keyed to the same run.
import enrich.findings.lifecycle as lifecycle_mod  # noqa: E402

_cfg = SimpleNamespace(
    elasticsearch=SimpleNamespace(
        indexes=SimpleNamespace(cowrie=SimpleNamespace(
            session_clusters="sc-idx", sessions_rollup="sr-idx",
        )),
    ),
    findings=SimpleNamespace(indexes=SimpleNamespace(
        default="findings-idx",
        playbook_lifecycle="pb-lc-idx",
        campaign_lifecycle="cmp-lc-idx",
    )),
)
COVERAGE_KIND = sorted(lifecycle_mod.COVERAGE_KINDS)[0]


def _seed_coverage_es(n: int, status: str = "new") -> tuple[FakeES, list[str]]:
    fake, ids = _seed_bulk_es(n, status=status)
    for i, fid in enumerate(ids):
        fake.docs[fid]["kind"] = COVERAGE_KIND
        fake.docs[fid]["artifact"] = {"kind": "playbook", "value": f"sescl-{i:016x}"}
    fake.search_hits = [{"_source": {"run_id": "run-ABC"}}]
    return fake, ids


_anchor_calls: list[dict] = []
_real_build = lifecycle_mod.build_anchor_payload
_real_write = lifecycle_mod.write_confirm_anchor


def _capture_build(es, cfg, **kw):
    _anchor_calls.append(kw)
    return {"ts": "now", "source": kw.get("source"),
            "confirmed_run_id": kw.get("confirmed_run_id")}


lifecycle_mod.build_anchor_payload = _capture_build          # type: ignore[assignment]
lifecycle_mod.write_confirm_anchor = lambda *a, **k: None    # type: ignore[assignment]
try:
    es_c, ids_c = _seed_coverage_es(4)
    n_upd, errs = bulk_mutate_status(
        es_c, "findings-idx", ids_c, new_status="confirmed", cfg=_cfg,
    )
    check("confirm batch counted", n_upd == 4, f"n_updated={n_upd}")
    check("latest cluster run resolved exactly once for the batch",
          es_c.search_calls == 1, f"search_calls={es_c.search_calls}")
    check("an anchor was built for every confirmed finding",
          len(_anchor_calls) == 4, f"anchor_calls={len(_anchor_calls)}")
    check("every anchor carries the batch's resolved run id",
          bool(_anchor_calls)
          and all(c.get("confirmed_run_id") == "run-ABC" for c in _anchor_calls),
          f"anchor_calls={_anchor_calls}")

    # A batch whose lookup legitimately finds no run must NOT let
    # build_anchor_payload search again per finding.
    _anchor_calls.clear()
    es_c2, ids_c2 = _seed_coverage_es(3)
    es_c2.search_hits = []
    bulk_mutate_status(es_c2, "findings-idx", ids_c2, new_status="confirmed", cfg=_cfg)
    check("an empty lookup still resolves only once",
          es_c2.search_calls == 1, f"search_calls={es_c2.search_calls}")
    check("an empty lookup threads an explicit None, not 'unset'",
          bool(_anchor_calls)
          and all(c.get("confirmed_run_id") is None for c in _anchor_calls),
          f"anchor_calls={_anchor_calls}")

    # Solo path: no run id supplied, so the anchor builder must resolve
    # one itself — the pre-existing behaviour must survive the new kwarg.
    _anchor_calls.clear()
    es_solo = FakeES()
    fid_solo = "find-pbk-solo"
    es_solo.docs[fid_solo] = {
        "finding_id": fid_solo, "kind": COVERAGE_KIND, "status": "new",
        "status_history": [], "artifact": {"kind": "playbook", "value": "sescl-solo"},
    }
    mutate_status(es_solo, "findings-idx", fid_solo, new_status="confirmed", cfg=_cfg)
    check("solo confirm leaves the run id unresolved for the anchor builder",
          bool(_anchor_calls)
          and _anchor_calls[0].get("confirmed_run_id") is lifecycle_mod.RUN_ID_UNSET,
          f"anchor_calls={_anchor_calls}")
finally:
    lifecycle_mod.build_anchor_payload = _real_build          # type: ignore[assignment]
    lifecycle_mod.write_confirm_anchor = _real_write          # type: ignore[assignment]


print("\n[15] a failing anchor build never fails the status write")
# Real dispatcher again — the matrix row is "anchor build fails", so the
# failure has to originate inside the lifecycle code, not in a stub
# standing in for the dispatcher's own try/except.
logging.getLogger("enrich.findings.writer").setLevel(logging.CRITICAL)


def _explode(es, cfg, **kw):
    raise RuntimeError("anchor build exploded")


lifecycle_mod.build_anchor_payload = _explode                 # type: ignore[assignment]
try:
    es_s, ids_s = _seed_coverage_es(4)
    n_upd, errs = bulk_mutate_status(
        es_s, "findings-idx", ids_s, new_status="confirmed", cfg=_cfg,
    )
    check("side-effect failure did not fail the batch", n_upd == 4, f"n_updated={n_upd}")
    check("side-effect failure produced no errors", errs == [], f"errors={errs}")
    check("status write committed anyway",
          all(es_s.docs[i]["status"] == "confirmed" for i in ids_s))
finally:
    lifecycle_mod.build_anchor_payload = _real_build          # type: ignore[assignment]


print("\n[16] bulk write failures are attributed, not assumed")
es_f, ids_f = _seed_bulk_es(4)
es_f.bulk_item_failures = {ids_f[1]}
n_upd, errs = bulk_mutate_status(es_f, "findings-idx", ids_f, new_status="ack")
check("item-level failure excluded from the count", n_upd == 3, f"n_updated={n_upd}")
check("the failed id is reported", [e["id"] for e in errs] == [ids_f[1]], f"errors={errs}")
check("the survivors were written",
      all(es_f.docs[i]["status"] == "ack" for i in ids_f if i != ids_f[1]))
check("the failed doc was not written", es_f.docs[ids_f[1]]["status"] == "new")

es_r, ids_r = _seed_bulk_es(3)
es_r.bulk_raises = RuntimeError("connection reset")
n_upd, errs = bulk_mutate_status(es_r, "findings-idx", ids_r, new_status="ack")
check("a raising bulk counts nothing", n_upd == 0, f"n_updated={n_upd}")
check("a raising bulk reports every id in the chunk",
      sorted(e["id"] for e in errs) == sorted(ids_r), f"errors={errs}")

es_u, ids_u = _seed_bulk_es(3)
es_u.bulk_error_without_id = True
n_upd, errs = bulk_mutate_status(es_u, "findings-idx", ids_u, new_status="confirmed",
                                 cfg=_cfg)
check("an unattributable error is reported", any(e["id"] == "" for e in errs),
      f"errors={errs}")
check("an unattributable error suppresses the whole chunk's side effects",
      es_u.search_calls == 0, f"search_calls={es_u.search_calls}")


print("\n[17] a found-but-sourceless doc is refused, not overwritten")
es_z, ids_z = _seed_bulk_es(3)
es_z.sourceless = {ids_z[0]}
n_upd, errs = bulk_mutate_status(es_z, "findings-idx", ids_z, new_status="ack")
check("sourceless doc not counted", n_upd == 2, f"n_updated={n_upd}")
check("sourceless doc reported once",
      [e["id"] for e in errs] == [ids_z[0]], f"errors={errs}")
check("sourceless doc left intact — kind/artifact not erased",
      "artifact" in es_z.docs[ids_z[0]] and es_z.docs[ids_z[0]]["status"] == "new",
      f"doc={es_z.docs[ids_z[0]]}")
check("an mget miss and a sourceless doc don't double-report",
      len(errs) == 1, f"errors={errs}")


print("\n[18] the HTTP layer — status codes the library layer can't show")
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

    # Python 3.13 + the pinned anyio can deadlock its worker portal in these
    # in-process route tests. The handlers are pure fakes here, so execute the
    # synchronous endpoint directly on the test loop.
    fastapi_routing.run_in_threadpool = _run_sync_inline

    class ASGIClient:
        """Tiny synchronous facade over httpx's async ASGI transport.

        Starlette's deprecated TestClient deadlocks with the pinned httpx on
        Python 3.13; this exercises the same in-process HTTP surface without a
        lifespan portal thread.
        """
        def __init__(self, app):
            self.app = app

        def post(self, path, **kwargs):
            async def request():
                transport = httpx.ASGITransport(app=self.app)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://testserver",
                ) as client:
                    return await client.post(path, **kwargs)
            return asyncio.run(request())

    logging.getLogger(console_server.__name__).setLevel(logging.CRITICAL)
    es_http, ids_http = _seed_bulk_es(3)
    console_server.make_client = lambda *a, **k: es_http
    app = console_server.build_app(str(REPO / "config" / "default.yaml"))
    client = ASGIClient(app)

    r = client.post("/api/findings/status", json={"ids": ids_http, "status": "bogus"})
    check("bulk invalid status → one 400, not N per-id errors",
          r.status_code == 400, f"{r.status_code} {r.text}")

    r = client.post("/api/findings/status", json={"ids": [], "status": "ack"})
    check("bulk empty ids → 400", r.status_code == 400, f"{r.status_code} {r.text}")
    check("bulk empty ids → 'no ids supplied'", "no ids supplied" in r.text, r.text)

    r = client.post("/api/findings/status",
                    json={"ids": ids_http + ["find-nope"], "status": "ack"})
    check("bulk partial failure stays 200", r.status_code == 200,
          f"{r.status_code} {r.text}")
    body = r.json() if r.status_code == 200 else {}
    check("bulk partial failure reports n_updated", body.get("n_updated") == 3, r.text)
    check("bulk partial failure reports the bad id per-id",
          [e["id"] for e in body.get("errors") or []] == ["find-nope"], r.text)

    before = len(es_http.indices.refresh_calls)
    r = client.post(f"/api/finding/{ids_http[0]}/status", json={"status": "confirmed"})
    check("single status → 200", r.status_code == 200, f"{r.status_code} {r.text}")
    check("single status forces exactly one refresh",
          len(es_http.indices.refresh_calls) == before + 1,
          f"refresh={es_http.indices.refresh_calls}")

    r = client.post("/api/finding/find-nope/status", json={"status": "ack"})
    check("single status on a missing id → 404", r.status_code == 404,
          f"{r.status_code} {r.text}")

    r = client.post(f"/api/finding/{ids_http[0]}/status", json={"status": "bogus"})
    check("single invalid status → 400", r.status_code == 400,
          f"{r.status_code} {r.text}")

    before = len(es_http.indices.refresh_calls)
    r = client.post(f"/api/finding/{ids_http[1]}/note", json={"note": "looked at it"})
    check("note → 200", r.status_code == 200, f"{r.status_code} {r.text}")
    check("note forces exactly one refresh",
          len(es_http.indices.refresh_calls) == before + 1,
          f"refresh={es_http.indices.refresh_calls}")

    r = client.post(f"/api/finding/{ids_http[1]}/note", json={"note": "  "})
    check("empty note → 400", r.status_code == 400, f"{r.status_code} {r.text}")


print(f"\n--- {len(PASSED)} passed, {len(FAILED)} failed ---")
if FAILED:
    for name, detail in FAILED:
        print(f"  FAILED  {name}  {detail}")
    sys.exit(1)
