"""Smoke test for the item-56 unminted-anchor gate ladder
(`scripts/diagnose_unminted_playbook.py`). Offline: no ES, no network, no LLM.

Covers every row of the spec's I/O matrix — at the level each row is implemented,
so the `no_anchor_library` / `no_novel_pool` rows drive `diagnose()` end-to-end
against a scripted fake ES rather than only the pure ladder underneath it — plus
the headline geometry: a playbook group whose centroid sits at cosine 0.96 to an
incumbent anchor while every member session sits at 0.91, which must be reported
as a confirmed centroid-vs-member mismatch, not as a missing behaviour.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

import diagnose_unminted_playbook as dux
from diagnose_unminted_playbook import (
    GATE_ORDER,
    cosine_summary,
    diagnose,
    evaluate_gates,
    group_has_public_commands,
    load_latest_run,
    load_naming_clusters,
    load_pool_inputs,
    pool_group_labels,
    public_filters,
    summarize,
    verdict,
    window_cutoff,
    zeroed_gates,
)
from eval_novel_pool import cluster_novel_pool

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


def _u(v):
    a = np.asarray(v, dtype=np.float32)
    return a / np.linalg.norm(a)


def _gate(gates, name):
    return next(g for g in gates if g["gate"] == name)


def _reconciles(gates, pool_size) -> bool:
    """The invariant the spec names: eliminations + survivors == pool size."""
    eliminated = sum(g["eliminated"] for g in gates)
    return 0 <= eliminated <= pool_size and (pool_size - eliminated) >= 0


ANCHOR = _u([1.0, 0.0, 0.0])
INCUMBENT = "spb-0000000000000001"
SECOND_ANCHOR = "spb-0000000000000002"
ANCHORS = [(ANCHOR, INCUMBENT)]
# A cluster centroid at cosine 0.96 to the incumbent anchor.
CENTROID_096 = _u([0.96, float(np.sqrt(1.0 - 0.96 ** 2)), 0.0])
# Members on the cone at cosine 0.91 — inside the cluster, outside the anchor.
_R = float(np.sqrt(1.0 - 0.91 ** 2))
MEMBERS_091 = [
    _u([0.91, _R * float(np.cos(t)), _R * float(np.sin(t))])
    for t in np.linspace(0.0, 2.0 * np.pi, 6, endpoint=False)
]

RUN_ALLTIME = {"run_id": "run-1", "@timestamp": "2026-07-29T00:00:00Z", "window_days": 0,
               "total_docs": 100, "n_clusters": 3, "n_outliers": 1}


def _rows(cluster_id, embeddings, in_window=True, start=0, status="novel"):
    return [
        {"session_id": f"s{start + i}", "cluster_id": cluster_id, "in_window": in_window,
         "assignment_status": status, "embedding": emb}
        for i, emb in enumerate(embeddings)
    ]


def _always_commands(_sids):
    return True


def _run_ladder(pool, run=RUN_ALLTIME, visible=None, clusters_in_run=None,
                anchors=ANCHORS, probe=_always_commands, merge_threshold=0.94):
    visible = [{"cluster_id": "cluster_1", "size": 12,
                "centroid": CENTROID_096.tolist()}] if visible is None else visible
    if clusters_in_run is None:
        clusters_in_run = len(visible)
    return evaluate_gates(
        pool, run, visible, clusters_in_run, anchors,
        merge_threshold=merge_threshold, assignment_tau=0.94, commands_probe=probe,
    )


# --- Headline: centroid-vs-member mismatch -------------------------------------

pool = _rows("cluster_1", MEMBERS_091)
gates = _run_ladder(pool)
g5 = _gate(gates, GATE_ORDER[5])
g6 = _gate(gates, GATE_ORDER[6])
check("G5 eliminates the whole pool (id reused, no mint)",
      g5["eliminated"] == len(pool), str(g5))
check("G5 names the incumbent anchor it folded into",
      g5["detail"]["groups"][0]["matched_anchor"] == INCUMBENT, str(g5["detail"]))
check("G5 reports the group centroid's cosine at ~0.96",
      abs(g5["detail"]["groups"][0]["matched_cosine"] - 0.96) < 0.005,
      str(g5["detail"]["groups"][0]))
check("G6 measured the member distribution", g6["detail"]["measured"] is True)
check("G6 members sit at ~0.91, not 0.96",
      abs(g6["detail"]["member_cosines"]["median"] - 0.91) < 0.005,
      str(g6["detail"]["member_cosines"]))
check("G6 no member clears tau=0.94",
      g6["detail"]["member_cosines"]["fraction_ge_tau"] == 0.0,
      str(g6["detail"]["member_cosines"]))
check("G6 flags the mismatch", g6["detail"]["mismatch"] is True, str(g6["detail"]))
check("G6 sessions_in is the population G5 eliminated",
      g6["sessions_in"] == g5["eliminated"], str(g6["sessions_in"]))
line = verdict(gates, len(pool))
check("verdict names G5 and confirms the mismatch",
      line.startswith(GATE_ORDER[5]) and "CONFIRMED" in line, line)
check("accounting reconciles (mismatch fixture)", _reconciles(gates, len(pool)),
      str([g["eliminated"] for g in gates]))
check("every gate is present in production order",
      [g["gate"] for g in gates] == list(GATE_ORDER), str([g["gate"] for g in gates]))

# --- The mismatch result survives an earlier gate firing first -------------------

early = _rows("cluster_1", MEMBERS_091[:3]) + _rows(
    "cluster_1", MEMBERS_091[3:], in_window=False, start=3)
gates_early = _run_ladder(early, run={**RUN_ALLTIME, "window_days": 30})
line_early = verdict(gates_early, len(early))
check("verdict names the FIRST firing gate", line_early.startswith(GATE_ORDER[0]), line_early)
check("verdict still surfaces the centroid-vs-member result",
      "Centroid-vs-member" in line_early and "CONFIRMED" in line_early, line_early)

# --- G0: the naming run never saw them ------------------------------------------

g0 = _gate(gates_early, GATE_ORDER[0])
check("G0 eliminates out-of-window pool sessions", g0["eliminated"] == 3, str(g0))
check("G0 reports the window", g0["detail"]["window_days"] == 30, str(g0["detail"]))
check("G0 reports the persisted novelty distribution",
      g0["detail"]["persisted_assignment_status"] == {"novel": 6},
      str(g0["detail"]["persisted_assignment_status"]))
check("G0 flags disagreement with persisted novelty",
      _gate(_run_ladder(_rows("cluster_1", MEMBERS_091, status="assigned")),
            GATE_ORDER[0])["detail"]["disagrees_with_persisted_novelty"] == 6)
check("accounting reconciles (G0 fixture)", _reconciles(gates_early, len(early)),
      str([g["eliminated"] for g in gates_early]))

# --- G1: not visible to naming — truncation vs a stale cluster id ----------------

gates_trunc = _run_ladder(_rows("cluster_9999", MEMBERS_091), clusters_in_run=1500)
g1t = _gate(gates_trunc, GATE_ORDER[1])
check("G1 eliminates sessions whose cluster naming cannot see",
      g1t["eliminated"] == len(MEMBERS_091), str(g1t))
check("G1 flags genuine truncation", g1t["detail"]["truncated"] is True, str(g1t["detail"]))
check("G1 attributes truncation as the cause",
      g1t["detail"]["cause"] == "size_1000_truncation", str(g1t["detail"]))
check("G1 discloses the unsorted-draw caveat",
      g1t["detail"]["unsorted_draw_caveat"] is not None, str(g1t["detail"]))

gates_stale = _run_ladder(_rows("cluster_9999", MEMBERS_091), clusters_in_run=12)
g1s = _gate(gates_stale, GATE_ORDER[1])
check("G1 fires on a stale cluster id with no truncation",
      g1s["eliminated"] == len(MEMBERS_091) and g1s["detail"]["truncated"] is False,
      str(g1s))
check("G1 does NOT blame truncation when nothing was truncated",
      g1s["detail"]["cause"] == "stale_or_absent_cluster_id", str(g1s["detail"]))
check("G1's gate name does not assert truncation",
      "truncation" not in GATE_ORDER[1], GATE_ORDER[1])
check("G1 does not fire below the cut",
      _gate(_run_ladder(_rows("cluster_1", MEMBERS_091)), GATE_ORDER[1])["eliminated"] == 0)

# --- G2: outlier / no cluster / centroid-less cluster ---------------------------

g2_pool = (_rows("outlier", MEMBERS_091[:2])
           + _rows(None, MEMBERS_091[2:4], start=2)
           + _rows("cluster_nc", MEMBERS_091[4:], start=4))
gates2 = _run_ladder(g2_pool, visible=[
    {"cluster_id": "cluster_1", "size": 12, "centroid": CENTROID_096.tolist()},
    {"cluster_id": "cluster_nc", "size": 3},
])
g2 = _gate(gates2, GATE_ORDER[2])
check("G2 eliminates outliers, unassigned and centroid-less clusters",
      g2["eliminated"] == 6, str(g2))
check("G2 breaks the reason down",
      (g2["detail"]["outlier"], g2["detail"]["no_cluster_assignment"],
       g2["detail"]["cluster_without_centroid"]) == (2, 2, 2), str(g2["detail"]))

# --- G3: merge absorb is descriptive, never eliminates ---------------------------

absorb_visible = [
    {"cluster_id": "cluster_1", "size": 6, "centroid": CENTROID_096.tolist()},
    {"cluster_id": "cluster_2", "size": 400, "centroid": _u([0.99, 0.14, 0.0]).tolist()},
]
gates3 = _run_ladder(_rows("cluster_1", MEMBERS_091), visible=absorb_visible)
g3 = _gate(gates3, GATE_ORDER[3])
check("G3 eliminates nobody", g3["eliminated"] == 0, str(g3["eliminated"]))
check("G3 reports absorption with an incumbent cluster",
      g3["detail"]["groups"][0]["absorbed_with_incumbents"] is True, str(g3["detail"]))
check("G3 merged both clusters into one playbook group",
      g3["detail"]["playbook_groups"] == 1, str(g3["detail"]["playbook_groups"]))
check("absorbed group still ends in a reuse",
      _gate(gates3, GATE_ORDER[5])["eliminated"] == len(MEMBERS_091))

# --- G4: the three pre-mint skips ------------------------------------------------

named_visible = [{"cluster_id": "cluster_1", "size": 12, "playbook_name": "SSH persistence",
                  "centroid": CENTROID_096.tolist()}]
gates_named = _run_ladder(_rows("cluster_1", MEMBERS_091), visible=named_visible)
g4_named = _gate(gates_named, GATE_ORDER[4])
check("G4 fires on skipped_already_named", g4_named["eliminated"] == len(MEMBERS_091),
      str(g4_named))
check("G4 names the skipped group",
      g4_named["detail"]["skipped_already_named"] != [], str(g4_named["detail"]))
check("G4 skips ahead of G5 (production order)",
      _gate(gates_named, GATE_ORDER[5])["eliminated"] == 0)

g4_nocmd = _gate(_run_ladder(_rows("cluster_1", MEMBERS_091), probe=lambda _s: False),
                 GATE_ORDER[4])
check("G4 fires on skipped_no_commands", g4_nocmd["eliminated"] == len(MEMBERS_091),
      str(g4_nocmd))
check("G4 marks the command probe conservative",
      g4_nocmd["detail"]["no_commands_probe"] == "public_only_conservative")

# --- G5: in-run anchor accumulation, argmax fidelity, null centroid ---------------

# Three clusters at 0°/10°/20.5° off a shared axis. Complete linkage cannot put all
# three in one playbook group (0°~20.5° is 0.9367, below 0.94), so it yields
# pg0={cluster_1,cluster_2} and pg1={cluster_3} — whose centroids sit at 0.9636.
# With an empty anchor library pg0 mints, and production then folds pg1 into that
# same-run mint. Against a static library pg1 would read `would_mint` instead.
def _axis(deg):
    rad = float(np.pi * deg / 180.0)
    return _u([float(np.cos(rad)), float(np.sin(rad)), 0.0])


accum_visible = [
    {"cluster_id": "cluster_1", "size": 6, "centroid": _axis(0.0).tolist()},
    {"cluster_id": "cluster_2", "size": 6, "centroid": _axis(10.0).tolist()},
    {"cluster_id": "cluster_3", "size": 6, "centroid": _axis(20.5).tolist()},
]
accum_pool = (_rows("cluster_1", MEMBERS_091[:3])
              + _rows("cluster_3", MEMBERS_091[3:], start=3))
gates_accum = _run_ladder(accum_pool, visible=accum_visible, anchors=[])
g5a = _gate(gates_accum, GATE_ORDER[5])
outcomes = sorted(g["outcome"] for g in g5a["detail"]["groups"])
check("G5 models production's in-run anchor accumulation",
      outcomes == ["id_reused", "would_mint"], str(outcomes))
check("G5 counts the anchors minted during the run",
      g5a["detail"]["anchors_minted_in_run"] == 1, str(g5a["detail"]))
check("G5 eliminates only the group folded into the in-run mint",
      g5a["eliminated"] == 3, str(g5a["eliminated"]))

two_anchors = [(ANCHOR, INCUMBENT), (CENTROID_096, SECOND_ANCHOR)]
g5m = _gate(_run_ladder(_rows("cluster_1", MEMBERS_091), anchors=two_anchors), GATE_ORDER[5])
matched = g5m["detail"]["groups"][0]
best = max(g5m["detail"]["groups"][0]["top3_anchor_cosines"], key=lambda a: a["cosine"])
check("matched_cosine belongs to matched_anchor (multi-anchor library)",
      matched["matched_anchor"] == best["playbook_id"]
      and abs(matched["matched_cosine"] - best["cosine"]) < 1e-9, str(matched))
check("G5 ranks the whole anchor library",
      len(matched["top3_anchor_cosines"]) == 2, str(matched["top3_anchor_cosines"]))

g5n = _gate(_run_ladder(_rows("cluster_nc", MEMBERS_091),
                        visible=[{"cluster_id": "cluster_nc", "size": 3,
                                  "centroid": []}]), GATE_ORDER[5])
check("a centroid-less group is eliminated at G2, never silently dropped",
      g5n["eliminated"] == 0
      and _gate(_run_ladder(_rows("cluster_nc", MEMBERS_091),
                            visible=[{"cluster_id": "cluster_nc", "size": 3,
                                      "centroid": []}]),
                GATE_ORDER[2])["eliminated"] == len(MEMBERS_091), str(g5n))

# --- No gate fires: the behaviour really would mint ------------------------------

far_visible = [{"cluster_id": "cluster_1", "size": 12,
                "centroid": _u([0.0, 1.0, 0.0]).tolist()}]
gates_mint = _run_ladder(_rows("cluster_1", MEMBERS_091), visible=far_visible)
check("no gate eliminates a genuinely new behaviour",
      sum(g["eliminated"] for g in gates_mint) == 0,
      str([g["eliminated"] for g in gates_mint]))
check("verdict says the mint block is reached",
      verdict(gates_mint, len(MEMBERS_091)).startswith("no_gate_fires"),
      verdict(gates_mint, len(MEMBERS_091)))
check("G5 reports would_mint",
      _gate(gates_mint, GATE_ORDER[5])["detail"]["groups"][0]["outcome"] == "would_mint")
check("G6 is not measured when nothing was reused",
      _gate(gates_mint, GATE_ORDER[6])["detail"]["measured"] is False)
check("accounting reconciles with nonzero survivors",
      _reconciles(gates_mint, len(MEMBERS_091))
      and len(MEMBERS_091) - sum(g["eliminated"] for g in gates_mint) == len(MEMBERS_091),
      str([g["eliminated"] for g in gates_mint]))

gates_noanchor = _run_ladder(_rows("cluster_1", MEMBERS_091), anchors=[])
check("empty anchor library eliminates nobody",
      sum(g["eliminated"] for g in gates_noanchor) == 0,
      str([g["eliminated"] for g in gates_noanchor]))
check("empty pool yields the no_novel_pool verdict",
      verdict([], 0).startswith("no_novel_pool"), verdict([], 0))
check("zeroed_gates emits all seven at zero",
      [g["gate"] for g in zeroed_gates()] == list(GATE_ORDER)
      and all(g["sessions_in"] == 0 and g["eliminated"] == 0 for g in zeroed_gates()))

# --- window arithmetic ------------------------------------------------------------

RUN_TS = "2026-07-29T06:30:00Z"
check("all-time run has no cutoff", window_cutoff(0, RUN_TS) is None)
check("windowed cutoff is floored to a day boundary, anchored to the run",
      window_cutoff(30, RUN_TS).isoformat() == "2026-06-29T00:00:00+00:00",
      str(window_cutoff(30, RUN_TS)))
check("cutoff falls back to now when the run has no timestamp",
      window_cutoff(30, None) is not None)
cutoff30 = window_cutoff(30, RUN_TS)
check("all-time run puts everything in window", dux._in_window("2020-01-01T00:00:00Z", None))
check("recent session is in a 30d window", dux._in_window("2026-07-20T00:00:00Z", cutoff30))
check("old session is out of a 30d window",
      not dux._in_window("2026-01-01T00:00:00Z", cutoff30))
check("session exactly on the day boundary is in window",
      dux._in_window("2026-06-29T00:00:00Z", cutoff30))
check("session just before the boundary is out",
      not dux._in_window("2026-06-28T23:59:59Z", cutoff30))
check("missing timestamp is never blamed on scope", dux._in_window(None, cutoff30))
check("unparseable timestamp is never blamed on scope",
      dux._in_window("not-a-date", cutoff30))
check("naive timestamp is treated as UTC", dux._in_window("2026-07-20T00:00:00", cutoff30))
check("the cutoff does not drift with the diagnostic's own clock",
      window_cutoff(30, "2026-01-15T12:00:00Z").isoformat() == "2025-12-16T00:00:00+00:00",
      str(window_cutoff(30, "2026-01-15T12:00:00Z")))

# --- cosine_summary --------------------------------------------------------------

summary = cosine_summary([0.90, 0.91, 0.92, 0.99], 0.94)
check("cosine_summary reports n/median/max",
      (summary["n"], summary["median"], summary["max"]) == (4, 0.915, 0.99), str(summary))
check("cosine_summary reports the tau-clearing fraction",
      summary["fraction_ge_tau"] == 0.25, str(summary))
check("cosine_summary handles an empty distribution", cosine_summary([], 0.94) == {"n": 0})

# --- pool_group_labels agrees with the aggregate implementation ------------------

rng = np.random.default_rng(56)
blob_a = rng.normal(0.0, 0.02, size=(40, 8)) + np.array([1.0] + [0.0] * 7)
blob_b = rng.normal(0.0, 0.02, size=(40, 8)) + np.array([0.0, 1.0] + [0.0] * 6)
pool_emb = np.vstack([blob_a, blob_b]).astype(np.float32)
pool_scalars = [{"command_count": 3, "unique_commands": 2,
                 "login_success_rate": 1.0, "mean_novelty_score": 0.1}] * 80
kwargs = dict(min_cluster_size=5, min_samples=3, scalar_weight=0.0,
              rescue_threshold=0.94, merge_threshold=0.94, svd_dim=0, n_jobs=1)
labels = pool_group_labels(pool_emb, pool_scalars, **kwargs)
shape = cluster_novel_pool(pool_emb, pool_scalars, **kwargs)
n_groups = len({int(x) for x in labels if int(x) >= 0})
check("labelled clustering matches cluster_novel_pool's group count",
      n_groups == shape["playbook_groups"], f"{n_groups} vs {shape['playbook_groups']}")
check("labelled clustering separates the two blobs", n_groups == 2, str(n_groups))
check("too-few-rows pool degrades to all-outlier",
      set(int(x) for x in pool_group_labels(pool_emb[:2], pool_scalars[:2], **kwargs)) == {-1})


# --- ES-facing helpers, with a recording fake -------------------------------------

class FakeES:
    """Records every call so the test can assert read-only, public-only access.

    `search_results` / `count_results` may map an index to a single response or to
    a FIFO list of responses (a `_scan` loop needs a terminating empty page).
    """

    def __init__(self, search_results=None, count_results=None, exists=True):
        self.search_results = {k: list(v) if isinstance(v, list) else [v]
                               for k, v in (search_results or {}).items()}
        self.count_results = {k: list(v) if isinstance(v, list) else [v]
                              for k, v in (count_results or {}).items()}
        self.calls: list[tuple[str, str, dict]] = []
        self.indices = SimpleNamespace(exists=self._exists)
        self._exists_value = exists

    def _exists(self, index):
        self.calls.append(("indices.exists", index, {}))
        return self._exists_value

    def _next(self, store, index, default):
        queue = store.get(index)
        if not queue:
            return default
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def search(self, index, **kwargs):
        self.calls.append(("search", index, kwargs))
        return self._next(self.search_results, index, {"hits": {"hits": []}})

    def count(self, index, **kwargs):
        self.calls.append(("count", index, kwargs))
        return self._next(self.count_results, index, {"count": 0})


CFG = SimpleNamespace()  # no `classification` attr → fail-safe posture
EXPLICIT_PUBLIC = {"term": {dux.CLASSIFICATION_KEYWORD: dux.PUBLIC}}

check("public_filters is the explicit fail-safe public term",
      public_filters(CFG) == [EXPLICIT_PUBLIC], str(public_filters(CFG)))

run_hit = {"hits": {"hits": [{"_source": {"run_id": "run-7", "window_days": 30,
                                          "@timestamp": "2026-07-29T00:00:00Z",
                                          "total_docs": 8636, "n_clusters": 12}}]}}
es = FakeES({"clusters": run_hit})
run = load_latest_run(es, "clusters")
check("load_latest_run returns the newest run_summary", run["run_id"] == "run-7", str(run))
check("load_latest_run sorts newest first",
      es.calls[0][2]["sort"] == [{"@timestamp": "desc"}], str(es.calls[0][2]))
check("load_latest_run fetches the run's own timestamp",
      "@timestamp" in es.calls[0][2]["_source"] and run["@timestamp"],
      str(es.calls[0][2]["_source"]))

try:
    load_latest_run(FakeES(), "clusters")
    check("missing run_summary raises", False, "no exception")
except RuntimeError as exc:
    check("missing run_summary raises", "cluster sessions" in str(exc), str(exc))

try:
    load_latest_run(FakeES({"clusters": {"hits": {"hits": [{"_source": {}}]}}}), "clusters")
    check("run_summary without run_id raises", False, "no exception")
except RuntimeError as exc:
    check("run_summary without run_id raises", "run_id" in str(exc), str(exc))

cluster_docs = {"hits": {"hits": [{"_source": {"cluster_id": "cluster_1", "size": 4}}]}}
es = FakeES({"clusters": cluster_docs}, {"clusters": {"count": 1500}})
visible, total = load_naming_clusters(es, "clusters", "run-7")
check("load_naming_clusters mirrors the production size=1000 load",
      es.calls[0][2]["size"] == dux.NAMING_CLUSTER_LOAD_SIZE == 1000, str(es.calls[0][2]))
check("load_naming_clusters returns the visible docs", len(visible) == 1, str(visible))
check("load_naming_clusters counts the run's true cluster total", total == 1500, str(total))
check("load_naming_clusters counts the same query it searched",
      es.calls[1][2]["query"] == es.calls[0][2]["query"], str(es.calls))

es = FakeES(count_results={"events": {"count": 3}})
found = group_has_public_commands(es, "events", ["s0", "s1"], public_filters(CFG))
check("command probe is True when public command events exist", found is True)
check("command probe carries the public-only filter",
      EXPLICIT_PUBLIC in es.calls[0][2]["query"]["bool"]["filter"], str(es.calls[0][2]))
check("command probe never names a command-text field",
      "process.command_line" not in str(es.calls[0][2]), str(es.calls[0][2]))
check("command probe is False with no session ids",
      group_has_public_commands(FakeES(), "events", [], public_filters(CFG)) is False)
check("command probe is False when nothing public matches",
      group_has_public_commands(FakeES(count_results={"events": {"count": 0}}),
                                "events", ["s0"], public_filters(CFG)) is False)


# --- diagnose() end to end, against a scripted fake ES ----------------------------

IDX = SimpleNamespace(sessions_rollup="rollup", playbook_anchors="anchors",
                      commands="commands", session_clusters="clusters",
                      sessions_raw="events")


def make_cfg(**session_overrides):
    session = dict(
        assignment_tau=0.94, assignment_rescue_tau=0.94, assignment_confident_tau=0.98,
        assignment_tfidf_tau=0.80, playbook_merge_threshold=0.94,
        playbook_naming_session_cap=500, cluster_min_cluster_size=3,
        cluster_min_samples=2, cluster_scalar_weight=0.0, cluster_svd_dim=0,
    )
    session.update(session_overrides)
    return SimpleNamespace(
        session=SimpleNamespace(**session),
        worker=SimpleNamespace(cluster_n_jobs=1),
        elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=IDX)),
    )


def _session_doc(i, emb, cluster_id, ts="2026-07-28T00:00:00Z"):
    return {
        "_id": f"s{i}", "sort": [i],
        "_source": {
            "@timestamp": ts,
            "cowrie": {"session_id": f"s{i}"},
            "dshield": {"cowrie": {"enrichment": {"session": {
                "embedding": [float(x) for x in emb],
                "command_set": ["h1"],
                "command_count": 3, "unique_commands": 2,
                "login_success_count": 1, "login_fail_count": 0,
                "mean_novelty_score": 0.1,
                "cluster": {"id": cluster_id, "assignment_status":
                            "novel" if cluster_id == "cluster_1" else "assigned"},
            }}}},
        },
    }


# 4 sessions sitting on the anchor (confidently assigned) + 6 novel members tightly
# grouped at cosine 0.91 to it. The live cluster doc's centroid is 0.96 — it also
# covers non-pool sessions, which is exactly how a centroid outruns its members.
BASE_091 = np.array([0.91, _R, 0.0], dtype=np.float32)
_jit = np.random.default_rng(7)
# Enough spread for HDBSCAN to see a density peak (perfectly duplicate points are
# all noise), still tight enough that every member lands at cosine ~0.91.
TIGHT_091 = [_u(BASE_091 + _jit.normal(0.0, 0.01, 3).astype(np.float32)) for _ in range(8)]
session_docs = ([_session_doc(i, ANCHOR, "cluster_0") for i in range(4)]
                + [_session_doc(4 + i, e, "cluster_1") for i, e in enumerate(TIGHT_091)])
anchor_hit = {"hits": {"hits": [{"_id": INCUMBENT, "_source": {
    "playbook_id": INCUMBENT, "anchor_centroid": [float(x) for x in ANCHOR]}}]}}
taxonomy_hit = {"hits": {"hits": [{"_id": "h1", "sort": [0], "_source": {"dshield": {
    "cowrie": {"enrichment": {"cluster": {"id": "cluster_5", "is_outlier": False}}}}}}]}}
EMPTY = {"hits": {"hits": []}}


def scripted_es(**over):
    base = dict(
        search_results={
            "anchors": [anchor_hit, anchor_hit],
            "rollup": [{"hits": {"hits": session_docs}}, EMPTY, EMPTY],
            "commands": [taxonomy_hit, EMPTY],
            "clusters": [
                {"hits": {"hits": [{"_source": {
                    "run_id": "run-9", "@timestamp": "2026-07-29T00:00:00Z",
                    "window_days": 0, "total_docs": 10, "n_clusters": 2,
                    "n_outliers": 0}}]}},
                {"hits": {"hits": [
                    {"_source": {"cluster_id": "cluster_0", "size": 4,
                                 "centroid": [float(x) for x in ANCHOR]}},
                    {"_source": {"cluster_id": "cluster_1", "size": 12,
                                 "centroid": [float(x) for x in CENTROID_096]}},
                ]}},
            ],
        },
        count_results={"clusters": {"count": 2}, "events": {"count": 9}},
    )
    base.update(over)
    return FakeES(**base)


es = scripted_es()
report = diagnose(es, make_cfg())
check("diagnose runs end to end and finds the novel pool",
      report["pool_size"] == 8 and report["novel"] == 8,
      f"pool={report.get('pool_size')} novel={report.get('novel')}")
check("diagnose reports every gate G0-G6",
      [g["gate"] for g in report["gates"]] == list(GATE_ORDER),
      str([g["gate"] for g in report["gates"]]))
check("diagnose's accounting reconciles exactly",
      sum(g["eliminated"] for g in report["gates"])
      + report["survivors_reaching_mint"] == report["pool_size"], str(report["gates"]))
check("diagnose reaches the centroid-vs-member verdict",
      report["verdict"].startswith(GATE_ORDER[5]) and "CONFIRMED" in report["verdict"],
      report["verdict"])
check("diagnose labels itself read-only and public-only",
      report["read_only"] is True and report["session_classification"] == "public_only")
check("diagnose records the naming run's timestamp",
      report["naming_run"]["@timestamp"] == "2026-07-29T00:00:00Z", str(report["naming_run"]))
check("summarize renders without raising and names the verdict",
      GATE_ORDER[5] in summarize(report) and "verdict:" in summarize(report))

writes = [c for c in es.calls if c[0] not in ("search", "count", "indices.exists")]
check("diagnose issues no write of any kind", writes == [], str(writes))
cowrie_searches = [c for c in es.calls
                   if c[0] == "search" and c[1] in ("rollup", "commands")]
check("every cowrie-index search carries the public-only filter",
      len(cowrie_searches) >= 3 and all(
          EXPLICIT_PUBLIC in c[2]["query"]["bool"]["filter"] for c in cowrie_searches),
      str([c[1] for c in cowrie_searches]))
check("the raw-events probe carries it too",
      all(EXPLICIT_PUBLIC in c[2]["query"]["bool"]["filter"]
          for c in es.calls if c[0] == "count" and c[1] == "events"))
check("no session id, IP or command text appears in the report",
      not any(tok in str(report) for tok in ("s0", "s4", "h1", "process.command_line")),
      str(report)[:200])

# I/O matrix — empty anchor library
inputs, rows = load_pool_inputs(
    FakeES(search_results={"anchors": EMPTY,
                           "rollup": [{"hits": {"hits": session_docs}}, EMPTY]}),
    make_cfg())
check("load_pool_inputs returns no inputs when the anchor library is empty",
      inputs is None and len(rows) == 12, str(inputs))
report_na = diagnose(scripted_es(search_results={
    "anchors": EMPTY, "rollup": [{"hits": {"hits": session_docs}}, EMPTY],
    "commands": [taxonomy_hit, EMPTY], "clusters": [EMPTY, EMPTY],
}), make_cfg())
check("empty anchor library yields the no_anchor_library verdict",
      report_na["verdict"].startswith("no_anchor_library"), report_na["verdict"])
check("early return still emits all seven zeroed gates",
      [g["gate"] for g in report_na["gates"]] == list(GATE_ORDER)
      and sum(g["eliminated"] for g in report_na["gates"]) == 0, str(report_na["gates"]))

# I/O matrix — empty pool (every session sits on the anchor)
on_anchor = [_session_doc(i, ANCHOR, "cluster_0") for i in range(6)]
report_np = diagnose(scripted_es(search_results={
    "anchors": [anchor_hit, anchor_hit],
    "rollup": [{"hits": {"hits": on_anchor}}, EMPTY, EMPTY],
    "commands": [taxonomy_hit, EMPTY],
    "clusters": [EMPTY, EMPTY],
}), make_cfg())
check("a fully-assigned corpus yields the no_novel_pool verdict",
      report_np["verdict"].startswith("no_novel_pool"), report_np["verdict"])
check("no_novel_pool still emits all seven zeroed gates",
      [g["gate"] for g in report_np["gates"]] == list(GATE_ORDER), str(report_np["gates"]))

# I/O matrix — no completed cluster run
try:
    diagnose(scripted_es(search_results={
        "anchors": [anchor_hit, anchor_hit],
        "rollup": [{"hits": {"hits": session_docs}}, EMPTY, EMPTY],
        "commands": [taxonomy_hit, EMPTY], "clusters": [EMPTY],
    }), make_cfg())
    check("no completed cluster run raises", False, "no exception")
except RuntimeError as exc:
    check("no completed cluster run raises", "cluster sessions" in str(exc), str(exc))

# Config guards
for label, overrides, needle in (
    ("a configured rescue tier", {"assignment_rescue_tau": 0.90}, "rescue"),
    ("a non-positive naming cap", {"playbook_naming_session_cap": 0}, "cap"),
):
    try:
        diagnose(scripted_es(), make_cfg(**overrides))
        check(f"diagnose refuses {label}", False, "no exception")
    except ValueError as exc:
        check(f"diagnose refuses {label}", needle in str(exc).lower(), str(exc))

try:
    diagnose(FakeES(exists=False), make_cfg())
    check("a missing index raises an actionable error", False, "no exception")
except RuntimeError as exc:
    check("a missing index raises an actionable error", "init-indexes" in str(exc), str(exc))


# --- CLI gating: no live path without operator confirmation ----------------------

def _explode(*_a, **_k):
    raise AssertionError("ES client constructed before operator confirmation")


_saved_client, _saved_argv = dux.make_client, sys.argv
dux.make_client = _explode
try:
    sys.argv = ["diagnose_unminted_playbook.py"]
    try:
        dux.main()
        check("missing confirmation flag exits non-zero", False, "main() returned")
    except SystemExit as exc:
        check("missing confirmation flag exits non-zero", exc.code == 2, str(exc.code))
    except AssertionError:
        check("missing confirmation flag exits before touching ES", False,
              "make_client was called")
finally:
    dux.make_client, sys.argv = _saved_client, _saved_argv


print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for name, detail in FAILED:
        print(f"  FAILED: {name} — {detail}")
    raise SystemExit(1)
