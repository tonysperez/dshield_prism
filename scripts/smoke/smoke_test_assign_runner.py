"""Smoke test for the authoritative assignment write cores
(`enrich.sources.cowrie.assign_runner`: assignment_action, build_actions) and the
I4b config flag. No ES.

The critical safety property: shadow mode NEVER touches playbook_id; authoritative mode
sets it for assigned, clears it for novel, and always writes the shadow fields.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from types import SimpleNamespace

import numpy as np

from enrich.sources.cowrie.assign_runner import (
    _PB_FIELD,
    _load_anchors,
    assignment_action,
    build_actions,
    run_assignment,
)
from enrich.sources.cowrie.assignment import (
    Assignment,
    assign_batch,
    compute_assignment_window,
)
from enrich.sources.cowrie.lexical import _MIN_ANCHOR_BAGS, prepare_assignment_lexical

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


NOW = "2026-06-14T00:00:00Z"


def _session(act):
    return act["doc"]["dshield"]["cowrie"]["enrichment"]["session"]


assigned = Assignment(playbook_id="spb-X", cosine=0.99, status="assigned", cascade_rank=0)
novel = Assignment(playbook_id=None, cosine=0.80, status="novel")

# --- shadow mode: never touches playbook_id ---
sa = _session(assignment_action("s1", assigned, NOW, authoritative=False, playbook_name="X"))
check("shadow: writes cluster.assigned_playbook_id",
      sa["cluster"]["assigned_playbook_id"] == "spb-X", str(sa))
check("shadow: status + cosine + cascade + at written",
      sa["cluster"]["assignment_status"] == "assigned" and sa["cluster"]["assignment_cosine"] == 0.99
      and sa["cluster"]["assignment_cascade_rank"] == 0 and sa["cluster"]["assignment_at"] == NOW)
check("shadow: does NOT set playbook_id / playbook_name / playbook_named_at",
      "playbook_id" not in sa and "playbook_name" not in sa and "playbook_named_at" not in sa,
      str(sa))

# --- authoritative assigned: sets playbook_id/name + bumps named_at ---
aa = _session(assignment_action("s2", assigned, NOW, authoritative=True, playbook_name="X-name"))
check("authoritative assigned: playbook_id set", aa.get("playbook_id") == "spb-X", str(aa))
check("authoritative assigned: playbook_name set", aa.get("playbook_name") == "X-name")
check("authoritative assigned: playbook_named_at bumped (IP rollups self-heal)",
      aa.get("playbook_named_at") == NOW)
check("authoritative assigned: shadow fields still written",
      aa["cluster"]["assigned_playbook_id"] == "spb-X")

# --- authoritative novel: clears playbook_id/name ---
an = _session(assignment_action("s3", novel, NOW, authoritative=True))
check("authoritative novel: playbook_id cleared to None",
      "playbook_id" in an and an["playbook_id"] is None, str(an))
check("authoritative novel: playbook_name cleared to None", an["playbook_name"] is None)
check("authoritative novel: shadow status novel",
      an["cluster"]["assignment_status"] == "novel" and an["cluster"]["assigned_playbook_id"] is None)

# --- band (post-resolve shouldn't occur) leaves playbook_id untouched in authoritative ---
band = Assignment(playbook_id="spb-Y", cosine=0.96, status="band", cascade_rank=0)
ab = _session(assignment_action("s4", band, NOW, authoritative=True, playbook_name="Y"))
check("authoritative band: playbook_id left untouched (not set/cleared)",
      "playbook_id" not in ab, str(ab))

# --- build_actions wires ids + names ---
acts = build_actions(["s1", "s2"], [assigned, novel], {"spb-X": "X-name"}, NOW, authoritative=True)
check("build_actions: one action per id, right ids",
      [a["_id"] for a in acts] == ["s1", "s2"], str([a["_id"] for a in acts]))
check("build_actions: resolved name applied to assigned",
      _session(acts[0]).get("playbook_name") == "X-name")

# --- I4b flag default ---
from enrich.config import SessionConfig

check("assignment_authoritative default True (operator request)",
      SessionConfig().assignment_authoritative is True)
check("assignment_band_bypass_anchor_ids defaults empty",
      SessionConfig().assignment_band_bypass_anchor_ids == [])

# --- compute_assignment_window parity with manual prepare_assignment_lexical + assign_batch ---
anchor_bags = ["cluster_a cluster_b", "cluster_a", "cluster_c cluster_c"]
anchor_bag_ids = ["A", "A", "B"]
window_bags = ["cluster_a cluster_b", "cluster_c"]
window_emb = np.asarray([[0.8, 0.6], [0.2, 0.98]], dtype=np.float32)
anchor_emb = np.asarray([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)
anchor_ids = ["A", "B"]

manual_lexical = prepare_assignment_lexical(anchor_bags, anchor_bag_ids, window_bags)


def _manual_tfidf_cos(i, a):
    c = manual_lexical.anchor_centroids.get(anchor_ids[a])
    return (float(manual_lexical.window_features[i] @ c)
            if manual_lexical.available and c is not None else None)


manual = assign_batch(window_emb, anchor_emb, anchor_ids, tau=0.0, confident_tau=2.0,
                      tfidf_tau=-1.0, tfidf_cos=_manual_tfidf_cos)
seam = compute_assignment_window(window_emb, anchor_emb, anchor_ids, anchor_bags,
                                 anchor_bag_ids, window_bags, tau=0.0, confident_tau=2.0,
                                 tfidf_tau=-1.0)
check("compute_assignment_window matches manual lexical+assign_batch composition",
      seam.assignments == manual, f"{seam.assignments} != {manual}")
check("compute_assignment_window reports tfidf_available "
      "(requires both a numerically usable fit AND >=1 anchor clearing _MIN_ANCHOR_BAGS; "
      "these anchors are thin, so the seam correctly reports False even though the raw "
      "SVD fit itself succeeded)",
      seam.tfidf_available is False and manual_lexical.available is True
      and not manual_lexical.anchor_centroids)

# --- no anchor bags → degrade to embedding-only (no TF-IDF space available) ---
degraded = compute_assignment_window(window_emb, anchor_emb, anchor_ids, [], [], window_bags,
                                     tau=0.0, confident_tau=2.0, tfidf_tau=-1.0)
check("no anchor bags: tfidf_available is False", degraded.tfidf_available is False)
check("no anchor bags: assignments still resolve via embedding-only path",
      all(a.status in ("assigned", "novel") for a in degraded.assignments),
      str(degraded.assignments))

# --- Item 81: anchor-scoped band bypass assigns only the configured anchor ---
sqrt_remainder = float(np.sqrt(1.0 - 0.95**2))
band_window = np.asarray([[0.95, sqrt_remainder], [sqrt_remainder, 0.95]], dtype=np.float32)
band_anchor = np.asarray([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)
band_trace: list[list[dict]] = []
band_bypassed = assign_batch(
    band_window, band_anchor, ["A", "B"],
    tau=0.94, confident_tau=0.98, tfidf_tau=0.50,
    tfidf_cos=lambda _i, _a: 0.05,
    band_bypass_anchor_ids={"A"},
    candidate_trace=band_trace,
)
check("assign_batch: configured band anchor bypasses low TF-IDF rejection",
      band_bypassed[0].status == "assigned"
      and band_bypassed[0].playbook_id == "A"
      and band_trace[0][0]["decision"] == "band_bypass_assigned"
      and band_trace[0][0]["tfidf_cos"] is None,
      str((band_bypassed[0], band_trace[0])))
check("assign_batch: unconfigured band anchor still rejects low TF-IDF",
      band_bypassed[1].status == "novel"
      and band_trace[1][0]["anchor_id"] == "B"
      and band_trace[1][0]["decision"] == "band_rejected"
      and band_trace[1][0]["tfidf_cos"] == 0.05,
      str((band_bypassed[1], band_trace[1])))
default_trace: list[list[dict]] = []
default_band = assign_batch(
    band_window[:1], band_anchor, ["A", "B"],
    tau=0.94, confident_tau=0.98, tfidf_tau=0.50,
    tfidf_cos=lambda _i, _a: 0.05,
    candidate_trace=default_trace,
)
check("assign_batch: default empty bypass keeps low-TF-IDF band rejection behavior",
      default_band[0].status == "novel"
      and default_trace[0][0]["decision"] == "band_rejected",
      str((default_band[0], default_trace[0])))
deferred_trace: list[list[dict]] = []
deferred_band = assign_batch(
    band_window[:1], band_anchor, ["A", "B"],
    tau=0.94, confident_tau=0.98, tfidf_tau=0.50,
    band_bypass_anchor_ids={"A"},
    defer_band=True,
    candidate_trace=deferred_trace,
)
check("assign_batch: defer_band forward pass is not finalized by anchor bypass",
      deferred_band[0].status == "band"
      and deferred_trace[0][0]["decision"] == "band_deferred",
      str((deferred_band[0], deferred_trace[0])))

# --- run_assignment end-to-end via mocked ES: status_counts/tfidf_available parity
# through the real ES-wiring path (anchors + window scan + anchor-sample scan +
# hash->cluster pull), not just the pure compute_assignment_window seam above. ---
WINDOW_MARKER = {"term": {"marker": "window"}}
SAMPLE_MARKER = {"term": {"marker": "anchor_sample"}}
ANCH_IDX, SESS_IDX, CMD_IDX = "anchors-idx", "sessions-idx", "commands-idx"


def _rt_hit(i, source):
    return {"_id": f"r{i}", "_source": source, "sort": [i]}


def _session_src(emb, cmdset):
    return {"dshield": {"cowrie": {"enrichment": {"session": {
        "embedding": emb, "command_set": cmdset}}}}}


class RunAssignmentMockES:
    """Serves fixed hit lists for the three ES reads `run_assignment` performs, with
    search_after paging. The window scan and the per-anchor sample scan both hit the
    same sessions index with different filters — dispatch reads the filter's leading
    marker term (window scan) or trailing playbook_id term (anchor sample) to tell
    them apart, mirroring how `run_assignment` actually builds those filters."""

    def __init__(self, anchors, window_hits, sample_hits_by_pb, commands):
        self._anchors = anchors
        self._window_hits = window_hits
        self._sample_hits_by_pb = sample_hits_by_pb
        self._commands = commands

    def _page(self, hits, body):
        size = body["size"]
        after = body.get("search_after")
        start = 0
        if after is not None:
            start = next((k for k, h in enumerate(hits) if h["sort"] > after), len(hits))
        return hits[start:start + size]

    def search(self, index, **body):
        if index == ANCH_IDX:
            return {"hits": {"hits": self._anchors}}
        if index == CMD_IDX:
            return {"hits": {"hits": self._page(self._commands, body)}}
        filt = body["query"]["bool"]["filter"]
        if WINDOW_MARKER in filt:
            return {"hits": {"hits": self._page(self._window_hits, body)}}
        pb_terms = [
            clause["term"][_PB_FIELD]
            for clause in filt
            if isinstance(clause, dict) and _PB_FIELD in clause.get("term", {})
        ]
        pb = pb_terms[-1]
        return {"hits": {"hits": self._page(self._sample_hits_by_pb.get(pb, []), body)}}


rt_cfg = SimpleNamespace(
    session=SimpleNamespace(assignment_authoritative=False, assignment_tau=0.5,
                            assignment_confident_tau=0.9, assignment_tfidf_tau=0.5),
    elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=SimpleNamespace(
        sessions_rollup=SESS_IDX, commands=CMD_IDX, playbook_anchors=ANCH_IDX))),
)
rt_es = RunAssignmentMockES(
    anchors=[
        _rt_hit(0, {"playbook_id": "A", "anchor_centroid": [1.0, 0.0]}),
        _rt_hit(1, {"playbook_id": "B", "anchor_centroid": [0.0, 1.0]}),
    ],
    window_hits=[
        _rt_hit(0, _session_src([1.0, 0.0], ["h1"])),   # cos(A)=1.0 -> confidently assigned
        _rt_hit(1, _session_src([-1.0, 0.0], ["h2"])),  # cos(A)=-1, cos(B)=0 -> novel
    ],
    sample_hits_by_pb={
        "A": [{"_id": "sa0", "_source": _session_src(None, ["h1"]), "sort": [0]}],
        "B": [{"_id": "sb0", "_source": _session_src(None, ["h3"]), "sort": [0]}],
    },
    commands=[],  # empty hash->cluster map: every bag degrades to the outlier token
)
rt_summary = run_assignment(
    rt_es, rt_cfg, window_filter=[WINDOW_MARKER], anchor_sample_filter=[SAMPLE_MARKER],
    per_anchor=10, apply=False,
)
check("run_assignment: status_counts reflect the mocked-ES window (1 assigned, 1 novel)",
      rt_summary["status_counts"] == {"assigned": 1, "novel": 1}, str(rt_summary))
check("run_assignment: tfidf_available False (all bags degrade to the same outlier token)",
      rt_summary["tfidf_available"] is False, str(rt_summary))
check("run_assignment: shadow mode makes no writes on dry-run",
      rt_summary["written"] == 0 and rt_summary["errors"] == 0, str(rt_summary))

# Item 81: production wiring passes assignment_band_bypass_anchor_ids into the
# assignment window. A's low-TF-IDF band candidate assigns via bypass; B's identical
# low-TF-IDF band candidate remains novel because B is not configured.
def _cmd_hit(i, command_hash, cluster_id):
    return {
        "_id": command_hash,
        "_source": {"dshield": {"cowrie": {"enrichment": {
            "cluster": {"id": cluster_id, "is_outlier": False},
        }}}},
        "sort": [i],
    }


def _sample_rows(prefix, command_hash):
    return [
        {"_id": f"{prefix}{i}", "_source": _session_src(None, [command_hash]), "sort": [i]}
        for i in range(_MIN_ANCHOR_BAGS)
    ]


bypass_cfg = SimpleNamespace(
    session=SimpleNamespace(assignment_authoritative=False, assignment_tau=0.94,
                            assignment_confident_tau=0.98, assignment_tfidf_tau=0.50,
                            assignment_band_bypass_anchor_ids=[" A ", " "]),
    elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=SimpleNamespace(
        sessions_rollup=SESS_IDX, commands=CMD_IDX, playbook_anchors=ANCH_IDX))),
)
bypass_summary = run_assignment(
    RunAssignmentMockES(
        anchors=[
            _rt_hit(0, {"playbook_id": "A", "anchor_centroid": [1.0, 0.0]}),
            _rt_hit(1, {"playbook_id": "B", "anchor_centroid": [0.0, 1.0]}),
        ],
        window_hits=[
            _rt_hit(0, _session_src([0.95, sqrt_remainder], ["hw-a"])),
            _rt_hit(1, _session_src([sqrt_remainder, 0.95], ["hw-b"])),
        ],
        sample_hits_by_pb={
            "A": _sample_rows("sa", "ha"),
            "B": _sample_rows("sb", "hb"),
        },
        commands=[
            _cmd_hit(0, "ha", "cluster_a"),
            _cmd_hit(1, "hb", "cluster_b"),
            _cmd_hit(2, "hw-a", "cluster_window_a"),
            _cmd_hit(3, "hw-b", "cluster_window_b"),
        ],
    ),
    bypass_cfg, window_filter=[WINDOW_MARKER], anchor_sample_filter=[SAMPLE_MARKER],
    per_anchor=_MIN_ANCHOR_BAGS, apply=False,
)
check("run_assignment: configured anchor-scoped band bypass assigns only target anchor",
      bypass_summary["status_counts"] == {"assigned": 1, "novel": 1}
      and bypass_summary["tfidf_available"] is True,
      str(bypass_summary))

# Item 78: production wiring must preserve a thin in-band anchor as an embedding candidate.
# The per-anchor sample has fewer than _MIN_ANCHOR_BAGS rows, so no TF-IDF centroid exists;
# run_assignment should still assign it in dry-run mode by degrading only that candidate to
# embedding-only, without writing anything.
thin_nearest_summary = run_assignment(
    RunAssignmentMockES(
        anchors=[
            _rt_hit(0, {"playbook_id": "Thin", "anchor_centroid": [1.0, 0.0]}),
        ],
        window_hits=[
            _rt_hit(
                0,
                _session_src([0.95, float(np.sqrt(1.0 - 0.95**2))], ["hthin"]),
            ),
        ],
        sample_hits_by_pb={
            "Thin": [
                {"_id": f"thin{i}", "_source": _session_src(None, ["hthin"]), "sort": [i]}
                for i in range(_MIN_ANCHOR_BAGS - 1)
            ],
        },
        commands=[],
    ),
    SimpleNamespace(
        session=SimpleNamespace(assignment_authoritative=False, assignment_tau=0.94,
                                assignment_confident_tau=0.98, assignment_tfidf_tau=0.8),
        elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=SimpleNamespace(
            sessions_rollup=SESS_IDX, commands=CMD_IDX, playbook_anchors=ANCH_IDX))),
    ),
    window_filter=[WINDOW_MARKER],
    anchor_sample_filter=[SAMPLE_MARKER],
    per_anchor=10,
    apply=False,
)
check("run_assignment: thin nearest in the band assigns through production wiring",
      thin_nearest_summary["status_counts"] == {"assigned": 1}
      and thin_nearest_summary["tfidf_available"] is False,
      str(thin_nearest_summary))
check("run_assignment: thin nearest dry-run makes no writes",
      thin_nearest_summary["written"] == 0 and thin_nearest_summary["errors"] == 0,
      str(thin_nearest_summary))

# --- _load_anchors: item 30 — now returns (ids, vecs, predicate_signatures) ---
la_ids, la_vecs, la_sigs = _load_anchors(
    RunAssignmentMockES(
        anchors=[
            _rt_hit(0, {"playbook_id": "A", "anchor_centroid": [1.0, 0.0],
                       "predicate_signature": {"key_write_immutability": 0.9}}),
            _rt_hit(1, {"playbook_id": "B", "anchor_centroid": [0.0, 1.0]}),
        ],
        window_hits=[], sample_hits_by_pb={}, commands=[],
    ),
    ANCH_IDX,
)
check("_load_anchors: returns a 3-tuple (ids, vecs, predicate_signatures)",
      la_ids == ["A", "B"] and la_vecs.shape == (2, 2), str((la_ids, la_vecs)))
check("_load_anchors: predicate_signature carried through, index-aligned",
      la_sigs[0] == {"key_write_immutability": 0.9}, str(la_sigs))
check("_load_anchors: anchor without a predicate_signature -> None (not a crash)",
      la_sigs[1] is None, str(la_sigs))

# --- item 30: below-tau structural-predicate rescue wired end-to-end through
# run_assignment (predicate pull + fold + rescue), via a mocked ES. Session cos(A)=0.90
# is below tau (0.94) but above rescue_tau (0.85); its one command carries
# has_key_write + has_immutability, and anchor A's signature is modal on
# key_write_immutability -> should rescue to ASSIGNED. ---
rescue_anchors = [
    _rt_hit(0, {"playbook_id": "A", "anchor_centroid": [1.0, 0.0],
               "predicate_signature": {"key_write_immutability": 0.9}}),
    _rt_hit(1, {"playbook_id": "B", "anchor_centroid": [0.0, 1.0],
               "predicate_signature": {"key_write_immutability": 0.0}}),
]
rescue_window_hits = [
    _rt_hit(0, _session_src([0.90, float(np.sqrt(1.0 - 0.90**2))], ["hkey"])),
]
rescue_sample_hits = {
    "A": [{"_id": "sa0", "_source": _session_src(None, ["hkey"]), "sort": [0]}],
    "B": [],
}
_all_false_subsignals = {
    "has_uname_m": False, "arch_tokens": [], "has_case_token": False,
    "has_c2_launch": False, "has_self_spread": False, "is_appliance_verb": False,
    "has_host_recon": False, "has_multi_dir_cd": False, "has_multi_tool_fallback": False,
}
rescue_commands = [{
    "_id": "hkey", "sort": [0],
    "_source": {"dshield": {"cowrie": {"enrichment": {
        "cluster": {"id": "c1"},
        "predicates": {**_all_false_subsignals, "has_key_write": True, "has_immutability": True},
    }}}},
}]

rescue_off_cfg = SimpleNamespace(
    session=SimpleNamespace(assignment_authoritative=False, assignment_tau=0.94,
                            assignment_confident_tau=0.98, assignment_tfidf_tau=0.80),
    elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=SimpleNamespace(
        sessions_rollup=SESS_IDX, commands=CMD_IDX, playbook_anchors=ANCH_IDX))),
)
rescue_off_summary = run_assignment(
    RunAssignmentMockES(rescue_anchors, rescue_window_hits, rescue_sample_hits, rescue_commands),
    rescue_off_cfg, window_filter=[WINDOW_MARKER], anchor_sample_filter=[SAMPLE_MARKER],
    per_anchor=10, apply=False,
)
check("run_assignment: rescue_tau unset (no-op default) -> below-tau session stays novel",
      rescue_off_summary["status_counts"] == {"novel": 1}, str(rescue_off_summary))

rescue_on_cfg = SimpleNamespace(
    session=SimpleNamespace(assignment_authoritative=False, assignment_tau=0.94,
                            assignment_confident_tau=0.98, assignment_tfidf_tau=0.80,
                            assignment_rescue_tau=0.85),
    elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=SimpleNamespace(
        sessions_rollup=SESS_IDX, commands=CMD_IDX, playbook_anchors=ANCH_IDX))),
)
rescue_on_summary = run_assignment(
    RunAssignmentMockES(rescue_anchors, rescue_window_hits, rescue_sample_hits, rescue_commands),
    rescue_on_cfg, window_filter=[WINDOW_MARKER], anchor_sample_filter=[SAMPLE_MARKER],
    per_anchor=10, apply=False,
)
check("run_assignment: rescue_tau=0.85 -> below-tau session with matching structural "
      "evidence gets rescued to ASSIGNED (predicate pull + fold wired end-to-end)",
      rescue_on_summary["status_counts"] == {"assigned": 1}, str(rescue_on_summary))

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
