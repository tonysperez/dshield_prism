"""Smoke test for the item-68 recheck (`scripts/diagnose_anchor_coverage_gap.py`).
Offline: no ES, no network, no LLM.

Covers the spec's I/O matrix: `_target_label_report`'s three assigned-detail
outcomes (matches_majority / conflated / anchor_unknown) and two novel-detail
outcomes (still_outlier / now_clustered) directly, then `analyze()` end to end
against a scripted fake ES with real 5-D geometry -- 3 anchors + a genuine novel
cluster + an isolated novel outlier -- so the label-join, leave-one-out majority,
and the `pool_group_labels`/`cluster_novel_pool` cross-check all exercise together.
"""
from __future__ import annotations

import sys
import tempfile
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import diagnose_anchor_coverage_gap as target

from enrich.classification import releasable_filter

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


# --- _target_label_report: pure, no ES ---------------------------------------

class _A:
    def __init__(self, status, playbook_id=None):
        self.status = status
        self.playbook_id = playbook_id


assignments = [
    _A(target.ASSIGNED, "spb-a"),   # 0: matches its anchor's independent majority
    _A(target.ASSIGNED, "spb-b"),   # 1: conflated with its anchor's independent majority
    _A(target.ASSIGNED, "spb-c"),   # 2: anchor has no other labelled member
    _A(target.NOVEL),               # 3: still an HDBSCAN outlier
    _A(target.NOVEL),               # 4: now lands in a real group
]
loo_majority = {0: "gap_label", 1: "other_label", 2: None}
outlier_status = {3: (True, 0, -1), 4: (False, 7, 2)}

report_full = target._target_label_report(
    "gap_label", [0, 1, 2, 3, 4], assignments, loo_majority, outlier_status,
)
check("matches_majority counted", report_full["assigned_detail"]["matches_majority"] == 1,
      str(report_full))
check("conflated counted", report_full["assigned_detail"]["conflated"] == 1, str(report_full))
check("anchor_unknown counted", report_full["assigned_detail"]["anchor_unknown"] == 1,
      str(report_full))
check("still_outlier counted", report_full["novel_detail"]["still_outlier"] == 1,
      str(report_full))
check("now_clustered counted with its group size and joinable group id",
      report_full["novel_detail"]["now_clustered"] == 1
      and report_full["novel_detail"]["clustered_group_sizes"] == [7]
      and report_full["novel_detail"]["clustered_group_ids"] == [2], str(report_full))
check("status_counts reconcile with n_labelled",
      sum(report_full["status_counts"].values()) == report_full["n_labelled"] == 5,
      str(report_full))

report_empty = target._target_label_report("gap_label", [], assignments, {}, {})
check("a target label absent from the window reports n_labelled=0, no crash",
      report_empty == {
          "n_labelled": 0,
          "status_counts": {"assigned": 0, "novel": 0},
          "assigned_detail": {"conflated": 0, "matches_majority": 0, "anchor_unknown": 0},
          "novel_detail": {
              "still_outlier": 0, "now_clustered": 0,
              "clustered_group_sizes": [], "clustered_group_ids": [],
          },
      }, str(report_empty))


# --- _novel_group_composition: pure, no ES ------------------------------------
# Finding 66C's exact shape: a group whose modal label rests on a minority of
# labelled members, a tie, and a group with no labelled member at all.

comp = target._novel_group_composition(
    np.asarray([10, 11, 12, 13, 20, 21, 30]),
    # group 0 holds 4 labelled of 9; group 1 is a 2-2 tie; group 2 has none labelled
    np.asarray([0, 0, 0, 0, 1, 1, 2]),
    Counter({0: 9, 1: 4, 2: 5}),
    {10: "botnet_loader", 11: "botnet_loader", 12: "botnet_loader",
     13: "host_recon", 20: "scp_upload", 21: "iot_cli_probe"},
)
by_group = {group["group"]: group for group in comp}

check("composition is ordered by group size, largest first",
      [group["group"] for group in comp] == [0, 2, 1], str(comp))
check("a modal label carried by a minority of the whole group still reads modal, "
      "with the unlabelled remainder reported separately",
      by_group[0]["modal_label"] == "botnet_loader"
      and by_group[0]["n_labelled"] == 4 and by_group[0]["n_unlabelled"] == 5
      and by_group[0]["modal_share_of_labelled"] == 0.75
      and by_group[0]["modal_share_of_group"] == round(3 / 9, 4), str(by_group[0]))
check("a tie reports no modal label and names both tied labels",
      by_group[1]["modal_label"] is None
      and by_group[1]["modal_tie"] == ["iot_cli_probe", "scp_upload"], str(by_group[1]))
check("a group with no labelled member reports empty, not a spurious modal label",
      by_group[2]["n_labelled"] == 0 and by_group[2]["labels"] == {}
      and by_group[2]["modal_label"] is None and by_group[2]["modal_tie"] == []
      and by_group[2]["modal_share_of_labelled"] == 0.0, str(by_group[2]))
check("HDBSCAN noise (group -1) never becomes a group",
      all(group["group"] >= 0 for group in comp), str(comp))


# --- analyze() end to end, against a scripted fake ES -------------------------

A = _u([1.0, 0.0, 0.0, 0.0, 0.0])
B = _u([0.0, 1.0, 0.0, 0.0, 0.0])
C = _u([0.0, 0.0, 1.0, 0.0, 0.0])
CLUSTER_AXIS = _u([0.0, 0.0, 0.0, 1.0, 0.0])
ISOLATED_AXIS = _u([0.0, 0.0, 0.0, 0.0, 1.0])
_jit = np.random.default_rng(68)
CLUSTER_PAIR = [
    _u(CLUSTER_AXIS + _jit.normal(0.0, 0.01, 5).astype(np.float32)) for _ in range(2)
]
# HDBSCAN needs more than 3 total points to ever extract a cluster (verified: a bare
# tight-pair-plus-outlier triple scores every point noise regardless of
# min_cluster_size/min_samples). These two unlabelled fillers give it a big-enough
# novel pool to work with; both sit well below tau=0.94 from every anchor, so they
# stay novel, and neither is labelled, so neither enters any `by_label` count.
FILLER_1 = _u([1.0, 1.0, 0.0, 0.0, 0.0])
FILLER_2 = _u([0.0, 1.0, 1.0, 0.0, 0.0])

LABELS_YAML = """
sA1:
  annotated: true
  is_real: true
  playbook_label: host_recon
sA2:
  annotated: true
  is_real: true
  playbook_label: host_recon
sA3:
  annotated: true
  is_real: true
  playbook_label: host_recon
sA4:
  annotated: true
  is_real: true
  playbook_label: iot_cli_probe
sB1:
  annotated: true
  is_real: true
  playbook_label: scp_upload
sB2:
  annotated: true
  is_real: true
  playbook_label: scp_upload
sC1:
  annotated: true
  is_real: true
  playbook_label: account_backdoor_persistence
sN1:
  annotated: true
  is_real: true
  playbook_label: inband_payload_drop
sN2:
  annotated: true
  is_real: true
  playbook_label: inband_payload_drop
sN3:
  annotated: true
  is_real: true
  playbook_label: inband_payload_drop
"""

# (session_id, embedding, label) -- labels are attached only via LABELS_YAML above;
# this list just drives the window doc + join.
SESSIONS = [
    ("sA1", A), ("sA2", A), ("sA3", A), ("sA4", A),
    ("sB1", B), ("sB2", B),
    ("sC1", C),
    ("sN1", CLUSTER_PAIR[0]), ("sN2", CLUSTER_PAIR[1]),
    ("sN3", ISOLATED_AXIS),
    ("sF1", FILLER_1), ("sF2", FILLER_2),
]


def _hit(doc_id, source, order):
    return {"_id": doc_id, "_source": source, "sort": [order]}


def _window_source(sid, embedding):
    return {
        "cowrie": {"session_id": sid},
        "dshield": {"cowrie": {"enrichment": {"session": {
            "embedding": [float(x) for x in embedding],
            "command_set": ["h1"],
            "command_count": 3, "unique_commands": 2,
            "login_success_count": 1, "login_fail_count": 0,
            "mean_novelty_score": 0.1,
        }}}},
    }


def _cfg(**session_overrides):
    session = {
        "assignment_tau": 0.94, "assignment_confident_tau": 0.98, "assignment_tfidf_tau": 0.80,
        "assignment_rescue_tau": 0.94, "playbook_merge_threshold": 0.5,
        "cluster_min_cluster_size": 2, "cluster_min_samples": 1,
        "cluster_scalar_weight": 0.0, "cluster_svd_dim": 0,
    }
    session.update(session_overrides)
    return SimpleNamespace(
        session=SimpleNamespace(**session),
        worker=SimpleNamespace(cluster_n_jobs=1),
        elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=SimpleNamespace(
            sessions_rollup="rollup", playbook_anchors="anchors", commands="commands",
        ))),
    )


class MockES:
    def __init__(self, no_anchors=False):
        self.queries: list[tuple[str, dict]] = []
        self.write_calls = 0
        self.no_anchors = no_anchors
        self.window = [
            _hit(f"rollup-{i}", _window_source(sid, emb), i)
            for i, (sid, emb) in enumerate(SESSIONS)
        ]

    @staticmethod
    def _page(rows, body):
        if body.get("search_after") is not None:
            return []
        return rows[:body["size"]]

    def search(self, index, **body):
        self.queries.append((index, body))
        if index == "anchors":
            if self.no_anchors:
                return {"hits": {"hits": []}}
            return {"hits": {"hits": [
                _hit("spb-a", {"playbook_id": "spb-a", "anchor_centroid": A.tolist()}, 0),
                _hit("spb-b", {"playbook_id": "spb-b", "anchor_centroid": B.tolist()}, 1),
                _hit("spb-c", {"playbook_id": "spb-c", "anchor_centroid": C.tolist()}, 2),
            ]}}
        filters = body["query"]["bool"]["filter"]
        if index == "commands":
            rows = [_hit("h1", {"dshield": {"cowrie": {"enrichment": {"cluster": {
                "id": "cluster_5", "is_outlier": False}}}}}, 0)]
            return {"hits": {"hits": self._page(rows, body)}}
        if any(target._PB in clause.get("term", {}) for clause in filters):
            return {"hits": {"hits": []}}  # per-anchor lexical sample: none needed
        return {"hits": {"hits": self._page(self.window, body)}}

    def bulk(self, *args, **kwargs):
        self.write_calls += 1
        raise AssertionError("write API called")

    def update(self, *args, **kwargs):
        self.write_calls += 1
        raise AssertionError("write API called")


with tempfile.TemporaryDirectory() as tmp:
    labels_path = Path(tmp) / "labels.yaml"
    labels_path.write_text(LABELS_YAML)

    mock = MockES()
    report = target.analyze(mock, _cfg(), labels_path)

    check("analyze issues no write of any kind", mock.write_calls == 0)
    cowrie_queries = [body for index, body in mock.queries if index in ("rollup", "commands")]
    public_clause = releasable_filter(_cfg())
    check(
        "every cowrie session/command query carries the exact public-only filter",
        cowrie_queries
        and all(public_clause in body["query"]["bool"]["filter"] for body in cowrie_queries),
        str(cowrie_queries),
    )
    check("report labels itself read-only and public-only",
          report["read_only"] is True and report["session_classification"] == "public_only",
          str(report))
    check("report never names a session id, IP or command field",
          "sA1" not in str(report) and "cowrie.session_id" not in str(report)
          and "process.command_line" not in str(report), str(report))

    by = report["by_label"]
    iot = by["iot_cli_probe"]
    check("iot_cli_probe: assigned and conflated with anchor A's independent majority "
          "(host_recon)",
          iot["status_counts"] == {"assigned": 1, "novel": 0}
          and iot["assigned_detail"]["conflated"] == 1, str(iot))

    scp = by["scp_upload"]
    check("scp_upload: both sessions match each other's independent majority at anchor B",
          scp["status_counts"] == {"assigned": 2, "novel": 0}
          and scp["assigned_detail"]["matches_majority"] == 2, str(scp))

    backdoor = by["account_backdoor_persistence"]
    check("account_backdoor_persistence: assigned to an anchor with no other labelled member",
          backdoor["status_counts"] == {"assigned": 1, "novel": 0}
          and backdoor["assigned_detail"]["anchor_unknown"] == 1, str(backdoor))

    inband = by["inband_payload_drop"]
    check("inband_payload_drop: all 3 resolve novel",
          inband["status_counts"] == {"assigned": 0, "novel": 3}, str(inband))
    check("inband_payload_drop: the isolated session is still an outlier",
          inband["novel_detail"]["still_outlier"] == 1, str(inband))
    check("inband_payload_drop: the tight pair now lands in a real group of size 2",
          inband["novel_detail"]["now_clustered"] == 2
          and inband["novel_detail"]["clustered_group_sizes"] == [2, 2], str(inband))

    composition = report["novel_group_composition"]
    pair_group = inband["novel_detail"]["clustered_group_ids"][0]
    check("both clustered sessions report the same group id, joinable to the composition",
          set(inband["novel_detail"]["clustered_group_ids"]) == {pair_group}
          and pair_group in {group["group"] for group in composition},
          str((inband["novel_detail"], composition)))
    pair = next(group for group in composition if group["group"] == pair_group)
    check("the pair's group composition is pure inband_payload_drop, fully labelled",
          pair["labels"] == {"inband_payload_drop": 2} and pair["n_unlabelled"] == 0
          and pair["modal_label"] == "inband_payload_drop"
          and pair["modal_share_of_group"] == 1.0, str(pair))
    check("every composition group's labelled + unlabelled reconciles with its size",
          all(group["n_labelled"] + group["n_unlabelled"] == group["size"]
              for group in composition), str(composition))

    check("novel count includes the 3 labelled + 2 filler novel sessions",
          report["novel"] == 5, str(report["novel"]))
    check("novel_pool_shape reports a real HDBSCAN partition, not an all-noise pool",
          (report["novel_pool_shape"].get("playbook_groups") or 0) >= 1,
          str(report["novel_pool_shape"]))

    line = target.summarize(report)
    check("summarize renders every target label without raising",
          all(label in line for label in target.TARGET_LABELS), line)
    check("summarize renders the group composition block",
          "novel groups:" in line and "modal=inband_payload_drop" in line, line)

    # --- the pool_group_labels / cluster_novel_pool cross-check --------------

    original_cnp = target.cluster_novel_pool

    def _lying_cluster_novel_pool(*args, **kwargs):
        shape = dict(original_cnp(*args, **kwargs))
        shape["playbook_groups"] = (shape.get("playbook_groups") or 0) + 1
        return shape

    target.cluster_novel_pool = _lying_cluster_novel_pool
    try:
        target.analyze(MockES(), _cfg(), labels_path)
        diverged_raised = None
    except RuntimeError as exc:
        diverged_raised = exc
    finally:
        target.cluster_novel_pool = original_cnp
    check("a pool_group_labels / cluster_novel_pool divergence raises RuntimeError",
          isinstance(diverged_raised, RuntimeError) and "diverged" in str(diverged_raised),
          repr(diverged_raised))

    # --- no anchor library ----------------------------------------------------

    try:
        target.analyze(MockES(no_anchors=True), _cfg(), labels_path)
        no_anchors_raised = None
    except ValueError as exc:
        no_anchors_raised = exc
    check("an empty anchor library raises a clean ValueError",
          isinstance(no_anchors_raised, ValueError)
          and "no pinned production anchors found" in str(no_anchors_raised),
          repr(no_anchors_raised))

    # --- novel pool below cluster_min_cluster_size -----------------------------

    report_too_few = target.analyze(
        MockES(), _cfg(cluster_min_cluster_size=10), labels_path,
    )
    check("a novel pool smaller than cluster_min_cluster_size skips HDBSCAN entirely",
          report_too_few["novel_pool_shape"].get("status") == "skipped_too_few",
          str(report_too_few["novel_pool_shape"]))
    inband_too_few = report_too_few["by_label"]["inband_payload_drop"]
    check("below the size floor, every novel target session reports still_outlier",
          inband_too_few["novel_detail"] == {
              "still_outlier": 3, "now_clustered": 0,
              "clustered_group_sizes": [], "clustered_group_ids": [],
          }, str(inband_too_few))
    check("a skipped HDBSCAN run reports no composition groups at all",
          report_too_few["novel_group_composition"] == [],
          str(report_too_few["novel_group_composition"]))


# --- CLI gating: no live path without operator confirmation --------------------

def _explode(*_a, **_k):
    raise AssertionError("ES client constructed before operator confirmation")


_saved_client, _saved_argv = target.make_client, sys.argv
target.make_client = _explode
try:
    sys.argv = ["diagnose_anchor_coverage_gap.py"]
    try:
        target.main()
        check("missing confirmation flag exits non-zero", False, "main() returned")
    except SystemExit as exc:
        check("missing confirmation flag exits non-zero", exc.code == 2, str(exc.code))
    except AssertionError:
        check("missing confirmation flag exits before touching ES", False,
              "make_client was called")
finally:
    target.make_client, sys.argv = _saved_client, _saved_argv


print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for name, detail in FAILED:
        print(f"  FAILED: {name} — {detail}")
    raise SystemExit(1)
