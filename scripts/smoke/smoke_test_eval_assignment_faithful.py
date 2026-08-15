"""Offline smoke coverage for the faithful assignment evaluator."""
from __future__ import annotations

import copy
import gzip
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from eval_assignment import EvalRecord, load_records_detailed
from eval_assignment_faithful import (
    RESCUE_ARMS,
    EvaluationInvalid,
    _band_diagnosis,
    _band_report,
    _cascade_slices,
    _identity_differences,
    _path_metrics,
    _path_of,
    _print_real_anchor_rescue_sweep,
    _real_anchor_replay,
    _required_nulls,
    apply_baseline,
    build_session_predicate_vectors,
    evaluate,
    evidence_ceilings,
    load_anchor_snapshot,
    load_background_cohort,
    main,
    novelty_trials,
    run_real_anchor_rescue_sweep,
    write_baseline,
)

from enrich.clustering import compute_lexical_features
from enrich.sources.cowrie.assignment import assign_batch, compute_assignment_window
from enrich.sources.cowrie.lexical import _MIN_ANCHOR_BAGS, prepare_assignment_lexical
from enrich.sources.cowrie.predicates import PREDICATE_NAMES

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name} ({detail})")


# Shared lexical extraction preserves the previous production calculation. Both anchors
# must clear _MIN_ANCHOR_BAGS (item 37) here or neither gets a centroid to compare.
anchor_bags = (["cluster_a cluster_b", "cluster_a"] * 25) + (
    ["cluster_c cluster_c"] * _MIN_ANCHOR_BAGS
)
anchor_ids = (["A"] * 50) + (["B"] * _MIN_ANCHOR_BAGS)
window_bags = ["cluster_a cluster_b", "cluster_c"]
n_anchor = len(anchor_bags)
shared = prepare_assignment_lexical(anchor_bags, anchor_ids, window_bags)
raw = compute_lexical_features(anchor_bags + window_bags, n_components=48)
old_centroids = {}
for label in ("A", "B"):
    centroid = raw[:n_anchor][np.asarray(anchor_ids) == label].mean(axis=0)
    old_centroids[label] = centroid / np.linalg.norm(centroid)
check("shared lexical window parity", np.allclose(shared.window_features, raw[n_anchor:]))
check("shared lexical centroid parity", all(
    np.allclose(shared.anchor_centroids[label], old_centroids[label])
    for label in old_centroids
))
embedding_anchors = np.asarray([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)
window_embedding = np.asarray([[0.8, 0.6], [0.2, 0.98]], dtype=np.float32)
before = assign_batch(
    window_embedding, embedding_anchors, ["A", "B"], tau=0.0, confident_tau=2.0,
    tfidf_tau=-1.0,
    tfidf_cos=lambda row, anchor: float(raw[n_anchor + row] @ old_centroids[["A", "B"][anchor]]),
)
after = assign_batch(
    window_embedding, embedding_anchors, ["A", "B"], tau=0.0, confident_tau=2.0,
    tfidf_tau=-1.0,
    tfidf_cos=lambda row, anchor: float(
        shared.window_features[row] @ shared.anchor_centroids[["A", "B"][anchor]]
    ),
)
check("assignment unchanged after lexical extraction", before == after)

# --- item 37: anchors under _MIN_ANCHOR_BAGS get no TF-IDF centroid, degrade gracefully ---
thin_anchor_bags = ["cluster_a", "cluster_a", "cluster_c cluster_c"]  # A: 2 bags, B: 1 bag
thin_anchor_ids = ["A", "A", "B"]
thin_window_bags = ["cluster_a", "cluster_c"]
thin = prepare_assignment_lexical(thin_anchor_bags, thin_anchor_ids, thin_window_bags)
check("thin anchor: below-threshold anchors get no centroid at all",
      thin.anchor_centroids == {}, str(thin.anchor_centroids))

adequate_anchor_bags = ["cluster_a"] * _MIN_ANCHOR_BAGS + ["cluster_c cluster_c"] * 3
adequate_anchor_ids = ["A"] * _MIN_ANCHOR_BAGS + ["B"] * 3
mixed = prepare_assignment_lexical(
    adequate_anchor_bags, adequate_anchor_ids, ["cluster_a", "cluster_c"],
)
check("thin anchor: adequate anchor gets a centroid, thin sibling does not",
      "A" in mixed.anchor_centroids and "B" not in mixed.anchor_centroids,
      str(mixed.anchor_centroids))

# A band-tier session against a thin (3-bag) anchor: tfidf_cos returns None for it, so
# compute_assignment_window degrades to the embedding-only decision (no exception, no
# near-zero-cosine noise) — the same path used when a whole snapshot has no bags.
band_anchor_matrix = np.asarray([[1.0, 0.0]], dtype=np.float32)
band_window_embedding = np.asarray([[0.95, np.sqrt(1 - 0.95 ** 2)]], dtype=np.float32)
thin_band_result = compute_assignment_window(
    band_window_embedding, band_anchor_matrix, ["A"],
    ["cluster_a"] * 3, ["A"] * 3, ["cluster_a"],
    tau=0.94, confident_tau=0.98, tfidf_tau=0.5,
)
check("thin anchor: band case degrades to embedding-only (assigned, no tfidf cosine)",
      thin_band_result.assignments[0].status == "assigned"
      and thin_band_result.assignments[0].tfidf_cosine is None,
      str(thin_band_result.assignments))

# Item 78: a farther thin anchor must not be dropped from the embedding cascade merely
# because it has no TF-IDF centroid. Once reached, it degrades to embedding-only for that
# candidate only; the adequate nearest anchor still gets band-rejected normally.
cascade_trace: list[list[dict]] = []
reached_thin = compute_assignment_window(
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    np.asarray([
        [0.96, float(np.sqrt(1.0 - 0.96**2))],
        [0.95, -float(np.sqrt(1.0 - 0.95**2))],
    ], dtype=np.float32),
    ["adequate", "thin"],
    ["cluster_a"] * _MIN_ANCHOR_BAGS + ["cluster_b"] * 3,
    ["adequate"] * _MIN_ANCHOR_BAGS + ["thin"] * 3,
    ["cluster_b"],
    tau=0.94,
    confident_tau=0.98,
    tfidf_tau=0.8,
    candidate_trace=cascade_trace,
)
check("thin farther anchor reached: assignment cascades onto embedding-only thin anchor",
      reached_thin.assignments[0].status == "assigned"
      and reached_thin.assignments[0].playbook_id == "thin"
      and reached_thin.assignments[0].cascade_rank == 1
      and reached_thin.assignments[0].band_rejections == 1
      and reached_thin.assignments[0].tfidf_cosine is None
      and reached_thin.tfidf_available is True,
      str((reached_thin.assignments, cascade_trace)))
check("thin farther anchor reached: candidate trace shows rejected adequate then thin None",
      [row["decision"] for row in cascade_trace[0]] == ["band_rejected", "assigned"]
      and cascade_trace[0][0]["anchor_id"] == "adequate"
      and cascade_trace[0][1]["anchor_id"] == "thin"
      and cascade_trace[0][1]["tfidf_cos"] is None,
      str(cascade_trace))

below_floor_trace: list[list[dict]] = []
below_floor_thin = compute_assignment_window(
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    np.asarray([
        [0.96, float(np.sqrt(1.0 - 0.96**2))],
        [0.93, -float(np.sqrt(1.0 - 0.93**2))],
    ], dtype=np.float32),
    ["adequate", "thin"],
    ["cluster_a"] * _MIN_ANCHOR_BAGS + ["cluster_b"] * 3,
    ["adequate"] * _MIN_ANCHOR_BAGS + ["thin"] * 3,
    ["cluster_b"],
    tau=0.94,
    confident_tau=0.98,
    tfidf_tau=0.8,
    candidate_trace=below_floor_trace,
)
check("thin farther anchor below floor: final status remains novel",
      below_floor_thin.assignments[0].status == "novel"
      and below_floor_thin.assignments[0].playbook_id is None
      and below_floor_thin.assignments[0].band_rejections == 1,
      str((below_floor_thin.assignments, below_floor_trace)))
check("thin farther anchor below floor: trace exposes stop without synthetic tfidf cosine",
      [row["decision"] for row in below_floor_trace[0]]
      == ["band_rejected", "below_floor_stop"]
      and below_floor_trace[0][1]["anchor_id"] == "thin"
      and below_floor_trace[0][1]["tfidf_cos"] is None,
      str(below_floor_trace))

# tfidf_available must reflect "at least one anchor has a usable centroid", not merely
# "the SVD fit produced >=2 dimensions" — a numerically healthy fit with every anchor
# below _MIN_ANCHOR_BAGS must still report unavailable, or callers reading the flag are
# misled into thinking a band confirm could fire when it never can.
all_thin_anchor_matrix = np.asarray([[1.0, 0.0]], dtype=np.float32)
all_thin_window_embedding = np.asarray([[0.95, np.sqrt(1 - 0.95 ** 2)]], dtype=np.float32)
all_thin_result = compute_assignment_window(
    all_thin_window_embedding, all_thin_anchor_matrix, ["A"],
    ["cluster_a cluster_b", "cluster_a cluster_c", "cluster_b cluster_c"], ["A"] * 3,
    ["cluster_d cluster_e"],
    tau=0.94, confident_tau=0.98, tfidf_tau=0.5,
)
check("tfidf_available is False when every anchor is below _MIN_ANCHOR_BAGS, "
      "even though the SVD fit itself is numerically healthy",
      all_thin_result.tfidf_available is False, str(all_thin_result))

# Decision-path attribution, including cascade and all-rejected abstention.
direct = SimpleNamespace(status="assigned", cascade_rank=0, confirmed_in_band=False, cosine=.99)
confirm = SimpleNamespace(status="assigned", cascade_rank=0, confirmed_in_band=True, cosine=.95)
cascade = SimpleNamespace(status="assigned", cascade_rank=2, confirmed_in_band=True, cosine=.95)
rejected = SimpleNamespace(status="novel", cascade_rank=0, confirmed_in_band=False, cosine=.95)
abstain = SimpleNamespace(status="novel", cascade_rank=0, confirmed_in_band=False, cosine=.90)
check("direct path", _path_of(direct) == "direct")
check("band-confirm path", _path_of(confirm) == "band_confirm")
check("cascade recovery path", _path_of(cascade) == "cascade_recovery")
check("all-band-rejected path", _path_of(rejected) == "band_reject_abstain")
check("below-floor abstention path", _path_of(abstain) == "abstain")

cascade_result = assign_batch(
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    np.asarray([[0.96, 0.28], [0.95, -np.sqrt(1 - .95 ** 2)]], dtype=np.float32),
    ["wrong", "right"], tau=.94, confident_tau=.98, tfidf_tau=.8,
    tfidf_cos=lambda _row, anchor: 0.0 if anchor == 0 else 1.0,
)[0]
check("actual assign_batch cascade", _path_of(cascade_result) == "cascade_recovery")
check("actual cascade retains rejected candidate",
      cascade_result.band_checks == 2 and cascade_result.band_rejections == 1)
all_rejected = assign_batch(
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    np.asarray([[0.96, 0.28], [0.95, -np.sqrt(1 - .95 ** 2)]], dtype=np.float32),
    ["wrong", "also_wrong"], tau=.94, confident_tau=.98, tfidf_tau=.8,
    tfidf_cos=lambda _row, _anchor: 0.0,
)[0]
check("actual all-rejected abstention", _path_of(all_rejected) == "band_reject_abstain")
check("all-rejected attempt count retained",
      all_rejected.band_checks == 2 and all_rejected.band_rejections == 2)
actual_direct = assign_batch(
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    ["A"], tau=.94, confident_tau=.98,
)[0]
actual_confirm = assign_batch(
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    np.asarray([[.96, .28]], dtype=np.float32),
    ["A"], tau=.94, confident_tau=.98, tfidf_tau=.8,
    tfidf_cos=lambda _row, _anchor: 1.0,
)[0]
actual_abstain = assign_batch(
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    np.asarray([[.90, np.sqrt(1 - .90 ** 2)]], dtype=np.float32),
    ["A"], tau=.94, confident_tau=.98,
)[0]
check("actual direct path", _path_of(actual_direct) == "direct")
check("actual band-confirm path", _path_of(actual_confirm) == "band_confirm")
check("actual below-floor abstention", _path_of(actual_abstain) == "abstain")

path_rows = [
    {
        "session_id": "p1", "true_label": "A", "path": "direct",
        "correct": True, "predicted_novel": False, "band_checks": 0,
        "band_rejections": 0, "band_confirmed": False,
    },
    {
        "session_id": "p2", "true_label": "A", "path": "band_reject_abstain",
        "correct": False, "predicted_novel": True, "band_checks": 2,
        "band_rejections": 2, "band_confirmed": False,
    },
]
path_report = _path_metrics(path_rows, 900)
band_report = _band_report(path_rows, 950)
check("path aggregation reconciles", path_report["direct"]["share"]["numerator"] == 1
      and path_report["band_reject_abstain"]["share"]["numerator"] == 1)
check("band aggregation retains attempts", band_report["totals"]["checks"] == 2
      and band_report["totals"]["rejections"] == 2)

synthetic = [
    {
        "session_id": "s1", "true_label": "A", "predicted_label": "A",
        "correct": True, "path": "cascade_recovery", "cascade_rank": 2,
    },
    {
        "session_id": "s2", "true_label": "B", "predicted_label": None,
        "correct": False, "path": "abstain", "cascade_rank": 0,
    },
]
slices = _cascade_slices(synthetic)
check("cascade total reconciles", slices["total"]["numerator"] == 1)
check("cascade true-label slice", slices["true_label"]["A"]["numerator"] == 1)
check("cascade predicted-label slice", slices["predicted_label"]["A"]["numerator"] == 1)
check("cascade correctness slice", slices["correctness"]["true"]["numerator"] == 1)
check("cascade rank slice", slices["rank"]["2"]["numerator"] == 1)

# Odd eligible counts form pairs plus one triple, with every behavior exactly once.
trials = novelty_trials(["A", "B", "C", "D", "E"])
flat = [label for trial in trials for label in trial]
check("odd holdouts all retained", sorted(flat) == ["A", "B", "C", "D", "E"], str(trials))
check("odd holdouts remain multi-behavior", all(len(trial) >= 2 for trial in trials), str(trials))

# Loader diagnostics name invalid evidence without raising.
with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    labels_path = temp / "labels.yaml"
    sessions_path = temp / "sessions.jsonl"
    labels_path.write_text(yaml.safe_dump({
        "missing": {"annotated": True, "playbook_label": "A", "rubric_version": "v1"},
        "bad": {"annotated": True, "playbook_label": "A", "rubric_version": "v1"},
        "zero": {"annotated": True, "playbook_label": "B", "rubric_version": "v1"},
        "bool": {"annotated": True, "playbook_label": "B", "rubric_version": "v1"},
        "lex": {"annotated": True, "playbook_label": "B", "rubric_version": "v1"},
        "dup": {"annotated": True, "playbook_label": "A", "rubric_version": "v1"},
        "dim": {"annotated": True, "playbook_label": "A", "rubric_version": "v1"},
    }))

    def row(session_id: str, embedding: list[float], commands: list[dict] | None) -> dict:
        return {
            "session_id": session_id,
            "rollup_doc": {
                "@timestamp": "2026-01-01T00:00:00Z",
                "dshield": {"cowrie": {"enrichment": {"session": {
                    "embedding": embedding, "embed_version": "v1",
                    "command_set": ["hash"], "cluster": {},
                }}}},
            },
            "command_enrichments": commands or [],
        }

    command = {
        "event": {"id": "hash"},
        "dshield": {"cowrie": {"enrichment": {
            "embed_config_hash": "cfg",
            "cluster": {"id": "cluster_1", "is_outlier": False},
        }}},
    }
    rows = [
        row("bad", [float("nan"), 1.0], [command]),
        row("zero", [0.0, 0.0], [command]),
        row("bool", [True, False], [command]),
        row("lex", [1.0, 0.0], None),
        row("dup", [1.0, 0.0], [command]),
        row("dup", [1.0, 0.0], [command]),
        row("dim", [1.0, 0.0, 0.0], [command]),
    ]
    sessions_path.write_text("\n".join(json.dumps(item) for item in rows) + "\n")
    loaded = load_records_detailed(labels_path, sessions_path)
    exclusions = loaded.diagnostics["exclusions"]
    check("nonfinite embedding named", exclusions.get("nonfinite_embedding") == 1, str(exclusions))
    check("zero embedding named", exclusions.get("zero_norm_embedding") == 1, str(exclusions))
    check("boolean embedding rejected", exclusions.get("nonnumeric_embedding") == 1,
          str(exclusions))
    check("missing lexical evidence named", exclusions.get("missing_lexical_evidence") == 1,
          str(exclusions))
    check("missing metadata named", exclusions.get("missing_embed_config_metadata") == 1,
          str(exclusions))
    check("missing labeled id named",
          exclusions.get("labeled_session_missing_from_corpus") == 1, str(exclusions))
    check("duplicate entity counted once",
          exclusions.get("duplicate_session_id") == 1
          and loaded.diagnostics["duplicate_json_occurrences"] == 1, str(loaded.diagnostics))
    check("inconsistent dimension named",
          exclusions.get("inconsistent_embedding_dimension") == 1, str(exclusions))
    underpowered = evaluate(labels_path, sessions_path)
    check("underpowered/incompatible evidence INVALID", underpowered["status"] == "INVALID",
          str(underpowered["invalid_reasons"]))

check("required null is located",
      _required_nulls({"metric": {
          "numerator": 0, "denominator": 0, "value": None, "interval": None,
      }}) == ["report.metric"])

# Real committed evidence: determinism, reconciled counts, intervals, singleton visibility.
report_a = evaluate(ROOT / "eval/labels.yaml", ROOT / "eval/sessions.unlabeled.jsonl.gz")
report_b = evaluate(ROOT / "eval/labels.yaml", ROOT / "eval/sessions.unlabeled.jsonl.gz")
encoded_a = json.dumps(report_a, sort_keys=True, allow_nan=False)
encoded_b = json.dumps(report_b, sort_keys=True, allow_nan=False)
check("grouped report deterministic", encoded_a == encoded_b)
check("diagnostic pending representative anchors", report_a["status"] == "DIAGNOSTIC")
check("singleton remains visible",
      report_a["behavior_counts"].get("account_backdoor_persistence") == 1)
check("singleton exclusion is explicit",
      report_a["eligibility"]["excluded_behaviors"]["account_backdoor_persistence"]["count"] == 1)
check("familiar confusion reconciles",
      sum(sum(predicted.values()) for predicted in report_a["familiar"]["confusion"].values())
      == report_a["familiar"]["n_outcomes"])
check("novelty confusion reconciles",
      sum(report_a["novelty"]["confusion"].values()) == report_a["novelty"]["n_outcomes"])
check("per-behavior novelty denominators reconcile", sum(
    metrics["novelty_recall"]["denominator"]
    for metrics in report_a["novelty"]["per_behavior"].values()
) == report_a["novelty"]["novelty_recall"]["denominator"])
check("required metrics have no nulls",
      not _required_nulls({"familiar": report_a["familiar"], "novelty": report_a["novelty"]}))
check("deployed row explicit",
      sum(point["deployed"] for point in report_a["operating_curve"]) == 1)

# Identity mismatch reports exact fields; malformed baselines fail closed.
changed = copy.deepcopy(report_a["identity"])
changed["config"]["deployed"]["tau"] = 0.1
differences = _identity_differences(changed, report_a["identity"])
check("identity mismatch names field",
      any("identity.config.deployed.tau" in item for item in differences), str(differences))

with tempfile.TemporaryDirectory() as directory:
    outside = Path(directory)
    baseline_path = outside / "baseline.json"
    write_baseline(report_a, baseline_path)
    check("outside-repository baseline writes", baseline_path.exists())
    gated = apply_baseline(copy.deepcopy(report_a), baseline_path)
    check("matching explicit baseline passes", gated["status"] == "PASS",
          str(gated["invalid_reasons"]))
    malformed_path = outside / "malformed.json"
    malformed = json.loads(baseline_path.read_text())
    malformed["gates"]["familiar_macro_f1"]["floor"] = "not-a-number"
    malformed_path.write_text(json.dumps(malformed))
    invalid = apply_baseline(copy.deepcopy(report_a), malformed_path)
    check("malformed baseline INVALID", invalid["status"] == "INVALID")
    check("malformed baseline names numeric field", any(
        "baseline.gates.familiar_macro_f1.floor" in reason
        for reason in invalid["invalid_reasons"]
    ), str(invalid["invalid_reasons"]))
    incomplete_path = outside / "incomplete.json"
    incomplete = json.loads(baseline_path.read_text())
    incomplete["gates"].pop("novelty_recall")
    incomplete["gates"]["familiar_macro_f1"].pop("floor")
    incomplete_path.write_text(json.dumps(incomplete))
    incomplete_result = apply_baseline(copy.deepcopy(report_a), incomplete_path)
    check("under-specified baseline INVALID", incomplete_result["status"] == "INVALID")
    check("missing gate and bound named", any(
        "baseline.gates.novelty_recall is required" in reason
        for reason in incomplete_result["invalid_reasons"]
    ) and any(
        "baseline.gates.familiar_macro_f1 requires floor or ceiling" in reason
        for reason in incomplete_result["invalid_reasons"]
    ), str(incomplete_result["invalid_reasons"]))

# --- backlog items 22/23: real anchor snapshot ingestion (--anchors) ---
check("no --anchors → report carries no real_anchor_replay key",
      "real_anchor_replay" not in report_a)

with tempfile.TemporaryDirectory() as directory:
    snapshot_path = Path(directory) / "anchors.jsonl.gz"
    with gzip.open(snapshot_path, "wt") as fh:
        fh.write(json.dumps({
            "playbook_id": "spb-A", "anchor_centroid": [1.0, 0.0],
            "n_public_sessions": 2,
            "command_cluster_bags": ["cluster_1", "cluster_1 cluster_2"],
            "predicate_signature": {"host_info_gather": 1.0, "self_spread": 0.0},
        }) + "\n")
        fh.write(json.dumps({  # old-schema row: no command_cluster_bags key
            "playbook_id": "spb-B", "anchor_centroid": [0.0, 1.0],
            "n_public_sessions": 3,
            "predicate_signature": "not-a-dict",  # malformed: must degrade, not crash
        }) + "\n")
    ids, matrix, bags, bag_ids, sigs = load_anchor_snapshot(snapshot_path)
    check("loaded anchor ids in file order", ids == ["spb-A", "spb-B"], str(ids))
    check("loaded anchor matrix is L2-normalized",
          np.allclose(np.linalg.norm(matrix, axis=1), 1.0), str(matrix))
    check("bags flattened from only the row that has them",
          bags == ["cluster_1", "cluster_1 cluster_2"], str(bags))
    check("bag ids align with the bag-bearing anchor only",
          bag_ids == ["spb-A", "spb-A"], str(bag_ids))
    check("signatures load positionally aligned to anchor ids (item 54)",
          sigs == [{"host_info_gather": 1.0, "self_spread": 0.0}, None], str(sigs))

    old_schema_path = Path(directory) / "old.jsonl.gz"
    with gzip.open(old_schema_path, "wt") as fh:
        fh.write(json.dumps({
            "playbook_id": "spb-C", "anchor_centroid": [1.0, 0.0], "n_public_sessions": 5,
        }) + "\n")
    _, _, old_bags, old_bag_ids, old_sigs = load_anchor_snapshot(old_schema_path)
    check("pre-bags snapshot loads with no bags at all",
          old_bags == [] and old_bag_ids == [], str((old_bags, old_bag_ids)))
    check("pre-signature snapshot yields a None signature, not a crash",
          old_sigs == [None], str(old_sigs))

    empty_path = Path(directory) / "empty.jsonl.gz"
    with gzip.open(empty_path, "wt") as fh:
        fh.write("\n")
    try:
        load_anchor_snapshot(empty_path)
        check("empty snapshot raises EvaluationInvalid", False, "did not raise")
    except EvaluationInvalid:
        check("empty snapshot raises EvaluationInvalid", True)

    dup_path = Path(directory) / "dup.jsonl.gz"
    with gzip.open(dup_path, "wt") as fh:
        fh.write(json.dumps({
            "playbook_id": "spb-A", "anchor_centroid": [1.0, 0.0], "n_public_sessions": 5,
        }) + "\n")
        fh.write(json.dumps({
            "playbook_id": "spb-A", "anchor_centroid": [0.0, 1.0], "n_public_sessions": 5,
        }) + "\n")
    try:
        load_anchor_snapshot(dup_path)
        check("duplicate playbook_id raises EvaluationInvalid", False, "did not raise")
    except EvaluationInvalid:
        check("duplicate playbook_id raises EvaluationInvalid", True)

    mixdim_path = Path(directory) / "mixdim.jsonl.gz"
    with gzip.open(mixdim_path, "wt") as fh:
        fh.write(json.dumps({
            "playbook_id": "spb-A", "anchor_centroid": [1.0, 0.0], "n_public_sessions": 5,
        }) + "\n")
        fh.write(json.dumps({
            "playbook_id": "spb-B", "anchor_centroid": [1.0, 0.0, 0.0], "n_public_sessions": 5,
        }) + "\n")
    try:
        load_anchor_snapshot(mixdim_path)
        check("inconsistent anchor dims raise EvaluationInvalid", False, "did not raise")
    except EvaluationInvalid:
        check("inconsistent anchor dims raise EvaluationInvalid", True)

real_anchor_ids = ["spb-A", "spb-B"]
real_anchor_matrix = np.asarray([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)
replay_records = [
    EvalRecord(
        session_id="r1", analyst_label="A", embedding=np.asarray([1.0, 0.0], dtype=np.float32),
        production_playbook_id="spb-A", command_cluster_bag=None, rubric_version=None,
        embed_version=None, embed_config_hash=None, capture_timestamp=None,
    ),
    EvalRecord(
        session_id="r2", analyst_label="B", embedding=np.asarray([0.0, 1.0], dtype=np.float32),
        production_playbook_id="spb-B", command_cluster_bag=None, rubric_version=None,
        embed_version=None, embed_config_hash=None, capture_timestamp=None,
    ),
    EvalRecord(
        session_id="r3", analyst_label="C", embedding=np.asarray([1.0, 0.0], dtype=np.float32),
        production_playbook_id=None, command_cluster_bag=None, rubric_version=None,
        embed_version=None, embed_config_hash=None, capture_timestamp=None,
    ),
]
replay = _real_anchor_replay(real_anchor_ids, real_anchor_matrix, [], [], replay_records)
check("real anchor replay scores only known-production sessions",
      replay["n_scored"] == 2, str(replay))
check("real anchor replay excludes and counts unknown production id",
      replay["excluded_no_production_id"] == 1, str(replay))
check("real anchor replay accuracy against production_playbook_id",
      replay["accuracy"] == 1.0, str(replay))
check("real anchor replay reports tfidf unavailable with no bags",
      replay["tfidf_available"] is False, str(replay))
check("real anchor replay carries band_diagnosis, empty when no band checks occur",
      replay["band_diagnosis"] == {"n": 0, "min": None, "median": None, "mean": None,
                                   "max": None, "sweep": []},
      str(replay))
check("band_diagnosis n matches band.checks (both zero here)",
      replay["band_diagnosis"]["n"] == replay["band"]["checks"], str(replay))
check("real anchor replay includes per-session candidate cascade trace",
      [row["session_id"] for row in replay["candidate_trace"]] == ["r1", "r2"]
      and replay["candidate_trace"][0]["candidates"][0]["anchor_id"] == "spb-A"
      and replay["candidate_trace"][0]["candidates"][0]["decision"] == "assigned",
      str(replay.get("candidate_trace")))

# --- item 54: rescue tier through the REAL-anchor replay ---
# r4 sits at cosine 0.91 to spb-A: below tau (0.94) so the ordinary cascade calls it NOVEL,
# above a rescue_tau of 0.90 so the rescue tier gets a look at it. r5 is identical but has
# no predicate vector at all.
_below_tau = np.asarray([0.91, float(np.sqrt(1.0 - 0.91**2))], dtype=np.float32)
rescue_records = [*replay_records, EvalRecord(session_id="r4", analyst_label="A", embedding=_below_tau, production_playbook_id="spb-A", command_cluster_bag=None, rubric_version=None, embed_version=None, embed_config_hash=None, capture_timestamp=None), EvalRecord(session_id="r5", analyst_label="A", embedding=_below_tau, production_playbook_id="spb-A", command_cluster_bag=None, rubric_version=None, embed_version=None, embed_config_hash=None, capture_timestamp=None)]
# Only r4 carries evidence; spb-A's signature is modal on the same predicate, spb-B's is not.
rescue_vectors = {"r4": {"host_info_gather": True, "self_spread": False}}
real_signatures = [{"host_info_gather": 1.0}, {"host_info_gather": 0.0}]
zero_signatures = [{"host_info_gather": 0.0}, {"host_info_gather": 0.0}]
true_signatures = [{"host_info_gather": 1.0}, {"host_info_gather": 1.0}]


def _rescue_replay(vectors, signatures, rescue_tau=0.90):
    return _real_anchor_replay(
        real_anchor_ids, real_anchor_matrix, [], [], rescue_records,
        rescue_tau=rescue_tau, session_predicates=vectors,
        anchor_predicate_signatures=signatures,
    )


no_rescue = _real_anchor_replay(real_anchor_ids, real_anchor_matrix, [], [], rescue_records)
check("rescue_tau=None leaves the report shape untouched (no item-54 keys)",
      "n_rescued" not in no_rescue and "n_assigned" not in no_rescue, str(sorted(no_rescue)))

gated = _rescue_replay(rescue_vectors, real_signatures)
check("gated arm rescues the below-tau session with matching evidence",
      gated["n_rescued"] == 1, str(gated))
check("gated rescue lands on the correct production playbook",
      gated["n_rescued_correct"] == 1 and gated["n_rescued_gt_in_library"] == 1, str(gated))
check("accuracy_in_library carries its own denominator, and rescue moves it",
      gated["n_assigned_in_library"] == 3
      and gated["accuracy_in_library"] == 1.0, str(gated))


def _assignment_ids(rescue_tau=None, vectors=None, signatures=None):
    """Per-session (status, playbook_id) straight from the cascade — the control check has
    to compare these, not aggregate counts: an inert-but-reshuffling rescue tier keeps
    n_assigned and rounded accuracy identical while assigning different anchors."""
    scored = [r for r in rescue_records if r.production_playbook_id]
    result = compute_assignment_window(
        np.stack([r.embedding for r in scored]), real_anchor_matrix, real_anchor_ids, [], [],
        [r.command_cluster_bag or "" for r in scored],
        rescue_tau=rescue_tau,
        window_predicates=([vectors.get(r.session_id) for r in scored] if vectors else None),
        anchor_predicate_signatures=signatures,
    )
    return [(r.session_id, a.status, a.playbook_id) for r, a in zip(scored, result.assignments, strict=False)]


forced_false = _rescue_replay(rescue_vectors, zero_signatures)
check("forced_false arm rescues nothing (the control)",
      forced_false["n_rescued"] == 0, str(forced_false))
check("forced_false control is per-session identical to the no-rescue cascade, "
      "not merely equal in aggregate",
      _assignment_ids(rescue_tau=0.90, vectors=rescue_vectors, signatures=zero_signatures)
      == _assignment_ids(),
      str(_assignment_ids(rescue_tau=0.90, vectors=rescue_vectors, signatures=zero_signatures)))

# Same control, but with the TF-IDF band path live. The embedding-only check above cannot
# see an interaction between the rescue tier and band confirm, and the production --anchors
# run always has bags, so an untested band+rescue combination is the one that would ship.
_banded_bags = ["cluster_a cluster_b"] * _MIN_ANCHOR_BAGS + ["cluster_c"] * _MIN_ANCHOR_BAGS
_banded_bag_ids = ["spb-A"] * _MIN_ANCHOR_BAGS + ["spb-B"] * _MIN_ANCHOR_BAGS
_banded_records = [
    EvalRecord(
        session_id=r.session_id, analyst_label=r.analyst_label, embedding=r.embedding,
        production_playbook_id=r.production_playbook_id,
        command_cluster_bag="cluster_a cluster_b", rubric_version=None,
        embed_version=None, embed_config_hash=None, capture_timestamp=None,
    )
    for r in rescue_records
] + [
    # Cosine 0.96 to spb-A: inside [TAU, CONFIDENT_TAU), the only range where band confirm
    # is consulted at all. Without this row the fixture has TF-IDF available but never
    # exercises it, and the control check below would be vacuous.
    EvalRecord(
        session_id="r6", analyst_label="A",
        embedding=np.asarray([0.96, float(np.sqrt(1.0 - 0.96**2))], dtype=np.float32),
        production_playbook_id="spb-A", command_cluster_bag="cluster_a cluster_b",
        rubric_version=None, embed_version=None, embed_config_hash=None,
        capture_timestamp=None,
    ),
]


def _banded_replay(rescue_tau=None, vectors=None, signatures=None):
    return _real_anchor_replay(
        real_anchor_ids, real_anchor_matrix, _banded_bags, _banded_bag_ids, _banded_records,
        rescue_tau=rescue_tau, session_predicates=vectors,
        anchor_predicate_signatures=signatures,
    )


_banded_control = _banded_replay(0.90, rescue_vectors, zero_signatures)
_banded_base = _banded_replay()
check("band path is actually live in the banded control fixture",
      _banded_base["tfidf_available"] is True and _banded_base["band"]["checks"] > 0,
      str(_banded_base))
_diagnostic_only_real_replay_keys = {"candidate_trace"}
check("forced_false control holds with TF-IDF band confirm live, not just embedding-only",
      {
          k: v for k, v in _banded_control.items()
          if k in _banded_base and k not in _diagnostic_only_real_replay_keys
      } == {
          k: v for k, v in _banded_base.items()
          if k not in _diagnostic_only_real_replay_keys
      },
      str((_banded_control, _banded_base)))

all_true_vectors = {record.session_id: {"host_info_gather": True} for record in rescue_records}
forced_true = _rescue_replay(all_true_vectors, true_signatures)
check("forced_true arm rescues at least as much as the gated arm",
      forced_true["n_rescued"] >= gated["n_rescued"], str((forced_true, gated)))
check("forced_true rescues both below-tau sessions, gated only the evidenced one",
      forced_true["n_rescued"] == 2, str(forced_true))
check("the gated arm rescued r4 (the evidenced session), not r5",
      [sid for sid, status, _ in
       _assignment_ids(rescue_tau=0.90, vectors=rescue_vectors, signatures=real_signatures)
       if status == "assigned"] == ["r1", "r2", "r4"],
      str(_assignment_ids(rescue_tau=0.90, vectors=rescue_vectors, signatures=real_signatures)))

at_tau = _rescue_replay(rescue_vectors, real_signatures, rescue_tau=0.94)
check("rescue_tau == TAU is a no-op: nothing rescued, metrics match no-rescue",
      at_tau["n_rescued"] == 0 and at_tau["accuracy"] == no_rescue["accuracy"], str(at_tau))

# --- evidence ceilings: arm-invariant, and armed means what the gate means by it ---
lib = set(real_anchor_ids)
scored_only = [r for r in rescue_records if r.production_playbook_id]
check("all-None signatures (pre-item-50 snapshot) rescue nothing and say so",
      _rescue_replay(rescue_vectors, [None, None])["n_rescued"] == 0
      and evidence_ceilings(scored_only, lib, rescue_vectors,
                            [None, None])["anchors_with_signature"] == 0)
check("all-zero signatures count as present but not armed",
      evidence_ceilings(scored_only, lib, rescue_vectors, zero_signatures)
      == {"gt_in_library": 4, "sessions_with_predicate_evidence": 1,
          "anchors_with_signature": 2, "anchors_armed": 0},
      str(evidence_ceilings(scored_only, lib, rescue_vectors, zero_signatures)))
check("sub-modal signature (0.25 < ANCHOR_MODAL_THRESHOLD) is not armed — it can never fire",
      evidence_ceilings(scored_only, lib, rescue_vectors,
                        [{"host_info_gather": 0.25}, None])["anchors_armed"] == 0)
check("signature keyed outside PREDICATE_NAMES is not armed — the gate never reads it",
      evidence_ceilings(scored_only, lib, rescue_vectors,
                        [{"not_a_predicate": 1.0}, None])["anchors_armed"] == 0)
check("all-False session fold counts as no evidence, not as a present vector",
      evidence_ceilings(scored_only, lib, {"r4": {"host_info_gather": False}},
                        real_signatures)["sessions_with_predicate_evidence"] == 0)

try:
    _rescue_replay(rescue_vectors, [*real_signatures, {"host_info_gather": 1.0}])
    check("misaligned signature list raises EvaluationInvalid", False, "did not raise")
except EvaluationInvalid:
    check("misaligned signature list raises EvaluationInvalid", True)

try:
    _real_anchor_replay(
        real_anchor_ids, real_anchor_matrix, [], [],
        [r for r in rescue_records if not r.production_playbook_id],
        rescue_tau=0.90, session_predicates={}, anchor_predicate_signatures=[None] * 5,
    )
    check("misalignment is caught even when no session is scorable", False, "did not raise")
except EvaluationInvalid:
    check("misalignment is caught even when no session is scorable", True)

sweep = run_real_anchor_rescue_sweep(
    real_anchor_ids, real_anchor_matrix, [], [], real_signatures, rescue_records,
    rescue_vectors, [0.94, 0.90],
)
check("sweep emits one row per rescue_tau, each with all three arms",
      len(sweep["rows"]) == 2
      and all(set(row["arms"]) == set(RESCUE_ARMS) for row in sweep["rows"]),
      str(sweep["rows"]))
check("sweep nests rows under 'rows', never shadowing the top-level rescue_tau_sweep key",
      "rescue_tau_sweep" not in sweep, str(sorted(sweep)))
check("sweep reports evidence ceilings once, from the real inputs — not per arm",
      sweep["evidence"]["anchors_armed"] == 1
      and sweep["evidence"]["sessions_with_predicate_evidence"] == 1
      and all("anchors_armed" not in row["arms"][arm]
              for row in sweep["rows"] for arm in RESCUE_ARMS),
      str(sweep["evidence"]))
check("sweep forced_false rescues 0 at every rescue_tau",
      all(row["arms"]["forced_false"]["n_rescued"] == 0 for row in sweep["rows"]),
      str(sweep["rows"]))
check("sweep gated never exceeds forced_true",
      all(row["arms"]["gated"]["n_rescued"] <= row["arms"]["forced_true"]["n_rescued"]
          for row in sweep["rows"]), str(sweep["rows"]))
check("blocked_fraction is None when tau-lowering rescues nothing (rescue_tau == TAU)",
      sweep["rows"][0]["blocked_fraction"] is None, str(sweep["rows"][0]))
check("blocked_fraction is the share of ungated rescues the gate refuses",
      sweep["rows"][1]["blocked_fraction"] == 0.5, str(sweep["rows"][1]))

no_evidence_sweep = run_real_anchor_rescue_sweep(
    real_anchor_ids, real_anchor_matrix, [], [], zero_signatures, rescue_records,
    {}, [0.90],
)
check("blocked_fraction is withheld when the gate had no evidence to weigh "
      "(not reported as 1.0 = 'refuses everything')",
      no_evidence_sweep["rows"][0]["blocked_fraction"] is None
      and no_evidence_sweep["rows"][0]["arms"]["forced_true"]["n_rescued"] == 2,
      str(no_evidence_sweep["rows"][0]))

_print_real_anchor_rescue_sweep(sweep)
_print_real_anchor_rescue_sweep({"arms": list(RESCUE_ARMS), "evidence": {}, "rows": []})
check("printer renders a populated sweep and an empty one without raising", True)

# --- the shared vector builder: both sweeps must derive session vectors identically ---
built = build_session_predicate_vectors({"s1": ("host_recon", ["uname -m", "crontab -l"])})
check("build_session_predicate_vectors keys on session_id and returns all 7 predicates",
      set(built) == {"s1"} and set(built["s1"]) == set(PREDICATE_NAMES), str(built))
check("build_session_predicate_vectors folds real command text into real evidence",
      built["s1"]["host_info_gather"] is True, str(built["s1"]))
check("empty command text yields no vectors at all",
      build_session_predicate_vectors({}) == {})

# --- main(): the CLI range guard, which runs before any replay ---
for bad in ("0.99", "0", "-0.5", "0.90,0.99"):
    argv = sys.argv
    sys.argv = ["eval_assignment_faithful.py", "--rescue-tau-sweep", bad]
    try:
        rc = main()
    finally:
        sys.argv = argv
    check(f"--rescue-tau-sweep {bad!r} is refused with exit 2 before any replay", rc == 2)

# --- _band_diagnosis (item 34): pure post-processing over a synthetic trace ---
synthetic_trace = [
    {"emb_cos": 0.95, "tfidf_cos": 0.85, "confirmed": True},
    {"emb_cos": 0.96, "tfidf_cos": 0.55, "confirmed": False},
    {"emb_cos": 0.97, "tfidf_cos": 0.30, "confirmed": False},
]
diag = _band_diagnosis(synthetic_trace)
check("band_diagnosis n/min/median/max over synthetic trace",
      diag["n"] == 3 and diag["min"] == 0.30 and diag["max"] == 0.85, str(diag))
check("band_diagnosis sweep has one row per TFIDF_TAU_SWEEP_GRID point",
      len(diag["sweep"]) == 10, str(diag))
check("band_diagnosis sweep confirms_at_tau non-increasing as tau rises",
      all(diag["sweep"][i]["confirms_at_tau"] >= diag["sweep"][i + 1]["confirms_at_tau"]
          for i in range(len(diag["sweep"]) - 1)),
      str(diag["sweep"]))
check("band_diagnosis sweep resolves the tfidf_tau=0.8 grid point on this synthetic trace "
      "(not a claim about the real corpus — see Finding 31 for that)",
      next(row for row in diag["sweep"] if row["tfidf_tau"] == 0.8)["confirms_at_tau"] == 1,
      str(diag["sweep"]))
check("empty trace → band_diagnosis n=0, no stats, empty sweep",
      _band_diagnosis([]) == {"n": 0, "min": None, "median": None, "mean": None,
                              "max": None, "sweep": []})

mismatched_anchor_matrix = np.asarray([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]], dtype=np.float32)
try:
    _real_anchor_replay(real_anchor_ids, mismatched_anchor_matrix, [], [], replay_records)
    check("anchor/corpus dimension mismatch raises EvaluationInvalid", False, "did not raise")
except EvaluationInvalid:
    check("anchor/corpus dimension mismatch raises EvaluationInvalid", True)

# --- item 38: background cohort — pads the fit, never scored; omitted is parity ---
bg_anchor_bags = ["cluster_a cluster_b"] * _MIN_ANCHOR_BAGS
bg_anchor_ids = ["spb-A"] * _MIN_ANCHOR_BAGS
bg_window_bags = ["cluster_a cluster_b", "cluster_c"]

no_background = prepare_assignment_lexical(bg_anchor_bags, bg_anchor_ids, bg_window_bags)
empty_tuple_background = prepare_assignment_lexical(
    bg_anchor_bags, bg_anchor_ids, bg_window_bags, background_bags=(),
)
check("background_bags omitted vs explicit empty tuple: byte-identical fit",
      np.allclose(no_background.window_features, empty_tuple_background.window_features)
      and no_background.available == empty_tuple_background.available
      and set(no_background.anchor_centroids) == set(empty_tuple_background.anchor_centroids))

padded_background = prepare_assignment_lexical(
    bg_anchor_bags, bg_anchor_ids, bg_window_bags,
    background_bags=["cluster_z cluster_z cluster_z"] * 40,
)
check("background_bags padding changes window row count NOT (only pads the fit)",
      padded_background.window_features.shape[0] == no_background.window_features.shape[0])
check("background_bags padding measurably changes the fitted geometry "
      "(different vocabulary/SVD dimensionality, or same shape but different values)",
      padded_background.window_features.shape != no_background.window_features.shape
      or not np.allclose(padded_background.window_features, no_background.window_features))
check("background cohort still yields a centroid for the (adequately sampled) anchor",
      "spb-A" in padded_background.anchor_centroids)

with tempfile.TemporaryDirectory() as directory:
    cohort_path = Path(directory) / "background-cohort.jsonl.gz"
    with gzip.open(cohort_path, "wt") as fh:
        for i in range(50):
            fh.write(json.dumps({
                "session_id": f"cohort{i}", "command_cluster_bag": "cluster_z cluster_z",
            }) + "\n")
    loaded_cohort = load_background_cohort(cohort_path)
    check("load_background_cohort reads one bag string per row",
          len(loaded_cohort) == 50 and loaded_cohort[0] == "cluster_z cluster_z",
          str(loaded_cohort[:2]))

    missing_path = Path(directory) / "does-not-exist.jsonl.gz"
    try:
        load_background_cohort(missing_path)
        check("missing background cohort file raises EvaluationInvalid", False, "did not raise")
    except EvaluationInvalid:
        check("missing background cohort file raises EvaluationInvalid", True)

    corrupt_path = Path(directory) / "corrupt.jsonl.gz"
    corrupt_path.write_bytes(b"not actually gzip")
    try:
        load_background_cohort(corrupt_path)
        check("corrupt background cohort file raises EvaluationInvalid", False, "did not raise")
    except EvaluationInvalid:
        check("corrupt background cohort file raises EvaluationInvalid", True)

    empty_cohort_path = Path(directory) / "empty-cohort.jsonl.gz"
    with gzip.open(empty_cohort_path, "wt") as fh:
        fh.write("\n")
    try:
        load_background_cohort(empty_cohort_path)
        check("empty background cohort file raises EvaluationInvalid", False, "did not raise")
    except EvaluationInvalid:
        check("empty background cohort file raises EvaluationInvalid", True)

    non_object_row_path = Path(directory) / "non-object-row.jsonl.gz"
    with gzip.open(non_object_row_path, "wt") as fh:
        fh.write(json.dumps(["not", "an", "object"]) + "\n")
    try:
        load_background_cohort(non_object_row_path)
        check("non-object row raises EvaluationInvalid, not a raw AttributeError",
              False, "did not raise")
    except EvaluationInvalid:
        check("non-object row raises EvaluationInvalid, not a raw AttributeError", True)

# `_real_anchor_replay` wiring: background_bags=None (the omitted default) is byte-identical
# to not passing the kwarg at all; scored/excluded counts never include cohort rows, since
# the cohort never enters `records`.
replay_no_kwarg = _real_anchor_replay(
    real_anchor_ids, real_anchor_matrix, bg_anchor_bags, bg_anchor_ids, replay_records,
)
replay_none_kwarg = _real_anchor_replay(
    real_anchor_ids, real_anchor_matrix, bg_anchor_bags, bg_anchor_ids, replay_records,
    background_bags=None,
)
check("real anchor replay: background_bags=None matches the omitted-kwarg call",
      replay_no_kwarg == replay_none_kwarg, str((replay_no_kwarg, replay_none_kwarg)))

replay_with_background = _real_anchor_replay(
    real_anchor_ids, real_anchor_matrix, bg_anchor_bags, bg_anchor_ids, replay_records,
    background_bags=loaded_cohort,
)
check("real anchor replay: background cohort present, scored count unaffected by cohort size",
      replay_with_background["n_scored"] == replay_no_kwarg["n_scored"] == 2,
      str(replay_with_background))
check("real anchor replay: excluded-count unaffected by cohort presence",
      replay_with_background["excluded_no_production_id"]
      == replay_no_kwarg["excluded_no_production_id"] == 1)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    raise SystemExit(1)
