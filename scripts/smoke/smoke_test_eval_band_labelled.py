"""Offline contract tests for scripts/eval_band_labelled.py."""
from __future__ import annotations

import math
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import eval_band_labelled as target

from enrich.classification import releasable_filter
from enrich.sources.cowrie.assignment import ASSIGNED, Assignment

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name} ({detail})")


def cfg():
    return SimpleNamespace(
        classification=SimpleNamespace(unclassified_is_confidential=True),
        session=SimpleNamespace(
            assignment_tau=0.80,
            assignment_confident_tau=0.95,
            assignment_tfidf_tau=0.80,
            assignment_band_bypass_anchor_ids=[" A ", "", " "],
            assignment_rescue_tau=0.80,
        ),
        elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=SimpleNamespace(
            sessions_rollup="sessions",
            commands="commands",
            playbook_anchors="anchors",
        ))),
    )


def hit(doc_id, source, order):
    return {"_id": doc_id, "_source": source, "sort": [order]}


def window_source(session_id, embedding, command_set, **extra):
    return {
        "cowrie": {"session_id": session_id},
        "dshield": {"cowrie": {"enrichment": {"session": {
            "embedding": embedding, "command_set": command_set, **extra,
        }}}},
    }


LABELS_YAML = """
sid-assigned:
  annotated: true
  is_real: true
  playbook_label: single_command_probe
sid-assigned-majority:
  annotated: true
  is_real: true
  playbook_label: single_command_probe
sid-band:
  annotated: true
  is_real: true
  playbook_label: inband_payload_drop
sid-b-majority:
  annotated: true
  is_real: true
  playbook_label: credential_spray
sid-b-majority-2:
  annotated: true
  is_real: true
  playbook_label: credential_spray
sid-false-familiar:
  annotated: true
  is_real: true
  playbook_label: scp_upload
sid-real-novel:
  annotated: true
  is_real: true
  playbook_label: iot_cli_probe
sid-false-positive:
  annotated: true
  is_real: true
  playbook_label: single_command_probe
sid-dup:
  annotated: true
  is_real: true
  playbook_label: host_recon
sid-missing:
  annotated: true
  is_real: true
  playbook_label: scp_upload
sid-not-annotated:
  annotated: false
  is_real: true
  playbook_label: iot_cli_probe
sid-not-real:
  annotated: true
  is_real: false
  playbook_label: botnet_loader
sid-no-label:
  annotated: true
  is_real: true
  playbook_label: ''
sid-unknown-label:
  annotated: true
  is_real: true
  playbook_label: not_a_real_playbook_typo
"""


class MockES:
    """Fixture: three anchors (A, B, C), a public window with one confidently-assigned
    session, one in-band target-label session that rejects thick A then lands on thin C,
    and a duplicate `cowrie.session_id` -- exercising both edge cases in item 65's I/O
    matrix (absent + duplicate). Rollup `_id`s are deliberately different strings from
    `cowrie.session_id` so a join that (incorrectly) used `_id` instead of the field
    would fail to resolve anything."""

    def __init__(self):
        self.queries: list[tuple[str, dict]] = []
        self.write_calls = 0
        band_angle_cos = 0.85
        self.thin_anchor_centroid = [0.4, math.sqrt(1 - 0.4 ** 2)]
        self.window = [
            hit("rollup-1", window_source(
                "sid-assigned", [1.0, 0.0], ["hash-a"],
            ), 0),
            hit("rollup-1b", window_source(
                "sid-assigned-majority", [1.0, 0.0], ["hash-a"],
            ), 1),
            hit("rollup-2", window_source(
                "sid-band", [band_angle_cos, math.sqrt(1 - band_angle_cos ** 2)],
                ["hash-a", "hash-b"],
            ), 2),
            hit("rollup-3", window_source(
                "sid-b-majority", [0.0, 1.0], ["hash-b"],
            ), 3),
            hit("rollup-3b", window_source(
                "sid-b-majority-2", [0.0, 1.0], ["hash-b"],
            ), 4),
            hit("rollup-4", window_source(
                "sid-false-familiar", [0.0, 1.0], ["hash-b"],
            ), 5),
            hit("rollup-5", window_source(
                "sid-real-novel", [-1.0, 0.0], ["hash-a"],
            ), 6),
            hit("rollup-5b", window_source(
                "sid-false-positive", [-1.0, 0.0], ["hash-a"],
            ), 7),
            hit("rollup-6a", window_source("sid-dup", [0.0, 1.0], ["hash-a"]), 8),
            hit("rollup-6b", window_source("sid-dup", [0.0, 1.0], ["hash-a"]), 9),
            hit("rollup-4", window_source(
                "sid-not-labelled", [0.0, -1.0], ["hash-a"],
            ), 10),
        ]

    @staticmethod
    def _page(rows, body):
        if body.get("search_after") is not None:
            return []
        return rows[:body["size"]]

    def search(self, index, **body):
        self.queries.append((index, body))
        if index == "anchors":
            return {"hits": {"hits": [
                hit("anchor-a", {"playbook_id": "A", "anchor_centroid": [1.0, 0.0]}, 0),
                hit("anchor-b", {"playbook_id": "B", "anchor_centroid": [0.0, 1.0]}, 1),
                hit("anchor-c", {
                    "playbook_id": "C", "anchor_centroid": self.thin_anchor_centroid,
                }, 2),
            ]}}
        filters = body["query"]["bool"]["filter"]
        if index == "commands":
            rows = [
                hit("hash-a", {"dshield": {"cowrie": {"enrichment": {"cluster": {
                    "id": "cluster-a", "is_outlier": False,
                }}}}}, 0),
                hit("hash-b", {"dshield": {"cowrie": {"enrichment": {"cluster": {
                    "id": "cluster-b", "is_outlier": False,
                }}}}}, 1),
                hit("hash-c", {"dshield": {"cowrie": {"enrichment": {"cluster": {
                    "id": "cluster-c", "is_outlier": False,
                }}}}}, 2),
            ]
            return {"hits": {"hits": self._page(rows, body)}}
        if any(target._PB in clause.get("term", {}) for clause in filters):
            anchor_id = next(clause["term"][target._PB] for clause in filters if "term" in clause and target._PB in clause["term"])
            if anchor_id == "C":
                return {"hits": {"hits": []}}
            command_set = ["hash-a"] if anchor_id == "A" else ["hash-b", "hash-c"]
            rows = [
                hit(f"anchor-sample-{anchor_id}-{i}", window_source(
                    f"anchor-sample-{anchor_id}-{i}", None, command_set,
                ), i)
                for i in range(50)
            ]
            return {"hits": {"hits": self._page(rows, body)}}
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

    labels = target.load_scorable_labels(labels_path)
    check(
        "scorable filter excludes unannotated/not-real/unlabelled/unknown-label rows",
        set(labels) == {
            "sid-assigned", "sid-assigned-majority", "sid-band", "sid-b-majority",
            "sid-b-majority-2", "sid-false-familiar", "sid-real-novel", "sid-dup",
            "sid-false-positive", "sid-missing",
        },
        str(labels),
    )
    check(
        "scorable labels preserve the playbook_label text",
        labels.get("sid-assigned") == "single_command_probe"
        and labels.get("sid-band") == "inband_payload_drop",
        str(labels),
    )
    check(
        "an unknown/typo'd playbook_label is excluded, not silently scored "
        "(mirrors eval_assignment.load_records_detailed's invalid_membership check)",
        "sid-unknown-label" not in labels,
        str(labels),
    )

    missing_path = Path(tmp) / "does-not-exist.yaml"
    try:
        target.load_scorable_labels(missing_path)
        missing_raised = None
    except Exception as exc:
        missing_raised = exc
    check(
        "a missing labels file fails clean with ValueError, not a raw OSError traceback",
        isinstance(missing_raised, ValueError),
        repr(missing_raised),
    )

    bad_yaml_path = Path(tmp) / "bad.yaml"
    bad_yaml_path.write_text("sid: [unbalanced")
    try:
        target.load_scorable_labels(bad_yaml_path)
        bad_yaml_raised = None
    except Exception as exc:
        bad_yaml_raised = exc
    check(
        "malformed YAML fails clean with ValueError, not a raw yaml.YAMLError traceback",
        isinstance(bad_yaml_raised, ValueError),
        repr(bad_yaml_raised),
    )

mock = MockES()
inputs = target.load_inputs(mock, cfg(), per_anchor=50)
public_clause = releasable_filter(cfg())
cowrie_queries = [body for index, body in mock.queries if index in {"sessions", "commands"}]
check(
    "every cowrie session/command query carries the exact public-only filter",
    cowrie_queries
    and all(public_clause in body["query"]["bool"]["filter"] for body in cowrie_queries),
    str(cowrie_queries),
)
check("loader performs no writes", mock.write_calls == 0)
check(
    "session ids are read from the cowrie.session_id field, not the rollup _id",
    "sid-assigned" in inputs.session_ids
    and "rollup-1" not in inputs.session_ids
    and "sid-dup" in inputs.session_ids,
    str(inputs.session_ids),
)
check(
    "window scan resolves duplicate cowrie.session_id occurrences",
    inputs.session_ids.count("sid-dup") == 2,
    str(inputs.session_ids),
)

resolved, unresolved = target.join_labels_to_window(inputs.session_ids, labels)
check(
    "label join resolves unique ids and buckets absent/duplicate ones by name",
    set(resolved.values()) == {
        "single_command_probe", "credential_spray", "inband_payload_drop",
        "scp_upload", "iot_cli_probe",
    }
    and unresolved.get("unresolved_absent_from_public_window") == 1
    and unresolved.get("unresolved_duplicate_session_id_in_window") == 1,
    str((resolved, unresolved)),
)
check(
    "label join never silently drops an unresolved labelled row",
    len(resolved) + sum(unresolved.values()) == len(labels),
    str((resolved, unresolved)),
)

calls = {"compute_assignment_window": 0, "assign_batch": 0}
band_bypass_calls = []
original_caw = target.compute_assignment_window
original_ab = target.assign_batch


def counting_caw(*args, **kwargs):
    calls["compute_assignment_window"] += 1
    band_bypass_calls.append(kwargs.get("band_bypass_anchor_ids"))
    return original_caw(*args, **kwargs)


def counting_ab(*args, **kwargs):
    calls["assign_batch"] += 1
    return original_ab(*args, **kwargs)


target.compute_assignment_window = counting_caw
target.assign_batch = counting_ab
try:
    report = target.analyze(inputs, cfg(), labels)
finally:
    target.compute_assignment_window = original_caw
    target.assign_batch = original_ab

check(
    "the two band-enabled arms each fit TF-IDF via compute_assignment_window",
    calls["compute_assignment_window"] == 2, str(calls),
)
check(
    "the two band-enabled arms receive the normalized anchor-scoped bypass allowlist",
    band_bypass_calls == [{"A"}, {"A"}], str(band_bypass_calls),
)
check(
    "the disabled arm calls assign_batch directly exactly once, no lexical fit at all",
    calls["assign_batch"] == 1, str(calls),
)
check(
    "effective_config reports sorted normalized anchor-scoped bypass ids",
    report["effective_config"]["assignment_band_bypass_anchor_ids"] == ["A"],
    str(report["effective_config"]),
)

scalar_bypass_cfg = cfg()
scalar_bypass_cfg.session.assignment_band_bypass_anchor_ids = " A "
scalar_bypass_report = target.analyze(inputs, scalar_bypass_cfg, labels)
check(
    "scalar string anchor-scoped bypass config is treated as one anchor id",
    scalar_bypass_report["effective_config"]["assignment_band_bypass_anchor_ids"] == ["A"],
    str(scalar_bypass_report["effective_config"]),
)

null_bypass_cfg = cfg()
null_bypass_cfg.session.assignment_band_bypass_anchor_ids = None
null_bypass_report = target.analyze(inputs, null_bypass_cfg, labels)
check(
    "null anchor-scoped bypass config is treated as empty",
    null_bypass_report["effective_config"]["assignment_band_bypass_anchor_ids"] == [],
    str(null_bypass_report["effective_config"]),
)

unknown_bypass_cfg = cfg()
unknown_bypass_cfg.session.assignment_band_bypass_anchor_ids = ["missing-anchor"]
try:
    target.analyze(inputs, unknown_bypass_cfg, labels)
    check("unknown anchor-scoped bypass ids are rejected", False)
except ValueError as exc:
    check(
        "unknown anchor-scoped bypass ids are rejected",
        "unknown anchor ids" in str(exc) and "missing-anchor" in str(exc),
        str(exc),
    )

check("report carries exactly three arms", len(report["arms"]) == 3, str(report["arms"]))
arm_names = [arm["name"] for arm in report["arms"]]
check("arms are named deployed/valley/disabled in order", arm_names == ["deployed", "valley", "disabled"], str(arm_names))

deployed, valley, disabled = report["arms"]
check("deployed arm carries the configured tfidf_tau", deployed["tfidf_tau"] == 0.80, str(deployed))
check("valley arm carries Finding 47's 0.50 tfidf_tau", valley["tfidf_tau"] == 0.50, str(valley))
check("disabled arm carries no tfidf_tau and is marked band-disabled",
      disabled["tfidf_tau"] is None and disabled["band_enabled"] is False, str(disabled))
check(
    "disabled arm never ran a lexical fit, so tfidf is reported unavailable",
    disabled["tfidf_available"] is False, str(disabled),
)
check(
    "disabled arm's band_separation is trivially empty (no band_trace ever populated)",
    disabled["band_separation"]["overall"]["n"] == 0, str(disabled["band_separation"]),
)

for arm in report["arms"]:
    expected_arm_keys = {
        "name", "tfidf_tau", "band_enabled", "tfidf_available", "n_scored",
        "n_true_labels", "status_counts", "assigned_rate", "purity",
        "per_label_accuracy", "macro_f1", "novelty_per_arm", "novelty_comparable",
        "band_separation", "candidate_trace", "target_label_candidate_summary",
        "status_delta_vs_deployed",
    }
    check(
        f"{arm['name']} arm has the stable aggregate output schema",
        set(arm) == expected_arm_keys, str(sorted(arm)),
    )
    check(
        f"{arm['name']} arm reports a bootstrap interval on purity",
        "interval" in arm["purity"], str(arm["purity"]),
    )
    check(
        f"{arm['name']} arm reports a bootstrap interval on macro_f1",
        "interval" in arm["macro_f1"], str(arm["macro_f1"]),
    )
    check(
        f"{arm['name']} arm scores exactly the resolved labelled rows",
        arm["n_scored"] == len(resolved), str(arm),
    )
    if arm["band_enabled"]:
        check(
            f"{arm['name']} arm carries one aggregate-safe candidate trace per labelled row",
            len(arm["candidate_trace"]) == len(resolved)
            and all(set(row) == {
                "session_id", "true_label", "status", "assigned_playbook_id", "candidates",
            } for row in arm["candidate_trace"]),
            str(arm["candidate_trace"]),
        )
        check(
            f"{arm['name']} arm candidate trace rows use synthetic ids only",
            {row["session_id"] for row in arm["candidate_trace"]} == {str(i) for i in resolved},
            str(arm["candidate_trace"]),
        )
    else:
        check(
            f"{arm['name']} arm reports no candidate trace for the band-disabled baseline",
            arm["candidate_trace"] == [],
            str(arm["candidate_trace"]),
        )
    target_summary = arm["target_label_candidate_summary"]
    expected_target_summary_keys = {
        "label", "n_rows", "final_status_counts", "final_assigned_anchor_counts",
        "candidate_decision_counts", "candidate_pre_status_counts",
        "tfidf_none_decision_counts", "tfidf_numeric_decision_counts",
        "assigned_winner_anchor_counts", "assigned_winner_rank_counts",
        "rows_with_below_floor_stop", "rows_with_band_rejection",
        "rows_with_tfidf_none_assignment", "rows_with_tfidf_numeric_assignment",
    }
    check(
        f"{arm['name']} arm reports the inband_payload_drop target-label summary schema",
        set(target_summary) == expected_target_summary_keys
        and target_summary["label"] == "inband_payload_drop"
        and target_summary["n_rows"] == 1,
        str(target_summary),
    )
    check(
        f"{arm['name']} arm no longer exposes the ambiguous single novelty key",
        "novelty" not in arm, str(arm),
    )
    novelty = arm["novelty_comparable"]
    expected_novelty_keys = {
        "basis", "familiar_labels", "novel_precision", "novel_recall",
        "false_familiar", "n_flagged_novel", "n_real_novel", "n_real_familiar",
        "true_positive", "false_positive", "false_negative", "true_negative",
    }
    check(
        f"{arm['name']} arm reports comparable real-geometry novelty metrics",
        set(novelty) == expected_novelty_keys
        and novelty["basis"] == "union_arm_majorities"
        and novelty["n_real_novel"] >= 1
        and novelty["n_real_familiar"] >= 1
        and novelty["true_positive"] >= 1
        and novelty["false_positive"] >= 1
        and novelty["false_negative"] >= 1
        and novelty["n_flagged_novel"] == (
            novelty["true_positive"] + novelty["false_positive"]
        )
        and novelty["novel_precision"] == round(
            novelty["true_positive"] / novelty["n_flagged_novel"], 4,
        ),
        str(novelty),
    )
    check(
        f"{arm['name']} arm retains a per-arm novelty diagnostic",
        set(arm["novelty_per_arm"]) == expected_novelty_keys
        and arm["novelty_per_arm"]["basis"] == "arm_majorities",
        str(arm["novelty_per_arm"]),
    )

comparable_denominators = {
    (arm["novelty_comparable"]["n_real_novel"], arm["novelty_comparable"]["n_real_familiar"])
    for arm in report["arms"]
}
check(
    "comparable novelty uses one invariant real-novel denominator across arms",
    len(comparable_denominators) == 1, str(comparable_denominators),
)

check(
    "predicted_label is the anchor's majority ANALYST LABEL, not the raw playbook id "
    "(item 66/Finding 49: per_label_accuracy/macro_f1 compared an spb-<hex> id against "
    "a label string and were silently 0.0 in every arm despite a non-trivial purity)",
    deployed["macro_f1"]["value"] > 0.0
    and any(v["numerator"] > 0 for v in deployed["per_label_accuracy"].values()),
    str((deployed["macro_f1"], deployed["per_label_accuracy"])),
)
check(
    "deployed arm's status_delta_vs_deployed is trivially zero against itself",
    deployed["status_delta_vs_deployed"] == {
        "n_compared": len(resolved), "assigned_to_novel": 0,
        "novel_to_assigned": 0, "label_changed_while_assigned": 0,
    },
    str(deployed["status_delta_vs_deployed"]),
)
check(
    "non-deployed arms report a status_delta_vs_deployed with a comparable n",
    valley["status_delta_vs_deployed"]["n_compared"] == len(resolved)
    and disabled["status_delta_vs_deployed"]["n_compared"] == len(resolved),
    str((valley["status_delta_vs_deployed"], disabled["status_delta_vs_deployed"])),
)

deployed_target_trace = next(
    row for row in deployed["candidate_trace"]
    if row["true_label"] == "inband_payload_drop"
)
deployed_target_candidates = deployed_target_trace["candidates"]
check(
    "deployed inband_payload_drop trace assigns configured thick anchor by band bypass",
    [row["decision"] for row in deployed_target_candidates[:1]] == [
        "band_bypass_assigned",
    ]
    and deployed_target_candidates[0]["anchor_id"] == "A"
    and deployed_target_candidates[0]["tfidf_cos"] is None
    and deployed_target_trace["assigned_playbook_id"] == "A",
    str(deployed_target_trace),
)
check(
    "deployed target-label summary counts the bypassed thick anchor winner",
    deployed["target_label_candidate_summary"]["candidate_decision_counts"] == {
        "band_bypass_assigned": 1,
    }
    and deployed["target_label_candidate_summary"]["tfidf_numeric_decision_counts"] == {}
    and deployed["target_label_candidate_summary"]["tfidf_none_decision_counts"] == {
        "band_bypass_assigned": 1,
    }
    and deployed["target_label_candidate_summary"]["final_assigned_anchor_counts"] == {"A": 1}
    and deployed["target_label_candidate_summary"]["assigned_winner_anchor_counts"] == {"A": 1}
    and deployed["target_label_candidate_summary"]["rows_with_tfidf_none_assignment"] == 1
    and deployed["target_label_candidate_summary"]["assigned_winner_rank_counts"] == {"0": 1},
    str(deployed["target_label_candidate_summary"]),
)
check(
    "disabled arm reports an empty candidate summary for the band-disabled baseline",
    disabled["target_label_candidate_summary"]["candidate_decision_counts"] == {}
    and disabled["target_label_candidate_summary"]["tfidf_none_decision_counts"] == {}
    and disabled["target_label_candidate_summary"]["tfidf_numeric_decision_counts"] == {}
    and disabled["target_label_candidate_summary"]["rows_with_tfidf_none_assignment"] == 0,
    str(disabled["target_label_candidate_summary"]),
)

rendered = str(report)
check(
    "the report never contains a real cowrie session id",
    all(
        secret not in rendered
        for secret in (
            "sid-assigned", "sid-band", "sid-b-majority", "sid-false-familiar",
            "sid-real-novel", "sid-false-positive", "sid-dup", "sid-missing",
            "rollup-",
        )
    ),
    rendered,
)

check(
    "labels block accounts for every scorable row (resolved + unresolved)",
    report["labels"]["scorable_total"] == len(labels)
    and report["labels"]["resolved"] == len(resolved)
    and sum(report["labels"]["unresolved"].values()) == len(labels) - len(resolved),
    str(report["labels"]),
)

all_assigned_report, _, _ = target.score_arm(
    "synthetic",
    None,
    False,
    [
        Assignment("A", 1.0, ASSIGNED),
        Assignment("A", 1.0, ASSIGNED),
        Assignment("A", 1.0, ASSIGNED),
    ],
    None,
    [[] for _ in range(3)],
    False,
    {
        0: "single_command_probe",
        1: "single_command_probe",
        2: "scp_upload",
    },
    None,
    9000,
)
check(
    "novel_precision is null when no rows are flagged novel, while false-familiar is scored",
    all_assigned_report["novelty_per_arm"]["novel_precision"] is None
    and all_assigned_report["novelty_per_arm"]["n_flagged_novel"] == 0
    and all_assigned_report["novelty_per_arm"]["novel_recall"] == 0.0
    and all_assigned_report["novelty_per_arm"]["false_familiar"] == 1.0,
    str(all_assigned_report["novelty_per_arm"]),
)

no_real_novel_report, _, _ = target.score_arm(
    "synthetic",
    None,
    False,
    [
        Assignment("A", 1.0, ASSIGNED),
        Assignment("A", 1.0, ASSIGNED),
    ],
    None,
    [[] for _ in range(2)],
    False,
    {
        0: "single_command_probe",
        1: "single_command_probe",
    },
    None,
    9100,
)
check(
    "novel_recall and false_familiar are null when there are no real-novel rows",
    no_real_novel_report["novelty_per_arm"]["novel_recall"] is None
    and no_real_novel_report["novelty_per_arm"]["false_familiar"] is None
    and no_real_novel_report["novelty_per_arm"]["n_real_novel"] == 0,
    str(no_real_novel_report["novelty_per_arm"]),
)

tied_majority_report, _, _ = target.score_arm(
    "synthetic",
    None,
    False,
    [
        Assignment("A", 1.0, ASSIGNED),
        Assignment("A", 1.0, ASSIGNED),
    ],
    None,
    [[] for _ in range(2)],
    False,
    {
        0: "single_command_probe",
        1: "credential_spray",
    },
    None,
    9200,
)
check(
    "tied anchor majority labels do not become row-order-dependent familiar labels",
    tied_majority_report["purity"]["numerator"] == 0
    and tied_majority_report["novelty_per_arm"]["n_real_novel"] == 2
    and tied_majority_report["novelty_per_arm"]["false_negative"] == 2,
    str(tied_majority_report),
)

synthetic_arms = [{"name": "arm-a"}, {"name": "arm-b"}]
synthetic_rows = [
    {"true_label": "single_command_probe", "status": ASSIGNED},
    {"true_label": "credential_spray", "status": ASSIGNED},
    {"true_label": "scp_upload", "status": target.NOVEL},
]
target._attach_comparable_novelty(
    synthetic_arms,
    [
        {"rows": synthetic_rows, "majority": {"A": "single_command_probe"}},
        {"rows": synthetic_rows, "majority": {"B": "credential_spray"}},
    ],
)
check(
    "differing arm-local majority labels produce one shared comparable novelty basis",
    synthetic_arms[0]["novelty_comparable"]["familiar_labels"]
    == synthetic_arms[1]["novelty_comparable"]["familiar_labels"]
    == ["credential_spray", "single_command_probe"]
    and synthetic_arms[0]["novelty_comparable"]["n_real_novel"] == 1
    and synthetic_arms[1]["novelty_comparable"]["n_real_familiar"] == 2,
    str(synthetic_arms),
)

# --- confirm-flag gate: refuse before any ES call when the flag is omitted ---
original_argv = sys.argv
sys.argv = ["eval_band_labelled.py"]
try:
    target.main()
    check("missing --confirm-mixed-derived-anchors exits before any ES call", False)
except SystemExit as exc:
    check(
        "missing --confirm-mixed-derived-anchors exits before any ES call",
        exc.code == 2, str(exc.code),
    )
finally:
    sys.argv = original_argv

# --- rescue-tier mismatch is rejected rather than silently ignored ---
active_rescue_cfg = cfg()
active_rescue_cfg.session.assignment_rescue_tau = 0.60
try:
    target.analyze(inputs, active_rescue_cfg, labels)
    check("an active structural rescue tier is rejected", False)
except ValueError:
    check("an active structural rescue tier is rejected", True)

# --- band_trace attribution arithmetic (pure, no ES) ---
class _FakeAssignment:
    def __init__(self, band_checks):
        self.band_checks = band_checks


fake_assignments = [_FakeAssignment(2), _FakeAssignment(0), _FakeAssignment(1)]
fake_trace = [{"n": 0}, {"n": 1}, {"n": 2}]
slices = target._attribute_band_trace(fake_assignments, fake_trace)
check(
    "band_trace attribution slices strictly in row order by band_checks length",
    slices == [[{"n": 0}, {"n": 1}], [], [{"n": 2}]], str(slices),
)

try:
    target._attribute_band_trace([_FakeAssignment(5)], fake_trace)
    check("mismatched band_trace attribution raises", False)
except RuntimeError:
    check("mismatched band_trace attribution raises", True)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    raise SystemExit(1)
