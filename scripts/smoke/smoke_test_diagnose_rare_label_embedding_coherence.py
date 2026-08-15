#!/usr/bin/env python
from __future__ import annotations

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

import diagnose_rare_label_embedding_coherence as target  # noqa: E402


def check(name: str, condition: bool) -> None:
    if not condition:
        raise AssertionError(name)
    print(f"ok - {name}")


def make_cfg() -> SimpleNamespace:
    return SimpleNamespace(
        classification=SimpleNamespace(unclassified_is_confidential=True),
        session=SimpleNamespace(assignment_tau=0.9),
        elasticsearch=SimpleNamespace(
            indexes=SimpleNamespace(cowrie=SimpleNamespace(sessions_rollup="sessions")),
        ),
    )


def session_hit(sid: str, embedding: list[float]) -> dict:
    return {
        "_source": {
            "cowrie": {"session_id": sid},
            "dshield": {
                "cowrie": {
                    "enrichment": {
                        "session": {
                            "embedding": embedding,
                            "command_set": ["redacted"],
                        },
                    },
                },
            },
        },
        "sort": [sid],
    }


class FakeES:
    def __init__(self, hits: list[dict]):
        self.hits = hits
        self.search_calls: list[dict] = []
        self.write_calls: list[str] = []

    def search(self, index, **body):  # noqa: A002 - mirrors ES client
        self.search_calls.append({"index": index, "body": body})
        if "search_after" in body:
            return {"hits": {"hits": []}}
        return {"hits": {"hits": self.hits}}

    def index(self, *args, **kwargs):  # noqa: A003, ARG002
        self.write_calls.append("index")
        raise AssertionError("diagnostic must be read-only")

    def update(self, *args, **kwargs):  # noqa: ARG002
        self.write_calls.append("update")
        raise AssertionError("diagnostic must be read-only")

    def bulk(self, *args, **kwargs):  # noqa: ARG002
        self.write_calls.append("bulk")
        raise AssertionError("diagnostic must be read-only")


def labels_file(tmp_path: Path, labels: dict[str, str]) -> Path:
    path = tmp_path / "labels.yaml"
    path.write_text(
        yaml.safe_dump({
            sid: {"annotated": True, "playbook_label": label}
            for sid, label in labels.items()
        }),
    )
    return path


cfg = make_cfg()
hits = [
    session_hit("tight-1", [1.0, 0.0, 0.0]),
    session_hit("tight-2", [0.99, 0.01, 0.0]),
    session_hit("spread-1", [1.0, 0.0, 0.0]),
    session_hit("spread-2", [0.0, 1.0, 0.0]),
    session_hit("single-1", [0.0, 0.0, 1.0]),
    session_hit("ambiguous-row", [0.0, 1.0, 1.0]),
    session_hit("ambiguous-row", [0.0, 1.0, 1.0]),
]
es = FakeES(hits)
inputs = target.load_public_inputs(es, cfg)
labels = {
    "tight-1": "inband_payload_drop",
    "tight-2": "inband_payload_drop",
    "spread-1": "scp_upload",
    "spread-2": "scp_upload",
    "single-1": "account_backdoor_persistence",
    "missing": "scp_upload",
    "ambiguous-row": "inband_payload_drop",
}
report = target.analyze(inputs, labels, assignment_tau=cfg.session.assignment_tau)

tight = report["target_labels"]["inband_payload_drop"]
spread = report["target_labels"]["scp_upload"]
single = report["target_labels"]["account_backdoor_persistence"]

check("tight target label reports high coherence", tight["verdict"] == "embedding_coherent")
check(
    "spread target label reports low coherence",
    spread["verdict"] == "not_coherent_enough_for_clustering_only_fix",
)
check("singleton target label reports insufficient pairs", single["verdict"] == "insufficient_pairs")
check("pair counts are pairwise combinations", tight["pair_count"] == 1 and spread["pair_count"] == 1)
check("cosine stats are aggregate only", tight["cosine"]["min"] > 0.99 and spread["cosine"]["max"] == 0.0)
check(
    "absent and duplicate joins are counted by named reason",
    report["labels"]["unresolved"] == {
        "unresolved_absent_from_public_window": 1,
        "unresolved_duplicate_session_id_in_window": 1,
    },
)
explicit_public = {"term": {target.CLASSIFICATION_KEYWORD: target.PUBLIC}}
check(
    "every cowrie session query carries the explicit public-only filter",
    es.search_calls
    and all(explicit_public in call["body"]["query"]["bool"]["filter"] for call in es.search_calls),
)
check("diagnostic did not write to Elasticsearch", es.write_calls == [])
rendered_json = json.dumps(report, sort_keys=True)
rendered_text = target.summarize(report)
for forbidden in (
    "tight-1",
    "tight-2",
    "spread-1",
    "spread-2",
    "single-1",
    "missing",
    "ambiguous-row",
    "cowrie.session_id",
    "redacted",
):
    check(f"aggregate output omits {forbidden}", forbidden not in rendered_json and forbidden not in rendered_text)

for bad_hits, expected in [
    ([session_hit("bad", [1.0, float("nan")])], "finite"),
    ([session_hit("bad", [])], "empty"),
    ([session_hit("good", [1.0, 0.0]), session_hit("bad", [])], "empty"),
    ([session_hit("bad", ["not-a-number", 0.0])], "numeric vectors"),
    ([session_hit("bad-1", [1.0]), session_hit("bad-2", [1.0, 0.0])], "consistent"),
    ([session_hit("bad", [0.0, 0.0])], "zero vectors"),
]:
    try:
        target.load_public_inputs(FakeES(bad_hits), cfg)
    except ValueError as exc:
        check(f"invalid embeddings fail cleanly: {expected}", expected in str(exc))
    else:
        raise AssertionError(f"invalid embeddings did not fail: {expected}")

try:
    target.analyze(
        target.RareLabelInputs(
            embeddings=np.asarray([[1.0, 0.0]], dtype=np.float32),
            session_ids=["other"],
        ),
        {"missing": "scp_upload"},
        assignment_tau=cfg.session.assignment_tau,
    )
except ValueError as exc:
    check("no resolved target-label embeddings fails cleanly", "no target-label embeddings" in str(exc))
else:
    raise AssertionError("no resolved target labels should fail")

with tempfile.TemporaryDirectory() as tmp:
    malformed = Path(tmp) / "labels.yaml"
    malformed.write_text(yaml.safe_dump(["not", "a", "mapping"]))
    try:
        target.load_scorable_labels(malformed)
    except ValueError as exc:
        check("non-mapping label YAML fails cleanly", "must be a mapping" in str(exc))
    else:
        raise AssertionError("non-mapping label YAML should fail")

near_tau = 0.89996
near_tau_inputs = target.RareLabelInputs(
    embeddings=np.asarray([
        [1.0, 0.0],
        [near_tau, float(np.sqrt(1.0 - near_tau**2))],
    ], dtype=np.float32),
    session_ids=["near-1", "near-2"],
)
near_tau_report = target.analyze(
    near_tau_inputs,
    {"near-1": "scp_upload", "near-2": "scp_upload"},
    assignment_tau=0.9,
)
near_tau_detail = near_tau_report["target_labels"]["scp_upload"]
check("reported cosine is rounded for display", near_tau_detail["cosine"]["min"] == 0.9)
check(
    "verdict uses raw cosine rather than rounded display value",
    near_tau_detail["verdict"] == "not_coherent_enough_for_clustering_only_fix",
)
