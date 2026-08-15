"""Offline contract tests for scripts/eval_novel_pool.py."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import eval_novel_pool as target  # noqa: E402
from enrich.classification import releasable_filter  # noqa: E402

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
            clustering_mode="hdbscan",
            assignment_tau=0.94,
            assignment_confident_tau=0.98,
            assignment_tfidf_tau=0.80,
            assignment_rescue_tau=0.94,
            cluster_min_cluster_size=3,
            cluster_min_samples=2,
            cluster_scalar_weight=0.0,
            cluster_svd_dim=0,
            playbook_merge_threshold=0.96,
        ),
        worker=SimpleNamespace(cluster_n_jobs=1),
        elasticsearch=SimpleNamespace(indexes=SimpleNamespace(cowrie=SimpleNamespace(
            sessions_rollup="sessions",
            commands="commands",
            playbook_anchors="anchors",
        ))),
    )


def hit(doc_id, source, order):
    return {"_id": doc_id, "_source": source, "sort": [order]}


def session_source(embedding, command_set, **extra):
    session = {"embedding": embedding, "command_set": command_set, **extra}
    return {"dshield": {"cowrie": {"enrichment": {"session": session}}}}


class MockES:
    def __init__(self):
        self.queries: list[tuple[str, dict]] = []
        self.write_calls = 0
        self.window = [
            hit("secret-id-1", session_source(
                [1.0, 0.0], ["secret-hash-1"], command_count=2, unique_commands=1,
            ), 0),
            hit("secret-id-2", session_source(
                [0.0, 1.0], ["secret-hash-2"], command_count=4, unique_commands=2,
            ), 1),
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
                hit("anchor-doc", {"playbook_id": "A", "anchor_centroid": [1.0, 0.0]}, 0),
            ]}}
        filters = body["query"]["bool"]["filter"]
        if index == "commands":
            rows = [
                hit(
                    "secret-hash-1",
                    {"dshield": {"cowrie": {"enrichment": {"cluster": {
                        "id": "command-cluster-1", "is_outlier": False,
                    }}}}},
                    0,
                ),
            ]
            return {"hits": {"hits": self._page(rows, body)}}
        if any(target._PB in clause.get("term", {}) for clause in filters):
            rows = [
                hit(f"a{i}", session_source(None, [f"secret-hash-{i % 2 + 1}"]), i)
                for i in range(3)
            ]
            return {"hits": {"hits": self._page(rows, body)}}
        return {"hits": {"hits": self._page(self.window, body)}}

    def bulk(self, *args, **kwargs):
        self.write_calls += 1
        raise AssertionError("write API called")

    def update(self, *args, **kwargs):
        self.write_calls += 1
        raise AssertionError("write API called")


mock = MockES()
loaded = target.load_public_inputs(mock, cfg(), per_anchor=3)
public_clause = releasable_filter(cfg())
cowrie_queries = [body for index, body in mock.queries if index in {"sessions", "commands"}]
check(
    "every cowrie session/command query carries exact public filter",
    cowrie_queries
    and all(public_clause in body["query"]["bool"]["filter"] for body in cowrie_queries),
    str(cowrie_queries),
)
check("loader performs no writes", mock.write_calls == 0)
check(
    "session embeddings, bags, and scalars remain index-aligned",
    loaded.embeddings.shape[0] == len(loaded.command_bags) == len(loaded.scalars) == 2,
)
check("public command taxonomy cardinality is reported", loaded.command_taxonomy_size == 1)

fail_open_cfg = cfg()
fail_open_cfg.classification.unclassified_is_confidential = False
fail_open_mock = MockES()
target.load_public_inputs(fail_open_mock, fail_open_cfg, per_anchor=3)
explicit_public = {"term": {target.CLASSIFICATION_KEYWORD: target.PUBLIC}}
check(
    "diagnostic remains explicitly public under a fail-open deployment posture",
    all(
        explicit_public in body["query"]["bool"]["filter"]
        for index, body in fail_open_mock.queries
        if index in {"sessions", "commands"}
    ),
)


class EmptyCommandTaxonomyES(MockES):
    def search(self, index, **body):
        if index == "commands":
            self.queries.append((index, body))
            return {"hits": {"hits": []}}
        return super().search(index, **body)


try:
    target.load_public_inputs(EmptyCommandTaxonomyES(), cfg(), per_anchor=3)
    check("empty public command taxonomy is rejected", False)
except ValueError as exc:
    check("empty public command taxonomy is rejected", "taxonomy is empty" in str(exc), str(exc))

for bad, message in [
    ((0.94, 0.94), "duplicate"),
    ((float("nan"), 0.94), "finite"),
    ((-0.1, 0.94), "within"),
    ((0.90, 0.92), "deployed"),
]:
    try:
        target.validate_taus(bad, deployed_tau=0.94, confident_tau=0.98)
        check(f"invalid τ grid rejected ({message})", False)
    except ValueError:
        check(f"invalid τ grid rejected ({message})", True)


def synthetic_inputs():
    angles = np.linspace(0.0, 1.1, 18)
    embeddings = np.asarray(
        [[np.cos(angle), np.sin(angle)] for angle in angles], dtype=np.float32,
    )
    return target.NovelPoolInputs(
        embeddings=embeddings,
        command_bags=["cluster_empty"] * len(embeddings),
        scalars=[{
            "command_count": 1,
            "unique_commands": 1,
            "login_success_rate": 0.0,
            "mean_novelty_score": 0.0,
        }] * len(embeddings),
        anchor_embeddings=np.asarray([[1.0, 0.0]], dtype=np.float32),
        anchor_ids=["A"],
        anchor_bags=[],
        anchor_bag_ids=[],
        command_taxonomy_size=1,
    )


report = target.analyze(synthetic_inputs(), cfg(), (0.88, 0.94, 0.98))
rows = report["rows"]
assigned = [row["assigned"] for row in rows]
check("deployed τ row is present", sum(row["deployed"] for row in rows) == 1)
check(
    "aggregate report states the mixed-derived anchor boundary",
    report["session_classification"] == "public_only"
    and report["command_taxonomy_classification"] == "public_only"
    and report["anchor_provenance"] == "pinned_mixed_classification_derived_aggregates",
)
check("every assignment row sums to the same corpus", all(
    row["assigned"] + row["novel"] == report["n_sessions"] for row in rows
))
check("lowering τ cannot reduce assigned count", assigned == sorted(assigned, reverse=True))
check("band counters are complete", all(
    row["band_checks"] == row["band_tfidf_confirms"] + row["band_rejections"]
    and row["band_confirms"]
    == row["band_tfidf_confirms"] + row["band_no_tfidf_fallbacks"]
    for row in rows
))
check(
    "effective report includes sampled anchor bags and all replay settings",
    report["n_public_anchor_bags"] == 0
    and report["effective_config"]["assignment_rescue_tau"] == 0.94
    and report["effective_config"]["noise_rescue_threshold"] == 0.96
    and report["effective_config"]["cluster_n_jobs"] == 1,
)
loaded_report = target.analyze(loaded, cfg(), (0.94,))
rendered = str(loaded_report)
check("aggregate report redacts ids, hashes, vectors, bags, labels, and command text", all(
    secret not in rendered
    for secret in ("secret-id", "secret-hash", "anchor-doc", "embedding", "command_bags")
))

tiny = target.cluster_novel_pool(
    np.asarray([[1.0, 0.0]], dtype=np.float32),
    [{"command_count": 1, "unique_commands": 1}],
    min_cluster_size=3,
    min_samples=2,
    scalar_weight=0.0,
    rescue_threshold=0.96,
    merge_threshold=0.96,
    svd_dim=0,
    n_jobs=1,
)
check(
    "tiny novel pool skips cleanly",
    tiny["status"] == "skipped_too_few" and tiny["playbook_groups"] == 0,
    str(tiny),
)

concentrated = np.asarray([
    [1.0, 0.00], [1.0, 0.01], [1.0, -0.01],
    [-1.0, 0.00], [-1.0, 0.01], [-1.0, -0.01],
], dtype=np.float32)
shape = target.cluster_novel_pool(
    concentrated,
    [{"command_count": 1, "unique_commands": 1}] * len(concentrated),
    min_cluster_size=3,
    min_samples=2,
    scalar_weight=0.0,
    rescue_threshold=0.96,
    merge_threshold=0.96,
    svd_dim=0,
    n_jobs=1,
)
check(
    "cluster report separates raw clusters, rescue, merge, and concentration",
    shape["status"] == "clustered"
    and shape["raw_clusters"] >= shape["playbook_groups"] >= 1
    and "rescued" in shape
    and shape["top5_share"] > 0.0,
    str(shape),
)

rng = np.random.default_rng(42)
noise = rng.normal(size=(12, 2)).astype(np.float32)
noise /= np.linalg.norm(noise, axis=1, keepdims=True)
all_noise = target.cluster_novel_pool(
    noise,
    [{"command_count": 1, "unique_commands": 1}] * len(noise),
    min_cluster_size=8,
    min_samples=8,
    scalar_weight=0.0,
    rescue_threshold=0.0,
    merge_threshold=0.96,
    svd_dim=0,
    n_jobs=1,
)
check(
    "fragmented/all-noise pool reports residual outlier mass",
    all_noise["residual_outliers"] > 0 and all_noise["residual_outlier_rate"] > 0.0,
    str(all_noise),
)


class FragmentedHDBSCAN:
    def __init__(self, **_kwargs):
        pass

    def fit_predict(self, matrix):
        return np.repeat(np.arange(6), 3)[:len(matrix)]


original_hdbscan = target.HDBSCAN
target.HDBSCAN = FragmentedHDBSCAN
try:
    fragmented_vectors = np.repeat(np.eye(6, dtype=np.float32), 3, axis=0)
    fragmented = target.cluster_novel_pool(
        fragmented_vectors,
        [{"command_count": 1, "unique_commands": 1}] * len(fragmented_vectors),
        min_cluster_size=3,
        min_samples=2,
        scalar_weight=0.0,
        rescue_threshold=0.0,
        merge_threshold=1.0,
        svd_dim=0,
        n_jobs=1,
    )
finally:
    target.HDBSCAN = original_hdbscan
check(
    "fragmented pool preserves many small post-merge groups",
    fragmented["raw_clusters"] == fragmented["playbook_groups"] == 6
    and fragmented["largest_share"] < 0.2
    and fragmented["effective_groups_per_1000"] > 300,
    str(fragmented),
)

bad_geometry = synthetic_inputs()
bad_geometry.embeddings[0, 0] = np.nan
try:
    target.analyze(bad_geometry, cfg(), (0.94,))
    check("non-finite geometry is rejected", False)
except ValueError:
    check("non-finite geometry is rejected", True)

active_rescue_cfg = cfg()
active_rescue_cfg.session.assignment_rescue_tau = 0.90
try:
    target.analyze(synthetic_inputs(), active_rescue_cfg, (0.94,))
    check("active structural rescue refuses an inexact replay", False)
except ValueError:
    check("active structural rescue refuses an inexact replay", True)

bad_cfg = cfg()
bad_cfg.session.clustering_mode = "late_fusion"
try:
    target.analyze(synthetic_inputs(), bad_cfg, (0.94,))
    check("non-HDBSCAN mode is rejected", False)
except ValueError:
    check("non-HDBSCAN mode is rejected", True)


def band_row(emb_cos, tfidf_cos, confirmed):
    return {"emb_cos": emb_cos, "tfidf_cos": tfidf_cos, "confirmed": confirmed}


mixed_trace = [
    band_row(0.95, 0.10, False),
    band_row(0.96, 0.85, True),
    band_row(0.97, 0.50, True),
    band_row(0.94, 0.05, False),
]
mixed_separation = target._band_separation(mixed_trace)
check(
    "mixed band_trace splits into confirmed/rejected/overall buckets",
    mixed_separation["overall"]["n"] == 4
    and mixed_separation["confirmed"]["n"] == 2
    and mixed_separation["rejected"]["n"] == 2,
    str(mixed_separation),
)
check(
    "mixed bucket shape matches _band_diagnosis output (n/min/median/mean/max/sweep)",
    all(
        set(bucket.keys()) == {"n", "min", "median", "mean", "max", "sweep"}
        for bucket in mixed_separation.values()
    ),
    str(mixed_separation),
)

empty_separation = target._band_separation([])
check(
    "empty band_trace reports n=0 in all three buckets with no crash",
    empty_separation["overall"]["n"] == 0
    and empty_separation["confirmed"]["n"] == 0
    and empty_separation["rejected"]["n"] == 0,
    str(empty_separation),
)

all_confirmed_trace = [band_row(0.95, 0.85, True), band_row(0.96, 0.90, True)]
all_confirmed_separation = target._band_separation(all_confirmed_trace)
check(
    "all-confirmed band_trace leaves the rejected bucket at n=0",
    all_confirmed_separation["confirmed"]["n"] == 2
    and all_confirmed_separation["rejected"]["n"] == 0,
    str(all_confirmed_separation),
)

all_rejected_trace = [band_row(0.95, 0.10, False), band_row(0.96, 0.05, False)]
all_rejected_separation = target._band_separation(all_rejected_trace)
check(
    "all-rejected band_trace leaves the confirmed bucket at n=0",
    all_rejected_separation["rejected"]["n"] == 2
    and all_rejected_separation["confirmed"]["n"] == 0,
    str(all_rejected_separation),
)

deployed_rows = [row for row in rows if row["deployed"]]
non_deployed_rows = [row for row in rows if not row["deployed"]]
check(
    "exactly one row of analyze()'s output carries non-None band_tfidf_diagnosis",
    len(deployed_rows) == 1
    and deployed_rows[0]["band_tfidf_diagnosis"] is not None
    and all(row["band_tfidf_diagnosis"] is None for row in non_deployed_rows),
    str([row["band_tfidf_diagnosis"] is not None for row in rows]),
)

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    raise SystemExit(1)
