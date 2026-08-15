"""ROADMAP P1 — `run_layer_clustering` scores per-doc novelty against the
reference centroid set when one is available, falling back to this-run's
centroids when absent / stale / disabled.

Strategy: feed synthetic embeddings clustered tightly in two groups, plus a
pre-baked reference whose centroids point in the OPPOSITE direction.

  - With reference active: per-doc novelty ≈ 1.0 (rows are orthogonal/opposite
    to the reference centroids).
  - With `use_reference=False`: per-doc novelty ≈ 0.0 (rows are at their own
    cluster centers, scored against in-run centroids).
  - With no reference present + `use_reference=True`: auto-bootstrap path —
    scores ≈ 0.0 (this run becomes the new reference) AND a reference doc set
    is written with generation=1.
  - With a reference whose `scalar_weight` doesn't match the current run:
    fallback to in-run scoring + `reference_status = stale_scalar_weight_mismatch`.

Standalone — uses real numpy + sklearn HDBSCAN, stubs ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_clustering_with_reference.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np

from enrich import clustering

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# -----------------------------------------------------------------------------
# Synthetic corpus: two clusters of 3 docs each, each cluster tight around a
# unit vector. Embedding dim = 4.
# -----------------------------------------------------------------------------
EMB_DIM = 4

CLUSTER_A_DIR = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
CLUSTER_B_DIR = np.array([0.0, 1.0, 0.0, 0.0], dtype=np.float32)

JITTER = 0.01


def _make_doc_iter():
    rng = np.random.default_rng(seed=42)
    docs = []
    for i in range(3):
        v = CLUSTER_A_DIR + rng.normal(0, JITTER, size=EMB_DIM).astype(np.float32)
        docs.append((f"doc_a_{i}", v.tolist(), f"label_a_{i}", {"f": 0.5}))
    for i in range(3):
        v = CLUSTER_B_DIR + rng.normal(0, JITTER, size=EMB_DIM).astype(np.float32)
        docs.append((f"doc_b_{i}", v.tolist(), f"label_b_{i}", {"f": 0.5}))
    return iter(docs)


# Reference centroids that point in the OPPOSITE direction → high novelty.
REF_CENTROIDS_OPPOSITE = [
    [-1.0, 0.0, 0.0, 0.0],
    [0.0, -1.0, 0.0, 0.0],
]


def _zero_scalar_block(scalars_list, weight):
    """No-op scalar block so the augmented space == pure space (weight=0)."""
    return np.zeros((len(scalars_list), 0), dtype=np.float32)


class _StubIndices:
    def __init__(self, *, exists: bool = True):
        self.exists_val = exists
        self.refreshed: list[str] = []

    def exists(self, *, index: str) -> bool:
        return self.exists_val

    def refresh(self, *, index: str):
        self.refreshed.append(index)
        return {}


class _StubES:
    """Routes searches by doc_type and records all activity."""

    def __init__(self, *, ref_payload: dict | None = None, exists: bool = True):
        self.indices = _StubIndices(exists=exists)
        self.ref_payload = ref_payload  # if None: no ref docs present
        self.calls: list[dict] = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        q = kwargs.get("query") or {}
        # Detect reference_centroid searches.
        if _query_doctype(q) == "reference_centroid":
            if self.ref_payload is None:
                return {"hits": {"hits": []}}
            sort = kwargs.get("sort") or []
            is_gen_lookup = any(
                isinstance(s, dict) and "reference_generation" in s for s in sort
            )
            if is_gen_lookup:
                return {"hits": {"hits": [
                    {"_source": {"reference_generation": self.ref_payload["generation"]}}
                ]}}
            return {"hits": {"hits": [
                {"_source": doc} for doc in self.ref_payload["docs"]
            ]}}
        return {"hits": {"hits": []}}


def _query_doctype(q):
    if isinstance(q, dict):
        if q.get("term", {}).get("doc_type"):
            return q["term"]["doc_type"]
        for v in q.values():
            r = _query_doctype(v)
            if r:
                return r
    if isinstance(q, list):
        for v in q:
            r = _query_doctype(v)
            if r:
                return r
    return None


# Monkey-patch ES-side writes to capture rather than hit a real cluster.
_CAPTURED_BULK: list[tuple[str, list[dict]]] = []


def _stub_bulk_write(es, index, actions):
    _CAPTURED_BULK.append((index, list(actions)))
    return len(actions), []


def _stub_init_index(es, mapping_path, index_name):
    return {"created": False, "stub": True}


clustering.bulk_write = _stub_bulk_write
clustering.init_index = _stub_init_index


def _per_doc_scores(bulk_actions: list[tuple[str, list[dict]]], docs_index: str) -> list[float]:
    """Pull novelty_score values from the captured doc-update bulk actions."""
    scores = []
    for idx, actions in bulk_actions:
        if idx != docs_index:
            continue
        for a in actions:
            params = (a.get("script") or {}).get("params") or {}
            if "novelty_score" in params:
                scores.append(params["novelty_score"])
    return scores


def _captured_reference_docs() -> list[dict]:
    """Pull all reference_centroid index actions from the captured bulk."""
    out = []
    for _idx, actions in _CAPTURED_BULK:
        for a in actions:
            src = a.get("_source") or {}
            if src.get("doc_type") == "reference_centroid":
                out.append(src)
    return out


def _reset_bulk():
    _CAPTURED_BULK.clear()


# -----------------------------------------------------------------------------
# [1] Reference present + valid → per-doc scores reflect REF geometry (high).
# -----------------------------------------------------------------------------
print("\n[1] reference present + valid → high novelty (scored against opposite centroids)")
_reset_bulk()
es = _StubES(ref_payload={
    "generation": 5,
    "docs": [
        {
            "centroid": c,
            "embedding_dims": EMB_DIM,
            "scalar_weight": 0.0,
            "reference_minted_at": "2026-01-01T00:00:00+00:00",
        }
        for c in REF_CENTROIDS_OPPOSITE
    ],
})
stats = clustering.run_layer_clustering(
    es=es,
    docs_iter=_make_doc_iter(),
    docs_index="docs-test",
    clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3,
    min_samples=2,
    scalar_weight=0.0,
    batch_size=100,
    sample_size=5,
    centroid_sample_field="sample_x",
    dry_run=False,
    layer_label="test.layer",
)
scores = _per_doc_scores(_CAPTURED_BULK, "docs-test")
check("reference_status == 'active'", stats["reference_status"] == "active", f"got {stats['reference_status']}")
check("reference_generation == 5", stats["reference_generation"] == 5, f"got {stats['reference_generation']}")
check("got 6 per-doc scores", len(scores) == 6, f"got {len(scores)}")
check(
    "all scores >= 0.9 (rows are opposite-to-reference)",
    all(s >= 0.9 for s in scores),
    f"got {scores}",
)


# -----------------------------------------------------------------------------
# [2] use_reference=False → in-run scoring; scores ≈ 0 (rows at cluster centers).
# -----------------------------------------------------------------------------
print("\n[2] use_reference=False → in-run scoring; low novelty")
_reset_bulk()
es = _StubES(ref_payload={
    "generation": 5,
    "docs": [
        {
            "centroid": c,
            "embedding_dims": EMB_DIM,
            "scalar_weight": 0.0,
            "reference_minted_at": "2026-01-01T00:00:00+00:00",
        }
        for c in REF_CENTROIDS_OPPOSITE
    ],
})
stats = clustering.run_layer_clustering(
    es=es,
    docs_iter=_make_doc_iter(),
    docs_index="docs-test",
    clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3,
    min_samples=2,
    scalar_weight=0.0,
    batch_size=100,
    sample_size=5,
    centroid_sample_field="sample_x",
    dry_run=False,
    layer_label="test.layer",
    use_reference=False,
)
scores = _per_doc_scores(_CAPTURED_BULK, "docs-test")
check("reference_status == 'disabled'", stats["reference_status"] == "disabled", f"got {stats['reference_status']}")
check(
    "all scores < 0.05 (rows at cluster centers, scored in-run)",
    all(s < 0.05 for s in scores),
    f"got {scores}",
)
check(
    "no reference_centroid docs written",
    _captured_reference_docs() == [],
    f"got {len(_captured_reference_docs())} ref docs",
)


# -----------------------------------------------------------------------------
# [3] No reference present + use_reference=True → bootstrap. Writes ref gen=1,
# scores against this run (≈ 0).
# -----------------------------------------------------------------------------
print("\n[3] no reference present → bootstrap: writes gen=1 + scores in-run")
_reset_bulk()
es = _StubES(ref_payload=None)
stats = clustering.run_layer_clustering(
    es=es,
    docs_iter=_make_doc_iter(),
    docs_index="docs-test",
    clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3,
    min_samples=2,
    scalar_weight=0.0,
    batch_size=100,
    sample_size=5,
    centroid_sample_field="sample_x",
    dry_run=False,
    layer_label="test.layer",
)
scores = _per_doc_scores(_CAPTURED_BULK, "docs-test")
ref_docs = _captured_reference_docs()
check("reference_status == 'bootstrap'", stats["reference_status"] == "bootstrap", f"got {stats['reference_status']}")
check("reference_generation == 1 (first bootstrap)", stats["reference_generation"] == 1, f"got {stats['reference_generation']}")
check("2 reference_centroid docs written", len(ref_docs) == 2, f"got {len(ref_docs)}")
check(
    "all reference docs carry source_run_id == run_id",
    all(d.get("source_run_id") == stats["run_id"] for d in ref_docs),
)
check(
    "all bootstrap scores < 0.05 (this run == new reference)",
    all(s < 0.05 for s in scores),
    f"got {scores}",
)


# -----------------------------------------------------------------------------
# [4] Reference present but scalar_weight mismatch → stale fallback.
# -----------------------------------------------------------------------------
print("\n[4] reference with mismatched scalar_weight → stale fallback")
_reset_bulk()


def _unit_scalar_block(scalars_list, weight):
    """Augmented dim = pure dim + 1. Adds a constant column for the test."""
    n = len(scalars_list)
    return np.full((n, 1), float(weight), dtype=np.float32)


es = _StubES(ref_payload={
    "generation": 9,
    "docs": [
        {
            "centroid": c,
            "centroid_augmented": [*c, 0.0],
            "embedding_dims": EMB_DIM,
            "augmented_dims": EMB_DIM + 1,
            "scalar_weight": 0.99,  # WRONG — current run will use 0.05
            "reference_minted_at": "2026-01-01T00:00:00+00:00",
        }
        for c in REF_CENTROIDS_OPPOSITE
    ],
})
stats = clustering.run_layer_clustering(
    es=es,
    docs_iter=_make_doc_iter(),
    docs_index="docs-test",
    clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_unit_scalar_block,
    min_cluster_size=3,
    min_samples=2,
    scalar_weight=0.05,  # mismatch vs ref's 0.99
    batch_size=100,
    sample_size=5,
    centroid_sample_field="sample_x",
    dry_run=False,
    layer_label="test.layer",
)
scores = _per_doc_scores(_CAPTURED_BULK, "docs-test")
check(
    "reference_status starts with 'stale_'",
    str(stats["reference_status"]).startswith("stale_"),
    f"got {stats['reference_status']}",
)
check(
    "stale → no new reference docs written (history preserved)",
    _captured_reference_docs() == [],
    f"got {len(_captured_reference_docs())} ref docs",
)
check(
    "stale → fell back to in-run scoring (low scores)",
    all(s < 0.1 for s in scores),
    f"got {scores}",
)


# -----------------------------------------------------------------------------
# [5] refresh_reference=True → writes new gen, scores against this run (≈ 0).
# Existing ref gen=5 should be incremented to 6.
# -----------------------------------------------------------------------------
print("\n[5] refresh_reference=True → bumps generation, scores in-run")
_reset_bulk()
es = _StubES(ref_payload={
    "generation": 5,
    "docs": [
        {
            "centroid": c,
            "embedding_dims": EMB_DIM,
            "scalar_weight": 0.0,
            "reference_minted_at": "2026-01-01T00:00:00+00:00",
        }
        for c in REF_CENTROIDS_OPPOSITE
    ],
})
stats = clustering.run_layer_clustering(
    es=es,
    docs_iter=_make_doc_iter(),
    docs_index="docs-test",
    clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3,
    min_samples=2,
    scalar_weight=0.0,
    batch_size=100,
    sample_size=5,
    centroid_sample_field="sample_x",
    dry_run=False,
    layer_label="test.layer",
    refresh_reference=True,
)
scores = _per_doc_scores(_CAPTURED_BULK, "docs-test")
ref_docs = _captured_reference_docs()
check("reference_status == 'refreshed'", stats["reference_status"] == "refreshed", f"got {stats['reference_status']}")
check("new generation == 6 (5 + 1)", stats["reference_generation"] == 6, f"got {stats['reference_generation']}")
check("ref docs written", len(ref_docs) == 2, f"got {len(ref_docs)}")
check(
    "ref docs carry reference_generation == 6",
    all(d.get("reference_generation") == 6 for d in ref_docs),
)
check(
    "refresh scores < 0.05 (this run == new reference)",
    all(s < 0.05 for s in scores),
    f"got {scores}",
)


# -----------------------------------------------------------------------------
# [6] reference_source filter — load + bootstrap pathways are per-source.
# Brutal-review phase 5.4.
# -----------------------------------------------------------------------------
print("\n[6] reference_source filter — load and bootstrap pathways are per-source")


class _SourceAwareES(_StubES):
    """Records every search query so we can verify the source filter
    travels through both the gen-lookup and centroid-fetch queries."""
    def __init__(self):
        super().__init__(ref_payload=None)
        self.last_must: list[dict] = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        q = kwargs.get("query") or {}
        if _query_doctype(q) == "reference_centroid":
            # Capture the `must` list so we can assert on the source filter
            # added in 5.4. ES nests reference_centroid under
            # bool.must[*].term.doc_type, and the per-source filter lives
            # alongside it as another must clause.
            must = (q.get("bool") or {}).get("must") or []
            self.last_must = must
        return {"hits": {"hits": []}}


# (a) load with reference_source=None: query must require ABSENCE of the field.
src_es = _SourceAwareES()
out = clustering.load_reference_centroids(src_es, "clusters-test")
check("load with source=None returns empty when no docs", out == {})
joined = json.dumps(src_es.last_must)
check(
    "load with source=None uses must_not exists filter on reference_source",
    '"must_not"' in joined and '"reference_source"' in joined,
    joined,
)

# (b) load with explicit external source uses term filter on .keyword.
src_es2 = _SourceAwareES()
clustering.load_reference_centroids(src_es2, "clusters-test", reference_source="external")
joined2 = json.dumps(src_es2.last_must)
check(
    "load with source='external' uses term filter on reference_source.keyword",
    '"reference_source.keyword"' in joined2 and '"external"' in joined2,
    joined2,
)

# (c) bootstrap_reference_now + reference_source stamps the field on each
# new reference centroid doc AND uses per-source max-gen.
_reset_bulk()
src_es3 = _SourceAwareES()
clustering.run_layer_clustering(
    es=src_es3,
    docs_iter=_make_doc_iter(),
    docs_index="docs-test",
    clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3,
    min_samples=2,
    scalar_weight=0.0,
    batch_size=100,
    sample_size=5,
    centroid_sample_field="sample_x",
    dry_run=False,
    layer_label="test.layer.external",
    use_reference=False,
    bootstrap_reference_now=True,
    reference_source="external",
)
ref_docs = _captured_reference_docs()
check(
    "external bootstrap writes reference centroid docs",
    len(ref_docs) >= 1, f"got {len(ref_docs)}",
)
check(
    "every external ref doc carries reference_source='external'",
    all(d.get("reference_source") == "external" for d in ref_docs),
    f"got: {[d.get('reference_source') for d in ref_docs]}",
)
check(
    "prev-gen lookup for external bootstrap filters by reference_source.keyword",
    '"reference_source.keyword"' in json.dumps(src_es3.last_must)
    and '"external"' in json.dumps(src_es3.last_must),
    json.dumps(src_es3.last_must),
)


# -----------------------------------------------------------------------------
# [7] Dual novelty — when an external ref exists, per-doc params carry
# both `novelty_score` and `novelty_score_external`. Without external ref,
# only `novelty_score` is emitted (the painless script's containsKey
# guard keeps the field absent from the doc).
# Brutal-review phase 5.5.
# -----------------------------------------------------------------------------
print("\n[7] dual novelty — novelty_score_external is conditional")


def _query_must_filters(q):
    """Walk a query dict and return the list of clauses under bool.must."""
    if not isinstance(q, dict):
        return []
    if "bool" in q and isinstance(q["bool"], dict):
        return q["bool"].get("must") or []
    return []


def _query_reference_source(q):
    """Inspect a reference_centroid query and infer which source it's
    targeting: ``__in_corpus__`` for the must_not-exists filter, or the
    string value of a term filter on `reference_source.keyword`."""
    for clause in _query_must_filters(q):
        if not isinstance(clause, dict):
            continue
        # term filter on reference_source.keyword → external
        term = clause.get("term") or {}
        if "reference_source.keyword" in term:
            return term["reference_source.keyword"]
        # bool.must_not exists on reference_source → in-corpus
        inner_bool = clause.get("bool") or {}
        must_not = inner_bool.get("must_not") or []
        if isinstance(must_not, dict):
            must_not = [must_not]
        for mn in must_not:
            if (isinstance(mn, dict) and "exists" in mn
                    and mn["exists"].get("field") == "reference_source"):
                return "__in_corpus__"
    return None


class _DualRefES(_StubES):
    """Returns separate ref payloads for the in-corpus vs external sources.
    `in_corpus_payload` / `external_payload` are the same shape as
    `_StubES.ref_payload` (dict with `generation` + `docs`)."""
    def __init__(self, *, in_corpus_payload=None, external_payload=None):
        super().__init__(ref_payload=None)
        self.in_corpus_payload = in_corpus_payload
        self.external_payload = external_payload

    def search(self, **kwargs):
        self.calls.append(kwargs)
        q = kwargs.get("query") or {}
        if _query_doctype(q) != "reference_centroid":
            return {"hits": {"hits": []}}
        which = _query_reference_source(q)
        payload = (
            self.in_corpus_payload if which == "__in_corpus__"
            else self.external_payload if which == "external"
            else None
        )
        if payload is None:
            return {"hits": {"hits": []}}
        sort = kwargs.get("sort") or []
        is_gen_lookup = any(
            isinstance(s, dict) and "reference_generation" in s for s in sort
        )
        if is_gen_lookup:
            return {"hits": {"hits": [
                {"_source": {"reference_generation": payload["generation"]}}
            ]}}
        return {"hits": {"hits": [
            {"_source": doc} for doc in payload["docs"]
        ]}}


def _per_doc_params(bulk_actions, docs_index):
    """Pull the full params dict for each per-doc update action."""
    out = []
    for idx, actions in bulk_actions:
        if idx != docs_index:
            continue
        for a in actions:
            params = (a.get("script") or {}).get("params") or {}
            if "novelty_score" in params:
                out.append(params)
    return out


def _ref_doc(centroid, gen=1):
    return {
        "centroid":            centroid,
        "centroid_augmented":  centroid + [0.0] * 0,  # no scalar block in tests
        "source_run_id":       "test-run",
        "embedding_dims":      len(centroid),
        "augmented_dims":      len(centroid),
        "scalar_weight":       0.0,
        "reference_minted_at": "2026-05-31T00:00:00+00:00",
        "reference_generation": gen,
    }


# (a) Only in-corpus ref present → novelty_score populated,
#     novelty_score_external absent.
_reset_bulk()
in_corpus = {
    "generation": 1,
    "docs": [_ref_doc(c, gen=1) for c in REF_CENTROIDS_OPPOSITE],
}
es_a = _DualRefES(in_corpus_payload=in_corpus, external_payload=None)
clustering.run_layer_clustering(
    es=es_a, docs_iter=_make_doc_iter(),
    docs_index="docs-test", clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3, min_samples=2, scalar_weight=0.0,
    batch_size=100, sample_size=5, centroid_sample_field="sample_x",
    dry_run=False, layer_label="test.no_external",
)
params_a = _per_doc_params(_CAPTURED_BULK, "docs-test")
check("in-corpus only: novelty_score populated on every doc",
      all("novelty_score" in p for p in params_a))
check("in-corpus only: novelty_score_external is ABSENT from params",
      all("novelty_score_external" not in p for p in params_a))

# (b) BOTH refs present → both fields populated, scored against
#     different geometries (in-corpus ref points opposite to docs;
#     external ref points SAME direction as cluster A).
_reset_bulk()
external = {
    "generation": 1,
    "docs": [_ref_doc(CLUSTER_A_DIR.tolist(), gen=1)],
}
es_b = _DualRefES(in_corpus_payload=in_corpus, external_payload=external)
clustering.run_layer_clustering(
    es=es_b, docs_iter=_make_doc_iter(),
    docs_index="docs-test", clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3, min_samples=2, scalar_weight=0.0,
    batch_size=100, sample_size=5, centroid_sample_field="sample_x",
    dry_run=False, layer_label="test.both_refs",
)
params_b = _per_doc_params(_CAPTURED_BULK, "docs-test")
check("dual ref: every non-outlier carries novelty_score_external",
      all("novelty_score_external" in p for p in params_b if not p.get("is_outlier")))
# In-corpus ref points OPPOSITE to docs → novelty_score is HIGH (~1.0)
# External ref points SAME direction as cluster A → novelty_score_external
# is LOW (~0) for cluster A docs.
in_corpus_scores = [p["novelty_score"] for p in params_b if not p.get("is_outlier")]
external_scores = [
    p["novelty_score_external"] for p in params_b
    if not p.get("is_outlier") and "novelty_score_external" in p
]
check("dual ref: in-corpus scores high (ref points opposite)",
      all(s > 0.5 for s in in_corpus_scores),
      f"in-corpus scores={in_corpus_scores}")
# Some external scores will be low (cluster A) some not (cluster B).
# At least one should be substantially LOWER than its in-corpus pair —
# verifying the two scores come from different geometries.
paired = [(p["novelty_score"], p.get("novelty_score_external")) for p in params_b
          if not p.get("is_outlier") and "novelty_score_external" in p]
diffs = [a - b for a, b in paired]
check("dual ref: at least one external score < its in-corpus score",
      any(d > 0.3 for d in diffs),
      f"diffs (in-corpus - external) = {diffs}")

# (c) External ref shape mismatch → fall back gracefully.
_reset_bulk()
external_bad = {
    "generation": 1,
    # wrong dims (3 instead of 4) — _validate_reference should flag this.
    "docs": [_ref_doc([1.0, 0.0, 0.0], gen=1)],
}
es_c = _DualRefES(in_corpus_payload=in_corpus, external_payload=external_bad)
stats_c = clustering.run_layer_clustering(
    es=es_c, docs_iter=_make_doc_iter(),
    docs_index="docs-test", clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3, min_samples=2, scalar_weight=0.0,
    batch_size=100, sample_size=5, centroid_sample_field="sample_x",
    dry_run=False, layer_label="test.bad_external",
)
check("external dim mismatch: reference_external_status starts with 'stale_'",
      str(stats_c.get("reference_external_status", "")).startswith("stale_"),
      stats_c.get("reference_external_status"))
params_c = _per_doc_params(_CAPTURED_BULK, "docs-test")
check("external dim mismatch: novelty_score_external omitted",
      all("novelty_score_external" not in p for p in params_c))


# -----------------------------------------------------------------------------
# [8] External-match attribution — brutal-review phase 5.9. Alongside
# the dual novelty score (5.5), every non-outlier doc emits the closest
# external centroid id + raw cosine similarity. Outliers carry no
# match (don't claim any centroid).
# -----------------------------------------------------------------------------
print("\n[8] external-match attribution — id + cosine")

_reset_bulk()
# External centroid at the SAME direction as cluster A — docs in cluster A
# should match it with cosine ≈ 1.0.
external_match_payload = {
    "generation": 1,
    "docs": [_ref_doc(CLUSTER_A_DIR.tolist(), gen=1)],
}
es_m = _DualRefES(in_corpus_payload=in_corpus, external_payload=external_match_payload)
clustering.run_layer_clustering(
    es=es_m, docs_iter=_make_doc_iter(),
    docs_index="docs-test", clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3, min_samples=2, scalar_weight=0.0,
    batch_size=100, sample_size=5, centroid_sample_field="sample_x",
    dry_run=False, layer_label="test.external_match",
)
params_m = _per_doc_params(_CAPTURED_BULK, "docs-test")
nonoutlier_params = [p for p in params_m if not p.get("is_outlier")]
check("external match: every non-outlier carries external_match_id",
      all("external_match_id" in p for p in nonoutlier_params),
      f"missing on {[p for p in nonoutlier_params if 'external_match_id' not in p]}")
check("external match: every non-outlier carries external_match_cosine",
      all("external_match_cosine" in p for p in nonoutlier_params))
check("external match: id format is 'cluster_<idx>'",
      all(str(p["external_match_id"]).startswith("cluster_") for p in nonoutlier_params))
# There's only one external centroid here (in CLUSTER_A's direction),
# so every doc matches `cluster_0`. The cosines split: cluster_A docs
# match closely (~1.0), cluster_B docs match weakly (~0). The
# attribution tells the analyst WHICH external centroid is the closest,
# regardless of how close — the cosine is the confidence.
all_cosines = sorted(
    (p["external_match_cosine"] for p in nonoutlier_params), reverse=True,
)
high_cosines = [c for c in all_cosines if c > 0.9]
low_cosines  = [c for c in all_cosines if c < 0.1]
check("external match: split between high cosines (cluster_A matches) and "
      "low cosines (cluster_B docs against the only available centroid)",
      len(high_cosines) >= 3 and len(low_cosines) >= 3,
      f"got cosines={all_cosines}")
check("external match: all docs attributed to the same centroid id "
      "(only one external centroid exists)",
      len({p["external_match_id"] for p in nonoutlier_params}) == 1,
      f"got ids={[p['external_match_id'] for p in nonoutlier_params]}")

# When NO external ref is loaded: no external_match_id / external_match_cosine.
_reset_bulk()
es_no_ext = _DualRefES(in_corpus_payload=in_corpus, external_payload=None)
clustering.run_layer_clustering(
    es=es_no_ext, docs_iter=_make_doc_iter(),
    docs_index="docs-test", clusters_index="clusters-test",
    mapping_path="/dev/null",
    update_script="ctx._source.novelty_score = params.novelty_score",
    scalar_block_builder=_zero_scalar_block,
    min_cluster_size=3, min_samples=2, scalar_weight=0.0,
    batch_size=100, sample_size=5, centroid_sample_field="sample_x",
    dry_run=False, layer_label="test.no_external_match",
)
params_no = _per_doc_params(_CAPTURED_BULK, "docs-test")
check("no external ref: external_match_id absent from every param",
      all("external_match_id" not in p for p in params_no))
check("no external ref: external_match_cosine absent from every param",
      all("external_match_cosine" not in p for p in params_no))


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
