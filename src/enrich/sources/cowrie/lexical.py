"""Command-cluster-id bag — the scale-stable lexical view used as the TF-IDF
secondary signal (Exp 3 / the consolidation engine / the assignment band check).

Maps a session's `command_set` (unique command hashes) to the command-cluster ids
those commands belong to, joined into a space-separated "bag" text. The bag vocabulary
is bounded by the command-cluster count (not raw command tokens, which proliferate), so
`compute_lexical_features`' TF-IDF+SVD geometry stays stable across corpus scales.

Single source of truth for the scripts (eval) and the production assignment runner.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...clustering import compute_lexical_features
from .predicates import SUBSIGNAL_NAMES, fold_session_predicates

if TYPE_CHECKING:  # numpy is import-time-optional — see the note below
    import numpy as np

# numpy is imported INSIDE `prepare_assignment_lexical`, not at module scope, so
# importing this module stays numpy-free. `clustering.py` holds the same line, and
# `assignment.py:assign_batch` does its own function-scoped `import numpy as np`.
# It is load-bearing: `sessions.py` imports `build_session_predicate_vectors` from
# here at module scope, so `cli.py:_load_source_layer` pulls this module in for
# EVERY cowrie verb. A module-level numpy here makes numpy a hard dependency of the
# whole CLI (`ModuleNotFoundError: No module named 'numpy'` on any verb, not just
# the ones that do vector math). All annotations below are lazy strings via
# `from __future__ import annotations`, so they need no runtime numpy.

_OUTLIER_TOKEN = "cluster_outlier"   # command not in any command cluster
_EMPTY_TOKEN = "cluster_empty"       # session with no resolvable commands
_BAG_SVD_COMPONENTS = 48
_MIN_ANCHOR_BAGS = 50   # anchors with fewer sampled bags get no TF-IDF centroid (item 37);
                        # tfidf_cos(...) returns None for them, degrading to embedding-only
                        # via the same path already used when a whole snapshot has no bags.


@dataclass(frozen=True)
class LexicalAssignmentSpace:
    """One fitted production-equivalent lexical space."""

    anchor_centroids: dict[str, np.ndarray]
    window_features: np.ndarray
    available: bool


def prepare_assignment_lexical(
    anchor_bags: list[str],
    anchor_ids: list[str],
    window_bags: list[str],
    *,
    n_components: int = _BAG_SVD_COMPONENTS,
    background_bags: tuple[str, ...] = (),
) -> LexicalAssignmentSpace:
    """Fit the one TF-IDF/SVD space used by production assignment.

    Anchor centroids and window rows are aligned because the fit covers both
    sets together. Empty/degenerate geometry is represented explicitly.

    `background_bags` (default empty) is an optional extra document pool fit
    jointly ahead of the window — it pads a thin fit (e.g. the eval replay's
    committed anchor snapshot) without changing what gets scored: it is never
    part of `window_features`, and it contributes no centroid of its own.

    Per-anchor gating (item 37): an anchor whose own sampled bag count is below
    `_MIN_ANCHOR_BAGS` gets no entry in `anchor_centroids`, so
    `anchor_centroids.get(anchor_id)` naturally returns `None` for it — callers
    already treat a `None` centroid as "degrade to embedding-only" for that
    anchor (`compute_assignment_window`'s `tfidf_cos` closure).
    """
    import numpy as np  # function-scoped: keeps this module import-time numpy-free

    if len(anchor_bags) != len(anchor_ids):
        raise ValueError("anchor_bags and anchor_ids must be index-aligned")
    n_anchor = len(anchor_bags)
    n_background = len(background_bags)
    features = compute_lexical_features(
        anchor_bags + list(background_bags) + window_bags, n_components=n_components,
    )
    available = features.shape[1] >= 2
    centroids: dict[str, np.ndarray] = {}
    if available and n_anchor:
        anchor_features = features[:n_anchor]
        grouped = np.asarray(anchor_ids)
        bag_counts = Counter(anchor_ids)
        for anchor_id in dict.fromkeys(anchor_ids):
            if bag_counts[anchor_id] < _MIN_ANCHOR_BAGS:
                continue
            centroid = anchor_features[grouped == anchor_id].mean(axis=0)
            norm = float(np.linalg.norm(centroid))
            centroids[anchor_id] = centroid / norm if norm > 0.0 else centroid
    return LexicalAssignmentSpace(
        anchor_centroids=centroids,
        window_features=features[n_anchor + n_background:],
        available=available,
    )


def pull_hash_to_cluster(
    es, commands_index: str, page_size: int = 5000, *, filt: list[dict] | None = None,
) -> dict[str, str]:
    """{command_hash (_id): command_cluster_id} for every scored command. `filt` adds
    extra `bool.filter` clauses (e.g. `releasable_filter(cfg)`) — callers writing a
    committed public-only artifact (`capture_anchor_snapshot.py`) must pass it; the
    production hot path (`assign_runner.py`) intentionally omits it to see the full
    (mixed-classification) cluster taxonomy."""
    base = "dshield.cowrie.enrichment.cluster"
    body = {
        "size": page_size,
        "_source": [f"{base}.id", f"{base}.is_outlier"],
        "query": {"bool": {"filter": [{"exists": {"field": f"{base}.id"}}, *list(filt or [])]}},
        "sort": [{"_doc": "asc"}],
    }
    out: dict[str, str] = {}
    sa = None
    while True:
        if sa:
            body["search_after"] = sa
        r = es.search(index=commands_index, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            cl = (h["_source"].get("dshield", {}).get("cowrie", {})
                  .get("enrichment", {}).get("cluster", {}))
            cid = cl.get("id")
            out[h["_id"]] = (_OUTLIER_TOKEN if (cl.get("is_outlier") or cid in (None, "outlier"))
                             else str(cid))
        sa = hits[-1]["sort"]
    return out


def build_bag_texts(command_sets: list[list[str]], hash_to_cluster: dict[str, str]) -> list[str]:
    """Per-session space-joined command-cluster-id tokens (multiplicity = the number of
    the session's unique commands in each cluster)."""
    texts: list[str] = []
    for cs in command_sets:
        toks = [hash_to_cluster.get(h, _OUTLIER_TOKEN) for h in cs]
        texts.append(" ".join(toks) if toks else _EMPTY_TOKEN)
    return texts


def pull_hash_to_predicates(
    es, commands_index: str, page_size: int = 5000, *, filt: list[dict] | None = None,
) -> dict[str, dict]:
    """{command_hash (_id): per-command structural-predicate sub-signal dict} (item 30)
    for every command carrying `dshield.cowrie.enrichment.predicates.*`. Mirrors
    `pull_hash_to_cluster`'s shape and `filt` contract exactly — see
    `.predicates.command_subsignals` for the sub-signal fields and
    `build_session_predicate_vectors` for how they fold into a session vector. A command
    doc from before this feature shipped has no `predicates` block and is simply absent
    from the returned map (fail-closed: `build_session_predicate_vectors` treats a
    missing hash as no evidence, same posture as `build_bag_texts`'s outlier fallback)."""
    base = "dshield.cowrie.enrichment.predicates"
    # Any sub-signal field works as the "does this doc carry predicates" existence
    # probe (they're always written together — see `command_subsignals`); reference
    # the first name in `SUBSIGNAL_NAMES` rather than a hardcoded literal so a future
    # rename of that sub-signal can't silently break this filter.
    body = {
        "size": page_size,
        "_source": [base],
        "query": {"bool": {
            "filter": [{"exists": {"field": f"{base}.{SUBSIGNAL_NAMES[0]}"}}, *list(filt or [])],
        }},
        "sort": [{"_doc": "asc"}],
    }
    out: dict[str, dict] = {}
    sa = None
    while True:
        if sa:
            body["search_after"] = sa
        r = es.search(index=commands_index, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            pred = (h["_source"].get("dshield", {}).get("cowrie", {})
                    .get("enrichment", {}).get("predicates", {}))
            out[h["_id"]] = pred
        sa = hits[-1]["sort"]
    return out


def build_session_predicate_vectors(
    command_sets: list[list[str]], hash_to_predicates: dict[str, dict],
) -> list[dict[str, bool]]:
    """Per-session composed 7-predicate booleans (item 30), folded from each command's
    precomputed sub-signals via `predicates.fold_session_predicates`. Index-aligned with
    `command_sets`, mirroring `build_bag_texts`. A command hash absent from
    `hash_to_predicates` contributes no sub-signal evidence for that command (fail-closed)."""
    return [
        fold_session_predicates([hash_to_predicates[h] for h in cs if h in hash_to_predicates])
        for cs in command_sets
    ]
