"""Command-cluster-id bag — the scale-stable lexical view used as the TF-IDF
secondary signal (Exp 3 / the consolidation engine / the assignment band check).

Maps a session's `command_set` (unique command hashes) to the command-cluster ids
those commands belong to, joined into a space-separated "bag" text. The bag vocabulary
is bounded by the command-cluster count (not raw command tokens, which proliferate), so
`compute_lexical_features`' TF-IDF+SVD geometry stays stable across corpus scales.

Single source of truth for the scripts (eval) and the production assignment runner.
"""
from __future__ import annotations

_OUTLIER_TOKEN = "cluster_outlier"   # command not in any command cluster
_EMPTY_TOKEN = "cluster_empty"       # session with no resolvable commands


def pull_hash_to_cluster(es, commands_index: str, page_size: int = 5000) -> dict[str, str]:
    """{command_hash (_id): command_cluster_id} for every scored command."""
    base = "dshield.cowrie.enrichment.cluster"
    body = {
        "size": page_size,
        "_source": [f"{base}.id", f"{base}.is_outlier"],
        "query": {"exists": {"field": f"{base}.id"}},
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
