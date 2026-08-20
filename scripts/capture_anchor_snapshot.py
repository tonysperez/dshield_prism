"""Capture a PUBLIC anchor snapshot for the offline prod-scale assignment eval
(`scripts/eval_assignment_prod.py`) and the faithful assignment replay
(`scripts/eval_assignment_faithful.py --anchors`). The output is committed to VCS, so
it must contain ONLY public data.

The production `playbook_anchors.anchor_centroid` is pinned from MIXED-classification
sessions, so it cannot be committed. Instead this **recomputes** each playbook's centroid
from its **public** sessions only (`releasable_filter` — fail-safe: explicit
`dshield.classification: public`), so every vector in the snapshot is public-derived.
There is deliberately NO `--allow-unclassified`: a committed artifact is public or it does
not exist.

Each anchor also carries a sample of per-session command-cluster bag texts (the same
`pull_hash_to_cluster` + `build_bag_texts` production's assignment runner uses for its
TF-IDF band confirm — see `src/enrich/sources/cowrie/lexical.py`), so an offline consumer
can replay that half of the assignment decision without live ES. It also carries a
`predicate_signature` (item 30) — a modal/frequency vector of the 7 structural predicates
(`src/enrich/sources/cowrie/predicates.py`) over the same sampled public sessions'
precomputed sub-signals (`pull_hash_to_predicates` + `build_session_predicate_vectors`),
so an offline consumer can also replay the below-tau rescue tier.

On the current untagged corpus the public filter returns 0, so the snapshot is **empty** —
that is the correct, safe outcome. Re-ingest sensors with `dshield.classification` tags
first, then re-capture. One gzipped-JSONL line per playbook:
`{playbook_id, anchor_centroid, n_public_sessions, command_cluster_bags, predicate_signature}`.

Any captured anchor whose bag sample lands under `lexical._MIN_ANCHOR_BAGS` is printed to
stderr (audit signal — rare-playbook public-session counts are corpus-limited, not a
`--per-anchor` setting); it still gets a row here, but the eval replay gives it no TF-IDF
centroid (item 37).

This script also emits a second, independent artifact: a broad **background cohort** of
public session command-cluster bags (`--background-out`, default
`eval/background-cohort-v1.jsonl.gz`), sampled across the whole public corpus with no
`playbook_id` filter and no embedding requirement. It exists only to pad the eval replay's
TF-IDF/SVD fit (`eval_assignment_faithful.py --background`) closer to production's much
larger natural fit corpus — cohort rows are never scored (item 38).

`--min-public` defaults to the deployed novel-pool minting floor
(`session.novel_pool_cluster_min_cluster_size`, currently 3) rather than a fixed number:
the snapshot must be able to represent every anchor production is allowed to mint. On a
fully-public corpus `n_public_sessions` IS the anchor's whole membership, so the floor is
a minting-parity choice, not a sampling one.

    console/.venv/bin/python scripts/capture_anchor_snapshot.py \
        --out eval/anchor-snapshot-v1.jsonl.gz \
        --background-out eval/background-cohort-v1.jsonl.gz
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import explicit_public_filters as explicitly_public_filters
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.lexical import (
    _EMPTY_TOKEN,
    _MIN_ANCHOR_BAGS,
    _OUTLIER_TOKEN,
    build_bag_texts,
    build_session_predicate_vectors,
    pull_hash_to_cluster,
    pull_hash_to_predicates,
)
from enrich.sources.cowrie.predicates import predicate_signature
from enrich.sources.cowrie.sessions import effective_novel_pool_min_cluster_size

_S = "dshield.cowrie.enrichment.session"
_PB = f"{_S}.playbook_id"
_EMB = f"{_S}.embedding"
_CMDSET = f"{_S}.command_set"


def centroid(embs: list[list[float]]) -> list[float]:
    """L2-normalised mean of the (public) session embeddings — the public-derived anchor."""
    import numpy as np
    m = np.asarray(embs, dtype=np.float32).mean(axis=0)
    n = float(np.linalg.norm(m))
    return (m / n).tolist() if n > 0 else m.tolist()


def anchor_row(
    pb: str,
    embs: list[list[float]],
    command_sets: list[list[str]],
    hash_to_cluster: dict[str, str],
    *,
    min_public: int,
    predicate_vectors: list[dict[str, bool]] | None = None,
) -> dict | None:
    """Pure snapshot-row assembly — no ES. `command_sets` (and `predicate_vectors`, when
    given) must be index-aligned with `embs` (same sampled sessions). Returns None when
    the anchor has too few public sessions to be trustworthy.

    `predicate_vectors` (item 30) defaults to `None`, which folds to the same all-zero
    signature as an anchor with zero sampled evidence — a caller that doesn't pass it
    (there are none left in this file, but external callers/tests may) gets a snapshot
    row whose `predicate_signature` never rescues anything, not a crash."""
    if len(embs) < min_public:
        return None
    return {
        "playbook_id": pb,
        "anchor_centroid": centroid(embs),
        "n_public_sessions": len(embs),
        "command_cluster_bags": build_bag_texts(command_sets, hash_to_cluster),
        "predicate_signature": predicate_signature(predicate_vectors or []),
    }


def require_public_command_taxonomy(hash_to_cluster: dict[str, str]) -> dict[str, str]:
    """Reject a capture without enough public lexical vocabulary diversity.

    Individual commands may still use production's fallback token, but an empty
    or single-token taxonomy makes every captured bag degenerate and must not
    become a fixture.
    """
    non_outlier_ids = {cluster_id for cluster_id in hash_to_cluster.values()
                       if cluster_id != _OUTLIER_TOKEN}
    if len(non_outlier_ids) < 2:
        raise ValueError(
            "public command taxonomy lacks lexical diversity (need at least two "
            "distinct non-outlier cluster IDs); refusing capture. Classify and "
            "rebuild the command enrichment index before rerunning",
        )
    return hash_to_cluster


def resolve_min_public(explicit: int | None, cfg) -> int:
    """The `--min-public` floor: an explicit flag wins, otherwise the deployed novel-pool
    minting floor.

    Pure so the coupling is testable offline. The floor must track what production is
    allowed to MINT, not a separate opinion about how many sessions make a trustworthy
    centroid — item 72 lowered novel-pool minting to 3, and a capture pinned at 5 drops
    every rare-behaviour anchor minted since, which is exactly the set the eval is short
    of. On a fully-public corpus `n_public_sessions` is the anchor's whole membership, so
    there is no sampling argument left for a higher floor.
    """
    if explicit is not None:
        return explicit
    return effective_novel_pool_min_cluster_size(cfg.session, novel_pool_only=True)


def _public_playbook_ids(es, idx, filt, size) -> list[tuple[str, int]]:
    r = es.search(index=idx, size=0, query={"bool": {"filter": filt}},
                  aggs={"pb": {"terms": {"field": _PB, "size": size}}})
    return [(b["key"], b["doc_count"]) for b in r["aggregations"]["pb"]["buckets"]]


def _sample_sessions(es, idx, filt, pb, n):
    """(embeddings, command_sets) for up to `n` public sessions of one playbook,
    index-aligned so the command-cluster bags line up with the embedding centroid sample."""
    r = es.search(index=idx, size=min(n, 10000), _source=[_EMB, _CMDSET],
                  query={"bool": {"filter": [*filt, {"term": {_PB: pb}}]}})
    embs, command_sets = [], []
    for h in r["hits"]["hits"]:
        s = (((h["_source"].get("dshield") or {}).get("cowrie") or {})
             .get("enrichment", {}).get("session", {}))
        if s.get("embedding"):
            embs.append(s["embedding"])
            command_sets.append(list(s.get("command_set") or []))
    return embs, command_sets


def background_query_filters(filt: list[dict]) -> list[dict]:
    """Background-cohort selection filters: public, plus a session that actually ran
    commands.

    Without the `command_set` requirement the cohort is worthless as TF-IDF fit padding:
    only ~1.3% of public sessions have any commands, so an unsorted sample returns
    command-less rows and `build_bag_texts` maps every one to `_EMPTY_TOKEN` — a
    2000-row, single-token cohort that pads the fit with no lexical information at all.
    """
    return [*filt, {"exists": {"field": _CMDSET}}]


def cohort_is_informative(bags: list[str]) -> bool:
    """True when the cohort contributes at least two distinct real cluster tokens.

    Fallback tokens (`cluster_outlier`, `cluster_empty`) carry no behavioural signal, so
    a cohort made only of them pads the TF-IDF fit with noise-free nothing. Two distinct
    real tokens is the minimum that can express a difference between documents.
    """
    real = {
        token
        for bag in bags
        for token in bag.split()
        if token not in (_OUTLIER_TOKEN, _EMPTY_TOKEN)
    }
    return len(real) >= 2


def _sample_background_sessions(es, idx, filt, n):
    """(session_ids, command_sets) for up to `n` public sessions sampled across the whole
    corpus, independent of playbook membership (item 38) — no `playbook_id` filter, so the
    background cohort's composition resembles a real assignment window rather than
    resampling the anchors themselves."""
    r = es.search(index=idx, size=min(n, 10000), _source=[_CMDSET],
                  query={"bool": {"filter": background_query_filters(filt)}})
    session_ids, command_sets = [], []
    for h in r["hits"]["hits"]:
        s = (((h["_source"].get("dshield") or {}).get("cowrie") or {})
             .get("enrichment", {}).get("session", {}))
        session_ids.append(h["_id"])
        command_sets.append(list(s.get("command_set") or []))
    return session_ids, command_sets


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--out", default="eval/anchor-snapshot-v1.jsonl.gz")
    ap.add_argument("--per-anchor", type=int, default=500, help="public sessions averaged per playbook")
    ap.add_argument("--min-public", type=int, default=None,
                    help="skip playbooks with fewer public sessions; default is the "
                         "deployed novel-pool minting floor "
                         "(session.novel_pool_cluster_min_cluster_size)")
    ap.add_argument("--background-out", default="eval/background-cohort-v1.jsonl.gz",
                     help="where to write the broad public session-bag cohort (item 38)")
    ap.add_argument("--background-n", type=int, default=2000,
                     help="max public sessions sampled for the background cohort, "
                          "any/no playbook")
    args = ap.parse_args()
    if args.background_n <= 0:
        ap.error("--background-n must be positive")

    cfg = load_config(args.config)
    args.min_public = resolve_min_public(args.min_public, cfg)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands
    # PUBLIC ONLY — committed to VCS. No override.
    public_filters = explicitly_public_filters(cfg)
    filt = [*public_filters, {"exists": {"field": _EMB}}]

    # Same public-only bar as the session query — a committed artifact must never
    # derive from a confidential/untagged command's cluster assignment.
    hash_to_cluster = pull_hash_to_cluster(es, cmd_idx, filt=public_filters)
    try:
        require_public_command_taxonomy(hash_to_cluster)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    # Same public-only bar again (item 30): the anchor's predicate_signature must be
    # derived only from public commands' precomputed sub-signals.
    hash_to_predicates = pull_hash_to_predicates(es, cmd_idx, filt=public_filters)
    pbs = _public_playbook_ids(es, idx, filt, size=5000)
    rows: list[str] = []
    thin_anchors: list[tuple[str, int]] = []
    for pb, count in pbs:
        if not pb or count < args.min_public:
            continue
        embs, command_sets = _sample_sessions(es, idx, filt, pb, args.per_anchor)
        predicate_vectors = build_session_predicate_vectors(command_sets, hash_to_predicates)
        row = anchor_row(pb, embs, command_sets, hash_to_cluster, min_public=args.min_public,
                         predicate_vectors=predicate_vectors)
        if row is None:
            continue
        n_bags = len(row["command_cluster_bags"])
        if n_bags < _MIN_ANCHOR_BAGS:
            thin_anchors.append((pb, n_bags))
        rows.append(json.dumps(row))

    if not rows:
        # Do NOT leave a committable empty snapshot — there's no public data to capture.
        print("0 public playbooks — the corpus has no `dshield.classification:public` "
              "sessions yet. Retro-tag your public sensor with "
              "scripts/backfill_classification.py, then re-capture. No snapshot written.",
              file=sys.stderr)
        return 0
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, "wt") as fh:
        fh.write("\n".join(rows) + "\n")
    print(f"wrote {len(rows)} public-derived anchors → {out}")
    print("Next: baseline + commit — `python scripts/eval_assignment_prod.py --write-baseline`")

    if thin_anchors:
        print(
            f"{len(thin_anchors)} anchor(s) below the min-bags threshold "
            f"({_MIN_ANCHOR_BAGS}) — these get no TF-IDF centroid downstream "
            "(audit signal, not a sampling bug: rare-playbook public-session counts "
            "are corpus-limited):",
            file=sys.stderr,
        )
        for pb, n_bags in thin_anchors:
            print(f"  {pb}: {n_bags} bags", file=sys.stderr)

    # Background cohort (item 38): broad public session bags, independent of anchor
    # membership — pads the eval replay's TF-IDF/SVD fit without ever being scored.
    background_filt = public_filters
    bg_ids, bg_command_sets = _sample_background_sessions(
        es, idx, background_filt, args.background_n,
    )
    if not bg_ids:
        print("0 public sessions available for the background cohort — skipping "
              f"{args.background_out}.", file=sys.stderr)
        return 0
    bg_bags = build_bag_texts(bg_command_sets, hash_to_cluster)
    if not cohort_is_informative(bg_bags):
        print("background cohort carries no real cluster tokens (every bag is a fallback) "
              f"— refusing to write a degenerate {args.background_out}. It would pad the "
              "eval replay's TF-IDF fit with zero lexical information.", file=sys.stderr)
        return 1
    bg_rows = [
        json.dumps({"session_id": session_id, "command_cluster_bag": bag})
        for session_id, bag in zip(bg_ids, bg_bags, strict=False)
    ]
    bg_out = Path(args.background_out)
    bg_out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(bg_out, "wt") as fh:
        fh.write("\n".join(bg_rows) + "\n")
    print(f"wrote {len(bg_rows)} public background-cohort sessions → {bg_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
