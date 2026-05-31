"""Per-cluster textual-purity diagnostic for the session layer
(brutal-review phase 3.1).

For each session cluster in the latest cluster run, reports three
purity metrics — all 0..1, higher = tighter cluster:

  * ``jaccard_commands``     — mean pairwise Jaccard of ``command_set``
    (sorted bag of unique command hashes per session). Captures shared
    vocabulary independent of order.
  * ``jaccard_sequences``    — mean pairwise Jaccard of
    ``command_bigram_set`` (sorted bag of consecutive-command bigrams
    per session). Captures sequence-relationship overlap. Substitutes
    for the original plan's "mean pairwise edit distance": edit
    distance on raw command_line text would require a per-command
    mget chain that bigram-Jaccard sidesteps while capturing the same
    "are these sessions textually similar" signal.
  * ``modal_signature_share`` — fraction of cluster members whose
    ``command_signature`` (sha256 over the sorted unique-command-hash
    list) equals the modal value within the cluster. Cargo-cult-script
    proxy: 1.0 means every member runs the EXACT same unique-command
    set. Substitutes for "first 8 tokens identical" — the rollup
    doesn't carry per-session command text, so first-N-tokens isn't
    cheaply derivable; modal-signature share captures the same
    "identical opening / identical script" smell at the bag level.

A loose cluster (low scores) and a high member count is the
"fragmented playbook" signal the brutal-review eval surfaced. A
tight cluster with low membership is "we found a small distinct
behaviour" — expected and good.

Sampling: pairwise metrics are O(N²) in cluster size. For clusters
larger than ``--pair-sample-cap`` members, we sample uniformly and
compute the metric on the sample. Default 60 members ≈ 1770 pairs.

Read-only. No ES writes, no centroid touches.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/eval_cluster_purity.py
"""
from __future__ import annotations

import argparse
import random
import sys
from itertools import combinations
from pathlib import Path
from typing import Iterable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client


def _latest_cluster_run_id(es, clusters_index: str) -> Optional[str]:
    """Pick the latest run_id from the run_summary docs in the
    session-clusters index."""
    body = {
        "size": 1,
        "_source": ["run_id", "@timestamp"],
        "query": {"term": {"doc_type": "run_summary"}},
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    resp = es.search(index=clusters_index, **body)
    hits = resp["hits"]["hits"]
    if not hits:
        return None
    return hits[0]["_source"].get("run_id")


def _list_clusters(es, clusters_index: str, run_id: str) -> list[dict]:
    """All cluster docs in the given run, ordered by size desc."""
    body = {
        "size": 1000,
        "_source": ["cluster_id", "playbook_id", "playbook_name", "size"],
        "query": {"bool": {"must": [
            {"term": {"doc_type": "cluster"}},
            {"term": {"run_id": run_id}},
        ]}},
        "sort": [{"size": {"order": "desc"}}],
    }
    resp = es.search(index=clusters_index, **body)
    return [h["_source"] for h in resp["hits"]["hits"]]


def _fetch_member_features(
    es, sessions_index: str, playbook_id: str,
) -> list[dict]:
    """All sessions assigned to ``playbook_id`` — yields a per-session
    dict with command_set, command_bigram_set, and command_signature.
    Uses search_after pagination because some playbooks span thousands
    of sessions on a long-running corpus."""
    base = "dshield.cowrie.enrichment.session"
    body = {
        "size": 1000,
        "_source": [
            f"{base}.command_set",
            f"{base}.command_bigram_set",
            f"{base}.command_signature",
        ],
        "query": {"term": {f"{base}.playbook_id": playbook_id}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    out: list[dict] = []
    search_after = None
    while True:
        if search_after is not None:
            body["search_after"] = search_after
        resp = es.search(index=sessions_index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return out
        for h in hits:
            s = (
                (((h["_source"].get("dshield") or {}).get("cowrie") or {})
                 .get("enrichment") or {})
                .get("session") or {}
            )
            out.append({
                "command_set":         set(s.get("command_set") or ()),
                "command_bigram_set":  set(s.get("command_bigram_set") or ()),
                "command_signature":   s.get("command_signature") or "",
            })
        search_after = hits[-1].get("sort")
        if search_after is None:
            return out


def _mean_pairwise_jaccard(
    members: list[set], rng: random.Random, sample_cap: int,
) -> Optional[float]:
    """Mean pairwise Jaccard over a (possibly sampled) member set.
    Returns None when fewer than 2 non-empty members are available."""
    pop = [m for m in members if m]
    if len(pop) < 2:
        return None
    if len(pop) > sample_cap:
        pop = rng.sample(pop, sample_cap)
    total = 0.0
    n = 0
    for a, b in combinations(pop, 2):
        union = a | b
        if not union:
            continue
        total += len(a & b) / len(union)
        n += 1
    return total / n if n > 0 else None


def _modal_signature_share(members: list[dict]) -> Optional[float]:
    """Fraction of members whose command_signature equals the modal
    value within the cluster. None when no member carries a signature."""
    sigs = [m.get("command_signature") or "" for m in members]
    sigs = [s for s in sigs if s]
    if not sigs:
        return None
    from collections import Counter
    top_sig, top_count = Counter(sigs).most_common(1)[0]
    return top_count / len(sigs)


def _print_table(rows: list[dict]) -> None:
    """Per-cluster table sorted by size DESC."""
    def _fmt(v: Optional[float]) -> str:
        return "    —" if v is None else f"{v:5.2f}"
    print(f"{'cluster_id':24} {'playbook_id':20} {'size':>6} "
          f"{'j_cmds':>7} {'j_seqs':>7} {'mod_sig':>8}  playbook_name")
    print("-" * 110)
    for r in rows:
        print(
            f"{r['cluster_id']:24} "
            f"{r['playbook_id']:20} "
            f"{r['size']:>6} "
            f"{_fmt(r['jaccard_commands']):>7} "
            f"{_fmt(r['jaccard_sequences']):>7} "
            f"{_fmt(r['modal_signature_share']):>8}  "
            f"{r['playbook_name'] or ''}"
        )


def _print_histogram(rows: list[dict]) -> None:
    """Coarse histogram of each metric over all clusters."""
    bins = [0.0, 0.2, 0.4, 0.6, 0.8, 1.01]
    labels = ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"]
    for metric in ("jaccard_commands", "jaccard_sequences", "modal_signature_share"):
        counts = [0] * len(labels)
        none_count = 0
        for r in rows:
            v = r[metric]
            if v is None:
                none_count += 1
                continue
            for i in range(len(labels)):
                if bins[i] <= v < bins[i + 1]:
                    counts[i] += 1
                    break
        print(f"\n  {metric}:")
        for label, c in zip(labels, counts):
            bar = "#" * c
            print(f"    {label}  {c:>4}  {bar}")
        if none_count:
            print(f"    n/a       {none_count:>4}  (insufficient members)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--clusters-index", default=None,
                    help="Defaults to cfg.elasticsearch.indexes.cowrie.session_clusters")
    ap.add_argument("--sessions-index", default=None,
                    help="Defaults to cfg.elasticsearch.indexes.cowrie.sessions_rollup")
    ap.add_argument("--run-id", default=None,
                    help="Override the run id. Defaults to the latest run_summary.")
    ap.add_argument("--pair-sample-cap", type=int, default=60,
                    help=(
                        "Max members per cluster used for pairwise metrics. "
                        "Default 60 (1770 pairs). Membership counts are still "
                        "reported exactly."
                    ))
    ap.add_argument("--seed", type=int, default=20260531,
                    help="Sampling seed (reproducible per corpus + seed).")
    ap.add_argument("--limit", type=int, default=None,
                    help="Diagnose only the top-N clusters by size.")
    args = ap.parse_args()

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)

    clusters_index = args.clusters_index or cfg.elasticsearch.indexes.cowrie.session_clusters
    sessions_index = args.sessions_index or cfg.elasticsearch.indexes.cowrie.sessions_rollup

    run_id = args.run_id or _latest_cluster_run_id(es, clusters_index)
    if not run_id:
        print(f"[ERROR] No run_summary found in {clusters_index}.", file=sys.stderr)
        return 1
    clusters = _list_clusters(es, clusters_index, run_id)
    if args.limit:
        clusters = clusters[: args.limit]

    print(f"clusters index   : {clusters_index}")
    print(f"sessions index   : {sessions_index}")
    print(f"run_id           : {run_id}")
    print(f"clusters in run  : {len(clusters)}")
    print(f"pair sample cap  : {args.pair_sample_cap}")
    print()

    rng = random.Random(args.seed)
    rows: list[dict] = []
    for c in clusters:
        pid = c.get("playbook_id")
        if not pid:
            continue
        members = _fetch_member_features(es, sessions_index, pid)
        rows.append({
            "cluster_id":            c.get("cluster_id") or "",
            "playbook_id":           pid,
            "playbook_name":         c.get("playbook_name"),
            "size":                  int(c.get("size") or len(members)),
            "n_members_fetched":     len(members),
            "jaccard_commands":      _mean_pairwise_jaccard(
                [m["command_set"]        for m in members], rng, args.pair_sample_cap),
            "jaccard_sequences":     _mean_pairwise_jaccard(
                [m["command_bigram_set"] for m in members], rng, args.pair_sample_cap),
            "modal_signature_share": _modal_signature_share(members),
        })

    _print_table(rows)
    print("\nHistogram:")
    _print_histogram(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
