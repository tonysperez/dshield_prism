"""G1 — Arm B (`cluster_bag`) at production scale.

Premise: the embedding's semantic abstraction lives at the *command-cluster*
level (where `cluster_7` won — `uname -m` / `whoami` / `/ip cloud print`
grouped as host recon despite near-zero textual overlap). Session-level
mean-pool of per-command embeddings washes it out because token mass
dominates. Arm B aggregates each session as a TF-IDF bag over **which
command clusters it visited**, preserving the cluster-level signal at the
session level. The vocabulary is bounded by the ~command-cluster count, so
the SVD geometry stays stable (unlike E4.4's raw-token bag, which
fragmented to 72).

Pipeline: per session, map `command_set` (unique command hashes) → command-
cluster ids → TF-IDF + SVD (`compute_lexical_features`) → HDBSCAN → rescue
+ merge (same consolidation as baseline, in the bag space). Scores all 7
F-phase metrics + dumps the full assignment map for the G0 cross-arm
comparison.

Runs against **live ES** (the snapshot carries embeddings only, not
`command_set` or the command-cluster index). Read-only.

    console/.venv/bin/python scripts/cluster_bag_prod.py
    console/.venv/bin/python scripts/cluster_bag_prod.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.clustering import (
    cluster_bag_labels,
    compute_centroids,
    l2_normalize,
    rescue_noise_points,
)
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.sessions import merge_clusters_into_playbooks

from eval_production_scale import _load_eval_session_ids_and_labels
from prod_corpus import pull_session_corpus, score_full

# Bounded SVD width — clamped down to vocab/n-1 by compute_lexical_features.
_BAG_SVD_COMPONENTS = 48
_OUTLIER_TOKEN = "cluster_outlier"   # command not in any command cluster
_EMPTY_TOKEN = "cluster_empty"       # session with no resolvable commands


def pull_hash_to_cluster(es, commands_index: str, page_size: int) -> dict[str, str]:
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
            out[h["_id"]] = _OUTLIER_TOKEN if (cl.get("is_outlier") or cid in (None, "outlier")) else str(cid)
        sa = hits[-1]["sort"]
    return out


def build_bag_texts(command_sets: list[list[str]], hash_to_cluster: dict[str, str]) -> list[str]:
    """Per-session space-joined command-cluster-id tokens (with multiplicity =
    number of the session's unique commands in each cluster)."""
    texts: list[str] = []
    for cs in command_sets:
        toks = [hash_to_cluster.get(h, _OUTLIER_TOKEN) for h in cs]
        texts.append(" ".join(toks) if toks else _EMPTY_TOKEN)
    return texts


def _apply_merge(labels: np.ndarray, norm_block: np.ndarray, threshold: float) -> np.ndarray:
    """Cluster→playbook merge in the bag space (same step as baseline, on the
    bag centroids instead of embedding centroids)."""
    cents = compute_centroids(norm_block, labels)
    cmap = {str(int(l)): cents[l].tolist() for l in cents}
    groups = merge_clusters_into_playbooks(cmap, threshold)
    pg_to_int: dict[str, int] = {}
    merged = np.empty_like(labels)
    for i, l in enumerate(labels):
        li = int(l)
        if li < 0:
            merged[i] = -1
            continue
        pg = groups[str(li)]
        if pg not in pg_to_int:
            pg_to_int[pg] = len(pg_to_int)
        merged[i] = pg_to_int[pg]
    return merged


def _self_test() -> int:
    """G1.1 verify: 10 sessions share bag {c1,c2}, 10 share {c3,c4}. The
    partition must follow bag similarity (two groups), regardless of text."""
    bag_texts = ["c1 c2 c1"] * 10 + ["c3 c4 c4"] * 10
    labels, block = cluster_bag_labels(
        bag_texts, min_cluster_size=5, min_samples=2, n_components=4,
    )
    groups = {}
    for i, l in enumerate(labels):
        groups.setdefault(int(l), []).append("A" if i < 10 else "B")
    # Each non-noise cluster should be pure A or pure B, and there should be
    # exactly two such clusters (the two bag types).
    nonnoise = {k: v for k, v in groups.items() if k >= 0}
    pure = all(len(set(v)) == 1 for v in nonnoise.values())
    two = len(nonnoise) == 2
    print(f"clusters: {[(k, len(v)) for k, v in sorted(groups.items())]}")
    print("SELF-TEST:", "PASS" if (pure and two) else "FAIL")
    return 0 if (pure and two) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-merge", action="store_true",
                    help="Skip the bag-space cluster→playbook merge.")
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()

    cfg = load_config()
    scfg = cfg.session
    es = make_client(cfg.elasticsearch, load_secrets())
    ix = cfg.elasticsearch.indexes.cowrie

    print(f"pulling corpus from {ix.sessions_rollup} ...", flush=True)
    corpus = pull_session_corpus(es, ix.sessions_rollup, scfg.page_size)
    print(f"  {len(corpus)} sessions", flush=True)
    print(f"pulling command→cluster map from {ix.commands} ...", flush=True)
    hash_to_cluster = pull_hash_to_cluster(es, ix.commands, cfg.command_cluster.page_size)
    print(f"  {len(hash_to_cluster)} commands; "
          f"{len(set(hash_to_cluster.values()))} distinct command clusters", flush=True)

    bag_texts = build_bag_texts(corpus.command_sets, hash_to_cluster)
    labels, block = cluster_bag_labels(
        bag_texts, min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples, n_components=_BAG_SVD_COMPONENTS,
    )
    norm_block = l2_normalize(block)
    merge_threshold = scfg.playbook_merge_threshold
    labels, n_rescued = rescue_noise_points(norm_block, labels, merge_threshold)
    if not args.no_merge:
        labels = _apply_merge(labels, norm_block, merge_threshold)

    sid_to_label, pairs = _load_eval_session_ids_and_labels(
        Path("eval/labels.yaml"), Path("eval/labels-v2.yaml"),
    )
    scored = score_full(labels, corpus, sid_to_label, pairs,
                        merge_threshold=merge_threshold)
    m = scored["metrics"]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scale": "production", "arm": "cluster_bag",
        "config": {
            "min_cluster_size": scfg.cluster_min_cluster_size,
            "min_samples": scfg.cluster_min_samples,
            "svd_components": _BAG_SVD_COMPONENTS,
            "rescue_threshold": merge_threshold,
            "merged": not args.no_merge,
        },
        "input": {
            "n_sessions": len(corpus),
            "n_commands": len(hash_to_cluster),
            "n_command_clusters": len(set(hash_to_cluster.values())),
        },
        "cluster_output": {
            "n_clusters_total": scored["n_clusters_total"],
            "n_outliers_total": scored["n_outliers_total"],
            "n_rescued": int(n_rescued),
        },
        "metrics": m,
        "assignments": {sid: int(c) for sid, c in zip(corpus.session_ids, labels)},
    }

    out: list[str] = []
    out.append("# G1 — Arm B (cluster_bag) at production scale")
    out.append("")
    out.append(f"_Captured {report['generated_at']}_")
    out.append("")
    out.append(f"- **Sessions:** {len(corpus)} · **command clusters (vocab):** "
               f"{report['input']['n_command_clusters']}")
    out.append(f"- **Clusters:** {scored['n_clusters_total']} · outliers "
               f"{scored['n_outliers_total']} · rescued {int(n_rescued)}")
    out.append(f"- **ARI:** {m['ari']} · completeness {m['completeness']} · "
               f"homogeneity {m['homogeneity']}")
    out.append(f"- **v2 divergent-pair rate:** {m.get('divergent_pair_resolution_rate')} "
               "(baseline ~0.667 = 4/6 — the key G signal)")
    out.append("")
    out.append("Next: `compare_clusterings.py <baseline> <this json>` for cross-arm "
               "ARI + disagreement manifest (G3).")
    md = "\n".join(out)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = args.output_dir / f"cluster-bag-prod-{ts}"
    Path(f"{stem}.md").write_text(md, encoding="utf-8")
    Path(f"{stem}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\n" + md)
    print(f"\nwrote {stem}.md\nwrote {stem}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
