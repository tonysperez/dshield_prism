"""G3 (corpus-wide) — baseline vs cluster_bag self-consistency on the full
live corpus, label-free.

The 108-session analyst label set is too thin to adjudicate the arms. This
clusters the whole production corpus both ways in one pass and compares
**self-consistency** signals that need no labels:

  * **intent coherence** — size-weighted mean per-cluster dominant-intent
    share. Soft signal (LLM intent), but a reasonable "are clusters
    behaviourally coherent" proxy.
  * **signature coherence** — size-weighted mean per-cluster modal
    command-signature share. Deterministic. The *discriminating* metric:
    if cluster_bag keeps intent coherence high while signature coherence
    *drops*, it is grouping behaviourally-similar but textually-different
    sessions — the "semantic abstraction over text" win Arm B is for. If
    intent coherence also drops, it is just shuffling.
  * cluster count / outlier rate, cross-arm ARI, and the v2 divergent-pair
    resolution (6 corpus-mined pairs — the only behaviour-not-text ground
    truth available).

Read-only, live ES. Run from the repo root via the console venv.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cluster_bag_prod import _BAG_SVD_COMPONENTS, build_bag_texts, pull_hash_to_cluster
from eval_production_scale import (
    _apply_session_merge,
    _load_eval_session_ids_and_labels,
)
from prod_corpus import cluster_hdbscan, pull_session_corpus

from enrich.clustering import (
    cluster_bag_labels,
    compute_centroids,
    l2_normalize,
    rescue_noise_points,
)
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.sessions import merge_clusters_into_playbooks


def _merge_bagspace(labels, norm_block, threshold):
    cents = compute_centroids(norm_block, labels)
    cmap = {str(int(l)): cents[l].tolist() for l in cents}
    groups = merge_clusters_into_playbooks(cmap, threshold)
    pg = {}
    out = np.empty_like(labels)
    for i, l in enumerate(labels):
        li = int(l)
        if li < 0:
            out[i] = -1; continue
        g = groups[str(li)]
        out[i] = pg.setdefault(g, len(pg))
    return out


def _self_consistency(labels, intents, signatures) -> dict:
    """Size-weighted mean intent + signature coherence over non-outlier
    clusters."""
    byc: dict[int, list[int]] = defaultdict(list)
    for i, l in enumerate(labels):
        if l >= 0:
            byc[int(l)].append(i)
    tot = intent_w = sig_w = 0
    for idxs in byc.values():
        n = len(idxs)
        its = [intents[i] for i in idxs if intents[i]]
        sgs = [signatures[i] for i in idxs if signatures[i]]
        if its:
            intent_w += (Counter(its).most_common(1)[0][1] / len(its)) * n
        if sgs:
            sig_w += (Counter(sgs).most_common(1)[0][1] / len(sgs)) * n
        tot += n
    n_out = int(sum(1 for l in labels if l == -1))
    return {
        "n_clusters": len(byc),
        "n_outliers": n_out,
        "outlier_rate": round(n_out / len(labels), 4),
        "intent_coherence": round(intent_w / tot, 4) if tot else None,
        "signature_coherence": round(sig_w / tot, 4) if tot else None,
    }


def _v2_rate(labels, session_ids, sid_to_label, pairs) -> str:
    sid_to_c = {s: int(c) for s, c in zip(session_ids, labels, strict=False)}
    res = tot = 0
    for members in pairs.values():
        if len(members) != 2 or any(m not in sid_to_c for m in members):
            continue
        a, b = members
        same_cluster = sid_to_c[a] == sid_to_c[b] and sid_to_c[a] != -1
        same_label = sid_to_label[a] == sid_to_label[b]
        tot += 1
        if same_cluster == same_label:
            res += 1
    return f"{res}/{tot}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    args = ap.parse_args()

    cfg = load_config(); scfg = cfg.session
    es = make_client(cfg.elasticsearch, load_secrets())
    ix = cfg.elasticsearch.indexes.cowrie
    thr = scfg.playbook_merge_threshold

    print(f"pulling corpus from {ix.sessions_rollup} ...", flush=True)
    corpus = pull_session_corpus(es, ix.sessions_rollup, scfg.page_size)
    print(f"  {len(corpus)} sessions", flush=True)
    hash_to_cluster = pull_hash_to_cluster(es, ix.commands, cfg.command_cluster.page_size)
    sid_to_label, pairs = _load_eval_session_ids_and_labels(
        Path("eval/labels.yaml"), Path("eval/labels-v2.yaml"))

    # Baseline: production hdbscan + rescue + merge (embedding space).
    base, _ = cluster_hdbscan(
        corpus, min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
        scalar_weight=scfg.cluster_scalar_weight, rescue_threshold=thr)
    base = _apply_session_merge(base, corpus.embeddings, thr)[0]

    # Arm B: cluster_bag + rescue + merge (bag space).
    bag_texts = build_bag_texts(corpus.command_sets, hash_to_cluster)
    arm, block = cluster_bag_labels(
        bag_texts, min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples, n_components=_BAG_SVD_COMPONENTS)
    nb = l2_normalize(block)
    arm, _ = rescue_noise_points(nb, arm, thr)
    arm = _merge_bagspace(arm, nb, thr)

    sc_base = _self_consistency(base, corpus.intents, corpus.signatures)
    sc_arm = _self_consistency(arm, corpus.intents, corpus.signatures)
    cross_ari = round(float(adjusted_rand_score(base, arm)), 4)
    cross_nmi = round(float(normalized_mutual_info_score(base, arm)), 4)

    lines = ["# Corpus-wide arm comparison — baseline vs cluster_bag (label-free)", ""]
    lines.append(f"_Captured {datetime.now(UTC).isoformat()}_ · {len(corpus)} sessions")
    lines.append("")
    lines.append("| metric | baseline | cluster_bag | read |")
    lines.append("|---|---:|---:|---|")
    lines.append(f"| clusters | {sc_base['n_clusters']} | {sc_arm['n_clusters']} | |")
    lines.append(f"| outlier_rate | {sc_base['outlier_rate']} | {sc_arm['outlier_rate']} | |")
    lines.append(f"| **intent coherence** | {sc_base['intent_coherence']} | "
                 f"{sc_arm['intent_coherence']} | high = behaviourally coherent |")
    lines.append(f"| **signature coherence** | {sc_base['signature_coherence']} | "
                 f"{sc_arm['signature_coherence']} | lower for bag = abstracts over text |")
    lines.append(f"| v2 divergent-pair | {_v2_rate(base, corpus.session_ids, sid_to_label, pairs)} "
                 f"| {_v2_rate(arm, corpus.session_ids, sid_to_label, pairs)} | "
                 "behaviour-not-text ground truth |")
    lines.append("")
    lines.append(f"**Cross-arm ARI** {cross_ari} · **NMI** {cross_nmi} "
                 "(low = the arms see different structure).")
    lines.append("")
    lines.append("**Interpretation.** If cluster_bag's intent coherence ≈ baseline "
                 "but its signature coherence is markedly lower, it is grouping "
                 "same-behaviour / different-text sessions (the Arm B thesis). If "
                 "intent coherence also drops, the bag partition is noisier, not "
                 "more semantic.")
    md = "\n".join(lines)
    print("\n" + md)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = args.output_dir / f"G-corpus-arm-comparison-{ts}.md"
    out.write_text(md, encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
