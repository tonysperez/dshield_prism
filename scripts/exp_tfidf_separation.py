"""Experiment 3 — does TF-IDF separate the behaviours the embedding conflates?

Experiment 2 found one held-out family (`spb-1b9a…`) whose sessions get absorbed
by a *different* surviving prototype (`spb-d0c4…`) at embedding cosine ~0.96 — so
threshold-OOD misses it. Open question: is that a **true twin** (consolidate) or a
**distinct behaviour the embedding conflates** (a representation limit)? If TF-IDF
(the divergent-pair winner) pulls the pair apart, the embedding is the limiter and
TF-IDF is the better substrate / the secondary signal the 0.94–0.98 band needs. If
TF-IDF also says they're close, they're genuinely the same and consolidation is the
right fix.

Method: sample sessions per playbook, vectorise each session two ways —
  * embedding (the production mean-pool, from the rollup), and
  * TF-IDF+SVD over the command-cluster-id bag (`compute_lexical_features` +
    `build_bag_texts` — the same proven, scale-stable lexical view used in the
    E/G phases and the divergent head-to-head).
Then per playbook PAIR report, in both spaces: centroid cosine and the
cross-assignment rate (fraction of A's sessions closer to B's centroid than A's).
Pairs = the embedding-close pairs (anchor cosine ≥ family_tau, the consolidation /
conflation candidates) plus any `--pairs` (default: the Exp-2 absorber pair).

Read-only; aggregates only. Same privacy boundary as Experiments 1–2: public-only
filter BY DEFAULT (0 docs on the untagged corpus); `--allow-unclassified` is an
OPERATOR decision, never set by the agent.

Run from repo root via the console venv:
    console/.venv/bin/python scripts/exp_tfidf_separation.py --families 12
"""
from __future__ import annotations

import argparse
import itertools
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # scripts/

from cluster_bag_prod import _BAG_SVD_COMPONENTS, build_bag_texts, pull_hash_to_cluster
from exp_prototype_assignment import _l2, load_anchors

from enrich.classification import releasable_filter
from enrich.clustering import compute_lexical_features
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_PB_FIELD = f"{_S}.playbook_id"
_EMB_FIELD = f"{_S}.embedding"
_CMDSET_FIELD = f"{_S}.command_set"
_MAX_WINDOW = 10000
_DEFAULT_ABSORBER_PAIRS = ("spb-1b9aa73264d8b7af:spb-d0c4af44ea4ea17b,"
                           "spb-1b9aa73264d8b7af:spb-54f54735dfa3bad4")


def _session_block(src: dict) -> dict:
    return (
        ((src.get("dshield") or {}).get("cowrie") or {})
        .get("enrichment", {})
        .get("session", {})
    )


# ---------------------------------------------------------------------------
# Pure math (smoke-tested)
# ---------------------------------------------------------------------------
def group_centroids(vecs: np.ndarray, groups: list[str]) -> dict[str, np.ndarray]:
    """L2-normalised mean vector per group label."""
    out: dict[str, np.ndarray] = {}
    g = np.asarray(groups)
    for label in dict.fromkeys(groups):
        m = vecs[g == label].mean(axis=0)
        n = np.linalg.norm(m)
        out[label] = m / n if n > 0 else m
    return out


def cross_assign_rate(vecs_a: np.ndarray, cent_a: np.ndarray, cent_b: np.ndarray) -> float:
    """Fraction of A's sessions strictly closer (cosine) to B's centroid than to
    A's own — the rate at which A would be confused for B in this space."""
    if len(vecs_a) == 0:
        return 0.0
    return float(((vecs_a @ cent_b) > (vecs_a @ cent_a)).mean())


def pair_report(emb_cents: dict, tfidf_cents: dict,
                emb_by_group: dict, tfidf_by_group: dict,
                pairs: list[tuple[str, str]], anchor_cos: dict) -> list[dict]:
    rows = []
    for a, b in pairs:
        if a not in emb_cents or b not in emb_cents:
            continue
        rows.append({
            "a": a, "b": b,
            "anchor_emb_cos": anchor_cos.get((a, b)),
            "sample_emb_cos": round(float(emb_cents[a] @ emb_cents[b]), 4),
            "tfidf_cos": round(float(tfidf_cents[a] @ tfidf_cents[b]), 4),
            "emb_cross_assign_a_to_b": round(
                cross_assign_rate(emb_by_group[a], emb_cents[a], emb_cents[b]), 4),
            "tfidf_cross_assign_a_to_b": round(
                cross_assign_rate(tfidf_by_group[a], tfidf_cents[a], tfidf_cents[b]), 4),
            "emb_cross_assign_b_to_a": round(
                cross_assign_rate(emb_by_group[b], emb_cents[b], emb_cents[a]), 4),
            "tfidf_cross_assign_b_to_a": round(
                cross_assign_rate(tfidf_by_group[b], tfidf_cents[b], tfidf_cents[a]), 4),
            "n_a": len(emb_by_group[a]), "n_b": len(emb_by_group[b]),
        })
    return rows


# ---------------------------------------------------------------------------
# Live-ES IO
# ---------------------------------------------------------------------------
def top_playbook_ids(es, index: str, filt: list[dict], size: int) -> list[str]:
    r = es.search(index=index, size=0, query={"bool": {"filter": filt}},
                  aggs={"pb": {"terms": {"field": _PB_FIELD, "size": size}}})
    return [b["key"] for b in r["aggregations"]["pb"]["buckets"]]


def sample_playbook(es, index: str, filt: list[dict], pb: str, n: int, seed: int):
    """Up to `n` (embedding, command_set) tuples for one playbook id."""
    base = {"bool": {"filter": [*filt, {"term": {_PB_FIELD: pb}}]}}
    embs, sets, seen, batch = [], [], set(), 0
    while len(embs) < n:
        take = min(n - len(embs), _MAX_WINDOW)
        q = {"function_score": {"query": base,
                                "random_score": {"seed": seed, "field": "_seq_no"},
                                "boost_mode": "replace"}}
        resp = es.search(index=index, size=take, _source=[_EMB_FIELD, _CMDSET_FIELD],
                         query=q, sort=[{"_score": "desc"}])
        hits = resp["hits"]["hits"]
        if not hits:
            break
        new = 0
        for h in hits:
            if h["_id"] in seen:
                continue
            seen.add(h["_id"])
            s = _session_block(h["_source"])
            emb = s.get("embedding")
            if not emb:
                continue
            embs.append(emb)
            sets.append(list(s.get("command_set") or []))
            new += 1
        batch += 1
        seed += 1
        if new == 0 or len(hits) < take:
            break
    return embs, sets


def run(es, idx, cmd_idx, anch_idx, filt, *, n_families, per_pb, family_tau,
        seed, explicit_pairs):
    anchor_ids, anchors = load_anchors(es, anch_idx)
    id_to_idx = {a: i for i, a in enumerate(anchor_ids)}

    targets = list(dict.fromkeys(top_playbook_ids(es, idx, filt, n_families)))
    for a, b in explicit_pairs:
        for pb in (a, b):
            if pb not in targets and pb in id_to_idx:
                targets.append(pb)

    emb_rows, all_sets, groups = [], [], []
    for pb in targets:
        embs, sets = sample_playbook(es, idx, filt, pb, per_pb, seed)
        if len(embs) < 5:
            continue
        emb_rows.extend(embs)
        all_sets.extend(sets)
        groups.extend([pb] * len(embs))
    if not groups:
        return {"error": "no playbook sessions sampled"}

    emb_mat = _l2(np.array(emb_rows, dtype=np.float32))
    hash_to_cluster = pull_hash_to_cluster(es, cmd_idx, page_size=5000)
    bag_texts = build_bag_texts(all_sets, hash_to_cluster)
    tfidf_mat = compute_lexical_features(bag_texts, n_components=_BAG_SVD_COMPONENTS)
    if tfidf_mat.shape[1] < 2:
        return {"error": "TF-IDF produced a degenerate (empty-vocab) block"}

    emb_cents = group_centroids(emb_mat, groups)
    tfidf_cents = group_centroids(tfidf_mat, groups)
    g = np.asarray(groups)
    emb_by_group = {pb: emb_mat[g == pb] for pb in emb_cents}
    tfidf_by_group = {pb: tfidf_mat[g == pb] for pb in tfidf_cents}

    # anchor-to-anchor canonical embedding cosine for any pair we report
    def acos(a, b):
        if a in id_to_idx and b in id_to_idx:
            return round(float(anchors[id_to_idx[a]] @ anchors[id_to_idx[b]]), 4)
        return None

    present = list(emb_cents)
    auto_pairs = [(a, b) for a, b in itertools.combinations(present, 2)
                  if (a in id_to_idx and b in id_to_idx
                      and float(anchors[id_to_idx[a]] @ anchors[id_to_idx[b]]) >= family_tau)]
    pairs = list(dict.fromkeys(explicit_pairs + auto_pairs))
    anchor_cos = {(a, b): acos(a, b) for a, b in pairs}
    rows = pair_report(emb_cents, tfidf_cents, emb_by_group, tfidf_by_group, pairs, anchor_cos)

    # headline: of the embedding-close pairs, how many does TF-IDF separate?
    close = [r for r in rows if (r["anchor_emb_cos"] or 0) >= family_tau]
    separated = [r for r in close if r["tfidf_cos"] < family_tau]
    return {
        "n_anchors": len(anchor_ids),
        "family_tau": family_tau,
        "n_playbooks_sampled": len(present),
        "n_sessions": len(groups),
        "tfidf_dims": int(tfidf_mat.shape[1]),
        "embedding_close_pairs": len(close),
        "tfidf_separated_pairs": len(separated),
        "mean_tfidf_cos_on_close_pairs": (
            round(float(np.mean([r["tfidf_cos"] for r in close])), 4) if close else None),
        "pairs": rows,
    }


def render_md(report, meta) -> str:
    L = ["# Experiment 3 — TF-IDF separation of embedding-close behaviours\n",
         (f"_Captured {meta['captured_at']}. classification={meta['classification']}, "
          f"family_tau={report.get('family_tau')}._\n")]
    if report.get("error"):
        L.append(f"**{report['error']}.** On the untagged corpus the public-only filter "
                 "returns 0 docs; operator may re-run with `--allow-unclassified`.\n")
        return "\n".join(L)
    L.append(f"- sampled {report['n_sessions']} sessions across "
             f"{report['n_playbooks_sampled']} playbooks; TF-IDF dims "
             f"{report['tfidf_dims']}\n")
    L.append(f"- **embedding-close pairs** (anchor cos ≥ {report['family_tau']}): "
             f"{report['embedding_close_pairs']}; of those, **TF-IDF separates "
             f"{report['tfidf_separated_pairs']}** (tfidf_cos < family_tau). "
             f"mean tfidf_cos on close pairs: {report['mean_tfidf_cos_on_close_pairs']}\n")
    L.append("\n## Pairs (emb cos vs tfidf cos; cross-assign = confusion rate)\n")
    L.append("| a | b | anchor emb | sample emb | tfidf | emb x-assign a→b | tfidf x-assign a→b | n_a | n_b |")
    L.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for r in report["pairs"]:
        L.append(f"| {r['a']} | {r['b']} | {r['anchor_emb_cos']} | {r['sample_emb_cos']} "
                 f"| {r['tfidf_cos']} | {r['emb_cross_assign_a_to_b']} "
                 f"| {r['tfidf_cross_assign_a_to_b']} | {r['n_a']} | {r['n_b']} |")
    L.append("\n## Reading it\n")
    L.append("For an embedding-close pair: tfidf_cos **low** + tfidf x-assign **low** ⇒ "
             "TF-IDF separates a behaviour the embedding conflates (representation limit; "
             "TF-IDF is the better substrate / 0.94–0.98-band secondary signal). tfidf_cos "
             "**also high** ⇒ genuinely the same behaviour ⇒ consolidate; embedding isn't "
             "the limiter on this pair.\n")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--families", type=int, default=12,
                    help="sample the N largest playbooks (auto pairs come from these)")
    ap.add_argument("--per-pb", type=int, default=1500, help="max sessions per playbook")
    ap.add_argument("--family-tau", type=float, default=None,
                    help="embedding-close cutoff (default: prod playbook_merge_threshold)")
    ap.add_argument("--pairs", default=_DEFAULT_ABSORBER_PAIRS,
                    help="comma-separated a:b playbook-id pairs always reported "
                         "(default: the Experiment-2 absorber pair)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--allow-unclassified", action="store_true",
                    help="OPERATOR ONLY: drop the public-only filter. Agent never sets it.")
    ap.add_argument("--out-dir", default="eval/results")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands
    anch_idx = cfg.elasticsearch.indexes.cowrie.playbook_anchors
    prod_tau = float(getattr(cfg.session, "playbook_merge_threshold", 0.96))
    family_tau = args.family_tau if args.family_tau is not None else prod_tau
    explicit_pairs = [tuple(p.split(":", 1)) for p in args.pairs.split(",") if ":" in p]

    emb_exists = {"exists": {"field": _EMB_FIELD}}
    pb_exists = {"exists": {"field": _PB_FIELD}}
    if args.allow_unclassified:
        print("WARNING: --allow-unclassified set; scanning WITHOUT the public-only "
              "filter (operator-authorised).", file=sys.stderr)
        filt = [emb_exists, pb_exists]
        classification = "unclassified-included"
    else:
        filt = [releasable_filter(cfg), emb_exists, pb_exists]
        classification = "public-only"

    report = run(es, idx, cmd_idx, anch_idx, filt, n_families=args.families,
                 per_pb=args.per_pb, family_tau=family_tau, seed=args.seed,
                 explicit_pairs=explicit_pairs)

    meta = {
        "captured_at": datetime.now(UTC).isoformat(),
        "classification": classification,
        "sessions_index": idx,
        "tfidf_input": "command-cluster-id bag (build_bag_texts)",
        "seed": args.seed,
    }
    report.setdefault("family_tau", family_tau)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = out_dir / f"exp-tfidf-separation-{ts}"
    stem.with_suffix(".json").write_text(json.dumps({"meta": meta, "report": report}, indent=2))
    stem.with_suffix(".md").write_text(render_md(report, meta))
    print(render_md(report, meta))
    print(f"\nwrote {stem}.json / .md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
