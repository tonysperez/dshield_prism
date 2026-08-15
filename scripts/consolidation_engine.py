"""Consolidation engine (planning pass) — Option A build, step one.

The held-out-novelty experiment (Exp 2) showed the anchor library carries
redundant near-twins (`spb-1b9a`'s sessions absorb into `spb-d0c4`), and the
TF-IDF experiment (Exp 3) showed that some of those absorptions are *genuine*
twins (d0c4, TF-IDF 0.90 → merge) while others are *distinct behaviours the
embedding conflates* (54f5, TF-IDF 0.67 → must NOT merge). This engine turns
those two findings into a consolidation plan:

  1. **Absorption graph (embedding).** Sample each anchor's sessions; for each,
     find its nearest *other* anchor (the anchor it would fall to if its own were
     removed — the Exp-2 hold-out, computed in one pass). Anchor X → Y edge when a
     majority of X's sessions land on Y above τ.
  2. **TF-IDF gate (Exp 3).** Keep an edge only if X and Y are ALSO close in
     TF-IDF (command-cluster-bag) space — accepts true twins, rejects conflations.
  3. **Resolve.** Union-find the surviving edges into groups; the canonical
     prototype per group is the largest by true session count. Everything else is
     an alias to merge into it.

Outputs a **plan** (read-only): the consolidated prototype count, the merge
groups with per-member evidence, and — separately — the edges TF-IDF *rejected*
(embedding wanted to merge, TF-IDF said distinct: the conflated-behaviour pairs
that justify keeping TF-IDF as a secondary signal). It does NOT mutate the live
`playbook_anchors` index; applying merges (re-pointing session playbook_ids,
retiring alias anchors) is a separate, destructive step with its own design.

Same privacy boundary as the experiments: public-only filter BY DEFAULT (0 docs
on the untagged corpus); `--allow-unclassified` is an OPERATOR decision, never
set by the agent. Emits aggregates only (anchor ids, counts, cosines).

Run from repo root via the console venv:
    console/.venv/bin/python scripts/consolidation_engine.py --per-anchor 500
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # scripts/

from cluster_bag_prod import _BAG_SVD_COMPONENTS, build_bag_texts, pull_hash_to_cluster
from exp_prototype_assignment import _l2, load_anchors
from exp_tfidf_separation import group_centroids, sample_playbook

from enrich.classification import releasable_filter
from enrich.clustering import compute_lexical_features
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_PB_FIELD = f"{_S}.playbook_id"
_EMB_FIELD = f"{_S}.embedding"


# ---------------------------------------------------------------------------
# Pure core (smoke-tested)
# ---------------------------------------------------------------------------
def nearest_other(sims: np.ndarray, source_idx: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """For each row (session), the nearest anchor that is NOT its own source
    anchor — i.e. where it would land if its own anchor were held out (Exp 2,
    one pass). Returns (other_idx, other_cos)."""
    s = sims.copy()
    s[np.arange(len(s)), source_idx] = -np.inf
    other_idx = s.argmax(axis=1)
    other_cos = s[np.arange(len(s)), other_idx]
    return other_idx, other_cos


def compute_absorption(source_ids: list[str], target_ids: list[str],
                       target_cos, tau: float, min_sessions: int,
                       min_edge: float) -> dict:
    """Per source anchor X: among its sessions, the fraction that absorb into
    some other anchor above τ, and the FULL distribution of absorbing targets Y
    with rate ≥ `min_edge` (not just the dominant one — so secondary conflations
    and diffuse redundancy surface)."""
    by_src: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for sid, tid, c in zip(source_ids, target_ids, target_cos, strict=False):
        by_src[sid].append((tid, float(c)))
    out: dict[str, dict] = {}
    for X, rows in by_src.items():
        n = len(rows)
        if n < min_sessions:
            out[X] = {"n": n, "small": True, "absorption_rate": None, "targets": []}
            continue
        absorbed = [tid for tid, c in rows if c >= tau]
        cnt = Counter(absorbed)
        targets = [{"target": Y, "rate": round(k / n, 4)}
                   for Y, k in cnt.most_common() if k / n >= min_edge]
        out[X] = {"n": n, "small": False,
                  "absorption_rate": round(len(absorbed) / n, 4),
                  "targets": targets}
    return out


def propose_edges(absorption: dict) -> list[tuple[str, str, float]]:
    """Flatten every (X, Y, rate) absorption edge (already ≥ min_edge filtered in
    compute_absorption). One source can emit several edges (its target spread)."""
    return [(X, t["target"], t["rate"])
            for X, a in absorption.items() if not a["small"]
            for t in a["targets"]]


def select_merges(confirmed: list[dict], merge_min: float) -> tuple[list[dict], list[dict]]:
    """Of the TF-IDF-confirmed edges, the STRONG ones (≥ merge_min) drive merges;
    the weaker confirmed edges are partial overlap — reported, not merged."""
    merges = [e for e in confirmed if e["absorption_rate"] >= merge_min]
    partial = [e for e in confirmed if e["absorption_rate"] < merge_min]
    return merges, partial


def tfidf_gate(edges, tfidf_cos, threshold: float) -> tuple[list[dict], list[dict]]:
    """Split candidate edges into TF-IDF-confirmed (true twins) and rejected
    (embedding wanted to merge, TF-IDF says distinct → conflation)."""
    confirmed, rejected = [], []
    for X, Y, rate in edges:
        c = tfidf_cos(X, Y)
        rec = {"x": X, "y": Y, "absorption_rate": rate,
               "tfidf_cos": (round(c, 4) if c is not None else None)}
        (confirmed if (c is not None and c >= threshold) else rejected).append(rec)
    return confirmed, rejected


def resolve_components(confirmed_edges: list[dict], sizes: dict) -> list[dict]:
    """Union-find the confirmed edges; canonical per component = largest by
    `sizes` (true session count)."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    nodes: set[str] = set()
    for e in confirmed_edges:
        union(e["x"], e["y"])
        nodes.update((e["x"], e["y"]))
    comps: dict[str, list[str]] = defaultdict(list)
    for nd in nodes:
        comps[find(nd)].append(nd)
    groups = []
    for members in comps.values():
        canonical = max(members, key=lambda m: sizes.get(m, 0))
        groups.append({
            "canonical": canonical,
            "canonical_n": sizes.get(canonical, 0),
            "members": sorted(members),
            "n_merged": len(members),
        })
    return sorted(groups, key=lambda g: -g["n_merged"])


# ---------------------------------------------------------------------------
# Live-ES IO
# ---------------------------------------------------------------------------
def anchor_sizes(es, index: str, filt: list[dict], size: int) -> dict[str, int]:
    r = es.search(index=index, size=0, query={"bool": {"filter": filt}},
                  aggs={"pb": {"terms": {"field": _PB_FIELD, "size": size}}})
    return {b["key"]: b["doc_count"] for b in r["aggregations"]["pb"]["buckets"]}


def run(es, idx, cmd_idx, anch_idx, filt, *, per_anchor, tau, merge_min,
        tfidf_threshold, min_sessions, min_edge, seed):
    anchor_ids, anchors = load_anchors(es, anch_idx)
    if anchors.shape[0] == 0:
        return {"error": "no anchors"}
    idx_of = {a: i for i, a in enumerate(anchor_ids)}
    sizes = anchor_sizes(es, idx, filt, size=max(len(anchor_ids) * 2, 500))

    emb_rows, all_sets, source_ids = [], [], []
    for pb in anchor_ids:
        embs, sets = sample_playbook(es, idx, filt, pb, per_anchor, seed)
        emb_rows.extend(embs)
        all_sets.extend(sets)
        source_ids.extend([pb] * len(embs))
    if not source_ids:
        return {"error": "no sessions sampled"}

    emb_mat = _l2(np.array(emb_rows, dtype=np.float32))
    sims = emb_mat @ anchors.T
    src_col = np.array([idx_of[s] for s in source_ids])
    other_idx, other_cos = nearest_other(sims, src_col)
    target_ids = [anchor_ids[i] for i in other_idx]

    absorption = compute_absorption(source_ids, target_ids, other_cos, tau,
                                    min_sessions, min_edge)

    # TF-IDF centroids per anchor (grouped by the anchor we sampled from)
    hash_to_cluster = pull_hash_to_cluster(es, cmd_idx, page_size=5000)
    tfidf_mat = compute_lexical_features(build_bag_texts(all_sets, hash_to_cluster),
                                         n_components=_BAG_SVD_COMPONENTS)
    tfidf_cents = (group_centroids(tfidf_mat, source_ids)
                   if tfidf_mat.shape[1] >= 2 else {})

    def tcos(a, b):
        if a in tfidf_cents and b in tfidf_cents:
            return float(tfidf_cents[a] @ tfidf_cents[b])
        return None

    edges = propose_edges(absorption)
    confirmed, rejected = tfidf_gate(edges, tcos, tfidf_threshold)
    merge_edges, partial_edges = select_merges(confirmed, merge_min)
    groups = resolve_components(merge_edges, sizes)

    merged_away = sum(g["n_merged"] - 1 for g in groups)
    # decorate each alias with the EDGE(S) that pulled it in (source→target +
    # the absorption that actually drove the merge), not its own sink-side rate.
    for g in groups:
        canon = g["canonical"]
        g["aliases"] = []
        for m in g["members"]:
            if m == canon:
                continue
            a = absorption.get(m, {})
            incident = [{"source": e["x"], "target": e["y"],
                         "absorption_rate": e["absorption_rate"], "tfidf_cos": e["tfidf_cos"]}
                        for e in merge_edges if m in (e["x"], e["y"])]
            g["aliases"].append({
                "anchor": m, "n_sampled": a.get("n"), "true_size": sizes.get(m),
                "own_absorption_rate": a.get("absorption_rate"),
                "merge_edges": incident,
                "tfidf_cos_to_canonical": (round(tcos(m, canon), 4)
                                           if tcos(m, canon) is not None else None),
            })

    return {
        "n_anchors": len(anchor_ids),
        "params": {"tau": tau, "merge_min": merge_min, "min_edge": min_edge,
                   "tfidf_threshold": tfidf_threshold, "min_sessions": min_sessions,
                   "per_anchor": per_anchor},
        "n_sessions_sampled": len(source_ids),
        "n_candidate_edges": len(edges),
        "n_confirmed_edges": len(confirmed),
        "n_merge_edges": len(merge_edges),
        "n_merge_groups": len(groups),
        "n_merged_away": merged_away,
        "n_anchors_after": len(anchor_ids) - merged_away,
        "merge_groups": groups,
        "partial_overlap": sorted(partial_edges, key=lambda r: -(r["absorption_rate"] or 0)),
        "rejected_conflations": sorted(rejected, key=lambda r: -(r["absorption_rate"] or 0)),
    }


def render_md(report, meta) -> str:
    L = ["# Consolidation plan (read-only)\n",
         f"_Captured {meta['captured_at']}. classification={meta['classification']}._\n"]
    if report.get("error"):
        L.append(f"**{report['error']}.** On the untagged corpus the public-only filter "
                 "returns 0 docs; operator may re-run with `--allow-unclassified`.\n")
        return "\n".join(L)
    p = report["params"]
    L.append(f"- **{report['n_anchors']} anchors → {report['n_anchors_after']} prototypes** "
             f"({report['n_merge_groups']} merge groups absorb "
             f"{report['n_merged_away']} aliases)\n")
    L.append(f"- params: τ={p['tau']}, merge_min={p['merge_min']}, "
             f"tfidf_threshold={p['tfidf_threshold']}, min_sessions={p['min_sessions']}, "
             f"per_anchor={p['per_anchor']}; sampled {report['n_sessions_sampled']} sessions\n")
    L.append(f"- edges: {report['n_candidate_edges']} candidate → "
             f"{report['n_confirmed_edges']} TF-IDF-confirmed "
             f"({report['n_merge_edges']} strong enough to merge); "
             f"{len(report['rejected_conflations'])} rejected as conflations; "
             f"{len(report['partial_overlap'])} partial overlap\n")
    L.append("\n## Merge groups (canonical ← aliases)\n")
    for g in report["merge_groups"]:
        L.append(f"### `{g['canonical']}` (n≈{g['canonical_n']}) ← {g['n_merged'] - 1} alias(es)")
        L.append("| alias | true size | own absorption | merge edge (source→target @ rate, tfidf) | tfidf→canonical |")
        L.append("|---|---:|---:|---|---:|")
        for a in g["aliases"]:
            ev = "; ".join(f"{e['source']}→{e['target']} @{e['absorption_rate']}/{e['tfidf_cos']}"
                           for e in a["merge_edges"]) or "—"
            L.append(f"| {a['anchor']} | {a['true_size']} | {a['own_absorption_rate']} "
                     f"| {ev} | {a['tfidf_cos_to_canonical']} |")
        L.append("")
    L.append("## Rejected conflations (embedding wanted merge, TF-IDF said distinct)\n")
    L.append("_These pairs are why TF-IDF is the secondary signal — do NOT merge. "
             "Includes secondary-target absorptions, not just dominant ones._\n")
    L.append("| x | y | absorption | tfidf cos |")
    L.append("|---|---|---:|---:|")
    for r in report["rejected_conflations"]:
        L.append(f"| {r['x']} | {r['y']} | {r['absorption_rate']} | {r['tfidf_cos']} |")
    if report["partial_overlap"]:
        L.append("\n## Partial overlap (TF-IDF-close but below merge_min — same behaviour, not dominant)\n")
        L.append("| x | y | absorption | tfidf cos |")
        L.append("|---|---|---:|---:|")
        for r in report["partial_overlap"]:
            L.append(f"| {r['x']} | {r['y']} | {r['absorption_rate']} | {r['tfidf_cos']} |")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--per-anchor", type=int, default=500, help="max sessions sampled per anchor")
    ap.add_argument("--tau", type=float, default=None,
                    help="absorption cosine threshold (default: prod playbook_merge_threshold)")
    ap.add_argument("--merge-min", type=float, default=0.5,
                    help="min fraction of an anchor's sessions absorbing into Y to MERGE X→Y")
    ap.add_argument("--min-edge", type=float, default=0.15,
                    help="min absorption fraction to record an edge at all (catches "
                         "secondary conflations + diffuse redundancy below merge_min)")
    ap.add_argument("--tfidf-threshold", type=float, default=0.80,
                    help="min TF-IDF centroid cosine to confirm a merge (Exp 3: 0.90 keep / 0.67 reject)")
    ap.add_argument("--min-sessions", type=int, default=20,
                    help="skip anchors with fewer sampled sessions as merge sources")
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
    tau = args.tau if args.tau is not None else float(
        getattr(cfg.session, "playbook_merge_threshold", 0.96))

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

    report = run(es, idx, cmd_idx, anch_idx, filt, per_anchor=args.per_anchor,
                 tau=tau, merge_min=args.merge_min, tfidf_threshold=args.tfidf_threshold,
                 min_sessions=args.min_sessions, min_edge=args.min_edge, seed=args.seed)

    meta = {"captured_at": datetime.now(UTC).isoformat(),
            "classification": classification, "sessions_index": idx}
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = out_dir / f"consolidation-plan-{ts}"
    stem.with_suffix(".json").write_text(json.dumps({"meta": meta, "report": report}, indent=2))
    stem.with_suffix(".md").write_text(render_md(report, meta))
    print(render_md(report, meta))
    print(f"\nwrote {stem}.json / .md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
