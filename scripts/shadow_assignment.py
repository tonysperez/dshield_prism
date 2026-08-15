"""I2 — shadow validation of the Option-A assignment algorithm over the live corpus.

Runs the FULL assignment (`enrich.sources.cowrie.assignment.assign_batch`: embedding
nearest-anchor + the TF-IDF band secondary signal) against the pinned anchor library,
and reports how it behaves vs the current `playbook_id` — the last check before any
pipeline change. Read-only; aggregates only. See handoff plan §5f (increment I2).

Method (per anchor, train/test split so the test sessions don't build their own
centroids):
  * pinned `anchor_centroid` (post-consolidation — retired anchors auto-drop) is the
    embedding prototype;
  * a TRAIN slice of each anchor's sessions builds that anchor's TF-IDF centroid
    (the I3 artifact, approximated here from a live sample);
  * a held-out TEST slice is assigned against the library and scored.

Reports on TEST: status mix (assigned/novel), the band breakdown (confident /
band-confirmed / band-rejected-as-conflation), agreement with the true anchor, and the
novel-pool rate (the only input HDBSCAN keeps post-cutover).

Privacy: public-only filter BY DEFAULT (0 docs on the untagged corpus);
`--allow-unclassified` is an OPERATOR decision. Emits aggregates only.

Run from repo root via the console venv:
    console/.venv/bin/python scripts/shadow_assignment.py --per-anchor 400
"""
from __future__ import annotations

import argparse
import json
import sys
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
from enrich.sources.cowrie.assignment import ASSIGNED, NOVEL, assign_batch

_S = "dshield.cowrie.enrichment.session"
_PB_FIELD = f"{_S}.playbook_id"
_EMB_FIELD = f"{_S}.embedding"


def run(es, idx, cmd_idx, anch_idx, filt, *, per_anchor, test_frac, tau,
        confident_tau, tfidf_tau, seed):
    anchor_ids, anchor_emb = load_anchors(es, anch_idx)
    if anchor_emb.shape[0] == 0:
        return {"error": "no anchors"}

    train_emb, train_sets, train_pb = [], [], []
    test_emb, test_sets, test_pb = [], [], []
    for pb in anchor_ids:
        embs, sets = sample_playbook(es, idx, filt, pb, per_anchor, seed)
        if len(embs) < 4:
            continue
        cut = max(1, int(len(embs) * (1.0 - test_frac)))
        for e, s in zip(embs[:cut], sets[:cut], strict=False):
            train_emb.append(e); train_sets.append(s); train_pb.append(pb)
        for e, s in zip(embs[cut:], sets[cut:], strict=False):
            test_emb.append(e); test_sets.append(s); test_pb.append(pb)
    if not test_emb:
        return {"error": "no test sessions sampled"}

    # one TF-IDF fit over train+test; anchor TF-IDF centroids from TRAIN only
    hash_to_cluster = pull_hash_to_cluster(es, cmd_idx, page_size=5000)
    n_train = len(train_emb)
    tfidf_all = compute_lexical_features(
        build_bag_texts(train_sets + test_sets, hash_to_cluster),
        n_components=_BAG_SVD_COMPONENTS)
    has_tfidf = tfidf_all.shape[1] >= 2
    tfidf_train, tfidf_test = tfidf_all[:n_train], tfidf_all[n_train:]
    anchor_tfidf = group_centroids(tfidf_train, train_pb) if has_tfidf else {}

    test_emb_mat = _l2(np.array(test_emb, dtype=np.float32))

    def tfidf_cos(i, a):
        c = anchor_tfidf.get(anchor_ids[a])
        return float(tfidf_test[i] @ c) if (has_tfidf and c is not None) else None

    res = assign_batch(test_emb_mat, anchor_emb, anchor_ids, tau=tau,
                       confident_tau=confident_tau, tfidf_tau=tfidf_tau,
                       tfidf_cos=tfidf_cos)

    n = len(res)
    assigned = [r for r in res if r.status == ASSIGNED]
    novel = [r for r in res if r.status == NOVEL]
    in_band = [r for r in res if tau <= r.cosine < confident_tau]
    band_confirmed = [r for r in in_band if r.status == ASSIGNED]
    band_rejected = [r for r in in_band if r.status == NOVEL]
    confident = [r for r in res if r.cosine >= confident_tau]
    agree = sum(1 for r, tp in zip(res, test_pb, strict=False)
                if r.status == ASSIGNED and r.playbook_id == tp)

    def rate(x, d):
        return round(x / d, 4) if d else None

    return {
        "n_anchors": len(anchor_ids), "tfidf_available": has_tfidf,
        "params": {"tau": tau, "confident_tau": confident_tau, "tfidf_tau": tfidf_tau,
                   "per_anchor": per_anchor, "test_frac": test_frac},
        "n_train": n_train, "n_test": n,
        "assigned_rate": rate(len(assigned), n),
        "novel_rate": rate(len(novel), n),
        "agreement_on_assigned": rate(agree, len(assigned)),
        "confident_rate": rate(len(confident), n),
        "band_rate": rate(len(in_band), n),
        "band_confirmed": len(band_confirmed),
        "band_rejected_as_conflation": len(band_rejected),
        "novel_pool_rate": rate(len(novel), n),
    }


def render_md(report, meta) -> str:
    L = ["# Shadow assignment (I2) — Option-A algorithm vs current labels\n",
         f"_Captured {meta['captured_at']}. classification={meta['classification']}._\n"]
    if report.get("error"):
        L.append(f"**{report['error']}.** Untagged corpus → public-only filter returns 0; "
                 "operator may re-run with `--allow-unclassified`.\n")
        return "\n".join(L)
    p = report["params"]
    L.append(f"- {report['n_test']} test sessions vs {report['n_anchors']} anchors "
             f"(τ={p['tau']}, confident={p['confident_tau']}, tfidf_τ={p['tfidf_tau']}; "
             f"tfidf_available={report['tfidf_available']})\n")
    L.append(f"- **assigned {report['assigned_rate']} / novel {report['novel_rate']}**; "
             f"agreement on assigned **{report['agreement_on_assigned']}**\n")
    L.append(f"- confident {report['confident_rate']} | band {report['band_rate']} "
             f"(confirmed {report['band_confirmed']}, "
             f"rejected-as-conflation {report['band_rejected_as_conflation']})\n")
    L.append(f"- **novel-pool rate {report['novel_pool_rate']}** — the only input HDBSCAN "
             "keeps after cutover\n")
    L.append("\n## Reading it (cutover criteria, plan §5f)\n")
    L.append("Cut over when agreement ≳0.94, novel-pool small + plausible, and the band "
             "secondary signal rejects conflations without inflating novel. Compare against "
             "Experiment 1 (agreement 0.94 tau-free, false-novel 2.5% @0.94).\n")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--per-anchor", type=int, default=400)
    ap.add_argument("--test-frac", type=float, default=0.5)
    ap.add_argument("--tau", type=float, default=0.94)
    ap.add_argument("--confident-tau", type=float, default=0.98)
    ap.add_argument("--tfidf-tau", type=float, default=0.80)
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
                 test_frac=args.test_frac, tau=args.tau, confident_tau=args.confident_tau,
                 tfidf_tau=args.tfidf_tau, seed=args.seed)

    meta = {"captured_at": datetime.now(UTC).isoformat(),
            "classification": classification, "sessions_index": idx}
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = out_dir / f"shadow-assignment-{ts}"
    stem.with_suffix(".json").write_text(json.dumps({"meta": meta, "report": report}, indent=2))
    stem.with_suffix(".md").write_text(render_md(report, meta))
    print(render_md(report, meta))
    print(f"\nwrote {stem}.json / .md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
