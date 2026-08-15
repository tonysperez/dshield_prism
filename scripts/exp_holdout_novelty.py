"""Experiment 2 — held-out novelty (true OOD) test for the prototype-assignment
reframe (Option A). The follow-up Experiment 1 structurally cannot answer.

Experiment 1 showed nearest-anchor assignment reproduces the current playbook
label ~94% of the time — but the anchors were minted by the current method, so
that says nothing about whether **genuinely-new behaviour is detected as novel**.
This simulates "new behaviour" by removing a behaviour's whole prototype family
from the library and asking whether its sessions are then flagged novel.

Procedure, per held-out family:
  1. Pick a seed anchor (auto: the largest by session count, or --seed-anchor).
  2. Family = the seed + every anchor within `--family-tau` cosine of it (the
     near-twin group) — removing the whole family so absorption by a twin can't
     mask the test.
  3. Hold the family out → reduced library S = all anchors minus the family.
  4. Sample sessions whose current playbook_id is in the family (the behaviour's
     own sessions = the OOD ground truth).
  5. Assign each against S; per tau report:
       - novelty_recall  = fraction with max_cos(S) < tau  (correctly novel)
       - absorbed_rate   = 1 - recall                      (snapped to a survivor)
     plus the nearest-surviving-cosine histogram and the top absorbing anchors
     (a different family by construction — absorption there = a real OOD miss).

A good OOD detector has high novelty_recall at the same tau where Experiment 1
had low false-novel. The two together are the novelty detector's ROC.

Read-only; emits aggregates only. Same data-privacy boundary as Experiment 1:
public-only filter BY DEFAULT (0 docs on the untagged corpus); `--allow-unclassified`
is an OPERATOR decision, never set by the agent. See
docs/decisions.md and
eval/results/exp-prototype-assignment-verdict.md.

Run from repo root via the console venv:
    console/.venv/bin/python scripts/exp_holdout_novelty.py --families 5
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # scripts/ — reuse Exp 1

from exp_prototype_assignment import _l2, load_anchors

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_PB_FIELD = f"{_S}.playbook_id"
_EMB_FIELD = f"{_S}.embedding"
_MAX_WINDOW = 10000
_DEFAULT_THRESHOLDS = [0.80, 0.85, 0.88, 0.90, 0.92, 0.94, 0.96, 0.97, 0.98, 0.99]
_MIN_FAMILY_SESSIONS = 30  # below this a per-family recall is too noisy to weight


def _session_block(src: dict) -> dict:
    return (
        ((src.get("dshield") or {}).get("cowrie") or {})
        .get("enrichment", {})
        .get("session", {})
    )


# ---------------------------------------------------------------------------
# Pure scoring (smoke-tested)
# ---------------------------------------------------------------------------
def select_family(anchors: np.ndarray, seed_idx: int, family_tau: float) -> list[int]:
    """Indices of every anchor within `family_tau` cosine of the seed (incl. the
    seed itself). Anchors are unit vectors, so dot == cosine."""
    cos = anchors @ anchors[seed_idx]
    return [int(i) for i in np.where(cos >= family_tau)[0]]


def score_holdout(held_embs: np.ndarray, retained_ids: list[str],
                  retained: np.ndarray, thresholds: list[float],
                  prod_tau: float) -> dict:
    """Assign held-out-behaviour sessions against the reduced library and measure
    how reliably they read as novel. `held_embs` is (n, d), not yet normalised."""
    embs = _l2(np.asarray(held_embs, dtype=np.float32))
    sims = embs @ retained.T                 # (n, |S|)
    max_cos = sims.max(axis=1)
    nn_idx = sims.argmax(axis=1)
    n = len(embs)

    sweep = []
    for tau in thresholds:
        novel = max_cos < tau
        sweep.append({
            "tau": tau,
            "novelty_recall": round(float(novel.mean()), 4),
            "absorbed_rate": round(float((~novel).mean()), 4),
        })

    # who absorbs the misses at prod tau, and how close (a different family by
    # construction → absorption here is a genuine OOD miss).
    absorbed = max_cos >= prod_tau
    counts: dict[str, list[float]] = {}
    for i in np.where(absorbed)[0]:
        aid = retained_ids[int(nn_idx[i])]
        counts.setdefault(aid, []).append(float(max_cos[i]))
    top_absorbers = sorted(
        ({"anchor": k, "n": len(v), "mean_cos": round(sum(v) / len(v), 4)}
         for k, v in counts.items()),
        key=lambda d: -d["n"],
    )[:5]

    bins = [0.0, 0.5, 0.7, 0.8, 0.85, 0.9, 0.92, 0.94, 0.96, 0.98, 1.0001]
    hist, _ = np.histogram(max_cos, bins=bins)
    return {
        "n_sessions": n,
        "prod_tau": prod_tau,
        "novelty_recall_at_prod_tau": round(float((max_cos < prod_tau).mean()), 4),
        "nearest_surviving_cos_bins": bins,
        "nearest_surviving_cos_hist": [int(x) for x in hist],
        "top_absorbers_at_prod_tau": top_absorbers,
        "sweep": sweep,
    }


# ---------------------------------------------------------------------------
# Live-ES IO
# ---------------------------------------------------------------------------
def top_playbook_ids(es, index: str, filt: list[dict], size: int) -> list[tuple[str, int]]:
    r = es.search(
        index=index, size=0,
        query={"bool": {"filter": filt}},
        aggs={"pb": {"terms": {"field": _PB_FIELD, "size": size}}},
    )
    return [(b["key"], b["doc_count"]) for b in r["aggregations"]["pb"]["buckets"]]


def sample_family_embeddings(es, index: str, filt: list[dict], family_ids: list[str],
                             n: int, seed: int) -> list[list[float]]:
    """Up to `n` seeded-random session embeddings whose playbook_id is in
    `family_ids`. Emits embeddings only — no other per-session fields."""
    base = {"bool": {"filter": [*filt, {"terms": {_PB_FIELD: family_ids}}]}}
    out: list[list[float]] = []
    seen: set[str] = set()
    batch = 0
    while len(out) < n:
        take = min(n - len(out), _MAX_WINDOW)
        q = {"function_score": {
            "query": base,
            "random_score": {"seed": seed + batch, "field": "_seq_no"},
            "boost_mode": "replace",
        }}
        resp = es.search(index=index, size=take, _source=[_EMB_FIELD], query=q,
                         sort=[{"_score": "desc"}])
        hits = resp["hits"]["hits"]
        if not hits:
            break
        new = 0
        for h in hits:
            if h["_id"] in seen:
                continue
            seen.add(h["_id"])
            emb = _session_block(h["_source"]).get("embedding")
            if emb:
                out.append(emb)
                new += 1
        batch += 1
        if new == 0 or len(hits) < take:
            break
    return out


def run(es, idx: str, anch_idx: str, filt: list[dict], *, n_families: int,
        family_tau: float, sample: int, seed: int, thresholds: list[float],
        prod_tau: float, seed_anchor: str | None) -> dict:
    anchor_ids, anchors = load_anchors(es, anch_idx)
    if anchors.shape[0] == 0:
        return {"error": "no anchors"}
    id_to_idx = {a: i for i, a in enumerate(anchor_ids)}

    # seed selection: explicit, or the largest behaviours by live session count
    if seed_anchor:
        seeds = [id_to_idx[s] for s in seed_anchor.split(",") if s in id_to_idx]
    else:
        sizes = top_playbook_ids(es, idx, filt, size=max(n_families * 4, 40))
        seeds = [id_to_idx[pid] for pid, _ in sizes if pid in id_to_idx]
    size_by_id = dict(top_playbook_ids(es, idx, filt, size=500))

    families = []
    used: set[int] = set()
    for s in seeds:
        if len(families) >= n_families:
            break
        if s in used:
            continue
        members = select_family(anchors, s, family_tau)
        if used.intersection(members):
            continue
        used.update(members)
        member_ids = [anchor_ids[i] for i in members]
        retained_idx = [i for i in range(len(anchor_ids)) if i not in set(members)]
        retained_ids = [anchor_ids[i] for i in retained_idx]
        retained = anchors[retained_idx]
        held = sample_family_embeddings(es, idx, filt, member_ids, sample, seed)
        fam = {
            "seed_anchor": anchor_ids[s],
            "family_anchor_ids": member_ids,
            "family_size_anchors": len(members),
            "retained_anchors": len(retained_ids),
            "sessions_sampled": len(held),
            "approx_family_session_count": sum(
                size_by_id.get(m, 0) for m in member_ids),
        }
        if held and retained.shape[0] > 0:
            fam.update(score_holdout(held, retained_ids, retained, thresholds, prod_tau))
        else:
            fam["error"] = "no held sessions or empty retained library"
        families.append(fam)

    scored = [f for f in families if f.get("sessions_sampled", 0) >= _MIN_FAMILY_SESSIONS
              and "sweep" in f]
    agg = {}
    if scored:
        for tau_i, tau in enumerate(thresholds):
            recalls = [f["sweep"][tau_i]["novelty_recall"] for f in scored]
            agg[str(tau)] = round(float(np.mean(recalls)), 4)
    return {
        "n_anchors": len(anchor_ids),
        "family_tau": family_tau,
        "prod_tau": prod_tau,
        "n_families_scored": len(scored),
        "mean_novelty_recall_by_tau": agg,
        "families": families,
    }


def render_md(report: dict, meta: dict) -> str:
    L = ["# Experiment 2 — held-out novelty (OOD)\n",
         (f"_Captured {meta['captured_at']}. classification={meta['classification']}, "
          f"family_tau={report.get('family_tau')}, prod_tau={report.get('prod_tau')}._\n")]
    if report.get("error") or "families" not in report:
        L.append(f"**{report.get('error', 'no result')}.** On the untagged corpus the "
                 "public-only filter returns 0 docs; operator may re-run with "
                 "`--allow-unclassified`.\n")
        return "\n".join(L)
    if not report["families"]:
        L.append("**No families selected** (0 anchors had public sessions).\n")
        return "\n".join(L)
    agg = report["mean_novelty_recall_by_tau"]
    if agg:
        L.append(f"- **mean novelty recall** across {report['n_families_scored']} "
                 "held-out families, by tau:\n")
        L.append("| tau | mean novelty recall |")
        L.append("|---:|---:|")
        for tau, r in agg.items():
            L.append(f"| {tau} | {r} |")
    L.append("\n## Per family\n")
    for f in report["families"]:
        L.append(f"### seed `{f['seed_anchor']}` "
                 f"(family of {f['family_size_anchors']} anchors, "
                 f"~{f.get('approx_family_session_count')} sessions; "
                 f"sampled {f.get('sessions_sampled')})")
        if "sweep" not in f:
            L.append(f"  _{f.get('error', 'not scored')}_\n")
            continue
        L.append(f"- novelty recall @prod_tau={f['prod_tau']}: "
                 f"**{f['novelty_recall_at_prod_tau']}**")
        L.append(f"- nearest-surviving cosine hist "
                 f"({', '.join(str(b) for b in f['nearest_surviving_cos_bins'])}): "
                 f"{f['nearest_surviving_cos_hist']}")
        if f["top_absorbers_at_prod_tau"]:
            ab = "; ".join(f"{a['anchor']}×{a['n']}@{a['mean_cos']}"
                           for a in f["top_absorbers_at_prod_tau"])
            L.append(f"- top absorbers @prod_tau (different family ⇒ OOD miss): {ab}")
        L.append("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--families", type=int, default=5,
                    help="auto-hold-out the N largest behaviours (by session count)")
    ap.add_argument("--seed-anchor", default=None,
                    help="comma-separated anchor ids to hold out instead of auto")
    ap.add_argument("--family-tau", type=float, default=None,
                    help="cosine radius for the near-twin family (default: prod "
                         "playbook_merge_threshold)")
    ap.add_argument("--sample", type=int, default=3000,
                    help="max session embeddings sampled per held-out family")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--thresholds", default=None)
    ap.add_argument("--allow-unclassified", action="store_true",
                    help="OPERATOR ONLY: drop the public-only filter. The agent "
                         "never sets this.")
    ap.add_argument("--out-dir", default="eval/results")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    anch_idx = cfg.elasticsearch.indexes.cowrie.playbook_anchors
    prod_tau = float(getattr(cfg.session, "playbook_merge_threshold", 0.96))
    family_tau = args.family_tau if args.family_tau is not None else prod_tau
    thresholds = ([float(x) for x in args.thresholds.split(",")]
                  if args.thresholds else _DEFAULT_THRESHOLDS)

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

    report = run(es, idx, anch_idx, filt, n_families=args.families,
                 family_tau=family_tau, sample=args.sample, seed=args.seed,
                 thresholds=thresholds, prod_tau=prod_tau,
                 seed_anchor=args.seed_anchor)

    meta = {
        "captured_at": datetime.now(UTC).isoformat(),
        "classification": classification,
        "sessions_index": idx,
        "anchors_index": anch_idx,
        "requested_sample_per_family": args.sample,
        "seed": args.seed,
    }
    report.setdefault("family_tau", family_tau)
    report.setdefault("prod_tau", prod_tau)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = out_dir / f"exp-holdout-novelty-{ts}"
    stem.with_suffix(".json").write_text(json.dumps({"meta": meta, "report": report}, indent=2))
    stem.with_suffix(".md").write_text(render_md(report, meta))
    print(render_md(report, meta))
    print(f"\nwrote {stem}.json / .md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
