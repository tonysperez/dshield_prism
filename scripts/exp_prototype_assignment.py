"""Experiment 1 for the prototype-assignment reframe (Option A).

Question: if the write-once playbook-anchor library were the *authority* and we
assigned each session directly to its nearest anchor (cosine), how well would
that reproduce the current HDBSCAN-mediated `playbook_id`, and what fraction of
the corpus becomes "known" (skips clustering) at each threshold tau?

Two arms, scored on a random sample of live session rollups:

  * current      — the `playbook_id` already on the doc (HDBSCAN-in-window →
                   merge → centroid→anchor). No playbook_id = current "novel".
  * prototype-A  — nearest anchor by cosine(session embedding, anchor_centroid);
                   max_cos >= tau → that anchor's playbook_id, else "novel".

Read-only. Emits **corpus-level aggregates only** — never any per-session
record — to eval/results/. See docs/handoff-prototype-assignment-plan.md §5.

Data-privacy boundary (binding; see CLAUDE.md): session rollups are per-sensor
cowrie data. This applies `releasable_filter(cfg)` (public-only) BY DEFAULT.
On the pre-tagging corpus that returns 0 docs (untagged == confidential,
fail-safe). `--allow-unclassified` widens the scan to the whole corpus; that is
an OPERATOR decision over their own box (mirrors the G-phase prod scripts), not
something the agent sets. Even then the script prints only aggregates.

Run from repo root via the console venv:
    console/.venv/bin/python scripts/exp_prototype_assignment.py --sample 10000
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_SOURCE_FIELDS = [
    f"{_S}.embedding",
    f"{_S}.playbook_id",
    f"{_S}.cluster.is_outlier",
    f"{_S}.cluster.novelty_score",
    f"{_S}.dominant_intent",
    f"{_S}.command_signature",
]
_MAX_WINDOW = 10000
_DEFAULT_THRESHOLDS = [0.80, 0.85, 0.88, 0.90, 0.92, 0.94, 0.96, 0.97, 0.98, 0.99]


def _session_block(src: dict) -> dict:
    return (
        ((src.get("dshield") or {}).get("cowrie") or {})
        .get("enrichment", {})
        .get("session", {})
    )


def _l2(mat: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms = np.where(norms == 0.0, 1.0, norms)
    return mat / norms


def load_anchors(es, index: str) -> tuple[list[str], np.ndarray]:
    """Every pinned anchor: (playbook_ids, L2-normalised centroid matrix)."""
    resp = es.search(
        index=index,
        size=10000,
        _source=["playbook_id", "anchor_centroid"],
        query={"exists": {"field": "anchor_centroid"}},
    )
    ids: list[str] = []
    vecs: list[list[float]] = []
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        cen = s.get("anchor_centroid")
        if not cen:
            continue
        ids.append(s.get("playbook_id") or h["_id"])
        vecs.append(cen)
    if not vecs:
        return ids, np.zeros((0, 0), dtype=np.float32)
    return ids, _l2(np.array(vecs, dtype=np.float32))


def sample_sessions(es, index: str, filt: list[dict], n: int, seed: int) -> list[dict]:
    """Approximately-uniform random sample of up to `n` session blocks via
    seeded random_score. Pages with successive seeds when n exceeds the result
    window. Returns the per-session dicts we score (no raw command content)."""
    want = n
    out: list[dict] = []
    seen: set[str] = set()
    batch = 0
    base_query = {"bool": {"filter": filt}}
    while len(out) < want:
        take = min(want - len(out), _MAX_WINDOW)
        q = {
            "function_score": {
                "query": base_query,
                "random_score": {"seed": seed + batch, "field": "_seq_no"},
                "boost_mode": "replace",
            }
        }
        resp = es.search(
            index=index, size=take, _source=_SOURCE_FIELDS, query=q,
            sort=[{"_score": "desc"}],
        )
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
            cl = s.get("cluster") or {}
            out.append({
                "emb": emb,
                "current_pb": s.get("playbook_id") or None,
                "is_outlier": bool(cl.get("is_outlier")),
                "novelty": cl.get("novelty_score"),
                "intent": s.get("dominant_intent"),
                "signature": s.get("command_signature"),
            })
            new += 1
        batch += 1
        if new == 0 or len(hits) < take:
            break
    return out


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def score(samples: list[dict], anchor_ids: list[str], anchors: np.ndarray,
          thresholds: list[float], prod_tau: float) -> dict:
    embs = _l2(np.array([s["emb"] for s in samples], dtype=np.float32))
    # cosine of every session to every anchor → nearest anchor + its cosine
    sims = embs @ anchors.T                      # (n_sessions, n_anchors)
    nn_idx = sims.argmax(axis=1)
    max_cos = sims.max(axis=1)
    nn_pb = np.array([anchor_ids[i] for i in nn_idx])

    cur_pb = np.array([s["current_pb"] or "" for s in samples])
    cur_assigned = cur_pb != ""                  # current method gave a playbook
    cur_novel = ~cur_assigned
    n = len(samples)

    # tau-independent: among current-assigned, does the *nearest* anchor already
    # equal the current label (regardless of any threshold)?
    nearest_eq_current = (
        _rate(int((nn_pb[cur_assigned] == cur_pb[cur_assigned]).sum()),
              int(cur_assigned.sum()))
    )

    sweep = []
    for tau in thresholds:
        assigned = max_cos >= tau
        both = assigned & cur_assigned
        sweep.append({
            "tau": tau,
            "known_rate": _rate(int(assigned.sum()), n),
            "novel_rate": _rate(int((~assigned).sum()), n),
            # of sessions both arms assign, do the labels match?
            "agreement_on_assigned": _rate(
                int((nn_pb[both] == cur_pb[both]).sum()), int(both.sum())),
            # of current-novel sessions, fraction A also calls novel
            "current_novel_recall": _rate(
                int((~assigned & cur_novel).sum()), int(cur_novel.sum())),
            # of current-assigned sessions, fraction A wrongly calls novel
            "false_novel_rate": _rate(
                int((~assigned & cur_assigned).sum()), int(cur_assigned.sum())),
        })

    # assignment concentration across anchors (heavy-tail check on 157 anchors)
    counts = np.bincount(nn_idx, minlength=len(anchor_ids))
    order = np.argsort(counts)[::-1]
    top10 = int(counts[order[:10]].sum())

    # cosine-to-nearest histogram, split by current arm (does a separating tau
    # exist?). Coarse bins, counts only.
    bins = [0.0, 0.5, 0.7, 0.8, 0.85, 0.9, 0.92, 0.94, 0.96, 0.98, 1.0001]
    def _hist(mask):
        h, _ = np.histogram(max_cos[mask], bins=bins)
        return [int(x) for x in h]

    return {
        "n_scored": n,
        "n_anchors": len(anchor_ids),
        "current_assigned": int(cur_assigned.sum()),
        "current_novel": int(cur_novel.sum()),
        "current_outlier": int(sum(1 for s in samples if s["is_outlier"])),
        "nearest_eq_current_rate": nearest_eq_current,
        "prod_tau": prod_tau,
        "headline_known_rate_at_prod_tau": _rate(
            int((max_cos >= prod_tau).sum()), n),
        "anchor_concentration": {
            "n_anchors_ever_nearest": int((counts > 0).sum()),
            "top10_share_of_assignments": _rate(top10, n),
        },
        "cosine_hist_bins": bins,
        "cosine_hist_current_assigned": _hist(cur_assigned),
        "cosine_hist_current_novel": _hist(cur_novel),
        "sweep": sweep,
    }


def render_md(report: dict, meta: dict) -> str:
    L = []
    L.append("# Experiment 1 — prototype-assignment vs current method\n")
    L.append(f"_Captured {meta['captured_at']}. classification={meta['classification']}._\n")
    if report is None:
        L.append("**No scorable sessions.** The public-only filter returned 0 "
                 "docs — the live corpus is untagged (fail-safe: untagged == "
                 "confidential). Re-ingest with `dshield.classification` tags, or "
                 "the operator may re-run with `--allow-unclassified`.\n")
        return "\n".join(L)
    L.append(f"- scored: **{report['n_scored']}** sessions vs "
             f"**{report['n_anchors']}** anchors\n")
    L.append(f"- current method assigned a playbook to "
             f"{report['current_assigned']} / {report['n_scored']} "
             f"({_rate(report['current_assigned'], report['n_scored'])}); "
             f"current-novel {report['current_novel']}; "
             f"current-outlier {report['current_outlier']}\n")
    L.append(f"- **nearest anchor already == current label** (tau-free, among "
             f"current-assigned): **{report['nearest_eq_current_rate']}**\n")
    L.append(f"- **headline:** at prod tau={report['prod_tau']}, known_rate = "
             f"**{report['headline_known_rate_at_prod_tau']}** "
             f"(share that would skip HDBSCAN)\n")
    conc = report["anchor_concentration"]
    L.append(f"- concentration: {conc['n_anchors_ever_nearest']} / "
             f"{report['n_anchors']} anchors are ever-nearest; top-10 cover "
             f"{conc['top10_share_of_assignments']} of assignments\n")
    L.append("\n## Threshold sweep\n")
    L.append("| tau | known | novel | agree(assigned) | "
             "current-novel recall | false-novel |")
    L.append("|---:|---:|---:|---:|---:|---:|")
    for r in report["sweep"]:
        L.append(f"| {r['tau']} | {r['known_rate']} | {r['novel_rate']} | "
                 f"{r['agreement_on_assigned']} | {r['current_novel_recall']} | "
                 f"{r['false_novel_rate']} |")
    L.append("\n## Cosine-to-nearest-anchor histogram\n")
    L.append("bins: " + ", ".join(str(b) for b in report["cosine_hist_bins"]))
    L.append(f"\ncurrent-assigned: {report['cosine_hist_current_assigned']}")
    L.append(f"\ncurrent-novel:    {report['cosine_hist_current_novel']}\n")
    L.append("\n## Decision rule (plan §5)\n")
    L.append("Build Option A if some tau gives high `agree(assigned)` (≳0.9), low "
             "`false-novel` (≲0.1), and high `known` (most of the corpus skips "
             "clustering). If no tau separates known from novel, prefer Option C "
             "(embedding as a novelty feature only).\n")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--sample", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--thresholds", default=None,
                    help="comma-separated taus (default: a 0.80–0.99 sweep)")
    ap.add_argument("--allow-unclassified", action="store_true",
                    help="OPERATOR ONLY: drop the public-only filter and scan the "
                         "whole (possibly confidential) corpus. The agent never "
                         "sets this.")
    ap.add_argument("--out-dir", default="eval/results")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    anch_idx = cfg.elasticsearch.indexes.cowrie.playbook_anchors
    prod_tau = float(getattr(cfg.session, "playbook_merge_threshold", 0.96))
    thresholds = ([float(x) for x in args.thresholds.split(",")]
                  if args.thresholds else _DEFAULT_THRESHOLDS)

    emb_exists = {"exists": {"field": f"{_S}.embedding"}}
    if args.allow_unclassified:
        print("WARNING: --allow-unclassified set; scanning WITHOUT the public-only "
              "filter. This reads per-sensor data the fail-safe gate would withhold. "
              "Operator-authorised only.", file=sys.stderr)
        filt = [emb_exists]
        classification = "unclassified-included"
    else:
        filt = [releasable_filter(cfg), emb_exists]
        classification = "public-only"

    anchor_ids, anchors = load_anchors(es, anch_idx)
    if anchors.shape[0] == 0:
        print("No anchors found — nothing to assign against.", file=sys.stderr)
        return 1

    samples = sample_sessions(es, idx, filt, args.sample, args.seed)
    report = score(samples, anchor_ids, anchors, thresholds, prod_tau) if samples else None

    meta = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "classification": classification,
        "sessions_index": idx,
        "anchors_index": anch_idx,
        "requested_sample": args.sample,
        "seed": args.seed,
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = out_dir / f"exp-prototype-assignment-{ts}"
    (stem.with_suffix(".json")).write_text(
        json.dumps({"meta": meta, "report": report}, indent=2))
    (stem.with_suffix(".md")).write_text(render_md(report, meta))
    print(render_md(report, meta))
    print(f"\nwrote {stem}.json / .md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
