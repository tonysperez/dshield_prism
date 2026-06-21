"""F2.0 — small-cluster inspection harness (analyst go/no-go gate).

Renders every cluster with **size ∈ [3, 10]** for a given layer +
clustering config, so an analyst can eyeball whether the surfaced
small clusters are *real* (textually-divergent same-behaviour — the
cluster_7 pattern) or *shards* (token-variant fragments of a big
copy/paste playbook — the over-fragmentation the E4 postmortem
rejected).

Clusters are selected **by size, not by any `small_` id prefix**, so
the same harness serves the baseline ``hdbscan`` run, the F4 low-mcs
sweep, and the F3 late-fusion output — all of which carry ordinary
cluster ids.

Per cluster it shows: member count, dominant intent + intent-share
(3a), modal-signature-share, cosine to the nearest large-cluster
(size > 100) centroid, the **shard flag** (3b: within
``playbook_merge_threshold`` cosine of a big centroid AND textually
homogeneous), and a sample of member command streams.

The **go/no-go is the analyst's judgement**, not a decimal — the
script prints a shard/non-shard tally as an aid only. A run where more
than a couple of clusters read as token-variant shredding is a no-go.

Read-only. No ES writes.

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/inspect_small_clusters.py \\
      --layer sessions --mode hdbscan
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

from compare_clusterings import disagreement_sessions
from eval_clustering import SMALL_BAND, small_cluster_metrics
from prod_corpus import (
    SessionCorpus,
    cluster_hdbscan,
    normalized_embeddings,
    pull_session_corpus,
)


def _truncate(text: str, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _render(
    layer: str,
    mode_desc: str,
    corpus: SessionCorpus,
    labels: np.ndarray,
    detail: list[dict],
    *,
    intent_available: bool,
    signature_available: bool,
    n_samples: int,
    sample_chars: int,
    n_clusters_total: int,
    n_outliers: int,
    n_rescued: int,
) -> tuple[str, dict]:
    """Render the size-∈[3,10] clusters to markdown. Returns (md, tally)."""
    # Map cluster label → member corpus indices (small clusters only).
    small_labels = {d["cluster_label"] for d in detail}
    members: dict[int, list[int]] = {l: [] for l in small_labels}
    for i, lbl in enumerate(labels):
        l = int(lbl)
        if l in members:
            members[l].append(i)

    n_shard = sum(1 for d in detail if d["is_shard"] is True)
    n_clean = sum(1 for d in detail if d["is_shard"] is False)
    n_unknown = sum(1 for d in detail if d["is_shard"] is None)
    tally = {
        "n_small_clusters": len(detail),
        "n_shard":          n_shard,
        "n_non_shard":      n_clean,
        "n_undetermined":   n_unknown,
        "shard_fraction":   round(n_shard / (n_shard + n_clean), 4)
        if (n_shard + n_clean) else None,
    }

    out: list[str] = []
    out.append(f"# Small-cluster inspection — {layer} layer")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append(f"- **Clustering:** {mode_desc}")
    out.append(f"- **Corpus:** {len(corpus)} sessions · "
               f"{n_clusters_total} clusters · {n_outliers} outliers · "
               f"{n_rescued} rescued")
    out.append(f"- **Small clusters (size ∈ [{SMALL_BAND[0]}, {SMALL_BAND[1]}]):** "
               f"{len(detail)}")
    out.append(f"- **Shard tally (3b):** {n_shard} shard · {n_clean} non-shard"
               + (f" · {n_unknown} undetermined" if n_unknown else "")
               + (f"  →  shard_fraction = {tally['shard_fraction']}"
                  if tally["shard_fraction"] is not None else ""))
    if not intent_available:
        out.append("- ⚠️ intent unavailable on this input — 3a not computed")
    if not signature_available:
        out.append("- ⚠️ signature unavailable on this input — 3b not computed")
    out.append("")
    out.append("> **Analyst go/no-go:** skim the clusters below. If more than a "
               "couple read as token-variant shredding (same script, trivial "
               "differences), it's a **no-go**. The shard tally is an aid, not "
               "the decision.")
    out.append("")

    # Sort: undetermined/non-shard first (the interesting ones), shards last;
    # within a group, larger clusters first.
    def _sort_key(d: dict):
        rank = 2 if d["is_shard"] else (1 if d["is_shard"] is None else 0)
        return (rank, -d["size"])

    for d in sorted(detail, key=_sort_key):
        lbl = d["cluster_label"]
        flag = ("🔴 SHARD" if d["is_shard"] else
                ("🟢 distinct" if d["is_shard"] is False else "⚪ undetermined"))
        out.append(f"## cluster {lbl} — n={d['size']} — {flag}")
        out.append("")
        cos = d["nearest_large_cosine"]
        out.append(
            f"- intent: `{d['dominant_intent']}` "
            f"(share {d['intent_share']})  ·  "
            f"modal_signature_share: {d['modal_signature_share']}  ·  "
            f"nearest_large_centroid_cos: {cos if cos is None else round(cos, 3)}"
        )
        out.append("")
        out.append("| session_id | intent | signature | command stream |")
        out.append("|---|---|---|---|")
        for i in members.get(lbl, [])[:n_samples]:
            sid = corpus.session_ids[i]
            it = corpus.intents[i] or "—"
            sig = (corpus.signatures[i] or "—")[:8]
            txt = _truncate(corpus.texts[i], sample_chars) or "_(no command text)_"
            txt = txt.replace("|", "\\|")
            out.append(f"| `{sid}` | {it} | `{sig}` | {txt} |")
        extra = len(members.get(lbl, [])) - n_samples
        if extra > 0:
            out.append(f"\n_… {extra} more member(s) not shown._")
        out.append("")

    return "\n".join(out), tally


def _run_live(args, cfg, mode_desc: str):
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)
    index = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    corpus = pull_session_corpus(es, index, cfg.session.page_size, args.limit)
    if len(corpus) < args.mcs:
        raise SystemExit(f"Pulled only {len(corpus)} sessions — too few to cluster.")

    rescue = cfg.session.playbook_merge_threshold if args.rescue_threshold is None \
        else args.rescue_threshold
    labels, n_rescued = cluster_hdbscan(
        corpus,
        min_cluster_size=args.mcs,
        min_samples=args.ms,
        scalar_weight=cfg.session.cluster_scalar_weight,
        rescue_threshold=rescue,
    )
    norm = normalized_embeddings(corpus)
    sc = small_cluster_metrics(
        labels, norm, corpus.intents, corpus.signatures,
        merge_threshold=cfg.session.playbook_merge_threshold,
    )
    n_clusters_total = len({int(c) for c in labels if c >= 0})
    n_outliers = int((labels == -1).sum())

    md, tally = _render(
        args.layer, mode_desc, corpus, labels, sc["small_cluster_detail"],
        intent_available=sc["intent_available"],
        signature_available=sc["signature_available"],
        n_samples=args.samples, sample_chars=args.sample_chars,
        n_clusters_total=n_clusters_total, n_outliers=n_outliers,
        n_rescued=n_rescued,
    )
    return md, tally


def _cluster_ctx(indices: list[int], corpus: SessionCorpus,
                 n_samples: int, sample_chars: int) -> tuple[int, str, list[str]]:
    """(size, dominant_intent, sample command streams) for a cluster's
    corpus indices."""
    from collections import Counter
    named = [corpus.intents[i] for i in indices if corpus.intents[i]]
    dom = Counter(named).most_common(1)[0][0] if named else "—"
    samples = [
        _truncate(corpus.texts[i], sample_chars) or "_(no command text)_"
        for i in indices[:n_samples]
    ]
    return len(indices), dom, samples


def _render_disagreements(corpus, labels, arm, base, mode_desc, args) -> str:
    """G0.2 disagreement render: one section per session the arm places
    differently than the baseline, with both clusters' context side by side
    and a `decision:` field for the G4 analyst go/no-go."""
    from collections import defaultdict
    sid_to_idx = {s: i for i, s in enumerate(corpus.session_ids)}
    arm_members: dict[int, list[int]] = defaultdict(list)
    for i, lbl in enumerate(labels):
        arm_members[int(lbl)].append(i)
    base_members: dict[int, list[int]] = defaultdict(list)
    for s, bc in base.items():
        if s in sid_to_idx:
            base_members[int(bc)].append(sid_to_idx[s])

    disagree = disagreement_sessions(base, arm)
    n_common = len(set(base) & set(arm))

    out: list[str] = []
    out.append("# Cross-arm disagreement render — sessions layer")
    out.append("")
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append(f"- **Arm:** {mode_desc}")
    out.append(f"- **Baseline:** `{args.compare}`")
    out.append(f"- **Disagreements:** {len(disagree)} of {n_common} common sessions "
               f"({len(disagree)/n_common:.1%} if any); rendering first "
               f"{min(len(disagree), args.max_disagreements)}")
    out.append("")
    out.append("> For each session below the arm and baseline disagree on placement. "
               "Read the session's commands, then both clusters' members, and set "
               "`decision:` to **g_better** (arm's placement is right), "
               "**baseline_better**, **equivalent**, or **both_wrong**. "
               "Adoption (G4) needs `g_better ≥ 40% AND both_wrong ≤ 20%`.")
    out.append("")
    for n, (sid, bc, ac) in enumerate(disagree[: args.max_disagreements], 1):
        i = sid_to_idx[sid]
        bsize, bintent, bsamp = _cluster_ctx(base_members[bc], corpus, args.samples, args.sample_chars)
        asize, aintent, asamp = _cluster_ctx(arm_members[ac], corpus, args.samples, args.sample_chars)
        out.append(f"## disagreement {n} — session `{sid}`")
        out.append("")
        out.append("```yaml")
        out.append("decision: pending  # g_better | baseline_better | equivalent | both_wrong")
        out.append("```")
        out.append(f"- **this session** (intent `{corpus.intents[i] or '—'}`): "
                   f"`{_truncate(corpus.texts[i], args.sample_chars) or '(no command text)'}`")
        out.append(f"- **baseline cluster {bc}** — n={bsize}, intent `{bintent}`:")
        for s in bsamp:
            out.append(f"    - `{s}`")
        out.append(f"- **arm cluster {ac}** — n={asize}, intent `{aintent}`:")
        for s in asamp:
            out.append(f"    - `{s}`")
        out.append("")
    return "\n".join(out)


def _run_compare(args, cfg, mode_desc) -> str:
    import json
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)
    index = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    corpus = pull_session_corpus(es, index, cfg.session.page_size, args.limit)
    rescue = cfg.session.playbook_merge_threshold if args.rescue_threshold is None \
        else args.rescue_threshold
    labels, _ = cluster_hdbscan(
        corpus, min_cluster_size=args.mcs, min_samples=args.ms,
        scalar_weight=cfg.session.cluster_scalar_weight, rescue_threshold=rescue,
    )
    arm = {corpus.session_ids[i]: int(labels[i]) for i in range(len(corpus))}
    base_rec = json.loads(Path(args.compare).read_text(encoding="utf-8"))
    base = base_rec.get("assignments")
    if not base:
        raise SystemExit(
            f"--compare {args.compare} has no `assignments` — produce it with "
            "eval_production_scale.py --dump-assignments."
        )
    base = {str(k): int(v) for k, v in base.items()}
    return _render_disagreements(corpus, labels, arm, base, mode_desc, args)


def _self_test() -> int:
    """Synthetic dry-run (plan F2.0 verify): one big cluster + three
    size-∈[3,10] clusters, one of them a deliberate shard (centroid within
    0.96 of the big centroid AND textually homogeneous). Asserts the shard
    is flagged and the two distinct ones are not.

    Labels are assigned explicitly rather than via HDBSCAN: the point is to
    exercise the shard-detection logic (3b), not HDBSCAN's density merging —
    which would absorb the spatially-near small clusters into the big one
    before the metric ever sees them.
    """
    rng = np.random.default_rng(20260601)
    d = 32
    rows: list[np.ndarray] = []
    intents: list[str] = []
    sigs: list[str] = []
    labels_list: list[int] = []

    def _add(center, n, intent, sig_fn, label, jitter):
        for k in range(n):
            rows.append(center + rng.normal(0, jitter, d))
            intents.append(intent)
            sigs.append(sig_fn(k))
            labels_list.append(label)

    big = rng.normal(0, 1, d); big /= np.linalg.norm(big)
    # label 0: large (size 150 > 100) — the shard reference set.
    _add(big, 150, "host_recon", lambda k: "BIGSIG", 0, jitter=0.02)
    # label 1: SHARD — hugs the big centroid (cos≈1) AND one modal signature.
    _add(big, 6, "host_recon", lambda k: "SHARDSIG", 1, jitter=0.001)
    # label 2: distinct A — far from big (cos<0.96), textually homogeneous.
    far = rng.normal(0, 1, d); far /= np.linalg.norm(far)
    _add(far, 6, "install_persistence", lambda k: "DISTINCT_A", 2, jitter=0.001)
    # label 3: distinct B — near big in space (cos≈1) BUT textually divergent
    # (unique sig per member). The cluster_7 / #20 pattern; NOT a shard.
    _add(big, 7, "credential_data_access", lambda k: f"UNIQUE_{k}", 3, jitter=0.001)

    from enrich.clustering import l2_normalize
    norm = l2_normalize(np.array(rows, dtype=np.float32))
    labels = np.array(labels_list, dtype=np.int64)

    sc = small_cluster_metrics(labels, norm, intents, sigs, merge_threshold=0.96)
    detail = sc["small_cluster_detail"]
    by_sig_intent = {}
    for d_ in detail:
        by_sig_intent[d_["dominant_intent"]] = d_

    print("self-test small clusters:")
    for d_ in detail:
        print(f"  intent={d_['dominant_intent']:18} n={d_['size']} "
              f"modal_sig={d_['modal_signature_share']} "
              f"cos={d_['nearest_large_cosine']} shard={d_['is_shard']}")

    ok = True
    shard = by_sig_intent.get("host_recon")
    if not (shard and shard["is_shard"] is True):
        print("FAIL: the deliberate shard was not flagged"); ok = False
    distinct_b = by_sig_intent.get("credential_data_access")
    if not (distinct_b and distinct_b["is_shard"] is False):
        print("FAIL: textually-divergent near-centroid cluster wrongly flagged shard"); ok = False
    distinct_a = by_sig_intent.get("install_persistence")
    if not (distinct_a and distinct_a["is_shard"] is False):
        print("FAIL: far distinct cluster wrongly flagged shard"); ok = False
    print("SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def _self_test_compare() -> int:
    """Synthetic dry-run (plan G0.2 verify): a hand-built disagreement set —
    baseline groups {s2,s3,s4,s5}, arm pulls s2 into {s0,s1}. Asserts the
    render produces exactly one disagreement section for s2 with both
    clusters' context + a decision field."""
    from types import SimpleNamespace
    corpus = SessionCorpus()
    for k in range(6):
        corpus.doc_ids.append(f"s{k}")
        corpus.session_ids.append(f"s{k}")
        corpus.embeddings.append([0.0])
        corpus.scalars.append({})
        corpus.intents.append("host_recon" if k < 3 else "install_persistence")
        corpus.signatures.append("")
        corpus.texts.append(f"command stream {k}")
    labels = np.array([0, 0, 0, 1, 1, 1])           # arm partition
    arm = {f"s{k}": int(labels[k]) for k in range(6)}
    base = {"s0": 0, "s1": 0, "s2": 1, "s3": 1, "s4": 1, "s5": 1}  # baseline
    args = SimpleNamespace(compare=Path("synthetic-base.json"),
                           max_disagreements=30, samples=3, sample_chars=80)
    md = _render_disagreements(corpus, labels, arm, base, "synthetic-arm", args)
    print(md)
    ok = (
        md.count("## disagreement") == 1
        and "session `s2`" in md
        and "decision: pending" in md
        and "baseline cluster 1" in md
        and "arm cluster 0" in md
    )
    print("SELF-TEST-COMPARE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--layer", choices=["sessions", "commands", "ips"],
                    default="sessions")
    ap.add_argument("--mode", choices=["hdbscan", "late_fusion"],
                    default="hdbscan",
                    help="Clustering to inspect. 'late_fusion' lands with F3.")
    ap.add_argument("--mcs", type=int, default=None,
                    help="HDBSCAN min_cluster_size (default: config).")
    ap.add_argument("--ms", type=int, default=None,
                    help="HDBSCAN min_samples (default: config).")
    ap.add_argument("--rescue-threshold", type=float, default=None,
                    help="Noise-rescue cosine threshold (default: config "
                         "playbook_merge_threshold).")
    ap.add_argument("--samples", type=int, default=4,
                    help="Member command streams rendered per cluster.")
    ap.add_argument("--sample-chars", type=int, default=160,
                    help="Truncate each rendered command stream to N chars.")
    ap.add_argument("--limit", type=int, default=None,
                    help="Cap the corpus pull (dev tool).")
    ap.add_argument("--compare", type=Path, default=None,
                    help="G0.2: a baseline run JSON (eval_production_scale "
                         "--dump-assignments). Switches to disagreement-render "
                         "mode — one section per session this arm places "
                         "differently than the baseline, for the G4 go/no-go.")
    ap.add_argument("--max-disagreements", type=int, default=30,
                    help="Max disagreement sessions rendered in --compare mode.")
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--no-md", action="store_true",
                    help="Print to stdout only; skip the markdown file.")
    ap.add_argument("--self-test", action="store_true",
                    help="Run the synthetic shard-detection dry-run and exit.")
    ap.add_argument("--self-test-compare", action="store_true",
                    help="Run the synthetic disagreement-render dry-run and exit.")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()
    if args.self_test_compare:
        return _self_test_compare()

    if args.layer != "sessions":
        raise SystemExit(
            f"--layer {args.layer} is F5 territory (per-layer rendering); "
            "only 'sessions' is wired today."
        )
    if args.mode == "late_fusion":
        raise SystemExit("--mode late_fusion lands with F3.1; use 'hdbscan'.")

    cfg = load_config()
    args.mcs = args.mcs if args.mcs is not None else cfg.session.cluster_min_cluster_size
    args.ms = args.ms if args.ms is not None else cfg.session.cluster_min_samples
    rescue = cfg.session.playbook_merge_threshold if args.rescue_threshold is None \
        else args.rescue_threshold
    mode_desc = (f"hdbscan (mcs={args.mcs}, ms={args.ms}, "
                 f"rescue={rescue}, scalar_weight={cfg.session.cluster_scalar_weight})")

    if args.compare is not None:
        md = _run_compare(args, cfg, mode_desc)
        print(md)
    else:
        md, tally = _run_live(args, cfg, mode_desc)
        print(md)
        print("\n" + "=" * 60)
        print(f"TALLY: {tally['n_small_clusters']} small clusters · "
              f"{tally['n_shard']} shard · {tally['n_non_shard']} non-shard"
              + (f" · {tally['n_undetermined']} undetermined" if tally['n_undetermined'] else ""))
        if tally["shard_fraction"] is not None:
            print(f"       shard_fraction = {tally['shard_fraction']} "
                  f"(adoption needs < 0.50 AND analyst 'go')")

    if not args.no_md:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = args.output_dir / f"small-cluster-inspect-{args.layer}-{ts}.md"
        out.write_text(md, encoding="utf-8")
        print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
