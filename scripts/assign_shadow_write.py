"""I3c — write Option-A assignment to the session rollup's SHADOW fields.

Assigns a sample of sessions (embedding nearest-anchor + cascade + TF-IDF band, with a
per-run batch TF-IDF refit — same as the validator; persistence is an I4 concern) and
writes the result to `…session.cluster.assignment_*` WITHOUT touching the
HDBSCAN-driven `playbook_id`. The operator then browses `assignment_status=novel` /
band sessions in situ to confirm the pool is sensible before the authoritative I4
cutover. See docs/handoff-prototype-assignment-plan.md §5f (I3c).

**Dry-run by default**; writes need `--apply --yes`. Prerequisite: deploy the shadow
mapping fields (`init-indexes --update-mapping --source cowrie`) first. The shadow
fields are additive — this never modifies `playbook_id`/`playbook_name`.

Privacy: assignment operates on all classifications by necessity; the writes are
blind server-side updates that surface no per-record data. public-only filter BY
DEFAULT (0 docs on the untagged corpus); `--allow-unclassified` is an OPERATOR
decision. The agent does not run the write path.

Run from repo root via the console venv:
    console/.venv/bin/python scripts/assign_shadow_write.py --sample 5000
    console/.venv/bin/python scripts/assign_shadow_write.py --sample 5000 --apply --yes
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # scripts/

from enrich.classification import releasable_filter
from enrich.clustering import compute_lexical_features
from enrich.config import load_config, load_secrets
from enrich.es_client import bulk_write, make_client
from enrich.sources.cowrie.assignment import assign_batch

from cluster_bag_prod import _BAG_SVD_COMPONENTS, build_bag_texts, pull_hash_to_cluster
from exp_prototype_assignment import _l2, load_anchors
from exp_tfidf_separation import group_centroids, sample_playbook

_S = "dshield.cowrie.enrichment.session"
_PB_FIELD = f"{_S}.playbook_id"
_EMB_FIELD = f"{_S}.embedding"
_CMDSET_FIELD = f"{_S}.command_set"
_MAX_WINDOW = 10000


def _session_block(src: dict) -> dict:
    return (((src.get("dshield") or {}).get("cowrie") or {})
            .get("enrichment", {}).get("session", {}))


def shadow_action(doc_id: str, a, now: str) -> dict:
    """ES bulk partial-update action that writes the shadow assignment fields onto an
    existing session rollup doc (merges into …session.cluster; touches nothing else)."""
    return {
        "_op_type": "update",
        "_id": doc_id,
        "doc": {"dshield": {"cowrie": {"enrichment": {"session": {"cluster": {
            "assigned_playbook_id": a.playbook_id,
            "assignment_status": a.status,
            "assignment_cosine": a.cosine,
            "assignment_cascade_rank": a.cascade_rank,
            "assignment_at": now,
        }}}}}},
    }


def sample_write_set(es, idx, filt, n, seed):
    """Up to `n` (doc_id, embedding, command_set) — the sessions to shadow-annotate."""
    out, seen, batch = [], set(), 0
    base = {"bool": {"filter": filt}}
    while len(out) < n:
        take = min(n - len(out), _MAX_WINDOW)
        q = {"function_score": {"query": base,
                                "random_score": {"seed": seed + batch, "field": "_seq_no"},
                                "boost_mode": "replace"}}
        resp = es.search(index=idx, size=take, _source=[_EMB_FIELD, _CMDSET_FIELD],
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
            out.append((h["_id"], emb, list(s.get("command_set") or [])))
            new += 1
        batch += 1
        if new == 0 or len(hits) < take:
            break
    return out


def run(es, idx, cmd_idx, anch_idx, filt, *, sample, per_anchor, tau, confident_tau,
        tfidf_tau, seed):
    anchor_ids, anchor_emb = load_anchors(es, anch_idx)
    if anchor_emb.shape[0] == 0:
        return None, {"error": "no anchors"}

    # per-anchor sample → anchor TF-IDF centroids (the band signal source)
    train_emb, train_sets, train_pb = [], [], []
    for pb in anchor_ids:
        embs, sets = sample_playbook(es, idx, filt, pb, per_anchor, seed)
        for e, s in zip(embs, sets):
            train_emb.append(e); train_sets.append(s); train_pb.append(pb)

    write_set = sample_write_set(es, idx, filt, sample, seed)
    if not write_set:
        return None, {"error": "no sessions sampled"}
    w_ids = [w[0] for w in write_set]
    w_emb = _l2(np.array([w[1] for w in write_set], dtype=np.float32))
    w_sets = [w[2] for w in write_set]

    hash_to_cluster = pull_hash_to_cluster(es, cmd_idx, page_size=5000)
    n_train = len(train_sets)
    tfidf_all = compute_lexical_features(
        build_bag_texts(train_sets + w_sets, hash_to_cluster), n_components=_BAG_SVD_COMPONENTS)
    has_tfidf = tfidf_all.shape[1] >= 2
    tfidf_train, tfidf_write = tfidf_all[:n_train], tfidf_all[n_train:]
    anchor_tfidf = group_centroids(tfidf_train, train_pb) if has_tfidf else {}

    def tfidf_cos(i, a):
        c = anchor_tfidf.get(anchor_ids[a])
        return float(tfidf_write[i] @ c) if (has_tfidf and c is not None) else None

    res = assign_batch(w_emb, anchor_emb, anchor_ids, tau=tau, confident_tau=confident_tau,
                       tfidf_tau=tfidf_tau, tfidf_cos=tfidf_cos)
    now = datetime.now(timezone.utc).isoformat()
    actions = [shadow_action(wid, a, now) for wid, a in zip(w_ids, res)]
    summary = {
        "n_anchors": len(anchor_ids), "tfidf_available": has_tfidf,
        "n_write": len(res),
        "status_counts": dict(Counter(a.status for a in res)),
        "n_cascaded": sum(1 for a in res if a.cascade_rank > 0),
    }
    return actions, summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--sample", type=int, default=5000, help="sessions to shadow-annotate")
    ap.add_argument("--per-anchor", type=int, default=300, help="sessions per anchor for TF-IDF centroids")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--apply", action="store_true", help="write shadow fields (default: dry-run)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    ap.add_argument("--allow-unclassified", action="store_true",
                    help="OPERATOR ONLY: drop the public-only filter. Agent never sets it.")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands
    anch_idx = cfg.elasticsearch.indexes.cowrie.playbook_anchors
    sc = cfg.session
    tau = getattr(sc, "assignment_tau", 0.94)
    confident_tau = getattr(sc, "assignment_confident_tau", 0.98)
    tfidf_tau = getattr(sc, "assignment_tfidf_tau", 0.80)

    emb_exists = {"exists": {"field": _EMB_FIELD}}
    if args.allow_unclassified:
        print("WARNING: --allow-unclassified set; scanning/writing WITHOUT the public-only "
              "filter (operator-authorised).", file=sys.stderr)
        filt = [emb_exists]
    else:
        filt = [releasable_filter(cfg), emb_exists]

    actions, summary = run(es, idx, cmd_idx, anch_idx, filt, sample=args.sample,
                           per_anchor=args.per_anchor, tau=tau, confident_tau=confident_tau,
                           tfidf_tau=tfidf_tau, seed=args.seed)
    if actions is None:
        print(f"{summary.get('error')}. (Untagged corpus → public-only returns 0; operator "
              "may re-run with --allow-unclassified.)")
        return 0

    print(f"Shadow assignment over {summary['n_write']} sessions vs {summary['n_anchors']} "
          f"anchors (tfidf={summary['tfidf_available']}):")
    for status, n in sorted(summary["status_counts"].items()):
        print(f"  {status}: {n}")
    print(f"  cascaded (rank>0): {summary['n_cascaded']}")

    if not args.apply:
        print("\nDRY-RUN — no writes. Re-run with --apply --yes to write the shadow fields.")
        return 0
    if not args.yes:
        try:
            resp = input(f"\nWrite shadow fields to {len(actions)} session docs? [y/N] ").strip().lower()
        except EOFError:
            resp = "n"
        if resp not in ("y", "yes"):
            print("Aborted.")
            return 1
    ok, errors = bulk_write(es, idx, actions)
    print(f"\nwrote shadow fields to {ok} docs; {len(errors)} errors")
    if errors:
        print("first error:", errors[0])
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
