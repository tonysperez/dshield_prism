"""Health check for the session-cluster → playbook merge.

For the latest `cluster sessions` run, lists every centroid pair at cosine
≥ `session.playbook_merge_threshold` and reports whether each pair is
MERGED (sharing a `playbook_id`) or UNMERGED (in different playbooks).

For each UNMERGED pair, computes the worst within-group pair that WOULD
exist if the two playbooks were unioned — under complete-linkage, an
UNMERGED pair is correct iff that worst within-union pair is below
threshold. The script flags any pair whose split is *not* explained that
way as a possible regression.

Also prints the current playbook grouping (clusters per playbook) for a
quick scan of "is this still doing the right thing."

Exit codes:
  0 — all UNMERGED pairs are correctness-driven (complete-linkage refuses
      the merge because at least one within-union pair is below threshold)
  1 — at least one UNMERGED pair has worst within-union sim ≥ threshold
      (i.e. should have merged) — possible merge regression

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/diagnose_playbook_merge.py
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np  # noqa: E402

from enrich.config import load_config, load_secrets  # noqa: E402
from enrich.es_client import make_client  # noqa: E402


def main() -> int:
    cfg = load_config()
    secrets = load_secrets()
    es = make_client(cfg.elasticsearch, secrets)
    idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    threshold = float(cfg.session.playbook_merge_threshold)

    if not es.indices.exists(index=idx):
        print(f"ERROR: index {idx} does not exist. Run `cluster sessions` first.")
        return 2

    r = es.search(
        index=idx, size=1,
        query={"term": {"doc_type": "cluster"}},
        sort=[{"@timestamp": "desc"}],
        _source=["run_id"],
    )
    hits = r["hits"]["hits"]
    if not hits:
        print(f"ERROR: no cluster docs in {idx}.")
        return 2
    run_id = hits[0]["_source"]["run_id"]

    r2 = es.search(
        index=idx, size=1000,
        query={"bool": {"must": [
            {"term": {"doc_type": "cluster"}},
            {"term": {"run_id": run_id}},
        ]}},
        _source=["cluster_id", "size", "centroid",
                 "playbook_id", "playbook_name"],
    )
    docs = sorted(
        [h["_source"] for h in r2["hits"]["hits"] if h["_source"].get("centroid")],
        key=lambda d: d["cluster_id"],
    )

    cluster_ids = [d["cluster_id"] for d in docs]
    n = len(cluster_ids)
    if n < 2:
        print(f"Only {n} centroid(s) in run {run_id}; nothing to audit.")
        return 0

    M = np.array([d["centroid"] for d in docs], dtype=np.float32)
    M = M / (np.linalg.norm(M, axis=1, keepdims=True) + 1e-12)
    sim = M @ M.T

    pid = {d["cluster_id"]: d.get("playbook_id") for d in docs}
    name = {d["cluster_id"]: d.get("playbook_name") or "(unnamed)" for d in docs}
    size = {d["cluster_id"]: int(d.get("size") or 0) for d in docs}
    cid_to_idx = {c: i for i, c in enumerate(cluster_ids)}

    members_of: dict[str, set[str]] = defaultdict(set)
    for cid, p in pid.items():
        members_of[p].add(cid)

    print(f"run_id: {run_id}")
    print(f"threshold (session.playbook_merge_threshold): {threshold:.3f}")
    print(f"clusters: {n}")
    print()

    # Above-threshold pairs.
    pairs: list[tuple[float, str, str]] = []
    for i in range(n):
        for j in range(i + 1, n):
            s = float(sim[i, j])
            if s >= threshold:
                pairs.append((s, cluster_ids[i], cluster_ids[j]))
    pairs.sort(reverse=True)

    merged = [p for p in pairs if pid[p[1]] == pid[p[2]] and pid[p[1]] is not None]
    unmerged = [p for p in pairs if not (pid[p[1]] == pid[p[2]] and pid[p[1]] is not None)]

    print(f"Pairs at sim >= {threshold:.3f}: {len(pairs)}")
    print(f"  MERGED  (same playbook):    {len(merged)}")
    print(f"  UNMERGED (split playbooks): {len(unmerged)}")
    print()

    # Playbook grouping summary.
    by_pid: dict[str, list[str]] = defaultdict(list)
    for cid, p in pid.items():
        by_pid[p or "<no-pid>"].append(cid)
    print(f"Playbook grouping ({len(by_pid)} playbooks):")
    for p, cids in sorted(by_pid.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(cids) <= 1:
            continue
        ex_name = name[cids[0]]
        print(f"  {p}  n_clusters={len(cids)}  name='{ex_name}'")
        for cid in sorted(cids):
            print(f"    {cid:<13} size={size[cid]:<6} '{name[cid]}'")
    n_singletons = sum(1 for cids in by_pid.values() if len(cids) == 1)
    print(f"  + {n_singletons} singleton playbook(s)")
    print()

    # Verify each UNMERGED pair is correctness-driven.
    print(f"=== UNMERGED pairs >= {threshold:.3f}: complete-linkage justification ===")
    print()
    regressions: list[tuple[float, str, str, float, tuple[str, str] | None]] = []
    for s, a, b in unmerged:
        union = sorted(members_of[pid[a]] | members_of[pid[b]])
        worst_pair: tuple[str, str] | None = None
        worst_sim = 2.0
        for ii in range(len(union)):
            for jj in range(ii + 1, len(union)):
                si = cid_to_idx[union[ii]]
                sj = cid_to_idx[union[jj]]
                ss = float(sim[si, sj])
                if ss < worst_sim:
                    worst_sim = ss
                    worst_pair = (union[ii], union[jj])
        ok = worst_sim < threshold
        verdict = "OK" if ok else "REGRESSION"
        wp = f"{worst_pair[0]} <-> {worst_pair[1]}" if worst_pair else "(self)"
        print(f"  [{verdict}] sim={s:.4f}  {a} <-> {b}")
        print(f"             '{name[a]}'  ↔  '{name[b]}'")
        print(f"             worst within-union pair: {wp} @ sim={worst_sim:.4f}")
        if not ok:
            regressions.append((s, a, b, worst_sim, worst_pair))
        print()

    if merged:
        lo = min(merged, key=lambda x: x[0])
        print(f"Cohesion floor (lowest-sim MERGED pair): {lo[0]:.4f}  "
              f"{lo[1]} <-> {lo[2]}")
        print()

    if regressions:
        print(f"!! {len(regressions)} possible regression(s) — pairs above threshold")
        print("   where the would-be merged group has every pairwise sim >= threshold,")
        print("   so complete-linkage should have merged them.")
        for s, a, b, ws, wp in regressions:
            print(f"   sim={s:.4f}  {a} <-> {b}  (worst sim in union = {ws:.4f})")
        return 1

    print("OK — every UNMERGED pair is correctly split under complete-linkage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
