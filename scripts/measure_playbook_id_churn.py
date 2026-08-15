"""Measure playbook_id flip-rate across consecutive cluster runs.

A regression sentinel for the cosine-anchored playbook identity. The id
should be stable: when two clusters in adjacent runs have cosine >=
playbook_merge_threshold, they should carry the same playbook_id. Any
flip is either a benign anchor-miss (centroid jiggled across the
threshold) or a regression worth investigating.

Output: per-scheme `frag` (ids per true playbook lineage; ideal 1.0),
`merged` (ids spanning multiple lineages; ideal 0), and `flip_rate`
(consecutive-run flips ÷ matched-pair count; ideal ~0% in steady state).

"True playbook" = a lineage: the connected component over all centroid
docs (every run) linked by L2-normalised cosine >= --threshold. Read-only.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/measure_playbook_id_churn.py
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import itertools

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client


def _unit(vec: np.ndarray) -> np.ndarray:
    n = float(np.linalg.norm(vec))
    return vec if n == 0.0 else vec / n


@dataclass
class Doc:
    run_id: str
    ts: str | None
    playbook_id: str
    unit: np.ndarray


def load_cluster_docs(es, index: str) -> list[Doc]:
    body = {
        "query": {"bool": {"must": [
            {"term": {"doc_type": "cluster"}},
            {"exists": {"field": "playbook_id"}},
            {"exists": {"field": "centroid"}},
        ]}},
        "_source": ["run_id", "@timestamp", "playbook_id", "centroid"],
    }
    docs: list[Doc] = []
    resp = es.search(index=index, size=5000, **body)
    for h in resp["hits"]["hits"]:
        s = h["_source"]
        cen = s.get("centroid")
        if not isinstance(cen, list):
            continue
        docs.append(Doc(
            s.get("run_id"), s.get("@timestamp"),
            s.get("playbook_id"),
            _unit(np.asarray(cen, dtype=np.float32)),
        ))
    return docs


def union_find_lineages(docs: list[Doc], threshold: float) -> list[list[int]]:
    """Connected components over cosine >= threshold across all docs."""
    n = len(docs)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    M = np.vstack([d.unit for d in docs])
    sim = M @ M.T
    iu = np.argwhere(np.triu(sim >= threshold, k=1))
    for i, j in iu:
        ri, rj = find(int(i)), find(int(j))
        if ri != rj:
            parent[ri] = rj

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)
    return list(groups.values())


def consecutive_flip_rate(
    docs: list[Doc], ids: list[str], threshold: float,
) -> tuple[int, int]:
    """For each adjacent run pair, match each later-run cluster to its
    nearest earlier-run cluster; if cosine >= threshold (same playbook),
    count a flip when the assigned id differs. Returns (flips, matched_pairs).
    """
    by_run: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(docs):
        by_run[d.run_id].append(i)
    run_order = sorted(by_run, key=lambda r: min(docs[i].ts or "" for i in by_run[r]))
    flips = matched = 0
    for a, b in itertools.pairwise(run_order):
        prev, cur = by_run[a], by_run[b]
        if not prev or not cur:
            continue
        P = np.vstack([docs[i].unit for i in prev])
        for i in cur:
            sims = P @ docs[i].unit
            k = int(np.argmax(sims))
            if float(sims[k]) >= threshold:
                matched += 1
                if ids[i] != ids[prev[k]]:
                    flips += 1
    return flips, matched


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--index", default=None,
                    help="session cluster index (default: from config)")
    ap.add_argument("--threshold", type=float, default=None,
                    help="cosine threshold for 'same playbook' "
                         "(default: session.playbook_merge_threshold)")
    args = ap.parse_args()

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)

    index = args.index or cfg.elasticsearch.indexes.cowrie.session_clusters
    threshold = args.threshold if args.threshold is not None \
        else cfg.session.playbook_merge_threshold

    docs = load_cluster_docs(es, index)
    if not docs:
        print(f"No cluster docs with centroid+playbook_id in {index!r}.")
        return 1

    n_runs = len({d.run_id for d in docs})
    n_pb_ids = len({d.playbook_id for d in docs})
    print(f"index            : {index}")
    print(f"threshold        : {threshold}")
    print(f"cluster docs     : {len(docs)}")
    print(f"runs covered     : {n_runs}")
    print(f"distinct pb ids  : {n_pb_ids}")

    lineages = union_find_lineages(docs, threshold)
    n_lin = len(lineages)
    print(f"true playbooks   : {n_lin}  (centroid lineages @ cos >= {threshold})")

    # Per-lineage fragmentation: how many ids does each lineage span?
    # Ideal 1.0 — one id per lineage.
    id_to_lineages: dict[str, set[int]] = defaultdict(set)
    ids_per_lineage: list[int] = []
    pb_ids = [d.playbook_id for d in docs]
    for li, group in enumerate(lineages):
        uniq = {pb_ids[i] for i in group}
        ids_per_lineage.append(len(uniq))
        for _id in uniq:
            id_to_lineages[_id].add(li)
    frag = float(np.mean(ids_per_lineage)) if ids_per_lineage else 0.0
    merged = sum(1 for v in id_to_lineages.values() if len(v) > 1)

    flips, matched = consecutive_flip_rate(docs, pb_ids, threshold)
    fr = f"{flips}/{matched} = {flips / matched:.2%}" if matched else "n/a"

    print()
    print(f"fragmentation    : {frag:.2f}   (ideal 1.00 — ids per lineage)")
    print(f"merged ids       : {merged}      (ideal 0 — ids spanning multiple lineages)")
    print(f"adj-run flip rate: {fr}  (ideal ~0% — ids should not change run-to-run)")

    if n_runs < 2:
        print("\nNote: only one run observed — flip rate needs >= 2 runs.")
    if flips > 0:
        print("\nFlips observed. If the rate is sustained > ~1%, investigate:")
        print("  - cluster merge threshold drift")
        print("  - anchor index integrity")
        print("  - clustering algorithm changes that moved centroids past anchors")

    return 0


if __name__ == "__main__":
    sys.exit(main())
