"""Measure playbook_id churn on the live corpus — the data ROADMAP #1
(centroid-keyed playbook identity) says must precede the surgery.

The current `playbook_id` is `sha256(sorted(member_session_ids))[:16]`.
Any membership change → new id → reset lifecycle state. The proposed
fix replaces that with a hash over a *quantised centroid vector*. Before
committing to that big migration, this tool answers two questions on
real run history:

  1. How often do ids genuinely flip today? (current-scheme churn)
  2. Would a centroid-keyed id actually be more stable, and at what
     quantisation? (the A/B the roadmap demands)

A subtle trap the tool is built to expose: a 1-session membership shift
nudges the centroid mean, so a high-precision quantised hash can churn
just as badly as the membership hash, while a low-precision one collides
distinct playbooks. The tool reports both fragmentation (ids per true
playbook — over-splitting) and collision (true playbooks per id —
over-merging) at each quantisation level so the trade-off is explicit.

"True playbook" = a lineage: the connected component over all centroid
docs (every run) linked by L2-normalised cosine >= --threshold, the same
similarity used by `merge_clusters_into_playbooks`. Read-only.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/measure_playbook_id_churn.py
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_HASH_LEN = 16  # mirrors sessions._PLAYBOOK_ID_HASH_LEN


def _unit(vec: np.ndarray) -> np.ndarray:
    n = float(np.linalg.norm(vec))
    return vec if n == 0.0 else vec / n


def _centroid_id(unit_vec: np.ndarray, decimals: int) -> str:
    """Proposed identity: hash over the quantised unit centroid."""
    rounded = np.round(unit_vec, decimals)
    rounded = rounded + 0.0  # normalise -0.0 -> 0.0 so the repr is stable
    payload = ",".join(format(x, f".{decimals}f") for x in rounded)
    return "cqv-" + hashlib.sha256(payload.encode()).hexdigest()[:_HASH_LEN]


def _lsh_id(unit_vec: np.ndarray, planes: np.ndarray) -> str:
    """Random-projection sign-bit LSH: id = hash of the sign pattern of
    the centroid projected onto K fixed random hyperplanes. Small angular
    shifts flip a bit only when the centroid sits near a plane, so it is
    locality-sensitive — unlike per-component rounding. `planes` is a
    fixed (K, dim) gaussian matrix (seeded → deterministic across runs).
    """
    bits = (planes @ unit_vec) >= 0.0
    packed = np.packbits(bits).tobytes()
    return f"lsh{planes.shape[0]}-" + hashlib.sha256(packed).hexdigest()[:_HASH_LEN]


def snap_assign(docs: list["Doc"], threshold: float) -> list[str]:
    """Online 'match to prior centroid' assignment — models the realistic
    fix: process runs chronologically, keep a registry of anchor
    centroids, reuse an anchor's id when cosine >= threshold, else mint a
    new id and register this centroid as a fresh anchor. This is
    *matching*, not *hashing*, so it is stable by construction. Returns an
    id per doc (parallel to `docs`)."""
    order = sorted(range(len(docs)), key=lambda i: docs[i].ts or "")
    anchors_vecs: list[np.ndarray] = []
    anchors_ids: list[str] = []
    out = [""] * len(docs)
    for i in order:
        u = docs[i].unit
        if anchors_vecs:
            sims = np.vstack(anchors_vecs) @ u
            j = int(np.argmax(sims))
            if float(sims[j]) >= threshold:
                out[i] = anchors_ids[j]
                continue
        nid = "snap-" + hashlib.sha256(
            (docs[i].run_id + docs[i].playbook_id).encode()).hexdigest()[:_HASH_LEN]
        anchors_vecs.append(u)
        anchors_ids.append(nid)
        out[i] = nid
    return out


class Doc:
    __slots__ = ("run_id", "ts", "playbook_id", "name", "unit")

    def __init__(self, run_id, ts, playbook_id, name, unit):
        self.run_id = run_id
        self.ts = ts
        self.playbook_id = playbook_id
        self.name = name
        self.unit = unit


def load_cluster_docs(es, index: str) -> list[Doc]:
    body = {
        "query": {"bool": {"must": [
            {"term": {"doc_type": "cluster"}},
            {"exists": {"field": "playbook_id"}},
            {"exists": {"field": "centroid"}},
        ]}},
        "_source": ["run_id", "@timestamp", "playbook_id", "playbook_name", "centroid"],
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
            s.get("playbook_id"), s.get("playbook_name") or "",
            _unit(np.asarray(cen, dtype=np.float32)),
        ))
    return docs


def union_find_lineages(docs: list[Doc], threshold: float) -> list[list[int]]:
    """Connected components over cosine >= threshold across ALL docs."""
    n = len(docs)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    M = np.vstack([d.unit for d in docs])          # rows already unit
    sim = M @ M.T                                    # cosine
    iu = np.argwhere(np.triu(sim >= threshold, k=1))
    for i, j in iu:
        ri, rj = find(int(i)), find(int(j))
        if ri != rj:
            parent[ri] = rj

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)
    return list(groups.values())


def consecutive_flip_rate(docs: list[Doc], ids: list[str],
                          threshold: float) -> tuple[int, int]:
    """For each adjacent run pair, match each later-run cluster to its
    nearest earlier-run cluster; if cosine >= threshold (same playbook),
    count a flip when the assigned id differs. `ids` is parallel to
    `docs`. Returns (flips, matched_pairs).
    """
    by_run: dict[str, list[int]] = defaultdict(list)
    for i, d in enumerate(docs):
        by_run[d.run_id].append(i)
    run_order = sorted(by_run, key=lambda r: min(docs[i].ts or "" for i in by_run[r]))
    flips = matched = 0
    for a, b in zip(run_order, run_order[1:]):
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
    ap.add_argument("--quant-levels", default="1,2,3",
                    help="comma-separated decimal places to test for the "
                         "centroid-keyed id (default 1,2,3)")
    args = ap.parse_args()

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)

    index = args.index or cfg.elasticsearch.indexes.cowrie.session_clusters
    threshold = args.threshold if args.threshold is not None \
        else cfg.session.playbook_merge_threshold
    levels = [int(x) for x in args.quant_levels.split(",") if x.strip()]

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
    print(f"\n'true playbooks' (centroid lineages @ cos>={threshold}): {n_lin}")

    def stats(ids: list[str]) -> tuple[float, int, int]:
        """Per-lineage fragmentation + global collision for an id-list."""
        ids_per_lineage = []
        id_to_lineages: dict[str, set[int]] = defaultdict(set)
        for li, group in enumerate(lineages):
            uniq = {ids[i] for i in group}
            ids_per_lineage.append(len(uniq))
            for _id in uniq:
                id_to_lineages[_id].add(li)
        frag = float(np.mean(ids_per_lineage))            # ideal 1.0 (no split)
        collided = sum(1 for v in id_to_lineages.values() if len(v) > 1)
        return frag, collided, len(id_to_lineages)

    rng = np.random.default_rng(1729)
    dim = len(docs[0].unit)
    lsh_ks = [8, 12, 16, 24, 32]

    # scheme name -> id-list (parallel to docs)
    schemes: list[tuple[str, list[str]]] = []
    schemes.append(("CURRENT membership-hash", [d.playbook_id for d in docs]))
    for L in levels:
        schemes.append((f"quant {L}dp", [_centroid_id(d.unit, L) for d in docs]))
    for K in lsh_ks:
        planes = rng.standard_normal((K, dim)).astype(np.float32)
        schemes.append((f"LSH {K}-bit", [_lsh_id(d.unit, planes) for d in docs]))
    schemes.append(("snap-to-prior", snap_assign(docs, threshold)))

    print("\n=== A/B over schemes (ideal: frag 1.0, merged 0, low flip) ===")
    print(f"  {'scheme':<24} {'frag':>6} {'merged':>7} {'ids':>5} {'flip_rate':>11}")
    for name, ids in schemes:
        frag, coll, nids = stats(ids)
        flips, matched = consecutive_flip_rate(docs, ids, threshold)
        fr = f"{flips}/{matched}={flips / matched:.1%}" if matched else "n/a"
        print(f"  {name:<24} {frag:>6.2f} {coll:>7} {nids:>5} {fr:>11}")

    print("\nReading the table:")
    print("  frag   = ids per true playbook; >1 means the scheme splits a")
    print("           stable playbook across ids (the churn we want gone).")
    print("  merged = ids spanning >1 true playbook; >0 means it collides")
    print("           distinct playbooks (too coarse).")
    print("  A scheme only beats CURRENT if it lowers frag AND keeps merged")
    print("  at 0. Hash-of-fingerprint schemes (quant/LSH) trade frag vs")
    print("  merged; snap-to-prior *matches* instead of hashing, so it is")
    print("  the realistic shape of a fix if the numbers bear it out.")

    # --- Cross-check: observed flips already captured by name co-id ----
    pb_lc = cfg.findings.indexes.playbook_lifecycle
    try:
        total = es.count(index=pb_lc)["count"]
        with_inh = es.count(index=pb_lc,
                            query={"exists": {"field": "inherited_from"}})["count"]
        print(f"\nlifecycle cross-check ({pb_lc}):")
        print(f"  {with_inh}/{total} live playbook docs carry inherited_from")
        print( "  (name-coid only sees flips within "
              f"{cfg.findings.lifecycle.coidentification_max_age_runs} "
               "runs with a matching name — a lower bound on real flips).")
    except Exception as e:  # noqa: BLE001
        print(f"\nlifecycle cross-check skipped: {e!r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
