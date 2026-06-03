"""Phase K — IP clustering diagnostic (current vs K2 geometry).

Read-only / non-mutating. Pulls the IP rollup corpus once, rebuilds the
production HDBSCAN in memory under a chosen geometry, and emits the metric set
the K success criteria need. Never writes cluster.id/centroids back to ES, so
it characterises a candidate geometry without reclustering production (the
in-memory approach used for the J3 and first-K measurements).

`--geometry current` = today's production block (behaviour + country + ASN +
cred + intel + HASSH).
`--geometry k2`      = Phase K: drop country + ASN + HASSH, add the Tier 1
behaviour sub-block (intent/playbook/diversity/temporal/volume), keep cred +
intel. Run both → K1 baseline and K3 post-change.

`--fix-hassh` populates the HASSH sub-block from the rollup's
`hassh_distribution` (which the deployed `iter_ip_docs` fails to fetch — the
ROADMAP IP-layer HASSH `_source` bug). Only affects `current` (k2 drops HASSH);
default reproduces production faithfully (HASSH dead). Intent-coherence /
diversity metrics use true per-IP labels regardless.

Emits `eval/results/<label>-<ts>.{md,json}`.

    console/.venv/bin/python scripts/diagnose_ip_clustering.py --geometry current --label K1-baseline
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import numpy as np

from enrich.clustering import l2_normalize
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.ips import (
    _active_days,
    _compute_top_asns,
    _pull_session_cluster_bags,
    make_full_scalar_builder,
)

_ZGRAB_PLAYBOOK = "spb-feab4397c2bdcac3"
_KNOWN_FRAG_CASES = [
    _ZGRAB_PLAYBOOK, "spb-89c10e55e4cfa78d", "spb-94d8703fbaf4fae1",
    "spb-bfb392ed9fdaa5e4", "spb-a30bd43f516f312e", "spb-d27502498192ccc5",
]


def _pull_corpus(es, ips_idx, page_size):
    body = {
        "size": page_size,
        "_source": [
            "source.ip", "source.geo.country_iso_code", "source.as.number",
            "dshield.cowrie.enrichment.ip.embedding",
            "dshield.cowrie.enrichment.ip.total_sessions",
            "dshield.cowrie.enrichment.ip.successful_sessions",
            "dshield.cowrie.enrichment.ip.mean_novelty_score",
            "dshield.cowrie.enrichment.ip.mean_session_duration_s",
            "dshield.cowrie.enrichment.ip.credentials",
            "dshield.cowrie.enrichment.ip.hassh",
            "dshield.cowrie.enrichment.ip.hassh_distribution",
            "dshield.cowrie.enrichment.ip.dominant_intent",
            "dshield.cowrie.enrichment.ip.intent_distribution",
            "dshield.cowrie.enrichment.ip.dominant_playbook_id",
            "dshield.cowrie.enrichment.ip.playbook_distribution",
            "dshield.cowrie.enrichment.ip.total_commands",
            "dshield.cowrie.enrichment.ip.file_download_count",
            "dshield.cowrie.enrichment.ip.first_seen",
            "dshield.cowrie.enrichment.ip.last_seen",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.ip.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    after = None
    while True:
        if after:
            body["search_after"] = after
        resp = es.search(index=ips_idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            ip_en = (((src.get("dshield") or {}).get("cowrie") or {})
                     .get("enrichment", {}).get("ip", {}))
            emb = ip_en.get("embedding")
            if not emb:
                continue
            source = src.get("source") or {}
            asn = ((source.get("as") or {}).get("number"))
            total = ip_en.get("total_sessions") or 1
            yield {
                "ip": source.get("ip", h["_id"]),
                "emb": emb,
                "country": ((source.get("geo") or {}).get("country_iso_code")) or "",
                "asn": int(asn) if asn is not None else None,
                "creds": list(ip_en.get("credentials") or []),
                "hassh": ip_en.get("hassh") or "",
                "hassh_distribution": list(ip_en.get("hassh_distribution") or []),
                "dominant_intent": ip_en.get("dominant_intent"),
                "intent_distribution": list(ip_en.get("intent_distribution") or []),
                "playbook": ip_en.get("dominant_playbook_id"),
                "playbook_distribution": list(ip_en.get("playbook_distribution") or []),
                "total_sessions": total,
                "total_commands": ip_en.get("total_commands") or 0,
                "file_download_count": ip_en.get("file_download_count") or 0,
                "active_days": _active_days(ip_en.get("first_seen"), ip_en.get("last_seen")),
                "login_success_rate": (ip_en.get("successful_sessions") or 0) / total,
                "mean_novelty_score": ip_en.get("mean_novelty_score") or 0.0,
                "mean_session_duration_s": ip_en.get("mean_session_duration_s") or 0.0,
            }
        after = hits[-1]["sort"]


def _profile_cluster(members: list[dict]) -> dict:
    size = len(members)
    pb = Counter(m["playbook"] for m in members if m["playbook"])
    intents = [m["dominant_intent"] for m in members if m["dominant_intent"]]
    ic = Counter(intents)
    modal_intent, modal_intent_n = (ic.most_common(1)[0] if ic else (None, 0))
    hassh_present = [m["hassh"] for m in members if m["hassh"]]
    hc = Counter(hassh_present)
    return {
        "size": size,
        "dominant_playbook": (pb.most_common(1)[0][0] if pb else None),
        "modal_intent": modal_intent,
        "modal_intent_share": round(modal_intent_n / len(intents), 4) if intents else None,
        "intent_present": len(intents),
        "intent_unique": len(ic),
        "modal_hassh_share": round(hc.most_common(1)[0][1] / len(hassh_present), 4) if hassh_present else None,
        "hassh_unique": len(hc),
        "country_unique": len(Counter(m["country"] or "??" for m in members)),
        "asn_unique": len(Counter(m["asn"] for m in members if m["asn"] is not None)),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--geometry", choices=["current", "k2", "k4"], required=True)
    ap.add_argument("--fix-hassh", action="store_true")
    ap.add_argument("--label", default=None)
    ap.add_argument("--top-k", type=int, default=10)
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    args = ap.parse_args()

    cfg = load_config()
    es = make_client(cfg.elasticsearch, load_secrets())
    ips_idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    ipcfg = cfg.ip

    print(f"pulling IP corpus from {ips_idx} ...", flush=True)
    corpus = list(_pull_corpus(es, ips_idx, ipcfg.page_size))
    n = len(corpus)
    print(f"  {n} IPs", flush=True)
    if n < ipcfg.cluster_min_cluster_size:
        print("ERROR: too few IPs.")
        return 1

    include_provenance = args.geometry == "current"
    include_tier1 = args.geometry in ("k2", "k4")
    include_tier2 = args.geometry == "k4"
    bags = None
    if include_tier2:
        sidx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
        print("pulling per-IP session-cluster bags (Tier 2) ...", flush=True)
        bags = _pull_session_cluster_bags(es, sidx)
        print(f"  bags for {len(bags)} IPs", flush=True)
    top_asns = _compute_top_asns(es, ips_idx, ipcfg.attribution_top_asns)
    builder = make_full_scalar_builder(
        top_asns=top_asns,
        attribution_weight=ipcfg.cluster_attribution_weight,
        cred_hash_dim=ipcfg.attribution_cred_hash_dim,
        hassh_weight=ipcfg.cluster_hassh_weight,
        hassh_hash_dim=ipcfg.attribution_hassh_hash_dim,
        include_provenance=include_provenance,
        include_tier1=include_tier1,
        include_tier2=include_tier2,
        session_cluster_bags=bags,
        tier2_dim=ipcfg.cluster_tier2_svd_dim,
    )
    scalars = [{
        "source_ip": m["ip"],
        "total_sessions": m["total_sessions"],
        "login_success_rate": m["login_success_rate"],
        "mean_novelty_score": m["mean_novelty_score"],
        "mean_session_duration_s": m["mean_session_duration_s"],
        "country_iso_code": m["country"],
        "as_number": m["asn"],
        "credentials": m["creds"],
        "hassh_distribution": m["hassh_distribution"] if args.fix_hassh else [],
        "external_rarity_score": 0.0,
        "consensus_malicious": False,
        "intent_distribution": m["intent_distribution"],
        "playbook_distribution": m["playbook_distribution"],
        "total_commands": m["total_commands"],
        "file_download_count": m["file_download_count"],
        "active_days": m["active_days"],
    } for m in corpus]

    normalized = l2_normalize(np.array([m["emb"] for m in corpus], dtype=np.float32))
    cluster_matrix = normalized
    if ipcfg.cluster_scalar_weight > 0.0:
        block = builder(scalars, ipcfg.cluster_scalar_weight)
        cluster_matrix = np.hstack([normalized, block])

    from sklearn.cluster import HDBSCAN
    labels = [int(x) for x in HDBSCAN(
        min_cluster_size=ipcfg.cluster_min_cluster_size,
        min_samples=ipcfg.cluster_min_samples,
        metric="euclidean",
    ).fit_predict(cluster_matrix)]

    by_cluster: dict[int, list[dict]] = defaultdict(list)
    for m, lbl in zip(corpus, labels):
        by_cluster[lbl].append(m)
    outliers = by_cluster.pop(-1, [])
    n_clusters = len(by_cluster)
    n_outliers = len(outliers)
    n_clustered = n - n_outliers

    profiles = []
    for cid, members in by_cluster.items():
        p = _profile_cluster(members)
        p["cluster"] = cid
        profiles.append(p)
    profiles.sort(key=lambda p: -p["size"])
    largest = profiles[0] if profiles else None
    largest_share = round(largest["size"] / n_clustered, 4) if largest and n_clustered else 0.0

    size_buckets = [(1, 2), (3, 5), (6, 10), (11, 25), (26, 50), (51, 100), (101, 10 ** 9)]
    hist = {f"{lo}-{hi if hi < 10**9 else '+'}":
            sum(1 for p in profiles if lo <= p["size"] <= hi) for lo, hi in size_buckets}

    pb_to_clusters: dict[str, list[int]] = defaultdict(list)
    for p in profiles:
        if p["dominant_playbook"]:
            pb_to_clusters[p["dominant_playbook"]].append(p["size"])
    fragmentation = {pb: sorted(sz, reverse=True)
                     for pb, sz in pb_to_clusters.items() if len(sz) > 1}

    zgrab_clusters = Counter(
        lbl for m, lbl in zip(corpus, labels) if m["playbook"] == _ZGRAB_PLAYBOOK
    )
    zgrab_real = {c: cnt for c, cnt in zgrab_clusters.items() if c != -1}

    result = {
        "geometry": args.geometry, "fix_hassh": args.fix_hassh,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_ips": n, "n_clusters": n_clusters, "n_clustered": n_clustered,
        "n_outliers": n_outliers, "outlier_rate": round(n_outliers / n, 4),
        "largest_cluster_size": largest["size"] if largest else 0,
        "largest_cluster_share": largest_share,
        "largest_cluster_profile": largest,
        "size_histogram": hist,
        "fragmentation_case_count": len(fragmentation),
        "known_frag_cases": {pb: pb_to_clusters.get(pb, []) for pb in _KNOWN_FRAG_CASES},
        "zgrab_total_ips": sum(zgrab_clusters.values()),
        "zgrab_in_outliers": zgrab_clusters.get(-1, 0),
        "zgrab_cluster_spread": zgrab_real,
        "top_clusters": profiles[:args.top_k],
        "matrix_dims": int(cluster_matrix.shape[1]),
    }

    label = args.label or f"K-ip-clustering-{args.geometry}"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / f"{label}-{ts}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    L: list[str] = []
    L.append(f"# {label} — IP clustering diagnostic ({ts})")
    L.append("")
    L.append(f"- geometry: **{args.geometry}** · matrix dims: {result['matrix_dims']} · "
             f"HASSH: {'populated' if args.fix_hassh else 'dead (faithful to prod)'}")
    L.append(f"- IPs {n} · clusters {n_clusters} · clustered {n_clustered} · "
             f"outliers {n_outliers} (rate {result['outlier_rate']})")
    L.append(f"- largest cluster: {result['largest_cluster_size']} IPs ({largest_share:.1%} of clustered)")
    if largest:
        L.append(f"- largest cluster modal intent share: {largest.get('modal_intent_share')} "
                 f"(intent={largest.get('modal_intent')})")
    L.append(f"- fragmentation cases: {len(fragmentation)}")
    L.append("")
    L.append(f"## Zgrab regression (`{_ZGRAB_PLAYBOOK}`)")
    L.append(f"- {result['zgrab_total_ips']} IPs → {len(zgrab_real)} cluster(s) "
             f"+ {result['zgrab_in_outliers']} outliers · spread {zgrab_real}")
    L.append("")
    L.append("## Size histogram")
    L.append("| bucket | clusters |")
    L.append("|---|---:|")
    for k, v in hist.items():
        L.append(f"| {k} | {v} |")
    L.append("")
    L.append("## Known fragmentation cases: cluster count")
    L.append("| dominant_playbook | clusters | sizes |")
    L.append("|---|---:|---|")
    for pb in _KNOWN_FRAG_CASES:
        szs = sorted(pb_to_clusters.get(pb, []), reverse=True)
        L.append(f"| `{pb}` | {len(szs)} | {szs[:12]}{' …' if len(szs) > 12 else ''} |")
    L.append("")
    L.append(f"## Top {args.top_k} clusters")
    L.append("| cluster | size | playbook | modal intent share | intent uniq | country uniq | ASN uniq |")
    L.append("|---:|---:|---|---:|---:|---:|---:|")
    for p in profiles[:args.top_k]:
        mis = f"{p['modal_intent_share']:.2f}" if p["modal_intent_share"] is not None else "—"
        L.append(f"| {p['cluster']} | {p['size']} | `{p['dominant_playbook']}` | "
                 f"{mis} ({p['modal_intent']}) | {p['intent_unique']} | "
                 f"{p['country_unique']} | {p['asn_unique']} |")
    L.append("")
    (args.output_dir / f"{label}-{ts}.md").write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))
    print(f"\nwrote {args.output_dir / f'{label}-{ts}.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
