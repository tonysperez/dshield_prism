"""IP noise-rescue viability + purity diagnostic (read-only).

Rebuilds the production IP clustering geometry (augmented `[embedding ⊕ scalars]`
space) from the live rollup using the PRODUCTION cluster labels — no re-cluster —
then applies `rescue_noise_points_augmented` at several intra-cluster-spread
percentiles and reports, for each:

  * rescued count + resulting outlier rate
  * rescue PURITY: of the rescued outliers, what fraction share the modal
    `dominant_playbook_id` / `dominant_intent` of the cluster they were rescued
    into. High purity = rescued IPs genuinely belong; low = the radius is too loose.

Use this to pick `ip.rescue_spread_percentile`. Never writes to ES.

    console/.venv/bin/python scripts/diagnose_ip_rescue.py
"""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import numpy as np

from enrich.clustering import compute_centroids, l2_normalize, rescue_noise_points_augmented
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.ips import (
    _active_days,
    _compute_top_asns,
    _pull_session_cluster_bags,
    make_full_scalar_builder,
)

PERCENTILES = (90, 95, 99)


def pull(es, idx, page):
    base = "dshield.cowrie.enrichment.ip"
    body = {
        "size": page,
        "_source": [
            "source.ip", "source.geo.country_iso_code", "source.as.number",
            f"{base}.embedding", f"{base}.total_sessions", f"{base}.successful_sessions",
            f"{base}.mean_novelty_score", f"{base}.mean_session_duration_s",
            f"{base}.credentials", f"{base}.hassh", f"{base}.hassh_distribution",
            f"{base}.dominant_intent", f"{base}.intent_distribution",
            f"{base}.dominant_playbook_id", f"{base}.playbook_distribution",
            f"{base}.total_commands", f"{base}.file_download_count",
            f"{base}.first_seen", f"{base}.last_seen", f"{base}.cluster.id",
        ],
        "query": {"exists": {"field": f"{base}.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    after = None
    while True:
        if after:
            body["search_after"] = after
        resp = es.search(index=idx, **body)
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
                "emb": emb,
                "label": str((ip_en.get("cluster") or {}).get("id") or "outlier"),
                "ip": source.get("ip", h["_id"]),
                "country": ((source.get("geo") or {}).get("country_iso_code")) or "",
                "asn": int(asn) if asn is not None else None,
                "creds": list(ip_en.get("credentials") or []),
                "hassh": ip_en.get("hassh") or "",
                "hassh_distribution": list(ip_en.get("hassh_distribution") or []),
                "dominant_intent": ip_en.get("dominant_intent"),
                "intent_distribution": list(ip_en.get("intent_distribution") or []),
                "dominant_playbook": ip_en.get("dominant_playbook_id"),
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


def main():
    cfg = load_config()
    es = make_client(cfg.elasticsearch, load_secrets())
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    ipc = cfg.ip
    print(f"pulling IP corpus from {idx} ...", flush=True)
    corpus = list(pull(es, idx, ipc.page_size))
    n = len(corpus)
    str_labels = np.array([m["label"] for m in corpus])
    is_out = str_labels == "outlier"
    n_out = int(is_out.sum())
    print(f"  {n} command-bearing IPs · clustered={n - n_out} · outliers={n_out} "
          f"({n_out / n * 100:.1f}%)", flush=True)

    # Integer-encode production labels (outlier -> -1) for the rescue function.
    cl_strs = sorted(set(str_labels[~is_out]))
    enc = {s: i for i, s in enumerate(cl_strs)}
    labels = np.array([-1 if s == "outlier" else enc[s] for s in str_labels])

    # Cluster modal dominant_playbook / dominant_intent from clustered members.
    modal_pb, modal_intent = {}, {}
    mem = defaultdict(list)
    for m, lb in zip(corpus, labels):
        if lb != -1:
            mem[lb].append(m)
    for lb, ms in mem.items():
        pb = Counter(x["dominant_playbook"] for x in ms if x["dominant_playbook"])
        it = Counter(x["dominant_intent"] for x in ms if x["dominant_intent"])
        modal_pb[lb] = pb.most_common(1)[0][0] if pb else None
        modal_intent[lb] = it.most_common(1)[0][0] if it else None

    # Build the augmented matrix (production geometry).
    print("building augmented vectors (production geometry) ...", flush=True)
    bags = _pull_session_cluster_bags(es, cfg.elasticsearch.indexes.cowrie.sessions_rollup)
    top_asns = _compute_top_asns(es, idx, ipc.attribution_top_asns)
    builder = make_full_scalar_builder(
        top_asns=top_asns, attribution_weight=ipc.cluster_attribution_weight,
        cred_hash_dim=ipc.attribution_cred_hash_dim, hassh_weight=ipc.cluster_hassh_weight,
        hassh_hash_dim=ipc.attribution_hassh_hash_dim,
        include_provenance=ipc.cluster_attribution_provenance_enabled,
        include_tier1=ipc.cluster_tier1_enabled, include_tier2=ipc.cluster_tier2_enabled,
        session_cluster_bags=bags, tier2_dim=ipc.cluster_tier2_svd_dim,
    )
    scalars = [{
        "source_ip": m["ip"], "total_sessions": m["total_sessions"],
        "login_success_rate": m["login_success_rate"], "mean_novelty_score": m["mean_novelty_score"],
        "mean_session_duration_s": m["mean_session_duration_s"], "country_iso_code": m["country"],
        "as_number": m["asn"], "credentials": m["creds"], "hassh_distribution": m["hassh_distribution"],
        "external_rarity_score": 0.0, "consensus_malicious": False,
        "intent_distribution": m["intent_distribution"], "playbook_distribution": m["playbook_distribution"],
        "total_commands": m["total_commands"], "file_download_count": m["file_download_count"],
        "active_days": m["active_days"],
    } for m in corpus]
    normalized = l2_normalize(np.array([m["emb"] for m in corpus], dtype=np.float32))
    block = builder(scalars, ipc.cluster_scalar_weight)
    aug = np.hstack([normalized, block]).astype(np.float32)
    cl_strs_by_enc = {i: s for s, i in enc.items()}
    print(f"  augmented dim={aug.shape[1]}  centroids={len(compute_centroids(aug, labels))}\n", flush=True)

    print(f"{'pctile':>6}  {'radius':>8}  {'rescued':>8}  {'outliers_left':>14}  "
          f"{'rate':>6}  {'playbook_purity':>15}  {'intent_purity':>13}")
    for p in PERCENTILES:
        new, n_resc, radius = rescue_noise_points_augmented(aug, labels, p)
        rescued_mask = (labels == -1) & (new != -1)
        pb_match = pb_tot = it_match = it_tot = 0
        for i in np.where(rescued_mask)[0]:
            assigned = int(new[i])
            ip = corpus[i]
            if ip["dominant_playbook"] and modal_pb.get(assigned):
                pb_tot += 1
                pb_match += int(ip["dominant_playbook"] == modal_pb[assigned])
            if ip["dominant_intent"] and modal_intent.get(assigned):
                it_tot += 1
                it_match += int(ip["dominant_intent"] == modal_intent[assigned])
        left = n_out - n_resc
        pbp = f"{pb_match / pb_tot * 100:.1f}%" if pb_tot else "n/a"
        itp = f"{it_match / it_tot * 100:.1f}%" if it_tot else "n/a"
        print(f"{p:>6}  {radius:>8.4f}  {n_resc:>8}  {left:>14}  "
              f"{left / n * 100:>5.1f}%  {pbp:>15}  {itp:>13}", flush=True)
        _ = cl_strs_by_enc  # (kept for ad-hoc cluster-id lookups)


if __name__ == "__main__":
    main()
