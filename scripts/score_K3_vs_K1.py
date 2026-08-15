"""Phase K — score a candidate-geometry run against the baseline on the 7
binding adoption metrics. Reads two JSONs from `diagnose_ip_clustering.py`.

Adoption requires ALL 7 PASS; any FAIL = revert (or, per K3.3, conditionally
escalate to Tier 2). Works for K1↔K3 (Tier 1 + drop) and K1↔K5 (Tier 2).

    console/.venv/bin/python scripts/score_K3_vs_K1.py \\
        --k1 eval/results/K1-baseline-<ts>.json \\
        --k3 eval/results/K3-post-tier1-drop-<ts>.json [--session-ari-delta 0.0]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

_KNOWN_FRAG_CASES = [
    "spb-feab4397c2bdcac3", "spb-89c10e55e4cfa78d", "spb-94d8703fbaf4fae1",
    "spb-bfb392ed9fdaa5e4", "spb-a30bd43f516f312e", "spb-d27502498192ccc5",
]


def _row(metric, ok, detail):
    return {"metric": metric, "pass": bool(ok), "detail": detail}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--k1", type=Path, required=True)
    ap.add_argument("--k3", type=Path, required=True)
    ap.add_argument("--session-ari-delta", type=float, default=0.0)
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    args = ap.parse_args()

    k1 = json.loads(args.k1.read_text())
    k3 = json.loads(args.k3.read_text())
    rows = []

    spread = k3.get("zgrab_cluster_spread", {})
    m1 = len(spread) == 1 and k3.get("zgrab_in_outliers", 0) == 0
    rows.append(_row("1_zgrab_consolidates", m1,
                     f"{len(spread)} cluster(s) + {k3.get('zgrab_in_outliers',0)} outliers"))

    k1f, k3f = k1["known_frag_cases"], k3["known_frag_cases"]
    consolidated = [pb for pb in _KNOWN_FRAG_CASES
                    if len(k3f.get(pb, [])) < len(k1f.get(pb, []))]
    rows.append(_row("2_fragmentation_drops", len(consolidated) >= 4,
                     f"{len(consolidated)}/6: " + ", ".join(
                         f"{pb.split('-')[1][:6]}:{len(k1f.get(pb,[]))}→{len(k3f.get(pb,[]))}"
                         for pb in _KNOWN_FRAG_CASES)))

    rows.append(_row("3_cluster_count_above_floor", k3["n_clusters"] >= 25,
                     f"{k3['n_clusters']} (floor 25)"))

    prof = k3.get("largest_cluster_profile") or {}
    share = prof.get("modal_intent_share")
    rows.append(_row("4_intent_coherence", share is not None and share >= 0.80,
                     f"largest-cluster modal intent share = {share} "
                     f"(intent={prof.get('modal_intent')}, {prof.get('intent_present')}/{prof.get('size')} labelled)"))

    rows.append(_row("5_no_mega_cluster", k3["largest_cluster_share"] <= 0.30,
                     f"largest = {k3['largest_cluster_size']} IPs "
                     f"({k3['largest_cluster_share']:.1%}, ceiling 30%)"))

    orate = k3["outlier_rate"]
    rows.append(_row("6_outlier_rate_in_band", 0.05 <= orate <= 0.25,
                     f"{orate:.1%} (band 5–25%)"))

    rows.append(_row("7_session_ari_stable", abs(args.session_ari_delta) < 0.01,
                     f"Δ={args.session_ari_delta:+.4f} (via eval_clustering gate)"))

    all_pass = all(r["pass"] for r in rows)
    # K3.3 decision tree.
    by = {r["metric"]: r["pass"] for r in rows}
    if all_pass:
        verdict = "ADOPT (K6.1a)"
    elif not by["5_no_mega_cluster"] and by["1_zgrab_consolidates"] and by["2_fragmentation_drops"]:
        verdict = "ESCALATE to Tier 2 (K4) — right direction, still mega-clustering"
    else:
        verdict = "REVERT (K6.1b)"

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    L = [f"# K scorecard — {args.k3.name} vs {args.k1.name} ({ts})", "",
         f"## VERDICT: {verdict}", "",
         "| metric | result | detail |", "|---|:--:|---|"]
    for r in rows:
        L.append(f"| {r['metric']} | {'PASS' if r['pass'] else '**FAIL**'} | {r['detail']} |")
    L += ["", "## K1 ↔ K3 diff", "", "| measure | K1 | K3 |", "|---|---:|---:|",
          f"| clusters | {k1['n_clusters']} | {k3['n_clusters']} |",
          f"| outlier rate | {k1['outlier_rate']:.1%} | {k3['outlier_rate']:.1%} |",
          (f"| largest cluster | {k1['largest_cluster_size']} ({k1['largest_cluster_share']:.1%}) "
           f"| {k3['largest_cluster_size']} ({k3['largest_cluster_share']:.1%}) |"),
          (f"| largest modal intent share | {(k1.get('largest_cluster_profile') or {}).get('modal_intent_share')} "
           f"| {(k3.get('largest_cluster_profile') or {}).get('modal_intent_share')} |"), ""]
    out = args.output_dir / f"K3-scorecard-{ts}.md"
    out.write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))
    print(f"\nwrote {out}")
    return 0 if all_pass else 2


if __name__ == "__main__":
    sys.exit(main())
