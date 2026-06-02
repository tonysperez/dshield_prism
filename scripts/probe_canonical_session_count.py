"""H0.1 — canonicalisation viability probe.

All of Phase H rests on one assumption: that deduping sessions by
``command_signature`` (the sha256 over a session's sorted unique command
hashes) collapses the command-bearing corpus to a *small* shape count, so
an LLM summary per shape (cached, sessions inherit) is affordable. This
measures it — read-only, via ES aggregations, no full pull.

Reports the H0.2 decision inputs:
  * total / command-bearing session counts
  * unique command_signature + command_bigram_signature shape counts
  * top-50 shapes by member count + their cumulative session coverage
  * distribution: shapes with ≥10 members (high caching value) vs exactly
    1 member (canonicalisation buys nothing — these fall back to baseline)

Decision (H0.2, hard gate):
  * shapes > 20,000           → H not affordable, stop.
  * ≤20,000 and top-50 ≥ 50% of command-bearing → highly viable.
  * 5k–20k and top-50 20–50%  → marginal (cap to top-K + baseline fallback).

Run from the repo root via the console venv.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_SB = "dshield.cowrie.enrichment.session"
_SIG = f"{_SB}.command_signature.keyword"
_BIGRAM = f"{_SB}.command_bigram_signature.keyword"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--top", type=int, default=50)
    args = ap.parse_args()

    cfg = load_config()
    es = make_client(cfg.elasticsearch, load_secrets())
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup

    total = es.count(index=idx, query={"match_all": {}})["count"]
    cmd_bearing = es.count(
        index=idx, query={"range": {f"{_SB}.command_count": {"gt": 0}}})["count"]
    with_sig = es.count(index=idx, query={"exists": {"field": _SIG}})["count"]
    bigram_shapes = es.search(
        index=idx, size=0, aggs={"c": {"cardinality": {"field": _BIGRAM}}}
    )["aggregations"]["c"]["value"]

    # Full shape distribution: terms agg sized above the cardinality so every
    # shape bucket comes back exactly (no doc_count_error).
    sig_card = es.search(
        index=idx, size=0, aggs={"c": {"cardinality": {"field": _SIG}}}
    )["aggregations"]["c"]["value"]
    agg_size = int(sig_card) + 100
    buckets = es.search(index=idx, size=0, aggs={
        "shapes": {"terms": {"field": _SIG, "size": agg_size}}
    })["aggregations"]["shapes"]["buckets"]
    counts = sorted((b["doc_count"] for b in buckets), reverse=True)
    n_shapes = len(counts)
    members_total = sum(counts)

    topn = counts[: args.top]
    top_cov = sum(topn)
    n_ge10 = sum(1 for c in counts if c >= 10)
    n_singletons = sum(1 for c in counts if c == 1)
    singleton_session_share = n_singletons / members_total if members_total else 0.0

    # dedup ratio = sessions per shape; >1 means caching pays off.
    dedup = members_total / n_shapes if n_shapes else 0.0
    top_cov_pct = top_cov / members_total if members_total else 0.0

    # H0.2 verdict
    if n_shapes > 20000:
        verdict = "STOP — > 20,000 shapes; H not affordable at this corpus size."
    elif top_cov_pct >= 0.50:
        verdict = f"HIGHLY VIABLE — top-{args.top} cover {top_cov_pct:.0%} ≥ 50%; proceed to H1."
    elif top_cov_pct >= 0.20:
        verdict = (f"MARGINAL — top-{args.top} cover {top_cov_pct:.0%} (20–50%); "
                   "cap H to top-K shapes + baseline fallback; escalate to operator.")
    else:
        verdict = (f"MARGINAL/POOR — top-{args.top} cover only {top_cov_pct:.0%}; "
                   "long-tail dominates, canonicalisation buys little. Escalate.")

    out = ["# H0 — canonicalisation viability probe", ""]
    out.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_ · index `{idx}`")
    out.append("")
    out.append(f"- total sessions: **{total}**")
    out.append(f"- command-bearing (command_count > 0): **{cmd_bearing}** "
               f"(with command_signature: {with_sig})")
    out.append(f"- **unique shapes (command_signature): {n_shapes}** "
               f"(command_bigram_signature: {bigram_shapes})")
    out.append(f"- dedup ratio (sessions / shape): **{dedup:.2f}**  "
               f"(1.0 = every session unique; higher = caching pays off)")
    out.append(f"- **top-{args.top} shapes cover {top_cov} / {members_total} sessions "
               f"= {top_cov_pct:.1%}**")
    out.append(f"- shapes with ≥10 members: {n_ge10}  ·  singletons (1 member): "
               f"{n_singletons} ({singleton_session_share:.1%} of command-bearing sessions)")
    out.append("")
    out.append(f"## H0.2 verdict: {verdict}")
    out.append("")
    out.append(f"Top {args.top} shapes by member count:")
    out.append("")
    out.append("| rank | members | cumulative % |")
    out.append("|---:|---:|---:|")
    cum = 0
    for i, c in enumerate(topn, 1):
        cum += c
        out.append(f"| {i} | {c} | {cum/members_total:.1%} |")
    md = "\n".join(out)
    print(md)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    p = args.output_dir / f"H0-canonical-probe-{ts}.md"
    p.write_text(md, encoding="utf-8")
    print(f"\nwrote {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
