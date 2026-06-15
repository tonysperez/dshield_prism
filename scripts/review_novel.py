"""Review aid for the I3 shadow novel pool — surface the sessions the console can't
filter yet.

Pulls session rollups tagged `cluster.assignment_status = novel` (written by
`assign_shadow_write.py`), groups them by `command_signature` so near-duplicates
collapse to one reviewable behaviour, splits them into the two novel categories, and
renders a review file. The question to answer per group: is this genuinely
marginal/new, or is Option-A being too strict on ordinary traffic?

Two categories (from `assignment_cosine`, the nearest-anchor cosine even for novels):
  * **below_tau**  (cos < tau)            — genuinely far from every known anchor.
  * **band_conflation** (tau ≤ cos < confident) — embedding thought it was close to a
    known anchor, but the TF-IDF secondary signal said different behaviour.

OUTPUT SPLIT (privacy): raw command text goes ONLY to the rendered review FILE (for the
operator to read on their own box). STDOUT is aggregates only — counts, distinct
signatures (hashes), intents (enums), categories — safe to share. The agent must not
read the review file (confidential honeypot command text).

public-only filter BY DEFAULT; `--allow-unclassified` is an OPERATOR decision. The
agent does not run the unfiltered review.

Run from repo root via the console venv:
    console/.venv/bin/python scripts/review_novel.py --limit 2000
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_STATUS_FIELD = f"{_S}.cluster.assignment_status"
_COS_FIELD = f"{_S}.cluster.assignment_cosine"
_SIG_FIELD = f"{_S}.command_signature"
_INTENT_FIELD = f"{_S}.dominant_intent"
_TEXT_FIELD = f"{_S}.command_stream_text"
_PB_FIELD = f"{_S}.playbook_id"
_PBNAME_FIELD = f"{_S}.playbook_name"
_SOURCE = [_SIG_FIELD, _INTENT_FIELD, _TEXT_FIELD, _PB_FIELD, _PBNAME_FIELD, _COS_FIELD]


def _sb(src: dict) -> dict:
    return (((src.get("dshield") or {}).get("cowrie") or {})
            .get("enrichment", {}).get("session", {}))


def categorize(cosine, *, tau: float, confident_tau: float) -> str:
    if cosine is None:
        return "below_tau"
    if cosine < tau:
        return "below_tau"
    if cosine < confident_tau:
        return "band_conflation"
    return "confident"  # shouldn't be novel; defensive bucket


def group_novel(rows: list[dict], *, tau: float, confident_tau: float) -> list[dict]:
    """Group novel rows by command_signature. Each row: {signature, intent, current_pb,
    current_name, cosine, text}. Returns groups sorted by count desc; `example_text` is
    one representative command stream (file-only — never put in the stdout summary)."""
    by_sig: dict[str, list[dict]] = {}
    for r in rows:
        by_sig.setdefault(r.get("signature") or "∅", []).append(r)
    groups = []
    for sig, members in by_sig.items():
        cosines = [m["cosine"] for m in members if m["cosine"] is not None]
        cats = Counter(categorize(m["cosine"], tau=tau, confident_tau=confident_tau)
                       for m in members)
        groups.append({
            "signature": sig, "count": len(members),
            "category": cats.most_common(1)[0][0],
            "intents": sorted({m["intent"] for m in members if m.get("intent")}),
            "current_playbooks": sorted({(m.get("current_name") or m.get("current_pb") or "?")
                                         for m in members}),
            "cosine_min": round(min(cosines), 4) if cosines else None,
            "cosine_max": round(max(cosines), 4) if cosines else None,
            "example_text": next((m.get("text") for m in members if m.get("text")), ""),
        })
    return sorted(groups, key=lambda g: -g["count"])


def fetch_novel(es, idx, filt, limit):
    body = {"size": min(limit, 10000), "_source": _SOURCE,
            "query": {"bool": {"filter": filt + [{"term": {_STATUS_FIELD: "novel"}}]}},
            "sort": [{"_doc": "asc"}]}
    rows, sa = [], None
    while len(rows) < limit:
        if sa:
            body["search_after"] = sa
        resp = es.search(index=idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            s = _sb(h["_source"])
            cl = s.get("cluster") or {}
            rows.append({
                "signature": s.get("command_signature"),
                "intent": s.get("dominant_intent"),
                "current_pb": s.get("playbook_id"),
                "current_name": s.get("playbook_name"),
                "cosine": cl.get("assignment_cosine"),
                "text": s.get("command_stream_text") or "",
            })
            if len(rows) >= limit:
                break
        sa = hits[-1]["sort"]
    return rows


def render_file(groups, meta) -> str:
    L = [f"# Novel-pool review — {meta['n_novel']} sessions, {len(groups)} distinct signatures\n",
         f"_Captured {meta['captured_at']}. tau={meta['tau']}, confident={meta['confident_tau']}._\n",
         "_Each group is one command-signature behaviour. Decide: genuinely new/marginal, "
         "or ordinary traffic Option-A is too strict on?_\n"]
    for g in groups:
        L.append(f"## [{g['category']}] signature `{g['signature']}` ×{g['count']} "
                 f"(cos {g['cosine_min']}–{g['cosine_max']})")
        L.append(f"- HDBSCAN currently calls these: {', '.join(g['current_playbooks'])}")
        L.append(f"- intents: {', '.join(g['intents']) or '—'}")
        L.append("- example command stream:")
        L.append("```")
        L.append((g["example_text"] or "").strip()[:2000])
        L.append("```\n")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--limit", type=int, default=2000)
    ap.add_argument("--allow-unclassified", action="store_true",
                    help="OPERATOR ONLY: drop the public-only filter. Agent never sets it.")
    ap.add_argument("--out-dir", default="eval/results")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    sc = cfg.session
    tau = getattr(sc, "assignment_tau", 0.94)
    confident_tau = getattr(sc, "assignment_confident_tau", 0.98)

    filt = ([] if args.allow_unclassified else [releasable_filter(cfg)])
    if args.allow_unclassified:
        print("WARNING: --allow-unclassified set; reading novel sessions WITHOUT the "
              "public-only filter (operator-authorised).", file=sys.stderr)

    rows = fetch_novel(es, idx, filt, args.limit)
    if not rows:
        print("No shadow-novel sessions found. (Run assign_shadow_write.py first; on the "
              "untagged corpus the public-only filter returns 0 — use --allow-unclassified.)")
        return 0
    groups = group_novel(rows, tau=tau, confident_tau=confident_tau)
    cats = Counter(g["category"] for g in groups)
    cat_sessions = Counter()
    for g in groups:
        cat_sessions[g["category"]] += g["count"]

    # STDOUT = aggregates only (no command text)
    print(f"Novel pool: {len(rows)} sessions, {len(groups)} distinct signatures")
    print(f"  by session: { dict(cat_sessions) }")
    print(f"  by signature: { dict(cats) }")
    print("  top signatures (count — category — intents):")
    for g in groups[:15]:
        print(f"    {g['signature']}  ×{g['count']}  {g['category']}  "
              f"{','.join(g['intents']) or '—'}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    meta = {"captured_at": datetime.now(timezone.utc).isoformat(), "n_novel": len(rows),
            "tau": tau, "confident_tau": confident_tau}
    review_path = out_dir / f"novel-review-{ts}.md"
    review_path.write_text(render_file(groups, meta))
    print(f"\nwrote review file (command text — operator only): {review_path}")
    print("Open it to eyeball each behaviour. Do NOT paste its contents to the agent "
          "(confidential); the summary above is safe to share.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
