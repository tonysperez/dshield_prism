"""F1.2 / F1.3 — per-layer outlier diagnostic (command + IP layers).

The session layer has a noise-rescue safety valve (outliers within
``playbook_merge_threshold`` cosine of a centroid rejoin it); the command
and IP layers do **not** — they run HDBSCAN with no rescue and no merge,
so their "outliers" are pre-rescue and over-counted relative to sessions.
The plan's ~1.5k outlier mass lives almost entirely here.

For a layer, this script answers the F1b decision question: are the
outliers *rescue candidates* (close to an existing centroid — HDBSCAN
density noise) or *genuinely novel* (far from everything)? It pulls every
scored doc, rebuilds non-outlier centroids in pure-embedding space (the
geometry ``rescue_noise_points`` uses), and for each outlier reports the
cosine to its nearest centroid + whether that centroid shares its intent.

If most outliers sit within ~the session merge threshold of a centroid,
**rescue** (F1b) is the right fix and will cut the outlier rate sharply.
If most are far, secondary HDBSCAN (F2) or "they're really novel" applies.

Read-only. Run from the repo root via the console venv:
    console/.venv/bin/python scripts/diagnose_outlier_subclusters.py --layer commands
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.clustering import l2_normalize
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

# Per-layer field map. `purity_field` is the per-doc label used to check that
# a rescued doc joins a same-behaviour cluster (the F1b sanity check); for
# commands/sessions it's the intent, for IPs the dominant playbook.
_LAYERS = {
    "commands": {
        "index_attr":  "commands",
        "base":        "dshield.cowrie.enrichment",
        "emb":         "dshield.cowrie.enrichment.embedding",
        "cid":         "dshield.cowrie.enrichment.cluster.id",
        "outlier":     "dshield.cowrie.enrichment.cluster.is_outlier",
        "purity":      "dshield.cowrie.enrichment.intent",
        "purity_name": "intent",
    },
    "ips": {
        "index_attr":  "ips_rollup",
        "base":        "dshield.cowrie.enrichment.ip",
        "emb":         "dshield.cowrie.enrichment.ip.embedding",
        "cid":         "dshield.cowrie.enrichment.ip.cluster.id",
        "outlier":     "dshield.cowrie.enrichment.ip.cluster.is_outlier",
        "purity":      "dshield.cowrie.enrichment.ip.dominant_playbook_id",
        "purity_name": "dominant_playbook_id",
    },
}

_THRESHOLDS = (0.98, 0.96, 0.94, 0.92, 0.90, 0.85, 0.80)


def _dig(src: dict, dotted: str):
    cur = src
    for k in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _pull(es, index: str, fields: dict):
    body = {
        "size": 1000,
        "_source": [fields["emb"], fields["cid"], fields["outlier"], fields["purity"]],
        "query": {"exists": {"field": fields["outlier"]}},
        "sort": [{"_doc": "asc"}],
    }
    embs, cids, outl, pur = [], [], [], []
    sa = None
    while True:
        if sa:
            body["search_after"] = sa
        r = es.search(index=index, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            src = h["_source"]
            emb = _dig(src, fields["emb"])
            if not emb:
                continue
            embs.append(emb)
            cids.append(_dig(src, fields["cid"]))
            outl.append(bool(_dig(src, fields["outlier"])))
            pur.append(_dig(src, fields["purity"]) or "")
        sa = hits[-1]["sort"]
    return embs, cids, outl, pur


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--layer", choices=sorted(_LAYERS), default="commands")
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--no-md", action="store_true")
    args = ap.parse_args()

    fields = _LAYERS[args.layer]
    cfg = load_config()
    es = make_client(cfg.elasticsearch, load_secrets())
    index = getattr(cfg.elasticsearch.indexes.cowrie, fields["index_attr"])
    if not es.indices.exists(index=index):
        raise SystemExit(f"index {index} absent")

    embs, cids, outl, pur = _pull(es, index, fields)
    if not embs:
        raise SystemExit(f"no scored {args.layer} docs with embeddings in {index}")
    norm = l2_normalize(np.array(embs, dtype=np.float32))
    outl = np.array(outl)
    pur = np.array(pur)
    n, n_out = len(embs), int(outl.sum())

    byc: dict = defaultdict(list)
    for i, (c, o) in enumerate(zip(cids, outl)):
        if not o and c not in (None, "outlier", ""):
            byc[c].append(i)
    cent_ids = sorted(byc)
    if not cent_ids:
        raise SystemExit("no non-outlier clusters — nothing to rescue toward")
    C = np.array([norm[byc[c]].mean(0) for c in cent_ids])
    C = C / (np.linalg.norm(C, axis=1, keepdims=True) + 1e-12)
    cent_purity = {c: Counter(pur[byc[c]]).most_common(1)[0][0] for c in cent_ids}

    oidx = np.where(outl)[0]
    sims = norm[oidx] @ C.T
    nearest = sims.max(1)
    nn = sims.argmax(1)

    rows = []
    for thr in _THRESHOLDS:
        mask = nearest >= thr
        cnt = int(mask.sum())
        # intent/playbook match among would-be-rescued at this threshold
        match = sum(
            1 for k in range(len(oidx))
            if mask[k] and pur[oidx[k]] and pur[oidx[k]] == cent_purity[cent_ids[nn[k]]]
        )
        rows.append((thr, cnt, cnt / n_out if n_out else 0.0,
                     match, (match / cnt if cnt else 0.0)))

    lines = []
    lines.append(f"# F1 outlier diagnostic — {args.layer} layer")
    lines.append("")
    lines.append(f"_Captured {datetime.now(timezone.utc).isoformat()}_")
    lines.append("")
    lines.append(f"- **Index:** `{index}`")
    lines.append(f"- **Scored docs:** {n}  ·  **non-outlier clusters:** {len(cent_ids)}")
    lines.append(f"- **Outliers:** {n_out}  (**{n_out/n:.1%}** — PRE-rescue; this "
                 "layer has no rescue valve, unlike sessions)")
    lines.append(f"- **Median outlier→nearest-centroid cosine:** {np.median(nearest):.3f}")
    lines.append("")
    lines.append("Rescue candidates by threshold (outliers within cosine of a "
                 f"non-outlier centroid) + {fields['purity_name']}-match of the "
                 "would-be-rescued:")
    lines.append("")
    lines.append(f"| threshold | rescuable | % outliers | {fields['purity_name']}-match |")
    lines.append("|---:|---:|---:|---:|")
    for thr, cnt, frac, match, mrate in rows:
        lines.append(f"| {thr} | {cnt} | {frac:.1%} | {match}/{cnt} ({mrate:.0%}) |")
    lines.append("")
    # headline: effect of rescue at the session threshold (0.94)
    thr94 = next(r for r in rows if abs(r[0] - 0.94) < 1e-9)
    new_rate = (n_out - thr94[1]) / n
    lines.append(f"**At rescue 0.94:** {thr94[1]} of {n_out} outliers rejoin a "
                 f"centroid → outlier rate **{n_out/n:.1%} → {new_rate:.1%}** "
                 f"({thr94[4]:.0%} join a {fields['purity_name']}-matching cluster). "
                 "Rescue creates no new clusters, so bulk-cluster quality is "
                 "untouched.")
    md = "\n".join(lines)
    print(md)

    if not args.no_md:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = args.output_dir / f"outlier-subcluster-diagnostic-{args.layer}-{ts}.md"
        out.write_text(md, encoding="utf-8")
        print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
