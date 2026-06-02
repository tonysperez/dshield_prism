"""Command-layer clustering regression gate (self-consistency).

The session layers have an analyst-labeled eval set; the command layer
does not. So this gate scores the command clustering on self-consistency
metrics that catch the regressions that matter — chiefly the F1b noise
rescue silently turning off (outlier rate spiking back from ~2% to ~28%)
or the clustering collapsing.

It re-runs the production command-clustering math offline (L2-normalize +
command scalar block + HDBSCAN + noise rescue — same as
``commands.run_cluster``) against a committed snapshot, with no ES, and
reports:

  * ``outlier_rate``          — n_outliers / n. Ceiling-gated (the rescue guard).
  * ``n_rescued``             — outliers rejoined to a centroid. Floor-gated.
  * ``n_clusters``            — non-noise clusters. Informational.
  * ``cluster_intent_purity`` — mean over clusters of the modal-``intent``
                                share. Floor-gated (clustering-quality guard).

Gate direction is per-metric (outlier_rate fails when it rises; purity /
n_rescued fail when they fall), unlike the session gate's uniform
higher-is-better tolerance.

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/eval_command_scale.py \\
      --snapshot eval/command-snapshot-v1.jsonl.gz \\
      --baseline eval/baseline-command-scale.json
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.cluster import HDBSCAN

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.clustering import l2_normalize, rescue_noise_points
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.commands import build_command_scalar_block

# Per-metric gate direction. "max" = current may not exceed baseline+tol
# (lower is better); "min" = current may not fall below baseline-tol.
_GATE = {
    "outlier_rate":         ("max", 0.05),
    "cluster_intent_purity": ("min", 0.05),
    "n_rescued":            ("min", 0.20),   # relative: allow 20% fewer rescued
}


def _scalars_from_source(src: dict) -> tuple[list[float] | None, dict, str | None]:
    en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment", {})
    emb = en.get("embedding")
    if not emb:
        return None, {}, None
    occ = en.get("occurrence_count") or 1
    scalars = {
        "occurrence_count":   occ,
        "unique_sessions":    en.get("unique_sessions") or 1,
        "unique_source_ips":  en.get("unique_source_ips") or 1,
        "confidence":         en.get("confidence") or 5,
        "session_reuse_rate": min((en.get("unique_sessions") or 1) / occ, 1.0),
    }
    return emb, scalars, en.get("intent")


def _load_snapshot(path: Path):
    embs, scalars, intents = [], [], []
    meta: dict = {}
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if i == 0 and rec.get("_metadata"):
                meta = rec
                continue
            emb, sc, intent = _scalars_from_source(rec.get("_source") or {})
            if emb is None:
                continue
            embs.append(emb)
            scalars.append(sc)
            intents.append(intent)
    return embs, scalars, intents, meta


def _load_live(cfg, secrets):
    es = make_client(cfg.elasticsearch, secrets)
    idx = cfg.elasticsearch.indexes.cowrie.commands
    embs, scalars, intents = [], [], []
    # iter_enriched_docs doesn't yield intent; pull it in a parallel _source.
    base = "dshield.cowrie.enrichment"
    body = {"size": cfg.command_cluster.page_size,
            "_source": [f"{base}.embedding", f"{base}.occurrence_count",
                        f"{base}.unique_sessions", f"{base}.unique_source_ips",
                        f"{base}.confidence", f"{base}.intent"],
            "query": {"exists": {"field": f"{base}.embedding"}},
            "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}]}
    sa = None
    while True:
        if sa:
            body["search_after"] = sa
        r = es.search(index=idx, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            emb, sc, intent = _scalars_from_source(h["_source"])
            if emb is None:
                continue
            embs.append(emb)
            scalars.append(sc)
            intents.append(intent)
        sa = hits[-1]["sort"]
    return embs, scalars, intents


def _evaluate(embs, scalars, intents, ccfg) -> dict:
    matrix = np.array(embs, dtype=np.float32)
    normalized = l2_normalize(matrix)
    if ccfg.scalar_weight > 0.0:
        block = build_command_scalar_block(scalars, ccfg.scalar_weight)
        cluster_matrix = np.hstack([normalized, block])
    else:
        cluster_matrix = normalized
    labels = HDBSCAN(min_cluster_size=ccfg.min_cluster_size,
                     min_samples=ccfg.min_samples,
                     metric="euclidean").fit_predict(cluster_matrix)
    n_rescued = 0
    if ccfg.rescue_threshold and ccfg.rescue_threshold > 0.0:
        labels, n_rescued = rescue_noise_points(normalized, labels, ccfg.rescue_threshold)

    n = len(labels)
    n_outliers = int((labels == -1).sum())
    n_clusters = len({int(c) for c in labels if c >= 0})

    # mean modal-intent share across non-noise clusters
    byc: dict = defaultdict(list)
    for lbl, it in zip(labels, intents):
        if lbl >= 0:
            byc[int(lbl)].append(it or "")
    purities = []
    for members in byc.values():
        named = [m for m in members if m]
        if named:
            top = Counter(named).most_common(1)[0][1]
            purities.append(top / len(named))
    purity = round(sum(purities) / len(purities), 4) if purities else None

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "min_cluster_size": ccfg.min_cluster_size,
            "min_samples": ccfg.min_samples,
            "scalar_weight": ccfg.scalar_weight,
            "rescue_threshold": ccfg.rescue_threshold,
        },
        "n_commands": n,
        "metrics": {
            "outlier_rate":          round(n_outliers / n, 4) if n else 0.0,
            "n_rescued":             n_rescued,
            "n_clusters":            n_clusters,
            "cluster_intent_purity": purity,
        },
    }


def _compare(report: dict, baseline_path: Path):
    base = json.loads(baseline_path.read_text(encoding="utf-8"))
    cur = report["metrics"]
    rows, ok = [], True
    for name, spec in base["metrics"].items():
        direction, tol = _GATE.get(name, ("min", spec.get("tolerance", 0.05)))
        b = spec["baseline"]
        c = cur.get(name)
        if c is None:
            rows.append((name, b, None, direction, "MISSING")); ok = False; continue
        if direction == "max":
            status = "PASS" if c <= b + tol else "FAIL"
        elif name == "n_rescued":  # relative floor
            status = "PASS" if c >= b * (1 - tol) else "FAIL"
        else:
            status = "PASS" if c >= b - tol else "FAIL"
        if status == "FAIL":
            ok = False
        rows.append((name, b, c, direction, status))
    return rows, ok


def _render(report: dict) -> str:
    m = report["metrics"]; c = report["config"]
    out = ["=" * 64, "Command-layer clustering eval (self-consistency)", "=" * 64]
    out.append(f"config   mcs={c['min_cluster_size']} ms={c['min_samples']} "
               f"scalar_weight={c['scalar_weight']} rescue={c['rescue_threshold']}")
    out.append(f"commands {report['n_commands']}")
    out.append(f"  outlier_rate           {m['outlier_rate']}")
    out.append(f"  n_rescued              {m['n_rescued']}")
    out.append(f"  n_clusters             {m['n_clusters']}")
    out.append(f"  cluster_intent_purity  {m['cluster_intent_purity']}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config-path", type=str, default=None)
    ap.add_argument("--snapshot", type=Path, default=None,
                    help="Score offline from a command snapshot (CI). Omit to use live ES.")
    ap.add_argument("--baseline", type=Path, default=None,
                    help="Gate against this baseline; non-zero exit on regression.")
    ap.add_argument("--write-baseline", type=Path, default=None)
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--no-json", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config_path)
    if args.snapshot is not None:
        embs, scalars, intents, meta = _load_snapshot(args.snapshot)
    else:
        secrets = load_secrets(args.config_path)
        embs, scalars, intents = _load_live(cfg, secrets)
        meta = {}
    if len(embs) < cfg.command_cluster.min_cluster_size:
        raise SystemExit(f"only {len(embs)} embedded commands — too few to cluster")

    report = _evaluate(embs, scalars, intents, cfg.command_cluster)
    report["snapshot_metadata"] = meta or None
    print(_render(report))

    if args.write_baseline is not None:
        doc = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "captured_from": "scripts/eval_command_scale.py --write-baseline",
            "config_at_capture": report["config"],
            "n_commands_at_capture": report["n_commands"],
            "tolerance_semantic": (
                "outlier_rate: ceiling (fail if > baseline + 0.05). "
                "cluster_intent_purity: floor (fail if < baseline - 0.05). "
                "n_rescued: relative floor (fail if < 80% of baseline). "
                "n_clusters: informational."
            ),
            "metrics": {
                "outlier_rate":          {"baseline": report["metrics"]["outlier_rate"]},
                "cluster_intent_purity": {"baseline": report["metrics"]["cluster_intent_purity"]},
                "n_rescued":             {"baseline": report["metrics"]["n_rescued"]},
                "n_clusters":            {"baseline": report["metrics"]["n_clusters"]},
            },
        }
        args.write_baseline.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote baseline {args.write_baseline}")

    if not args.no_json:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        p = args.output_dir / f"command-scale-{ts}.json"
        p.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {p}")

    if args.baseline is not None:
        rows, ok = _compare(report, args.baseline)
        print("\n" + "=" * 64)
        print("Command-layer regression gate")
        print("=" * 64)
        print(f"  {'metric':24} {'baseline':>10} {'current':>10} {'dir':>5}  status")
        for name, b, c, d, st in rows:
            cs = "—" if c is None else f"{c}"
            print(f"  {name:24} {b:>10} {cs:>10} {d:>5}  {st}")
        print(f"\nGATE: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
