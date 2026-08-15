"""G2 — Arm C (deterministic_fingerprint) at production scale + corpus-wide
comparison vs baseline (label-free).

Clusters the live corpus on the G2.1 deterministic behavioural fingerprint
(file events, HASSH, login pattern, credentials, shape, geo/ASN — no LLM,
no embeddings) and compares it to the embedding baseline on the same
corpus-wide self-consistency signals used for Arm B, plus the v2
divergent-pair set (where Arm C *should* win — dp-009 shares the command
stream but plausibly differs in file events / HASSH).

Read-only, live ES.
    console/.venv/bin/python scripts/fingerprint_prod.py
    console/.venv/bin/python scripts/fingerprint_prod.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.cluster import HDBSCAN
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from compare_arms_corpus import _merge_bagspace, _self_consistency, _v2_rate
from eval_production_scale import (
    _apply_session_merge,
    _load_eval_session_ids_and_labels,
)
from prod_corpus import cluster_hdbscan, pull_session_corpus

from enrich.clustering import rescue_noise_points
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.session_fingerprint import (
    FINGERPRINT_DIM,
    build_fingerprint,
)

_FP_FIELDS = [
    "dshield.cowrie.enrichment.session.file_events",
    "dshield.cowrie.enrichment.session.credentials",
    "dshield.cowrie.enrichment.session.login_success_count",
    "dshield.cowrie.enrichment.session.login_fail_count",
    "dshield.cowrie.enrichment.session.command_count",
    "dshield.cowrie.enrichment.session.unique_commands",
    "dshield.cowrie.enrichment.session.command_entropy",
    "dshield.cowrie.enrichment.session.file_download_count",
    "dshield.cowrie.enrichment.session.file_upload_count",
    "cowrie.hassh",
    "cowrie.session_id",
    "source.geo.country_iso_code",
    "source.as.organization",
]


def pull_fingerprints(es, index: str, page_size: int) -> dict[str, np.ndarray]:
    body = {
        "size": page_size,
        "_source": _FP_FIELDS,
        "query": {"exists": {"field": "dshield.cowrie.enrichment.session.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    out: dict[str, np.ndarray] = {}
    sa = None
    while True:
        if sa:
            body["search_after"] = sa
        r = es.search(index=index, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            sid = (h["_source"].get("cowrie") or {}).get("session_id") or h["_id"]
            out[sid] = build_fingerprint(h["_source"])
        sa = hits[-1]["sort"]
    return out


def _self_test() -> int:
    base = {
        "dshield": {"cowrie": {"enrichment": {"session": {
            "command_count": 3, "unique_commands": 3, "login_success_count": 1,
            "credentials": ["root:x"], "file_events": [],
        }}}},
        "cowrie": {"hassh": "abc"}, "source": {"geo": {"country_iso_code": "CN"}},
    }
    import copy
    a1 = build_fingerprint(base)
    a2 = build_fingerprint(copy.deepcopy(base))
    det = bool(np.array_equal(a1, a2)) and a1.shape == (FINGERPRINT_DIM,)
    # identical commands, different file events -> different fingerprint
    diff = copy.deepcopy(base)
    diff["dshield"]["cowrie"]["enrichment"]["session"]["file_events"] = [
        {"action": "download", "sha256": "deadbeef"}]
    b = build_fingerprint(diff)
    distinct = not np.array_equal(a1, b)
    print(f"determinism (identical inputs -> identical vec): {det}")
    print(f"file-event sensitivity (same commands, diff files -> diff vec): {distinct}")
    ok = det and distinct
    print("SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-merge", action="store_true")
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()

    cfg = load_config(); scfg = cfg.session
    es = make_client(cfg.elasticsearch, load_secrets())
    ix = cfg.elasticsearch.indexes.cowrie
    thr = scfg.playbook_merge_threshold

    print(f"pulling corpus from {ix.sessions_rollup} ...", flush=True)
    corpus = pull_session_corpus(es, ix.sessions_rollup, scfg.page_size)
    print(f"  {len(corpus)} sessions", flush=True)
    print("building fingerprints ...", flush=True)
    fp_by_sid = pull_fingerprints(es, ix.sessions_rollup, scfg.page_size)
    fp = np.vstack([
        fp_by_sid.get(sid, np.zeros(FINGERPRINT_DIM, dtype=np.float32))
        for sid in corpus.session_ids
    ]).astype(np.float32)
    sid_to_label, pairs = _load_eval_session_ids_and_labels(
        Path("eval/labels.yaml"), Path("eval/labels-v2.yaml"))

    # Baseline: production hdbscan + rescue + merge.
    base, _ = cluster_hdbscan(
        corpus, min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
        scalar_weight=scfg.cluster_scalar_weight, rescue_threshold=thr)
    base = _apply_session_merge(base, corpus.embeddings, thr)[0]

    # Arm C: fingerprint HDBSCAN + rescue + merge (fingerprint space).
    arm = HDBSCAN(min_cluster_size=scfg.cluster_min_cluster_size,
                  min_samples=scfg.cluster_min_samples,
                  metric="euclidean").fit_predict(fp)
    arm, n_rescued = rescue_noise_points(fp, arm, thr)
    if not args.no_merge:
        arm = _merge_bagspace(arm, fp, thr)

    sc_base = _self_consistency(base, corpus.intents, corpus.signatures)
    sc_arm = _self_consistency(arm, corpus.intents, corpus.signatures)
    cross_ari = round(float(adjusted_rand_score(base, arm)), 4)
    cross_nmi = round(float(normalized_mutual_info_score(base, arm)), 4)
    v2_base = _v2_rate(base, corpus.session_ids, sid_to_label, pairs)
    v2_arm = _v2_rate(arm, corpus.session_ids, sid_to_label, pairs)

    lines = ["# G2 — Arm C (deterministic_fingerprint) vs baseline (corpus-wide, label-free)", ""]
    lines.append(f"_Captured {datetime.now(UTC).isoformat()}_ · {len(corpus)} sessions · "
                 f"fingerprint {FINGERPRINT_DIM}-dim")
    lines.append("")
    lines.append("| metric | baseline | fingerprint | read |")
    lines.append("|---|---:|---:|---|")
    lines.append(f"| clusters | {sc_base['n_clusters']} | {sc_arm['n_clusters']} | |")
    lines.append(f"| outlier_rate | {sc_base['outlier_rate']} | {sc_arm['outlier_rate']} | |")
    lines.append(f"| intent coherence | {sc_base['intent_coherence']} | "
                 f"{sc_arm['intent_coherence']} | high = behaviourally coherent |")
    lines.append(f"| signature coherence | {sc_base['signature_coherence']} | "
                 f"{sc_arm['signature_coherence']} | |")
    lines.append(f"| v2 divergent-pair | {v2_base} | {v2_arm} | Arm C should win here |")
    lines.append("")
    lines.append(f"**Cross-arm ARI** {cross_ari} · **NMI** {cross_nmi} "
                 "(low = different structure — expected; fingerprint clusters on "
                 "out-of-stream signal the command embedding never sees).")
    lines.append("")
    lines.append("**Interpretation.** Arm C clusters on a *parallel channel*, so "
                 "low cross-arm ARI is by design. It's worth running only if it "
                 "stays intent-coherent AND lifts the v2 divergent-pair rate (the "
                 "dp-009 case). If intent coherence collapses, the fingerprint is "
                 "grouping on operator/host noise, not behaviour.")
    md = "\n".join(lines)
    print("\n" + md)

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "arm": "deterministic_fingerprint", "scale": "production",
        "fingerprint_dim": FINGERPRINT_DIM,
        "baseline_self_consistency": sc_base, "arm_self_consistency": sc_arm,
        "cross_arm_ari": cross_ari, "cross_arm_nmi": cross_nmi,
        "v2_baseline": v2_base, "v2_fingerprint": v2_arm,
        "n_rescued": int(n_rescued),
        "assignments": {sid: int(c) for sid, c in zip(corpus.session_ids, arm, strict=False)},
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = args.output_dir / f"deterministic-fingerprint-prod-{ts}"
    Path(f"{stem}.md").write_text(md, encoding="utf-8")
    Path(f"{stem}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {stem}.md\nwrote {stem}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
