"""Smoke test the late-fusion clustering math against the E4.4 sweep.

Verifies the pure-function fusion path in ``enrich.clustering``
(``compute_lexical_features`` + ``fusion_cluster_labels``) reproduces
the numbers from the E4.4 sweep's winning configuration on the merged
v1+v2 eval set. If this passes, the fusion math is byte-identical to
the sweep's reference implementation and the pipeline-integration step
can layer in confidence.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_clustering_fusion.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.clustering import (
    compute_lexical_features,
    fusion_cluster_labels,
    l2_normalize,
)
from enrich.config import load_config
from enrich.sources.cowrie.sessions import build_session_scalar_block
from eval_clustering import (  # type: ignore
    _load_labels, _extract_session_features, _extract_session_text,
    _divergent_pair_metrics,
)


def check(name: str, ok: bool, detail: str = "") -> bool:
    sym = "✓" if ok else "✗"
    suffix = f" — {detail}" if detail else ""
    print(f"  {sym} {name}{suffix}")
    return ok


def _ingest():
    v1 = _load_labels(Path("eval/labels-v1.yaml"))
    v2 = _load_labels(Path("eval/labels-v2.yaml"))
    label_blocks = {**v1, **v2}
    pair_to_sessions: dict[str, list[str]] = {}
    for sid, b in v2.items():
        pid = b.get("divergent_pair_id")
        if isinstance(pid, str) and pid:
            pair_to_sessions.setdefault(pid, []).append(sid)

    session_ids: list[str] = []
    labels: list[str] = []
    embeddings: list[list[float]] = []
    scalars: list[dict] = []
    texts: list[str] = []
    seen: set[str] = set()
    for jl in (
        Path("eval/sessions-v1.unlabeled.jsonl"),
        Path("eval/sessions-v2.unlabeled.jsonl"),
    ):
        with jl.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                sid = rec.get("session_id")
                if not isinstance(sid, str) or sid in seen:
                    continue
                if sid not in label_blocks:
                    continue
                feats = _extract_session_features(rec)
                if feats is None:
                    continue
                emb, sc = feats
                text = _extract_session_text(rec)
                if text is None:
                    continue
                seen.add(sid)
                session_ids.append(sid)
                labels.append(label_blocks[sid]["playbook_label"])
                embeddings.append(emb)
                scalars.append(sc)
                texts.append(text)
    return session_ids, labels, embeddings, scalars, texts, pair_to_sessions


def main() -> int:
    print("=" * 72)
    print("Smoke test: late-fusion clustering math (E4.4 adoption)")
    print("=" * 72)
    cfg = load_config()
    scfg = cfg.session

    print()
    print("[1] Ingesting merged v1+v2 eval set")
    session_ids, labels, embeddings, scalars, texts, pair_to_sessions = _ingest()
    print(f"  {len(session_ids)} sessions, {len(pair_to_sessions)} v2 pairs")
    ok_load = check("ingested non-empty session set", len(session_ids) > 0)

    print()
    print("[2] Building production-equivalent embedding cluster matrix")
    emb_matrix = np.array(embeddings, dtype=np.float32)
    normalized = l2_normalize(emb_matrix)
    scalar_block = build_session_scalar_block(scalars, scfg.cluster_scalar_weight)
    cluster_matrix = np.hstack([normalized, scalar_block])
    ok_shape = check(
        "cluster_matrix shape matches expectation",
        cluster_matrix.shape[0] == len(session_ids) and cluster_matrix.shape[1] > 768,
        f"shape={cluster_matrix.shape}",
    )

    print()
    print("[3] Computing lexical features (TF-IDF + SVD + L2)")
    lexical = compute_lexical_features(texts, n_components=scfg.cluster_lexical_features_dim)
    ok_lex = check(
        f"lexical block shape is (n_sessions, ≤{scfg.cluster_lexical_features_dim})",
        lexical.shape[0] == len(session_ids) and 1 < lexical.shape[1] <= scfg.cluster_lexical_features_dim,
        f"shape={lexical.shape}",
    )
    # L2 norm per row should be ~1.0
    row_norms = np.linalg.norm(lexical, axis=1)
    ok_norm = check(
        "lexical rows are L2-normalized (||r|| ≈ 1)",
        bool(np.allclose(row_norms[row_norms > 0], 1.0, atol=1e-4)),
        f"min={row_norms.min():.4f} max={row_norms.max():.4f}",
    )

    print()
    print("[4] Running fusion clustering with default n_clusters rule")
    fusion_labels, emb_outliers, n_emb, n_lex = fusion_cluster_labels(
        cluster_matrix, lexical,
        min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
    )
    print(f"  base HDBSCAN: emb={n_emb} clusters, lex={n_lex} clusters")
    print(f"  fusion: {len(set(int(l) for l in fusion_labels))} clusters, "
          f"{int(emb_outliers.sum())} embedding-outliers")
    ok_no_noise = check(
        "fusion labels contain no -1 (Agglomerative produces no noise)",
        not (fusion_labels == -1).any(),
    )
    ok_outliers = check(
        "embedding_outlier_flags is a bool mask of correct length",
        emb_outliers.dtype == bool and len(emb_outliers) == len(session_ids),
    )

    print()
    print("[5] Scoring fusion result against analyst labels")
    ari = float(adjusted_rand_score(labels, fusion_labels))
    comp = float(completeness_score(labels, fusion_labels))
    hom = float(homogeneity_score(labels, fusion_labels))
    v2m, _outcomes = _divergent_pair_metrics(
        session_ids, fusion_labels, labels, pair_to_sessions,
    )
    dpr = v2m["divergent_pair_resolution_rate"]
    print(f"  ARI={ari:.4f}  completeness={comp:.4f}  homogeneity={hom:.4f}  "
          f"divergent_pair_resolution_rate={dpr:.4f}")
    # E4.4 winner published in eval/results/E4-verdict.md was n_clusters=10.
    # The default rule (max(n_emb, n_lex)) lands at n_clusters=12 on this
    # corpus → ARI 0.5147, completeness 0.6176, homogeneity 0.8205.
    # Tolerances are tight — every bit reproducible from the same
    # eval set + sklearn versions.
    ok_ari = check(
        "ARI matches the published E4.4 rule-default within 0.001",
        abs(ari - 0.5147) < 0.001, f"got {ari:.4f}, expected 0.5147",
    )
    ok_comp = check(
        "completeness matches within 0.001",
        abs(comp - 0.6176) < 0.001, f"got {comp:.4f}, expected 0.6176",
    )
    ok_hom = check(
        "homogeneity matches within 0.001",
        abs(hom - 0.8205) < 0.001, f"got {hom:.4f}, expected 0.8205",
    )
    ok_dpr = check(
        "divergent_pair_resolution_rate matches",
        abs(dpr - 0.8333) < 0.001, f"got {dpr:.4f}, expected 0.8333",
    )
    ok_plan = check(
        "homogeneity stays above plan's binding 0.80 rule",
        hom >= 0.80, f"hom={hom:.4f}",
    )

    print()
    print("[6] Explicit n_clusters=10 should reproduce the E4.4 sweep winner")
    fusion_labels_10, _, _, _ = fusion_cluster_labels(
        cluster_matrix, lexical,
        min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
        n_clusters=10,
    )
    ari_10 = float(adjusted_rand_score(labels, fusion_labels_10))
    comp_10 = float(completeness_score(labels, fusion_labels_10))
    hom_10 = float(homogeneity_score(labels, fusion_labels_10))
    print(f"  ARI={ari_10:.4f}  completeness={comp_10:.4f}  homogeneity={hom_10:.4f}")
    ok_winner = check(
        "n_clusters=10 reproduces the E4.4 sweep winner ARI 0.5301",
        abs(ari_10 - 0.5301) < 0.001,
        f"got {ari_10:.4f}, expected 0.5301",
    )

    print()
    print("[7] cluster_fn closure (mirrors production session-caller wiring)")
    # This is the exact pattern run_session_clustering builds when
    # clustering_mode='late_fusion'. The closure captures the texts
    # list (Python scope); run_layer_clustering invokes it with the
    # materialised cluster_matrix + normalized + min_cluster_size +
    # min_samples kwargs. Verifying the closure returns identical
    # output to a direct fusion_cluster_labels call is enough to
    # confirm the hook glue.
    def _fusion_cluster_fn(*, cluster_matrix, normalized, min_cluster_size, min_samples):
        lexical_block = compute_lexical_features(
            texts, n_components=scfg.cluster_lexical_features_dim,
        )
        fusion_labels, outlier_flags, _n_emb, _n_lex = fusion_cluster_labels(
            cluster_matrix, lexical_block,
            min_cluster_size=min_cluster_size, min_samples=min_samples,
        )
        return fusion_labels, outlier_flags
    closure_labels, closure_outliers = _fusion_cluster_fn(
        cluster_matrix=cluster_matrix, normalized=normalized,
        min_cluster_size=scfg.cluster_min_cluster_size,
        min_samples=scfg.cluster_min_samples,
    )
    ok_closure_labels = check(
        "closure cluster labels equal direct fusion_cluster_labels output",
        bool(np.array_equal(closure_labels, fusion_labels)),
    )
    ok_closure_outliers = check(
        "closure outlier flags equal direct fusion_cluster_labels output",
        bool(np.array_equal(closure_outliers, emb_outliers)),
    )

    print()
    print("=" * 72)
    all_ok = all([
        ok_load, ok_shape, ok_lex, ok_norm, ok_no_noise, ok_outliers,
        ok_ari, ok_comp, ok_hom, ok_dpr, ok_plan, ok_winner,
        ok_closure_labels, ok_closure_outliers,
    ])
    print(f"SMOKE TEST: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
