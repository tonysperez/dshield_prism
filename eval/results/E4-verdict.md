# E4 — hybrid features verdict

_Captured 2026-06-01_

## Headline

**Late fusion wins. +0.085 ARI vs production, +0.033 completeness,
homogeneity stays above 0.80.** Production adoption is designed but
not yet implemented; this doc captures the measurement, the analysis,
and the open design questions for the production migration.

## The full E4 picture (E4.2 + E4.4)

E4 ran two sub-phases per the plan:

- **E4.2 — concat sweep** (`scripts/sweep_lexical_weight.py`, output:
  `eval/results/lexical-weight-sweep-20260601T154254Z.md`).
  *Result: null.* Concatenating a TF-IDF + SVD lexical block onto the
  cluster matrix at weight ∈ {0.0, 0.05, 0.10, 0.20, 0.40, 0.80} either
  has no effect (low weights are absorbed by the embedding signal) or
  hurts (high weights override the embedding's better structure). No
  sweet spot. Per plan, the contingent next test is late fusion.

- **E4.4 — late fusion sweep** (`scripts/sweep_late_fusion.py`,
  output: `eval/results/late-fusion-sweep-20260601T154449Z.md`).
  *Result: win.* Clustering on embedding + scalar block (HDBSCAN) and
  on TF-IDF + SVD (HDBSCAN) separately, then building a per-pair
  disagreement distance matrix and re-clustering via Agglomerative
  with `n_clusters=10, linkage=average`, scores:

| | Production (E2.1) | **Fusion (E4.4 winner)** | Δ |
|---|---|---|---|
| ARI | 0.4447 | **0.5301** | **+0.0854** (+19%) |
| Completeness | 0.6040 | **0.6369** | **+0.0329** |
| Homogeneity | 0.8446 | 0.8154 | −0.0292 (stays ≥ 0.80) |
| NMI | 0.7043 | 0.7152 | +0.0109 |
| V-measure | 0.7043 | 0.7152 | +0.0109 |
| divergent_pair_resolution_rate | 0.8333 | 0.8333 | 0.0000 |

Plan E2 binding rule (homogeneity ≥ 0.80) holds: 0.8154 ≥ 0.80.

## A second discovery worth keeping

**Lexical-only (TF-IDF + SVD) scores `divergent_pair_resolution_rate
= 1.0000`** — every divergent pair in v2 is correctly resolved by the
lexical clusterer alone. Compare to embedding-only's 0.8333 (5/6) and
fusion's 0.8333 (5/6).

This locates dp-009's failure mode precisely: the embedding is mis-
clustering the BusyBox-Enable pair (analyst labeled them as different
behaviors, embedding clusters them together). The TF-IDF view splits
them correctly. The fusion picks the embedding's stronger overall
structure but inherits the embedding's specific failure on dp-009.

A future variant that weights the lexical view more heavily on the v2
metric — or that uses the lexical-only assignment as a soft-prior for
disambiguating embedding ties — might push divergent_pair_resolution_rate
above the fusion's 0.8333. Out of scope for this commit; documented for
the next iteration.

## Production adoption — open design questions

Fusion is not a config flip. Five questions must settle before we
flip production:

### 1. What clustering frontend?

The sweep uses Agglomerative as the final clusterer. Agglomerative
**doesn't produce outliers** — every session lands in a cluster. HDBSCAN
noise (`cluster_id = -1`) is currently load-bearing downstream:

- Novelty scoring uses noise-vs-cluster geometry.
- The session-layer "rescue" path looks at outlier sessions whose
  cosine to a nearest centroid clears `playbook_merge_threshold`.
- Findings consumers (e.g. `outlier_burst` discovery) expect a noise
  population.

Three sub-options:

  a. **Two-stage**: keep HDBSCAN on the embedding as a front-end that
     emits noise; apply fusion only to the non-noise. Preserves noise
     semantics; production downstream is unaffected.
  b. **Replace HDBSCAN with fusion**: lose noise as a first-class
     concept; novelty / rescue / outlier_burst all need redefinition.
     Bigger change.
  c. **HDBSCAN on the distance matrix instead of Agglomerative**:
     HDBSCAN accepts `metric='precomputed'`. Try it; if it produces
     comparable metrics it preserves outlier semantics naturally.

(a) is the least disruptive. (c) is the cleanest if HDBSCAN-on-distance
matches Agglomerative-on-distance metrically.

### 2. How to choose `n_clusters` in production?

The sweep tried {5, 6, 7, 8, 10, 12}. n_clusters=10 won. The merged
v1+v2 eval has 6 distinct analyst labels — the optimum is `analyst_n +
4`, but that's not a stable production rule.

Two reasonable rules:

  a. `n_clusters = max(base_emb_n_clusters, base_lex_n_clusters)`.
     The fusion picks the finer-grained partition from either base
     clusterer. Self-tuning per corpus.
  b. **Elbow detection on the linkage distances.** Agglomerative
     produces a hierarchy; an elbow finder over the merge distances
     picks the natural cluster count without hand-tuning. More work,
     more robust.

Both decoupled from `analyst_n` (which production doesn't know).

### 3. Where does the lexical feature live?

TF-IDF + SVD is per-session, computed once per cluster run. Options:

  a. **Recompute every cluster run** (cheap at thousands of sessions;
     borderline at tens of thousands). No persisted state.
  b. **Persist per-session lexical vector in
     `prism.rollup.cowrie.session`** under
     `dshield.cowrie.enrichment.session.lexical_features` (additive
     mapping migration; `init-indexes --update-mapping --layer session`).
     Cluster runs read persisted vectors. Production-grade.

(b) is the plan's stated approach (`session.lexical_features` field
explicitly mentioned in E4.1).

### 4. What's the migration path?

If we go with (1a) two-stage + (2a) max-n_clusters rule + (3b)
persisted lexical_features:

  i. Additive ES mapping: add `dshield.cowrie.enrichment.session.lexical_features`
     as a dense_vector (or float array). Init-indexes --update-mapping.
  ii. Add `session.cluster_lexical_weight` and `session.clustering_mode`
      (`"hdbscan"` (default) | `"late_fusion"`) to `config/default.yaml`.
  iii. Extend `src/enrich/clustering.py` `run_layer_clustering` with a
       fusion branch. Default config stays on HDBSCAN — a config-only
       revert restores production.
  iv. Backfill: one-shot script populates `lexical_features` for every
      existing session rollup. Recompute is cheap (TF-IDF + SVD is
      seconds for thousands of sessions).
  v. Flip config to `clustering_mode: late_fusion`; the next backward
     cycle re-clusters using the fusion path.

Reversion: flip config back. Persisted `lexical_features` stays
(harmless, only read when mode is fusion).

### 5. Does this generalize beyond v1+v2?

The sweep measured on 108 sessions. Real production has tens of
thousands of session rollups. Two unknowns:

  - Does the lexical-only clusterer (HDBSCAN on TF-IDF+SVD) still find
    a sensible cluster count at production scale? The eval found 11
    clusters on 108 sessions; production scale may surface many more
    or many fewer.
  - Does Agglomerative on the n × n distance matrix stay tractable?
    n=10K is 100M cell entries — still fits in memory but tight.
    Production might want sampling-based agglomerative or
    HDBSCAN-on-distance for scale.

These are answerable empirically — backfill once on production data and
measure.

## Where this leaves the plan

- **E0** (diagnostics) — shipped
- **E1** (v2 divergent-pair eval set) — shipped
- **E2** (cheap interventions) — shipped (cooccurrence off; pool
  unchanged)
- **E3** (alternative models) — shipped null (BGE ties Nomic exactly;
  general embedder ceiling)
- **E4** (hybrid features) — **win discovered, adoption designed but
  not yet implemented**
- **E5** (LoRA fine-tune) — not started; lower priority now that E4
  has surfaced a real lift

## Next concrete steps (when ready)

1. Decide on (1) — two-stage, replace, or HDBSCAN-on-distance.
2. Decide on (2) — `n_clusters` rule.
3. Decide on (3) — recompute vs persist lexical features.
4. Implement E4.1 (production refactor) and E4.3 (config + migration).
5. Backfill `lexical_features` on production rollups.
6. Flip `session.clustering_mode: late_fusion`.
7. Re-measure on production data (not just the 108-session eval).
8. If production-scale metrics hold: re-capture `eval/baseline.json`
   with the new floor; that's the metric every E5+ experiment measures
   against.
