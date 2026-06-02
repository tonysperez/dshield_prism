# E4.2 — lexical-weight sweep

_Captured 2026-06-01T15:42:54.626011+00:00_

Sorted by ARI descending. 6 weights swept against the merged v1+v2 eval set (108 sessions). Lexical block = per-session TF-IDF (max_features 5000, (1,2) ngrams, sublinear_tf, l2 norm) + truncated SVD to 100 dims, L2-normalized per row. Stacked alongside the embedding + scalar block at the specified weight before HDBSCAN.

Anchor: `lexical_weight=0.0` reproduces the production baseline.

| lexical_weight | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters | n_outliers |
|---|---|---|---|---|---|---|---|---|
| 0.00 | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 | 12 | 34 |
| 0.05 | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 | 12 | 34 |
| 0.10 | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 | 12 | 34 |
| 0.20 | 0.3975 | 0.5750 | 0.8200 | 0.6760 | 0.6760 | 0.8333 | 12 | 31 |
| 0.40 | 0.3722 | 0.5672 | 0.8200 | 0.6706 | 0.6706 | 0.8333 | 12 | 31 |
| 0.80 | 0.3423 | 0.5409 | 0.7814 | 0.6393 | 0.6393 | 0.6667 | 12 | 31 |