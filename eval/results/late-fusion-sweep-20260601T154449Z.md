# E4.4 — late-fusion sweep

_Captured 2026-06-01T15:44:49.007378+00:00_

Sorted by ARI descending. 8 agglomerative-fusion configurations swept against the merged v1+v2 eval set (108 sessions). The embedding clusterer is production HDBSCAN; the lexical clusterer is HDBSCAN over a TF-IDF + SVD block (11 clusters found). Late fusion = agglomerative clustering on the pair-disagreement distance matrix.

Anchor rows: the two base clusterers' standalone metrics for reference.

| row | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters | n_outliers |
|---|---|---|---|---|---|---|---|---|
| fusion (n_clusters=10, linkage=average) | 0.5301 | 0.6369 | 0.8154 | 0.7152 | 0.7152 | 0.8333 | 10 | 0 |
| fusion (n_clusters=12, linkage=average) | 0.5147 | 0.6176 | 0.8205 | 0.7048 | 0.7048 | 0.8333 | 12 | 0 |
| fusion (n_clusters=8, linkage=average) | 0.4456 | 0.6200 | 0.6942 | 0.6550 | 0.6550 | 0.8333 | 8 | 0 |
| embedding-only (anchor) | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 | 12 | 34 |
| lexical-only (anchor) | 0.4120 | 0.5719 | 0.8262 | 0.6759 | 0.6759 | 1.0000 | 11 | 20 |
| fusion (n_clusters=7, linkage=average) | 0.3987 | 0.6284 | 0.6420 | 0.6351 | 0.6351 | 0.8333 | 7 | 0 |
| fusion (n_clusters=6, linkage=average) | 0.3469 | 0.6312 | 0.5658 | 0.5967 | 0.5967 | 0.8333 | 6 | 0 |
| fusion (n_clusters=5, linkage=average) | 0.2795 | 0.5873 | 0.4704 | 0.5224 | 0.5224 | 0.8333 | 5 | 0 |