# E9.2 — code-trained embedder at production scale (unixcoder-base)

_Captured 2026-06-01T20:17:56.830133+00:00_

Tested ``microsoft/unixcoder-base`` (max_seq_length=1024) against the full production corpus (~200 rollups), scored on the 108-session labeled subset.

| model | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters_total | n_outliers_total |
|---|---|---|---|---|---|---|---|---|
| nomic_baseline | 0.3906 | 0.5478 | — | — | — | — | — | — |
| unixcoder-base | 0.4233 | 0.7004 | 0.7333 | 0.7165 | 0.7165 | 0.0000 | 9 | 11 |

**Δ ARI vs nomic_baseline = +0.0327.**