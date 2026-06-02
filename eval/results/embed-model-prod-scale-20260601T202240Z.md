# E9.2 — code-trained embedder at production scale (unixcoder-base)

_Captured 2026-06-01T20:18:29.774875+00:00_

Tested ``microsoft/unixcoder-base`` (max_seq_length=1024) against the full production corpus (~4035 rollups), scored on the 108-session labeled subset.

| model | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters_total | n_outliers_total |
|---|---|---|---|---|---|---|---|---|
| nomic_baseline | 0.3906 | 0.5478 | — | — | — | — | — | — |
| unixcoder-base | 0.2423 | 0.4870 | 0.7064 | 0.5766 | 0.5766 | 0.8333 | 23 | 56 |

**Δ ARI vs nomic_baseline = -0.1483.**