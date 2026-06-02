# E8.2 — embed_input_order sweep (production scale)

_Captured 2026-06-01T19:56:08.196154+00:00_

Sorted by ARI descending. 3 layouts swept against the full production corpus (~200 rollups), scored on the labeled eval subset.

| layout | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters_total | n_outliers_total |
|---|---|---|---|---|---|---|---|---|
| command_first | 0.5057 | 0.7199 | 0.8519 | 0.7804 | 0.7804 | 0.0000 | 10 | 9 |
| prelude_first | 0.4170 | 0.6674 | 0.7861 | 0.7219 | 0.7219 | 0.0000 | 10 | 7 |
| command_only_with_tag | 0.2935 | 0.6250 | 0.6341 | 0.6295 | 0.6295 | 0.0000 | 9 | 8 |

**Baseline** (persisted production cluster ids, no re-embed): ARI 0.4170, completeness 0.6674.