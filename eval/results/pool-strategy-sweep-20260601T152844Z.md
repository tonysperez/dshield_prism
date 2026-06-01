# E2.2 — pool strategy sweep

_Captured 2026-06-01T15:28:44.363807+00:00_

Sorted by ARI descending. 7 pool strategies swept against the merged v1+v2 eval set (108 sessions). Per-command vectors come from the persisted JSONL embeddings (base_dim=768); no LLM calls.

| strategy | embedding_dim | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters | n_outliers |
|---|---|---|---|---|---|---|---|---|---|
| mean | 768 | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 | 12 | 34 |
| mean_unweighted | 768 | 0.4260 | 0.5978 | 0.8446 | 0.7001 | 0.7001 | 0.6667 | 12 | 34 |
| attention_pool | 768 | 0.4142 | 0.5854 | 0.8187 | 0.6827 | 0.6827 | 0.6667 | 12 | 35 |
| max | 768 | 0.3052 | 0.5493 | 0.8748 | 0.6748 | 0.6748 | 0.6667 | 14 | 21 |
| concat_top_3 | 2304 | 0.3010 | 0.5514 | 0.8459 | 0.6676 | 0.6676 | 0.8333 | 13 | 24 |
| concat_top_5 | 3840 | 0.2981 | 0.5344 | 0.7901 | 0.6376 | 0.6376 | 0.8333 | 12 | 23 |
| concat_top_10 | 7680 | 0.2668 | 0.5108 | 0.7891 | 0.6202 | 0.6202 | 0.8333 | 13 | 23 |