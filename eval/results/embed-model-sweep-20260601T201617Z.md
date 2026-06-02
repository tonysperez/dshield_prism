# E3 — embedding model sweep

_Captured 2026-06-01T20:16:17.218524+00:00_

Sorted by ARI descending. 2 models swept against the merged v1+v2 eval set (108 sessions). All non-baseline models loaded via sentence-transformers on CPU. embed_context = production (`[intent, tactics, techniques, description]`, cooc=false). Pool = production IDF-weighted mean.

| model | embedding_dim | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters | n_outliers |
|---|---|---|---|---|---|---|---|---|---|
| nomic_baseline | 768 | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 | 12 | 34 |
| unixcoder-base | 768 | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 | 12 | 34 |

Notes per model:

- **nomic_baseline**: LM Studio q8_0; numbers from refreshed JSONL session embeddings
- **unixcoder-base**: Microsoft code-trained encoder, 768-d, OOD candidate (E9)