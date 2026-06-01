# E2.1 — embed_context sweep

_Captured 2026-06-01T14:47:33.246516+00:00_

Sorted by ARI descending. 8 configurations swept against the merged v1+v2 eval set.

| config | embed_context | cooc | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters | n_outliers |
|---|---|---|---|---|---|---|---|---|---|---|
| production | [intent, tactics, techniques, description] | False | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 | 12 | 34 |
| bare | [] | False | 0.4238 | 0.5982 | 0.8482 | 0.7016 | 0.7016 | 0.8333 | 12 | 32 |
| intent_desc | [intent, description] | False | 0.4023 | 0.5801 | 0.8446 | 0.6878 | 0.6878 | 0.6667 | 13 | 34 |
| description_only | [description] | False | 0.3650 | 0.5563 | 0.8006 | 0.6565 | 0.6565 | 0.6667 | 13 | 36 |
| intent_desc_cooc | [intent, description] | True | 0.3550 | 0.5481 | 0.8338 | 0.6614 | 0.6614 | 0.8333 | 13 | 24 |
| mitre_only | [tactics, techniques] | False | 0.3399 | 0.5564 | 0.7767 | 0.6483 | 0.6483 | 0.8333 | 12 | 36 |
| intent_only | [intent] | False | 0.3381 | 0.5525 | 0.8588 | 0.6724 | 0.6724 | 0.6667 | 14 | 27 |
| bare_cooc | [] | True | 0.2493 | 0.5077 | 0.7472 | 0.6045 | 0.6045 | 0.6667 | 12 | 28 |
