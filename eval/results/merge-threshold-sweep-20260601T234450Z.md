# Fragmentation sweep — merge threshold (production scale)

_Captured 2026-06-01T23:44:50.231733+00:00_

4049 sessions · base granularity HDBSCAN(mcs=5,ms=2) + rescue(0.96) → 24 clusters, held fixed. Only the complete-linkage merge threshold varies. `none` = pre-merge (what the spike measured); `0.96` = current production. `distinct` = small clusters cos < merge_threshold from every big playbook; `near_lg` = density-fragment fraction. Down = less fragmentation; up = more.

| merge_thr | clusters | outliers | ari | cmp | hom | dpr | n_small | distinct | near_lg | purity | shard |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| none | 24 | 37 | 0.3906 | 0.5478 | 0.8640 | 0.6667 | 8 | 7 | 0.1250 | 0.9028 | 0.0000 |
| 1.00 | 24 | 37 | 0.3906 | 0.5478 | 0.8640 | 0.6667 | 8 | 7 | 0.1250 | 0.9028 | 0.0000 |
| 0.98 | 19 | 37 | 0.4046 | 0.5661 | 0.8640 | 0.6667 | 6 | 6 | 0.0000 | 0.8704 | 0.0000 |
| 0.96 | 17 | 37 | 0.4160 | 0.5763 | 0.8640 | 0.6667 | 6 | 6 | 0.0000 | 0.8704 | 0.0000 | *
| 0.94 | 15 | 37 | 0.4361 | 0.5919 | 0.8640 | 0.6667 | 5 | 5 | 0.0000 | 0.8444 | 0.0000 |
| 0.92 | 12 | 37 | 0.4494 | 0.5990 | 0.7864 | 0.6667 | 4 | 4 | 0.0000 | 0.8889 | 0.0000 |
| 0.90 | 10 | 37 | 0.5295 | 0.6532 | 0.7864 | 0.8333 | 1 | 1 | 0.0000 | 1.0000 | 0.0000 |

_* = current production merge threshold._