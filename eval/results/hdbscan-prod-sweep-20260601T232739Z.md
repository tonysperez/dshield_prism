# F4.1 — multi-mcs HDBSCAN sweep (production scale)

_Captured 2026-06-01T23:27:39.438142+00:00_

All metrics over the full production corpus except ari / completeness / homogeneity / divergent-pair, which score the labeled eval subset against the production cluster ids. Production config is (mcs=5, ms=2). `lbl_in_S` = labeled-eval members landing in size-∈[3,10] clusters (metric-5 diagnostic).

| mcs | ms | clusters | outliers | ari | cmp | hom | dpr | out_rate | n_small | distinct | near_lg | purity | shard_frac | lbl_in_S |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 1 | 311 | 14 | 0.1641 | 0.4510 | 0.9208 | 0.8333 | 0.0035 | 161 | 14 | 0.9130 | 0.9964 | 0.0000 | 46 |
| 2 | 2 | 311 | 14 | 0.1641 | 0.4510 | 0.9208 | 0.8333 | 0.0035 | 161 | 14 | 0.9130 | 0.9964 | 0.0000 | 46 |
| 3 | 1 | 93 | 23 | 0.2078 | 0.4809 | 0.8934 | 0.8333 | 0.0057 | 61 | 16 | 0.7377 | 0.9798 | 0.0000 | 52 |
| 3 | 2 | 93 | 23 | 0.2078 | 0.4809 | 0.8934 | 0.8333 | 0.0057 | 61 | 16 | 0.7377 | 0.9798 | 0.0000 | 52 |
| 5 | 1 | 24 | 37 | 0.3906 | 0.5478 | 0.8640 | 0.6667 | 0.0091 | 8 | 7 | 0.1250 | 0.9028 | 0.0000 | 28 |
| 5 | 2 | 24 | 37 | 0.3906 | 0.5478 | 0.8640 | 0.6667 | 0.0091 | 8 | 7 | 0.1250 | 0.9028 | 0.0000 | 28 | *
| 8 | 2 | 17 | 56 | 0.2927 | 0.5428 | 0.7020 | 0.6667 | 0.0138 | 1 | 1 | 0.0000 | 1.0000 | 0.0000 | 3 |
| 13 | 2 | 15 | 56 | 0.2890 | 0.5447 | 0.6639 | 0.6667 | 0.0138 | 0 | 0 | — | — | — | 0 |

_* = current production config._