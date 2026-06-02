# F3.1 — late-fusion sweep (production scale)

_Captured 2026-06-01T23:23:49.699303+00:00_

4045 sessions · embedding base 24 clusters · linkage=average. ARI / completeness / homogeneity / dpr score the labeled eval subset; the small-cluster axis is corpus-wide. **outlier_rate is structurally 0** (agglomerative has no noise label) — ignore it here. `distinct` = small clusters with centroid cos < merge_threshold to every big playbook (the genuine surfacing yield); `near_lg` = density-fragment fraction.

| lex_mcs | n_clusters | clusters | ari | cmp | hom | dpr | n_small | distinct | purity | shard | near_lg | lbl_in_S |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | auto | 24 | 0.2783 | 0.5075 | 0.7227 | 0.6667 | 2 | 2 | 0.7857 | 0.0000 | 0.0000 | 9 |
| 5 | 40 | 40 | 0.2546 | 0.4897 | 0.7330 | 0.6667 | 3 | 3 | 0.8571 | 0.0000 | 0.0000 | 9 |
| 5 | 60 | 60 | 0.2210 | 0.4603 | 0.8272 | 0.6667 | 4 | 4 | 0.8929 | 0.0000 | 0.0000 | 14 |
| 5 | 93 | 93 | 0.1539 | 0.4325 | 0.9328 | 0.8333 | 13 | 8 | 0.9255 | 0.0000 | 0.3846 | 35 |
| 15 | auto | 24 | 0.2780 | 0.5126 | 0.6977 | 0.6667 | 4 | 3 | 0.9000 | 0.0000 | 0.2500 | 8 |
| 15 | 40 | 40 | 0.2418 | 0.4717 | 0.7680 | 0.6667 | 5 | 4 | 0.9200 | 0.0000 | 0.2000 | 13 |
| 15 | 60 | 60 | 0.2105 | 0.4560 | 0.9087 | 0.6667 | 7 | 6 | 0.9143 | 0.0000 | 0.1429 | 24 |
| 15 | 93 | 93 | 0.1618 | 0.4409 | 0.9413 | 0.8333 | 11 | 7 | 0.9303 | 0.0000 | 0.3636 | 27 |
| 25 | auto | 24 | 0.3148 | 0.5413 | 0.7641 | 0.6667 | 2 | 2 | 1.0000 | 0.0000 | 0.0000 | 5 |
| 25 | 40 | 40 | 0.2729 | 0.4985 | 0.8044 | 0.6667 | 3 | 3 | 1.0000 | 0.0000 | 0.0000 | 5 |
| 25 | 60 | 60 | 0.2765 | 0.4848 | 0.9836 | 0.6667 | 5 | 5 | 1.0000 | 0.0000 | 0.0000 | 15 |
| 25 | 93 | 93 | 0.1729 | 0.4482 | 1.0000 | 0.8333 | 10 | 7 | 0.9150 | 0.0000 | 0.3000 | 27 |