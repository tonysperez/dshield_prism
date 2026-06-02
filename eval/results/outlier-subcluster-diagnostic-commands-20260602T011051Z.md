# F1 outlier diagnostic — commands layer

_Captured 2026-06-02T01:10:51.325332+00:00_

- **Index:** `prism.enriched.cowrie.command`
- **Scored docs:** 4610  ·  **non-outlier clusters:** 68
- **Outliers:** 1279  (**27.7%** — PRE-rescue; this layer has no rescue valve, unlike sessions)
- **Median outlier→nearest-centroid cosine:** 0.993

Rescue candidates by threshold (outliers within cosine of a non-outlier centroid) + intent-match of the would-be-rescued:

| threshold | rescuable | % outliers | intent-match |
|---:|---:|---:|---:|
| 0.98 | 1146 | 89.6% | 1146/1146 (100%) |
| 0.96 | 1173 | 91.7% | 1173/1173 (100%) |
| 0.94 | 1173 | 91.7% | 1173/1173 (100%) |
| 0.92 | 1173 | 91.7% | 1173/1173 (100%) |
| 0.9 | 1174 | 91.8% | 1174/1174 (100%) |
| 0.85 | 1188 | 92.9% | 1186/1188 (100%) |
| 0.8 | 1254 | 98.0% | 1230/1254 (98%) |

**At rescue 0.94:** 1173 of 1279 outliers rejoin a centroid → outlier rate **27.7% → 2.3%** (100% join a intent-matching cluster). Rescue creates no new clusters, so bulk-cluster quality is untouched.