# P0 — scale-baseline projection

_Captured 2026-06-03T00:10:04.431156+00:00_ · ES `https://so.tonystech.net:9200`

Read-only measurement that replaces the scale-hardening plan's "rough 90×" multiplier with the figure derived from the live per-doc / per-run cost below.

## Horizon

- Measured corpus window: **36.0 days** (= 0.099 sensor-years, 1 sensor)
- Target: **3 sensors × 3 years = 9 sensor-years**
- **Derived corpus multiplier: 91.3×** (plan assumed ~90×)
- Cluster-run cadence (run-axis growth): projecting on the **steady-state 4.0 runs/day** (every-6h backward timer) → ~4,383 runs over 3 calendar years.
  - _Observed_ cadence is **6.58 runs/day** (inflated by manual/dev runs over a short run_summary window). Note the plan's **2.76/day** undercounts even the timer rate — it divided runs by the full corpus window; P2.1 dead-state accumulation is therefore *larger* than the plan projected.

## Per-doc / per-run cost (P0.1)

- avg events / session: **4.35**
- avg commands / command-bearing session: **14.52** (4,139 command-bearing sessions)
- avg bytes / raw event: **1.1 KB**
- avg bytes / session rollup: **1.1 KB**
- embed-rate (clustering N / total sessions): **1.82%** (4,139 / 227,595)

Cluster runtime per N (latest run_summary per layer):

| layer | docs (N) | runtime (s) | ms/doc | runs so far | runs/day |
|---|---:|---:|---:|---:|---:|
| session | 4,139 | 20.2 | 4.88 | 100 | 6.58 |
| command | 4,733 | 30.3 | 6.41 | 97 | 6.38 |
| ip | 2,280 | 10.2 | 4.47 | 96 | 6.31 |

## Re-projected target table (P0.2)

| Index | axis | docs today | store today | docs target | store target | failure mode if untouched |
|---|---|---:|---:|---:|---:|---|
| `raw cowrie events` | corpus | 989,676 | 1.0 GB | 90,345,745 | 92.0 GB | data stream + ILM — fine |
| `session rollups` | corpus | 227,595 | 237.5 MB | 20,776,739 | 21.2 GB | single shard → near ~50 GB ceiling; full re-pool every 6 h |
| `IP rollups` | corpus | 10,971 | 78.8 MB | 1,001,523 | 7.0 GB | I3 firewall adds 5–10×; scalar block balloons |
| `enriched commands` | corpus | 4,733 | 155.5 MB | 432,067 | 13.9 GB | strong dedup; sub-linear in practice |
| `source_ip lifecycle` | corpus | 10,925 | 21.7 MB | 997,324 | 1.9 GB | one doc per IP forever; I3 explodes cardinality |
| `session clusters` | run | 3,857 | 67.9 MB | 169,052 | 2.9 GB | dead centroid accumulation (P2.1) |
| `command clusters` | run | 3,489 | 51.8 MB | 157,652 | 2.3 GB | dead centroid accumulation (P2.1) |
| `IP clusters` | run | 16,336 | 268.0 MB | 745,840 | 11.9 GB | dead centroid accumulation (P2.1) |

- **corpus axis** rows scale by the derived 91.3× corpus multiplier (sensors × years of append-only ingest).
- **run axis** rows (`prism.cluster.*`) scale by projected run count, not corpus size — this is the P2.1 dead-state accumulation. The per-run cost grows further as cluster counts rise, so these projections are a *lower bound*.

### Corrections to the plan's live snapshot

Doc counts above are live top-level docs (`_count`), not `_cat/indices docs.count` (which includes `nested` sub-docs). Two rows the plan's snapshot got wrong as a result:

- **source_ip lifecycle** is **~10.9k actual IPs**, not the 332k the plan reported — that figure was ~30 nested rolling-snapshots per IP. Real cardinality tracks the IP rollup (~11k), so the "332k → 30M+" projection should be read as **~11k → ~1M** (still I3-sensitive: the firewall source explodes distinct-IP count).
- **session rollups** are ~228k live, not 240k (minor nested inflation). Storage projection is unaffected (bytes are real).

## P0.3 decision

(a) **confirms the ~90× framing** (measured 91×). Build proceeds as planned.

> Verify: counts above reconcile to `GET _cat/indices?bytes=b` and `GET <index>/_count` on the live sensor. Re-run after any reindex or retention change to refresh the multiplier.