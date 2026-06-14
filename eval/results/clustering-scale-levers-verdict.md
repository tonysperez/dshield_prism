# Clustering full-recluster scale levers — verdict

**Date:** 2026-06-11. **Context:** the full-corpus HDBSCAN reclusters
(`cluster … --window-days 0`: `pipeline --backfill` + the weekly
`recluster-full` timers) run for hours at production scale — a session backfill
hit **~12 h** (266k sessions × 772-d) and a command full-recluster **~3 h**
(335k × 132-d). This records what was tried to speed the full-recluster, with
metrics, so the rejected levers aren't re-litigated. See
[phase-3-clustering.md](../../docs/history/phase-3-clustering.md) for the
shipped behaviour and [`scripts/sweep_session_svd.py`](../../scripts/sweep_session_svd.py) /
[`scripts/sweep_command_svd.py`](../../scripts/sweep_command_svd.py) for the sweeps.

## Root constraint

sklearn HDBSCAN (`metric="euclidean"`) runs `_hdbscan_prims` — **Prim's MST,
single-threaded, O(n²)**, in `_hdbscan/_linkage.pyx` (no `prange`/`nogil`).
`n_jobs`/`cluster_n_jobs` parallelises **only** the kNN core-distance phase, not
the MST. So the post-kNN phase pins one core for the bulk of a large fit — the
142-min single-core stretch behind the original heartbeat gap.

## Shipped (kept)

- **Fit-only SVD reduction** (`session.cluster_svd_dim`, `command_cluster.cluster_svd_dim`):
  reduces the embedding for label assignment only; rescue/centroids/novelty/
  reference stay full-dim. Cuts per-distance cost (the O(n²) constant), not the
  serial/quadratic nature. Session default **96** (ARI 1.0 vs full across
  400→60k; identical clustering, ~6× fit).
- **Process-based heartbeat** (`_fit_with_heartbeat`): the liveness log runs in a
  forked child so it survives the MST's GIL hold — the long run is now
  observable instead of looking hung.

## Levers explored & rejected

### 1. UMAP low-dim (nonlinear reduction) — **rejected**
Hypothesis: UMAP-15/24 preserves local structure where SVD collapses, so the
trees engage. On sessions (108 analyst labels), default clustering config
(`n_neighbors=15, min_dist=0`):

| reducer·dim | ARI vs labels | clusters |
|---|---|---|
| full (768-d) | 0.40 | 23 |
| SVD-32 | **0.40** | 24 |
| UMAP-24 | **0.19** | 167 |

UMAP **over-fragments** (166–204 clusters, ARI vs ground truth halves). High
intrinsic purity is the fragmentation artifact. Would need heavy `n_neighbors`
tuning, and the premise evaporated (SVD-32 already ground-truth-neutral). Adds a
numba/llvmlite dependency for a loss.

### 2. Aggressive low-SVD — **layer-dependent floor, not a free win**
Judged against **ground truth** (not fidelity-to-full): sessions hold to ~32-d
(SVD-32 ARI vs labels = full; SVD-24 dips ~0.07). But **commands over-merge hard
below ~96**:

| command SVD dim | clusters (full=68) | purity | ari_full | speed |
|---|---|---|---|---|
| 96 | 67 | 0.976 | 0.89 | 8.1× |
| 64 | 44 | 0.961 | 0.69 | 10.7× |
| ≤48 | **26–29** | 0.91–0.93 | 0.67 | 15–18× |

Commands pack ~68 families whose distinctions live in low-variance directions
SVD discards first → below 96 they collapse. **Command floor ≈ 96** (and 96 ≥
the current 128 default at eval scale — a possible 128→96 tweak, pending a 335k
sweep). Caveat: low-SVD also **churns cluster identity** (non-monotonic
`ari_full`: SVD-64 → 0.68), which the cosine-anchor playbook ids feel.

### 3. Sample-then-assign (the IP B0.5 pattern) — **works for sessions, fails for commands**
Cluster a fraction f, take pure-embedding centroids, assign all by nearest cosine
(faithful to `ips.run_assign`, no outlier threshold):

| f=0.25 | sessions (full=24) | commands (full=68) |
|---|---|---|
| clusters recovered | 14 | **10** |
| `ari_full` | 0.94 ✓ | **0.67** ✗ |
| ground-truth ARI | 0.28 (vs full 0.39) | — |

Sessions: cluster identity well-preserved (assign is ~free, ~16× less MST work
at scale), though it blurs ~0.1 ground-truth ARI. Commands: a 25% sample only
recovers **10 of 68** clusters — the rare long tail falls below `min_cluster_size`
and is lost. The assign step itself is fine (f=1.0 → `ari_full` 0.98); it's
**sampling** that drops the tail.

### 4. `hdbscan`-package Boruvka MST — **rejected**
The literal "parallelise the MST" lever (`algorithm="boruvka_kdtree",
core_dist_n_jobs=-1`). 24-core box. On real commands (dim 100):

| algo | clusters | purity | ARI vs sklearn |
|---|---|---|---|
| sklearn (prims) | 67 | 0.976 | 1.00 |
| boruvka (approx MST) | 43 | 0.968 | 0.79 |
| boruvka (exact MST) | 43 | 0.968 | 0.79 |

- **Not multi-core.** `cpu/wall ≈ 1`; it used ~12× *less* total CPU than sklearn,
  not 24× across cores. The speedup is algorithmic (dual-tree does less work),
  not parallel — the 24 cores stay idle. Wall: 2.2× (exact) / 2.9× (approx) at
  tiled 40k.
- **Coarser clustering.** 43 vs 67 clusters, ARI 0.79 — and **exact MST is
  identical to approx**, so the loss is inherent to the package's cluster
  extraction, not the approximation. It merges away the command long tail (same
  wall as #2/#3).
- High migration cost: re-baseline every eval gate, churn all playbook ids.

### 5. GPU (`cuml.HDBSCAN`) — **N/A on this box (no NVIDIA GPU)**
The only path that is **both** massively parallel **and** faithful (preserves the
tail). Revisit if a GPU is ever added to the deploy.

## Verdict

Every approximation (low-SVD, sample-then-assign, Boruvka) fails for **commands**
for the same reason: their value is a long tail of small, rare clusters that
dimensionality reduction merges, sampling drops, and a different MST backend
merges. Only a faithful full sklearn O(n²) run — or a GPU — preserves it.

- **Commands:** **accept the ~3 h weekly full-recluster.** Faithful, zero quality
  cost, and now observable via the heartbeat. SVD stays 96–128.
- **Sessions:** SVD-96 default stands (cheap levers exist — SVD-32, sample-assign
  — but each has an identity/ground-truth cost not worth it).
- **Revisit with a GPU** (`cuml`) if one lands — see [ROADMAP](../../docs/ROADMAP.md).
