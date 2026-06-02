# E4 postmortem — fusion adoption regressed at production scale

_Captured 2026-06-01_

## TL;DR

The E4.4 late-fusion adoption (ARI +0.085 on the merged v1+v2 eval set)
**did not generalize to production scale**. Production runs over 4030
session rollups (vs the eval's 108); at that scale, the TF-IDF + SVD
lexical view fragments far more aggressively than the embedding view,
breaking the fusion math. Best fusion configuration at production scale
beats HDBSCAN-only by **+0.008 ARI** — within noise — and the
default-rule deployment regressed by **−0.173 ARI**.

**Action: revert by flipping `clustering_mode: hdbscan` in production's
`local.yaml`.** Code + ES schema + backfilled `command_stream_text`
stay (harmless when unused; preserves the option of a future redesign).

## What we measured before the adoption

The E4.4 sweep ran on the merged v1+v2 eval set (108 sessions, 6
distinct analyst labels). The fusion math produced:

| | Eval-isolated (108 sessions) |
|---|---|
| HDBSCAN-on-embedding only (E2.1 result) | ARI 0.4447 |
| Fusion (n_emb=12, n_lex=11, n_clusters=12) | **ARI 0.5147** |
| Difference | **+0.085 ARI, +0.033 completeness** |

The smoke test reproduced these numbers byte-for-byte against the
eval JSONL. The +0.085 was real for what we measured.

## What's actually true at production scale

Pulling all 4030 production session rollups and re-running the same
math:

| | Production-scale (4030 sessions, scored on 108 labeled subset) |
|---|---|
| HDBSCAN-on-embedding only (real pre-fusion floor) | **ARI 0.3340** |
| HDBSCAN-on-lexical only | ARI 0.2522 |
| Fusion with default rule (n_lex=72 dominates max()) ← what live production ran | ARI 0.1608 |
| Fusion with `n_clusters = n_emb` (24) | ARI 0.3229 |
| Fusion with coarsened lex (lex_mcs=25, n_lex=16, n_clusters=24) ← best config found | **ARI 0.3419** |
| Best alternative fusion beats HDBSCAN-only by | **+0.008 ARI** (noise) |
| Live production deploy regressed HDBSCAN-only by | **−0.173 ARI** |

## Why the eval-scale win didn't generalize

At eval-isolated scale, the two base clusterers found similar (small)
numbers of clusters:
- HDBSCAN-on-embedding: 12 clusters
- HDBSCAN-on-lexical: 11 clusters
- Fusion's `max()` rule: 12 — aligned well with 6 analyst labels.

At production scale:
- HDBSCAN-on-embedding: 24 clusters (~2× the eval scale; modest growth)
- HDBSCAN-on-lexical: **72 clusters** (~6× the eval scale; aggressive growth)
- Fusion's `max()` rule: 72 — dominated by the lexical view's
  fine-graining, producing way too many small clusters.

The TF-IDF + truncated-SVD pipeline behaves nonlinearly with corpus
size: a larger session vocabulary lets the SVD project into more
distinct sub-regions, which HDBSCAN finds at the default `mcs=5`.

Even when we coarsen the lexical HDBSCAN to bring its cluster count
to similar magnitude as the embedding's (`lex_mcs=25` → 16 clusters),
fusion's best result matches HDBSCAN-only by +0.008 ARI. The lexical
view at production scale doesn't carry information the embedding
misses meaningfully enough to survive disagreement-distance fusion.

The +0.085 ARI eval-set win was an artifact of corpus size: at small
n, the two views agree enough on coarseness that their fusion adds
useful structure. At larger n, they don't.

## Lessons (for future E-phase work)

1. **Eval-set metrics are a stress test for a specific corpus
   snapshot.** They don't necessarily generalize to production
   corpora at materially different scale. Before adopting a metric
   improvement, validate at production scale on a held-out
   subset.

2. **Cluster-count dynamics aren't linear in corpus size.** Different
   feature pipelines (embedding vs TF-IDF) have different
   cluster-count growth rates as n_docs grows. A rule like
   `max(n_emb, n_lex)` is brittle when the two grow at different
   rates.

3. **Adoption gating.** The E-phase plan documents "stop conditions"
   per phase based on the eval-set metric. We should also add a
   "production-scale check before adoption" gate to the same plan
   — pulling N production sessions, running the proposed change at
   production hyperparameters, scoring on the eval subset.

## What stays vs what reverts

| Component | Decision |
|---|---|
| `clustering_mode: late_fusion` in production `local.yaml` | **Flip back to `"hdbscan"`** (the revert) |
| `clustering_mode` config field in `SessionConfig` | Keep — default is `"hdbscan"`, opt-in only |
| `cluster_lexical_features_dim` config field | Keep — only read in fusion mode |
| `command_stream_text` ES mapping + rollup builder | **Keep** — harmless additive field, populated for all rollups, useful for any future lexical-based design |
| `command_stream_text` backfill | **Keep** (4030/4030 rollups have it) |
| `compute_lexical_features` + `fusion_cluster_labels` in `enrich.clustering` | Keep — pure-function helpers, no runtime cost when unused |
| `iter_session_docs_with_text` in `cowrie/sessions.py` | Keep — only called in fusion mode |
| `cluster_fn` hook in `run_layer_clustering` | Keep — generic refactor, unused by default, could enable other alt-clusterer experiments |
| Smoke test (`scripts/smoke_test_clustering_fusion.py`) | Keep — validates the math; useful if anyone revisits |
| E4 verdict doc + sweep markdown / scripts | Keep as the measurement record |

## Concrete revert step

In production's `config/local.yaml`:

```yaml
session:
  clustering_mode: "hdbscan"   # was "late_fusion"; revert per E4-postmortem.md
```

Next backward cycle re-clusters using single-pass HDBSCAN; eval-subset
ARI returns to ~0.3340 (the real production floor).

No ES rollback needed — the persisted `command_stream_text` field
becomes inert.
