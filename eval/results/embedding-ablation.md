# Embedding ablation — Nomic vs. TF-IDF + SVD baseline

Brutal-review phase 3.3 + 3.4 reconciliation. Captured 2026-05-31
against the v1 labeled eval set (100 labeled+embedded sessions, 6
distinct playbook labels). Re-runnable any time via:

```bash
console/.venv/bin/python scripts/eval_clustering.py --no-json
console/.venv/bin/python scripts/eval_clustering.py --no-json --embedding-source tfidf-svd
```

Both modes share the eval pipeline (L2-normalize → +scalar block @
production weight → HDBSCAN at production hyperparameters → ARI / NMI
/ homogeneity / completeness / v-measure vs. analyst labels). The only
varying input is the per-session vector source.

## Result depends on the HDBSCAN config

Two captures are kept because the ablation flipped between commits:

### At mcs=3, ms=2 (the original phase 3.3 baseline)

| metric | Nomic (768d) | TF-IDF + SVD (100d) | Δ (Nomic − baseline) |
|---|---:|---:|---:|
| ARI | **0.238** | 0.207 | **+0.031** |
| NMI | **0.652** | 0.607 | **+0.045** |
| Homogeneity | **0.892** | 0.830 | **+0.062** |
| Completeness | **0.514** | 0.479 | **+0.035** |
| V-measure | **0.652** | 0.607 | **+0.045** |

Nomic wins every metric, biggest gap on homogeneity. Looks like a
clear case for the embedding-based approach.

### At mcs=5, ms=2 (the post-phase-3.4 production config)

| metric | Nomic (768d) | TF-IDF + SVD (100d) | Δ (Nomic − baseline) |
|---|---:|---:|---:|
| ARI | 0.301 | **0.357** | **−0.057** |
| NMI | 0.651 | **0.653** | −0.002 |
| Homogeneity | **0.838** | 0.817 | **+0.020** |
| Completeness | 0.532 | **0.544** | −0.012 |
| V-measure | 0.651 | **0.653** | −0.002 |
| n_clusters | 14 | 12 | +2 |
| n_outliers | 24 | 20 | +4 |

**TF-IDF wins ARI by +0.057 absolute (+19% relative).** Homogeneity
flips the other way (Nomic +0.020); the remaining metrics are
essentially tied.

## What flipped, and why

At mcs=3, the Nomic embedding's semantic smoothing pulled
behaviourally-related sessions close enough in 768-dim space that
HDBSCAN found them as one cluster. TF-IDF's sparser representation
left them slightly further apart and mcs=3 fragmented them more.

At mcs=5, both representations are more forgiving — HDBSCAN merges
nearby points more aggressively, so the spread penalty for TF-IDF
shrinks. The inherent "shared command tokens" structure is enough to
find clusters at this granularity, and the Nomic semantic smoothing
adds little. On *this* corpus, the literal-token signal dominates.

The corpus dominance is documented in `scripts/eval_cluster_purity.py`
output: 5 of the top-20 clusters are cargo-cult tight (`modal_sig`
≥ 0.8 — every member runs the *exact same* command set), and many of
the loose clusters share the SSH Credential Spray playbook across
many fragmented HDBSCAN cluster docs. Both representations cluster
cargo-cult scripts equally well; neither does spectacularly on the
fragmented playbook.

## Honest conclusion on the embedding thesis

The README's "embeddings see through wget vs curl" thesis is
**mechanistically correct** but **not currently demonstrated** at
corpus scale. Two specific reasons:

1. **The eval set is dominated by cargo-cult scripts** where every
   session runs near-identical text. TF-IDF nails these because
   literal-token overlap IS the signal. The embedding's value-add —
   pulling textually-divergent same-behaviour sessions together — is
   only exercised on a handful of labeled sessions (notably the
   `mirai_busybox_probe` natural split and `shell_wrapper_only`'s two
   payload shapes).
2. **The labels themselves don't anchor-load the test.** A labeling
   pass that includes more sessions where `wget` vs `curl`,
   `busybox wget` vs `wget`, or different shell wrappers achieve the
   same outcome would amplify the embedding margin substantially.

## What ships next

- **Production stays on Nomic embeddings.** This isn't a "TF-IDF is
  better" verdict — it's "TF-IDF is competitive on this corpus's
  current label distribution". Embeddings still carry value the
  ablation can't measure (downstream novelty scoring, per-command
  intent enrichment, cluster naming) that TF-IDF can't replace.
- **The README is rewritten honestly** (commit 3.5) — the cluster_7
  anecdote stays as a mechanistic demonstration but is no longer the
  load-bearing trustworthiness claim. The actual corpus-wide ARI
  number is cited instead, with the caveat that TF-IDF is in the
  same neighbourhood.
- **Phase 6 or 8 should include a labeling expansion** targeting
  textually-divergent same-behaviour sessions, after which a
  re-ablation can settle the question properly.

## How to reproduce

```bash
# Both modes; same eval set; deterministic given pinned inputs +
# fixed sklearn random_state.
console/.venv/bin/python scripts/eval_clustering.py --no-json
console/.venv/bin/python scripts/eval_clustering.py --no-json \
  --embedding-source tfidf-svd

# Toggle the config temporarily to verify the mcs=3 vs mcs=5 flip:
#   1. Edit config/default.yaml: session.cluster_min_cluster_size: 3
#   2. Re-run both modes — Nomic should win ARI by ~0.03
#   3. Revert: session.cluster_min_cluster_size: 5
#   4. Re-run both modes — TF-IDF should win ARI by ~0.06
```

The `--embedding-source` flag is strictly opt-in; the CI eval gate
(`.github/workflows/eval.yml`) runs without the flag and is unchanged.
