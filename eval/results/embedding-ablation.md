# Embedding ablation — Nomic vs. TF-IDF + SVD baseline

Brutal-review phase 3.3. One-time doc captured 2026-05-31 against the
v1 labeled eval set (100 labeled+embedded sessions, 6 distinct
playbook labels). Re-runnable any time via:

```bash
console/.venv/bin/python scripts/eval_clustering.py --no-json
console/.venv/bin/python scripts/eval_clustering.py --no-json --embedding-source tfidf-svd
```

Both modes share the eval pipeline (L2-normalize → +scalar block @
production weight → HDBSCAN at production hyperparameters → ARI / NMI
/ homogeneity / completeness / v-measure vs. analyst labels). The only
varying input is the per-session vector source.

## Side-by-side metrics

| metric | model (Nomic 768d) | tfidf-svd (100d) | Δ (model − baseline) |
|---|---:|---:|---:|
| ARI | **0.2380** | 0.2071 | **+0.0309** |
| NMI | **0.6521** | 0.6072 | **+0.0449** |
| Homogeneity | **0.8920** | 0.8298 | **+0.0622** |
| Completeness | **0.5138** | 0.4788 | **+0.0350** |
| V-measure | **0.6521** | 0.6072 | **+0.0449** |
| n_clusters | 17 | 17 | 0 |
| n_outliers | 16 | 15 | −1 |

The Nomic embedding wins on every metric. The margin is consistent
(~+0.03–0.06 absolute across the row) and shows up most clearly on
homogeneity (+0.062): embeddings produce more internally-coherent
clusters than TF-IDF on the same data.

## Why TF-IDF is closer than you might expect

The corpus is **dominated by cargo-cult scripts** where the same
commands appear literally across many sessions
(`scripts/eval_cluster_purity.py` already surfaced this: cluster_20
SSH Key Dropper has 526 sessions with modal-signature share 0.99 —
every member runs the *exact same* command set). TF-IDF nails cargo-
cult clusters because it captures literal-token overlap. The Nomic
embedding only pulls ahead when sessions are semantically similar but
textually different — and the v1 eval set has a limited number of
those (notably the `shell_wrapper_only` clusters with two payload
shapes and `mirai_busybox_probe`'s natural split).

## Verdict

**Embeddings hold on this corpus**, but the margin is modest. Three
implications for what ships next:

1. **The phase-3.4 hyperparameter commit stays with Nomic embeddings.**
   The sweep winner (mcs=5, ms=1, ARI 0.301) is on top of the model
   embeddings; the equivalent TF-IDF run would float around 0.27.
2. **The "embeddings see through textually-unrelated synonyms"
   thesis the README headlined is correct but currently
   underutilised** — the eval set isn't anchor-loaded with the kind of
   `wget` vs `curl` substitution cases where embeddings dominate. A
   future labeling expansion that includes more textually-divergent
   same-behaviour sessions would amplify the margin.
3. **The TF-IDF baseline at 0.21 ARI is a respectable floor** — within
   striking distance of the production system. The pipeline isn't
   being *saved* by embeddings; it's being *improved*. Worth keeping
   in mind when reasoning about the cost (LLM enrichment budget,
   embedding inference latency) of the model-based path.

## How to reproduce / re-run

```bash
# Both modes; same eval set; deterministic given pinned inputs.
console/.venv/bin/python scripts/eval_clustering.py --no-json
console/.venv/bin/python scripts/eval_clustering.py --no-json --embedding-source tfidf-svd

# Or split the runs into JSON dumps for archival:
console/.venv/bin/python scripts/eval_clustering.py \
  --output-dir eval/results --no-json     # writes via default path; switch off --no-json
console/.venv/bin/python scripts/eval_clustering.py \
  --embedding-source tfidf-svd            # writes a tfidf-svd-tagged dump
```

The `--embedding-source` flag is **strictly opt-in**; the CI eval gate
(`.github/workflows/eval.yml`) runs without the flag and is unchanged.
