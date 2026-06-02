# E3 + E9 — embedding model ablation

_Captured 2026-06-01 (E3); E9 row added 2026-06-01._

## Verdict: null across both phases. Production Nomic stays.

E3 swept three general-purpose embedders at eval scale; no alternative
cleared E2's best (ARI 0.4447, completeness 0.6040). One candidate
matched it exactly across all metrics (BGE), one underperformed by ~5%
ARI (MiniLM), and the code-specific candidate (Jina v2 code) didn't
load on the current `transformers` version.

E9 added one OOD-leaning candidate (`microsoft/unixcoder-base`) that
imports cleanly and measured it at **both eval and production scale**.
UniXcoder ties Nomic exactly at eval scale (same pattern as BGE) but
**regresses −0.148 ARI at production scale** — the first time a model
swap has shown a measurable difference, and the difference is in the
wrong direction.

The model-class question stays technically open (one code-trained
candidate isn't a complete falsification of the OOD hypothesis), but
priority drops to "investigate when bandwidth allows." See E9 section
below.

## Sweep table

| Phase | Model | Embedding dim | ARI | Completeness | Homogeneity | NMI | V-measure | divergent_pair_resolution_rate |
|---|---|---|---|---|---|---|---|---|
| E3 | **nomic_baseline** | 768 | **0.4447** | **0.6040** | 0.8446 | 0.7043 | 0.7043 | 0.8333 |
| E3 | bge-base-en-v1.5 | 768 | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 |
| E3 | all-MiniLM-L6-v2 | 384 | 0.3975 | 0.5750 | 0.8200 | 0.6760 | 0.6760 | 0.8333 |
| E3 | jina-v2-code | — | DNF | DNF | DNF | DNF | DNF | DNF |
| E9 | unixcoder-base (eval scale) | 768 | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 |
| E9 | unixcoder-base (production scale) | 768 | **0.2423** | 0.4870 | 0.7064 | 0.5766 | 0.5766 | 0.8333 |

- All non-baseline models run via `sentence-transformers` on CPU
  (see [scripts/sweep_embedding_model.py](../../scripts/sweep_embedding_model.py)).
- `embed_context` fixed to production (`[intent, tactics, techniques,
  description]`, cooc=false).
- Pool: production IDF-weighted mean.
- Source JSON: `eval/results/embed-model-sweep-20260601T153743Z.json`.

## What the BGE-Nomic tie tells us

Per-session cosine similarity between Nomic and BGE output vectors is
**median −0.0035**, range **[−0.0386, +0.0292]** — the two models
produce completely orthogonal vector spaces. Yet HDBSCAN finds **the
same cluster structure** in both, to identical decimal places on every
metric (ARI/NMI/homogeneity/completeness/v_measure).

This means the cluster geometry on this corpus is dominated by the
**semantic signal** both general-purpose models capture, not by the
specific embedding space they project into. Two strong text embedders
trained on overlapping general corpora produce equivalent groupings
even if their raw vectors differ. The model choice is not the
bottleneck on this corpus.

## What MiniLM tells us

The 384-d small model loses ~0.05 ARI / 0.03 completeness. Probably a
combination of:
- Lower dimensionality compressing the semantic distinctions between
  similar-but-different playbooks.
- Smaller capacity (22M vs 137M params) — less granular semantics for
  noisy / unusual input.

But it still clears E2's ARI ≥ 0.36 target on its own, just not E2's
best. So small models work; small models lose to bigger ones in the
same family.

## What happened with jina-v2-code

Failed to import on `transformers==5.9.0`:

```
cannot import name 'find_pruneable_heads_and_indices'
  from 'transformers.pytorch_utils'
```

Jina's custom modeling code (`modeling_bert.py` from
`jinaai/jina-bert-v2-qk-post-norm`, fetched via `trust_remote_code=True`)
expects a transformers API that was removed in a recent transformers
release. Workarounds:

- Pin `transformers<5.0` (regression risk for other transformers-using
  code in the venv — defer)
- Patch the cached `modeling_bert.py` locally (brittle to model updates)
- Swap in a different code-specific embedder
  (e.g. `microsoft/unixcoder-base`, `Salesforce/codet5p-110m-embedding`,
  or `nomic-ai/CodeRankEmbed`)

Given BGE — a strong general-purpose embedder of the same scale —
matched Nomic exactly, the prior on code-specific models winning is
weak. Not pursued further unless the corpus grows in a way that
exposes a semantic boundary general models actually miss.

## E2 + E3 combined picture

Across two phases of cheap-knob and model-swap testing, **no
configuration meaningfully beats production Nomic with the E2.1
embed_context + cooc=false adoption**. The configuration we adopted
in E2 is the ceiling of what's achievable with general-purpose
embedding tweaks on this corpus.

The remaining headroom to the plan's E4 target (completeness ≥ 0.70)
is structural: it would require either

- a corpus expansion that surfaces semantic distinctions current
  general-purpose embedders can't see (which they actually CAN — the
  tie above is the evidence), or
- a hybrid signal (E4: lexical + embedding) that picks up information
  the embedding alone misses, or
- task-specific fine-tuning (E5).

Plan E3's stop condition (no model clears E2's best) fires; next gate
is E4.

## E9 — code-trained candidate retry (one OOD candidate)

E3 declared the model-class question null at eval scale, but only on
three general-purpose embedders. The "shell commands are out-of-
distribution for general-text encoders" hypothesis was never
falsified — `jina-v2-code` DNF'd. E9 picks one fresh OOD candidate
that imports cleanly and runs it at **both** eval scale (for direct
comparison to the E3 table) and production scale (E6.1 pattern).

### Candidate selection

Plan's fallback order:
1. `microsoft/unixcoder-base` — imports cleanly on `transformers 5.9`,
   no `trust_remote_code` needed. Max position embeddings = 1024 (vs
   sentence-transformers' default tokenizer ceiling of 1e9). The sweep
   harness now introspects `auto_model.config.max_position_embeddings`
   and clamps `model.max_seq_length` accordingly so the encode doesn't
   crash on the corpus' longer commands.
2. `Salesforce/codet5p-110m-embedding` — failed with
   `AttributeError: 'CodeT5pEmbeddingConfig' object has no attribute
   'is_decoder'` even with `trust_remote_code=True`.
3. `nomic-ai/CodeRankEmbed` — failed: needs `einops` and
   `safe_serialization` kwarg mismatch.

UniXcoder wins the fallback chase. Microsoft's code-trained encoder
(~6M repos across Python, Java, Go, PHP, Ruby, JavaScript) — closer in
training distribution to shell commands than any general-purpose
encoder the E3 phase tested.

### Eval scale: ties Nomic exactly

| Model | ARI | Completeness | Homogeneity | NMI | V-measure | v2 pair rate |
|---|---|---|---|---|---|---|
| nomic_baseline | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 |
| unixcoder-base | 0.4447 | 0.6040 | 0.8446 | 0.7043 | 0.7043 | 0.8333 |

Byte-identical to 4 decimal places — same pattern as the BGE-Nomic tie
from E3. At 108 sessions the cluster geometry is dominated by signal
both embedders capture; the differentiator (code-trained vs general)
makes no measurable difference.

### Production scale: regresses by 0.148 ARI

| Model | ARI | Completeness | Homogeneity | NMI | V-measure | v2 pair rate | n_clusters | n_outliers |
|---|---|---|---|---|---|---|---|---|
| nomic_baseline (production) | **0.3906** | 0.5478 | 0.8640 | 0.6705 | 0.6705 | 0.6667 | 24 | 37 |
| unixcoder-base (production) | 0.2423 | 0.4870 | 0.7064 | 0.5766 | 0.5766 | **0.8333** | 23 | 56 |
| **Δ (unixcoder − nomic)** | **−0.1483** | −0.0608 | −0.1576 | −0.0939 | −0.0939 | **+0.1666** | −1 | +19 |

The headline ARI regresses well past the gate's ±0.05 tolerance.
Homogeneity drops 0.158 (clusters less internally pure). Outlier count
jumps from 37 → 56 (UniXcoder finds tighter density requirements,
pushes more sessions to noise).

A surprising note: the **divergent-pair resolution rate improves**
from 0.6667 to 0.8333 (5/6 → 5/6, but a DIFFERENT 5/6 — the
pair UniXcoder solves that Nomic missed is offset by a pair Nomic
solved that UniXcoder misses). The model is sensitive to different
features of the corpus, just not in a way that translates to better
overall ARI.

Source: [embed-model-prod-scale-20260601T202240Z.json](embed-model-prod-scale-20260601T202240Z.json).

### Why the eval-scale tie reverses at production scale

Two effects compound:

1. **Coverage of the encoder's lexical neighborhood.** UniXcoder
   trained on Python/Java/Go/PHP/Ruby/JavaScript — five high-level
   languages. On 108 eval-set sessions, the commands fall within the
   subset of shell vocabulary that intersects those languages' usage
   patterns (`wget`, `curl`, `ls`, etc. are documented in code corpora
   too). At ~4000 production sessions, the corpus surfaces more
   adversarial-shell-specific vocabulary (BusyBox subroutines, /tmp
   scratch-file conventions, base64 droppers, MikroTik RouterOS
   commands) that the code corpus didn't index. UniXcoder treats those
   commands as more-novel-than-they-are.

2. **Position-embedding sensitivity.** Some production commands hit
   the 1024-token clamp; UniXcoder truncates and loses tail signal.
   Nomic's 8192-token context window absorbs the full command. This
   doesn't affect eval scale (only ~3% of eval commands hit even 512
   tokens) but matters at corpus scale where the long-tail wrappers
   are more represented.

### E9 verdict

**Null. Production Nomic stays.** UniXcoder doesn't clear the
production-scale floor (binding ARI gate at 0.3773 per
`eval/baseline-prod-scale.json`); the regression of 0.148 ARI is well
outside the gate's ±0.05 tolerance and fails the per-label
fragmentation rule (homogeneity drops 0.16, outliers grow ~50%). No
config change.

The plan's E9 stop condition fires: one OOD-leaning candidate didn't
move the metric at production scale. The model-class question stays
technically open (one model isn't enough to close it conclusively), but
priority drops to "investigate when bandwidth allows" per the
operator's lowest-priority-lever framing in
[docs/handoff-embedding-quality-plan.md](../../docs/handoff-embedding-quality-plan.md).
E5 (LoRA fine-tune) remains gated behind its original condition.

### What this measurement adds to the picture

This is the cleanest demonstration of "eval-scale != production-scale"
the project has captured. Three data points now exist:

| Phase | Eval scale | Production scale | Lesson |
|---|---|---|---|
| E2.1 cooc=off | +0.0897 ARI | +0.0536 ARI | direction holds, magnitude compresses (~40%) |
| E4.4 fusion | +0.0850 ARI | −0.1731 ARI | direction reverses (E4 postmortem) |
| E9 unixcoder | ±0.0000 ARI | −0.1483 ARI | tied at eval, regressed at production |

Eval-scale ties can hide production-scale failures. This is exactly
why the E6 gate exists. Any future model-swap E-phase needs to run via
E6.1 before adoption — the eval-scale row alone is not safe to act on.

The E9 row was captured via
[scripts/sweep_embedding_model_prod.py](../../scripts/sweep_embedding_model_prod.py).
That script lives on as opt-in dead infrastructure: future OOD
candidates can be plugged in by editing `_CANDIDATES`, with no other
machinery changes.
