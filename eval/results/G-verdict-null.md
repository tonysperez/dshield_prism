# Phase G verdict — both arms null

_Captured 2026-06-02._

## Headline

**Both alternative representations null on the real corpus.** Neither
recovers a *better* session-level partition than the embedding baseline.
Phase G re-confirms, from the representation angle, what F confirmed from
the clusterer angle: on this corpus the session-level semantic structure
the embedding mean-pool captures is near the ceiling, and the remaining
"different" structure the arms surface is finer fragmentation, not better
behaviour grouping. The arm code stays as opt-in dead infrastructure
(`cluster_bag_labels`, `session_fingerprint.py`) for re-evaluation if a
corpus shift changes the calculus.

Decided label-free over the full ~4,077-session corpus (the 108 analyst
labels are too thin to adjudicate), via `scripts/compare_arms_corpus.py`
and `scripts/fingerprint_prod.py`.

## What was tested

| arm | clusters | intent coh. | signature coh. | v2 pairs | cross-arm ARI |
|---|---:|---:|---:|---:|---:|
| **baseline** (embedding) | 14 | 0.995 | 0.210 | 4/6 | — |
| **Arm B** `cluster_bag` | 115 | 0.984 | 0.239 | **5/6** | 0.087 |
| **Arm C** `fingerprint` | 134 | 0.949 | 0.324 | 4/6 | 0.076 |

- **Arm B — bag of command-cluster ids.** Thesis: bagging command-cluster
  ids preserves the cluster-level semantic signal (`cluster_7`) at the
  session level that mean-pool washes out, showing up as *lower* signature
  coherence (grouping same-behaviour / different-text sessions). **Not
  supported.** Arm B's signature coherence (0.239) is ~equal to baseline's
  (0.210), not lower — baseline already abstracts over exact command text
  comparably. What Arm B actually does is fragment ~8× (115 vs 14 clusters)
  with intent coherence held up automatically by the smaller clusters. Its
  only edge is +1 on the 6-pair v2 set — too thin to weight.
- **Arm C — deterministic out-of-stream fingerprint.** Thesis: the dp-009
  lesson generalises — file events / HASSH / login / credentials carry the
  behavioural distinction the command stream can't. **Not supported.** On
  the real corpus the fingerprint scatters 60% of sessions to noise (the
  high-cardinality HASSH/credential/geo combinations make most sessions
  look unique), fragments to 134 clusters, drops intent coherence, and —
  decisively — leaves the v2 divergent-pair rate at 4/6, i.e. it does **not**
  resolve dp-009 better. The out-of-stream signal, as captured, is operator/
  host identity, not a parallel behaviour channel.

## Why neither cleared

The deciding metric is not the 108-label ARI (which the operator rightly
flagged as too limited) but the corpus-wide self-consistency + the v2
ground truth. Both arms produce *different* partitions (cross-arm ARI ≈
0.08), but "different" here means **more fragmented**, not more behaviourally
coherent: intent coherence is flat-to-down and the v2 resolution moves by at
most one pair on a six-pair set. That is the F-spike pattern again — extra
structure that is fragmentation rather than signal. By the G framework
(`g_better ≥ 40%` on the analyst render), neither arm earns the G4 eyeball:
Arm C is an outright null (60% noise, no v2 gain), Arm B a marginal-at-best
that doesn't justify adopting an 8×-finer partition.

## What's left on the semantic-not-textual table

Both remaining candidates are larger / project-level decisions, deferred:

- **Session-shape dedup + canonical-session LLM summaries** (pre-plan idea
  A). The only path that might still work, but a real build: a new
  `prism.identity.cowrie.session_shape` anchoring index + a canonical-session
  LLM call budget (within the no-per-session-LLM constraint by amortizing
  over shapes) + shape→summary cache invalidation. A Phase H decision.
- **Trajectory-level or hierarchical reframes** — cluster operators across
  sessions, or abandon the flat-partition objective. Structurally different
  ground; a project-level call, not a clustering-mode tweak.

Net across E → F → G: on this single-sensor corpus the session-level
semantic clustering is at its ceiling. The shipped wins (0.94 merge
consolidation, command-layer rescue) came from *fixing fragmentation and
outliers*, not from extracting more semantic structure — which is the
honest shape of what this corpus supports.
