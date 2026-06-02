# F-phase decision spike — verdict

_Captured 2026-06-01._

## Headline

**Null on the global-re-partition arms (F3 late fusion, F4 low-mcs). The
corpus has ~7–8 genuinely-distinct small clusters and the *current*
production config (`mcs=5`) already surfaces them.** Neither lower-mcs
HDBSCAN nor late fusion surfaces *more* genuinely-distinct small clusters
without breaking the relaxed ARI floor — they surface more *clusters*, but
those are density fragments of the existing big playbooks, not new
behaviours. Per the spike rule (Execution strategy), this **re-confirms
Plan E's ceiling: stop, do not build F1b / F2.1 / F5** for the session
layer. ~3 days spent, ~6 weeks of speculative build avoided.

This is the spike's designed-for outcome ("Spike is all shards / null →
stop"), with one refinement: the failure mode is not *lexical* shards
(3b shard fraction is 0.0 everywhere) but *density* fragments — a gap the
original 3b metric did not name. The spike earned a new first-class
metric for it (see "Metric refinement" below).

## What ran (spike scope, all on existing/cheap code)

| Phase | What | Output |
|---|---|---|
| F0.1 | small-cluster + outlier metrics in `eval_clustering.py` | shared `small_cluster_metrics()` |
| F0.2 | same metrics corpus-wide in `eval_production_scale.py` (binding) | live-ES 3a/3b + snapshot degrade |
| F2.0 | `scripts/inspect_small_clusters.py` size-∈[3,10] render harness | self-test + live eyeball |
| F4.1 | `scripts/sweep_hdbscan.py --prod` — 8-point (mcs,ms) grid, 7 metrics | `hdbscan-prod-sweep-*.md` |
| F3.1 | `scripts/sweep_late_fusion_prod.py` — late fusion, 7 metrics | `late-fusion-prod-sweep-*.md` |

All at production scale (4,045 sessions, live ES). The labeled subset (108
sessions / 6 coarse labels) is too small to translate to prod geometry, so
metrics 1–3 (the small-cluster axis) are scored corpus-wide; only ARI /
completeness / homogeneity / divergent-pair use the labels.

## The decisive table

`distinct` = size-∈[3,10] clusters whose centroid is cosine < 0.96 from
**every** big (size > 100) playbook — i.e. genuinely not a fragment of an
existing behaviour. This is the real surfacing yield. `near-big` = density
fragments (cos ≥ 0.96 to a big playbook centroid).

| config | ARI | n_small | **distinct** | near-big | shard (3b) | purity |
|---|---:|---:|---:|---:|---:|---:|
| **baseline mcs=5 (prod)** | **0.3906** | 8 | **7** | 1 | 0.0 | 0.90 |
| F4 mcs=3 | 0.2078 ✗ | 61 | 16 | 45 | 0.0 | 0.98 |
| F4 mcs=2 | 0.1641 ✗ | 161 | 14 | 147 | 0.0 | 0.996 |
| F4 mcs=8 | 0.2927 ✗ | 1 | 1 | 0 | 0.0 | 1.0 |
| F3 fusion lex25/auto | 0.3148 | 2 | 2 | 0 | 0.0 | 1.0 |
| F3 fusion lex25/nc=60 | 0.2765 ✗ | 5 | 5 | 0 | 0.0 | 1.0 |
| F3 fusion lex5/nc=93 | 0.1539 ✗ | 13 | 8 | 5 | 0.0 | 0.93 |

✗ = below the relaxed ARI floor (0.30 = unconditional rejection, metric 4).

## Why this is a null

1. **Distinct-small-cluster yield plateaus at ~7–8, independent of the
   knob.** Baseline already finds 7. Lowering mcs to 3 nudges it to 16 but
   floods 45 density fragments and breaks the ARI floor (0.21). Lowering to
   2 *reduces* distinct to 14 while flooding 147 fragments (ARI 0.16). Late
   fusion tops out at 8 distinct only at nc=93, where ARI craters to 0.15.

2. **The big copy/paste playbooks survive at every mcs** (n_large = 5–7
   across the grid), so the 0.0 shard fraction is real, not an artifact of
   a vanishing reference set. What lowering mcs does is shred those intact
   big playbooks' *periphery* into size-7 pockets at cos ≈ 1.0 — same
   behaviour, different density bucket.

3. **Late fusion is strictly dominated by the embedding baseline.** The
   only fusion config clearing the ARI floor (lex25/auto, 0.3148) yields
   *fewer* distinct clusters than baseline (2 < 7). Every config with more
   distinct clusters than baseline sits far below the floor. There is no
   point on the fusion Pareto front that beats baseline on both axes. This
   re-confirms the E4 postmortem (the eval-scale fusion win does not survive
   at prod scale) under the *new* metric framework that was built to credit
   the qualitative small-cluster win — and it still says baseline wins.

4. **The analyst go/no-go on baseline is "go, and they're already here."**
   The 7 distinct baseline small clusters are real, textually-divergent
   same-behaviour groups: MikroTik `/ip cloud print` host-recon (the
   README's cluster_7), chattr+ssh-key injection with divergent key text,
   the `echo "…; echo __<nonce>" | sh` probe (embedding sees through the
   per-session nonce), the "meow" dropper with rotating IPs. The clusters
   the alternative knobs *add* on top read as recon density-pockets, not
   new behaviours — exactly the over-fragmentation Plan E / the E4
   postmortem rejected.

## Metric refinement the spike earned

Metric 3b (shard fraction) was specified as *lexical*: near a big centroid
**AND** textually homogeneous (`modal_signature_share ≥ 0.8`). The spike
showed that on this corpus the dominant fragmentation mode is **density,
not lexical** — fragments hugging a big recon centroid (cos ≈ 1.0) but
textually *diverse* (modal_sig ≈ 0.1), which 3b passes as "distinct." Added
two first-class metrics in `small_cluster_metrics()` to close the gap:

- `n_small_clusters_distinct` — small clusters with cos < merge_threshold
  to every big playbook (the genuine yield).
- `small_cluster_near_large_fraction` — share that are density fragments.

Without these, metric 2 ("n_small_clusters up by ≥ 5") is satisfiable by
pure density fragmentation (mcs=3 trivially "passes" with +53), exactly the
gaming the plan warned 3a alone permits. `n_small_clusters_distinct` is the
honest version of metric 2 and should replace it in any future F-phase gate.

## Recommendation

- **Do not adopt** any F3/F4 config. Leave `clustering_mode: hdbscan`,
  `mcs=5`, `ms=2`. The late-fusion path stays as opt-in dead infrastructure.
- **Skip F1b / F2.1 / F5.** The premise (HDBSCAN suppresses interesting
  small clusters) does not hold at the distinct level; the suppressed
  clusters are density fragments.
- **F2 (secondary HDBSCAN on outliers only) is the one un-falsified lever**,
  but its ceiling is tiny here: the session layer has only **37 outliers
  (0.91%)** post-rescue, so a secondary pass can mint at most ~1–3 size-≥3
  clusters. Not worth the `small_` graduation machinery. If revisited, it is
  additive (no big-playbook shredding) and so structurally avoids the
  density-fragment failure mode F3/F4 hit.
- **Leave the ARI floor at its original 0.3773 / 0.3906 baselines.** The
  relaxed 0.30 floor was only ever *proposed* (F0.3, deliberately not run
  once the spike nulled), so `eval/baseline.json` /
  `eval/baseline-prod-scale.json` were never loosened — nothing to revert.
- **F0 metric infrastructure is worth keeping** regardless — it is what made
  this a 3-day measured decision instead of a 6-week guess, and the
  distinct/near-large decomposition is the durable artifact.

## Addendum — both-ways fragmentation test (the premise was backwards)

After the spike, the operator flagged that Plan F's *under*-fragmentation
premise might be wrong and asked to test fragmentation in **both**
directions. Done via `scripts/sweep_merge_threshold.py`
(`merge-threshold-sweep-*.md`), which — for the first time — runs the
session-layer `merge_clusters_into_playbooks` pass in the measurement
(the established eval scores HDBSCAN+rescue **pre-merge**). Base
granularity held fixed at HDBSCAN(5,2)+rescue(0.96); only the merge
threshold varies.

| merge_thr | clusters | ARI | completeness | homogeneity | n_small | distinct | near_lg |
|---|---:|---:|---:|---:|---:|---:|---:|
| none (pre-merge) | 24 | 0.3906 | 0.5478 | 0.864 | 8 | 7 | 0.125 |
| 0.96 (**current**) | 17 | 0.4160 | 0.5763 | 0.864 | 6 | 6 | 0.000 |
| 0.94 | 15 | **0.4361** | **0.5919** | 0.864 | 5 | 5 | 0.000 |
| 0.92 | 12 | 0.4494 | 0.5990 | 0.786 ✗ | 4 | 4 | 0.000 |
| 0.90 | 10 | 0.5295 | 0.6532 | 0.786 ✗ | 1 | 1 | 0.000 |

Findings:

1. **The premise was backwards: the corpus *over*-fragments, not under.**
   *More* fragmentation (no merge, 24 clusters) is *worse* (ARI 0.39 vs
   0.42 current). Plan F's whole "HDBSCAN suppresses small clusters"
   motivation is refuted at production scale.
2. **Two of my mid-spike claims were pre-merge artifacts.** The "density
   fragment at the margin" is already absorbed by production's 0.96 merge
   (near_lg 0.125 → 0.0). And the eval baseline 0.3906 is **pre-merge** —
   real production ARI is **0.4160**; the established eval understates it
   by skipping the merge step.
3. **A modest, real consolidation win exists at `merge_threshold ≈ 0.94`.**
   ARI 0.4160 → 0.4361, completeness +0.016, homogeneity flat at 0.864,
   shard 0, density fragments 0. Below 0.94 homogeneity breaks (0.786 <
   0.80) — distinct behaviours start merging and the further ARI gain is
   the 6-coarse-label artifact (merging toward 6 clusters), not a real win.
4. **Eyeball confirms 0.94 is benign consolidation, not behaviour collapse.**
   The merges it adds over 0.96: four `uname` recon variants → one
   uname-fingerprinting playbook; the bare `chattr -ia .ssh` lock fragment
   folded into the full SSH-key-injection playbook (same chattr+ssh
   family). The README's distinct behaviours (MikroTik recon, SSH-key
   campaign) stay separate.

**This is the one genuine improvement the work surfaced — but a small and
caveated one.** The ARI delta (+0.02) is on 108 sessions / 6 labels;
what makes it credible is the flat homogeneity + the eyeball, not the ARI
alone. Caveats for adoption:

- `playbook_merge_threshold` is a *single* knob driving rescue (sessions.py:1787),
  the cluster→playbook merge (2635), **and** cosine-anchor identity matching
  (2657/2781). Lowering it to 0.94 also rescues a few more outliers and
  changes which playbooks re-use existing `spb-` ids vs mint new — a
  playbook-identity migration, fine in dev (re-process freely) but a real
  production step. The sweep isolated the dominant (merge) effect; a true
  adoption run should set the knob and re-capture `baseline-prod-scale.json`.
- It does **not** reopen F1b/F2.1/F5 — those targeted surfacing *more*
  clusters; this consolidates. The corpus wants fewer, cleaner playbooks.

**Recommendation:** treat `playbook_merge_threshold: 0.96 → 0.94` as the
adoptable candidate (operator sign-off + re-baseline). Headroom beyond
this is the input-signal direction (A), not any merge/partition knob.

## Files

- `scripts/eval_clustering.py` — `small_cluster_metrics()` (F0.1) + density decomposition.
- `scripts/eval_production_scale.py` — corpus-wide binding metrics (F0.2).
- `scripts/prod_corpus.py` — shared live-ES puller + `score_full()`.
- `scripts/inspect_small_clusters.py` — F2.0 eyeball harness.
- `scripts/sweep_hdbscan.py --prod` — F4.1.
- `scripts/sweep_late_fusion_prod.py` — F3.1.
- Sweep outputs: `hdbscan-prod-sweep-*.md`, `late-fusion-prod-sweep-*.md`,
  `small-cluster-inspect-sessions-*.md`.
