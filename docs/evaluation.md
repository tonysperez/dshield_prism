# Evaluation

How clustering and labeling quality is measured, and what the measurements
found. Without a labeled set, clustering quality reduces to anecdote — so every
representation/algorithm change is gated against analyst ground truth before it
ships.

The CI gate commands are in [reference.md](reference.md#ci-gates). The labeling
rule book is [`eval/RUBRIC.md`](../eval/RUBRIC.md); the eval-set mechanics are in
[`eval/README.md`](../eval/README.md).

## The labeled set

A **variety-first sample** of cowrie sessions, hand-labeled with the
*behavior* each session expresses (independent of textual command form — two
sessions doing the same job through different commands get the same label).
Bucketed by `playbook_id` (each unattributed session its own bucket) with a
per-playbook cap, so a single dominant behavior can't crowd out the rest —
not a stratified-random draw. `dshield.classification: public`-gated and
defanged at sample time (`scripts/build_eval_set.py`), so it's safe to
publish.

- `eval/labels.yaml` — the labels, one block per `session_id` (tracked; the
  deliverable).
- `eval/sessions.unlabeled.jsonl.gz` — the sampled, public-only, defanged
  session data the labels join against (tracked — safe to publish post-defang;
  rebuildable from the corpus via `scripts/build_eval_set.py`).
- `eval/RUBRIC.md`, `eval/labeling-prompt.md` — the labeling rule book and a
  self-contained prompt to automate it (tracked).
- `eval/baseline*.json` — metric snapshots the gates diff against (tracked).
- The rendered per-session markdown is **generated**, not committed
  (rebuildable via `scripts/render_eval_set.py`).

Labels join against the unlabeled JSONL by `session_id` at load time — no
labeled JSONL ever materializes on disk. Session embeddings are frozen in the
unlabeled JSONL at sample time, not recomputed per eval run —
`scripts/refresh_eval_embeddings.py` is the only supported refresh path after
a production re-embed. Command-cluster-id tokens (`command_enrichments[*]`'s
`cluster` block — the TF-IDF bag vocabulary) are likewise frozen at sample
time; `scripts/refresh_eval_taxonomy.py` is the refresh path after a
clustering/taxonomy re-run, public-only gated the same way as
`capture_anchor_snapshot.py`.

## The gates

The gates run in CI; run them all locally before any commit.

| Gate | Script | Measures |
|---|---|---|
| **Operational** | `eval_operational.py` | the operator jobs on the eval geometry: assignment macro-F1 + per-label accuracy, novel precision/recall + false-familiar at the shipped τ (whole-label holdout), minted-playbook purity + distinct count |
| Real-anchor assignment | `eval_assignment_prod.py` | assignment against the committed public anchor snapshot; fails if the snapshot anchor count and baseline `n_anchors` disagree |
| Production-scale | `eval_production_scale.py` | the eval-labeled subset clustered *inside* the full production HDBSCAN |
| Command-scale | `eval_command_scale.py` | command-layer clustering at production scale |
| Clustering (diagnostic) | `eval_clustering.py` | partition metrics (ARI/NMI/homogeneity/completeness/v_measure) — **prints, does not gate** |
| Assignment (diagnostic) | `eval_assignment.py` | accuracy / macro-F1 / mean_auc_novel — **prints, does not gate** |
| Production-path assignment (temporary diagnostic) | `eval_assignment_faithful.py` | shared TF-IDF band confirmation + cascade, familiar classification and whole-behavior novelty at deployed/fixed-grid thresholds |
| Reliability (diagnostic) | `eval_agreement.py` | intra/inter-annotator agreement (Cohen's κ, PABAK, per-label percent agreement, plus vocabulary-aligned agreement) against `eval/baseline-agreement.json` — currently **κ=0.866, PABAK=0.788, 89.4% raw agreement over n=160** — and an `expected_findings` precision/recall diagnostic — **prints, does not gate** |

The operational gate is the semantic gate: each metric maps to a named operator
failure (a wrong label, a missed novel, an incoherent minted playbook), and every
threshold is variance-justified — a bootstrap-CI half-width for metrics with real
n, a hard absolute floor for per-label accuracy (a collapse detector). No flat
absolute drop, so a green gate means the tool still does its job rather than that
a chance-adjusted partition score held steady. Novelty is gated at the shipped τ
only if the baseline shows it non-degenerate in the label-mean geometry; false-
familiar (= 1 − novel recall) is reported, not double-gated.

The partition metrics measure a geometry off the shipped nearest-prototype assign
path, so `eval_clustering.py` and `eval_assignment.py` still print for a coarse
sanity check but no longer fail a build.

`eval_assignment_faithful.py` closes the decision-path measurement gap: it uses
the production lexical preparation boundary and `assign_batch`, reports
session/behavior-grouped uncertainty for aggregates, eligible labels,
behaviors, decision paths, and cascade slices, and protects the complete run
identity when a baseline is explicitly supplied. Its current label-derived
prototypes are substantially broader than production anchors, so its low
coverage/large false-novel result is a geometry diagnostic, not an adoption
gate. Representative public anchors are committed (29 public-derived of 33 live), so
that prerequisite is met.

The `--anchors` replay fits its TF-IDF/SVD lexical space over just the
committed anchor snapshot plus the ~70 attributed eval sessions — thin enough
(median 16 bags/anchor at capture time) that early runs measured fixture noise,
not the band-confirm mechanism itself, and wrongly read as the mechanism being
broken; a corpus-scale check later confirmed the real mechanism works
(agreement 1.0000) and retracted that reading. Two fixes close the gap: an
anchor gets no TF-IDF centroid at all once its sampled bag count falls under
`lexical._MIN_ANCHOR_BAGS` (50) — it degrades to embedding-only for that anchor
rather than contributing a noisy cosine — and `--background PATH` (a broad,
non-scored public session sample from `capture_anchor_snapshot.py
--background-out`) can pad the fit's document space closer to production's.
Omitting `--background` leaves output unchanged. TF-IDF-dependent numbers from
this replay (including the coverage figure above) should be read against a
`--background`-padded run; the plain `--anchors` run without it still fits a
comparatively thin space.

Baselines are re-captured only for an *intentional* production change — never to
silence a regression. That's the whole point of the gates.

### Eval-scale vs production-scale

Two clustering gates run because the difference matters. The **eval-isolated**
gate clusters only the ~148 labeled sessions — fast, gate-on-every-push. The
**production-scale** gate clusters the same labeled subset *inside* the full
~4000-session production HDBSCAN, which finds tighter density requirements and
fragments the same labels across more clusters. The resulting ARI gap between the
two scales is a **measurement property, not a regression**: production HDBSCAN
operates on more sessions. The eval-isolated gate is for fast iteration; the
production-scale gate is the floor for adoption decisions. (This split exists
because an earlier change won at eval scale and regressed at production scale.)

The production-scale gate reads a committed, redacted snapshot
(`eval/production-snapshot-v1.jsonl.gz`) so it needs no ES. The snapshot is
refreshed quarterly (`scripts/refresh_production_snapshot.py`); the gate warns
at >90 days and hard-fails at >180 to force the cadence.

## What the measurements found

These are the durable conclusions that shaped the current design. Exact metric
values live in the `eval/baseline*.json` snapshots (the source of truth);
numbers below are headline figures, not contracts.

**The embedding earns no edge over text — so labeling is assignment, not
clustering.** A faithful, payload-keyed evaluation (same-payload sessions with
disjoint commands vs. different-payload controls, command overlap held constant)
found the session embedding does **not** separate behavior better than a TF-IDF
baseline; on a 4-year corpus its cosine is dominated by coarse intent, and
TF-IDF edges it on the controlled test. Prism therefore makes **no "semantics
over text" claim**. Session labeling moved from unsupervised full-corpus
clustering to **nearest-prototype assignment with a TF-IDF confirm** — cheaper,
identity-stable, and it surfaces novelty directly. The standing consequence — do
not reintroduce a "semantics over text" claim without a corpus that shows it —
is recorded in [decisions.md](decisions.md). The experiment's own scripts and
result files were not retained; the conclusion is the deliverable.

**Every metric here belongs to one of two geometries; a bare number is a wrong
number.** *Label-prototype* geometry builds one reference vector per analyst
behavior — it grades the **algorithm**. *Real-anchor* geometry assigns against the
actual production anchor library — it grades the **deployed system**. macro-F1 is
**0.7898 on prototypes** and **0.6385 deployed / 0.6702 band-disabled** on the live
real-anchor library; coverage is **0.9978 on the assignment path** and **0.9095 on the
naming path**. Always name which, and always quote the CI half-width belonging to that
geometry — **±0.1579** on the prototype gate, **±0.080** on the real-anchor measurement. The prototype
interval is wide enough that most single-change claims are unprovable, and several
conclusions in this project's history were retracted for ignoring it.

**Read per-label accuracy below n=5 with care.** Only singletons leave the macro-F1
mean (`eval_assignment.MIN_MACRO_SUPPORT` = 2) — everything else counts, by decision.
But at n=3–4 the score is an artifact of support: k-fold puts each member in its own
fold while its two near-identical siblings build the prototype it is then trivially
nearest to, so `iot_cli_probe`, `scp_upload` and `dropped_binary_exec` all read exactly
**1.0000**. That is a label the fold structure cannot test, not evidence the behavior is
handled. Pruning them was measured and declined: it *widens* the interval (half-width
0.1594 at n≥2, 0.1661 at n≥5) because a mean over fewer labels is noisier — ±0.15 is
structural to averaging labels equally, not a rare-label artifact. `macro_f1_support` in
the report names exactly which labels formed the mean.

**Assignment recovers analyst labels moderately well; novelty over-calls.**
Nearest-prototype assignment recovers the analyst playbook on a held-out split
at 0.8565 accuracy / 0.7898 macro-F1 (`baseline-assignment.json`, label-prototype).
Whole-label holdout at the shipped τ reads held-out behaviors as novel at 0.8841
recall, but at only 0.5865 precision (`baseline-operational.json`). Re-measured on
the real-anchor geometry the system actually runs, novel precision was **0.21–0.30**
— the gated figure is the optimistic one. That measurement predates the anchor-library
fixes and is due a re-run. The failure is not missed discoveries
(real-novel recall stays ~0.74) but familiar-tail sessions flagged novel. The novel
pool is the noisiest surface in the system. Gated by `eval_operational.py`.

**Real-anchor macro-F1 is 0.6702, up from 0.4944, and the gap was anchor coverage —
not the model, not the labels.** The old figure decomposed to roughly **−0.27
coverage, −0.09 geometry, 0 labelling**: four of ten analyst behaviors had **no
anchor that represented them**, so they scored zero regardless of matcher quality.
Most of the coverage share is now paid, and it was paid by two deployment fixes
rather than any change to the matcher — production had been clustering its novel
pool at `min_cluster_size` 5 while the config said 3, and one cosine threshold was
serving three unrelated comparisons, letting a cluster inherit an anchor identity
none of its own sessions could be assigned to. Behaviors with no anchor: **4 → 2**
(`iot_cli_probe`, conflated with no novel-side presence; and one label with n=1).

No threshold *redistribution* could have done this — a threshold only moves
sessions among anchors that exist. Two mechanisms that tried — a below-τ
structural-predicate rescue tier and an in-band conflation veto — were built,
measured, and declined for exactly that reason; both are validated and shipped
feature-off ([decisions.md](decisions.md)). What worked was a threshold that
*refuses a wrong identity inheritance*, which lets a new anchor be created.
The ordered plan for the remaining geometry share is in
[roadmap.md](roadmap.md#quality--raising-real-anchor-macro-f1).

**The eval set is two strata, and three metrics scope to one of them.** The original
draw is variety-first by playbook under a per-playbook cap; a targeted pass
(`scripts/select_eval_candidates.py`) adds candidates for labels that draw crowds out,
each tagged `selection_channel` (`structural` / `anchor` / `random`). `macro_f1` and
per-label accuracy weight labels equally and run on everything. `novel_precision`,
`novel_recall` and `minted_purity` are session-weighted, so they read the label mix
directly — they scope to the variety-first rows, or a deliberate over-sample of a rare
label reads as a system change. `eval_operational.py` reports which rows each family saw
under `scope`. Selection never uses embedding similarity: drawing eval candidates as
nearest neighbours of known examples builds the test set out of the system under test.

**Assignment coverage: 0.9978 corpus-wide, 0.6824 on the committed snapshot.** The
committed public snapshot holds **37** anchors — every playbook with at least
`session.novel_pool_cluster_min_cluster_size` public sessions — against 42 carrying
sessions and 46 centroid-carrying live. Against the snapshot, **0.6824** of labeled
sessions clear τ (`baseline-assignment-prod.json`); the rest fall to the novel pool for
minting. What *does* assign stays clean — **0.9505** anchor label purity, **0.9407**
homogeneity. The gate hard-fails when the snapshot's anchor count and the baseline
disagree, so a stale snapshot cannot silently degrade the geometry the number is read
against — but note that check compares snapshot to *baseline*, not snapshot to *live*,
so both can go stale together and stay green. Recapture after every minting change.

**The capture floor is a minting-parity choice, not a sampling one.** `--min-public`
defaults to the deployed novel-pool minting floor rather than a fixed number. Pinned at
5 it dropped `scp_upload` and `inband_payload_drop` — whose only anchors hold 4 public
sessions each — from the fixture entirely, scoring back to 0.0000 the two labels the
minting fixes had just moved off zero. On a fully-public corpus `n_public_sessions` is
the anchor's whole membership, so there is no sampling argument for a floor above what
production may mint.

**One threshold move, +0.28 coverage — found by plotting, not sweeping.** The
TF-IDF band confirm was rejecting sessions it should have kept. The deployed
`assignment_tfidf_tau` of 0.80 sat *inside* a dense population, with an empty valley
at 0.2–0.7; moving it into the valley took corpus-wide assignment from **0.7078 →
0.9911**, a prediction made before the run and accurate to 4%. Every sweep-first
attempt in this project underdelivered; measuring the distribution first is now a
standing rule.

**Lowering τ buys coverage and no correctness — the structural-predicate rescue
tier stays off.** The rescue band `[rescue_tau, τ)` assigns a below-τ session when
its structural predicate vector overlaps its nearest anchor's `predicate_signature`.
Replayed against the real anchor snapshot — not label-derived prototypes — dropping
to 0.88 lifts assigned rate 0.7714 → 0.9857 while **every rescued session lands on
the wrong playbook**: rescue precision is 0 at every candidate, including the 10
rescues whose ground truth the snapshot library does contain. Correct in-library
assignments never move off 20; only the denominator grows. The gate itself is barely
selective here, blocking 6–9% of what pure τ-lowering would rescue versus 34–52% on
label prototypes, because live anchor signatures are saturated — three of the seven
predicates fire on 71–87% of sessions. `assignment_rescue_tau` therefore stays at
0.94 and the tier ships inert; see [decisions.md](decisions.md). Measured by
`eval_assignment_faithful.py --anchors ... --rescue-tau-sweep` (diagnostic, not
gated). The methodological lesson generalizes: a sweep that does not read the
committed snapshot is not measuring the production geometry, and the two disagree by
roughly a factor of five here.

**Copy/paste scripts dominate the signal.** Around 5 of the top-20 corpus
behaviors are copy/paste-tight — every member runs the exact same command set
(`modal_signature_share ≥ 0.8`, per `scripts/eval_cluster_purity.py`). On this
corpus, script lineage drives most of the signal regardless of representation.
This is *why* the embedding earns no edge: there's little behavioral nuance left
once you account for shared scripts.

**Behavior-driven IP geometry beats provenance-driven.** Putting country/ASN/
HASSH into the IP clustering geometry over-fragments the same behavior across
hosting platforms and client tools (a single Zgrab probe split three ways by
ASN). Dropping them and clustering on behavior (intent mix, playbook mix,
IP-as-bag-of-session-clusters) cut the largest cluster from ~70% to ~27% of the
corpus while keeping behaviorally-distinct populations apart. See
[decisions.md](decisions.md) for the full rationale.

**Late-fusion clustering looked like a win, then failed at scale.** Fusing an
embedding-HDBSCAN with a TF-IDF/SVD lexical-HDBSCAN scored +0.085 ARI over plain
HDBSCAN on the 108-session eval set — and then regressed at production scale. On
4030 sessions the lexical view fragments ~6× harder than the embedding (72 vs 24
clusters), which broke the fusion math: the live deploy lost **−0.173 ARI** vs
plain HDBSCAN, and the best-tuned config only matched it (+0.008, noise). It was
**reverted** to plain HDBSCAN; `clustering_mode: late_fusion` survives only as
inert opt-in infrastructure (default `hdbscan`). This is the concrete case that
motivated the production-scale gate above — a real eval-scale win that didn't
generalize. See [decisions.md](decisions.md).
