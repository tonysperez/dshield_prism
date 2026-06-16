# Evaluation

How clustering and labeling quality is measured, and what the measurements
found. Without a labeled set, clustering quality reduces to anecdote — so every
representation/algorithm change is gated against analyst ground truth before it
ships.

The CI gate commands are in [reference.md](reference.md#ci-gates). The labeling
rule book is [`eval/RUBRIC.md`](../eval/RUBRIC.md); the eval-set mechanics are in
[`eval/README.md`](../eval/README.md).

## The labeled set

A **stratified random sample** of cowrie sessions, hand-labeled with the
*behavior* each session expresses (independent of textual command form — two
sessions doing the same job through different commands get the same label).
Stratified across size band × intent × intel verdict so the sample isn't all
commodity brute-force.

- `eval/labels-v1.yaml` — the labels, one block per `session_id` (tracked; the
  deliverable).
- `eval/RUBRIC.md`, `eval/labeling-prompt-v1.md` — the labeling rule book and a
  self-contained prompt to automate it (tracked).
- `eval/baseline*.json` — metric snapshots the gates diff against (tracked).
- The rendered per-session markdown and the unlabeled JSONL are **generated**
  (rebuildable from the corpus via `scripts/build_eval_set.py` +
  `render_eval_set.py`); they are not committed.

Labels join against an unlabeled JSONL by `session_id` at load time — no labeled
JSONL ever materializes on disk.

## The gates

Five gates run in CI; run them all locally before any commit.

| Gate | Script | Measures |
|---|---|---|
| Clustering quality | `eval_clustering.py` | HDBSCAN session clustering vs analyst labels (ARI, completeness, homogeneity) |
| Assignment quality | `eval_assignment.py` | nearest-prototype assignment accuracy + held-out novelty (the Option-A labeler) |
| Real-anchor assignment | `eval_assignment_prod.py` | assignment against the committed public anchor snapshot |
| Production-scale | `eval_production_scale.py` | the eval-labeled subset clustered *inside* the full production HDBSCAN |
| Command-scale | `eval_command_scale.py` | command-layer clustering at production scale |

Baselines are re-captured only for an *intentional* production change — never to
silence a regression. That's the whole point of the gates.

### Eval-scale vs production-scale

Two clustering gates run because the difference matters. The **eval-isolated**
gate clusters only the ~108 labeled sessions — fast, gate-on-every-push. The
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
identity-stable, and it surfaces novelty directly. The full evaluation and the
negative result are archived under
[`eval/archive/semantic-clustering-claim/`](../eval/archive/semantic-clustering-claim/).

**Assignment recovers analyst labels well.** Nearest-prototype assignment
recovers the analyst playbook on a held-out split at ≈0.84 accuracy / ≈0.83
macro-F1, and held-out behaviors read as novel at ≈0.74 AUC. Gated by
`eval_assignment.py`.

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
