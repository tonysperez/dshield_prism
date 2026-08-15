# Eval set — labeled cowrie sessions

The eval set is the analyst-labeled ground truth the operational CI gate
measures against ([`scripts/eval_operational.py`](../scripts/eval_operational.py)
— assignment macro-F1 + per-label accuracy, novelty precision/recall, minted-
playbook purity). Without it, quality reduces to anecdote.

`scripts/eval_clustering.py` also reads this set but is **diagnostic only** —
it scores raw HDBSCAN-vs-label partition metrics (ARI/NMI/etc.), a geometry the
shipped nearest-prototype assign path doesn't use. It prints for a coarse
sanity check and never fails a build; don't read a bad number there as a
regression. Full gate catalog + what each one measures:
[`docs/evaluation.md`](../docs/evaluation.md#the-gates).

It is a **variety-first sample** of cowrie sessions bucketed by `playbook_id`
(one bucket per named behavior, each unattributed session its own bucket) with
a per-playbook cap, so no single behavior dominates the set — not a
stratified-random draw. Hand-labeled with the behavior each session
expresses. The eval scripts join the labels against an unlabeled JSONL by
`session_id` at load time.

This file is the eval-set *mechanics*. For what the gates measure and what the
measurements found, see [`docs/evaluation.md`](../docs/evaluation.md).

## Files

| File | Status | Tracked? | What it is |
|---|---|---|---|
| `sessions.unlabeled.jsonl.gz` | generated | yes | Output of `scripts/build_eval_set.py`. Public-only (classification-gated), defanged, variety-first sample. Committed because it's safe to publish post-defang; not analyst-readable. Gzipped, and carries no per-command `embedding` — those were 79% of the bytes and no consumer reads them back (the sweeps that pool per-command vectors go to live ES), which put the plain file over GitHub's 100 MB blob ceiling. Readers accept either spelling via `scripts/eval_jsonl.py`. |
| `sessions/<session_id>.md` | generated | no | Per-session human-readable rendering from `scripts/render_eval_set.py`. |
| `labels.yaml` | hand-edited | yes | The labels — one block per `session_id`. Deliverable. |
| `labeling-prompt.md` | hand-written | yes | Self-contained LLM prompt to automate labeling. |
| `RUBRIC.md` | hand-written | yes | Labeling rubric. |
| `labels-relabel-*.yaml`, `labels-secondary.yaml` | generated skeleton, hand-filled | no | Second-pass label files, same schema as `labels.yaml` — intra-annotator (delayed self-relabel, via `scripts/build_relabel_subset.py`) or inter-annotator (concurrent second annotator) agreement input. Gitignored: a committed second pass is readable by the next annotator, which destroys the blindness the measurement depends on. |
| `baseline-operational.json` | generated | yes | Metric snapshot `eval_operational.py` (the actual CI gate) diffs against. |
| `baseline.json` | generated | yes | Metric snapshot `eval_clustering.py` (diagnostic-only, doesn't gate) diffs against. |
| `results/` | generated | no | Per-run JSON + per-experiment markdown verdicts from the `eval_*.py` / `sweep_*.py` / `exp_*.py` scripts. Rebuildable; gitignored, so don't cite a path under it from a tracked doc. |

## Labeling workflow

```bash
# 1. Variety-first sample from the live ES (deterministic per corpus + seed)
console/.venv/bin/python scripts/build_eval_set.py --n 300

# 2. Render into per-session markdown + a labels.yaml skeleton
console/.venv/bin/python scripts/render_eval_set.py
```

Then walk `eval/sessions/*.md` one file at a time (any order — they
are independent), read the rendered markdown, and fill the matching
block in `eval/labels.yaml`. Re-running `render_eval_set.py` is
idempotent — existing label blocks are preserved verbatim; new
sessions get empty skeletons appended.

After every ~25 entries, run the validator:

```bash
console/.venv/bin/python scripts/validate_eval_labels.py \
  --labels eval/labels.yaml \
  --unlabeled eval/sessions.unlabeled.jsonl.gz
```

When you're done, gate the final set on a minimum record count:

```bash
console/.venv/bin/python scripts/validate_eval_labels.py \
  --labels eval/labels.yaml \
  --unlabeled eval/sessions.unlabeled.jsonl.gz \
  --min-records 200
```

Then run the actual quality gate — assignment macro-F1, per-label accuracy,
novelty precision/recall, minted-playbook purity:

```bash
console/.venv/bin/python scripts/eval_operational.py --baseline eval/baseline-operational.json --no-json
```

For decision-path fidelity, also run:

```bash
console/.venv/bin/python scripts/eval_assignment_faithful.py --no-json
```

This fits one shared TF-IDF/SVD space per fold/trial and calls the same
`assign_batch` cascade as production. It reports deployed thresholds
(`tau=0.94`, `confident_tau=0.98`, `tfidf_tau=0.80`) plus the fixed
low/deployed/high operating curve, exact confusion/path counts, grouped
intervals, margins, and per-behavior novelty. Current anchors are folded
analyst-label prototypes, not representative production anchors, so the result
is a temporary diagnostic and no baseline is committed. An explicit baseline
protects corpus, rubric, representation, sample design, thresholds, code,
dependencies, Git revision, capture identity, seed, and exclusions.

`scripts/eval_clustering.py --baseline eval/baseline.json --no-json` also
runs against this set but is diagnostic-only (prints, never fails a build) —
see the note above. Don't treat it as the pass/fail signal.

## Annotator agreement (reliability)

The labels above are worth only as much as they are consistent. `scripts/eval_agreement.py`
publishes that reliability ceiling — how much any downstream metric (assignment
macro-F1, novel P/R) can honestly claim, since a model can't beat the labels it's
graded against.

**Intra-annotator (the headline workflow, single operator).** After finishing a
labeling batch, wait long enough to forget the specifics, then blind re-label a
subset — don't peek at the originals. `scripts/build_relabel_subset.py` picks
the subset and emits the empty skeletons:

```bash
console/.venv/bin/python scripts/build_relabel_subset.py
```

It writes **two** files, because one subset can't do both jobs:

| File | What it is | How to read it |
|---|---|---|
| `labels-relabel-core.yaml` | Uniform random draw (default 60) over every annotated session | **The quotable number.** Representative, so its agreement is *the* reliability estimate. At n=60 and true agreement ~0.85 the 95% CI is roughly ±0.09 — enough to separate "at the ceiling" from "real headroom" |
| `labels-relabel-supplement.yaml` | Every member of a category with n < 10 that core didn't already draw | Per-label detail only. **Never pool it into the core number** — it over-weights the hard tail and understates reliability |

Blocks are emitted with every label field empty and in shuffled order, so
walking a file top-to-bottom won't retrace the original labeling sequence.
The script refuses to overwrite existing output (pass `--force`) and warns
when the first pass is too recent for the re-label to be blind — run it a day
later and you measure recall, not reproducibility.

Label against [`RUBRIC.md`](RUBRIC.md) v2 only, without opening `labels.yaml`.
Then score core first and alone:

```bash
console/.venv/bin/python scripts/eval_agreement.py \
  --labels-a eval/labels.yaml \
  --labels-b eval/labels-relabel-core.yaml

# separately — per-label detail, not the headline
console/.venv/bin/python scripts/eval_agreement.py \
  --labels-a eval/labels.yaml \
  --labels-b eval/labels-relabel-supplement.yaml
```

**Inter-annotator (concurrent second label set).** Same command, two
annotators' files — the tool is agnostic to which mode, and the two
files can be produced at any time relative to each other (not just a
delayed self-relabel). To run one:

```bash
# 1. Fresh empty skeleton at a second path — never touches labels.yaml
console/.venv/bin/python scripts/render_eval_set.py \
  --labels-yaml eval/labels-secondary.yaml

# 2. Label it (by hand, or via eval/labeling-prompt.md — set its
#    "Target labels file" line to eval/labels-secondary.yaml). Do this
#    blind: the second labeler must not see eval/labels.yaml.

# 3. Score
console/.venv/bin/python scripts/eval_agreement.py \
  --labels-a eval/labels.yaml \
  --labels-b eval/labels-secondary.yaml
```

Same mechanism as the intra-annotator flow above, minus the subset draw —
a concurrent second annotator labels the whole set, so there is no
core/supplement split to make.

It reports Cohen's κ, PABAK, and overall + per-label percent agreement, each with
a bootstrap CI, over the annotated **overlap** (sessions `annotated: true` in
both files). The agreement unit is a three-way category — the `playbook_label`,
`__novel__` (real, no matching playbook), or `__reject__` (not real) — and
`__novel__` / `__reject__` are never merged, so a "novel vs noise" split counts
as the disagreement it is. Read κ *alongside* PABAK and the per-label breakdown:
on this prevalence-skewed set κ alone hits the paradox (high agreement, deflated
κ). It is a diagnostic — it never fails a build; the only error exit is an empty
overlap or an unreadable file.

**`aligned_agreement`** is reported next to the raw number. Agreement is scored
on label *strings*, so two annotators naming the same behavior differently score
as a total mismatch. The alignment block finds the best 1:1 renaming and
re-scores under it; a category present in **both** vocabularies is locked to
itself, because both annotators knew that term and chose differently — genuine
disagreement, not naming. The raw number is the headline; the gap is the naming
component, and the residual is behavioral. Since rubric v2 the vocabulary is
closed (`validate_eval_labels.py` enforces it), so on a clean pair the gap should
be zero — a non-zero gap means someone labeled outside the rubric.

## YAML schema (committed file)

The renderer pre-creates one block per sampled session with
`annotated: false` and default-empty fields. Edit the block in place
(open the rendered markdown side-by-side) and flip `annotated: true`
when you're done — the validator only enforces the schema on
annotated blocks.

```yaml
6504648f3ee2:
  annotated:          true                      # flip from false when done
  is_real:            true
  playbook_label:     "ssh_key_chattr_persistence"
  expected_findings:  []
  notes:              "Persistence playbook with recon padding."
  # Optional label-schema v2 provenance + rare-class re-weighting.
  # All four are optional and type-checked only when present; the
  # renderer backfills these defaults (null / 1.0) on re-render.
  annotator:          "ts"                       # who labeled it (null = unset)
  labeled_at:         "2026-07-03"               # ISO-8601 date (YYYY-MM-DD)
  rubric_version:     "v1"                        # rubric version applied
  boost_weight:       1.0                         # >0; rare-class oversample weight (1.0 = no boost)

d2ab2ca67303:
  annotated:          true
  is_real:            false
  playbook_label:     null
  expected_findings:  []
  notes:              "HTTP request leaked into command-input field; reject."
```

The four provenance/boost fields are **optional** — legacy blocks without
them validate clean. When present they're typed: `boost_weight` a finite
number `> 0`, `labeled_at` a real `YYYY-MM-DD` date, `annotator` /
`rubric_version` non-empty strings (or `null`).

## Unlabeled JSONL schema (rebuildable, not tracked)

Each line of `sessions.unlabeled.jsonl.gz`:

```jsonc
{
  "session_id": "<cowrie session_id>",
  "stratum": {
    "size_band": "solo|small|medium|large|unattributed",
    "intent":    "<dominant_intent or 'intent_unknown'>",
    "intel":     "malicious|clean|unknown"
  },
  "rollup_doc":          { /* the prism.rollup.cowrie.session doc, verbatim */ },
  "raw_events":          [ /* cowrie.session.* events, asc by @timestamp     */ ],
  "command_enrichments": [ /* one per unique command line in this session    */ ]
}
```

`rollup_doc`'s `embedding` field (when present) is frozen in the file at
sample time — it is **not** recomputed at eval time. After a production
re-embed, `scripts/refresh_eval_embeddings.py` is the only supported way to
bring it current. Display strata appear under `stratum` so downstream eval
scripts don't have to recompute them (they no longer drive sampling — see
above).

Every eval script (`eval_operational.py`, `eval_clustering.py`,
`eval_assignment.py`, ...) joins `labels.yaml` against the unlabeled JSONL
by `session_id` at load time — no labeled-JSONL file materialises on disk.
