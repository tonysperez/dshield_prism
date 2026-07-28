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
| `sessions.unlabeled.jsonl` | generated | yes | Output of `scripts/build_eval_set.py`. Public-only (classification-gated), defanged, variety-first sample. Committed because it's safe to publish post-defang; not analyst-readable. |
| `sessions/<session_id>.md` | generated | no | Per-session human-readable rendering from `scripts/render_eval_set.py`. |
| `labels.yaml` | hand-edited | yes | The labels — one block per `session_id`. Deliverable. |
| `labeling-prompt.md` | hand-written | yes | Self-contained LLM prompt to automate labeling. |
| `RUBRIC.md` | hand-written | yes | Labeling rubric. |
| `labels-relabel.yaml` | hand-edited | no | Optional delayed blind re-label of a subset, same schema — the intra-annotator agreement input. Not committed. |
| `baseline-operational.json` | generated | yes | Metric snapshot `eval_operational.py` (the actual CI gate) diffs against. |
| `baseline.json` | generated | yes | Metric snapshot `eval_clustering.py` (diagnostic-only, doesn't gate) diffs against. |
| `results/` | generated | no | Per-run JSON + per-experiment markdown verdicts from the `eval_*.py` / `sweep_*.py` / `exp_*.py` scripts. Rebuildable; gitignored. |
| `archive/` | frozen | yes | Retired experiments (see the note above). |

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
  --unlabeled eval/sessions.unlabeled.jsonl
```

When you're done, gate the final set on a minimum record count:

```bash
console/.venv/bin/python scripts/validate_eval_labels.py \
  --labels eval/labels.yaml \
  --unlabeled eval/sessions.unlabeled.jsonl \
  --min-records 200
```

Then run the actual quality gate — assignment macro-F1, per-label accuracy,
novelty precision/recall, minted-playbook purity:

```bash
console/.venv/bin/python scripts/eval_operational.py --baseline eval/baseline-operational.json --no-json
```

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
subset into a second file (same schema, e.g. `eval/labels-relabel.yaml`) —
don't peek at the originals. Score self-consistency:

```bash
console/.venv/bin/python scripts/eval_agreement.py \
  --labels-a eval/labels.yaml \
  --labels-b eval/labels-relabel.yaml
```

**Inter-annotator (when a second annotator exists).** Same command, two
annotators' files. The tool is agnostic to which mode.

It reports Cohen's κ, PABAK, and overall + per-label percent agreement, each with
a bootstrap CI, over the annotated **overlap** (sessions `annotated: true` in
both files). The agreement unit is a three-way category — the `playbook_label`,
`__novel__` (real, no matching playbook), or `__reject__` (not real) — and
`__novel__` / `__reject__` are never merged, so a "novel vs noise" split counts
as the disagreement it is. Read κ *alongside* PABAK and the per-label breakdown:
on this prevalence-skewed set κ alone hits the paradox (high agreement, deflated
κ). It is a diagnostic — it never fails a build; the only error exit is an empty
overlap or an unreadable file.

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

Each line of `sessions.unlabeled.jsonl`:

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
