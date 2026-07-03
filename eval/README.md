# Eval set — labeled cowrie sessions

The eval set is the analyst-labeled ground truth the clustering-quality
CI gate measures against ([`scripts/eval_clustering.py`](../scripts/eval_clustering.py)).
Without it, clustering quality reduces to anecdote.

It is a **stratified random sample** of cowrie sessions, hand-labeled with
the behavior each session expresses. The eval scripts join the labels
against an unlabeled JSONL by `session_id` at load time.

This file is the eval-set *mechanics*. For what the gates measure and what the
measurements found, see [`docs/evaluation.md`](../docs/evaluation.md).

> **Archived:** the divergent-pair / "behavior-not-text" stress-test (v2)
> machinery that used to live here is retired — a faithful evaluation did
> not support the claim that the embedding clusters by semantics rather
> than text. It's preserved under
> [`archive/semantic-clustering-claim/`](archive/semantic-clustering-claim/)
> (scripts, data, prompts, and the write-up of the negative result).

## Files

| File | Status | Tracked? | What it is |
|---|---|---|---|
| `sessions-v1.unlabeled.jsonl` | generated | no | Output of `scripts/build_eval_set.py`. Stratified random sample. Not analyst-readable. |
| `sessions-v1/<session_id>.md` | generated | no | Per-session human-readable rendering from `scripts/render_eval_set.py`. |
| `labels-v1.yaml` | hand-edited | yes | The labels — one block per `session_id`. Deliverable. |
| `labeling-prompt-v1.md` | hand-written | yes | Self-contained LLM prompt to automate labeling. |
| `RUBRIC.md` | hand-written | yes | Labeling rubric. |
| `labels-v1-relabel.yaml` | hand-edited | no | Optional delayed blind re-label of a subset, same schema — the intra-annotator agreement input. Not committed. |
| `baseline.json` | generated | yes | Metric snapshot the CI gate diffs against. |
| `results/` | generated | no | Per-run JSON + per-experiment markdown verdicts from the `eval_*.py` / `sweep_*.py` / `exp_*.py` scripts. Rebuildable; gitignored. |
| `archive/` | frozen | yes | Retired experiments (see the note above). |

## Labeling workflow

```bash
# 1. Stratified sample from the live ES (deterministic per corpus + seed)
console/.venv/bin/python scripts/build_eval_set.py --n 300

# 2. Render into per-session markdown + a labels-v1.yaml skeleton
console/.venv/bin/python scripts/render_eval_set.py
```

Then walk `eval/sessions-v1/*.md` one file at a time (any order — they
are independent), read the rendered markdown, and fill the matching
block in `eval/labels-v1.yaml`. Re-running `render_eval_set.py` is
idempotent — existing label blocks are preserved verbatim; new
sessions get empty skeletons appended.

After every ~25 entries, run the validator:

```bash
console/.venv/bin/python scripts/validate_eval_labels.py \
  --labels eval/labels-v1.yaml \
  --unlabeled eval/sessions-v1.unlabeled.jsonl
```

When you're done, gate the final set with `--min-records 200`.

Then score the clustering against the labels (the CI gate):

```bash
console/.venv/bin/python scripts/eval_clustering.py --baseline eval/baseline.json --no-json
```

## Annotator agreement (reliability)

The labels above are worth only as much as they are consistent. `scripts/eval_agreement.py`
publishes that reliability ceiling — how much any downstream metric (assignment
macro-F1, novel P/R) can honestly claim, since a model can't beat the labels it's
graded against.

**Intra-annotator (the headline workflow, single operator).** After finishing a
labeling batch, wait long enough to forget the specifics, then blind re-label a
subset into a second file (same schema, e.g. `eval/labels-v1-relabel.yaml`) —
don't peek at the originals. Score self-consistency:

```bash
console/.venv/bin/python scripts/eval_agreement.py \
  --labels-a eval/labels-v1.yaml \
  --labels-b eval/labels-v1-relabel.yaml
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

d2ab2ca67303:
  annotated:          true
  is_real:            false
  playbook_label:     null
  expected_findings:  []
  notes:              "HTTP request leaked into command-input field; reject."
```

## Unlabeled JSONL schema (rebuildable, not tracked)

Each line of `sessions-v1.unlabeled.jsonl`:

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

No embeddings — those get recomputed at eval time from whatever
embedding model is configured then. Stratification axes appear under
`stratum` so downstream eval scripts don't have to recompute them.

`eval_clustering.py` joins `labels-v1.yaml` against the unlabeled JSONL
by `session_id` at load time — no labeled-JSONL file materialises on disk.
