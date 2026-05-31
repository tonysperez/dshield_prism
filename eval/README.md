# Eval set — labeled cowrie sessions

The eval set is what every quality claim in the brutal-review phases
3 and 4 will measure against. Without it, those workstreams reduce to
anecdote.

## Files

| File | Status | Tracked? | What it is |
|---|---|---|---|
| `sessions-v1.unlabeled.jsonl` | generated | no | Output of `scripts/build_eval_set.py`. Stratified random sample of cowrie sessions in dense JSON-lines. Not analyst-readable. |
| `sessions-v1/<session_id>.md` | generated | no | Per-session human-readable rendering produced by `scripts/render_eval_set.py`. Read these to label. |
| `labels-v1.yaml` | hand-edited | yes | The labels themselves — one block per `session_id`. This is the deliverable. |
| `labels-v1.example.yaml` | hand-written | yes | Five worked examples drawn from real sessions in the corpus. Reference, not edited. |
| `RUBRIC.md` | hand-written | yes | The labeling rubric. |
| `baseline.json` | generated | yes | Snapshot of `eval_clustering.py` + `eval_discovery.py` output that the CI gate diffs against. Lands in commit 1.5. |
| `results/` | generated | no | Per-run JSON outputs from `eval_*.py` scripts. |

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

When you're done:

```bash
console/.venv/bin/python scripts/validate_eval_labels.py \
  --labels eval/labels-v1.yaml \
  --unlabeled eval/sessions-v1.unlabeled.jsonl \
  --min-records 200
```

See [`RUBRIC.md`](RUBRIC.md) for the labeling rule book and worked
examples.

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

cadcbc1a2854:
  annotated:          false                     # untouched skeleton; validator skips
  is_real:            true
  playbook_label:     null
  expected_findings:  []
  notes:              ""
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

Downstream eval scripts (`eval_clustering.py` in 1.3,
`eval_discovery.py` in 1.4) join `labels-v1.yaml` against the unlabeled
JSONL by `session_id` at load time — the labeled-JSONL file the earlier
plan called for never needs to materialise on disk.
