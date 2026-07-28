# Labeling rubric — `eval/labels.yaml`

The rule book for filling in `eval/labels.yaml` (the stratified
analyst sample) against the per-session markdown files under
`eval/sessions/`. The clustering-quality CI gate
([`scripts/eval_clustering.py`](../scripts/eval_clustering.py)) joins
this YAML against the unlabeled JSONL by `session_id`. Garbage labels
here become garbage measurements downstream.

Goal: ≥200 labeled blocks. Don't optimise for speed; the file ships
once and is consulted dozens of times.

> The divergent-pair (v2) stress-test rubric that used to live here is
> retired with the semantic-clustering claim — see
> [`archive/semantic-clustering-claim/`](archive/semantic-clustering-claim/).

---

## Workflow

1. Build the unlabeled sample (one-time, deterministic per corpus+seed):
   ```bash
   console/.venv/bin/python scripts/build_eval_set.py --n 300
   ```
2. Render it into human-readable markdown plus the labels skeleton:
   ```bash
   console/.venv/bin/python scripts/render_eval_set.py
   ```
   Produces `eval/sessions/<session_id>.md` (one file per session)
   and `eval/labels.yaml` (one empty block per session, preserves
   existing entries on re-render).
3. Walk `eval/sessions/*.md` in any order — they're independent.
4. Fill in the matching block in `eval/labels.yaml`.
5. After every ~25 entries, validate:
   ```bash
   console/.venv/bin/python scripts/validate_eval_labels.py \
     --labels eval/labels.yaml \
     --unlabeled eval/sessions.unlabeled.jsonl
   ```
   Catches schema mistakes early, before you make the same mistake 200
   times. Use `--min-records 200` once you're done to gate the final
   commit.

Only `RUBRIC.md`, `labels.yaml`, `README.md`, and `baseline.json` are
tracked. The rendered session markdown and the unlabeled JSONL are
local-only — anyone can rebuild them from the corpus.

---

## What to read in the rendered file

Each per-session markdown has four sections. Read them in this order so
the LLM's opinions don't anchor your judgement:

1. **Header** (Stratum, Source IP, Login, HASSH, Window) — pure facts.
2. **Command stream** — the chronological list of commands plus the
   LLM's enrichment for each. **Read the commands first, ignore the
   `→` enrichment lines, form your own picture of what the attacker
   was doing.** Then go back and read the enrichments to see what the
   pipeline thought.
3. **Rollup summary** — the session-level rollup (`playbook_id`,
   `dominant_intent`, `file_events`, `artifact_set`, intel). Use as a
   cross-check, **not** as your label source. The `playbook_id` and
   `dominant_intent` are exactly what the eval is grading.
4. **Your label** — copy/paste hint for `labels.yaml`.

---

## YAML schema

Each entry in `eval/labels.yaml` is keyed by `session_id`. The
renderer pre-creates one block per sampled session — you edit the
existing block, you don't create new ones.

### `annotated` — required, boolean

`false` on every block the renderer creates. Flip to `true` once
you've filled the rest of the block. The validator only enforces the
schema on blocks with `annotated: true` — that's how you label a few
at a time without the whole file failing the check.

### `playbook_label` — required, string

A short snake_case label naming the *behavior* the session expresses,
independent of textual command form. Two sessions that do the same job
through different commands get the same label.

- **Use the same label vocabulary across the whole file.** Pick a label
  the *first* time you see a behavior, then re-use it. Don't proliferate.
- Aim for ~10–25 distinct labels across 200 records. Fewer = you're
  conflating behaviors; many more = you're labeling text, not behavior.
- Suggested skeleton vocabulary (extend / contract as you go):
  - `host_recon` — `w`, `whoami`, `uname -a`, `cat /proc/cpuinfo`, etc.
  - `credential_spray` — login attempts only, zero command activity
  - `ssh_key_chattr_persistence` — write key + chattr immutable
  - `ssh_key_cron_persistence` — write key + crontab re-install
  - `cryptominer_staging` — `wget … xmrig`, `chmod +x`, `./run`
  - `botnet_loader` — IRC / TCP beacon + secondary fetch
  - `shell_wrapper_only` — single `echo "…" | sh` with no follow-up
  - `single_command_probe` — exactly one command, then disconnect
- Mint a new label only when no existing one fits. Pick the closest
  existing label otherwise and explain in `notes` if it was borderline.

Set to `null` only when `is_real: false`.

### `is_real` — required, boolean

`true` when the session reflects a real attacker action; `false` when
the record is corrupted, mis-rolled-up, or otherwise not analysable.

`is_real: false` cases:
- Empty / single-empty-string command lines.
- HTTP headers leaked into the command stream (the
  `Accept-Encoding: gzip` rendering — analyst-visible sign: the "Login"
  line shows `GET / HTTP/1.1:Accept: */*` style values).
- Session rollups that span clearly-unrelated traffic (two disjoint
  attacker activities merged into one session_id — rare).

When `is_real: false`:
- `playbook_label = null`
- `expected_findings = []`
- `notes` MUST explain why.

### `expected_findings` — required, list of strings

Which finding kinds *should* fire on this session, if we lined up
adjacent pipeline runs and let the discovery/drift miners look at it.
The vocabulary is closed; the validator rejects unknown values.

Scored as a **diagnostic only** — `eval_agreement.py` reports set-level
precision/recall of one labeling pass's `expected_findings` against
another's over the annotated overlap. It never gates CI; it's a signal for
how crisply this axis is being labeled, not a pipeline-correctness check
(it doesn't run the discovery/drift miners against ES).

| Kind | Source | When it should fire |
|---|---|---|
| `new_playbook` | `discovery.py` | First-ever observation of a stable behavior |
| `intel_verdict_flip` | `discovery.py` | Source IP's CTI verdict flipped recently |
| `ip_behavior_shift` | `discovery.py` | IP's playbook mix changed materially from its prior baseline |
| `outlier_burst` | `discovery.py` | Cluster of sessions with shared artifact within a short window |
| `campaign_convergence` | `discovery.py` | Two campaigns started sharing IPs |
| `playbook_command_drift` | `drift.py` | Playbook's command set drifted |
| `playbook_sequence_drift` | `drift.py` | Playbook's command-bigram sequence drifted |
| `playbook_artifact_drift` | `drift.py` | Playbook's artifact set drifted |
| `playbook_geo_drift` | `drift.py` | Playbook's source-country mix drifted |
| `playbook_size_drift` | `drift.py` | Playbook's session-count band changed |
| `playbook_resurgence` | `drift.py` | Silent playbook came back |
| `campaign_growth` | `drift.py` | Campaign added new IPs / playbooks |

Rules:
- Most labeled sessions should have an **empty list** here. Findings
  are by definition the *anomalous* slice; if you're labeling 200
  random sessions, the vast majority shouldn't trigger anything.
- Only add a kind when the session, taken on its own and contextualised
  by the rollup, makes the case for that kind crisp. If you have to
  argue with yourself, leave it out.
- `intel_verdict_flip` and `ip_behavior_shift` need cross-session
  context — usually you'll be inferring "if the pipeline knew the
  history, would it fire this?" from the rollup's snapshots.

### `notes` — required, string

Free-form. Empty string is fine on obvious cases. **Always** populate
when:
- `is_real: false`.
- You're inventing a new `playbook_label`.
- The rendered command-stream `→ <intent>` lines disagree with your
  reading.
- `expected_findings` has more than one entry.

---

## Worked examples

The rendered markdown for each smoke-test session lives under
`eval/sessions/<session_id>.md` after `render_eval_set.py` runs.
Walk through these with the rubric:

## Anti-patterns

- **Labeling by `dominant_intent`.** That's the LLM's output, which is
  what the eval is grading. If you copy it as your label, you grade the
  LLM against itself.
- **Inventing a new label for every borderline case.** Force consistency.
  When in doubt, pick the closest existing label and explain in `notes`.
- **Stuffing `expected_findings` with every plausible kind.** Each entry
  is a precision-recall lever for the eval — `["new_playbook",
  "playbook_command_drift", "playbook_artifact_drift"]` on a session
  where you only weakly believe in one of them makes the eval punish
  whichever miner *correctly* didn't fire.
- **Skipping `notes` because the label feels self-evident.** Six months
  from now you won't remember why you split borderline cases the way
  you did. The rubric is the durable record.
- **Labeling against the rollup's `playbook_id` / `dominant_intent`.**
  Those are also the pipeline's output. Read the commands first, form
  your own opinion, *then* check the rollup.
