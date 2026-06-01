# Labeling rubric — `eval/labels-v{1,2}.yaml`

The rule book for filling in `eval/labels-v1.yaml` (general stratified
sample) and `eval/labels-v2.yaml` (divergent-pair stress test) against
the per-session markdown files under `eval/sessions-v{1,2}/`. Every
later phase that compares pipeline output to ground truth — clustering
eval (1.3), discovery eval (1.4), the CI gate (1.5), embedding ablation
(3.3), threshold migrations (4.x) — joins these YAMLs against the
unlabeled JSONLs by `session_id`. Garbage labels here become garbage
measurements everywhere downstream.

v1 goal: ≥200 labeled blocks. v2 goal: ~40 labeled blocks (=~20 pairs)
per the embedding-quality plan E1.2. Time budget: ~6h for v1, ~2h for
v2 (with v2 borrowing the v1 vocabulary so the analyst isn't inventing
labels from scratch). Don't optimise for speed; both files ship once
and are consulted dozens of times.

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
   Produces `eval/sessions-v1/<session_id>.md` (one file per session)
   and `eval/labels-v1.yaml` (one empty block per session, preserves
   existing entries on re-render).
3. Walk `eval/sessions-v1/*.md` in any order — they're independent.
4. Fill in the matching block in `eval/labels-v1.yaml`.
5. After every ~25 entries, validate:
   ```bash
   console/.venv/bin/python scripts/validate_eval_labels.py \
     --labels eval/labels-v1.yaml \
     --unlabeled eval/sessions-v1.unlabeled.jsonl
   ```
   Catches schema mistakes early, before you make the same mistake 200
   times. Use `--min-records 200` once you're done to gate the final
   commit.

Only `RUBRIC.md`, `labels-v{1,2}.yaml`, `divergent-pairs/*.md`,
`README.md`, and `baseline.json` are tracked. The rendered v1/v2
session markdown and the unlabeled JSONLs are local-only — anyone
can rebuild them from the corpus + the committed triage MDs (whose
frontmatter carries the keep/skip decisions).

For the v2 (divergent-pair) workflow — mining candidates, triaging
pairs in `divergent-pairs/*.md` frontmatter, building
`sessions-v2.unlabeled.jsonl`, labeling `labels-v2.yaml` — see
[README.md](README.md#labeling-workflow--v2-divergent-pair-stress-test)
and the [`divergent_pair_id` schema section](#divergent_pair_id--optional-string-v2-only)
below.

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
4. **Your label** — copy/paste hint for `labels-v1.yaml`.

---

## YAML schema

Each entry in `eval/labels-v1.yaml` is keyed by `session_id`. The
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

### Picks-stage triage (v2 only)

Before any v2 session reaches the labeling step, the analyst (or the
[picks-triage LLM agent](picks-triage-prompt.md)) decides which pairs
from the miner's candidate pool are worth labeling. This is a separate
rule book from the per-session label rubric below; the picks step
operates on pair markdown (`eval/divergent-pairs/<pair_id>.md`), not
on individual sessions.

**The MD file is the source of truth for the decision.** Each pair's
YAML frontmatter carries `decision: pending | keep | skip` and a
`notes:` justification — the analyst (or the LLM agent) edits those
two fields in place. There is no separate picks YAML; `build_eval_set.py
--mode picks` reads MD frontmatter directly to determine which pairs
flow into v2.

Each pair gets exactly one of three outcomes:

| Outcome | `decision` | Meaning |
|---|---|---|
| **Same behavior, different text** | `keep` | The embedding *should* group them — positive test case for the v2 metric. |
| **Different behaviors, same intent** | `keep` | The embedding is *correct* to split them — negative test case. |
| **Junk / non-informative** | `skip` | One side is a single-command probe, corrupted, login-only, or the pair adds no signal v1 didn't already cover. |

`pending` is the initial state on a fresh render. **Every MD must end
with `keep` or `skip` before `build_eval_set.py --mode picks` will
run** — the build refuses to materialise v2 while any decision is
still pending.

Always populate `notes:` — `decision: keep` requires a one-sentence
justification of WHICH behavior the sessions share (or which different
behaviors they express, for category B); `decision: skip` requires a
phrase on what makes the pair non-informative. The build step
validates that `keep` carries a non-empty `notes:`.

Triage signals to use:
- **The command streams in both `## Session A` and `## Session B`** — the
  load-bearing content. Read both top-to-bottom and decide whether the
  underlying attacker action is the same.
- **Login attempts + file events** — corroborate the command stream.
- **Bucket label (jaccard, playbook_name, dominant_intent)** — NOT
  proof of anything. The miner used it as the candidacy gate, but the
  gate is too coarse. Re-derive the comparison from the actual
  commands.

Volume target: ~20 kept pairs (= ~40 labeled sessions) per the
embedding-quality plan E1.2. Bias toward `keep` on category A, reject
category C decisively, and cap category B (negative test cases) at ~5
of the total budget.

What NOT to edit in a triage MD:
- `pair_id`, `bucket_kind`, `bucket_value`, `jaccard`, `sessions` —
  contract fields the build step validates.
- Anything below the closing `---` of the frontmatter — that's the
  rendered body, regenerated every time `render_divergent_candidates.py`
  runs. Your edits there get clobbered.

### `divergent_pair_id` — optional, string (v2 only)

Present on `eval/labels-v2.yaml` blocks; absent on v1. The renderer
auto-populates it from the picks-driven build
(`scripts/build_eval_set.py --mode picks`). Do not edit the value — the
validator cross-checks it against the JSONL and fails on drift.

Label both members of a pair **independently first** — open each
`eval/sessions-v2/<sid>.md` cold, ignore the pair_id, form your own
judgment, write `playbook_label`. *Then* compare. Three outcomes:

- **Same `playbook_label`** — the miner's "behavior-not-text" claim
  holds; the v2 metric `divergent_pair_resolution_rate` will count this
  pair as one the embedding *should* group together.
- **Different `playbook_label`** — the miner falsely paired two
  different behaviors that happen to share a coarse intent label.
  That's a valid label; the v2 metric counts this pair as one the
  embedding is *correct* to split. Add a `notes:` line on at least one
  side explaining the divergence.
- **Borderline / same family, different sub-behavior** — pick the
  same playbook_label and explain the nuance in `notes:` on both
  sides. The eval grades behavioral coarseness, not analyst hair-
  splitting.

---

## Worked examples

The rendered markdown for each smoke-test session lives under
`eval/sessions-v1/<session_id>.md` after `render_eval_set.py` runs.
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
