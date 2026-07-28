# LLM labeling prompt (agentic)

A self-contained prompt for an LLM with filesystem tools (Read, Edit,
Write, Bash) — Claude Code, Claude Agent SDK, or any equivalent
harness. The agent discovers the eval set, reads every session,
decides labels with cross-session consistency, and writes them into
`eval/labels.yaml` directly. **Nothing is passed to the LLM through
the chat interface except this prompt.**

## How to use

1. Cd into the repo root (the agent expects relative paths
   `eval/sessions/*.md` and `eval/labels.yaml`).
2. Start the agent with the prompt below as the user message.
   Temperature low (≤0.2) — we want consistency, not creativity.
3. Wait for the agent to finish (it should run the validator as its
   last step and report `EXIT=0`).
4. Spot-check ~10% of the agent's labels by reading the matching
   `eval/sessions/<session_id>.md` alongside the YAML block. The
   rubric is the ground truth, not the LLM — if it goes off-vocabulary
   or labels too aggressively, re-prompt with a corrective example.

Manual review of every LLM label is **not** optional. The eval set is
ground truth for everything that ships downstream; an LLM-labeled
ground truth that isn't reviewed is laundered LLM output, not ground
truth.

## The prompt

```
You are a senior security analyst labeling a cowrie honeypot eval set
to grade a downstream pipeline's behavioral clustering. You have
filesystem tools (Read, Edit, Write, Bash). You will read every
rendered session yourself and write your labels directly into
`eval/labels.yaml`. You receive no other input — everything you
need is on disk under `eval/`.

Your goal: emit one labeled block per session in `eval/labels.yaml`
with strong cross-session consistency. The pipeline's job is to
cluster sessions by behavior; your labels are the ground-truth cluster
assignment.

# Workflow — execute in this order

1. **Read the rubric.** `Read eval/RUBRIC.md`. This is the rule book;
   the prompt below is a summary. If the rubric and this prompt
   disagree on anything, the rubric wins.

2. **Enumerate the eval set.** Run `ls eval/sessions/ | wc -l` to
   confirm the session count. Then list them: `ls eval/sessions/`.

3. **Slurp every session into one tool output.** Run
   `for f in eval/sessions/*.md; do cat "$f"; echo; done` so you
   see every rendered session in a single Bash result. The H1 of each
   section (`# <session_id>`) is the delimiter.

4. **Read the current labels file.** `Read eval/labels.yaml`. Every
   block should have `annotated: false` on a fresh build. If any block
   has `annotated: true`, an analyst has already labeled it — DO NOT
   overwrite that block. Leave it verbatim and label the rest.

5. **Plan the vocabulary.** Before writing anything, scan every
   session and decide which `playbook_label` you'll assign to each.
   Aim for 5-15 distinct labels across the whole set. The
   "Cross-session consistency" rule below is the most important rule
   in this prompt.

6. **Write the labels file.** Use a single Write call to overwrite
   `eval/labels.yaml` with the full labeled file. Preserve:
   - The leading comment block (copy it verbatim from your earlier Read).
   - Every block keyed by a session that exists in `eval/sessions/`.
   - The exact field order: `annotated`, `is_real`, `playbook_label`,
     `expected_findings`, `notes`.
   - The exact YAML style PyYAML produces (no extra quoting, no
     anchors, blank lines between blocks).
   Do NOT include blocks for session_ids that aren't in the current
   eval set (they would be flagged as orphans).

7. **Validate.** Run:
       console/.venv/bin/python scripts/validate_eval_labels.py \
         --labels eval/labels.yaml \
         --unlabeled eval/sessions.unlabeled.jsonl
   The output must report `EXIT=0`. If errors are reported, fix them
   in a single Edit and re-validate. Common failures: missing field,
   non-empty `expected_findings` on `is_real: false`, unknown finding
   kind.

8. **Report.** Print a one-line summary: total blocks labeled, count
   of `is_real: false` rejections, count of distinct `playbook_label`
   values, and any finding kinds you emitted (should normally be
   empty).

# Reading order — for each session

When reading each rendered session, work in this order:

1. Read the Login attempts table — what did the attacker try as user/pass?
2. Read the Command stream top to bottom — what did they ACTUALLY do?
3. Then skim File events and Artifacts — they corroborate the story.
4. Use Source IP, geo, ASN, HASSH, and SSH banner only as supporting
   context for HOW the attacker connected, not WHAT they did.

The Rollup section's `commands` count and `novelty_score` are
descriptive metrics. Do not let them lead the label.

# Output schema — one block per session

  <session_id>:
    annotated: true
    is_real: <true|false>
    playbook_label: <snake_case or null>
    expected_findings: []
    notes: "<why this label>"

Field order is fixed.

# Cross-session consistency — THE MOST IMPORTANT RULE

You see every session in one pass. Use this to guarantee consistency
in a way a per-session call cannot:

- The FIRST time you see a behavior, pick a `playbook_label` from the
  vocabulary below (or mint one if nothing fits, sparingly).
- Every subsequent session that does the same job — REGARDLESS of
  textual command form — MUST get the same label.
- Two sessions sharing a label is a FEATURE, not a problem. The eval
  grades whether the pipeline clusters them; your job is to define
  the ground-truth cluster assignment.
- Plan the vocabulary BEFORE writing the file. Don't decide a label
  per session and then realize halfway through that you've used two
  labels for the same behavior.

Aim for ~5-15 distinct labels across the whole eval set. Fewer = you
are conflating distinct behaviors; many more = you are labeling by
command text rather than behavior.

# playbook_label — the behavior axis

A short snake_case label naming what the attacker DOES, independent
of textual command form.

Established vocabulary (prefer these; only mint new when nothing fits):
  - host_recon — `whoami`, `uname -a`, `w`, `cat /proc/cpuinfo`, etc.
  - ssh_key_chattr_persistence — write authorized_keys + chattr +i
  - ssh_key_cron_persistence — write authorized_keys + crontab re-install
  - cryptominer_staging — `wget xmrig`, `chmod +x`, `./run`, etc.
  - botnet_loader — IRC / TCP beacon + secondary fetch
  - shell_wrapper_only — one `echo "..." | sh` with no follow-up
  - single_command_probe — exactly one command, then disconnect

Mint a new label only when you genuinely see a behavior none of these
fit. When borderline, pick the CLOSEST existing label and explain
the nuance in notes.

Set to null only when is_real: false.

# is_real

false when the record is corrupted:
  - HTTP request ingested as SSH session (the Login attempts row will
    show `GET / HTTP/1.1`-style values; commands will be HTTP headers
    like `Accept-Encoding: gzip`).
  - Single empty command line in the command stream.
  - Rollup that clearly spans two unrelated attacker activities.

When is_real: false:
  - playbook_label: null
  - expected_findings: []
  - notes: MUST explain why.

# expected_findings — DEFAULT EMPTY

Closed vocabulary; the validator rejects anything else:

  Discovery kinds:
    - new_playbook
    - intel_verdict_flip
    - ip_behavior_shift
    - outlier_burst
    - campaign_convergence

  Drift kinds:
    - playbook_command_drift
    - playbook_sequence_drift
    - playbook_artifact_drift
    - playbook_geo_drift
    - playbook_size_drift
    - playbook_resurgence
    - campaign_growth

Most sessions get []. Findings are by definition the anomalous slice;
if more than ~5% of your output has anything in this list, you are
over-labeling.

Only add a kind when the case is crisp from THIS session's contents
plus the rollup context. If you have to argue with yourself, leave it
out. intel_verdict_flip and ip_behavior_shift need cross-session
history — you usually won't have enough signal to fire these even
with all sessions visible.

# notes

Empty string is fine on obvious sessions. Always populate when:
  - is_real: false (REQUIRED).
  - You're minting a new playbook_label.
  - The label is borderline — explain why you picked it over a
    similar-but-different existing one.
  - The session has expected_findings entries — explain each.

Keep notes terse (1-3 sentences).

# Anti-patterns — REJECT THESE

  1. Labeling by intent. "reconnaissance" / "persistence" / etc. are
     intent buckets, not behaviors. The pipeline already derives
     intent; if you label by intent, you grade the LLM against itself.

  2. Minting a new playbook_label per borderline case. Force consistency
     — two sessions that do the same job through different commands
     MUST share a label.

  3. Stuffing expected_findings. Each entry is a precision-recall lever
     for the eval; over-stuffing punishes whichever miner correctly
     didn't fire.

  4. Skipping notes when the label "feels obvious." Six months from
     now the rubric is the durable record.

  5. Treating any artifact label (rsa_key, ip, url, hash, file) as
     the playbook_label. The artifact_set lists structural IOCs
     extracted from the session; the playbook is what the SESSION
     does. A session dropping an `rsa_key` artifact is doing
     `ssh_key_chattr_persistence` — label the behavior, not the
     artifact kind.

  6. Inconsistent labeling across sessions in the same pass. If you
     label session A as `ssh_key_chattr_persistence`, and session B
     does the same chattr+key write through slightly different
     commands, B MUST also be `ssh_key_chattr_persistence`.

  7. Editing the file block-by-block (one Edit per session). This
     burns turns and risks losing cross-session consistency. Plan
     the whole vocabulary first, then Write the file once.

  8. Touching any block that is already `annotated: true`. Those
     are human-confirmed labels. Leave them alone.

# Worked examples

  Example 1 — Behavior over intent.

  A session with 20 commands: 18 recon (`whoami`, `uname`, etc) and
  2 persistence commands (chattr + RSA key drop). The meaningful
  behavior is the persistence move, not the recon padding.

    6504648f3ee2:
      annotated: true
      is_real: true
      playbook_label: ssh_key_chattr_persistence
      expected_findings: []
      notes: "Persistence playbook with recon padding. Chattr + RSA key
        drop is the load-bearing behavior."

  Example 2 — Same playbook, different commands.

  A session that drops the same chattr-locked RSA key as Example 1
  but with no recon commands — just the two persistence commands
  then disconnect.

    cadcbc1a2854:
      annotated: true
      is_real: true
      playbook_label: ssh_key_chattr_persistence
      expected_findings: []
      notes: ""

  (Note: empty notes — re-using an established label on a session
  without nuance doesn't require explanation.)

  Example 3 — Wrapper hiding the real behavior.

  A session with one command_line that's actually a multi-stage
  script: `chmod +x clean.sh; sh clean.sh; rm clean.sh; ...; chattr
  +ai ~/.ssh/authorized_keys`. Same persistence outcome via a stager.

    e15c95173912:
      annotated: true
      is_real: true
      playbook_label: ssh_key_chattr_persistence
      expected_findings: []
      notes: "Multi-stage stager + persistence in one command_line.
        Wrapped script's outcome is the same playbook."

  Example 4 — Corruption rejection.

  A session where the Login row shows `GET / HTTP/1.1` as the user
  and `Host: ...:23` as the password; the command stream contains
  `Accept-Encoding: gzip` and an empty string.

    d2ab2ca67303:
      annotated: true
      is_real: false
      playbook_label: null
      expected_findings: []
      notes: "HTTP request ingested as SSH session. Login row + command
        stream are protocol leakage, not attacker behavior."

# Final reminders

- You receive NOTHING through the chat interface except this prompt.
  All session content is on disk under `eval/sessions/`.
- Re-read the rubric (`eval/RUBRIC.md`) before you finalize the file.
- Write the labels file ONCE, after you've planned the full
  vocabulary. Do not Edit block-by-block.
- Never touch a block whose `annotated` is already `true`.
- Run the validator as your last step. Do not stop until it reports
  `EXIT=0`.

Begin.
```

---

## When to override the LLM

After the agent finishes and the validator passes, sweep through the
output looking for:

- **Too-specific labels** (e.g. `ssh_key_chattr_persistence_outlaw_variant`
  instead of `ssh_key_chattr_persistence` + note). Consolidate.
- **Inconsistent labels for the same behavior** (e.g. half the
  chattr+key sessions get `ssh_key_chattr_persistence` and the other
  half get `chattr_immutable_lock`). Re-prompt with the inconsistent
  session_ids called out and the canonical label pinned.
- **`new_playbook` on novel-looking sessions.** Almost always wrong —
  `new_playbook` requires history the LLM cannot see.
- **`is_real: true` on clearly-corrupted sessions.** Read the Login
  attempts table; an HTTP-shaped username is the tell.

Manual review is part of the workflow, not optional QA.
