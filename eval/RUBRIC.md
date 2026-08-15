# Labeling rubric — `eval/labels.yaml`

The rule book for filling in `eval/labels.yaml` (the variety-first
analyst sample) against the per-session markdown files under
`eval/sessions/`. The operational CI gate
([`scripts/eval_operational.py`](../scripts/eval_operational.py)) joins
this YAML against the unlabeled JSONL by `session_id`. Garbage labels
here become garbage measurements downstream.

**Current version: `v2`.** Set `rubric_version: "v2"` on blocks labeled
under it. v2 closed the label vocabulary, added precedence rules for the
overlapping pairs, and generalized the protocol-leakage `is_real` rule —
see [`docs/decisions.md`](../docs/decisions.md).

Goal: ≥200 labeled blocks. Don't optimise for speed; the file ships
once and is consulted dozens of times.

> The divergent-pair (v2) stress-test rubric that used to live here is
> retired along with the semantic-clustering claim it existed to test. The
> conclusion that retired it — the session embedding earns no measurable edge
> over TF-IDF on this corpus — is recorded in
> [`docs/evaluation.md`](../docs/evaluation.md#what-the-measurements-found) and
> [`docs/decisions.md`](../docs/decisions.md). Don't re-derive the v2 rubric
> without a corpus that reopens the claim.

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
     --unlabeled eval/sessions.unlabeled.jsonl.gz
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

A snake_case label naming the *behavior* the session expresses —
independent of textual command form, command count, and delivery
mechanism. Two sessions that do the same job through different commands
get the same label.

**The vocabulary is closed.** Pick from the canonical table below.
Minting a new label is a rubric change, not a labeling decision — see
*Extending the vocabulary*.

> Why closed: the previous rule ("suggested skeleton — extend/contract as
> you go") let each annotator grow their own vocabulary. Two passes over
> the same 160 sessions, both compliant with `rubric_version: v1`,
> produced 11 and 12 labels with only 5 in common. Because
> `eval_agreement.py` compares label *strings*, a pure rename scored as
> total disagreement — measured agreement 0.4813, but 0.5813 once the
> vocabularies were aligned 1:1. An unpinned vocabulary makes the
> reliability instrument unreadable.

#### Canonical labels

| Label | Fires when | Distinguishing test |
|---|---|---|
| `host_recon` | The session gathers host/system information — `uname`, `/proc/cpuinfo`, `hostname`, `whoami`, `w`, `id`, `netstat`, `free`, `ls /`, `lscpu` | Does the attacker *learn something about this host*? Then `host_recon`, whatever the command count or delivery form. |
| `single_command_probe` | A one-shot capability, liveness, or write test that gathers nothing — `PING`, `echo SHELL_TEST`, `busybox abc`, `echo -n test>/tmp/.config`, `nc <ip> <port>` | The attacker learns only *"the shell answered"*. If they learn anything about the host, it's `host_recon`. |
| `iot_cli_probe` | The **whole session** is enumerating an embedded/appliance CLI — `sh`, `shell`, `enable`, `system`, `linuxshell`, `help`, `busybox` as menu words rather than shell commands | Are these *appliance menu verbs*, not POSIX commands, **and** does the session end there? If the menu walk reaches a real shell and then does something, label what it does — see precedence rule 6. |
| `credential_spray` | Login attempts only, zero command activity | Session has no command stream at all. |
| `payload_fetch_exec` | Fetches a remote payload and runs it — `wget`/`curl`/`tftp`/`ftpget` + `chmod +x` + execute | A remote fetch is present and **none** of `botnet_loader`'s three fleet-intent forms are. This is the default for fetch-and-run; `botnet_loader` is the exception that must earn itself. |
| `botnet_loader` | The session shows **fleet intent** — see the test | **Any one of:** (a) multi-architecture targeting, whether by runtime detection (`uname -m`, `case "$A" in x86_64)`) or by brute-force fetching several arch variants in turn; (b) the payload is launched with a **C2 address/port argument** (`./bot 1.2.3.4 1338`); (c) **self-spread** — starts a listener or scanner (`busybox telnetd -l /bin/sh -p 31337 &`). A single fixed binary fetched and run, with none of these, is `payload_fetch_exec`. |
| `cryptominer_staging` | Fetch + stage of a miner specifically — `xmrig`, pool config, `--donate-level` | Miner-specific artifact names visible. |
| `inband_payload_drop` | Payload *content* is written inline — `echo '<base64>' >> file`, `printf`, heredoc — reconstructing a binary with no remote fetch | The bytes arrive over the SSH channel itself. |
| `dropped_binary_exec` | Executes a binary already present on disk — `chmod +x /tmp/X && ./X` — with no fetch and no inline write in this session | The binary's arrival is *not* in this session (usually a prior `scp_upload`). |
| `scp_upload` | An `scp -t` / SFTP sink receiving a file, no execution observed | Upload vector only. |
| `ssh_key_chattr_persistence` | Writes `authorized_keys` and locks it — `chattr -ia` / `lockr -ia` on `.ssh` | Key write + immutability manipulation. |
| `ssh_key_cron_persistence` | Writes `authorized_keys` and re-installs it via crontab | Key write + cron re-install. |
| `account_backdoor_persistence` | Creates or modifies an *account* for re-entry — sudoers `NOPASSWD`, `chsh`, `passwd` on a service account | Persistence via the account database, not via `authorized_keys`. |

`credential_spray`, `ssh_key_cron_persistence`, and `cryptominer_staging`
are defined but unobserved in the current sample — they are listed so a
future annotator uses the canonical name instead of minting a synonym.

#### Precedence rules

Apply in order. These exist because the pairs below genuinely overlap.

1. **Content beats form.** `single_command_probe` is *not* "exactly one
   command" — over half the sample is one command line. It is a probe
   that gathers nothing. A session whose single command is
   `uname -a ; w` is `host_recon`.
2. **Delivery mechanism is never the label.** `echo "cat /proc/cpuinfo;
   uname -a" | sh` is `host_recon`. The `echo | sh` wrapper is form.
3. **Don't infer purpose you can't see — but do read the evidence that
   is there.** `wget y.sh; ./y.sh` alone is `payload_fetch_exec`;
   calling it `botnet_loader` asserts a C2 role the session doesn't
   evidence. The `botnet_loader` test is *fleet intent* and all three
   of its forms are visible in the command stream: multi-architecture
   targeting, a C2 address/port passed at launch, or self-spread. Don't
   demand an explicit beacon packet — the honeypot never sees one.
4. **Payload arrival decides the drop labels.** Remote fetch →
   `payload_fetch_exec`. Inline bytes → `inband_payload_drop`. Already
   on disk → `dropped_binary_exec`.
5. **Persistence is named by mechanism**, not by the recon that pads it.
   A session that runs `uname -a` then writes an SSH key is
   `ssh_key_chattr_persistence`.
6. **`iot_cli_probe` requires the appliance CLI to be the whole
   session.** Many appliance sessions walk a menu (`enable`, `system`,
   `linuxshell`, `su`) to *reach* a shell and then fetch a payload.
   The menu walk is a means, not the behavior — label the payload
   action. `iot_cli_probe` is for sessions that probe the CLI and stop.

#### Do not mint these

Observed synonyms and form-labels from prior passes. Use the canonical
label instead.

| Don't use | Use instead | Why |
|---|---|---|
| `shell_wrapper_only` | Whatever the wrapped commands do | Names the delivery form, not the behavior — violates the premise of this field. |
| `uploaded_payload_staging` | `scp_upload` | Synonym. |
| `uploaded_payload_execution` | `dropped_binary_exec` | Synonym. |
| `inline_payload_staging`, `file_staging` | `inband_payload_drop` | Synonym. |
| `shell_escape_probe` | `iot_cli_probe` | Synonym for the appliance-CLI case. |

#### Extending the vocabulary

A behavior that genuinely fits no canonical label is a rubric change:

1. Label it with the closest canonical label and explain the misfit in
   `notes`.
2. Raise the gap. If it holds up, add a row to the canonical table, bump
   `rubric_version`, and record which sessions motivated it.
3. Re-label the affected sessions under the new version.

Never introduce a label by using it. That is the failure this section
exists to prevent.

Set to `null` only when `is_real: false`.

### `is_real` — required, boolean

`true` when the session reflects a real attacker action; `false` when
the record is corrupted, mis-rolled-up, or otherwise not analysable.

`is_real: false` cases:
- Empty / single-empty-string command lines.
- **Any non-shell protocol leaked into the command stream.** The
  honeypot records whatever arrives on the port; when a client speaks a
  different protocol, its framing is recorded as if it were commands.
  The test is *"could this string ever be a shell command?"* — if not,
  the record is unanalysable as shell behavior regardless of whether the
  traffic was hostile. Observed forms:
  - HTTP — the "Login" line shows `GET / HTTP/1.1:Accept: */*` style
    values, or `Accept-Encoding: gzip` appears as a command.
  - Redis RESP — a bare `PING` as the entire command stream.
  - FTP — a bare `USER <name>` as the entire command stream.

  Judgement call: a *shell* command that happens to be one word
  (`hostname`, `busybox`) is real. A protocol verb that is not a shell
  command (`PING`, `USER test`) is leakage. When the same string is both
  (`help`), use the surrounding stream to decide, and say so in `notes`.
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
- **Inventing a new label.** The vocabulary is closed. When in doubt,
  pick the closest canonical label and explain in `notes`; if it truly
  doesn't fit, that's a rubric change, not a label.
- **Labeling the delivery form.** `echo "…" | sh`, "exactly one
  command", "used scp" — these describe *how* the commands arrived, not
  what the attacker did. A form label looks consistent and measures
  nothing.
- **Inferring purpose the session doesn't show.** `wget x.sh; ./x.sh`
  evidences a fetch-and-execute, not a botnet. Label the observed
  behavior; put the suspicion in `notes`.
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
