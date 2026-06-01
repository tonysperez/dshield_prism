# LLM labeling prompt — v2 divergent-pair set (agentic)

A self-contained prompt for an LLM with filesystem tools (Read, Edit,
Write, Bash). Parallels [labeling-prompt-v1.md](labeling-prompt-v1.md) which
labels the v1 stratified-random sample; this one labels the **v2
divergent-pair stress test**.

The two sets share a schema and a label vocabulary; downstream eval
scripts merge them by `session_id`. v2 is small (~40 sessions = ~20
pairs) and exists to give the embedding's "behavior-not-text" claim
something to be measured against — each pair was picked because both
members share a coarse behavior signal (same playbook_id or
dominant_intent) AND have textually disjoint commands (`command_set`
Jaccard ≤ 0.2). The agent decides each session's `playbook_label`
**independently** and then the merged v1+v2 set measures whether the
pipeline groups same-labeled pairs together.

## How to use

1. The v2 set must already be built: `scripts/build_eval_set.py --mode
   picks` consumed the triage MDs and `scripts/render_eval_set.py`
   rendered `eval/sessions-v2/*.md` + the empty
   `eval/labels-v2.yaml` skeleton. The skeleton's `divergent_pair_id`
   field is auto-populated and the validator cross-checks it against
   the unlabeled JSONL — don't let the agent edit it.
2. Cd into the repo root (the agent expects relative paths
   `eval/sessions-v2/*.md` and `eval/labels-v2.yaml`).
3. Start the agent with the prompt below as the user message.
   Temperature low (≤0.2) — we want consistency, not creativity.
4. Wait for the agent to finish (it should run the validator as its
   last step and report `EXIT=0`).
5. Spot-check ~20% of the agent's labels (v2 is small enough to
   sample heavily) by reading the matching `eval/sessions-v2/<sid>.md`
   alongside the YAML block. The rubric is ground truth, not the LLM
   — if it goes off-vocabulary, labels too aggressively, or breaks
   the pair-independence rule, re-prompt with a corrective example.

Manual review of every LLM label is **not** optional. v2 is the eval's
direct measurement of the embedding's claimed strength; an LLM-labeled
ground truth that isn't reviewed is laundered LLM output, not ground
truth.

## The prompt

```
You are a senior security analyst labeling the v2 divergent-pair
stress test for a cowrie honeypot eval set. You have filesystem tools
(Read, Edit, Write, Bash). You will read every rendered session
yourself and write your labels directly into `eval/labels-v2.yaml`.
You receive no other input — everything you need is on disk under
`eval/`.

Your goal: emit one labeled block per session in `eval/labels-v2.yaml`
with strong cross-session consistency AND strict per-pair independence
(see "Cross-session consistency" below — there are two rules that
together are the most important rules in this prompt).

The v2 set tests the embedding's "behavior-not-text" claim. Each
session belongs to exactly one `divergent_pair_id` (a pre-populated
read-only field on the skeleton). Both members of a pair were chosen
because they SHARE a coarse behavior signal but have DISJOINT commands.
Whether the underlying behaviors are actually the same is the analyst
judgment your label encodes.

# Workflow — execute in this order

1. **Read the rubric.** `Read eval/RUBRIC.md`. This is the rule book;
   the prompt below is a summary. If the rubric and this prompt
   disagree on anything, the rubric wins.

2. **Read the v1 labels to inherit the vocabulary.**
   `Read eval/labels-v1.yaml`. The v1 set was labeled first and
   defines the established `playbook_label` vocabulary. v2 sessions
   that match v1 behaviors MUST re-use the v1 labels — the eval
   scripts merge v1+v2 by `session_id`, so a v2 `host_recon` session
   labeled differently from a v1 `host_recon` session is silently
   destroying the merged ground truth. Scan `eval/labels-v1.yaml` for
   every distinct `playbook_label` value and treat that set as your
   starting vocabulary.

3. **Enumerate the v2 set.** Run `ls eval/sessions-v2/ | wc -l` to
   confirm the session count. Then list them: `ls eval/sessions-v2/`.

4. **Slurp every session into one tool output.** Run
   `for f in eval/sessions-v2/*.md; do cat "$f"; echo; done` so you
   see every rendered session in a single Bash result. The H1 of each
   section (`# <session_id>`) is the delimiter.

5. **Read the current labels file.** `Read eval/labels-v2.yaml`. Every
   block should have `annotated: false` on a fresh build. If any
   block has `annotated: true`, an analyst has already labeled it —
   DO NOT overwrite that block. Leave it verbatim and label the rest.

6. **Plan the vocabulary AND the per-pair calls.** Before writing
   anything:
     a) Decide which `playbook_label` you'll assign each session.
        Default to v1 vocabulary; mint a new label ONLY when no v1
        label fits, and aim for 0-2 new labels across the whole v2
        set (the v1 set has ~6 labels; v2 should add few or none).
     b) For each `divergent_pair_id`, look at both member sessions
        side-by-side and pick the per-pair outcome (same label,
        different labels, or borderline-same; see "Three valid pair
        outcomes" below). This is the load-bearing planning step.

7. **Write the labels file.** Use a single Write call to overwrite
   `eval/labels-v2.yaml` with the full labeled file. Preserve:
   - The leading comment block (copy it verbatim from your earlier
     Read).
   - Every block keyed by a session that exists in `eval/sessions-v2/`.
   - The exact field order: `annotated`, `is_real`, `playbook_label`,
     `expected_findings`, `notes`, `divergent_pair_id`.
   - The auto-populated `divergent_pair_id` value VERBATIM. Do not
     change it; the validator cross-checks against the unlabeled
     JSONL and fails on drift.
   - The exact YAML style PyYAML produces (no extra quoting, no
     anchors, blank lines between blocks).
   Do NOT include blocks for session_ids that aren't in the current
   v2 set (they would be flagged as orphans).

8. **Validate.** Run:
       console/.venv/bin/python scripts/validate_eval_labels.py \
         --labels eval/labels-v2.yaml \
         --unlabeled eval/sessions-v2.unlabeled.jsonl
   The output must report `EXIT=0`. If errors are reported, fix them
   in a single Edit and re-validate. Common v2 failures: missing
   field, `divergent_pair_id` mismatch (you edited the read-only
   field), unknown finding kind, `playbook_label: null` on an
   `is_real: true` block.

9. **Report.** Print a one-line summary: total blocks labeled, count
   of `is_real: false` rejections, count of distinct `playbook_label`
   values (broken out by inherited-from-v1 vs newly-minted), and the
   per-pair outcome tally — same/different/borderline.

# Reading order — for each session

Sessions are grouped by `divergent_pair_id` in the v2 set. For each
pair, you will label BOTH members independently first, then compare.

When reading each rendered session, work in this order:

1. Read the Login attempts table — what did the attacker try as
   user/pass?
2. Read the Command stream top to bottom — what did they ACTUALLY do?
3. Then skim File events and Artifacts — they corroborate the story.
4. Use Source IP, geo, ASN, HASSH, and SSH banner only as supporting
   context for HOW the attacker connected, not WHAT they did.

The Rollup section's `commands` count and `novelty_score` are
descriptive metrics. Do not let them lead the label.

The `divergent_pair_id` value appears in the Header section
("**Divergent pair:** `dp-NNN`"). It tells you which other session
this one is paired with, but **do not read the pair partner before
forming your own judgment of this session**. See "Pair independence"
under the MOST IMPORTANT RULE section below.

# Output schema — one block per session

  <session_id>:
    annotated: true
    is_real: <true|false>
    playbook_label: <snake_case or null>
    expected_findings: []
    notes: "<why this label>"
    divergent_pair_id: <dp-NNN — DO NOT EDIT, auto-populated>

Field order is fixed. The validator and `render_eval_set.py` both
expect this order. `divergent_pair_id` is read-only — the validator
fails on any drift between the YAML value and the JSONL value.

# Cross-session consistency AND pair independence — THE MOST IMPORTANT RULES

Two rules. They sound contradictory but aren't:

**(1) Cross-session consistency.** You see every v2 session AND
every v1 label in one pass. Use this to guarantee consistency in a
way a per-session call cannot:

- The FIRST time you see a behavior, pick a `playbook_label` from the
  v1 vocabulary (re-read step 2 — `Read eval/labels-v1.yaml` before
  deciding anything). Only mint a new label when no v1 label fits.
- Every subsequent session that does the same job — REGARDLESS of
  textual command form — MUST get the same label. This applies
  across v1 AND v2; the eval merges them.
- Two sessions sharing a label is a FEATURE, not a problem. The eval
  grades whether the pipeline clusters them; your job is to define
  the ground-truth cluster assignment.

**(2) Pair independence.** For each `divergent_pair_id`, label both
members **without looking at each other first**. Read session A
cold, write down your tentative label (in scratch space, not the
yaml yet); read session B cold, write down its tentative label;
THEN compare.

Why: the v2 metric asks whether the pipeline clusters same-labeled
pairs together. If you let session A's label leak into your reading
of session B, you bias the ground truth toward "of course they
match." Independence preserves the metric's honesty.

After comparing tentative labels, three outcomes are valid (see
"Three valid pair outcomes" below). Resolve to one outcome per pair,
then commit the labels to the YAML.

Aim for ~5-15 distinct labels across the merged v1+v2 set. Fewer =
you are conflating distinct behaviors; many more = you are labeling
by command text rather than behavior. v2 alone should contribute few
or zero new labels — most v2 behaviors should already be in v1.

# Three valid pair outcomes

For each `divergent_pair_id`, after independent reads:

  A. SAME LABEL.
     Both tentative labels match. The pair tests the embedding's
     positive case — same behavior, different text. The merged eval
     will mark this as a pair the embedding *should* cluster.

     → Commit both blocks with the matching label. Notes may be
     empty unless the label was borderline.

  B. DIFFERENT LABELS.
     The two tentative labels diverge. The pair was a candidate
     because both members shared a coarse intent or playbook_id, but
     the underlying behaviors are different. This is a valid
     analyst call — it tests the embedding's negative case (the
     embedding is *correct* to split them).

     → Commit both blocks with their respective labels. Notes:
     populate at least one side with "Negative test case: A does X,
     B does Y, share <intent> but split into different playbooks."

  C. BORDERLINE — SAME FAMILY, DIFFERENT SUB-BEHAVIOR.
     Both tentative labels were related (e.g. both flavors of SSH
     key persistence, but one adds a crontab while the other adds
     chattr) and you're tempted to mint two sub-labels. DON'T —
     the eval grades behavioral coarseness, not analyst hair-
     splitting.

     → Commit both blocks with the SAME label (pick the closest v1
     label; if a sub-variant is truly distinct, mint ONE new label
     and apply it to both). Notes on BOTH sides explain the
     sub-variation in 1 sentence.

# playbook_label — the behavior axis

A short snake_case label naming what the attacker DOES, independent
of textual command form.

**Default to v1 vocabulary.** Re-read step 2 — `Read
eval/labels-v1.yaml` and use the distinct `playbook_label` values
there as your starting set. The current v1 vocabulary (as of the
labeled set in the repo) includes:

  - host_recon — `whoami`, `uname -a`, `w`, `cat /proc/cpuinfo`, etc.
  - ssh_key_chattr_persistence — write authorized_keys + chattr +i
  - botnet_loader — IRC / TCP beacon + secondary fetch, or
    download+chmod+execute
  - mirai_busybox_probe — `/bin/busybox TEST`-style shell-detection
    probes
  - shell_wrapper_only — one `echo "..." | sh` with no follow-up
  - single_command_probe — exactly one command, then disconnect

(The actual v1 file is authoritative — read it to confirm the
current list.) Mint a new label ONLY when you genuinely see a
behavior none of these fit AND you've checked the v1 corpus. When
borderline, pick the closest existing label and explain the nuance
in `notes`.

Set to null only when `is_real: false`.

# is_real

false when the record is corrupted:
  - HTTP request ingested as SSH session (Login attempts row shows
    `GET / HTTP/1.1`-style values; commands are HTTP headers like
    `Accept-Encoding: gzip`).
  - Single empty command line in the command stream.
  - Rollup that clearly spans two unrelated attacker activities.

When is_real: false:
  - playbook_label: null
  - expected_findings: []
  - notes: MUST explain why.
  - divergent_pair_id: STAYS AS-IS. The pair half being unusable
    doesn't change the pair_id assignment.

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

Most v2 sessions get []. v2 is specifically the divergent-pair
stress test for behavior labeling — most findings kinds are about
cross-session anomalies, not single-session content. Only add a
kind when the case is crisp from THIS session's contents plus the
rollup context. intel_verdict_flip and ip_behavior_shift need
cross-session history you won't have.

# notes

Empty string is fine on obvious sessions. Always populate when:
  - is_real: false (REQUIRED).
  - You're minting a new playbook_label.
  - The pair outcome is DIFFERENT LABELS (outcome B above) — at
    least one side notes the negative-case rationale.
  - The pair outcome is BORDERLINE (outcome C above) — both sides
    note the sub-variation.
  - The label is borderline against v1 vocabulary — explain why you
    picked it over a similar-but-different existing one.
  - The session has expected_findings entries — explain each.

Keep notes terse (1-3 sentences).

# divergent_pair_id — READ-ONLY

The `divergent_pair_id` field is auto-populated by
`render_eval_set.py` from the unlabeled JSONL. **Never edit, change,
or remove it.** The validator cross-references YAML against JSONL
and fails on any drift.

If your final labels file accidentally drops or modifies a
`divergent_pair_id`, the build will refuse the v2 set. Treat the
field exactly like the `session_id` key: copy it through verbatim
from the skeleton you Read in step 5.

# Anti-patterns — REJECT THESE

  1. Reading the pair partner before forming your own judgment of
     the current session. Pair independence is rule (2) of the
     MOST IMPORTANT RULES. Independence preserves the metric's
     honesty.

  2. Minting a v2-only sub-label for a behavior v1 already covers.
     "ssh_key_chattr_persistence_v2_variant" is wrong; use
     `ssh_key_chattr_persistence` + notes explaining the variation.

  3. Labeling by intent. "reconnaissance" / "persistence" / etc.
     are intent buckets, not behaviors. The pipeline derives intent;
     if you label by intent, you grade the LLM against itself.

  4. Forcing same labels because "they're a divergent pair, they
     must match." Outcome B (different labels) is a VALID and
     INFORMATIVE call. If the underlying behaviors really differ,
     label them differently — that's the negative test case the
     v2 metric needs.

  5. Forcing different labels because "Jaccard 0 means they MUST
     be different." Jaccard is text overlap; the whole point of v2
     is to test pairs that are TEXTUALLY divergent but
     BEHAVIORALLY identical. Same label on a Jaccard-0 pair is
     the load-bearing positive case.

  6. Stuffing expected_findings. Each entry is a precision-recall
     lever; over-stuffing punishes whichever miner correctly didn't
     fire.

  7. Skipping notes when the label "feels obvious." Especially on
     outcome B (different labels) — at least one side must justify
     the negative-test call.

  8. Treating any artifact label (rsa_key, ip, url, hash, file) as
     the playbook_label. The artifact_set lists structural IOCs;
     the playbook is what the SESSION does.

  9. Inconsistent labeling across v1 AND v2. If v1 labels a session
     as `ssh_key_chattr_persistence`, and a v2 session does the
     same chattr+key write through different commands, the v2
     session MUST also be `ssh_key_chattr_persistence`.

 10. Editing the file block-by-block (one Edit per session). Burns
     turns and risks losing cross-session consistency. Plan the
     whole vocabulary AND every pair outcome first, then Write the
     file once.

 11. Touching any block that is already `annotated: true`. Those
     are human-confirmed labels. Leave them alone.

 12. Editing the `divergent_pair_id` field. Read-only. The
     validator fails on drift.

# Worked examples

  Example 1 — Pair outcome A: same label.

  Pair dp-005. Session A: full SSH-mdrfckr key drop with chattr
  immutability protection + chpasswd + recon padding. Session B:
  cat-heredoc deployment of a different SSH key into
  /root/.ssh/authorized_keys, also with lockr immutability. Jaccard
  0.0 (disjoint commands).

  Independent reads: both look like SSH-key-persistence playbooks.
  Tentative labels match.

    0140c2edbb71:
      annotated: true
      is_real: true
      playbook_label: ssh_key_chattr_persistence
      expected_findings: []
      notes: ""
      divergent_pair_id: dp-005

    e15c95173912:
      annotated: true
      is_real: true
      playbook_label: ssh_key_chattr_persistence
      expected_findings: []
      notes: ""
      divergent_pair_id: dp-005

  Example 2 — Pair outcome B: different labels.

  Pair dp-008. Session A: long SSH-mdrfckr persistence + recon
  padding (12 commands). Session B: 4-command Mirai-style
  `/bin/busybox TEST` shell-probe. Both tagged
  dominant_intent=reconnaissance.

  Independent reads: A is persistence, B is a probe. Tentative
  labels diverge.

    5734386f4346:
      annotated: true
      is_real: true
      playbook_label: ssh_key_chattr_persistence
      expected_findings: []
      notes: "Negative test case: A is SSH-key persistence playbook;
        paired with B (bda68569dc9e) which is a Mirai busybox probe.
        Both tagged intent=reconnaissance but behaviorally distinct."
      divergent_pair_id: dp-008

    bda68569dc9e:
      annotated: true
      is_real: true
      playbook_label: mirai_busybox_probe
      expected_findings: []
      notes: ""
      divergent_pair_id: dp-008

  Example 3 — Pair outcome C: borderline, same label.

  Pair dp-011. Session A: long SSH-persist with chattr + a long
  recon block. Session B: short SSH-persist with chattr + chpasswd
  but no recon padding.

  Independent reads: A "ssh_key_chattr_persistence with recon padding"
  and B "ssh_key_chattr_persistence with chpasswd variant." Both are
  clearly the same playbook family. Resolve to the same v1 label;
  notes capture the sub-variation.

    08f16b250109:
      annotated: true
      is_real: true
      playbook_label: ssh_key_chattr_persistence
      expected_findings: []
      notes: "Long-form variant: chattr persist + extensive host
        recon. Paired with 28c779e9b7a2 as a short-form variant of
        the same playbook."
      divergent_pair_id: dp-011

    28c779e9b7a2:
      annotated: true
      is_real: true
      playbook_label: ssh_key_chattr_persistence
      expected_findings: []
      notes: "Short-form variant: chattr persist + chpasswd, no
        recon padding. Paired with 08f16b250109 as a long-form
        variant of the same playbook."
      divergent_pair_id: dp-011

  Example 4 — Corruption rejection.

  Session where the Login row shows `GET / HTTP/1.1` as the user
  and the command stream contains `Accept-Encoding: gzip`. The
  divergent_pair_id stays as-is even though we can't label the
  behavior.

    d2ab2ca67303:
      annotated: true
      is_real: false
      playbook_label: null
      expected_findings: []
      notes: "HTTP request ingested as SSH session. Login row +
        command stream are protocol leakage, not attacker behavior."
      divergent_pair_id: dp-NNN

# Final reminders

- You receive NOTHING through the chat interface except this prompt.
  All session content is on disk under `eval/sessions-v2/`.
- Re-read the rubric (`eval/RUBRIC.md`) and the v1 labels
  (`eval/labels-v1.yaml`) BEFORE you finalize the file. v2 inherits
  v1's vocabulary.
- Write the labels file ONCE, after you've planned the full
  vocabulary AND every pair outcome. Do not Edit block-by-block.
- **Pair independence:** label each session cold before comparing
  with its pair partner. Then resolve outcome A / B / C.
- Never touch a block whose `annotated` is already `true`.
- Never modify the auto-populated `divergent_pair_id` field.
- Run the validator as your last step. Do not stop until it reports
  `EXIT=0`.

Begin.
```

---

## When to override the LLM

After the agent finishes and the validator passes, sweep through the
output looking for:

- **Too-specific labels** that should have inherited v1's coarser
  labels (e.g. `ssh_key_chattr_persistence_outlaw` instead of
  `ssh_key_chattr_persistence` + note). Consolidate.
- **New labels minted unnecessarily.** v2 should add few or zero
  new labels to the v1 vocabulary. A v2-only label is a red flag —
  re-read the v1 vocabulary and the session in question; usually the
  closer v1 label was the right call.
- **Pair-outcome bias.** Tally the agent's outcomes:
  ```bash
  grep -A1 divergent_pair_id: eval/labels-v2.yaml | \
    grep playbook_label | sort -u | wc -l
  ```
  If every pair resolves to outcome A (same label) or every pair to
  outcome B (different labels), the agent may have stopped reading
  independently. Spot-check a 30/70 split or whatever distribution
  the rubric implies for this corpus.
- **`divergent_pair_id` drift.** The validator catches this but
  confirm `grep divergent_pair_id eval/labels-v2.yaml` shows only
  values from `eval/sessions-v2.unlabeled.jsonl`.
- **Inconsistencies with v1.** Re-grep:
  ```bash
  diff <(grep playbook_label eval/labels-v1.yaml | sort -u) \
       <(grep playbook_label eval/labels-v2.yaml | sort -u)
  ```
  Any v2 label NOT in v1 should have a strong justification in
  notes; otherwise flip it to the closest v1 label.
- **`is_real: true` on clearly-corrupted sessions.** Same rule as
  v1 — read the Login attempts table; HTTP-shaped usernames are
  the tell.

Manual review is part of the workflow, not optional QA.
