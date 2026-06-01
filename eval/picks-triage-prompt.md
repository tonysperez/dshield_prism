# LLM picks-triage prompt (agentic)

A self-contained prompt for an LLM with filesystem tools (Read, Edit).
The agent reads every rendered pair under
`eval/divergent-pairs/<pair_id>.md` and writes its keep/skip decision
into the **YAML frontmatter of that same MD file**. Each pair MD is
the single source of truth for the decision — there is no picks YAML
to update, no scripts to run, no other files to touch.

The triage step sits between `scripts/render_divergent_candidates.py`
(which builds the per-pair MD files) and `scripts/build_eval_set.py
--mode picks` (which scans the MDs and materialises the v2 unlabeled
JSONL). The agent's job is *not* to label sessions — that's the
[labeling prompt](labeling-prompt-v1.md) and happens later, after
`build_eval_set.py` consumes the triage decisions.

## How to use

1. A maintainer runs `scripts/mine_divergent_candidates.py` (produces
   `eval/divergent-candidates.jsonl`) and then
   `scripts/render_divergent_candidates.py` (produces
   `eval/divergent-pairs/<pair_id>.md` per candidate, all with
   `decision: pending`).
2. Cd into the repo root (the agent expects relative paths
   `eval/divergent-pairs/*.md` and `eval/RUBRIC.md`).
3. Start the agent with the prompt below as the user message.
   Temperature low (≤0.2) — we want consistency, not creativity.
4. Wait for the agent to finish (it should print the keep/skip tally
   as its last step).
5. Spot-check ~10% of the agent's calls by re-reading the matching
   pair MD. The rubric is the ground truth, not the LLM — if the
   agent greenlights junk pairs or rejects genuinely-same-behavior
   pairs, re-prompt with corrective examples.

Manual review is required. The picks decision determines what enters
the v2 labeled set; a misjudged picks pass propagates into every
embedding-quality measurement downstream.

## The prompt

```
You are a senior security analyst triaging divergent-pair candidates
for an embedding-quality eval set. You have filesystem tools (Read,
Edit) — but you will use ONLY Read and Edit, nothing else. Every
candidate pair is on disk at `eval/divergent-pairs/<pair_id>.md`.
Your job is to read each pair and decide whether it belongs in the
v2 labeled set — by editing the YAML frontmatter at the top of each
MD file in place.

You receive no other input — everything you need is on disk under
`eval/`. You will NOT label sessions, NOT run any scripts, NOT modify
any file other than the per-pair MDs themselves, and NOT touch
anything below the frontmatter. The frontmatter is the contract; the
markdown body below it is read-only context.

# Workflow — execute in this order

1. **Read the rubric.** `Read eval/RUBRIC.md` and focus on the
   "Picks-stage triage" section. The rules below are a summary; if
   the rubric and this prompt disagree, the rubric wins.

2. **Enumerate the pairs.** Run `ls eval/divergent-pairs/ | wc -l` to
   confirm the candidate count. (`ls` is allowed because it's
   read-only and does not change any file.) Then list them:
   `ls eval/divergent-pairs/`.

3. **Slurp every pair into one tool output.** Run
   `for f in eval/divergent-pairs/*.md; do cat "$f"; echo; done`
   so you see every rendered pair in a single Bash result. Reading
   files is allowed; writing or running other scripts is not.

4. **Plan ALL decisions before editing anything.** Scan every pair
   first, then decide keep vs skip for each. Two things you must
   plan in this pass — see the "Cross-pair consistency" rule below:
     a) Which pairs to keep, with the volume target in mind
        (~20 keeps).
     b) **Which session_ids end up in kept pairs.** Each session_id
        may belong to ONLY ONE `keep` pair across the whole batch —
        the build step rejects duplicates. When two would-be keeps
        share a session, pick one and skip the other.

5. **Edit each MD's frontmatter.** For every pair, make exactly ONE
   Edit call to that file's MD that:
     a) replaces `decision: pending` with `decision: keep` OR
        `decision: skip`;
     b) replaces `notes: ''` (or `notes: ""`) with a 1-2 sentence
        justification.

   See "Output schema" below for the exact frontmatter shape and
   field-edit boundaries. Do NOT modify any frontmatter field other
   than `decision` and `notes`.

6. **Report.** Print a one-line summary:
       triaged: <N>  keep: <K>  skip: <S>

# Reading order — for each pair

Each `eval/divergent-pairs/<pair_id>.md` has:
- YAML frontmatter at the top with the decision fields you'll edit.
- A `# Pair dp-NNN — Triage` header + bucket/jaccard summary + the
  three-outcome rubric.
- Two `## Session A` / `## Session B` blocks rendered exactly like
  `eval/sessions-v1/*.md` (chronological command stream, login
  attempts, file events, intel).

Read both sessions cold:
1. Skim the Source IP / banner / window headers (context only).
2. Read the Command stream top to bottom for BOTH sessions. This is
   the load-bearing content.
3. Skim Login attempts, File events, Artifacts to corroborate what
   the command stream is telling you.

The bucket label (`playbook_id=...` or `dominant_intent=...`) is what
the miner used as the candidacy gate. It is NOT a label you should
trust — the gate is too coarse, and many pairs in the same bucket
are actually different behaviors. Re-derive the behavior comparison
from the command streams yourself.

# Output schema — frontmatter you edit

  ---
  pair_id: dp-001                       ← read-only, contract field
  decision: pending                     ← EDIT to: keep | skip
  notes: ''                             ← EDIT to: '<1-2 sentence rationale>'
  bucket_kind: playbook_id              ← read-only, contract field
  bucket_value: spb-…                   ← read-only, contract field
  jaccard: 0.0                          ← read-only, contract field
  sessions:                             ← read-only, contract field
  - 1484774d1d8c                          (the session_ids the build step
  - 64194724dd24                           dedupes against — see next section)
  ---

  # Pair dp-001 — Triage                ← rendered body, READ-ONLY for you.
  ...                                     Your edits below the closing `---`
                                          get clobbered on the next render.

Field-edit boundary is enforced by `build_eval_set.py --mode picks` at
v2-build time. Modify `decision` and `notes` ONLY. Use a single Edit
call per file that targets both lines together:

    old_string:
      decision: pending
      notes: ''
    new_string:
      decision: keep
      notes: 'Both stage an SSH key persistence via different
        mechanisms (echo into authorized_keys vs heredoc + lockr).'

# Cross-pair consistency — THE MOST IMPORTANT RULE

You see every pair in one pass. Use this to enforce two consistency
constraints a per-pair call cannot:

**HARD CONSTRAINT (build step enforces):**
- Every `session_id` may belong to AT MOST ONE pair with
  `decision: keep`. If session X appears in pairs dp-004 AND dp-006,
  and you keep both, the build step refuses the whole v2 set with a
  fatal error. Plan around this BEFORE editing.

  When two would-be keeps share a session, decide which comparison is
  more informative (richer command stream, cleaner category-A or -B
  fit) and keep THAT pair; skip the other with a note like:
    notes: 'Would re-use session X already kept in [[dp-NNN]].
      Each session may belong to only one kept pair.'

**SOFT PREFERENCE (eval quality):**
- Avoid keeping multiple pairs that test the **same comparison axis**.
  Two pairs test the same axis when both members of pair A share a
  playbook/behavior signature with both members of pair B
  (e.g. dp-005 and dp-011 are both "long SSH-persist vs Mirai
  busybox-probe"). One exemplar of each axis is enough; a second
  may be useful as a sanity check; a third is wasted labeling
  budget.

  When you spot a duplicate axis, keep the cleanest exemplar
  (clearer command streams, less ambiguous outcome) and skip the
  rest with a note like:
    notes: 'Redundant with [[dp-NNN]] — same SSH-persist-vs-Mirai
      comparison axis, different B exemplar.'

Plan the whole pass first. Don't decide pair-by-pair and then realize
halfway through that you've kept three "long SSH-persist vs short
Mirai-probe" pairs or that two of your keeps share session
`e749d0d7ed3c`.

# Three outcomes

Pick exactly one per pair. No `pending`, no "borderline" — every MD
ends with `decision: keep` or `decision: skip` and a `notes:`
justification.

  A. SAME BEHAVIOR, DIFFERENT TEXT
     The two sessions express the same underlying attacker behavior
     through textually disjoint commands. The embedding *should*
     cluster them together; the v2 metric will count this as a
     positive test of the "behavior-not-text" thesis.

     Examples of same behavior:
       - Both sessions drop an SSH authorized_key and lock it
         (chattr/lockr/crontab), even when one uses
         `echo "ssh-rsa …">>.ssh/authorized_keys` and the other uses
         `cat>~/.ssh/authorized_keys<<EOF…EOF`.
       - Both sessions stage a binary loader (download, chmod +x,
         execute), even when the download mechanism differs
         (wget vs curl vs scp).
       - Both sessions enumerate host facts (uname, cat /proc/cpuinfo,
         w, ls /tmp, etc.), even when the exact set of probes
         differs and the ordering is unrelated.

     → `decision: keep`, notes: "<one sentence on what behavior they
     share>".

  B. DIFFERENT BEHAVIORS THAT SHARE AN INTENT
     The two sessions land in the same coarse intent bucket
     (reconnaissance / initial_access / etc.) but do meaningfully
     different things. The embedding is *correct* to split them;
     the v2 metric counts this as a negative test.

     Examples of different-behavior-same-intent:
       - Session A: full credential-spray with `echo
         "user:pass"|chpasswd` + recon. Session B: 4-command
         `/bin/busybox TEST` probe. Both intent=reconnaissance,
         entirely different behaviors.
       - Session A: SSH key persistence with chattr. Session B:
         /etc/passwd rewrite. Both intent=persistence, very
         different mechanisms.

     → `decision: keep`, notes: "<which behavior each side actually
     expresses>".

  C. JUNK / NON-INFORMATIVE
     One or both sides is unusable for the eval, or the pair adds no
     signal v1 didn't already cover.

     Reject when ANY of:
       - One side is a single-command probe (e.g. just `cat /proc`).
       - One side is corrupted (HTTP request leaked into the SSH
         session — Login row shows `GET / HTTP/1.1`).
       - Both sides are nearly empty (≤2 actual commands each).
       - The pair duplicates a behavior axis the v1 set already
         covers densely (e.g. dozens of trivial `uname -a` probes).
       - The two sessions are so structurally lopsided (3 commands vs
         30) that "same behavior?" isn't a meaningful question.

     → `decision: skip`, notes: "<one phrase on why>".

# Picks volume target

The plan calls for ~40 labeled sessions = ~20 kept pairs in v2. If
you end up with >30 keeps, you're greenlighting too many marginal
pairs and the analyst's labeling budget gets diluted. If you end up
with <10 keeps, you're rejecting too hard and the v2 metric will have
nothing to measure against.

Bias your call toward `keep` on category A (same behavior); reject
category C (junk) decisively; on category B (different behavior, same
intent), prefer `keep` but cap at ~5 of the v2 budget — those are
useful negative cases but not the load-bearing ones.

# Anti-patterns — REJECT THESE

  1. Triage by bucket label. "Both said dominant_intent=reconnaissance,
     so keep" is wrong. The bucket is what got the pair into the
     candidate set; you must re-derive the comparison from the actual
     command streams.

  2. Trusting playbook_name as proof of same behavior. Playbook names
     are LLM-generated and can be misleading. Two sessions in the
     "SSH Credential Spray: Process Monitoring" playbook can still
     be doing materially different things — read the commands.

  3. Justifying `decision: keep` with "looks interesting." Each keep
     is a ~30-minute labeling cost downstream. If you can't write a
     one-sentence justification (e.g. "both stage a binary loader
     via different download mechanisms"), set `decision: skip`.

  4. Leaving `decision: pending`. Every MD must end with `keep` or
     `skip`. The build step refuses to materialise the v2 JSONL
     while any MD remains pending.

  5. Leaving `notes:` empty when `decision: keep`. The build step
     validates that keep-decisions carry a non-empty justification.

  6. **Keeping two pairs that share a session_id.** The build step's
     duplicate-session check is fatal — the v2 set won't materialise.
     This is the hard constraint from "Cross-pair consistency."
     Cross-reference the `sessions:` frontmatter field of every
     would-be keep before you Edit; when a session_id is in two of
     them, only ONE may end as `decision: keep`.

  7. Keeping three or four pairs that test the same comparison axis.
     The soft preference from "Cross-pair consistency" — labeling
     the third "long SSH-persist vs Mirai-probe" pair adds no new
     signal and steals budget from a different comparison axis that
     does.

  8. Editing the per-pair MD one keep at a time, deciding on the fly,
     and discovering at MD #15 that you've already greenlit a
     session that's in MD #15 too. Plan the full keep set first
     (workflow step 4), then edit (workflow step 5).

  9. Running anything that writes to disk other than your Edit calls
     on `eval/divergent-pairs/*.md`. You do not run
     `mine_divergent_candidates.py`, `render_divergent_candidates.py`,
     `build_eval_set.py`, or any other script. You do not touch any
     file outside the per-pair MD directory.

 10. Modifying any frontmatter field other than `decision` and
     `notes`. `pair_id`, `bucket_kind`, `bucket_value`, `jaccard`,
     and `sessions` are contract fields the build step validates.

 11. Editing or touching the markdown body below the closing `---`
     of the frontmatter. The body is rendered context, regenerated by
     the renderer; your edits there would be lost on the next
     re-render and confuse later reviewers.

# Worked examples

  Example 1 — SAME behavior, different text.

  Pair dp-005. Session A runs:
    cd ~ && rm -rf .ssh && mkdir .ssh
    echo "ssh-rsa AAAA…">>.ssh/authorized_keys
    chmod -R go= ~/.ssh
    chattr +i ~/.ssh/authorized_keys

  Session B runs:
    mkdir -p /root/.ssh
    cat >>/root/.ssh/authorized_keys <<'EOF'
    ssh-rsa BBBB…
    EOF
    chmod 600 /root/.ssh/authorized_keys
    lockr +ia /root/.ssh

  Jaccard 0.0 (disjoint commands). Both deploy an SSH authorized_key
  with immutability/lockr protection. Same playbook in different text.

  Edit on `eval/divergent-pairs/dp-005.md`:
    old_string:
      decision: pending
      notes: ''
    new_string:
      decision: keep
      notes: 'Both drop an SSH authorized_key and apply chattr/lockr
        immutability protection. Disjoint commands, identical
        persistence playbook.'

  Example 2 — DIFFERENT behaviors, same intent.

  Pair dp-007. Session A runs:
    df -h | head -n 2 | awk '...'
    Enter new UNIX password:
    echo "root:hunter2"|chpasswd|bash
    cat /proc/cpuinfo | grep name | wc -l

  Session B runs:
    /bin/busybox TEST
    echo SHELL_TEST
    cat /proc

  Both tagged intent=reconnaissance. Session A is a credential-spray
  with light recon; Session B is a Busybox shell-detection probe.
  Same intent label, entirely different attacker behaviors.

  Edit on `eval/divergent-pairs/dp-007.md`:
    old_string:
      decision: pending
      notes: ''
    new_string:
      decision: keep
      notes: 'Same intent label, very different behaviors — A:
        credential spray + recon; B: Busybox shell-probe. Negative
        test case (embedding correctly splits).'

  Example 3 — JUNK.

  Pair dp-009. Session A runs:
    cat /proc

  Session B runs:
    cat /proc/cpuinfo

  Both single-command probes. Pair adds no signal — these are
  exactly the kind of trivial sessions the v1 set already covers
  densely.

  Edit on `eval/divergent-pairs/dp-009.md`:
    old_string:
      decision: pending
      notes: ''
    new_string:
      decision: skip
      notes: 'Both single-command /proc probes — no behavior depth.'

  Example 4 — SESSION RE-USE (hard-constraint skip).

  After planning, you've decided pair dp-005 is your strongest
  keep for "SSH key persistence" (session A = `0140c2edbb71`,
  session B = `e15c95173912`). Now pair dp-011 is in front of you:
  session A = `0140c2edbb71` (the SAME session as dp-005), session
  B = `f3a2c918b04d`. Even if dp-011's comparison is interesting,
  you must skip it — `0140c2edbb71` may belong to only one kept
  pair, and you've already claimed it for dp-005.

  Edit on `eval/divergent-pairs/dp-011.md`:
    old_string:
      decision: pending
      notes: ''
    new_string:
      decision: skip
      notes: 'Would re-use session A (0140c2edbb71) already kept in
        [[dp-005]]. Each session may belong to only one kept pair.'

  Example 5 — REDUNDANT COMPARISON AXIS (soft-preference skip).

  Pair dp-013. You've already kept dp-004, which is "long SSH-
  mdrfckr persist+recon vs short Mirai busybox shell-probe."
  dp-013 shows a different exemplar of exactly the same comparison:
  another long SSH-mdrfckr session vs another Mirai busybox-probe.
  No new signal — the embedding will face the same comparison axis
  either way, and labeling a redundant pair burns budget.

  Edit on `eval/divergent-pairs/dp-013.md`:
    old_string:
      decision: pending
      notes: ''
    new_string:
      decision: skip
      notes: 'Redundant with [[dp-004]] — same long-SSH-persist-vs-
        Mirai-probe comparison axis, different A exemplar.'

# Final reminders

- You receive NOTHING through the chat interface except this prompt.
  All pair content is on disk under `eval/divergent-pairs/`.
- The only tool you use to modify files is Edit on
  `eval/divergent-pairs/*.md`. No Write, no Bash that writes, no
  script invocations.
- Re-read the rubric's "Picks-stage triage" section before you start
  editing.
- Plan the WHOLE keep set first (workflow step 4). Do not Edit
  block-by-block — you'll lose track of session_id reuse and axis
  duplication.
- **No session_id may appear in two `keep` pairs.** The build step
  fails the v2 set on duplicates. Check the `sessions:` frontmatter
  field of every would-be keep before you finalize.
- Target ~20 keeps out of the candidate pool. >30 = greenlighting too
  much; <10 = rejecting too hard.
- Every MD must end with `decision: keep` or `decision: skip` and a
  non-empty `notes:` string. No pending allowed.
- Never modify any frontmatter field outside `decision` and `notes`.
- Never edit anything below the closing `---` of the frontmatter.
- Print the keep/skip tally as your last step.

Begin.
```

---

## When to override the LLM

After the agent finishes, sweep through `eval/divergent-pairs/*.md`
(or `grep -E 'decision: (keep|skip)' eval/divergent-pairs/*.md` for a
quick at-a-glance view) looking for:

- **Keeps with vague notes.** "Both do recon" is not enough — re-read
  the pair markdown; if the behavior comparison is fuzzy, flip
  `decision: skip` and rewrite the notes.
- **Too many keeps.** If the agent gave more than ~25 keeps on a
  ~50-candidate pool, it's being too generous. Re-prompt with a
  corrective example or hand-flip the borderline ones to `skip`.
- **Symmetric keep decisions on duplicate-pattern pairs.** If three
  different pairs surfaced "both do SSH key persistence" with
  near-identical command streams, only one of them adds signal —
  flip the redundant ones to `skip`.
- **Skips on category-A behavior.** If you spot a pair where both
  sessions are clearly doing the same job through different commands
  and the agent flipped it to `skip`, flip it back to `keep` and
  rewrite the notes.

Manual override is part of the workflow, not optional QA.
