# Design decisions

The load-bearing choices that still constrain the system, and the dead-ends that
were measured and rejected (so they aren't re-attempted). This is the "why";
the "what it does now" is in [architecture.md](architecture.md) /
[reference.md](reference.md), and the measurements behind several of these are in
[evaluation.md](evaluation.md). For the production war-stories told in the
operator's voice, see the **Lessons Learned** section of
[`README.md`](../README.md).

## Decisions that still constrain

**The CI quality gate measures operator jobs, not partition agreement.** The old
gate graded unsupervised-partition metrics (ARI/NMI/homogeneity/completeness/
v_measure) with a flat absolute-0.05 tolerance — a geometry off the shipped
nearest-prototype assign path, and a tolerance that let a 12% relative slide pass.
`eval_operational.py` replaces it: every gated metric maps to a named operator
failure (assignment macro-F1 + per-label accuracy; novel precision/recall + false-
familiar at the shipped τ via a whole-label holdout; minted-playbook purity +
distinct count). Thresholds are **per-metric, variance-justified** — a bootstrap-CI
half-width for metrics with real n, a **hard absolute floor** for per-label accuracy
(n is too small there for a CI, so a CI-derived tolerance would gate nothing on a
collapse). Novelty is gated only if the generated baseline shows it non-degenerate
at τ in the label-mean geometry — measured, not assumed (it reads 0.8841 recall at
0.5865 precision, so it gates on both); false-familiar (= 1 − novel recall) is
reported, never a second gate on
the same quantity. The partition metrics are kept as printed diagnostics
(`eval_clustering.py` / `eval_assignment.py` exit 0). Novelty measured against the
real production anchors, an expanded label set, and a labeled drift set are
deferred follow-ups (quality-metrics Slices B/D/E).

**Production-path assignment measurement stays diagnostic until anchor geometry
is representative.** `eval_assignment_faithful.py` now replays the shipped
TF-IDF band confirmation and cascade, including whole-behavior holdouts and a
fixed operating curve. The committed evidence can currently construct only
broad analyst-label prototypes; those yield very low familiar coverage and
therefore cannot ground an adoption baseline. The evaluator is kept in CI for
decision-path and evidence-contract diagnostics, while explicit baselines fail
closed. Blocking activation waits for a representative public production-anchor
snapshot with capture provenance.

That prerequisite is now **met**: the corpus is classified entirely `public` and holds 27
production anchors, all of which clear the capture floor, so the committed
`eval/anchor-snapshot-v1.jsonl.gz` carries the complete library (27, up from a stale 15).
The evaluator gained `--anchors` to ingest it, and the snapshot schema gained the per-anchor
command-cluster bags its TF-IDF confirm needs. Measured outcome: familiar coverage on the
attributed subset rose 0.0612 → 0.786, confirming that broad label prototypes caused the
pre-band coverage collapse — but the band confirm's rejection rate rose 96.6% → 100%, so
that half of the attribution is refuted and is now tracked separately. Note the ceiling is structural: centroids are
recomputed from public sessions only, because the pinned production ones are
mixed-classification and cannot be committed — so "complete coverage" holds on a fully-public
corpus and would not on a mixed one.

**The eval label vocabulary is closed (rubric v2), and agreement is reported
both raw and vocabulary-aligned.** The v1 rubric offered a *suggested* skeleton
vocabulary to "extend / contract as you go", while `eval_agreement.py` compares
label strings — so two passes over the same 160 sessions, both compliant with
`rubric_version: v1`, produced 11 and 12 categories with only 5 shared, and every
rename scored as a total mismatch. Measured agreement 0.4813; 0.5813 once the
vocabularies were aligned 1:1. An unpinned vocabulary makes the reliability
instrument unreadable, so `eval/RUBRIC.md` now carries a closed canonical table
enforced by `validate_eval_labels.py` (`KNOWN_PLAYBOOK_LABELS`), a retired-synonym
table that names each replacement, and an explicit "adding a label is a rubric
version bump" process. `eval_agreement.py::vocabulary_alignment` reports agreement
under the best 1:1 renaming, with any category present in **both** vocabularies
locked to itself — both annotators knew that term and chose differently, which is
genuine disagreement, not naming. The raw number stays the headline; the gap
between them is the naming component.

**Two eval labels are defined by behavior, never by form.** The same divergence
exposed three rubric defects that an open vocabulary had hidden. (1)
`single_command_probe` was defined as "exactly one command, then disconnect" —
but over half the sample is a single command line, and 31 `host_recon` sessions
are single-command. It is now defined by what the attacker *learns* (nothing —
`PING`, `echo SHELL_TEST`, `busybox abc`), with an explicit content-beats-form
precedence rule against `host_recon`. (2) `shell_wrapper_only` (a skeleton label
naming the `echo "…" | sh` delivery form) is retired — `echo "cat /proc/cpuinfo;
uname -a" | sh` is `host_recon`. (3) `botnet_loader` now requires an observed
beacon or arch-selection preamble; a plain `wget x.sh; ./x.sh` is
`payload_fetch_exec`, since calling it a loader asserts a C2 role the session
doesn't evidence. Form labels look consistent and measure nothing.

**`botnet_loader` fires on fleet intent, not on an observed beacon.** The first
v2 wording required "runtime arch detection or an observed C2 beacon" — written
to stop an annotator over-calling the label on any fetch-and-execute. It
overcorrected: a cowrie honeypot never observes a beacon packet, so real loaders
fell through to `payload_fetch_exec`. The test is now any one of three forms that
*are* visible in the command stream — multi-architecture targeting (runtime
detection or brute-force fetching several variants), a C2 address/port passed at
launch (`./bot 1.2.3.4 1338`), or self-spread (`busybox telnetd -l /bin/sh -p
31337 &`). `payload_fetch_exec` is the default; `botnet_loader` is the exception
that must earn itself. Related: `iot_cli_probe` now requires the appliance CLI to
be the *whole* session — appliance sessions routinely walk a menu (`enable`,
`system`, `linuxshell`) to reach a shell and then fetch a payload, and the menu
walk is a means, not the behavior.

**Macro-F1 excludes labels a held-out split cannot learn.** A label with one
member corpus-wide has zero training examples whenever that member is the test
case, so it scores a structural 0.0 that no prototype quality could move — while
still contributing 1/n_labels of the macro mean (measured: 0.7612 → 0.7777 on the
148-session set). `eval_operational.gate` already exempted `n < 2` labels from the
per-label floor on exactly this reasoning; `classification_metrics(...,
scoreable=)` makes macro-F1 agree with that judgement instead of contradicting it.
The exclusion forgives only what no prototype could have fixed: those sessions
stay in the test set and still cost some other label precision when misassigned.
Rare labels are otherwise *stabilizers*, not noise — at n=3, `dropped_binary_exec`
/ `iot_cli_probe` / `scp_upload` each score recall 1.000 ± 0.000, and dropping all
labels with n<6 *raises* the macro-F1 CI half-width from 0.1954 to 0.2310. Don't
prune rare labels to "reduce variance"; the variance lives in the confusable
middle.

**`is_real: false` covers any non-shell protocol leaking into the command
stream, not just HTTP.** The v1 rule named only the HTTP case. Cowrie records
whatever arrives on the port, so Redis RESP (`PING`) and FTP (`USER test`) frames
are recorded as commands and embed as if they were shell behavior. The test is
"could this string ever be a shell command?" — a one-word *shell* command
(`hostname`, `busybox`) is real; a protocol verb is leakage regardless of whether
the traffic was hostile.

**Labeling is nearest-prototype assignment, not full-corpus clustering.** The
embedding earns no measurable edge over a TF-IDF text baseline on this corpus
(see [evaluation.md](evaluation.md)), so re-partitioning the whole corpus every
cycle bought churn without quality. Sessions are assigned to a pinned anchor
library; HDBSCAN only mints new playbooks from the novel tail. Don't reintroduce
a "the embedding is semantically better than text" claim without a new corpus
that actually shows it.

**Playbook ids are content-addressed and cosine-anchored to a write-once index.**
Anchors are pinned at first mint and never updated. Re-anchoring to the latest
centroid would let transitive chains (A~B≥τ, B~C≥τ, A~C<τ) collapse distinct
lineages under one id. This is what keeps a playbook's identity stable as its
membership shifts run-to-run. Campaign/operation ids inherit the stability via
content-hash over their member sets.

**History is a longitudinal per-playbook lifecycle list, not archive discovery.**
The original History was salience-ranked "standout" cards over the >14d archive —
the same rate metric as Browse, scrubbed back — and showed no per-behaviour arc.
History is now one row per playbook over a selectable window (30/90/180d · all ·
custom; default 90d), each rendering that playbook's own activity band on a shared
adaptive time axis, ranked by a composite `interest` score (liveness·.30 +
trend·.25 + recurrence·.20 + mass·.15 + escalation·.10, each min-max normalized
across the returned pool so one hot playbook can't peg the rest). The archive-only
`now-14d` exclusion is gone — the window includes recent days. The legacy
`_rank_standout` salience lens is retained only for its smoke test. The page also
covers session-clusters, IP-clusters, campaigns, and operations via an entity
selector. Direct per-session fields (playbook_id, session cluster.id) use a `terms`
agg; the rest have no per-session field so each band is built by a shared
`_band_msearch` over `sessions_rollup` (campaigns by member_session_ids, operations
by member_source_ips, IP-clusters by member IPs collected from `ips_rollup`) —
rather than schema-backfilling ids onto every session, which would be a pipeline +
corpus-write change. Campaign/operation membership is a mining-time snapshot, so
those bands miss later-backfilled sessions until re-mined. This was the path
toward folding Browse into History — now done: Browse is retired (its
Operations/Campaigns tables were superseded by this entity selector), its
corpus-summary stat bar moved to the Health page's Overview section, and the
page itself was renamed History → Explore.

**Clustering accumulates embeddings as chunked float32, never a whole-corpus
`list[list[float]]`.** A Python list of 768 float objects costs ~25KB/doc (24B
per float + list pointers) vs ~3KB as a float32 numpy row — an ~8× multiplier
that OOM-killed the historical backfill mid-fetch at ~570K enriched commands on
a 16GB box (raw corpus ~70M docs). `run_layer_clustering` buffers each ES page
and flushes to a float32 chunk every 50K docs, `np.vstack` at the end. This is
purely a memory-representation fix — HDBSCAN input and cluster output are
byte-identical (eval gates moved +0.0000). The command layer clusters
all-at-once by design; unlike sessions/IPs it has no `window_days` escape hatch,
so keeping its peak footprint at the float32 floor is what makes full-corpus
backfill survivable. Size a scale ceiling off `_count`, not `_cat docs.count`.

**Playbook merge uses complete-linkage, not single-linkage.** A merged group
forms only when *every* pairwise centroid cosine clears the threshold, so a chain
of borderline edges can't bridge unrelated behaviors into one playbook.

**IP clustering is behavior-driven; provenance is dropped from the geometry.**
Country, ASN, and HASSH are queryable post-hoc and over-fragment the same
behavior across hosting platforms and client tools. Clustering on behavior
instead cut the largest cluster from ~70% to ~27% of the corpus. The dropped
provenance blocks stay in the codebase behind
`ip.cluster_attribution_provenance_enabled` for reversibility, but the default is
behavior-only.

**Session embedding is an IDF-weighted mean-pool.** Boilerplate (`cd /tmp`,
`whoami`) gets near-zero weight; rare commands dominate the session vector.
Without it, every session looks like its boilerplate.

**The run is complete only when its `run_summary` sentinel exists.** Cluster
runs write the per-run summary *last*, after centroids and per-doc patches, and
every reader gates on it — so a crash mid-write leaves a half-built run invisible
and readers fall back to the previous complete run. Chosen over a physical
alias-swap: same read-atomicity, no per-run index duplication.

**Command intent is a honeypot-native action enum, single-label per command.**
The taxonomy is 11 decidable-from-one-line action labels (`host_recon`,
`download_ingress`, `execute_payload`, `install_persistence`, `defense_evasion`,
`credential_data_access`, `account_manipulation`, `cryptomining`, `ddos_botnet`,
`benign_noise`, `unknown`) — not MITRE ATT&CK tactics. Tactics are session-scoped
goals and mislabel single post-login commands (a small model reaches for
`reconnaissance`/`initial_access`, which are pre-compromise category errors
in-session); the prior bare tactic enum with no per-label guidance was the main
driver of inconsistent labels. The set is the single source of truth in
`enrich/llm/schemas.py` (the IP behaviour matrix derives its intent columns and
its diversity denominator from it), it's advertised as a JSON-schema `enum` so a
grammar-constrained local decoder can only emit valid values, and the prompt
carries explicit INTENT RULES + few-shot examples + a "label by the terminal
objective" tie-breaker.

**Cache invalidation is hash-based, not manual.** `llm_config_hash` /
`embed_config_hash` are auto-derived from prompts + config + grounding data.
Manual `prompt_version` knobs got forgotten in ops; a hash can't be.

**Functionally-identical commands inherit instead of re-running the local LLM.**
Same-shape commands (literals → placeholders) inherit intent/description
from a canonical sibling. The local GPU saturated on thousands of near-identical
commands; this is the relief valve.

**Scale escape valves preserve the persisted geometry.** Windowed clustering
(rolling 30-day 6 h runs + a weekly all-time pass) and fit-only SVD reduction
both keep the full-dim centroids, novelty, and cross-run reference intact — only
the cheap label-assignment step is approximated. So a scale knob never
invalidates the reference set or shifts novelty scores.

**Naming cadence must track whichever pass minted the clusters, and mint+name
must share one flock hold, not two.** `name playbooks` just names the newest
completed cluster run — it carries no window concept itself. Item 58 found
that the weekly full-corpus mint (`cluster sessions --novel-pool
--window-days 0`) never called `name playbooks` afterward, so 83.8% of the
novel pool sat permanently unnamed: the 6h chain's own naming step only ever
saw ITS 30-day-windowed run. The first fix attempt added naming as a second,
separate `ExecStart` line — review caught that `flock` in this codebase is
acquired/released per `ExecStart=` line, not held for a unit's whole run, so
the gap between two lines let the 6h chain's own windowed mint+name pair
interleave and overwrite "latest run_summary," silently reproducing the same
bug. The shipped fix combines mint+name into one `flock`-wrapped shell
invocation (`mint && { name || true; }`) so the lock is held continuously
between them; any other unit's flock'd step blocks (no `-n`) rather than
racing in. Mint keeps hard-fail semantics unchanged; naming's failure is
swallowed so it still never blocks downstream IP/prune work.

**The privacy gate is fail-safe.** Untagged per-sensor data is treated as
confidential, propagated most-restrictive-wins, and confidential data never
reaches the cloud LLM or CTI feeds. Better to leak nothing and under-enrich than
to leak once.

**Cluster specificity uses un-smoothed IDF.** `ln(C/df)/ln(C)`, no Laplace
smoothing — the smoothed form caps singletons below 1.0, which contradicts the
analyst intuition that "appears in only this cluster" is the maximum signal.

**Cost + validation guardrails are first-class, not afterthoughts.** A per-day
cloud-LLM budget cap and output-side schema validation (intent clamped to a
closed enum, IOCs filtered to their surface shapes) were built early; both
caught real failures in production (a runaway escalation loop; hallucinated
non-IOC strings).

**ES backpressure rides on the client, not the call sites.** A heap-constrained
node trips the parent circuit breaker (429) at unpredictable places, and the
transport's millisecond retries are far too fast for the breaker to drain. Rather
than harden the handful of sites that happen to fail, a transparent
`ResilientClient` wraps the one object every read/write flows through
([`make_client`](../src/enrich/es_client.py)), so all requests — plus
`helpers.bulk`/`scan` — inherit "wait for heap to drain, then retry" with a shared
~1 h patience budget. The pipeline prefers waiting a long time over failing a
step. Chosen over transport/node subclassing (brittle across elasticsearch-py
versions) and over per-site try/except (doesn't scale to new sites or smaller
nodes).

**IP noise rescue is augmented-space euclidean, not pure-embedding cosine.** The
IP layer flagged ~70% of command-bearing IPs as HDBSCAN noise (every run,
`rescued=0`) while commands/sessions sit at 0.1–0.4%. The obvious fix — reuse the
command `rescue_threshold` (`rescue_noise_points`, pure-embedding cosine) — was
**measured wrong before shipping**: the IP pooled embedding is thin, so the IP
layer clusters on the *augmented* `[embedding ⊕ Tier1/Tier2/attribution]` euclidean
vector. Validation (`scripts/diagnose_ip_rescue.py`, production labels, no
re-cluster): outliers sit at pure-cosine 0.997 to nearest centroid but only 0.73 to
a random one (so the embedding *is* discriminative — rescue is warranted), yet a
pure-cosine rescue would reclaim ~99.5% vs only ~62% that are actually close in the
augmented space — the 38% gap being IPs the scalar blocks *correctly* separated.
So rescue runs in the augmented space HDBSCAN fit on, within a percentile of the
intra-cluster spread (`rescue_noise_points_augmented`). The default is the
**aggressive p99** because purity held flat across thresholds — rescued IPs match
their cluster's modal playbook ~94% and modal intent ~99.7% at p90 *through* p99 —
so p99 reclaims the most (70% → ~6% outliers) without quality loss. (Implementation
note: nearest-centroid distance uses the `‖a-b‖²` matmul identity batched over rows
— the naive 3-D broadcast needed 46 GiB at IP scale and would have OOM'd the live
run.)

- **Daily write-leaves split out of the 6h backward chain** — `intel refresh`,
  `apply-artifact-rules`, `track threshold-distributions`, and `mine file-crossref`
  are write-leaves (nothing in the pipeline reads their output *same-cycle*), so
  they moved to `dshield_prism-analytics.service` (daily 04:15, all soft-fail).
  Under the single shared flock this buys **cadence-reduction** (the lock is held
  for these 1×/day, not 4×) and an **honest soft-fail exit status** separate from
  backward's hard-fail model core — *not* parallelism (the mutex is unchanged).
  `escalate` stayed in backward: it is a write-leaf but reads *this-cycle*
  clustering novelty, so its cadence must equal the model's. Consequence to keep
  in mind: `intel refresh` is now daily, so the `intel_verdict_flip` finding's
  resolution is daily-grained (was 6h). Detection stays correct and single-count
  because both timers are wall-clock (`OnCalendar`) and phase-stable — the ~06:00
  backward pass always snapshots the fresh 04:15 verdict first; that guarantee
  breaks if either timer is switched to `OnUnitActiveSec`.

- **Unit attribution for run telemetry is stamped by systemd, not mapped by the
  console.** Each unit sets `Environment=PRISM_SYSTEMD_UNIT=%n`, which
  `enrich.ops.run_start` copies onto every `prism.ops` doc, so the console groups
  runs by unit with a pure ES read. The alternative — a console-side unit→verb
  table — was rejected because it is hand-maintained against `ExecStart` lines
  that do change (the analytics split moved four verbs in one commit), and it
  cannot distinguish a scheduled run from an operator's manual one. Cost: the
  field must be added to the `dynamic: strict` ops mapping *before* the writer
  deploys, so `run_start` retries once without `unit` on rejection — otherwise a
  wrong deploy order silently voids all telemetry, including the running banner
  and the health badge.
- **A unit's health cannot be read off "latest run per verb".** `prism.ops.verb`
  holds only the top-level argparse verb, so `backward` stamps `verb="mine"` for
  four distinct steps; the newest doc overwrites an earlier sibling's failure and
  the unit renders green. The `/health` unit panel therefore derives state from a
  separate windowed `status=failed` filter, and treats a `status=started` doc
  outside the heartbeat window as a ghost rather than a live run. Making `verb`
  finer-grained would fix this at the source but changes an established field's
  values mid-corpus, breaking `pipeline_cycle_health`'s latest-per-verb read.
  Everything in that panel is bounded to a 30-day window: unbounded, a verb
  dropped from a unit's chain keeps its final doc forever and pins the unit red.
- **A hunt's `enabled` flag gates writing findings, not loading it**, and hunts
  stay YAML files rather than moving into ES. Dropping disabled hunts inside
  `load_hunts` made the flag one-way — a hunt you cannot list is a hunt you
  cannot switch back on. Filtering only on the write path makes the toggle
  symmetric and lets an analyst *preview* a hunt (run the query, persist
  nothing) before committing it to the inbox; hence all shipped hunts are off
  by default. An absent `enabled` key still means `true`, so an upgrade never
  silently disables an operator's hand-written hunts. Keeping the definitions as
  files keeps `load_hunts` the single source of truth for CLI and console, so
  the console's toggle rewrites one line and swaps it in via `os.replace`
  instead of a `yaml.safe_dump` round-trip that would flatten the seeds'
  `description: |` blocks and inline comments — and because one unparseable
  file aborts the whole directory load, a torn write would take out the very
  page you'd use to fix it.
- **Console hunt edits re-dump the whole YAML; only the toggle stays
  surgical.** Create / edit / delete write the same `config/hunts/*.yaml`
  files the loader reads, so hunts stay git-diffable and `load_hunts` stays
  the single source of truth — but a full-document edit cannot preserve
  comments or `description: |` blocks, so `write_hunt` uses `yaml.safe_dump`
  and the UI warns before every save. Top-level keys the console doesn't
  know (`owner:`, `tags:`) are carried through rather than dropped. The loss
  is bounded to the rare, explicit case (a human saving from the builder)
  while `set_hunt_enabled` — the frequent one — keeps its byte-faithful
  single-line path. The authoring surface is a structured filter builder,
  never a raw-YAML textarea. An id from HTTP becomes a filename, so it is
  regex-sanitised whenever it *names* the file; an edit writing back to an
  existing path is gated on containment in `config_dir` instead, which is
  what keeps a legacy hand-written id editable. Every write re-runs the
  loader's own `validate_hunt_doc` before `os.replace` installs it.

- **Finding status mutations force one refresh per request rather than
  `wait_for` per document.** `prism.finding` is declared `refresh_interval: 5s`,
  so `es.index(..., refresh="wait_for")` paid up to 5 s *per document* — a
  31-item bulk inbox action measured 2m30s. Lowering the index's
  `refresh_interval` was rejected: it taxes every miner write to serve a
  read-your-write need that only the console's post-action reload has. An
  explicit `es.indices.refresh()` after the write gives the identical guarantee
  at one payment per request — sub-100 ms on a 1-shard, 0-replica index — and
  leaves the interval free to serve indexing throughput. The bulk path
  additionally collapses `2N` round-trips into one `mget` plus one `_bulk`. Two
  consequences are deliberate: a refresh failure is logged and swallowed
  (the write is already committed, and reporting a successful mutation as failed
  is worse than a briefly stale list), and an invalid `status` in a bulk request
  is now one HTTP 400 instead of N identical per-id errors under HTTP 200.

- **Structural predicates are decomposed into per-command sub-signals, not stored
  as the 7 composed booleans.** `eval_predicate_falsification.py` (item 29) computes
  its 7 predicates over a whole session's joined command text in one pass, but
  enrichment (`commands.py`) only ever sees one command at a time. Storing the 7
  composed booleans per command and OR-folding them at session-vector build time is
  only correct for the 3 pure evidence-presence predicates — `appliance_menu_only`
  is an AND-fold over every command, `multi_arch_targeting` needs the *distinct*
  architecture-token set pooled across commands (not just an any-token flag), and
  `key_write_immutability`/`hetero_target_fallback` each OR-pool two independent
  conditions before ANDing them. `predicates.py` stores the constituent regex
  sub-signals instead (`has_uname_m`, `arch_tokens`, `has_case_token`, `has_c2_launch`,
  `has_self_spread`, `is_appliance_verb`, `has_host_recon`, `has_key_write`,
  `has_immutability`, `has_multi_dir_cd`, `has_multi_tool_fallback`) and
  `lexical.build_session_predicate_vectors` recomposes the 7 predicates with each
  one's correct fold. Verified byte-for-byte against the reference implementation on
  all 148 labelled real eval sessions (`smoke_test_predicates.py`). The known gap:
  OR-pooling per-command sub-signals is not literally identical to a regex over the
  whole session's *joined* text in the rare case a match would only appear by two
  adjacent commands' text landing next to each other across the join boundary — an
  accepted approximation inherent to precomputing per command, and the falsification
  script's own patterns are written to match within one shell command.

- **A below-tau rescue only fires when the anchor's predicate signature is modal
  (>= 0.5), not merely nonzero.** `playbook_anchors.predicate_signature` is a
  per-predicate member-session frequency in [0, 1]. Gating "the anchor fires this
  predicate" on any nonzero frequency would let one incidental member session with,
  say, `key_write_immutability` open every unrelated below-tau session sharing that
  one predicate to a rescue against that anchor. `predicates.ANCHOR_MODAL_THRESHOLD`
  (0.5) requires the predicate to be the majority behavior among the anchor's sampled
  members before it counts as rescue evidence — this is on top of, not instead of,
  the hard evidence gate (an all-false session vector, or a missing/all-zero anchor
  signature, never rescues regardless of threshold).

## Dead-ends — measured and rejected

Don't re-attempt these without new evidence; each was tried against the live
corpus and recorded as a null result.

- **LLM-derived MITRE ATT&CK tactic/technique IDs** — the local model's
  technique mapping was unreliable best-guess work even after schema-validating
  every emitted ID against the vendored ATT&CK corpus (the prompt itself flagged
  it as "best-guess"). They were also measured *embedding-inert*: the E8.3
  strip-and-measure sweep produced byte-identical clusters with and without the
  MITRE codes in the embed input. Pulled entirely — generation, storage, embed
  context, metrics, and console surfaces. The only MITRE labels that remain are
  the **reference-corpus ground truth** (Atomic Red Team, `dshield.reference.*`),
  which are authored, not inferred.
- **MITRE ATT&CK tactics or techniques as the command-intent label set** — tactics
  are the wrong granularity (session-scoped goals, plus pre-compromise categories
  like `reconnaissance`/`initial_access` that never apply to a post-login
  in-session command), and a curated technique subset is a lossy many-to-one fit
  for single commands (`host_recon` alone spans several Discovery techniques).
  Replaced with the honeypot-native action enum (see *Decisions that still
  constrain*).
- **Cooccurrence text appended to the embed input** — regressed clustering ARI
  (badly on short commands). LLM-side cooccurrence grounding stays on; only the
  embed-text append was dropped.
- **Alternate embed-input orderings** (`command_first`, `command_only_with_tag`)
  — both regressed ARI vs. `prelude_first`. The knob ships as opt-in dead
  infrastructure for future experiments.
- **Late-fusion clustering** (fuse an embedding-HDBSCAN with a TF-IDF/SVD
  lexical-HDBSCAN) — won +0.085 ARI at *eval* scale, then **regressed at
  production scale** (−0.173 ARI on the live deploy; the lexical view fragments
  ~6× harder as the corpus grows, breaking the fusion). Reverted to plain
  HDBSCAN; `clustering_mode: late_fusion` stays only as inert opt-in
  infrastructure. This is the canonical "won at eval scale, lost at production
  scale" case — it's what motivated the production-scale eval gate
  ([evaluation.md](evaluation.md)). Don't re-enable it expecting an upgrade.
- **IP-cluster consolidation gate** — a multi-clause merge gate over-merged
  catastrophically on this corpus (its safety clauses are flat here: intel is
  off, one playbook dominates). Pure-embedding cosine doesn't separate IPs; the
  attribution/behavior block does.
- **Small-cluster surfacing** as a novelty premise — refuted; the corpus's small
  clusters were not where the interesting signal lived. A different lever
  (behavior-driven IP geometry) paid off instead.
- **Dropping artifacts that appear in >50% of sessions as "too generic"** — killed
  real campaigns where everyone shared one staging URL. Replaced with IDF
  weighting: commodity artifacts sink without being categorically dropped.
- **A high-volume finding kind** — shipped one that produced ~2,000 findings on a
  single corpus and retired it after one cycle. Not a bug; the detection itself
  was too noisy to be useful. (This is why miners now carry a per-run noise
  valve.)
- **Letting Elastic Fleet manage the indices** — Fleet wiped the indices it
  controlled. Setup now creates them manually so Fleet can't.
- **Computing command-grounding coverage on the console request path** — the
  Curation page tokenized (`parse_shell_line`) and counted the *entire* commands
  index in Python on every load. Fine at a handful of commands; ~15 min at 500k.
  It cannot scale from the console: the grouping key (the parsed shell token)
  isn't an ES field, so ES can't aggregate it — some process must read and
  tokenize every doc. Caching only hides it until the scan outruns the TTL. The
  page was retired; coverage must be precomputed by a scheduled pipeline job that
  writes one summary doc the console reads O(1) (`samples` gated on
  `releasable_filter` — literal command lines are per-sensor). Don't re-add a
  full-scan console endpoint.
- **Shipping the below-tau structural-predicate rescue tier** — item 30's rescue
  band `[rescue_tau, tau)` is wired end-to-end and correct, but measured on the real
  anchor library it buys coverage and nothing else, so `assignment_rescue_tau` stays
  at `assignment_tau` (0.94, a no-op). The three-arm ablation
  (`eval_assignment_faithful.py --anchors ... --rescue-tau-sweep`, gate on / forced
  True / forced False) over 70 scored eval sessions against the 19-anchor snapshot:
  lowering to 0.88 raises assigned rate 0.77 -> 0.99, and **every rescued session is
  assigned to the wrong playbook** — `n_rescued_correct` is 0 at every candidate,
  including the 10 rescues whose ground truth the snapshot library actually contains.
  Correct in-library assignments stay pinned at 20 while the denominator grows 20 ->
  30, so `accuracy_in_library` falls 1.0000 -> 0.6667. The predicate gate is also
  barely selective on this geometry: it blocks only 6-9% of what pure tau-lowering
  would rescue, against 34-52% on the earlier label-prototype prototypes — live anchor
  signatures are saturated (three of seven predicates fire on 71-87% of sessions),
  while label-grouped signatures were artificially tight. Only 9 of 19 snapshot
  anchors are armed at all (a signature at or above the modal threshold) and only 54
  of 70 sessions fold to any predicate evidence. Do not re-derive a `rescue_tau` from
  the label-prototype sweep — it does not read the snapshot and is not the production
  geometry. Reopen only behind a rarity-weighted or multi-predicate overlap rule
  (`docs/roadmap.md`).

### `assignment_tfidf_tau` is 0.50 — a valley placement, not a tuned value

The band's TF-IDF confirm cutoff moved 0.80 → 0.50. Measured corpus-wide over 8,825
band checks at the deployed `assignment_tau`, the traced `tfidf_cos` distribution is
**bimodal with an empty valley**: ~2,813 checks at 0.12–0.2 (genuinely dissimilar
sessions the band should reject), only **108 across the whole of 0.2–0.7**, then
~2,382 at 0.7–0.8 sitting immediately below ~3,522 confirms at 0.8–1.0. The old 0.80
cut a continuous 0.7–1.0 mass in half and discarded its lower 2,382 as false
conflations — sessions whose command-cluster bag profiles match the *assigned* members
of the same playbook to within ~1% on every common token.

Any value in roughly 0.25–0.65 produces the same partition, so this is a placement in
a gap, not an optimum on a curve. Do not nudge it; re-measure the distribution with
`scripts/eval_novel_pool.py`'s `band_tfidf_diagnosis` if the corpus changes shape.

**The band is kept, not retired.** On the 148-session labelled subset the 0.50 arm and
a band-disabled arm are indistinguishable (identical 92/56 assigned/novel, macro-F1
0.4212 vs 0.4181 inside overlapping CIs), which reads as "the band does nothing". That
reading is wrong: the labelled subset contains **one** band check below 0.5 while the
corpus contains **2,813** below 0.2. The band still rejects that entire low mode; the
labelled sample simply contains none of it.

Labelled evidence for the change is a **non-result in both directions** — macro-F1
0.4124 → 0.4212 against CI half-widths of ~0.08 — but it establishes no harm: purity
holds (0.9302 → 0.9348), no session changes label while assigned, and the 6 that flip
novel→assigned are 5 `host_recon` plus 1 `ssh_key_chattr_persistence`. The coverage
gain (~2,382 recovered checks) is corpus-measured and label-unconfirmed; the 148
labelled sessions produce only 17 band checks, ~500× under-sampling the band.

Note `scripts/eval_assignment_faithful.py` hardcodes `TFIDF_TAU` and does not read
config — both must be changed together or the replay silently reports old behaviour.
