# Deferred Work

Pre-existing issues surfaced incidentally during quick-dev reviews, not caused
by the story that found them. Not scheduled — collected for later attention.

## `boost_weight: null` must coalesce to 1.0 in the re-weighting consumer

Surfaced during review of `spec-slice-b-label-schema-v2.md` (2026-07-03). The
label validator allows `boost_weight: null` (the spec permits null on all four
provenance fields), but the renderer merge (`block.update(existing[sid])` in
`render_eval_set.py`) lets an explicit `null` overwrite the skeleton default of
`1.0` — so a merged block can carry `boost_weight: None`. Nothing reads the
field yet, so this is latent. When the B-power re-weighting step lands, its
consumer must coalesce `None → 1.0` (or reject explicit null at that point)
before any `sample_weight * boost_weight` math, or it will `TypeError` / drop
the sample.

## config/default.yaml has an unrelated local edit

Surfaced during review of `spec-retire-discover-page.md` (2026-07-01).
`elasticsearch.hosts` was changed from `https://localhost:9200` to
`https://so.tonystech.net:9200` in the working tree, predating that story's
baseline commit. Looks like local/environment-specific config, not something
meant to ship. Flagging so it doesn't get swept into an unrelated commit —
review and either commit deliberately or revert before it lands elsewhere.

## Console ignores the YAML `ops.pipeline_running_window_min`

Surfaced during review of `spec-health-badge-door.md` (2026-07-01). The
console's `load_config` never populated `AppConfig.ops`, so the site-wide
"pipeline running" banner has always used the `OpsConfig` default window (60m),
silently ignoring `config/default.yaml`'s `ops.pipeline_running_window_min`
(currently 2880 for the backfill phase). The badge work deliberately kept this
behaviour (only `cycle_stale_min` is read from YAML) to avoid changing the
banner as a side effect. Fixing it — making the console honour the YAML window —
is a one-line change to the `ops_fields` pluck in `console/src/console/_config.py`,
but it widens the banner's crashed-verb ghost window from 60m to 48h, so it's an
operator decision (matches the spec's Ask-First on `pipeline_running_window_min`).
Decide the intended console window, then wire it deliberately.

## Grounding-coverage report doc has no optimistic-concurrency guard

Surfaced during review of `spec-grounding-precompute.md` (2026-07-25). The
`track grounding-coverage` job writes the single `latest` doc via a plain
`es.index()`, no `if_seq_no`/`if_primary_term`. The systemd timer's `flock`
serializes scheduled runs, but a manual CLI run racing the scheduled one has no
guard — whichever finishes last silently overwrites the other's report with no
conflict signal. Low likelihood in practice; add the optimistic-concurrency
check if manual/ad-hoc runs become common.

## Grounding-coverage worklists cap at 200 with no truncation notice

Surfaced during review of `spec-grounding-precompute.md` (2026-07-25). The
job's `max_list_len` (default 200, `src/enrich/config.py`) caps the
`needs_def`/`tldr_only`/`denied` lists it writes, but the Tune "Grounding" tab
stat bar shows the true uncapped count from `stats`, and neither
`console/src/console/web/js/grounding.js` nor `tune.html` surfaces a "showing
top 200 of N" notice when the list is truncated — a command ranked beyond 200
is invisible to the tab's search and reports as "no match" even though the
stat bar's total includes it. Unlikely to bite at current corpus sizes (real
distinct command-verb cardinality is low), but worth a UI notice or a higher
cap if it does. Related: the `denied` list also has no search/pagination UI,
unlike its two siblings — fine while denylist stays small, revisit if it grows.

## Grounding-coverage console/pipeline duplicate near-identical code

Surfaced during review of `spec-grounding-precompute.md` (2026-07-25). Two
minor DRY gaps, both cosmetic (correctness unaffected): (1)
`console/src/console/server.py`'s `tune_grounding_coverage_api` and
`health_grounding_coverage_api` both wrap `queries.grounding_coverage_summary`
in the identical try/except-degrade-to-JSON pattern — candidate for a shared
helper if a third consumer appears. (2) `health.js` and `grounding.js` each
independently render stat-cards for the same report doc with different visual
treatment (only the Tune version color-codes by threshold) — candidate for a
shared renderer if the Health version ever needs the same treatment.

## `dshield_prism-grounding-coverage.service`'s ExecStartPre flock looks like dead weight

Surfaced during review of `spec-grounding-precompute.md` (2026-07-25).
`ExecStartPre=/usr/bin/flock /var/lib/dshield_prism/.lock /bin/true` acquires
and immediately releases the lock before `ExecStart` re-acquires it (blocking)
anyway — doesn't appear to gate anything the blocking `ExecStart` flock
doesn't already handle. Possibly cargo-culted from another unit; worth
checking whether the other systemd units have the same pattern for a reason
before trimming it.

## `setup/scripts/destroy.sh` doesn't clean up the `recluster-full` timer/service

Surfaced (not caused) while extending `install.sh` for
`spec-grounding-precompute.md` (2026-07-25) — pre-existing gap, predates this
story. `destroy.sh` should probably tear down every unit `install.sh` installs,
including `dshield_prism-recluster-full.timer`/`.service`; noted while touching
the adjacent install list, not fixed here.

## Quality-metrics overhaul — deferred slices

Split out of the `spec-quality-metrics` kernel
(`_bmad-output/specs/spec-quality-metrics/`) during quick-dev routing
(2026-07-02). Slice A (operational gate over the existing eval set + a
whole-playbook novel holdout) is being built now as
`spec-operational-quality-gate.md`. The remaining capabilities are independently
shippable and deferred:

- **Slice B — Eval-set rebuild + reliability (CAP-6).** More playbooks than the
  current 6, minimum-examples-per-label floor, annotator agreement (inter- via
  ≤2 annotators / intra- via delayed re-label), statistical power sizing, and a
  versioned labeling protocol. Large single-operator labeling effort; mostly
  methodology, not code. Slice A consumes whatever labeled set exists; B raises
  its reliability.
- **Slice D — Drift measurement (CAP-4).** Net-new drift / no-drift eval set
  (new-command / new-geo / returned-dormant sequences + matched controls),
  drift precision/recall, and a findings-per-corpus-unit bound. Largest net-new
  labeling cost; kernel flags it as a candidate phase 2.
- **Slice E — Reproducibility hardening (CAP-7).** Formalize the two frozen,
  content-hashed geometries (eval-geometry labeled-only; production-geometry
  labeled-in-corpus) with recorded provenance + classification verification.
  Partly exists (`eval/production-snapshot-v1.jsonl.gz`,
  `eval/command-snapshot-v1.jsonl.gz`); Slice A reuses these. Deferred work is
  the provenance/verification discipline and the labeled-only geometry.
- **Slice F — Improvement loop (CAP-8).** The one-lever-per-iteration
  before/after workflow in `improvement-levers.md` plus a compare harness that
  runs the gate on a fixed snapshot hash and diffs metrics with bootstrap CIs.
  Reference menu already written; needs the harness + docs.

### Slice B sub-goals — split during quick-dev routing (2026-07-02)

Slice B (eval-set rebuild + reliability, CAP-6) was itself multi-goal. The
**reliability tooling** sub-goal (inter/intra annotator agreement scorer) is
being built now as `spec-slice-b-reliability-tooling.md`. The rest are
independently shippable and deferred:

- **B-power — Power/floor tooling.** A per-metric power / sample-size
  calculator (smallest operator-cared regression distinguishable from noise at
  a stated confidence) plus a minimum-examples-per-label floor wired into
  `eval_operational.py`'s macro gate — labels below the floor are reported but
  excluded from the gate to avoid noise-driven failures. Needs an operator input
  for the target regression size. Pure code.
- **B-schema — Label-schema v2 + provenance.** Extend `labels-v1.yaml` to carry
  label provenance (annotator id, timestamp, rubric version) and the recorded
  rare-class boost weight, then update `validate_eval_labels.py` and
  `render_eval_set.py` to read/preserve the new fields. The reliability and
  power tools can default the missing fields, so this is an enabling change they
  build on rather than a hard dependency.
- **B-protocol — Versioned labeling protocol + expanded labeling.** RUBRIC v2
  with documented tie-breaking / ambiguous-case handling and a versioned label
  set, plus the large single-operator effort to label materially more playbooks
  than the current 6 (oversampling rare/high-value behaviors). Mostly human
  labeling, blocked on the operator's labeling-budget decision (SPEC open
  question).

## HDBSCAN calls emit a sklearn 1.10 `copy`-default FutureWarning

Surfaced during review of `spec-operational-quality-gate.md` (2026-07-02). The
existing HDBSCAN call sites (`scripts/eval_clustering.py:392`,
`scripts/eval_production_scale.py`, `scripts/eval_command_scale.py`,
`src/enrich/clustering.py`) don't set `copy=`, so sklearn warns that the default
flips `False→True` in 1.10 — which, once the pin bumps past it, would change the
fit (input no longer mutated in place). Cosmetic under the pinned
`scikit-learn==1.8.0`, but set `copy=True` explicitly repo-wide before the next
sklearn bump so the clustering geometry doesn't shift silently. `eval_operational.py`
already sets it; the rest predate this story.

## late_fusion session clustering still materializes full corpus (texts + 2× embeddings)

Surfaced during review of `spec-backfill-embedding-scan-oom.md` (2026-07-02). The
backfill OOM fix chunk-streams the **active** assignment path
(`assign_runner._scan_window_embeddings`, float32 chunks — bounded). The
**dormant** `late_fusion` branch (`sessions.py` `run_cluster`,
`clustering_mode == "late_fusion"`) was only narrowed to float32 rows, not
chunk-flushed: `session_texts` holds every `command_stream_text` for the corpus,
`_core_docs` holds the whole corpus as a Python list, and `run_layer_clustering`
then re-buffers the same embeddings — so peak holds embeddings ~2× plus all texts.
Fine at today's scale and off by default (`clustering_mode` defaults to `hdbscan`),
but if late_fusion is ever enabled on the full (~90×) corpus this path can OOM on
text-heavy data. Fix: make the late_fusion path stream texts/embeddings in bounded
chunks (or a second streamed embedding pass) instead of full pre-materialization.
