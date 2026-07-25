---
title: 'Precompute grounding coverage in the pipeline; restore stats to Health + command list to Tune'
type: 'feature'
created: '2026-07-01'
status: 'done'
context: ['{project-root}/_bmad-output/project-context.md']
baseline_commit: '90a7ed0f644c6e70a7bb87d4368fc010c75565a2'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Command-grounding coverage (which shell commands lack curated YAML / tldr entries) is analyst-valuable but cannot be computed on the console request path — it requires reading and Python-tokenizing the entire commands index (~15 min at 500k). Spec 1 deleted that scan. Coverage stats and the needs-definition worklist are currently unavailable.

**Approach:** Move the scan **off the request path** into a scheduled pipeline job that runs today's classification (`parse_shell_line` → needs_def / tldr_only / curated / denied, weighted by `occurrence_count`) **once per cadence** and writes a single summary doc to an ops/metrics-style index. The console then reads that one doc in O(1): **Health** shows the coverage stats; **Tune** gains a second tab reviving the command worklist + block/unblock. Because the grouping key is materialized once by the job, ES/console never re-scan.

## Boundaries & Constraints

**Always:**
- The expensive scan runs **only** in the pipeline job, on its own cadence — never in a console endpoint.
- The summary doc lives in an ops/metrics-style index (no per-sensor grain, e.g. alongside `prism.metrics`); the console reads it directly, O(1).
- **`samples` are literal command lines = per-sensor data.** The job MUST gate sample selection on `releasable_filter` / `is_releasable` — only public commands may contribute `samples` to the committed/console-readable doc. Counts may aggregate all data, but no confidential command string may land in the report doc.
- Reuse the classification logic parked in `src/enrich/command_grounding.py` (buckets, occurrence weighting, denylist) — rebuild it in the job, don't reinvent.
- Console reads gate normally; the report doc itself must be provably public-only before the console (or anything) surfaces it.

**Ask First:** (resolved during planning — recorded here for traceability)
- Cadence: **new CLI verb + its own systemd timer/service**, not folded into the existing forward/backward pipeline stages — isolates the expensive scan from the main pipeline's runtime.
- Doc lifecycle: **single latest doc, fixed id**, overwritten each cadence run — not per-run history.
- Block/unblock: **live write** to `denylist.yaml` via the existing `add_to_denylist`/`remove_from_denylist` (same as the deleted Curation page); the report doc catches up on the next scheduled job run — no queueing mechanism.

**Never:**
- No re-introduction of a full-scan console endpoint.
- No confidential/untagged command strings in the report doc's `samples`.
- No mapping change that would move clustering/eval baselines.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Cadence run | pipeline job fires | scans commands (in-code, gated), writes one summary doc {stats, needs_def[], tldr_only[], denied[]} to fixed id `latest` | job failure logged via `ops.py` run_start/run_finish; last good doc stays |
| Health stats | GET Health | reads summary doc, renders coverage stat bar, O(1) | no doc yet → "pending first run" |
| Tune curation tab | GET `/tune` grounding panel | reads summary doc; paginated/searchable worklist + block/unblock | no doc yet → empty state |
| Confidential corpus | mixed classifications | counts aggregate; `samples` only from public docs | untagged excluded (fail-safe) |
| Block/unblock | POST/DELETE denylist endpoint | writes `denylist.yaml` immediately via existing helpers | stats stay stale until next cadence run (expected, documented in UI) |

</frozen-after-approval>

## Code Map

- `src/enrich/command_grounding.py` — `parse_shell_line` (`:453`), `_load_command_data` (`:323`), `list_denied_commands` (`:114`), `add_to_denylist`/`remove_from_denylist` (`:289`/`:306`), denylist file `src/enrich/data/commands/denylist.yaml`. Reuse verbatim; unchanged since the console-scan deletion.
- `src/enrich/classification.py` — `is_releasable` (`:38`), `releasable_filter` (`:73`) — gate for `samples`.
- `src/enrich/config.py` — `OpsIndexes`/`OpsConfig` (`:1018-1045`) is the pattern to mirror for a new `GroundingCoverageConfig` (index default `prism.metrics.grounding_coverage`, doc id `latest`); hang off `AppConfig` (`:1103`).
- `src/enrich/cli.py` — `_build_parser` (`:849`); nested-subject pattern under `track` (`p_track` `:1340`, `track_sub` subparsers for `lifecycles`/`drift`) — add `track grounding-coverage` here.
- `src/enrich/ops.py` — `run_start`/`run_finish` (`:31`/`:58`) — job telemetry, same pattern as other pipeline jobs.
- `systemd/` — existing `dshield_prism-forward.timer`/`-service` etc. as the template for new `dshield_prism-grounding-coverage.timer`/`-service`.
- `console/src/console/queries.py` — `es_pressure` (`:1753`), `sensor_freshness` (`:1793`) — pattern for a new `grounding_coverage_summary(es, cfg)` O(1) doc-get.
- `console/src/console/server.py` — add `GET /api/health/grounding-coverage` (stats for Health), `GET /api/tune/grounding-coverage` (full worklist for Tune), `POST /api/tune/grounding-coverage/denylist`, `DELETE /api/tune/grounding-coverage/denylist/{token}`. Old shape for reference: `git show de42736^ -- console/src/console/health.py`.
- `console/src/console/templates/health.html` — no grounding section currently (confirmed removed); add a stat-bar section.
- `console/src/console/templates/tune.html` — tab strip `:130-134`, panel pattern `:136-153`, insertion point flagged at `:155-157`; add `data-tab="grounding"` button + `#tab-grounding` panel.
- `console/src/console/web/js/tune.js` — generic tab controller (`:12-21`); no changes needed, just register the new panel/module.
- `console/src/console/web/js/grounding.js` (new) — mirror deleted `curation.js` render logic (`git show de42736^ -- console/src/console/web/js/curation.js`), fetch the new O(1) endpoints instead of the old full-scan one.
- `console/src/console/web/js/health.js` — add coverage stat-bar fetch/render.
- `scripts/smoke/smoke_test_health_observability.py` — pattern for unit-testing the new offline classifier/job logic.
- `scripts/smoke/smoke_test_tune_page.py` — currently asserts `/api/health/commands*` are gone; update to assert the new routes exist.
- Old test shape for reference: `git show de42736^:scripts/smoke/smoke_test_health_commands.py`.
- `docs/decisions.md:231-238` — already records the "why precompute" rationale; no new entry needed, just confirm it stays accurate.
- `docs/reference.md:489-497`, `docs/architecture.md:236-238` — currently describe this as pending; update to current-state once shipped.

## Tasks & Acceptance

**Execution:**
- [x] `src/enrich/config.py` -- add `GroundingCoverageConfig`/`GroundingCoverageIndexes` (index default `prism.metrics.grounding_coverage`, `doc_id = "latest"`) hung off `AppConfig` -- never inline the index literal
- [x] `src/enrich/grounding_coverage_job.py` (new) -- job function: paginate `cowrie.commands`, classify via `parse_shell_line`/`_load_command_data`, weight by `occurrence_count`, bucket into needs_def/tldr_only/curated/denied, gate `samples` on `releasable_filter`, write single doc (id `latest`) to the configured index -- reuses old `health.py` scan logic (see `git show de42736^`), rebuilt off the request path
- [x] `src/enrich/cli.py` -- add `track grounding-coverage` verb invoking the job, wired through `ops.run_start`/`run_finish` for telemetry -- matches existing nested-subject CLI pattern
- [x] `systemd/dshield_prism-grounding-coverage.timer` + `.service` (new) -- own cadence, isolated from forward/backward pipeline stages
- [x] `console/src/console/queries.py` -- add `grounding_coverage_summary(es, cfg)` reading the single doc by id, O(1) -- mirrors `es_pressure`/`sensor_freshness`
- [x] `console/src/console/server.py` -- add `GET /api/health/grounding-coverage`, `GET /api/tune/grounding-coverage`, `POST`/`DELETE` denylist endpoints reusing `add_to_denylist`/`remove_from_denylist` -- block/unblock live-write, no queue
- [x] `console/src/console/templates/health.html` -- restore coverage stat-bar section reading the new stats endpoint
- [x] `console/src/console/templates/tune.html` -- add `grounding` tab button + `#tab-grounding` panel at the flagged insertion point
- [x] `console/src/console/web/js/grounding.js` (new) -- tab module: fetch worklist, render needs_def/tldr_only/denied lists, wire block/unblock buttons -- mirrors deleted `curation.js`
- [x] `console/src/console/web/js/health.js` -- fetch + render the coverage stat bar
- [x] `scripts/smoke/smoke_test_grounding_coverage_job.py` (new) -- offline (mock ES): classification bucketing, occurrence weighting, `samples` gated to public-only, single-doc write shape
- [x] `scripts/smoke/smoke_test_tune_page.py` -- update to assert the new grounding routes exist (currently asserts old routes are gone)
- [x] `docs/reference.md`, `docs/architecture.md` -- update from "pending" to current-state: new index, job cadence, endpoints

**Acceptance Criteria:**
- Given a cadence run completed, when I open Health, then coverage stats render instantly with no full-corpus scan.
- Given a mixed-classification corpus, when the report is written, then no confidential command string appears in any `samples` field.
- Given the report doc exists, when I open Tune's curation tab, then I can reach any needs_def entry (search/paginate) and block/unblock still works.
- Given no summary doc exists yet (first deploy, before first cadence run), when I open Health or Tune's grounding tab, then both render an explicit "pending first run" / empty state, not an error.
- Given I block a command via the Tune tab, when I check the report doc, then `denylist.yaml` reflects the change immediately but the report's bucket counts don't reclassify it until the next job run (documented, not a bug).

## Design Notes

Report doc shape (single doc, id `latest`):
```json
{
  "generated_at": "2026-07-25T00:00:00Z",
  "stats": {"total_unique_cmds": 0, "curated": 0, "tldr_only": 0, "needs_def": 0, "denied": 0, "total_corpus_occurrences": 0},
  "needs_def": [{"name": "...", "count": 0, "samples": ["..."]}],
  "tldr_only": [{"name": "...", "count": 0, "samples": ["..."]}],
  "denied": [{"name": "...", "count": 0, "samples": ["..."], "rationale": "..."}]
}
```
`samples` arrays are built only from docs matching `releasable_filter`; `count`/stats aggregate across all classifications regardless of tag (untagged included in counts, excluded from samples — same fail-safe posture as the read-side filter, applied here on the write side since this is pipeline code, not an interactive query).

## Verification

**Commands:**
- `console/.venv/bin/ruff check src scripts` -- expect: clean
- `console/.venv/bin/python scripts/run_smoke.py` -- expect: new grounding-coverage-job smoke test passes, tune-page smoke updated and passing
- Full CLAUDE.md CI list (eval gates) -- expect: no regressions (this feature doesn't touch clustering/assignment)

**Manual checks (if no CLI):**
- Run the new job once against a real (or fixture) ES cluster; inspect the written doc directly to confirm `samples` contains no confidential/untagged command strings.
- Load Health and Tune in a browser before/after a job run to confirm the "pending first run" → populated transition.

## Suggested Review Order

**Job: scan, classify, gate, write**

- Entry point — full-corpus scan, classification, privacy gate, and stat aggregation.
  [`grounding_coverage_job.py:46`](../../src/enrich/grounding_coverage_job.py#L46)

- Scan failure now propagates instead of silently overwriting the last-good doc (review-loop fix).
  [`grounding_coverage_job.py:94`](../../src/enrich/grounding_coverage_job.py#L94)

- Write path skips `es.index()` entirely on a failed compute, preserving the last-good doc.
  [`grounding_coverage_job.py:197`](../../src/enrich/grounding_coverage_job.py#L197)

**Privacy gate**

- `samples` gated on `is_releasable`; `counts`/stats aggregate every classification — the load-bearing constraint.
  [`grounding_coverage_job.py:46`](../../src/enrich/grounding_coverage_job.py#L46)

- Offline coverage of the gate across public/confidential/untagged.
  [`smoke_test_grounding_coverage_job.py:201`](../../scripts/smoke/smoke_test_grounding_coverage_job.py#L201)

**CLI + cadence wiring**

- `track grounding-coverage` verb dispatch — job invocation, dry-run, exit-code contract.
  [`cli.py:2021`](../../src/enrich/cli.py#L2021)

- New mapping registered under the existing `metrics` layer source, not a parallel one.
  [`cli.py:242`](../../src/enrich/cli.py#L242)

- Own cadence, isolated from forward/backward — hard-fail semantics now match the code.
  [`dshield_prism-grounding-coverage.service:1`](../../systemd/dshield_prism-grounding-coverage.service#L1)

**Index config (pydantic, both sides)**

- Pipeline-side index declaration — never inline the literal.
  [`config.py:1018`](../../src/enrich/config.py#L1018)

- Console-side mirror; `load_config` now actually wires YAML overrides through (review-loop fix).
  [`_config.py:275`](../../console/src/console/_config.py#L275)

**Console reads: O(1), no live scan**

- Single `es.get` by fixed id `latest` — the whole point of the precompute move.
  [`queries.py:1820`](../../console/src/console/queries.py#L1820)

- Health stats endpoint — thin wrapper over the same O(1) read.
  [`server.py:1047`](../../console/src/console/server.py#L1047)

- Tune worklist endpoint — same read, full doc for the tab.
  [`server.py:801`](../../console/src/console/server.py#L801)

**Block/unblock: live write, next-cadence catch-up**

- Add-to-denylist route — now exception-safe and rejects unaddressable `/`-bearing tokens (both review-loop fixes).
  [`server.py:811`](../../console/src/console/server.py#L811)

- Remove-from-denylist route — same exception-safety fix.
  [`server.py:840`](../../console/src/console/server.py#L840)

- UI is explicit that stats lag until the next job run, not instant.
  [`grounding.js:204`](../../console/src/console/web/js/grounding.js#L204)

**UI surfaces**

- Tune "Grounding" tab — worklist render, search, pagination, block/unblock wiring.
  [`grounding.js:258`](../../console/src/console/web/js/grounding.js#L258)

- Tune tab strip — new tab button + panel, follows the existing tab-controller pattern.
  [`tune.html:221`](../../console/src/console/templates/tune.html#L221)

- Health stat-bar section — restores what the deleted Curation page used to show.
  [`health.html:224`](../../console/src/console/templates/health.html#L224)

**Tests (peripheral)**

- Full job test suite, including the three review-loop regression cases (scan-failure, malformed-doc, dedup).
  [`smoke_test_grounding_coverage_job.py:396`](../../scripts/smoke/smoke_test_grounding_coverage_job.py#L396)

- Updated to assert the new routes exist (previously asserted the opposite).
  [`smoke_test_tune_page.py:1`](../../scripts/smoke/smoke_test_tune_page.py#L1)
