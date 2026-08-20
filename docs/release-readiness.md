# Release Readiness Review

Date: 2026-08-20

Scope: release-blocking review. This review is intentionally narrower than the full roadmap: it records issues that could undermine the security story, privacy guarantees, install experience, or reviewer confidence at release time.

All P0 and P1 items found by the review have been fixed. P2 (polish) items remain open and are tracked below.

## Resolved — P0 (release blockers)

- **Cloud co-occurrence could leak confidential raw commands.**
  `fetch_cooccurring_commands()` (`src/enrich/sources/cowrie/commands.py`) now
  bounds every query with `releasable_filter(cfg)`, plus an `observer.name`
  scope when the caller knows a single sensor produced the anchor command
  (`_single_sensor`, fed by `iter_command_events()`'s `_source` projection —
  see the classification fix below). Covered by
  `scripts/smoke/smoke_test_cooccurrence_privacy_gate.py`.
- **Write-up cloud path had no server-side classification gate.** `anchor`/
  `scope` in `POST /api/writeup` are client-supplied JSON, never resolved
  server-side against ES by stable ID, so nothing could prove the content was
  explicit-public before cloud egress. Cloud escalation for write-ups is now
  refused at the route (`console/src/console/server.py`) and hard-disabled in
  `console/src/console/writeup.py::call_cloud`, documented in `README.md` and
  `console/README.md`. Re-enabling needs server-side anchor/scope resolution
  by stable ID plus a classification proof — not yet built.

## Resolved — P1

- **Fresh command classification was dropped.** `iter_command_events()`'s
  `_source` now includes `dshield.classification` and `observer.name`; the
  existing aggregation code was already correct, it just never received the
  field. Covered by `scripts/smoke/smoke_test_cooccurrence_privacy_gate.py`.
- **Multi-sensor session reads used raw session IDs.** The rollup read path
  (`_iter_closed_sessions`, `_fetch_session_events`, `run_rollup` in
  `src/enrich/sources/cowrie/sessions.py`) is now sensor-qualified end to end,
  so a raw `cowrie.session_id` collision across two sensors can no longer
  merge into one corrupted rollup doc. Covered by
  `scripts/smoke/smoke_test_session_multi_sensor.py`. Console/graph-layer
  session lookups downstream of the rollup are still raw-id-only and correct
  only for a single-sensor deployment — tracked as an open item in
  [roadmap.md](roadmap.md).
- **Committed production snapshots weren't public-only.**
  `scripts/refresh_production_snapshot.py` and
  `scripts/refresh_command_snapshot.py` now filter on
  `enrich.classification.explicit_public_filters(cfg)` (hoisted out of
  `scripts/capture_anchor_snapshot.py`, which already had this pattern),
  print a skipped-non-public count, and refuse to write an empty snapshot.
- **Console was documented as read-only but writes ES and local YAML.**
  `console/README.md` and `docs/reference.md` now describe it as read-mostly,
  list the actual mutation routes (finding status/notes, artifact rules,
  hunts, grounding denylist), and call out the lack of auth/CSRF.
- **Systemd hardening blocked the console's advertised writes.**
  `hunts.config_dir` (`config/default.yaml`) now points at
  `/var/lib/dshield_prism/hunts`, inside every unit's `ReadWritePaths`, seeded
  on install from the shipped starter hunts (`setup/scripts/install.sh`). The
  command-grounding denylist write path (`src/enrich/command_grounding.py`)
  now honors a `PRISM_STATE_DIR` env var, set identically by every unit in
  `systemd/*.service`, redirecting it to
  `/var/lib/dshield_prism/command_grounding/denylist.yaml` (also seeded on
  install) so the pipeline's reads and the console's writes can't split-brain.
  Covered by `scripts/smoke/smoke_test_grounding_state_dir.py`.
- **Setup/install could expose local secrets or private artifacts.**
  `.gitignore` now excludes `*.bak`; `setup/scripts/install.sh`'s deploy rsync
  now excludes `*.bak`, `eval/`, and `.agents/`.

## P2 Polish

### Known Front-End XSS Cleanup Is Still Open

The roadmap already documents unresolved `innerHTML` risks:

- `docs/roadmap.md:111`

One live sink still injects raw error text:

- `console/src/console/web/js/findings.js:1663`

Impact: this is the kind of issue a security reviewer will search for first.
Even if exploitability is limited today, leaving a known XSS cleanup weakens the presentation.

Required fix: replace the remaining raw interpolation paths with DOM/textContent
rendering, centralize escaping, and add a simple guard for unsafe `innerHTML`
use in CI.

### Python Package/Wheel Surface Is Not Release-Grade

Runtime code loads nested command-grounding data:

- `src/enrich/command_grounding.py:47`

But package data only includes one shallow JSON glob:

- `pyproject.toml:107`

Impact: editable installs hide missing-package-data problems. A reviewer trying
a clean wheel install can hit missing runtime files even though local smoke
tests pass.

Required fix: include recursive package data for `src/enrich/data/commands/**`
or move mutable/default data into an install-safe application data directory.
Add a CI job that builds a wheel, installs it into a clean venv, and exercises
the command-grounding imports/data loads.

### Documentation Drift

Known examples:

- `config/default.yaml:253` contains a malformed duplicate
  `assignment_tfidf_tau: float = 0.50` before the real value at
  `config/default.yaml:347`.
- `setup/scripts/bootstrap-reference-corpus.sh:18` and
  `setup/scripts/install.sh:592` refer to `docs/reference-corpus.md`, which is
  not present.

(The `console/README.md:15` "no dependency on `enrich`" claim was fixed as
part of the P1 console-read-only pass above.)

Required fix: remove the duplicate config key and add link/duplicate-key
checks to CI.

## Verification

Full local CI surface (`CLAUDE.md`) run after the P0/P1 fixes, all green:

```bash
console/.venv/bin/ruff check src scripts
console/.venv/bin/python scripts/run_smoke.py                                 # 154 passed
console/.venv/bin/python scripts/eval_operational.py --baseline eval/baseline-operational.json --no-json
console/.venv/bin/python scripts/eval_clustering.py --baseline eval/baseline.json --no-json
console/.venv/bin/python scripts/eval_assignment.py --baseline eval/baseline-assignment.json --no-json
console/.venv/bin/python scripts/eval_assignment_faithful.py --no-json
console/.venv/bin/python scripts/eval_assignment_prod.py --baseline eval/baseline-assignment-prod.json --no-json
console/.venv/bin/python scripts/eval_production_scale.py --snapshot eval/production-snapshot-v1.jsonl.gz --baseline eval/baseline-prod-scale.json --no-json
console/.venv/bin/python scripts/eval_command_scale.py --snapshot eval/command-snapshot-v1.jsonl.gz --baseline eval/baseline-command-scale.json --no-json
```

Notes:

- No `.env`, `config/local.yaml`, or `eval/confidential` content was
  reviewed.
- No live Elasticsearch queries were run — the classification/sensor filter
  fixes are covered by offline smoke tests with fake ES clients, not a live
  corpus scan.
- The committed snapshots (`eval/production-snapshot-v1.jsonl.gz`,
  `eval/command-snapshot-v1.jsonl.gz`) were not re-captured — the refresh
  scripts' *query* now filters public-only for the next capture; the
  currently-committed files were unaffected by this change and still pass
  their regression gates.
- A wheel/package verification attempt was not completed successfully in the
  local venv, so the P2 package-release surface remains unverified.
