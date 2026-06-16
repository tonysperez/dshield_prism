# Data privacy — never read confidential honeypot data

Per-sensor honeypot data is tagged `dshield.classification` (`public` |
`confidential`). Confidential data must **never** enter your context. The
pipeline gates its own cloud-LLM / CTI egress in code, but **the interactive ES
queries you run bypass those gates entirely** — they use the broad `.env`
credentials and return whatever you ask for.

Therefore: **every Elasticsearch search you run against any index that can hold
per-sensor records — raw events, the session / IP rollups, commands, findings,
anything cowrie-derived — MUST be bounded with the public-only filter so only
public docs come back.** Put this in the query's `bool.filter`:

```json
{ "term": { "dshield.classification.keyword": "public" } }
```

This is fail-safe: it returns only explicitly-`public` docs and excludes both
`confidential` and *untagged* records (untagged may be confidential — and the
pre-tagging corpus is untagged, so expect empty results there until it is
re-ingested). Never run an unbounded `match_all` / `_search` against a cowrie
data index. Indices that carry no sensor records and no `dshield.classification`
field (e.g. `prism.metrics`, ops / cluster-run indices) don't take the filter,
but when in doubt, add it. This mirrors `releasable_filter(cfg)` in
[`src/enrich/classification.py`](src/enrich/classification.py).

## Exception — eval labeling / triage

There is **one** deliberate, owner-sanctioned exception to the rule above: the
eval **labeling / triage** workflow (the divergent-pair triage + labeling
prompts under `eval/archive/semantic-clustering-claim/`). When run with `FLOW: confidential`, the interactive
agent **may read the `eval/confidential/` tree** — the divergent-pair MDs and
the confidential sessions they render — directly into context in order to make
keep/skip decisions and edit the per-pair frontmatter.

This is a knowing acceptance that confidential per-sensor data reaches the cloud
LLM for this task. It is scoped **only** to reading files under
`eval/confidential/` for eval triage/labeling. It does **not** relax anything
else: interactive ES queries against cowrie data indices still **must** carry
the public-only filter, and no confidential data may be forwarded to CTI feeds
or any other external service.

# Writes, egress, and destructive actions — operator-confirmed only

The privacy rule above governs **reads**. These govern **writes and what leaves
the box** — equally load-bearing, and the source of the worse failures.

- **Never run corpus-wide writes or classification retags** (e.g.
  `backfill_classification.py --apply`, an `update_by_query` against a live
  cowrie index) without explicit operator confirmation. A `--whole-corpus
  --classification public` run on a mixed corpus silently relabels confidential
  data releasable. Mislabeled `public` data is the egress hole, not just a
  cosmetic tag.
- **Never generate a committed/published artifact from the live corpus without
  proving it's public-only** — snapshot/anchor captures
  (`capture_anchor_snapshot.py`, `refresh_production_snapshot.py`) recompute from
  whatever the classification filter matches. If the live tags are wrong, the
  artifact ships confidential-derived data into git (and possibly GitHub). Verify
  the source data's classification *before* capturing, and treat
  confidential/untagged-derived data as non-releasable.
- **Never run destructive or production-mutating commands** — `pipeline
  --force`, `purge lifecycles`, index wipes/reinit, anything that drops or
  rewrites live state — programmatically. List what would change, then hand back;
  the operator runs it.
- When in doubt about whether an action writes, egresses, or destroys, **stop and
  ask**. These are not reversible by re-running a read.

# Git

**Never run `git commit`** (nor `amend`, `push`, or any history-finalizing command). The user always makes commits themselves. Staging (`git add`) is allowed *when explicitly asked* — that is the most you ever do. After staging, hand back to the user; do not commit on their behalf.

**Run all CI actions, but only just before handing work back for commit, and they must all pass.** This is mandatory before every commit, not optional. Run them via the `console/.venv` and fix anything that fails (lint *and* gates) before handing back. The full CI surface is the two workflows in `.github/workflows/`:

```bash
# ci.yml — lint + offline smoke gate (always)
console/.venv/bin/ruff check src scripts
console/.venv/bin/python scripts/run_smoke.py   # ES-independent smoke tests

# eval.yml — clustering quality gates (always run them all; the prod/command
# gates are path-scoped in CI but run them locally regardless)
console/.venv/bin/python scripts/eval_clustering.py \
  --baseline eval/baseline.json --no-json
console/.venv/bin/python scripts/eval_assignment.py \
  --baseline eval/baseline-assignment.json --no-json   # Option-A assignment gate
console/.venv/bin/python scripts/eval_assignment_prod.py \
  --baseline eval/baseline-assignment-prod.json --no-json   # real-anchor gate; SKIPs until the public anchor snapshot is committed
console/.venv/bin/python scripts/eval_production_scale.py \
  --snapshot eval/production-snapshot-v1.jsonl.gz \
  --baseline eval/baseline-prod-scale.json --no-json
console/.venv/bin/python scripts/eval_command_scale.py \
  --snapshot eval/command-snapshot-v1.jsonl.gz \
  --baseline eval/baseline-command-scale.json --no-json
```

If you add a CI job, add its local command here too so this list stays the
complete pre-commit checklist.

# Documentation maintenance

This repo's docs are organised by reader-need, not by chronology. Each doc
answers one question. Keep them that way; `docs/README.md` is the index.

| File | Audience | When to edit |
|---|---|---|
| `README.md` | New user (human) + portfolio reader | When the top-level pitch, highlights, install command, or showcase changes. It's the marketing tentpole — screenshots + lessons stay; trim toward ~200 lines, not below |
| `docs/architecture.md` | Anyone | When *how it works* changes — pipeline, the behavioral model, labeling, intel, findings. Describes current state, not history |
| `docs/operations.md` | Operators | When install, config, CLI verbs, the systemd cadence, backfill, or troubleshooting change |
| `docs/reference.md` | Agents working on the code | When indices, ECS schemas, stable ids, tunable knobs, triage rules, intel internals, finding kinds, or CI gates change |
| `docs/evaluation.md` | Anyone | When the eval set, a quality gate, or a headline measured finding changes |
| `docs/decisions.md` | Anyone | When a new load-bearing design choice lands, or a measured dead-end should be recorded so it isn't re-attempted |
| `docs/roadmap.md` | Anyone | Forward-only. Add new open items; remove items when they ship |
| `docs/README.md` | Anyone | Only when a doc is added or removed |

`console/README.md` and `eval/README.md` live next to the code they describe —
edit them when the console or the eval-set mechanics change.

## When work ships

1. Update the doc that owns the *current behavior* — usually
   `docs/architecture.md` (what it does) and/or `docs/reference.md` (the exact
   contract). Rewrite so the doc reads as current state; don't append a "what
   changed" log.
2. If the work establishes a load-bearing design choice — or settles a
   measured dead-end — add a terse entry to `docs/decisions.md`. This is the
   **one** place the "why" lives; keep it out of the other docs.
3. Remove the now-closed item from `docs/roadmap.md`; add any new open items.
4. If it changes eval methodology or a headline measured result, update
   `docs/evaluation.md`.
5. Run the cross-reference check (below).

## The detail rules

The granular guidance — **what to prune** every edit, **what to keep**,
cross-reference conventions, and per-doc **size targets** — lives in
[`docs/doc-maintenance.md`](docs/doc-maintenance.md). Read it before a
non-trivial doc edit. In short: cut postmortems, phase tags, dated snapshots,
and meta-commentary; keep current behavior, file pointers, stable ids/defaults,
and load-bearing constraints; verify links resolve after every edit.
