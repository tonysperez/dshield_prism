# Operations

Installing, running, and operating Prism. For what the knobs *mean* and the
field schemas, see [reference.md](reference.md); for how it works, see
[architecture.md](architecture.md).

- [Install](#install)
- [Configuration](#configuration)
- [Running it](#running-it)
- [systemd cadence](#systemd-cadence)
- [CLI verbs](#cli-verbs)
- [Backfilling a new sensor](#backfilling-a-new-sensor)
- [Workstation operations](#workstation-operations)
- [Smoke testing](#smoke-testing)
- [Troubleshooting — is anything actually wrong](#troubleshooting--is-anything-actually-wrong)

## Install

```bash
sudo bash setup/2-setup.sh
```

Idempotent. Requires `.env` + `config/local.yaml` filled in, and a reachable LLM
server. The script creates the service user, installs to `/opt/dshield_prism`,
and installs the systemd units. It manually creates the ES indices (rather than
letting Elastic Fleet manage them) so Fleet can't wipe them.

The **console** installs separately — it's self-contained with no dependency on
the `enrich` package. See [`console/README.md`](../console/README.md).

## Configuration

| File | Role |
|---|---|
| `config/default.yaml` | committed defaults — the documented baseline |
| `config/local.yaml` | per-deploy overrides (gitignored) |
| `.env` | secrets: ES credentials, provider API keys (gitignored) |

Override knobs in `local.yaml`; never edit `default.yaml` for a deploy. ES
credentials come from `.env` (`ES_USERNAME`/`ES_PASSWORD` or `ES_API_KEY`).
Provider API keys (`GREYNOISE_API_KEY`, `ABUSEIPDB_API_KEY`,
`ABUSE_CH_AUTH_KEY`, `VIRUSTOTAL_API_KEY`) are read from `.env`; a provider
silently skips itself when its key is unset. The full knob catalog is in
[reference.md](reference.md#tunable-knobs).

## Running it

All verbs run as the service user from the install dir:

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli <subcommand>
```

Verify connectivity, then run one enrichment pass:

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli healthcheck
sudo -u dshield_prism .venv/bin/python -m enrich.cli enrich
```

The systemd timers handle steady state — you rarely run verbs by hand except
for the [backfill runbook](#backfilling-a-new-sensor) and diagnostics.

```bash
systemctl list-timers 'dshield_prism-*.timer'
journalctl -fu dshield_prism-{forward,backward}.service
```

**Logging.** Verbs log to the journal/terminal **and** a rotating file
(`<log_dir>/cli.log`, 10 MB × 5; `PRISM_LOG_DIR` overrides). A failed run is
reconstructable from `cli.log`, not just journald. Per-command fallbacks in the
hot loop are rate-capped (one warning per failure-type per run + an aggregate
count) so a degraded ES/LLM doesn't write millions of log lines at scale.

## systemd cadence

Three timers, all serialised on `flock /var/lib/dshield_prism/.lock` (the manual
`pipeline` verb takes the same lock, so an ad-hoc run can't collide):

| Timer | Cadence | What it does | Failure mode |
|---|---|---|---|
| `dshield_prism-forward.timer` | every 30 min | `healthcheck --scope llm` → `enrich` → `rollup sessions` → `rollup ips` | LLM down → unit fails, retries next cycle |
| `dshield_prism-backward.timer` | every 6 h | full-corpus recompute: re-enrich/reembed stale → conditional re-pool → rollups → `cluster commands` → `reference-heal` → `assign_sessions` → `cluster sessions --novel-pool` → `cluster ips` → `prune-clusters` → `escalate` → `name playbooks` → `name ip-clusters` → `mine campaigns` → `track lifecycles` → `intel refresh` → `mine findings` | most steps soft-fail (log and continue). `mine findings` runs **last** so names + lifecycle snapshots exist before findings reference them |
| `dshield_prism-recluster-full.timer` | weekly (Mon 03:30 UTC) | full all-time re-cluster + reference refresh + retire dead anchors | a failed full pass marks the unit failed; aborts nothing else |

Forward verbs are watermark-driven and only touch new data; backward verbs do
full-corpus recomputes. The weekly full pass is the other half of the windowed-
clustering hybrid: the 6 h cycle clusters a rolling 30-day window
(`session.cluster_window_days`), the weekly pass re-pools the long tail and
refreshes the reference-centroid set the windowed runs score novelty against.

A fourth unit, **`dshield_prism-backfill.service`**, is installed but **not
enabled** — a manual one-shot for ingesting a historical backlog (see below).

## CLI verbs

`<verb> [<layer>] [--source <source>]`. Run as the service user (above). The
most-used verbs:

### Health + index management
| Verb | Does |
|---|---|
| `healthcheck [--scope es,llm,sqlite,cloud-conn,cloud,intel,all]` | Verify dependencies. Default `cloud-conn` is a zero-token round-trip; `--scope cloud` burns budget |
| `init-indexes [--source <s>] [--layer <l>] [--update-mapping]` | PUT indices from `setup/es-mappings/`. Idempotent. `--update-mapping` pushes **additive** changes only |
| `reference-heal` | Self-heal the external reference baseline (local-only, idempotent) |

### Enrichment + embeddings
| Verb | Does |
|---|---|
| `enrich [--dry-run] [--no-cloud] [--ignore-config-hash]` | One pass: read new command events, dedup, LLM-classify, embed, write |
| `reembed` | Re-embed from stored enrichment fields (smart-skip-if-fresh) |
| `re-enrich-stale` | Re-call local LLM on docs whose `llm_config_hash` drifted |
| `re-triage --backward [--window-days N]` | Re-evaluate `triage_reasons` against current rules (no LLM) |
| `bless-cache` / `backfill-shape` | One-shot legacy-cache / shape-hash stamping |

### Rollup + clustering (needs `.[cluster]` extras)
| Verb | Does |
|---|---|
| `rollup {sessions,ips}` | Build/refresh the session / IP rollup docs |
| `cluster {commands,sessions,ips,all} [--dry-run] [--refresh-reference\|--no-reference] [--window-days N] [--novel-pool]` | HDBSCAN per layer; per-doc novelty scored against the persisted reference set |
| `prune-clusters [--keep-runs N]` | Cap each cluster index to the newest N runs (reference generations preserved) |

### Labeling + mining
| Verb | Does |
|---|---|
| `assign_sessions` | Authoritative session labeling (nearest-anchor assignment + novelty) |
| `escalate` | Cloud-escalate locally-enriched docs by novelty + confidence band |
| `name playbooks [--force]` | Two-pass local-LLM naming for session clusters (never escalates) |
| `name ip-clusters` | Annotate IP cluster centroids with their dominant playbook |
| `mine campaigns [--kind behaviour\|infrastructure\|all] [--window-days N]` | FP-growth + shared-artifact campaign miners |
| `mine findings [--dry-run]` | Emit coverage / drift / discovery findings into `prism.finding` |
| `track lifecycles [--dry-run]` | Snapshot per-run lifecycle state; retire long-silent artifacts |

### Intel
| Verb | Does |
|---|---|
| `intel refresh [--force]` | Walk artifact rollups, dispatch through enabled providers, write merged verdicts. Honors per-kind TTL unless `--force` |
| `intel backfill` | Like refresh but always bypasses the TTL (after wiring a new provider) |
| `intel reapply-rules [--dry-run]` | Re-derive verdicts from already-persisted data — zero upstream calls |
| `budget` | Print today's cloud-LLM spend, cap, calls, token totals |

### Orchestration
| Verb | Does |
|---|---|
| `pipeline [--continue-on-error] [--no-cloud] [--dry-run]` | Run every stage in order |
| `pipeline --backfill` | Historical-backfill safe mode (see below) |
| `pipeline --force --yes` | **Destructive** — wipes every processed ES index + SQLite, then runs |
| `reset [--cache] [--watermark] [--if-stale] [--yes]` | Clear local SQLite state. `--if-stale` is the backward chain's conditional re-pool gate |
| `purge lifecycles [--yes]` | **Destructive** — wipe + recreate lifecycle/findings/campaign/anchor indices |

## Backfilling a new sensor

The pipeline is built for steady-state forward operation. A historical backlog
(a multi-month/-year archive) is bulk and out-of-time-order — the one mode with
no safe forward path — so `pipeline --backfill` quarantines the temporal steps:
it full-rescans `enrich` (the per-command cache skips re-LLM on already-enriched
commands), clears the rollup watermarks for a full re-pool, forces an all-time
re-cluster, and **drops** `track lifecycles` + `mine findings` (they'd stamp
backfill wall-clock onto old activity and flood the inbox).

**Before any data lands**

1. **Name the sensor and verify it's unique.** Cowrie doesn't emit a sensor
   field, so `observer.name` must be stamped at ingest, per sensor — it's the
   `_id` namespace, and a `default` collision silently merges two sensors'
   sessions on upsert. Use
   [`setup/1-create-sensor-pipelines.sh`](../setup/1-create-sensor-pipelines.sh)
   (prompts for `name:classification`), then point that sensor's Fleet Cowrie
   integration `pipeline:` field at `prism.cowrie.session.<name>`. Pick a
   `public`/`confidential` classification per sensor — see
   [reference.md](reference.md#data-classification-privacy-gate).
2. **Disable intel + cloud for the phase** (`intel.enabled: false`,
   `cloud.enabled: false`). Intel verdicts are as-of-now and anachronistic on
   historical data; cloud escalation would burn its budget on backfill novelty.
   `pipeline --backfill` warns if either is on.
3. **For a large pooled corpus, set `ip.full_recluster_weekly: true`** so the
   6 h chain runs the cheap incremental IP assign instead of the O(n²) full IP
   fit every cycle.

**Run it as a service** (a bulk backfill runs for hours/days; an SSH disconnect
must not kill it):

```bash
sudo systemctl start dshield_prism-backfill    # one-shot `pipeline --backfill`
journalctl -fu dshield_prism-backfill          # watch; Ctrl-C just detaches
sudo systemctl stop dshield_prism-backfill     # abort if needed
```

Starting the unit stops the three timers for the duration (`Conflicts=`); they
don't auto-restart by design. Re-run the unit as more of the archive lands.

**After the backfill completes**

```bash
# refresh references from the final corpus (forward novelty scores against these)
cluster sessions --window-days 0 --refresh-reference
cluster ips --window-days 0 --refresh-reference
prune-clusters                       # backfill produces many runs; keep newest 5
pipeline                             # one normal run to build the forward findings/lifecycle layer
sudo systemctl start dshield_prism-{forward,backward,recluster-full}.timer
```

Treat any intel minted later as as-of-now; don't read backfilled drift /
verdict-flips as signal. If you used `pipeline --force --backfill` (a
wipe-and-rebuild rehearsal), it also wipes the Tradecraft reference corpus —
re-bootstrap with
[`setup/3-bootstrap-reference-corpus.sh`](../setup/3-bootstrap-reference-corpus.sh).

## Workstation operations

Two installs are usually in play: the **git checkout** (edits land here; picked
up by `console/.venv` via the editable install) and **`/opt/dshield_prism`**
(what the timers run — stale until redeployed). The user deploys; agents never
run `pipeline --force` programmatically. Two snags when running verbs from a
workstation:

1. No `pipeline` console-script in `console/.venv` — use `python -m enrich.cli`.
2. `local.yaml` points `worker.state_db` at a path the workstation user can't
   write. Override via `PRISM_LOCAL_CONFIG` pointing at a *merged* config
   (copy `local.yaml`, append a `worker.state_db: /tmp/...` redirect) — the
   loader uses the override as the entire `local.yaml`, so merge, don't replace.

**Reading ES directly** (self-signed cert → `-k`), bounded with the public-only
filter for any cowrie data index:

```bash
ES_USER=$(grep ES_USERNAME .env | cut -d= -f2); ES_PASS=$(grep ES_PASSWORD .env | cut -d= -f2)
curl -ksS -u "$ES_USER:$ES_PASS" "$ES/_cat/indices/*cowrie*?v&s=index"
```

**Run the console locally:**

```bash
console/.venv/bin/dshield_prism_console serve --port 8765 --host 127.0.0.1 & disown
# restart (busts the 60s insights cache):
pkill -f "dshield_prism_console serve"   # exits 144 on success — ignore
```

**After a manual `cp`/`rsync` redeploy on SELinux-enforcing hosts**
(RHEL/Rocky/Oracle Linux and derivatives), new files inherit the wrong security
context and systemd is refused on reads — fix with
`sudo restorecon -Rv /opt/dshield_prism/`.

## Smoke testing

ES-independent smoke tests live at `scripts/smoke_test_*.py` (also reachable via
`scripts/run_smoke.py`). Each imports a pure function from `src/`, feeds
synthetic inputs, asserts via a local `check()`, exits 0/1 — no ES or LLM calls.
When adding a feature with a pure-function core, add a smoke test next to the
others. Persistent read-only live-ES diagnostics live at `scripts/diagnose_*.py`
and are safe to schedule.

The full pre-commit CI surface (lint + smoke + eval gates) is in
[reference.md](reference.md#ci-gates).

## Troubleshooting — is anything actually wrong

1. **No playbooks in console** → check session-cluster centroids for
   `playbook_name`. None → `name playbooks` didn't run; run it manually.
2. **Fewer clustered docs than expected** → refresh-interval race; confirm by
   counting docs with `cluster.id` vs with `embedding`.
3. **No campaigns** → not necessarily a bug. If IPs each run a single playbook
   (brute-force-dominated data) or too few sessions have extractable artifacts,
   both miners legitimately return zero.
4. **`name playbooks` raises "No cluster docs found"** → previous `cluster
   sessions` didn't finish or writes aren't visible; refresh the index, retry.
5. **`bulk` error like `'PING' is not an IP string literal`** → the LLM
   hallucinated a non-IOC; the schema validator in `src/enrich/llm/schemas.py`
   filters these — extend it for the new variant.
6. **A config edit seems ignored** → either `worker.cache_auto_invalidate:
   false`, or the change is forward-only (use `re-enrich-stale`/`reembed`/
   `re-triage --backward`). `bless-cache --dry-run` shows live hashes.
7. **`@timestamp` on enriched docs is event time, not write time** — don't use
   `now-1h` aggregations to confirm "did the pipeline just run." Check the
   SQLite cache `enriched_at` or run verbs with `--dry-run`.
