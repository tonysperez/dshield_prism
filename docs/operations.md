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

## Install (WIP)

Requires:
- ElasticStack + Fleet
   - Tested using SecurityOnion's managed ES. This is a very easy way to get a managed ES + Fleet.
   - Recommended 16GB RAM and 4 CPU cores
- Elastic Agent installed on whatever device you want to ingest DShield logs from
- Local AI hosting to provide Nomic embedding and a small LLM. 8GB V/RAM tested/recommended to host the default Qwen3:8B
- Server to host the Prism pipeline and Prism Console. ES, Prism, and Prism Console can all be hosted on separate servers.
   - Tested running Prism on Ubuntu 24.04 LTS
   - Recommended 2GB RAM and 2 CPU cores for a small deployment, up to 8GB RAM and 6 CPU cores for larger deployments with frequent backfilling

One command. An interactive wizard writes `.env` + `config/local.yaml` for you
(no manual editing), then installs everything:

```bash
sudo bash setup/setup.sh
```

It prompts for the ES URL + credentials, the local LLM endpoint + models, your
sensor name(s) + `public`/`confidential` classification, and optional cloud /
intel API keys — **validating live that the ES credentials authenticate and that
the chosen models are actually loaded on the LLM box** (retry / continue / abort
on failure; `--no-verify` skips these checks) — then creates the service user,
installs to `/opt/dshield_prism`,
applies the ES templates + ingest pipelines + indices (created manually rather
than letting Fleet manage them, so Fleet can't wipe them), and installs the
systemd units. Idempotent — safe to re-run; existing config is kept unless you
pass `--reconfigure`.

- Just (re)write config without installing: `bash setup/setup.sh --configure-only`.
- Installer flags pass straight through, e.g. `sudo bash setup/setup.sh --no-console --ufw`.

The underlying steps stay runnable standalone under `setup/scripts/`:
`create-sensor-pipelines.sh`, `install.sh`, and `bootstrap-reference-corpus.sh`
(the external reference corpus is optional + best-effort — `install.sh` runs it
for you). Teardown lives at [`setup/destroy.sh`](../setup/destroy.sh).

**Final manual step** (Security Onion / Fleet, not scriptable from here): in
Kibana → Fleet, set each sensor's Cowrie integration `pipeline:` field to
`prism.cowrie.session.<sensor-name>` (printed at the end of setup).

The **console** installs alongside — self-contained, no dependency on the
`enrich` package. See [`console/README.md`](../console/README.md).

### Exposing the console on the LAN

The console has **no built-in authentication**, so the systemd unit binds it to
`127.0.0.1:8765` (loopback only). Serving it directly on `0.0.0.0` would leave
honeypot-derived data readable by anyone on the network. To reach it from other
machines, front it with a reverse proxy that terminates auth on the LAN
interface and forwards to the loopback port. Caddy is the shortest path (auto
HTTPS + basic auth in a few lines):

```
# /etc/caddy/Caddyfile — reachable at https://<server-lan-ip>
prism.internal.example {
    basicauth {
        analyst <bcrypt-hash>   # caddy hash-password --plaintext '...'
    }
    reverse_proxy 127.0.0.1:8765
}
```

The console unit stays loopback-bound and unchanged; only the proxy listens on
the LAN. Prefer this over binding the app directly — it gives you auth, TLS,
and access logs the app doesn't provide.

If you understand the exposure and still want the app itself on the LAN (e.g.
an already-authenticated segment), override the bind with a systemd drop-in so
it survives reinstall — never edit the shipped unit:

```bash
sudo systemctl edit dshield_prism-console   # writes …/override.conf
```
```ini
[Service]
ExecStart=
ExecStart=/opt/dshield_prism/console/.venv/bin/python -m console.cli serve \
    --host 0.0.0.0 --port 8765 --config /opt/dshield_prism/config/default.yaml
```

(The empty `ExecStart=` clears the unit's value before the override — systemd
requires this for `Type=simple`.) This bypasses auth entirely; only do it on a
trusted segment.

## Configuration

| File | Role |
|---|---|
| `config/default.yaml` | committed defaults — the documented baseline |
| `config/local.yaml` | per-deploy overrides (gitignored) |
| `.env` | secrets: ES credentials, provider API keys (gitignored) |

`setup/setup.sh` generates `.env` + a minimal `config/local.yaml` for you on a
fresh install (re-run with `--reconfigure` to regenerate); edit `local.yaml`
directly for anything the wizard doesn't prompt for.

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

Four timers, all serialised on `flock /var/lib/dshield_prism/.lock` (the manual
`pipeline` verb takes the same lock, so an ad-hoc run can't collide):

| Timer | Cadence | What it does | Failure mode |
|---|---|---|---|
| `dshield_prism-forward.timer` | every 30 min | `healthcheck --scope llm` → `enrich` → `rollup sessions` → `rollup ips` | LLM down → unit fails, retries next cycle |
| `dshield_prism-backward.timer` | every 6 h | full-corpus recompute: re-enrich/reembed stale → conditional re-pool → rollups → `cluster commands` → `reference-heal` → `assign_sessions` → `cluster sessions --novel-pool` → `cluster ips` → `prune-clusters` → `escalate` → `name playbooks` → `name ip-clusters` → `mine campaigns` → `track lifecycles` → `intel refresh` → `mine findings` | most steps soft-fail (log and continue). `mine findings` runs **last** so names + lifecycle snapshots exist before findings reference them |
| `dshield_prism-recluster-full.timer` | weekly (Mon 03:30 UTC) | full all-time re-cluster + reference refresh + retire dead anchors | a failed full pass marks the unit failed; aborts nothing else |
| `dshield_prism-grounding-coverage.timer` | daily (02:15 UTC) | `track grounding-coverage` (spec-grounding-precompute) — full `cowrie.commands` scan, classifies via `enrich.command_grounding`, overwrites the single report doc in `prism.metrics.grounding_coverage` that the console reads O(1) | hard-fail (no `-` prefix); last-good report doc stays in place so Health/Tune degrade gracefully, not to an error |

Forward verbs are watermark-driven and only touch new data; backward verbs do
full-corpus recomputes. The weekly full pass is the other half of the windowed-
clustering hybrid: the 6 h cycle clusters a rolling 30-day window
(`session.cluster_window_days`), the weekly pass re-pools the long tail and
refreshes the reference-centroid set the windowed runs score novelty against.
The grounding-coverage timer is isolated on its own cadence rather than folded
into forward/backward specifically because its full-corpus commands scan is
expensive (spec-grounding-precompute; see `docs/decisions.md`).

A fifth unit, **`dshield_prism-backfill.service`**, is installed but **not
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
| `track grounding-coverage [--dry-run]` | Full `cowrie.commands` scan; overwrites the single command-grounding coverage report doc the console reads O(1) (spec-grounding-precompute) |

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
   [`setup/scripts/create-sensor-pipelines.sh`](../setup/scripts/create-sensor-pipelines.sh)
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
[`setup/scripts/bootstrap-reference-corpus.sh`](../setup/scripts/bootstrap-reference-corpus.sh).

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
   `re-triage --backward`). `bless-cache --dry-run` shows live hashes. If cache
   rows carry an *old non-empty* hash (not empty-legacy), `bless-cache` stamps 0
   — see [Restamping a non-semantic config-hash change](#restamping-a-non-semantic-config-hash-change).
7. **`@timestamp` on enriched docs is event time, not write time** — don't use
   `now-1h` aggregations to confirm "did the pipeline just run." Check the
   SQLite cache `enriched_at` or run verbs with `--dry-run`.
8. **`circuit_breaking_exception` / `429` ("Data too large") storms, usually a
   step failing right after cluster assignment** → ES heap pressure on a
   constrained node, not a pipeline bug. The pipeline now senses parent-breaker
   pressure and pauses + retries (logs `"ES heap at N%, pausing…"`) for up to
   `elasticsearch.backpressure.max_wait_s` (1 h default) before failing. If it
   still can't keep up, the levers are: give the ES node more heap; lower
   `elasticsearch.backpressure.heap_high_watermark` so it pauses earlier; or
   reduce the heaviest aggregation's footprint via `session.specificity_store_cap`.
   Set `elasticsearch.backpressure.enabled: false` to opt out entirely.

## Restamping a non-semantic config-hash change

When an `llm_config_hash`-affecting edit lands that you've confirmed does **not**
change enrichment outputs (e.g. a comment/whitespace touch to a prompt or a
`src/enrich/data/commands/` grounding file), the cache would otherwise force a
full re-enrichment cycle. `bless-cache` only stamps *empty-legacy* rows, so it
reports `stamped_rows: 0` against rows carrying an old **non-empty** hash. To
accept those enrichments as current you restamp both stores — the SQLite cache
(drives skip-if-fresh) **and** the ES docs (carry
`dshield.cowrie.enrichment.llm_config_hash` for the backward/stale pass).

This is a corpus-wide production write. **Pause the pipeline/backfill first** so
`enrich` can't re-key mid-flight, and only proceed after confirming the change
is non-semantic. Substitute the old hash(es) you're collapsing and the live hash
(`bless-cache --dry-run` prints the live hash; the `GROUP BY` query in
[reference.md](reference.md#cache-and-config-hashes) lists what's present):

```bash
set -a && . ./.env && set +a        # ES_USERNAME / ES_PASSWORD
ES_URL="$(python -c 'import yaml,sys;print(yaml.safe_load(open("config/local.yaml"))["elasticsearch"]["hosts"][0])')"
OLD_HASHES='["<OLD_HASH_A>","<OLD_HASH_B>"]'   # gens being collapsed
LIVE_HASH='<LIVE_HASH>'                          # current llm_config_hash

# 1. Pre-check: confirm the row count before writing. Abort if it looks wrong.
curl -sS -u "$ES_USERNAME:$ES_PASSWORD" \
  "$ES_URL/prism.enriched.cowrie.command/_count" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"terms\":{\"dshield.cowrie.enrichment.llm_config_hash\":$OLD_HASHES}}}"

# 2. ES restamp (async; slices for throughput; proceed past version bumps).
curl -sS -u "$ES_USERNAME:$ES_PASSWORD" \
  "$ES_URL/prism.enriched.cowrie.command/_update_by_query?conflicts=proceed&slices=auto&wait_for_completion=false" \
  -H 'Content-Type: application/json' \
  -d "{\"query\":{\"terms\":{\"dshield.cowrie.enrichment.llm_config_hash\":$OLD_HASHES}},
       \"script\":{\"lang\":\"painless\",
         \"source\":\"if (ctx._source.dshield?.cowrie?.enrichment != null) { ctx._source.dshield.cowrie.enrichment.llm_config_hash = params.h }\",
         \"params\":{\"h\":\"$LIVE_HASH\"}}}"
# Poll the returned task id until completed:true, version_conflicts:0
curl -sS -u "$ES_USERNAME:$ES_PASSWORD" "$ES_URL/_tasks/<TASK_ID>"

# 3. SQLite cache restamp (path = worker.state_db).
sqlite3 /var/lib/dshield_prism/state.sqlite \
  "UPDATE enrichment_cache SET llm_config_hash='$LIVE_HASH'
   WHERE llm_config_hash IN (<OLD_HASH_A>, <OLD_HASH_B>);"

# 4. Verify both collapsed to the single live hash (ES count should be 0).
sqlite3 /var/lib/dshield_prism/state.sqlite \
  "SELECT llm_config_hash, COUNT(*) FROM enrichment_cache GROUP BY 1;"
```

No `dshield.classification` filter on the ES write **on purpose**: you're
restamping a config hash on every old-hash doc regardless of classification (a
public-only filter would strand confidential docs on the old hash). It's a
field write, not a read, so no per-sensor content leaves the box. Resume the
pipeline once verified.
