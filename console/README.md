# dshield_prism_console

Browser-based, read-only investigation console for the enriched DShield/Cowrie
indices produced by the `enrich` pipeline in the parent repository.

Search any IOC — IP, session id, command sha256, raw command text, campaign
name, cluster id, ASN, country code — and see it plus its first-
degree neighborhood as an interactive node-link graph. Click a node to fill the
detail panel. Double-click to expand its neighbors into the existing graph
without losing position. Click links inside the detail panel to pivot to that
IOC.

## Install

Self-contained — no dependency on the parent `enrich` package.

```bash
cd console
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

By default the console reads the parent repo's `config/default.yaml` (+
`local.yaml` override) and `.env` so it Just Works in-repo. To point it at
configs elsewhere, set `PRISM_CONFIG=/path/to/default.yaml` (or pass
`--config`) and optionally `PRISM_ENV=/path/to/.env`. The
`PRISM_*` env vars are honored as fallbacks.

Only the `elasticsearch.*` block of the YAML is required; all other keys
(llm, worker, cloud, …) are ignored. ES credentials come from `.env`
(`ES_USERNAME`/`ES_PASSWORD` or `ES_API_KEY`).

## Run

```bash
dshield_prism_console serve --open
```

Defaults to `127.0.0.1:8765`. Pass `--config config/local.yaml` if you want a
non-default config path. `--open` launches the system browser.

Healthcheck (no server needed):
```bash
dshield_prism_console healthcheck
```

## What you can search

The single search box accepts any of:

| Pattern | Resolved as |
|---|---|
| `1.2.3.4` / `2001:db8::1` | IP |
| 64 hex chars | command (by sha256) |
| 12 lowercase alnum | session id |
| integer (e.g. `42`) | cluster id (you pick command / session / ip from suggestions) |
| `AS12345` | ASN |
| 2-letter ISO country code | country |
| anything else | free-text — searches `process.command_line`, `playbook_name`, and the multi-session campaigns index |

## Architecture

* **Backend**: FastAPI + the `elasticsearch` Python client. Self-contained
  YAML + .env loader (reads the parent repo's `config/default.yaml` by
  default, but has no Python dependency on `enrich`). Strips 768-dim
  embeddings server-side; they never reach the browser.
* **Frontend**: vanilla JS with a custom `<canvas>` graph renderer — no
  framework, no build step, no CDN. Loads from `web/` (`css/`, `js/`).
* **State**: read-only against ES — the console never writes to it. Local YAML
  files are the sole exception: the grounding denylist, and hunt files, which
  the Hunts page creates, edits, deletes and toggles.

Pages:

| Path | Page |
|---|---|
| `/inbox` | **Findings inbox** — the default landing (`/` redirects here). Drift, novel-behavior, and coverage findings with a facet rail (score / age / IP-count band / intent / intel verdict) and a new → ack → confirmed status flow |
| `/graph` | **Investigation graph** — search any IOC and pivot through its first-degree behavioral neighborhood as a node-link graph; detail panel with inline **compare** and a copy-ready **write-up** builder |
| `/explore` | **Longitudinal lifecycle list** — one row per **playbook / session-cluster / IP-cluster / campaign / operation** (entity selector), each with its own time-flipped activity band on a shared adaptive axis, a live-period strip, and an `interest` composite ranking. Window selector (30/90/180d · all · custom, default 90d), all/recurring + alive/dead filters, sort lens; click a row to open it in the graph |
| `/hunts` | **Hunts** — YAML-defined AND-combined session filters, each with an enable toggle (gates whether it writes findings; all ship off) and a **Preview** that runs the query and shows matching sessions without saving anything. A filter builder creates, edits and deletes the hunt YAML files themselves — no raw-YAML escape hatch, so an invalid clause cannot be composed. Plus a **Tradecraft Matches** view ranking sessions against the Atomic Red Team reference corpus |
| `/tune` | **Tune** — command-grounding coverage, the artifact-rule curation surface, and the grounding denylist |
| `/health` | **Health** — corpus-summary stat bar, index freshness, clustering performance, ES heap pressure, per-sensor breakdown, and **Pipeline & schedule**: one row per systemd unit with a tooltip of what it does, its `OnCalendar` cadence, last run, and whether it is running, expanding to the steps that ran under it |
| `/artifact/{ip,url,hash}/…` | Standalone artifact detail pages |

Legacy deep links still resolve as 302s: `/findings` → `/inbox`; `/history`,
`/browse`, `/insights` → `/explore`; `/compare` → `/graph` (compare is now an
inline panel); `/curation` → `/tune`.

API endpoints (representative — see `server.py` for the full set):

```
GET  /api/health                         # ES / LLM / SQLite / cloud / intel status
GET  /api/health/overview                # corpus-summary stat bar (IPs / Sessions / Commands / Playbooks / Clusters / Outliers)
GET  /api/findings                       # findings inbox (faceted)
GET  /api/finding/{id}/detail            # one finding + its evidence
POST /api/finding/{id}/status            # new → ack → confirmed
GET  /api/history?entity=playbook&window=90d&sort=interest   # entity∈{playbook,session_cluster,ip_cluster,campaign,operation}; window∈{30d,90d,180d,all,custom} (+&start=&end= ISO); state∈{all,live,dead}
GET  /api/search?q=...                    # IOC / free-text resolver
GET  /api/ioc/{type}/{id}                 # IOC detail
GET  /api/ioc/{type}/{id}/neighbors?limit=50&require_login=&require_commands=
GET  /api/cluster/{kind}/{cid}/members
GET  /api/hunts                           # every hunt incl. disabled, + finding counts
POST /api/hunts                           # author <config_dir>/<id>.yaml, always enabled:false -> 201 (409 on a clash)
PUT  /api/hunts/{id}                      # rewrite that hunt's own file (name/description/filters); `enabled` and unknown keys survive
DELETE /api/hunts/{id}                    # unlink the YAML; the findings it already wrote stay in the inbox
POST /api/hunts/{id}/preview?limit=100    # run one hunt, return matching sessions + true total, write NOTHING
POST /api/hunts/{id}/toggle               # {"enabled": bool} -> rewrites that key in the hunt's YAML (400 if not a bool)
POST /api/hunts/run                       # writes findings for enabled hunts only
GET  /api/tune/grounding-coverage
POST /api/compare/explain                 # inline cluster / playbook / campaign compare
POST /api/ask                             # natural-language Q&A (parent LLM config)
POST /api/writeup                         # copy-ready report (defanged; txt / md / csv / json)
```

Where `type` ∈ `ip session command command_hash playbook campaign
command_cluster session_cluster ip_cluster asn country`. `playbook` is
the LLM-named session cluster (anchored by
`playbook_id` = `sescl-<16hex>`, content-hashed over the member-session-id set); `campaign` is the multi-session
pattern mined by `mine campaigns` (anchored by `campaign_id` =
`cmp-bhv-…` / `cmp-inf-…`).

The `require_login` / `require_commands` filters on the neighbors and sessions tables default to `true`, so the default view only shows sessions where the attacker actually logged in **and** ran at least one command. Toggle them off in the UI (or pass `?require_login=false&require_commands=false`) to see credential-spray-only sessions.

## Files

```
console/
  pyproject.toml
  src/console/
    cli.py                  -- `dshield_prism_console serve|healthcheck`
    server.py               -- FastAPI app, routes, detail builders
    ioc.py                  -- IOC type detection from query string
    queries.py              -- ES query functions
    graph.py                -- ES rows -> graph nodes/edges
    models.py               -- pydantic response shapes
    _config.py              -- self-contained YAML + .env loader
    _es.py                  -- Elasticsearch client factory
    templates/              -- Jinja2 pages: _base, findings, index (graph),
                               explore, hunts, tune, health,
                               artifact_{ip,url,hash}
    web/
      css/app.css           -- vanilla CSS, no framework
      js/                   -- app, graph, timeline, explore, findings, hunts,
                               tune, health, grounding, copy, topbar,
                               artifact_{ip,url,hash}, artifact_rule[s|_modal]
      tour/                 -- guided-tour JSON (detail / row / writeup)
```

## Duplicated code

To keep this package free of cross-package imports, two small pieces are
deliberately duplicated from the parent `enrich` package:

| Console file | Duplicates |
|---|---|
| [`_config.py`](src/console/_config.py) | `CowrieIndexes` / `SourceIndexes` / `ESConfig` / `Secrets` models + YAML+`.env` loader from `src/enrich/config.py` |
| [`_es.py`](src/console/_es.py) | `make_client` from `src/enrich/es_client.py` |

**Drift risk**: the two copies must agree on the
`elasticsearch.indexes.cowrie.*` field shape. If a new cowrie index is added
(or one is renamed) on the parent side, mirror the change in
`console/src/console/_config.py`. Everything else (LLM config, worker
config, cloud config, …) is intentionally absent from the console copy and
can drift safely.

## Security notes

* Default bind is `127.0.0.1` — single-user workstation use.
* No auth on the local HTTP server. If exposing on a LAN, add a reverse proxy
  with auth (or extend the FastAPI app with token middleware).
* Read-only: the only ES operations are search / get / count / info.

## Known limitations

* Cluster ids are run-scoped. The console resolves the most-recent
  `run_summary` doc and filters cluster lookups by that `run_id`. If you want
  to investigate a historical run, that's a v1.x feature.
* ASN / country anchors can fan out to thousands of IPs. They're capped at
  `limit=50` in the graph by default; the related-rows table can paginate the
  rest in v1.x (current build shows the first 50 only).
* Free-text command search returns the top-25 hits by score. For more
  specific lookups, search by sha256 directly.
