# Reference

The contract: indices, schemas, stable ids, tunable knobs, and subsystem
internals. Agent-facing. For how it works see [architecture.md](architecture.md);
for how to run it see [operations.md](operations.md).

- [Indices and pivots](#indices-and-pivots)
- [Stable ids and formats](#stable-ids-and-formats)
- [ECS field reference](#ecs-field-reference)
- [Cache and config hashes](#cache-and-config-hashes)
- [Watermarks](#watermarks)
- [Embedding model](#embedding-model)
- [Tunable knobs](#tunable-knobs)
- [Triage rules](#triage-rules)
- [Playbooks and campaigns](#playbooks-and-campaigns)
- [Findings](#findings)
- [Intel subsystem](#intel-subsystem)
- [Data classification (privacy gate)](#data-classification-privacy-gate)
- [Console](#console)
- [CI gates](#ci-gates)

## Indices and pivots

| Layer | Index |
|---|---|
| Raw cowrie events | `prism.raw.cowrie.session` |
| Enriched commands | `prism.enriched.cowrie.command` |
| Command cluster centroids | `prism.clusters.cowrie.command` |
| Session rollup | `prism.rollup.cowrie.session` |
| Session cluster centroids (playbook source-of-truth) | `prism.clusters.cowrie.session` |
| IP rollup | `prism.rollup.cowrie.ip` |
| IP cluster centroids | `prism.clusters.cowrie.ip` |
| Mined campaigns | `prism.campaigns.cowrie` |
| Playbook identity anchors (write-once, one doc per `spb-`) | `prism.identity.cowrie.playbook_anchor` |
| External reference corpus (Tradecraft) | `prism.reference.cowrie.session` |
| IP / URL / hash intel | `prism.intel.{ip,url,hash}` |
| Findings | `prism.finding` |
| Playbook / campaign / source-IP lifecycle | `lifecycle-dshield.cowrie.{playbook,campaign,source_ip}-default` |
| Metrics snapshots (threshold distributions, TTP rates) | `prism.metrics` |
| Run telemetry | `prism.ops` |

Cluster indexes carry three `doc_type`s: `cluster` (per-run centroid),
`run_summary` (one per run), and `reference_centroid` (the cross-run novelty
anchor set). **"Latest run"** = the `run_summary` with the most recent
`@timestamp`; it is the **run-complete sentinel** (written last, after centroids
and per-doc patches), so every reader gates on it and a half-built run is
invisible everywhere. `prune-clusters` keeps the newest few runs and deletes the
rest; every `reference_centroid` generation is preserved.

**Run telemetry (`prism.ops`).** Every tracked verb writes a `status=started`
doc on entry, patched to `finished`/`failed` on exit (`verb`, `host`, timings,
`rc`, `error`). Best-effort (never breaks the verb). The console reads it for
the `/health` "Pipeline activity" panel and the site-wide "pipeline running"
banner.

Cross-index joins:

| From | To | Shared field |
|---|---|---|
| Events → command enrichment | | `_id` = `sha256(normalized cmd)[:16]`, or `process.command_line.keyword` |
| Events → sessions | | `cowrie.session_id` |
| Sessions ↔ IP rollup | | `source.ip` |

## Stable ids and formats

These are contracts — readers key on them.

| Id | Format | Notes |
|---|---|---|
| Command doc `_id` | `sha256(normalized_command)[:16]` | |
| Session rollup `_id` | `<observer.name>:<cowrie.session_id>` | sensor-namespaced (`default:` when unnamed). **Reads go by the `cowrie.session_id` field, never `_id`** |
| IP rollup `_id` | source IP | |
| Playbook id | `spb-<16hex>` | cosine-anchored to a write-once anchor; stable across membership changes. Internal mint seed is `sescl-<16hex>` (`sha256(sorted member session ids)[:16]`) |
| Behavior campaign | `cmp-bhv-<hash>` | content-addressed over member playbook-id set |
| Infrastructure campaign | `cmp-inf-<hash>` | content-addressed over member artifact set |
| Operation | `cmp-ope-<hash>` | behavior×infrastructure overlap |
| Command shape hash | `cmp-bhv-…` style 16-hex | shape signature (literals → placeholders) |

## ECS field reference

Custom enrichment fields live under `dshield.<source>.enrichment.*`.

### Command enrichment (`prism.enriched.cowrie.command`)

| Path | Type | Notes |
|---|---|---|
| `event.provider` | keyword | `local` / `local_failed` / `claude` / `local_inherited` (shape-dedup child) |
| `event.reason` | text | LLM description |
| `process.command_line` | text+keyword | normalized command |
| `process.hash.sha256` | keyword | full sha256 of normalized command |
| `threat.tactic.id` / `threat.technique.id` | keyword[] | validated against vendored ATT&CK STIX |
| `threat.indicator` | nested[] | `{type, ip, domain, url.full, file.name, file.hash.sha256}` |
| `dshield.cowrie.enrichment.intent` | keyword | LLM enum |
| `dshield.cowrie.enrichment.confidence` | byte | 1–10 |
| `dshield.cowrie.enrichment.{llm,embed}_config_hash` | keyword | see [Cache](#cache-and-config-hashes) |
| `dshield.cowrie.enrichment.embedding` | dense_vector(768) | |
| `dshield.cowrie.enrichment.triage_reasons` | keyword[] | see [Triage rules](#triage-rules) |
| `dshield.cowrie.enrichment.cluster.{id,novelty_score,is_outlier,scored_at}` | mixed | `id` is run-scoped |
| `dshield.cowrie.enrichment.shape.{hash,role,functional_parent}` | keyword | shape-dedup: `role` ∈ `canonical`/`standalone`/`child`; child carries its canonical's `_id` |

### Session rollup (`prism.rollup.cowrie.session`)

5 shards. `observer.name` stored for per-sensor filtering.

| Path | Type | Notes |
|---|---|---|
| `source.ip` / `source.port` | ip / integer | |
| `source.geo.*`, `source.as.*` | object | enriched by ingest |
| `cowrie.hassh` / `cowrie.hassh_algorithms` | text+keyword | SSH client fingerprint (md5; derived from algorithms when cowrie didn't emit one) |
| `dshield.cowrie.enrichment.session.command_count` / `unique_commands` | long | |
| `…session.login_{success,fail}_count` / `file_{download,upload}_count` | long | |
| `…session.command_{failure,success}_count` | long | cowrie command-outcome events; captured, not yet read by clustering |
| `…session.proxy_{request,data}_count` + `proxy_attempts` | long + nested | direct-tcpip relay abuse; `proxy_attempts[] = {target_ip, target_port, ts}` |
| `…session.file_events` | nested | `{action, sha256, url?, ts, filename?, command_hash?, command_attribution}` — each hash attributed to the dropping command; feeds the hash intel queue + console Files lane |
| `…session.dominant_intent` / `intent_distribution` | keyword / nested | mode (deterministic lex tie-break) + top-3 |
| `…session.{mean,max}_novelty_score`, `mean_confidence` | float | |
| `…session.command_entropy` | float | Shannon (high = interactive, low = scripted) |
| `…session.command_stream_text` | text | raw command lines in order; fits TF-IDF for `late_fusion` mode |
| `…session.credentials` | keyword[] | sorted-dedup `user:pass` from every login event (cap 200; protocol-confusion noise filtered) |
| `…session.embedding` | dense_vector(768) | IDF-weighted mean-pool, L2-normalized |
| `…session.cluster.{id,novelty_score,is_outlier,scored_at}` | mixed | run-scoped `id`; preserved across re-index |
| `…session.playbook_id` / `playbook_name` / `playbook_named_at` | keyword/date | `spb-<16hex>`, cosine-anchored; LLM name |
| `…session.source_ip_intel.*` | object | denormalized intel verdict |

### IP rollup (`prism.rollup.cowrie.ip`)

| Path | Type | Notes |
|---|---|---|
| `source.ip` | ip | |
| `…ip.total_sessions` / `successful_sessions` / `command_sessions` | long | |
| `…ip.total_commands` / `file_download_count` | long | |
| `…ip.{dominant_intent,intent_distribution}` | mixed | |
| `…ip.{mean,max}_novelty_score` / `mean_session_duration_s` | float | |
| `…ip.first_seen` / `last_seen` | date | |
| `…ip.credentials` | keyword[] | union across sessions (cap 200); hashed into the IP cluster cred-hash sub-block |
| `…ip.hassh` / `hassh_distribution` | text+keyword / nested | modal SSH-client fingerprint + per-fingerprint counts |
| `…ip.dominant_playbook_id` / `playbook_distribution` | keyword / nested | modal playbook + per-playbook counts; drives source-IP lifecycle + `ip_behavior_shift` |
| `…ip.embedding` | dense_vector(768) | mean-pool of session embeddings, L2-normalized |
| `…ip.cluster.{id,novelty_score,is_outlier,scored_at}` | mixed | run-scoped; preserved across the forward re-index so active IPs keep their cluster between backward runs |

IP cluster centroid docs additionally carry `dominant_playbook_id`,
`dominant_playbook_name`, `playbook_distribution` (top-3) at the doc root —
the cluster-wide modal, written by `name ip-clusters`.

## Cache and config hashes

Cache key: `(short_command_hash, generation_model, llm_config_hash,
embed_config_hash)`. Both hashes are auto-derived (no manual `prompt_version`).

| Hash | Inputs | Effect on change |
|---|---|---|
| `llm_config_hash` | prompt files + LLM-side cooccurrence params + `src/enrich/data/commands/` contents + injection-fencing `SYSTEM_PROMPT` | LLM output stale → `re-enrich-stale` re-calls local LLM |
| `embed_config_hash` | `llm.embed_context`, `llm.embedding_model`, `llm.embed_input_order`, `cooccurrence.embed_cooccurrence` | embedding stale → `reembed` refreshes vectors |

`reembed` updates **only** `embed_config_hash` — a stale prompt can't be silently
blessed by an embed-only refresh. `bless-cache` stamps legacy rows with live
hashes after a deploy where cached enrichments are known-correct. Both are
smart-skip-if-fresh. Toggle with `worker.cache_auto_invalidate: false` or
`--ignore-config-hash`. **Limitation:** `enrich` reads forward from the
watermark, so a prompt edit doesn't retroactively re-enrich — `re-enrich-stale`
(backward pass) handles that.

## Watermarks

Keys in `/var/lib/dshield_prism/state.sqlite`:

| Key | Advanced by | Cleared by |
|---|---|---|
| `last_processed_at` | `enrich` | `reset --watermark` / `reset` |
| `session_last_processed_at` | `rollup sessions` | `reset --session-watermark` / `reset --if-stale` (gated) |
| `ip_rollup_last_processed_at` | `rollup ips` | `reset --ip-watermark` / `reset --if-stale` (gated) |
| `rollup_command_dirty` | `re-enrich-stale`/`reembed` on ≥1 rewrite | `reset --if-stale` |

**Conditional re-pool.** The backward chain runs `reset --if-stale` so steady
state stops re-pooling the whole corpus every 6 h. It forces a full re-pool only
when a command doc was rewritten since the last re-pool **or** the rollup
builder's schema changed. Fail-safe: it re-pools unless confidently clean.

**Watermarks assume monotonic forward-in-time ingestion.** Data loaded with
*past* timestamps lands behind the watermark and is skipped — to ingest a
backfill you roll the marks back (`reset --watermark --yes; enrich; rollup …`)
so the next forward pass re-scans. Clearing makes `enrich` re-scan the entire
history, but the per-command cache means the cost is ES I/O, not LLM spend. See
[operations.md](operations.md#backfilling-a-new-sensor).

## Embedding model

| Property | Value |
|---|---|
| Name | `text-embedding-nomic-embed-text-v1.5@q8_0` |
| Source | [Nomic Embed Text v1.5](https://huggingface.co/nomic-ai/nomic-embed-text-v1.5) (Apache-2.0), served by the local Ollama / LM Studio instance |
| Output dim | 768 native |

Trained on general English, not code/shell. Functional grouping of textually
unrelated commands is achieved by prepending intent + tactics + description
(`llm.embed_context`) before embedding, not by a shell-tuned model. The full
model string (incl. the `@q8_0` quant) is part of `embed_config_hash`, so
swapping quants/checkpoints/models triggers `reembed` on the next backward
cycle. The Matryoshka truncation property is not used today (full 768 ships).

## Tunable knobs

`config/default.yaml` is committed; override in `config/local.yaml`. Defaults in
parentheses.

**Clustering (HDBSCAN per layer):**
- `command_cluster.scalar_weight` (0.05); `command_cluster.cluster_svd_dim`
  (128; 0 = off) — fit-only TruncatedSVD dim for the command HDBSCAN (HDBSCAN on
  768-d euclidean is ~O(n²); SVD speeds the fit ~768/dim without touching the
  persisted full-dim centroids/novelty/reference). Auto-skips to full-dim below
  the dim. `command_cluster.rescue_threshold` (0.94; 0 = off) — outlier commands
  within this pure-embedding cosine of a centroid rejoin it post-HDBSCAN.
- `session.cluster_{min_cluster_size,min_samples}` (5, 2);
  `session.cluster_scalar_weight` (0.05); `session.cluster_svd_dim` (96; 0 = off)
  — session-layer SVD (reproduces full-dim clustering exactly at every tested
  corpus size; only bites the full-corpus paths). Don't drop below 96 without
  sweeping your own corpus (`scripts/sweep_session_svd.py`).
- `session.playbook_merge_threshold` (0.94; 1.0 disables) — drives both the
  centroid-level playbook merge and the session-layer noise rescue.
- `session.assignment_authoritative` (true) — Option-A cutover gate: when true,
  `assign_sessions` is the session **labeler** (nearest-anchor assignment), and
  `cluster sessions --novel-pool` only mints new playbooks from the novel tail.
- `session.assignment_tau` (0.94) / `assignment_confident_tau` (0.98) /
  `assignment_tfidf_tau` (0.80) — novel floor / embedding-trusted ceiling /
  band TF-IDF confirm cutoff.
- `session.clustering_mode` (`hdbscan`; `late_fusion` opt-in) — `late_fusion`
  fuses an embedding-HDBSCAN and a TF-IDF/SVD lexical-HDBSCAN; needs
  `command_stream_text`; O(N²) so guarded by `session.fusion_max_docs` (15000).
  `session.cluster_lexical_features_dim` (100). **Inert opt-in only:** it won at
  eval scale but regressed at production scale and was reverted — don't re-enable
  it expecting an upgrade ([decisions.md](decisions.md), [evaluation.md](evaluation.md)).
- `session.cluster_window_days` (30) — when > 0, the 6 h cycle clusters only the
  last N days; the weekly full pass (`--window-days 0`) re-pools the long tail
  and refreshes the reference. `0` reverts to all-time-every-6 h.
- `session.playbook_merge_distinctiveness_floor` (0.25) — pass-2 merge gate:
  colliding playbooks sharing every prevalent feature are merged.
- `session.playbook_naming_session_cap` (500); `playbook_naming_max_command_chars`
  (600) / `max_chars` (8000) — naming context budget.
- `session.specificity_store_cap` (10000); `specificity_threshold` (0.5) — UI
  distinctive-vs-commodity cutoff (`df ≤ √C`).
- `ip.cluster_{min_cluster_size,min_samples}` (3, 2); `cluster_scalar_weight`
  (0.05); `cluster_attribution_weight` (0.10).
- **Behavior-driven IP geometry** (adopted defaults):
  `ip.cluster_attribution_provenance_enabled` (false) — drops country + ASN +
  HASSH from the geometry (queryable post-hoc; they over-fragment behavior);
  `ip.cluster_tier1_enabled` (true) — per-IP behavior block; `cluster_tier2_enabled`
  (true) / `cluster_tier2_svd_dim` (24) — IP-as-bag-of-session-clusters. Changing
  any changes the scalar dims, so re-run `cluster ips --refresh-reference` once.
- `ip.full_recluster_weekly` (false) — when true, the 6 h chain does the cheap
  incremental nearest-centroid IP assign and the full O(n²) IP fit runs weekly.
  Flip true before pooling a multi-sensor backlog.
- `{command_cluster,session,ip}.reference_max_age_days` (45) — warn when the
  reference set is older than this; operator decides when to `--refresh-reference`.

**Cloud escalation:** `cloud.enabled` (false); `daily_budget_usd` (5.0);
`triage.confidence_max` (4); `novel_embedding_threshold` (0.5);
`novel_confidence_min` (4); `escalate_confidence_max` (7); `base64_min_run`
(200); `suspicious_tlds` (list); `sample_rate` (0.01); `intel_aware` (true).

**Cooccurrence:** `cooccurrence.{enabled,top_k,session_sample_size,min_sessions}`;
`embed_cooccurrence` (false) — LLM-side cooccurrence stays on; only the
embed-text append is off. `llm.embed_context` (fields prepended to embed text);
`llm.embed_input_order` (`prelude_first`).

**Findings:** `findings.noise_threshold_pct` (0.005) — per-miner safety valve;
`discovery.ip_shift_js_distance_min` (0.3) / `convergence_min_ip_overlap_ratio`
(0.4) — fallbacks when the corpus-percentile lookup is below floor.

**Intel:** `intel.enabled` (false); `refresh_ttl_days` (per kind: ip 7 / url 14
/ domain 14 / hash 30; 0 disables; `--force` bypasses). Per-provider
`daily_budget`, `refresh_minutes`.

**Shape dedup:** `command_shape_dedup.enabled` (true) — same-shape commands
inherit intent/description/tactics from a canonical sibling instead of running
the local LLM; `min_parent_confidence` (5); `require_known_intent` (true).

**Throughput at scale:** `session.rollup_workers` / `ip.rollup_workers` (5);
`session.page_size` / `ip.page_size` (2000); `worker.cluster_n_jobs` (-1 = all
cores, HDBSCAN nearest-neighbour phase). The IP rollup is one ES query per IP,
so its worker count is the biggest lever.

## Triage rules

Any rule fires → escalate. Codes recorded as `triage_reasons[]`.

| Rule | Fires when |
|---|---|
| `low_confidence<=N` | local confidence ≤ `cloud.triage.confidence_max` |
| `local_failed` | local LLM returned invalid JSON twice |
| `base64_blob` | run ≥ `base64_min_run` chars AND mixed character classes |
| `ip_literal` | IPv4 literal in command |
| `rare_tld` | domain TLD in `suspicious_tlds`, near a network tool keyword |
| `novel_embedding` | (by `escalate`) novelty ≥ threshold AND confidence in band |
| `sample` | random `sample_rate` (1%) quality monitoring |
| `budget_exhausted` | daily cap hit; no cloud call |
| `cloud_parse_failed` | cloud returned unparseable JSON |
| `intel_skip_authoritative_clean` | every source IP had intel `authoritative_clean` |
| `intel_skip_commodity_consensus` | every source IP had ≥2 independent providers agreeing malicious |

Triage-rule changes don't flow through the cache hashes — run `re-triage
--backward [--window-days N]` to rewrite stored `triage_reasons`.

## Playbooks and campaigns

**Playbook.** `name playbooks` first collapses HDBSCAN session clusters via
complete-linkage agglomerative clustering on pairwise centroid-cosine distance,
cut at `1 − playbook_merge_threshold` — a group forms only when *every* pair
within it clears the threshold, so chains of borderline edges can't bridge
unrelated centroids. Then the local LLM gives one 3–5-word label per merged
group. Names anchor on commands/IOCs ranked by **session coverage** over a
subsample (`playbook_naming_session_cap`). Pass-2 collision resolution first
**merges** colliding playbooks with no distinguishing feature
(`playbook_merge_distinctiveness_floor`, a deterministic behavioral merge), then
LLM-renames the genuinely-distinct survivors. Playbook id is cosine-anchored to
the write-once anchor index (see [Stable ids](#stable-ids-and-formats)). Stability
sentinel: `scripts/measure_playbook_id_churn.py`.

**Noise rescue.** Before naming, `cluster sessions` reassigns HDBSCAN outlier
sessions to their nearest centroid when pure-embedding cosine ≥
`playbook_merge_threshold` (recorded as `n_rescued`). Genuinely-distant sessions
stay outliers.

**Campaign.** Two independent miners (`mine campaigns`): **behavior** (FP-growth
over per-IP playbook bags → `cmp-bhv-…`) and **infrastructure** (connected
components of a session graph through shared artifacts → `cmp-inf-…`). Names are
programmatic; no LLM. Window: `--window-days N` (default 30; 0 disables). Miner
constants live in `src/enrich/sources/cowrie/campaigns.py`
(`_BEHAVIOUR_MIN_SUPPORT_IPS=5`, `_INFRA_MIN_SESSIONS=3`, …). Zero campaigns is
often a corpus property, not a bug (see
[troubleshooting](operations.md#troubleshooting--is-anything-actually-wrong)).

**Cluster specificity.** Each session-cluster pass scores how distinctive each
member IP/command is: `specificity = ln(C/df)/ln(C)` (df = clusters the key
appears in, C = total clusters; df=1 → 1.0). Persisted as `ip_specificity` /
`command_specificity` on the centroid docs and read by the console drawer pills,
the spotlight toggle, and the `/api/{ip,command,playbook}` activity endpoints.

## Findings

`mine findings` emits into `prism.finding`; status (`new`/`ack`/`confirmed`/
`rejected`) persists across re-mines. Two miner families:

| Kind | Source | Fires when |
|---|---|---|
| `new_playbook` | discovery | first-ever observation of a stable behavior |
| `intel_verdict_flip` | discovery | a source IP's CTI verdict flipped recently |
| `ip_behavior_shift` | discovery | an IP's playbook mix changed materially |
| `outlier_burst` | discovery | cluster of sessions sharing an artifact in a short window |
| `campaign_convergence` | discovery | two campaigns started sharing IPs |
| `playbook_command_drift` | drift | playbook's command set drifted |
| `playbook_sequence_drift` | drift | playbook's command-bigram sequence drifted |
| `playbook_artifact_drift` | drift | playbook's artifact set drifted |
| `playbook_geo_drift` | drift | playbook's source-country mix drifted |
| `playbook_size_drift` | drift | playbook's session-count band changed |
| `playbook_resurgence` | drift | a silent playbook came back |
| `campaign_growth` | drift | a campaign added IPs/playbooks |

Drift-finding LLM narratives are gated on classification — a confidential or
untagged playbook is never narrated.

## Intel subsystem

Opt-in (`intel.enabled: true`, off by default). Re-query cadence is
`intel.refresh_ttl_days` per kind; per-IP/-hash budgets are per-provider.

**IP providers:** `tor`, `isc`, `feodotracker`, `firehol` (bulk, unlimited);
`greynoise` (per-IP, 50/week), `abuseipdb` (per-IP, 1000/day). **URL:**
`urlhaus` (bulk), `threatfox` (per-URL/-hash). **Hash:** `malwarebazaar`,
`threatfox`, `virustotal_public` (off by default; 4/min). Providers feeding the
hash kind take cowrie file-event hashes first (real drops > content-writes >
regex-from-command). Keys in `.env`; a provider skips itself when its key is
unset.

**Consensus rule** (`src/enrich/intel/writer.py:compute_derived`):

1. **Direct-evidence malicious wins absolutely** (`malicious AND evidence_direct`
   — FeodoTracker active C2, GreyNoise own-malicious).
2. **Authoritative-clean overrides aggregator-only malicious** (GreyNoise
   benign/riot, AbuseIPDB whitelisted) — rescues researcher scanners.
3. Otherwise **any-positive** flips consensus.

`derived.override_applied` ∈ `{direct_malicious, authoritative_clean, ""}`.

**Independence guard.** The cloud-escalation skip gate requires ≥2 malicious
votes from **disjoint upstream feeds**, not ≥2 providers by raw count — so two
abuse.ch wrappers, or FireHOL + ISC (both carry DShield), don't count as
corroboration. Each provider's `upstream_feeds` is curated in
[`src/enrich/intel/provider_registry.py`](../src/enrich/intel/provider_registry.py)
(enforced by `scripts/smoke_test_intel_independence.py`).

**Queue + migration.** A SQLite-backed priority queue spends scarce budgets on
highest-novelty artifacts first, with per-provider circuit breakers. Intel
mappings are **strict-dynamic** — push the additive `init-indexes --update-mapping`
before deploying new-provider code, or ES rejects writes. Prefer
`intel reapply-rules` (re-derives verdicts from persisted data, zero upstream
calls) over wiping the index.

## Data classification (privacy gate)

A per-sensor `dshield.classification` (`public` | `confidential`) stamped at
ingest decides whether data may leave the box. **Confidential data is never
escalated to the cloud LLM and never queried against CTI feeds.** Central logic:
[`src/enrich/classification.py`](../src/enrich/classification.py).

- **Three egress boundaries, all gated:** the intel discovery scan
  (`releasable_filter` in `intel/queue.py`), cloud command escalation
  (`is_releasable` in `sources/cowrie/commands.py`), and drift-finding narratives
  (`findings/narrative.py`).
- **Most-restrictive-wins propagation:** a deduped command / session / IP rollup
  is confidential if *any* contributing source is; public only if *every* source
  is explicitly public. Deduped-command updates are sticky (never downgrade
  confidential → public).
- `classification.unclassified_is_confidential` (**true** = fail-safe) — absent
  tags are treated as confidential and `releasable_filter` matches only explicit
  `public`. Leave true unless every ingest path is known to stamp the field.

> Interactive ES queries you run by hand bypass these code gates. Any query
> against a cowrie data index **must** carry
> `{"term": {"dshield.classification.keyword": "public"}}` in its `bool.filter`.
> See the project `CLAUDE.md`.

## Console

Read-only FastAPI + vanilla-JS app; never writes to ES. Nav:
**Inbox · Graph · Browse · History · Hunts · Rules · Curation · Health**
(`/findings`, `/insights`, `/compare` are 302 redirects to `/inbox`, `/browse`,
`/graph`). The graph swim-lane is IP → Session → Command → File → MITRE; inline
compare renders a verdict card for a peer cluster/playbook/campaign; the Report
tool gathers in-view artifacts into a copy-ready writeup (IOCs defanged by
default). Search, install, page list, API endpoints, and the deliberately-
duplicated config/ES code are documented in [`console/README.md`](../console/README.md).

## CI gates

The full pre-commit surface — all must pass before handing back for commit. Run
via `console/.venv`:

```bash
# Lint + offline smoke (always)
console/.venv/bin/ruff check src scripts
console/.venv/bin/python scripts/run_smoke.py

# Clustering / assignment quality gates (always run them all)
console/.venv/bin/python scripts/eval_clustering.py --baseline eval/baseline.json --no-json
console/.venv/bin/python scripts/eval_assignment.py --baseline eval/baseline-assignment.json --no-json
console/.venv/bin/python scripts/eval_assignment_prod.py --baseline eval/baseline-assignment-prod.json --no-json
console/.venv/bin/python scripts/eval_production_scale.py --snapshot eval/production-snapshot-v1.jsonl.gz --baseline eval/baseline-prod-scale.json --no-json
console/.venv/bin/python scripts/eval_command_scale.py --snapshot eval/command-snapshot-v1.jsonl.gz --baseline eval/baseline-command-scale.json --no-json
```

What each gate measures, the eval-scale-vs-production-scale distinction, and the
snapshot refresh cadence are in [evaluation.md](evaluation.md).
