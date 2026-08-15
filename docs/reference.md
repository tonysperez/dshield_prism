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
| Playbook identity anchors (write-once; one primary doc per `spb-`, plus optional drift "satellite" docs — see below) | `prism.identity.cowrie.playbook_anchor` |
| External reference corpus (Tradecraft) | `prism.reference.cowrie.session` |
| IP / URL / hash intel | `prism.intel.{ip,url,hash}` |
| Findings | `prism.finding` |
| Playbook / campaign / source-IP lifecycle | `lifecycle-dshield.cowrie.{playbook,campaign,source_ip}-default` |
| Metrics snapshots (threshold distributions) | `prism.metrics` |
| Command-grounding coverage report (single doc, id `latest`) | `prism.metrics.grounding_coverage` |
| Run telemetry | `prism.ops` |

Cluster indexes carry three `doc_type`s: `cluster` (per-run centroid),
`run_summary` (one per run), and `reference_centroid` (the cross-run novelty
anchor set). **"Latest run"** = the `run_summary` with the most recent
`@timestamp`; it is the **run-complete sentinel** (written last, after centroids
and per-doc patches), so every reader gates on it and a half-built run is
invisible everywhere. `prune-clusters` keeps the newest few runs and deletes the
rest; every `reference_centroid` generation is preserved.

**Run telemetry (`prism.ops`).** Every tracked verb writes a `status=started`
doc on entry, patched to `finished`/`failed` on exit (`verb`, `unit`, `host`,
timings, `rc`, `error`). Best-effort (never breaks the verb). `unit` is the
owning systemd unit, copied from `PRISM_SYSTEMD_UNIT`, which each unit file sets
to `%n`; it is absent for a manual CLI run. The index is `dynamic: strict`, so
the mapping must be applied (`init-indexes --update-mapping --source ops`)
*before* a writer stamps a new field — otherwise ES rejects every doc and the
best-effort writer swallows it, silently losing all telemetry.

**`verb` is coarse.** It holds the top-level argparse verb only — `mine`,
`cluster`, `rollup`, `name`, `track`, `intel` — so one bucket can cover several
steps (`backward` stamps `verb="mine"` for `mine campaigns`, `operations`,
`findings` and `hunts`). Any consumer that reduces to "latest doc per verb"
therefore loses an earlier sibling's outcome.

The console reads it for the `/health` "Pipeline & schedule" panel, the
site-wide "pipeline running" banner, and the topbar Health badge's cycle dot.
The panel groups runs by unit via `queries._unit_rows` off a unit-then-verb agg
(`unit.keyword` terms with `missing: "manual / ad-hoc"`, then `verb`), bounded to
`_UNIT_LOOKBACK_DAYS` (30). Bucketing by unit first is load-bearing, since
`rollup` runs under both forward and backward, and `cluster`/`prune-clusters`
under both backward and recluster-full — a verb-only agg keeps one doc and makes
the other unit look like it never ran the step. Because `verb` is coarse, unit
state comes from a **separate windowed `status=failed` filter**, not from the
latest doc per verb: otherwise a failed `mine findings` followed by a successful
`mine hunts` would render the unit green. A `status=started` doc counts as live
only inside `ops.pipeline_running_window_min`; past that it is a ghost, since
`running` outranks `failed` and would mask a real failure. Unit state ranks
`running` > `failed` > `ok` > `never`.

The window matters: without it, a verb removed from a unit's `ExecStart` chain
keeps its last doc forever and can pin that unit red permanently.

Each unit's tooltip text and cadence come from the static
`queries._UNIT_CATALOG` — cadence is the timer's `OnCalendar` string verbatim.
`scripts/smoke/smoke_test_unit_catalog.py` guards it: the build fails when a
`systemd/*.service` is added or removed without a matching catalog entry, when a
unit stops setting `PRISM_SYSTEMD_UNIT`, when a cadence diverges from its timer,
or when `unit` disappears from the ops mapping.

The badge's cycle dot is separate: `queries.pipeline_cycle_health` takes the
latest `verb_run` per verb via its own flat `by_verb` agg — unrelated to the
panel's unit-then-verb agg, so changing one does not change the other — and
classifies via the pure `_derive_cycle_state`: `ok` (all latest runs finished and
newest within `ops.cycle_stale_min`, default 120 min, or a verb in-flight),
`warn` (a latest run `failed`), `behind` (newest older than `cycle_stale_min`,
none running), `unknown` (no telemetry / ES error). `cycle_stale_min` is distinct
from `pipeline_running_window_min` (live-verb window).

**Command-grounding coverage (`prism.metrics.grounding_coverage`,
spec-grounding-precompute).** `track grounding-coverage` (own systemd timer,
`dshield_prism-grounding-coverage.{timer,service}`, daily) walks the full
`cowrie.commands` index, classifies every parsed command via
`enrich.command_grounding` (`needs_def` / `tldr_only` / `curated` / `denied`,
weighted by `occurrence_count`), and overwrites a single doc at fixed id
`latest` (`src/enrich/grounding_coverage_job.py`,
`GroundingCoverageConfig`/`GroundingCoverageIndexes` in `config.py`). `count`
aggregates every classification; `samples` (literal command lines) are gated
through `classification.is_releasable` — only `public`-tagged docs may
contribute a sample. The console reads that one doc O(1)
(`queries.grounding_coverage_summary`): `/api/health/grounding-coverage`
feeds the Health stat bar, `/api/tune/grounding-coverage` feeds the Tune
"Grounding" tab's searchable/paginated worklist. Block/unblock
(`POST`/`DELETE /api/tune/grounding-coverage/denylist[/{token}]`) writes
`denylist.yaml` immediately via `add_to_denylist`/`remove_from_denylist`; the
report's bucket counts catch up on the next scheduled job run, not
instantly. No doc yet (fresh deploy, before the first cadence run) renders an
explicit "pending first run" empty state, never an error.

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
| `threat.indicator` | nested[] | `{type, ip, domain, url.full, file.name, file.hash.sha256}` |
| `dshield.cowrie.enrichment.intent` | keyword | one of 11 honeypot-native action labels (see [Intent taxonomy](#intent-taxonomy)) |
| `dshield.cowrie.enrichment.confidence` | byte | 1–10 |
| `dshield.cowrie.enrichment.{llm,embed}_config_hash` | keyword | see [Cache](#cache-and-config-hashes) |
| `dshield.cowrie.enrichment.embedding` | dense_vector(768) | |
| `dshield.cowrie.enrichment.triage_reasons` | keyword[] | see [Triage rules](#triage-rules) |
| `dshield.cowrie.enrichment.cluster.{id,novelty_score,is_outlier,scored_at}` | mixed | `id` is run-scoped |
| `dshield.cowrie.enrichment.shape.{hash,role,functional_parent}` | keyword | shape-dedup: `role` ∈ `canonical`/`standalone`/`child`; child carries its canonical's `_id` |

#### Intent taxonomy

Single-label per command, chosen from a honeypot-native action set (not MITRE
ATT&CK tactics — see [decisions.md](decisions.md)). Each label is decidable from
one shell line; the per-label definitions, tie-breakers ("label by the terminal
objective"), and few-shot examples live in `config/prompts/command_enrichment.txt`.
The enum is the single source of truth in `enrich/llm/schemas.py` (`INTENTS`) and
is advertised as a JSON-schema `enum` so a grammar-constrained local decoder can
only emit valid values; off-enum strings coerce to `unknown`.

| label | command signal |
|---|---|
| `host_recon` | enumerate box/env (uname, /proc/cpuinfo, id, w, ps, ls, read /etc/passwd) |
| `download_ingress` | fetch a remote payload to disk, no run step (wget/curl/tftp) |
| `execute_payload` | run a dropped/staged binary or inline interpreter (`./x`, `\| sh`, busybox) |
| `install_persistence` | cron, rc.local, systemd, authorized_keys |
| `defense_evasion` | history wipe, chattr, rm logs, `iptables -F`, kill rivals |
| `credential_data_access` | read /etc/shadow, ssh keys, wallets, .aws/credentials |
| `account_manipulation` | passwd change, useradd/usermod, sshd PermitRootLogin |
| `cryptomining` | install/configure/run a coin miner (xmrig, stratum pool) |
| `ddos_botnet` | botnet enroll (Mirai/Gafgyt), flood, destructive `rm -rf /` |
| `benign_noise` | login probes / non-actions (exit, echo, cd, banners) |
| `unknown` | can't tell / truncated / gibberish |

Adding/removing a label changes the IP behaviour-matrix width (one intent column
per label) and the diversity denominator — both derive from `INTENTS`, so they
stay in sync automatically; a corpus re-enrich + IP re-cluster is required to
repopulate.

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

Inspect which hash generations the cache holds (count of rows per distinct
hash) — a single generation means no config drift; multiple means a
config/prompt/model change re-keyed part of the cache:

```bash
sqlite3 /var/lib/dshield_prism/state.sqlite "
SELECT 'LLM Config Hash: '   || llm_config_hash   || ' - ' || COUNT(*) FROM enrichment_cache GROUP BY llm_config_hash
UNION ALL
SELECT 'Embed Config Hash: ' || embed_config_hash || ' - ' || COUNT(*) FROM enrichment_cache GROUP BY embed_config_hash;
"
```

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
unrelated commands is achieved by prepending intent + description
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
  `assignment_tfidf_tau` (**0.50**) — novel floor / embedding-trusted ceiling /
  band TF-IDF confirm cutoff. `tfidf_tau` is a **valley placement, not a tuned
  value**: corpus-wide the band's TF-IDF cosines are bimodal — ~2,813 checks at
  0.12–0.2, only ~108 across the whole of 0.2–0.7, then ~2,382 at 0.7–0.8 sitting
  immediately below ~3,522 confirms at 0.8–1.0. Anything in ~0.25–0.65 behaves
  identically. Re-measure with `eval_novel_pool.py`'s `band_tfidf_diagnosis` before
  changing it; do not hand-tune. Note `scripts/eval_assignment_faithful.py` carries
  its own `TFIDF_TAU` module constant and does **not** read config — keep the two in
  step by hand.
- `session.assignment_rescue_tau` (0.94, i.e. == `assignment_tau` — no-op by default) —
  below-tau structural-predicate rescue floor (item 30). `assign_batch`'s cascade
  extends from `assignment_tau` down to this value; a session in that band gets
  rescued from NOVEL to ASSIGNED when its structural predicate vector positively
  overlaps its nearest anchor's `predicate_signature` (never on an all-false match on
  either side — see `src/enrich/sources/cowrie/predicates.py`). The 7 structural
  predicates are precomputed per command at enrichment time
  (`dshield.cowrie.enrichment.predicates.*`, `commands.json`) and folded into a
  session vector by `lexical.build_session_predicate_vectors`; each `playbook_anchors`
  doc carries a `predicate_signature` (modal/frequency vector over its member
  sessions, `capture_anchor_snapshot.py:predicate_signature`). Lowering this below
  `assignment_tau` is an operator decision made from a `rescue_tau` sweep
  (`eval_assignment_faithful.py --rescue-tau-sweep`) — not shipped as a lowered
  default without reviewing the tradeoff. **Measured on real anchors: keep it at
  0.94.** See `docs/decisions.md`.
  `--rescue-tau-sweep` alone runs the label-prototype sweep
  (`report["rescue_tau_sweep"]`: `novelty_precision`/`novelty_recall` per candidate).
  Combined with `--anchors` it also runs the real-anchor three-arm ablation into
  `report["real_anchor_rescue_sweep"]` — `evidence` (arm-invariant ceilings:
  `gt_in_library`, `sessions_with_predicate_evidence`, `anchors_with_signature`,
  `anchors_armed`) plus `rows`, one per candidate, each carrying `gated` /
  `forced_true` / `forced_false` arms and a `blocked_fraction`. The arms differ only
  in the predicate inputs handed to the same gate: `forced_true` uses all-True vectors
  and all-1.0 signatures (pure tau-lowering), `forced_false` all-0.0 signatures (inert
  control, must rescue 0). Candidates must lie in `(0.0, assignment_tau]`. Both sweeps
  are diagnostic — never baseline-gated.
- `session.anchor_satellite_minting_enabled` (false); `anchor_satellite_drift_fraction`
  (0.15) — item 59, write-once anchor drift. A pinned anchor's centroid is never
  updated, so a growing/drifting cluster's own newer members can fall below
  `assignment_tau` and become permanently novel even though `name playbooks` still
  recognises the group as already-named (measured: 22% of one playbook's members,
  `spb-afafb73ec79a60cb`). When enabled, an already-named group whose drift fraction —
  sessions carrying its `playbook_id` that replay as `cluster.assignment_status ==
  novel`, over all such sessions — meets the threshold mints an *additional* "satellite"
  anchor doc for the same `playbook_id` (distinct `_id`, `<playbook_id>-sat-<8hex>`)
  instead of being skipped. The incumbent anchor doc is never touched.
  `_assign_playbook_id` / `assignment.py` already argmax-match over every loaded anchor
  and return the winning anchor's `playbook_id`, so satellites resolve identically to
  the primary on the read side — no assignment-path code change. Off by default:
  widening what one playbook id covers is exactly the conflation risk the write-once
  rule guards against, so enabling it and re-measuring `anchor_label_purity`/
  `homogeneity` (`eval_assignment_prod.py`) is an operator decision.
- `lexical._MIN_ANCHOR_BAGS` (50; code constant, not a config knob, single
  source of truth in `src/enrich/sources/cowrie/lexical.py`) — an anchor whose
  sampled `command_cluster_bags` count is below this gets no TF-IDF centroid;
  its band checks degrade to embedding-only instead of a noisy cosine, the
  same graceful path already used when a whole snapshot has no bags.
  `capture_anchor_snapshot.py` prints (stderr) which anchors land under it at
  capture time — audit signal, since rare-playbook public-session counts are
  corpus-limited, not a `--per-anchor` setting.
- `scripts/refresh_eval_taxonomy.py` — operator-run companion to
  `refresh_eval_embeddings.py`: re-pulls each eval-JSONL command hash's
  current cluster id from live ES via `lexical.pull_hash_to_cluster`
  (public-only filtered) and overwrites just the `cluster` sub-object in
  place. Run after a clustering/taxonomy re-run so the eval set's TF-IDF
  bag vocabulary stays aligned with the live anchor snapshot's; a hash that
  no longer resolves publicly has its stale `cluster` block cleared rather
  than left stale, falling back to the outlier token downstream.
- `session.clustering_mode` (`hdbscan`; `late_fusion` opt-in) — `late_fusion`
  fuses an embedding-HDBSCAN and a TF-IDF/SVD lexical-HDBSCAN; needs
  `command_stream_text`; O(N²) so guarded by `session.fusion_max_docs` (15000).
  `session.cluster_lexical_features_dim` (100). **Inert opt-in only:** it won at
  eval scale but regressed at production scale and was reverted — don't re-enable
  it expecting an upgrade ([decisions.md](decisions.md), [evaluation.md](evaluation.md)).
- `session.cluster_window_days` (30) — when > 0, the 6 h cycle clusters only the
  last N days; the weekly full pass (`--window-days 0`) re-pools the long tail
  and refreshes the reference. `0` reverts to all-time-every-6 h. `name
  playbooks` has no window concept of its own — it just names whichever
  cluster run is newest — so both the 6h windowed pass and the weekly full
  pass call it themselves, right after their own mint, under one continuous
  `flock` hold spanning mint+name (so the other cadence's naming call can't
  interleave and claim the wrong run as "latest").
- `session.playbook_merge_distinctiveness_floor` (0.25) — pass-2 merge gate:
  colliding playbooks sharing every prevalent feature are merged.
- `session.playbook_naming_session_cap` (500); `playbook_naming_max_command_chars`
  (600) / `max_chars` (8000) — naming context budget.
- `session.specificity_store_cap` (10000); `specificity_threshold` (0.5) — UI
  distinctive-vs-commodity cutoff (`df ≤ √C`).
- `ip.cluster_{min_cluster_size,min_samples}` (3, 2); `cluster_scalar_weight`
  (0.05); `cluster_attribution_weight` (0.10).
- `ip.rescue_spread_percentile` (99; 0 = off) — noise rescue: reassign an HDBSCAN
  outlier to its nearest centroid when within the Pth percentile of the
  intra-cluster spread, **in the augmented `[embedding ⊕ scalars]` euclidean space**
  (the geometry HDBSCAN fit on — *not* the pure-embedding cosine that
  `command_cluster.rescue_threshold` / `session.playbook_merge_threshold` use,
  because the IP geometry is scalar-driven and pure-cosine over-rescues ~38%; see
  [decisions.md](decisions.md)). Takes IP outliers ~70% → ~6% at p99 (~94% playbook
  purity; purity held flat p90→p99). Tune with `scripts/diagnose_ip_rescue.py`.
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
inherit intent/description from a canonical sibling instead of running
the local LLM; `min_parent_confidence` (5); `require_known_intent` (true).

**Throughput at scale:** `session.rollup_workers` / `ip.rollup_workers` (5);
`session.page_size` / `ip.page_size` (2000); `worker.cluster_n_jobs` (-1 = all
cores, HDBSCAN nearest-neighbour phase). The IP rollup is one ES query per IP,
so its worker count is the biggest lever.

**ES backpressure** (`elasticsearch.backpressure.*`): heap/circuit-breaker-aware
retry so a heap-constrained node degrades gracefully instead of hard-failing a
step. `enabled` (true); `heap_high_watermark` (0.85) / `heap_resume_watermark`
(0.70) — parent-breaker estimated/limit ratios to pause at / resume below;
`poll_interval_s` (2.0); `max_wait_s` (3600) — shared wall-clock patience budget
per operation (prefer waiting over failing); `retry_max_attempts` (200, a
secondary ceiling); `retry_base_delay_s` (2.0) / `retry_max_delay_s` (30).
Implemented as a transparent `ResilientClient` wrapper over the ES client (every
read + write inherits it, plus `helpers.bulk`/`scan`) in
[`es_health.py`](../src/enrich/es_health.py); the pipeline also gates between
steps so a heap-spiking step (e.g. cluster-assignment) lets the node drain before
the next one piles on.

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

**Anchor drift / satellite anchors (item 59).** A pinned anchor centroid never
updates, so an already-named group's own newer members can drift below
`assignment_tau` and go permanently novel while naming still recognises the
group (`skipped_already_named`). Gated by `anchor_satellite_minting_enabled`
(off by default): when the drift fraction crosses `anchor_satellite_drift_fraction`,
`name playbooks` mints an *additional* anchor doc sharing the group's `playbook_id`
under a distinct `_id` rather than updating or skipping — see
`session.anchor_satellite_minting_enabled` above.

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

**Status mutations.** `mutate_status`, `add_note` and `bulk_mutate_status`
([`src/enrich/findings/writer.py`](../src/enrich/findings/writer.py)) index with
`refresh=False`; the caller owns visibility and forces exactly one
`es.indices.refresh()` per HTTP request — and only when something was written.
`prism.finding` is declared `refresh_interval: 5s`, so no *finding* mutation
path may use `refresh="wait_for"`. `POST /api/findings/status` costs one `mget`
+ one `_bulk` per 500 ids (`_BULK_STATUS_CHUNK`, matching `helpers.bulk`'s own
chunking so a failure is attributable to its chunk) plus one refresh for the
whole request. It returns `{"n_updated", "errors": [{"id","error"}]}` at HTTP
200 on partial failure — a missing id fails only itself — but rejects an invalid
`status` once with HTTP 400 before touching ES, and 400s on empty `ids`. A
`prev == new_status` transition writes nothing and still counts in `n_updated`;
duplicate ids collapse to one transition; a doc that comes back from `mget`
found-but-sourceless is refused rather than overwritten with a stub. The
batch-invariant latest cluster run resolves once through `latest_cluster_run_id`
([`lifecycle.py`](../src/enrich/findings/lifecycle.py)) and is passed into every
anchor build — an explicit `None` means "already looked, there is none", and
`RUN_ID_UNSET` is the only value that makes `build_anchor_payload` search for
itself. Lifecycle side effects stay per-finding and logged-and-swallowed, never
failing a status write, and are skipped for any id the bulk write did not land.

## Hunts

Analyst-authored YAML in `cfg.findings.hunts.config_dir` (default
`config/hunts/`), one file per hunt. `mine hunts` AND-combines a hunt's filters
into one query over the session rollup and emits `kind=analyst_hunt` — one
finding per (hunt, session), with `delta_signature = hunt:<hunt_id>` so two
hunts matching the same session stay distinct findings. Cap:
`findings.hunts.max_findings_per_hunt` (default 500). Code:
[`src/enrich/findings/hunts.py`](../src/enrich/findings/hunts.py).

Filter kinds: `artifact_set_contains_any` / `artifact_set_contains_all` /
`intent_in` (`values: [...]`), `command_count_gte` / `login_fail_count_gte`
(`threshold: int`), `external_match_cosine_gte` (`threshold: 0..1`), `window`
(`last_days: int`, 1–3650). `values` members must be non-empty strings and a
`bool` is never accepted where a number belongs. One malformed file aborts the
whole directory load.

**`enabled` gates writing, not loading.** Every valid hunt is loaded, listed and
executable regardless of the flag; a disabled one simply never contributes to
`prism.finding`. That is what lets the console list a hunt in order to switch it
back on. The four shipped seed hunts are all `enabled: false`. A hunt file that
omits the key defaults to `true`, so an operator's hand-written hunts survive an
upgrade unchanged.

| Surface | Behavior |
|---|---|
| `mine hunts` | runs enabled hunts only; disabled ids returned under `skipped`, `loaded` counts every hunt on disk |
| `mine hunts --dry-run --include-disabled` | executes disabled hunts too (naming them under `ran_disabled`); writes nothing. Rejected with a JSON error and exit 2 without `--dry-run` — a flag must never write for a hunt the operator switched off |
| `POST /api/hunts/{id}/preview?limit=` (1–100, default 100) | executes one hunt and returns matching sessions; **no** finding write, no `init_index`, no refresh, no `run_id`. Works on disabled hunts. Returns `total` (true `_count`, i.e. how many findings enabling it would write), `shown` (page size) and `truncated` = `total > shown` |
| `POST /api/hunts/{id}/toggle` | `{"enabled": <bool>}` flips `enabled` in the hunt's own YAML. Non-bool body is a 400 with no file touched. Surgical single-line rewrite (replace the first top-level bare-or-quoted `enabled:` key, else append) preserving trailing comments and the file's line endings; the candidate content is parsed *before* it replaces anything and swapped in via `os.replace`, so a torn write can't leave the directory unloadable |
| `POST /api/hunts` | `{id,name,description,filters}` writes `<config_dir>/<id>.yaml` and 201s. Always `enabled: false` — a hunt authored from a half-formed hypothesis must be previewed before it writes findings. 409 when the id is already loaded *or* the filename already exists; 400 (never 422) on a bad id, name or filter clause, carrying `validate_hunt_doc`'s own message |
| `PUT /api/hunts/{id}` | `{name,description,filters}` rewrites the hunt's existing `_source_path` — which may be `.yml` or named off-id — never a second file. The file's current `enabled` and any top-level keys the console doesn't know (`owner:`, `tags:`) are carried through untouched; `id` in the body must match the path or it's a 400, since rename is out of scope. Full `yaml.safe_dump` rewrite: comments and `description: \|` blocks do not survive. The id regex is enforced only when the id *names* a new file, so a legacy hand-written id stays editable |
| `DELETE /api/hunts/{id}` | Unlinks `_source_path`. The `analyst_hunt` findings the hunt already wrote are deliberately left in the inbox — findings outlive their definition; deleting only stops future writes |

Every write re-runs `validate_hunt_doc` — the loader's own per-document rules,
factored out of `load_hunts` so a hunt that saves can never fail to load — and
re-parses the candidate text before `os.replace` installs it. Console-authored
ids must match `^[a-z0-9][a-z0-9-]{0,63}$` and the resolved target must still be
inside `config_dir`; the existing file's mode is restored after the swap, since
`mkstemp` creates `0600` and `os.replace` keeps the temp file's mode (new files
get `0o644 & ~umask`). Hunt ids arriving over HTTP are resolved against the ids
`load_hunts` returned, never interpolated into a path; unknown id is a 404.
`load_hunts` refuses a directory with duplicate hunt ids, or any file resolving
outside `config_dir` (a symlink would otherwise redirect the toggle's write). `enabled` accepts
YAML bools and the usual string spellings (`"true"`/`"no"`/`"off"`/…); anything
else aborts the load rather than guessing — `bool("false")` is `True`, and a
hunt that fires when the operator switched it off is the failure mode this
whole contract exists to prevent.

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

Read-only FastAPI + vanilla-JS app; never writes to ES. Every write it makes is
to a local YAML file: the grounding denylist below, and hunt files — created,
edited, deleted and toggled from the Hunts page (see [Hunts](#hunts)). Nav:
**Inbox · Explore · Graph · Hunts · Tune** — Tune is a sub-tab shell hosting
two tabs (the old `/artifact-rules` and `/curation` URLs 302 here): **Rules**
(analyst artifact rules) and **Grounding** (command-grounding coverage,
spec-grounding-precompute). The retired Curation page's on-load full-corpus
scan (`/api/health/commands`) didn't scale — the parsed-token grouping key
isn't an ES field, so some process had to read + tokenize every command doc
on every page load. Coverage is now precomputed by the `track
grounding-coverage` pipeline job (own systemd timer, daily) into a single doc
in `prism.metrics.grounding_coverage`; the console reads it O(1)
(`queries.grounding_coverage_summary`). `/api/health/grounding-coverage`
feeds the Health stat bar; `/api/tune/grounding-coverage` feeds the Tune tab's
searchable/paginated needs_def/tldr_only/denied worklist. Block/unblock
(`POST`/`DELETE /api/tune/grounding-coverage/denylist[/{token}]`) still
writes `denylist.yaml` immediately via `enrich.command_grounding`'s
`add_to_denylist`/`remove_from_denylist`; the report's counts catch up on the
next scheduled job run, not instantly. No report doc yet (fresh deploy)
renders an explicit "pending first run" empty state on both pages. Health is off the nav;
its door is the topbar Health badge, a keyboard-focusable `<a href="/health">`
carrying two signal dots (ingestion freshness from the rollup `@timestamp`;
pipeline-cycle health inferred from `prism.ops`, see Run telemetry above) plus a
chevron, with a tooltip breaking out both signals. `/health` still resolves
directly and adds a **Clustering performance** section: a per-type
clusters/outliers grid (IP/session/command) with each type's outlier share
(`n_outliers / total_docs`, `—` when `total_docs == 0` or the type never ran),
rendered client-side from the existing `/api/health/runs` rows.
`/health` also carries an **observability lane** (all read-only, best-effort):
a top **status strip** with an ES-pressure tile (`/api/health/pressure` →
`es_pressure`, the parent-breaker ratio via `enrich.es_health.parent_breaker_ratio`
classified ok/warn/crit against the `heap_high`/`heap_resume` watermarks, or
`unknown` when the probe is unavailable/denied) and a per-sensor freshness table
(`/api/health/sensors` → `sensor_freshness`, a `terms` agg on `observer.name.keyword`
+ max `@timestamp` over the **sessions rollup only**, `stale` per
`ops.sensor_stale_min` minutes); an **Intel coverage** block (per-kind doc count +
last refresh, filtered client-side from the `intel_*` rows already in
`/api/health/freshness` — no extra query); and prominent failed-run emphasis in
the Pipeline-activity panel (row highlighted, `rc` shown). The two pure
classifiers (`_derive_pressure_state`, `_sensor_freshness_rows`) are unit-tested
offline (`smoke_test_health_observability.py`)
(`/findings` redirects to `/inbox`; `/compare` redirects to `/graph`; `/history`,
`/browse`, and `/insights` all redirect to `/explore`, with `/history` preserving
its query string). The graph swim-lane is IP → Session → Command → File; inline
compare renders a verdict card for a peer cluster/playbook/campaign; the Report
tool gathers in-view artifacts into a copy-ready writeup (IOCs defanged by
default). Explore (formerly History) is a longitudinal one-row-per-playbook list ranked by a
composite `interest` score — weights liveness·.30 / trend·.25 / recurrence·.20 /
mass·.15 / escalation·.10 in `_HISTORY_WEIGHTS` (queries.py). `/api/history` takes
`entity` (playbook/session_cluster/ip_cluster/campaign/operation), `window`
(30d/90d/180d/all/custom, default 90d), `sort`, `filter` (all/recurring), and
`state` (all/live/dead) params. Playbooks and session-clusters are a direct `terms`
agg on `session.playbook_id` / `session.cluster.id` (native novelty). The member-set
entities have no per-session field, so each band is built by a shared `_band_msearch`
filtering `sessions_rollup`: campaigns by `member_session_ids` (`cowrie.session_id`),
operations by `member_source_ips` (`source.ip`), IP-clusters by member IPs collected
from `ips_rollup`'s `ip.cluster.id` (top `_IPCLUSTER_MEMBER_CAP`=200 by activity).
Campaign/operation membership is a mining-time snapshot (misses later-backfilled
sessions until re-mined). Each row's band is
time-flipped (now on the left) with a live-period strip marking alive spans; an
entity is `dead` when silent for `_HISTORY_DEAD_DAYS` (14) at the leading edge. Search, install, page list, API endpoints, and the deliberately-
duplicated config/ES code are documented in [`console/README.md`](../console/README.md).

## CI gates

The full pre-commit surface — all must pass before handing back for commit. Run
via `console/.venv`:

```bash
# Lint + offline smoke (always)
console/.venv/bin/ruff check src scripts
console/.venv/bin/python scripts/run_smoke.py

# Quality gates (always run them all)
console/.venv/bin/python scripts/eval_operational.py --baseline eval/baseline-operational.json --no-json   # THE operational gate
console/.venv/bin/python scripts/eval_clustering.py --baseline eval/baseline.json --no-json   # DIAGNOSTIC (exits 0)
console/.venv/bin/python scripts/eval_assignment.py --baseline eval/baseline-assignment.json --no-json   # DIAGNOSTIC (exits 0)
console/.venv/bin/python scripts/eval_assignment_faithful.py --no-json   # TEMPORARY DIAGNOSTIC; shared production decision path
console/.venv/bin/python scripts/eval_assignment_prod.py --baseline eval/baseline-assignment-prod.json --no-json
console/.venv/bin/python scripts/eval_production_scale.py --snapshot eval/production-snapshot-v1.jsonl.gz --baseline eval/baseline-prod-scale.json --no-json
console/.venv/bin/python scripts/eval_command_scale.py --snapshot eval/command-snapshot-v1.jsonl.gz --baseline eval/baseline-command-scale.json --no-json
```

**Lint contract.** Both the rule set and the ruff version are pinned: the
enforced rules live in `[tool.ruff.lint] select` / `ignore` in
[`pyproject.toml`](../pyproject.toml), and CI installs `ruff==0.16.3`
([`ci.yml`](../.github/workflows/ci.yml)) to match `console/.venv`. Without the
`select` pin, "the default rules" means whatever the installed ruff decides, so
a ruff release changes what CI enforces with no code change. Every entry in
`ignore` carries the reason it is off; bump the version in both places together.

What each gate measures, the eval-scale-vs-production-scale distinction, and the
snapshot refresh cadence are in [evaluation.md](evaluation.md).
`eval_assignment_prod.py` also checks the current snapshot anchor count against
the baseline `n_anchors`, so a recaptured snapshot must be rebaselined before
the gate can pass.

**Faithful-replay fixture depth.** `eval_assignment_faithful.py --anchors
eval/anchor-snapshot-v1.jsonl.gz` replays against the committed public anchor
snapshot; `--background eval/background-cohort-v1.jsonl.gz` (optional, operator
must first run `capture_anchor_snapshot.py --background-out ...` against live
ES) pads that replay's TF-IDF/SVD fit with a broader, non-scored public session
sample so the fit's document-space size approaches production's rather than the
eval window alone. Omitting `--background` is byte-identical to not having the
flag at all — it changes nothing unless supplied. Capture refuses any
explicitly-public command taxonomy with fewer than two distinct non-outlier
cluster IDs before it samples sessions or writes either fixture. Outlier-only
and single-real-cluster mappings are equally degenerate, so
committed lexical bags cannot be derived from the fallback token; classify and
rebuild the command enrichment index before retrying.

**Reliability diagnostic (not a gate).** `scripts/eval_agreement.py` scores
annotator agreement over the overlap of two `labels.yaml`-schema files —
intra-annotator (an operator's original vs a delayed blind re-label) or
inter-annotator (two annotators). It reports Cohen's κ, PABAK, and overall +
per-label percent agreement, each with a bootstrap CI, over a **three-way**
per-session category: the `playbook_label`, `__novel__` (real, no playbook), or
`__reject__` (not real) — `__novel__` and `__reject__` are never merged. The
number bounds how good any downstream metric can honestly claim to be. It is a
diagnostic (exit 0); the only non-zero exit is a usage error (empty overlap /
unreadable file). Not wired into CI — there is no committed second-label file
yet, and κ has no code-regression semantics.

```bash
console/.venv/bin/python scripts/eval_agreement.py \
  --labels-a eval/labels.yaml --labels-b eval/labels-relabel.yaml
```
