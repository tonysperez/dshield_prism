# Scale-hardening architecture decisions

_Decided 2026-06-02, after the P0 measurement spike ([P0-projection.md](P0-projection.md))._

Four decisions that gate the P1/P2 build. Resolves the scale-hardening plan's
"Open questions" and the required P2.2 / P6 decision docs.

## D1 — Clustering scope: **Hybrid (window + weekly full)** · resolves P1.2 / Open-Q1

6-hourly backward cluster runs operate over a rolling window (last *N* days,
tunable; start ~90d). A full all-time re-cluster runs on a slow cadence
(weekly).

**Why.** P0 projects ~370k command-bearing sessions at target → all-time
clustering every 6h is tens of minutes–hours per layer. Windowing bounds
steady-state cost; the content-addressed `spb-` anchors + persisted
`reference_centroid` set already make identity and novelty stable across
windows, so a window re-derives the same ids. The weekly full pass preserves
completeness for long-tail / dormant playbooks.

**Build implications.**
- Add a window filter (session `@timestamp`) to the cluster `docs_iter` for the
  6h cycle; a `--full` mode (or separate slow timer) for the all-time pass.
- Window length *N* is a config tunable — ship a conservative default, measure,
  tune (repo pattern). Campaign miner already windows at 30d.
- P1.3 (late_fusion O(N²) hard refusal) still ships — windowing lowers N but the
  guard stays.
- P5.1 reuse + lifecycle already preserve dormant playbook identity/name, so a
  window dropping a playbook from the live centroid set is safe.

## D2 — Rollup retention: **Hot forever, shard bump 1→5** · resolves P2.2 (Option B) / Open-Q2

Keep all session/IP rollups hot and queryable; partition by bumping
`number_of_shards` 1→5 on the next reindex. No data-stream / ILM migration for
the processed indices.

**Why.** P0 projects session rollups at ~21M docs / ~21 GB at 3yr — under the
~50 GB single-shard soft ceiling. 5 shards ≈ 250 GB headroom (years). Avoids the
data-stream custom-`_id` problem: the `_id` upsert is the load-bearing
idempotency primitive. The console keeps doing all-time aggregations.

**Build implications.**
- Reindex session rollup (and IP rollup) into 5-shard indices. **Combine with
  the D3 `_id` change — one reindex.** Set `replicas` per HA appetite (0 today).
- **P2.3 (firewall-IP TTL):** "hot forever" does *not* extend to firewall-only
  IPs — the I3 source adds 5–10× IP cardinality (dormant scanners). Apply
  silent-run retirement / TTL to firewall-only `source_ip` lifecycle docs (reuse
  the `findings.lifecycle.retire_silent_runs_*` pattern). Set the TTL when I3
  ships.

## D3 — Multi-sensor session ids: **Namespace now** · resolves P6.2 / Open-Q5

Change session-doc `_id` to `<sensor_id>:<cowrie_session_id>` across
session-keyed docs now, via a one-time reindex.

**Why.** Cost-of-delay — ~228k rollups today vs ~21M after the 90× ramp.
Eliminates cross-sensor collision risk before the data grows. `observer.name`
is already pulled by the ingest pipeline.

**Build implications.**
- Reindex session rollup with the new `_id` — **combine with D2's shard bump
  (single reindex).**
- Update the rollup builder (`_build_session_doc` / `run_rollup`) to key `_id`
  as `<sensor>:<session_id>`; thread the sensor id through (defaults to
  `observer.name`, or a configured `sensor_id`, while single-sensor).
- Audit downstream `session_id` references for the new format: findings,
  lifecycle, campaign `member_session_ids`, file-crossref (this is P6.1's
  `observer.name`-propagation audit).
- No collision monitoring needed (namespacing removes the race); P4.2 ops docs
  still wanted for telemetry.

## D4 — Cross-sensor playbook identity: **Same playbook by design** · resolves P6.3 / Open-Q6

An `spb-` playbook that matches across sensors by centroid cosine **is the same
playbook**. No sensor scoping on the anchor index.

**Why.** Supports "how widely is this attack used?" — the core question.
`observer.name` rides along for per-sensor filtering without fragmenting
identity.

**Build implications.**
- Document the contract: `spb-` ids (and IP-cluster / campaign ids) are
  corpus-wide and sensor-agnostic. Add a guard note so no one introduces
  sensor-scoping downstream.

## Derived (not separately asked)

- **P4 telemetry path:** `prism.ops` sentinel docs (the ROADMAP residual's
  "sentinel doc written by the verbs"). Build **P4.2 alongside P1.1** so the
  windowed re-pool is measurable.
- **P6.4 flock:** keep the single `flock` for now; revisit per-sensor locking
  when I3 + multi-sensor cadences actually overlap. Direction if contention
  shows: per-source lock.

## Recommended build sequence

1. ~~**One reindex** = D2 (5 shards) + D3 (namespaced `_id`)~~ — **SHIPPED
   2026-06-02** (see below).
2. **P4.2** ops docs (pairs with P1.1 measurement).
3. **P1** hybrid windowed clustering (D1) + P1.1 conditional re-pool + P1.3
   late_fusion guard.
4. **P6.1** `observer.name` propagation audit + **P6.3** identity declaration
   (cheap; alongside P1).
5. **P2.3** firewall-IP TTL when I3 lands.

## Shipped: D2 + D3 (2026-06-02)

- **D2** — `setup/es-mappings/cowrie/{sessions,ips}.json` bumped to
  `number_of_shards: 5`.
- **D3** — session rollup `_id` = `<sensor>:<session_id>` (`_session_uid`,
  `_DEFAULT_SENSOR="default"`); `_build_session_doc` captures `observer.name`;
  the two raw-id rollup reads (`_fetch_ioc_coverage`, console report
  `mget→search`) now query the `cowrie.session_id` field; `lookup_session`
  already had a field fallback. Smoke: `scripts/smoke/smoke_test_session_uid.py`.
- **Sensor-name source (verified against live ES):** `observer.name` /
  `cowrie.sensor` are present on **0%** of raw events — cowrie isn't configured
  to emit a sensor name — so left alone D3 degenerates to `default:` for
  everything (no real collision protection). Resolution (operator-chosen): stamp
  `observer.name` at ingest, per sensor. The base pipeline now preserves an
  externally-set `observer.name`, and `setup/1-create-sensor-pipelines.sh`
  generates the per-sensor wrapper pipeline file(s) (prompts for names, never
  edits existing). Verified with `_ingest/pipeline/_simulate`: wrapper value
  survives; legacy `cowrie.sensor` still maps; neither → `default:`. Operator
  action: run the generator, apply, then set each sensor's Fleet integration
  `pipeline:` field + its own agent policy.
- **Open follow-up (multi-sensor only):** field-query reads of the rollup don't
  yet filter by `observer.name`, so once a 2nd sensor shares a raw session id
  those reads could match both. Single-sensor is exact. Harden when sensor #2
  lands (part of P6.1).

### Post-rebuild verification (dev box rebuilds from raw)

Shard/`_id` changes need a fresh index — run `pipeline --force` (or
`init-indexes` after deleting the rollup), then check:

1. `GET prism.rollup.cowrie.session/_settings` → `number_of_shards: 5`.
2. A rollup doc `_id` looks like `default:<hex>` (or `<sensor>:<hex>`); the
   `cowrie.session_id` field still holds the raw id; `observer.name` present.
3. `name playbooks` runs and **IOC coverage is non-empty** (proves
   `_fetch_ioc_coverage`'s field query post-namespacing).
4. Console: a session pivot opens (lookup_session fallback) and the **Report
   tool** lists gathered sessions (proves the report field-query).
