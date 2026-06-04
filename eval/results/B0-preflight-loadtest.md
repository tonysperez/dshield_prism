# B0 pre-flight — measured results (backlog readiness)

**Date:** 2026-06-04. **Context:** Phase B0 of
[handoff-backlog-readiness-review.md](../../docs/handoff-backlog-readiness-review.md)
— the "do before any data lands" pre-flight, run against the **live single-sensor
deployment** (`so.tonystech.net`, 1 sensor, 37-day corpus) to settle the
backlog's scale and cost assumptions with real numbers before ingesting the
3-sensor × 2-year backlog. Harness: [scripts/loadtest_ip_recluster.py](../../scripts/loadtest_ip_recluster.py).

## Current-corpus baseline (the projection base)

All cardinalities via `_count` / `cardinality` agg (never `docs.count` — nested
sub-docs inflate it).

| Quantity | Value |
|---|---|
| Corpus span | 2026-04-27 → 2026-06-04 (**37 days ≈ 1.2 months**, 1 sensor) |
| Raw cowrie events | 1,055,564 |
| Command-input events | 65,068 |
| Distinct **exact** commands (enriched docs) | 5,818 |
| Distinct command **shapes** (`shape.hash`) | **659** |
| Distinct source IPs (rollup) | 11,217 |
| **IP-cluster matrix size** (IPs with an embedding) | **2,376 (21%)** |
| Distinct session clusters | 55 |
| Sessions (rollup) | 237,106 |

## B0.1 — Sensor naming: **clean**

All 1,055,564 raw events carry `observer.name = dshield01` — a distinct,
non-`default` name. The catastrophic `"default"`-collision risk (catalog #3) is
**not present** for sensor 1. The session-rollup `observer.name` agg fails live
(field is `text`, no fielddata) and the P6.1 stamp is **local-only / undeployed**,
so the rollup field isn't populated yet — fine for 1 sensor; re-verify the
**new** sensors emit unique `observer.name` at the ingest pipeline before
enrolling them.

## B0.3 — IP full re-cluster: SVD is cheap, HDBSCAN is the wall

**Load-bearing correction to catalog #2:** the IP clustering read filters on
`exists: dshield.cowrie.enrichment.ip.embedding`
([ips.py:557](../../src/enrich/sources/cowrie/ips.py#L557)), so HDBSCAN only sees
**command-bearing IPs (~21% here)**, not all distinct IPs. The doc's "500K rows
into HDBSCAN" is really ~21% of that. Size the wall off **embedded-IP count
`n_e`**, not total distinct IPs.

### Tier-2 SVD — not a wall
`TfidfVectorizer → TruncatedSVD(24)` over `(n_ips, n_session_clusters=2000)`:

| n_ips | 11K | 50K | 100K | 250K | 500K |
|---|---|---|---|---|---|
| elapsed | 0.40s | 0.69s | 1.30s | 2.29s | **4.00s** |
| peak RSS | 136 MB | 181 MB | 243 MB | 392 MB | 620 MB |

Linear, trivial. The "SVD re-fit every run is its own scale event" worry is
**retired** — even at 500K IPs it is 4 s / 620 MB.

### HDBSCAN — the wall, **O(n²)**, time-bound (not memory)
Measured on **real** IP embeddings (768-dim, L2-normalised) and confirmed on
synthetic 824-dim data (both blob-structured and diffuse-random):

| source | n | elapsed | note |
|---|---|---|---|
| real embeddings | 2,000 | 2.2s | |
| real embeddings | 2,376 (full live matrix) | **3.1s** | matches prod `cluster all` p50 11.8s |
| synthetic blobs | 2,000 | 4.1s | |
| synthetic blobs | 11,000 | 148.9s | |
| synthetic random | 5,000 | 29.1s | |
| synthetic random | 11,000 | 149.3s | |
| synthetic random | 25,000 | >180s timeout | |

Fitted exponent **O(n^2.01)** (real) / O(n^2.1) (synthetic) — sklearn HDBSCAN
can't use a space-partitioning tree at 824 dims, so it runs brute-force.
**Memory is never the constraint** (11K → ~250 MB; a 500K × 824 float32 matrix
is only 1.6 GB). **Wall-clock is.**

Projection from the real anchor (`3.1s @ 2,376`, `t ≈ 3.1·(n_e/2376)²`):

| embedded IPs `n_e` | re-cluster time | ≈ total distinct IPs (at 21%) |
|---|---|---|
| 10,000 | 55 s | ~47K |
| 25,000 | 5.7 min | ~118K |
| 50,000 | 23 min | ~236K |
| 100,000 | 1.5 h | ~470K |
| 250,000 | 9.5 h | ~1.2M |
| 500,000 | 38 h | ~2.4M |

**The real operational problem isn't the weekly full re-cluster — it's that the
IP layer has _no window_.** Sessions have the `--window-days` escape valve; the
IP layer reads the whole embedded set **every backward cycle (6-hourly)**. So an
O(n²) pass that reaches ~25 min (≈250K distinct IPs) is paid **4×/day**, not
weekly. That, not memory, is what breaks at backlog scale.

**Mitigations (cheap → structural):**
1. Measure embedded-IP count per sensor from a raw sample; the 21% lever moves
   the wall ~5× vs. the naive all-IPs assumption.
2. The weekly full re-cluster can absorb a ~25 min–1.7 h IP pass; the 6-hourly
   cycle cannot. Backlog scale needs an **IP-layer window or incremental
   re-cluster** (no current escape valve — ROADMAP item).
3. Stage the backfill one sensor at a time (B1) to keep `n_e` under the knee.

## B0.2 — LLM enrichment cost: ~8× cheaper than the catalog assumed

**Correction to catalog #6:** the LLM bill is **not** ~5.2K "unique commands."
A shape-inherit layer ([commands.py:1163](../../src/enrich/sources/cowrie/commands.py#L1163),
`command_shape_dedup.enabled=true`) collapses same-shape commands onto one
canonical LLM generation; the rest inherit:

| | count |
|---|---|
| distinct exact commands | 5,818 |
| ├ shaped (inherit-eligible) | 5,752 |
| └ degenerate (own LLM call) | 70 |
| distinct shapes | 659 |
| **≈ actual LLM generations** | **659 + 70 ≈ 729** |
| naive (no dedup) | 5,818 |

Dedup saves **~87%** of generation calls. The **LLM (generation) bill scales
with distinct _shapes_ + degenerates (~729 now)**; **embeddings** (per exact
command, local Nomic, fast) scale with distinct exact commands (5,818). Shapes
saturate hard (finite attacker tooling, high cross-sensor overlap), so the
3-sensor × 2-year backlog plausibly adds only **low-thousands of net-new
generations** — a one-time local-inference cost of hours, not a blocker. Confirm
with a per-sensor unique-shape sample at ingest (B0.2 in the checklist).

## Net effect on the catalog

- #2 (IP scale wall): **confirmed and quantified** — O(n²) HDBSCAN, time-bound,
  on the **embedded (~21%)** subset; SVD worry retired; the no-window 6-hourly
  cadence is the real break point.
- #5 (intel saturation): unchanged (not measured here).
- #6 (over-built clustering / LLM cost): the **clustering** critique stands; the
  **LLM-cost** framing was ~8× pessimistic — real driver is ~729 generations.
- #3 (sensor identity): sensor 1 is clean (`dshield01`); the check moves to the
  new sensors at enrollment.
