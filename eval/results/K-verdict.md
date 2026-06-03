# Phase K verdict — ADOPTED + VERIFIED in production (behaviour-driven IP geometry)

_Captured 2026-06-03._

## TL;DR

**K adopted, default-on, and verified against the live cluster.** Dropping the
queryable provenance/tool dims (country + ASN + HASSH) and replacing them with
behaviour signal — **Tier 1** (per-IP intent/playbook/diversity/temporal/volume
scalars) + **Tier 2** (IP-as-bag-of-session-clusters, TF-IDF→SVD fit at cluster
time) — fixed the mega-cluster the first two K attempts and Phase J could not.
Largest cluster **69.6% → 27.2%** of clustered IPs; **6 of 7** binding metrics
pass. The deployed recluster reproduced the in-memory measurement essentially
exactly (see Production verification below).

## Production verification (deployed run `49a8c5de`, 2026-06-03 19:34Z, 2,331 IPs)

Read back from the persisted cluster run + per-IP rollup assignments:

| metric | K5 measured | deployed (real) |
|---|---:|---:|
| clusters | 146 | 146 |
| largest cluster | 554 (27.2%) | 555 (27.2%) |
| outlier rate | 12.6% | 12.5% |
| largest modal intent | 1.0 reconnaissance | 100% reconnaissance |
| Zgrab consolidation | 18/22 + 4 out | 18/22 in cluster_7 + 4 out |

All **top-10 clusters are 100% intent-coherent AND 100% playbook-coherent** — the
behaviour-driven geometry produces clean clusters and the mega-cluster is gone.

## The three measurements (in-memory, non-mutating; `scripts/diagnose_ip_clustering.py`)

`current` reproduced the deployed run exactly (222 clusters / ~350 outliers / 6
J0 fragmentation cases), confirming fidelity.

| metric | K1 current | K3 Tier 1 + drop | K5 + Tier 2 (adopted) |
|---|---:|---:|---:|
| clusters | 222 | 66 | 146 |
| outlier rate | 15.1% | 5.0% | 12.6% |
| largest cluster | 5.4%¹ | **69.6% FAIL** | **27.2% PASS** |
| largest modal intent share | 1.0 | 1.0 | 1.0 |

¹ low only because `current` over-fragments into 222 clusters.

**Tier 1 alone wasn't enough** (K3): it made the dominant reconnaissance
population intent-*coherent* but couldn't break it up — those ~1,540 IPs share
intent + modal playbook + a near-identical command embedding, differing only in
the country/ASN that was dropped. **Tier 2 was the unlock**: the recon IPs run
*different mixes* of session clusters (the modal playbook spans ~20 session
clusters: cluster_18 ≈50%, cluster_50 ≈17%, long tail), so the
bag-of-session-clusters signature re-separates them where the mean embedding
can't.

## Scorecard (`scripts/score_K3_vs_K1.py`, K5 vs K1)

| metric | result | detail |
|---|:--:|---|
| 1 Zgrab consolidates | borderline | 22 IPs → **1** cluster (18) + 4 outliers — no longer split across 3; not the strict "0 outliers" |
| 2 fragmentation drops (≥4/6) | PASS | 5/6 (feab 3→1, 89c10e 141→90, 94d870 37→21, bfb392 27→12, d275 3→2) |
| 3 cluster count ≥25 | PASS | 146 |
| 4 intent coherence (largest ≥80%) | PASS | 1.0 reconnaissance |
| 5 largest ≤30% | PASS | 27.2% |
| 6 outlier rate 5–25% | PASS | 12.6% |
| 7 session ARI stable | PASS | Δ 0.0000 (IP geometry doesn't feed session clustering) |

Metric 1 is the only non-pass, and only on its strict "0 outliers" clause: the
Zgrab IPs are *consolidated into one cluster* (the original 3-way ASN split is
gone), with 4 edge IPs falling to HDBSCAN noise. Operator decision: ship and
verify real-world rather than tune the 4 outliers away.

## What shipped (default ON)

- `ip.cluster_attribution_provenance_enabled = false` — drop country + ASN + HASSH.
- `ip.cluster_tier1_enabled = true` — Tier 1 behaviour scalars (`_build_tier1_block`).
- `ip.cluster_tier2_enabled = true` / `ip.cluster_tier2_svd_dim = 24` — Tier 2
  bag-of-session-clusters (`_pull_session_cluster_bags` + `_build_tier2_block`,
  fit at cluster time inside `run_cluster`).

Code: `src/enrich/sources/cowrie/ips.py`. Smoke tests:
`scripts/smoke_test_ip_tier1_block.py`, `scripts/smoke_test_ip_tier2_block.py`,
`scripts/smoke_test_ip_attribution_prune.py`. The diagnostic's `--geometry k4`
path drives the **same production builder**, so the measurement equals what ships.

## Deploy (done 2026-06-03)

`cluster ips --refresh-reference` was run on the live cluster; the reference
set re-bootstrapped on the dim change and the run reproduced the measurement
(Production verification table above). To re-confirm on a later corpus, read the
persisted run + per-IP `cluster.id` assignments back from ES (cluster count,
largest-cluster share, top-cluster intent coherence, Zgrab spread).

## Open follow-ups

- **Metric 1's 4 Zgrab outliers** — acceptable now; revisit with mcs/min_samples
  or Tier 2 weight if real-world shows useful IPs dropping to noise.
- **HASSH `_source` bug** (ROADMAP IP-layer) is now moot for clustering (HASSH is
  dropped from the geometry) but still leaves the rollup's HASSH analytics thin;
  fix independently if HASSH querying matters.
