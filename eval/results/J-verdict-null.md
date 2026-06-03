# Phase J verdict — NULL (do not adopt; knobs stay default-off)

_Captured 2026-06-03._

## TL;DR

**J nulls at the J3 sweep.** The three-clause gate (pure-embedding cosine +
intel verdict + dominant playbook) is built and ships as opt-in dead
infrastructure, but **no threshold in the swept grid is adoptable** on this
corpus. At every `(rescue, merge) ∈ {0.92,0.94,0.96,0.98}²` config the merge
collapses the IP layer from **222 clusters to 15–20** and rescues **304–309 of
350 outliers** — catastrophic over-merge, not the targeted Zgrab fix. Both
`ip.cluster_rescue_threshold` (0.0) and `ip.cluster_merge_threshold` (1.0) stay
default-off.

## What the gate was supposed to do

Consolidate genuine over-fragmentation — same probe split across ASN-distinct
centroids — while the gate's two safety clauses kept attributionally-distinct
IPs apart. The motivating case (`docs/handoff-ip-cluster-consolidation-plan.md`)
was the Zgrab HTTP spray: 3 IP clusters sharing `dominant_playbook =
spb-feab4397c2bdcac3`, differing only by ASN.

## What J0 measured (`scripts/diagnose_ip_fragmentation.py`)

run_id `8c0f0e82…` — 222 centroids, 1,978 clustered IPs, 350 outliers.

| | value |
|---|---|
| fragmentation cases (same playbook, >1 cluster) | 6 |
| would-be-rescue outliers (gate passes @0.94) | **308 / 350** |
| would-be-merge centroid pairs (gate passes @0.94) | **10,841 / 10,899** |

The Zgrab case **reproduces exactly** — `spb-feab4397c2bdcac3` → 3 clusters of
sizes 11/6/3 (the 20-IP cluster_8/9/10 case). But it is one of six, and the
other cases are the problem:

| dominant_playbook | clusters sharing it |
|---|---|
| `spb-89c10e55e4cfa78d` | **141** |
| `spb-94d8703fbaf4fae1` | 37 |
| `spb-bfb392ed9fdaa5e4` | 27 |
| `spb-a30bd43f516f312e` | 4 |
| `spb-feab4397c2bdcac3` (Zgrab) | 3 |
| `spb-d27502498192ccc5` | 3 |

## What J3 measured (`scripts/sweep_ip_consolidation.py`)

2,328 IPs · base HDBSCAN → 222 clusters / 350 outliers, held fixed. Rescue +
merge applied in memory across the 16-config grid. Representative rows:

| rescue | merge | rescued | clusters | centroid_drop | consolidation |
|---:|---:|---:|---:|---:|---:|
| 0.92 | 0.92 | 309 | **15** | 207 | 10,897 |
| 0.98 | 0.98 | 304 | **20** | 202 | 10,887 |

The grid is essentially flat: the most conservative config tested (0.98/0.98)
still removes 202 of 222 clusters. There is no knee — no threshold where the
gate catches Zgrab-like cases and leaves the rest intact.

## Why it fails (the gate's safety clauses are flat on this corpus)

The gate is only as restrictive as its three clauses. Two of them carry no
signal here, so it degrades to "merge anything within cosine threshold":

1. **Clause (b) intel verdict — dead.** Intel is disabled on this deployment
   (`intel.enabled=false`), so every IP groups as `no_data`. The
   ShadowServer-vs-malicious discriminator the attribution block was built
   for contributes nothing.
2. **Clause (c) dominant playbook — too coarse.** One playbook
   (`spb-89c10e55e4cfa78d`) is the modal intent for **141 of 222 clusters**.
   "Same dominant playbook" therefore does not separate genuinely-distinct
   actor profiles — most of the corpus shares it.
3. **Clause (a) pure-embedding cosine — non-discriminating at the IP layer.**
   With (b) and (c) flat, only cosine remains, and IP *behaviour* embeddings
   are near-identical across most IPs (10,841/10,899 same-playbook pairs ≥0.94).
   **The attribution block (ASN/country/cred/HASSH/intel) is what creates the
   222 clusters in the first place** — merging on pure embedding undoes exactly
   the separation that produced them.

This re-confirms the original F1 decision to decline IP-layer rescue
(`eval/results/F1-outlier-diagnostic.md`): IP outliers sit at median
pure-embedding cosine 1.000 to a cluster but are attributionally distinct. The
plan's "both cases or neither" reconciliation cuts the other way here —
**neither** — because the restrictiveness it relied on isn't present.

## Success-metric scorecard (all binding metrics fail)

| # | metric | target | result |
|---|---|---|---|
| 1 | cluster-pair consolidation | ~3 (Zgrab) | 10,887–10,897 — over-merge |
| 2 | outlier reduction only for gate-passers; F1's ~309 mostly stay | small | 304–309/350 rescued — opposite |
| 3 | centroid count drop = pairs that consolidate | a handful | 202–207 of 222 removed |
| 4 | session ARI not regressed | ≥0.30 floor | unaffected (IP clusters don't feed session ARI; eval gate Δ=0.0000) |
| 6 | analyst confirm ≥0.80 | — | not run; collapsing 222→15 is not analyst-confirmable |

J3.2 (analyst render) was not run — the sweep result is disqualifying on its
own; no analyst confirms a 222→15 collapse.

## Disposition

- **Implementation reverted.** Unlike the plan's J3.3 "keep as opt-in dead
  infra" branch, the operator chose to back the code out entirely after the
  null. Removed: the `ips_consolidation` module, the
  `rescue_predicate_factory` / `cluster_merge_fn` hooks added to
  `run_layer_clustering`, the `ip.cluster_rescue_threshold` /
  `ip.cluster_merge_threshold` knobs, the `merged_from` mapping field, and the
  J0/J3 diagnostic + sweep scripts. The IP clusterer is back to its pre-J state
  (HDBSCAN over embedding + attribution block, no post-hoc consolidation). This
  verdict is the self-contained record; re-implement from
  `docs/handoff-ip-cluster-consolidation-plan.md` if revisited.
- **Do not revisit without first** (a) enabling intel so clause (b) carries
  signal, AND (b) a per-IP behavioural label finer than `dominant_playbook_id`
  (the current label is too coarse — one value covers 141 clusters). Even then
  the clause-(a) premise is suspect: pure-embedding cosine is not discriminating
  at the IP layer.
- **More promising directions** for the actual Zgrab over-fragmentation, both
  parked in the plan's "what this does NOT touch" section: option C
  (cloud-ASN pooling — treat Akamai/HE/DO as one "cloud" ASN column at the
  scalar-block level) and the existing
  [ROADMAP IP-layer "augmented-space noise rescue"](../../docs/ROADMAP.md#ip-layer)
  bullet. These attack the attribution block directly rather than discarding it.

The raw per-run dumps (`J0-ip-fragmentation-*.md`, `J3-sweep-*.{md,json}`)
were derivative and not retained — every salient number from them is inlined
above.
