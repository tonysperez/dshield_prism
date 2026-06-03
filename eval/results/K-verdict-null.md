# Phase K verdict — NULL (revert; under-clustering as predicted)

_Captured 2026-06-03._

## TL;DR

**K reverts at K3.** Dropping country + ASN from the IP attribution block does
exactly what its own success metric 5 was written to catch: it collapses
**69.5% of clustered IPs (1,533 of 2,206) into a single mega-cluster**. Six of
the seven binding metrics pass — Zgrab consolidates, fragmentation drops, the
cluster floor and outlier band hold — but metric 5 (no mega-cluster, ≤30%) fails
decisively, and metric 5 is the failure the plan said means "revert." The code
change + scripts are reverted; production geometry is unchanged.

## What K tried

Where J (`J-verdict-null.md`) tried to consolidate *after* clustering, K fixed
the geometry at the source: drop the country one-hot + ASN bucket (provenance —
queryable post-hoc) from `_build_attribution_block`, keep cred-hash + intel +
HASSH (behaviour / actor-identity). Premise: cluster on behaviour, leave
provenance to analyst queries.

## Method (`scripts/diagnose_ip_clustering.py`, in-memory, non-mutating)

Pulled the 2,328-IP rollup once and rebuilt production HDBSCAN under each
geometry in memory — no production recluster. The `current` baseline reproduced
the deployed run **exactly** (222 clusters / 1,978 clustered / 350 outliers; all
6 J0 fragmentation cases incl. Zgrab 3 clusters [11,6,3]), confirming fidelity.

## Scorecard (`scripts/score_K3_vs_K1.py`)

| metric | result | detail |
|---|:--:|---|
| 1 Zgrab consolidates | PASS | 22 Zgrab IPs → 1 cluster, 0 outliers |
| 2 fragmentation drops (≥4/6) | PASS | 4/6: feab 3→1, 89c10e 141→17, 94d870 37→23, bfb392 27→10 |
| 3 cluster count ≥25 | PASS | 67 |
| 4 largest cluster ≥80% modal HASSH | PASS | 0.91 (but on a 1,533-IP blob — see below) |
| 5 largest cluster ≤30% | **FAIL** | **1,533 IPs = 69.5% of clustered** |
| 6 outlier rate 5–25% | PASS | 5.2% |
| 7 session ARI stable | PASS | Δ 0.0000 (IP geometry doesn't feed session clustering) |

## K1 ↔ K3 diff

| measure | K1 (current) | K3 (pruned) |
|---|---:|---:|
| clusters | 222 | 67 |
| outlier rate | 15.0% | 5.2% |
| largest cluster | 106 (5.4%) | **1,533 (69.5%)** |

## Why it fails — and why the HASSH fix doesn't save it

The 1,533-IP mega-cluster is the dominant-playbook population (`spb-89c10e55…`)
that J already flagged: behaviour embeddings are near-identical across most IPs.
Country + ASN were the *only* dimensions holding those IPs apart; removing them
collapses them. The plan hoped HASSH + cred would re-separate. They don't:

- **HASSH (with the `_source` bug fixed for the test): makes it worse.** Pruned
  + `--fix-hassh` → largest cluster **1,719 IPs (77.9%)**. The mega-cluster is
  already 91% HASSH-homogeneous, so adding HASSH to the geometry pulls in *more*,
  not fewer. HASSH only separates SSH actors that already differ in client stack;
  the dominant scanner population shares one.
- **Cred-hash** is too sparse on this corpus to re-separate scanners that send
  few/no credentials.

Control: `current --fix-hassh` stays at largest = 106 (5.4%), 232 clusters — i.e.
fixing HASSH does not by itself create or avoid the mega-cluster; **dropping
country+ASN is the cause.** This confirms J's deeper finding from the other
direction: at the IP layer the attribution block (specifically country+ASN) is
doing the load-bearing separation; pure-behaviour geometry under-clusters.

The geometry is bracketed: keep country+ASN → over-fragment (Zgrab split 3 ways);
drop them → 70% mega-cluster. Neither extreme is right.

## Disposition

- **Reverted.** The provenance toggle (`_build_attribution_block` /
  `make_full_scalar_builder` `include_provenance` param, the
  `ip.cluster_attribution_provenance_enabled` knob) and the K0/K2/K3 scripts are
  removed; the IP clusterer is back to its production geometry. This verdict is
  the self-contained record — re-implement from
  `docs/handoff-ip-attribution-prune-plan.md` if revisited.
- **Next, per both verdicts: cloud-ASN pooling (Option C).** K's failure is the
  expected one the plan named — pruning *all* ASN signal under-clusters. The
  surgical middle ground is to pool only cloud/hosting ASNs (Akamai, HE, DO,
  etc.) into one "cloud" column while keeping residential ASN discrimination:
  that collapses the Zgrab-style cloud-scanner fragmentation without dropping
  the ASN separation that prevents the mega-cluster. It needs a curated
  cloud-ASN list (the cost K avoided), which is now the justified next step.
- **Independent prerequisite for any IP-geometry work: fix the HASSH `_source`
  bug** (ROADMAP IP-layer) so HASSH actually reaches the geometry — though K
  shows it won't change the mega-cluster outcome here, future work shouldn't
  reason about a dead signal.

Raw per-run dumps (`K1-baseline-*`, `K3-post-change-*`, `K3-scorecard-*`,
`*-hasshfix-*`) were derivative and not retained — every salient number is
inlined above.
