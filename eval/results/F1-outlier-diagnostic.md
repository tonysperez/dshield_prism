# F1 — per-layer outlier diagnostic + F1b decision

_Captured 2026-06-02._

Reproduce: `console/.venv/bin/python scripts/diagnose_outlier_subclusters.py --layer {commands,ips}`

## Headline

**The command layer carries the corpus's outlier mass — 27.7% (1,279 of
4,610) — and 91.7% of it is HDBSCAN density noise, not novelty. Wiring the
session layer's noise-rescue valve into the command layer at 0.94 cuts the
command outlier rate to ~2.3%, with 100% of rescued commands joining an
intent-matching cluster.** Shipped as `command_cluster.rescue_threshold:
0.94` (F1b). The IP layer is a different story — its outliers are
behaviourally near-identical to existing clusters but **attributionally
distinct** (different country/ASN), so they cluster apart by design and
pure-embedding rescue would misassign them (below).

This is the plan's metric-1 target (outlier rate ↓ ≥20% relative) hit by a
wide margin — a 92% relative reduction — on the layer where the mass
actually is. The session layer, by contrast, is already at 0.9% outliers.

## The pipeline asymmetry (confirmed by reading the code)

`run_layer_clustering` takes `rescue_threshold` (default `None` = off,
[clustering.py:158](../../src/enrich/clustering.py#L158)). The session
layer passes it (`playbook_merge_threshold`); the command + IP layers did
not. So command/IP "outliers" are **pre-rescue** and over-counted relative
to the post-rescue session outliers — the plan's "1.5k" was almost all
command-layer pre-rescue noise.

## Command layer — rescue is a clean win

| | value |
|---|---|
| scored docs | 4,610 |
| non-outlier clusters | 68 |
| outliers (pre-rescue) | 1,279 (**27.7%**) |
| median outlier→nearest-centroid cosine | **0.993** |
| rescuable at 0.94 | 1,173 (**91.7%**), **100% intent-matching** |
| outlier rate after rescue@0.94 | **2.3%** |

The outliers sit essentially *on top of* existing centroids (median 0.993)
— commodity commands HDBSCAN dropped on density, not behaviour. Rescue
reassigns them to the nearest centroid and creates no new clusters, so
bulk-cluster quality is untouched. Geometry is safe: command
`scalar_weight=0.05` (same light augmentation as sessions), so the
pure-embedding rescue cosine is faithful.

**F1b shipped:** `CommandClusterConfig.rescue_threshold` (model default
0.0; `config/default.yaml` ships 0.94), wired into the command clustering
call ([commands.py](../../src/enrich/sources/cowrie/commands.py)). Deploy +
verify on the production box: re-run `cluster commands`, expect
`n_rescued ≈ 1,170` in the run summary and the outlier rate to fall to ~2%.

## IP layer — pure-embedding rescue would misassign (augmented-space geometry)

| | value |
|---|---|
| scored IPs | 2,237 |
| non-outlier clusters | 206 |
| outliers | 309 (**13.8%**) |
| median outlier→nearest-centroid cosine (pure embedding) | **1.000** |
| "rescuable" at 0.94 (pure embedding) | 286 (92.6%) |
| of those, **differ in country** from nearest centroid | **94%** |
| of those, **differ in ASN** from nearest centroid | **97%** |

> **Correction.** An earlier draft of this doc reported "28 of 2,231 IPs
> scored, 2 clusters, median cosine 0.757" and called it a coverage
> anomaly. That was a **measurement artifact** — the query landed mid-
> rollup-rebuild, when `cluster ips` hadn't re-run on the freshly re-pooled
> rollup. The IP layer is healthy: it clusters all ~2,237 IPs into ~206
> clusters every run. The numbers above are from the settled pipeline.

The IP layer is **not** a rescue win, but for the opposite reason from the
old draft. IP outliers sit essentially *on top of* existing centroids in
pure-embedding space (median cosine 1.000) — behaviourally near-identical.
But the IP clusterer runs in the **augmented** space (embedding +
`cluster_attribution_weight=0.10` over country / ASN / cred-hash / intel /
HASSH), and **94% of the would-be-rescued differ in country, 97% in ASN**
from the cluster they're near. They are outliers *by design*: same
behaviour, different attribution. Pure-embedding rescue (the
`rescue_noise_points` mechanism) would pull 286 IPs into clusters they
don't belong to in HDBSCAN's actual geometry, erasing the attribution
distinction the IP layer deliberately preserves — exactly the geometry
caveat the plan flagged for IPs.

So **no IP `rescue_threshold` was wired** (the plan's F1b.2 is correctly
declined). A correct IP rescue would need an *augmented-space* variant
(rescue on the same embedding+attribution geometry HDBSCAN clustered in),
and even then it is questionable whether collapsing attribution-distinct
IPs is desirable — for IPs, a different ASN is arguably a different actor.
The 13.8% IP outlier rate is plausibly *correct*, not a defect.

## What this means for the rest of the plan

- **F1b: ship command rescue (done), decline IP rescue** — pure-embedding
  rescue is geometry-wrong for the attribution-augmented IP space.
- **F2 (secondary HDBSCAN on outliers) is now low-value for commands** —
  after rescue only ~106 command outliers remain, and they're the genuinely
  novel tail. Not worth the `small_` machinery.
- **F5 (IP layer): no rescue/merge intervention warranted.** The IP layer
  is healthy and its outliers are meaningfully attribution-distinct. Any
  future IP outlier work is an augmented-space-rescue research item, not an
  F-phase parity fix.
