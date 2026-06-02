# F1 — per-layer outlier diagnostic + F1b decision

_Captured 2026-06-02._

Reproduce: `console/.venv/bin/python scripts/diagnose_outlier_subclusters.py --layer {commands,ips}`

## Headline

**The command layer carries the corpus's outlier mass — 27.7% (1,279 of
4,610) — and 91.7% of it is HDBSCAN density noise, not novelty. Wiring the
session layer's noise-rescue valve into the command layer at 0.94 cuts the
command outlier rate to ~2.3%, with 100% of rescued commands joining an
intent-matching cluster.** Shipped as `command_cluster.rescue_threshold:
0.94` (F1b). The IP layer is a different story — rescue won't help it, and
it has a separate coverage anomaly (below).

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

## IP layer — rescue does NOT help, and a coverage anomaly

| | value |
|---|---|
| embedded IPs | 2,231 |
| **scored IPs** | **28** |
| non-outlier clusters | 2 |
| outliers | 21 (75%) |
| median outlier→nearest-centroid cosine | **0.757** |
| rescuable at 0.94 | **0** |

Two problems, neither solved by rescue:

1. **IP outliers are genuinely distant** (median 0.757; 0 within 0.94).
   Unlike commands, these aren't density noise next to a centroid —
   rescue at any reasonable threshold is a no-op. So **no IP
   `rescue_threshold` was wired** (the plan's F1b.2 is data-rejected here).
2. **Only 28 of 2,231 embedded IPs are scored** — the IP clusterer is
   running on a tiny fraction of the population (2 clusters total). That,
   not rescue, is the IP layer's real issue, and it's why the diagnostic is
   thin. Tracked as a follow-up (ROADMAP, IP layer); likely a coverage
   filter or a stale/partial cluster run, not addressed by F-phase rescue.

## What this means for the rest of the plan

- **F1b: ship command rescue (done), skip IP rescue (data-rejected).**
- **F2 (secondary HDBSCAN on outliers) is now low-value for commands** —
  after rescue only ~106 command outliers remain, and they're the genuinely
  novel tail. Not worth the `small_` machinery.
- **F5 (IP layer) is blocked on the coverage anomaly**, not on rescue —
  fixing "28 of 2,231 scored" is the prerequisite, separate from this plan.
