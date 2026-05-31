# Threshold inventory — phase 4 calibration target

One-time doc (brutal-review phase 4.1). Catalogs every hardcoded
constant and configurable knob in `evidence_quality.py`, `discovery.py`,
and `drift.py` that decides whether a finding fires or which band it
lands in. Phase 4.2–4.4 commits migrate the headline thresholds from
fixed values to percentile lookups against the per-run distributions
that `src/enrich/findings/metrics.py:compute_threshold_distributions`
writes into `prism.metrics`.

The columns:

  * **Location** — file + symbol, with current default in parens.
  * **Underlying quantity** — what the threshold compares against. The
    percentile-snapshot writer produces a distribution of THIS.
  * **Percentile target** — once the migration ships, the threshold
    becomes a lookup of this percentile from the latest distribution
    doc with a sensible fallback to the current fixed value.

## `evidence_quality.py` — verdict bands (hardcoded)

| Symbol | Location | Underlying quantity | Migrating in | Percentile target |
|---|---|---|---|---|
| `sess >= 20 and ips >= 5` (Strong band) | `_evidence_band` 132 | playbook lifecycle latest-snapshot `session_count` × `ip_count` | **4.2** | p90 of session_count, p90 of ip_count |
| `sess <= 1 or ips <= 1` (Single-point band) | `_evidence_band` 130 | same | **4.2** | p10 of session_count, p10 of ip_count |
| `runs >= 3` (multi-run threshold) | `_evidence_band` 141 | playbook lifecycle `runs_observed` | **4.2** | p50 of runs_observed |
| `magnitude < 0.7` (command/bigram drift band) | `_drift_verdict` 178/182 | command/bigram Jaccard | 4.2 (kept) | hardcoded — already in tight 0..1 range |
| `dist >= 0.30` (artifact/ASN drift band) | `_drift_verdict` 186/190 | artifact Jaccard distance, ASN cosine distance | 4.2 (kept) | hardcoded — already in tight 0..1 range |
| `days >= 1.0` (resurgence "Resurfaced" verdict) | `_resurgence_verdict` 206 | gap_hours / 24 | 4.2 (kept) | hardcoded — interpretable as-is |
| `days >= 1.5` / `hours >= 1.0` (heuristic time deltas) | `_summary_window` 293/296 | same | 4.2 (kept) | hardcoded |
| `sess >= 10 or cmds >= 50` (volume band) | `_volume_band` 379 | session_count / cmd_count | **4.2** | p75 of session_count, p75 of cmd_count |

The drift / time-delta bands stay hardcoded because their underlying
quantities (Jaccard ∈ [0, 1], hours, days) are dimensionless or
human-meaningful — percentile-tuning them would obscure intent.

## `discovery.py` — configurable thresholds

| Knob | Default | Underlying quantity | Migrating in |
|---|---|---|---|
| `discovery.ip_shift_js_distance_min` | 0.3 | JS distance between source-IP lifecycle current vs prior playbook distribution | **4.3** |
| `discovery.ip_shift_min_sessions` | 5 | latest snapshot's `session_count` per source-IP lifecycle | 4.3 (kept; bot-traffic threshold not a corpus-derived value) |
| `discovery.unattributed_min_sessions` | 5 | same | (vestigial — see config.py comment) |
| `discovery.outlier_burst_min_sessions` | 5 | sessions per artifact within `outlier_burst_window_hours` | (later) |
| `discovery.outlier_burst_window_hours` | 24 | time window length | (kept; not corpus-derived) |
| `discovery.convergence_min_ip_overlap_ratio` | 0.4 | `len(bhv_ips ∩ inf_ips) / min(\|bhv_ips\|, \|inf_ips\|)` | **4.4** |
| `discovery.intel_flip_recent_session_days` | 7 | days since the most recent session matching the flipped IP | (kept; calendar window, not corpus-derived) |

## `drift.py` — configurable thresholds (`DriftConfig`)

| Knob | Default | Underlying quantity | Migrating in |
|---|---|---|---|
| `drift.command_jaccard_threshold` | 0.5 | Jaccard(command_set_now, command_set_anchor) | (later) |
| `drift.bigram_jaccard_threshold` | 0.4 | Jaccard(bigram_set_now, bigram_set_anchor) | (later) |
| `drift.artifact_set_drift_min` | 0.5 | Jaccard distance (1 − sim) on artifact_set | (later) |
| `drift.asn_cosine_drift_min` | 0.4 | cosine distance on per-playbook ASN distribution | (later) |
| `drift.size_growth_pct_min` | 0.75 | (curr_ip_count − anchor_ip_count) / anchor_ip_count | (later) |
| `drift.size_growth_min_delta_ips` | 3 | absolute IP delta | (kept; small-N floor) |
| `drift.resurgence_silent_runs` | 8 | snapshot gap count | (kept; calendar floor at 6h cadence) |
| `drift.campaign_growth_pct_min` | 0.75 | same as size_growth for campaign lifecycle | (later) |
| `drift.campaign_growth_min_delta_ips` | 3 | same | (kept) |

## What 4.1 ships

Two distribution computers (the simplest cases that feed 4.2):

  1. `playbook_session_count_per_run` — per playbook-lifecycle latest
     snapshot's `session_count`. Used by 4.2's evidence-band migration.
  2. `playbook_ip_count_per_run` — per playbook-lifecycle latest
     snapshot's `ip_count`. Same.

Each commit 4.2/4.3/4.4 adds its own quantity computer alongside its
consumer change so the work is local. The contract on the writer is
stable: any function `(es, cfg) -> list[float]` registered in
`_THRESHOLD_QUANTITIES` becomes a metrics doc with the standard
percentile shape.
