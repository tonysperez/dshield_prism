# E8.2 — embed_input_order sweep (production scale)

_Captured 2026-06-01T19:56:27.217986+00:00_

Sorted by ARI descending. 3 layouts swept against the full production corpus (~4033 rollups), scored on the labeled eval subset.

| layout | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters_total | n_outliers_total |
|---|---|---|---|---|---|---|---|---|
| prelude_first | 0.3906 | 0.5478 | 0.8640 | 0.6705 | 0.6705 | 0.6667 | 24 | 37 |
| command_first | 0.3506 | 0.5289 | 0.8057 | 0.6386 | 0.6386 | 0.6667 | 50 | 43 |
| command_only_with_tag | 0.3010 | 0.5176 | 0.7800 | 0.6223 | 0.6223 | 0.6667 | 52 | 45 |

**Baseline** (persisted production cluster ids, no re-embed): ARI 0.3906, completeness 0.5478.

## Verdict

**`prelude_first` (current production default) wins.** No adoption — the
E8.1 knob ships at its default value.

- `command_first` regressed −0.040 ARI / −0.058 homogeneity. Doubled the
  cluster count from 24 → 50, suggesting the rearranged layout makes
  HDBSCAN over-segment.
- `command_only_with_tag` regressed −0.090 ARI / −0.084 homogeneity.
  Also produced ~50 clusters. Drops the prelude entirely and falsifies
  the E0.3 "prelude is noise" hypothesis at production scale: the
  enrichment-context prelude is doing real clustering work on this
  corpus, not diluting the encoder's signal.
- `divergent_pair_resolution_rate` is flat at 0.6667 across all three —
  the same `dp-009` BusyBox-Enable failure case the existing eval
  baseline carries. The layout change doesn't help (or hurt) the
  divergent-pair stress test.

The knob stays in `config/default.yaml` as `embed_input_order:
"prelude_first"` — opt-in for future experiments without churning the
existing default. The 4571 commands stamped with the cooc=false hash
`5399ddfcd1e0a803` remain valid; no reembed required to land E8.