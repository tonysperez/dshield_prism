# E8.3 — MITRE strip-and-measure (production scale)

_Captured 2026-06-01T20:03:33.776471+00:00_

Two embed_context configurations swept against the full production corpus, scored on the labeled eval subset.

| config | embed_context | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters_total | n_outliers_total |
|---|---|---|---|---|---|---|---|---|---|
| production | [intent, tactics, techniques, description] | 0.4170 | 0.6674 | 0.7861 | 0.7219 | 0.7219 | 0.0000 | 10 | 7 |
| mitre_stripped | [intent, description] | 0.4170 | 0.6674 | 0.7861 | 0.7219 | 0.7219 | 0.0000 | 10 | 7 |

**Baseline** (persisted production cluster ids, no re-embed): ARI 0.4170.

## Verdict

**within_noise**

|Δ ARI| = |+0.0000| < ±0.02. The two configs are within the plan's noise band. **Keep production** (`[intent, tactics, techniques, description]`) for stability — there's no signal to justify a config change. MITRE-IDs neither help nor hurt clustering at production scale on this corpus; E0.3's eval-scale "opaque noise" claim doesn't generalise. The production-scale numbers don't crown either config; the existing one wins on inertia.