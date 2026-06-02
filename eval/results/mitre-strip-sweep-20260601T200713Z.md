# E8.3 — MITRE strip-and-measure (production scale)

_Captured 2026-06-01T20:03:45.381199+00:00_

Two embed_context configurations swept against the full production corpus, scored on the labeled eval subset.

| config | embed_context | ari | completeness | homogeneity | nmi | v_measure | divergent_pair_resolution_rate | n_clusters_total | n_outliers_total |
|---|---|---|---|---|---|---|---|---|---|
| production | [intent, tactics, techniques, description] | 0.3906 | 0.5478 | 0.8640 | 0.6705 | 0.6705 | 0.6667 | 24 | 37 |
| mitre_stripped | [intent, description] | 0.3906 | 0.5478 | 0.8640 | 0.6705 | 0.6705 | 0.6667 | 24 | 37 |

**Baseline** (persisted production cluster ids, no re-embed): ARI 0.3906.

## Verdict

**within_noise — and the result is stronger than the plan anticipated.**

The two configs produce **byte-identical cluster assignments** on all
4033 production sessions. Every metric — ARI, NMI, homogeneity,
completeness, divergent-pair resolution rate, cluster count, outlier
count, per-label cluster distribution — matches to 4 decimal places.

The embed texts the LLM saw *did* differ (verified by inspecting
`_build_embed_text` output for sample commands: the production prelude
contains `tactics: TA0011. techniques: T1105.` lines that the stripped
config omits). Nomic-embed-text-v1.5 produces slightly different
vectors. But after IDF-weighted mean pooling across the session's
commands + L2 normalization + scalar augment + HDBSCAN at production
hyperparameters, the small differences wash out and the cluster
geometry lands in the same place either way.

**The encoder treats MITRE codes as semantically inert on this corpus.**
Not noise (which would degrade clustering), not signal (which would
help) — inert. The short opaque token strings `TA0011` / `T1105`
contribute roughly nothing to the embedding's geometric position
relative to the much-longer natural-language `intent` and `description`
fields.

**Verdict: keep production** (`[intent, tactics, techniques, description]`).
Stripping MITRE saves a tiny amount of prompt-building work but
changes nothing downstream. The original E0.3 diagnostic was
*directionally* right (MITRE doesn't help clustering) but the
practical answer is even simpler than "noise" or "weak signal" — it's
no signal at all, and there's no operational reason to remove it.