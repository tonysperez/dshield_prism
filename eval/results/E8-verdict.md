# E8 verdict — untested cheap knobs

_Captured 2026-06-01._

Two production-scale sweeps; both null. No config changes shipped under
E8. The E8.1 `llm.embed_input_order` knob lands in `config/default.yaml`
at its default value (`prelude_first`) so future experiments can opt in
without churning the existing default.

## E8.2 — embed_input_order layout sweep

Full results: [embed-input-order-sweep-20260601T200117Z.md](embed-input-order-sweep-20260601T200117Z.md).

| layout | ARI | Δ vs prod | n_clusters |
|---|---|---|---|
| **`prelude_first` (current production)** | **0.3906** | — | 24 |
| `command_first` | 0.3506 | −0.0400 | 50 |
| `command_only_with_tag` | 0.3010 | −0.0896 | 52 |

Production default wins decisively. Both alternatives doubled the
cluster count and lost ARI. The E0.3 hypothesis ("prelude is noise on
this corpus, characters per command roughly 10×") is falsified at
production scale — the enrichment-context prelude is doing real
clustering work, not diluting the encoder's signal.

## E8.3 — MITRE strip-and-measure

Full results: [mitre-strip-sweep-20260601T200713Z.md](mitre-strip-sweep-20260601T200713Z.md).

| config | embed_context | ARI |
|---|---|---|
| **`production`** | `[intent, tactics, techniques, description]` | **0.3906** |
| `mitre_stripped` | `[intent, description]` | 0.3906 |

Byte-identical cluster assignments across 4033 production sessions —
every metric matches to 4 decimal places. The LLM saw genuinely
different inputs (the production prelude carries `tactics: TA0011.
techniques: T1105.` lines that the stripped version omits), but
Nomic-embed-text-v1.5 treats those short opaque MITRE strings as
semantically inert relative to the longer natural-language `intent`
and `description` fields. After IDF-weighted mean pooling +
L2-normalize + HDBSCAN, the small per-command vector differences wash
out and the clustering lands in the same place either way.

MITRE codes are not noise. They're inert. Keep them for completeness
(they're useful in downstream analyst views, even if the encoder
ignores them) — there's no operational reason to strip them.

## E8 exit

| Question | Answer at production scale |
|---|---|
| Best embed-input layout? | `prelude_first` (current default). |
| Does the MITRE prelude help, hurt, or neither? | Neither — semantically inert; the encoder ignores it. |
| Should `config/default.yaml` change? | No. |
| Per the plan's stop condition: do we proceed to E9? | Yes. |

The E8.1 knob (`llm.embed_input_order`) ships as opt-in dead
infrastructure — zero runtime cost at the default, available for any
future alt-layout experiment without further code changes.

## Production state

Production rollups are still stamped with the cooc=false hash
`5399ddfcd1e0a803` from the E6.3 revert; no reembed has occurred since.
Adding `embed_input_order` to `compute_embed_config_hash` will trigger
one full reembed on the next backward cycle (the hash shifts even
though `prelude_first` produces byte-identical embeddings to the
pre-E8.1 layout). The reembed will produce identical vectors and stamp
a new hash; the next backward after THAT will show `skipped_fresh:
4571` as the cache settles. Expected and idempotent — flagged in
`config/default.yaml`'s comment block.