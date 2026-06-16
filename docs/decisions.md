# Design decisions

The load-bearing choices that still constrain the system, and the dead-ends that
were measured and rejected (so they aren't re-attempted). This is the "why";
the "what it does now" is in [architecture.md](architecture.md) /
[reference.md](reference.md), and the measurements behind several of these are in
[evaluation.md](evaluation.md). For the production war-stories told in the
operator's voice, see the **Lessons Learned** section of
[`README.md`](../README.md).

## Decisions that still constrain

**Labeling is nearest-prototype assignment, not full-corpus clustering.** The
embedding earns no measurable edge over a TF-IDF text baseline on this corpus
(see [evaluation.md](evaluation.md)), so re-partitioning the whole corpus every
cycle bought churn without quality. Sessions are assigned to a pinned anchor
library; HDBSCAN only mints new playbooks from the novel tail. Don't reintroduce
a "the embedding is semantically better than text" claim without a new corpus
that actually shows it.

**Playbook ids are content-addressed and cosine-anchored to a write-once index.**
Anchors are pinned at first mint and never updated. Re-anchoring to the latest
centroid would let transitive chains (A~B≥τ, B~C≥τ, A~C<τ) collapse distinct
lineages under one id. This is what keeps a playbook's identity stable as its
membership shifts run-to-run. Campaign/operation ids inherit the stability via
content-hash over their member sets.

**Playbook merge uses complete-linkage, not single-linkage.** A merged group
forms only when *every* pairwise centroid cosine clears the threshold, so a chain
of borderline edges can't bridge unrelated behaviors into one playbook.

**IP clustering is behavior-driven; provenance is dropped from the geometry.**
Country, ASN, and HASSH are queryable post-hoc and over-fragment the same
behavior across hosting platforms and client tools. Clustering on behavior
instead cut the largest cluster from ~70% to ~27% of the corpus. The dropped
provenance blocks stay in the codebase behind
`ip.cluster_attribution_provenance_enabled` for reversibility, but the default is
behavior-only.

**Session embedding is an IDF-weighted mean-pool.** Boilerplate (`cd /tmp`,
`whoami`) gets near-zero weight; rare commands dominate the session vector.
Without it, every session looks like its boilerplate.

**The run is complete only when its `run_summary` sentinel exists.** Cluster
runs write the per-run summary *last*, after centroids and per-doc patches, and
every reader gates on it — so a crash mid-write leaves a half-built run invisible
and readers fall back to the previous complete run. Chosen over a physical
alias-swap: same read-atomicity, no per-run index duplication.

**Cache invalidation is hash-based, not manual.** `llm_config_hash` /
`embed_config_hash` are auto-derived from prompts + config + grounding data.
Manual `prompt_version` knobs got forgotten in ops; a hash can't be.

**Functionally-identical commands inherit instead of re-running the local LLM.**
Same-shape commands (literals → placeholders) inherit intent/description/tactics
from a canonical sibling. The local GPU saturated on thousands of near-identical
commands; this is the relief valve.

**Scale escape valves preserve the persisted geometry.** Windowed clustering
(rolling 30-day 6 h runs + a weekly all-time pass) and fit-only SVD reduction
both keep the full-dim centroids, novelty, and cross-run reference intact — only
the cheap label-assignment step is approximated. So a scale knob never
invalidates the reference set or shifts novelty scores.

**The privacy gate is fail-safe.** Untagged per-sensor data is treated as
confidential, propagated most-restrictive-wins, and confidential data never
reaches the cloud LLM or CTI feeds. Better to leak nothing and under-enrich than
to leak once.

**Cluster specificity uses un-smoothed IDF.** `ln(C/df)/ln(C)`, no Laplace
smoothing — the smoothed form caps singletons below 1.0, which contradicts the
analyst intuition that "appears in only this cluster" is the maximum signal.

**Cost + validation guardrails are first-class, not afterthoughts.** A per-day
cloud-LLM budget cap and schema-validation of every LLM-emitted MITRE TTP against
the real ATT&CK corpus were built early; both caught real failures in production
(a runaway escalation loop; invented technique IDs).

## Dead-ends — measured and rejected

Don't re-attempt these without new evidence; each was tried against the live
corpus and recorded as a null result.

- **Cooccurrence text appended to the embed input** — regressed clustering ARI
  (badly on short commands). LLM-side cooccurrence grounding stays on; only the
  embed-text append was dropped.
- **Alternate embed-input orderings** (`command_first`, `command_only_with_tag`)
  — both regressed ARI vs. `prelude_first`. The knob ships as opt-in dead
  infrastructure for future experiments.
- **Late-fusion clustering** (fuse an embedding-HDBSCAN with a TF-IDF/SVD
  lexical-HDBSCAN) — won +0.085 ARI at *eval* scale, then **regressed at
  production scale** (−0.173 ARI on the live deploy; the lexical view fragments
  ~6× harder as the corpus grows, breaking the fusion). Reverted to plain
  HDBSCAN; `clustering_mode: late_fusion` stays only as inert opt-in
  infrastructure. This is the canonical "won at eval scale, lost at production
  scale" case — it's what motivated the production-scale eval gate
  ([evaluation.md](evaluation.md)). Don't re-enable it expecting an upgrade.
- **IP-cluster consolidation gate** — a multi-clause merge gate over-merged
  catastrophically on this corpus (its safety clauses are flat here: intel is
  off, one playbook dominates). Pure-embedding cosine doesn't separate IPs; the
  attribution/behavior block does.
- **Small-cluster surfacing** as a novelty premise — refuted; the corpus's small
  clusters were not where the interesting signal lived. A different lever
  (behavior-driven IP geometry) paid off instead.
- **Dropping artifacts that appear in >50% of sessions as "too generic"** — killed
  real campaigns where everyone shared one staging URL. Replaced with IDF
  weighting: commodity artifacts sink without being categorically dropped.
- **A high-volume finding kind** — shipped one that produced ~2,000 findings on a
  single corpus and retired it after one cycle. Not a bug; the detection itself
  was too noisy to be useful. (This is why miners now carry a per-run noise
  valve.)
- **Letting Elastic Fleet manage the indices** — Fleet wiped the indices it
  controlled. Setup now creates them manually so Fleet can't.
