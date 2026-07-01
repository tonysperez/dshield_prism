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

**History is a longitudinal per-playbook lifecycle list, not archive discovery.**
The original History was salience-ranked "standout" cards over the >14d archive —
the same rate metric as Browse, scrubbed back — and showed no per-behaviour arc.
History is now one row per playbook over a selectable window (30/90/180d · all ·
custom; default 90d), each rendering that playbook's own activity band on a shared
adaptive time axis, ranked by a composite `interest` score (liveness·.30 +
trend·.25 + recurrence·.20 + mass·.15 + escalation·.10, each min-max normalized
across the returned pool so one hot playbook can't peg the rest). The archive-only
`now-14d` exclusion is gone — the window includes recent days. The legacy
`_rank_standout` salience lens is retained only for its smoke test. The page also
covers session-clusters, IP-clusters, campaigns, and operations via an entity
selector. Direct per-session fields (playbook_id, session cluster.id) use a `terms`
agg; the rest have no per-session field so each band is built by a shared
`_band_msearch` over `sessions_rollup` (campaigns by member_session_ids, operations
by member_source_ips, IP-clusters by member IPs collected from `ips_rollup`) —
rather than schema-backfilling ids onto every session, which would be a pipeline +
corpus-write change. Campaign/operation membership is a mining-time snapshot, so
those bands miss later-backfilled sessions until re-mined. This was the path
toward folding Browse into History — now done: Browse is retired (its
Operations/Campaigns tables were superseded by this entity selector), its
corpus-summary stat bar moved to the Health page's Overview section, and the
page itself was renamed History → Explore.

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

**Command intent is a honeypot-native action enum, single-label per command.**
The taxonomy is 11 decidable-from-one-line action labels (`host_recon`,
`download_ingress`, `execute_payload`, `install_persistence`, `defense_evasion`,
`credential_data_access`, `account_manipulation`, `cryptomining`, `ddos_botnet`,
`benign_noise`, `unknown`) — not MITRE ATT&CK tactics. Tactics are session-scoped
goals and mislabel single post-login commands (a small model reaches for
`reconnaissance`/`initial_access`, which are pre-compromise category errors
in-session); the prior bare tactic enum with no per-label guidance was the main
driver of inconsistent labels. The set is the single source of truth in
`enrich/llm/schemas.py` (the IP behaviour matrix derives its intent columns and
its diversity denominator from it), it's advertised as a JSON-schema `enum` so a
grammar-constrained local decoder can only emit valid values, and the prompt
carries explicit INTENT RULES + few-shot examples + a "label by the terminal
objective" tie-breaker.

**Cache invalidation is hash-based, not manual.** `llm_config_hash` /
`embed_config_hash` are auto-derived from prompts + config + grounding data.
Manual `prompt_version` knobs got forgotten in ops; a hash can't be.

**Functionally-identical commands inherit instead of re-running the local LLM.**
Same-shape commands (literals → placeholders) inherit intent/description
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
cloud-LLM budget cap and output-side schema validation (intent clamped to a
closed enum, IOCs filtered to their surface shapes) were built early; both
caught real failures in production (a runaway escalation loop; hallucinated
non-IOC strings).

**ES backpressure rides on the client, not the call sites.** A heap-constrained
node trips the parent circuit breaker (429) at unpredictable places, and the
transport's millisecond retries are far too fast for the breaker to drain. Rather
than harden the handful of sites that happen to fail, a transparent
`ResilientClient` wraps the one object every read/write flows through
([`make_client`](../src/enrich/es_client.py)), so all requests — plus
`helpers.bulk`/`scan` — inherit "wait for heap to drain, then retry" with a shared
~1 h patience budget. The pipeline prefers waiting a long time over failing a
step. Chosen over transport/node subclassing (brittle across elasticsearch-py
versions) and over per-site try/except (doesn't scale to new sites or smaller
nodes).

**IP noise rescue is augmented-space euclidean, not pure-embedding cosine.** The
IP layer flagged ~70% of command-bearing IPs as HDBSCAN noise (every run,
`rescued=0`) while commands/sessions sit at 0.1–0.4%. The obvious fix — reuse the
command `rescue_threshold` (`rescue_noise_points`, pure-embedding cosine) — was
**measured wrong before shipping**: the IP pooled embedding is thin, so the IP
layer clusters on the *augmented* `[embedding ⊕ Tier1/Tier2/attribution]` euclidean
vector. Validation (`scripts/diagnose_ip_rescue.py`, production labels, no
re-cluster): outliers sit at pure-cosine 0.997 to nearest centroid but only 0.73 to
a random one (so the embedding *is* discriminative — rescue is warranted), yet a
pure-cosine rescue would reclaim ~99.5% vs only ~62% that are actually close in the
augmented space — the 38% gap being IPs the scalar blocks *correctly* separated.
So rescue runs in the augmented space HDBSCAN fit on, within a percentile of the
intra-cluster spread (`rescue_noise_points_augmented`). The default is the
**aggressive p99** because purity held flat across thresholds — rescued IPs match
their cluster's modal playbook ~94% and modal intent ~99.7% at p90 *through* p99 —
so p99 reclaims the most (70% → ~6% outliers) without quality loss. (Implementation
note: nearest-centroid distance uses the `‖a-b‖²` matmul identity batched over rows
— the naive 3-D broadcast needed 46 GiB at IP scale and would have OOM'd the live
run.)

## Dead-ends — measured and rejected

Don't re-attempt these without new evidence; each was tried against the live
corpus and recorded as a null result.

- **LLM-derived MITRE ATT&CK tactic/technique IDs** — the local model's
  technique mapping was unreliable best-guess work even after schema-validating
  every emitted ID against the vendored ATT&CK corpus (the prompt itself flagged
  it as "best-guess"). They were also measured *embedding-inert*: the E8.3
  strip-and-measure sweep produced byte-identical clusters with and without the
  MITRE codes in the embed input. Pulled entirely — generation, storage, embed
  context, metrics, and console surfaces. The only MITRE labels that remain are
  the **reference-corpus ground truth** (Atomic Red Team, `dshield.reference.*`),
  which are authored, not inferred.
- **MITRE ATT&CK tactics or techniques as the command-intent label set** — tactics
  are the wrong granularity (session-scoped goals, plus pre-compromise categories
  like `reconnaissance`/`initial_access` that never apply to a post-login
  in-session command), and a curated technique subset is a lossy many-to-one fit
  for single commands (`host_recon` alone spans several Discovery techniques).
  Replaced with the honeypot-native action enum (see *Decisions that still
  constrain*).
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
