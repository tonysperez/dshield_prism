"""Config loading. YAML file + .env overrides for secrets."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .__about__ import ENV_PREFIX

_CONFIG_ENV = f"{ENV_PREFIX}CONFIG"
_LOCAL_CONFIG_ENV = f"{ENV_PREFIX}LOCAL_CONFIG"
_ENV_FILE_ENV = f"{ENV_PREFIX}ENV"


class CowrieIndexes(BaseModel):
    """All index names for the cowrie source. One layer per field.

    Naming convention (post-2026-05-17 rename): `prism.<function>.<source>.<layer>`.
    The `prism.*` prefix isn't claimed by any Fleet integration template,
    so these indices are wholly project-owned and survive integration
    upgrades. See docs/reference.md for the full layout.
    """
    sessions_raw: str       # raw cowrie session-log events
    commands: str           # per-command enrichment docs
    command_clusters: str   # HDBSCAN centroids over commands
    sessions_rollup: str    # session-level rollup docs
    session_clusters: str   # HDBSCAN centroids over sessions ("playbooks")
    ips_rollup: str         # source-IP rollup docs
    ip_clusters: str        # HDBSCAN centroids over IPs
    # Multi-session campaign docs. Holds the output of `mine campaigns`
    # — frequent-itemset (behaviour) and connected-component (infrastructure)
    # groupings of sessions that span multiple connections. Distinct from
    # session_clusters (those are playbooks). See docs/PLAYBOOKS_AND_CAMPAIGNS.md.
    campaigns: str = "prism.campaign.cowrie"
    # Write-once churn-resistant playbook-identity anchors (ROADMAP #1).
    # One doc per stable_playbook_id pinning its first-mint centroid. See
    # setup/es-mappings/cowrie/playbook_anchors.json.
    playbook_anchors: str = "prism.identity.cowrie.playbook_anchor"
    # Operations — bhv×inf campaign pairs promoted to first-class
    # entities (brutal-review phase 7.1). One doc per overlap-clearing
    # pair, content-addressed on `sorted([bhv_id, inf_id])` so re-mines
    # converge on the same operation_id.
    operations: str = "prism.operations"
    # Cross-session file -> command attribution (brutal-review 7.6).
    # One doc per (sha256, source.ip) carrying first_seen + first_executed
    # session pointers. Drives the artifact-hash pane's "first seen
    # uploaded in session X, first executed in session Y" surface.
    file_command_crossref: str = "prism.crossref.file_command"
    # External reference-corpus sessions (brutal-review phase 5.2).
    # Synthetic sessions imported from Atomic Red Team — feeds the
    # `reference_source=external` centroid set built in 5.4, which 5.5
    # uses to compute `novelty_score_external` alongside the in-corpus
    # score. Strict-dynamic mapping at
    # setup/es-mappings/cowrie/reference_session.json.
    reference_sessions: str = "prism.reference.cowrie.session"


class DshieldIndexes(BaseModel):
    """Index names for the DShield-firewall source (Phase I3).

    `firewall` is the raw per-connection event stream the sensor's DShield
    client submits (`localdshield.log`), fanned out one doc per attempt by the
    upstream Logstash `split` and ECS-normalised by the `prism.dshield.firewall`
    ingest pipeline. `firewall_ip` is the per-source-IP rollup built by
    `rollup firewall-ips` (I3.3). Defaults so deploys without a `dshield:` block
    still parse.
    """
    firewall: str = "prism.raw.dshield.firewall"
    firewall_ip: str = "prism.rollup.dshield.firewall_ip"


class SourceIndexes(BaseModel):
    """Top-level container. Add a sibling model + field per new source."""
    cowrie: CowrieIndexes
    dshield: DshieldIndexes = Field(default_factory=DshieldIndexes)


class ESBackpressureConfig(BaseModel):
    """Heap/circuit-breaker-aware backpressure for ES requests.

    The pipeline runs against ES nodes of very different sizes. On a small,
    heap-constrained node a heavy aggregation / scan / bulk can trip the
    parent circuit breaker (HTTP 429 `circuit_breaking_exception`). The
    client transport retries those within milliseconds — far too fast for
    the breaker to drain — and then raises, hard-failing a pipeline step.

    When enabled, every ES call is routed through an overload-retry path
    (see `enrich.es_health`): on a 429/breaker rejection it polls the node's
    parent-breaker ratio, waits for heap to drain, then retries with
    exponential backoff. `max_wait_s` is a single shared wall-clock budget
    per operation — we'd rather wait a long time than fail a step.
    """
    enabled: bool = True
    heap_high_watermark: float = 0.85   # pause new work at/above this parent-breaker ratio
    heap_resume_watermark: float = 0.70  # resume below this (hysteresis)
    poll_interval_s: float = 2.0        # breaker re-probe cadence while paused
    max_wait_s: float = 3600.0          # overall patience budget per operation (~1h)
    retry_max_attempts: int = 200       # secondary ceiling; max_wait_s is the real limit
    retry_base_delay_s: float = 2.0     # exponential backoff base, clamped to remaining budget
    retry_max_delay_s: float = 30.0     # per-retry backoff cap


class ESConfig(BaseModel):
    hosts: list[str]
    verify_certs: bool = False
    ca_certs: Optional[str] = None
    request_timeout: int = 60
    indexes: SourceIndexes
    backpressure: ESBackpressureConfig = Field(default_factory=ESBackpressureConfig)


class LLMConfig(BaseModel):
    provider: str = "ollama"  # "ollama" | "openai_compat"
    base_url: Optional[str] = None
    generation_model: str
    embedding_model: str
    request_timeout: int = 120
    max_retries: int = 2
    api_key: Optional[str] = None  # for openai_compat servers that require it
    embed_context: list[str] = Field(
        default_factory=lambda: ["intent", "description"]
    )
    # Layout of the embed-input string (E8.1). Three layouts that
    # ``_build_embed_text`` will materialise:
    #   - ``prelude_first`` (default, unchanged):
    #         "{enrichment-context}\nCommand: {command}"
    #   - ``command_first``:
    #         "Command: {command}\n{enrichment-context}"
    #   - ``command_only_with_tag``:
    #         "[shell] {command}"  — prelude dropped entirely; only the
    #         command + a corpus-disambiguation tag goes to the encoder.
    # Folded into ``compute_embed_config_hash`` so a flip invalidates the
    # embed cache and reembed re-runs every command under the new layout.
    embed_input_order: str = "prelude_first"


class CooccurrenceConfig(BaseModel):
    """Per-command session-co-occurrence context.

    For each cache-miss command, queries ES for the sessions that ran the
    command, then aggregates the other commands run in those sessions. Top-K
    co-occurring commands are passed to the LLM (and optionally appended to
    the embed text) as context, so enrichment sees the command in the
    company it usually keeps.
    """
    enabled: bool = True
    # Sample at most this many sessions per command when computing co-occurrence.
    # Lower = faster ES query, less stable. 50 is plenty for tail commands;
    # head commands cap out anyway.
    session_sample_size: int = 50
    # Number of co-occurring commands surfaced to the LLM and embed text.
    top_k: int = 8
    # Skip co-occurrence when the command appears in fewer than this many
    # sessions — too little signal to be meaningful.
    min_sessions: int = 3
    # NOTE: `max_corpus_session_ratio` (the old binary boilerplate cutoff)
    # was removed in ROADMAP #6. The ranker now uses TF-IDF weighting —
    # corpus-common siblings demote themselves continuously. Stray YAML
    # entries are silently ignored by pydantic.
    # If true, append "co-occurs with: ..." to the embed text alongside
    # other enrichment context. Goes into embed_config_hash automatically;
    # no manual version bump required.
    embed_cooccurrence: bool = True


class CloudTriageConfig(BaseModel):
    # Anchor of "actually low confidence" — model's modal/default rating
    # was 6 on this corpus, escalating below that burnt budget on docs the
    # model was sure about. ROADMAP issue #4.
    confidence_max: int = 4
    escalate_confidence_max: int = 7
    sample_rate: float = 0.01
    base64_min_run: int = 200
    # File extensions removed (`zip`, `exe`): more often filename suffixes
    # than TLDs; the host-context anchor on _TLD_RE in triage.py rejects
    # bare-filename matches anyway. ROADMAP issue #4.
    suspicious_tlds: list[str] = Field(default_factory=lambda: [
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "club", "icu", "buzz",
        "monster", "rest", "bar", "fit", "online", "site", "stream", "cam",
    ])
    novel_embedding_threshold: float = 0.5
    # Suppress novelty-based escalation/surfacing when the local model's
    # self-rated confidence is below this floor. Confidence-1 enrichments
    # are typically encoding artifacts (raw ELF bytes, mojibake) where
    # novelty=1.0 is meaningless — see docs/roadmap.md issue #3.
    novel_confidence_min: int = 4
    # M3.A: intel-aware escalation gate. When True (default), the triage
    # consults each command's source-IP intel summaries before
    # dispatching to the cloud LLM. Two skip rules fire:
    #   - all source IPs have `override_applied=authoritative_clean`
    #     (e.g. all are GreyNoise-RIOT or AbuseIPDB-whitelisted) →
    #     "intel_skip_authoritative_clean"
    #   - all source IPs have malicious_provider_count >= 2 AND all
    #     existing triage_reasons are gateable (low_confidence /
    #     novel_embedding / sample, NOT base64_blob / ip_literal /
    #     rare_tld) → "intel_skip_commodity_consensus"
    # Disable to revert to the M2-and-earlier behaviour where intel
    # doesn't gate escalation. See src/enrich/triage.py
    # `intel_skip_reason` for the canonical rule. ROADMAP M3.A.
    intel_aware: bool = True


class CloudPricingConfig(BaseModel):
    input_per_mtok: float = 3.0
    output_per_mtok: float = 15.0


class CloudConfig(BaseModel):
    enabled: bool = False
    provider: str = "anthropic"
    base_url: Optional[str] = None
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 1024
    request_timeout: int = 120
    daily_budget_usd: float = 5.0
    # Separate budget bucket for console-driven write-up generation
    # (Item #2 of the analyst-first UX push). Default 0.0 = cloud
    # escalation for write-ups is disabled. Lives in its own bucket so
    # writeups can't starve the enrichment escalation budget, and the
    # enrichment storm can't starve the analyst.
    writeup_daily_budget_usd: float = 0.0
    rpm_limit: int = 10
    triage: CloudTriageConfig = Field(default_factory=CloudTriageConfig)
    pricing: CloudPricingConfig = Field(default_factory=CloudPricingConfig)


class CommandClusterConfig(BaseModel):
    min_cluster_size: int = 5
    min_samples: int = 2
    page_size: int = 1000
    batch_size: int = 200
    scalar_weight: float = 0.05
    # Noise-rescue cosine threshold (F1b). Outlier commands within this
    # pure-embedding cosine of a cluster centroid are reassigned to it
    # post-HDBSCAN instead of left as noise — the same safety valve the
    # session layer has. Model default 0.0 = disabled (any config missing
    # the key stays off); config/default.yaml ships it enabled at 0.94.
    # The F1 diagnostic found 91.7% of command outliers sit within 0.94 of a
    # centroid (median 0.993, 100% intent-matching) — HDBSCAN density noise,
    # not novelty — so rescue cuts the command outlier rate ~27.7% -> ~2.3%.
    rescue_threshold: float = 0.0
    # Reference centroids older than this trigger a stats warning but still
    # score (operator decides when to `cluster commands --refresh-reference`).
    # ROADMAP P1.
    reference_max_age_days: int = 45
    # Fit-only TruncatedSVD dimensionality for the command HDBSCAN. HDBSCAN on
    # 768-d euclidean embeddings is ~O(n^2) (spatial trees collapse in high
    # dimensions), so this is the command-layer scale wall. When >0, the
    # embedding is SVD-reduced to this many dims for the cluster-label
    # assignment ONLY — rescue, persisted centroids, novelty, and the cross-run
    # reference stay full-dim, so nothing downstream (incl. the novel_embedding
    # threshold) shifts. 0 = off (full-dim, legacy). 128 (default) was validated
    # to preserve — even slightly improve — cluster quality at ~6x speed (purity
    # +0.004, more clusters not fewer, lower outlier rate); see
    # scripts/sweep_command_svd.py. Auto-skips (full-dim) on corpora smaller than
    # this. Sweep your own corpus if you change it.
    cluster_svd_dim: int = 128


class SessionConfig(BaseModel):
    embed_version: str = "v1"
    cluster_min_cluster_size: int = 3
    # min_samples=2 avoids collapsing HDBSCAN's mutual-reachability distance
    # to raw distance (single-linkage), which can let one mega-cluster
    # swallow the bulk on a duplicate-heavy corpus. ROADMAP issue #5.
    cluster_min_samples: int = 2
    cluster_scalar_weight: float = 0.05
    # Rollup pagination: sessions per batch (also the events-fetch page size and
    # the bulk-write feed — helpers.bulk re-chunks writes at 500 internally).
    # Bigger = fewer ES round-trips on a large re-pool; push higher in local.yaml
    # if ES has the heap for it.
    page_size: int = 2000
    batch_size: int = 200
    # `rollup sessions` worker threads. Each processes an independent session-id
    # batch with its own in-flight ES requests; the work is round-trip-bound so
    # this scales ~linearly up to ES capacity. 1 = serial (legacy behaviour).
    rollup_workers: int = 5
    # Max unique commands sampled per playbook (session cluster) for LLM
    # name generation.
    playbook_sample_commands: int = 15
    # ROADMAP #11 — naming accuracy. Cap on how many of a cluster's member
    # sessions are sampled when computing cluster-wide command/IOC coverage
    # for naming. Random-subsampled when the cluster is larger; bounds the
    # per-playbook aggregation cost while keeping the sample representative.
    playbook_naming_session_cap: int = 500
    # Cluster-naming LLM context budget (huge-cluster guard). `playbook_sample_commands`
    # caps the *count* of commands/IOCs in the naming prompt, but a single attacker
    # command can be a multi-KB base64 / here-doc blob, so a diverse cluster can still
    # build a 100k+ prompt that overflows the LLM context window. These cap *size*: each
    # over-long command is truncated to `playbook_naming_max_command_chars`, and the whole
    # coverage block is capped at `playbook_naming_max_chars`, dropping the lowest-coverage
    # (least-defining) tail. Coverage-ranked, so the kept set stays representative.
    playbook_naming_max_command_chars: int = 600
    playbook_naming_max_chars: int = 8000
    # ROADMAP #11 — merge-on-no-distinction. In pass-2 disambiguation, a
    # feature (command or IOC) is "distinctive" to a colliding cluster when
    # its session coverage is >= this floor while every sibling's coverage is
    # below it. Two colliding playbooks with NO distinctive feature between
    # them are merged into one playbook instead of being given fabricated
    # distinct names. Conservative low default: even a weakly-prevalent
    # separating feature (>=25% of one cluster's sessions, absent in the
    # other) blocks the merge, so only genuinely-indistinguishable clusters
    # collapse. This is a behavioral-feature merge authority operating below
    # the embedding-geometry merge (`playbook_merge_threshold`). Raise to
    # merge more aggressively; 1.0 effectively disables merging.
    playbook_merge_distinctiveness_floor: float = 0.25
    # Cosine-similarity threshold for merging HDBSCAN clusters into a single
    # playbook. A playbook is a *group* of one or more clusters whose
    # centroids are pairwise (single-linkage) at least this similar. 1.0
    # disables merging (1 cluster = 1 playbook, legacy behaviour). 0.96 is
    # the empirically-tuned default — see scripts/diagnose_centroid_similarity.py.
    playbook_merge_threshold: float = 0.96
    # Option A — direct nearest-anchor assignment (the pipeline inversion). See
    # src/enrich/sources/cowrie/assignment.py and
    # docs/decisions.md §5f. Embedding cosine to the nearest
    # anchor: >= confident_tau assigns outright; [tau, confident_tau) is the band
    # (confirm with the TF-IDF secondary signal >= tfidf_tau, else the nearest anchor
    # is a conflation and we cascade to the next-nearest); < tau is novel.
    assignment_tau: float = 0.94
    assignment_confident_tau: float = 0.98
    assignment_tfidf_tau: float = 0.80
    # Flag gate for the I3 shadow write (non-authoritative; writes cluster.assignment_*
    # without touching playbook_id). Off by default.
    assignment_shadow_enabled: bool = False
    # I4 cutover gate. When True, the `assign_sessions` runner writes `playbook_id`/
    # `playbook_name` authoritatively (assigned), clears them (novel), and bumps
    # `playbook_named_at` so IP rollups self-heal — replacing HDBSCAN as the labeller for
    # the assignable bulk. **Inert until the runner is wired into the pipeline** (it is
    # not in any systemd unit by default), so this default only takes effect once the
    # operator runs `scripts/assign_sessions.py --apply` or swaps it into the backward
    # service in place of `cluster sessions` + `name playbooks`. Reversal: set False +
    # re-run the HDBSCAN `cluster sessions`/`name playbooks` steps (playbook_id is
    # recomputable from embeddings). When False the runner writes shadow fields only.
    assignment_authoritative: bool = True
    # ROADMAP #4 — cluster specificity. Max keys stored per centroid in each
    # of `ip_specificity` / `command_specificity`. Set well past realistic
    # cluster sizes so EVERY member IP / command carries a score (so the
    # drawer / graph can show a commodity pill, not a missing one). The cap
    # remains a safety valve against a pathological cluster blowing up
    # centroid doc size; lower it if you observe a problem at scale.
    specificity_store_cap: int = 10000
    # ROADMAP #4 — UI threshold for "distinctive" classification. Pills /
    # graph rings at or above this score render as filled accent; below
    # render as faded outline. 0.5 corresponds to `df ≤ √C` (appears in
    # fewer than ~√C clusters); semantics scale with corpus size. Served
    # to the frontend via /api/config/ui; an analyst can override per-browser
    # via localStorage `prism.spotlightThreshold`.
    specificity_threshold: float = 0.5
    # ROADMAP P1: see CommandClusterConfig.reference_max_age_days.
    reference_max_age_days: int = 45
    # Session-layer clustering mode. Default "hdbscan" reproduces the
    # historical behaviour: a single HDBSCAN pass over the embedding +
    # weighted scalar block. "late_fusion" runs HDBSCAN twice (once over
    # the embedding+scalar augmentation, once over a per-session
    # TF-IDF+SVD lexical view) then re-clusters via Agglomerative on the
    # per-pair disagreement distance matrix. Adopted per the E4.4 sweep
    # (eval/results/E4-verdict.md): +0.085 ARI vs production while
    # keeping homogeneity above the plan's 0.80 binding rule. Outlier
    # semantics are preserved — `cluster.is_outlier` is still sourced
    # from the embedding-only HDBSCAN pass, so novelty / rescue /
    # outlier_burst downstream behaviour does not change. Reversible by
    # config flip.
    clustering_mode: str = "hdbscan"
    # P1.3 — hard ceiling on the late-fusion doc count. The fusion path builds
    # an O(N^2) pure-Python pair-distance matrix (`_disagreement_distance`) plus
    # an n×n float32 matrix, so it cannot run unbounded at scale (it hangs long
    # before it OOMs). Above this, `cluster sessions` refuses with a clear error
    # unless `--accept-fallback` is passed (which clusters with plain HDBSCAN
    # instead). Ignored when clustering_mode == "hdbscan". 15k ≈ a ~0.9 GB
    # matrix and minutes of pair-looping — the practical edge before unusable.
    fusion_max_docs: int = 15000
    # Lexical-view dimensionality for the late-fusion path. 100-d is the
    # E0.2 ablation baseline that has carried through every subsequent
    # sweep. Lower values (50) collapse semantic distinctions; higher
    # values (200+) start fitting per-corpus noise. Ignored when
    # clustering_mode == "hdbscan".
    cluster_lexical_features_dim: int = 100
    # Scale-hardening P1.2 — windowed clustering (D1 hybrid). When > 0,
    # `cluster sessions` only pulls command-bearing sessions whose `@timestamp`
    # is within the last N days, instead of scanning the entire rollup every
    # backward cycle (the dominant clustering cost at scale). 0 reverts to the
    # historical all-time behaviour. Identity stays stable under windowing
    # because playbook `spb-` ids match by centroid cosine to the pinned anchor
    # and per-doc novelty scores against the frozen `reference_centroid` set,
    # not this run's centroids — a window that re-derives the same centroid
    # re-matches the same playbook. Sessions older than the window keep their
    # last-assigned `cluster.id`. Default 30 (on): the 6h backward cycle
    # windows; a slower weekly full re-cluster
    # (`cluster sessions --window-days 0 --refresh-reference`, shipped as the
    # `dshield_prism-recluster-full` timer) refreshes the reference and
    # re-pools the long tail. The CLI `--window-days` flag overrides this
    # per-run (pass 0 to force a full run).
    cluster_window_days: int = 30
    # Fit-only TruncatedSVD dimensionality for the session HDBSCAN. Mirrors
    # CommandClusterConfig.cluster_svd_dim: HDBSCAN on the 768-d session
    # embedding (mean-pooled command vectors) is ~O(n^2) because spatial trees
    # collapse in high dimensions, so a full-corpus run (`--window-days 0`:
    # `pipeline --backfill` and the weekly `dshield_prism-recluster-full` timer)
    # fits at full dim and can run for HOURS on hundreds of thousands of
    # sessions. When >0 the embedding is SVD-reduced to this many dims for the
    # cluster-label assignment ONLY — noise rescue, persisted centroids,
    # novelty, and the cross-run reference all stay full-dim, so nothing
    # downstream shifts (no reference rebuild, no novel_embedding retune). 0 =
    # off (full-dim, legacy). Auto-skips to full-dim on corpora smaller than
    # this. 96 is the speed/quality balance: it reproduced the full-dim
    # clustering EXACTLY (ARI 1.0 vs full) across corpus sizes ~400 → 60k — both
    # subsampled prod-scale snapshots and a live 60k corpus — while running
    # faster than 128. 64 is NOT a safe default: it stays exact only up to ~1k
    # sessions, then diverges in the medium/labeled range (ARI ~0.70 at the 4k
    # labeled eval set, where the hard distinctions concentrate). Bump to 128
    # for more variance margin, or sweep your own corpus
    # (scripts/sweep_session_svd.py) to push lower — the windowed 6h runs are
    # small, so this only bites the full-corpus paths.
    cluster_svd_dim: int = 96


class IPConfig(BaseModel):
    embed_version: str = "v1"
    cluster_min_cluster_size: int = 3
    # See SessionConfig.cluster_min_samples for rationale. ROADMAP issue #5.
    cluster_min_samples: int = 2
    # Noise rescue (augmented-space euclidean). HDBSCAN's density rule flags ~70%
    # of command-bearing IPs as noise even when they sit a normal-cluster's-radius
    # from a centroid; this reassigns an outlier to its nearest centroid when it
    # falls within the Pth percentile of the intra-cluster spread, in the SAME
    # augmented `[embedding ⊕ scalars]` euclidean space HDBSCAN fit on (NOT the
    # pure-embedding cosine the command/session `rescue_threshold` uses — the IP
    # geometry is scalar-driven and pure-cosine over-rescues ~38%; see
    # docs/decisions.md). 0 disables. 99 ≈ 92% of outliers rescued (70% → ~6%),
    # at ~94% playbook / ~99.7% intent purity — which held flat p90→p99, so the
    # aggressive default reclaims the most without quality loss
    # (validated by scripts/diagnose_ip_rescue.py).
    rescue_spread_percentile: int = 99
    # Weight on the behavior-scalar sub-block (total_sessions,
    # login_success_rate, mean_novelty, mean_session_duration_s). These
    # break ties on the embedding axis and should stay subdued — 0.05 is
    # the empirically-tuned default.
    cluster_scalar_weight: float = 0.05
    # Weight on the attribution-scalar sub-block (country one-hot, ASN
    # bucket, credential hash). Slightly hotter than behavior because
    # these are attribution signals, not noise. ROADMAP issue #8.
    cluster_attribution_weight: float = 0.10
    # ASN bucketing: top-N ASNs each get a dedicated one-hot column; all
    # other ASNs share a single pooled "other" column. Computed via a
    # corpus-wide ES terms agg at cluster time.
    attribution_top_asns: int = 50
    # Credential feature-hash dimension. Each unique (user:pass) the IP
    # tried is hashed into one of K bins (stable SHA-256-based hash); the
    # column value is that bin's share of the IP's credential set, so the
    # block sums to 1 per row. K=16 trades collisions for compactness.
    attribution_cred_hash_dim: int = 16
    # SSH client fingerprint (HASSH) sub-block. Weight kept lower than the
    # attribution block: SSH stack diversity is small, so HASSH is a weak
    # corroborating signal (two IPs with the same client stack lean together,
    # it won't override behaviour). 0 disables. ROADMAP attribution scaffolding.
    cluster_hassh_weight: float = 0.05
    # Phase K (ADOPTED 2026-06-03) — behaviour-driven IP geometry. When False,
    # drop the queryable provenance / tool-fingerprint dims (country one-hot +
    # ASN one-hot + HASSH) from the IP clustering geometry. They are filterable
    # post-hoc and over-fragment the same behaviour across hosting platforms /
    # client tools (J + first-K verdicts). Cred-hash + intel stay. Defaults to
    # False = K geometry (provenance dropped) per the K5 verdict.
    cluster_attribution_provenance_enabled: bool = False
    # Phase K Tier 1 — per-IP behaviour sub-block (intent distribution, playbook
    # distribution, diversity, temporal, volume) from existing rollup fields,
    # thickening the thin per-command-mean IP embedding so behaviour can carry
    # the geometry once provenance is dropped. Default True (adopted).
    cluster_tier1_enabled: bool = True
    # Phase K Tier 2 — IP-as-bag-of-session-clusters: TF-IDF over each IP's
    # session-cluster ids → TruncatedSVD(24), fit at cluster time. This is what
    # re-separated the behaviour-homogeneous reconnaissance population that Tier 1
    # alone left as a 70%-of-corpus mega-cluster (K3→K5: 69.6%→27.2% largest).
    # Default True (adopted). Disabling reverts to the Tier-1-only geometry.
    cluster_tier2_enabled: bool = True
    # Tier 2 SVD target dimensionality (bounded below by the live session-cluster
    # count at fit time). 24 ≈ the production session-cluster cardinality.
    cluster_tier2_svd_dim: int = 24
    # Feature-hash dimension for the HASSH distribution (same scheme as the
    # credential hash). Small — observed HASSH cardinality is low.
    attribution_hassh_hash_dim: int = 8
    # Rollup pagination + bulk-write accumulation. Bigger = fewer ES round-trips.
    page_size: int = 2000
    batch_size: int = 1000
    # `rollup ips` worker threads. Parallelises the per-IP session fetch — the
    # IP rollup's dominant cost is one ES query per IP, so this is the big lever
    # at scale. 1 = serial (legacy behaviour).
    rollup_workers: int = 5
    # ROADMAP P1: see CommandClusterConfig.reference_max_age_days. IP layer
    # persists pure-embedding references only (scalar block is variable-width)
    # so per-doc novelty scored against the reference reflects embedding
    # geometry only — scalar-driven cluster membership is not factored in.
    reference_max_age_days: int = 45
    # Backlog scale-hardening B0.5 — IP-layer re-cluster cadence. The IP layer
    # has no windowing escape valve (unlike sessions' cluster_window_days): an
    # IP's embedding is built from its cumulative all-time rollup, so a recency
    # window would drop dormant-then-active scanners — exactly the signal you
    # want. And a full HDBSCAN over the embedded-IP set is O(n^2)
    # (eval/results/B0-preflight-loadtest.md: ~23 min at 50K embedded IPs,
    # ~1.5 h at 100K). When True, the 6-hourly backward `cluster ips` skips the
    # full re-cluster; the full pass runs once/week in
    # dshield_prism-recluster-full instead (forced there via `--window-days 0`).
    # Existing IPs keep their cluster.id between weekly runs (forward `rollup
    # ips` _preserve_ip_cluster); new IPs land unclustered until the weekly
    # pass — the accepted MVP cost (the incremental nearest-reference-centroid
    # assign is the follow-up, B0.5 Option B). Default False = full re-cluster
    # every backward run (legacy). Flip True for the multi-sensor backlog.
    full_recluster_weekly: bool = False


class IntelProviderConfig(BaseModel):
    """Generic per-provider toggle + key holder.

    Each provider's own config (api key, refresh cadence, etc.) lives
    in a typed sub-model below. This base just carries `enabled` so
    operators can flip a provider off without removing the block.
    """
    enabled: bool = True


class TorProviderConfig(IntelProviderConfig):
    """Tor exit-list provider — bulk file download, no API key."""
    # URL of the public exit-list file. Default is the canonical Tor
    # Project endpoint; override only when mirroring locally.
    exit_list_url: str = "https://check.torproject.org/torbulkexitlist"
    # How often to re-download the full list. The file updates hourly
    # upstream; refreshing more often wastes bandwidth.
    refresh_minutes: int = 60
    # On-disk cache path. Survives process restarts so a worker reboot
    # doesn't re-download. Stored alongside other state.
    cache_file: str = "/var/lib/dshield_prism/intel_tor_exits.txt"


class FeodoTrackerProviderConfig(IntelProviderConfig):
    """abuse.ch FeodoTracker — active malware C2 IP list. No API key.

    Replaces the previous Spamhaus DNS provider after the public-
    resolver block proved an architectural mismatch for the
    transportable / research-honeypot use case. FeodoTracker is
    HTTP-based bulk download, high-precision (active C2 only),
    sibling format to URLhaus / ThreatFox / MalwareBazaar from the
    same operator.
    """
    # Recommended endpoint — pre-filtered to currently-active C2 only.
    # `ipblocklist.json` exists too but includes historical entries.
    feed_url: str = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    refresh_minutes: int = 60
    cache_file: str = "/var/lib/dshield_prism/intel_feodotracker.json"


class FireholProviderConfig(IntelProviderConfig):
    """FireHOL Level 1 IP reputation aggregator. No API key, no auth.

    Aggregates hundreds of upstream feeds (CINS Army, DROP/EDROP,
    BinaryDefense, AlienVault, EmergingThreats compromised hosts,
    …) into a single very-low-FP block list. Level 1 is the
    strictest tier — entries the maintainers consider safe for null-
    routing at a network edge.
    """
    feed_url: str = "https://iplists.firehol.org/files/firehol_level1.netset"
    refresh_minutes: int = 360
    cache_file: str = "/var/lib/dshield_prism/intel_firehol_level1.netset"


class GreyNoiseProviderConfig(IntelProviderConfig):
    """GreyNoise Community provider — per-IP HTTP lookup.

    Free-tier limits (verified 2026-05-17): **50 lookups per week**
    on the Community plan — much tighter than the marketing
    "10k/month" suggests. Daily ceiling of 6 here gives ~42/week,
    leaving headroom for healthcheck probes plus any retries.

    Re-query cadence is the other half of the throughput model: an
    artifact already resolved stays resolved until it ages out, so we
    can keep growing the corpus and the budget covers it as long as we
    resolve the 6 highest-novelty new artifacts each day. That age-out
    is now governed centrally by `intel.refresh_ttl_days.ip` (default
    7d, matching this weekly budget) rather than a per-provider TTL.

    A separate constraint: GreyNoise rate-limits short bursts. The
    provider sleeps `min_inter_call_seconds` between calls to stay
    below the per-second cap.
    """
    base_url: str = "https://api.greynoise.io"
    # Community endpoint: GET /v3/community/<ip> → {classification, name, last_seen, ...}
    request_timeout_seconds: float = 8.0
    daily_budget: int = 6
    min_inter_call_seconds: float = 1.0


class URLhausProviderConfig(IntelProviderConfig):
    """abuse.ch URLhaus — known-malicious URL list. HTTP bulk-download CSV.

    No API key; unmetered. Sibling family to FeodoTracker / ThreatFox /
    MalwareBazaar. M4 first URL-kind provider.
    """
    # `csv_online` is the actively-malicious subset; the broader
    # `csv` endpoint includes offline entries too.
    feed_url: str = "https://urlhaus.abuse.ch/downloads/csv_online/"
    refresh_minutes: int = 60
    cache_file: str = "/var/lib/dshield_prism/intel_urlhaus.csv"


class ThreatFoxProviderConfig(IntelProviderConfig):
    """abuse.ch ThreatFox — per-IOC HTTP POST API.

    Free, no API key required for low-volume usage. POSTs a search
    body per artifact; returns rich IOC metadata (malware family,
    threat type, confidence). M4 ships URL-kind handling; IP /
    domain / hash extensions are a single-line change to
    `ThreatFoxProvider.handles`.
    """
    base_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    request_timeout_seconds: float = 8.0
    # Gentle throttle — abuse.ch politely accepts steady traffic.
    min_inter_call_seconds: float = 0.5


class MalwareBazaarProviderConfig(IntelProviderConfig):
    """abuse.ch MalwareBazaar — per-hash malware-sample DB (#2).

    Same abuse.ch family/auth as ThreatFox (shared ABUSE_CH_AUTH_KEY). A hit
    means the file is a *known malware sample* — direct evidence, not an
    aggregate vote. POSTs `get_info` per hash; returns the malware
    signature/family, file type, tags. Free; auth key recommended.
    """
    base_url: str = "https://mb-api.abuse.ch/api/v1/"
    request_timeout_seconds: float = 8.0
    min_inter_call_seconds: float = 0.5


class VirusTotalPublicProviderConfig(IntelProviderConfig):
    """VirusTotal public API v3 — per-hash lookup (#2 scaffold).

    Disabled by default. Even with `VIRUSTOTAL_API_KEY` set, stays off unless
    `enabled: true`. Free tier is 4 req/min / 500 per day, so the worker
    gates on `daily_budget` like GreyNoise/AbuseIPDB.
    """
    enabled: bool = False
    base_url: str = "https://www.virustotal.com/api/v3"
    request_timeout_seconds: float = 10.0
    # Free public tier: 500/day. Stay under to leave headroom.
    daily_budget: int = 450
    min_inter_call_seconds: float = 16.0  # 4 req/min ceiling


class AbuseIPDBProviderConfig(IntelProviderConfig):
    """AbuseIPDB provider — per-IP HTTP lookup. Free tier: 1000/day."""
    base_url: str = "https://api.abuseipdb.com"
    request_timeout_seconds: float = 8.0
    daily_budget: int = 900
    min_inter_call_seconds: float = 0.0
    # AbuseIPDB lets you ask "how far back in reports to look" — 90
    # days is their max for the free tier and matches the default UI.
    max_age_days: int = 90


class ISCProviderConfig(IntelProviderConfig):
    """SANS Internet Storm Center / DShield top-attackers daily feed.

    The ISC API publishes a top-N list of attacking IPs daily. We
    download once per `refresh_minutes` and answer per-IP lookups
    from the in-memory snapshot.
    """
    # ISC API. Adjust if/when ISC publishes a research-friendly mirror.
    sources_url: str = "https://isc.sans.edu/api/sources/attacks/2000?json"
    refresh_minutes: int = 360
    cache_file: str = "/var/lib/dshield_prism/intel_isc_top.json"


class IntelProvidersConfig(BaseModel):
    """Per-provider sub-blocks. Add one field per new provider."""
    tor: TorProviderConfig = Field(default_factory=TorProviderConfig)
    feodotracker: FeodoTrackerProviderConfig = Field(default_factory=FeodoTrackerProviderConfig)
    firehol: FireholProviderConfig = Field(default_factory=FireholProviderConfig)
    isc: ISCProviderConfig = Field(default_factory=ISCProviderConfig)
    greynoise: GreyNoiseProviderConfig = Field(default_factory=GreyNoiseProviderConfig)
    abuseipdb: AbuseIPDBProviderConfig = Field(default_factory=AbuseIPDBProviderConfig)
    # M4: URL-kind providers.
    urlhaus: URLhausProviderConfig = Field(default_factory=URLhausProviderConfig)
    threatfox: ThreatFoxProviderConfig = Field(default_factory=ThreatFoxProviderConfig)
    # #2: hash-kind providers.
    malwarebazaar: MalwareBazaarProviderConfig = Field(default_factory=MalwareBazaarProviderConfig)
    virustotal_public: VirusTotalPublicProviderConfig = Field(default_factory=VirusTotalPublicProviderConfig)


class IntelPriorityConfig(BaseModel):
    """Weights on the priority-queue scoring function.

    `priority = novelty_w * novelty + low_conf_w * (1 - conf/10)
              + centrality_w * centrality_norm
              + recency_w * recency_decay`

    Defaults follow the design decision (2026-05-16) that local
    novelty dominates — scarce free-tier budget goes to artifacts most
    likely to be discoveries. Weights need not sum to 1; the queue
    sorts on the raw score.
    """
    novelty_w: float = 0.50
    low_conf_w: float = 0.20
    centrality_w: float = 0.15
    recency_w: float = 0.15
    # Half-life of the recency term, in hours. Recent artifacts get
    # close to 1.0; week-old gets ~0.5; month-old gets ~0.07.
    recency_half_life_hours: float = 168.0


class IntelIndexes(BaseModel):
    """Project-owned intel indices. One per artifact kind.

    Only `ip` is end-to-end in milestone 1. The other names are
    pre-allocated so adding a kind later doesn't require config
    migration on existing deploys.
    """
    ip:     str = "prism.intel.ip"
    url:    str = "prism.intel.url"
    domain: str = "prism.intel.domain"
    hash:   str = "prism.intel.hash"


class IntelRefreshTTLConfig(BaseModel):
    """Per-artifact-kind cache age-out for `intel refresh`, in DAYS.

    A refresh skips re-querying any artifact whose intel doc was
    `last_refreshed` within this many days — so a steady-state refresh only
    looks up artifacts that are new or have aged out, instead of re-hitting
    every provider for every known artifact on every run (which also burns the
    rate-limited VirusTotal budget). `0` disables the skip for that kind
    (always re-query). `intel backfill` ignores these entirely.

    Tune per kind by how volatile the verdict is: a known-malware hash
    effectively never changes verdict, so a long TTL is safe; an IP's
    reputation can flip benign↔malicious, so keep it shorter.
    """
    ip:     float = 7.0
    url:    float = 14.0
    domain: float = 14.0
    hash:   float = 30.0

    def for_kind(self, kind: str) -> float:
        """TTL in days for `kind`; 0.0 (always re-query) for unknown kinds."""
        return {
            "ip": self.ip, "url": self.url,
            "domain": self.domain, "hash": self.hash,
        }.get(kind, 0.0)


class IntelConfig(BaseModel):
    """External threat-intel subsystem.

    Disabled by default. Per-deploy enable + provider keys go in
    `config/local.yaml`. See ROADMAP "Research-mode strategic gaps"
    section A for the design.
    """
    enabled: bool = False
    indexes: IntelIndexes = Field(default_factory=IntelIndexes)
    providers: IntelProvidersConfig = Field(default_factory=IntelProvidersConfig)
    priority: IntelPriorityConfig = Field(default_factory=IntelPriorityConfig)
    # Per-kind cache age-out (days). See IntelRefreshTTLConfig.
    refresh_ttl_days: IntelRefreshTTLConfig = Field(default_factory=IntelRefreshTTLConfig)
    # CIDRs the worker MUST NOT look up against external feeds. RFC1918
    # is already filtered at canonicalisation time (artifact.py); list
    # the operator's egress + research peer CIDRs here.
    never_query_cidrs: list[str] = Field(default_factory=list)
    # ES `size:` parameter for the discovery scans (IP rollup search,
    # threat.indicator nested terms agg). NOT an artifact-dispatch
    # cap — the prior global-cap semantics starved URL artifacts and
    # were removed. Provider rate enforcement belongs at the
    # *integration* level: providers with API limits (GreyNoise,
    # AbuseIPDB) set `RateLimit.daily_budget` and the worker gates on
    # `intel_provider_calls_today` per call. Unmetered bulk providers
    # (Tor / ISC / FireHOL / FeodoTracker / URLhaus) have effectively
    # zero per-artifact cost after their once-per-window bulk
    # download, so they shouldn't be capped.
    max_per_run: int = 5000


class FindingsIndexes(BaseModel):
    """Persisted findings index. M5. Lifecycle indices added in Findings v2 step 1 —
    one per artifact kind (playbook / campaign / source_ip)."""
    default: str = "prism.finding"
    playbook_lifecycle:  str = "lifecycle-dshield.cowrie.playbook-default"
    campaign_lifecycle:  str = "lifecycle-dshield.cowrie.campaign-default"
    source_ip_lifecycle: str = "lifecycle-dshield.cowrie.source_ip-default"


class LifecycleConfig(BaseModel):
    """Findings v2 — lifecycle snapshot rotation + provisional-anchor cadence."""
    # Rolling per-run snapshot cap on the lifecycle docs. 30 ≈ 7.5 days at
    # the 6h backward-cadence — long enough to compute rolling baselines for
    # drift kinds without unbounded doc growth.
    snapshot_cap: int = 30
    # Number of consecutive stable snapshots before `track lifecycles`
    # writes a provisional anchor (used for drift baselining when no
    # analyst has confirmed yet). 8 runs ≈ 2 days at 6h.
    provisional_stable_runs: int = 8
    # Hard-delete a lifecycle doc once its `silent_runs_current` reaches
    # this threshold. A re-emerging artifact mints a fresh doc through the
    # normal path; no archive index. Set to 0 to disable retirement on a
    # given layer. Defaults at 6h cadence: 120 ≈ 30 days, 28 ≈ 7 days.
    retire_silent_runs_playbook: int = 120
    retire_silent_runs_campaign: int = 120
    retire_silent_runs_source_ip: int = 28


class DiscoveryConfig(BaseModel):
    """Findings v2 step 3 — stream B (discovery) thresholds."""
    # `intel_verdict_flip`: how recent must the corpus session be to fire?
    intel_flip_recent_session_days: int = 7
    # `ip_behavior_shift`: JS-distance gate between current playbook
    # distribution and the IP's prior history.
    ip_shift_js_distance_min: float = 0.3
    # `ip_behavior_shift` + `unattributed_active_ip`: latest snapshot's
    # session_count floor — bots that hit once per week don't fire.
    ip_shift_min_sessions: int = 5
    unattributed_min_sessions: int = 5
    # `outlier_burst`: window + grouping thresholds.
    outlier_burst_window_hours: int = 24
    outlier_burst_min_sessions: int = 5
    # Vestigial — `novel_edge_session` was retired. Knobs kept on the
    # model so existing `local.yaml` files keep parsing.
    novel_edge_top_k_per_cluster: int = 3
    novel_edge_min_cluster_size: int = 20
    # `campaign_convergence`: IP overlap ratio between cmp-bhv-X and
    # cmp-inf-Y (intersection / min(|bhv|, |inf|)).
    convergence_min_ip_overlap_ratio: float = 0.4


class NarrativeConfig(BaseModel):
    """Findings v2 step 5 — drift narrative generator."""
    # Master kill-switch. If false, no LLM calls; drift findings keep
    # their structured narrative_template.
    enabled: bool = True
    # Skip the LLM call when the remaining daily cloud budget drops below
    # this floor — protects the `escalate` step from being starved by a
    # storm of unique deltas. USD.
    budget_floor_usd: float = 0.05
    # Per-call max tokens; one-sentence narratives don't need more.
    max_tokens: int = 160


class DriftConfig(BaseModel):
    """Findings v2 step 4 — stream A (drift) thresholds."""
    # `playbook_command_drift`: Jaccard floor over command_set. The
    # default in the design doc is 0.5; we ship signature-mode parity as
    # the gate today (full Jaccard requires materialising command sets on
    # the rollup) — see drift.py docstring.
    command_jaccard_threshold: float = 0.5
    # `playbook_sequence_drift`: Jaccard floor over command_bigram_set.
    # Fires only when command_drift did NOT fire — the smarter signal.
    bigram_jaccard_threshold: float = 0.4
    # `playbook_artifact_drift`: Jaccard distance floor over artifact_set.
    artifact_set_drift_min: float = 0.5
    # `playbook_geo_drift`: cosine distance floor over ASN distribution.
    asn_cosine_drift_min: float = 0.4
    # `playbook_size_drift`: both gates must clear (relative growth + abs delta).
    size_growth_pct_min: float = 0.75
    size_growth_min_delta_ips: int = 3
    # `playbook_resurgence`: consecutive silent runs before a return fires.
    resurgence_silent_runs: int = 8
    # `campaign_growth`: same relative + absolute gates as size_drift.
    campaign_growth_pct_min: float = 0.75
    campaign_growth_min_delta_ips: int = 3


class HuntsConfig(BaseModel):
    """Hypothesis-driven hunts subsystem (brutal-review phase 6.1).

    A hunt is a YAML file under ``config_dir`` carrying an `id`, a
    `name`, a list of `filters`, and an optional `enabled` flag.
    Matching sessions produce one `kind=analyst_hunt` finding per
    (hunt, session) pair into `prism.findings`.
    """
    # Where the loader looks for `*.yaml` / `*.yml` hunt files. Relative
    # paths resolve from the process working directory (matches the
    # other `config/*.yaml` lookups in this project).
    config_dir: str = "config/hunts"
    # Cap on findings emitted by a single hunt per run. Hunts that match
    # more sessions than this silently truncate — operator sees the
    # count in the stats and can refine the filters.
    max_findings_per_hunt: int = 500


class FindingsConfig(BaseModel):
    """Findings-mining subsystem (M5).

    The miner walks IP rollups (for `likely_discovery`) and joins
    URL ↔ host-IP intel (for `axis_disagreement`), upserting one
    finding doc per (kind, artifact_kind, artifact_value). Status
    workflow lives on each doc; the miner is careful to overwrite
    only the evidence/score/last_seen_at fields so the analyst's
    triage state survives re-mines.
    """
    enabled: bool = True
    indexes: FindingsIndexes = Field(default_factory=FindingsIndexes)
    # Likely-discovery thresholds. Both halves must clear: high local
    # novelty AND high external rarity. Defaults err on the side of a
    # short ranked list — easier to lower than to wade through noise.
    likely_discovery_novelty_min: float = 0.70
    likely_discovery_rarity_min: float = 0.50
    # Floor on local activity to avoid surfacing IPs we barely saw
    # — single-session IPs aren't candidate discoveries even when
    # both scores spike.
    likely_discovery_min_sessions: int = 3
    # Cap on how many findings of each kind the miner persists per
    # run. The console paginates; a 5000-finding backlog is rarely
    # useful and bloats the index.
    max_findings_per_kind: int = 500
    # Lifecycle subsystem (Findings v2).
    lifecycle: LifecycleConfig = Field(default_factory=LifecycleConfig)
    # Discovery (stream B) thresholds (Findings v2 step 3).
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    # Drift (stream A) thresholds (Findings v2 step 4).
    drift: DriftConfig = Field(default_factory=DriftConfig)
    # Drift narrative generator (Findings v2 step 5).
    narrative: NarrativeConfig = Field(default_factory=NarrativeConfig)
    # Look-back window (days) for "recent activity" — IPs/URLs whose
    # `last_seen` is older than this are ineligible for new findings.
    # Existing finding docs keep their status; the miner just stops
    # emitting fresh ones for stale artifacts.
    window_days: int = 30
    # Hypothesis-driven hunts (brutal-review phase 6.1) — analyst-authored
    # YAML queries that produce `kind=analyst_hunt` findings against the
    # session rollup. The directory `config_dir` is scanned at every
    # `mine hunts` invocation; an empty/missing directory is a no-op.
    hunts: HuntsConfig = Field(default_factory=HuntsConfig)
    # Noise-threshold safety valve (brutal-review phase 4.5).
    # Generalises the lesson from `unattributed_active_ip`'s retirement
    # (discovery.py:18-23): any miner whose output exceeds this fraction
    # of the corpus its artifacts are drawn from is auto-suppressed for
    # that run with a log warning. The aggregate signal might still be
    # real, but the analyst inbox is the wrong surface for it.
    # 0.005 = 0.5% — `unattributed_active_ip` would have been gated at
    # ~20%, so the floor is well below any pathological miner's output.
    # Set to 0 to disable the gate entirely.
    noise_threshold_pct: float = 0.005


class WorkerConfig(BaseModel):
    state_db: str
    page_size: int = 1000
    command_max_chars: int = 4000
    initial_lookback_days: Optional[int] = None
    log_level: str = "INFO"
    # Directory for project-owned log files. The CLI installs a rotating
    # file handler at `<log_dir>/cli.log` when this path is writable;
    # setup.sh and destroy.sh write `<log_dir>/setup.log` and
    # `<log_dir>/destroy.log`. Set to "" or an unwritable path to disable
    # file logging entirely (the CLI keeps its stderr handler either
    # way, so systemd's journal capture is unaffected). Override per
    # run via the PRISM_LOG_DIR env var.
    log_dir: str = "/var/log/dshield_prism"
    # When True (default), the cache key includes two SHA-256 hashes over
    # the inputs that affect enrichment output (see
    # `compute_llm_config_hash` and `compute_embed_config_hash`). Edits to
    # prompts, cooccurrence config, embed_context, or embedding_model then
    # auto-invalidate stale cache rows on the appropriate side. Set to
    # False to bypass the auto-invalidation when LLM budget is tight and
    # you'd rather keep current enrichments through a config drift — you
    # can still wipe or bless the cache manually. ROADMAP issue #7.
    cache_auto_invalidate: bool = True
    # CPU parallelism for the HDBSCAN clustering passes (`cluster commands /
    # sessions / ips`). Passed to sklearn HDBSCAN's `n_jobs` — parallelises the
    # nearest-neighbour / core-distance computation, the dominant cost of the
    # O(n^2) IP clustering at scale. -1 = all cores (default), 1 = single-core
    # (legacy), N = cap at N. Only the NN phase parallelises; the linkage step
    # is still single-threaded.
    cluster_n_jobs: int = -1


class PromptsConfig(BaseModel):
    command_enrichment: str
    command_deep_dive: Optional[str] = None
    playbook_name: Optional[str] = None
    # Pass-2 of `name playbooks`: re-prompts the LLM when multiple clusters
    # end up with the same pass-1 name, asking it to produce distinct
    # names that capture what makes each cluster substantively different.
    # Optional — when unset, pass 2 is skipped (collisions keep their
    # pass-1 names). ROADMAP issue #10.
    playbook_disambiguate: Optional[str] = None
    # Console-facing: plain-language explanation of why two session clusters
    # weren't merged into the same playbook. Used by the /compare endpoint
    # and the explain_cluster_pair.py CLI's --explain flag.
    cluster_pair_explanation: Optional[str] = None


class ShapeDedupConfig(BaseModel):
    """Functional-duplicate gating on command enrichment (ROADMAP #9).

    When a new command's shape signature (literals replaced with type
    placeholders, see `command_shape.normalize_to_shape`) matches an
    already-enriched canonical, skip the LLM generation call and inherit
    the canonical's intent/description. The new
    command still gets its own embedding + regex-extracted IOCs because
    those are per-command-unique.

    Toggle off to force a full LLM call on every command (useful for
    A/B'ing the dedup quality or for debugging a suspected miscanon).
    """
    enabled: bool = True
    # Parent must have at least this confidence (1-10 scale) for a child
    # to inherit. Cutoff guards against propagating a noisy enrichment.
    min_parent_confidence: int = 5
    # Parent's intent must not be "unknown" — a parent whose enrichment
    # failed to commit an intent shouldn't be canonical for anyone.
    require_known_intent: bool = True


class AnalystIndexes(BaseModel):
    artifact_rules: str = "prism.analyst.artifact_rules"


class MetricsIndexes(BaseModel):
    """Threshold-distribution snapshots index (brutal-review phase 4).

    One doc per (run_id, kind, layer) capturing corpus-wide percentile
    bands. Miners that previously used hardcoded thresholds will look up
    a fresh distribution doc here and pick a band by percentile.
    """
    default: str = "prism.metrics"


class MetricsConfig(BaseModel):
    """Per-run threshold distribution writer.

    The `track threshold-distributions` step in the backward chain writes
    one doc per metric kind per run. Disabled until the writer ships in
    phase 4.1; the index + config stub land first so the mapping is
    available for downstream readers.
    """
    enabled: bool = False
    indexes: MetricsIndexes = Field(default_factory=MetricsIndexes)


class OpsIndexes(BaseModel):
    """Per-run pipeline-telemetry index (P4.2)."""
    default: str = "prism.ops"


class OpsConfig(BaseModel):
    """Run-telemetry writer. Each tracked CLI verb writes a started→
    finished/failed doc to `indexes.default`. Best-effort; the writer skips
    silently when the index is absent."""
    indexes: OpsIndexes = Field(default_factory=OpsIndexes)
    # Console "pipeline running" banner freshness window (minutes). A
    # `status=started` ops doc counts as a live run until its `started_at` is
    # older than this — long enough to cover the longest single run, short
    # enough that a crashed verb (which never wrote its finish patch) stops
    # showing as "running". Default 60 suits the per-verb systemd cadence
    # (each finishes in minutes). Raise it for a bulk-backfill phase, where a
    # single `pipeline --backfill` writes one started doc that lives for hours
    # (e.g. 2880 = 48h); revert to 60 for steady state.
    pipeline_running_window_min: int = 60


class AnalystRuleConfig(BaseModel):
    """Analyst-authored artifact extraction rules (ROADMAP #5).

    Runtime tunables for the rule subsystem. Index name lives under
    `indexes.artifact_rules`. The forward-application path consults active
    rules once at the start of each worker run (CLI verbs are one-shot, so
    no live cache-invalidation is needed); the console POST handler reads
    rules per request.
    """
    enabled: bool = True
    indexes: AnalystIndexes = Field(default_factory=AnalystIndexes)
    scan_batch_size: int = 100
    # Cap matches per command doc to bound the analyst_artifacts nested array.
    max_match_per_doc: int = 50
    # POST scans inline when affected_estimate < threshold; else queues for
    # the next backward cycle's `apply-artifact-rules` run.
    sync_scan_doc_threshold: int = 5000
    # Pattern compile guard (regex match_type only).
    regex_compile_timeout_ms: int = 50
    # Dry-run sample size for catastrophic-pattern probe.
    regex_sample_size: int = 500
    # Hard ceiling on retroactive scan output per rule.
    max_match_count_per_rule: int = 50000


class ClassificationConfig(BaseModel):
    """Data-privacy gate (src/enrich/classification.py). Confidential sensor
    data must never be escalated to the cloud LLM or queried against CTI feeds.
    A per-sensor ingest pipeline stamps `dshield.classification: public|
    confidential`; the gate releases only explicit `public` data."""
    # Fail-safe (True, default): data with no explicit `public` tag is treated
    # as confidential and never released. Set False (fail-open) — only explicit
    # `confidential` is gated — once every public sensor is tagged `public`.
    unclassified_is_confidential: bool = True


class AppConfig(BaseModel):
    elasticsearch: ESConfig
    llm: LLMConfig
    worker: WorkerConfig
    prompts: PromptsConfig
    cloud: CloudConfig = Field(default_factory=CloudConfig)
    classification: ClassificationConfig = Field(default_factory=ClassificationConfig)
    command_cluster: CommandClusterConfig = Field(default_factory=CommandClusterConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    ip: IPConfig = Field(default_factory=IPConfig)
    cooccurrence: CooccurrenceConfig = Field(default_factory=CooccurrenceConfig)
    intel: IntelConfig = Field(default_factory=IntelConfig)
    findings: FindingsConfig = Field(default_factory=FindingsConfig)
    command_shape_dedup: ShapeDedupConfig = Field(default_factory=ShapeDedupConfig)
    analyst: AnalystRuleConfig = Field(default_factory=AnalystRuleConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    ops: OpsConfig = Field(default_factory=OpsConfig)


class Secrets(BaseSettings):
    """Secrets pulled from environment / .env."""
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    es_username: Optional[str] = None
    es_password: Optional[str] = None
    es_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    # Intel-subsystem provider keys (M2). Both free-tier:
    # GreyNoise Community (~10k req/month), AbuseIPDB (1000 checks/day).
    # When unset, the corresponding provider is silently skipped at
    # `intel.refresh._build_providers` construction time — no error,
    # the rest of the providers run normally.
    greynoise_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    # M4: abuse.ch unified auth key. ONE key covers URLhaus,
    # ThreatFox, FeodoTracker, and the future MalwareBazaar provider.
    # Register at https://auth.abuse.ch/. Optional: the abuse.ch
    # endpoints we use also serve unauthenticated callers at lower
    # rate limits — when this is set, the providers send the key
    # as the `Auth-Key` request header; when unset, they fall back
    # to unauthenticated requests and just hope the rate limit
    # holds.
    abuse_ch_auth_key: Optional[str] = None
    # #2: VirusTotal public API v3 key. Scaffold only — the provider is
    # disabled by default; even with a key it stays off unless
    # `intel.providers.virustotal_public.enabled` is set. Free tier is
    # 4 req/min / 500 per day, so it's budget-gated like GreyNoise.
    virustotal_api_key: Optional[str] = None


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Optional[str] = None) -> AppConfig:
    """Load default.yaml, then deep-merge local.yaml override if it exists.

    Path resolution:
      1. --config / <ENV_PREFIX>CONFIG -> base file
      2. else: config/default.yaml
      3. local override: sibling file 'local.yaml' next to base
      4. or <ENV_PREFIX>LOCAL_CONFIG (absolute override path)
      (ENV_PREFIX is defined in __about__.py; currently "PRISM_")
    """
    cfg_path = path or os.environ.get(_CONFIG_ENV, "config/default.yaml")
    p = Path(cfg_path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {cfg_path}")
    data = yaml.safe_load(p.read_text()) or {}

    local_env = os.environ.get(_LOCAL_CONFIG_ENV)
    if local_env:
        candidates = [Path(local_env)]
    else:
        candidates = [p.parent / "local.yaml", p.parent / "local.yml"]
    for local_path in candidates:
        if local_path.exists():
            local_data = yaml.safe_load(local_path.read_text()) or {}
            data = _deep_merge(data, local_data)
            break

    return AppConfig(**data)


def _resolve_env_file(config_path: Optional[str]) -> Optional[Path]:
    """Find the .env file. Search order:
      1. <ENV_PREFIX>ENV (explicit absolute path)
      2. Sibling of the resolved config file
      3. Parent of the config file
      4. Current working directory
    """
    explicit = os.environ.get(_ENV_FILE_ENV)
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None

    if config_path:
        cfg = Path(config_path).resolve()
        for candidate in (cfg.parent.parent / ".env", cfg.parent / ".env"):
            if candidate.exists():
                return candidate

    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        return cwd_env
    return None


def load_secrets(config_path: Optional[str] = None) -> Secrets:
    """Load ES credentials. Reads OS env first; if a .env file is locatable,
    it is layered in too (OS env wins on conflict, per pydantic-settings).
    """
    env_path = _resolve_env_file(config_path)
    if env_path is not None:
        return Secrets(_env_file=str(env_path))  # type: ignore[call-arg]
    return Secrets()


def load_prompt(cfg: AppConfig, name: str = "command_enrichment") -> str:
    path = getattr(cfg.prompts, name)
    return Path(path).read_text()


# CooccurrenceConfig fields that change the LLM prompt (affect the
# sibling block injected into the prompt). Pinned so the hash doesn't
# churn when unrelated fields are added later.
_LLM_COOC_FIELDS = ("enabled", "top_k", "session_sample_size", "min_sessions")
# CooccurrenceConfig fields that only affect the embed text, not the LLM
# prompt. `embed_cooccurrence` toggles whether siblings appear in the
# embedded representation; it doesn't change anything the LLM sees.
_EMBED_COOC_FIELDS = ("embed_cooccurrence",)
_CONFIG_HASH_LEN = 16

# Prompt files that feed the *command-enrichment* LLM path and therefore
# belong in `llm_config_hash`: the local enrichment prompt and the cloud
# escalation prompt (`command_deep_dive`, used by `escalate`). The remaining
# prompts — `playbook_name`, `playbook_disambiguate`, `cluster_pair_explanation`
# — run over already-enriched clusters; editing them must NOT invalidate
# cached command enrichments (which would force a needless full
# re-enrich-stale). Pinned so adding a new unrelated prompt later doesn't
# silently re-couple it to the enrichment cache.
_LLM_PROMPT_FIELDS = ("command_enrichment", "command_deep_dive")


def _hash_prompt_files(cfg: AppConfig) -> str:
    """SHA-256 each enrichment-affecting prompt file's content; combine
    deterministically. Only `_LLM_PROMPT_FIELDS` are hashed — see that
    constant for why the naming/console prompts are excluded."""
    parts: list[str] = []
    prompts_dict = cfg.prompts.model_dump()
    for name in sorted(_LLM_PROMPT_FIELDS):
        path = prompts_dict.get(name)
        if not path:
            continue
        try:
            content = Path(path).read_bytes()
        except OSError:
            # Missing prompt file: fold the path into the digest so a typo
            # doesn't silently produce the same hash as a correct config.
            digest = hashlib.sha256(f"missing:{path}".encode("utf-8")).hexdigest()
        else:
            digest = hashlib.sha256(content).hexdigest()
        parts.append(f"{name}={digest}")
    return "\n".join(parts)


# Path to the command-grounding data directory (ROADMAP #11). Hashed into
# `compute_llm_config_hash` so that edits to curated descriptions or a
# refreshed tldr.json bundle automatically invalidate cached enrichments.
# Resolved relative to this module so it works regardless of cwd.
_COMMANDS_DATA_DIR = Path(__file__).parent / "data" / "commands"


def _hash_command_grounding() -> str:
    """SHA-256 over the command-grounding data directory's content.

    Walks `src/enrich/data/commands/` recursively, hashing every regular
    file's content alongside its relative path. Missing directory returns
    a fixed sentinel rather than a random digest so an unconfigured
    install doesn't churn the cache.
    """
    if not _COMMANDS_DATA_DIR.exists():
        return "missing"
    parts: list[str] = []
    for path in sorted(_COMMANDS_DATA_DIR.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(_COMMANDS_DATA_DIR).as_posix()
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = hashlib.sha256(f"unreadable:{rel}".encode("utf-8")).hexdigest()
        parts.append(f"{rel}={digest}")
    return "\n".join(parts)


def compute_llm_config_hash(cfg: AppConfig) -> str:
    """Fingerprint of the inputs that affect *LLM* enrichment output.

    Returns a 16-hex prefix of SHA-256 over:
      - LLM-affecting cooccurrence fields (sibling-context inputs).
      - SHA-256 of the enrichment-path prompt files' content
        (`_LLM_PROMPT_FIELDS`: local enrichment + cloud `command_deep_dive`).
        Naming/console prompts are excluded so editing them doesn't churn
        the command-enrichment cache.
      - SHA-256 of the command-grounding data directory's content
        (ROADMAP #11) — edits to curated descriptions or a refreshed
        tldr.json bundle change the ground-truth block injected into
        the prompt and therefore should invalidate cached enrichments.

    Used as one half of the auto-invalidating cache key (ROADMAP #7). A
    change here means the cached intent/description
    are no longer trustworthy — the next `enrich` will re-run the LLM.
    Embed-only changes (see `compute_embed_config_hash`) do NOT flip
    this; they're handled separately so `reembed` doesn't waste an LLM
    call.
    """
    cooc = cfg.cooccurrence.model_dump()
    cooc_subset = {k: cooc[k] for k in _LLM_COOC_FIELDS if k in cooc}
    cooc_payload = json.dumps(cooc_subset, sort_keys=True, separators=(",", ":"))
    prompt_payload = _hash_prompt_files(cfg)
    grounding_payload = _hash_command_grounding()
    # Shape-dedup gate flips cached-LLM trust: when gating turns on, a
    # row written as standalone-via-LLM is still trustworthy, but a row
    # previously written via inherit-path is only as trustworthy as its
    # parent. Including the toggle here so an operator-level flip
    # (off→on or on→off) routes through the normal re-enrich-stale
    # machinery rather than silently changing semantics.
    dedup_payload = json.dumps({
        "enabled": cfg.command_shape_dedup.enabled,
        "require_known_intent": cfg.command_shape_dedup.require_known_intent,
    }, sort_keys=True, separators=(",", ":"))
    # The injection-fencing system prompt is part of what the model sees, so
    # editing it changes enrichment output — fold it in so a change routes
    # through the normal re-enrich-stale invalidation.
    from .llm.fencing import SYSTEM_PROMPT
    combined = (
        f"cooc:{cooc_payload}\n"
        f"prompts:{prompt_payload}\n"
        f"grounding:{grounding_payload}\n"
        f"shape_dedup:{dedup_payload}\n"
        f"system:{SYSTEM_PROMPT}"
    )
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:_CONFIG_HASH_LEN]


def compute_embed_config_hash(cfg: AppConfig) -> str:
    """Fingerprint of the inputs that affect *embedding* output.

    Returns a 16-hex prefix of SHA-256 over:
      - `llm.embed_context` (which stored fields get prepended to the
        embed text — sorted JSON so list ordering is stable).
      - `llm.embedding_model` (changing models obviously changes vectors).
      - `llm.embed_input_order` (E8.1 — prelude/command layout selector).
      - `cooccurrence.embed_cooccurrence` (whether siblings get appended
        to the embed text — independent of whether they were fetched for
        the LLM prompt).

    Used as the other half of the auto-invalidating cache key (ROADMAP
    #7). A change here means only the embedding is stale — `reembed`
    can refresh it without re-running the LLM. `mark_embed_cached`
    updates only this hash, preserving `llm_config_hash`, so a stale
    LLM output can't be silently blessed by an embed-only refresh.
    """
    cooc = cfg.cooccurrence.model_dump()
    cooc_subset = {k: cooc[k] for k in _EMBED_COOC_FIELDS if k in cooc}
    embed_payload = json.dumps({
        "embed_context": sorted(cfg.llm.embed_context or []),
        "embedding_model": cfg.llm.embedding_model,
        "embed_input_order": cfg.llm.embed_input_order,
        "cooc": cooc_subset,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(embed_payload.encode("utf-8")).hexdigest()[:_CONFIG_HASH_LEN]
