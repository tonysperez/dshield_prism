"""Intel priority queue.

Owns the priority formula + the artifact-discovery scan that feeds the
queue. Pure functions where possible — the priority math has its own
smoke test at `scripts/smoke_test_intel_priority.py`.

Design (ROADMAP "Research-mode strategic gaps" section A):

  priority = novelty_w * novelty
           + low_conf_w * (1 - confidence/10)
           + centrality_w * centrality_norm
           + recency_w * recency_decay

Local novelty dominates by design — the scarce free-tier budgets go
first to artifacts most likely to be discoveries. Weights are
configurable in `cfg.intel.priority`.

The discovery scan walks the per-source enrichment indices, extracts
artifacts (currently only source IPs in milestone 1), canonicalises
them, filters never-query CIDRs, and upserts them into the SQLite
`intel_queue` table with the computed priority.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from ..cache import StateDB
from ..classification import releasable_filter
from ..config import AppConfig, IntelPriorityConfig
from .artifact import Artifact, canonical_hash, canonical_ip, canonical_url, is_in_cidrs

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Priority computation — pure function.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PriorityInputs:
    """All signals the priority formula consumes. None = signal unavailable."""
    novelty_score: Optional[float] = None       # 0.0–1.0 (or None)
    confidence: Optional[int] = None            # 1–10 LLM self-rating
    centrality_norm: Optional[float] = None     # 0.0–1.0, log-normalised occurrence
    age_hours: Optional[float] = None           # hours since first-observed locally
    # Additive tier offset, added verbatim to the score (#2). Default 0 leaves
    # ip/url ordering untouched; the hash scans use it to layer file-event
    # hashes (tier 1; real drops > content-writes) above regex-from-command
    # hashes (tier 2). Tiers only order WITHIN a kind (the queue pops per-kind),
    # so this never perturbs cross-kind behaviour.
    base_boost: float = 0.0


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def compute_priority(
    inputs: PriorityInputs, weights: IntelPriorityConfig,
) -> float:
    """Compute the priority score for a queue entry.

    Each term is in [0, 1] before weighting; missing signals contribute
    0 (their weight is effectively skipped). The result is the weighted
    sum — not normalised to [0, 1] since only relative ordering matters
    when popping from the queue.
    """
    novelty_term = _clamp(inputs.novelty_score) if inputs.novelty_score is not None else 0.0
    if inputs.confidence is not None:
        low_conf_term = _clamp(1.0 - inputs.confidence / 10.0)
    else:
        low_conf_term = 0.0
    centrality_term = _clamp(inputs.centrality_norm) if inputs.centrality_norm is not None else 0.0
    if inputs.age_hours is not None and weights.recency_half_life_hours > 0:
        # Half-life decay: 1 at age=0, 0.5 at age=half_life.
        recency_term = math.exp(
            -math.log(2.0) * max(0.0, inputs.age_hours) / weights.recency_half_life_hours
        )
    else:
        recency_term = 0.0
    return (
        weights.novelty_w * novelty_term
        + weights.low_conf_w * low_conf_term
        + weights.centrality_w * centrality_term
        + weights.recency_w * recency_term
        + inputs.base_boost
    )


# ---------------------------------------------------------------------------
# Artifact discovery from project-owned indices.
# ---------------------------------------------------------------------------


def _iter_ip_artifacts_from_rollup(es, cfg: AppConfig) -> Iterator[tuple[Artifact, PriorityInputs]]:
    """Scan the IP rollup index and yield (artifact, priority inputs).

    The IP rollup is the canonical place — every source IP we've ever
    observed locally appears here, with the behavioural stats (mean
    novelty, total sessions, first/last seen) needed to compute
    priority. Encoding artifacts and other one-off oddities don't show
    up in the IP rollup, so the queue stays clean.
    """
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    if not es.indices.exists(index=idx):
        return
    body = {
        "size": cfg.intel.max_per_run,
        "_source": [
            "source.ip",
            "dshield.cowrie.enrichment.ip.mean_novelty_score",
            "dshield.cowrie.enrichment.ip.max_novelty_score",
            "dshield.cowrie.enrichment.ip.total_sessions",
            "dshield.cowrie.enrichment.ip.first_seen",
        ],
        # Classification gate: never queue a confidential IP for CTI lookup.
        # releasable_filter() excludes any IP whose rollup isn't explicitly
        # public (fail-safe), so confidential data never reaches an intel feed.
        "query": {"bool": {"filter": [
            {"exists": {"field": "source.ip"}},
            releasable_filter(cfg),
        ]}},
        "sort": [{"_doc": "asc"}],
    }
    now = datetime.now(timezone.utc)
    # Corpus-scale denominator for centrality. Bounded so a single
    # very-active IP doesn't pin every other IP at centrality≈0. Same
    # rationale as ROADMAP #14 (fixed-denominator scalar normalisation).
    _TOTAL_SESSIONS_DENOM = 1000.0
    try:
        resp = es.search(index=idx, **body)
    except Exception as exc:                       # pragma: no cover
        log.warning("intel: IP rollup scan failed: %s", exc)
        return
    for hit in resp.get("hits", {}).get("hits", []) or []:
        src = hit.get("_source") or {}
        ip_raw = (src.get("source") or {}).get("ip")
        canon = canonical_ip(ip_raw) if ip_raw else None
        if canon is None:
            continue
        if is_in_cidrs(canon, cfg.intel.never_query_cidrs):
            continue
        enrich = (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}).get("ip") or {}
        # Use max_novelty so a single high-novelty session dominates a
        # bag of boilerplate ones (mean would dilute the signal we
        # most want to act on).
        novelty = enrich.get("max_novelty_score")
        if novelty is None:
            novelty = enrich.get("mean_novelty_score")
        total_sessions = enrich.get("total_sessions") or 0
        centrality_norm = (
            math.log1p(total_sessions) / math.log1p(_TOTAL_SESSIONS_DENOM)
            if total_sessions > 0 else 0.0
        )
        first_seen_str = enrich.get("first_seen")
        age_hours: Optional[float]
        if first_seen_str:
            try:
                fs = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
                age_hours = max(0.0, (now - fs).total_seconds() / 3600.0)
            except (ValueError, TypeError):
                age_hours = None
        else:
            age_hours = None
        yield (
            Artifact("ip", canon),
            PriorityInputs(
                novelty_score=float(novelty) if novelty is not None else None,
                confidence=None,  # IP-level rollup doesn't carry a confidence
                centrality_norm=centrality_norm,
                age_hours=age_hours,
            ),
        )


def _iter_in_command_ip_artifacts_from_commands(es, cfg: AppConfig) -> Iterator[tuple[Artifact, PriorityInputs]]:
    """Discover `ipv4-addr` indicators inside command bodies — the C2
    hosts the attacker pointed at (in wget / curl / nc lines), as
    distinct from `source.ip` (the attacker IP itself).

    Source IPs come from the IP rollup. In-command IPs come from
    `threat.indicator.type=ipv4-addr` nested entries on the enriched
    command docs. The Artifact is still `kind=ip` — same intel index,
    same provider dispatch — but the discovery path differs. The
    `(kind, value)` queue key naturally dedupes when an IP appears
    in both populations.

    M4.1. Closes the gap that left URL artifact panes showing
    `host_ip_intel=None` for in-command IPs that had never been
    queued for enrichment.

    Priority signal: only centrality (occurrence count from the
    nested agg). No novelty/confidence available at the indicator
    level; recency is omitted (could be added via top_hits agg
    later if needed).
    """
    idx = cfg.elasticsearch.indexes.cowrie.commands
    if not es.indices.exists(index=idx):
        return
    _OCCURRENCE_DENOM = 100.0
    try:
        resp = es.search(
            index=idx, size=0,
            query=releasable_filter(cfg),  # classification gate: releasable docs only
            aggs={
                "indicators": {
                    "nested": {"path": "threat.indicator"},
                    "aggs": {
                        "ipv4_addr": {
                            "filter": {"term": {"threat.indicator.type": "ipv4-addr"}},
                            "aggs": {
                                "by_ip": {
                                    "terms": {
                                        "field": "threat.indicator.ip",
                                        "size": cfg.intel.max_per_run,
                                    }
                                }
                            }
                        }
                    }
                }
            },
        )
    except Exception as exc:                           # pragma: no cover
        log.warning("intel: in-command IP nested-agg scan failed: %s", exc)
        return
    buckets = (
        resp.get("aggregations", {}).get("indicators", {})
        .get("ipv4_addr", {}).get("by_ip", {}).get("buckets", [])
    ) or []
    for b in buckets:
        raw = b.get("key")
        if not raw:
            continue
        canon = canonical_ip(raw)
        if canon is None:
            continue
        if is_in_cidrs(canon, cfg.intel.never_query_cidrs):
            continue
        occurrence = int(b.get("doc_count") or 0)
        centrality_norm = (
            math.log1p(occurrence) / math.log1p(_OCCURRENCE_DENOM)
            if occurrence > 0 else 0.0
        )
        yield (
            Artifact("ip", canon),
            PriorityInputs(
                novelty_score=None,        # no command-level novelty for these
                confidence=None,
                centrality_norm=centrality_norm,
                age_hours=None,
            ),
        )


def _iter_url_artifacts_from_commands(es, cfg: AppConfig) -> Iterator[tuple[Artifact, PriorityInputs]]:
    """Discover URL artifacts from the command-enrichment index.

    URLs are stored under `threat.indicator[]` (mapped `nested`) with
    `type=url` and `url.full` as the value. We aggregate distinct
    `url.full` values via a nested terms agg — that gives both the
    URLs and their corpus occurrence count in a single query.

    Priority signal: log-scaled `occurrence_count` as centrality. No
    direct novelty or confidence available at the URL level (those
    live on the command docs the URL is referenced from). Recency is
    omitted since the URL itself doesn't have a single
    first_observed time across the command corpus — could be added
    via a top_hits agg later if needed.
    """
    idx = cfg.elasticsearch.indexes.cowrie.commands
    if not es.indices.exists(index=idx):
        return
    # Bounded denominator; corpus URLs are few hundreds at most.
    _OCCURRENCE_DENOM = 100.0
    try:
        resp = es.search(
            index=idx, size=0,
            query=releasable_filter(cfg),  # classification gate: releasable docs only
            aggs={
                "indicators": {
                    "nested": {"path": "threat.indicator"},
                    "aggs": {
                        "urls": {
                            "filter": {"term": {"threat.indicator.type": "url"}},
                            "aggs": {
                                "by_url": {
                                    "terms": {
                                        "field": "threat.indicator.url.full",
                                        "size": cfg.intel.max_per_run,
                                    }
                                }
                            }
                        }
                    }
                }
            },
        )
    except Exception as exc:                           # pragma: no cover
        log.warning("intel: URL nested-agg scan failed: %s", exc)
        return
    buckets = (
        resp.get("aggregations", {}).get("indicators", {})
        .get("urls", {}).get("by_url", {}).get("buckets", [])
    ) or []
    for b in buckets:
        raw = b.get("key")
        if not raw:
            continue
        canon = canonical_url(raw)
        if canon is None:
            continue
        occurrence = int(b.get("doc_count") or 0)
        centrality_norm = (
            math.log1p(occurrence) / math.log1p(_OCCURRENCE_DENOM)
            if occurrence > 0 else 0.0
        )
        yield (
            Artifact("url", canon),
            PriorityInputs(
                novelty_score=None,        # no URL-level novelty
                confidence=None,           # no URL-level confidence
                centrality_norm=centrality_norm,
                age_hours=None,            # not tracked at URL level (yet)
            ),
        )


# --- Hash artifacts (ROADMAP #2) ----------------------------------------------
# 3-tier priority via PriorityInputs.base_boost (see project memory
# `hash-intel-priority`): cowrie file-event hashes are tier 1 (real drops
# outrank shell content-writes); regex-from-command hashes are tier 2.
_HASH_TIER1_DROP_BOOST = 2.0    # url-fetched payload or binary/script drop
_HASH_TIER1_WRITE_BOOST = 1.0   # shell content-write (authorized_keys, etc.)
# (tier 2 = command-regex hashes use the default base_boost of 0.0)

# Substrings marking a shell *content-write* target rather than a payload drop.
_CONTENT_WRITE_MARKERS = (
    "authorized_keys", "hosts.deny", "hosts.allow", "/dev/null",
    ".ssh", "/etc/", ".bashrc", ".profile", "bash_history", "/root/.",
)
# Well-known trivial-content hashes (empty string / newline / "test") — cowrie
# hashing an `echo`/redirect, never malware. Always content-write tier.
_TRIVIAL_HASHES = frozenset({
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # ""
    "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",  # "\n"
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # "test"
})


def _hash_drop_boost(sha256: str, filename: Optional[str], has_url: bool) -> float:
    """Within-tier-1 boost: real drops outrank content-writes. A hash is a drop
    if it was url-fetched OR its filename isn't a shell content-write target and
    it isn't a known-trivial constant. Pure."""
    if sha256.lower() in _TRIVIAL_HASHES:
        return _HASH_TIER1_WRITE_BOOST
    if has_url:
        return _HASH_TIER1_DROP_BOOST
    fn = (filename or "").lower()
    if fn and any(m in fn for m in _CONTENT_WRITE_MARKERS):
        return _HASH_TIER1_WRITE_BOOST
    return _HASH_TIER1_DROP_BOOST


def _iter_hash_artifacts_from_sessions(es, cfg: AppConfig) -> Iterator[tuple[Artifact, PriorityInputs]]:
    """Tier 1: cowrie-computed file hashes from the session-rollup `file_events`
    (ROADMAP #3 output). Highest-confidence hashes in the corpus. Within tier 1,
    `base_boost` ranks real drops above shell content-writes."""
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    if not es.indices.exists(index=idx):
        return
    fe = "dshield.cowrie.enrichment.session.file_events"
    _OCCURRENCE_DENOM = 100.0
    try:
        resp = es.search(
            index=idx, size=0, query=releasable_filter(cfg),  # classification gate: releasable docs only
            aggs={"fe": {"nested": {"path": fe}, "aggs": {
                "by_hash": {"terms": {"field": f"{fe}.sha256", "size": cfg.intel.max_per_run},
                    "aggs": {
                        "has_url": {"filter": {"exists": {"field": f"{fe}.url"}}},
                        "top_filename": {"terms": {"field": f"{fe}.filename.keyword", "size": 1}},
                    }}}}},
        )
    except Exception as exc:  # pragma: no cover
        log.warning("intel: session file_events hash scan failed: %s", exc)
        return
    buckets = (resp.get("aggregations", {}).get("fe", {}).get("by_hash", {}).get("buckets", [])) or []
    for b in buckets:
        canon = canonical_hash(b.get("key"))
        if canon is None:
            continue
        has_url = int((b.get("has_url") or {}).get("doc_count") or 0) > 0
        fn_buckets = (b.get("top_filename") or {}).get("buckets") or []
        filename = fn_buckets[0]["key"] if fn_buckets else None
        occurrence = int(b.get("doc_count") or 0)
        centrality_norm = (
            math.log1p(occurrence) / math.log1p(_OCCURRENCE_DENOM) if occurrence > 0 else 0.0
        )
        yield (
            Artifact("hash", canon),
            PriorityInputs(
                centrality_norm=centrality_norm,
                base_boost=_hash_drop_boost(canon, filename, has_url),
            ),
        )


def _iter_hash_artifacts_from_commands(es, cfg: AppConfig) -> Iterator[tuple[Artifact, PriorityInputs]]:
    """Tier 2: file hashes extracted from command text (regex / LLM IOCs), via
    the command `threat.indicator` file entries. Mirrors the URL scan. Default
    `base_boost` (0) keeps these below all file-event hashes."""
    idx = cfg.elasticsearch.indexes.cowrie.commands
    if not es.indices.exists(index=idx):
        return
    _OCCURRENCE_DENOM = 100.0
    try:
        resp = es.search(
            index=idx, size=0, query=releasable_filter(cfg),  # classification gate: releasable docs only
            aggs={"indicators": {"nested": {"path": "threat.indicator"}, "aggs": {
                "files": {"filter": {"term": {"threat.indicator.type": "file"}}, "aggs": {
                    "by_hash": {"terms": {
                        "field": "threat.indicator.file.hash.sha256",
                        "size": cfg.intel.max_per_run,
                    }}}}}}},
        )
    except Exception as exc:  # pragma: no cover
        log.warning("intel: in-command hash nested-agg scan failed: %s", exc)
        return
    buckets = (
        resp.get("aggregations", {}).get("indicators", {})
        .get("files", {}).get("by_hash", {}).get("buckets", [])
    ) or []
    for b in buckets:
        canon = canonical_hash(b.get("key"))
        if canon is None:
            continue
        occurrence = int(b.get("doc_count") or 0)
        centrality_norm = (
            math.log1p(occurrence) / math.log1p(_OCCURRENCE_DENOM) if occurrence > 0 else 0.0
        )
        yield (Artifact("hash", canon), PriorityInputs(centrality_norm=centrality_norm))


def discover_and_enqueue(
    es, db: StateDB, cfg: AppConfig,
) -> dict[str, int]:
    """Walk the per-source indices, compute priorities, upsert into the queue.

    Returns a stats dict (`{kind: count_enqueued}`) for the CLI to print.
    Idempotent and cheap-when-no-change: existing rows get their
    priority refreshed but the row stays in place.

    Scans:
      - IP rollup → `ip` artifacts (source IPs, M1)
      - command enrichment threat.indicator → `url` artifacts (M4)
      - command enrichment threat.indicator → `ip` artifacts
        (in-command IPs — C2 hosts in wget/curl commands, M4.1)
    """
    weights = cfg.intel.priority
    now_iso = datetime.now(timezone.utc).isoformat()
    counts: dict[str, int] = {}
    for source_iter in (
        _iter_ip_artifacts_from_rollup(es, cfg),
        _iter_in_command_ip_artifacts_from_commands(es, cfg),
        _iter_url_artifacts_from_commands(es, cfg),
        # Hash scans (#2): command-regex (tier 2) BEFORE session file-events
        # (tier 1) so the tier-1 priority wins the per-(kind,value) upsert when
        # a hash appears in both.
        _iter_hash_artifacts_from_commands(es, cfg),
        _iter_hash_artifacts_from_sessions(es, cfg),
    ):
        for artifact, inputs in source_iter:
            prio = compute_priority(inputs, weights)
            db.intel_queue_upsert(artifact.kind, artifact.value, prio, now_iso)
            counts[artifact.kind] = counts.get(artifact.kind, 0) + 1
    return counts


def select_for_provider(
    db: StateDB, provider_handles: Iterable[str], limit: int,
) -> list[Artifact]:
    """Pop top-N queued artifacts the provider can answer.

    Doesn't actually remove rows — the refresh worker calls
    `intel_queue_mark_done` only after the lookup succeeds across
    every applicable provider. A row stays in the queue until every
    provider that handles its kind has had a successful pass.
    """
    out: list[Artifact] = []
    remaining = limit
    for kind in provider_handles:
        if remaining <= 0:
            break
        rows = db.intel_queue_pop_top(kind, remaining)
        for value, _prio in rows:
            try:
                out.append(Artifact(kind, value))
            except ValueError:
                # Skip rows that fail re-validation (kind was renamed,
                # canonicaliser was tightened, …) so they don't poison
                # the worker. The row stays in the queue until manually
                # cleared.
                continue
        remaining -= len(rows)
    return out
