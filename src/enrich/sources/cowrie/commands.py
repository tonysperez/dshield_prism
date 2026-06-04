"""Cowrie command layer: enrichment, escalation, re-embed, and clustering.

Phase 1: read raw cowrie command events -> dedup -> enrich (local LLM, optional
cloud escalation) -> embed -> write to the commands index.
Phase 2: escalate locally-enriched docs whose novelty rose above threshold.
Phase 3: HDBSCAN over command embeddings (delegated to clustering.run_layer_clustering).
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterator, Optional

if TYPE_CHECKING:
    import numpy as np

from pydantic import ValidationError
from elasticsearch import Elasticsearch

from ...cache import StateDB
from ...command_shape import compute_shape_hash, extract_iocs_regex
from ...config import (
    AppConfig, Secrets, CommandClusterConfig,
    compute_embed_config_hash, compute_llm_config_hash, load_prompt,
)
from ...es_client import bulk_write, make_client
from ...llm import make_llm_client
from ...llm.schemas import CommandEnrichment, CloudCommandEnrichment
from ... import triage as triage_mod

log = logging.getLogger(__name__)

# P4.1 — per-item graceful-degradation fallbacks (e.g. a co-occurrence agg query
# failing for ONE command) must not log a `warning` each: at corpus scale that
# floods the journal with hundreds of thousands of identical lines. Instead warn
# ONCE per run per failure-type (the operator signal), count the rest, and log
# them at `debug`. Each verb runs as its own process, so these module-level
# counters are naturally per-run; `flush_degraded_fallbacks` surfaces the totals
# once at the end of the dominant `enrich` path (mirrors the MITRE-drop aggregate).
_DEGRADED_FALLBACKS: dict[str, int] = defaultdict(int)
_DEGRADED_WARNED: set[str] = set()


def _note_degraded(key: str, msg: str, *args) -> None:
    """Record a per-item degradation: warn once per run per `key`, then debug."""
    _DEGRADED_FALLBACKS[key] += 1
    if key not in _DEGRADED_WARNED:
        _DEGRADED_WARNED.add(key)
        log.warning(msg + " [per-item fallback; further occurrences this run at debug]", *args)
    else:
        log.debug(msg, *args)


def flush_degraded_fallbacks() -> dict:
    """Return + reset the per-run degraded-fallback counts so the caller can
    surface the aggregate once (see the scale of any degradation without the
    per-item flood)."""
    snapshot = dict(_DEGRADED_FALLBACKS)
    _DEGRADED_FALLBACKS.clear()
    _DEGRADED_WARNED.clear()
    return snapshot


_COMMANDS_MAPPING = "setup/es-mappings/cowrie/commands.json"
_COMMAND_CLUSTERS_MAPPING = "setup/es-mappings/cowrie/command_clusters.json"

# Fixed corpus-scale denominators for the log1p-normalized scalar block
# (ROADMAP #14). See sessions.py for the rationale. occurrence_count P99.9
# ≈ 50 today on a young corpus, but on multi-year data widely-deployed
# commands like `ls`/`cat` will easily hit 6+ figures; 100000 covers that.
# unique_source_ips scales sublinearly with occurrences — 10000 is fine.
_SCALAR_DENOM_OCCURRENCE_COUNT = 100000.0
_SCALAR_DENOM_UNIQUE_SOURCE_IPS = 10000.0

# Painless: patch only the embedding vector.
_REEMBED_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "ctx._source.dshield.cowrie.enrichment.embedding = params.embedding;"
    "ctx._source.dshield.cowrie.enrichment.embed_config_hash = params.embed_config_hash;"
)

# Painless: re-enrich stale rows. Overwrites the LLM-derived fields
# (intent/tactics/techniques/description/confidence/embedding/iocs/model)
# and the two auto-hashes; leaves event-derived fields (occurrence_count,
# unique_sessions, etc.) and the cluster.* block untouched. ROADMAP #7.5.
_REENRICH_SCRIPT = (
    "if (ctx._source.event == null) { ctx._source.event = [:]; }"
    "ctx._source.event.provider = params.provider;"
    "ctx._source.event.reason = params.description;"
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "en.intent = params.intent;"
    "en.confidence = params.confidence;"
    "en.model = params.model;"
    "en.llm_config_hash = params.llm_config_hash;"
    "en.embed_config_hash = params.embed_config_hash;"
    "en.embedding = params.embedding;"
    "en.analyst_artifacts = params.analyst_artifacts;"
    "if (ctx._source.threat == null) { ctx._source.threat = [:]; }"
    "if (ctx._source.threat.tactic == null) { ctx._source.threat.tactic = [:]; }"
    "if (ctx._source.threat.technique == null) { ctx._source.threat.technique = [:]; }"
    "ctx._source.threat.tactic.id = params.tactics;"
    "ctx._source.threat.technique.id = params.techniques;"
    "ctx._source.threat.indicator = params.indicators;"
)

_WS_RE = re.compile(r"\s+")

# Painless: patch only cloud-overwritten fields (embedding, cluster.*, etc. untouched).
_ESCALATE_SCRIPT = (
    "ctx._source.event.provider = params.provider;"
    "ctx._source.event.reason = params.description;"
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "en.intent = params.intent;"
    "en.confidence = params.confidence;"
    "en.model = params.model;"
    "en.triage_reasons = params.triage_reasons;"
    "en.notes = params.notes;"
    "en.local_fallback = params.local_fallback;"
    "en.analyst_artifacts = params.analyst_artifacts;"
    "if (ctx._source.threat == null) { ctx._source.threat = [:]; }"
    "if (ctx._source.threat.tactic == null) { ctx._source.threat.tactic = [:]; }"
    "if (ctx._source.threat.technique == null) { ctx._source.threat.technique = [:]; }"
    "ctx._source.threat.tactic.id = params.tactics;"
    "ctx._source.threat.technique.id = params.techniques;"
    "ctx._source.threat.indicator = params.indicators;"
)

_CLUSTER_UPDATE_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "if (en.cluster == null) { en.cluster = [:]; }"
    "en.cluster.id = params.cluster_id;"
    "en.cluster.novelty_score = params.novelty_score;"
    # Dual novelty (brutal-review 5.5).
    "if (params.containsKey('novelty_score_external')) {"
    "  en.cluster.novelty_score_external = params.novelty_score_external;"
    "}"
    # External-match attribution (5.9).
    "if (params.containsKey('external_match_id')) {"
    "  en.cluster.external_match_id = params.external_match_id;"
    "}"
    "if (params.containsKey('external_match_cosine')) {"
    "  en.cluster.external_match_cosine = params.external_match_cosine;"
    "}"
    "en.cluster.is_outlier = params.is_outlier;"
    "en.cluster.scored_at = params.scored_at;"
)

# Painless: replace `triage_reasons` in-place. Used by `re-triage --backward`
# to retroactively re-evaluate rule-derived escalation reasons after a triage-
# rule change (e.g. ROADMAP #23 tightening the `base64_blob` gate). Does NOT
# touch enrichment fields or cluster.* — purely cosmetic to the stored list.
# An empty `params.triage_reasons` removes the field entirely so a row that
# would no longer escalate doesn't carry a stale empty list.
# Painless: backfill the `shape` block on an existing doc. Stamps hash +
# role + linked_at without touching any LLM-derived field. Used by
# `backfill-shape` to retroactively label the corpus so the inherit gate
# in `enrich` can find canonicals among historically-enriched commands.
_BACKFILL_SHAPE_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "if (en.shape == null) { en.shape = [:]; }"
    "en.shape.hash = params.shape_hash;"
    "en.shape.role = params.role;"
    "en.shape.linked_at = params.linked_at;"
    "if (params.confidence_at_link != null) { en.shape.confidence_at_link = params.confidence_at_link; }"
)

# Painless: re-enrich a child via the inherit path. Overwrites the LLM-
# derived fields with the parent's values + writes the shape block.
# Same field set as `_REENRICH_SCRIPT` but adds the shape pointer
# updates and uses `local_inherited` as the provider.
_REENRICH_INHERIT_SCRIPT = (
    "if (ctx._source.event == null) { ctx._source.event = [:]; }"
    "ctx._source.event.provider = 'local_inherited';"
    "ctx._source.event.reason = params.description;"
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "en.intent = params.intent;"
    "en.confidence = params.confidence;"
    "en.model = params.model;"
    "en.llm_config_hash = params.llm_config_hash;"
    "en.embed_config_hash = params.embed_config_hash;"
    "en.embedding = params.embedding;"
    "en.analyst_artifacts = params.analyst_artifacts;"
    "if (en.shape == null) { en.shape = [:]; }"
    "en.shape.hash = params.shape_hash;"
    "en.shape.role = 'child';"
    "en.shape.functional_parent = params.functional_parent;"
    "en.shape.linked_at = params.linked_at;"
    "en.shape.inherited_from_model = params.inherited_from_model;"
    "en.shape.confidence_at_link = params.confidence_at_link;"
    "if (ctx._source.threat == null) { ctx._source.threat = [:]; }"
    "if (ctx._source.threat.tactic == null) { ctx._source.threat.tactic = [:]; }"
    "if (ctx._source.threat.technique == null) { ctx._source.threat.technique = [:]; }"
    "ctx._source.threat.tactic.id = params.tactics;"
    "ctx._source.threat.technique.id = params.techniques;"
    "ctx._source.threat.indicator = params.indicators;"
)

_RETRIAGE_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "def en = ctx._source.dshield.cowrie.enrichment;"
    "if (params.triage_reasons == null || params.triage_reasons.size() == 0) {"
    "  en.remove('triage_reasons');"
    "} else {"
    "  en.triage_reasons = params.triage_reasons;"
    "}"
)

_CLUSTER_SAMPLE_SIZE = 5


# ---------------------------------------------------------------------------
# Source-event iteration (cowrie-specific event shape)
# ---------------------------------------------------------------------------

def iter_command_events(
    es: Elasticsearch,
    index: str,
    since: Optional[str],
    page_size: int = 1000,
) -> Iterator[dict]:
    """Yield Cowrie command.input events ordered by @timestamp asc.

    Uses search_after for stable deep pagination.
    """
    must = [{"term": {"event.action": "cowrie.command.input"}}]
    if since:
        must.append({"range": {"@timestamp": {"gt": since}}})

    body = {
        "size": page_size,
        "_source": [
            "@timestamp",
            "process.command_line",
            "cowrie.session_id",
            "source.ip",
        ],
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }

    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h
        search_after = hits[-1]["sort"]


def iter_reference_command_events(
    es: Elasticsearch,
    reference_idx: str,
    page_size: int = 100,
) -> Iterator[dict]:
    """Yield synthetic command "events" from the reference-corpus rollup
    (brutal-review phase 5.3).

    The reference index doesn't carry raw cowrie events — it carries
    rollup-shaped docs with the source command lines under
    ``dshield.reference.command_lines[]``. Fan those out one-per-event
    in the same hit shape that :func:`iter_command_events` produces, so
    the downstream enrich loop doesn't care which path produced its
    input.

    No watermark; the reference corpus is a one-shot import. Subsequent
    invocations rely on the `prism.enriched.cowrie.command` cache to
    skip already-enriched commands.
    """
    body = {
        "size":    page_size,
        "_source": [
            "@timestamp",
            "cowrie.session_id",
            "dshield.reference.command_lines",
        ],
        "query":   {"match_all": {}},
        "sort":    [{"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=reference_idx, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            ts = src.get("@timestamp")
            sid = (src.get("cowrie") or {}).get("session_id")
            ref = (src.get("dshield") or {}).get("reference") or {}
            cmds = ref.get("command_lines") or []
            for cmd in cmds:
                # Mirror the iter_command_events hit shape so
                # `_extract_command` / `_extract_session` / `_extract_ip`
                # all see what they expect. `source.ip` is intentionally
                # absent — reference docs have no real source.
                yield {
                    "_source": {
                        "@timestamp": ts,
                        "process":    {"command_line": cmd},
                        "cowrie":     {"session_id": sid},
                    }
                }
        search_after = hits[-1]["sort"]


# ---------------------------------------------------------------------------
# Normalization + hashing
# ---------------------------------------------------------------------------

def normalize(cmd: str, max_chars: int) -> tuple[str, bool]:
    """Strip + collapse whitespace, truncate. Returns (normalized, was_truncated)."""
    s = _WS_RE.sub(" ", cmd.strip())
    truncated = len(s) > max_chars
    if truncated:
        s = s[:max_chars]
    return s, truncated


def hash_command_full(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def hash_command(normalized: str) -> str:
    """Short hash used as ES _id and event.id."""
    return hash_command_full(normalized)[:16]


def _extract_command(src: dict) -> Optional[str]:
    p = src.get("process") or {}
    cmd = p.get("command_line")
    return cmd if isinstance(cmd, str) and cmd else None


def _extract_session(src: dict) -> Optional[str]:
    c = src.get("cowrie") or {}
    return c.get("session_id")


def _extract_ip(src: dict) -> Optional[str]:
    s = src.get("source") or {}
    return s.get("ip")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_indicators(iocs: dict) -> list[dict]:
    """Convert flat IOC arrays into ECS threat.indicator nested-object array."""
    out: list[dict] = []
    for ip in iocs.get("ips") or []:
        if not ip:
            continue
        kind = "ipv6-addr" if ":" in ip else "ipv4-addr"
        out.append({"type": kind, "ip": ip})
    for d in iocs.get("domains") or []:
        if d:
            out.append({"type": "domain-name", "domain": d})
    for u in iocs.get("urls") or []:
        if u:
            out.append({"type": "url", "url": {"full": u}})
    for f in iocs.get("files") or []:
        if f:
            out.append({"type": "file", "file": {"name": f}})
    for hh in iocs.get("hashes") or []:
        if hh:
            out.append({"type": "file", "file": {"hash": {"sha256": hh}}})
    return out


def _build_ecs_doc(
    *,
    now: str,
    short_hash: str,
    full_hash: str,
    command: str,
    truncated: bool,
    first_seen: Optional[str],
    last_seen: Optional[str],
    occurrence_count: int,
    unique_sessions: int,
    unique_source_ips: int,
    description: str,
    provider: str,
    model: str,
    llm_config_hash: str,
    embed_config_hash: str,
    intent: str,
    confidence: int,
    tactics: list[str],
    techniques: list[str],
    indicators: list[dict],
    embedding: list[float],
    triage_reasons: Optional[list[str]] = None,
    notes: str = "",
    local_fallback: Optional[dict] = None,
    shape: Optional[dict] = None,
    analyst_artifacts: Optional[list[dict]] = None,
) -> dict:
    enrichment_block = {
        "intent": intent,
        "confidence": confidence,
        "model": model,
        "llm_config_hash": llm_config_hash,
        "embed_config_hash": embed_config_hash,
        "occurrence_count": occurrence_count,
        "unique_sessions": unique_sessions,
        "unique_source_ips": unique_source_ips,
        "command_truncated": truncated,
        "embedding": embedding,
    }
    if triage_reasons:
        enrichment_block["triage_reasons"] = triage_reasons
    if notes:
        enrichment_block["notes"] = notes
    if local_fallback:
        enrichment_block["local_fallback"] = local_fallback
    if shape:
        enrichment_block["shape"] = shape
    if analyst_artifacts:
        # Analyst-authored rule matches (ROADMAP #5). Empty list omitted so
        # docs without rule hits stay terse; the field is dynamic-strict
        # nested so re-stamping is additive.
        enrichment_block["analyst_artifacts"] = analyst_artifacts
    return {
        "@timestamp": now,
        "event": {
            "kind": "enrichment",
            "category": ["process"],
            "type": ["info"],
            "module": "cowrie",
            "dataset": "dshield.cowrie.enrichment.command",
            "provider": provider,
            "ingested": now,
            "start": first_seen,
            "end": last_seen,
            "id": short_hash,
            "reason": description,
        },
        "process": {
            "command_line": command,
            "hash": {"sha256": full_hash},
        },
        "observer": {
            "type": "honeypot",
            "vendor": "Cowrie",
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": tactics} if tactics else {},
            "technique": {"id": techniques} if techniques else {},
            "indicator": indicators,
        },
        "dshield": {
            "cowrie": {
                "enrichment": enrichment_block,
            },
        },
    }


def _try_parse(raw: str) -> Optional[CommandEnrichment]:
    try:
        return CommandEnrichment(**json.loads(raw))
    except (json.JSONDecodeError, ValidationError) as e:
        log.debug("LLM JSON parse failed: %s; raw=%r", e, raw[:300])
        return None


_ENRICHMENT_SCHEMA = CommandEnrichment.model_json_schema()


def _fetch_total_session_count(es: Elasticsearch, events_index: str) -> int:
    """Total distinct cowrie.session_id over all command.input events.

    Used as `N` in the TF-IDF salience weight for cooccurring siblings
    (see `score_cooccurring_siblings`). Replaces the old boilerplate-cutoff
    denominator; the change to continuous IDF weighting is ROADMAP #6.
    """
    try:
        resp = es.search(
            index=events_index,
            size=0,
            query={"term": {"event.action": "cowrie.command.input"}},
            aggs={"sessions": {"cardinality": {"field": "cowrie.session_id", "precision_threshold": 40000}}},
        )
        return int(resp["aggregations"]["sessions"]["value"])
    except Exception as e:
        log.warning("could not compute total session count: %s", e)
        return 0


def score_cooccurring_siblings(
    tf_by_sib: dict[str, int],
    df_by_sib: dict[str, int],
    total_sessions: int,
    top_k: int,
) -> list[tuple[str, int]]:
    """Rank candidate siblings by TF-IDF salience; return top-k.

    Pure function — no ES, easy to unit-test. ROADMAP issue #6.

    `tf` = window session count (how many of the anchor's window sessions
    ran the sibling). `df` = corpus session count (how many sessions
    corpus-wide ran the sibling). `N` = total_sessions.

    Salience = tf * ln((N + 1) / (df + 1)). Log-smoothed, parameter-free.
    Corpus-common siblings (high df) get small idf and drop in ranking
    without being categorically rejected; specifically-correlated siblings
    (high tf, low df) rise.

    Falls back to ranking by raw tf when `total_sessions <= 0` or when
    `df_by_sib` is empty — the idf term is undefined in those cases and
    raw-count order is the most we can do.

    Returned tuples carry the *original window tf*, not the score, so
    downstream prompt-display continues to show concrete session counts.
    """
    if not tf_by_sib:
        return []

    use_idf = total_sessions > 0 and bool(df_by_sib)
    log_n = math.log(total_sessions + 1) if use_idf else 0.0

    scored: list[tuple[float, int, str]] = []
    for sib, tf in tf_by_sib.items():
        if use_idf:
            df = df_by_sib.get(sib, 1)
            idf = log_n - math.log(df + 1)
            score = tf * idf
        else:
            score = float(tf)
        scored.append((score, tf, sib))

    scored.sort(key=lambda x: (-x[0], -x[1], x[2]))
    return [(sib, tf) for _, tf, sib in scored[:top_k]]


def fetch_cooccurring_commands(
    es: Elasticsearch,
    events_index: str,
    command: str,
    *,
    session_sample_size: int,
    top_k: int,
    min_sessions: int,
    total_sessions: int,
) -> list[tuple[str, int]]:
    """Return [(sibling_command, window_session_count), ...] ordered by
    TF-IDF salience (most informative siblings first).

    Strategy (see also `score_cooccurring_siblings`):
      1. Find up to `session_sample_size` sessions that ran this command.
      2. In those sessions, aggregate other command_line values, counting
         distinct sessions per sibling (sessions, not raw events — a
         session that runs `wget X` 5 times still counts once).
      3. One corpus-wide query fetches `df` (session cardinality) for all
         candidate siblings at once.
      4. Rank each surviving sibling by `tf * ln((N+1)/(df+1))` — the
         tf-idf weight inside the cooccurrence window — and return top-k.

    Continuous IDF weighting replaces the prior binary
    `max_corpus_session_ratio` boilerplate cutoff: corpus-common siblings
    are *demoted*, not rejected. Net cost is lower than the old code,
    which ran one cardinality query per candidate above the cutoff.
    ROADMAP issue #6.
    """
    if not command:
        return []
    try:
        resp = es.search(
            index=events_index,
            size=0,
            query={"bool": {"must": [
                {"term": {"event.action": "cowrie.command.input"}},
                {"term": {"process.command_line": command}},
            ]}},
            aggs={"sessions": {"terms": {"field": "cowrie.session_id", "size": session_sample_size}}},
        )
        sids = [b["key"] for b in resp["aggregations"]["sessions"]["buckets"] if b.get("key")]
    except Exception as e:
        _note_degraded("cooccurrence_session_lookup",
                       "co-occurrence: session lookup failed for %r: %s", command[:80], e)
        return []

    if len(sids) < min_sessions:
        return []

    # Pull a generous candidate bucket so corpus-common siblings still
    # appear and can be ranked against specific ones — they'll demote
    # themselves via the IDF weight in score_cooccurring_siblings.
    bucket_size = max(top_k * 5, 20)
    try:
        resp2 = es.search(
            index=events_index,
            size=0,
            query={"bool": {"must": [
                {"term": {"event.action": "cowrie.command.input"}},
                {"terms": {"cowrie.session_id": sids}},
            ]}},
            aggs={
                "siblings": {
                    "terms": {"field": "process.command_line", "size": bucket_size},
                    "aggs": {"sessions": {"cardinality": {"field": "cowrie.session_id"}}},
                }
            },
        )
        buckets = resp2["aggregations"]["siblings"]["buckets"]
    except Exception as e:
        _note_degraded("cooccurrence_sibling_agg",
                       "co-occurrence: sibling agg failed for %r: %s", command[:80], e)
        return []

    tf_by_sib: dict[str, int] = {}
    for b in buckets:
        sib = b.get("key") or ""
        if not sib or sib == command:
            continue
        tf = int(b.get("sessions", {}).get("value", 0))
        if tf > 0:
            tf_by_sib[sib] = tf
    if not tf_by_sib:
        return []

    # One corpus-wide query for df (session cardinality) per candidate. When
    # total_sessions is unknown the IDF term is undefined and we fall back
    # to raw-tf ordering inside score_cooccurring_siblings.
    df_by_sib: dict[str, int] = {}
    if total_sessions > 0:
        try:
            resp3 = es.search(
                index=events_index,
                size=0,
                query={"bool": {"must": [
                    {"term": {"event.action": "cowrie.command.input"}},
                    {"terms": {"process.command_line": list(tf_by_sib.keys())}},
                ]}},
                aggs={
                    "by_cmd": {
                        "terms": {"field": "process.command_line", "size": len(tf_by_sib)},
                        "aggs": {"sessions": {"cardinality": {"field": "cowrie.session_id"}}},
                    }
                },
            )
            df_by_sib = {
                b["key"]: int(b["sessions"]["value"])
                for b in resp3["aggregations"]["by_cmd"]["buckets"]
            }
        except Exception as e:
            _note_degraded("cooccurrence_corpus_df",
                           "co-occurrence: corpus df agg failed for %r: %s", command[:80], e)

    return score_cooccurring_siblings(tf_by_sib, df_by_sib, total_sessions, top_k)


def _format_cooccurring_block(siblings: list[tuple[str, int]]) -> str:
    """Render the co-occurrence list for prompt injection.

    Returns "(none)" when empty so the placeholder is never blank — keeps the
    surrounding prompt structure stable for the LLM.
    """
    if not siblings:
        return "(none)"
    lines = [f"  - {cmd}  (sessions: {n})" for cmd, n in siblings]
    return "\n".join(lines)


def _build_embed_text(
    command: str,
    parsed: Optional[CommandEnrichment],
    context_fields: list[str],
    cooccurring: Optional[list[tuple[str, int]]] = None,
    embed_cooccurrence: bool = False,
    order: str = "prelude_first",
) -> str:
    """Build the text string to embed. Prepends enrichment fields when context_fields is set.

    When `embed_cooccurrence` is True and `cooccurring` is non-empty, appends a
    "co-occurs with: cmd1; cmd2; ..." line so the embedding picks up the
    behavioral neighborhood of the command, not just its surface form.

    ``order`` selects the layout (E8.1):
      * ``prelude_first`` — production default; head context first, then
        ``Command: {command}`` on the next line. Maintains backwards
        compatibility with every existing cache row.
      * ``command_first`` — same content as ``prelude_first`` but the
        command line leads, head context follows. Tests whether the
        encoder's attention prioritises the command surface form when
        the prelude dilutes the leading tokens.
      * ``command_only_with_tag`` — drops the head context entirely and
        emits ``[shell] {command}``. Tests the E0.3 "prelude/command
        character ratio 10.6× median, 277× max" hypothesis: if the
        prelude is noise on this corpus, removing it should not hurt
        and may help cluster quality.
    """
    parts: list[str] = []
    if context_fields and parsed is not None:
        if "intent" in context_fields and parsed.intent:
            parts.append(f"intent: {parsed.intent}.")
        if "tactics" in context_fields and parsed.tactics:
            parts.append(f"tactics: {', '.join(parsed.tactics)}.")
        if "techniques" in context_fields and parsed.techniques:
            parts.append(f"techniques: {', '.join(parsed.techniques)}.")
        if "description" in context_fields and parsed.description:
            parts.append(parsed.description)

    cooc_line = ""
    if embed_cooccurrence and cooccurring:
        joined = "; ".join(c for c, _ in cooccurring)
        cooc_line = f"co-occurs with: {joined}."

    if order == "command_only_with_tag":
        # Prelude + cooc both dropped. The "[shell] " tag is a
        # one-token corpus disambiguator so the embedder doesn't
        # mistake a command for general text.
        return f"[shell] {command}"

    if not parts and not cooc_line:
        return command

    head = " ".join(parts)
    if cooc_line:
        head = f"{head} {cooc_line}".strip()

    if order == "command_first":
        return f"Command: {command}\n{head}"

    # Default: prelude_first.
    return f"{head}\nCommand: {command}"


def _build_local_fallback(parsed: Optional[CommandEnrichment], model: str) -> Optional[dict]:
    if parsed is None:
        return {"model": model, "intent": "unknown", "confidence": 1, "description": "",
                "tactics": [], "techniques": []}
    return {
        "model": model,
        "intent": parsed.intent,
        "confidence": parsed.confidence,
        "description": parsed.description,
        "tactics": parsed.tactics,
        "techniques": parsed.techniques,
    }


def cloud_enrich_one(
    cloud_client,
    prompt_template: str,
    command: str,
    triage_reasons: list[str],
    cooccurring_block: str = "(none)",
) -> tuple[Optional[CloudCommandEnrichment], int, int]:
    """Returns (parsed_or_None, input_tokens, output_tokens)."""
    from ...llm.anthropic import parse_cloud_json, _strip_code_fences
    from ...llm.fencing import SYSTEM_PROMPT, fence, make_nonce
    # Fence attacker-controlled regions (the command + co-occurring siblings);
    # the triage-reason tags are a trusted enum, left unfenced.
    nonce = make_nonce()
    prompt = (
        prompt_template
        .replace("<<<COMMAND>>>", fence("command", command, nonce))
        .replace("<<<TRIAGE_REASONS>>>", ", ".join(triage_reasons) if triage_reasons else "(none)")
        .replace("<<<COOCCURRING_COMMANDS>>>",
                 fence("cooccurring_commands", cooccurring_block, nonce))
    )
    try:
        text, in_tok, out_tok = cloud_client.generate_with_usage(prompt, system=SYSTEM_PROMPT)
    except Exception as e:
        log.warning("cloud generate failed: %s", e)
        return None, 0, 0
    parsed = parse_cloud_json(_strip_code_fences(text))
    return parsed, in_tok, out_tok


def lookup_canonical_for_shape(
    es: Elasticsearch,
    commands_index: str,
    shape_hash: str,
    min_confidence: int,
    require_known_intent: bool,
) -> Optional[dict]:
    """Find the best already-enriched canonical doc for a shape signature.

    Returns a compact dict of inheritable fields, or None when no parent
    qualifies. Used by the functional-duplicate gate (ROADMAP #9):
    callers skip the LLM generation step and inherit `intent`,
    `description`, `tactics`, `techniques`, `confidence`, `model`, and
    `notes` from the returned dict.

    Selection rules:
      - `shape.hash` must equal `shape_hash`.
      - `shape.role` must be `canonical` or `standalone` — children
        themselves are never canonical for further inheritance (avoids
        a chain that propagates a regression).
      - `confidence` >= `min_confidence`.
      - When `require_known_intent`, intent must not be `unknown`.

    Tie-break: highest confidence first, then highest occurrence_count
    (most-representative doc wins).
    """
    must_not: list[dict] = []
    if require_known_intent:
        must_not.append({"term": {"dshield.cowrie.enrichment.intent": "unknown"}})
    body = {
        "size": 1,
        "_source": [
            "process.command_line",
            "event.reason",
            "dshield.cowrie.enrichment.intent",
            "dshield.cowrie.enrichment.confidence",
            "dshield.cowrie.enrichment.model",
            "dshield.cowrie.enrichment.notes",
            "dshield.cowrie.enrichment.llm_config_hash",
            "dshield.cowrie.enrichment.embed_config_hash",
            "dshield.cowrie.enrichment.occurrence_count",
            "dshield.cowrie.enrichment.shape",
            "threat.tactic",
            "threat.technique",
        ],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"dshield.cowrie.enrichment.shape.hash": shape_hash}},
                    {"terms": {"dshield.cowrie.enrichment.shape.role": ["canonical", "standalone"]}},
                    {"range": {"dshield.cowrie.enrichment.confidence": {"gte": min_confidence}}},
                ],
                "must_not": must_not,
            }
        },
        "sort": [
            {"dshield.cowrie.enrichment.confidence": "desc"},
            {"dshield.cowrie.enrichment.occurrence_count": "desc"},
        ],
    }
    try:
        resp = es.search(index=commands_index, **body)
    except Exception as exc:
        _note_degraded("shape_canonical_lookup",
                       "shape canonical lookup failed (%s): %s", shape_hash, exc)
        return None
    hits = resp.get("hits", {}).get("hits", [])
    if not hits:
        return None
    h0 = hits[0]
    src = h0["_source"]
    enr = (src.get("dshield") or {}).get("cowrie", {}).get("enrichment") or {}
    threat = src.get("threat") or {}
    tactic = threat.get("tactic") or {}
    technique = threat.get("technique") or {}
    return {
        "_id": h0["_id"],
        "intent": enr.get("intent") or "unknown",
        "confidence": int(enr.get("confidence") or 0),
        "description": (src.get("event") or {}).get("reason") or "",
        "tactics": tactic.get("id") or [],
        "techniques": technique.get("id") or [],
        "model": enr.get("model") or "",
        "notes": enr.get("notes") or "",
        "llm_config_hash": enr.get("llm_config_hash") or "",
        "embed_config_hash": enr.get("embed_config_hash") or "",
    }


def _synth_parsed_from_parent(parent: dict) -> CommandEnrichment:
    """Build a `CommandEnrichment`-shaped object from a canonical parent's
    inheritable fields. The downstream `_build_embed_text` / cluster step
    consume `parsed.intent` / `parsed.description` / etc. — this gives
    the inherit path the same object shape as the LLM path.

    `iocs` is left empty here; the caller fills indicators from the
    child command's own regex extraction so they reflect THIS command's
    literals, not the parent's.
    """
    return CommandEnrichment(
        description=parent.get("description", "") or "",
        intent=parent.get("intent", "unknown") or "unknown",
        tactics=list(parent.get("tactics") or []),
        techniques=list(parent.get("techniques") or []),
        confidence=int(parent.get("confidence") or 1),
    )


def enrich_one(
    llm,
    prompt_template: str,
    command: str,
    max_retries: int,
    cooccurring_block: str = "(none)",
) -> tuple[Optional[CommandEnrichment], str, str]:
    """Returns (enrichment_or_None, source, model).

    Injects a `<<<COMMAND_GROUND_TRUTH>>>` block (ROADMAP #11) listing the
    binaries and the meaning of any flags actually present in the
    command being enriched. Filtered to actually-present flags so the
    LLM sees only what's relevant, not the whole flag vocabulary.
    """
    from ...command_grounding import build_ground_truth_block
    from ...llm.fencing import SYSTEM_PROMPT, fence, make_nonce
    # Fence attacker-controlled regions (the command + co-occurring siblings);
    # leave the curated ground-truth block unfenced (trusted).
    nonce = make_nonce()
    base_prompt = (
        prompt_template
        .replace("<<<COMMAND>>>", fence("command", command, nonce))
        .replace("<<<COOCCURRING_COMMANDS>>>",
                 fence("cooccurring_commands", cooccurring_block, nonce))
        .replace("<<<COMMAND_GROUND_TRUTH>>>", build_ground_truth_block(command))
    )
    prompt = base_prompt
    last_raw = ""
    for attempt in range(max_retries + 1):
        try:
            raw = llm.generate_json(
                prompt,
                schema=_ENRICHMENT_SCHEMA,
                schema_name="command_enrichment",
                system=SYSTEM_PROMPT,
            )
        except Exception as e:
            _note_degraded("llm_generate_retry",
                           "llm generate failed (attempt %d): %s", attempt, e)
            continue
        last_raw = raw
        parsed = _try_parse(raw)
        if parsed is not None:
            return parsed, "local", llm.gen_model
        prompt = (
            base_prompt
            + "\n\nYour previous response was invalid JSON. It was:\n"
            + raw[:500]
            + "\nReturn ONLY valid JSON."
        )
    _note_degraded("local_enrich_failed",
                   "local enrichment failed after retries; last_raw=%r", last_raw[:200])
    return None, "local_failed", llm.gen_model


# ---------------------------------------------------------------------------
# Enrich entry point
# ---------------------------------------------------------------------------

def run_enrich(
    cfg: AppConfig, secrets: Secrets, dry_run: bool = False, no_cloud: bool = False,
    *, reference_mode: bool = False, budget: Optional[int] = None,
) -> dict:
    """Main worker entry. Returns stats dict.

    When ``reference_mode=True`` (brutal-review phase 5.3), the input
    source switches from `prism.raw.cowrie.session` to the rollup-shaped
    reference index `prism.reference.cowrie.session`. Watermark + corpus
    cooccurrence are disabled (reference is a one-shot import with no
    session temporality). ``budget`` caps the number of cache-miss LLM
    calls per invocation — useful for incremental enrichment runs that
    want bounded cost.
    """
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    prompt = load_prompt(cfg, "command_enrichment")
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    events_idx = (
        cfg.elasticsearch.indexes.cowrie.reference_sessions
        if reference_mode
        else cfg.elasticsearch.indexes.cowrie.sessions_raw
    )

    # Analyst-authored artifact rules (ROADMAP #5). Loaded once per run;
    # cleanly empty when the subsystem is disabled or no rules exist.
    from ...analyst.artifact_rules import apply_rules as _apply_rules
    from ...analyst.artifact_rules import load_active_rules as _load_rules
    analyst_rules = _load_rules(es, cfg)
    analyst_cap = cfg.analyst.max_match_per_doc

    # Auto-invalidating cache key components. Empty strings when the
    # toggle is off — the cache then behaves like the pre-#7 key for
    # this run. ROADMAP issue #7.
    if cfg.worker.cache_auto_invalidate:
        llm_config_hash = compute_llm_config_hash(cfg)
        embed_config_hash = compute_embed_config_hash(cfg)
        legacy = db.legacy_cache_row_count()
        if legacy > 0:
            log.info(
                "cache: %d row(s) missing one or both auto-derived hashes "
                "will be treated as miss and re-enriched. Run "
                "`dshield_prism bless-cache` to stamp them with current "
                "hashes instead if they're known good.",
                legacy,
            )
    else:
        llm_config_hash = ""
        embed_config_hash = ""

    cloud_enabled = bool(cfg.cloud.enabled and not no_cloud and secrets.anthropic_api_key)
    cloud_prompt: Optional[str] = None
    cloud_client = None
    if cloud_enabled:
        if cfg.prompts.command_deep_dive is None:
            log.warning("cloud enabled but prompts.command_deep_dive is unset; skipping cloud")
            cloud_enabled = False
        else:
            cloud_prompt = load_prompt(cfg, "command_deep_dive")
            from ...llm.anthropic import AnthropicClient
            cloud_client = AnthropicClient(
                api_key=secrets.anthropic_api_key,
                model=cfg.cloud.model,
                max_tokens=cfg.cloud.max_tokens,
                timeout=cfg.cloud.request_timeout,
                base_url=cfg.cloud.base_url,
            )
            try:
                cloud_client.ping()
                log.info("cloud escalation enabled: model=%s daily_budget=$%.2f remaining=$%.2f",
                         cfg.cloud.model, cfg.cloud.daily_budget_usd,
                         triage_mod.budget_remaining_usd(db, cfg.cloud))
            except Exception as e:
                log.warning("cloud preflight failed (%s); continuing local-only", e)
                try:
                    cloud_client.close()
                except Exception:
                    pass
                cloud_client = None
                cloud_enabled = False

    # M3.A: intel-aware escalation gate. Single lookup helper for the
    # whole run — repeated commands sharing the same source IPs hit
    # the in-memory cache rather than ES. Disabled when cloud is off
    # (nothing to gate) or when the operator opted out via
    # cfg.cloud.triage.intel_aware=False.
    intel_lookup = None
    if cloud_enabled and cfg.cloud.triage.intel_aware:
        from ...intel.lookup import IntelLookup
        intel_lookup = IntelLookup(es, cfg)
        log.info("intel-aware triage gate enabled (cfg.cloud.triage.intel_aware=true)")

    cooc_cfg = cfg.cooccurrence
    # Reference mode forces co-occurrence off — the reference corpus has
    # no temporal session structure (atomic tests are independent), and
    # sampling siblings from an unrelated index would just inject noise
    # into the embed text.
    if reference_mode and cooc_cfg.enabled:
        log.info("reference mode: co-occurrence disabled for this run")
        cooc_cfg = cooc_cfg.model_copy(update={
            "enabled":            False,
            "embed_cooccurrence": False,
        })
    total_sessions = (
        _fetch_total_session_count(es, events_idx) if cooc_cfg.enabled else 0
    )
    if cooc_cfg.enabled:
        log.info(
            "co-occurrence enabled: top_k=%d sample=%d sessions, "
            "tf-idf weighted against %d total corpus sessions",
            cooc_cfg.top_k, cooc_cfg.session_sample_size, total_sessions,
        )

    # Reference mode skips the watermark entirely — every invocation
    # walks the full reference index, and the per-command cache prevents
    # re-LLM on already-enriched commands.
    if reference_mode:
        since = None
        log.info("reference mode: full reference-index scan; no watermark")
    else:
        since = db.get_watermark()
        if since is None and cfg.worker.initial_lookback_days is not None:
            from datetime import timedelta
            since_dt = datetime.now(timezone.utc) - timedelta(days=cfg.worker.initial_lookback_days)
            since = since_dt.isoformat()
        log.info("Watermark: %s", since or "(none, full backfill)")

    stats = defaultdict(int)
    groups: dict[str, dict] = {}
    last_ts = since

    # Reset the MITRE-validation drop counter so the value reported at the end
    # of this run reflects only this run's hallucinations.
    from enrich.llm.schemas import reset_mitre_drop_counts
    reset_mitre_drop_counts()

    event_iter = (
        iter_reference_command_events(es, events_idx, cfg.worker.page_size)
        if reference_mode
        else iter_command_events(es, events_idx, since, cfg.worker.page_size)
    )
    for hit in event_iter:
        stats["events_seen"] += 1
        src = hit["_source"]
        ts = src.get("@timestamp")
        if ts:
            last_ts = ts

        cmd = _extract_command(src)
        if not cmd:
            stats["events_no_command"] += 1
            continue

        norm, truncated = normalize(cmd, cfg.worker.command_max_chars)
        if not norm:
            continue
        h = hash_command(norm)

        g = groups.get(h)
        if g is None:
            g = {
                "command": norm,
                "truncated": truncated,
                "sessions": set(),
                "ips": set(),
                "first_seen": ts,
                "last_seen": ts,
                "count": 0,
            }
            groups[h] = g
        g["count"] += 1
        sid = _extract_session(src)
        if sid:
            g["sessions"].add(sid)
        ip = _extract_ip(src)
        if ip:
            g["ips"].add(ip)
        if ts:
            if not g["first_seen"] or ts < g["first_seen"]:
                g["first_seen"] = ts
            if not g["last_seen"] or ts > g["last_seen"]:
                g["last_seen"] = ts

    log.info("Collected %d events into %d unique commands", stats["events_seen"], len(groups))

    if dry_run:
        log.info("dry-run: skipping LLM + writes")
        return dict(stats, unique_commands=len(groups))

    # Functional-duplicate gating (ROADMAP #9): compute a shape signature
    # for each unique command. Same shape_hash → candidate to inherit
    # enrichment from a canonical sibling instead of running the LLM.
    dedup_cfg = cfg.command_shape_dedup
    for h, g in groups.items():
        g["shape_hash"] = compute_shape_hash(g["command"]) if dedup_cfg.enabled else ""

    # Iterate so that for each shape_hash bucket, the highest-count
    # group is processed first. When two new commands share a shape and
    # neither has an ES canonical yet, the most-representative one runs
    # the LLM and becomes the in-batch canonical; the rest inherit.
    def _iter_order():
        # Two passes: groups with no shape signature (degenerate parse,
        # or dedup disabled) keep insertion order. Groups with a shape
        # are bucketed and emitted in (shape_hash, -count) order so the
        # canonical candidate comes first within each shape.
        no_shape = [h for h, g in groups.items() if not g.get("shape_hash")]
        with_shape: dict[str, list[str]] = defaultdict(list)
        for h, g in groups.items():
            sh = g.get("shape_hash")
            if sh:
                with_shape[sh].append(h)
        for sh in with_shape:
            with_shape[sh].sort(key=lambda h: -groups[h]["count"])
        for h in no_shape:
            yield h
        for sh, members in with_shape.items():
            for h in members:
                yield h

    # Cached canonical info for shapes seen in this run. Populated either
    # by an ES lookup (cross-corpus parent) or by a just-built in-batch
    # canonical doc. Subsequent same-shape members consult this map
    # instead of re-querying ES (and to find in-batch parents that
    # haven't been refreshed into ES yet).
    shape_canonical_cache: dict[str, dict] = {}

    actions: list[dict] = []

    with make_llm_client(cfg.llm) as llm:
        for h in _iter_order():
            g = groups[h]
            cached = db.is_cached(
                h, cfg.llm.generation_model, llm_config_hash, embed_config_hash,
            )
            if cached:
                stats["cache_hits"] += 1
                actions.append({
                    "_op_type": "update",
                    "_id": h,
                    "script": {
                        "source": (
                            "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
                            "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
                            "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
                            "def en = ctx._source.dshield.cowrie.enrichment;"
                            "en.occurrence_count = (en.occurrence_count ?: 0) + params.add_count;"
                            "if (ctx._source.event == null) { ctx._source.event = [:]; }"
                            "if (ctx._source.event.end == null || params.last_seen.compareTo(ctx._source.event.end) > 0) { ctx._source.event.end = params.last_seen; }"
                            "if (ctx._source.event.start == null || params.first_seen.compareTo(ctx._source.event.start) < 0) { ctx._source.event.start = params.first_seen; }"
                        ),
                        "params": {
                            "add_count": g["count"],
                            "last_seen": g["last_seen"],
                            "first_seen": g["first_seen"],
                        },
                    },
                })
                continue

            stats["cache_miss"] += 1

            # Budget cap (brutal-review phase 5.3) — when set, stop
            # spending LLM cycles after `budget` cache-misses this run.
            # Subsequent cache-miss commands are deferred to a future
            # invocation; the cache means they'll pick up where this
            # run left off.
            if budget is not None and stats["cache_miss"] > budget:
                stats["budget_skipped"] += 1
                continue

            # ---- Functional-duplicate gate (ROADMAP #9) -------------------
            #
            # If this command's shape signature matches an already-enriched
            # canonical (either from ES corpus or from a just-built
            # in-batch parent), skip the LLM generation entirely and
            # inherit intent / description / tactics / techniques. The
            # per-command-unique parts (regex IOCs, embedding) still run.
            sh = g.get("shape_hash") or ""
            inherit_parent: Optional[dict] = None
            if sh and dedup_cfg.enabled:
                inherit_parent = shape_canonical_cache.get(sh)
                if inherit_parent is None:
                    inherit_parent = lookup_canonical_for_shape(
                        es, commands_idx, sh,
                        min_confidence=dedup_cfg.min_parent_confidence,
                        require_known_intent=dedup_cfg.require_known_intent,
                    )
                    if inherit_parent is not None:
                        shape_canonical_cache[sh] = inherit_parent

            if inherit_parent is not None:
                now = _now()
                full_hash = hash_command_full(g["command"])
                # Cooccurrence siblings still inform the embed text, so
                # children sitting in different behavioral neighborhoods
                # get distinguishable vectors. Skip when cooc disabled
                # to match the standalone path.
                cooccurring = []
                if cooc_cfg.enabled:
                    cooccurring = fetch_cooccurring_commands(
                        es, events_idx, g["command"],
                        session_sample_size=cooc_cfg.session_sample_size,
                        top_k=cooc_cfg.top_k,
                        min_sessions=cooc_cfg.min_sessions,
                        total_sessions=total_sessions,
                    )

                parent_parsed = _synth_parsed_from_parent(inherit_parent)
                embed_text = _build_embed_text(
                    g["command"], parent_parsed, cfg.llm.embed_context,
                    cooccurring=cooccurring,
                    embed_cooccurrence=cooc_cfg.enabled and cooc_cfg.embed_cooccurrence,
                    order=cfg.llm.embed_input_order,
                )
                try:
                    embedding = llm.embed(embed_text)
                except Exception as e:
                    log.error("inherit-path embed failed for %s: %s", h, e)
                    stats["embed_failed"] += 1
                    continue

                # Inherit structural fields, but pull IOCs from THIS
                # command's literals via the regex extractor.
                indicators = _build_indicators(extract_iocs_regex(g["command"]))
                analyst_artifacts = _apply_rules(g["command"], analyst_rules, cap=analyst_cap)

                shape_block = {
                    "hash": sh,
                    "role": "child",
                    "functional_parent": inherit_parent["_id"],
                    "linked_at": now,
                    "inherited_from_model": inherit_parent.get("model", ""),
                    "confidence_at_link": int(inherit_parent.get("confidence", 0)),
                }
                doc = _build_ecs_doc(
                    now=now,
                    short_hash=h,
                    full_hash=full_hash,
                    command=g["command"],
                    truncated=g["truncated"],
                    first_seen=g["first_seen"],
                    last_seen=g["last_seen"],
                    occurrence_count=g["count"],
                    unique_sessions=len(g["sessions"]),
                    unique_source_ips=len(g["ips"]),
                    description=parent_parsed.description,
                    provider="local_inherited",
                    model=inherit_parent.get("model", ""),
                    llm_config_hash=inherit_parent.get("llm_config_hash") or "",
                    embed_config_hash=embed_config_hash,
                    intent=parent_parsed.intent,
                    confidence=parent_parsed.confidence,
                    tactics=parent_parsed.tactics,
                    techniques=parent_parsed.techniques,
                    indicators=indicators,
                    embedding=embedding,
                    shape=shape_block,
                    analyst_artifacts=analyst_artifacts,
                )
                actions.append({"_op_type": "index", "_id": h, "_source": doc})
                # Stamp the child cache row with the parent's llm hash so
                # re-enrich-stale skips the child when the parent is still
                # fresh and revisits it when the parent drifts. The embed
                # hash is current — we just embedded.
                db.mark_cached(
                    h, cfg.llm.generation_model,
                    inherit_parent.get("llm_config_hash") or "",
                    embed_config_hash, now,
                )
                stats["functional_duplicates_linked"] += 1
                stats["generation_calls_saved"] += 1

                if len(actions) >= 50:
                    ok, errs = bulk_write(es, commands_idx, actions)
                    stats["bulk_ok"] += ok
                    stats["bulk_errors"] += len(errs)
                    if errs:
                        log.warning("bulk errors (%d): %s", len(errs), errs[:2])
                    actions = []
                continue

            # ---- Standalone / canonical path (full LLM call) --------------
            cooccurring: list[tuple[str, int]] = []
            if cooc_cfg.enabled:
                cooccurring = fetch_cooccurring_commands(
                    es, events_idx, g["command"],
                    session_sample_size=cooc_cfg.session_sample_size,
                    top_k=cooc_cfg.top_k,
                    min_sessions=cooc_cfg.min_sessions,
                    total_sessions=total_sessions,
                )
                if cooccurring:
                    stats["cooccurrence_hits"] += 1
                else:
                    stats["cooccurrence_empty"] += 1
            cooc_block = _format_cooccurring_block(cooccurring)

            parsed, source, model = enrich_one(
                llm, prompt, g["command"], cfg.llm.max_retries,
                cooccurring_block=cooc_block,
            )
            now = _now()
            full_hash = hash_command_full(g["command"])
            if parsed is not None:
                description = parsed.description
                intent = parsed.intent
                confidence = parsed.confidence
                tactics = parsed.tactics
                techniques = parsed.techniques
                indicators = _build_indicators(parsed.iocs.model_dump())
                stats["enriched_ok"] += 1
            else:
                description = ""
                intent = "unknown"
                confidence = 1
                tactics, techniques = [], []
                indicators = []
                stats["enriched_failed"] += 1

            triage_reasons: list[str] = []
            notes = ""
            local_fallback_doc: Optional[dict] = None
            doc_provider = source
            doc_model = model
            final_parsed = parsed

            if cloud_enabled:
                triage_reasons = triage_mod.reasons_to_escalate(
                    command=g["command"],
                    parsed=parsed,
                    local_failed=(source == "local_failed"),
                    cfg=cfg.cloud,
                    embedding=None,
                    centroids=None,
                )
                if triage_reasons:
                    stats["triaged"] += 1
                    # M3.A: intel-aware skip gate. If the operator
                    # opted in and every source IP for this command
                    # is either authoritative-clean or strong-commodity
                    # consensus, suppress the cloud call. The skip
                    # reason is appended to triage_reasons so the doc
                    # records why we didn't escalate.
                    intel_skip: Optional[str] = None
                    if intel_lookup is not None:
                        ip_summaries_map = intel_lookup.get_many("ip", list(g["ips"]))
                        ip_summaries = [
                            s for s in ip_summaries_map.values() if s is not None
                        ]
                        # Only gate when EVERY source IP has intel data;
                        # one unknown IP among knowns is a signal the
                        # gate must not suppress.
                        if (
                            ip_summaries
                            and len(ip_summaries) == len(g["ips"])
                        ):
                            intel_skip = triage_mod.intel_skip_reason(
                                triage_reasons=triage_reasons,
                                ip_summaries=ip_summaries,
                                cfg=cfg.cloud,
                            )
                    if intel_skip is not None:
                        stats["cloud_skipped_intel"] += 1
                        triage_reasons.append(intel_skip)
                    elif not triage_mod.can_spend(db, cfg.cloud):
                        stats["cloud_skipped_budget"] += 1
                        triage_reasons.append("budget_exhausted")
                    else:
                        cloud_parsed, in_tok, out_tok = cloud_enrich_one(
                            cloud_client, cloud_prompt, g["command"], triage_reasons,
                            cooccurring_block=cooc_block,
                        )
                        from ...llm.anthropic import cost_usd as _cost_usd
                        spend = _cost_usd(
                            in_tok, out_tok,
                            cfg.cloud.pricing.input_per_mtok,
                            cfg.cloud.pricing.output_per_mtok,
                        )
                        if in_tok or out_tok:
                            db.add_spend(triage_mod.utc_today(), in_tok, out_tok, spend)
                            stats["cloud_calls"] += 1
                            stats["cloud_input_tokens"] += in_tok
                            stats["cloud_output_tokens"] += out_tok
                            stats["cloud_cost_usd_x10000"] += int(round(spend * 10000))
                        if cloud_parsed is not None:
                            local_fallback_doc = _build_local_fallback(parsed, model)
                            description = cloud_parsed.description
                            intent = cloud_parsed.intent
                            confidence = cloud_parsed.confidence
                            tactics = cloud_parsed.tactics
                            techniques = cloud_parsed.techniques
                            indicators = _build_indicators(cloud_parsed.iocs.model_dump())
                            notes = cloud_parsed.notes
                            doc_provider = "claude"
                            doc_model = cfg.cloud.model
                            final_parsed = cloud_parsed
                            stats["cloud_enriched_ok"] += 1
                        else:
                            stats["cloud_enriched_failed"] += 1
                            triage_reasons.append("cloud_parse_failed")

            embed_text = _build_embed_text(
                g["command"], final_parsed, cfg.llm.embed_context,
                cooccurring=cooccurring,
                embed_cooccurrence=cooc_cfg.enabled and cooc_cfg.embed_cooccurrence,
                order=cfg.llm.embed_input_order,
            )
            try:
                embedding = llm.embed(embed_text)
            except Exception as e:
                log.error("embed failed for %s: %s", h, e)
                stats["embed_failed"] += 1
                continue

            # Shape role: canonical if the shape signature is non-empty
            # and we produced a usable parsed enrichment; standalone if
            # parse failed or the shape signature is degenerate (so it
            # never canonicalizes for anyone). Children would have taken
            # the inherit branch above and never reach this point.
            if sh and parsed is not None and parsed.intent != "unknown":
                shape_role = "canonical"
            else:
                shape_role = "standalone"
            shape_block_canon: Optional[dict] = None
            if sh:
                shape_block_canon = {
                    "hash": sh,
                    "role": shape_role,
                    "functional_parent": None,
                    "linked_at": now,
                    "inherited_from_model": "",
                    "confidence_at_link": int(confidence),
                }

            analyst_artifacts = _apply_rules(g["command"], analyst_rules, cap=analyst_cap)
            doc = _build_ecs_doc(
                now=now,
                short_hash=h,
                full_hash=full_hash,
                command=g["command"],
                truncated=g["truncated"],
                first_seen=g["first_seen"],
                last_seen=g["last_seen"],
                occurrence_count=g["count"],
                unique_sessions=len(g["sessions"]),
                unique_source_ips=len(g["ips"]),
                description=description,
                provider=doc_provider,
                model=doc_model,
                llm_config_hash=llm_config_hash,
                embed_config_hash=embed_config_hash,
                intent=intent,
                confidence=confidence,
                tactics=tactics,
                techniques=techniques,
                indicators=indicators,
                embedding=embedding,
                triage_reasons=triage_reasons,
                notes=notes,
                local_fallback=local_fallback_doc,
                shape=shape_block_canon,
                analyst_artifacts=analyst_artifacts,
            )
            actions.append({"_op_type": "index", "_id": h, "_source": doc})
            if doc_provider in ("local", "claude"):
                db.mark_cached(
                    h, cfg.llm.generation_model,
                    llm_config_hash, embed_config_hash, now,
                )

            # Register this just-built canonical in the per-run cache so
            # subsequent same-shape members in this batch inherit from
            # it without waiting for an ES refresh.
            if (
                shape_role == "canonical"
                and parsed is not None
                and confidence >= dedup_cfg.min_parent_confidence
            ):
                shape_canonical_cache[sh] = {
                    "_id": h,
                    "intent": intent,
                    "confidence": int(confidence),
                    "description": description,
                    "tactics": list(tactics or []),
                    "techniques": list(techniques or []),
                    "model": doc_model,
                    "notes": notes,
                    "llm_config_hash": llm_config_hash,
                    "embed_config_hash": embed_config_hash,
                }
                stats["functional_canonicals_promoted"] += 1

            if len(actions) >= 50:
                ok, errs = bulk_write(es, commands_idx, actions)
                stats["bulk_ok"] += ok
                stats["bulk_errors"] += len(errs)
                if errs:
                    log.warning("bulk errors (%d): %s", len(errs), errs[:2])
                actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("bulk errors (%d): %s", len(errs), errs[:2])

    # Refresh so the next pipeline step (`rollup sessions`, then `cluster
    # commands`) sees every enriched command. The mapping uses default 1s
    # refresh but the index can lag under load; explicit refresh removes the
    # race entirely.
    try:
        es.indices.refresh(index=commands_idx)
    except Exception as exc:
        log.warning("enrich refresh failed (continuing): %s", exc)

    if not reference_mode and last_ts and last_ts != since:
        db.set_watermark(last_ts)
        log.info("Watermark advanced to %s", last_ts)

    if cloud_client is not None:
        cloud_client.close()

    out = dict(stats, unique_commands=len(groups))
    if "cloud_cost_usd_x10000" in out:
        out["cloud_cost_usd"] = out.pop("cloud_cost_usd_x10000") / 10000.0
    # Surface MITRE ID hallucination rate from this run.
    from enrich.llm.schemas import mitre_drop_counts
    mitre_drops = mitre_drop_counts()
    if mitre_drops["tactics"] or mitre_drops["techniques"]:
        log.info(
            "MITRE ATT&CK invalid IDs dropped this run: tactics=%d techniques=%d",
            mitre_drops["tactics"], mitre_drops["techniques"],
        )
    out["mitre_invalid_tactics"] = mitre_drops["tactics"]
    out["mitre_invalid_techniques"] = mitre_drops["techniques"]
    # P4.1 — surface the per-item degradation counts once (the per-item warnings
    # were capped to one-per-run + debug above), so a degraded ES is visible at
    # its true scale without flooding the journal.
    degraded = flush_degraded_fallbacks()
    if degraded:
        log.warning(
            "degraded per-item fallbacks this run: %s",
            ", ".join(f"{k}={v}" for k, v in sorted(degraded.items())),
        )
        out["degraded_fallbacks"] = degraded
    db.close()
    return out


# ---------------------------------------------------------------------------
# Escalate
# ---------------------------------------------------------------------------

def iter_novel_local_docs(
    es: Elasticsearch,
    index: str,
    novelty_threshold: float,
    confidence_max: int,
    confidence_min: int,
    page_size: int = 50,
) -> Iterator[dict]:
    """Yield enrichment docs with event.provider='local', novelty_score >= novelty_threshold,
    and confidence in [confidence_min, confidence_max]. Sorted novelty_score desc.

    The lower bound on confidence is the novelty-noise floor — see
    ROADMAP issue #3. Local-LLM confidence below this is almost always an
    encoding artifact whose novelty score is meaningless; gating those out
    here stops them from burning cloud budget.
    """
    body: dict = {
        "size": page_size,
        "_source": [
            "process.command_line",
            "event.reason",
            "dshield.cowrie.enrichment.intent",
            "dshield.cowrie.enrichment.confidence",
            "dshield.cowrie.enrichment.model",
            "threat.tactic.id",
            "threat.technique.id",
        ],
        "query": {
            "bool": {
                "must": [
                    {"term": {"event.provider": "local"}},
                    {"range": {
                        "dshield.cowrie.enrichment.cluster.novelty_score": {"gte": novelty_threshold}
                    }},
                    {"range": {
                        "dshield.cowrie.enrichment.confidence": {
                            "gte": confidence_min,
                            "lte": confidence_max,
                        }
                    }},
                ]
            }
        },
        "sort": [
            {"dshield.cowrie.enrichment.cluster.novelty_score": "desc"},
            {"_doc": "asc"},
        ],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h
        search_after = hits[-1]["sort"]


def run_escalate(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
) -> dict:
    """Cloud-escalate locally-enriched docs whose novelty_score >= threshold."""
    if not cfg.cloud.enabled:
        raise RuntimeError(
            "cloud.enabled is false. Set it in config/local.yaml to use escalate."
        )
    if not secrets.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set in .env.")
    if not cfg.prompts.command_deep_dive:
        raise RuntimeError("prompts.command_deep_dive is unset in config.")

    threshold = cfg.cloud.triage.novel_embedding_threshold
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    cloud_prompt = load_prompt(cfg, "command_deep_dive")
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    # Analyst rules — re-applied here so a cloud-escalated doc carries the
    # same `analyst_artifacts` block the local pass would have written.
    from ...analyst.artifact_rules import apply_rules as _apply_rules
    from ...analyst.artifact_rules import load_active_rules as _load_rules
    analyst_rules = _load_rules(es, cfg)
    analyst_cap = cfg.analyst.max_match_per_doc

    cooc_cfg = cfg.cooccurrence
    total_sessions = (
        _fetch_total_session_count(es, events_idx) if cooc_cfg.enabled else 0
    )

    from ...llm.anthropic import AnthropicClient, cost_usd as _cost_usd
    cloud_client = AnthropicClient(
        api_key=secrets.anthropic_api_key,
        model=cfg.cloud.model,
        max_tokens=cfg.cloud.max_tokens,
        timeout=cfg.cloud.request_timeout,
        base_url=cfg.cloud.base_url,
    )
    try:
        cloud_client.ping()
    except Exception as exc:
        cloud_client.close()
        db.close()
        raise RuntimeError(f"Cloud preflight failed: {exc}") from exc

    confidence_max = cfg.cloud.triage.escalate_confidence_max
    confidence_min = cfg.cloud.triage.novel_confidence_min
    log.info(
        "escalate: novelty_threshold=%.2f confidence=[%d,%d] model=%s budget_remaining=$%.4f",
        threshold, confidence_min, confidence_max, cfg.cloud.model,
        triage_mod.budget_remaining_usd(db, cfg.cloud),
    )

    stats: dict = defaultdict(int)
    actions: list[dict] = []

    for hit in iter_novel_local_docs(
        es, commands_idx, threshold, confidence_max, confidence_min,
    ):
        stats["candidates"] += 1

        if not dry_run and not triage_mod.can_spend(db, cfg.cloud):
            stats["skipped_budget"] += 1
            log.warning("Budget exhausted; stopping escalate run")
            break

        if dry_run:
            continue

        src = hit["_source"]
        doc_id = hit["_id"]
        command = (src.get("process") or {}).get("command_line", "")
        if not command:
            stats["skipped_no_command"] += 1
            continue

        en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
        local_fallback = {
            "model": en.get("model", ""),
            "intent": en.get("intent", "unknown"),
            "confidence": en.get("confidence", 1),
            "description": (src.get("event") or {}).get("reason", ""),
            "tactics": ((src.get("threat") or {}).get("tactic") or {}).get("id") or [],
            "techniques": ((src.get("threat") or {}).get("technique") or {}).get("id") or [],
        }

        triage_reasons = ["novel_embedding"]
        cooccurring: list[tuple[str, int]] = []
        if cooc_cfg.enabled:
            cooccurring = fetch_cooccurring_commands(
                es, events_idx, command,
                session_sample_size=cooc_cfg.session_sample_size,
                top_k=cooc_cfg.top_k,
                min_sessions=cooc_cfg.min_sessions,
                total_sessions=total_sessions,
            )
        cloud_parsed, in_tok, out_tok = cloud_enrich_one(
            cloud_client, cloud_prompt, command, triage_reasons,
            cooccurring_block=_format_cooccurring_block(cooccurring),
        )
        spend = _cost_usd(
            in_tok, out_tok,
            cfg.cloud.pricing.input_per_mtok,
            cfg.cloud.pricing.output_per_mtok,
        )
        if in_tok or out_tok:
            db.add_spend(triage_mod.utc_today(), in_tok, out_tok, spend)
            stats["cloud_calls"] += 1
            stats["cloud_input_tokens"] += in_tok
            stats["cloud_output_tokens"] += out_tok
            stats["cloud_cost_usd_x10000"] += int(round(spend * 10000))

        if cloud_parsed is None:
            stats["cloud_failed"] += 1
            log.warning("cloud parse failed for doc %s", doc_id)
            continue

        stats["cloud_ok"] += 1
        analyst_artifacts = _apply_rules(command, analyst_rules, cap=analyst_cap)
        actions.append({
            "_op_type": "update",
            "_id": doc_id,
            "script": {
                "source": _ESCALATE_SCRIPT,
                "params": {
                    "provider": "claude",
                    "description": cloud_parsed.description,
                    "intent": cloud_parsed.intent,
                    "confidence": cloud_parsed.confidence,
                    "model": cfg.cloud.model,
                    "triage_reasons": triage_reasons,
                    "notes": cloud_parsed.notes,
                    "local_fallback": local_fallback,
                    "tactics": cloud_parsed.tactics,
                    "techniques": cloud_parsed.techniques,
                    "indicators": _build_indicators(cloud_parsed.iocs.model_dump()),
                    "analyst_artifacts": analyst_artifacts,
                },
            },
        })

        if len(actions) >= 20:
            ok, errs = bulk_write(es, commands_idx, actions)
            stats["bulk_ok"] += ok
            stats["bulk_errors"] += len(errs)
            if errs:
                log.warning("escalate bulk errors (%d): %s", len(errs), errs[:2])
            actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("escalate bulk errors (%d): %s", len(errs), errs[:2])

    # Refresh so downstream `cluster sessions` / `rollup ips` see the
    # cloud-rewritten enrichment immediately.
    try:
        es.indices.refresh(index=commands_idx)
    except Exception as exc:
        log.warning("escalate refresh failed (continuing): %s", exc)

    cloud_client.close()
    db.close()

    out = dict(
        stats, dry_run=dry_run,
        novelty_threshold=threshold,
        confidence_min=confidence_min,
        confidence_max=confidence_max,
    )
    if "cloud_cost_usd_x10000" in out:
        out["cloud_cost_usd"] = out.pop("cloud_cost_usd_x10000") / 10000.0
    return out


# ---------------------------------------------------------------------------
# Re-embed
# ---------------------------------------------------------------------------

def iter_docs_for_reembed(
    es: Elasticsearch,
    index: str,
    page_size: int = 200,
) -> Iterator[dict]:
    """Yield dicts with the enrichment fields needed to rebuild an embedding."""
    body: dict = {
        "size": page_size,
        "_source": [
            "process.command_line",
            "event.reason",
            "dshield.cowrie.enrichment.intent",
            "threat.tactic.id",
            "threat.technique.id",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
            yield {
                "doc_id": h["_id"],
                "command": (src.get("process") or {}).get("command_line", ""),
                "intent": en.get("intent", ""),
                "tactics": ((src.get("threat") or {}).get("tactic") or {}).get("id") or [],
                "techniques": ((src.get("threat") or {}).get("technique") or {}).get("id") or [],
                "description": (src.get("event") or {}).get("reason", ""),
            }
        search_after = hits[-1]["sort"]


def run_reembed(cfg: AppConfig, secrets: Secrets, dry_run: bool = False) -> dict:
    """Re-embed all enrichment docs using stored fields — no LLM generation calls."""
    from types import SimpleNamespace

    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    # Reembed touches only the embed side. We stamp `embed_config_hash`
    # on each cache row (via mark_embed_cached) but leave
    # `llm_config_hash` untouched — that way, if the LLM prompt has also
    # changed and the user runs reembed first, the next enrich still
    # sees a stale llm_config_hash and correctly re-runs the LLM.
    # ROADMAP issue #7.
    embed_config_hash = compute_embed_config_hash(cfg) if cfg.worker.cache_auto_invalidate else ""

    cooc_cfg = cfg.cooccurrence
    use_cooc = cooc_cfg.enabled and cooc_cfg.embed_cooccurrence
    total_sessions = (
        _fetch_total_session_count(es, events_idx) if use_cooc else 0
    )

    # Skip-if-fresh: pull every cache row's stored embed_config_hash up
    # front. If a doc's cached hash already matches the live hash, the
    # embedding is current under this config — no need to redo it.
    # Honors `cache_auto_invalidate`: when off, treat all docs as "needs
    # work" (the embed_config_hash variable is "" so nothing will match
    # anyway, but be explicit).
    cached_embed_hashes: dict[str, str] = (
        db.get_cached_embed_hashes() if cfg.worker.cache_auto_invalidate else {}
    )

    log.info(
        "re-embed: embed_context=%s embed_config_hash=%s embed_cooccurrence=%s index=%s dry_run=%s",
        cfg.llm.embed_context, embed_config_hash, use_cooc, commands_idx, dry_run,
    )

    stats: dict = defaultdict(int)
    actions: list[dict] = []
    now = _now()

    with make_llm_client(cfg.llm) as llm:
        for doc in iter_docs_for_reembed(es, commands_idx):
            stats["docs_seen"] += 1
            if not doc["command"]:
                stats["skipped_no_command"] += 1
                continue

            # Skip-if-fresh: cached embed hash matches live → no work to do.
            # Only honored when auto-invalidate is on (otherwise the user
            # asked to bypass the hash check, run unconditionally).
            if (
                cfg.worker.cache_auto_invalidate
                and embed_config_hash
                and cached_embed_hashes.get(doc["doc_id"]) == embed_config_hash
            ):
                stats["skipped_fresh"] += 1
                continue

            parsed_stub = SimpleNamespace(
                intent=doc["intent"],
                tactics=doc["tactics"],
                techniques=doc["techniques"],
                description=doc["description"],
            )
            cooccurring: list[tuple[str, int]] = []
            if use_cooc:
                cooccurring = fetch_cooccurring_commands(
                    es, events_idx, doc["command"],
                    session_sample_size=cooc_cfg.session_sample_size,
                    top_k=cooc_cfg.top_k,
                    min_sessions=cooc_cfg.min_sessions,
                    total_sessions=total_sessions,
                )
            embed_text = _build_embed_text(
                doc["command"], parsed_stub, cfg.llm.embed_context,
                cooccurring=cooccurring,
                embed_cooccurrence=use_cooc,
                order=cfg.llm.embed_input_order,
            )

            if dry_run:
                stats["would_embed"] += 1
                continue

            try:
                embedding = llm.embed(embed_text)
            except Exception as e:
                log.error("embed failed for doc %s: %s", doc["doc_id"], e)
                stats["embed_failed"] += 1
                continue

            stats["embedded_ok"] += 1
            actions.append({
                "_op_type": "update",
                "_id": doc["doc_id"],
                "script": {
                    "source": _REEMBED_SCRIPT,
                    "params": {
                        "embedding": embedding,
                        "embed_config_hash": embed_config_hash,
                    },
                },
            })

            db.mark_embed_cached(doc["doc_id"], embed_config_hash, now)

            if len(actions) >= 50:
                ok, errs = bulk_write(es, commands_idx, actions)
                stats["bulk_ok"] += ok
                stats["bulk_errors"] += len(errs)
                if errs:
                    log.warning("re-embed bulk errors (%d): %s", len(errs), errs[:2])
                actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("re-embed bulk errors (%d): %s", len(errs), errs[:2])

    # P1.1 — a re-embed that rewrote ≥1 doc dirties the rollup, so the next
    # backward pass re-pools sessions to absorb the new vectors.
    if not dry_run and stats.get("bulk_ok", 0) > 0:
        from ...rollup_gate import mark_rollup_dirty
        mark_rollup_dirty(db)
    db.close()
    return dict(stats, dry_run=dry_run, embed_config_hash=embed_config_hash)


# ---------------------------------------------------------------------------
# Shape backfill (ROADMAP #9 — one-time admin op after mapping deploy)
# ---------------------------------------------------------------------------

def iter_docs_for_shape_backfill(
    es: Elasticsearch,
    index: str,
    page_size: int = 500,
) -> Iterator[dict]:
    """Yield (doc_id, command_line, existing_shape_hash, confidence) tuples
    for every doc in the commands index. Driver for `run_backfill_shape`.

    Projects `confidence` so the backfill can stamp `confidence_at_link`
    on the shape block at the same time as `hash` and `role`.
    """
    body: dict = {
        "size": page_size,
        "_source": [
            "process.command_line",
            "dshield.cowrie.enrichment.confidence",
            "dshield.cowrie.enrichment.shape.hash",
        ],
        "query": {"exists": {"field": "process.command_line"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            cmd = (src.get("process") or {}).get("command_line") or ""
            if not cmd:
                continue
            enr = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
            yield {
                "doc_id": h["_id"],
                "command_line": cmd,
                "existing_shape_hash": (enr.get("shape") or {}).get("hash") or "",
                "confidence": int(enr.get("confidence") or 0),
            }
        search_after = hits[-1]["sort"]


def run_backfill_shape(cfg: AppConfig, secrets: Secrets, dry_run: bool = False) -> dict:
    """Stamp `shape.hash` + `shape.role` on every existing commands doc.

    One-shot admin operation, run once after the mapping deploy that adds
    `dshield.cowrie.enrichment.shape.*`. Every doc gets role=standalone
    because each was LLM-enriched independently — the canonical/child
    distinction only applies to the inherit gate in `enrich`. Once the
    backfill runs, subsequent `enrich` passes can promote standalones to
    canonicals (or re-label existing docs as children) organically as
    new same-shape commands arrive.

    No LLM. No embedding. Just a structural label.

    Idempotent: if `shape.hash` is already set on a doc and matches the
    recomputed value, the update is suppressed via `detect_noop`.
    """
    es = make_client(cfg.elasticsearch, secrets)
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    now = _now()

    log.info(
        "backfill-shape: index=%s dry_run=%s", commands_idx, dry_run,
    )

    stats: dict = defaultdict(int)
    actions: list[dict] = []

    for doc in iter_docs_for_shape_backfill(es, commands_idx):
        stats["docs_seen"] += 1
        norm, _ = normalize(doc["command_line"], cfg.worker.command_max_chars)
        sh = compute_shape_hash(norm) if norm else ""
        if not sh:
            stats["shape_degenerate"] += 1
            continue
        if doc["existing_shape_hash"] == sh:
            stats["shape_unchanged"] += 1
            continue
        stats["shape_stamped"] += 1
        if dry_run:
            continue
        actions.append({
            "_op_type": "update",
            "_id": doc["doc_id"],
            "script": {
                "source": _BACKFILL_SHAPE_SCRIPT,
                "params": {
                    "shape_hash": sh,
                    "role": "standalone",
                    "linked_at": now,
                    "confidence_at_link": doc["confidence"],
                },
            },
        })
        if len(actions) >= 200:
            ok, errs = bulk_write(es, commands_idx, actions)
            stats["bulk_ok"] += ok
            stats["bulk_errors"] += len(errs)
            if errs:
                log.warning("backfill-shape bulk errors (%d): %s", len(errs), errs[:2])
            actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("backfill-shape bulk errors (%d): %s", len(errs), errs[:2])

    try:
        es.indices.refresh(index=commands_idx)
    except Exception as exc:
        log.warning("backfill-shape refresh failed (continuing): %s", exc)

    return dict(stats, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Re-enrich stale rows (LLM-side mirror of reembed)
# ---------------------------------------------------------------------------

def iter_docs_for_reenrich(
    es: Elasticsearch,
    index: str,
    page_size: int = 200,
    role_filter: Optional[str] = None,
    exclude_role: Optional[str] = None,
) -> Iterator[dict]:
    """Yield {doc_id, command_line, shape_hash, shape_role} for every
    enriched-commands doc.

    `role_filter` scopes the walk to a single shape role
    (`"canonical"`, `"standalone"`, or `"child"`). Used by the two-pass
    re-enrich: pass-1 excludes children via `exclude_role`, pass-2
    walks children directly via `role_filter`.

    `exclude_role` removes one role from the walk. Used in pass-1 so
    children (handled in pass-2) don't get a wasted LLM call before
    pass-2 overwrites them via inheritance.
    """
    filters: list[dict] = [{"exists": {"field": "process.command_line"}}]
    must_not: list[dict] = []
    if role_filter:
        filters.append({"term": {"dshield.cowrie.enrichment.shape.role": role_filter}})
    if exclude_role:
        must_not.append({"term": {"dshield.cowrie.enrichment.shape.role": exclude_role}})
    body: dict = {
        "size": page_size,
        "_source": [
            "process.command_line",
            "dshield.cowrie.enrichment.shape",
        ],
        "query": {"bool": {"filter": filters, "must_not": must_not}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            cmd = (src.get("process") or {}).get("command_line") or ""
            if not cmd:
                continue
            enr = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
            shape = enr.get("shape") or {}
            yield {
                "doc_id": h["_id"],
                "command_line": cmd,
                "shape_hash": shape.get("hash") or "",
                "shape_role": shape.get("role") or "",
            }
        search_after = hits[-1]["sort"]


def run_reenrich_stale(cfg: AppConfig, secrets: Secrets, dry_run: bool = False) -> dict:
    """Re-run the local LLM on every doc whose cached llm_config_hash is stale.

    Mirror of `reembed` for the LLM side: walks the commands ES index,
    consults the SQLite cache to find rows whose `llm_config_hash` !=
    the live value (i.e. produced under an older prompt or
    LLM-side cooccurrence config), re-calls the local LLM with the
    current prompt + sibling block, computes a fresh embedding, and
    patches the doc + cache. Rows whose cached llm_config_hash matches
    live are skipped without an LLM call. ROADMAP issue #7.5.

    Cloud escalation is NOT involved here. The separate `escalate` verb
    handles re-routing newly-stale-low-confidence docs to the cloud.

    When `cache_auto_invalidate=false` or there's no live hash, this is
    a no-op — there's no signal to identify staleness.
    """
    if not cfg.worker.cache_auto_invalidate:
        log.info(
            "re-enrich-stale: worker.cache_auto_invalidate=false → "
            "no signal to identify stale rows. Skipping."
        )
        return {"skipped_reason": "auto_invalidate_off"}

    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    prompt = load_prompt(cfg, "command_enrichment")
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw

    # Analyst rules — re-stamped on every touched doc so the historical
    # corpus picks up rules that landed after enrichment.
    from ...analyst.artifact_rules import apply_rules as _apply_rules
    from ...analyst.artifact_rules import load_active_rules as _load_rules
    analyst_rules = _load_rules(es, cfg)
    analyst_cap = cfg.analyst.max_match_per_doc

    live_llm_hash = compute_llm_config_hash(cfg)
    live_embed_hash = compute_embed_config_hash(cfg)
    cached_llm_hashes: dict[str, str] = db.get_cached_llm_hashes()

    cooc_cfg = cfg.cooccurrence
    total_sessions = (
        _fetch_total_session_count(es, events_idx) if cooc_cfg.enabled else 0
    )

    log.info(
        "re-enrich-stale: live_llm_hash=%s cache_rows=%d index=%s dry_run=%s",
        live_llm_hash, len(cached_llm_hashes), commands_idx, dry_run,
    )

    stats: dict = defaultdict(int)
    actions: list[dict] = []
    now = _now()

    # Functional-duplicate gating (ROADMAP #9) extends into re-enrich:
    #
    # Pass-1 here walks canonicals + standalones (children skipped via
    # `exclude_role` — pass-2 handles them). For each stale doc we
    # check the shape-bucket: if another doc with the same shape has
    # already been re-LLM'd in THIS pass, the current doc inherits
    # without re-running the LLM. Same savings as `run_enrich`'s
    # in-batch dedup, applied to the re-enrich path.
    #
    # We also check ES for an already-fresh canonical via
    # `lookup_canonical_for_shape` (with a freshness gate on the
    # parent's llm_config_hash) so a partial drift — where some shape
    # members are fresh and others aren't — converges in one pass.
    dedup_cfg = cfg.command_shape_dedup
    shape_parent_cache: dict[str, Optional[dict]] = {}

    def _maybe_get_fresh_parent(sh: str, exclude_id: str) -> Optional[dict]:
        """Lookup helper memoized for the run. Returns the parent only
        when its `llm_config_hash` already matches live (we won't
        inherit from a parent that's itself stale — its values are
        about to change).
        """
        if not sh or not dedup_cfg.enabled:
            return None
        if sh in shape_parent_cache:
            cached = shape_parent_cache[sh]
            if cached is None or cached["_id"] == exclude_id:
                return None
            return cached
        cand = lookup_canonical_for_shape(
            es, commands_idx, sh,
            min_confidence=dedup_cfg.min_parent_confidence,
            require_known_intent=dedup_cfg.require_known_intent,
        )
        if cand is not None and cand["_id"] == exclude_id:
            cand = None
        if cand is not None and (cand.get("llm_config_hash") or "") != live_llm_hash:
            cand = None
        shape_parent_cache[sh] = cand
        return cand

    with make_llm_client(cfg.llm) as llm:
        for doc in iter_docs_for_reenrich(
            es, commands_idx, exclude_role="child",
        ):
            stats["docs_seen"] += 1
            cached_hash = cached_llm_hashes.get(doc["doc_id"], "")
            if cached_hash == live_llm_hash:
                stats["skipped_fresh"] += 1
                continue
            if not cached_hash:
                # No cache row, or row carries the legacy '' hash. Treat
                # as stale — caller can `bless-cache` first if they want
                # legacy rows assumed-current.
                stats["stale_legacy"] += 1
            else:
                stats["stale_drifted"] += 1

            if dry_run:
                stats["would_reenrich"] += 1
                continue

            norm, truncated = normalize(doc["command_line"], cfg.worker.command_max_chars)
            if not norm:
                stats["skipped_empty_command"] += 1
                continue

            # ---- Inherit branch: same shape already has a fresh parent.
            sh = doc["shape_hash"]
            parent = _maybe_get_fresh_parent(sh, doc["doc_id"])
            if parent is not None:
                cooccurring2: list[tuple[str, int]] = []
                if cooc_cfg.enabled:
                    cooccurring2 = fetch_cooccurring_commands(
                        es, events_idx, norm,
                        session_sample_size=cooc_cfg.session_sample_size,
                        top_k=cooc_cfg.top_k,
                        min_sessions=cooc_cfg.min_sessions,
                        total_sessions=total_sessions,
                    )
                parent_parsed = _synth_parsed_from_parent(parent)
                embed_text = _build_embed_text(
                    norm, parent_parsed, cfg.llm.embed_context,
                    cooccurring=cooccurring2,
                    embed_cooccurrence=cooc_cfg.enabled and cooc_cfg.embed_cooccurrence,
                    order=cfg.llm.embed_input_order,
                )
                try:
                    embedding = llm.embed(embed_text)
                except Exception as e:
                    log.error("pass-1 inherit embed failed on %s: %s", doc["doc_id"], e)
                    stats["embed_failed"] += 1
                    continue
                indicators = _build_indicators(extract_iocs_regex(doc["command_line"]))
                analyst_artifacts = _apply_rules(doc["command_line"], analyst_rules, cap=analyst_cap)
                actions.append({
                    "_op_type": "update",
                    "_id": doc["doc_id"],
                    "script": {
                        "source": _REENRICH_INHERIT_SCRIPT,
                        "params": {
                            "description": parent_parsed.description,
                            "intent": parent_parsed.intent,
                            "confidence": parent_parsed.confidence,
                            "model": parent.get("model", ""),
                            "llm_config_hash": live_llm_hash,
                            "embed_config_hash": live_embed_hash,
                            "embedding": embedding,
                            "tactics": parent_parsed.tactics,
                            "techniques": parent_parsed.techniques,
                            "indicators": indicators,
                            "analyst_artifacts": analyst_artifacts,
                            "shape_hash": sh,
                            "functional_parent": parent["_id"],
                            "linked_at": now,
                            "inherited_from_model": parent.get("model", ""),
                            "confidence_at_link": int(parent_parsed.confidence),
                        },
                    },
                })
                db.mark_cached(
                    doc["doc_id"], cfg.llm.generation_model,
                    live_llm_hash, live_embed_hash, now,
                )
                # Keep cached_llm_hashes consistent so pass-2 (which
                # re-reads from the in-memory dict) doesn't treat the
                # doc as still stale after the inherit-write.
                cached_llm_hashes[doc["doc_id"]] = live_llm_hash
                stats["reenrich_inherited"] += 1

                if len(actions) >= 50:
                    ok, errs = bulk_write(es, commands_idx, actions)
                    stats["bulk_ok"] += ok
                    stats["bulk_errors"] += len(errs)
                    if errs:
                        log.warning("re-enrich bulk errors (%d): %s", len(errs), errs[:2])
                    actions = []
                continue

            # ---- Standalone branch: full LLM call.
            cooccurring: list[tuple[str, int]] = []
            if cooc_cfg.enabled:
                cooccurring = fetch_cooccurring_commands(
                    es, events_idx, norm,
                    session_sample_size=cooc_cfg.session_sample_size,
                    top_k=cooc_cfg.top_k,
                    min_sessions=cooc_cfg.min_sessions,
                    total_sessions=total_sessions,
                )
            cooc_block = _format_cooccurring_block(cooccurring)

            parsed, source, model = enrich_one(
                llm, prompt, norm,
                max_retries=cfg.llm.max_retries,
                cooccurring_block=cooc_block,
            )
            if parsed is None:
                stats["llm_no_parse"] += 1
                continue

            embed_text = _build_embed_text(
                norm, parsed, cfg.llm.embed_context,
                cooccurring=cooccurring,
                embed_cooccurrence=cooc_cfg.enabled and cooc_cfg.embed_cooccurrence,
                order=cfg.llm.embed_input_order,
            )
            try:
                embedding = llm.embed(embed_text)
            except Exception as e:
                log.error("re-enrich: embed failed on %s: %s", doc["doc_id"], e)
                stats["embed_failed"] += 1
                continue

            indicators = _build_indicators(parsed.iocs.model_dump())
            analyst_artifacts = _apply_rules(doc["command_line"], analyst_rules, cap=analyst_cap)
            actions.append({
                "_op_type": "update",
                "_id": doc["doc_id"],
                "script": {
                    "source": _REENRICH_SCRIPT,
                    "params": {
                        "provider": source,
                        "description": parsed.description,
                        "intent": parsed.intent,
                        "confidence": parsed.confidence,
                        "model": model,
                        "llm_config_hash": live_llm_hash,
                        "embed_config_hash": live_embed_hash,
                        "embedding": embedding,
                        "tactics": parsed.tactics,
                        "techniques": parsed.techniques,
                        "indicators": indicators,
                        "analyst_artifacts": analyst_artifacts,
                    },
                },
            })
            # Update both hashes — re-enrich produces fresh LLM output AND
            # a fresh embedding (since intent/etc. just changed).
            db.mark_cached(
                doc["doc_id"], cfg.llm.generation_model,
                live_llm_hash, live_embed_hash, now,
            )
            cached_llm_hashes[doc["doc_id"]] = live_llm_hash
            stats["reenriched_ok"] += 1

            # Promote this just-re-LLM'd doc as the in-batch parent for
            # its shape so subsequent same-shape stale docs inherit.
            if (
                sh
                and dedup_cfg.enabled
                and parsed.intent != "unknown"
                and parsed.confidence >= dedup_cfg.min_parent_confidence
            ):
                shape_parent_cache[sh] = {
                    "_id": doc["doc_id"],
                    "intent": parsed.intent,
                    "confidence": int(parsed.confidence),
                    "description": parsed.description,
                    "tactics": list(parsed.tactics or []),
                    "techniques": list(parsed.techniques or []),
                    "model": model,
                    "llm_config_hash": live_llm_hash,
                    "embed_config_hash": live_embed_hash,
                }

            if len(actions) >= 50:
                ok, errs = bulk_write(es, commands_idx, actions)
                stats["bulk_ok"] += ok
                stats["bulk_errors"] += len(errs)
                if errs:
                    log.warning("re-enrich bulk errors (%d): %s", len(errs), errs[:2])
                actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("re-enrich bulk errors (%d): %s", len(errs), errs[:2])

    try:
        es.indices.refresh(index=commands_idx)
    except Exception as exc:
        log.warning("re-enrich refresh failed (continuing): %s", exc)

    # ---- Pass-2: re-inherit children from now-refreshed canonicals ----
    #
    # Functional-duplicate gating (ROADMAP #9). Children carry the
    # parent's `llm_config_hash`, so when a parent re-enriches its hash
    # flips and every child shows up as stale in pass-1's cache check.
    # Pass-1 would have re-LLM'd them — wasteful. Pass-2 instead
    # looks up the current best canonical for each child's shape and
    # re-inherits, skipping the LLM and just re-embedding.
    #
    # NB: we walk pass-2 unconditionally (even when dedup is disabled in
    # config) because legacy children written under an earlier toggle
    # still need maintenance. The lookup respects min_confidence /
    # require_known_intent from current config.
    #
    # Note: this is a separate lookup cache from pass-1's
    # `shape_parent_cache`. Pass-1 only accepts parents whose own
    # llm_config_hash already matches live (so the inherited values
    # aren't about to change). Pass-2 runs after pass-1's refresh, so
    # any newly-fresh canonical is fair game.
    canonical_cache: dict[str, Optional[dict]] = {}

    actions = []
    with make_llm_client(cfg.llm) as llm:
        for doc in iter_docs_for_reenrich(es, commands_idx, role_filter="child"):
            stats["children_seen"] += 1
            sh = doc["shape_hash"]
            if not sh:
                stats["children_orphaned"] += 1
                continue

            if sh in canonical_cache:
                parent = canonical_cache[sh]
            else:
                parent = lookup_canonical_for_shape(
                    es, commands_idx, sh,
                    min_confidence=dedup_cfg.min_parent_confidence,
                    require_known_intent=dedup_cfg.require_known_intent,
                )
                canonical_cache[sh] = parent

            # Skip self-referential parent (child's own doc somehow
            # returned by lookup, e.g. role flipped between passes).
            if parent is not None and parent["_id"] == doc["doc_id"]:
                parent = None

            if parent is None:
                # No usable canonical for this shape anymore — leave the
                # child's existing enrichment intact. A future enrich
                # cycle will re-promote when a new canonical appears.
                stats["children_no_canonical"] += 1
                continue

            cached_hash = cached_llm_hashes.get(doc["doc_id"], "")
            parent_hash = parent.get("llm_config_hash") or ""
            if cached_hash and cached_hash == parent_hash:
                # Child already carries this parent's hash — inheritance
                # is fresh, nothing to do.
                stats["children_skipped_fresh"] += 1
                continue

            if dry_run:
                stats["children_would_relink"] += 1
                continue

            norm, _ = normalize(doc["command_line"], cfg.worker.command_max_chars)
            if not norm:
                continue

            cooccurring2: list[tuple[str, int]] = []
            if cooc_cfg.enabled:
                cooccurring2 = fetch_cooccurring_commands(
                    es, events_idx, norm,
                    session_sample_size=cooc_cfg.session_sample_size,
                    top_k=cooc_cfg.top_k,
                    min_sessions=cooc_cfg.min_sessions,
                    total_sessions=total_sessions,
                )
            parent_parsed = _synth_parsed_from_parent(parent)
            embed_text = _build_embed_text(
                norm, parent_parsed, cfg.llm.embed_context,
                cooccurring=cooccurring2,
                embed_cooccurrence=cooc_cfg.enabled and cooc_cfg.embed_cooccurrence,
                order=cfg.llm.embed_input_order,
            )
            try:
                embedding = llm.embed(embed_text)
            except Exception as e:
                log.error("pass-2 embed failed on %s: %s", doc["doc_id"], e)
                stats["children_embed_failed"] += 1
                continue
            indicators = _build_indicators(extract_iocs_regex(doc["command_line"]))
            analyst_artifacts = _apply_rules(doc["command_line"], analyst_rules, cap=analyst_cap)

            actions.append({
                "_op_type": "update",
                "_id": doc["doc_id"],
                "script": {
                    "source": _REENRICH_INHERIT_SCRIPT,
                    "params": {
                        "description": parent_parsed.description,
                        "intent": parent_parsed.intent,
                        "confidence": parent_parsed.confidence,
                        "model": parent.get("model", ""),
                        "llm_config_hash": parent_hash,
                        "embed_config_hash": live_embed_hash,
                        "embedding": embedding,
                        "tactics": parent_parsed.tactics,
                        "techniques": parent_parsed.techniques,
                        "indicators": indicators,
                        "analyst_artifacts": analyst_artifacts,
                        "shape_hash": sh,
                        "functional_parent": parent["_id"],
                        "linked_at": now,
                        "inherited_from_model": parent.get("model", ""),
                        "confidence_at_link": int(parent_parsed.confidence),
                    },
                },
            })
            db.mark_cached(
                doc["doc_id"], cfg.llm.generation_model,
                parent_hash, live_embed_hash, now,
            )
            stats["children_relinked"] += 1

            if len(actions) >= 50:
                ok, errs = bulk_write(es, commands_idx, actions)
                stats["bulk_ok"] += ok
                stats["bulk_errors"] += len(errs)
                if errs:
                    log.warning("pass-2 bulk errors (%d): %s", len(errs), errs[:2])
                actions = []

    if actions:
        ok, errs = bulk_write(es, commands_idx, actions)
        stats["bulk_ok"] += ok
        stats["bulk_errors"] += len(errs)
        if errs:
            log.warning("pass-2 bulk errors (%d): %s", len(errs), errs[:2])

    try:
        es.indices.refresh(index=commands_idx)
    except Exception as exc:
        log.warning("pass-2 refresh failed (continuing): %s", exc)

    # P1.1 — a re-enrich that rewrote ≥1 command doc dirties the rollup so the
    # next backward pass re-pools sessions to absorb the refreshed enrichment.
    if not dry_run and stats.get("bulk_ok", 0) > 0:
        from ...rollup_gate import mark_rollup_dirty
        mark_rollup_dirty(db)
    db.close()
    return dict(
        stats, dry_run=dry_run,
        live_llm_config_hash=live_llm_hash,
        live_embed_config_hash=live_embed_hash,
    )


# ---------------------------------------------------------------------------
# Re-triage (rule-derived triage_reasons rewrite — no LLM, no cloud)
# ---------------------------------------------------------------------------

# Reasons emitted by `reasons_to_escalate` whose firing is rule-derived and
# reproducible from the stored doc. Re-triage owns these — they get rewritten
# on every run.
_RULE_DERIVED_REASONS = frozenset({
    "low_confidence",  # prefix match; see _strip_rule_reasons below for the actual filter
    "base64_blob",
    "ip_literal",
    "rare_tld",
    "novel_embedding",
    "local_failed",    # also reproducible — derived from confidence==1 + intent==unknown
})

# Reasons that came from RUNTIME state at original-enrich time and can't be
# reproduced now (e.g. cloud was down, budget was exhausted, the random
# `sample` rule fired). Re-triage leaves these alone if present.
_RUNTIME_ONLY_REASONS = frozenset({
    "budget_exhausted",
    "cloud_parse_failed",
    "cloud_failed",
    "sample",
})


def _strip_rule_reasons(reasons: list[str]) -> list[str]:
    """Drop rule-derived reasons from a stored list, preserving runtime-only
    reasons. The `low_confidence<=N` reason embeds the threshold value so we
    match by prefix."""
    out: list[str] = []
    for r in reasons or []:
        if r.startswith("low_confidence"):
            continue
        if r in _RULE_DERIVED_REASONS:
            continue
        out.append(r)
    return out


def _iter_docs_for_retriage(
    es: Elasticsearch,
    commands_index: str,
    window_days: Optional[int] = None,
    page_size: int = 1000,
) -> Iterator[tuple[str, dict]]:
    """Yield `(doc_id, source_dict)` for every enriched command. Optional
    `window_days` scopes to docs with `@timestamp` in the last N days
    (matches the #21 windowing pattern; default None = scan everything).

    `_source` is projected to just what `reasons_to_escalate` needs:
    command text, confidence, embedding, and the existing triage_reasons
    so we can diff. Stable iteration via search_after on `_id`.
    """
    must: list[dict] = [
        {"exists": {"field": "dshield.cowrie.enrichment.confidence"}},
    ]
    if window_days and window_days > 0:
        must.append({"range": {"@timestamp": {"gte": f"now-{int(window_days)}d/d"}}})
    body = {
        "size": page_size,
        "_source": [
            "process.command_line",
            "dshield.cowrie.enrichment.confidence",
            "dshield.cowrie.enrichment.intent",
            "dshield.cowrie.enrichment.embedding",
            "dshield.cowrie.enrichment.triage_reasons",
        ],
        "query": {"bool": {"must": must}},
        # Sort on `@timestamp` + `_doc` for stable search_after pagination
        # — matches the other iterators in this file. Sorting by `_id`
        # directly requires `indices.id_field_data.enabled` which ES 8+
        # ships disabled by default.
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=commands_index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h["_id"], h["_source"]
        search_after = hits[-1]["sort"]


def run_retriage(
    cfg: AppConfig,
    secrets: Secrets,
    *,
    dry_run: bool = False,
    window_days: Optional[int] = None,
) -> dict:
    """Retroactively re-evaluate `triage_reasons` on every enriched command
    using the *current* rules in `enrich.triage`. No LLM/cloud calls.

    Use case: a triage-rule change (e.g. ROADMAP #23 tightening `base64_blob`)
    can leave stored `triage_reasons` lists carrying stale entries that
    wouldn't fire under current rules. `re-enrich-stale` doesn't pick this
    up because `triage.py` lives outside the `llm_config_hash`. This verb
    closes the gap.

    Semantics:
      - Rule-derived reasons in `_RULE_DERIVED_REASONS` (plus the
        `low_confidence<=N` prefix) are recomputed and replace whatever was
        stored.
      - Runtime-only reasons in `_RUNTIME_ONLY_REASONS` (`budget_exhausted`,
        `cloud_failed`, `cloud_parse_failed`, `sample`) are preserved
        unchanged — they reflect what happened back then and can't be
        reproduced now.
      - The random `sample` rule is suppressed during re-triage by passing
        a deterministic rng so re-runs over the same corpus produce the
        same output.
      - Empty result removes the `triage_reasons` field entirely (rather
        than leaving an empty array).

    `window_days`: optional time scoping (matches #21 pattern). Default
    `None` = scan every enriched command. Pass an int to limit to docs in
    the last N days.
    """
    import random
    from ...clustering import load_centroids
    from ...llm.schemas import IOCs

    es = make_client(cfg.elasticsearch, secrets)
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    clusters_idx = cfg.elasticsearch.indexes.cowrie.command_clusters

    t0 = time.time()
    log.info(
        "[re-triage] scanning %s (window_days=%s, dry_run=%s)",
        commands_idx, window_days if window_days else "all", dry_run,
    )

    # Load centroids once for the novel_embedding rule. If there are no
    # cluster centroids yet, the rule will silently no-op per
    # reasons_to_escalate's existing guard.
    # Dual centroids (brutal-review 5.6): if an external reference set
    # exists for this layer, the triage rule scores against it instead
    # of the in-corpus set — reserving cloud escalation for behavior
    # novel to BOTH the sensor AND the documented adversary catalog.
    centroids = load_centroids(es, clusters_idx)
    centroids_external = load_centroids(
        es, clusters_idx, reference_source="external",
    )
    log.info(
        "[re-triage] loaded %d in-corpus centroids and %d external "
        "centroids for novel_embedding rule",
        len(centroids), len(centroids_external),
    )

    deterministic_rng = random.Random(0)
    stats: dict = {
        "scanned":  0,
        "changed":  0,
        "unchanged": 0,
        "added_by_rule":   defaultdict(int),
        "removed_by_rule": defaultdict(int),
    }
    update_actions: list[dict] = []

    for doc_id, src in _iter_docs_for_retriage(
        es, commands_idx, window_days=window_days,
    ):
        stats["scanned"] += 1
        en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
        confidence = en.get("confidence")
        if confidence is None:
            # No usable parsed enrichment; can't re-triage. Skip.
            continue
        command = (src.get("process") or {}).get("command_line") or ""
        embedding = en.get("embedding")
        old_reasons = list(en.get("triage_reasons") or [])

        # Reconstruct a minimal CommandEnrichment shim. Only `confidence`
        # is read by reasons_to_escalate; other fields don't influence
        # rule firing.
        parsed = CommandEnrichment(
            intent=en.get("intent") or "unknown",
            confidence=int(confidence),
            description="",
            tactics=[],
            techniques=[],
            notes="",
            iocs=IOCs(ips=[], domains=[], urls=[], hashes=[], files=[]),
        )

        # Re-run the rule set. `local_failed=False` is the safe choice —
        # if this doc has a parsed enrichment with a confidence, local
        # enrichment didn't fail. `sample` is random; suppress for
        # determinism (also dropped explicitly below).
        new_reasons_full = triage_mod.reasons_to_escalate(
            command=command,
            parsed=parsed,
            local_failed=False,
            cfg=cfg.cloud,
            embedding=embedding,
            centroids=centroids if embedding and centroids else None,
            centroids_external=(
                centroids_external if embedding and centroids_external
                else None
            ),
            rng=deterministic_rng,
        )
        # Keep only rule-derived reasons from the new run; merge in
        # runtime-only reasons from the old list.
        new_rule_reasons = [
            r for r in new_reasons_full if r != "sample"
        ]
        preserved_runtime = [
            r for r in old_reasons if r in _RUNTIME_ONLY_REASONS
        ]
        merged = sorted(set(new_rule_reasons) | set(preserved_runtime))

        old_set = set(old_reasons)
        new_set = set(merged)
        if old_set == new_set:
            stats["unchanged"] += 1
            continue

        stats["changed"] += 1
        for r in (new_set - old_set):
            stats["added_by_rule"][r] += 1
        # Removals come only from rule-derived reasons we own; the
        # runtime-only ones are preserved above, so any old reason
        # missing from merged must be a rule-derived one.
        for r in (old_set - new_set):
            stats["removed_by_rule"][r] += 1

        update_actions.append({
            "_op_type": "update",
            "_id": doc_id,
            "script": {
                "source": _RETRIAGE_SCRIPT,
                "params": {"triage_reasons": merged},
            },
        })

    # Convert defaultdicts to plain dicts for clean JSON output.
    stats["added_by_rule"] = dict(stats["added_by_rule"])
    stats["removed_by_rule"] = dict(stats["removed_by_rule"])
    stats["runtime_seconds"] = round(time.time() - t0, 2)

    if dry_run:
        log.info("[re-triage] dry-run: would update %d/%d docs", stats["changed"], stats["scanned"])
        stats["status"] = "dry_run"
        return stats

    if not update_actions:
        log.info("[re-triage] no docs to update")
        return stats

    bulk_ok = 0
    bulk_errors = 0
    batch = 500
    for start in range(0, len(update_actions), batch):
        chunk = update_actions[start: start + batch]
        ok, errs = bulk_write(es, commands_idx, chunk)
        bulk_ok += ok
        bulk_errors += len(errs)
        if errs:
            log.warning("[re-triage] bulk errors (%d): %s", len(errs), errs[:2])
    try:
        es.indices.refresh(index=commands_idx)
    except Exception as exc:
        log.warning("[re-triage] post-write refresh failed (continuing): %s", exc)

    stats["docs_updated"] = bulk_ok
    stats["bulk_errors"] = bulk_errors
    log.info("[re-triage] wrote %d updates in %ss; +%s -%s",
             bulk_ok, stats["runtime_seconds"],
             stats["added_by_rule"], stats["removed_by_rule"])
    return stats


# ---------------------------------------------------------------------------
# Cluster commands
# ---------------------------------------------------------------------------

def iter_enriched_docs(
    es: Elasticsearch,
    index: str,
    page_size: int = 1000,
) -> Iterator[tuple[str, list[float], str, dict]]:
    """Yield (doc_id, embedding, command, scalars) for docs that have an embedding.

    scalars keys: occurrence_count, unique_source_ips, confidence, session_reuse_rate.
    """
    body: dict = {
        "size": page_size,
        "_source": [
            "dshield.cowrie.enrichment.embedding",
            "dshield.cowrie.enrichment.occurrence_count",
            "dshield.cowrie.enrichment.unique_sessions",
            "dshield.cowrie.enrichment.unique_source_ips",
            "dshield.cowrie.enrichment.confidence",
            "process.command_line",
        ],
        "query": {"exists": {"field": "dshield.cowrie.enrichment.embedding"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            en = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment", {})
            emb = en.get("embedding")
            if not emb:
                continue
            cmd = (src.get("process") or {}).get("command_line", "")
            occ = en.get("occurrence_count") or 1
            scalars = {
                "occurrence_count": occ,
                "unique_sessions": en.get("unique_sessions") or 1,
                "unique_source_ips": en.get("unique_source_ips") or 1,
                "confidence": en.get("confidence") or 5,
                "session_reuse_rate": min((en.get("unique_sessions") or 1) / occ, 1.0),
            }
            yield h["_id"], emb, cmd, scalars
        search_after = hits[-1]["sort"]


def build_command_scalar_block(scalars_list: list[dict], weight: float) -> "np.ndarray":
    """(n, 4) weighted scalar matrix appended to L2-normalized embeddings.

    log1p-normalized fields use fixed corpus-scale denominators (ROADMAP #14)
    so a given command yields identical scalar contributions across re-runs.
    Output clipped to [0, 1].
    """
    import numpy as np
    counts = np.array([s.get("occurrence_count") or 1 for s in scalars_list], dtype=np.float32)
    ips = np.array([s.get("unique_source_ips") or 1 for s in scalars_list], dtype=np.float32)
    conf = np.array([s.get("confidence") or 5 for s in scalars_list], dtype=np.float32)
    reuse = np.array([s.get("session_reuse_rate", 1.0) for s in scalars_list], dtype=np.float32)

    denom_count = float(np.log1p(_SCALAR_DENOM_OCCURRENCE_COUNT))
    denom_ips = float(np.log1p(_SCALAR_DENOM_UNIQUE_SOURCE_IPS))

    block = np.zeros((len(scalars_list), 4), dtype=np.float32)
    block[:, 0] = np.clip(np.log1p(counts) / denom_count, 0.0, 1.0) * weight
    block[:, 1] = np.clip(np.log1p(ips) / denom_ips, 0.0, 1.0) * weight
    block[:, 2] = (conf / 10.0) * weight
    block[:, 3] = np.clip(reuse, 0.0, 1.0) * weight
    return block


def run_cluster(
    cfg: AppConfig,
    secrets: Secrets,
    dry_run: bool = False,
    refresh_reference: bool = False,
    use_reference: bool = True,
) -> dict:
    """Cluster command embeddings + write novelty scores back. Delegates to clustering core."""
    from ...clustering import run_layer_clustering
    es = make_client(cfg.elasticsearch, secrets)
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands
    clusters_idx = cfg.elasticsearch.indexes.cowrie.command_clusters
    ccfg: CommandClusterConfig = cfg.command_cluster

    if not es.indices.exists(index=commands_idx):
        raise RuntimeError(
            f"Commands index '{commands_idx}' not found. "
            "Run 'enrich' first, or check elasticsearch.indexes.cowrie.commands in config."
        )

    return run_layer_clustering(
        es=es,
        docs_iter=iter_enriched_docs(es, commands_idx, ccfg.page_size),
        docs_index=commands_idx,
        clusters_index=clusters_idx,
        mapping_path=_COMMAND_CLUSTERS_MAPPING,
        update_script=_CLUSTER_UPDATE_SCRIPT,
        scalar_block_builder=build_command_scalar_block,
        min_cluster_size=ccfg.min_cluster_size,
        min_samples=ccfg.min_samples,
        scalar_weight=ccfg.scalar_weight,
        batch_size=ccfg.batch_size,
        sample_size=_CLUSTER_SAMPLE_SIZE,
        centroid_sample_field="sample_commands",
        dry_run=dry_run,
        layer_label="cowrie.commands",
        refresh_reference=refresh_reference,
        use_reference=use_reference,
        reference_max_age_days=ccfg.reference_max_age_days,
        # F1b: bring noise-rescue to parity with the session layer. Outlier
        # commands within this cosine of a centroid join it rather than
        # staying noise (default off in the model; default.yaml ships 0.94).
        rescue_threshold=ccfg.rescue_threshold,
    )
