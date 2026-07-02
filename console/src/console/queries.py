"""Elasticsearch queries used by the console API.

Design notes:
* Field paths follow the mappings in `setup/es-mappings/cowrie/*.json`. Anything that
  changes there must be reflected here.
* Every query strips `dshield.*.embedding` from `_source` so 768-dim vectors
  never leave the server.
* Latest-cluster-run resolution: clusters indices store a `run_summary` doc
  per run. We look up the most recent run_id and filter cluster lookups by it.
* All sizes are bounded; callers pick `size` within [1, 500].
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from elasticsearch import Elasticsearch, NotFoundError

from ._config import AppConfig

log = logging.getLogger(__name__)

# ES parent-circuit-breaker probe for the /health status strip (observability
# lane). Lives in the parent `enrich` package, so the import is guarded the same
# way `console.health` guards `command_grounding`: a console-only install (no
# pipeline) or any import failure degrades to state=unknown, never a page error.
try:
    from enrich.es_health import parent_breaker_ratio as _parent_breaker_ratio
    _ES_HEALTH_AVAILABLE = True
except Exception:  # pragma: no cover — console-only install / import failure
    _ES_HEALTH_AVAILABLE = False

# Parent-breaker watermarks for the pressure tile. Mirror the defaults of
# `enrich.config.ESBackpressureConfig` (heap_high_watermark / heap_resume_
# watermark) so the tile's ok/warn/crit thresholds match the pipeline's real
# backpressure behaviour. The console's slim config carries no backpressure
# block, so these are constants — an operator who retunes the pipeline's
# watermarks won't shift the tile, which is acceptable for a best-effort UI.
_ES_HEAP_HIGH_WATERMARK = 0.85
_ES_HEAP_RESUME_WATERMARK = 0.70


# Mirror of `enrich.sources.cowrie.commands.normalize` + `hash_command_full`.
# Duplicated so the console package stays standalone. If the worker's
# normalization ever changes, mirror the edit here — otherwise we'd silently
# fail to join raw command-input events to their enrichment docs.
_WS_RE = re.compile(r"\s+")

# Floor for surfacing novelty in the insights panel. Mirrors the pipeline's
# `cloud.triage.novel_confidence_min` (config/default.yaml) — confidence-1
# enrichments are typically raw-byte / encoding artifacts whose novelty score
# is noise. The console's AppConfig is intentionally slim and doesn't pull
# triage config, so the value is duplicated here. See ROADMAP issue #3.
_NOVEL_CONFIDENCE_MIN = 4


def _hash_command(cmd: str, max_chars: int = 4000) -> str:
    s = _WS_RE.sub(" ", (cmd or "").strip())[:max_chars]
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------
# Aggregation-safe field resolver.
#
# When a field was first written via Painless before its mapping declared it,
# ES dynamic-maps strings as `text` with a `.keyword` sub-field. `_source`
# reads still work, but aggregations and term queries on the bare path silently
# fail (the agg `try/except` returns empty results; the term query matches the
# analyzed tokens, not the original string). For new indexes built from the
# updated mapping the field is `keyword` directly with no sub-field.
#
# `_resolve_agg_field` inspects the live mapping and returns whichever path
# actually works for aggregations on this index. Results are cached per
# (index, dotted_path) so we only hit the mapping API once per pair.
# ----------------------------------------------------------------------------

_AGG_FIELD_CACHE: dict[tuple[str, str], str] = {}


def _resolve_agg_field(es: Elasticsearch, index: str, dotted_path: str) -> str:
    cache_key = (index, dotted_path)
    if cache_key in _AGG_FIELD_CACHE:
        return _AGG_FIELD_CACHE[cache_key]
    resolved: str | None = None
    try:
        full = es.indices.get_mapping(index=index)
        if full:
            # `full` is { <resolved_index_name>: { mappings: { ... } } }.
            first_key = next(iter(full.keys()))
            mappings = full[first_key].get("mappings", {})
            node: Any = mappings
            for seg in dotted_path.split("."):
                props = (node or {}).get("properties") or {}
                node = props.get(seg)
                if node is None:
                    break
            if node:
                ftype = node.get("type")
                if ftype == "keyword":
                    resolved = dotted_path
                elif ftype == "text":
                    sub = (node.get("fields") or {}).get("keyword") or {}
                    if sub.get("type") == "keyword":
                        resolved = f"{dotted_path}.keyword"
                    else:
                        resolved = dotted_path
                else:
                    resolved = dotted_path
            else:
                # Field truly absent from the mapping — bare path is the
                # safest fallback. It's worth caching: if the field is added
                # later we'll pick it up on the next process restart.
                resolved = dotted_path
    except Exception as exc:
        log.debug("_resolve_agg_field(%s, %s) failed: %s", index, dotted_path, exc)
        # Do NOT cache on transient errors (ES timeout, etc.); next call
        # gets a fresh attempt. Falling back to the bare path is a
        # best-effort guess for the current call only.
        return dotted_path
    _AGG_FIELD_CACHE[cache_key] = resolved or dotted_path
    return resolved or dotted_path


# ----------------------------------------------------------------------------
# Session quality filter
# ----------------------------------------------------------------------------
#
# Most useful threat-hunting views want sessions that actually did something
# (logged in successfully AND ran a command). The login-only scanners blast
# every IP with credentials and never get in; the dropped-but-no-commands
# sessions are noise. The defaults reflect that.

class SessionFilter:
    """Quality filter applied to session rollup queries. Each flag is
    independent; both default ON so callers get the threat-hunter-useful
    view unless they explicitly opt out."""

    __slots__ = ("require_login", "require_commands")

    def __init__(self, require_login: bool = True, require_commands: bool = True) -> None:
        self.require_login = bool(require_login)
        self.require_commands = bool(require_commands)

    @property
    def active(self) -> bool:
        return self.require_login or self.require_commands

    def es_filters(self) -> list[dict]:
        """ES range clauses to AND into a bool/filter or bool/must. Returns []
        when nothing is active so callers can splice unconditionally."""
        out: list[dict] = []
        if self.require_login:
            out.append({"range": {"dshield.cowrie.enrichment.session.login_success_count": {"gte": 1}}})
        if self.require_commands:
            out.append({"range": {"dshield.cowrie.enrichment.session.command_count": {"gte": 1}}})
        return out


_NO_FILTER = SessionFilter(require_login=False, require_commands=False)


def _empty_search_result() -> dict:
    """Shape that mimics an ES search response with zero hits, so callers
    that index into `result['hits']['hits']` keep working when an index is
    missing."""
    return {"hits": {"total": {"value": 0}, "hits": []}}


# Fields excluded from every response — embeddings are too big to ship and
# never useful to the GUI.
_EXCLUDE = [
    "dshield.cowrie.enrichment.embedding",
    "dshield.cowrie.enrichment.session.embedding",
    "dshield.cowrie.enrichment.ip.embedding",
    "centroid",
]


def _src(*extra: str) -> dict:
    """Build a `_source` filter that includes everything except embeddings."""
    return {"excludes": _EXCLUDE}


# ----------------------------------------------------------------------------
# Latest-cluster-run resolution
# ----------------------------------------------------------------------------

class RunCache:
    """Caches the most recent run_id per cluster index for a short TTL."""

    def __init__(self, ttl_seconds: float = 60.0) -> None:
        self.ttl = ttl_seconds
        self._cache: dict[str, tuple[float, str | None]] = {}

    def latest(self, es: Elasticsearch, index: str) -> str | None:
        now = time.monotonic()
        hit = self._cache.get(index)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        try:
            r = es.search(
                index=index,
                size=1,
                _source=["run_id", "@timestamp"],
                query={"term": {"doc_type": "run_summary"}},
                sort=[{"@timestamp": {"order": "desc"}}],
            )
            hits = r["hits"]["hits"]
            run_id = hits[0]["_source"].get("run_id") if hits else None
        except Exception as e:  # pragma: no cover -- network paths
            log.warning("run-id lookup failed for %s: %s", index, e)
            run_id = None
        self._cache[index] = (now, run_id)
        return run_id


# ----------------------------------------------------------------------------
# Lookups (single-doc fetches keyed by IOC)
# ----------------------------------------------------------------------------

def lookup_ip(es: Elasticsearch, cfg: AppConfig, ip: str) -> dict | None:
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    try:
        r = es.get(index=idx, id=ip, source_excludes=_EXCLUDE)
        return {"_id": r["_id"], "_source": r["_source"]}
    except Exception:
        # Fall back to search by source.ip just in case _id != ip on some doc.
        r = es.search(index=idx, size=1, _source=_src(),
                      query={"term": {"source.ip": ip}})
        hits = r["hits"]["hits"]
        return {"_id": hits[0]["_id"], "_source": hits[0]["_source"]} if hits else None


def lookup_session(es: Elasticsearch, cfg: AppConfig, session_id: str) -> dict | None:
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        r = es.get(index=idx, id=session_id, source_excludes=_EXCLUDE)
        return {"_id": r["_id"], "_source": r["_source"]}
    except Exception:
        r = es.search(index=idx, size=1, _source=_src(),
                      query={"term": {"cowrie.session_id": session_id}})
        hits = r["hits"]["hits"]
        return {"_id": hits[0]["_id"], "_source": hits[0]["_source"]} if hits else None


def lookup_command(es: Elasticsearch, cfg: AppConfig, sha256: str) -> dict | None:
    idx = cfg.elasticsearch.indexes.cowrie.commands
    # First try _id == sha256 (the worker upserts with the hash as _id).
    try:
        r = es.get(index=idx, id=sha256, source_excludes=_EXCLUDE)
        return {"_id": r["_id"], "_source": r["_source"]}
    except Exception:
        r = es.search(index=idx, size=1, _source=_src(),
                      query={"term": {"process.hash.sha256": sha256}})
        hits = r["hits"]["hits"]
        return {"_id": hits[0]["_id"], "_source": hits[0]["_source"]} if hits else None


_FE_PATH = "dshield.cowrie.enrichment.session.file_events"


def file_hash_exists(es: Elasticsearch, cfg: AppConfig, sha256: str) -> bool:
    """True if `sha256` is a dropped-file hash (file_events.sha256) in any
    session rollup. Used to disambiguate a 64-hex query that could be a command
    process-hash and/or a dropped file."""
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        r = es.count(index=idx, query={"nested": {"path": _FE_PATH,
            "query": {"term": {f"{_FE_PATH}.sha256": sha256.lower()}}}})
        return r.get("count", 0) > 0
    except Exception:
        return False


def lookup_cluster(
    es: Elasticsearch, cfg: AppConfig, kind: str, cluster_id: str,
    run_cache: RunCache,
) -> dict | None:
    """`kind` ∈ {'command', 'session', 'ip'}."""
    idx_map = {
        "command": cfg.elasticsearch.indexes.cowrie.command_clusters,
        "session": cfg.elasticsearch.indexes.cowrie.session_clusters,
        "ip":      cfg.elasticsearch.indexes.cowrie.ip_clusters,
    }
    idx = idx_map[kind]
    run_id = run_cache.latest(es, idx)
    must: list[dict] = [
        {"term": {"cluster_id": cluster_id}},
        {"term": {"doc_type": "cluster"}},
    ]
    if run_id:
        must.append({"term": {"run_id": run_id}})
    r = es.search(index=idx, size=1, _source=_src(),
                  query={"bool": {"must": must}})
    hits = r["hits"]["hits"]
    return {"_id": hits[0]["_id"], "_source": hits[0]["_source"]} if hits else None


def bulk_session_enrichment(
    es: Elasticsearch, cfg: AppConfig, session_ids: list[str],
) -> dict[str, dict]:
    """Resolve {session_id -> dshield.cowrie.enrichment.session} for many ids
    in one search. Used by graph builders that emit session nodes coming
    from non-session anchors (e.g. sessions_for_command rows) so the
    session's cluster_id / playbook_id / etc. land on the node even though
    the front-end's pipeline traversal won't re-fetch them as a real
    session anchor."""
    if not session_ids:
        return {}
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        r = es.search(
            index=idx, size=len(session_ids),
            _source=["cowrie.session_id", "source.ip",
                     "dshield.cowrie.enrichment.session"],
            query={"terms": {"cowrie.session_id": list(set(session_ids))}},
        )
    except Exception as e:
        log.warning("bulk_session_enrichment failed: %s", e)
        return {}
    out: dict[str, dict] = {}
    for h in r["hits"]["hits"]:
        src = h["_source"]
        sid = (src.get("cowrie") or {}).get("session_id")
        if not sid:
            continue
        senr = (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}).get("session") or {}
        out[sid] = {
            "enrichment": senr,
            "src_ip": (src.get("source") or {}).get("ip"),
        }
    return out


def bulk_ip_enrichment(
    es: Elasticsearch, cfg: AppConfig, ips: list[str],
) -> dict[str, dict]:
    """Resolve {ip -> {enrichment, asn, country}} for many ips in one search.
    Same motivation as bulk_session_enrichment: anchor functions need
    cluster / asn / country for source IPs they emit so the front-end's
    cluster bubbles include them, even though the IP node arrives as a
    'leaf' in pipeline-traversal terms."""
    if not ips:
        return {}
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    try:
        r = es.search(
            index=idx, size=len(ips),
            _source=["source.ip", "source.as", "source.geo",
                     "dshield.cowrie.enrichment.ip"],
            query={"terms": {"source.ip": list(set(ips))}},
        )
    except Exception as e:
        log.warning("bulk_ip_enrichment failed: %s", e)
        return {}
    out: dict[str, dict] = {}
    for h in r["hits"]["hits"]:
        src = h["_source"]
        ip = (src.get("source") or {}).get("ip")
        if not ip:
            continue
        ienr = (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}).get("ip") or {}
        out[ip] = {
            "enrichment": ienr,
            "asn": ((src.get("source") or {}).get("as") or {}).get("number"),
            "asn_org": (((src.get("source") or {}).get("as") or {}).get("organization") or {}).get("name"),
            "country": ((src.get("source") or {}).get("geo") or {}).get("country_iso_code"),
        }
    return out


def lookup_campaign(es: Elasticsearch, cfg: AppConfig, campaign_id: str) -> dict | None:
    """Read one campaign doc from the campaigns index (the multi-session
    concept mined by `dshield_prism mine campaigns`). Returns None if no
    matching doc exists.

    Distinct from `lookup_playbook`, which operates on the session-cluster
    centroid index — a playbook is one named session cluster.
    """
    idx = cfg.elasticsearch.indexes.cowrie.campaigns
    cid_field = _resolve_agg_field(es, idx, "campaign_id")
    try:
        r = es.search(
            index=idx, size=1,
            query={"bool": {"must": [
                {"term": {"doc_type": "campaign"}},
                {"term": {cid_field: campaign_id}},
            ]}},
        )
        hits = r["hits"]["hits"]
    except Exception as exc:
        log.warning("lookup_campaign failed for %s: %s", campaign_id, exc)
        return None
    if not hits:
        return None
    return hits[0]["_source"]


def lookup_operation(es: Elasticsearch, cfg: AppConfig, operation_id: str) -> dict | None:
    """Read one operation doc by ``operation_id`` (brutal-review 7.2).

    Operations are mined by 7.1's `mine operations` step from
    (bhv-campaign × inf-campaign) pairs whose IP overlap clears the
    corpus-p75 threshold. Stable across re-mines because the id is
    content-addressed on the sorted (bhv, inf) pair.

    Returns None if no matching doc exists (e.g. an operation that
    fell below threshold on the most recent re-mine).
    """
    idx = cfg.elasticsearch.indexes.cowrie.operations
    try:
        r = es.search(
            index=idx, size=1,
            query={"term": {"operation_id": operation_id}},
        )
        hits = r["hits"]["hits"]
    except Exception as exc:
        log.warning("lookup_operation failed for %s: %s", operation_id, exc)
        return None
    if not hits:
        return None
    return hits[0]["_source"]


def list_operations(es: Elasticsearch, cfg: AppConfig, *, size: int = 25) -> list[dict]:
    """Top operations by ``shared_ip_count`` (brutal-review 7.2 — used by
    the Insights surface). Empty list when the index doesn't exist yet."""
    idx = cfg.elasticsearch.indexes.cowrie.operations
    try:
        if not es.indices.exists(index=idx):
            return []
        r = es.search(
            index=idx, size=size,
            _source=[
                "operation_id",
                "behaviour_id", "behaviour_name",
                "infrastructure_id", "infrastructure_name",
                "shared_ip_count", "bhv_ip_count", "inf_ip_count",
                "overlap_ratio", "overlap_threshold",
                "first_seen", "last_seen",
            ],
            sort=[{"shared_ip_count": {"order": "desc"}}],
        )
        return [h["_source"] for h in r["hits"]["hits"]]
    except Exception as exc:
        log.warning("list_operations failed: %s", exc)
        return []


def list_campaigns(
    es: Elasticsearch, cfg: AppConfig, *,
    kind: str | None = None, size: int = 25,
) -> list[dict]:
    """Top campaigns by session_count, optionally filtered by kind
    (`behaviour` | `infrastructure`). Used by the insights page."""
    idx = cfg.elasticsearch.indexes.cowrie.campaigns
    must: list[dict] = [{"term": {"doc_type": "campaign"}}]
    if kind:
        must.append({"term": {"kind": kind}})
    try:
        r = es.search(
            index=idx, size=size,
            _source=[
                "campaign_id", "kind", "name", "rationale",
                "ip_count", "session_count", "first_seen", "last_seen",
                "support", "member_playbook_ids",
            ],
            query={"bool": {"must": must}},
            sort=[{"session_count": {"order": "desc"}}],
        )
        return [h["_source"] for h in r["hits"]["hits"]]
    except Exception as exc:
        log.warning("list_campaigns failed: %s", exc)
        return []


def lookup_playbook(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str,
) -> dict:
    """Look up a playbook by its id (`spb-<16hex>`, cosine-anchored at
    name time; see `sessions._assign_playbook_id`).

    A playbook may be backed by one or more session-cluster centroid docs
    (HDBSCAN clusters merged by `session.playbook_merge_threshold` at name
    time share a `playbook_id`). Anchoring on the playbook returns the
    session members plus the source IPs that produced those sessions. IPs
    don't carry a playbook field; their playbook membership is derived
    from the sessions they ran.

    The return shape is rich on purpose — the playbook detail panel reads
    timespan / top-countries / top-ASNs / dominant intent / 24h delta /
    sample commands directly from it.
    """
    sess_idx     = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters

    # Centroid docs hold the display name + per-cluster sizes. With merge
    # enabled, a playbook can span >1 centroid doc, so we sum sizes across
    # every centroid that carries this playbook_id. The name is identical
    # across constituent docs (write-time invariant in run_name_playbooks).
    name = None
    size = None
    centroid_field = _resolve_agg_field(es, clusters_idx, "playbook_id")
    try:
        cresp = es.search(
            index=clusters_idx, size=100,
            _source=["playbook_name", "size", "cluster_id", "run_id"],
            query={"term": {centroid_field: playbook_id}},
        )
        chits = cresp["hits"]["hits"]
        if chits:
            name = chits[0]["_source"].get("playbook_name")
            size = sum(int(h["_source"].get("size") or 0) for h in chits)
    except Exception:
        pass

    # Post-cutover the centroid name is often absent (novel-pool only refreshes a few);
    # fall back to the session rollup's authoritative playbook_name.
    if not name:
        name = _playbook_names(es, cfg, [playbook_id]).get(playbook_id)

    pb_field = _resolve_agg_field(
        es, sess_idx, "dshield.cowrie.enrichment.session.playbook_id",
    )
    base_q = {"term": {pb_field: playbook_id}}

    # Sample sessions (for the "Sample IPs" / "Sample Sessions" rows).
    sess_hits = es.search(
        index=sess_idx, size=10, _source=_src(),
        query=base_q,
    )
    sample_sessions = []
    sample_ips_in_sample: list[str] = []
    seen_ips_in_sample: set[str] = set()
    for h in sess_hits["hits"]["hits"]:
        src = h["_source"]
        sid = (src.get("cowrie") or {}).get("session_id")
        if sid:
            sample_sessions.append(sid)
        ip = (src.get("source") or {}).get("ip")
        if ip and ip not in seen_ips_in_sample:
            seen_ips_in_sample.add(ip)
            sample_ips_in_sample.append(ip)

    # Rich aggregations: one round-trip pulls every field the playbook
    # detail panel reads, so the page renders in one ES hit + the centroid
    # lookup above. `now-24h` and `now-48h..now-24h` give the recent-delta.
    aggs_body = {
        "first_seen":     {"min": {"field": "event.start"}},
        "last_seen":      {"max": {"field": "event.start"}},
        "distinct_ips":   {"cardinality": {"field": "source.ip"}},
        "top_countries":  {"terms": {"field": "source.geo.country_iso_code", "size": 5}},
        "top_asns":       {"terms": {"field": "source.as.number", "size": 5}},
        "top_intents":    {"terms": {
            "field": "dshield.cowrie.enrichment.session.dominant_intent",
            "size": 3,
            "missing": "unknown",
        }},
        "last_24h":       {"filter": {"range": {"event.start": {"gte": "now-24h"}}}},
        "prior_24h":      {"filter": {"range": {"event.start": {"gte": "now-48h", "lt": "now-24h"}}}},
    }
    first_seen = last_seen = None
    distinct_ips = 0
    top_countries: list[dict] = []
    top_asns:      list[dict] = []
    top_intents:   list[dict] = []
    last_24h = prior_24h = 0
    try:
        agg_resp = es.search(index=sess_idx, size=0, query=base_q, aggs=aggs_body)
        a = agg_resp.get("aggregations", {})
        first_seen   = (a.get("first_seen") or {}).get("value_as_string")
        last_seen    = (a.get("last_seen")  or {}).get("value_as_string")
        distinct_ips = int((a.get("distinct_ips") or {}).get("value") or 0)
        top_countries = [
            {"cc": b["key"], "count": b["doc_count"]}
            for b in (a.get("top_countries") or {}).get("buckets", [])
        ]
        top_asns = [
            {"asn": b["key"], "count": b["doc_count"]}
            for b in (a.get("top_asns") or {}).get("buckets", [])
        ]
        top_intents = [
            {"intent": b["key"], "count": b["doc_count"]}
            for b in (a.get("top_intents") or {}).get("buckets", [])
        ]
        last_24h  = int((a.get("last_24h")  or {}).get("doc_count") or 0)
        prior_24h = int((a.get("prior_24h") or {}).get("doc_count") or 0)
    except Exception as exc:
        log.warning("lookup_playbook rich aggs failed for %s: %s", playbook_id, exc)

    # Sample commands the playbook's sessions are running. The session
    # rollup doesn't store full command lines, so we cross-join via the
    # commands index, looking up command_lines that appear most often in
    # this playbook's sessions. Three samples is enough to convey flavour.
    sample_commands: list[str] = []
    try:
        # First, get the session ids in this playbook (top N by command_count).
        sids_resp = es.search(
            index=sess_idx, size=20,
            _source=["cowrie.session_id"],
            query=base_q,
            sort=[{"dshield.cowrie.enrichment.session.command_count": {"order": "desc"}}],
        )
        sids = [
            (h["_source"].get("cowrie") or {}).get("session_id")
            for h in sids_resp["hits"]["hits"]
        ]
        sids = [s for s in sids if s]
        if sids:
            raw_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
            # `process.command_line` is the canonical raw-command field
            # (matches the rest of this module's command-input queries).
            # We resolve the agg-safe variant so a legacy index with a
            # `.keyword` sub-field still works.
            cmd_field = _resolve_agg_field(es, raw_idx, "process.command_line")
            cmd_resp = es.search(
                index=raw_idx, size=0,
                query={"bool": {"filter": [
                    {"term": {"event.action": "cowrie.command.input"}},
                    {"terms": {"cowrie.session_id": sids}},
                ]}},
                aggs={"by_cmd": {"terms": {"field": cmd_field, "size": 5}}},
            )
            for b in (cmd_resp.get("aggregations", {}).get("by_cmd") or {}).get("buckets", []):
                cl = (b.get("key") or "")[:120]
                if cl:
                    sample_commands.append(cl)
    except Exception as exc:
        log.debug("lookup_playbook sample_commands failed for %s: %s", playbook_id, exc)

    return {
        "id":              playbook_id,
        "name":            name,
        "cluster_size":    size,
        "session_count":   sess_hits["hits"]["total"]["value"],
        "ip_count":        distinct_ips,
        "first_seen":      first_seen,
        "last_seen":       last_seen,
        "last_24h":        last_24h,
        "prior_24h":       prior_24h,
        "top_countries":   top_countries,
        "top_asns":        top_asns,
        "top_intents":     top_intents,
        "sample_commands": sample_commands,
        "sample_ips":      sample_ips_in_sample,
        "sample_sessions": sample_sessions,
    }


# ----------------------------------------------------------------------------
# Related-rows queries (paginated tables for the detail panel)
# ----------------------------------------------------------------------------

def sessions_for_ip(
    es: Elasticsearch, cfg: AppConfig, ip: str, *,
    size: int = 50, frm: int = 0,
    sf: SessionFilter | None = None,
) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    must: list[dict] = [{"term": {"source.ip": ip}}]
    if sf:
        must.extend(sf.es_filters())
    return es.search(
        index=idx, from_=frm, size=size, _source=_src(),
        query={"bool": {"must": must}},
        sort=[{"event.start": {"order": "desc"}}],
    )


def commands_for_session(
    es: Elasticsearch, cfg: AppConfig, session_id: str, *, size: int = 50,
) -> dict:
    """Pull command-input events for the session from sessions_raw, then look
    up enrichment for each unique hash. Returns rows: [{command_line, hash,
    enrichment?}, ...]."""
    raw_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
    enr_idx = cfg.elasticsearch.indexes.cowrie.commands

    try:
        raw = es.search(
            index=raw_idx, size=min(size * 4, 500), _source=["process.command_line", "process.hash.sha256", "@timestamp", "event.action"],
            query={"bool": {"must": [
                {"term": {"cowrie.session_id": session_id}},
                {"term": {"event.action": "cowrie.command.input"}},
            ]}},
            sort=[{"@timestamp": {"order": "asc"}}],
        )
    except NotFoundError:
        log.warning("sessions_raw index %s missing; returning empty commands_for_session", raw_idx)
        return {"rows": [], "total": 0}
    rows: list[dict] = []
    hashes: list[str] = []
    for h in raw["hits"]["hits"]:
        src = h["_source"]
        cmd = (src.get("process") or {}).get("command_line")
        sha = ((src.get("process") or {}).get("hash") or {}).get("sha256")
        if not cmd:
            continue
        # Raw SO docs typically don't carry the sha; the worker computes it
        # during enrichment. Mirror that hash so we can join to enrichment.
        if not sha:
            sha = _hash_command(cmd)
        rows.append({
            "ts": src.get("@timestamp"),
            "command_line": cmd,
            "sha256": sha,
        })
        if sha:
            hashes.append(sha)

    enrichment: dict[str, dict] = {}
    if hashes:
        e = es.search(
            index=enr_idx, size=min(len(hashes), 500), _source=_src(),
            query={"terms": {"process.hash.sha256": list(set(hashes))}},
        )
        for h in e["hits"]["hits"]:
            sha = ((h["_source"].get("process") or {}).get("hash") or {}).get("sha256")
            if sha:
                enrichment[sha] = h["_source"]

    for row in rows:
        if row.get("sha256") and row["sha256"] in enrichment:
            full = enrichment[row["sha256"]]
            row["enrichment"] = full.get("dshield", {}).get("cowrie", {}).get("enrichment")
    return {"rows": rows[:size], "total": raw["hits"]["total"]["value"]}


def sessions_for_command(
    es: Elasticsearch, cfg: AppConfig, sha256: str, *,
    size: int = 50,
    sf: SessionFilter | None = None,
) -> dict:
    """Sessions that ran a given command (by hash).

    Raw cowrie events don't carry `process.hash.sha256` — the enricher
    computes it. The enricher also NORMALIZES the command_line before
    hashing (whitespace strip + collapse). So a term-match against raw
    `process.command_line` using the enriched (normalized) value fails for
    every command whose raw form has a trailing newline, double space, or
    other whitespace that normalisation collapsed. Cowrie's `command.input`
    events very commonly include a trailing space, so this hit ~every
    multi-line command in practice (and was the root cause of the
    "commands not linked to sessions" symptom in Prism).

    Strategy: use a prefix query on the normalised line as a cheap filter
    in ES, then re-hash each candidate raw command_line client-side and
    keep the ones whose hash actually matches. The prefix is bounded so
    keyword-field prefix queries stay fast; the in-Python hash uses the
    SAME `_hash_command` the session anchor already uses for the inverse
    direction, so both joins are now symmetric.
    """
    raw_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
    enr_idx = cfg.elasticsearch.indexes.cowrie.commands

    # Step 1: resolve sha -> normalized command_line via the enriched doc.
    try:
        e = es.search(
            index=enr_idx, size=1, _source=["process.command_line"],
            query={"term": {"process.hash.sha256": sha256}},
        )
        hits = e["hits"]["hits"]
        norm_cmd = ((hits[0]["_source"].get("process") or {}).get("command_line")) if hits else None
    except Exception:
        norm_cmd = None
    if not norm_cmd:
        return {"rows": [], "total": 0}

    # Step 2: prefix-narrow on raw events. The prefix is the first 120 chars
    # of the normalised line; ES keyword prefix queries are O(log n) on the
    # term dictionary so this stays fast. We over-fetch (size * 20, capped)
    # so the Python-side hash filter has enough candidates to find `size`
    # distinct sessions even when the prefix is shared by other commands.
    prefix = norm_cmd[:120]
    fetch = max(size * 20, 500)
    try:
        r = es.search(
            index=raw_idx, size=fetch,
            _source=["process.command_line", "cowrie.session_id"],
            query={"bool": {"must": [
                {"prefix": {"process.command_line": prefix}},
                {"term": {"event.action": "cowrie.command.input"}},
            ]}},
        )
    except NotFoundError:
        log.warning("sessions_raw index %s missing; returning empty sessions_for_command", raw_idx)
        return {"rows": [], "total": 0}

    # Step 3: hash each candidate raw command_line and keep the matches.
    by_session: dict[str, int] = {}
    for h in r["hits"]["hits"]:
        src = h["_source"]
        cmd = (src.get("process") or {}).get("command_line")
        sid = (src.get("cowrie") or {}).get("session_id")
        if not cmd or not sid:
            continue
        if _hash_command(cmd) != sha256:
            continue
        by_session[sid] = by_session.get(sid, 0) + 1
    rows = [{"session_id": sid, "command_count": cnt} for sid, cnt in by_session.items()]
    rows.sort(key=lambda x: -x["command_count"])
    rows = rows[:size]

    # Step 4: optional session-quality filter. Cross-reference against
    # sessions_rollup with the filter clauses, then keep only rows whose
    # session_id is in the filtered set.
    if sf and sf.active and rows:
        sids = [x["session_id"] for x in rows]
        rollup_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
        try:
            r2 = es.search(
                index=rollup_idx, size=len(sids),
                _source=["cowrie.session_id"],
                query={"bool": {"must": [
                    {"terms": {"cowrie.session_id": sids}},
                    *sf.es_filters(),
                ]}},
            )
            keep = {h["_source"].get("cowrie", {}).get("session_id") for h in r2["hits"]["hits"]}
            rows = [x for x in rows if x["session_id"] in keep]
        except Exception as e:
            log.warning("session quality filter join failed: %s", e)

    return {"rows": rows, "total": len(rows)}


# ----------------------------------------------------------------------------
# Cluster-anchored investigation pivots (ROADMAP #4)
#
# "Where else has this IP / command shown up, and is it distinctive to this
# cluster or commodity?" Specificity is precomputed on the session-cluster
# centroid docs (ip_specificity / command_specificity flattened maps); the
# pivot lookups read cross-cluster footprints from the session rollup.
# ----------------------------------------------------------------------------

_PB_ID_PATH = "dshield.cowrie.enrichment.session.playbook_id"
_PB_NAME_PATH = "dshield.cowrie.enrichment.session.playbook_name"
_CMD_SET_PATH = "dshield.cowrie.enrichment.session.command_set.keyword"
_INTEL_LABEL_PATH = "dshield.cowrie.enrichment.session.source_ip_intel.consensus_label"


def playbook_specificity_maps(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str,
) -> tuple[dict[str, float], dict[str, float]]:
    """Merge `ip_specificity` / `command_specificity` across every centroid
    doc carrying this playbook_id (a playbook can span >1 cluster). Keeps the
    max score per key. Returns `(ip_scores, command_scores)` — possibly empty
    if the cluster pass hasn't yet written specificity for this playbook."""
    idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    ip_scores: dict[str, float] = {}
    cmd_scores: dict[str, float] = {}
    try:
        field = _resolve_agg_field(es, idx, "playbook_id")
        r = es.search(
            index=idx, size=100,
            _source=["ip_specificity", "command_specificity"],
            query={"bool": {"must": [
                {"term": {"doc_type": "cluster"}},
                {"term": {field: playbook_id}},
            ]}},
        )
    except Exception as exc:  # pragma: no cover -- network paths
        log.warning("specificity maps lookup failed for %s: %s", playbook_id, exc)
        return ip_scores, cmd_scores
    for h in r["hits"]["hits"]:
        src = h["_source"]
        for store, key in ((ip_scores, "ip_specificity"), (cmd_scores, "command_specificity")):
            for k, v in (src.get(key) or {}).items():
                try:
                    fv = float(v)
                except (TypeError, ValueError):
                    continue
                if fv > store.get(k, -1.0):
                    store[k] = fv
    return ip_scores, cmd_scores


def _playbooks_for_sessions(
    es: Elasticsearch, cfg: AppConfig, base_query: dict, *, size: int = 25,
) -> list[dict]:
    """Playbooks (with names + session counts) over the sessions matched by
    `base_query`. Drives the IP / command pivot 'also appears in' list."""
    sess_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    pb_field = _resolve_agg_field(es, sess_idx, _PB_ID_PATH)
    try:
        r = es.search(
            index=sess_idx, size=0, query=base_query,
            aggs={"pb": {
                "terms": {"field": pb_field, "size": size},
                "aggs": {"name": {"top_hits": {"size": 1, "_source": [_PB_NAME_PATH]}}},
            }},
        )
    except Exception as exc:  # pragma: no cover
        log.warning("playbooks-for-sessions agg failed: %s", exc)
        return []
    out: list[dict] = []
    for b in r["aggregations"]["pb"]["buckets"]:
        hits = b["name"]["hits"]["hits"]
        name = None
        if hits:
            name = (((hits[0]["_source"].get("dshield") or {}).get("cowrie") or {})
                    .get("enrichment", {}).get("session", {}).get("playbook_name"))
        out.append({
            "playbook_id": b["key"], "playbook_name": name,
            "session_count": int(b["doc_count"]),
        })
    return out


def ip_activity(es: Elasticsearch, cfg: AppConfig, ip: str) -> dict:
    """Cross-cluster footprint for an IP: playbooks + campaigns it belongs to,
    total sessions, first/last seen, intel verdict. ROADMAP #4."""
    sess_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    camp_idx = cfg.elasticsearch.indexes.cowrie.campaigns
    base = {"term": {"source.ip": ip}}
    total = 0
    first_seen = last_seen = verdict = None
    try:
        r = es.search(index=sess_idx, size=1, query=base,
                      _source=[_INTEL_LABEL_PATH],
                      sort=[{"event.start": {"order": "desc"}}],
                      aggs={"first": {"min": {"field": "event.start"}},
                            "last": {"max": {"field": "event.start"}}})
        total = int(r["hits"]["total"]["value"])
        first_seen = r["aggregations"]["first"].get("value_as_string")
        last_seen = r["aggregations"]["last"].get("value_as_string")
        hits = r["hits"]["hits"]
        if hits:
            verdict = (((hits[0]["_source"].get("dshield") or {}).get("cowrie") or {})
                       .get("enrichment", {}).get("session", {})
                       .get("source_ip_intel", {}).get("consensus_label"))
    except Exception as exc:  # pragma: no cover
        log.warning("ip_activity sessions agg failed for %s: %s", ip, exc)
    playbooks = _playbooks_for_sessions(es, cfg, base)
    campaigns: list[dict] = []
    try:
        cr = es.search(index=camp_idx, size=25, _source=["campaign_id", "name"],
                       query={"term": {"member_source_ips": ip}})
        campaigns = [{"campaign_id": h["_source"].get("campaign_id"),
                      "name": h["_source"].get("name")} for h in cr["hits"]["hits"]]
    except Exception:
        pass
    return {
        "ip": ip, "total_sessions": total,
        "first_seen": first_seen, "last_seen": last_seen,
        "intel_verdict": verdict, "playbooks": playbooks, "campaigns": campaigns,
    }


def command_activity(
    es: Elasticsearch, cfg: AppConfig, short_hash: str, *, sample: int = 10,
) -> dict:
    """Cross-cluster footprint for a command (by its 16-hex short id =
    command_set key): sessions / playbooks / IPs that ran it, occurrence
    count, sample sessions. ROADMAP #4."""
    sess_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    base = {"term": {_CMD_SET_PATH: short_hash}}
    command_line = intent = None
    occurrence = None
    doc = lookup_command(es, cfg, short_hash)
    if doc:
        enr = ((doc["_source"].get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
        command_line = ((doc["_source"].get("process") or {}).get("command_line"))
        intent = enr.get("intent")
        occurrence = enr.get("occurrence_count")
    total = 0
    ips: list[dict] = []
    samples: list[str] = []
    try:
        r = es.search(index=sess_idx, size=sample, query=base,
                      _source=["cowrie.session_id"],
                      aggs={"by_ip": {"terms": {"field": "source.ip", "size": 25}}})
        total = int(r["hits"]["total"]["value"])
        ips = [{"ip": b["key"], "session_count": int(b["doc_count"])}
               for b in r["aggregations"]["by_ip"]["buckets"]]
        samples = [((h["_source"].get("cowrie") or {}).get("session_id"))
                   for h in r["hits"]["hits"]]
        samples = [s for s in samples if s]
    except Exception as exc:  # pragma: no cover
        log.warning("command_activity agg failed for %s: %s", short_hash, exc)
    playbooks = _playbooks_for_sessions(es, cfg, base)
    return {
        "command_id": short_hash, "command_line": command_line,
        "intent": intent, "occurrence_count": occurrence,
        "total_sessions": total, "playbooks": playbooks, "ips": ips,
        "sample_session_ids": samples,
    }


def playbook_distinctive(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str, *, top_n: int = 20,
) -> dict:
    """Top-N most cluster-specific IPs + commands for a playbook, read from the
    persisted specificity maps and ranked by score desc. Command text is joined
    by `_id` (= the 16-hex command_set key). ROADMAP #4."""
    ip_scores, cmd_scores = playbook_specificity_maps(es, cfg, playbook_id)
    top_ips = sorted(ip_scores.items(), key=lambda kv: -kv[1])[:top_n]
    top_cmds = sorted(cmd_scores.items(), key=lambda kv: -kv[1])[:top_n]

    cmd_text: dict[str, str] = {}
    if top_cmds:
        try:
            cr = es.search(
                index=cfg.elasticsearch.indexes.cowrie.commands,
                size=len(top_cmds), _source=["process.command_line"],
                query={"terms": {"_id": [h for h, _ in top_cmds]}},
            )
            for h in cr["hits"]["hits"]:
                line = ((h["_source"].get("process") or {}).get("command_line")) or ""
                cmd_text[h["_id"]] = line[:240]
        except Exception as exc:  # pragma: no cover
            log.warning("distinctive command-text join failed for %s: %s", playbook_id, exc)
    return {
        "playbook_id": playbook_id,
        "ips": [{"ip": ip, "specificity": sc} for ip, sc in top_ips],
        "commands": [{"command_id": h, "specificity": sc,
                      "command": cmd_text.get(h, "")} for h, sc in top_cmds],
    }


def members_of_cluster(
    es: Elasticsearch, cfg: AppConfig, kind: str, cluster_id: str, *,
    size: int = 50,
    sf: SessionFilter | None = None,
) -> dict:
    field_map = {
        "command": ("commands", "dshield.cowrie.enrichment.cluster.id"),
        "session": ("sessions_rollup", "dshield.cowrie.enrichment.session.cluster.id"),
        "ip":      ("ips_rollup", "dshield.cowrie.enrichment.ip.cluster.id"),
    }
    attr, field = field_map[kind]
    idx = getattr(cfg.elasticsearch.indexes.cowrie, attr)
    sort_field = {
        "command": "dshield.cowrie.enrichment.occurrence_count",
        "session": "dshield.cowrie.enrichment.session.command_count",
        "ip":      "dshield.cowrie.enrichment.ip.total_sessions",
    }[kind]
    must: list[dict] = [{"term": {field: cluster_id}}]
    if kind == "session" and sf:
        must.extend(sf.es_filters())
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"bool": {"must": must}},
        sort=[{sort_field: {"order": "desc", "missing": "_last"}}],
    )


def playbooks_for_ip(
    es: Elasticsearch, cfg: AppConfig, ip: str, *, size: int = 50,
) -> list[dict]:
    """All playbooks this IP ran, derived from its sessions.

    Aggregates over the sessions rollup filtered by source.ip, buckets on
    `playbook_id`, then decorates each bucket with the LLM display name from
    the session-cluster centroid. Returns `[{id, name, session_count,
    first_seen, last_seen}, ...]` sorted by session_count desc.

    Playbook membership isn't stored on the IP doc — the answer is derived
    through the sessions the IP produced.
    """
    sess_idx     = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    pb_field     = _resolve_agg_field(
        es, sess_idx, "dshield.cowrie.enrichment.session.playbook_id",
    )
    try:
        r = es.search(
            index=sess_idx, size=0,
            query={"term": {"source.ip": ip}},
            aggs={"by_playbook": {
                "terms": {"field": pb_field, "size": size, "min_doc_count": 1},
                "aggs": {
                    "first_seen": {"min": {"field": "event.start"}},
                    "last_seen":  {"max": {"field": "event.start"}},
                },
            }},
        )
        buckets = r["aggregations"]["by_playbook"]["buckets"]
    except Exception as exc:
        log.warning("playbooks_for_ip agg failed for %s: %s", ip, exc)
        return []
    if not buckets:
        return []
    pb_ids = [b["key"] for b in buckets if b.get("key")]
    # Names from the session rollup (authoritative post-cutover) — see _playbook_names.
    name_map = _playbook_names(es, cfg, pb_ids)
    rows: list[dict] = []
    for b in buckets:
        pid = b.get("key")
        if not pid:
            continue
        fs = (b.get("first_seen") or {}).get("value_as_string")
        ls = (b.get("last_seen")  or {}).get("value_as_string")
        rows.append({
            "id":            pid,
            "name":          name_map.get(pid, ""),
            "session_count": b["doc_count"],
            "first_seen":    fs,
            "last_seen":     ls,
        })
    return rows


def ips_for_playbook(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str, *, size: int = 50,
) -> dict:
    """Return the IPs that contributed sessions to this playbook.

    Because playbooks live at the session-cluster layer, the IPs for a
    playbook are *derived*: collect the source IPs of every session in the
    playbook, then look those IPs up in the rollup so we get their full
    enrichment. Implemented as a terms agg over sessions then a `terms`
    lookup against the IP rollup.
    """
    sess_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    ips_idx  = cfg.elasticsearch.indexes.cowrie.ips_rollup
    pb_field = _resolve_agg_field(
        es, sess_idx, "dshield.cowrie.enrichment.session.playbook_id",
    )
    try:
        r = es.search(
            index=sess_idx, size=0,
            query={"term": {pb_field: playbook_id}},
            aggs={"src_ips": {"terms": {"field": "source.ip", "size": size}}},
        )
        ip_list = [b["key"] for b in r["aggregations"]["src_ips"]["buckets"]]
    except Exception:
        ip_list = []
    if not ip_list:
        return {"hits": {"hits": [], "total": {"value": 0}}}
    return es.search(
        index=ips_idx, size=len(ip_list), _source=_src(),
        query={"terms": {"source.ip": ip_list}},
        sort=[{"dshield.cowrie.enrichment.ip.total_sessions": {"order": "desc"}}],
    )


def sessions_for_playbook(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str, *,
    size: int = 50,
    sf: SessionFilter | None = None,
) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    pb_field = _resolve_agg_field(
        es, idx, "dshield.cowrie.enrichment.session.playbook_id",
    )
    must: list[dict] = [{"term": {pb_field: playbook_id}}]
    if sf:
        must.extend(sf.es_filters())
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"bool": {"must": must}},
        sort=[{"event.start": {"order": "desc"}}],
    )


def ips_for_asn(es: Elasticsearch, cfg: AppConfig, asn: str, *, size: int = 50) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"term": {"source.as.number": int(asn)}},
        sort=[{"dshield.cowrie.enrichment.ip.total_sessions": {"order": "desc"}}],
    )


def ips_for_country(es: Elasticsearch, cfg: AppConfig, cc: str, *, size: int = 50) -> dict:
    idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
    return es.search(
        index=idx, size=size, _source=_src(),
        query={"term": {"source.geo.country_iso_code": cc}},
        sort=[{"dshield.cowrie.enrichment.ip.total_sessions": {"order": "desc"}}],
    )


# ----------------------------------------------------------------------------
# Free-text search (fallback when query isn't a typed pattern)
# ----------------------------------------------------------------------------

def freetext_search(es: Elasticsearch, cfg: AppConfig, q: str, *, size: int = 25) -> list[dict]:
    """Multi-index search across command_line + playbook names + campaign names.

    Returns shallow candidate IOCRef-like dicts the API forwards to the client
    for disambiguation.
    """
    idx = cfg.elasticsearch.indexes
    candidates: list[dict] = []

    # 1. command lines (most useful free-text target).
    # Use a bool/should so:
    #   a) match — fast full-text token match (works for whole words / multiple tokens)
    #   b) wildcard on .keyword — substring match for partial words that the standard
    #      tokenizer keeps intact (e.g. "lsb" matching "lsb_release", "_release"
    #      matching any command containing that substring).
    # Escape wildcard special chars in user input so `?` / `*` aren't interpreted.
    q_esc = q.replace("\\", "\\\\").replace("?", "\\?").replace("*", "\\*")
    r = es.search(
        index=idx.cowrie.commands, size=size, _source=["process.command_line", "process.hash.sha256"],
        query={"bool": {"should": [
            {"match": {"process.command_line": {"query": q, "boost": 2}}},
            {"wildcard": {"process.command_line.keyword": {
                "value": f"*{q_esc}*",
                "case_insensitive": True,
            }}},
        ], "minimum_should_match": 1}},
    )
    for h in r["hits"]["hits"]:
        src = h["_source"]
        cmd = (src.get("process") or {}).get("command_line", "")
        sha = ((src.get("process") or {}).get("hash") or {}).get("sha256")
        if not sha:
            continue
        candidates.append({
            "type": "command_hash",
            "id": sha,
            "label": (cmd[:80] + ("…" if len(cmd) > 80 else "")) or sha[:12],
            "score": h.get("_score", 0),
        })

    # 2. Playbook names live on session-cluster centroid docs. Each centroid
    # carries a `playbook_id` (the canonical primary key) plus a display
    # `playbook_name` from the LLM. With cluster merging enabled multiple
    # centroid docs can share one playbook_id (and identical name) — we
    # collapse those to a single dropdown candidate keyed on playbook_id.
    # Distinct playbooks with identical display names still surface as
    # separate candidates and get a disambiguating suffix.
    # Match playbook display names on the SESSION ROLLUP (authoritative post-cutover) —
    # the session-cluster centroids only carry the novel pool now, scoped to the latest
    # run, so a name search there misses every established playbook. Aggregate by
    # playbook_id; the modal playbook_name is the label, session count is the rank.
    sess_idx   = idx.cowrie.sessions_rollup
    pb_field   = _resolve_agg_field(es, sess_idx, "dshield.cowrie.enrichment.session.playbook_id")
    name_field = "dshield.cowrie.enrichment.session.playbook_name"
    name_q = {"bool": {"should": [
        {"term":     {name_field: q}},
        {"wildcard": {name_field: {"value": f"*{q_esc}*", "case_insensitive": True}}},
    ], "minimum_should_match": 1}}
    pb_buckets: list[dict] = []
    try:
        r = es.search(
            index=sess_idx, size=0, query=name_q,
            aggs={"by_pb": {
                "terms": {"field": pb_field, "size": 20},
                "aggs": {"name": {"terms": {"field": name_field, "size": 1}}},
            }},
        )
        pb_buckets = r["aggregations"]["by_pb"]["buckets"]
    except Exception:
        pb_buckets = []
    pb_names = _names_from_pb_buckets(pb_buckets)
    # Disambiguate distinct playbooks sharing a display name (suffix the id tail).
    name_to_pids: dict[str, set[str]] = {}
    for pid, nm in pb_names.items():
        name_to_pids.setdefault(nm, set()).add(pid)
    for b in pb_buckets:
        pid = b.get("key")
        if not pid:
            continue
        nm = pb_names.get(pid) or "(unnamed)"
        suffix = f" · {pid[-6:]}" if len(name_to_pids.get(nm, ())) > 1 else ""
        candidates.append({
            "type":  "playbook",
            "id":    pid,
            "label": f"playbook: {nm}{suffix}",
            "score": int(b.get("doc_count") or 0),
        })

    # 2b. Multi-session campaigns mined by `mine campaigns`. Has its own
    # index with its own `campaign_id` keyword. Same wildcard/exact pattern
    # as playbook search.
    camp_idx = idx.cowrie.campaigns
    try:
        r = es.search(
            index=camp_idx, size=10,
            _source=["campaign_id", "name", "kind", "ip_count", "session_count"],
            query={"bool": {"must": [
                {"term": {"doc_type": "campaign"}},
                {"bool": {"should": [
                    {"term":     {"name": q}},
                    {"wildcard": {"name": {"value": f"*{q_esc}*", "case_insensitive": True}}},
                ], "minimum_should_match": 1}},
            ]}},
        )
        cam_hits = r["hits"]["hits"]
    except Exception:
        cam_hits = []
    for h in cam_hits:
        src = h["_source"]
        cid  = src.get("campaign_id")
        nm   = src.get("name") or "(unnamed)"
        kind = src.get("kind") or "?"
        if not cid:
            continue
        candidates.append({
            "type":  "campaign",
            "id":    cid,
            "label": f"campaign [{kind}]: {nm}",
            "score": h.get("_score", 0),
        })

    # 3. Cluster IDs (name-style: "cluster_11", "outlier") across all three
    # cluster indices.  Uses prefix + term so partial names work too.
    for cl_idx, cl_kind, cl_type in [
        (idx.cowrie.session_clusters, "session", "session_cluster"),
        (idx.cowrie.ip_clusters,      "ip",      "ip_cluster"),
        (idx.cowrie.command_clusters, "command",  "command_cluster"),
    ]:
        run_cache_obj = RunCache(ttl_seconds=60)
        run_id = run_cache_obj.latest(es, cl_idx)
        must_clauses: list[dict] = [{"term": {"doc_type": "cluster"}}]
        if run_id:
            must_clauses.append({"term": {"run_id": run_id}})
        must_clauses.append({"bool": {"should": [
            {"term":   {"cluster_id": q.lower()}},
            {"prefix": {"cluster_id": q.lower()}},
        ], "minimum_should_match": 1}})
        # `playbook_name` only exists on session_clusters; other cluster
        # indexes ignore the field gracefully.
        try:
            r = es.search(index=cl_idx, size=5,
                          _source=["cluster_id", "playbook_name"],
                          query={"bool": {"must": must_clauses}})
        except Exception:
            continue
        for h in r["hits"]["hits"]:
            cid = h["_source"].get("cluster_id")
            if not cid:
                continue
            pb_name = h["_source"].get("playbook_name")
            label = f"{cl_kind} cluster {cid}" + (f" · {pb_name}" if pb_name else "")
            candidates.append({
                "type": cl_type,
                "id":    cid,
                "label": label,
                "score": 0.5,
            })

    # 4. Dropped files by name (ROADMAP #3/#2). Nested file_events on the
    # session rollup, matched on the attacker-facing filename (match + keyword
    # wildcard, same pattern as command lines). One candidate per distinct sha,
    # labelled with a representative filename; anchors the file node directly.
    try:
        r = es.search(index=idx.cowrie.sessions_rollup, size=0, query={"match_all": {}}, aggs={
            "fe": {"nested": {"path": _FE_PATH}, "aggs": {
                "m": {"filter": {"bool": {"should": [
                    {"match": {f"{_FE_PATH}.filename": q}},
                    {"wildcard": {f"{_FE_PATH}.filename.keyword": {
                        "value": f"*{q_esc}*", "case_insensitive": True}}},
                ], "minimum_should_match": 1}}, "aggs": {
                    "by_sha": {"terms": {"field": f"{_FE_PATH}.sha256", "size": 15}, "aggs": {
                        "fn": {"terms": {"field": f"{_FE_PATH}.filename.keyword", "size": 1}},
                    }},
                }},
            }},
        })
        file_buckets = (
            r.get("aggregations", {}).get("fe", {}).get("m", {})
            .get("by_sha", {}).get("buckets", [])
        ) or []
    except Exception:
        file_buckets = []
    for b in file_buckets:
        sha = b.get("key")
        if not sha:
            continue
        fn_b = b.get("fn", {}).get("buckets", [])
        fn = fn_b[0]["key"] if fn_b else sha[:12]
        candidates.append({
            "type": "file", "id": sha,
            "label": f"file: {fn}", "score": 1.5,
        })

    candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
    return candidates[:size]


# ----------------------------------------------------------------------------
# Health
# ----------------------------------------------------------------------------

def health(es: Elasticsearch, cfg: AppConfig) -> dict:
    info = es.info()
    indexes = cfg.elasticsearch.indexes.cowrie.model_dump()
    counts: dict[str, Any] = {}
    for name, idx in indexes.items():
        try:
            counts[name] = es.count(index=idx).get("count", 0)
        except Exception as e:
            counts[name] = f"error: {e.__class__.__name__}"

    # Freshest @timestamp across the analyst-visible rollup indices —
    # drives the topbar's "data Xm ago" indicator. Sessions + IP rollups
    # update on every backward cycle; whichever is fresher wins.
    last_data_ts: str | None = None
    for key in ("sessions_rollup", "ips_rollup"):
        idx = indexes.get(key)
        if not idx:
            continue
        try:
            r = es.search(
                index=idx, size=0,
                aggs={"max_ts": {"max": {"field": "@timestamp"}}},
            )
            ts = r["aggregations"]["max_ts"].get("value_as_string")
            if ts and (last_data_ts is None or ts > last_data_ts):
                last_data_ts = ts
        except Exception:
            pass

    return {
        "elasticsearch_version": info.get("version", {}).get("number"),
        "cluster_name": info.get("cluster_name"),
        "indexes": indexes,
        "doc_counts": counts,
        "last_data_ts": last_data_ts,
    }


def health_freshness(es: Elasticsearch, cfg: AppConfig) -> list[dict]:
    """Per-index freshness for the /health page.

    For each index (cowrie rollup + cluster + findings + intel), return
    `{name, idx, doc_count, last_ts}` where `last_ts` is the max
    @timestamp in that index. None means the index doesn't exist yet
    or the aggregation failed. Cheap — one size:0 search per index.
    """
    rows: list[dict] = []

    def _probe(name: str, idx: str) -> None:
        if not idx:
            return
        doc_count: int | None
        last_ts: str | None
        try:
            doc_count = es.count(index=idx).get("count", 0)
        except Exception:
            doc_count = None
        try:
            r = es.search(
                index=idx, size=0,
                aggs={"max_ts": {"max": {"field": "@timestamp"}}},
            )
            last_ts = r["aggregations"]["max_ts"].get("value_as_string")
        except Exception:
            last_ts = None
        rows.append({
            "name": name, "idx": idx,
            "doc_count": doc_count, "last_ts": last_ts,
        })

    cowrie = cfg.elasticsearch.indexes.cowrie.model_dump()
    for name, idx in cowrie.items():
        _probe(name, idx)
    _probe("findings", cfg.findings.indexes.default)
    intel = cfg.intel.indexes.model_dump()
    for name, idx in intel.items():
        _probe(f"intel_{name}", idx)
    return rows


def health_runs(es: Elasticsearch, cfg: AppConfig) -> list[dict]:
    """Most recent run_summary doc from each cluster index. Each entry
    is `{verb, idx, run_id, ts, total_docs, n_clusters, n_outliers}`.
    Indices without run_summary docs (or that don't exist) yield None
    fields so the UI can render a "never run" placeholder.
    """
    idxs = cfg.elasticsearch.indexes.cowrie
    targets = [
        ("cluster commands", idxs.command_clusters),
        ("cluster sessions", idxs.session_clusters),
        ("cluster ips",      idxs.ip_clusters),
    ]
    rows: list[dict] = []
    for verb, idx in targets:
        row: dict = {"verb": verb, "idx": idx}
        try:
            r = es.search(
                index=idx, size=1,
                _source=["run_id", "@timestamp", "total_docs",
                         "n_clusters", "n_outliers"],
                query={"term": {"doc_type": "run_summary"}},
                sort=[{"@timestamp": {"order": "desc"}}],
            )
            hits = r["hits"]["hits"]
            src = hits[0]["_source"] if hits else {}
        except Exception:
            src = {}
        row.update({
            "run_id":     src.get("run_id"),
            "ts":         src.get("@timestamp"),
            "total_docs": src.get("total_docs"),
            "n_clusters": src.get("n_clusters"),
            "n_outliers": src.get("n_outliers"),
        })
        rows.append(row)
    return rows


def health_overview(es: Elasticsearch, cfg: AppConfig) -> dict:
    """Corpus-summary stat bar for the Health page's Overview section
    (formerly Browse/Insights' top stat bar). Returns
    `{total_ips, total_sessions, total_commands, active_playbooks,
    total_clusters, total_outliers}`. Cluster/outlier totals are summed
    from `health_runs()` rather than re-running a separate per-verb
    run_summary query — `health_runs()` is already the canonical "latest
    run per cluster verb" source. Every field defaults to 0 on any
    per-query failure so a partial ES outage degrades gracefully instead
    of failing the whole panel.
    """
    idxs = cfg.elasticsearch.indexes.cowrie

    def _count(idx: str) -> int:
        try:
            return es.count(index=idx).get("count", 0)
        except Exception:
            return 0

    total_ips = _count(idxs.ips_rollup)
    total_sessions = _count(idxs.sessions_rollup)
    total_commands = _count(idxs.commands)

    try:
        pb_field = _resolve_agg_field(
            es, idxs.sessions_rollup, "dshield.cowrie.enrichment.session.playbook_id",
        )
        r = es.search(index=idxs.sessions_rollup, size=0, aggs={
            "playbooks": {"cardinality": {"field": pb_field}}
        })
        active_playbooks = r["aggregations"]["playbooks"]["value"]
    except Exception:
        active_playbooks = 0

    total_clusters = 0
    total_outliers = 0
    for row in health_runs(es, cfg):
        total_clusters += row.get("n_clusters") or 0
        total_outliers += row.get("n_outliers") or 0

    return {
        "total_ips":        total_ips,
        "total_sessions":   total_sessions,
        "total_commands":   total_commands,
        "active_playbooks": active_playbooks,
        "total_clusters":   total_clusters,
        "total_outliers":   total_outliers,
    }


# A `status=started` ops doc is patched in place to finished/failed on normal
# exit, so one that's still "started" is either a live verb or a crashed one
# that never got patched. Treat started docs older than this as ghosts, not live
# runs. Default is generous enough to cover a long enrich/backfill, short enough
# to clear a crashed-verb ghost within the hour — and is overridable via
# `ops.pipeline_running_window_min` (raise it for a multi-hour bulk-backfill
# pipeline run, where one `started` doc lives for hours).
_PIPELINE_RUNNING_WINDOW_MIN = 60
# Burst detection (the running-banner's stable elapsed). Each pipeline step is
# its own process, so the "run started at" is the earliest step in the current
# *contiguous* burst. Continuity is measured finished->started (steps run
# back-to-back under flock, sub-second apart) — NOT started->started, because a
# single long step (a backfill `enrich` can be 15 min+) would otherwise look
# like a gap. Two activity bursts more than this many seconds apart are
# distinct runs.
_PIPELINE_BURST_GAP_S = 120
_PIPELINE_BURST_LOOKBACK_H = 6  # bound the scan; a cycle is minutes, not hours


def _current_burst_start(es: Elasticsearch, idx: str) -> str | None:
    """`started_at` of the earliest step in the current contiguous activity
    burst — a server-stable "this run started at" the banner can render elapsed
    from (so it doesn't reset on reload / tab-switch). Walks recent docs newest
    -> oldest and stops at the first finished->started gap > the burst gap.
    """
    try:
        r = es.search(
            index=idx, size=300,
            query={"bool": {"must": [
                {"term": {"kind": "verb_run"}},
                {"range": {"started_at": {"gte": f"now-{_PIPELINE_BURST_LOOKBACK_H}h"}}},
            ]}},
            sort=[{"started_at": {"order": "desc"}}],
            _source=["started_at", "finished_at"],
        )
        docs = [h["_source"] for h in r["hits"]["hits"]]
    except Exception:
        return None
    if not docs:
        return None

    def _parse(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    gap = timedelta(seconds=_PIPELINE_BURST_GAP_S)
    burst_start = docs[0].get("started_at")
    earliest = _parse(burst_start)
    for d in docs[1:]:
        d_started = _parse(d.get("started_at"))
        # An in-flight older step has no finished_at — treat its start as its
        # end for the gap test (it hasn't created a gap yet).
        d_finished = _parse(d.get("finished_at")) or d_started
        if earliest is None or d_finished is None:
            break
        if earliest - d_finished <= gap:
            burst_start = d.get("started_at")
            earliest = d_started
        else:
            break
    return burst_start


def _running_ops(es: Elasticsearch, idx: str,
                 window_min: int = _PIPELINE_RUNNING_WINDOW_MIN) -> list[dict]:
    """`status=started` verb_run docs within the freshness window — the live
    pipeline steps (P4.3 heartbeat). Newest first. Empty on any failure."""
    try:
        r = es.search(
            index=idx, size=25,
            query={"bool": {"must": [
                {"term": {"kind": "verb_run"}},
                {"term": {"status": "started"}},
                {"range": {"started_at": {"gte": f"now-{window_min}m"}}},
            ]}},
            sort=[{"started_at": {"order": "desc"}}],
            _source=["verb", "host", "started_at"],
        )
        return [h["_source"] for h in r["hits"]["hits"]]
    except Exception:
        return []


def pipeline_running(es: Elasticsearch, cfg: AppConfig) -> dict:
    """Live pipeline verbs for the global running-banner (P4.3 heartbeat /
    deferred topbar half of ROADMAP #17.18). Polled site-wide by topbar.js.

    Returns `{"running": [{verb, host, started_at}], "active": bool,
    "since": <earliest started_at>}`. Empty/inactive when `prism.ops` is
    absent or no verb has an in-flight `status=started` doc within the
    freshness window.
    """
    out: dict = {"running": [], "active": False, "since": None}
    idx = cfg.ops.indexes.default
    try:
        if not es.indices.exists(index=idx):
            return out
    except Exception:
        return out
    running = _running_ops(es, idx, cfg.ops.pipeline_running_window_min)
    out["running"] = running
    out["active"] = bool(running)
    if running:
        # Server-stable run start = the earliest step of the current contiguous
        # burst (not the current step, which is always ~0s). The banner renders
        # elapsed from this, so it survives reloads / tab-switches. Fall back to
        # the oldest in-flight step if the burst scan finds nothing.
        out["since"] = _current_burst_start(es, idx) or min(
            r.get("started_at") for r in running if r.get("started_at")
        )
    return out


def health_ops_runs(es: Elasticsearch, cfg: AppConfig) -> dict:
    """Per-verb run telemetry from `prism.ops` (P4.3) — the all-verb companion
    to `health_runs` (which only covers the 3 cluster steps). Surfaces the
    P4.2 sentinel docs the verbs write so the console can show *every* pipeline
    step, not just clustering, plus an in-progress heartbeat.

    Returns `{"rows": [...latest run per verb...], "running": [...in-flight...]}`.
    Each row: `{verb, status, host, started_at, finished_at, duration_s, rc}`.
    A `running` entry is a `status=started` doc not yet patched to
    finished/failed. The `prism.ops` index is optional (created by
    `init-indexes --source ops`); when absent we return empty lists so the
    panel renders a "no telemetry yet" placeholder instead of erroring.
    """
    out: dict = {"rows": [], "running": []}
    idx = cfg.ops.indexes.default
    try:
        if not es.indices.exists(index=idx):
            return out
    except Exception:
        return out

    src_fields = ["verb", "status", "host", "started_at",
                  "finished_at", "duration_s", "rc"]
    # Latest run per verb: one terms bucket per verb, newest doc in each.
    try:
        r = es.search(
            index=idx, size=0,
            query={"term": {"kind": "verb_run"}},
            aggs={"by_verb": {
                "terms": {"field": "verb", "size": 100},
                "aggs": {"latest": {"top_hits": {
                    "size": 1,
                    "sort": [{"started_at": {"order": "desc"}}],
                    "_source": src_fields,
                }}},
            }},
        )
        buckets = r["aggregations"]["by_verb"]["buckets"]
        rows = [b["latest"]["hits"]["hits"][0]["_source"] for b in buckets]
        rows.sort(key=lambda x: x.get("started_at") or "", reverse=True)
        out["rows"] = rows
    except Exception:
        pass

    # In-progress: started but not yet finished/failed, within the freshness
    # window (the heartbeat) — shared with the global running-banner.
    out["running"] = _running_ops(es, idx, cfg.ops.pipeline_running_window_min)

    return out


# ----------------------------------------------------------------------------
# Observability lane for the /health status strip: ES parent-breaker pressure
# and per-sensor data freshness. Both pure classifiers (`_derive_pressure_state`,
# `_sensor_freshness_rows`) take no ES so every I/O-matrix row is unit-testable
# offline; the ES-touching wrappers are best-effort and degrade to a neutral
# state rather than raising into the page. See docs/reference.md.
# ----------------------------------------------------------------------------

def _derive_pressure_state(
    ratio: float | None, high_wm: float, resume_wm: float,
) -> dict:
    """Pure ES-pressure classifier (no ES) — see the spec's I/O matrix.

    `ratio` = the node parent-breaker estimated/limit (0..1) or None; `high_wm`
    / `resume_wm` = the heap high / resume watermarks. States:
      * `unknown` — ratio is None (denied / no stats / import failure) → neutral.
      * `crit`    — ratio >= high watermark.
      * `warn`    — resume <= ratio < high.
      * `ok`      — ratio < resume watermark.
    Returns `{state, ratio, detail}`.
    """
    if ratio is None:
        return {"state": "unknown", "ratio": None,
                "detail": "breaker stats unavailable"}
    pct = f"{ratio * 100:.0f}%"
    if ratio >= high_wm:
        state = "crit"
    elif ratio >= resume_wm:
        state = "warn"
    else:
        state = "ok"
    return {"state": state, "ratio": ratio, "detail": f"heap breaker {pct}"}


def es_pressure(es: Elasticsearch, cfg: AppConfig) -> dict:
    """ES parent-circuit-breaker pressure for the /health status strip.

    Best-effort: a console-only install (no `enrich.es_health`), a denied
    `nodes.stats`, or malformed stats all degrade to `state=unknown` (neutral) —
    `parent_breaker_ratio` never raises and returns None on any failure.
    Returns `{state, ratio, detail}`.
    """
    ratio = _parent_breaker_ratio(es) if _ES_HEALTH_AVAILABLE else None
    return _derive_pressure_state(
        ratio, _ES_HEAP_HIGH_WATERMARK, _ES_HEAP_RESUME_WATERMARK,
    )


def _sensor_freshness_rows(
    agg_buckets: list[dict], now: datetime, stale_min: int,
) -> list[dict]:
    """Pure per-sensor freshness classifier (no ES) — see the spec's I/O matrix.

    `agg_buckets` = the `by_sensor` terms buckets, each
    `{key: <observer.name>, last_ts: {value_as_string: <iso>}}`; `now` = an aware
    datetime; `stale_min` = minutes before a sensor's newest doc is `stale`.
    Returns one `{sensor, last_ts, state}` per bucket (`state` ok|stale). Zero
    buckets → `[]` (the caller renders an empty-state placeholder, not an error).
    A bucket whose ts is missing/unparseable is `stale` — we can't confirm it is
    fresh, so fail safe toward "a sensor may have gone quiet".
    """
    rows: list[dict] = []
    for b in agg_buckets or []:
        last_ts = ((b.get("last_ts") or {}).get("value_as_string"))
        dt = _parse_ops_ts(last_ts)
        if dt is None:
            state = "stale"
        else:
            age_min = (now - dt).total_seconds() / 60.0
            state = "stale" if age_min > stale_min else "ok"
        rows.append({"sensor": b.get("key"), "last_ts": last_ts, "state": state})
    return rows


def sensor_freshness(es: Elasticsearch, cfg: AppConfig) -> dict:
    """Per-sensor data freshness for the /health status strip.

    Terms-aggregates the **sessions rollup** on `observer.name.keyword` (the only
    cowrie rollup carrying `observer.name` — commands has `observer.{type,vendor}`
    only, ips has no `observer` block) with a `max(@timestamp)` sub-agg, then
    classifies each bucket via the pure `_sensor_freshness_rows`. Best-effort:
    any ES error → `{rows: []}` (empty-state), never raises. Renders one row for
    a single-sensor deploy (today: bucket `default`) and one per bucket for N.
    Returns `{rows:[{sensor, last_ts, state}]}`.
    """
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        r = es.search(
            index=idx, size=0,
            aggs={"by_sensor": {
                "terms": {"field": "observer.name.keyword", "size": 100},
                "aggs": {"last_ts": {"max": {"field": "@timestamp"}}},
            }},
        )
        buckets = r["aggregations"]["by_sensor"]["buckets"]
    except Exception:
        return {"rows": []}
    now = datetime.now(timezone.utc)
    return {"rows": _sensor_freshness_rows(buckets, now, cfg.ops.sensor_stale_min)}


# ----------------------------------------------------------------------------
# Pipeline-cycle health for the topbar badge's second dot.
#
# The badge carries two independent signals: ingestion freshness (rollup
# @timestamp, handled by `health()`), and pipeline-CYCLE health — is the
# scheduled backward cycle actually running its verbs? A stalled cycle is
# invisible from ingestion freshness alone until data goes stale hours later.
#
# `_derive_cycle_state` is a PURE function (no ES) so every I/O-matrix row is
# unit-testable offline. `pipeline_cycle_health` does the ES fetch, then calls
# it. See `docs/reference.md` (console Health surface).
# ----------------------------------------------------------------------------

def _parse_ops_ts(s: str | None) -> datetime | None:
    """Parse an ISO-8601 ops timestamp to an aware datetime, or None if
    unparseable/absent. A timestamp lacking a `Z`/offset is assumed UTC so the
    result is always tz-aware — `_derive_cycle_state` subtracts it from an aware
    `now_ts`, and a naive value would raise `TypeError`."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _derive_cycle_state(
    rows: list[dict],
    running: list[dict],
    now_ts: datetime,
    stale_min: int,
) -> dict:
    """Pure cycle-state classifier (no ES) — see the spec's I/O matrix.

    `rows` = the latest `verb_run` per verb `{verb, status, started_at,
    finished_at}`; `running` = in-flight `status=started` docs; `now_ts` = an
    aware datetime; `stale_min` = the freshness threshold in minutes.

    States:
      * `unknown` — no telemetry (no rows) → neutral dot.
      * `warn`    — any latest row `status=failed` (failed verb names in detail).
      * `ok`      — a verb is currently running (recent activity), OR all latest
                    rows finished and the newest is within `stale_min`.
      * `behind`  — newest finished ts older than `stale_min`, none running.

    Returns `{state, detail, newest_ts, failed_verbs}`.
    """
    if not rows:
        return {"state": "unknown", "detail": "no pipeline telemetry",
                "newest_ts": None, "failed_verbs": []}

    failed_verbs = [
        r.get("verb") for r in rows if r.get("status") == "failed" and r.get("verb")
    ]

    # Newest activity timestamp across the latest-per-verb rows. Prefer the
    # finish time; fall back to start for an in-flight/unfinished row.
    newest_dt: datetime | None = None
    newest_iso: str | None = None
    for r in rows:
        for key in ("finished_at", "started_at"):
            dt = _parse_ops_ts(r.get(key))
            if dt is not None and (newest_dt is None or dt > newest_dt):
                newest_dt = dt
                newest_iso = r.get(key)
            if dt is not None:
                break  # prefer a parseable finished_at; else fall back to started_at

    if failed_verbs:
        return {
            "state": "warn",
            "detail": "failed: " + ", ".join(failed_verbs),
            "newest_ts": newest_iso,
            "failed_verbs": failed_verbs,
        }

    # A verb currently in-flight means the schedule is alive — never "behind".
    if running:
        verbs = sorted({r.get("verb") for r in running if r.get("verb")})
        detail = ("running: " + ", ".join(verbs)) if verbs else "running"
        return {"state": "ok", "detail": detail,
                "newest_ts": newest_iso, "failed_verbs": []}

    if newest_dt is None:
        # Rows exist but carry no parseable timestamp — can't judge freshness.
        return {"state": "unknown", "detail": "no run timestamps",
                "newest_ts": None, "failed_verbs": []}

    age_min = (now_ts - newest_dt).total_seconds() / 60.0
    if age_min > stale_min:
        return {
            "state": "behind",
            "detail": f"newest run {int(age_min)}m ago (> {stale_min}m)",
            "newest_ts": newest_iso,
            "failed_verbs": [],
        }
    return {"state": "ok", "detail": "cycle current",
            "newest_ts": newest_iso, "failed_verbs": []}


def pipeline_cycle_health(es: Elasticsearch, cfg: AppConfig) -> dict:
    """Cycle-health signal for the topbar badge's second dot, inferred from
    `prism.ops` `verb_run` telemetry. Fetches the latest run per verb (same
    `by_verb` terms+top_hits agg as `health_ops_runs`) plus the in-flight
    heartbeat, then classifies via the pure `_derive_cycle_state`.

    Graceful: an absent `prism.ops` or any ES error → `{state: "unknown"}`
    (neutral dot). Returns `{state, detail, newest_ts, failed_verbs}`.
    """
    idx = cfg.ops.indexes.default
    src_fields = ["verb", "status", "started_at", "finished_at"]
    try:
        if not es.indices.exists(index=idx):
            return {"state": "unknown", "detail": "no pipeline telemetry",
                    "newest_ts": None, "failed_verbs": []}
        r = es.search(
            index=idx, size=0,
            query={"term": {"kind": "verb_run"}},
            aggs={"by_verb": {
                "terms": {"field": "verb", "size": 100},
                "aggs": {"latest": {"top_hits": {
                    "size": 1,
                    "sort": [{"started_at": {"order": "desc"}}],
                    "_source": src_fields,
                }}},
            }},
        )
        buckets = r["aggregations"]["by_verb"]["buckets"]
        rows = [b["latest"]["hits"]["hits"][0]["_source"] for b in buckets]
        running = _running_ops(es, idx, cfg.ops.pipeline_running_window_min)
    except Exception as exc:  # pragma: no cover -- network paths
        log.warning("pipeline_cycle_health failed: %s", exc)
        return {"state": "unknown", "detail": "telemetry query failed",
                "newest_ts": None, "failed_verbs": []}
    now_ts = datetime.now(timezone.utc)
    return _derive_cycle_state(rows, running, now_ts, cfg.ops.cycle_stale_min)


# ---------------------------------------------------------------------------
# Timeline: session data for the Timeline view.
# ---------------------------------------------------------------------------

_TL_SOURCE = [
    "cowrie.session_id",
    "source.ip",
    "@timestamp",
    "event.start",
    "event.end",
    "dshield.cowrie.enrichment.session.command_count",
    "dshield.cowrie.enrichment.session.dominant_intent",
    "dshield.cowrie.enrichment.session.playbook_id",
    "dshield.cowrie.enrichment.session.playbook_name",
    "dshield.cowrie.enrichment.session.cluster.id",
    "dshield.cowrie.enrichment.session.cluster.is_outlier",
    "dshield.cowrie.enrichment.session.login_success_count",
    "dshield.cowrie.enrichment.session.mean_novelty_score",
]


# --- History ---------------------------------------------------------------
# The History page is the longitudinal lifecycle surface (see `history_summary`
# below): one row per playbook, each its whole activity arc on a shared time axis,
# ranked by an `interest` composite. `_rank_standout` below is the legacy salience
# lens from the earlier "archive discovery" design — retained only for its smoke
# test; the live page no longer calls it.


def _rank_standout(buckets: list[dict], sort_mode: str,
                   name_map: dict, limit: int) -> list[dict]:
    """Rank playbook aggregation buckets for the History 'Standout' section.

    Pure (no ES) so the two ranking lenses are unit-tested directly:
      * ``novel``       — by avg `novelty_score` alone (the anomalous one-offs:
        "show me the strangest thing, even if it ran once").
      * ``novel_reach`` — by `novelty * log1p(distinct_ips)` (anomalous AND
        widespread). distinct-IPs, not session count, is the "actually used"
        signal (spread across the internet, not one noisy IP); the log keeps
        novelty in the driver's seat so this never collapses to a size sort.

    Each bucket: ``{key: playbook_id, doc_count, novelty:{value}, ips:{value},
    first:{value_as_string}, last:{value_as_string}}``. Returns the top `limit`
    display dicts, score-sorted desc.
    """
    import math
    rows: list[dict] = []
    for b in buckets:
        pid = b.get("key")
        if not pid:
            continue
        nov = float((b.get("novelty") or {}).get("value") or 0.0)
        ips = int((b.get("ips") or {}).get("value") or 0)
        score = nov if sort_mode == "novel" else nov * math.log1p(ips)
        rows.append({
            "playbook_id": pid,
            "name":        name_map.get(pid, ""),
            "novelty":     round(nov, 3),
            "sessions":    int(b.get("doc_count") or 0),
            "ips":         ips,
            "first_seen":  (b.get("first") or {}).get("value_as_string"),
            "last_seen":   (b.get("last") or {}).get("value_as_string"),
            "score":       round(score, 4),
        })
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:limit]


def _names_from_pb_buckets(buckets: list[dict]) -> dict:
    """Pure: terms-agg-on-playbook_id buckets (each with a `name` sub-agg of modal
    `playbook_name`) → `{playbook_id: playbook_name}`, dropping empties."""
    out: dict = {}
    for b in buckets:
        pid = b.get("key")
        nb = ((b.get("name") or {}).get("buckets")) or []
        if pid and nb and nb[0].get("key"):
            out[pid] = nb[0]["key"]
    return out


def _playbook_names(es: Elasticsearch, cfg: AppConfig, pb_ids: list[str]) -> dict:
    """`{playbook_id: playbook_name}` — the canonical resolver. Reads from the SESSION
    ROLLUP's `playbook_name`, which is the authoritative per-session label after the
    Option-A cutover (assignment + `name playbooks` both keep it current). The old
    centroid-only source broke once `cluster sessions --novel-pool` stopped refreshing
    `session_clusters` centroids for the assigned bulk (and `prune-clusters` aged them
    out). Falls back to the centroids for any id the rollup can't name."""
    if not pb_ids:
        return {}
    idxs = cfg.elasticsearch.indexes.cowrie
    sess = idxs.sessions_rollup
    pb_field = _resolve_agg_field(es, sess, "dshield.cowrie.enrichment.session.playbook_id")
    name_field = "dshield.cowrie.enrichment.session.playbook_name"
    out: dict = {}
    try:
        r = es.search(
            index=sess, size=0, query={"terms": {pb_field: pb_ids}},
            aggs={"by_pb": {
                "terms": {"field": pb_field, "size": len(pb_ids)},
                "aggs": {"name": {"terms": {"field": name_field, "size": 1}}},
            }},
        )
        out = _names_from_pb_buckets(r["aggregations"]["by_pb"]["buckets"])
    except Exception as e:
        log.warning("playbook-name lookup (rollup) failed: %s", e)
    missing = [p for p in pb_ids if p not in out]
    if missing:  # legacy fallback: session-cluster centroids
        try:
            field = _resolve_agg_field(es, idxs.session_clusters, "playbook_id")
            r = es.search(
                index=idxs.session_clusters,
                size=min(10000, max(len(missing) * 20, 100)),
                _source=["playbook_id", "playbook_name"],
                query={"terms": {field: missing}},
            )
            for h in r["hits"]["hits"]:
                s = h["_source"]
                pid = s.get("playbook_id")
                if pid and pid not in out and s.get("playbook_name"):
                    out[pid] = s["playbook_name"]
        except Exception as e:
            log.warning("playbook-name centroid fallback failed: %s", e)
    return out


# ---- longitudinal History — per-playbook lifecycle scoring (all pure) --------
# The reworked History is a ranked, one-row-per-playbook longitudinal list: each
# row is that playbook's whole activity arc on a SHARED time axis, ranked by a
# composite `interest` score. Weights come straight from the mockup
# (discover-history-v2); kept in one constant so they stay tunable. All ranking /
# recurrence / state logic below is pure (no ES) so it is smoke-tested directly.
_HISTORY_WEIGHTS = {
    "liveness": 0.30, "trend": 0.25, "recurrence": 0.20,
    "mass": 0.15, "escalation": 0.10,
}
_HISTORY_WINDOWS = {"30d": 30, "90d": 90, "180d": 180}
_HISTORY_SORTS = {"interest", "recency", "mass", "trend", "longevity"}
_HISTORY_ENTITIES = {"playbook", "campaign", "session_cluster", "ip_cluster", "operation"}
_HISTORY_POOL_CAP = 250   # max rows; surfaced via scope.capped — never a silent cut
_HISTORY_DEAD_DAYS = 14    # silent this long (real time) at the leading edge → "dead"
_BUCKET_DAYS = {"1d": 1, "7d": 7, "30d": 30, "90d": 90}
_CAMPAIGN_ID_CAP = 6000    # member ids per campaign/operation to band on (keeps msearch light)
_IPCLUSTER_MEMBER_CAP = 200  # top member IPs per ip-cluster (bounds the members sub-agg buckets)


def _pick_interval(span_days: float) -> tuple[str, str]:
    """Adaptive bucket for the shared axis, mirroring the mockup: days<90d ·
    weeks<2y · months<decade · quarters beyond. Returns (fixed_interval, unit)."""
    if span_days <= 92:
        return "1d", "day"
    if span_days <= 731:
        return "7d", "week"
    if span_days <= 3651:
        return "30d", "month"
    return "90d", "quarter"


def _modal_name(agg: dict | None) -> str:
    """First key of a terms sub-agg (the modal label), or ''."""
    bs = (agg or {}).get("buckets") or []
    return bs[0].get("key", "") if bs else ""


def _history_rows(buckets: list[dict], name_map: dict | None, *,
                  kind: str = "playbook") -> list[dict]:
    """Pure: direct-agg terms buckets (each with a `band` date_histogram + ips/first/
    last/novelty sub-aggs) → display rows carrying an aligned integer `band` array.
    Every band shares the same bucket boundaries, so arrays compare directly on one
    axis. Name comes from `name_map` when given, else the bucket's `name` modal
    sub-agg. Keyless buckets are dropped."""
    rows: list[dict] = []
    for b in buckets:
        pid = b.get("key")
        if not pid:
            continue
        band = [
            int(db.get("doc_count") or 0)
            for db in ((b.get("band") or {}).get("buckets") or [])
        ]
        name = name_map.get(pid, "") if name_map is not None else _modal_name(b.get("name"))
        rows.append({
            "id":          pid,
            "kind":        kind,
            "name":        name,
            "sessions":    int(b.get("doc_count") or 0),
            "ips":         int((b.get("ips") or {}).get("value") or 0),
            "novelty":     round(float((b.get("novelty") or {}).get("value") or 0.0), 3),
            "first_seen":  (b.get("first") or {}).get("value_as_string"),
            "last_seen":   (b.get("last") or {}).get("value_as_string"),
            "band":        band,
        })
    return rows


def _band_recurs(band: list[int], gap: int) -> int:
    """Pure: how many times a playbook re-activates after a dormant run of >= `gap`
    empty buckets. One continuous episode → 0; two episodes split by a long gap → 1.
    Leading zeros (before it is ever born) don't count."""
    recurs = born = 0
    zero_run = 0
    for v in band:
        if v > 0:
            if born and zero_run >= gap:
                recurs += 1
            born = 1
            zero_run = 0
        elif born:
            zero_run += 1
    return recurs


def _band_episodes(band: list[int], gap: int) -> list[list[int]]:
    """Pure: the contiguous ALIVE spans as `[start_idx, end_idx]` bucket ranges
    (inclusive). A dormant run shorter than `gap` bridges (still one episode); a run
    of >= `gap` empty buckets ends the episode; leading/trailing zeros are dead. The
    UI draws one marker per span, so a recurring playbook's live periods read at a
    glance. `len(episodes) - 1 == _band_recurs` once born."""
    eps: list[list[int]] = []
    start = end = -1
    zero_run = 0
    for i, v in enumerate(band):
        if v > 0:
            if start < 0:
                start = i
            elif zero_run >= gap:
                eps.append([start, end])
                start = i
            end = i
            zero_run = 0
        elif start >= 0:
            zero_run += 1
    if start >= 0:
        eps.append([start, end])
    return eps


def _score_history(rows: list[dict], *, gap: int, dead_tail: int) -> None:
    """Pure, in place: derive per-row lifecycle signals (mass/liveness/trend/
    recurrence/escalation, plus recurs, trend_dir, state, span_buckets), then blend
    the min-max-normalized signals into a 0–100 `interest` (weights =
    _HISTORY_WEIGHTS). Normalizing across the pool keeps one hot playbook from
    pegging everyone else's score."""
    import math
    if not rows:
        return
    for r in rows:
        band = r["band"]
        n = len(band)
        total = sum(band)
        tail = band[-dead_tail:] if dead_tail else band
        early = sum(band[: n // 2])
        late = sum(band[n // 2:])
        last_fifth = band[-max(1, n // 5):] if n else []
        episodes = _band_episodes(band, gap)
        recurs = max(0, len(episodes) - 1)
        nz = [i for i, v in enumerate(band) if v > 0]
        r["_mass"] = math.log1p(total)
        r["_live"] = (sum(last_fifth) / total) if total else 0.0
        r["_trend"] = ((late - early) / (late + early)) if (n >= 2 and late + early) else 0.0
        r["_recur"] = float(recurs)
        r["_esc"] = float(r.get("novelty") or 0.0)
        r["recurs"] = recurs
        r["episodes"] = episodes
        r["trend_dir"] = ("up" if r["_trend"] > 0.15 else
                          "down" if r["_trend"] < -0.15 else "flat")
        r["state"] = "live" if sum(tail) > 0 else "dead"
        r["span_buckets"] = (nz[-1] - nz[0] + 1) if nz else 0

    def _norm(key: str) -> None:
        vals = [r[key] for r in rows]
        lo, hi = min(vals), max(vals)
        rng = hi - lo
        # rng==0 (single row, or a signal constant across the pool) → neutral 0.5,
        # not 0.0, so a lone / uniform playbook doesn't render as maximally boring.
        for r in rows:
            r[key + "_n"] = ((r[key] - lo) / rng) if rng else 0.5

    for k in ("_mass", "_live", "_trend", "_recur", "_esc"):
        _norm(k)
    w = _HISTORY_WEIGHTS
    for r in rows:
        r["interest"] = round(100.0 * (
            w["liveness"]   * r["_live_n"] +
            w["trend"]      * r["_trend_n"] +
            w["recurrence"] * r["_recur_n"] +
            w["mass"]       * r["_mass_n"] +
            w["escalation"] * r["_esc_n"]
        ), 1)
        r["terms"] = {
            "liveness":   round(r["_live_n"], 3),
            "trend":      round(r["_trend_n"], 3),
            "recurrence": round(r["_recur_n"], 3),
            "mass":       round(r["_mass_n"], 3),
            "escalation": round(r["_esc_n"], 3),
        }
        for k in [k for k in r if k.startswith("_")]:
            del r[k]


def _sort_history(rows: list[dict], sort_mode: str) -> list[dict]:
    """Pure, in place: re-order rows by the analyst's lens (desc). Unknown → interest."""
    keymap = {
        "interest":  lambda r: r.get("interest", 0.0),
        "recency":   lambda r: r.get("last_seen") or "",
        "mass":      lambda r: r.get("sessions", 0),
        "trend":     lambda r: r.get("terms", {}).get("trend", 0.0),
        "longevity": lambda r: r.get("span_buckets", 0),
    }
    rows.sort(key=keymap.get(sort_mode, keymap["interest"]), reverse=True)
    return rows


def _band_msearch(
    es: Elasticsearch, sess: str, *,
    band_hist: dict, range_q: dict, sess_field: str, id_lists: list[list],
) -> list[dict]:
    """One `msearch`: for each id-list, a windowed band + ip/first/last over
    `sessions_rollup` filtered by `sess_field IN ids`. Returns one dict per input
    list (aligned by position): `{band, ips, first, last}`; empty band on error /
    no ids. Used by the member-set entities (campaign, operation, ip_cluster)."""
    if not id_lists:
        return []
    body: list[dict] = []
    for ids in id_lists:
        body.append({})   # per-search header; index is passed to msearch()
        body.append({"size": 0, "query": {"bool": {"filter": [
            range_q, {"terms": {sess_field: ids}}]}},
            "aggs": {"band":  {"date_histogram": band_hist},
                     "ips":   {"cardinality": {"field": "source.ip"}},
                     "first": {"min": {"field": "event.start"}},
                     "last":  {"max": {"field": "event.start"}}}})
    try:
        responses = (es.msearch(searches=body, index=sess).get("responses")) or []
    except Exception as e:
        log.warning("history band msearch failed: %s", e)
        responses = []
    out: list[dict] = []
    for sub in responses:
        aggs = (sub or {}).get("aggregations") or {}
        out.append({
            "band":  [int(b.get("doc_count") or 0)
                      for b in ((aggs.get("band") or {}).get("buckets") or [])],
            "ips":   int((aggs.get("ips") or {}).get("value") or 0),
            "first": (aggs.get("first") or {}).get("value_as_string"),
            "last":  (aggs.get("last") or {}).get("value_as_string"),
        })
    while len(out) < len(id_lists):   # pad if msearch returned short
        out.append({"band": [], "ips": 0, "first": None, "last": None})
    return out


def _member_rows(docs: list[dict], band_data: list[dict], *, id_key: str,
                 name_fn, kind: str | None = None, kind_fn=None,
                 novelty_fn=None) -> list[dict]:
    """Zip member-entity docs with their `_band_msearch` results into history rows.
    Metrics are windowed (from the band); first/last are session-derived, matching
    the direct-agg rows."""
    rows: list[dict] = []
    for d, bd in zip(docs, band_data):
        cid = d.get(id_key)
        if not cid:
            continue
        rows.append({
            "id":         cid,
            "kind":       kind_fn(d) if kind_fn else kind,
            "name":       name_fn(d) or "",
            "sessions":   sum(bd["band"]),
            "ips":        bd["ips"],
            "novelty":    float(novelty_fn(d)) if novelty_fn else 0.0,
            "first_seen": bd["first"],
            "last_seen":  bd["last"],
            "band":       bd["band"],
        })
    return rows


def _campaign_history_rows(
    es: Elasticsearch, cfg: AppConfig, run_cache: Any, *,
    band_hist: dict, range_q: dict, limit: int,
) -> tuple[list[dict], int]:
    """Campaign rows: banded by each campaign's `member_session_ids` over
    `sessions_rollup` (capped `_CAMPAIGN_ID_CAP`). NOTE: membership is a mining-time
    snapshot, so backfilled sessions ingested after the last `mine campaigns` run
    aren't included — re-mine with a wider window to pick them up."""
    idx = cfg.elasticsearch.indexes.cowrie.campaigns
    sess = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    run_id = run_cache.latest(es, idx)
    must: list[dict] = [{"term": {"doc_type": "campaign"}}]
    if run_id:
        must.append({"term": {"run_id": run_id}})
    q = {"bool": {"must": must}}
    total = 0
    try:
        total = int(es.count(index=idx, query=q)["count"])
    except Exception as e:
        log.warning("campaign count failed: %s", e)
    try:
        r = es.search(index=idx, size=limit,
                      _source=["campaign_id", "kind", "name", "member_session_ids"],
                      query=q, sort=[{"session_count": {"order": "desc"}}])
        camps = [h["_source"] for h in r["hits"]["hits"]]
    except Exception as e:
        log.warning("campaign list failed: %s", e)
        return [], total
    id_lists = [list(dict.fromkeys(c.get("member_session_ids") or []))[:_CAMPAIGN_ID_CAP]
                for c in camps]
    bands = _band_msearch(es, sess, band_hist=band_hist, range_q=range_q,
                          sess_field="cowrie.session_id", id_lists=id_lists)
    rows = _member_rows(camps, bands, id_key="campaign_id",
                        name_fn=lambda c: c.get("name") or "",
                        kind_fn=lambda c: "campaign:" + (c.get("kind") or ""))
    return rows, total


def _operation_history_rows(
    es: Elasticsearch, cfg: AppConfig, *,
    band_hist: dict, range_q: dict, limit: int,
) -> tuple[list[dict], int]:
    """Operation rows: banded by each operation's `member_source_ips` over
    `sessions_rollup` (filter on `source.ip`). Operations are (behaviour × infra)
    campaign mergers; same snapshot caveat as campaigns."""
    idx = cfg.elasticsearch.indexes.cowrie.operations
    sess = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    total = 0
    try:
        if not es.indices.exists(index=idx):
            return [], 0
        total = int(es.count(index=idx)["count"])
    except Exception as e:
        log.warning("operation count failed: %s", e)
    try:
        r = es.search(index=idx, size=limit,
                      _source=["operation_id", "behaviour_name",
                               "infrastructure_name", "member_source_ips"],
                      sort=[{"shared_ip_count": {"order": "desc"}}])
        ops = [h["_source"] for h in r["hits"]["hits"]]
    except Exception as e:
        log.warning("operation list failed: %s", e)
        return [], total
    id_lists = [list(dict.fromkeys(o.get("member_source_ips") or []))[:_CAMPAIGN_ID_CAP]
                for o in ops]
    bands = _band_msearch(es, sess, band_hist=band_hist, range_q=range_q,
                          sess_field="source.ip", id_lists=id_lists)

    def _opname(o: dict) -> str:
        b, i = o.get("behaviour_name"), o.get("infrastructure_name")
        return (f"{b} × {i}") if (b and i) else (b or i or "")

    rows = _member_rows(ops, bands, id_key="operation_id",
                        kind="operation", name_fn=_opname)
    return rows, total


def _ipcluster_history_rows(
    es: Elasticsearch, cfg: AppConfig, *,
    band_hist: dict, range_q: dict, limit: int,
) -> tuple[list[dict], int]:
    """IP-cluster rows. No per-session ip-cluster field exists, so member IPs are
    collected from `ips_rollup` (the live `ip.cluster.id` enrichment, top
    `_IPCLUSTER_MEMBER_CAP` by activity per cluster), then each cluster is banded by
    those `source.ip`s over `sessions_rollup`."""
    sess = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    ips = cfg.elasticsearch.indexes.cowrie.ips_rollup
    cl_field = _resolve_agg_field(es, ips, "dshield.cowrie.enrichment.ip.cluster.id")
    nov_field = "dshield.cowrie.enrichment.ip.mean_novelty_score"
    total = 0
    clusters: list[dict] = []
    try:
        r = es.search(index=ips, size=0, aggs={
            "total": {"cardinality": {"field": cl_field}},
            "by_cluster": {
                "terms": {"field": cl_field, "size": limit,
                          "order": {"_count": "desc"}, "min_doc_count": 1},
                "aggs": {
                    "members": {"terms": {"field": "source.ip",
                                          "size": _IPCLUSTER_MEMBER_CAP}},
                    "novelty": {"avg": {"field": nov_field}},
                },
            },
        })
        aggs = r["aggregations"]
        total = int((aggs.get("total") or {}).get("value") or 0)
        for b in aggs["by_cluster"]["buckets"]:
            cid = b.get("key")
            if not cid:
                continue
            member_ips = [mb.get("key")
                          for mb in ((b.get("members") or {}).get("buckets") or [])
                          if mb.get("key")]
            clusters.append({
                "cluster_id": cid,
                "novelty": float((b.get("novelty") or {}).get("value") or 0.0),
                "ips": member_ips,
            })
    except Exception as e:
        log.warning("ip-cluster agg failed: %s", e)
        return [], total
    bands = _band_msearch(es, sess, band_hist=band_hist, range_q=range_q,
                          sess_field="source.ip", id_lists=[c["ips"] for c in clusters])
    rows = _member_rows(clusters, bands, id_key="cluster_id", kind="ip_cluster",
                        name_fn=lambda c: "",
                        novelty_fn=lambda c: c.get("novelty") or 0.0)
    return rows, total


def _sesscluster_history_rows(
    es: Elasticsearch, cfg: AppConfig, *,
    band_hist: dict, range_q: dict, limit: int,
) -> tuple[list[dict], int]:
    """Session-cluster rows — a direct `terms` agg on the per-session
    `session.cluster.id` (like playbooks; native novelty). The label is the modal
    `playbook_name` (session clusters are the raw grain below the named playbook)."""
    sess = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    cl_field = _resolve_agg_field(
        es, sess, "dshield.cowrie.enrichment.session.cluster.id")
    nov_field = "dshield.cowrie.enrichment.session.cluster.novelty_score"
    name_field = "dshield.cowrie.enrichment.session.playbook_name"
    total = 0
    rows: list[dict] = []
    try:
        r = es.search(index=sess, size=0, query=range_q, aggs={
            "total": {"cardinality": {"field": cl_field}},
            "by_cluster": {
                "terms": {"field": cl_field, "size": limit,
                          "order": {"novelty": "desc"}, "min_doc_count": 1},
                "aggs": {
                    "band":    {"date_histogram": band_hist},
                    "ips":     {"cardinality": {"field": "source.ip"}},
                    "first":   {"min": {"field": "event.start"}},
                    "last":    {"max": {"field": "event.start"}},
                    "novelty": {"avg": {"field": nov_field}},
                    "name":    {"terms": {"field": name_field, "size": 1}},
                },
            },
        })
        aggs = r["aggregations"]
        total = int((aggs.get("total") or {}).get("value") or 0)
        rows = _history_rows(aggs["by_cluster"]["buckets"], None, kind="session_cluster")
    except Exception as e:
        log.warning("session-cluster history failed: %s", e)
    return rows, total


def history_summary(
    es: Elasticsearch, cfg: AppConfig, run_cache: Any, *,
    entity: str = "playbook",
    window: str | None = None,
    start: str | None = None, end: str | None = None,
    sort: str = "interest", filter_: str = "all", state_: str = "all",
    limit: int = _HISTORY_POOL_CAP,
) -> dict:
    """Longitudinal History payload (`/api/history`): one row per entity over a
    shared time window, each with an aligned activity `band` and an `interest`
    composite score. `entity` ∈ {playbook,campaign}. `window` ∈
    {30d,90d,180d,all,custom}; `custom` uses `start`/`end` (ISO dates). See
    docs/reference.md for the full contract.
    """
    entity = (entity or "playbook").lower()
    if entity not in _HISTORY_ENTITIES:
        entity = "playbook"
    idxs = cfg.elasticsearch.indexes.cowrie
    sess = idxs.sessions_rollup
    pb_field = _resolve_agg_field(
        es, sess, "dshield.cowrie.enrichment.session.playbook_id",
    )
    nov_field = "dshield.cowrie.enrichment.session.cluster.novelty_score"

    now = datetime.now(timezone.utc)

    # Resolve the concrete [gte, lt) window + adaptive bucket interval.
    window = (window or "90d").lower()
    if window in _HISTORY_WINDOWS:
        lt, gte = now, now - timedelta(days=_HISTORY_WINDOWS[window])
    elif window == "custom":
        try:
            gte = datetime.fromisoformat((start or "").replace("Z", "+00:00"))
            lt = datetime.fromisoformat((end or "").replace("Z", "+00:00"))
            if gte.tzinfo is None:
                gte = gte.replace(tzinfo=timezone.utc)
            if lt.tzinfo is None:
                lt = lt.replace(tzinfo=timezone.utc)
            lt = min(lt, now)   # never let a future end pad the band with fake-dead zeros
            if lt <= gte:
                raise ValueError("end <= start")
        except Exception:
            window, lt, gte = "90d", now, now - timedelta(days=90)
    elif window == "all":
        lt = now
        try:
            r0 = es.search(index=sess, size=0,
                           aggs={"m": {"min": {"field": "event.start"}}})
            mn = (r0["aggregations"]["m"] or {}).get("value")
            gte = (datetime.fromtimestamp(mn / 1000.0, tz=timezone.utc)
                   if mn else now - timedelta(days=90))
        except Exception as e:
            log.warning("history corpus-min failed: %s", e)
            gte = now - timedelta(days=90)
    else:
        window, lt, gte = "90d", now, now - timedelta(days=90)

    span_days = max(1.0, (lt - gte).total_seconds() / 86400.0)
    interval, unit = _pick_interval(span_days)
    gte_ms, lt_ms = int(gte.timestamp() * 1000), int(lt.timestamp() * 1000)
    band_hist = {
        "field": "event.start", "fixed_interval": interval,
        "min_doc_count": 0, "extended_bounds": {"min": gte_ms, "max": lt_ms},
    }
    range_q = {"range": {"event.start":
                         {"gte": gte_ms, "lt": lt_ms, "format": "epoch_millis"}}}

    rows: list[dict] = []
    total = n_buckets = pool_n = 0
    try:
        if entity == "campaign":
            rows, total = _campaign_history_rows(
                es, cfg, run_cache, band_hist=band_hist, range_q=range_q, limit=limit)
        elif entity == "operation":
            rows, total = _operation_history_rows(
                es, cfg, band_hist=band_hist, range_q=range_q, limit=limit)
        elif entity == "ip_cluster":
            rows, total = _ipcluster_history_rows(
                es, cfg, band_hist=band_hist, range_q=range_q, limit=limit)
        elif entity == "session_cluster":
            rows, total = _sesscluster_history_rows(
                es, cfg, band_hist=band_hist, range_q=range_q, limit=limit)
        else:
            resp = es.search(index=sess, size=0, query=range_q, aggs={
                "total": {"cardinality": {"field": pb_field}},
                "by_playbook": {
                    # Retrieve the pool by novelty, not raw session count: History's
                    # job is surfacing genuinely unusual behaviour, so a low-volume but
                    # novel playbook must win a pool slot over the noisy scanners. The
                    # final on-page order is still the `interest` composite (below).
                    "terms": {"field": pb_field, "size": limit,
                              "order": {"novelty": "desc"}, "min_doc_count": 1},
                    "aggs": {
                        "band":    {"date_histogram": band_hist},
                        "ips":     {"cardinality": {"field": "source.ip"}},
                        "first":   {"min": {"field": "event.start"}},
                        "last":    {"max": {"field": "event.start"}},
                        "novelty": {"avg": {"field": nov_field}},
                    },
                },
            })
            aggs = resp["aggregations"]
            total = int((aggs.get("total") or {}).get("value") or 0)
            buckets = aggs["by_playbook"]["buckets"]
            name_map = _playbook_names(es, cfg, [b["key"] for b in buckets if b.get("key")])
            rows = _history_rows(buckets, name_map)
        n_buckets = max((len(r["band"]) for r in rows), default=0)
        # dead_tail is a REAL-TIME threshold (silent >= _HISTORY_DEAD_DAYS at the
        # leading edge → dead), converted to buckets, so "dead" means the same thing
        # whether the window buckets by day, week, or month.
        bucket_days = _BUCKET_DAYS.get(interval, 1)
        dead_tail = max(1, -(-_HISTORY_DEAD_DAYS // bucket_days))   # ceil-div
        _score_history(rows, gap=max(2, n_buckets // 15), dead_tail=dead_tail)
        pool_n = len(rows)   # the fetched pool, before the row filters
        if (filter_ or "all") == "recurring":
            rows = [r for r in rows if r["recurs"] >= 1]
        if state_ in ("live", "dead"):
            rows = [r for r in rows if r["state"] == state_]
        _sort_history(rows, sort)
    except Exception as e:
        log.warning("history longitudinal failed: %s", e)

    return {
        "entity": entity,
        "scope": {"start": gte.isoformat(), "end": lt.isoformat(), "window": window,
                  "total": total, "pool": pool_n,
                  "returned": len(rows), "limit": limit,
                  "capped": total > limit},
        "axis": {"start": gte.isoformat(), "end": lt.isoformat(),
                 "unit": unit, "buckets": n_buckets},
        "sort": sort if sort in _HISTORY_SORTS else "interest",
        "filter": "recurring" if (filter_ or "all") == "recurring" else "all",
        "state": state_ if state_ in ("live", "dead") else "all",
        "rows": rows,
    }


def timeline_sessions(
    es: Elasticsearch, cfg: AppConfig,
    *,
    kind: str,       # "ip" | "session_cluster" | "playbook"
    id_: str,
    limit: int = 500,
    sf: SessionFilter | None = None,
) -> dict:
    """Fetch sessions for the Timeline view, scoped to a specific IOC.

    Returns sessions sorted ascending by event.start together with metadata
    needed to lay out the swimlane canvas: unique cluster ids, time bounds,
    total count (pre-truncation).
    """
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup

    field_map = {
        "ip":              "source.ip",
        "session_cluster": "dshield.cowrie.enrichment.session.cluster.id",
    }
    if kind not in field_map and kind != "playbook":
        return {"sessions": [], "clusters": [], "time_range": None, "total": 0, "shown": 0}

    if kind == "playbook":
        # Playbooks live at the session-cluster layer — filter sessions
        # directly by `playbook_id`.
        pb_field = _resolve_agg_field(
            es, idx, "dshield.cowrie.enrichment.session.playbook_id",
        )
        must: list[dict] = [{"term": {pb_field: id_}}]
    else:
        must = [{"term": {field_map[kind]: id_}}]

    if sf and sf.active:
        must.extend(sf.es_filters())

    try:
        r = es.search(
            index=idx, size=limit,
            _source=_TL_SOURCE,
            query={"bool": {"must": must}},
            sort=[{"event.start": {"order": "asc", "unmapped_type": "date"}}],
        )
    except Exception as e:
        log.warning("timeline_sessions failed: %s", e)
        return {"sessions": [], "clusters": [], "time_range": None, "total": 0, "shown": 0}

    total = r["hits"]["total"]["value"]
    hits = r["hits"]["hits"]
    sessions: list[dict] = []
    cluster_set: dict[str, dict] = {}   # cluster_id -> {id, playbook_id, playbook_name, is_outlier}
    t_min: str | None = None
    t_max: str | None = None

    for h in hits:
        s = h["_source"]
        enr = ((s.get("dshield") or {}).get("cowrie") or {}).get("enrichment", {}).get("session") or {}
        cl = enr.get("cluster") or {}
        start = (s.get("event") or {}).get("start") or s.get("@timestamp")
        end = (s.get("event") or {}).get("end") or start
        cluster_id = cl.get("id") or "none"

        sessions.append({
            "id":              (s.get("cowrie") or {}).get("session_id") or h["_id"],
            "src_ip":          (s.get("source") or {}).get("ip") or "",
            "start":           start,
            "end":             end,
            "command_count":   enr.get("command_count") or 0,
            "intent":          enr.get("dominant_intent"),
            # `playbook_id` is the stable grouping key; `playbook_name` is the
            # display label. Two playbooks can share a name but never an id.
            "playbook_id":     enr.get("playbook_id"),
            "playbook_name":   enr.get("playbook_name"),
            "cluster_id":      cluster_id,
            "is_outlier":      cl.get("is_outlier", False),
            "novelty":         enr.get("mean_novelty_score"),
            "login_success":   enr.get("login_success_count") or 0,
        })

        if cluster_id not in cluster_set:
            cluster_set[cluster_id] = {
                "id":            cluster_id,
                "playbook_id":   enr.get("playbook_id"),
                "playbook_name": enr.get("playbook_name"),
                "is_outlier":    cl.get("is_outlier", False),
            }

        if start:
            if t_min is None or start < t_min:
                t_min = start
            if t_max is None or end > t_max:
                t_max = end

    # Sort clusters so named ones come first, then outliers last.
    clusters = sorted(cluster_set.values(), key=lambda c: (
        c["is_outlier"], c["id"] == "none", c["id"]
    ))

    return {
        "sessions":   sessions,
        "clusters":   clusters,
        "time_range": {"start": t_min, "end": t_max} if t_min else None,
        "total":      total,
        "shown":      len(sessions),
    }
