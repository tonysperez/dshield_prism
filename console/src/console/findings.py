"""Console-side queries for the M5 findings page.

Read-only against `prism.finding` (list, filter, sort) and
the IP rollup + intel-ip indices (calibration scatter). Status
mutations are handled inline by the `/api/finding/{id}/status` route
in `server.py`, which calls into the parent package's writer to keep
the upsert + history-append logic in one place.

The miner writes; the console reads. The only mutation the console
performs is the analyst's status change, and that's surfaced via a
single explicit endpoint.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


_VALID_STATUSES: frozenset[str] = frozenset({"new", "ack", "confirmed", "rejected"})

# Findings v2 — three streams. Drift kinds populate as step 4 ships; the
# full set is declared here so the page renders three sections from day 1
# (drift section will simply be empty until step 4).
_COVERAGE_KINDS: frozenset[str] = frozenset({"playbook", "campaign"})
_DRIFT_KINDS: frozenset[str] = frozenset({
    "playbook_command_drift", "playbook_artifact_drift", "playbook_geo_drift",
    "playbook_size_drift", "playbook_resurgence", "playbook_sequence_drift",
    "campaign_growth",
})
_DISCOVERY_KINDS: frozenset[str] = frozenset({
    "new_playbook", "outlier_burst", "novel_edge_session",
    "unattributed_active_ip", "campaign_convergence", "ip_behavior_shift",
    "intel_verdict_flip",
})
_VALID_KINDS: frozenset[str] = _COVERAGE_KINDS | _DRIFT_KINDS | _DISCOVERY_KINDS


def stream_for_kind(kind: str) -> str:
    """Map a finding kind to its UI stream: 'drift', 'discovery', 'coverage'."""
    if kind in _DRIFT_KINDS:
        return "drift"
    if kind in _DISCOVERY_KINDS:
        return "discovery"
    if kind in _COVERAGE_KINDS:
        return "coverage"
    return "unknown"


def valid_streams() -> frozenset[str]:
    return frozenset({"drift", "discovery", "coverage"})


def list_findings(
    es, cfg, *,
    status: Optional[list[str]] = None,
    kind: Optional[str] = None,
    stream: Optional[str] = None,
    size: int = 100,
    frm: int = 0,
    sort: str = "score",
) -> dict[str, Any]:
    """Paginated findings list.

    Filters:
      - `status`: list of valid statuses (default: ["new"] — the
        analyst's inbox; explicit `[]` returns everything).
      - `kind`: optional single kind.
      - `stream`: optional stream ('drift' | 'discovery' | 'coverage') —
        expanded to the kinds set on the server side. Findings v2 step 3.

    Sort:
      - `score` (desc) — default; ranks the most interesting first.
      - `last_seen` (desc) — recency.
      - `first_seen` (desc) — discovery age.

    Returns `{total, rows, page: {from, size}}` where each row is the
    finding's _source augmented with `_id` for client convenience.
    """
    idx = cfg.findings.indexes.default
    if not es.indices.exists(index=idx):
        return {"total": 0, "rows": [], "page": {"from": frm, "size": size},
                "index_missing": True}

    must: list[dict] = []
    if status is None:
        status = ["new"]
    if status:
        must.append({"terms": {"status": status}})
    if kind:
        if kind not in _VALID_KINDS:
            raise ValueError(f"invalid kind: {kind!r}")
        must.append({"term": {"kind": kind}})
    if stream:
        if stream not in valid_streams():
            raise ValueError(f"invalid stream: {stream!r}")
        kinds_in_stream = (
            _COVERAGE_KINDS if stream == "coverage" else
            _DRIFT_KINDS if stream == "drift" else
            _DISCOVERY_KINDS
        )
        must.append({"terms": {"kind": sorted(kinds_in_stream)}})

    sort_clause: list[dict]
    if sort == "last_seen":
        sort_clause = [{"last_seen_at": {"order": "desc"}}]
    elif sort == "first_seen":
        sort_clause = [{"first_seen_at": {"order": "desc"}}]
    else:
        sort_clause = [{"score": {"order": "desc"}}, {"last_seen_at": {"order": "desc"}}]

    body = {
        "size": size, "from": frm,
        "query": {"bool": {"must": must or [{"match_all": {}}]}},
        "sort": sort_clause,
    }
    try:
        resp = es.search(index=idx, **body)
    except Exception as exc:
        log.warning("findings: list query failed: %s", exc)
        return {"total": 0, "rows": [], "page": {"from": frm, "size": size},
                "error": str(exc)}

    hits = resp.get("hits", {})
    rows = []
    for h in hits.get("hits", []):
        src = h.get("_source") or {}
        src["_id"] = h.get("_id")
        rows.append(src)
    total = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else 0
    return {"total": total, "rows": rows, "page": {"from": frm, "size": size}}


def status_counts(es, cfg) -> dict[str, int]:
    """Counts per status across all findings. Cheap aggregation —
    drives the page's status filter chips."""
    idx = cfg.findings.indexes.default
    if not es.indices.exists(index=idx):
        return {}
    try:
        resp = es.search(
            index=idx, size=0,
            aggs={"by_status": {"terms": {"field": "status", "size": 10}}},
        )
    except Exception as exc:
        log.warning("findings: status_counts failed: %s", exc)
        return {}
    buckets = resp.get("aggregations", {}).get("by_status", {}).get("buckets", []) or []
    return {b["key"]: int(b["doc_count"]) for b in buckets}


def kind_counts(es, cfg, *, status: Optional[list[str]] = None) -> dict[str, int]:
    """Per-kind counts, optionally constrained by status. Drives the
    kind filter."""
    idx = cfg.findings.indexes.default
    if not es.indices.exists(index=idx):
        return {}
    must: list[dict] = []
    if status:
        must.append({"terms": {"status": status}})
    try:
        resp = es.search(
            index=idx, size=0,
            query={"bool": {"must": must or [{"match_all": {}}]}},
            aggs={"by_kind": {"terms": {"field": "kind", "size": 50}}},
        )
    except Exception as exc:
        log.warning("findings: kind_counts failed: %s", exc)
        return {}
    buckets = resp.get("aggregations", {}).get("by_kind", {}).get("buckets", []) or []
    return {b["key"]: int(b["doc_count"]) for b in buckets}


def stream_counts(es, cfg, *, status: Optional[list[str]] = None) -> dict[str, int]:
    """Per-stream counts (drift / discovery / coverage). Findings v2 step 3.

    Returns `{stream: count}`. Drives the three-section page header chips.
    """
    counts = kind_counts(es, cfg, status=status)
    out: dict[str, int] = {"drift": 0, "discovery": 0, "coverage": 0}
    for k, n in counts.items():
        s = stream_for_kind(k)
        if s in out:
            out[s] += n
    return out


def get_finding(es, cfg, finding_id: str) -> Optional[dict[str, Any]]:
    """Single-finding detail. Returns None if missing."""
    idx = cfg.findings.indexes.default
    try:
        resp = es.get(index=idx, id=finding_id)
    except Exception:
        return None
    src = resp.get("_source") or {}
    src["_id"] = resp.get("_id")
    return src


def get_finding_detail(es, cfg, finding_id: str) -> Optional[dict[str, Any]]:
    """Detail-drawer payload: finding + server-side joins.

    Findings v2 step 6 — drives the slide-in drawer in `findings.html`.
    Joins:
      - `lifecycle` — the matching `playbook` / `campaign` / `source_ip`
        lifecycle doc (snapshots, confirm_anchors, drift_suppressions)
      - `top_commands` — for playbook-artifact findings, top-3 commands
        by novelty across the playbook's member sessions
      - `top_ips` — for playbook/campaign findings, top-5 member IPs by
        session count, paired with their cached intel verdict pill
      - `convergent_campaigns` — for playbook findings, any campaigns
        whose member IP set overlaps this playbook's (read from the
        campaigns index; cheap when none exist)

    Returns None if the base finding doesn't exist. The joined sub-keys
    are best-effort: a failed inner query yields an empty list, not a
    500 — drawer renders the parts that worked.
    """
    finding = get_finding(es, cfg, finding_id)
    if finding is None:
        return None
    out: dict[str, Any] = dict(finding)
    artifact = finding.get("artifact") or {}
    a_kind = artifact.get("kind")
    a_value = artifact.get("value")
    if not a_kind or not a_value:
        return out
    cowrie_idx = cfg.elasticsearch.indexes.cowrie

    # Resolve lifecycle index names defensively. A partial deploy can leave
    # the venv with an older FindingsIndexes class that lacks the new
    # `playbook_lifecycle` / `campaign_lifecycle` / `source_ip_lifecycle`
    # fields; rather than 500 the whole drawer, fall back to the default
    # mapping names and record `detail_error` so the UI can show "limited
    # detail" instead of breaking entirely.
    def _idx_attr(name: str, default: str) -> str:
        try:
            v = getattr(cfg.findings.indexes, name, None)
            return v or default
        except Exception:
            return default

    try:
        if a_kind == "playbook":
            lc_index = _idx_attr("playbook_lifecycle",
                                 "lifecycle-dshield.cowrie.playbook-default")
            out["lifecycle"] = _fetch_lifecycle(es, lc_index, a_value)
            out["lineage"] = _fetch_lineage(
                es, lc_index, out["lifecycle"].get("inherited_from") or [],
                name_field="playbook_name", id_field="playbook_id",
            )
            out["top_commands"] = _top_commands_for_playbook(es, cowrie_idx, a_value)
            out["top_ips"] = _top_ips_for_playbook(es, cowrie_idx, a_value)
            out["convergent_campaigns"] = _convergent_campaigns(es, cowrie_idx, a_value)
        elif a_kind == "campaign":
            lc_index = _idx_attr("campaign_lifecycle",
                                 "lifecycle-dshield.cowrie.campaign-default")
            out["lifecycle"] = _fetch_lifecycle(es, lc_index, a_value)
            out["lineage"] = _fetch_lineage(
                es, lc_index, out["lifecycle"].get("inherited_from") or [],
                name_field="campaign_name", id_field="campaign_id",
            )
        elif a_kind == "ip":
            lc_index = _idx_attr("source_ip_lifecycle",
                                 "lifecycle-dshield.cowrie.source_ip-default")
            out["lifecycle"] = _fetch_lifecycle(es, lc_index, a_value)
    except Exception as exc:
        log.warning(
            "findings: get_finding_detail joins for %s (%s:%s) failed: %s",
            finding_id, a_kind, a_value, exc,
        )
        out["detail_error"] = str(exc)
    return out


def _fetch_lineage(
    es, index: str, predecessor_ids: list[str], *,
    name_field: str, id_field: str,
) -> list[dict[str, Any]]:
    """Materialise the predecessor chain for the detail drawer.

    `predecessor_ids` is the lifecycle doc's `inherited_from[]` (oldest →
    newest). Returns a list of summary dicts in the same order, with
    `missing=True` on any predecessor that's been deleted/pruned.

    Findings v2 P2.2 — drives the lineage section in the drawer so the
    analyst can see "this playbook was previously known as A, B, C" and
    confirm that their inherited anchor still applies.
    """
    if not predecessor_ids:
        return []
    out: list[dict[str, Any]] = []
    try:
        if not es.indices.exists(index=index):
            return [{"id": pid, "missing": True} for pid in predecessor_ids]
    except Exception:
        pass
    for pid in predecessor_ids:
        try:
            r = es.get(index=index, id=pid)
            src = r.get("_source") or {}
            snaps = src.get("snapshots") or []
            out.append({
                "id":             pid,
                "name":           src.get(name_field),
                "first_seen":     src.get("first_seen_ever"),
                "last_seen":      src.get("last_seen"),
                "runs_observed":  src.get("runs_observed"),
                "silent_runs":    src.get("silent_runs_current"),
                "snapshot_count": len(snaps),
                "anchors_count":  len(src.get("confirm_anchors") or []),
            })
        except Exception:
            out.append({"id": pid, "missing": True})
    return out


def _fetch_lifecycle(es, index: str, doc_id: str) -> dict:
    try:
        if not es.indices.exists(index=index):
            return {}
        resp = es.get(index=index, id=doc_id)
        return resp.get("_source") or {}
    except Exception as exc:
        log.warning("findings: lifecycle fetch %s/%s failed: %s", index, doc_id, exc)
        return {}


def _top_commands_for_playbook(es, cowrie_idx, playbook_id: str) -> list[dict]:
    """Top-3 commands by mean novelty among this playbook's member sessions."""
    try:
        sess_field = "dshield.cowrie.enrichment.session.playbook_id"
        # Member session ids first.
        sess_resp = es.search(
            index=cowrie_idx.sessions_rollup, size=200,
            query={"term": {sess_field: playbook_id}},
            _source=["cowrie.session_id"],
        )
        sids = [
            ((h.get("_source") or {}).get("cowrie") or {}).get("session_id")
            for h in sess_resp.get("hits", {}).get("hits", [])
        ]
        sids = [s for s in sids if s]
        if not sids:
            return []
        # Top-3 commands inside those sessions, ranked by mean novelty.
        cmd_resp = es.search(
            index=cowrie_idx.commands, size=0,
            query={"terms": {"cowrie.session_id": sids}},
            aggs={"top": {
                "terms": {"field": "_id", "size": 3,
                          "order": {"avg_novelty": "desc"}},
                "aggs": {
                    "avg_novelty": {"avg": {"field":
                        "dshield.cowrie.enrichment.cluster.novelty_score"}},
                    "sample": {"top_hits": {"size": 1, "_source": [
                        "process.command_line",
                        "dshield.cowrie.enrichment.description",
                    ]}},
                },
            }},
        )
        out: list[dict] = []
        for b in (cmd_resp.get("aggregations", {}).get("top", {}).get("buckets") or []):
            hits = ((b.get("sample") or {}).get("hits", {}).get("hits") or [])
            if not hits:
                continue
            src = hits[0].get("_source") or {}
            cmd = (src.get("process") or {}).get("command_line") or ""
            desc = (((src.get("dshield") or {}).get("cowrie") or {})
                    .get("enrichment", {}).get("description")) or ""
            out.append({
                "command_id":   b.get("key"),
                "novelty":      round(float(((b.get("avg_novelty") or {}).get("value")) or 0.0), 3),
                "command":      cmd[:240],
                "description":  desc[:240],
            })
        return out
    except Exception as exc:
        log.warning("findings: top_commands for %s failed: %s", playbook_id, exc)
        return []


def _top_ips_for_playbook(es, cowrie_idx, playbook_id: str) -> list[dict]:
    """Top-5 IPs by session count for this playbook. Each carries a
    short intel verdict pill from the IP rollup (denormalised intel).
    """
    try:
        sess_field = "dshield.cowrie.enrichment.session.playbook_id"
        resp = es.search(
            index=cowrie_idx.sessions_rollup, size=0,
            query={"term": {sess_field: playbook_id}},
            aggs={"by_ip": {
                "terms": {"field": "source.ip", "size": 5},
                "aggs": {
                    "intel": {"top_hits": {"size": 1, "_source": [
                        "dshield.cowrie.enrichment.session.source_ip_intel.consensus_label",
                        "dshield.cowrie.enrichment.session.source_ip_intel.consensus_malicious",
                    ]}},
                },
            }},
        )
        out: list[dict] = []
        for b in (resp.get("aggregations", {}).get("by_ip", {}).get("buckets") or []):
            hits = ((b.get("intel") or {}).get("hits", {}).get("hits") or [])
            verdict = None
            if hits:
                intel = ((hits[0].get("_source") or {})
                         .get("dshield", {}).get("cowrie", {})
                         .get("enrichment", {}).get("session", {})
                         .get("source_ip_intel", {})) or {}
                verdict = intel.get("consensus_label")
            out.append({
                "ip":            b.get("key"),
                "session_count": int(b.get("doc_count") or 0),
                "intel_verdict": verdict,
            })
        return out
    except Exception as exc:
        log.warning("findings: top_ips for %s failed: %s", playbook_id, exc)
        return []


def _convergent_campaigns(es, cowrie_idx, playbook_id: str) -> list[dict]:
    """Campaigns whose member set lists this playbook id."""
    try:
        resp = es.search(
            index=cowrie_idx.campaigns, size=5,
            query={"bool": {"must": [
                {"term": {"doc_type": "campaign"}},
                {"term": {"playbook_ids.keyword": playbook_id}},
            ]}},
            _source=["campaign_id", "name", "kind", "ip_count"],
        )
        out = []
        for h in resp.get("hits", {}).get("hits", []) or []:
            src = h.get("_source") or {}
            out.append({
                "campaign_id":   src.get("campaign_id") or h.get("_id"),
                "campaign_name": src.get("name") or "(unnamed)",
                "kind":          src.get("kind") or "",
                "ip_count":      int(src.get("ip_count") or 0),
            })
        return out
    except Exception as exc:
        log.warning("findings: convergent_campaigns for %s failed: %s", playbook_id, exc)
        return []


def valid_statuses() -> frozenset[str]:
    return _VALID_STATUSES


def valid_kinds() -> frozenset[str]:
    return _VALID_KINDS
