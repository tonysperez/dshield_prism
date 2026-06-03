"""Findings v2 — lifecycle subsystem (step 1).

One doc per `playbook_id` / `campaign_id` / `source.ip`. Each doc carries:

  - `first_seen_ever`, `last_seen`, `first_run_id`, `last_run_id`,
    `runs_observed`, `silent_runs_current`
  - `snapshots[]` — rolling cap N per-run snapshots (default 30)
  - `confirm_anchors[]` — append-only history (analyst + provisional;
    written by step 2)
  - `drift_suppressions[]` — `delta_signature`s the analyst rejected
    (written by step 2)

Step 1 ships only the snapshot append + silent-run bump path; anchors
and suppressions stay empty until step 2 lands `mutate_status` side
effects.

`run_track_lifecycles` is the orchestrator wired into the CLI `track
lifecycles` verb. It queries the cluster + rollup + campaign + intel
indices to materialise this-run snapshots, upserts the lifecycle docs,
then bumps `silent_runs_current` on any artifact that was not touched
this run.
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_doc(es: Elasticsearch, index: str, doc_id: str) -> dict:
    try:
        existing = es.get(index=index, id=doc_id)
        return existing.get("_source") or {}
    except Exception:
        return {}


def _apply_snapshot(
    doc: dict,
    *,
    snapshot: dict,
    run_id: str,
    snapshot_cap: int,
    key_field: str,
    key_value: Any,
    extra_init: Optional[dict] = None,
) -> dict:
    """In-place merge of a new snapshot into a lifecycle doc.

    `doc` may be empty (new artifact) — caller's `_read_doc` returns `{}`
    when the id doesn't exist yet. Pure function over the doc dict; the
    caller writes the result back to ES.
    """
    now = snapshot.get("@timestamp") or _now_iso()
    if not doc:
        doc = {
            key_field: key_value,
            "first_seen_ever": now,
            "first_run_id": run_id,
            "runs_observed": 0,
            "silent_runs_current": 0,
            "snapshots": [],
            "confirm_anchors": [],
            "drift_suppressions": [],
        }
        if extra_init:
            doc.update(extra_init)
    # Source-IP lifecycle has no confirm_anchors[] / drift_suppressions[] —
    # the strict mapping rejects those fields. Drop them on the source_ip path.
    doc["last_seen"] = now
    doc["last_run_id"] = run_id
    doc["runs_observed"] = int(doc.get("runs_observed", 0)) + 1
    doc["silent_runs_current"] = 0
    snaps = list(doc.get("snapshots") or [])
    snaps.append(snapshot)
    if len(snaps) > snapshot_cap:
        snaps = snaps[-snapshot_cap:]
    doc["snapshots"] = snaps
    return doc


def update_playbook_lifecycle(
    es: Elasticsearch,
    index: str,
    *,
    playbook_id: str,
    playbook_name: Optional[str],
    run_id: str,
    snapshot: dict,
    snapshot_cap: int = 30,
) -> str:
    """Upsert a single playbook lifecycle doc. Returns the doc id."""
    doc = _read_doc(es, index, playbook_id)
    extra: dict = {}
    if playbook_name:
        extra["playbook_name"] = playbook_name
    doc = _apply_snapshot(
        doc,
        snapshot=snapshot,
        run_id=run_id,
        snapshot_cap=snapshot_cap,
        key_field="playbook_id",
        key_value=playbook_id,
        extra_init=extra,
    )
    if playbook_name:
        doc["playbook_name"] = playbook_name
    es.index(index=index, id=playbook_id, document=doc, refresh=False)
    return playbook_id


def update_campaign_lifecycle(
    es: Elasticsearch,
    index: str,
    *,
    campaign_id: str,
    campaign_name: Optional[str],
    campaign_kind: Optional[str],
    run_id: str,
    snapshot: dict,
    snapshot_cap: int = 30,
) -> str:
    """Upsert a single campaign lifecycle doc. Returns the doc id."""
    doc = _read_doc(es, index, campaign_id)
    extra: dict = {}
    if campaign_name:
        extra["campaign_name"] = campaign_name
    if campaign_kind:
        extra["campaign_kind"] = campaign_kind
    doc = _apply_snapshot(
        doc,
        snapshot=snapshot,
        run_id=run_id,
        snapshot_cap=snapshot_cap,
        key_field="campaign_id",
        key_value=campaign_id,
        extra_init=extra,
    )
    if campaign_name:
        doc["campaign_name"] = campaign_name
    if campaign_kind:
        doc["campaign_kind"] = campaign_kind
    es.index(index=index, id=campaign_id, document=doc, refresh=False)
    return campaign_id


def update_source_ip_lifecycle(
    es: Elasticsearch,
    index: str,
    *,
    source_ip: str,
    run_id: str,
    snapshot: dict,
    snapshot_cap: int = 30,
) -> str:
    """Upsert a single source-IP lifecycle doc. Returns the doc id.

    IP lifecycle has no `confirm_anchors[]` / `drift_suppressions[]` —
    `ip_behavior_shift` self-anchors against the IP's own snapshot
    history, so the analyst confirmation surface doesn't apply.
    """
    doc = _read_doc(es, index, source_ip)
    doc = _apply_snapshot(
        doc,
        snapshot=snapshot,
        run_id=run_id,
        snapshot_cap=snapshot_cap,
        key_field="source_ip",
        key_value=source_ip,
    )
    # Strict-dynamic source_ip mapping forbids these fields.
    doc.pop("confirm_anchors", None)
    doc.pop("drift_suppressions", None)
    es.index(index=index, id=source_ip, document=doc, refresh=False)
    return source_ip


COVERAGE_KINDS: frozenset[str] = frozenset({"playbook", "campaign"})
DRIFT_KINDS: frozenset[str] = frozenset({
    "playbook_command_drift", "playbook_artifact_drift", "playbook_geo_drift",
    "playbook_size_drift", "playbook_resurgence", "playbook_sequence_drift",
    "campaign_growth",
})


def _append_to_list_field(
    es: Elasticsearch, index: str, artifact_id: str, field: str, entry: dict,
) -> bool:
    """Read-modify-write append of `entry` to a nested-list field on a
    lifecycle doc. Returns True on success.

    Used for `confirm_anchors[]` and `drift_suppressions[]` — both
    append-only by design (history-as-audit-trail).
    """
    try:
        existing = es.get(index=index, id=artifact_id)
        doc = existing.get("_source") or {}
    except Exception as exc:
        log.warning("[lifecycle] cannot read %s/%s for append: %s", index, artifact_id, exc)
        return False
    arr = list(doc.get(field) or [])
    arr.append(entry)
    doc[field] = arr
    es.index(index=index, id=artifact_id, document=doc, refresh=False)
    return True


def write_confirm_anchor(
    es: Elasticsearch, index: str, *, artifact_id: str, anchor: dict,
) -> bool:
    """Append an anchor (analyst or provisional) to `confirm_anchors[]` on
    the lifecycle doc. `anchor["source"]` must be `"analyst"` or
    `"provisional"`.

    Drift detectors (step 4) read the latest anchor regardless of source.
    Older anchors stay as audit trail.
    """
    if anchor.get("source") not in ("analyst", "provisional"):
        raise ValueError(f"anchor source must be 'analyst' or 'provisional', got {anchor.get('source')!r}")
    return _append_to_list_field(es, index, artifact_id, "confirm_anchors", anchor)


def write_provisional_anchor(
    es: Elasticsearch, index: str, *, artifact_id: str, anchor: dict,
) -> bool:
    """Same as `write_confirm_anchor` with `source` forced to 'provisional'."""
    anchor = {**anchor, "source": "provisional"}
    return _append_to_list_field(es, index, artifact_id, "confirm_anchors", anchor)


def record_drift_suppression(
    es: Elasticsearch, index: str, *, artifact_id: str, delta_signature: str, kind: str,
) -> bool:
    """Record a rejected drift's `delta_signature` so the miner skips it on
    future runs. Append-only — the analyst can un-reject via a fresh
    confirm anchor, which rebaselines and effectively voids prior
    suppressions.
    """
    entry = {
        "delta_signature": delta_signature,
        "kind": kind,
        "ts": _now_iso(),
    }
    return _append_to_list_field(es, index, artifact_id, "drift_suppressions", entry)


def remove_anchors_by_source(
    es: Elasticsearch, index: str, *, artifact_id: str, source: str,
) -> int:
    """Drop every anchor with the given `source` from a lifecycle doc.
    Used when the analyst rejects a coverage finding — strip provisional
    AND analyst anchors so drift no longer fires on the artifact.

    Returns the number of anchors removed.
    """
    try:
        existing = es.get(index=index, id=artifact_id)
        doc = existing.get("_source") or {}
    except Exception as exc:
        log.warning("[lifecycle] cannot read %s/%s for anchor removal: %s", index, artifact_id, exc)
        return 0
    arr = list(doc.get("confirm_anchors") or [])
    kept = [a for a in arr if a.get("source") != source]
    removed = len(arr) - len(kept)
    if removed:
        doc["confirm_anchors"] = kept
        es.index(index=index, id=artifact_id, document=doc, refresh=False)
    return removed


def build_anchor_payload(
    es: Elasticsearch,
    cfg,
    *,
    artifact_kind: str,
    artifact_id: str,
    source: str,
    confirming_finding_id: Optional[str] = None,
) -> dict:
    """Materialise an anchor doc from the current state of `artifact_id`.

    Pulls the latest snapshot from the lifecycle doc for asn/intent/size
    info, then queries the session rollup to compute mode-aggregated
    command + bigram signatures + capped command_set / artifact_set
    unions across the artifact's member sessions. The latest cluster
    `run_id` is read from session_clusters so the anchor is keyed to
    the run the analyst was looking at when they confirmed.

    `source` is `"analyst"` (called from mutate_status) or
    `"provisional"` (called from `track lifecycles` after N stable runs).
    """
    f_idx = cfg.findings.indexes
    cowrie_idx = cfg.elasticsearch.indexes.cowrie

    # Lifecycle doc → asn/intent/size from latest snapshot.
    if artifact_kind == "playbook":
        lc_index = f_idx.playbook_lifecycle
        sess_filter_field = "dshield.cowrie.enrichment.session.playbook_id"
    elif artifact_kind == "campaign":
        lc_index = f_idx.campaign_lifecycle
        sess_filter_field = "dshield.cowrie.enrichment.session.playbook_id"
    else:
        raise ValueError(f"anchor build not supported for artifact_kind={artifact_kind!r}")

    snap_asn: dict = {}
    snap_intent: Optional[str] = None
    snap_session_count = 0
    snap_ip_count = 0
    try:
        lc_doc = (es.get(index=lc_index, id=artifact_id) or {}).get("_source") or {}
    except Exception:
        lc_doc = {}
    snaps = lc_doc.get("snapshots") or []
    if snaps:
        latest = snaps[-1]
        snap_asn = latest.get("asn_distribution") or {}
        snap_intent = latest.get("dominant_intent")
        snap_session_count = int(latest.get("session_count") or 0)
        snap_ip_count = int(latest.get("ip_count") or 0)

    # Latest cluster run_id from session_clusters.
    confirmed_run_id: Optional[str] = None
    try:
        resp = es.search(
            index=cowrie_idx.session_clusters,
            size=1,
            query={"term": {"doc_type": "cluster"}},
            sort=[{"@timestamp": "desc"}],
            _source=["run_id"],
        )
        h = resp["hits"]["hits"]
        if h:
            confirmed_run_id = h[0]["_source"].get("run_id")
    except Exception:
        pass

    # Session aggregations — for campaign, sess_filter_field is wrong (we'd
    # want member_session_ids from the campaign doc). Step 2 ships playbook
    # anchors with full signatures; campaign anchors get the snapshot-level
    # fields only and the signature lookups are skipped. Step 4 widens
    # campaign anchors once a campaign-session join exists.
    command_signature_mode: Optional[str] = None
    bigram_signature_mode: Optional[str] = None
    command_set: list[str] = []
    artifact_set: list[str] = []

    if artifact_kind == "playbook":
        try:
            agg_resp = es.search(
                index=cowrie_idx.sessions_rollup,
                size=0,
                query={"term": {sess_filter_field: artifact_id}},
                aggs={
                    "cmd_sig":    {"terms": {"field": "dshield.cowrie.enrichment.session.command_signature.keyword", "size": 1}},
                    "bigram_sig": {"terms": {"field": "dshield.cowrie.enrichment.session.command_bigram_signature.keyword", "size": 1}},
                    "cmd_set":    {"terms": {"field": "dshield.cowrie.enrichment.session.command_set.keyword",        "size": 500}},
                    "artifacts":  {"terms": {"field": "dshield.cowrie.enrichment.session.artifact_set.keyword",       "size": 200}},
                },
            )
            aggs = agg_resp.get("aggregations") or {}
            cs_buckets = ((aggs.get("cmd_sig") or {}).get("buckets")) or []
            if cs_buckets:
                command_signature_mode = cs_buckets[0]["key"]
            bs_buckets = ((aggs.get("bigram_sig") or {}).get("buckets")) or []
            if bs_buckets:
                bigram_signature_mode = bs_buckets[0]["key"]
            cset_buckets = ((aggs.get("cmd_set") or {}).get("buckets")) or []
            command_set = [b["key"] for b in cset_buckets]
            a_buckets = ((aggs.get("artifacts") or {}).get("buckets")) or []
            artifact_set = [b["key"] for b in a_buckets]
        except Exception as exc:
            log.warning("[lifecycle] anchor session-agg for %s failed: %s", artifact_id, exc)

    import hashlib
    artifact_signature = (
        hashlib.sha256("|".join(sorted(artifact_set)).encode("utf-8")).hexdigest()[:32]
        if artifact_set else None
    )

    anchor: dict = {
        "ts": _now_iso(),
        "source": source,
        "confirmed_run_id": confirmed_run_id,
        "confirming_finding_id": confirming_finding_id,
        "session_count": snap_session_count,
        "ip_count": snap_ip_count,
        "asn_distribution": snap_asn,
        "dominant_intent": snap_intent,
    }
    if command_signature_mode:
        anchor["command_signature"] = command_signature_mode
    if bigram_signature_mode:
        anchor["command_bigram_signature"] = bigram_signature_mode
    if artifact_set:
        anchor["artifact_set"] = artifact_set
    if artifact_signature:
        anchor["artifact_signature"] = artifact_signature
    if command_set:
        anchor["command_set"] = command_set
    return anchor


def kind_classification(kind: str) -> str:
    """`'coverage' | 'drift' | 'discovery'`. Used by `mutate_status` to
    route lifecycle side effects on status transitions.
    """
    if kind in COVERAGE_KINDS:
        return "coverage"
    if kind in DRIFT_KINDS:
        return "drift"
    return "discovery"


def increment_silent_runs(
    es: Elasticsearch,
    index: str,
    *,
    current_run_id: str,
) -> int:
    """Bump `silent_runs_current` on every lifecycle doc whose
    `last_run_id` does not equal `current_run_id` — i.e. the ones we
    did NOT touch this run. Used as the silent-run accumulator for
    `playbook_resurgence` and the retirement sweep.

    Returns the number of docs updated. `0` is fine on first run.
    """
    if not es.indices.exists(index=index):
        return 0
    body = {
        "query": {
            "bool": {
                "must_not": [
                    {"term": {"last_run_id": current_run_id}},
                ]
            }
        },
        "script": {
            "source": (
                "ctx._source.silent_runs_current = "
                "(ctx._source.silent_runs_current == null ? 0 : ctx._source.silent_runs_current) + 1;"
            ),
            "lang": "painless",
        },
    }
    try:
        resp = es.update_by_query(index=index, body=body, refresh=True, conflicts="proceed")
        return int(resp.get("updated") or 0)
    except Exception as exc:
        log.warning("[lifecycle] silent-run bump on %s failed: %s", index, exc)
        return 0


def retire_silent_lifecycles(
    es: Elasticsearch,
    index: str,
    *,
    threshold: int,
) -> int:
    """Hard-delete lifecycle docs whose `silent_runs_current >= threshold`.
    A retired artifact that later re-emerges mints a fresh lifecycle doc
    through the normal path — no archive index to consult.

    `threshold <= 0` disables the sweep. Returns the number of docs
    deleted.
    """
    if threshold <= 0:
        return 0
    if not es.indices.exists(index=index):
        return 0
    try:
        resp = es.delete_by_query(
            index=index,
            body={"query": {"range": {"silent_runs_current": {"gte": threshold}}}},
            conflicts="proceed",
            refresh=True,
        )
        return int(resp.get("deleted") or 0)
    except Exception as exc:
        log.warning("[lifecycle] retirement sweep on %s failed: %s", index, exc)
        return 0


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def _latest_session_cluster_window_days(
    es: Elasticsearch, session_clusters_idx: str
) -> int:
    """`window_days` from the most recent session-cluster `run_summary` (P1.2).

    0 = the latest `cluster sessions` run was full-corpus (all-time); >0 = it
    was windowed to that many days. The playbook silence accounting keys on
    this: a playbook absent from a *windowed* run only means "no sessions in
    the last N days", not "gone from the corpus", so windowed runs must NOT
    advance `silent_runs_current` — otherwise the entire >Nd-dormant long tail
    would be marked resurged (and eventually retired) at every weekly full
    pass. Absent index / no run_summary / pre-P1.2 docs without the field → 0
    (treat as full: the historical bump-every-run behaviour, which is safe on
    an append-only corpus where a full run always re-sees every playbook).
    """
    if not es.indices.exists(index=session_clusters_idx):
        return 0
    try:
        resp = es.search(
            index=session_clusters_idx,
            size=1,
            query={"term": {"doc_type": "run_summary"}},
            sort=[{"@timestamp": "desc"}],
            _source=["window_days"],
        )
    except Exception as exc:
        log.warning("[lifecycle] could not read latest run_summary window_days: %s", exc)
        return 0
    hits = resp["hits"]["hits"]
    if not hits:
        return 0
    return int(hits[0]["_source"].get("window_days") or 0)


def _iter_current_playbooks(
    es: Elasticsearch, session_clusters_idx: str, sessions_idx: str
) -> Iterable[dict]:
    """Yield per-playbook aggregates for the most recent cluster run.

    Output dict shape:
        {playbook_id, playbook_name, session_count, ip_count,
         mean_novelty, dominant_intent, asn_top, asn_distribution}
    """
    if not es.indices.exists(index=session_clusters_idx):
        return
    # 1) Find the latest cluster run id.
    resp = es.search(
        index=session_clusters_idx,
        size=1,
        query={"term": {"doc_type": "cluster"}},
        sort=[{"@timestamp": "desc"}],
        _source=["run_id"],
    )
    hits = resp["hits"]["hits"]
    if not hits:
        return
    latest_run = hits[0]["_source"].get("run_id")
    if not latest_run:
        return

    # 2) All playbook ids for that run. A playbook may span multiple
    # cluster docs (merged via session.playbook_merge_threshold); collapse
    # to one entry per playbook_id.
    resp2 = es.search(
        index=session_clusters_idx,
        size=1000,
        query={"bool": {"must": [
            {"term": {"doc_type": "cluster"}},
            {"term": {"run_id": latest_run}},
        ]}},
        _source=["playbook_id", "playbook_name"],
    )
    by_id: dict[str, dict] = {}
    for h in resp2["hits"]["hits"]:
        src = h["_source"]
        pid = src.get("playbook_id")
        if not pid:
            continue
        if pid not in by_id:
            by_id[pid] = {
                "playbook_id": pid,
                "playbook_name": src.get("playbook_name"),
            }

    # 3) For each playbook id, aggregate from sessions_rollup.
    cluster_field = "dshield.cowrie.enrichment.session.playbook_id"
    novelty_field = "dshield.cowrie.enrichment.session.cluster.novelty_score"
    intent_field  = "dshield.cowrie.enrichment.session.dominant_intent"
    asn_field     = "source.as.number"
    ip_field      = "source.ip"

    for pid, base in by_id.items():
        try:
            agg_resp = es.search(
                index=sessions_idx,
                size=0,
                query={"term": {cluster_field: pid}},
                aggs={
                    "session_count":  {"value_count": {"field": cluster_field}},
                    "ip_count":       {"cardinality": {"field": ip_field}},
                    "mean_novelty":   {"avg": {"field": novelty_field}},
                    "dominant_intent":{"terms": {"field": intent_field, "size": 1}},
                    "asn_top":        {"terms": {"field": asn_field,    "size": 10}},
                },
            )
        except Exception as exc:
            log.warning("[lifecycle] agg for playbook %s failed: %s", pid, exc)
            continue
        aggs = agg_resp.get("aggregations") or {}
        sc = int(((aggs.get("session_count") or {}).get("value")) or 0)
        ic = int(((aggs.get("ip_count") or {}).get("value")) or 0)
        mn = float(((aggs.get("mean_novelty") or {}).get("value")) or 0.0)
        di_buckets = ((aggs.get("dominant_intent") or {}).get("buckets")) or []
        di = di_buckets[0]["key"] if di_buckets else None
        asn_buckets = ((aggs.get("asn_top") or {}).get("buckets")) or []
        asn_top = str(asn_buckets[0]["key"]) if asn_buckets else None
        asn_distribution = {str(b["key"]): int(b["doc_count"]) for b in asn_buckets}
        yield {
            **base,
            "session_count": sc,
            "ip_count": ic,
            "mean_novelty": mn,
            "dominant_intent": di,
            "asn_top": asn_top,
            "asn_distribution": asn_distribution,
        }


def _iter_current_campaigns(es: Elasticsearch, campaigns_idx: str) -> Iterable[dict]:
    """Yield per-campaign aggregates from the latest snapshot of the campaigns index."""
    if not es.indices.exists(index=campaigns_idx):
        return
    body = {
        "size": 1000,
        "query": {"match_all": {}},
        "_source": [
            "campaign_id", "campaign_name", "kind",
            "session_count", "ip_count", "mean_novelty",
            "dominant_intent", "asn_distribution",
        ],
        "sort": [{"@timestamp": "desc"}, {"_doc": "asc"}],
    }
    try:
        resp = es.search(index=campaigns_idx, **body)
    except Exception as exc:
        log.warning("[lifecycle] campaigns scan failed: %s", exc)
        return
    seen: set[str] = set()
    for h in resp["hits"]["hits"]:
        src = h["_source"]
        cid = src.get("campaign_id")
        if not cid or cid in seen:
            continue
        seen.add(cid)
        asn_dist = src.get("asn_distribution") or {}
        asn_top = None
        if isinstance(asn_dist, dict) and asn_dist:
            asn_top = str(max(asn_dist.items(), key=lambda kv: kv[1])[0])
        yield {
            "campaign_id":      cid,
            "campaign_name":    src.get("campaign_name"),
            "campaign_kind":    src.get("kind"),
            "session_count":    int(src.get("session_count") or 0),
            "ip_count":         int(src.get("ip_count") or 0),
            "mean_novelty":     float(src.get("mean_novelty") or 0.0),
            "dominant_intent":  src.get("dominant_intent"),
            "asn_top":          asn_top,
            "asn_distribution": asn_dist if isinstance(asn_dist, dict) else {},
        }


def _iter_current_ips(es: Elasticsearch, ips_idx: str) -> Iterable[dict]:
    """Yield per-IP snapshot input from the IP rollup index."""
    if not es.indices.exists(index=ips_idx):
        return
    body = {
        "size": 1000,
        "_source": [
            "source.ip",
            "source.as.number",
            "source.geo.country_iso_code",
            "dshield.cowrie.enrichment.ip.total_sessions",
            "dshield.cowrie.enrichment.ip.dominant_playbook_id",
            "dshield.cowrie.enrichment.ip.playbook_distribution",
            "dshield.cowrie.enrichment.ip.intel.consensus_verdict",
            "dshield.cowrie.enrichment.ip.intel.consensus_score",
        ],
        "query": {"exists": {"field": "source.ip"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=ips_idx, **body)
        except Exception as exc:
            log.warning("[lifecycle] ip scan failed: %s", exc)
            return
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            ip = ((src.get("source") or {}).get("ip"))
            if not ip:
                continue
            enr = ((src.get("dshield") or {}).get("cowrie", {}).get("enrichment", {}).get("ip", {})) or {}
            pd_raw = enr.get("playbook_distribution") or []
            pd_flat: dict[str, int] = {}
            if isinstance(pd_raw, list):
                for entry in pd_raw:
                    if isinstance(entry, dict) and entry.get("playbook_id"):
                        pd_flat[entry["playbook_id"]] = int(entry.get("count") or 0)
            intel = enr.get("intel") or {}
            yield {
                "source_ip":              ip,
                "session_count":          int(enr.get("total_sessions") or 0),
                "dominant_playbook_id":   enr.get("dominant_playbook_id"),
                "playbook_distribution":  pd_flat,
                "intel_verdict":          intel.get("consensus_verdict"),
                "intel_consensus_score":  float(intel.get("consensus_score") or 0.0),
                "asn":                    ((src.get("source") or {}).get("as") or {}).get("number"),
                "geo_country":            ((src.get("source") or {}).get("geo") or {}).get("country_iso_code"),
            }
        search_after = hits[-1]["sort"]


def _sweep_provisional_anchors(
    es: Elasticsearch,
    cfg,
    *,
    lifecycle_index: str,
    artifact_kind: str,
    key_field: str,
    stable_min: int,
    run_id: str,
) -> int:
    """Find all lifecycle docs eligible for a provisional anchor and write one.

    Eligibility: `runs_observed >= stable_min` AND `silent_runs_current == 0`
    AND no entry in `confirm_anchors[]` yet. Returns the number of anchors
    written. ROADMAP / findings-v2 step 2.
    """
    if not es.indices.exists(index=lifecycle_index):
        return 0
    # `confirm_anchors` is a nested field; the "empty" check needs `script` or
    # a "nested" must_not exists. Cheap path: pull candidates that satisfy the
    # numeric gates, then filter in Python on the nested array length. The
    # candidate set is small (~hundreds at most) so no scaling concern.
    body = {
        "size": 1000,
        "query": {
            "bool": {
                "must": [
                    {"range": {"runs_observed":       {"gte": stable_min}}},
                    {"term":  {"silent_runs_current": 0}},
                ]
            }
        },
        "_source": [key_field, "confirm_anchors"],
    }
    try:
        resp = es.search(index=lifecycle_index, **body)
    except Exception as exc:
        log.warning("[lifecycle] provisional-anchor sweep on %s failed: %s", lifecycle_index, exc)
        return 0

    written = 0
    for h in resp["hits"]["hits"]:
        src = h["_source"]
        if src.get("confirm_anchors"):
            continue
        artifact_id = src.get(key_field) or h["_id"]
        try:
            payload = build_anchor_payload(
                es, cfg,
                artifact_kind=artifact_kind,
                artifact_id=artifact_id,
                source="provisional",
                confirming_finding_id=None,
            )
        except Exception as exc:
            log.warning("[lifecycle] provisional anchor build for %s failed: %s", artifact_id, exc)
            continue
        if write_provisional_anchor(es, lifecycle_index, artifact_id=artifact_id, anchor=payload):
            written += 1
    return written


def run_track_lifecycles(cfg, secrets, *, dry_run: bool = False) -> dict:
    """End-to-end lifecycle pass: append this-run snapshots for every active
    playbook, campaign, and source IP; bump `silent_runs_current` on the
    rest; retire docs whose silent-run count exceeds the per-layer
    threshold. Drift detectors consume the snapshots + anchors this writer
    produces.
    """
    from ..es_client import make_client
    es = make_client(cfg.elasticsearch, secrets)

    cap = int(cfg.findings.lifecycle.snapshot_cap)
    f_idx = cfg.findings.indexes
    cowrie_idx = cfg.elasticsearch.indexes.cowrie

    run_id = str(uuid.uuid4())
    now = _now_iso()
    t_start = time.monotonic()

    stats: dict = {
        "run_id": run_id,
        "dry_run": dry_run,
        "playbook": {"updated": 0, "silent_bumped": 0},
        "campaign": {"updated": 0, "silent_bumped": 0},
        "source_ip": {"updated": 0, "silent_bumped": 0},
        "errors": [],
    }

    # --- Playbooks ---------------------------------------------------------
    for pb in _iter_current_playbooks(es, cowrie_idx.session_clusters, cowrie_idx.sessions_rollup):
        snapshot = {
            "run_id":           run_id,
            "@timestamp":       now,
            "session_count":    pb["session_count"],
            "ip_count":         pb["ip_count"],
            "mean_novelty":     pb["mean_novelty"],
            "dominant_intent":  pb.get("dominant_intent"),
            "asn_top":          pb.get("asn_top"),
            "asn_distribution": pb.get("asn_distribution") or {},
        }
        if dry_run:
            stats["playbook"]["updated"] += 1
            continue
        try:
            update_playbook_lifecycle(
                es, f_idx.playbook_lifecycle,
                playbook_id=pb["playbook_id"],
                playbook_name=pb.get("playbook_name"),
                run_id=run_id,
                snapshot=snapshot,
                snapshot_cap=cap,
            )
            stats["playbook"]["updated"] += 1
        except Exception as exc:
            stats["errors"].append({"layer": "playbook", "id": pb["playbook_id"], "error": str(exc)})

    # --- Campaigns ---------------------------------------------------------
    for c in _iter_current_campaigns(es, cowrie_idx.campaigns):
        snapshot = {
            "run_id":           run_id,
            "@timestamp":       now,
            "session_count":    c["session_count"],
            "ip_count":         c["ip_count"],
            "mean_novelty":     c["mean_novelty"],
            "dominant_intent":  c.get("dominant_intent"),
            "asn_top":          c.get("asn_top"),
            "asn_distribution": c.get("asn_distribution") or {},
        }
        if dry_run:
            stats["campaign"]["updated"] += 1
            continue
        try:
            update_campaign_lifecycle(
                es, f_idx.campaign_lifecycle,
                campaign_id=c["campaign_id"],
                campaign_name=c.get("campaign_name"),
                campaign_kind=c.get("campaign_kind"),
                run_id=run_id,
                snapshot=snapshot,
                snapshot_cap=cap,
            )
            stats["campaign"]["updated"] += 1
        except Exception as exc:
            stats["errors"].append({"layer": "campaign", "id": c["campaign_id"], "error": str(exc)})

    # --- Source IPs --------------------------------------------------------
    for ip in _iter_current_ips(es, cowrie_idx.ips_rollup):
        snapshot = {
            "run_id":                  run_id,
            "@timestamp":              now,
            "session_count":           ip["session_count"],
            "dominant_playbook_id":    ip.get("dominant_playbook_id"),
            "playbook_distribution":   ip.get("playbook_distribution") or {},
            "intel_verdict":           ip.get("intel_verdict"),
            "intel_consensus_score":   ip.get("intel_consensus_score"),
            "asn":                     ip.get("asn"),
            "geo_country":             ip.get("geo_country"),
        }
        if dry_run:
            stats["source_ip"]["updated"] += 1
            continue
        try:
            update_source_ip_lifecycle(
                es, f_idx.source_ip_lifecycle,
                source_ip=ip["source_ip"],
                run_id=run_id,
                snapshot=snapshot,
                snapshot_cap=cap,
            )
            stats["source_ip"]["updated"] += 1
        except Exception as exc:
            stats["errors"].append({"layer": "source_ip", "id": ip["source_ip"], "error": str(exc)})

    # --- Provisional anchors: write one on any playbook/campaign that has
    # been stable for N runs and has no anchor yet. "Stable" today is a
    # coarse proxy: runs_observed >= N AND silent_runs_current == 0 AND
    # confirm_anchors[] is empty. Step 2 implementation; can be tightened
    # later to require command_signature consistency across the last N
    # snapshots (would need the field promoted to snapshot level first).
    if not dry_run:
        stable_min = int(cfg.findings.lifecycle.provisional_stable_runs)
        # Refresh the lifecycle indexes once so the just-written snapshots are
        # visible to the sweep query below.
        try:
            es.indices.refresh(index=",".join([
                f_idx.playbook_lifecycle, f_idx.campaign_lifecycle,
            ]))
        except Exception:
            pass
        for lc_index, artifact_kind, key_field in (
            (f_idx.playbook_lifecycle, "playbook", "playbook_id"),
            (f_idx.campaign_lifecycle, "campaign", "campaign_id"),
        ):
            written = _sweep_provisional_anchors(
                es, cfg,
                lifecycle_index=lc_index,
                artifact_kind=artifact_kind,
                key_field=key_field,
                stable_min=stable_min,
                run_id=run_id,
            )
            stats[artifact_kind]["provisional_anchors_written"] = written

    # --- Silent-run bump on the artifacts we did NOT touch this run --------
    if not dry_run:
        # Refresh the lifecycle indexes once so the just-written docs are
        # visible to the update_by_query below.
        try:
            es.indices.refresh(index=",".join([
                f_idx.playbook_lifecycle,
                f_idx.campaign_lifecycle,
                f_idx.source_ip_lifecycle,
            ]))
        except Exception:
            pass
        # P1.2 — a playbook absent from a *windowed* session-cluster run only
        # means "no sessions in the last N days", not "gone from the corpus".
        # Bumping silence on windowed runs would push the whole >Nd-dormant
        # long tail past `resurgence_silent_runs` (and eventually
        # `retire_silent_runs_playbook`) and then mark them all resurged at
        # every weekly full pass. So playbook silence advances ONLY when the
        # latest run was full-corpus (window_days == 0); the weekly full
        # re-cluster is what establishes true absence. Campaign / source-IP
        # layers are not windowed, so they bump as before.
        pb_window_days = _latest_session_cluster_window_days(es, cowrie_idx.session_clusters)
        if pb_window_days > 0:
            stats["playbook"]["silent_bumped"] = 0
            stats["playbook"]["silent_skipped_windowed"] = pb_window_days
        else:
            stats["playbook"]["silent_bumped"] = increment_silent_runs(es, f_idx.playbook_lifecycle, current_run_id=run_id)
        stats["campaign"]["silent_bumped"] = increment_silent_runs(es, f_idx.campaign_lifecycle, current_run_id=run_id)
        stats["source_ip"]["silent_bumped"] = increment_silent_runs(es, f_idx.source_ip_lifecycle, current_run_id=run_id)

        lc_cfg = cfg.findings.lifecycle
        stats["playbook"]["retired"]  = retire_silent_lifecycles(
            es, f_idx.playbook_lifecycle,  threshold=int(lc_cfg.retire_silent_runs_playbook),
        )
        stats["campaign"]["retired"] = retire_silent_lifecycles(
            es, f_idx.campaign_lifecycle, threshold=int(lc_cfg.retire_silent_runs_campaign),
        )
        stats["source_ip"]["retired"] = retire_silent_lifecycles(
            es, f_idx.source_ip_lifecycle, threshold=int(lc_cfg.retire_silent_runs_source_ip),
        )

    stats["runtime_seconds"] = round(time.monotonic() - t_start, 2)
    return stats
