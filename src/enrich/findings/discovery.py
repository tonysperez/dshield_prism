"""Findings v2 step 3 — stream B (discovery) miners.

Each miner produces findings of one `kind`. The headline pair is
`intel_verdict_flip` ("community caught up to what we saw") and
`ip_behavior_shift` ("actor changed behavior") — both self-anchored
against per-IP lifecycle history, no analyst confirm required.

This module ships 6 of the 7 designed discovery kinds:

  - `new_playbook`           — playbook lifecycle `runs_observed == 1`
  - `intel_verdict_flip`     — IP intel verdict transition + recent corpus session
  - `ip_behavior_shift`      — modal playbook flip OR JS distance >= threshold
  - `outlier_burst`          — HDBSCAN-outlier sessions sharing artifacts in 24h
  - `novel_edge_session`     — top-K novelty within each cluster
  - `campaign_convergence`   — cmp-bhv × cmp-inf member-IP overlap >= threshold

`unattributed_active_ip` was specified in the design but retired before
ship: a single corpus produced ~2k findings of this kind in one pass
(every active IP whose sessions landed in HDBSCAN-outlier space), and
per-IP triage isn't a workflow analysts use. The aggregate signal
(coverage gap in clustering) is real but belongs on the Insights page,
not in the findings inbox. The kind is removed; corresponding finding
docs in the index are tombstoned by the operator (see migration in the
phase-8 doc).

All miners read the lifecycle indices produced by `track lifecycles`
(step 1) and consume snapshots written by the backward chain. Each
miner is a pure function `(es, cfg, run_id) -> list[finding]` shaped
for `bulk_upsert_findings`.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _scroll(es, index: str, body: dict, page_size: int = 500):
    """Yield each _source from a search_after scroll. Bounded by `_doc` sort."""
    body = dict(body)
    body.setdefault("size", page_size)
    body.setdefault("sort", [{"_doc": "asc"}])
    search_after: Optional[list] = None
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=index, **body)
        except Exception as exc:
            log.warning("findings.discovery: scroll on %s failed: %s", index, exc)
            return
        hits = resp.get("hits", {}).get("hits") or []
        if not hits:
            return
        for h in hits:
            yield h.get("_source") or {}
        search_after = hits[-1].get("sort")
        if not search_after:
            return


# ---------------------------------------------------------------------------
# new_playbook
# ---------------------------------------------------------------------------

def mine_new_playbook(es: Elasticsearch, cfg: Any, run_id: str) -> list[dict[str, Any]]:
    """Fire once per playbook the moment it first shows up.

    `playbook_lifecycle.runs_observed == 1` is the trigger. Re-mine is
    idempotent — once the lifecycle ticks to 2, this miner stops
    emitting the same finding (finding_id is keyed on playbook_id, so
    the existing doc stays put but status state is preserved by the
    writer's upsert).
    """
    lc_idx = cfg.findings.indexes.playbook_lifecycle
    if not es.indices.exists(index=lc_idx):
        return []
    out: list[dict[str, Any]] = []
    body = {
        "query": {"term": {"runs_observed": 1}},
        "_source": [
            "playbook_id", "playbook_name", "first_seen_ever",
            "snapshots",
        ],
    }
    for src in _scroll(es, lc_idx, body):
        pid = src.get("playbook_id")
        if not pid:
            continue
        name = src.get("playbook_name") or "(unnamed playbook)"
        first_seen = src.get("first_seen_ever") or ""
        snaps = src.get("snapshots") or []
        s = snaps[-1] if snaps else {}
        sc = int(s.get("session_count") or 0)
        ic = int(s.get("ip_count") or 0)
        score = math.log1p(sc) + math.log1p(ic)
        out.append({
            "kind": "new_playbook",
            "run_id": run_id,
            "artifact": {"kind": "playbook", "value": pid},
            "score": score,
            "narrative": f"New playbook '{name}' — first appearance: {sc} sessions across {ic} IPs.",
            "evidence": {
                "playbook_id":   pid,
                "playbook_name": name,
                "first_seen":    first_seen,
                "session_count": sc,
                "ip_count":      ic,
            },
        })
    out.sort(key=lambda f: f["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# intel_verdict_flip
# ---------------------------------------------------------------------------

def _is_meaningful_flip(prev: Optional[str], curr: Optional[str]) -> bool:
    """Verdict transitions that count.

    `clean` ↔ `malicious`/`mixed` flip both ways (community catching up,
    or attacker pivoting onto previously-flagged infra). `no_data` →
    anything also counts (first labelling). Same verdict → not a flip.
    """
    if not curr or prev == curr:
        return False
    if prev is None or prev == "no_data":
        return curr in ("malicious", "mixed", "clean")
    return (prev != curr) and curr in ("malicious", "mixed", "clean")


def mine_intel_verdict_flip(es: Elasticsearch, cfg: Any, run_id: str) -> list[dict[str, Any]]:
    """Fire when an IP's intel verdict changed AND the IP appears in the
    corpus recently (≤ `intel_flip_recent_session_days`, default 7).

    Compares `intel_verdict` between the latest source_ip_lifecycle
    snapshot and the prior snapshot. The "recent session" gate uses the
    lifecycle's `last_seen` field — the IP was active in some run within
    the cutoff window.
    """
    lc_idx = cfg.findings.indexes.source_ip_lifecycle
    if not es.indices.exists(index=lc_idx):
        return []
    # `findings.discovery.intel_flip_recent_session_days` lands in step 3's
    # config addition. Fall back to 7 if absent (older configs).
    days_cutoff = int(getattr(getattr(cfg.findings, "discovery", None),
                              "intel_flip_recent_session_days", 7))
    cutoff = _now() - timedelta(days=days_cutoff)
    out: list[dict[str, Any]] = []
    body = {
        "_source": ["source_ip", "last_seen", "snapshots"],
        "query": {"range": {"runs_observed": {"gte": 2}}},
    }
    for src in _scroll(es, lc_idx, body):
        ip = src.get("source_ip")
        if not ip:
            continue
        last_seen = _parse_ts(src.get("last_seen"))
        if not last_seen or last_seen < cutoff:
            continue
        snaps = src.get("snapshots") or []
        if len(snaps) < 2:
            continue
        prev_v = snaps[-2].get("intel_verdict")
        curr_v = snaps[-1].get("intel_verdict")
        if not _is_meaningful_flip(prev_v, curr_v):
            continue
        prev_score = float(snaps[-2].get("intel_consensus_score") or 0.0)
        curr_score = float(snaps[-1].get("intel_consensus_score") or 0.0)
        # Higher score when the flip is into "malicious" — the validation
        # payoff we set out to capture.
        weight = 1.0 if curr_v in ("malicious", "mixed") else 0.5
        score = weight * (abs(curr_score - prev_score) + 0.5)
        out.append({
            "kind": "intel_verdict_flip",
            "run_id": run_id,
            "artifact": {"kind": "ip", "value": ip},
            "score": score,
            "narrative": (
                f"Intel verdict {prev_v or 'no_data'} → {curr_v} on {ip}; "
                f"last seen in corpus {src.get('last_seen')}."
            ),
            "evidence": {
                "source_ip":      ip,
                "verdict_prev":   prev_v,
                "verdict_curr":   curr_v,
                "score_prev":     prev_score,
                "score_curr":     curr_score,
                "last_seen":      src.get("last_seen"),
                "asn":            snaps[-1].get("asn"),
                "geo_country":    snaps[-1].get("geo_country"),
            },
        })
    out.sort(key=lambda f: f["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# ip_behavior_shift
# ---------------------------------------------------------------------------

def _jensen_shannon(a: dict[str, float], b: dict[str, float]) -> float:
    """JS distance between two discrete distributions. Range [0, 1].

    Treats each dict's values as un-normalised weights and renormalises
    to probability distributions before computing. Returns 0 when both
    are empty.
    """
    sa = sum(float(v) for v in a.values())
    sb = sum(float(v) for v in b.values())
    if sa <= 0 and sb <= 0:
        return 0.0
    if sa <= 0 or sb <= 0:
        return 1.0
    keys = set(a) | set(b)
    pa = {k: float(a.get(k, 0.0)) / sa for k in keys}
    pb = {k: float(b.get(k, 0.0)) / sb for k in keys}

    def _kl(p, q):
        s = 0.0
        for k in keys:
            pk = p[k]
            qk = q[k]
            if pk > 0 and qk > 0:
                s += pk * math.log(pk / qk, 2)
        return s

    m = {k: (pa[k] + pb[k]) / 2 for k in keys}
    js_div = 0.5 * _kl(pa, m) + 0.5 * _kl(pb, m)
    # JS divergence with log base 2 is in [0, 1]; distance is its sqrt.
    return math.sqrt(max(0.0, min(1.0, js_div)))


def mine_ip_behavior_shift(es: Elasticsearch, cfg: Any, run_id: str) -> list[dict[str, Any]]:
    """Fire when an IP's playbook activity shifts.

    Two triggers (either fires):
      - Modal `dominant_playbook_id` of the latest snapshot differs from
        the modal across the IP's prior history (last N-1 snapshots).
      - JS distance between latest `playbook_distribution` and the union
        of prior distributions >= `ip_shift_js_distance_min` (default 0.3).

    Gate: latest snapshot's `session_count >= ip_shift_min_sessions`
    (default 5) so single-session blips don't fire.
    """
    lc_idx = cfg.findings.indexes.source_ip_lifecycle
    if not es.indices.exists(index=lc_idx):
        return []
    js_min = float(getattr(getattr(cfg.findings, "discovery", None),
                           "ip_shift_js_distance_min", 0.3))
    sess_min = int(getattr(getattr(cfg.findings, "discovery", None),
                           "ip_shift_min_sessions", 5))
    out: list[dict[str, Any]] = []
    body = {
        "_source": ["source_ip", "snapshots"],
        "query": {"range": {"runs_observed": {"gte": 2}}},
    }
    for src in _scroll(es, lc_idx, body):
        ip = src.get("source_ip")
        if not ip:
            continue
        snaps = src.get("snapshots") or []
        if len(snaps) < 2:
            continue
        curr = snaps[-1]
        if int(curr.get("session_count") or 0) < sess_min:
            continue
        curr_dist = curr.get("playbook_distribution") or {}
        # Aggregate prior snapshots' distributions for the baseline.
        prior_dist: dict[str, float] = {}
        prior_dominants: list[str] = []
        for s in snaps[:-1]:
            for k, v in (s.get("playbook_distribution") or {}).items():
                prior_dist[k] = prior_dist.get(k, 0.0) + float(v)
            d = s.get("dominant_playbook_id")
            if d:
                prior_dominants.append(d)
        # Modal of prior — pick the most-frequent dominant_playbook_id.
        prior_modal = None
        if prior_dominants:
            from collections import Counter
            prior_modal = Counter(prior_dominants).most_common(1)[0][0]
        curr_modal = curr.get("dominant_playbook_id")
        modal_flip = bool(curr_modal and prior_modal and curr_modal != prior_modal)
        js = _jensen_shannon(prior_dist, curr_dist) if (prior_dist and curr_dist) else 0.0
        if not modal_flip and js < js_min:
            continue
        score = (1.5 if modal_flip else 0.0) + js
        out.append({
            "kind": "ip_behavior_shift",
            "run_id": run_id,
            "artifact": {"kind": "ip", "value": ip},
            "score": score,
            "narrative": (
                f"{ip} shifted: modal {prior_modal or '?'} → {curr_modal or '?'}, "
                f"JS distance {js:.2f} over {len(snaps)} snapshots."
            ),
            "evidence": {
                "source_ip":             ip,
                "modal_prev":            prior_modal,
                "modal_curr":            curr_modal,
                "modal_flip":            modal_flip,
                "js_distance":           round(js, 4),
                "snapshots_compared":    len(snaps),
                "session_count":         int(curr.get("session_count") or 0),
                "playbook_distribution": curr_dist,
            },
        })
    out.sort(key=lambda f: f["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# outlier_burst (P1b follow-up)
# ---------------------------------------------------------------------------

def mine_outlier_burst(es: Elasticsearch, cfg: Any, run_id: str) -> list[dict[str, Any]]:
    """HDBSCAN-outlier sessions sharing an artifact within the last
    `discovery.outlier_burst_window_hours`.

    Fires when >= `discovery.outlier_burst_min_sessions` outlier sessions
    share an artifact_set value. The shared artifact is the finding's
    artifact — different shared artifacts produce distinct findings even
    when the underlying sessions overlap. Surfaces coordinated outliers
    that clustering hasn't yet bound into a named playbook.
    """
    cowrie = cfg.elasticsearch.indexes.cowrie
    sess_idx = cowrie.sessions_rollup
    if not es.indices.exists(index=sess_idx):
        return []
    win_h = int(getattr(getattr(cfg.findings, "discovery", None),
                        "outlier_burst_window_hours", 24))
    min_sess = int(getattr(getattr(cfg.findings, "discovery", None),
                           "outlier_burst_min_sessions", 5))
    cutoff = (_now() - timedelta(hours=win_h)).isoformat()
    try:
        resp = es.search(
            index=sess_idx, size=0,
            query={"bool": {"must": [
                {"term":  {"dshield.cowrie.enrichment.session.cluster.is_outlier": True}},
                {"range": {"@timestamp": {"gte": cutoff}}},
            ]}},
            aggs={"by_artifact": {
                "terms": {
                    "field": "dshield.cowrie.enrichment.session.artifact_set.keyword",
                    "size":  200,
                    "min_doc_count": min_sess,
                },
                "aggs": {
                    "unique_ips": {"cardinality": {"field": "source.ip"}},
                    "sample":     {"top_hits": {"size": 5, "_source": ["cowrie.session_id", "source.ip"]}},
                },
            }},
        )
    except Exception as exc:
        log.warning("findings.discovery: outlier_burst agg failed: %s", exc)
        return []
    buckets = ((resp.get("aggregations") or {}).get("by_artifact") or {}).get("buckets") or []
    out: list[dict[str, Any]] = []
    for b in buckets:
        artifact = b.get("key")
        sess_count = int(b.get("doc_count") or 0)
        ip_count = int(((b.get("unique_ips") or {}).get("value")) or 0)
        sample_hits = ((b.get("sample") or {}).get("hits", {}).get("hits") or [])
        sample_ips = sorted({
            ((h.get("_source") or {}).get("source") or {}).get("ip")
            for h in sample_hits
            if (((h.get("_source") or {}).get("source") or {}).get("ip"))
        })
        score = math.log1p(sess_count) + math.log1p(ip_count)
        out.append({
            "kind": "outlier_burst",
            "run_id": run_id,
            "artifact": {"kind": "shared_artifact", "value": artifact},
            "score": score,
            "narrative": (
                f"{sess_count} outlier session(s) across {ip_count} IP(s) "
                f"share {artifact!r} in the last {win_h}h."
            ),
            "evidence": {
                "shared_artifact": artifact,
                "session_count":   sess_count,
                "ip_count":        ip_count,
                "window_hours":    win_h,
                "sample_ips":      sample_ips[:5],
            },
        })
    out.sort(key=lambda f: f["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# novel_edge_session (P1b follow-up)
# ---------------------------------------------------------------------------

def mine_novel_edge_session(es: Elasticsearch, cfg: Any, run_id: str) -> list[dict[str, Any]]:
    """Sessions whose `cluster.novelty_score` is in the top-K per cluster.

    Per-cluster terms agg with a top_hits sub-agg ordered by novelty_score
    descending, capped at `discovery.novel_edge_top_k_per_cluster` (default
    3) — approximates the design's "top 1%" without a per-cluster
    percentile round-trip. Gated by `novel_edge_min_cluster_size` so a
    cluster of 3 sessions doesn't produce 3 "edge" findings.
    """
    cowrie = cfg.elasticsearch.indexes.cowrie
    sess_idx = cowrie.sessions_rollup
    if not es.indices.exists(index=sess_idx):
        return []
    top_k = int(getattr(getattr(cfg.findings, "discovery", None),
                        "novel_edge_top_k_per_cluster", 3))
    min_cl = int(getattr(getattr(cfg.findings, "discovery", None),
                         "novel_edge_min_cluster_size", 20))
    cluster_field = "dshield.cowrie.enrichment.session.cluster.id"
    novelty_field = "dshield.cowrie.enrichment.session.cluster.novelty_score"
    try:
        resp = es.search(
            index=sess_idx, size=0,
            query={"bool": {
                "must":     [{"exists": {"field": cluster_field}}],
                "must_not": [{"term":   {cluster_field: "outlier"}}],
            }},
            aggs={"by_cluster": {
                "terms": {"field": cluster_field, "size": 200,
                          "min_doc_count": min_cl},
                "aggs": {
                    "top": {"top_hits": {
                        "size":    top_k,
                        "sort":    [{novelty_field: {"order": "desc"}}],
                        "_source": ["cowrie.session_id", "source.ip",
                                     novelty_field,
                                     "dshield.cowrie.enrichment.session.playbook_id",
                                     "dshield.cowrie.enrichment.session.playbook_name"],
                    }},
                },
            }},
        )
    except Exception as exc:
        log.warning("findings.discovery: novel_edge_session agg failed: %s", exc)
        return []
    buckets = ((resp.get("aggregations") or {}).get("by_cluster") or {}).get("buckets") or []
    out: list[dict[str, Any]] = []
    for b in buckets:
        cl_id = b.get("key")
        for h in ((b.get("top") or {}).get("hits", {}).get("hits") or []):
            src = h.get("_source") or {}
            sid = ((src.get("cowrie") or {}).get("session_id")) or h.get("_id")
            if not sid:
                continue
            enr_sess = (((src.get("dshield") or {}).get("cowrie") or {})
                        .get("enrichment", {}).get("session", {})) or {}
            novelty = float((enr_sess.get("cluster") or {}).get("novelty_score") or 0.0)
            pid = enr_sess.get("playbook_id")
            pname = enr_sess.get("playbook_name") or "(unnamed)"
            ip = ((src.get("source") or {}).get("ip"))
            out.append({
                "kind": "novel_edge_session",
                "run_id": run_id,
                "artifact": {"kind": "session", "value": sid},
                "score": novelty,
                "narrative": (
                    f"Session {sid} sits at the novelty edge of playbook "
                    f"'{pname}' (novelty {novelty:.2f}) — top-{top_k} within its cluster."
                ),
                "evidence": {
                    "session_id":     sid,
                    "source_ip":      ip,
                    "playbook_id":    pid,
                    "playbook_name":  enr_sess.get("playbook_name"),
                    "cluster_id":     cl_id,
                    "novelty_score":  round(novelty, 4),
                    "cluster_size":   int(b.get("doc_count") or 0),
                },
            })
    out.sort(key=lambda f: f["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# campaign_convergence (P1b follow-up)
# ---------------------------------------------------------------------------

def mine_campaign_convergence(es: Elasticsearch, cfg: Any, run_id: str) -> list[dict[str, Any]]:
    """Behaviour campaign × infrastructure campaign IP overlap >= threshold.

    Pairwise compare every `cmp-bhv-*` against every `cmp-inf-*`; emit
    when the intersection of `member_source_ips` divided by
    `min(|bhv|, |inf|)` clears
    `discovery.convergence_min_ip_overlap_ratio`. Surfaces "the IPs
    running this playbook are also running this infrastructure" without
    requiring an analyst to spot it.
    """
    cowrie = cfg.elasticsearch.indexes.cowrie
    cidx = cowrie.campaigns
    if not es.indices.exists(index=cidx):
        return []
    ratio_min = float(getattr(getattr(cfg.findings, "discovery", None),
                              "convergence_min_ip_overlap_ratio", 0.4))
    bhv: list[dict] = []
    inf: list[dict] = []
    # Pull every campaign once. `member_source_ips` is a keyword[] capped
    # at the campaign miner's per-campaign limit, so totals are bounded.
    body = {
        "size": 500,
        "_source": ["campaign_id", "name", "kind", "member_source_ips"],
        "query": {"term": {"doc_type": "campaign"}},
        "sort": [{"_doc": "asc"}],
    }
    for src in _scroll(es, cidx, body):
        kind = (src.get("kind") or "").lower()
        ips = src.get("member_source_ips") or []
        if not ips:
            continue
        entry = {"id": src.get("campaign_id"),
                 "name": src.get("name"),
                 "ips": set(ips)}
        if kind in ("behaviour", "behavior"):
            bhv.append(entry)
        elif kind in ("infrastructure", "infra"):
            inf.append(entry)

    out: list[dict[str, Any]] = []
    for b in bhv:
        for i in inf:
            inter = b["ips"] & i["ips"]
            if not inter:
                continue
            denom = min(len(b["ips"]), len(i["ips"]))
            ratio = len(inter) / denom if denom > 0 else 0.0
            if ratio < ratio_min:
                continue
            pair_key = f"{b['id']}+{i['id']}"
            out.append({
                "kind": "campaign_convergence",
                "run_id": run_id,
                "artifact": {"kind": "campaign_pair", "value": pair_key},
                "score": ratio + math.log1p(len(inter)),
                "narrative": (
                    f"{len(inter)} shared IP(s) between behaviour campaign "
                    f"'{b['name']}' and infrastructure campaign '{i['name']}' "
                    f"(overlap ratio {ratio:.2f})."
                ),
                "evidence": {
                    "behaviour_id":         b["id"],
                    "behaviour_name":       b["name"],
                    "infrastructure_id":    i["id"],
                    "infrastructure_name":  i["name"],
                    "shared_ip_count":      len(inter),
                    "behaviour_ip_count":   len(b["ips"]),
                    "infrastructure_ip_count": len(i["ips"]),
                    "overlap_ratio":        round(ratio, 4),
                    "sample_shared_ips":    sorted(inter)[:10],
                },
            })
    out.sort(key=lambda f: f["score"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Public set
# ---------------------------------------------------------------------------

DISCOVERY_MINERS = {
    "new_playbook":         mine_new_playbook,
    "intel_verdict_flip":   mine_intel_verdict_flip,
    "ip_behavior_shift":    mine_ip_behavior_shift,
    "outlier_burst":        mine_outlier_burst,
    "novel_edge_session":   mine_novel_edge_session,
    "campaign_convergence": mine_campaign_convergence,
}

# Step 3 follow-up will add: outlier_burst, novel_edge_session,
# campaign_convergence. `unattributed_active_ip` is in the set so the
# console's stream classifier still routes any stragglers to the
# discovery section while the operator tombstones them; the kind has no
# miner here and will produce zero new findings going forward.
DISCOVERY_KINDS: frozenset[str] = frozenset({
    "new_playbook", "outlier_burst", "novel_edge_session",
    "unattributed_active_ip", "campaign_convergence", "ip_behavior_shift",
    "intel_verdict_flip",
})


def run_discovery(es: Elasticsearch, cfg: Any, run_id: str) -> dict[str, list[dict[str, Any]]]:
    """Run every implemented discovery miner; return `{kind: findings}`."""
    out: dict[str, list[dict[str, Any]]] = {}
    for kind, fn in DISCOVERY_MINERS.items():
        try:
            out[kind] = fn(es, cfg, run_id)
        except Exception as exc:
            log.warning("findings.discovery: %s miner failed: %s", kind, exc)
            out[kind] = []
    return out
