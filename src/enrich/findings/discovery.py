"""Findings v2 step 3 — stream B (discovery) miners.

Each miner produces findings of one `kind`. The headline pair is
`intel_verdict_flip` ("community caught up to what we saw") and
`ip_behavior_shift` ("actor changed behavior") — both self-anchored
against per-IP lifecycle history, no analyst confirm required.

This module ships 3 of the 7 designed discovery kinds:

  - `new_playbook`           — playbook lifecycle `runs_observed == 1`
  - `intel_verdict_flip`     — IP intel verdict transition + recent corpus session
  - `ip_behavior_shift`      — modal playbook flip OR JS distance >= threshold

`unattributed_active_ip` was specified in the design but retired before
ship: a single corpus produced ~2k findings of this kind in one pass
(every active IP whose sessions landed in HDBSCAN-outlier space), and
per-IP triage isn't a workflow analysts use. The aggregate signal
(coverage gap in clustering) is real but belongs on the Insights page,
not in the findings inbox. The kind is removed; corresponding finding
docs in the index are tombstoned by the operator (see migration in the
phase-8 doc).

The remaining three (`outlier_burst`, `novel_edge_session`,
`campaign_convergence`) are deferred to a step 3 follow-up — they need
heavier cross-index joins and would be hard to land + verify alongside
the four payoff kinds.

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
# Public set
# ---------------------------------------------------------------------------

DISCOVERY_MINERS = {
    "new_playbook":       mine_new_playbook,
    "intel_verdict_flip": mine_intel_verdict_flip,
    "ip_behavior_shift":  mine_ip_behavior_shift,
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
