"""Findings v2 step 4 — stream A (drift) miners.

For each playbook with a `confirm_anchors[]` entry (analyst or
provisional), compare the current state to the latest anchor and emit a
drift finding when any threshold is crossed. Each finding carries a
`delta_signature` so a *new* delta on the same playbook produces a
distinct doc id; rejected deltas land in
`playbook_lifecycle.drift_suppressions[]` (step 2) and are skipped on
re-mine.

Kinds shipped here:

  | Kind | Trigger |
  |---|---|
  | `playbook_command_drift`     | command_signature mode differs from anchor's |
  | `playbook_sequence_drift`    | Jaccard(bigram_set_now, bigram_set_anchor) < threshold AND command_drift did NOT fire |
  | `playbook_artifact_drift`    | Jaccard(artifact_set_now, artifact_set_anchor) < 1 - threshold (i.e. set distance >= threshold) |
  | `playbook_geo_drift`         | Cosine distance over normalised ASN distribution >= threshold |
  | `playbook_size_drift`        | ip_count grew >= pct_min AND >= min_delta_ips since anchor |
  | `playbook_resurgence`        | silent_runs_current >= resurgence_silent_runs then artifact returned this run |
  | `campaign_growth`            | ip_count grew >= pct_min AND >= min_delta_ips on a confirmed/provisional-anchored campaign |

Note on `playbook_command_drift`: the design specifies a Jaccard
threshold over `command_set`. Materialising the full unique-command set
at the playbook level requires a per-session join we don't have today
(sessions carry `command_signature` only, not the literal set), so the
signature-equality gate ships as the v1 implementation. The threshold
knob (`drift.command_jaccard_threshold`) is preserved for the followup
that wires the full set up — interim semantics: anchor signature ==
current signature → no drift; signatures differ → drift. The bigram
miner does the full Jaccard since `command_bigram_set` is materialised
on the rollup.
"""
from __future__ import annotations

import hashlib
import logging
import math
from collections import Counter
from typing import Any, Iterable, Optional

from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _scroll(es, index: str, body: dict, page_size: int = 500):
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
            log.warning("findings.drift: scroll on %s failed: %s", index, exc)
            return
        hits = resp.get("hits", {}).get("hits") or []
        if not hits:
            return
        for h in hits:
            yield h.get("_source") or {}
        search_after = hits[-1].get("sort")
        if not search_after:
            return


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    sa, sb = set(a or []), set(b or [])
    if not sa and not sb:
        return 1.0  # treat identical-empty as fully similar
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


def _cosine_dict(a: dict[str, float], b: dict[str, float]) -> float:
    """Cosine SIMILARITY over two sparse vectors (dict-as-vector). 0–1."""
    keys = set(a) | set(b)
    dot = sum(float(a.get(k, 0.0)) * float(b.get(k, 0.0)) for k in keys)
    na = math.sqrt(sum(float(v) ** 2 for v in a.values()))
    nb = math.sqrt(sum(float(v) ** 2 for v in b.values()))
    if na == 0 or nb == 0:
        return 1.0 if (na == 0 and nb == 0) else 0.0
    return dot / (na * nb)


def _delta_sig(*parts: str) -> str:
    """Stable hex prefix over a tuple of strings, joined by `|`. Used as
    the per-drift unique key — same delta on same playbook → same id."""
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _aggregate_playbook_state(
    es: Elasticsearch, sessions_idx: str, playbook_id: str,
) -> dict:
    """Aggregate the playbook's current state from session_rollup.

    Returns:
      {
        command_signature: mode (str | None),
        command_bigram_signature: mode (str | None),
        command_bigram_set: list[str] (union, top-K),
        artifact_set: list[str] (union, top-K),
        session_count: int,
        ip_count: int,
        asn_distribution: dict[str, int],
        dominant_intent: str | None,
      }
    """
    sess_filter = "dshield.cowrie.enrichment.session.playbook_id"
    bigram_field = "dshield.cowrie.enrichment.session.command_bigram_set.keyword"
    artifact_field = "dshield.cowrie.enrichment.session.artifact_set.keyword"
    try:
        resp = es.search(
            index=sessions_idx,
            size=0,
            query={"term": {sess_filter: playbook_id}},
            aggs={
                "session_count":  {"value_count": {"field": sess_filter}},
                "ip_count":       {"cardinality": {"field": "source.ip"}},
                "cmd_sig":        {"terms": {"field": "dshield.cowrie.enrichment.session.command_signature.keyword", "size": 1}},
                "bigram_sig":     {"terms": {"field": "dshield.cowrie.enrichment.session.command_bigram_signature.keyword", "size": 1}},
                "bigram_set":     {"terms": {"field": bigram_field, "size": 200}},
                "artifact_set":   {"terms": {"field": artifact_field, "size": 200}},
                "asn":            {"terms": {"field": "source.as.number", "size": 50}},
                "dominant_intent":{"terms": {"field": "dshield.cowrie.enrichment.session.dominant_intent", "size": 1}},
            },
        )
    except Exception as exc:
        log.warning("findings.drift: playbook agg for %s failed: %s", playbook_id, exc)
        return {}
    aggs = resp.get("aggregations") or {}
    def _bucket_keys(a, key="key"): return [b[key] for b in ((a or {}).get("buckets") or [])]
    def _mode(a):  bs = (a or {}).get("buckets") or []; return bs[0]["key"] if bs else None
    asn_buckets = (aggs.get("asn") or {}).get("buckets") or []
    return {
        "session_count":            int((aggs.get("session_count") or {}).get("value") or 0),
        "ip_count":                 int((aggs.get("ip_count") or {}).get("value") or 0),
        "command_signature":        _mode(aggs.get("cmd_sig")),
        "command_bigram_signature": _mode(aggs.get("bigram_sig")),
        "command_bigram_set":       _bucket_keys(aggs.get("bigram_set")),
        "artifact_set":             _bucket_keys(aggs.get("artifact_set")),
        "asn_distribution":         {str(b["key"]): int(b["doc_count"]) for b in asn_buckets},
        "dominant_intent":          _mode(aggs.get("dominant_intent")),
    }


# ---------------------------------------------------------------------------
# Per-kind miners — each takes (cfg, run_id, lc_doc, anchor, current_state)
# and returns Optional[finding]. The orchestrator dedupes suppressions.
# ---------------------------------------------------------------------------

def _f_command_drift(cfg, run_id, lc, anchor, curr) -> Optional[dict]:
    """signature mode differs from anchor → drift."""
    a_sig = anchor.get("command_signature")
    c_sig = curr.get("command_signature")
    if not a_sig or not c_sig:
        return None
    if a_sig == c_sig:
        return None
    return {
        "kind": "playbook_command_drift",
        "delta_signature": _delta_sig("cmd", a_sig, c_sig),
        "evidence": {
            "signature_anchor": a_sig,
            "signature_current": c_sig,
            "session_count_current": curr.get("session_count"),
        },
        "narrative_template": "command set changed",
    }


def _f_sequence_drift(cfg, run_id, lc, anchor, curr, *, command_fired: bool) -> Optional[dict]:
    """bigram Jaccard < threshold AND command_drift did NOT fire."""
    if command_fired:
        return None
    a_bg = anchor.get("command_bigram_set") or []
    c_bg = curr.get("command_bigram_set") or []
    if not a_bg and not c_bg:
        return None
    sim = _jaccard(a_bg, c_bg)
    if sim >= cfg.findings.drift.bigram_jaccard_threshold:
        return None
    a_sig = anchor.get("command_bigram_signature") or _delta_sig("ah", *sorted(a_bg))
    c_sig = curr.get("command_bigram_signature") or _delta_sig("ch", *sorted(c_bg))
    return {
        "kind": "playbook_sequence_drift",
        "delta_signature": _delta_sig("seq", a_sig, c_sig),
        "evidence": {
            "bigram_jaccard": round(sim, 4),
            "bigram_signature_anchor": a_sig,
            "bigram_signature_current": c_sig,
        },
        "narrative_template": f"bigram Jaccard {sim:.2f} vs anchor",
    }


def _f_artifact_drift(cfg, run_id, lc, anchor, curr) -> Optional[dict]:
    """artifact_set Jaccard distance >= threshold."""
    a_art = anchor.get("artifact_set") or []
    c_art = curr.get("artifact_set") or []
    if not a_art and not c_art:
        return None
    sim = _jaccard(a_art, c_art)
    dist = 1.0 - sim
    if dist < cfg.findings.drift.artifact_set_drift_min:
        return None
    added = sorted(set(c_art) - set(a_art))[:50]
    removed = sorted(set(a_art) - set(c_art))[:50]
    return {
        "kind": "playbook_artifact_drift",
        "delta_signature": _delta_sig("art", *added, "::", *removed),
        "evidence": {
            "artifact_jaccard_distance": round(dist, 4),
            "added": added, "removed": removed,
        },
        "narrative_template": f"artifact set distance {dist:.2f} vs anchor",
    }


def _f_geo_drift(cfg, run_id, lc, anchor, curr) -> Optional[dict]:
    """Cosine distance on ASN distribution >= threshold."""
    a_asn = anchor.get("asn_distribution") or {}
    c_asn = curr.get("asn_distribution") or {}
    if not a_asn and not c_asn:
        return None
    sim = _cosine_dict({k: float(v) for k, v in a_asn.items()},
                       {k: float(v) for k, v in c_asn.items()})
    dist = 1.0 - sim
    if dist < cfg.findings.drift.asn_cosine_drift_min:
        return None
    asn_sig_a = "+".join(sorted(a_asn.keys()))
    asn_sig_c = "+".join(sorted(c_asn.keys()))
    return {
        "kind": "playbook_geo_drift",
        "delta_signature": _delta_sig("geo", asn_sig_a, asn_sig_c),
        "evidence": {
            "asn_cosine_distance": round(dist, 4),
            "asn_distribution_anchor": a_asn,
            "asn_distribution_current": c_asn,
        },
        "narrative_template": f"ASN cosine distance {dist:.2f} vs anchor",
    }


def _f_size_drift(cfg, run_id, lc, anchor, curr) -> Optional[dict]:
    """ip_count grew by >= pct_min AND >= min_delta_ips."""
    a_ic = int(anchor.get("ip_count") or 0)
    c_ic = int(curr.get("ip_count") or 0)
    delta = c_ic - a_ic
    if delta < cfg.findings.drift.size_growth_min_delta_ips:
        return None
    if a_ic <= 0:
        # Growth from zero; treat any delta >= min_delta_ips as drift.
        pct = float("inf")
    else:
        pct = delta / a_ic
        if pct < cfg.findings.drift.size_growth_pct_min:
            return None
    return {
        "kind": "playbook_size_drift",
        "delta_signature": _delta_sig("size", str(a_ic), str(c_ic)),
        "evidence": {
            "ip_count_anchor": a_ic, "ip_count_current": c_ic,
            "delta_ips": delta, "growth_pct": round(pct, 4) if pct != float("inf") else None,
        },
        "narrative_template": f"+{delta} IPs ({(pct*100):.0f}%) since anchor" if pct != float("inf") else f"+{delta} IPs since anchor",
    }


def _f_resurgence(cfg, run_id, lc, anchor, curr) -> Optional[dict]:
    """Was silent for >= resurgence_silent_runs and reappeared this run.

    Trigger condition: lifecycle's silent_runs_current dropped to 0 this
    run (we appended a snapshot, which resets silent), AND the PRIOR
    snapshot's `run_id` was different (we know we just touched it).
    We approximate "silent before return" by reading the lifecycle doc's
    snapshots[] gap: if the second-to-last snapshot is N+ runs older
    than the last one (we can't know exact gap without timestamps), but
    we *can* use the `runs_observed` vs `len(snapshots)` heuristic — for
    step 4 minimum-viable we just fire when silent_runs_current == 0
    AND the prior step's silent counter exceeded the threshold. Without
    a "previous silent_runs_current" record on the doc, we can't compute
    that retroactively. Step-4 v1 uses the simple proxy: if the doc has
    >= resurgence_silent_runs entries in `snapshots[]` with the same
    artifact id AND the deltas in `snapshots[*].@timestamp` show a gap
    longer than the cadence, fire. To avoid hand-rolling timestamp gap
    analysis, we emit a finding when:
      - silent_runs_current == 0 (we touched it this run)
      - runs_observed < len(snapshots[]) is impossible (cap), but a
        big gap between consecutive snapshot @timestamps is a proxy.
    For initial ship we fire when `runs_observed >= 8` AND
    `snapshots[]` has at least one timestamp gap >= 8 * 6h. Tighten in
    follow-up.
    """
    silent_threshold = int(cfg.findings.drift.resurgence_silent_runs)
    snaps = lc.get("snapshots") or []
    if len(snaps) < 2:
        return None
    if int(lc.get("silent_runs_current") or 0) != 0:
        return None
    from datetime import datetime
    def _t(s):
        try:
            return datetime.fromisoformat(str(s.get("@timestamp")).replace("Z", "+00:00"))
        except Exception:
            return None
    # Find any consecutive gap >= silent_threshold * ~6h (assume 6h cadence).
    gap_hours_threshold = silent_threshold * 6
    triggered_gap_hours: Optional[float] = None
    prev_t = None
    for s in snaps:
        t = _t(s)
        if prev_t and t:
            gap_h = (t - prev_t).total_seconds() / 3600.0
            if gap_h >= gap_hours_threshold:
                triggered_gap_hours = gap_h
        prev_t = t
    if triggered_gap_hours is None:
        return None
    return {
        "kind": "playbook_resurgence",
        "delta_signature": _delta_sig("res", str(int(triggered_gap_hours)), snaps[-1].get("run_id") or ""),
        "evidence": {
            "max_gap_hours":  round(triggered_gap_hours, 1),
            "snapshots_seen": len(snaps),
            "session_count_current": curr.get("session_count"),
        },
        "narrative_template": f"resurfaced after {triggered_gap_hours/24:.1f}d silence",
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def _suppressed(lc_doc: dict, kind: str, sig: str) -> bool:
    for s in lc_doc.get("drift_suppressions") or []:
        if s.get("kind") == kind and s.get("delta_signature") == sig:
            return True
    return False


def _expand_lineage_snapshots(es: Elasticsearch, lc_index: str, lc: dict) -> dict:
    """ROADMAP P2.2 — fold predecessor lifecycle snapshots into the current
    doc's view before detectors run.

    Without this, `_f_resurgence` (and any other detector that walks
    snapshot timestamps) can't fire across id transitions: after P2.1
    inheritance the new lc has at most one fresh snapshot, with the
    silent period buried in the predecessor's `snapshots[]`.

    Returns a shallow-copied `lc` whose `snapshots[]` is the merged
    chain (oldest-first, deduped by `(@timestamp, run_id)`). Original
    confirm_anchors / drift_suppressions / id fields are preserved.
    """
    inherited = lc.get("inherited_from") or []
    if not inherited:
        return lc
    merged: list[dict] = []
    seen: set[tuple[str, str]] = set()
    # Predecessor chain is oldest → newest; iterate in that order.
    for pred_id in inherited:
        try:
            pred = es.get(index=lc_index, id=pred_id)
            for s in ((pred.get("_source") or {}).get("snapshots") or []):
                key = (str(s.get("@timestamp") or ""), str(s.get("run_id") or ""))
                if key in seen:
                    continue
                seen.add(key)
                merged.append(s)
        except Exception as exc:
            log.warning("findings.drift: lineage predecessor %s fetch failed: %s", pred_id, exc)
    # Append the current doc's snapshots last (newest).
    for s in lc.get("snapshots") or []:
        key = (str(s.get("@timestamp") or ""), str(s.get("run_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        merged.append(s)
    out = dict(lc)
    out["snapshots"] = merged
    return out


def run_drift(es: Elasticsearch, cfg: Any, run_id: str) -> dict[str, list[dict[str, Any]]]:
    """Mine every drift kind against the latest anchor of each anchored
    playbook (analyst or provisional). Returns `{kind: findings}`.

    A drift finding is dropped when its `delta_signature` is already in
    the artifact's `drift_suppressions[]` — the analyst already said
    "this exact delta is noise."
    """
    out: dict[str, list[dict[str, Any]]] = {
        "playbook_command_drift": [], "playbook_sequence_drift": [],
        "playbook_artifact_drift": [], "playbook_geo_drift": [],
        "playbook_size_drift": [], "playbook_resurgence": [],
        "campaign_growth": [],
    }
    f_idx = cfg.findings.indexes
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    pb_lc_idx = f_idx.playbook_lifecycle
    if not es.indices.exists(index=pb_lc_idx):
        return out

    body = {
        "query": {"bool": {
            "must": [
                {"exists": {"field": "confirm_anchors"}},
                {"term":   {"silent_runs_current": 0}},
            ],
        }},
        "_source": [
            "playbook_id", "playbook_name", "snapshots",
            "silent_runs_current", "runs_observed",
            "confirm_anchors", "drift_suppressions",
        ],
    }
    for lc in _scroll(es, pb_lc_idx, body):
        anchors = lc.get("confirm_anchors") or []
        if not anchors:
            continue
        anchor = anchors[-1]
        pid = lc.get("playbook_id")
        if not pid:
            continue
        curr = _aggregate_playbook_state(es, sessions_idx, pid)
        if not curr:
            continue
        # P2.2: fold predecessor snapshots in so the snapshot-walking
        # detectors (resurgence in particular) see the full timeline
        # across id transitions.
        lc = _expand_lineage_snapshots(es, pb_lc_idx, lc)

        command_fired = False
        emitters: list[tuple[str, Optional[dict]]] = []
        # command + sequence: command first, sequence skipped if command fired.
        f_cmd = _f_command_drift(cfg, run_id, lc, anchor, curr)
        if f_cmd:
            command_fired = True
            emitters.append(("command", f_cmd))
        emitters.append(("sequence", _f_sequence_drift(cfg, run_id, lc, anchor, curr, command_fired=command_fired)))
        emitters.append(("artifact", _f_artifact_drift(cfg, run_id, lc, anchor, curr)))
        emitters.append(("geo",      _f_geo_drift(cfg, run_id, lc, anchor, curr)))
        emitters.append(("size",     _f_size_drift(cfg, run_id, lc, anchor, curr)))
        emitters.append(("resurg",   _f_resurgence(cfg, run_id, lc, anchor, curr)))

        for _tag, f in emitters:
            if not f:
                continue
            kind = f["kind"]
            sig = f["delta_signature"]
            if _suppressed(lc, kind, sig):
                continue
            f.setdefault("run_id", run_id)
            f.setdefault("artifact", {"kind": "playbook", "value": pid})
            f.setdefault("score", 1.0)  # drift findings prioritise recency; refined in step 5
            template = f.pop("narrative_template", "")
            f.setdefault("narrative", f"{lc.get('playbook_name') or pid}: {template}")
            out[kind].append(f)

    # --- campaign_growth ---------------------------------------------------
    cmp_lc_idx = f_idx.campaign_lifecycle
    if es.indices.exists(index=cmp_lc_idx):
        cmp_body = {
            "query": {"bool": {
                "must": [
                    {"exists": {"field": "confirm_anchors"}},
                    {"term":   {"silent_runs_current": 0}},
                ],
            }},
            "_source": [
                "campaign_id", "campaign_name", "snapshots",
                "confirm_anchors", "drift_suppressions",
            ],
        }
        for lc in _scroll(es, cmp_lc_idx, cmp_body):
            anchors = lc.get("confirm_anchors") or []
            if not anchors:
                continue
            anchor = anchors[-1]
            # P2.2: lineage merge so size_drift sees pre-transition snapshots.
            lc = _expand_lineage_snapshots(es, cmp_lc_idx, lc)
            snaps = lc.get("snapshots") or []
            if not snaps:
                continue
            a_ic = int(anchor.get("ip_count") or 0)
            c_ic = int(snaps[-1].get("ip_count") or 0)
            delta = c_ic - a_ic
            if delta < cfg.findings.drift.campaign_growth_min_delta_ips:
                continue
            pct = (delta / a_ic) if a_ic > 0 else float("inf")
            if pct != float("inf") and pct < cfg.findings.drift.campaign_growth_pct_min:
                continue
            cid = lc.get("campaign_id")
            sig = _delta_sig("cmpsize", str(a_ic), str(c_ic))
            if _suppressed(lc, "campaign_growth", sig):
                continue
            out["campaign_growth"].append({
                "kind": "campaign_growth",
                "run_id": run_id,
                "artifact": {"kind": "campaign", "value": cid},
                "delta_signature": sig,
                "score": 1.0,
                "narrative": (
                    f"{lc.get('campaign_name') or cid}: "
                    f"+{delta} IPs ({(pct*100):.0f}%) since anchor"
                    if pct != float("inf")
                    else f"{lc.get('campaign_name') or cid}: +{delta} IPs since anchor"
                ),
                "evidence": {
                    "ip_count_anchor": a_ic, "ip_count_current": c_ic,
                    "delta_ips": delta, "growth_pct": round(pct, 4) if pct != float("inf") else None,
                },
            })
    return out


DRIFT_KINDS: frozenset[str] = frozenset({
    "playbook_command_drift", "playbook_sequence_drift",
    "playbook_artifact_drift", "playbook_geo_drift",
    "playbook_size_drift", "playbook_resurgence",
    "campaign_growth",
})
