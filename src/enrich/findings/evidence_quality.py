"""One-line evidence-quality verdict for a finding row.

A finding's score is an uncalibrated meta-number. The analyst needs a
plain-language read on *how strong the evidence is* — at a glance, in
the inbox table or on the graph orientation card or in a writeup
paragraph. This module produces that string.

Verdict formatting is a pure function — inputs are the finding's
`_source` shape returned by `findings.list_findings()` plus an
optional lifecycle doc (for `runs_observed` when available). The
*thresholds* the Strong/Moderate band uses are now corpus-derived
(brutal-review phase 4.2): callers fetch the latest percentile
snapshots from `prism.metrics` via ``band_thresholds(es, cfg)`` and
pass them through. Sites without an ES handle get the historical
(20, 5) fallback automatically.

The vocabulary is deliberately small. Different finding kinds carry
different evidence axes, so the verdict shape varies — but the
*adjectives* recur (`Strong`, `Moderate`, `Single-point`) and
intentionally mirror the Compare view's verdict vocabulary
(`Likely`, `Borderline`, `Unlikely`) so the analyst learns one
mental scale, not three.

Until per-cluster centroid-cohesion ships (open audit item in
docs/ROADMAP.md), the membership-strength bands use *member count*
as the cohesion proxy. The function is deliberately named
"evidence_quality" not "cluster_cohesion" — it summarises what we
have, not what HDBSCAN measured.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Optional

log = logging.getLogger(__name__)


_COVERAGE_KINDS = frozenset({"playbook", "campaign", "new_playbook"})
_DRIFT_KINDS = frozenset({
    "playbook_command_drift", "playbook_artifact_drift",
    "playbook_geo_drift", "playbook_sequence_drift",
})


# Historical Strong-band cutoff: sess >= 20 AND ips >= 5. Used as the
# fallback when no `prism.metrics` percentile snapshot exists yet
# (fresh deploys), and as the documented default for tests + callers
# that don't have an ES handle.
_BAND_THRESHOLD_DEFAULT: tuple[int, int] = (20, 5)


# Module-level cache for the percentile lookup. Keyed by metrics index
# name; the (timestamp, thresholds) pair is invalidated after
# `_BAND_THRESHOLD_TTL_SEC` to pick up fresh distribution snapshots
# without re-querying ES on every finding.
_BAND_THRESHOLD_CACHE: dict[str, tuple[float, tuple[int, int]]] = {}
_BAND_THRESHOLD_TTL_SEC = 3600.0


def band_thresholds(es, cfg) -> tuple[int, int]:
    """Return ``(strong_sess_min, strong_ips_min)`` for the membership band.

    Reads the latest ``playbook_session_count_per_run`` +
    ``playbook_ip_count_per_run`` percentile snapshots from
    ``cfg.metrics.indexes.default`` (written by
    ``track threshold-distributions`` — brutal-review phase 4.1) and
    returns the p75 of each. Falls back to ``_BAND_THRESHOLD_DEFAULT``
    when the metrics index doesn't exist, no snapshots have been
    written, or any field is missing.

    Cached per-process with a 1h TTL — distribution snapshots move at
    backward-cycle cadence (hourly), so re-querying ES on every
    finding row is wasted work. The cache key is the metrics index
    name; if a deploy retargets the index, the new key cold-misses.

    Returned values are clamped to ``>= 2`` so the
    ``sess <= 1 or ips <= 1`` Single-point rule remains meaningful
    even on tiny corpora where p75 could otherwise collapse to 1.
    """
    try:
        idx = cfg.metrics.indexes.default
    except AttributeError:
        return _BAND_THRESHOLD_DEFAULT
    now = time.time()
    cached = _BAND_THRESHOLD_CACHE.get(idx)
    if cached and (now - cached[0]) < _BAND_THRESHOLD_TTL_SEC:
        return cached[1]
    try:
        sess_p75 = _latest_percentile(
            es, idx, "playbook_session_count_per_run", "p75",
        )
        ips_p75 = _latest_percentile(
            es, idx, "playbook_ip_count_per_run", "p75",
        )
    except Exception as exc:  # noqa: BLE001 — best-effort observability
        log.warning("band_thresholds: lookup on %s failed: %s", idx, exc)
        _BAND_THRESHOLD_CACHE[idx] = (now, _BAND_THRESHOLD_DEFAULT)
        return _BAND_THRESHOLD_DEFAULT
    if sess_p75 is None or ips_p75 is None:
        _BAND_THRESHOLD_CACHE[idx] = (now, _BAND_THRESHOLD_DEFAULT)
        return _BAND_THRESHOLD_DEFAULT
    out = (
        max(2, int(round(sess_p75))),
        max(2, int(round(ips_p75))),
    )
    _BAND_THRESHOLD_CACHE[idx] = (now, out)
    return out


def _latest_percentile(
    es, idx: str, kind: str, field: str,
) -> Optional[float]:
    """Pull a single percentile value from the most recent metrics doc
    for ``kind``. Returns None when the index / doc / field is missing.
    """
    if not es.indices.exists(index=idx):
        return None
    body = {
        "size":    1,
        "sort":    [{"generated_at": {"order": "desc"}}],
        "query":   {"term": {"kind": kind}},
        "_source": [field],
    }
    resp = es.search(index=idx, **body)
    hits = (resp.get("hits") or {}).get("hits") or []
    if not hits:
        return None
    v = (hits[0].get("_source") or {}).get(field)
    if v is None:
        return None
    return float(v)


def format_evidence_quality(
    finding: dict[str, Any],
    lifecycle: Optional[dict[str, Any]] = None,
    *,
    thresholds: Optional[tuple[int, int]] = None,
) -> str:
    """Return a short verdict string for the finding.

    Examples by kind:
      playbook / campaign / new_playbook  →
        "Strong · 47 sess / 19 IPs · 12d"
        "Moderate · 6 sess / 4 IPs · 2d"
        "Single-point · 1 sess / 1 IP · today"
      intel_verdict_flip →
        "Verdict flip · clean → malicious"
        "Verdict flip · no_data → mixed"
      ip_behavior_shift →
        "Modal flip · JS 0.43 · 7 snapshots"
        "Distribution shift · JS 0.31"
      playbook_command_drift / _artifact_drift / _geo_drift / _sequence_drift →
        "Material drift · command Jaccard 0.42"
        "Border drift · ASN cosine 0.18"
      playbook_size_drift →
        "Growth · +35 IPs (140%)"
      playbook_resurgence →
        "Resurfaced · after 12d silence"
      outlier_burst →
        "Burst · 14 sess / 6 IPs"
      campaign_convergence →
        "Overlap · 24 shared IPs"

    Returns an empty string when no useful evidence is available.
    """
    if not isinstance(finding, dict):
        return ""
    kind = finding.get("kind") or ""
    ev = finding.get("evidence") or {}

    if kind in _COVERAGE_KINDS:
        return _membership_verdict(finding, ev, lifecycle, thresholds)
    if kind == "intel_verdict_flip":
        return _intel_flip_verdict(ev)
    if kind == "ip_behavior_shift":
        return _ip_shift_verdict(ev)
    if kind in _DRIFT_KINDS:
        return _drift_verdict(kind, ev)
    if kind == "playbook_size_drift":
        return _size_drift_verdict(ev)
    if kind == "playbook_resurgence":
        return _resurgence_verdict(ev)
    if kind == "campaign_growth":
        return _campaign_growth_verdict(ev)
    if kind == "outlier_burst":
        return _outlier_burst_verdict(ev)
    if kind == "campaign_convergence":
        return _convergence_verdict(ev)
    if kind == "unattributed_active_ip":
        return _unattributed_verdict(ev)
    if kind == "operation_emergence":
        return _operation_emergence_verdict(ev)
    return ""


# ---------------------------------------------------------------------------
# Membership-based verdicts (coverage + new_playbook)
# ---------------------------------------------------------------------------

def _membership_verdict(
    finding: dict[str, Any],
    ev: dict[str, Any],
    lifecycle: Optional[dict[str, Any]],
    thresholds: Optional[tuple[int, int]] = None,
) -> str:
    # Coverage findings use member_sessions/member_ips; new_playbook uses
    # session_count/ip_count. Accept either.
    sess = _as_int(ev.get("member_sessions") or ev.get("session_count"))
    ips = _as_int(ev.get("member_ips") or ev.get("ip_count"))
    first_seen = ev.get("first_seen") or finding.get("first_seen_at")
    last_seen = ev.get("last_seen") or finding.get("last_seen_at")
    runs = _as_int((lifecycle or {}).get("runs_observed"))
    return _membership_banded_verdict(
        sess, ips, first_seen, last_seen, runs, thresholds,
    )


def _membership_banded_verdict(
    sess: int, ips: int,
    first_seen: Any, last_seen: Any,
    runs: int,
    thresholds: Optional[tuple[int, int]] = None,
) -> str:
    """Primitive shared by finding-shaped and anchor-shaped callers.

    Returns one of:
      "Strong · 47 sess / 19 IPs · 12d · 9 runs"
      "Moderate · 6 sess / 4 IPs · 2d"
      "Single-point · 1 sess / 1 IP · today"
    Or an empty string when there's nothing to say.

    The Strong-band cutoff is corpus-derived when ``thresholds`` is
    supplied (callers pass the output of ``band_thresholds(es, cfg)``);
    otherwise it falls back to the historical (20, 5) constants.
    """
    window = _window_phrase(first_seen, last_seen)
    strong_sess, strong_ips = thresholds or _BAND_THRESHOLD_DEFAULT
    if sess <= 1 or ips <= 1:
        band = "Single-point"
    elif sess >= strong_sess and ips >= strong_ips:
        band = "Strong"
    else:
        band = "Moderate"
    parts: list[str] = [band]
    if sess or ips:
        parts.append(f"{sess} sess / {ips} IPs")
    if window:
        parts.append(window)
    if runs >= 3 and band != "Single-point":
        parts.append(f"{runs} runs")
    return " · ".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Per-kind verdicts
# ---------------------------------------------------------------------------

def _intel_flip_verdict(ev: dict[str, Any]) -> str:
    prev = ev.get("verdict_prev") or "no_data"
    curr = ev.get("verdict_curr") or "?"
    return f"Verdict flip · {prev} → {curr}"


def _ip_shift_verdict(ev: dict[str, Any]) -> str:
    js = _as_float(ev.get("js_distance"))
    snaps = _as_int(ev.get("snapshots_compared"))
    modal_flip = bool(ev.get("modal_flip"))
    head = "Modal flip" if modal_flip else "Distribution shift"
    parts = [head]
    if js:
        parts.append(f"JS {js:.2f}")
    if snaps:
        parts.append(f"{snaps} snapshots")
    return " · ".join(parts)


def _drift_verdict(kind: str, ev: dict[str, Any]) -> str:
    # Pick the right magnitude per drift kind. Material vs Border bands
    # use 0.30 as the cut — same threshold the drift miner uses for
    # "this is a real change" elsewhere.
    if kind == "playbook_command_drift":
        magnitude = _as_float(ev.get("command_jaccard"))
        if magnitude == 0.0 and "command_jaccard" not in ev:
            # legacy signature-only fallback
            return "Material drift · command set changed"
        band = "Material" if magnitude < 0.7 else "Border"
        return f"{band} drift · command Jaccard {magnitude:.2f}"
    if kind == "playbook_sequence_drift":
        magnitude = _as_float(ev.get("bigram_jaccard"))
        band = "Material" if magnitude < 0.7 else "Border"
        return f"{band} drift · bigram Jaccard {magnitude:.2f}"
    if kind == "playbook_artifact_drift":
        dist = _as_float(ev.get("artifact_jaccard_distance"))
        band = "Material" if dist >= 0.30 else "Border"
        return f"{band} drift · artifact distance {dist:.2f}"
    if kind == "playbook_geo_drift":
        dist = _as_float(ev.get("asn_cosine_distance"))
        band = "Material" if dist >= 0.30 else "Border"
        return f"{band} drift · ASN cosine {dist:.2f}"
    return "Drift"


def _size_drift_verdict(ev: dict[str, Any]) -> str:
    delta = _as_int(ev.get("delta_ips"))
    pct = ev.get("growth_pct")
    if pct is None:
        return f"Growth · +{delta} IPs"
    return f"Growth · +{delta} IPs ({int(round(float(pct) * 100))}%)"


def _resurgence_verdict(ev: dict[str, Any]) -> str:
    hrs = _as_float(ev.get("max_gap_hours"))
    days = hrs / 24.0 if hrs else 0.0
    if days >= 1.0:
        return f"Resurfaced · after {days:.1f}d silence"
    return "Resurfaced"


def _campaign_growth_verdict(ev: dict[str, Any]) -> str:
    # Drift module's campaign_growth carries delta_ips / growth_pct
    # OR ip_count_current / ip_count_anchor depending on path. Be lenient.
    delta = _as_int(ev.get("delta_ips") or (
        _as_int(ev.get("ip_count_current")) - _as_int(ev.get("ip_count_anchor"))
    ))
    pct = ev.get("growth_pct")
    if delta <= 0:
        return "Growth · campaign expanded"
    if pct is None:
        return f"Growth · +{delta} IPs"
    return f"Growth · +{delta} IPs ({int(round(float(pct) * 100))}%)"


def _outlier_burst_verdict(ev: dict[str, Any]) -> str:
    sess = _as_int(ev.get("session_count"))
    ips = _as_int(ev.get("ip_count"))
    if sess or ips:
        return f"Burst · {sess} sess / {ips} IPs"
    return "Burst"


def _convergence_verdict(ev: dict[str, Any]) -> str:
    shared = _as_int(ev.get("shared_ip_count") or ev.get("shared_ips"))
    if shared:
        return f"Overlap · {shared} shared IPs"
    return "Overlap"


def _unattributed_verdict(ev: dict[str, Any]) -> str:
    sess = _as_int(ev.get("session_count"))
    if sess:
        return f"Unattributed · {sess} sess"
    return "Unattributed"


def _operation_emergence_verdict(ev: dict[str, Any]) -> str:
    """Brutal-review 7.3 — verdict for operation_emergence findings.

    Two flavors:
      "Formed · 73 shared IPs · 60% overlap"
      "Grew · 73 → 142 shared IPs · ×1.95"

    The `event` field distinguishes the two — same finding kind, same
    artifact, different `delta_signature`. Falls back to a minimal
    "Operation" verdict when evidence is sparse.
    """
    event = (ev.get("event") or "").lower()
    shared = _as_int(ev.get("shared_ip_count"))
    if event == "grew":
        prior = _as_int(ev.get("shared_ip_count_prior"))
        if prior > 0 and shared > prior:
            return (
                f"Grew · {prior} → {shared} shared IPs · "
                f"×{(shared / prior):.2f}"
            )
        return f"Grew · {shared} shared IPs"
    # Default + formed path
    overlap = ev.get("overlap_ratio")
    parts = ["Formed"]
    if shared:
        parts.append(f"{shared} shared IPs")
    if isinstance(overlap, (int, float)) and overlap > 0:
        parts.append(f"{int(round(overlap * 100))}% overlap")
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_int(v: Any) -> int:
    try:
        if v is None:
            return 0
        return int(v)
    except (TypeError, ValueError):
        return 0


def _as_float(v: Any) -> float:
    try:
        if v is None:
            return 0.0
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _parse_iso(ts: Any) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _window_phrase(first_seen: Any, last_seen: Any) -> str:
    """Compact window string: '12d', '6h', 'today', or ''.

    Uses first→last span when both present; falls back to silence on
    missing data rather than guessing.
    """
    a = _parse_iso(first_seen)
    b = _parse_iso(last_seen)
    if not a or not b:
        return ""
    delta = b - a
    secs = delta.total_seconds()
    if secs < 0:
        return ""
    days = secs / 86400.0
    if days >= 1.5:
        return f"{int(round(days))}d"
    hours = secs / 3600.0
    if hours >= 1.0:
        return f"{int(round(hours))}h"
    return "today"


# ---------------------------------------------------------------------------
# Anchor-shaped verdicts (graph anchors / IOCDetail surfaces)
# ---------------------------------------------------------------------------
#
# Findings carry an `evidence` block keyed by finding kind. Graph anchors
# carry an IOCDetail `summary` keyed by anchor type. Different shapes,
# same vocabulary. format_anchor_evidence_quality dispatches by anchor
# type and reuses the same membership-banded primitive as findings.
#
# Consumed by:
#   - The graph orientation card via state.currentDetail.evidence_quality
#   - The /browse catalog rows (Item C of the analyst-first UX patch)
#   - Per-IOC artifact pages (/artifact/ip, /artifact/url, /artifact/hash)


def format_anchor_evidence_quality(
    anchor_type: str,
    summary: dict[str, Any],
    lifecycle: Optional[dict[str, Any]] = None,
    *,
    thresholds: Optional[tuple[int, int]] = None,
) -> str:
    """Anchor-shaped verdict — same vocabulary as findings, different input.

    Examples by anchor type:
      playbook  →  "Strong · 47 sess / 19 IPs · 12d · 9 runs"
      campaign  →  "Strong · 275 sess / 73 IPs · 12d"
      ip        →  "Active · 18 sess / 142 commands · 7d"
                or "Single-point · 1 session · today"
      session_cluster  → "19 members · playbook anchored"
      ip_cluster       → "47 members"
      command_cluster  → "39 members"

    Returns an empty string when nothing useful applies (e.g. asn,
    country, mitre anchors — those have their own count surfaces).
    """
    if not isinstance(summary, dict):
        return ""
    if not anchor_type:
        return ""

    if anchor_type == "playbook":
        return _membership_banded_verdict(
            sess=_as_int(summary.get("session_count")),
            ips=_as_int(summary.get("ip_count")),
            first_seen=summary.get("first_seen"),
            last_seen=summary.get("last_seen"),
            runs=_as_int((lifecycle or {}).get("runs_observed")),
            thresholds=thresholds,
        )
    if anchor_type == "campaign":
        return _membership_banded_verdict(
            sess=_as_int(summary.get("session_count")),
            ips=_as_int(summary.get("ip_count")),
            first_seen=summary.get("first_seen"),
            last_seen=summary.get("last_seen"),
            runs=_as_int((lifecycle or {}).get("runs_observed")),
            thresholds=thresholds,
        )
    if anchor_type == "ip":
        return _ip_anchor_verdict(summary, lifecycle)
    if anchor_type in ("session_cluster", "ip_cluster", "command_cluster"):
        return _cluster_anchor_verdict(anchor_type, summary)
    return ""


def _ip_anchor_verdict(
    summary: dict[str, Any], lifecycle: Optional[dict[str, Any]],
) -> str:
    """IPs are single-IP by nature — Strong/Moderate/Single-point doesn't
    apply the same way. Report activity volume + time window honestly.
    """
    sess = _as_int(summary.get("total_sessions"))
    cmds = _as_int(summary.get("total_commands"))
    first = summary.get("first_seen")
    last = summary.get("last_seen")
    window = _window_phrase(first, last)
    # Activity band: a one-session probe reads differently from a
    # 200-session beachhead. Bands intentionally permissive — the analyst
    # gets a hint, not a final word.
    if sess <= 1 and cmds <= 1:
        band = "Single-point"
    elif sess >= 10 or cmds >= 50:
        band = "Active"
    else:
        band = "Light"
    parts: list[str] = [band]
    if sess or cmds:
        bits = []
        if sess: bits.append(f"{sess} sess")
        if cmds: bits.append(f"{cmds} commands")
        parts.append(" / ".join(bits))
    if window:
        parts.append(window)
    return " · ".join(p for p in parts if p)


def _cluster_anchor_verdict(
    anchor_type: str, summary: dict[str, Any],
) -> str:
    """Cluster anchors carry `size`; until per-cluster centroid-cohesion
    stats land (open audit item), the verdict is honestly just the
    member count + (for session clusters) whether a playbook anchored.
    """
    size = _as_int(summary.get("size"))
    if not size:
        return ""
    if anchor_type == "session_cluster" and summary.get("playbook_name"):
        return f"{size} members · playbook anchored"
    return f"{size} members"
