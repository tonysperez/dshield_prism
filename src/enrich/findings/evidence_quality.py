"""One-line evidence-quality verdict for a finding row.

A finding's score is an uncalibrated meta-number. The analyst needs a
plain-language read on *how strong the evidence is* — at a glance, in
the inbox table or on the graph orientation card or in a writeup
paragraph. This module produces that string.

Pure function; no ES, no config. Inputs are the finding's `_source`
shape returned by `findings.list_findings()` plus an optional lifecycle
doc (for `runs_observed` / `silent_runs_current` when available).

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

from datetime import datetime
from typing import Any, Optional


_COVERAGE_KINDS = frozenset({"playbook", "campaign", "new_playbook"})
_DRIFT_KINDS = frozenset({
    "playbook_command_drift", "playbook_artifact_drift",
    "playbook_geo_drift", "playbook_sequence_drift",
})


def format_evidence_quality(
    finding: dict[str, Any],
    lifecycle: Optional[dict[str, Any]] = None,
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
      novel_edge_session →
        "Novel edge · 1 session"
      campaign_convergence →
        "Overlap · 24 shared IPs"

    Returns an empty string when no useful evidence is available.
    """
    if not isinstance(finding, dict):
        return ""
    kind = finding.get("kind") or ""
    ev = finding.get("evidence") or {}

    if kind in _COVERAGE_KINDS:
        return _membership_verdict(finding, ev, lifecycle)
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
    if kind == "novel_edge_session":
        return _novel_edge_verdict(ev)
    if kind == "campaign_convergence":
        return _convergence_verdict(ev)
    if kind == "unattributed_active_ip":
        return _unattributed_verdict(ev)
    return ""


# ---------------------------------------------------------------------------
# Membership-based verdicts (coverage + new_playbook)
# ---------------------------------------------------------------------------

def _membership_verdict(
    finding: dict[str, Any],
    ev: dict[str, Any],
    lifecycle: Optional[dict[str, Any]],
) -> str:
    # Coverage findings use member_sessions/member_ips; new_playbook uses
    # session_count/ip_count. Accept either.
    sess = _as_int(ev.get("member_sessions") or ev.get("session_count"))
    ips = _as_int(ev.get("member_ips") or ev.get("ip_count"))
    first_seen = ev.get("first_seen") or finding.get("first_seen_at")
    last_seen = ev.get("last_seen") or finding.get("last_seen_at")
    window = _window_phrase(first_seen, last_seen)

    if sess <= 1 or ips <= 1:
        band = "Single-point"
    elif sess >= 20 and ips >= 5:
        band = "Strong"
    else:
        band = "Moderate"

    parts: list[str] = [band]
    if sess or ips:
        parts.append(f"{sess} sess / {ips} IPs")
    if window:
        parts.append(window)

    runs = _as_int((lifecycle or {}).get("runs_observed"))
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


def _novel_edge_verdict(ev: dict[str, Any]) -> str:
    edge = ev.get("edge_kind") or ev.get("kind") or ""
    if edge:
        return f"Novel edge · {edge}"
    return "Novel edge"


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
