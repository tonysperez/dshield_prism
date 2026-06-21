"""Smoke test for `enrich.findings.evidence_quality` — the one-line
verdict string the inbox row + drawer + graph orientation card all
consume.

Pure-function only; no ES, no config.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_evidence_quality.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.findings.evidence_quality import (  # noqa: E402
    _BAND_THRESHOLD_CACHE,
    _BAND_THRESHOLD_DEFAULT,
    band_thresholds,
    format_anchor_evidence_quality,
    format_evidence_quality,
)


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# ---------------------------------------------------------------------------
# Coverage findings — playbook / campaign / new_playbook
# ---------------------------------------------------------------------------
print("[1] coverage findings (membership-banded verdict)")

f_strong = {
    "kind": "playbook",
    "evidence": {
        "member_sessions": 47, "member_ips": 19,
        "first_seen": "2026-05-18T00:00:00Z",
        "last_seen":  "2026-05-30T00:00:00Z",
    },
}
v = format_evidence_quality(f_strong)
check("strong band labels 'Strong'", v.startswith("Strong · "), v)
check("strong band carries counts", "47 sess / 19 IPs" in v, v)
check("strong band carries window", "12d" in v, v)

f_moderate = {
    "kind": "campaign",
    "evidence": {
        "member_sessions": 6, "member_ips": 4,
        "first_seen": "2026-05-28T00:00:00Z",
        "last_seen":  "2026-05-30T00:00:00Z",
    },
}
v = format_evidence_quality(f_moderate)
check("moderate band labels 'Moderate'", v.startswith("Moderate · "), v)
check("moderate band carries counts", "6 sess / 4 IPs" in v, v)
check("moderate band carries window", "2d" in v, v)

f_single = {
    "kind": "new_playbook",
    "evidence": {
        "session_count": 1, "ip_count": 1,
        "first_seen": "2026-05-30T00:00:00Z",
    },
}
v = format_evidence_quality(f_single)
check("single-point band labels 'Single-point'", v.startswith("Single-point · "), v)

# Lifecycle adds the "X runs" tail when established and we know runs.
v_runs = format_evidence_quality(f_strong, lifecycle={"runs_observed": 9})
check("strong + lifecycle adds runs tail", "9 runs" in v_runs, v_runs)
v_runs_low = format_evidence_quality(f_single, lifecycle={"runs_observed": 9})
check("single-point hides runs tail", "runs" not in v_runs_low, v_runs_low)

# ---------------------------------------------------------------------------
# Intel verdict flip
# ---------------------------------------------------------------------------
print("[2] intel_verdict_flip")

v = format_evidence_quality({
    "kind": "intel_verdict_flip",
    "evidence": {"verdict_prev": "clean", "verdict_curr": "malicious"},
})
check("flip verdict shows transition", v == "Verdict flip · clean → malicious", v)

v = format_evidence_quality({
    "kind": "intel_verdict_flip",
    "evidence": {"verdict_prev": None, "verdict_curr": "mixed"},
})
check("flip verdict handles missing prev", v == "Verdict flip · no_data → mixed", v)

# ---------------------------------------------------------------------------
# IP behavior shift
# ---------------------------------------------------------------------------
print("[3] ip_behavior_shift")

v = format_evidence_quality({
    "kind": "ip_behavior_shift",
    "evidence": {"modal_flip": True, "js_distance": 0.43, "snapshots_compared": 7},
})
check("modal flip head", v.startswith("Modal flip · "), v)
check("modal flip carries JS", "JS 0.43" in v, v)
check("modal flip carries snapshots", "7 snapshots" in v, v)

v = format_evidence_quality({
    "kind": "ip_behavior_shift",
    "evidence": {"modal_flip": False, "js_distance": 0.31, "snapshots_compared": 5},
})
check("distribution shift head", v.startswith("Distribution shift · "), v)

# ---------------------------------------------------------------------------
# Drift kinds
# ---------------------------------------------------------------------------
print("[4] drift kinds (magnitude-banded)")

v = format_evidence_quality({
    "kind": "playbook_command_drift",
    "evidence": {"command_jaccard": 0.42},
})
check("command drift carries Jaccard", "command Jaccard 0.42" in v, v)
check("command drift bands as Material", v.startswith("Material drift · "), v)

v = format_evidence_quality({
    "kind": "playbook_sequence_drift",
    "evidence": {"bigram_jaccard": 0.55},
})
check("sequence drift carries bigram", "bigram Jaccard 0.55" in v, v)

v = format_evidence_quality({
    "kind": "playbook_artifact_drift",
    "evidence": {"artifact_jaccard_distance": 0.45},
})
check("artifact drift Material at >= 0.30", v.startswith("Material drift · "), v)

v = format_evidence_quality({
    "kind": "playbook_geo_drift",
    "evidence": {"asn_cosine_distance": 0.18},
})
check("ASN drift bands as Border at < 0.30", v.startswith("Border drift · "), v)

# ---------------------------------------------------------------------------
# Size drift / resurgence / outlier_burst / convergence / unattributed
# ---------------------------------------------------------------------------
print("[5] miscellaneous kinds")

v = format_evidence_quality({
    "kind": "playbook_size_drift",
    "evidence": {"delta_ips": 35, "growth_pct": 1.4},
})
check("size drift", v == "Growth · +35 IPs (140%)", v)

v = format_evidence_quality({
    "kind": "playbook_resurgence",
    "evidence": {"max_gap_hours": 288.0},
})
check("resurgence in days", v == "Resurfaced · after 12.0d silence", v)

v = format_evidence_quality({
    "kind": "outlier_burst",
    "evidence": {"session_count": 14, "ip_count": 6},
})
check("outlier burst", v == "Burst · 14 sess / 6 IPs", v)

v = format_evidence_quality({
    "kind": "campaign_convergence",
    "evidence": {"shared_ip_count": 24},
})
check("campaign convergence", v == "Overlap · 24 shared IPs", v)

v = format_evidence_quality({
    "kind": "unattributed_active_ip",
    "evidence": {"session_count": 8},
})
check("unattributed active IP", v == "Unattributed · 8 sess", v)

# ---------------------------------------------------------------------------
# Defensive — missing fields, unknown kind, malformed input
# ---------------------------------------------------------------------------
print("[6] defensive paths")

check("unknown kind returns empty",
      format_evidence_quality({"kind": "totally_unknown"}) == "",
      "")
check("missing evidence returns empty for unknown",
      format_evidence_quality({}) == "",
      "")
check("non-dict input returns empty",
      format_evidence_quality(None) == "",  # type: ignore[arg-type]
      "")
check("malformed timestamps don't raise",
      format_evidence_quality({
          "kind": "playbook",
          "evidence": {"member_sessions": 4, "member_ips": 2,
                       "first_seen": "garbage", "last_seen": "also-garbage"},
      }).startswith("Moderate · "),
      "")

# ---------------------------------------------------------------------------
# Anchor-shaped verdicts (IOCDetail surfaces — graph orientation card,
# browse catalog, per-IOC artifact pages).
# ---------------------------------------------------------------------------
print("[7] format_anchor_evidence_quality — playbook + campaign")
v = format_anchor_evidence_quality("playbook", {
    "session_count": 47, "ip_count": 19,
    "first_seen": "2026-05-18T00:00:00Z",
    "last_seen":  "2026-05-30T00:00:00Z",
})
check("playbook anchor Strong band", v.startswith("Strong · "), v)
check("playbook anchor counts",       "47 sess / 19 IPs" in v, v)
check("playbook anchor window",       "12d" in v, v)

v = format_anchor_evidence_quality("playbook", {
    "session_count": 47, "ip_count": 19,
    "first_seen": "2026-05-18T00:00:00Z",
    "last_seen":  "2026-05-30T00:00:00Z",
}, lifecycle={"runs_observed": 9})
check("playbook anchor + lifecycle adds runs", "9 runs" in v, v)

v = format_anchor_evidence_quality("campaign", {
    "session_count": 275, "ip_count": 73,
    "first_seen": "2026-04-29T00:00:00Z",
    "last_seen":  "2026-05-11T00:00:00Z",
})
check("campaign anchor Strong band", v.startswith("Strong · "), v)
check("campaign anchor counts",      "275 sess / 73 IPs" in v, v)
check("campaign anchor window",      "12d" in v, v)

print("[8] format_anchor_evidence_quality — ip / cluster")
v = format_anchor_evidence_quality("ip", {
    "total_sessions": 18, "total_commands": 142,
    "first_seen": "2026-05-23T00:00:00Z",
    "last_seen":  "2026-05-30T00:00:00Z",
})
check("ip anchor Active band",      v.startswith("Active · "), v)
check("ip anchor sess + commands",  "18 sess / 142 commands" in v, v)
check("ip anchor window",           "7d" in v, v)

v = format_anchor_evidence_quality("ip", {
    "total_sessions": 1, "total_commands": 0,
})
check("ip anchor single-point",     v.startswith("Single-point · "), v)

v = format_anchor_evidence_quality("session_cluster", {
    "size": 19, "playbook_name": "SSH Key Installer",
})
check("session_cluster anchored with playbook",
      v == "19 members · playbook anchored", v)
v = format_anchor_evidence_quality("ip_cluster", {"size": 47})
check("ip_cluster size only",       v == "47 members", v)
v = format_anchor_evidence_quality("command_cluster", {"size": 39})
check("command_cluster size only",  v == "39 members", v)

print("[9] format_anchor_evidence_quality — empty for non-anchored kinds")
check("asn returns empty",          format_anchor_evidence_quality("asn", {"asn": "12345"}) == "")
check("country returns empty",      format_anchor_evidence_quality("country", {"country_iso_code": "US"}) == "")
check("session returns empty",      format_anchor_evidence_quality("session", {"session_id": "x"}) == "")
check("command returns empty",      format_anchor_evidence_quality("command", {"sha256": "abc"}) == "")
check("unknown anchor_type empty",  format_anchor_evidence_quality("nonsense", {"size": 99}) == "")
check("None summary handled",       format_anchor_evidence_quality("playbook", None) == "")  # type: ignore[arg-type]
check("empty summary handled",      format_anchor_evidence_quality("playbook", {}) == "Single-point")

# ---------------------------------------------------------------------------
# Band-threshold override (brutal-review 4.2 — corpus-derived Strong cutoff)
# ---------------------------------------------------------------------------
print("[10] band threshold override — corpus-derived Strong cutoff")

# Default fallback: sess >= 20 AND ips >= 5. A 10/4 row is Moderate.
f_borderline = {
    "kind": "playbook",
    "evidence": {
        "member_sessions": 10, "member_ips": 4,
        "first_seen": "2026-05-28T00:00:00Z",
        "last_seen":  "2026-05-30T00:00:00Z",
    },
}
v_default = format_evidence_quality(f_borderline)
check("borderline row Moderate at default 20/5",
      v_default.startswith("Moderate · "), v_default)

# Looser thresholds (low-volume corpus): same row reads Strong at 8/3.
v_loose = format_evidence_quality(f_borderline, thresholds=(8, 3))
check("borderline row Strong at corpus-derived 8/3",
      v_loose.startswith("Strong · "), v_loose)

# Tighter thresholds (high-volume corpus): a 50/10 row is Moderate at 75/15.
f_big = {
    "kind": "playbook",
    "evidence": {
        "member_sessions": 50, "member_ips": 10,
        "first_seen": "2026-05-18T00:00:00Z",
        "last_seen":  "2026-05-30T00:00:00Z",
    },
}
v_strict = format_evidence_quality(f_big, thresholds=(75, 15))
check("big row Moderate at corpus-derived 75/15",
      v_strict.startswith("Moderate · "), v_strict)
v_strict_pass = format_evidence_quality(f_big, thresholds=(50, 10))
check("big row Strong at corpus-derived 50/10",
      v_strict_pass.startswith("Strong · "), v_strict_pass)

# Single-point rule wins even under permissive thresholds.
f_solo = {
    "kind": "new_playbook",
    "evidence": {"session_count": 1, "ip_count": 1,
                 "first_seen": "2026-05-30T00:00:00Z"},
}
v_solo = format_evidence_quality(f_solo, thresholds=(2, 2))
check("Single-point survives permissive thresholds",
      v_solo.startswith("Single-point · "), v_solo)

# Anchor-shaped verdicts pick up thresholds too.
v_anchor = format_anchor_evidence_quality("campaign", {
    "session_count": 12, "ip_count": 4,
    "first_seen": "2026-05-18T00:00:00Z",
    "last_seen":  "2026-05-30T00:00:00Z",
}, thresholds=(10, 3))
check("campaign anchor Strong under loose thresholds",
      v_anchor.startswith("Strong · "), v_anchor)

# ---------------------------------------------------------------------------
# band_thresholds — fallback + clamp + cache (no live ES)
# ---------------------------------------------------------------------------
print("[11] band_thresholds — fallback + clamp + cache")


class _FakeIndices:
    def __init__(self, present: bool) -> None:
        self.present = present
    def exists(self, *, index: str) -> bool:  # noqa: ARG002
        return self.present


class _FakeES:
    """Minimal stand-in. ``hits[]`` is a list of (kind, field, value)
    tuples; the search picks the first matching."""
    def __init__(self, present: bool, snapshots: dict[str, dict[str, float]]) -> None:
        self.indices = _FakeIndices(present)
        self.snapshots = snapshots
    def search(self, *, index, size, sort, query, _source):  # noqa: ARG002
        kind = query["term"]["kind"]
        snap = self.snapshots.get(kind)
        if snap is None:
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [{"_source": {k: snap[k] for k in _source if k in snap}}]}}


class _FakeCfg:
    class metrics:
        class indexes:
            default = "smoke.metrics.idx"


# 1) Missing index -> default fallback
_BAND_THRESHOLD_CACHE.clear()
out = band_thresholds(_FakeES(present=False, snapshots={}), _FakeCfg())
check("missing metrics index -> default fallback",
      out == _BAND_THRESHOLD_DEFAULT, str(out))

# 2) Index present but no snapshots -> default fallback
_BAND_THRESHOLD_CACHE.clear()
out = band_thresholds(_FakeES(present=True, snapshots={}), _FakeCfg())
check("present but empty -> default fallback",
      out == _BAND_THRESHOLD_DEFAULT, str(out))

# 3) Healthy snapshots -> rounded p75 returned
_BAND_THRESHOLD_CACHE.clear()
fake = _FakeES(present=True, snapshots={
    "playbook_session_count_per_run": {"p75": 33.4},
    "playbook_ip_count_per_run":      {"p75": 8.6},
})
out = band_thresholds(fake, _FakeCfg())
check("healthy snapshot returns rounded p75",
      out == (33, 9), str(out))

# 4) Clamp: p75 below 2 must clamp up to 2 (Single-point rule guard)
_BAND_THRESHOLD_CACHE.clear()
fake = _FakeES(present=True, snapshots={
    "playbook_session_count_per_run": {"p75": 0.4},
    "playbook_ip_count_per_run":      {"p75": 0.0},
})
out = band_thresholds(fake, _FakeCfg())
check("tiny-corpus p75 clamps to >= 2",
      out == (2, 2), str(out))

# 5) Cache: second call with a swapped-snapshot ES still returns the
#    cached (33, 9) until the TTL expires.
_BAND_THRESHOLD_CACHE.clear()
fake1 = _FakeES(present=True, snapshots={
    "playbook_session_count_per_run": {"p75": 33.0},
    "playbook_ip_count_per_run":      {"p75": 9.0},
})
band_thresholds(fake1, _FakeCfg())
fake2 = _FakeES(present=True, snapshots={
    "playbook_session_count_per_run": {"p75": 99.0},
    "playbook_ip_count_per_run":      {"p75": 99.0},
})
out = band_thresholds(fake2, _FakeCfg())
check("cached read returns first call's value within TTL",
      out == (33, 9), str(out))

# ---------------------------------------------------------------------------
print()
print(f"{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
