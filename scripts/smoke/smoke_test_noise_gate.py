"""Smoke test for the noise-threshold safety valve
(brutal-review phase 4.5).

Asserts:
  * Output below threshold passes through unchanged.
  * Output above threshold is suppressed; warning logged.
  * Unknown artifact.kind (no denominator) skips the gate and passes
    through with skip_reason recorded.
  * Disabled gate (threshold_pct=0) passes everything.
  * Per-kind isolation: one miner being gated doesn't affect another.

Pure-function offline; stubs ES with synthetic per-index counts.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_noise_gate.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.findings.miner import apply_noise_gate

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _FakeIndices:
    def __init__(self, present: dict[str, bool]) -> None:
        self.present = present
    def exists(self, *, index: str) -> bool:
        return self.present.get(index, True)


class _FakeES:
    """`counts` maps index name -> doc count. exists() returns True
    unless explicitly set False in `missing_indexes`."""
    def __init__(self, *, counts: dict[str, int],
                 missing_indexes: set[str] | None = None) -> None:
        self.counts = counts
        self.indices = _FakeIndices(
            dict.fromkeys(missing_indexes or set(), False)
        )
    def count(self, *, index: str, **kwargs):
        return {"count": self.counts.get(index, 0)}


class _Cfg:
    class findings:
        class indexes:
            source_ip_lifecycle = "lc-ip"
            playbook_lifecycle = "lc-pb"
    class elasticsearch:
        class indexes:
            class cowrie:
                campaigns = "camp-idx"


def _finding(kind: str, artifact_kind: str, value: str) -> dict:
    return {"kind": kind, "artifact": {"kind": artifact_kind, "value": value}}


# ---------------------------------------------------------------------------
# [1] Under-threshold output passes through unchanged.
# ---------------------------------------------------------------------------
print("[1] below-threshold output passes through")

es = _FakeES(counts={"lc-ip": 10_000})
findings = {"ip_behavior_shift": [_finding("ip_behavior_shift", "ip", f"1.1.1.{i}")
                                  for i in range(40)]}
gated, stats = apply_noise_gate(findings, es, _Cfg, threshold_pct=0.005)
check("findings preserved",
      len(gated["ip_behavior_shift"]) == 40, str(len(gated["ip_behavior_shift"])))
check("stats: gated=False",
      stats["ip_behavior_shift"]["gated"] is False)
check("stats: share computed correctly",
      stats["ip_behavior_shift"]["share_pct"] == 0.4)


# ---------------------------------------------------------------------------
# [2] Over-threshold output is suppressed.
# ---------------------------------------------------------------------------
print("\n[2] over-threshold output is suppressed")

es = _FakeES(counts={"lc-ip": 10_000})
findings = {"ip_behavior_shift": [_finding("ip_behavior_shift", "ip", f"1.1.1.{i}")
                                  for i in range(2000)]}
gated, stats = apply_noise_gate(findings, es, _Cfg, threshold_pct=0.005)
check("findings suppressed to []",
      gated["ip_behavior_shift"] == [], str(gated))
check("stats: gated=True",
      stats["ip_behavior_shift"]["gated"] is True)
check("stats: emitted count preserved",
      stats["ip_behavior_shift"]["emitted"] == 2000)
check("stats: share = 20%",
      stats["ip_behavior_shift"]["share_pct"] == 20.0)


# ---------------------------------------------------------------------------
# [3] Boundary: exactly at threshold (not strictly greater) passes through.
# ---------------------------------------------------------------------------
print("\n[3] boundary: exactly at threshold passes")

es = _FakeES(counts={"lc-ip": 10_000})
findings = {"ip_behavior_shift": [_finding("ip_behavior_shift", "ip", f"1.1.1.{i}")
                                  for i in range(50)]}  # exactly 0.5%
gated, stats = apply_noise_gate(findings, es, _Cfg, threshold_pct=0.005)
check("at-threshold passes through",
      gated["ip_behavior_shift"] == findings["ip_behavior_shift"],
      f"gated={len(gated['ip_behavior_shift'])}")


# ---------------------------------------------------------------------------
# [4] Unknown artifact.kind skips the gate with reason recorded.
# ---------------------------------------------------------------------------
print("\n[4] unknown artifact.kind skips gate")

es = _FakeES(counts={"lc-ip": 10_000, "lc-pb": 50})
findings = {"campaign_convergence": [_finding("campaign_convergence", "campaign_pair",
                                              f"cmp-beh-{i}+cmp-inf-x")
                                     for i in range(500)]}
gated, stats = apply_noise_gate(findings, es, _Cfg, threshold_pct=0.005)
check("unknown kind passes through (no gate applied)",
      len(gated["campaign_convergence"]) == 500)
check("skip_reason recorded",
      "skip_reason" in stats["campaign_convergence"]
      and "campaign_pair" in stats["campaign_convergence"]["skip_reason"])
check("not flagged as gated",
      stats["campaign_convergence"]["gated"] is False)


# ---------------------------------------------------------------------------
# [5] Disabled gate (threshold_pct=0) passes everything.
# ---------------------------------------------------------------------------
print("\n[5] threshold_pct=0 disables the gate")

es = _FakeES(counts={"lc-ip": 100})  # 50 findings / 100 = 50% — would be gated at 0.5%
findings = {"ip_behavior_shift": [_finding("ip_behavior_shift", "ip", f"1.1.1.{i}")
                                  for i in range(50)]}
gated, stats = apply_noise_gate(findings, es, _Cfg, threshold_pct=0.0)
check("disabled gate preserves output",
      len(gated["ip_behavior_shift"]) == 50)
check("disabled gate emits no stats",
      stats == {}, str(stats))


# ---------------------------------------------------------------------------
# [6] Per-kind isolation: one over-threshold miner doesn't affect another.
# ---------------------------------------------------------------------------
print("\n[6] one gated miner doesn't affect others")

es = _FakeES(counts={"lc-ip": 10_000, "lc-pb": 100})
findings = {
    "ip_behavior_shift": [_finding("ip_behavior_shift", "ip", f"1.1.1.{i}")
                          for i in range(2000)],   # 20% — gated
    "new_playbook":      [_finding("new_playbook", "playbook", f"spb-{i:04x}")
                          for i in range(2)],      # 2% — gated against pb=100
    "playbook_command_drift": [_finding("playbook_command_drift", "playbook",
                                        f"spb-{i:04x}") for i in range(0)],
}
# Tweak: bring new_playbook below threshold by adding more playbooks.
es = _FakeES(counts={"lc-ip": 10_000, "lc-pb": 1000})
findings = {
    "ip_behavior_shift": [_finding("ip_behavior_shift", "ip", f"1.1.1.{i}")
                          for i in range(2000)],   # 20% — gated
    "new_playbook":      [_finding("new_playbook", "playbook", f"spb-{i:04x}")
                          for i in range(3)],      # 0.3% — passes
}
gated, stats = apply_noise_gate(findings, es, _Cfg, threshold_pct=0.005)
check("ip_behavior_shift gated",
      gated["ip_behavior_shift"] == [])
check("new_playbook preserved",
      len(gated["new_playbook"]) == 3)
check("gate isolation: stats[ip].gated=True",
      stats["ip_behavior_shift"]["gated"] is True)
check("gate isolation: stats[playbook].gated=False",
      stats["new_playbook"]["gated"] is False)


# ---------------------------------------------------------------------------
# [7] Empty input is a no-op.
# ---------------------------------------------------------------------------
print("\n[7] empty findings list — no-op")

es = _FakeES(counts={"lc-ip": 10_000})
gated, stats = apply_noise_gate({"ip_behavior_shift": []}, es, _Cfg, threshold_pct=0.005)
check("empty findings unchanged",
      gated == {"ip_behavior_shift": []})


# ---------------------------------------------------------------------------
# [8] Missing source index → denominator 0 → skip gate.
# ---------------------------------------------------------------------------
print("\n[8] missing source index skips the gate")

es = _FakeES(counts={"lc-ip": 0}, missing_indexes={"lc-ip"})
findings = {"ip_behavior_shift": [_finding("ip_behavior_shift", "ip", f"1.1.1.{i}")
                                  for i in range(50)]}
gated, stats = apply_noise_gate(findings, es, _Cfg, threshold_pct=0.005)
check("missing index — findings pass through",
      len(gated["ip_behavior_shift"]) == 50)
check("missing index — denominator=0 in stats",
      stats["ip_behavior_shift"]["denominator"] == 0)


# ---------------------------------------------------------------------------
print()
print(f"{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for n, d in FAILED:
        print(f"  - {n}: {d}")
    sys.exit(1)
sys.exit(0)
