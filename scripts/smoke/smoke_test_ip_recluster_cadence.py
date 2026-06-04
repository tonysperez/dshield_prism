"""IP-layer re-cluster cadence + incremental assign (backlog scale-hardening B0.5).

The IP layer has no windowing escape valve and a full HDBSCAN over the embedded
IP set is O(n^2) (eval/results/B0-preflight-loadtest.md). `ip.full_recluster_weekly`
moves the full fit off the 6-hourly backward chain onto the weekly
`dshield_prism-recluster-full` timer; in the 6h chain `cluster ips` instead runs
the cheap incremental **nearest-centroid assign** (Option B): new IPs land on the
nearest existing centroid, no HDBSCAN.

Sections:
  [1] shipped default is legacy (full re-cluster every backward run).
  [2] `_ip_full_recluster_skipped` gate matrix (flag x window_days).
  [3] `run_assign` nearest-centroid math — each unassigned IP is mapped to its
      nearest pure-embedding centroid; zero / dim-mismatch vectors are skipped;
      no completed run → skipped="no_centroids". ES is monkeypatched (no I/O).

Standalone — no real ES, no pytest. Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_ip_recluster_cadence.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from enrich import clustering as clustering_mod
from enrich import config as config_mod
from enrich.cli import _ip_full_recluster_skipped
from enrich.sources.cowrie import ips as ips_mod

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


cfg = config_mod.load_config(str(REPO / "config" / "default.yaml"))

print("\n[1] shipped default is legacy (full re-cluster every backward run)")
check("ip.full_recluster_weekly defaults False", cfg.ip.full_recluster_weekly is False,
      repr(cfg.ip.full_recluster_weekly))
check("default + no window → not skipped",
      _ip_full_recluster_skipped(cfg, None) is False)
check("default + window 0 → not skipped",
      _ip_full_recluster_skipped(cfg, 0) is False)

print("\n[2] flag on → 6h backward run skips full fit, weekly forced pass does not")
cfg.ip.full_recluster_weekly = True
check("flag on + no window → skipped (runs assign instead)",
      _ip_full_recluster_skipped(cfg, None) is True)
check("flag on + non-zero window → skipped",
      _ip_full_recluster_skipped(cfg, 30) is True)
check("flag on + window 0 → NOT skipped (weekly forced full)",
      _ip_full_recluster_skipped(cfg, 0) is False)


# =============================================================================
# [3] run_assign nearest-centroid math, ES monkeypatched.
# =============================================================================
print("\n[3] run_assign maps each new IP to its nearest pure-embedding centroid")


class _DummyES:
    class _Indices:
        def refresh(self, **_kw):
            return None
    indices = _Indices()


# Three orthogonal unit centroids in a 4-dim toy embedding space.
_CENTROIDS = {
    "cluster_0": [1.0, 0.0, 0.0, 0.0],
    "cluster_1": [0.0, 1.0, 0.0, 0.0],
    "cluster_2": [0.0, 0.0, 1.0, 0.0],
}
# (doc_id, embedding) — near-0, near-1, near-2, a zero vec (skip), wrong dim (skip).
_NEW_IPS = [
    ("ip_a", [0.9, 0.1, 0.0, 0.0]),
    ("ip_b", [0.2, 0.8, 0.1, 0.0]),
    ("ip_c", [0.0, 0.1, 0.95, 0.0]),
    ("ip_zero", [0.0, 0.0, 0.0, 0.0]),
    ("ip_baddim", [1.0, 0.0]),
]
_EXPECT = {"ip_a": "cluster_0", "ip_b": "cluster_1", "ip_c": "cluster_2"}


def _run_with(centroids, new_ips):
    """Invoke run_assign(dry_run=False) with ES/loaders patched; capture the
    bulk_write actions instead of writing."""
    captured: list[dict] = []
    orig = {
        "make_client": ips_mod.make_client,
        "bulk_write": ips_mod.bulk_write,
        "iter": ips_mod._iter_unassigned_embedded_ips,
        "load": clustering_mod.load_run_centroids,
    }
    ips_mod.make_client = lambda *_a, **_k: _DummyES()
    ips_mod.bulk_write = lambda _es, _idx, actions: (captured.extend(actions), (len(actions), []))[1]
    ips_mod._iter_unassigned_embedded_ips = lambda _es, _idx, _ps: iter(new_ips)
    clustering_mod.load_run_centroids = lambda _es, _idx: dict(centroids)
    try:
        stats = ips_mod.run_assign(cfg, None, dry_run=False)
    finally:
        ips_mod.make_client = orig["make_client"]
        ips_mod.bulk_write = orig["bulk_write"]
        ips_mod._iter_unassigned_embedded_ips = orig["iter"]
        clustering_mod.load_run_centroids = orig["load"]
    return stats, captured


stats, actions = _run_with(_CENTROIDS, _NEW_IPS)
by_id = {a["_id"]: a["script"]["params"] for a in actions}

check("assigned the 3 valid IPs (zero + bad-dim skipped)", stats["assigned"] == 3,
      str(stats))
check("candidates counted all 5 scanned", stats["candidates"] == 5, str(stats))
for ip, want in _EXPECT.items():
    check(f"{ip} → {want}", by_id.get(ip, {}).get("cluster_id") == want,
          str(by_id.get(ip)))
check("ip_zero not assigned", "ip_zero" not in by_id)
check("ip_baddim not assigned", "ip_baddim" not in by_id)
check("assign leaves is_outlier False",
      all(p["is_outlier"] is False for p in by_id.values()))
check("novelty_score in [0,1]",
      all(0.0 <= p["novelty_score"] <= 1.0 for p in by_id.values()))

stats_empty, actions_empty = _run_with({}, _NEW_IPS)
check("no centroids → skipped=no_centroids, nothing assigned",
      stats_empty.get("skipped") == "no_centroids" and not actions_empty,
      str(stats_empty))


# =============================================================================
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
