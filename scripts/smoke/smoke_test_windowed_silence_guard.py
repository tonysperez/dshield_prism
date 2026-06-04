"""Windowed-run lifecycle silence guard (scale-hardening P1.2).

Lifecycle "presence" = "appeared in the latest session-cluster run"
(`_iter_current_playbooks` reads only the newest run's cluster docs). With
windowed clustering on, that newest run only contains playbooks active in the
last N days — so every >Nd-dormant playbook looks absent every 6h and
`increment_silent_runs` would push the whole long tail past
`resurgence_silent_runs` (8) and eventually `retire_silent_runs_playbook`
(120), then mark them all resurged at each weekly full pass.

The fix: `cluster sessions` stamps `window_days` on its `run_summary` doc, and
`run_track_lifecycles` advances the *playbook* silence accumulator ONLY when
the latest run was full-corpus (`window_days == 0`). Campaign / source-IP
layers are unwindowed and bump as before.

Scenarios:
  [1] _latest_session_cluster_window_days reads the newest run_summary's
      window_days — windowed (30), full (0), missing field (0), no
      run_summary (0), missing index (0).
  [2] run_track_lifecycles on a WINDOWED latest run: playbook silence NOT
      bumped; campaign + source_ip still bumped.
  [3] run_track_lifecycles on a FULL latest run (window_days=0): all three
      layers bumped (legacy behaviour preserved).

Standalone — no real ES, no pytest. The heavy collaborators of
run_track_lifecycles are monkeypatched so only the silence-gate path runs.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_windowed_silence_guard.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from enrich import config as config_mod
from enrich.findings import lifecycle as lc

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# =============================================================================
# [1] _latest_session_cluster_window_days — reads the newest run_summary.
# =============================================================================
print("\n[1] _latest_session_cluster_window_days reads the latest run_summary")


class _SummaryES:
    """Minimal ES stub: one configurable run_summary hit + index presence."""

    def __init__(self, hit_source, index_exists=True):
        self._hit_source = hit_source
        self.indices = type(
            "_Idx", (), {"exists": staticmethod(lambda index: index_exists)}
        )()

    def search(self, *, index, size, query, sort, _source):
        # Assert the caller asks for the newest run_summary specifically.
        assert query == {"term": {"doc_type": "run_summary"}}, query
        assert sort == [{"@timestamp": "desc"}], sort
        hits = [] if self._hit_source is None else [{"_source": self._hit_source}]
        return {"hits": {"hits": hits}}


check("windowed run_summary (window_days=30) → 30",
      lc._latest_session_cluster_window_days(_SummaryES({"window_days": 30}), "ix") == 30)
check("full run_summary (window_days=0) → 0",
      lc._latest_session_cluster_window_days(_SummaryES({"window_days": 0}), "ix") == 0)
check("pre-P1.2 run_summary (no window_days field) → 0",
      lc._latest_session_cluster_window_days(_SummaryES({}), "ix") == 0)
check("no run_summary docs → 0",
      lc._latest_session_cluster_window_days(_SummaryES(None), "ix") == 0)
check("missing index → 0 (no search attempted)",
      lc._latest_session_cluster_window_days(
          _SummaryES({"window_days": 30}, index_exists=False), "ix") == 0)


# =============================================================================
# [2]/[3] run_track_lifecycles gates the PLAYBOOK silence bump on the window.
# =============================================================================
cfg = config_mod.load_config(str(REPO / "config" / "default.yaml"))
PB_IDX = cfg.findings.indexes.playbook_lifecycle
CAMP_IDX = cfg.findings.indexes.campaign_lifecycle
IP_IDX = cfg.findings.indexes.source_ip_lifecycle


class _TrackES:
    """Only the direct es calls run_track_lifecycles makes once its
    collaborators are patched out: indices.exists / indices.refresh."""

    def __init__(self):
        self.indices = type(
            "_Idx", (), {
                "exists": staticmethod(lambda index: True),
                "refresh": staticmethod(lambda index: None),
            },
        )()


def _run_with_window(window_days: int):
    """Run run_track_lifecycles with every heavy collaborator patched out and
    the latest-run window pinned. Returns the list of indexes that
    increment_silent_runs was called on."""
    bumped: list[str] = []
    saved = {}

    def patch(name, value):
        saved[name] = getattr(lc, name)
        setattr(lc, name, value)

    # No artifacts to snapshot — exercise only the silence-gate path.
    patch("_iter_current_playbooks", lambda *a, **k: iter(()))
    patch("_iter_current_campaigns", lambda *a, **k: iter(()))
    patch("_iter_current_ips", lambda *a, **k: iter(()))
    patch("_sweep_provisional_anchors", lambda *a, **k: 0)
    patch("retire_silent_lifecycles", lambda *a, **k: 0)
    patch("_latest_session_cluster_window_days", lambda *a, **k: window_days)
    patch("increment_silent_runs",
          lambda es, index, *, current_run_id: (bumped.append(index), 0)[1])
    # Inject the stub client.
    import enrich.es_client as esc
    saved["make_client"] = esc.make_client
    esc.make_client = lambda *a, **k: _TrackES()
    try:
        stats = lc.run_track_lifecycles(cfg, None, dry_run=False)
    finally:
        for name, value in saved.items():
            if name == "make_client":
                esc.make_client = value
            else:
                setattr(lc, name, value)
    return bumped, stats


print("\n[2] windowed latest run → playbook silence NOT bumped")
bumped_w, stats_w = _run_with_window(30)
check("playbook index NOT bumped", PB_IDX not in bumped_w, str(bumped_w))
check("campaign index still bumped", CAMP_IDX in bumped_w, str(bumped_w))
check("source_ip index still bumped", IP_IDX in bumped_w, str(bumped_w))
check("stats record the skip reason",
      stats_w["playbook"].get("silent_skipped_windowed") == 30
      and stats_w["playbook"]["silent_bumped"] == 0,
      str(stats_w["playbook"]))


print("\n[3] full latest run (window_days=0) → all three layers bumped")
bumped_f, stats_f = _run_with_window(0)
check("playbook index bumped", PB_IDX in bumped_f, str(bumped_f))
check("campaign index bumped", CAMP_IDX in bumped_f, str(bumped_f))
check("source_ip index bumped", IP_IDX in bumped_f, str(bumped_f))
check("no skip reason recorded on a full run",
      "silent_skipped_windowed" not in stats_f["playbook"],
      str(stats_f["playbook"]))


# =============================================================================
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
