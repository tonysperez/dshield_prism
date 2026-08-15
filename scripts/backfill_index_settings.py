"""Quiesce / restore the rollup indices' refresh_interval around a bulk backfill.

`quiesce` — record each rollup index's current refresh_interval, then set it to
  `-1` (no periodic refresh → much faster bulk writes during `pipeline
  --backfill`).
`restore` — put each index's refresh_interval back to exactly what it was (the
  recorded value, including `null`/default if it was unset). Falls back to `30s`
  (the rollup mapping's value) only if the state file was lost, so an index is
  never left stuck at `-1`. Then removes the state file.

Wired into `dshield_prism-backfill.service` as `ExecStartPre` (quiesce) and
`ExecStopPost` (restore), so the speedup is automatic and self-reverting even if
the backfill fails or is stopped. Best-effort: it logs and always exits 0 so it
can never block or fail the backfill unit.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import contextlib

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

# In the backfill unit's ReadWritePaths (same dir as the state DB).
_STATE = Path("/var/lib/dshield_prism/backfill-index-settings.json")
# Used ONLY when the state file is lost — the rollup mapping's interval, so a
# restore can never leave an index at -1.
_FALLBACK_REFRESH = "30s"


def _rollup_indices(cfg) -> list[str]:
    cw = cfg.elasticsearch.indexes.cowrie
    return [cw.sessions_rollup, cw.ips_rollup]


def _current_refresh(es, idx):
    """The index's explicit refresh_interval, or None if it isn't set."""
    resp = es.indices.get_settings(index=idx, name="index.refresh_interval")
    for v in dict(resp).values():
        return ((v.get("settings", {}) or {}).get("index", {}) or {}).get("refresh_interval")
    return None


def quiesce(es, indices) -> None:
    saved: dict = {}
    for idx in indices:
        try:
            cur = _current_refresh(es, idx)
            saved[idx] = cur  # record before changing, so restore stays exact if the set half-fails
            es.indices.put_settings(index=idx, settings={"index": {"refresh_interval": "-1"}})
            print(f"[backfill-index-settings] quiesce {idx}: refresh_interval {cur!r} -> -1")
        except Exception as exc:  # never block the backfill
            print(f"[backfill-index-settings] quiesce {idx} FAILED: {exc}", file=sys.stderr)
    try:
        _STATE.write_text(json.dumps(saved))
    except Exception as exc:
        print(f"[backfill-index-settings] could not write {_STATE}: {exc}", file=sys.stderr)


def restore(es, indices) -> None:
    try:
        saved = json.loads(_STATE.read_text())
    except Exception:
        saved = {}  # state lost → per-index fallback below
    for idx in indices:
        # Exact original (incl. None=unset); _FALLBACK only if the key is absent.
        val = saved.get(idx, _FALLBACK_REFRESH)
        try:
            es.indices.put_settings(index=idx, settings={"index": {"refresh_interval": val}})
            print(f"[backfill-index-settings] restore {idx}: refresh_interval -> {val!r}")
        except Exception as exc:
            print(f"[backfill-index-settings] restore {idx} FAILED ({exc}) — index may be "
                  f"left at refresh_interval=-1; fix manually", file=sys.stderr)
    with contextlib.suppress(FileNotFoundError):
        _STATE.unlink()


def main() -> int:
    ap = argparse.ArgumentParser(description="Quiesce/restore rollup refresh_interval.")
    ap.add_argument("mode", choices=["quiesce", "restore"])
    ap.add_argument("--config", default="config/default.yaml")
    args = ap.parse_args()
    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    indices = _rollup_indices(cfg)
    (quiesce if args.mode == "quiesce" else restore)(es, indices)
    return 0  # best-effort: never fail the backfill unit


if __name__ == "__main__":
    raise SystemExit(main())
