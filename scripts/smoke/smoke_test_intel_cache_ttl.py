#!/usr/bin/env python3
"""Smoke test: intel refresh per-kind cache age-out.

Covers the freshness decision (`_fresh_within_ttl`) and the per-kind TTL
config (`IntelRefreshTTLConfig.for_kind`) without a live ES — a stub client
answers `indices.exists` + `mget` so the cutoff comparison, missing-doc =
stale, and TTL=0 = disabled paths are all exercised offline.

Run: ./console/.venv/bin/python scripts/smoke_test_intel_cache_ttl.py
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from types import SimpleNamespace

from enrich.config import IntelConfig, IntelRefreshTTLConfig
from enrich.intel.refresh import _fresh_within_ttl


class _StubIndices:
    def __init__(self, exists: bool) -> None:
        self._exists = exists

    def exists(self, index: str) -> bool:
        return self._exists


class _StubES:
    """Minimal ES stand-in: `last_refreshed` per id, served via mget."""

    def __init__(self, last_refreshed: dict[str, str], *, index_exists: bool = True) -> None:
        self._lr = last_refreshed
        self.indices = _StubIndices(index_exists)

    def mget(self, *, index: str, ids: list[str], _source=None):
        docs = []
        for i in ids:
            if i in self._lr:
                docs.append({"_id": i, "found": True,
                             "_source": {"last_refreshed": self._lr[i]}})
            else:
                docs.append({"_id": i, "found": False})
        return {"docs": docs}


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def main() -> int:
    # `_fresh_within_ttl` only reads `cfg.intel.indexes` (via index_for_kind);
    # a full AppConfig isn't needed, so shim just the intel sub-config.
    cfg = SimpleNamespace(intel=IntelConfig())  # defaults: hash ttl=30d, ip=7d
    now = datetime(2026, 5, 29, 12, 0, 0, tzinfo=UTC)
    fresh_ts = _iso(now - timedelta(days=2))     # within 30d and 7d
    stale_ts = _iso(now - timedelta(days=40))    # beyond every default TTL
    naive_ts = (now - timedelta(days=2)).replace(tzinfo=None).isoformat()  # no tz

    es = _StubES({
        "fresh": fresh_ts,
        "stale": stale_ts,
        "naive_fresh": naive_ts,
        # "missing" intentionally absent → never looked up
    })
    values = ["fresh", "stale", "naive_fresh", "missing"]

    failures: list[str] = []

    def check(name: str, got, want) -> None:
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")
        print(f"  {'ok ' if got == want else 'FAIL'} {name}: {got!r}")

    # 1. hash TTL=30d: fresh + naive_fresh skipped; stale + missing queried.
    out = _fresh_within_ttl(es, cfg, "hash", values, 30.0, now=now)
    check("hash@30d skips fresh+naive", out, {"fresh", "naive_fresh"})

    # 2. TTL=0 disables the skip entirely.
    check("ttl=0 skips nothing", _fresh_within_ttl(es, cfg, "hash", values, 0.0, now=now), set())

    # 3. Tiny TTL ages everything out.
    check("ttl~1s skips nothing", _fresh_within_ttl(es, cfg, "hash", values, 1e-5, now=now), set())

    # 4. Long TTL still excludes the missing doc (never looked up → stale).
    out = _fresh_within_ttl(es, cfg, "hash", values, 1000.0, now=now)
    check("missing doc never fresh", "missing" in out, False)

    # 5. Index absent → empty (nothing to skip; everything gets queried).
    es_noidx = _StubES({"fresh": fresh_ts}, index_exists=False)
    check("no index → empty", _fresh_within_ttl(es_noidx, cfg, "hash", ["fresh"], 30.0, now=now), set())

    # 6. for_kind mapping + unknown-kind default.
    ttl = IntelRefreshTTLConfig()
    check("for_kind hash", ttl.for_kind("hash"), 30.0)
    check("for_kind ip", ttl.for_kind("ip"), 7.0)
    check("for_kind unknown=0", ttl.for_kind("nope"), 0.0)

    print()
    if failures:
        print(f"FAILED ({len(failures)}):")
        for f in failures:
            print("  -", f)
        return 1
    print("All intel cache-TTL smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
