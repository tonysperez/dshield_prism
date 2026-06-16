"""Smoke test: incremental rollups preserve cross-writer cluster / playbook
fields across their full-document re-index.

Regression guard for the forward-pipeline bug where `rollup ips` (every 30 min)
re-indexed each active IP's rollup doc with `_op_type: index`, wiping the
`dshield.cowrie.enrichment.ip.cluster` block that only the backward `cluster ips`
step writes — so IP cluster membership vanished from the console between backward
runs. The session layer carries the same kind of cross-writer fields and is
guarded defensively.

Three assertions:
  1. `fetch_source_subset` chunks `mget`, returns only `found` docs pruned to
     the requested `_source` paths, and tolerates a missing index.
  2. `_preserve_ip_cluster` grafts a prior cluster block onto a freshly built
     `_build_ip_doc` output without disturbing the recomputed rollup fields.
  3. `_preserve_session_attribution` preserves each cluster / playbook field
     independently (a session with `cluster` but no `playbook_*` is fine).

Run standalone from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_rollup_cluster_preservation.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.es_client import deep_get, fetch_source_subset
from enrich.sources.cowrie.ips import (
    _IP_CLUSTER_FIELD,
    _build_ip_doc,
    _preserve_ip_cluster,
)
from enrich.sources.cowrie.sessions import (
    _SESSION_PRESERVE_FIELDS,
    _preserve_session_attribution,
)


# ---------------------------------------------------------------------------
# Fake ES double — just enough surface for fetch_source_subset.
# ---------------------------------------------------------------------------
def _prune(source: dict, paths) -> dict:
    """Emulate an ES `_source` filter: keep only the requested dotted paths."""
    out: dict = {}
    for p in paths:
        val = deep_get(source, p)
        if val is None:
            continue
        cur = out
        keys = p.split(".")
        for k in keys[:-1]:
            cur = cur.setdefault(k, {})
        cur[keys[-1]] = val
    return out


class _FakeIndices:
    def __init__(self, exists: bool):
        self._exists = exists

    def exists(self, index=None) -> bool:
        return self._exists


class _FakeES:
    def __init__(self, store: dict, index_exists: bool = True):
        self._store = store  # {doc_id: full _source}
        self.indices = _FakeIndices(index_exists)
        self.mget_calls = 0

    def mget(self, index=None, ids=None, _source=None):
        self.mget_calls += 1
        docs = []
        for i in ids:
            if i in self._store:
                docs.append({"_id": i, "found": True,
                             "_source": _prune(self._store[i], _source)})
            else:
                docs.append({"_id": i, "found": False})
        return {"docs": docs}


def _check_fetch_source_subset() -> None:
    # 2500 stored docs, plus we'll request 100 ids that don't exist.
    store = {
        f"ip-{n}": {
            "dshield": {"cowrie": {"enrichment": {"ip": {
                "cluster": {"id": f"ipcl_{n}", "is_outlier": False},
                "total_sessions": n,  # NOT requested — must be pruned out
            }}}},
        }
        for n in range(2500)
    }
    es = _FakeES(store)
    ids = [f"ip-{n}" for n in range(2500)] + [f"missing-{n}" for n in range(100)]

    out = fetch_source_subset(es, "ips", ids, [_IP_CLUSTER_FIELD], chunk_size=1000)

    assert len(out) == 2500, f"expected 2500 found docs, got {len(out)}"
    assert "missing-0" not in out, "not-found docs must be excluded"
    # 2600 ids / 1000 per chunk => 3 mget calls.
    assert es.mget_calls == 3, f"expected 3 chunked mget calls, got {es.mget_calls}"
    # Pruned to the requested path only.
    sample = out["ip-7"]
    assert deep_get(sample, _IP_CLUSTER_FIELD) == {"id": "ipcl_7", "is_outlier": False}
    assert deep_get(sample, "dshield.cowrie.enrichment.ip.total_sessions") is None, \
        "unrequested field leaked through the _source filter"

    # Missing index → {} (no raise).
    es_missing = _FakeES(store, index_exists=False)
    assert fetch_source_subset(es_missing, "ips", ids, [_IP_CLUSTER_FIELD]) == {}
    assert es_missing.mget_calls == 0, "must not mget when the index is absent"

    # Empty id list → {} (no call).
    assert fetch_source_subset(es, "ips", [], [_IP_CLUSTER_FIELD]) == {}

    print("  [ok] fetch_source_subset: chunking, found-filter, pruning, missing-index")


def _check_ip_cluster_graft() -> None:
    cfg = SimpleNamespace(ip=SimpleNamespace(embed_version="test-v1"))
    sessions = [
        {
            "dshield": {"cowrie": {"enrichment": {"session": {
                "command_count": 3, "login_success_count": 1,
            }}}},
            "event": {"start": "2026-06-01T00:00:00Z", "end": "2026-06-01T00:05:00Z"},
            "source": {"ip": "1.2.3.4"},
        },
    ]
    doc = _build_ip_doc("1.2.3.4", sessions, cfg)
    # A freshly built rollup doc has no cluster block.
    assert deep_get(doc, _IP_CLUSTER_FIELD) is None
    fresh_total = deep_get(doc, "dshield.cowrie.enrichment.ip.total_sessions")
    assert fresh_total == 1

    prior = {"dshield": {"cowrie": {"enrichment": {"ip": {
        "cluster": {"id": "ipcl_42", "novelty_score": 0.7, "is_outlier": False},
        "total_sessions": 999,  # stale value that must NOT win
    }}}}}

    assert _preserve_ip_cluster(doc, prior) is True
    # Clobber is gone: cluster block restored ...
    assert deep_get(doc, "dshield.cowrie.enrichment.ip.cluster.id") == "ipcl_42"
    # ... but the rollup-owned recompute still wins.
    assert deep_get(doc, "dshield.cowrie.enrichment.ip.total_sessions") == fresh_total == 1

    # No prior doc / no cluster block → no-op, returns False.
    doc2 = _build_ip_doc("1.2.3.4", sessions, cfg)
    assert _preserve_ip_cluster(doc2, None) is False
    assert _preserve_ip_cluster(doc2, {"dshield": {"cowrie": {"enrichment": {"ip": {}}}}}) is False
    assert deep_get(doc2, _IP_CLUSTER_FIELD) is None

    print("  [ok] _preserve_ip_cluster: restores cluster, recompute wins, safe no-op")


def _check_session_attribution_graft() -> None:
    def _fresh() -> dict:
        return {"dshield": {"cowrie": {"enrichment": {"session": {
            "command_count": 5,
        }}}}}

    sess_path = "dshield.cowrie.enrichment.session"

    # Full prior attribution → all four fields preserved.
    full = {"dshield": {"cowrie": {"enrichment": {"session": {
        "cluster": {"id": "scl_3", "is_outlier": False},
        "playbook_id": "spb-abc123",
        "playbook_name": "credential harvest",
        "playbook_named_at": "2026-06-01T06:00:00Z",
    }}}}}
    doc = _fresh()
    assert _preserve_session_attribution(doc, full) is True
    for path in _SESSION_PRESERVE_FIELDS:
        leaf = path.rsplit(".", 1)[1]
        assert deep_get(doc, f"{sess_path}.{leaf}") == deep_get(full, path), leaf
    # Recomputed field untouched.
    assert deep_get(doc, f"{sess_path}.command_count") == 5

    # Cluster but no playbook (the re-cluster step clears the label) → cluster
    # preserved, playbook fields stay absent.
    cluster_only = {"dshield": {"cowrie": {"enrichment": {"session": {
        "cluster": {"id": "scl_9", "is_outlier": True},
    }}}}}
    doc2 = _fresh()
    assert _preserve_session_attribution(doc2, cluster_only) is True
    assert deep_get(doc2, f"{sess_path}.cluster.id") == "scl_9"
    assert deep_get(doc2, f"{sess_path}.playbook_id") is None

    # No prior doc → no-op.
    doc3 = _fresh()
    assert _preserve_session_attribution(doc3, None) is False
    assert deep_get(doc3, f"{sess_path}.cluster") is None

    print("  [ok] _preserve_session_attribution: independent fields, recompute kept")


def main() -> int:
    print("smoke: rollup cluster/playbook preservation")
    _check_fetch_source_subset()
    _check_ip_cluster_graft()
    _check_session_attribution_graft()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
