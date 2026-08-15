"""Smoke test for ROADMAP #24: IP cluster centroids now carry a
`dominant_playbook_id` / `dominant_playbook_name` / `playbook_distribution`
annotation computed as a post-pass after IP clustering.

Pre-fix: IP cluster docs were unnamed actor-profile buckets — answering
"what does cluster_9 *do*?" required a multi-hop join from the console.
Post-fix: a one-pass join in `annotate_ip_clusters_with_dominant_playbook`
stamps the modal playbook (across the cluster's member IPs' sessions)
onto each centroid doc.

Determinism: ties on count resolve lexically by `playbook_id` (matches
the #15 / #17 pattern). Re-runs over unchanged data write the same value.

Standalone — no real ES, no pytest. Stub ES intercepts every API call.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_ip_dominant_playbook.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.ips import annotate_ip_clusters_with_dominant_playbook

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _Indices:
    def __init__(self) -> None:
        self.refreshes: list[str] = []
    def refresh(self, *, index: str) -> None:
        self.refreshes.append(index)


class _StubES:
    """Stub ES for the post-pass.

    Layout the stub responds to:
      - `ip_clusters_index` search → returns latest run_id and (separately
        on the same index) the cluster docs we'd update.
      - `ips_rollup_index` search → returns ip-rollup docs with cluster.id.
      - `sessions_rollup_index` search → returns session docs with
        playbook_id/name (terms filter on source.ip).
    """

    def __init__(
        self,
        *,
        run_id: str = "run-A",
        ip_to_cluster: dict[str, str],            # source.ip -> cluster_id
        ip_to_sessions: dict[str, list[dict]],    # source.ip -> [session_doc]
    ) -> None:
        self.indices = _Indices()
        self.run_id = run_id
        self.ip_to_cluster = ip_to_cluster
        self.ip_to_sessions = ip_to_sessions
        self.searches: list[dict] = []
        self.update_by_queries: list[dict] = []

    def search(self, *, index: str, **kwargs):
        self.searches.append({"index": index, **kwargs})
        q = kwargs.get("query") or {}

        # (a) latest run lookup on the IP-cluster index.
        if "doc_type" in str(q):
            return {"hits": {"hits": [
                {"_id": "x", "_source": {"run_id": self.run_id}},
            ]}}

        # (b) walking IP rollup for cluster.id.
        if "cluster.id" in str(q):
            # First call: return all hits. Second call: return empty (terminate loop).
            key = ("ips", index)
            cache = getattr(self, "_ip_yielded", set())
            if key in cache:
                return {"hits": {"hits": []}}
            cache.add(key)
            self._ip_yielded = cache
            return {"hits": {"hits": [
                {
                    "_id": ip,
                    "sort": [i],
                    "_source": {
                        "source": {"ip": ip},
                        "dshield": {"cowrie": {"enrichment": {"ip": {
                            "cluster": {"id": cid},
                        }}}},
                    },
                }
                for i, (ip, cid) in enumerate(self.ip_to_cluster.items())
            ]}}

        # (c) sessions for a terms filter on source.ip.
        must = (q.get("bool") or {}).get("must") or []
        ip_terms: list[str] = []
        for m in must:
            terms = m.get("terms") or {}
            if "source.ip" in terms:
                ip_terms = terms["source.ip"]
                break
        if ip_terms:
            # Return one page of all matching sessions, then empty.
            key = ("sessions", tuple(sorted(ip_terms)))
            cache = getattr(self, "_sess_yielded", set())
            if key in cache:
                return {"hits": {"hits": []}}
            cache.add(key)
            self._sess_yielded = cache
            hits = []
            i = 0
            for ip in ip_terms:
                for sess in self.ip_to_sessions.get(ip, []):
                    hits.append({
                        "_id": f"sess-{i}",
                        "sort": [i],
                        "_source": sess,
                    })
                    i += 1
            return {"hits": {"hits": hits}}

        return {"hits": {"hits": []}}

    def update_by_query(self, *, index: str, query: dict, script: dict, **kwargs):
        self.update_by_queries.append({
            "index":  index,
            "query":  query,
            "script": script,
        })
        return {"updated": 1}


def _sess(pid: str | None, name: str | None = None) -> dict:
    en: dict = {}
    if pid is not None:
        en["playbook_id"] = pid
    if name is not None:
        en["playbook_name"] = name
    return {"dshield": {"cowrie": {"enrichment": {"session": en}}}}


# -----------------------------------------------------------------------------
# [1] Single-cluster basic: one cluster, 2 IPs, 3 sessions, one playbook → 1
# update_by_query with that playbook as dominant.
# -----------------------------------------------------------------------------
print("\n[1] single cluster, single playbook")
es = _StubES(
    ip_to_cluster={"1.1.1.1": "cluster_0", "2.2.2.2": "cluster_0"},
    ip_to_sessions={
        "1.1.1.1": [_sess("sescl-aaaa", "Recon"), _sess("sescl-aaaa", "Recon")],
        "2.2.2.2": [_sess("sescl-aaaa", "Recon")],
    },
)
stats = annotate_ip_clusters_with_dominant_playbook(
    es,
    ips_rollup_index="ips",
    ip_clusters_index="ipc",
    sessions_rollup_index="sess",
)
check(
    "1 cluster annotated",
    stats["clusters_annotated"] == 1 and stats["clusters_seen"] == 1,
    f"got {stats}",
)
check(
    "1 update_by_query issued",
    len(es.update_by_queries) == 1,
    f"got {len(es.update_by_queries)}",
)
params = es.update_by_queries[0]["script"]["params"]
check(
    "dominant_playbook_id is sescl-aaaa",
    params["dominant_playbook_id"] == "sescl-aaaa",
    f"got {params}",
)
check(
    "dominant_playbook_name is 'Recon'",
    params["dominant_playbook_name"] == "Recon",
    f"got {params}",
)
check(
    "playbook_distribution carries count=3",
    params["playbook_distribution"] == [
        {"playbook_id": "sescl-aaaa", "playbook_name": "Recon", "count": 3},
    ],
    f"got {params['playbook_distribution']}",
)


# -----------------------------------------------------------------------------
# [2] Lex tie-break on equal counts.
# -----------------------------------------------------------------------------
print("\n[2] tied counts resolve lex on playbook_id")
es = _StubES(
    ip_to_cluster={"1.1.1.1": "cluster_0"},
    ip_to_sessions={
        "1.1.1.1": [
            _sess("sescl-zzzz", "Z-name"),
            _sess("sescl-aaaa", "A-name"),
        ],
    },
)
stats = annotate_ip_clusters_with_dominant_playbook(
    es,
    ips_rollup_index="ips",
    ip_clusters_index="ipc",
    sessions_rollup_index="sess",
)
params = es.update_by_queries[0]["script"]["params"]
check(
    "tied counts: lex-smallest playbook_id wins ('sescl-aaaa')",
    params["dominant_playbook_id"] == "sescl-aaaa",
    f"got {params['dominant_playbook_id']}",
)
# Distribution sorted same way: aaaa first.
dist = params["playbook_distribution"]
check(
    "distribution sorted by (-count, playbook_id)",
    [d["playbook_id"] for d in dist] == ["sescl-aaaa", "sescl-zzzz"],
    f"got {dist}",
)


# -----------------------------------------------------------------------------
# [3] Outlier IPs are skipped (cluster.id == 'outlier').
# -----------------------------------------------------------------------------
print("\n[3] outlier IPs excluded from any cluster")
es = _StubES(
    ip_to_cluster={"1.1.1.1": "cluster_0", "2.2.2.2": "outlier"},
    ip_to_sessions={
        "1.1.1.1": [_sess("sescl-aaaa", "Recon")],
        "2.2.2.2": [_sess("sescl-bbbb", "Dropper")],  # excluded as outlier
    },
)
stats = annotate_ip_clusters_with_dominant_playbook(
    es,
    ips_rollup_index="ips",
    ip_clusters_index="ipc",
    sessions_rollup_index="sess",
)
check(
    "outlier-bearing IP not seen in any cluster annotation",
    stats["clusters_seen"] == 1 and stats["clusters_annotated"] == 1,
    f"got {stats}",
)
params = es.update_by_queries[0]["script"]["params"]
check(
    "dominant_playbook_id is the non-outlier IP's playbook",
    params["dominant_playbook_id"] == "sescl-aaaa",
    f"got {params['dominant_playbook_id']}",
)


# -----------------------------------------------------------------------------
# [4] Cluster with no playbook-bearing sessions: not annotated, no update.
# -----------------------------------------------------------------------------
print("\n[4] cluster with zero playbook sessions → no annotation")
es = _StubES(
    ip_to_cluster={"1.1.1.1": "cluster_5"},
    ip_to_sessions={
        "1.1.1.1": [_sess(None)],  # session exists but no playbook_id
    },
)
stats = annotate_ip_clusters_with_dominant_playbook(
    es,
    ips_rollup_index="ips",
    ip_clusters_index="ipc",
    sessions_rollup_index="sess",
)
check(
    "seen=1 annotated=0",
    stats["clusters_seen"] == 1 and stats["clusters_annotated"] == 0,
    f"got {stats}",
)
check(
    "no update_by_query issued",
    es.update_by_queries == [],
    f"got {es.update_by_queries}",
)


# -----------------------------------------------------------------------------
# [5] Multiple clusters: each gets its own annotation, independently.
# -----------------------------------------------------------------------------
print("\n[5] multiple clusters annotated independently")
es = _StubES(
    ip_to_cluster={
        "1.1.1.1": "cluster_0",
        "2.2.2.2": "cluster_0",
        "3.3.3.3": "cluster_1",
    },
    ip_to_sessions={
        "1.1.1.1": [_sess("sescl-aaaa", "Recon")],
        "2.2.2.2": [_sess("sescl-aaaa", "Recon")],
        "3.3.3.3": [_sess("sescl-bbbb", "Dropper")],
    },
)
stats = annotate_ip_clusters_with_dominant_playbook(
    es,
    ips_rollup_index="ips",
    ip_clusters_index="ipc",
    sessions_rollup_index="sess",
)
check(
    "seen=2 annotated=2",
    stats["clusters_seen"] == 2 and stats["clusters_annotated"] == 2,
    f"got {stats}",
)
ids = {ubq["script"]["params"]["dominant_playbook_id"] for ubq in es.update_by_queries}
check(
    "both playbooks surfaced as dominants",
    ids == {"sescl-aaaa", "sescl-bbbb"},
    f"got {ids}",
)
# Each update_by_query targets exactly one cluster_id (via the query filter).
cluster_filters = [
    m for ubq in es.update_by_queries
    for m in ubq["query"]["bool"]["must"]
    if "cluster_id" in m.get("term", {})
]
check(
    "update_by_query queries filter by exactly one cluster_id each",
    len(cluster_filters) == 2 and len({c["term"]["cluster_id"] for c in cluster_filters}) == 2,
    f"got {cluster_filters}",
)


# -----------------------------------------------------------------------------
# [6] No latest run / empty cluster index → no-op, no exception.
# -----------------------------------------------------------------------------
print("\n[6] empty cluster index → graceful no-op")
class _EmptyES:
    indices = _Indices()
    def search(self, *, index: str, **kwargs):
        return {"hits": {"hits": []}}
    def update_by_query(self, **kwargs):
        raise AssertionError("should not be called")

stats = annotate_ip_clusters_with_dominant_playbook(
    _EmptyES(),
    ips_rollup_index="ips",
    ip_clusters_index="ipc",
    sessions_rollup_index="sess",
)
check(
    "seen=0 annotated=0 (no exception)",
    stats["clusters_seen"] == 0 and stats["clusters_annotated"] == 0,
    f"got {stats}",
)


# -----------------------------------------------------------------------------
# [7] Update script shape: writes the three fields + removes name when absent.
# -----------------------------------------------------------------------------
print("\n[7] update script writes three fields + handles missing name")
# Replay [1]'s scenario without a playbook_name.
es = _StubES(
    ip_to_cluster={"1.1.1.1": "cluster_0"},
    ip_to_sessions={"1.1.1.1": [_sess("sescl-aaaa")]},  # no name
)
stats = annotate_ip_clusters_with_dominant_playbook(
    es,
    ips_rollup_index="ips",
    ip_clusters_index="ipc",
    sessions_rollup_index="sess",
)
script = es.update_by_queries[0]["script"]
params = script["params"]
check(
    "dominant_playbook_name omitted from params when absent in source",
    "dominant_playbook_name" not in params,
    f"got params={params}",
)
check(
    "script writes dominant_playbook_id + distribution",
    "ctx._source.dominant_playbook_id" in script["source"]
        and "ctx._source.playbook_distribution" in script["source"],
    f"got source={script['source'][:100]}",
)
check(
    "script removes dominant_playbook_name when params lack it",
    "ctx._source.remove('dominant_playbook_name')" in script["source"],
    "",
)


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
