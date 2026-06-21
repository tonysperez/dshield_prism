"""Build Cytoscape-shaped {nodes, edges} JSON from ES result rows.

A node is `{data: {id, type, label, ...metadata}}`.
An edge is `{data: {id, source, target, label, kind}}`.

`id` for nodes uses a typed prefix so the frontend can disambiguate without
inspecting `type`: e.g. `ip:1.2.3.4`, `session:abc123`, `cmd:<sha256>`,
`cmdcl:42`, `sescl:7`, `ipcl:3`, `pb:<playbook_id>`, `camp:<campaign_id>`,
`asn:12345`, `cc:US`, `tt:T1059.003`, `ta:TA0002`.
"""
from __future__ import annotations

import math

from elasticsearch import Elasticsearch

from ._config import AppConfig

from . import queries


def _nid(t: str, ident: str) -> str:
    return f"{t}:{ident}"


def _log_size(n: int | float | None, *, base: float = 24.0, scale: float = 8.0) -> float:
    n = n or 0
    if n <= 0:
        return base
    return base + scale * math.log10(1 + n)


# ----------------------------------------------------------------------------
# "Resolve a pipeline node's clusterings + playbook" helpers. Each anchor
# function returns pipeline nodes (ip / session / command) in directions
# the front-end won't follow up on via further fetches (the role-based
# pipeline traversal treats them as "leaf"). Without these helpers those
# nodes would arrive without their cluster_id / playbook_name fields and
# without their cluster / playbook pill nodes — meaning sibling-expanded
# IOCs never join the cluster bubbles or playbook bubbles the front-end
# draws from those fields. Emitting the pills + edges inline closes the
# gap so siblings get the same visual context the anchor's neighbors do.
# ----------------------------------------------------------------------------

def _emit_ip_cluster(nodes: list, edges: list, ip: str, ienr: dict) -> None:
    """Attach the IP's cluster pill. IPs don't carry a playbook or campaign
    field — those concepts are derived from the IP's sessions."""
    nid_ip = _nid("ip", ip)
    cid = (ienr.get("cluster") or {}).get("id")
    if cid:
        nodes.append({"data": {"id": _nid("ipcl", cid), "type": "ip_cluster",
                               "label": f"ip cluster {cid}"}})
        edges.append({"data": {"id": f"{nid_ip}->{_nid('ipcl', cid)}",
                               "source": nid_ip, "target": _nid("ipcl", cid),
                               "label": "member_of", "kind": "member_of"}})


def _emit_session_cluster_playbook(nodes: list, edges: list, sid: str, senr: dict) -> None:
    """Attach the session's cluster pill and (if named) its playbook node.

    A playbook is the LLM-named group of 1+ HDBSCAN session clusters. The
    playbook node id is the stable `playbook_id` value (`sescl-<16hex>`,
    content-hashed over the sorted member-session-id set). Sessions from a
    merged playbook still emit their own per-cluster pill, so the graph
    shows the playbook node wired to each constituent cluster. Two
    playbooks with the same display name are distinct because they have
    different ids.
    """
    nid_s = _nid("session", sid)
    scid = (senr.get("cluster") or {}).get("id")
    if scid:
        nodes.append({"data": {"id": _nid("sescl", scid), "type": "session_cluster",
                               "label": f"sess cluster {scid}"}})
        edges.append({"data": {"id": f"{nid_s}->{_nid('sescl', scid)}",
                               "source": nid_s, "target": _nid("sescl", scid),
                               "label": "member_of", "kind": "member_of"}})
    pb_id   = senr.get("playbook_id")
    pb_name = senr.get("playbook_name")
    if pb_id:
        nodes.append({"data": {"id": _nid("pb", pb_id), "type": "playbook",
                               "playbook_id": pb_id,
                               "label": pb_name or pb_id}})
        edges.append({"data": {"id": f"{nid_s}->{_nid('pb', pb_id)}",
                               "source": nid_s, "target": _nid("pb", pb_id),
                               "label": "playbook_of", "kind": "playbook_of"}})


def _emit_command_cluster(nodes: list, edges: list, sha: str, cenr: dict) -> None:
    nid_c = _nid("cmd", sha)
    ccid = (cenr.get("cluster") or {}).get("id")
    if ccid:
        nodes.append({"data": {"id": _nid("cmdcl", ccid), "type": "command_cluster",
                               "label": f"cmd cluster {ccid}"}})
        edges.append({"data": {"id": f"{nid_c}->{_nid('cmdcl', ccid)}",
                               "source": nid_c, "target": _nid("cmdcl", ccid),
                               "label": "member_of", "kind": "member_of"}})


# ----------------------------------------------------------------------------
# File-drop lane (ROADMAP #3/#2): cowrie file-event hashes linked to the
# command that dropped/used them (`file_events[].command_hash`), flagged with
# the intel verdict from prism.intel.hash.
# ----------------------------------------------------------------------------

_FE = "dshield.cowrie.enrichment.session.file_events"


def _fetch_hash_verdicts(es: Elasticsearch, cfg: AppConfig, shas: list[str]) -> dict[str, dict]:
    """`{sha256: {malicious, family}}` from prism.intel.hash (mget). Missing
    docs / index → empty. `family` = consensus_label or a provider signature."""
    out: dict[str, dict] = {}
    if not shas:
        return out
    idx = cfg.intel.indexes.hash
    try:
        if not es.indices.exists(index=idx):
            return out
        resp = es.mget(index=idx, ids=shas)
    except Exception:  # noqa: BLE001 — verdict is best-effort decoration
        return out
    for doc in resp.get("docs", []):
        if not doc.get("found"):
            continue
        src = doc.get("_source") or {}
        derived = src.get("derived") or {}
        prov = src.get("providers") or {}
        family = (
            (prov.get("malwarebazaar") or {}).get("structured", {}).get("signature")
            or (prov.get("threatfox") or {}).get("structured", {}).get("malware")
            or derived.get("consensus_label")
        )
        out[doc["_id"]] = {
            "malicious": bool(derived.get("consensus_malicious")),
            "family": family,
        }
    return out


def _file_node(sha: str, filename: str | None, action: str | None, verdict: dict | None) -> dict:
    """Cytoscape file node. Label prefers the attacker-facing filename."""
    v = verdict or {}
    return {"data": {
        "id": _nid("file", sha), "type": "file",
        "label": (filename or sha[:12]),
        "sha256": sha, "filename": filename, "action": action,
        "malicious": v.get("malicious"), "family": v.get("family"),
    }}


def _emit_command_files(
    es: Elasticsearch, cfg: AppConfig, nodes: list, edges: list, command_shas: list[str],
) -> None:
    """For each command sha in `command_shas`, attach the files it dropped/ran
    (`file_events.command_hash == sha`) as `file` nodes + `cmd→file` edges. One
    batched nested agg over the session rollup; intel verdicts batch-fetched.

    Command graph nodes are keyed by the full `process.hash.sha256` (64 hex),
    but `file_events.command_hash` stores the command doc `_id`, which is that
    sha truncated to 16 hex. We query on the 16-hex form and map matches back
    to the full node id so the emitted edges attach to the existing node."""
    shas = [s for s in dict.fromkeys(command_shas) if s]
    if not shas:
        return
    # 16-hex command_hash (file_events) -> full node sha (graph command node id)
    short_to_full = {s[:16]: s for s in shas}
    short_shas = list(short_to_full)
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        resp = es.search(index=idx, size=0, query={"match_all": {}}, aggs={
            "fe": {"nested": {"path": _FE}, "aggs": {
                "match": {"filter": {"terms": {f"{_FE}.command_hash": short_shas}}, "aggs": {
                    "by_cmd": {"terms": {"field": f"{_FE}.command_hash", "size": len(short_shas)}, "aggs": {
                        "by_file": {"terms": {"field": f"{_FE}.sha256", "size": 50}, "aggs": {
                            "fn": {"terms": {"field": f"{_FE}.filename.keyword", "size": 1}},
                            "act": {"terms": {"field": f"{_FE}.action", "size": 1}},
                        }},
                    }},
                }},
            }},
        })
    except Exception:  # noqa: BLE001
        return
    cmd_buckets = (
        resp.get("aggregations", {}).get("fe", {}).get("match", {})
        .get("by_cmd", {}).get("buckets", [])
    ) or []
    # Collect (cmd_sha, file_sha, filename, action) and the distinct file shas.
    pairs: list[tuple[str, str, str | None, str | None]] = []
    file_shas: list[str] = []
    for cb in cmd_buckets:
        # bucket key is the 16-hex file_events.command_hash; map back to the
        # full node sha so edges attach to the command node already in-graph.
        cmd_sha = short_to_full.get(cb.get("key"), cb.get("key"))
        for fb in (cb.get("by_file", {}).get("buckets", []) or []):
            fsha = fb.get("key")
            if not fsha:
                continue
            fn_b = fb.get("fn", {}).get("buckets", [])
            act_b = fb.get("act", {}).get("buckets", [])
            pairs.append((cmd_sha, fsha,
                          fn_b[0]["key"] if fn_b else None,
                          act_b[0]["key"] if act_b else None))
            file_shas.append(fsha)
    verdicts = _fetch_hash_verdicts(es, cfg, file_shas)
    seen_files: set[str] = set()
    for cmd_sha, fsha, fn, act in pairs:
        if fsha not in seen_files:
            seen_files.add(fsha)
            nodes.append(_file_node(fsha, fn, act, verdicts.get(fsha)))
        edges.append({"data": {"id": f"{_nid('cmd', cmd_sha)}->{_nid('file', fsha)}",
                               "source": _nid("cmd", cmd_sha), "target": _nid("file", fsha),
                               "label": "dropped", "kind": "dropped"}})


# ----------------------------------------------------------------------------
# Cluster-specificity attachment (ROADMAP #4 graph extension)
#
# Attach `specificity` to IP / command nodes when the graph view has a
# single-playbook scope (playbook anchor or a session whose playbook_id is
# known). Multi-playbook anchors (raw ip / command / campaign / ip_cluster
# etc.) intentionally skip — one score per node would mean different things
# across the multiple playbooks in view. Command graph nodes use the 64-hex
# `sha256`; specificity maps key on the 16-hex command_id (same `[:16]`
# convention used in `_emit_command_files`). Best-effort: a missing maps
# fetch silently leaves nodes unscored.
# ----------------------------------------------------------------------------

def _attach_specificity(
    nodes: list[dict], ip_scores: dict[str, float], cmd_scores: dict[str, float],
) -> None:
    """Stamp `specificity` onto IP nodes by `label` (the IP value) and on
    command nodes by `sha256[:16]`. Idempotent — re-running on the same
    node list with the same maps is a no-op."""
    for n in nodes:
        d = n.get("data") or {}
        t = d.get("type")
        if t == "ip":
            s = ip_scores.get(d.get("label"))
            if s is not None:
                d["specificity"] = s
        elif t == "command":
            sha = d.get("sha256") or ""
            if sha:
                s = cmd_scores.get(sha[:16])
                if s is not None:
                    d["specificity"] = s


# ----------------------------------------------------------------------------
# Per-anchor neighborhood builders
# ----------------------------------------------------------------------------

def _ip_anchor(es: Elasticsearch, cfg: AppConfig, ip: str, *, limit: int, sf: "queries.SessionFilter | None" = None) -> dict:
    ip_doc = queries.lookup_ip(es, cfg, ip)
    nodes: list[dict] = []
    edges: list[dict] = []
    if ip_doc:
        src = ip_doc["_source"]
        enr = (src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
        asn_obj = (src.get("source", {}).get("as") or {})
        geo_obj = (src.get("source", {}).get("geo") or {})
        nodes.append({"data": {
            "id": _nid("ip", ip),
            "type": "ip",
            "label": ip,
            "size": _log_size(enr.get("total_sessions")),
            "novelty": enr.get("mean_novelty_score"),
            "cluster_id": (enr.get("cluster") or {}).get("id"),
            "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
            "asn": asn_obj.get("number"),
            "country": geo_obj.get("country_iso_code"),
        }})

        # ASN
        asn = (src.get("source", {}).get("as") or {}).get("number")
        org = ((src.get("source", {}).get("as") or {}).get("organization") or {}).get("name")
        if asn:
            nodes.append({"data": {"id": _nid("asn", str(asn)), "type": "asn",
                                   "label": f"AS{asn}" + (f" {org}" if org else "")}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('asn',str(asn))}",
                                   "source": _nid("ip", ip), "target": _nid("asn", str(asn)),
                                   "label": "asn", "kind": "asn"}})
        # Country
        cc = (src.get("source", {}).get("geo") or {}).get("country_iso_code")
        if cc:
            nodes.append({"data": {"id": _nid("cc", cc), "type": "country", "label": cc}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('cc',cc)}",
                                   "source": _nid("ip", ip), "target": _nid("cc", cc),
                                   "label": "country", "kind": "country"}})
        # ip cluster (IP-layer "actor profile"; no playbook attachment at this layer)
        cluster_id = (enr.get("cluster") or {}).get("id")
        if cluster_id:
            nodes.append({"data": {"id": _nid("ipcl", cluster_id), "type": "ip_cluster",
                                   "label": f"ip cluster {cluster_id}"}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('ipcl',cluster_id)}",
                                   "source": _nid("ip", ip), "target": _nid("ipcl", cluster_id),
                                   "label": "member_of", "kind": "member_of"}})

    # sessions for this ip — the playbook-bearing layer. Each session
    # carries its own playbook_id / playbook_name; playbook nodes get
    # merged across sessions by `_emit_session_cluster_playbook`.
    sess = queries.sessions_for_ip(es, cfg, ip, size=limit, sf=sf)
    for h in sess["hits"]["hits"]:
        sid = (h["_source"].get("cowrie") or {}).get("session_id") or h["_id"]
        senr = (h["_source"].get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
        nodes.append({"data": {
            "id": _nid("session", sid), "type": "session", "label": sid,
            "size": _log_size(senr.get("command_count")),
            "novelty": senr.get("mean_novelty_score"),
            "playbook_id":   senr.get("playbook_id"),
            "playbook_name": senr.get("playbook_name"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',sid)}",
                               "source": _nid("ip", ip), "target": _nid("session", sid),
                               "label": "saw", "kind": "saw"}})
        _emit_session_cluster_playbook(nodes, edges, sid, senr)
    return _dedup({"nodes": nodes, "edges": edges})


def _session_anchor(es: Elasticsearch, cfg: AppConfig, session_id: str, *, limit: int, sf: "queries.SessionFilter | None" = None) -> dict:
    sdoc = queries.lookup_session(es, cfg, session_id)
    nodes: list[dict] = []
    edges: list[dict] = []
    if sdoc:
        src = sdoc["_source"]
        senr = (src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
        nodes.append({"data": {
            "id": _nid("session", session_id), "type": "session", "label": session_id,
            "size": _log_size(senr.get("command_count")),
            "playbook_id":   senr.get("playbook_id"),
            "playbook_name": senr.get("playbook_name"),
            "novelty": senr.get("mean_novelty_score"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        # source ip — look up its enrichment so the IP arrives with cluster_id /
        # asn / country fields. The IP doesn't carry a playbook attribute
        # of its own; playbooks are derived from the IP's sessions.
        ip = (src.get("source") or {}).get("ip")
        if ip:
            ip_doc = queries.lookup_ip(es, cfg, ip)
            ienr: dict = {}
            ip_asn = None
            ip_asn_org = None
            ip_cc = None
            if ip_doc:
                isrc = ip_doc["_source"]
                ienr = (isrc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
                ip_asn = ((isrc.get("source") or {}).get("as") or {}).get("number")
                ip_asn_org = (((isrc.get("source") or {}).get("as") or {}).get("organization") or {}).get("name")
                ip_cc = ((isrc.get("source") or {}).get("geo") or {}).get("country_iso_code")
            nodes.append({"data": {
                "id": _nid("ip", ip), "type": "ip", "label": ip,
                "cluster_id": (ienr.get("cluster") or {}).get("id"),
                "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
                "asn": ip_asn, "country": ip_cc,
            }})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',session_id)}",
                                   "source": _nid("ip", ip), "target": _nid("session", session_id),
                                   "label": "saw", "kind": "saw"}})
            _emit_ip_cluster(nodes, edges, ip, ienr)
            if ip_asn:
                nodes.append({"data": {"id": _nid("asn", str(ip_asn)), "type": "asn",
                                       "label": f"AS{ip_asn}" + (f" {ip_asn_org}" if ip_asn_org else "")}})
                edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('asn',str(ip_asn))}",
                                       "source": _nid("ip", ip), "target": _nid("asn", str(ip_asn)),
                                       "label": "asn", "kind": "asn"}})
            if ip_cc:
                nodes.append({"data": {"id": _nid("cc", ip_cc), "type": "country", "label": ip_cc}})
                edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('cc',ip_cc)}",
                                       "source": _nid("ip", ip), "target": _nid("cc", ip_cc),
                                       "label": "country", "kind": "country"}})
        # session cluster + playbook (playbook_id is the merge key)
        _emit_session_cluster_playbook(nodes, edges, session_id, senr)

    # commands in this session
    cmd_rows = queries.commands_for_session(es, cfg, session_id, size=limit)
    seen_hashes: set[str] = set()
    for row in cmd_rows["rows"]:
        sha = row.get("sha256")
        if not sha or sha in seen_hashes:
            continue
        seen_hashes.add(sha)
        enr = row.get("enrichment") or {}
        label = (row.get("command_line") or sha)[:80]
        nodes.append({"data": {
            "id": _nid("cmd", sha), "type": "command", "label": label,
            "sha256": sha,
            "intent": enr.get("intent"),
            "novelty": (enr.get("cluster") or {}).get("novelty_score"),
            "size": _log_size(enr.get("occurrence_count")),
            "cluster_id": (enr.get("cluster") or {}).get("id"),
            "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
        }})
        edges.append({"data": {"id": f"{_nid('session',session_id)}->{_nid('cmd',sha)}",
                               "source": _nid("session", session_id), "target": _nid("cmd", sha),
                               "label": "ran", "kind": "ran"}})
        _emit_command_cluster(nodes, edges, sha, enr)
    # ROADMAP #4 — if the session belongs to a known playbook, attach
    # cluster-specificity to its IP + the emitted command nodes. A session
    # without playbook_id (pre-naming, or genuine outlier) leaves nodes
    # unscored — the frontend just renders no badge / ring.
    session_pid = (sdoc["_source"].get("dshield", {}).get("cowrie", {})
                   .get("enrichment", {}).get("session", {}).get("playbook_id")
                   if sdoc else None)
    if session_pid:
        ip_scores, cmd_scores = queries.playbook_specificity_maps(es, cfg, session_pid)
        if ip_scores or cmd_scores:
            _attach_specificity(nodes, ip_scores, cmd_scores)
    return _dedup({"nodes": nodes, "edges": edges})


def _command_anchor(es: Elasticsearch, cfg: AppConfig, sha256: str, *, limit: int, sf: "queries.SessionFilter | None" = None) -> dict:
    cdoc = queries.lookup_command(es, cfg, sha256)
    nodes: list[dict] = []
    edges: list[dict] = []
    if cdoc:
        src = cdoc["_source"]
        cmd = ((src.get("process") or {}).get("command_line") or sha256)
        enr = (src.get("dshield", {}).get("cowrie", {}).get("enrichment") or {})
        nodes.append({"data": {
            "id": _nid("cmd", sha256), "type": "command", "label": cmd[:80],
            "sha256": sha256, "intent": enr.get("intent"),
            "size": _log_size(enr.get("occurrence_count")),
            "novelty": (enr.get("cluster") or {}).get("novelty_score"),
            "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
            "cluster_id": (enr.get("cluster") or {}).get("id"),
        }})
        ccid = (enr.get("cluster") or {}).get("id")
        if ccid:
            nodes.append({"data": {"id": _nid("cmdcl", ccid), "type": "command_cluster",
                                   "label": f"cmd cluster {ccid}"}})
            edges.append({"data": {"id": f"{_nid('cmd',sha256)}->{_nid('cmdcl',ccid)}",
                                   "source": _nid("cmd", sha256), "target": _nid("cmdcl", ccid),
                                   "label": "member_of", "kind": "member_of"}})

    # sessions that ran this command — bulk-enrich so each session arrives
    # with cluster_id / playbook and its source-IP context, both of which
    # the front-end needs to fold these nodes into the right cluster /
    # playbook bubbles. (sessions_for_command returns just session_id +
    # command_count, so we hydrate explicitly here.)
    sess = queries.sessions_for_command(es, cfg, sha256, size=limit, sf=sf)
    sids = [row["session_id"] for row in sess["rows"]]
    senr_map = queries.bulk_session_enrichment(es, cfg, sids)
    src_ips: list[str] = []
    for v in senr_map.values():
        if v.get("src_ip"):
            src_ips.append(v["src_ip"])
    ienr_map = queries.bulk_ip_enrichment(es, cfg, src_ips)
    for row in sess["rows"]:
        sid = row["session_id"]
        info = senr_map.get(sid, {})
        senr = info.get("enrichment", {}) if isinstance(info, dict) else {}
        nodes.append({"data": {
            "id": _nid("session", sid), "type": "session", "label": sid,
            "size": _log_size(senr.get("command_count")),
            "playbook_id":   senr.get("playbook_id"),
            "playbook_name": senr.get("playbook_name"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        edges.append({"data": {"id": f"{_nid('session',sid)}->{_nid('cmd',sha256)}",
                               "source": _nid("session", sid), "target": _nid("cmd", sha256),
                               "label": "ran", "kind": "ran"}})
        _emit_session_cluster_playbook(nodes, edges, sid, senr)
        # Pull the session's source IP into the graph too. Without this the
        # IP arrives later via a leaf-traversal fetch and never carries its
        # ip_cluster_id, so the ip_cluster bubble never groups it.
        ip = info.get("src_ip") if isinstance(info, dict) else None
        if not ip:
            continue
        ipinfo = ienr_map.get(ip) or {}
        ienr = ipinfo.get("enrichment") or {}
        ip_asn = ipinfo.get("asn")
        ip_cc = ipinfo.get("country")
        nodes.append({"data": {
            "id": _nid("ip", ip), "type": "ip", "label": ip,
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn": ip_asn, "country": ip_cc,
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',sid)}",
                               "source": _nid("ip", ip), "target": _nid("session", sid),
                               "label": "saw", "kind": "saw"}})
        _emit_ip_cluster(nodes, edges, ip, ienr)
        if ip_asn:
            nodes.append({"data": {"id": _nid("asn", str(ip_asn)), "type": "asn",
                                   "label": f"AS{ip_asn}"}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('asn',str(ip_asn))}",
                                   "source": _nid("ip", ip), "target": _nid("asn", str(ip_asn)),
                                   "label": "asn", "kind": "asn"}})
        if ip_cc:
            nodes.append({"data": {"id": _nid("cc", ip_cc), "type": "country", "label": ip_cc}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('cc',ip_cc)}",
                                   "source": _nid("ip", ip), "target": _nid("cc", ip_cc),
                                   "label": "country", "kind": "country"}})
    return _dedup({"nodes": nodes, "edges": edges})


def _cluster_anchor(
    es: Elasticsearch, cfg: AppConfig, kind: str, cluster_id: str, *, limit: int,
    run_cache: queries.RunCache,
    sf: "queries.SessionFilter | None" = None,
) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    cluster_node_type = {"command": "command_cluster", "session": "session_cluster", "ip": "ip_cluster"}[kind]
    cluster_node_prefix = {"command": "cmdcl", "session": "sescl", "ip": "ipcl"}[kind]
    cnid = _nid(cluster_node_prefix, cluster_id)
    cdoc = queries.lookup_cluster(es, cfg, kind, cluster_id, run_cache)
    if cdoc:
        src = cdoc["_source"]
        nodes.append({"data": {
            "id": cnid, "type": cluster_node_type,
            "label": f"{kind} cluster {cluster_id}",
            "size": _log_size(src.get("size"), base=32),
            "playbook_id":   src.get("playbook_id"),
            "playbook_name": src.get("playbook_name"),
            "member_count": src.get("size"),
        }})
        # Only session clusters carry a playbook label.
        if kind == "session":
            pb_id   = src.get("playbook_id")
            pb_name = src.get("playbook_name")
            if pb_id:
                nodes.append({"data": {"id": _nid("pb", pb_id), "type": "playbook",
                                       "playbook_id": pb_id,
                                       "label": pb_name or pb_id}})
                edges.append({"data": {"id": f"{cnid}->{_nid('pb', pb_id)}",
                                       "source": cnid, "target": _nid("pb", pb_id),
                                       "label": "named", "kind": "named"}})

    members = queries.members_of_cluster(es, cfg, kind, cluster_id, size=limit, sf=sf)
    for h in members["hits"]["hits"]:
        s = h["_source"]
        if kind == "command":
            sha = ((s.get("process") or {}).get("hash") or {}).get("sha256") or h["_id"]
            cmd = ((s.get("process") or {}).get("command_line") or sha)
            enr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment") or {})
            nodes.append({"data": {
                "id": _nid("cmd", sha), "type": "command",
                "label": cmd[:80], "sha256": sha,
                "intent": enr.get("intent"),
                "novelty": (enr.get("cluster") or {}).get("novelty_score"),
                "size": _log_size(enr.get("occurrence_count")),
                "cluster_id": (enr.get("cluster") or {}).get("id"),
                "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
            }})
            edges.append({"data": {"id": f"{_nid('cmd',sha)}->{cnid}",
                                   "source": _nid("cmd", sha), "target": cnid,
                                   "label": "member_of", "kind": "member_of"}})
            _emit_command_cluster(nodes, edges, sha, enr)
        elif kind == "session":
            sid = (s.get("cowrie") or {}).get("session_id") or h["_id"]
            senr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
            nodes.append({"data": {
                "id": _nid("session", sid), "type": "session", "label": sid,
                "size": _log_size(senr.get("command_count")),
                "novelty": senr.get("mean_novelty_score"),
                "playbook_id":   senr.get("playbook_id"),
                "playbook_name": senr.get("playbook_name"),
                "cluster_id": (senr.get("cluster") or {}).get("id"),
                "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
            }})
            edges.append({"data": {"id": f"{_nid('session',sid)}->{cnid}",
                                   "source": _nid("session", sid), "target": cnid,
                                   "label": "member_of", "kind": "member_of"}})
            _emit_session_cluster_playbook(nodes, edges, sid, senr)
        else:  # ip
            ip = (s.get("source") or {}).get("ip") or h["_id"]
            ienr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
            asn_obj = (s.get("source", {}).get("as") or {})
            geo_obj = (s.get("source", {}).get("geo") or {})
            nodes.append({"data": {
                "id": _nid("ip", ip), "type": "ip", "label": ip,
                "size": _log_size(ienr.get("total_sessions")),
                "novelty": ienr.get("mean_novelty_score"),
                "cluster_id": (ienr.get("cluster") or {}).get("id"),
                "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
                "asn": asn_obj.get("number"),
                "country": geo_obj.get("country_iso_code"),
            }})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{cnid}",
                                   "source": _nid("ip", ip), "target": cnid,
                                   "label": "member_of", "kind": "member_of"}})
            _emit_ip_cluster(nodes, edges, ip, ienr)
    return _dedup({"nodes": nodes, "edges": edges})


TOUR_CAMPAIGN_ID = "cmp-beh-e6e6e5569e56d396"


def _tour_campaign_graph() -> dict:
    """Synthetic campaign graph for the onboarding tour.

    Builds the same node/edge shape `_campaign_anchor` would, but from
    constant data — no ES round-trips. Calls the same emit helpers
    (`_emit_session_cluster_playbook`, `_emit_ip_cluster`) so lane
    assignment, edge kinds, cluster bubbling, and playbook anchoring
    all match the real renderer's expectations.

    Returns the same `{nodes, edges}` shape as the live campaign anchor.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    camp_id = TOUR_CAMPAIGN_ID

    # Anchor — matches the cnode shape in _campaign_anchor.
    nodes.append({"data": {
        "id":            _nid("camp", camp_id),
        "type":          "campaign",
        "campaign_id":   camp_id,
        "campaign_kind": "behaviour",
        "label":         "Defense-in-depth SSH persistence",
        "ip_count":      73,
        "session_count": 275,
    }})

    # (session_id, playbook_id, playbook_name, source_ip, asn, country)
    sessions = [
        ("tour-sess-a01", "spb-tour-keylock",  "SSH Key Injection with chattr Locking", "203.0.113.42",   "64500", "RU"),
        ("tour-sess-a02", "spb-tour-keylock",  "SSH Key Injection with chattr Locking", "198.51.100.71",  "64501", "CN"),
        ("tour-sess-a03", "spb-tour-cronlist", "SSH Key Installer: Crontab list",       "192.0.2.55",     "64502", "BR"),
        ("tour-sess-a04", "spb-tour-cronlist", "SSH Key Installer: Crontab list",       "203.0.113.180",  "64503", "IN"),
        ("tour-sess-a05", "spb-tour-keylock",  "SSH Key Injection with chattr Locking", "198.51.100.140", "64504", "VN"),
    ]
    for sid, pid, pname, ip, asn, cc in sessions:
        # Session node + session→campaign edge.
        nodes.append({"data": {
            "id":            _nid("session", sid),
            "type":          "session",
            "label":         sid,
            "size":          _log_size(3),
            "playbook_id":   pid,
            "playbook_name": pname,
            "novelty":       0.32,
            "cluster_id":    f"tour-sescl-{pid[-8:]}",
            "is_outlier":    False,
        }})
        edges.append({"data": {
            "id":     f"{_nid('session', sid)}->{_nid('camp', camp_id)}",
            "source": _nid("session", sid),
            "target": _nid("camp", camp_id),
            "label":  "in_campaign", "kind": "in_campaign",
        }})
        # Session cluster + playbook via the same helper the real builder uses.
        senr = {
            "playbook_id":   pid,
            "playbook_name": pname,
            "cluster":       {"id": f"tour-sescl-{pid[-8:]}"},
        }
        _emit_session_cluster_playbook(nodes, edges, sid, senr)

        # Source IP + ip→session edge — same shape as the real builder.
        nodes.append({"data": {
            "id":         _nid("ip", ip),
            "type":       "ip",
            "label":      ip,
            "cluster_id": "tour-ipcl-1",
            "is_outlier": False,
            "asn":        asn,
            "country":    cc,
        }})
        edges.append({"data": {
            "id":     f"{_nid('ip', ip)}->{_nid('session', sid)}",
            "source": _nid("ip", ip),
            "target": _nid("session", sid),
            "label":  "saw", "kind": "saw",
        }})
        # IP cluster pill via the same helper.
        ienr = {"cluster": {"id": "tour-ipcl-1"}}
        _emit_ip_cluster(nodes, edges, ip, ienr)

        # Geo lane — ASN + country nodes wired via canonical edges.
        nodes.append({"data": {
            "id":    _nid("asn", asn),
            "type":  "asn",
            "label": f"AS{asn}",
        }})
        edges.append({"data": {
            "id":     f"{_nid('ip', ip)}->{_nid('asn', asn)}",
            "source": _nid("ip", ip),
            "target": _nid("asn", asn),
            "label":  "asn", "kind": "asn",
        }})
        nodes.append({"data": {
            "id":    _nid("cc", cc),
            "type":  "country",
            "label": cc,
        }})
        edges.append({"data": {
            "id":     f"{_nid('ip', ip)}->{_nid('cc', cc)}",
            "source": _nid("ip", ip),
            "target": _nid("cc", cc),
            "label":  "country", "kind": "country",
        }})

    return _dedup({"nodes": nodes, "edges": edges})


def _campaign_anchor(
    es: Elasticsearch, cfg: AppConfig, campaign_id: str, *, limit: int,
    sf: "queries.SessionFilter | None" = None,
) -> dict:
    """Anchor on a multi-session campaign.

    Unlike a playbook (one session cluster), a campaign here is a derived
    multi-session grouping mined by `dshield_prism mine campaigns`. The
    doc in `prism.campaign.cowrie` carries explicit lists of
    member session ids and source ips, so the graph build is a direct
    `terms` fetch — no aggregation needed.
    """
    if campaign_id == TOUR_CAMPAIGN_ID:
        return _tour_campaign_graph()
    nodes: list[dict] = []
    edges: list[dict] = []
    camp = queries.lookup_campaign(es, cfg, campaign_id)
    if not camp:
        # Anchor on an unknown campaign id — return a sentinel node so the
        # UI can show "not found" instead of a blank canvas.
        nodes.append({"data": {
            "id":   _nid("camp", campaign_id),
            "type": "campaign",
            "campaign_id": campaign_id,
            "label": campaign_id,
            "kind": "unknown",
        }})
        return _dedup({"nodes": nodes, "edges": edges})

    cnode = {
        "id":            _nid("camp", campaign_id),
        "type":          "campaign",
        "campaign_id":   campaign_id,
        "campaign_kind": camp.get("kind") or "unknown",
        "label":         camp.get("name") or campaign_id,
        "ip_count":      camp.get("ip_count"),
        "session_count": camp.get("session_count"),
    }
    nodes.append({"data": cnode})

    # Pull a sample of member sessions and their source IPs into the graph.
    sids = (camp.get("member_session_ids") or [])[:limit]
    if sids:
        try:
            sresp = es.search(
                index=cfg.elasticsearch.indexes.cowrie.sessions_rollup,
                size=len(sids),
                _source=queries._src(),
                query={"terms": {"cowrie.session_id": sids}},
            )
        except Exception:
            sresp = {"hits": {"hits": []}}
        for h in sresp["hits"]["hits"]:
            s = h["_source"]
            sid = (s.get("cowrie") or {}).get("session_id") or h["_id"]
            senr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
            nodes.append({"data": {
                "id":           _nid("session", sid), "type": "session", "label": sid,
                "size":         _log_size(senr.get("command_count")),
                "playbook_id":   senr.get("playbook_id"),
                "playbook_name": senr.get("playbook_name"),
                "novelty":      senr.get("mean_novelty_score"),
                "cluster_id":   (senr.get("cluster") or {}).get("id"),
                "is_outlier":   (senr.get("cluster") or {}).get("is_outlier"),
            }})
            edges.append({"data": {
                "id":     f"{_nid('session', sid)}->{_nid('camp', campaign_id)}",
                "source": _nid("session", sid),
                "target": _nid("camp", campaign_id),
                "label":  "in_campaign", "kind": "in_campaign",
            }})
            _emit_session_cluster_playbook(nodes, edges, sid, senr)
            # Source IP into view.
            ip = (s.get("source") or {}).get("ip")
            if not ip:
                continue
            ip_doc = queries.lookup_ip(es, cfg, ip)
            ienr: dict = {}
            ip_asn = ip_cc = None
            if ip_doc:
                isrc = ip_doc["_source"]
                ienr = (isrc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
                ip_asn = ((isrc.get("source") or {}).get("as") or {}).get("number")
                ip_cc  = ((isrc.get("source") or {}).get("geo") or {}).get("country_iso_code")
            nodes.append({"data": {
                "id": _nid("ip", ip), "type": "ip", "label": ip,
                "cluster_id": (ienr.get("cluster") or {}).get("id"),
                "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
                "asn": ip_asn, "country": ip_cc,
            }})
            edges.append({"data": {
                "id":     f"{_nid('ip', ip)}->{_nid('session', sid)}",
                "source": _nid("ip", ip), "target": _nid("session", sid),
                "label":  "saw", "kind": "saw",
            }})
            _emit_ip_cluster(nodes, edges, ip, ienr)

    return _dedup({"nodes": nodes, "edges": edges})


def _playbook_anchor(
    es: Elasticsearch, cfg: AppConfig, playbook_id: str, *, limit: int,
    sf: "queries.SessionFilter | None" = None,
) -> dict:
    """Anchor on a playbook by its stable primary key.

    Playbook = a named session cluster. Anchoring returns the playbook's
    session members, the source IPs that produced those sessions, and the
    relevant IP-cluster pills. IPs are derived via session ownership;
    there is no direct IP→playbook edge.
    """
    sess_clusters_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    playbook_name = None
    centroid_field = queries._resolve_agg_field(es, sess_clusters_idx, "playbook_id")
    try:
        cresp = es.search(
            index=sess_clusters_idx, size=1,
            _source=["playbook_name"],
            query={"term": {centroid_field: playbook_id}},
        )
        chits = cresp["hits"]["hits"]
        if chits:
            playbook_name = chits[0]["_source"].get("playbook_name")
    except Exception:
        pass

    nodes: list[dict] = [{"data": {
        "id": _nid("pb", playbook_id),
        "type": "playbook",
        "playbook_id": playbook_id,
        "label": playbook_name or playbook_id,
    }}]
    edges: list[dict] = []

    # Sessions in this playbook (the authoritative membership).
    r = queries.sessions_for_playbook(es, cfg, playbook_id, size=limit, sf=sf)
    for h in r["hits"]["hits"]:
        s = h["_source"]
        sid = (s.get("cowrie") or {}).get("session_id") or h["_id"]
        senr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session") or {})
        nodes.append({"data": {
            "id": _nid("session", sid), "type": "session", "label": sid,
            "size": _log_size(senr.get("command_count")),
            "playbook_id":   playbook_id,
            "playbook_name": playbook_name,
            "novelty": senr.get("mean_novelty_score"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        edges.append({"data": {"id": f"{_nid('session',sid)}->{_nid('pb',playbook_id)}",
                               "source": _nid("session", sid), "target": _nid("pb", playbook_id),
                               "label": "playbook_of", "kind": "playbook_of"}})
        _emit_session_cluster_playbook(nodes, edges, sid, senr)
        # Pull the source IP into view so the hunter can see who's running
        # this playbook. The IP doesn't get a direct edge to the playbook —
        # the session sits in between, which is the relationship that
        # actually exists in the data.
        ip = (s.get("source") or {}).get("ip")
        if not ip:
            continue
        ip_doc = queries.lookup_ip(es, cfg, ip)
        ienr: dict = {}
        ip_asn = None
        ip_cc = None
        if ip_doc:
            isrc = ip_doc["_source"]
            ienr = (isrc.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
            ip_asn = ((isrc.get("source") or {}).get("as") or {}).get("number")
            ip_cc = ((isrc.get("source") or {}).get("geo") or {}).get("country_iso_code")
        nodes.append({"data": {
            "id": _nid("ip", ip), "type": "ip", "label": ip,
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn": ip_asn, "country": ip_cc,
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',sid)}",
                               "source": _nid("ip", ip), "target": _nid("session", sid),
                               "label": "saw", "kind": "saw"}})
        _emit_ip_cluster(nodes, edges, ip, ienr)
    # ROADMAP #4 — single-playbook scope: attach cluster-specificity to IP
    # nodes. Commands aren't emitted at this anchor; that lands in
    # `_session_anchor` when the analyst expands a session.
    ip_scores, cmd_scores = queries.playbook_specificity_maps(es, cfg, playbook_id)
    if ip_scores or cmd_scores:
        _attach_specificity(nodes, ip_scores, cmd_scores)
    return _dedup({"nodes": nodes, "edges": edges})


def _asn_anchor(es: Elasticsearch, cfg: AppConfig, asn: str, *, limit: int) -> dict:
    nodes: list[dict] = [{"data": {"id": _nid("asn", asn), "type": "asn", "label": f"AS{asn}"}}]
    edges: list[dict] = []
    r = queries.ips_for_asn(es, cfg, asn, size=limit)
    for h in r["hits"]["hits"]:
        s = h["_source"]
        ip = (s.get("source") or {}).get("ip") or h["_id"]
        ienr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
        geo_obj = (s.get("source", {}).get("geo") or {})
        nodes.append({"data": {
            "id": _nid("ip", ip), "type": "ip", "label": ip,
            "size": _log_size(ienr.get("total_sessions")),
            "novelty": ienr.get("mean_novelty_score"),
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn": asn,
            "country": geo_obj.get("country_iso_code"),
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('asn',asn)}",
                               "source": _nid("ip", ip), "target": _nid("asn", asn),
                               "label": "asn", "kind": "asn"}})
        _emit_ip_cluster(nodes, edges, ip, ienr)
    return _dedup({"nodes": nodes, "edges": edges})


def _country_anchor(es: Elasticsearch, cfg: AppConfig, cc: str, *, limit: int) -> dict:
    nodes: list[dict] = [{"data": {"id": _nid("cc", cc), "type": "country", "label": cc}}]
    edges: list[dict] = []
    r = queries.ips_for_country(es, cfg, cc, size=limit)
    for h in r["hits"]["hits"]:
        s = h["_source"]
        ip = (s.get("source") or {}).get("ip") or h["_id"]
        ienr = (s.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip") or {})
        asn_obj = (s.get("source", {}).get("as") or {})
        nodes.append({"data": {
            "id": _nid("ip", ip), "type": "ip", "label": ip,
            "size": _log_size(ienr.get("total_sessions")),
            "novelty": ienr.get("mean_novelty_score"),
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn": asn_obj.get("number"),
            "country": cc,
        }})
        edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('cc',cc)}",
                               "source": _nid("ip", ip), "target": _nid("cc", cc),
                               "label": "country", "kind": "country"}})
        _emit_ip_cluster(nodes, edges, ip, ienr)
    return _dedup({"nodes": nodes, "edges": edges})


def _file_anchor(es: Elasticsearch, cfg: AppConfig, sha256: str, *, limit: int, sf: "queries.SessionFilter | None" = None) -> dict:
    """Anchor on a dropped file: emit the file node (+ intel verdict) and its
    droppers — the sessions that dropped it and, where attributable, the
    commands (`file_events.command_hash`). Files with no in-session command
    (SFTP uploads) attach via a direct session→file edge."""
    sha = sha256.lower()
    nodes: list[dict] = []
    edges: list[dict] = []
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    try:
        resp = es.search(index=idx, size=limit,
            query={"nested": {"path": _FE, "query": {"term": {f"{_FE}.sha256": sha}},
                              "inner_hits": {"size": 20, "_source": [
                                  f"{_FE}.command_hash", f"{_FE}.filename", f"{_FE}.action"]}}},
            _source=["cowrie.session_id"])
        hits = resp.get("hits", {}).get("hits", []) or []
    except Exception:  # noqa: BLE001
        hits = []

    filename = None
    action = None
    # session_id -> list of (command_hash|None); also gather distinct cmd hashes.
    per_session: list[tuple[str, list[str | None]]] = []
    cmd_hashes: list[str] = []
    for h in hits:
        sid = (h.get("_source", {}).get("cowrie") or {}).get("session_id")
        if not sid:
            continue
        inner = (((h.get("inner_hits") or {}).get(_FE) or {}).get("hits") or {}).get("hits", [])
        ch_list: list[str | None] = []
        for ih in inner:
            fe = ih.get("_source", {})
            # inner_hit _source is the nested object's fields
            fe = fe.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session", {}).get("file_events", fe) if "dshield" in fe else fe
            filename = filename or fe.get("filename")
            action = action or fe.get("action")
            ch = fe.get("command_hash")
            ch_list.append(ch)
            if ch:
                cmd_hashes.append(ch)
        per_session.append((sid, ch_list))

    verdicts = _fetch_hash_verdicts(es, cfg, [sha])
    nodes.append(_file_node(sha, filename, action, verdicts.get(sha)))

    # Session nodes (+ cluster/playbook + ip) for the droppers.
    sids = [s for s, _ in per_session]
    senr_map = queries.bulk_session_enrichment(es, cfg, sids)
    src_ips = [v["src_ip"] for v in senr_map.values() if isinstance(v, dict) and v.get("src_ip")]
    ienr_map = queries.bulk_ip_enrichment(es, cfg, src_ips)
    # Command labels for the attributing commands. file_events.command_hash is
    # the 16-hex command doc _id; every other anchor keys command nodes by the
    # full process.hash.sha256, so resolve to the full sha to keep one node id.
    cmd_labels: dict[str, str] = {}
    cmd_full: dict[str, str] = {}
    for ch in dict.fromkeys(cmd_hashes):
        cdoc = queries.lookup_command(es, cfg, ch)
        if cdoc:
            proc = cdoc["_source"].get("process") or {}
            cmd_labels[ch] = (proc.get("command_line") or ch)[:80]
            cmd_full[ch] = (proc.get("hash") or {}).get("sha256") or ch

    for sid, ch_list in per_session:
        info = senr_map.get(sid, {})
        senr = info.get("enrichment", {}) if isinstance(info, dict) else {}
        nodes.append({"data": {
            "id": _nid("session", sid), "type": "session", "label": sid,
            "size": _log_size(senr.get("command_count")),
            "playbook_id": senr.get("playbook_id"), "playbook_name": senr.get("playbook_name"),
            "cluster_id": (senr.get("cluster") or {}).get("id"),
            "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        }})
        _emit_session_cluster_playbook(nodes, edges, sid, senr)
        ip = info.get("src_ip") if isinstance(info, dict) else None
        if ip:
            ienr = (ienr_map.get(ip) or {}).get("enrichment") or {}
            nodes.append({"data": {"id": _nid("ip", ip), "type": "ip", "label": ip,
                                   "cluster_id": (ienr.get("cluster") or {}).get("id"),
                                   "is_outlier": (ienr.get("cluster") or {}).get("is_outlier")}})
            edges.append({"data": {"id": f"{_nid('ip',ip)}->{_nid('session',sid)}",
                                   "source": _nid("ip", ip), "target": _nid("session", sid),
                                   "label": "saw", "kind": "saw"}})
            _emit_ip_cluster(nodes, edges, ip, ienr)
        linked = False
        for ch in ch_list:
            if not ch:
                continue
            linked = True
            cnode = cmd_full.get(ch, ch)
            nodes.append({"data": {"id": _nid("cmd", cnode), "type": "command",
                                   "label": cmd_labels.get(ch, ch[:12]), "sha256": cnode}})
            edges.append({"data": {"id": f"{_nid('session',sid)}->{_nid('cmd',cnode)}",
                                   "source": _nid("session", sid), "target": _nid("cmd", cnode),
                                   "label": "ran", "kind": "ran"}})
            edges.append({"data": {"id": f"{_nid('cmd',cnode)}->{_nid('file',sha)}",
                                   "source": _nid("cmd", cnode), "target": _nid("file", sha),
                                   "label": "dropped", "kind": "dropped"}})
        if not linked:
            # SFTP / no in-session command — connect the session straight to the file.
            edges.append({"data": {"id": f"{_nid('session',sid)}->{_nid('file',sha)}",
                                   "source": _nid("session", sid), "target": _nid("file", sha),
                                   "label": "dropped", "kind": "dropped"}})
    return _dedup({"nodes": nodes, "edges": edges})


# ----------------------------------------------------------------------------
# Public dispatch
# ----------------------------------------------------------------------------

def _operation_anchor(
    es: Elasticsearch, cfg: AppConfig, operation_id: str, *, limit: int,
    sf: "queries.SessionFilter | None" = None,
) -> dict:
    """Anchor on an operation (brutal-review 7.2).

    Operations are bhv × inf campaign pair mergers minted by 7.1. The
    graph view renders the operation node connected to its two parent
    campaigns and the shared source IPs — so the analyst can see at a
    glance which IPs the merge attributed to.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    op = queries.lookup_operation(es, cfg, operation_id)
    if not op:
        nodes.append({"data": {
            "id":           _nid("op", operation_id),
            "type":         "operation",
            "operation_id": operation_id,
            "label":        operation_id,
            "kind":         "unknown",
        }})
        return _dedup({"nodes": nodes, "edges": edges})

    bhv_id = op.get("behaviour_id")
    inf_id = op.get("infrastructure_id")
    shared_ips = (op.get("member_source_ips") or [])[:limit]

    op_nid = _nid("op", operation_id)
    nodes.append({"data": {
        "id":                  op_nid,
        "type":                "operation",
        "operation_id":        operation_id,
        "label":               f"{op.get('behaviour_name') or bhv_id} ↔ "
                               f"{op.get('infrastructure_name') or inf_id}",
        "bhv_ip_count":        op.get("bhv_ip_count"),
        "inf_ip_count":        op.get("inf_ip_count"),
        "shared_ip_count":     op.get("shared_ip_count"),
        "overlap_ratio":       op.get("overlap_ratio"),
    }})

    # Each parent campaign as a node + an edge to the operation.
    for camp_id, role in ((bhv_id, "behaviour"), (inf_id, "infrastructure")):
        if not camp_id:
            continue
        camp = queries.lookup_campaign(es, cfg, camp_id)
        camp_nid = _nid("camp", camp_id)
        nodes.append({"data": {
            "id":            camp_nid,
            "type":          "campaign",
            "campaign_id":   camp_id,
            "campaign_kind": role,
            "label":         (camp or {}).get("name") or camp_id,
            "ip_count":      (camp or {}).get("ip_count"),
            "session_count": (camp or {}).get("session_count"),
        }})
        edges.append({"data": {
            "id":     f"{camp_nid}->{op_nid}",
            "source": camp_nid, "target": op_nid,
            "label":  "merged_into", "kind": "merged_into",
        }})

    # Shared source IPs as their own nodes, edged to the operation.
    for ip in shared_ips:
        ip_nid = _nid("ip", ip)
        ip_doc = queries.lookup_ip(es, cfg, ip)
        ienr: dict = {}
        ip_asn = ip_cc = None
        if ip_doc:
            isrc = ip_doc["_source"]
            ienr = (isrc.get("dshield", {}).get("cowrie", {})
                    .get("enrichment", {}).get("ip") or {})
            ip_asn = ((isrc.get("source") or {}).get("as") or {}).get("number")
            ip_cc  = ((isrc.get("source") or {}).get("geo") or {}).get("country_iso_code")
        nodes.append({"data": {
            "id":         ip_nid, "type": "ip", "label": ip,
            "cluster_id": (ienr.get("cluster") or {}).get("id"),
            "is_outlier": (ienr.get("cluster") or {}).get("is_outlier"),
            "asn":        ip_asn, "country": ip_cc,
        }})
        edges.append({"data": {
            "id":     f"{ip_nid}->{op_nid}",
            "source": ip_nid, "target": op_nid,
            "label":  "attributed_to", "kind": "attributed_to",
        }})
        _emit_ip_cluster(nodes, edges, ip, ienr)

    return _dedup({"nodes": nodes, "edges": edges})


def neighbors(
    es: Elasticsearch, cfg: AppConfig, ioc_type: str, ident: str, *,
    limit: int = 50, run_cache: queries.RunCache,
    sf: queries.SessionFilter | None = None,
) -> dict:
    if ioc_type in ("file", "hash"):
        return _file_anchor(es, cfg, ident, limit=limit, sf=sf)
    if ioc_type == "ip":
        result = _ip_anchor(es, cfg, ident, limit=limit, sf=sf)
    elif ioc_type == "session":
        result = _session_anchor(es, cfg, ident, limit=limit, sf=sf)
    elif ioc_type in ("command", "command_hash"):
        result = _command_anchor(es, cfg, ident.lower(), limit=limit, sf=sf)
    elif ioc_type == "command_cluster":
        result = _cluster_anchor(es, cfg, "command", ident, limit=limit, run_cache=run_cache, sf=sf)
    elif ioc_type == "session_cluster":
        result = _cluster_anchor(es, cfg, "session", ident, limit=limit, run_cache=run_cache, sf=sf)
    elif ioc_type == "ip_cluster":
        result = _cluster_anchor(es, cfg, "ip", ident, limit=limit, run_cache=run_cache, sf=sf)
    elif ioc_type == "playbook":
        result = _playbook_anchor(es, cfg, ident, limit=limit, sf=sf)
    elif ioc_type == "campaign":
        result = _campaign_anchor(es, cfg, ident, limit=limit, sf=sf)
    elif ioc_type == "operation":
        result = _operation_anchor(es, cfg, ident, limit=limit, sf=sf)
    elif ioc_type == "asn":
        result = _asn_anchor(es, cfg, ident, limit=limit)
    elif ioc_type == "country":
        result = _country_anchor(es, cfg, ident.upper(), limit=limit)
    else:
        raise ValueError(f"unsupported ioc_type: {ioc_type}")

    # File-drop lane: attach the files dropped/run by any command this anchor
    # surfaced, so the flow extends Command→File for every entry point. Batched
    # (one query); no-op when the anchor produced no command nodes.
    command_shas = [
        n["data"].get("sha256") for n in result["nodes"]
        if n["data"].get("type") == "command" and n["data"].get("sha256")
    ]
    if command_shas:
        _emit_command_files(es, cfg, result["nodes"], result["edges"], command_shas)
        result = _dedup(result)
    return result


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _dedup(g: dict) -> dict:
    """Drop duplicate nodes (last write wins) and duplicate edges by id."""
    nodes: dict[str, dict] = {}
    for n in g["nodes"]:
        nid = n["data"]["id"]
        # Prefer the entry that has more keys (typically the fuller anchor doc).
        if nid not in nodes or len(n["data"]) > len(nodes[nid]["data"]):
            nodes[nid] = n
    edges: dict[str, dict] = {}
    for e in g["edges"]:
        edges[e["data"]["id"]] = e
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}
