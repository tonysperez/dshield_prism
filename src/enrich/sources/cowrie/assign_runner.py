"""I4 — authoritative session assignment runner (Option A cutover).

Single window-batch pass that replaces "HDBSCAN-cluster every session" with
"assign each session to its nearest anchor; band cases resolved by an in-batch TF-IDF
fit; whatever matches nothing is novel". Because the TF-IDF is fit per run over the
batch (anchor sessions + the window), there is NO persisted lexical model and NO
forward/backward pending state — bands resolve in the same pass.

Gated by `cfg.session.assignment_authoritative`:
  * True  — writes `playbook_id`/`playbook_name` (assigned), clears them (novel), bumps
            `playbook_named_at` (so the next `rollup ips` re-rolls the affected IPs).
            This replaces HDBSCAN as the labeller; run it where `cluster sessions` +
            `name playbooks` run today (the operator swaps it into the backward service).
  * False — writes the `cluster.assignment_*` shadow fields only (non-authoritative).

Novel sessions (`assignment_status=novel`) are the only input the HDBSCAN clusterer
still needs post-cutover (to mint new anchors). Reversal of an authoritative run: set
the flag False and re-run the HDBSCAN `cluster sessions`/`name playbooks` steps —
`playbook_id` is recomputable from the embeddings.

Pure cores (`assignment_action`, `build_actions`) are unit-tested; `run_assignment` is
the thin ES wiring around them and the assignment core (`assignment.assign_batch`).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ...es_client import bulk_write
from .assignment import ASSIGNED, NOVEL, compute_assignment_window
from .lexical import (
    build_bag_texts,
    build_session_predicate_vectors,
    pull_hash_to_cluster,
    pull_hash_to_predicates,
)

_S = "dshield.cowrie.enrichment.session"
_PB_FIELD = f"{_S}.playbook_id"
_PBNAME_FIELD = f"{_S}.playbook_name"
_EMB_FIELD = f"{_S}.embedding"
_CMDSET_FIELD = f"{_S}.command_set"


def _sb(src: dict) -> dict:
    return (((src.get("dshield") or {}).get("cowrie") or {})
            .get("enrichment", {}).get("session", {}))


# ---------------------------------------------------------------------------
# Pure write-action cores (unit-tested)
# ---------------------------------------------------------------------------
def assignment_action(doc_id: str, a, now: str, *, authoritative: bool,
                      playbook_name: Optional[str] = None) -> dict:
    """ES bulk partial-update for one session. Always writes the `cluster.assignment_*`
    shadow fields. When `authoritative`, ALSO sets the real `playbook_id`/`playbook_name`
    (assigned) or clears them (novel), and bumps `playbook_named_at`."""
    session: dict = {"cluster": {
        "assigned_playbook_id": a.playbook_id,
        "assignment_status": a.status,
        "assignment_cosine": a.cosine,
        "assignment_cascade_rank": a.cascade_rank,
        "assignment_at": now,
    }}
    if authoritative:
        if a.status == ASSIGNED:
            session["playbook_id"] = a.playbook_id
            session["playbook_name"] = playbook_name
            session["playbook_named_at"] = now
        elif a.status == NOVEL:
            session["playbook_id"] = None
            session["playbook_name"] = None
            session["playbook_named_at"] = now
        # any other status (shouldn't occur after a full resolve) leaves playbook_id as-is
    return {"_op_type": "update", "_id": doc_id,
            "doc": {"dshield": {"cowrie": {"enrichment": {"session": session}}}}}


def build_actions(ids: list[str], assignments: list, name_of: dict, now: str, *,
                  authoritative: bool) -> list[dict]:
    """Map (doc_id, assignment) → bulk actions, resolving each assigned anchor's name."""
    return [assignment_action(i, a, now, authoritative=authoritative,
                              playbook_name=name_of.get(a.playbook_id))
            for i, a in zip(ids, assignments)]


# ---------------------------------------------------------------------------
# ES wiring
# ---------------------------------------------------------------------------
def _load_anchors(es, anch_idx):
    """Returns `(ids, vecs, predicate_signatures)`: `predicate_signatures` (item 30) is
    index-aligned with `ids`/`vecs`, each entry the anchor's `predicate_signature` dict
    (a modal/frequency vector over the 7 structural predicates, see
    `scripts/capture_anchor_snapshot.py:predicate_signature`) or `None` when the anchor
    predates the feature / carries no signature."""
    import numpy as np
    r = es.search(index=anch_idx, size=10000,
                  _source=["playbook_id", "anchor_centroid", "predicate_signature"],
                  query={"exists": {"field": "anchor_centroid"}})
    ids, vecs, sigs = [], [], []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        if s.get("anchor_centroid"):
            ids.append(s.get("playbook_id") or h["_id"])
            vecs.append(s["anchor_centroid"])
            sigs.append(s.get("predicate_signature"))
    if not vecs:
        return ids, np.zeros((0, 0), dtype=np.float32), sigs
    m = np.array(vecs, dtype=np.float32)
    n = np.linalg.norm(m, axis=1, keepdims=True)
    return ids, m / np.where(n == 0.0, 1.0, n), sigs


def _iter_scan(es, idx, filt, fields, page=2000):
    """Stream hits via search_after — never materializes the full result set.
    Bounded callers wrap this in `_scan`; the full-corpus window scan in
    `run_assignment` consumes it directly so embeddings never pile up as a
    corpus-wide list[list[float]] (mirrors the chunked fix in clustering.py)."""
    body = {"size": page, "_source": fields, "query": {"bool": {"filter": filt}},
            "sort": [{"_doc": "asc"}]}
    sa = None
    while True:
        if sa:
            body["search_after"] = sa
        r = es.search(index=idx, **body)
        hits = r["hits"]["hits"]
        if not hits:
            break
        yield from hits
        sa = hits[-1]["sort"]


def _scan(es, idx, filt, fields, page=2000, limit=None):
    out = []
    for h in _iter_scan(es, idx, filt, fields, page=page):
        out.append(h)
        if limit and len(out) >= limit:
            break
    return out


def _scan_window_embeddings(es, idx, window_filter, src_fields, chunk=50_000):
    """Stream the full-corpus window scan, returning (win_ids, win_sets, W) with W
    an L2-normalized float32 matrix (None when empty). Embeddings accumulate in
    float32 chunks so the whole corpus never sits in RAM as list[list[float]] —
    the OOM the backfill hit at scale. Docs without an embedding are dropped (the
    old `keep` filter). Mirrors the chunked-flush pattern in clustering.py:1162."""
    import numpy as np
    win_ids: list[str] = []
    win_sets: list[list[str]] = []
    emb_chunks: list = []
    emb_buf: list[list[float]] = []

    def _flush() -> None:
        if emb_buf:
            emb_chunks.append(np.asarray(emb_buf, dtype=np.float32))
            emb_buf.clear()

    for h in _iter_scan(es, idx, window_filter, src_fields):
        s = _sb(h["_source"])
        e = s.get("embedding")
        if not e:
            continue
        win_ids.append(h["_id"])
        win_sets.append(list(s.get("command_set") or []))
        emb_buf.append(e)
        if len(emb_buf) >= chunk:
            _flush()
    _flush()
    if not win_ids:
        return win_ids, win_sets, None
    W = np.vstack(emb_chunks) if len(emb_chunks) > 1 else emb_chunks[0]
    norms = np.linalg.norm(W, axis=1, keepdims=True)
    return win_ids, win_sets, W / np.where(norms == 0.0, 1.0, norms)


def _resolve_names(es, idx, filt, playbook_ids):
    """playbook_id → playbook_name (one representative session each)."""
    names = {}
    for pb in playbook_ids:
        if pb is None:
            continue
        r = es.search(index=idx, size=1, _source=[_PBNAME_FIELD],
                      query={"bool": {"filter": filt + [{"term": {_PB_FIELD: pb}}]}})
        hits = r["hits"]["hits"]
        names[pb] = _sb(hits[0]["_source"]).get("playbook_name") if hits else None
    return names


def run_assignment(es, cfg, *, window_filter: list[dict], anchor_sample_filter: list[dict],
                   per_anchor: int = 300, apply: bool = False) -> dict:
    """Assign the sessions matched by `window_filter` against the anchor library, with an
    in-batch TF-IDF fit for the band check. Writes (authoritative or shadow per
    `cfg.session.assignment_authoritative`) when `apply`. Returns a summary."""
    sc = cfg.session
    authoritative = bool(getattr(sc, "assignment_authoritative", False))
    tau = float(getattr(sc, "assignment_tau", 0.94))
    confident_tau = float(getattr(sc, "assignment_confident_tau", 0.98))
    tfidf_tau = float(getattr(sc, "assignment_tfidf_tau", 0.80))
    band_bypass_anchor_ids = {
        normalized
        for anchor_id in getattr(sc, "assignment_band_bypass_anchor_ids", [])
        if (normalized := str(anchor_id).strip())
    }
    # Item 30 — below-tau structural-predicate rescue tier. Defaults equal to `tau` (a
    # no-op): only when explicitly lowered below `tau` do we pay the extra
    # `pull_hash_to_predicates` scan below.
    rescue_tau = float(getattr(sc, "assignment_rescue_tau", tau))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    cmd_idx = cfg.elasticsearch.indexes.cowrie.commands
    anch_idx = cfg.elasticsearch.indexes.cowrie.playbook_anchors

    anchor_ids, anchor_emb, anchor_predicate_signatures = _load_anchors(es, anch_idx)
    if anchor_emb.shape[0] == 0:
        return {"error": "no anchors", "authoritative": authoritative}

    src_fields = [_EMB_FIELD, _CMDSET_FIELD]
    # Full-corpus window scan, streamed as float32 chunks (see _scan_window_embeddings)
    # so the whole corpus of 768-d embeddings never sits in RAM as list[list[float]].
    win_ids, win_sets, W = _scan_window_embeddings(es, idx, window_filter, src_fields)
    if not win_ids:
        return {"error": "no sessions in window", "authoritative": authoritative}

    # per-anchor sample → anchor TF-IDF centroids; one fit over (anchors + window)
    anc_sets, anc_pb = [], []
    for pb in anchor_ids:
        f = anchor_sample_filter + [{"term": {_PB_FIELD: pb}}]
        for h in _scan(es, idx, f, [_CMDSET_FIELD], page=min(per_anchor, 2000), limit=per_anchor):
            anc_sets.append(list(_sb(h["_source"]).get("command_set") or []))
            anc_pb.append(pb)
    h2c = pull_hash_to_cluster(es, cmd_idx)
    all_bags = build_bag_texts(anc_sets + win_sets, h2c)
    # Item 30: only pull + fold predicate sub-signals when the rescue tier is actually
    # active (rescue_tau < tau) — feature-off is a true no-op, no extra ES scan.
    window_predicates = None
    if rescue_tau < tau:
        h2p = pull_hash_to_predicates(es, cmd_idx)
        window_predicates = build_session_predicate_vectors(win_sets, h2p)
    result = compute_assignment_window(
        W, anchor_emb, anchor_ids,
        all_bags[:len(anc_sets)], anc_pb, all_bags[len(anc_sets):],
        tau=tau, confident_tau=confident_tau, tfidf_tau=tfidf_tau,
        band_bypass_anchor_ids=band_bypass_anchor_ids,
        rescue_tau=rescue_tau, window_predicates=window_predicates,
        anchor_predicate_signatures=(
            anchor_predicate_signatures if window_predicates is not None else None
        ),
    )
    res = result.assignments
    now = datetime.now(timezone.utc).isoformat()
    name_of = (_resolve_names(es, idx, anchor_sample_filter,
                              {a.playbook_id for a in res if a.status == ASSIGNED})
               if authoritative else {})
    actions = build_actions(win_ids, res, name_of, now, authoritative=authoritative)

    from collections import Counter
    summary = {"authoritative": authoritative, "n_sessions": len(res),
               "tfidf_available": result.tfidf_available,
               "status_counts": dict(Counter(a.status for a in res)),
               "written": 0, "errors": 0}
    if apply:
        ok, errors = bulk_write(es, idx, actions)
        summary["written"] = ok
        summary["errors"] = len(errors)
    return summary
