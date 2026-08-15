"""Option A — direct nearest-anchor session assignment (the pipeline inversion).

Replaces "cluster every session with HDBSCAN every cycle" with "assign each session
to its nearest playbook anchor; whatever matches nothing is the novel pool (the only
input HDBSCAN still sees)". This module is the pure decision core; ES/pipeline wiring
(shadow first, then authoritative) lives in the cluster-sessions flow. See
docs/decisions.md §5f.

Per session, against the anchor library (the pinned `anchor_centroid` set), with the
nearest anchor's embedding cosine `c`:

  * `c < tau`                         → NOVEL  (no playbook; goes to the novel pool)
  * `tau <= c < confident_tau`        → BAND   (assigned-pending): confirm with the
                                        TF-IDF secondary signal — `tfidf_cos >= tfidf_tau`
                                        keeps it ASSIGNED, else it is REJECTED as a
                                        conflation and becomes NOVEL. Degraded (no
                                        TF-IDF available) → trust the embedding.
  * `c >= confident_tau`              → ASSIGNED (no secondary check; ~88% of traffic)

The thresholds default to the validated values: tau 0.94 (Exp 1 assignment floor),
confident_tau 0.98 (above it the embedding is reliable — Exp 1 histogram), tfidf_tau
0.80 (Exp 3 gate: 0.90 keep / 0.67 reject). The BAND + TF-IDF step is the Exp-3
mechanism on the per-session hot path; it catches the conflation slice (e.g. the
`1b9a`→`54f5` 18%) the embedding alone would mis-assign.
"""
from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

from .lexical import prepare_assignment_lexical
from .predicates import predicate_overlap

ASSIGNED = "assigned"
NOVEL = "novel"
BAND = "band"  # transient: an in-band session before the secondary signal resolves it


@dataclass
class Assignment:
    """Outcome for one session. `status` is ASSIGNED or NOVEL once resolved (BAND is
    never a final status). `playbook_id` is None iff NOVEL. `cascade_rank` is the rank
    of the winning anchor among the session's nearest (0 = nearest; >0 means the nearer
    anchor(s) were band-rejected conflations and we fell through). `rescued` (item 30) is
    True iff this ASSIGNED outcome came from the below-tau structural-predicate rescue
    tier rather than the embedding cascade — always False for BAND/NOVEL and for any
    ordinary (>= tau) ASSIGNED outcome."""
    playbook_id: str | None
    cosine: float
    status: str
    tfidf_cosine: float | None = None
    confirmed_in_band: bool = False
    cascade_rank: int = 0
    band_checks: int = 0
    band_rejections: int = 0
    rescued: bool = False


def classify_status(cosine: float, *, tau: float, confident_tau: float) -> str:
    """Pre-secondary-signal status from the embedding cosine alone."""
    if cosine < tau:
        return NOVEL
    if cosine < confident_tau:
        return BAND
    return ASSIGNED


def resolve(emb_cos: float, tfidf_cos: float | None, *,
            tau: float, confident_tau: float, tfidf_tau: float,
            defer_band: bool = False) -> str:
    """Final status. In the BAND, the TF-IDF cosine to the SAME nearest anchor decides:
    >= tfidf_tau confirms (ASSIGNED), below rejects (NOVEL = conflation). With no TF-IDF
    in-band: `defer_band=True` returns BAND (leave pending — the forward pass, resolved
    later in the backward batch); `defer_band=False` degrades to trusting the embedding
    (ASSIGNED)."""
    status = classify_status(emb_cos, tau=tau, confident_tau=confident_tau)
    if status != BAND:
        return status
    if tfidf_cos is None:
        return BAND if defer_band else ASSIGNED
    return ASSIGNED if tfidf_cos >= tfidf_tau else NOVEL


def assign_batch(
    emb: object, anchor_emb: object, anchor_ids: list[str], *,
    tau: float = 0.94, confident_tau: float = 0.98, tfidf_tau: float = 0.80,
    tfidf_cos: Callable[[int, int], float | None] | None = None,
    band_bypass_anchor_ids: set[str] | None = None,
    defer_band: bool = False,
    band_trace: list[dict] | None = None,
    candidate_trace: list[list[dict]] | None = None,
    rescue_tau: float | None = None,
    session_predicates: list[dict | None] | None = None,
    anchor_predicate_signatures: list[dict | None] | None = None,
) -> list[Assignment]:
    """Assign every row of `emb` (n×d, L2-normalised) against `anchor_emb` (A×d,
    L2-normalised). For each session we walk its anchors nearest-first: a confident
    (≥confident_tau) or a band-confirmed (TF-IDF ≥ tfidf_tau) anchor wins; a
    band-rejected anchor (a conflation — TF-IDF too low) is skipped and we fall through
    to the next-nearest; once cosine drops below τ the session is NOVEL. The cascade
    rescues sessions whose nearest anchor is a conflation but whose true home is a
    farther anchor (shadow I2: without it the band-rejects inflate the novel pool).

    `defer_band=True` is the **forward-pass** mode: with no `tfidf_cos`, a band anchor
    yields a BAND result (status='band', provisional playbook_id = that anchor) instead
    of being resolved — the backward batch re-runs with TF-IDF to finalise it. Default
    (`defer_band=False`) resolves fully.

    `tfidf_cos(session_idx, anchor_idx)` is called lazily, only for band anchors we
    actually inspect. Returns one Assignment per row.

    `band_bypass_anchor_ids` (item 81) is an explicit anchor-id allowlist for anchors
    whose TF-IDF signature has been measured as unreliable. A candidate for one of
    those anchors still needs to be inside the normal embedding BAND, but it assigns
    embedding-only instead of consulting TF-IDF. The default empty set preserves the
    ordinary band behavior for every anchor.

    `band_trace`, when passed a list, gets one `{"emb_cos", "tfidf_cos", "confirmed"}`
    row appended for every anchor where a TF-IDF cosine was actually looked up in the
    BAND tier — a rejected one included, since we then cascade to the next-nearest —
    diagnostic-only (item 34). Leaving it `None` (every existing call site) changes
    nothing about the returned assignments. Callers must pass a fresh list per
    `assign_batch` invocation; it is only ever appended to, never cleared.

    `candidate_trace`, when passed a list, gets one list appended per session. Each inner
    list records every cascade candidate reached, including the anchor id/rank, embedding
    cosine, pre-secondary status, optional TF-IDF cosine (`None` when unavailable/not
    consulted), and the candidate decision. It is diagnostic-only (item 78) and separate
    from `band_trace` so historical band metrics keep their one-row-per-TF-IDF-check
    shape.

    `rescue_tau` (item 30) extends the cascade below `tau`: while a candidate anchor's
    cosine is still >= `rescue_tau` (even if < `tau`, i.e. it would otherwise be NOVEL),
    a positive structural-predicate overlap (`predicates.predicate_overlap`) between
    `session_predicates[i]` and `anchor_predicate_signatures[a]` rescues it to ASSIGNED
    (`Assignment.rescued=True`); no overlap leaves it NOVEL and the cascade continues to
    the next-nearest anchor still within the rescue band. This is monotone — rescue is
    only ever considered where the ordinary cascade would already have produced NOVEL
    (a BAND/ASSIGNED anchor is resolved exactly as before and never re-examined for
    rescue). `rescue_tau=None` (default), `rescue_tau == tau`, or passing no
    `session_predicates`/`anchor_predicate_signatures` makes the rescue tier empty;
    `rescue_tau < tau` enables the below-tau rescue band."""
    import numpy as np

    A = np.asarray(anchor_emb)
    E = np.asarray(emb)
    if A.shape[0] == 0:
        if candidate_trace is not None:
            candidate_trace.extend([] for _ in range(E.shape[0]))
        return [Assignment(None, 0.0, NOVEL) for _ in range(E.shape[0])]
    if session_predicates is not None and len(session_predicates) != E.shape[0]:
        raise ValueError(
            f"session_predicates has {len(session_predicates)} entries but emb has "
            f"{E.shape[0]} rows — must be index-aligned one entry per session"
        )
    if anchor_predicate_signatures is not None and len(anchor_predicate_signatures) != A.shape[0]:
        raise ValueError(
            f"anchor_predicate_signatures has {len(anchor_predicate_signatures)} entries "
            f"but anchor_emb has {A.shape[0]} rows — must be index-aligned one entry per anchor"
        )
    if rescue_tau is not None:
        if not math.isfinite(rescue_tau):
            raise ValueError(f"rescue_tau must be finite, got {rescue_tau!r}")
        if rescue_tau > tau:
            raise ValueError(
                f"rescue_tau ({rescue_tau}) must be <= tau ({tau}); a rescue_tau above tau "
                "cannot define a below-tau rescue band"
            )
    effective_rescue_tau = tau if rescue_tau is None else min(rescue_tau, tau)
    band_bypass_anchor_ids = band_bypass_anchor_ids or set()
    sims = E @ A.T
    # nearest-first order per session (descending cosine)
    order = np.argsort(-sims, axis=1)
    out: list[Assignment] = []
    for i in range(E.shape[0]):
        nearest_cos = float(sims[i, order[i, 0]])
        decided: Assignment | None = None
        band_checks = 0
        band_rejections = 0
        svec = session_predicates[i] if session_predicates is not None else None
        session_trace: list[dict] = []
        for rank in range(order.shape[1]):
            a = int(order[i, rank])
            ec = float(sims[i, a])
            if ec < effective_rescue_tau:
                if candidate_trace is not None:
                    session_trace.append({
                        "anchor_id": anchor_ids[a],
                        "rank": rank,
                        "emb_cos": ec,
                        "pre_status": NOVEL,
                        "tfidf_cos": None,
                        "decision": "below_floor_stop",
                    })
                break  # farther anchors are only worse (by cosine) — stop entirely
            pre = classify_status(ec, tau=tau, confident_tau=confident_tau)
            if pre == NOVEL:
                # Below tau but still >= rescue_tau: the ordinary cascade would stop
                # here (and does, byte-identically, when rescue_tau == tau since then
                # effective_rescue_tau == tau breaks above before we ever reach this
                # branch). Try the structural rescue; no overlap → keep cascading to
                # the next-nearest anchor still within the rescue band.
                sig = (anchor_predicate_signatures[a]
                       if anchor_predicate_signatures is not None else None)
                if predicate_overlap(svec, sig):
                    if candidate_trace is not None:
                        session_trace.append({
                            "anchor_id": anchor_ids[a],
                            "rank": rank,
                            "emb_cos": ec,
                            "pre_status": pre,
                            "tfidf_cos": None,
                            "decision": "rescue_assigned",
                        })
                    decided = Assignment(
                        playbook_id=anchor_ids[a], cosine=round(ec, 4), status=ASSIGNED,
                        cascade_rank=rank, band_checks=band_checks,
                        band_rejections=band_rejections, rescued=True)
                    break
                if candidate_trace is not None:
                    session_trace.append({
                        "anchor_id": anchor_ids[a],
                        "rank": rank,
                        "emb_cos": ec,
                        "pre_status": pre,
                        "tfidf_cos": None,
                        "decision": "rescue_rejected",
                    })
                continue
            if pre == BAND and not defer_band and anchor_ids[a] in band_bypass_anchor_ids:
                if candidate_trace is not None:
                    session_trace.append({
                        "anchor_id": anchor_ids[a],
                        "rank": rank,
                        "emb_cos": ec,
                        "pre_status": pre,
                        "tfidf_cos": None,
                        "decision": "band_bypass_assigned",
                    })
                decided = Assignment(
                    playbook_id=anchor_ids[a], cosine=round(ec, 4), status=ASSIGNED,
                    cascade_rank=rank, band_checks=band_checks,
                    band_rejections=band_rejections)
                break
            tc = tfidf_cos(i, a) if (pre == BAND and tfidf_cos is not None) else None
            if pre == BAND and tc is not None:
                band_checks += 1
            r = resolve(ec, tc, tau=tau, confident_tau=confident_tau,
                        tfidf_tau=tfidf_tau, defer_band=defer_band)
            if pre == BAND and tc is not None and band_trace is not None:
                band_trace.append(
                    {"emb_cos": ec, "tfidf_cos": tc, "confirmed": r == ASSIGNED},
                )
            if r == ASSIGNED:
                if candidate_trace is not None:
                    session_trace.append({
                        "anchor_id": anchor_ids[a],
                        "rank": rank,
                        "emb_cos": ec,
                        "pre_status": pre,
                        "tfidf_cos": tc,
                        "decision": "assigned",
                    })
                decided = Assignment(
                    playbook_id=anchor_ids[a], cosine=round(ec, 4), status=ASSIGNED,
                    tfidf_cosine=(round(tc, 4) if tc is not None else None),
                    confirmed_in_band=(pre == BAND), cascade_rank=rank,
                    band_checks=band_checks, band_rejections=band_rejections)
                break
            if r == BAND:
                # forward pass, no TF-IDF yet → leave pending on the nearest band anchor
                if candidate_trace is not None:
                    session_trace.append({
                        "anchor_id": anchor_ids[a],
                        "rank": rank,
                        "emb_cos": ec,
                        "pre_status": pre,
                        "tfidf_cos": tc,
                        "decision": "band_deferred",
                    })
                decided = Assignment(
                    playbook_id=anchor_ids[a], cosine=round(ec, 4), status=BAND,
                    cascade_rank=rank, band_checks=band_checks,
                    band_rejections=band_rejections)
                break
            # r == NOVEL: band-rejected conflation → fall through to the next-nearest
            if candidate_trace is not None:
                session_trace.append({
                    "anchor_id": anchor_ids[a],
                    "rank": rank,
                    "emb_cos": ec,
                    "pre_status": pre,
                    "tfidf_cos": tc,
                    "decision": "band_rejected",
                })
            band_rejections += 1
        if candidate_trace is not None:
            candidate_trace.append(session_trace)
        out.append(decided or Assignment(
            None, round(nearest_cos, 4), NOVEL,
            band_checks=band_checks, band_rejections=band_rejections,
        ))
    return out


def is_novel(a: Assignment) -> bool:
    """Novel-pool predicate — the only sessions HDBSCAN still clusters post-cutover."""
    return a.status == NOVEL


@dataclass
class AssignmentWindowResult:
    """Output of `compute_assignment_window` — the resolved per-session assignments
    plus whether the TF-IDF band confirm was available for this fit. `tfidf_available`
    requires both a numerically usable SVD fit AND at least one anchor that cleared
    `_MIN_ANCHOR_BAGS` — an SVD fit with zero surviving anchor centroids (e.g. every
    anchor in this window is thin) reports unavailable, since no band check could ever
    confirm against it."""
    assignments: list[Assignment]
    tfidf_available: bool


def compute_assignment_window(
    window_embeddings: object, anchor_embeddings: object, anchor_ids: list[str],
    anchor_bags: list[str], anchor_bag_ids: list[str], window_bags: list[str], *,
    tau: float = 0.94, confident_tau: float = 0.98, tfidf_tau: float = 0.80,
    band_bypass_anchor_ids: set[str] | None = None,
    band_trace: list[dict] | None = None,
    candidate_trace: list[list[dict]] | None = None,
    background_bags: list[str] | None = None,
    rescue_tau: float | None = None,
    window_predicates: list[dict | None] | None = None,
    anchor_predicate_signatures: list[dict | None] | None = None,
) -> AssignmentWindowResult:
    """The shared assignment-window compute seam (Finding 28 / Mechanism 1): fits one
    TF-IDF/SVD lexical space over `anchor_bags` + `window_bags` (`prepare_assignment_lexical`)
    and resolves every window row against the anchor embeddings (`assign_batch`). No ES —
    every input is explicit, so production (`assign_runner.run_assignment`) and the offline
    replay gate (`eval_assignment_faithful._replay`) call this instead of each independently
    reassembling the same lexical-fit + assign_batch block.

    `band_trace` is forwarded to `assign_batch` unchanged — diagnostic-only (item 34),
    `None` by default and leaving output byte-identical. As in `assign_batch`, pass a
    fresh list per call; it is append-only.

    `candidate_trace` is forwarded to `assign_batch` unchanged — diagnostic-only (item 78),
    `None` by default and leaving returned assignments and `tfidf_available`
    byte-identical. Pass a fresh list per call; it is append-only.

    `band_bypass_anchor_ids` is forwarded to `assign_batch` unchanged — empty by default,
    so callers only opt into item 81's anchor-scoped embedding-only band behavior when
    they pass explicit anchor ids.

    `background_bags` (item 38) is forwarded to `prepare_assignment_lexical` to pad a
    thin fit (e.g. the eval replay's committed anchor snapshot) with a broader session
    sample. `None`/omitted (every production caller) is byte-identical to before.

    `rescue_tau`/`window_predicates`/`anchor_predicate_signatures` (item 30) are forwarded
    to `assign_batch` unchanged (`window_predicates` as its `session_predicates`, aligned to
    `window_embeddings`/`window_bags` by row). All three default to `None`, which keeps
    `assign_batch`'s rescue tier empty and this function's output byte-identical to before
    the rescue tier existed."""
    lexical = prepare_assignment_lexical(
        anchor_bags, anchor_bag_ids, window_bags,
        background_bags=() if background_bags is None else background_bags,
    )

    def tfidf_cos(i: int, a: int) -> float | None:
        c = lexical.anchor_centroids.get(anchor_ids[a])
        return (
            float(lexical.window_features[i] @ c)
            if lexical.available and c is not None
            else None
        )

    assignments = assign_batch(
        window_embeddings, anchor_embeddings, anchor_ids,
        tau=tau, confident_tau=confident_tau, tfidf_tau=tfidf_tau, tfidf_cos=tfidf_cos,
        band_bypass_anchor_ids=band_bypass_anchor_ids,
        band_trace=band_trace, candidate_trace=candidate_trace, rescue_tau=rescue_tau,
        session_predicates=window_predicates,
        anchor_predicate_signatures=anchor_predicate_signatures,
    )
    return AssignmentWindowResult(
        assignments=assignments,
        tfidf_available=lexical.available and bool(lexical.anchor_centroids),
    )
