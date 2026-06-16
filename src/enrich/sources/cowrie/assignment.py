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

from dataclasses import dataclass
from typing import Callable, Optional

ASSIGNED = "assigned"
NOVEL = "novel"
BAND = "band"  # transient: an in-band session before the secondary signal resolves it


@dataclass
class Assignment:
    """Outcome for one session. `status` is ASSIGNED or NOVEL once resolved (BAND is
    never a final status). `playbook_id` is None iff NOVEL. `cascade_rank` is the rank
    of the winning anchor among the session's nearest (0 = nearest; >0 means the nearer
    anchor(s) were band-rejected conflations and we fell through)."""
    playbook_id: Optional[str]
    cosine: float
    status: str
    tfidf_cosine: Optional[float] = None
    confirmed_in_band: bool = False
    cascade_rank: int = 0


def classify_status(cosine: float, *, tau: float, confident_tau: float) -> str:
    """Pre-secondary-signal status from the embedding cosine alone."""
    if cosine < tau:
        return NOVEL
    if cosine < confident_tau:
        return BAND
    return ASSIGNED


def resolve(emb_cos: float, tfidf_cos: Optional[float], *,
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
    emb: "object", anchor_emb: "object", anchor_ids: list[str], *,
    tau: float = 0.94, confident_tau: float = 0.98, tfidf_tau: float = 0.80,
    tfidf_cos: Optional[Callable[[int, int], Optional[float]]] = None,
    defer_band: bool = False,
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
    actually inspect. Returns one Assignment per row."""
    import numpy as np

    A = np.asarray(anchor_emb)
    E = np.asarray(emb)
    if A.shape[0] == 0:
        return [Assignment(None, 0.0, NOVEL) for _ in range(E.shape[0])]
    sims = E @ A.T
    # nearest-first order per session (descending cosine)
    order = np.argsort(-sims, axis=1)
    out: list[Assignment] = []
    for i in range(E.shape[0]):
        nearest_cos = float(sims[i, order[i, 0]])
        decided: Optional[Assignment] = None
        for rank in range(order.shape[1]):
            a = int(order[i, rank])
            ec = float(sims[i, a])
            pre = classify_status(ec, tau=tau, confident_tau=confident_tau)
            if pre == NOVEL:
                break  # farther anchors are only worse — stop
            tc = tfidf_cos(i, a) if (pre == BAND and tfidf_cos is not None) else None
            r = resolve(ec, tc, tau=tau, confident_tau=confident_tau,
                        tfidf_tau=tfidf_tau, defer_band=defer_band)
            if r == ASSIGNED:
                decided = Assignment(
                    playbook_id=anchor_ids[a], cosine=round(ec, 4), status=ASSIGNED,
                    tfidf_cosine=(round(tc, 4) if tc is not None else None),
                    confirmed_in_band=(pre == BAND), cascade_rank=rank)
                break
            if r == BAND:
                # forward pass, no TF-IDF yet → leave pending on the nearest band anchor
                decided = Assignment(
                    playbook_id=anchor_ids[a], cosine=round(ec, 4), status=BAND,
                    cascade_rank=rank)
                break
            # r == NOVEL: band-rejected conflation → fall through to the next-nearest
        out.append(decided or Assignment(None, round(nearest_cos, 4), NOVEL))
    return out


def is_novel(a: Assignment) -> bool:
    """Novel-pool predicate — the only sessions HDBSCAN still clusters post-cutover."""
    return a.status == NOVEL
