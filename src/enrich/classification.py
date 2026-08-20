"""Data classification gate (public | confidential).

A per-sensor ingest pipeline stamps ``dshield.classification`` on raw events.
**Confidential data must never leave the box** — no cloud-LLM escalation, no
CTI-feed (intel) queries, nothing that would expose it externally.

The gate is **fail-safe**: by default (``classification.unclassified_is_confidential``
= True) only data explicitly tagged ``public`` is releasable; anything tagged
``confidential`` OR carrying no tag at all is withheld. Propagation onto derived
docs (session/IP rollups, the content-deduped command) follows "most restrictive
source wins": any confidential source taints the derived doc, and a doc is only
``public`` when *every* source is explicitly public (see ``aggregate``).

So even if propagation is incomplete, an untagged derived doc is gated under the
default posture — the boundary checks (``is_releasable``) are the safety net.
"""
from __future__ import annotations

from collections.abc import Iterable

# ES field (text+keyword multifield in the mappings; exact-match queries use
# `dshield.classification.keyword`).
CLASSIFICATION_FIELD = "dshield.classification"
CLASSIFICATION_KEYWORD = "dshield.classification.keyword"
PUBLIC = "public"
CONFIDENTIAL = "confidential"
VALID = frozenset({PUBLIC, CONFIDENTIAL})


def _unclassified_is_confidential(cfg) -> bool:
    """The posture knob, defaulting fail-safe when config is absent."""
    cc = getattr(cfg, "classification", None)
    if cc is None:
        return True
    return bool(getattr(cc, "unclassified_is_confidential", True))


def is_releasable(classification: str | None, cfg) -> bool:
    """True if data with this classification may leave the box (cloud
    escalation / CTI query). Explicit ``public`` always may; explicit
    ``confidential`` never may; an absent/unknown value follows the posture knob
    (fail-safe default → not releasable)."""
    if classification == PUBLIC:
        return True
    if classification == CONFIDENTIAL:
        return False
    return not _unclassified_is_confidential(cfg)


def aggregate(classifications: Iterable[str | None]) -> str | None:
    """Roll source classifications up onto a derived doc, "most restrictive
    wins": ``confidential`` if ANY source is confidential; ``public`` only if
    every source is explicitly public; otherwise ``None`` (some source carried
    no tag and none were confidential — the gate's posture knob then decides).

    Three-valued on purpose so both postures work: under fail-safe a ``None``
    result still gates (``is_releasable(None)`` is False); under fail-open it
    releases.
    """
    seen_any = False
    seen_unclassified = False
    for c in classifications:
        seen_any = True
        if c == CONFIDENTIAL:
            return CONFIDENTIAL
        if c != PUBLIC:
            seen_unclassified = True
    if not seen_any or seen_unclassified:
        return None
    return PUBLIC


def releasable_filter(cfg) -> dict:
    """An ES bool-query clause matching only **releasable** docs — for the
    queries that must never surface confidential data (the intel discovery scan,
    the cloud-escalation candidate scan). Fail-safe (default): only docs with an
    explicit ``dshield.classification:public`` keyword; a missing field does not
    match, so untagged docs are excluded. Fail-open: everything except an
    explicit ``confidential``."""
    if _unclassified_is_confidential(cfg):
        return {"term": {CLASSIFICATION_KEYWORD: PUBLIC}}
    return {"bool": {"must_not": {"term": {CLASSIFICATION_KEYWORD: CONFIDENTIAL}}}}


def explicit_public_filters(cfg) -> list[dict]:
    """ES filter clauses that always require an explicit public tag,
    regardless of the configurable releasability posture.

    `releasable_filter` follows the operator's chosen posture, which under
    fail-open also passes untagged docs — fine for local operations, but not
    for an artifact committed to VCS. Anything captured into a repo-committed
    snapshot (`capture_anchor_snapshot.py`, `refresh_production_snapshot.py`,
    `refresh_command_snapshot.py`) must be explicit-public no matter the
    posture, so callers should AND this into their query's `bool.filter`
    instead of `releasable_filter` alone.
    """
    explicit = {"term": {CLASSIFICATION_KEYWORD: PUBLIC}}
    releasable = releasable_filter(cfg)
    return [releasable] if releasable == explicit else [releasable, explicit]


def stickier(existing: str | None, incoming: str | None) -> str | None:
    """Combine an already-stored classification with a new observation, never
    downgrading: once ``confidential`` it stays confidential. Used when a
    content-deduped command doc that already exists is updated with events from
    another (possibly confidential) sensor."""
    if existing == CONFIDENTIAL or incoming == CONFIDENTIAL:
        return CONFIDENTIAL
    if existing == PUBLIC and incoming == PUBLIC:
        return PUBLIC
    # at least one side is None/unknown and neither is confidential
    return existing if incoming is None else incoming
