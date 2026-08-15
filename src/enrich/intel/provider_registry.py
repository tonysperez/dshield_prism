"""Static mapping: provider name → set of upstream-feed identifiers it
draws from. Used by the M3 consensus-skip gate (``triage.maybe_skip_for_intel``)
to require ≥2 providers from DISJOINT upstream feeds before suppressing
cloud-LLM escalation — avoiding the footgun where two abuse.ch providers
agree because they're querying the same upstream database, not because
two independent sources observed the same artifact.

Keep entries in sync with each ``src/enrich/intel/providers/<name>.py``
class's ``upstream_feeds`` attribute. ``scripts/smoke_test_intel_independence.py``
enforces parity.

Upstream-identifier conventions:
  - A provider's first-party data collection appears as its own name
    (e.g. ``greynoise`` runs its own scanners → ``{"greynoise"}``).
  - Aggregators list the underlying feeds they aggregate so the gate
    can rule them out as independent partners for those upstreams.
    FireHOL Level 1 includes DShield + Spamhaus + others, so it
    overlaps with ISC (whose first-party data IS DShield).
  - abuse.ch operates a family of related feeds (FeodoTracker /
    MalwareBazaar / ThreatFox / URLhaus) that share infrastructure
    and cross-reference each other. All four declare ``{"abuse.ch"}``
    so any two of them count as ONE source.
  - VirusTotal aggregates 70+ AV engines and URL scanners, but its
    output is delivered as a single normalized verdict — treat as
    one identity (``virustotal``).
"""
from __future__ import annotations

from itertools import combinations

# Curated registry. The smoke test verifies each provider class's
# `upstream_feeds` attribute matches the entry here.
PROVIDER_UPSTREAM_FEEDS: dict[str, frozenset[str]] = {
    "abuseipdb":         frozenset({"abuseipdb"}),
    "feodotracker":      frozenset({"abuse.ch"}),
    "firehol":           frozenset({"firehol", "spamhaus", "dshield"}),
    "greynoise":         frozenset({"greynoise"}),
    "isc":               frozenset({"dshield"}),
    "malwarebazaar":     frozenset({"abuse.ch"}),
    "threatfox":         frozenset({"abuse.ch"}),
    "tor":               frozenset({"tor"}),
    "urlhaus":           frozenset({"abuse.ch"}),
    "virustotal_public": frozenset({"virustotal"}),
}


def max_independent_set(provider_names: frozenset[str] | set[str]) -> int:
    """Largest subset of ``provider_names`` whose ``upstream_feeds`` sets
    are pairwise disjoint.

    Two providers are independent IFF their declared upstreams don't
    intersect. ``threatfox`` and ``malwarebazaar`` both declare
    ``{"abuse.ch"}`` so they count as ONE source for consensus purposes;
    ``firehol`` (which aggregates DShield) cannot pair with ``isc``
    (which IS DShield) since their upstreams share ``"dshield"``.

    Unknown provider names contribute a synthetic singleton upstream
    that intersects nothing else — they count toward consensus on
    their own without polluting the existing graph.
    """
    if not provider_names:
        return 0

    entries: list[frozenset[str]] = []
    for name in provider_names:
        feeds = PROVIDER_UPSTREAM_FEEDS.get(name)
        if feeds is None:
            feeds = frozenset({f"unknown:{name}"})
        entries.append(feeds)

    # Brute-force max independent set. We have ≤10 providers in practice;
    # 2**10 = 1024 subsets — trivial.
    n = len(entries)
    for k in range(n, 0, -1):
        for combo in combinations(entries, k):
            seen: set[str] = set()
            ok = True
            for feeds in combo:
                if seen & feeds:
                    ok = False
                    break
                seen |= feeds
            if ok:
                return k
    return 0
