"""Smoke test: provider-independence guard on the M3 consensus-skip gate
(brutal-review phase 2.1).

Two assertions:
  1. `max_independent_set` rejects correlated provider pairs and accepts
     disjoint ones, across the cases the curated registry covers.
  2. Every Provider subclass's class-level `upstream_feeds` matches the
     registry — class definition and registry can't drift apart silently.

Run standalone from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_intel_independence.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.intel.provider_registry import (
    PROVIDER_UPSTREAM_FEEDS,
    max_independent_set,
)


def _check_pair_logic() -> None:
    cases = [
        # (provider names, expected max-independent-set size, why)
        (frozenset(),                                        0, "empty input"),
        (frozenset({"greynoise"}),                           1, "single provider"),
        # abuse.ch family — all share one upstream
        (frozenset({"threatfox", "malwarebazaar"}),          1, "two abuse.ch sibs"),
        (frozenset({"threatfox", "malwarebazaar", "urlhaus"}), 1,
         "three abuse.ch sibs"),
        # firehol overlaps with isc on dshield
        (frozenset({"firehol", "isc"}),                      1, "firehol + dshield"),
        # disjoint pairs
        (frozenset({"threatfox", "greynoise"}),              2,
         "abuse.ch + greynoise"),
        (frozenset({"firehol", "greynoise"}),                2, "firehol + greynoise"),
        (frozenset({"abuseipdb", "greynoise"}),              2,
         "abuseipdb + greynoise (no overlap)"),
        # three disjoint providers
        (frozenset({"abuseipdb", "greynoise", "isc"}),       3,
         "three disjoint feeds"),
        # mixed — only 2 of 3 are mutually disjoint (threatfox + greynoise + isc;
        # firehol kills the isc pairing)
        (frozenset({"firehol", "greynoise", "isc"}),         2,
         "firehol + greynoise + isc → fh blocks isc"),
        # unknown name gets a synthetic singleton upstream (counts on its own)
        (frozenset({"some_future_provider", "greynoise"}),   2,
         "unknown provider + greynoise"),
    ]
    for names, expected, why in cases:
        got = max_independent_set(names)
        assert got == expected, (
            f"max_independent_set({set(names)!r}) = {got}, expected {expected}  "
            f"({why})"
        )
    print(f"pair logic: {len(cases)} cases pass")


def _check_class_registry_parity() -> None:
    # Import every provider module by name. Each is supposed to declare a
    # class-level `upstream_feeds` that matches PROVIDER_UPSTREAM_FEEDS.
    from enrich.intel.providers import (
        abuseipdb, feodotracker, firehol, greynoise, isc,
        malwarebazaar, threatfox, tor, urlhaus, virustotal_public,
    )
    from enrich.intel.providers.base import Provider

    modules = [
        abuseipdb, feodotracker, firehol, greynoise, isc,
        malwarebazaar, threatfox, tor, urlhaus, virustotal_public,
    ]
    seen_names: set[str] = set()
    for mod in modules:
        # The provider class is the one Provider subclass in the module.
        candidates = [
            v for v in vars(mod).values()
            if isinstance(v, type) and issubclass(v, Provider) and v is not Provider
        ]
        assert len(candidates) == 1, (
            f"{mod.__name__} should define exactly one Provider subclass, "
            f"got {len(candidates)}: {candidates}"
        )
        provider_cls = candidates[0]
        name = provider_cls.name
        assert name, f"{provider_cls.__name__} has no `name` set"
        seen_names.add(name)
        cls_feeds = provider_cls.upstream_feeds
        reg_feeds = PROVIDER_UPSTREAM_FEEDS.get(name)
        assert reg_feeds is not None, (
            f"{name} missing from PROVIDER_UPSTREAM_FEEDS — add an entry"
        )
        assert cls_feeds == reg_feeds, (
            f"{name}: class upstream_feeds={set(cls_feeds)!r} != "
            f"registry={set(reg_feeds)!r}"
        )

    # Registry shouldn't carry any phantom entries either.
    phantom = set(PROVIDER_UPSTREAM_FEEDS) - seen_names
    assert not phantom, f"Registry has entries for unknown providers: {phantom}"
    print(f"class<->registry parity: {len(modules)} providers checked")


def main() -> int:
    _check_pair_logic()
    _check_class_registry_parity()
    print("intel independence smoke OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
