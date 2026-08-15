"""Intel refresh orchestrator.

One pass over the priority queue: for each enabled provider, pop the
top-N artifacts it can handle, call `provider.lookup`, group results
by artifact, and write through `writer.upsert_intel_doc`.

The worker is intentionally sync. Milestone-1 providers are either
local-in-memory (Tor, ISC after the periodic bulk fetch) or a single
DNS round-trip (Spamhaus), so async parallelism would not pay off
yet. When a paid HTTP-API provider lands (GreyNoise, AbuseIPDB) the
worker can be promoted to asyncio with no shape change to providers
themselves.

Circuit-breaker policy:

- After `_FAILURE_THRESHOLD` consecutive failures, the provider's
  circuit is opened and the rest of the run skips it.
- The breaker resets on the next successful call (any future run).
- Per-call failures don't poison other providers; each is isolated.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from ..cache import StateDB
from ..config import AppConfig, Secrets
from ..es_client import make_client
from .artifact import Artifact
from .providers.abuseipdb import AbuseIPDBProvider
from .providers.base import (
    Provider,
    ProviderError,
    ProviderRateLimited,
    ProviderResult,
    ProviderUnavailable,
)
from .providers.feodotracker import FeodoTrackerProvider
from .providers.firehol import FireholProvider
from .providers.greynoise import GreyNoiseProvider
from .providers.isc import ISCProvider
from .providers.malwarebazaar import MalwareBazaarProvider
from .providers.threatfox import ThreatFoxProvider
from .providers.tor import TorProvider
from .providers.urlhaus import URLhausProvider
from .providers.virustotal_public import VirusTotalPublicProvider
from .queue import discover_and_enqueue
from .writer import upsert_intel_doc

log = logging.getLogger(__name__)


# After this many consecutive failures, open the provider's circuit
# and skip it for the rest of the run. Low number — the worker is
# called frequently from the backward systemd pass, so a transient
# provider outage gets retried on the next pass without piling more
# damage in this one.
_FAILURE_THRESHOLD = 5

# Defensive ceiling on `intel_queue_pop_top` per kind per run. There
# is intentionally NO artifact-dispatch cap (a runaway queue is
# better discovered than silently truncated), but a buggy producer
# enqueuing billions of rows shouldn't OOM the worker. Million-row
# horizon is well above any realistic honeypot corpus.
_QUEUE_FETCH_HARD_LIMIT = 1_000_000


def _build_providers(cfg: AppConfig, secrets: Secrets | None = None) -> list[Provider]:
    """Construct the enabled providers from config.

    New providers are added here. Order is the dispatch order per
    artifact — cheap/local first so a single artifact's enrichment
    has its in-memory hits computed before any network calls.

    M1 providers (`tor`, `isc`, `feodotracker`, `firehol`) are bulk-
    download style: one fetch per refresh window, then in-memory
    lookup. M2 providers (`greynoise`, `abuseipdb`) are per-IP HTTP
    calls with daily-budget gates enforced by the worker via the
    SQLite spend tracker.

    `secrets` carries the M2 API keys. When unset, or when the
    relevant `*_api_key` field is None, the corresponding M2 provider
    silently skips construction — runtime degrades to "we run the
    M1 providers and skip the others." That keeps a missing key from
    being a fatal config error.
    """
    out: list[Provider] = []
    pc = cfg.intel.providers
    # abuse.ch unified auth key shared across URLhaus / ThreatFox /
    # FeodoTracker. Optional — providers accept None and fall back to
    # unauthenticated endpoints with tighter rate limits.
    abusech_key = (secrets.abuse_ch_auth_key if secrets else None)
    if pc.tor.enabled:
        out.append(TorProvider(pc.tor))
    if pc.isc.enabled:
        out.append(ISCProvider(pc.isc))
    if pc.feodotracker.enabled:
        out.append(FeodoTrackerProvider(pc.feodotracker, auth_key=abusech_key))
    if pc.firehol.enabled:
        out.append(FireholProvider(pc.firehol))
    gn_key = (secrets.greynoise_api_key if secrets else None)
    if pc.greynoise.enabled and gn_key:
        out.append(GreyNoiseProvider(pc.greynoise, gn_key))
    abuse_key = (secrets.abuseipdb_api_key if secrets else None)
    if pc.abuseipdb.enabled and abuse_key:
        out.append(AbuseIPDBProvider(pc.abuseipdb, abuse_key))
    # M4: URL-kind providers. abuse.ch family — accept optional
    # auth_key, work unauthenticated when None.
    if pc.urlhaus.enabled:
        out.append(URLhausProvider(pc.urlhaus, auth_key=abusech_key))
    if pc.threatfox.enabled:
        out.append(ThreatFoxProvider(pc.threatfox, auth_key=abusech_key))
    # #2: hash-kind providers. MalwareBazaar is abuse.ch family (shared key,
    # unauthenticated fallback). VirusTotal is key-gated AND enabled-gated —
    # skips construction unless both are present (scaffold; off by default).
    if pc.malwarebazaar.enabled:
        out.append(MalwareBazaarProvider(pc.malwarebazaar, auth_key=abusech_key))
    vt_key = (secrets.virustotal_api_key if secrets else None)
    if pc.virustotal_public.enabled and vt_key:
        out.append(VirusTotalPublicProvider(pc.virustotal_public, vt_key))
    return out


def _utc_today() -> str:
    return datetime.now(UTC).date().isoformat()


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _fresh_within_ttl(
    es, cfg: AppConfig, kind: str, values: list[str], ttl_days: float,
    *, now: datetime,
) -> set[str]:
    """Return the subset of `values` whose intel doc was `last_refreshed`
    within `ttl_days` — i.e. still fresh, so the refresh can skip re-querying
    providers for them. Batched via `_mget`; missing docs (never looked up) and
    parse failures are treated as stale so they always get queried."""
    if ttl_days <= 0 or not values:
        return set()
    from .writer import index_for_kind  # local import: avoid import cycle
    idx = index_for_kind(cfg, kind)
    try:
        if not es.indices.exists(index=idx):
            return set()
    except Exception:
        return set()
    cutoff = now - timedelta(days=ttl_days)
    fresh: set[str] = set()
    for i in range(0, len(values), 1000):
        chunk = values[i:i + 1000]
        try:
            resp = es.mget(index=idx, ids=chunk, _source=["last_refreshed"])
        except Exception:
            continue
        for doc in resp.get("docs", []):
            if not doc.get("found"):
                continue
            lr = (doc.get("_source") or {}).get("last_refreshed")
            if not lr:
                continue
            try:
                ts = datetime.fromisoformat(str(lr))
            except (ValueError, TypeError):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            if ts >= cutoff:
                fresh.add(doc["_id"])
    return fresh


def run_refresh(
    cfg: AppConfig, secrets: Secrets, *, dry_run: bool = False, force: bool = False,
) -> dict[str, Any]:
    """Single refresh pass. Returns a stats dict suitable for `print(json.dumps(…))`.

    Steps:
      1. Build the provider set from config.
      2. Run discovery to repopulate the SQLite priority queue from
         the current IP rollup state.
      3. For each artifact kind, pop top-N from the queue, skip any
         artifact still fresh within its per-kind cache TTL
         (`cfg.intel.refresh_ttl_days`; bypassed when `force`), and
         dispatch the rest through every applicable provider.
      4. Group ProviderResults per artifact, write the merged doc to
         the intel-* index.
      5. Mark the artifact done in the queue when at least one
         provider returned data (others can retry next pass).

    `force=True` ignores the per-kind cache TTL and re-queries everything —
    used by `intel backfill` (e.g. after wiring a new provider).
    """
    if not cfg.intel.enabled:
        return {"enabled": False, "skipped": True}

    run_started = datetime.now(UTC)
    es = make_client(cfg.elasticsearch, secrets)
    db = StateDB(cfg.worker.state_db)
    providers = _build_providers(cfg, secrets)
    by_kind: dict[str, list[Provider]] = defaultdict(list)
    for p in providers:
        for kind in p.handles:
            by_kind[kind].append(p)

    stats: dict[str, Any] = {
        "enabled": True,
        "dry_run": dry_run,
        "providers": [p.name for p in providers],
        "discovered": {},
        "processed": {},
        # Artifacts skipped this run because their intel doc is still fresh
        # within the per-kind cache TTL (cfg.intel.refresh_ttl_days). {kind: n}.
        "skipped_fresh": {},
        "writes": 0,
        "errors": [],
        "provider_calls": {p.name: 0 for p in providers},
        "provider_failures": {p.name: 0 for p in providers},
        # Providers with a daily_budget that's already at-or-past its
        # limit when this run starts. Surfaced explicitly so a 0 in
        # `provider_calls` doesn't look mysterious — these are
        # waiting for the UTC midnight reset.
        "provider_budget_exhausted": [],
        "provider_circuits_open": [],
    }

    # Pre-flight: identify providers whose daily budget is already
    # exhausted (GreyNoise / AbuseIPDB after a few runs in one day).
    # Surfaced in stats; the per-call gate inside the dispatch loop
    # still enforces, but reporting upfront is clearer.
    today = _utc_today()
    budget_exhausted: set[str] = set()
    for prov in providers:
        budget = prov.rate_limit.daily_budget
        if budget is None:
            continue
        spent = db.intel_provider_calls_today(prov.name, today)
        if spent >= budget:
            budget_exhausted.add(prov.name)
            log.info(
                "intel: %s daily budget already exhausted "
                "(%d/%d); will skip this run, resets at UTC midnight",
                prov.name, spent, budget,
            )
    stats["provider_budget_exhausted"] = sorted(budget_exhausted)

    # Step 1: discovery (queue upsert).
    discovered = discover_and_enqueue(es, db, cfg)
    stats["discovered"] = discovered

    if dry_run:
        stats["queue_depth"] = db.intel_queue_depth()
        db.close()
        return stats

    # Step 2: per-kind processing. No artifact-dispatch cap — the
    # whole queue gets a chance per run. Per-provider daily budgets
    # (above) and circuit breakers (below) are the real safety
    # gates; unmetered bulk providers don't have or need a cap.
    circuits_open: set[str] = set()

    for kind, kind_providers in by_kind.items():
        # Pop the entire queue slice for this kind. `intel_queue_pop_top`
        # only RETURNS; it doesn't remove. Rows stay until
        # `intel_queue_mark_done` after a successful dispatch.
        kind_queue = db.intel_queue_pop_top(kind, _QUEUE_FETCH_HARD_LIMIT)
        artifacts: list[Artifact] = []
        for value, _prio in kind_queue:
            try:
                artifacts.append(Artifact(kind, value))
            except ValueError:
                continue

        # Cache age-out: drop artifacts whose intel doc is still fresh within
        # this kind's TTL so a steady-state run re-queries only new/aged-out
        # ones. `force` (intel backfill) bypasses the skip. Marking the fresh
        # ones done drains them from the queue; discovery re-enqueues them next
        # run, where they're re-checked and skipped again until the TTL lapses.
        fresh: set[str] = set()
        if not force:
            fresh = _fresh_within_ttl(
                es, cfg, kind, [a.value for a in artifacts],
                cfg.intel.refresh_ttl_days.for_kind(kind), now=run_started,
            )
        if fresh:
            for value in fresh:
                db.intel_queue_mark_done(kind, value)
            stats["skipped_fresh"][kind] = len(fresh)

        for artifact in artifacts:
            if artifact.value in fresh:
                continue
            results: list[ProviderResult] = []
            any_success = False
            for prov in kind_providers:
                if prov.name in circuits_open:
                    continue
                # Per-provider daily-budget gate. None means unmetered.
                budget = prov.rate_limit.daily_budget
                if budget is not None:
                    spent = db.intel_provider_calls_today(prov.name, today)
                    if spent >= budget:
                        continue
                try:
                    result = prov.lookup(artifact)
                except ProviderRateLimited as exc:
                    # Don't open circuit — just stop dispatching this
                    # provider for the rest of the run. It'll come back
                    # next pass.
                    circuits_open.add(prov.name)
                    stats["provider_failures"][prov.name] += 1
                    stats["errors"].append({
                        "provider": prov.name, "kind": artifact.kind,
                        "value": artifact.value, "error": f"rate_limited: {exc}",
                    })
                    continue
                except (ProviderUnavailable, ProviderError) as exc:
                    stats["provider_failures"][prov.name] += 1
                    db.intel_provider_record_failure(
                        prov.name, str(exc), _utc_now_iso(),
                        open_circuit=False,
                    )
                    state = db.intel_provider_get_state(prov.name)
                    if state["consecutive_failures"] >= _FAILURE_THRESHOLD:
                        circuits_open.add(prov.name)
                        db.intel_provider_record_failure(
                            prov.name, str(exc), _utc_now_iso(),
                            open_circuit=True,
                        )
                    stats["errors"].append({
                        "provider": prov.name, "kind": artifact.kind,
                        "value": artifact.value, "error": str(exc),
                    })
                    continue
                except Exception as exc:                # pragma: no cover
                    # Unknown failure mode — log loudly but don't crash the run.
                    log.exception("intel: unexpected error in %s.lookup", prov.name)
                    stats["provider_failures"][prov.name] += 1
                    stats["errors"].append({
                        "provider": prov.name, "kind": artifact.kind,
                        "value": artifact.value, "error": f"unexpected: {exc}",
                    })
                    continue
                results.append(result)
                any_success = True
                stats["provider_calls"][prov.name] += 1
                db.intel_provider_record_call(prov.name, today)
                db.intel_provider_record_success(prov.name, _utc_now_iso())

            if results:
                try:
                    upsert_intel_doc(es, cfg, artifact, results)
                    stats["writes"] += 1
                except Exception as exc:                # pragma: no cover
                    stats["errors"].append({
                        "kind": artifact.kind, "value": artifact.value,
                        "error": f"upsert: {exc}",
                    })
                    any_success = False

            if any_success:
                db.intel_queue_mark_done(artifact.kind, artifact.value)
            else:
                db.intel_queue_mark_attempt(
                    artifact.kind, artifact.value, "all providers failed or skipped",
                )

        stats["processed"][kind] = stats["processed"].get(kind, 0) + len(artifacts)

    stats["provider_circuits_open"] = sorted(circuits_open)
    stats["queue_depth_after"] = db.intel_queue_depth()
    db.close()
    return stats


def run_backfill(
    cfg: AppConfig, secrets: Secrets, *, dry_run: bool = False,
) -> dict[str, Any]:
    """Force discovery to re-queue every artifact, then refresh.

    Same as `run_refresh` but bypasses the per-kind cache TTL
    (`force=True`) so every artifact is re-queried regardless of how
    recently it was last refreshed — useful after wiring up a new
    provider so existing artifacts get the new provider's coverage.
    Discovery already upserts everything in the rollup unconditionally;
    the `force` flag is what makes this a true re-query of the whole set.
    """
    return run_refresh(cfg, secrets, dry_run=dry_run, force=True)
