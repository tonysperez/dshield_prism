"""VirusTotal public API v3 — per-hash lookup (ROADMAP #2 scaffold).

**Disabled by default.** Even with `VIRUSTOTAL_API_KEY` set, the provider only
runs when `intel.providers.virustotal_public.enabled: true`. The free public
tier is 4 req/min / 500 per day, so the worker gates dispatch on
`rate_limit.daily_budget` (like GreyNoise / AbuseIPDB) and the provider
self-throttles to the per-minute ceiling.

API:
    GET {base_url}/files/{hash}
    Headers: x-apikey: <key>
    200 -> {"data": {"attributes": {"last_analysis_stats": {...}, ...}}}
    404 -> hash unknown to VT (no opinion)
    401 -> bad/missing key; 429 -> rate-limited.

VT aggregates many AV engines, so a detection is treated as a (well-sourced)
aggregate vote — `evidence_direct=False`, consistent with how the consensus
rule weights aggregators vs direct-observation providers.
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Any, Optional

import httpx

from ..artifact import Artifact
from .base import (
    DerivedSignals,
    HealthStatus,
    Provider,
    ProviderError,
    ProviderRateLimited,
    ProviderResult,
    ProviderUnavailable,
    RateLimit,
)

log = logging.getLogger(__name__)

# Minimum AV-engine detections before we vote malicious — guards against a
# single noisy engine flipping a benign file.
_MIN_MALICIOUS_ENGINES = 3


def classify_virustotal(
    attributes: dict[str, Any],
) -> tuple[Optional[bool], Optional[str], Optional[int], tuple[str, ...], bool, bool]:
    """Pure-function: VT v3 file `attributes` → DerivedSignals fields.

    `(malicious, label, confidence, tags, authoritative_clean, evidence_direct)`.
    Votes malicious when `last_analysis_stats.malicious >= _MIN_MALICIOUS_ENGINES`;
    confidence scales with detection count. evidence_direct is always False
    (aggregated AV verdicts, not direct observation by VT itself).
    """
    stats = attributes.get("last_analysis_stats") or {}
    n_mal = int(stats.get("malicious") or 0)
    label_block = attributes.get("popular_threat_classification") or {}
    suggested = (label_block.get("suggested_threat_label") or "").strip().lower() or None

    if n_mal < _MIN_MALICIOUS_ENGINES:
        # In VT but few/no detections — informational, no malicious vote.
        return None, "virustotal_low", None, ("virustotal_seen",), False, False

    # 3 engines → ~6, 10+ → 10.
    confidence = max(5, min(10, 5 + n_mal // 3))
    tags = ("virustotal_detected",)
    if suggested:
        tags = tags + (suggested,)
    label = f"virustotal_{suggested}" if suggested else "virustotal_detected"
    return True, label, confidence, tags, False, False


class VirusTotalPublicProvider(Provider):
    name = "virustotal_public"
    handles = frozenset({"hash"})

    def __init__(self, provider_cfg, api_key: str) -> None:
        super().__init__(provider_cfg)
        self.ttl = timedelta(days=int(provider_cfg.ttl_days))
        self.rate_limit = RateLimit(
            capacity=4, refill_per_second=4 / 60.0,
            daily_budget=int(provider_cfg.daily_budget),
        )
        self._client = httpx.Client(
            timeout=float(provider_cfg.request_timeout_seconds),
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )
        self._last_call: float = 0.0

    def _throttle(self) -> None:
        gap = float(self.cfg.min_inter_call_seconds)
        if gap <= 0:
            return
        delta = time.monotonic() - self._last_call
        if delta < gap:
            time.sleep(gap - delta)

    def lookup(self, artifact: Artifact) -> ProviderResult:
        if artifact.kind not in self.handles:
            raise ValueError(f"virustotal_public: cannot handle kind {artifact.kind!r}")
        self._throttle()
        url = f"{self.cfg.base_url.rstrip('/')}/files/{artifact.value}"
        try:
            r = self._client.get(url)
        except (httpx.HTTPError, httpx.RequestError) as exc:
            raise ProviderUnavailable(f"virustotal: HTTP {exc}") from exc
        finally:
            self._last_call = time.monotonic()

        if r.status_code == 404:
            return ProviderResult.make(
                provider=self.name, artifact=artifact,
                structured={"in_virustotal": False}, raw={}, derived=DerivedSignals(),
                ttl=self.ttl,
            )
        if r.status_code == 429:
            raise ProviderRateLimited(f"virustotal: rate-limited (429): {r.text[:200]}")
        if r.status_code in (401, 403):
            raise ProviderError(f"virustotal: auth failed ({r.status_code})")
        if r.status_code != 200:
            raise ProviderUnavailable(f"virustotal: HTTP {r.status_code}: {r.text[:200]}")

        try:
            payload = r.json()
        except ValueError as exc:
            raise ProviderUnavailable(f"virustotal: non-JSON body: {exc}") from exc

        attributes = ((payload.get("data") or {}).get("attributes")) or {}
        (malicious, label, confidence, tags, ac, ed) = classify_virustotal(attributes)
        derived = DerivedSignals(
            malicious=malicious, confidence=confidence, label=label,
            tags=tags, authoritative_clean=ac, evidence_direct=ed,
        )
        stats = attributes.get("last_analysis_stats") or {}
        structured = {
            "in_virustotal": True,
            "malicious_engines": int(stats.get("malicious") or 0),
            "suspicious_engines": int(stats.get("suspicious") or 0),
            "type_description": attributes.get("type_description"),
            "meaningful_name": attributes.get("meaningful_name"),
        }
        return ProviderResult.make(
            provider=self.name, artifact=artifact,
            structured=structured, raw=payload, derived=derived, ttl=self.ttl,
        )

    def health(self) -> HealthStatus:
        # Cheap: HEAD-ish GET on a known sample hash would cost budget, so just
        # confirm the key is present. Full liveness is exercised on first lookup.
        return HealthStatus(ok=True, detail="virustotal_public: key configured (scaffold)")
