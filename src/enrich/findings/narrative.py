"""Findings v2 step 5 — drift narrative generator.

For each drift finding (stream A), call the cloud LLM to produce a
one-sentence summary of the delta. Strict JSON output; reject + fall
back to the structured `narrative_template` on parse failure. Cached
on the finding doc itself (`narrative_source: "llm"`) so re-mining
the same delta_signature reuses the existing summary without a fresh
LLM call.

Skipped kinds (already render fine from structured fields):
  - intel_verdict_flip   (verdict transition + IP fully describes it)
  - playbook_size_drift  (+N IPs (M%) since anchor is self-explanatory)
  - playbook_resurgence  (resurfaced after Nd silence is self-explanatory)
  - campaign_growth      (size delta narrative)

Budget: shares the `cloud.daily_budget_usd` pool with `escalate`. The
narrative pass runs inside `mine findings` (hourly), which precedes the
forward `enrich` step in the natural cadence; a hard floor
(`findings.narrative.budget_floor_usd`) prevents a delta storm from
starving escalation entirely.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from ..classification import is_releasable

log = logging.getLogger(__name__)


_KINDS_SKIPPED: frozenset[str] = frozenset({
    "intel_verdict_flip",
    "playbook_size_drift",
    "playbook_resurgence",
    "campaign_growth",
})


def _build_prompt(finding: dict) -> str:
    kind = finding.get("kind", "drift")
    ev = finding.get("evidence") or {}
    # Bound evidence aggressively — long artifact_set lists would balloon
    # the prompt without changing the narrative. Cap lists to 5 entries.
    safe_ev: dict = {}
    for k, v in ev.items():
        if isinstance(v, list):
            safe_ev[k] = v[:5]
        elif isinstance(v, dict):
            # Cap dict to 5 entries, by value desc.
            try:
                top = sorted(v.items(), key=lambda kv: float(kv[1]), reverse=True)[:5]
                safe_ev[k] = dict(top)
            except (TypeError, ValueError):
                safe_ev[k] = v
        else:
            safe_ev[k] = v
    return (
        "You write one-sentence drift narratives for a security research console.\n"
        f"Drift kind: {kind}\n"
        f"Delta (structured): {json.dumps(safe_ev, default=str)}\n\n"
        "Respond strict JSON only — exactly two keys:\n"
        '  {"summary": "<one sentence describing what changed>", '
        '"confidence": <float 0..1>}\n'
        "Constraints:\n"
        "- One sentence, <=120 chars.\n"
        "- No emojis, no hedging language, no preamble.\n"
        "- Reference specific values from the delta (not generic descriptions).\n"
    )


def parse_narrative_response(text: str) -> Optional[dict]:
    """Parse strict JSON `{summary, confidence}` from raw LLM text.

    Returns None on any parse failure or missing/invalid fields. Tolerates
    code-fenced output (```json ... ```) since some Claude responses wrap.
    """
    if not text:
        return None
    s = text.strip()
    if s.startswith("```"):
        nl = s.find("\n")
        if nl != -1:
            s = s[nl + 1 :]
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    try:
        data = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return None
    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    return {
        "summary": summary.strip()[:200],
        "confidence": max(0.0, min(1.0, confidence)),
    }


def _make_client(cfg: Any, secrets: Any):
    """Build the cloud LLM client. Returns None when the cloud provider
    isn't anthropic or credentials are missing.
    """
    if not cfg.cloud.enabled:
        return None
    if cfg.cloud.provider != "anthropic":
        log.warning("narrative: cloud.provider=%s unsupported; skipping", cfg.cloud.provider)
        return None
    api_key = (
        getattr(secrets, "anthropic_api_key", None)
        or getattr(secrets, "cloud_api_key", None)
    )
    if not api_key:
        return None
    from ..llm.anthropic import AnthropicClient
    return AnthropicClient(
        api_key=api_key,
        model=cfg.cloud.model,
        max_tokens=cfg.findings.narrative.max_tokens,
        base_url=cfg.cloud.base_url,
        timeout=cfg.cloud.request_timeout,
    )


def generate_delta_narrative(cfg: Any, secrets: Any, finding: dict) -> Optional[dict]:
    """Produce `{summary, confidence, input_tokens, output_tokens}` for a
    single drift finding. Returns None when:
      - cloud disabled, or
      - the kind is in `_KINDS_SKIPPED`, or
      - credentials missing, or
      - LLM call raises, or
      - the response fails strict-JSON validation.

    Caller is responsible for budget gating + spend recording — this
    function does not touch the state DB.
    """
    if finding.get("kind") in _KINDS_SKIPPED:
        return None
    # Privacy gate (authoritative, defense-in-depth): a confidential — or,
    # under the fail-safe default, untagged — playbook delta is never sent to
    # the cloud for narration. `_classification` is stamped by the drift miner.
    if not is_releasable(finding.get("_classification"), cfg):
        return None
    client = _make_client(cfg, secrets)
    if client is None:
        return None
    try:
        prompt = _build_prompt(finding)
        text, in_tok, out_tok = client.generate_with_usage(
            prompt, max_tokens=cfg.findings.narrative.max_tokens,
        )
    except Exception as exc:
        log.warning("narrative LLM call failed: %s", exc)
        try:
            client.close()
        except Exception:
            pass
        return None
    finally:
        try:
            client.close()
        except Exception:
            pass
    parsed = parse_narrative_response(text)
    if parsed is None:
        return None
    parsed["input_tokens"] = int(in_tok)
    parsed["output_tokens"] = int(out_tok)
    return parsed


def attach_drift_narratives(
    es,
    cfg: Any,
    secrets: Any,
    db,
    findings_idx: str,
    drift_findings: list[dict],
) -> dict[str, int]:
    """Walk every drift finding; either reuse the existing LLM narrative
    on the same delta_signature (cache hit) or call the LLM (cache miss).

    Mutates `drift_findings` in place: sets `narrative` /
    `narrative_source` / `narrative_confidence`. Returns counters.
    """
    stats = {
        "cached": 0, "generated": 0, "budget_skipped": 0,
        "skipped_kind": 0, "skipped_confidential": 0, "failed": 0,
    }
    if not drift_findings:
        return stats
    if not (cfg.cloud.enabled and cfg.findings.narrative.enabled):
        return stats

    from .writer import finding_id
    from ..triage import budget_remaining_usd

    ids = [
        finding_id(
            f["kind"], f["artifact"]["kind"], f["artifact"]["value"],
            f.get("delta_signature"),
        )
        for f in drift_findings
    ]
    existing: dict[str, dict] = {}
    try:
        resp = es.mget(index=findings_idx, ids=ids)
        for d in resp.get("docs") or []:
            if d.get("found"):
                existing[d["_id"]] = d.get("_source") or {}
    except Exception as exc:
        log.warning("narrative: mget for existing findings failed: %s", exc)

    floor = float(cfg.findings.narrative.budget_floor_usd)
    for fid, finding in zip(ids, drift_findings):
        if finding.get("kind") in _KINDS_SKIPPED:
            stats["skipped_kind"] += 1
            continue
        # Privacy gate: skip confidential/untagged playbooks entirely — no
        # cloud call and no cache-reuse. The finding keeps the structured
        # `narrative` template the drift miner already set.
        if not is_releasable(finding.get("_classification"), cfg):
            stats["skipped_confidential"] += 1
            continue
        prev = existing.get(fid) or {}
        if (
            prev.get("narrative_source") == "llm"
            and prev.get("delta_signature") == finding.get("delta_signature")
            and prev.get("narrative")
        ):
            finding["narrative"] = prev["narrative"]
            finding["narrative_source"] = "llm"
            if prev.get("narrative_confidence") is not None:
                finding["narrative_confidence"] = prev["narrative_confidence"]
            stats["cached"] += 1
            continue
        try:
            if budget_remaining_usd(db, cfg.cloud) < floor:
                stats["budget_skipped"] += 1
                continue
        except Exception:
            pass
        result = generate_delta_narrative(cfg, secrets, finding)
        if result is None:
            stats["failed"] += 1
            continue
        finding["narrative"] = result["summary"]
        finding["narrative_source"] = "llm"
        finding["narrative_confidence"] = result["confidence"]
        # Record spend on the StateDB.
        try:
            from ..llm.anthropic import cost_usd
            from ..triage import utc_today
            cost = cost_usd(
                result["input_tokens"], result["output_tokens"],
                cfg.cloud.pricing.input_per_mtok,
                cfg.cloud.pricing.output_per_mtok,
            )
            db.add_spend(utc_today(), result["input_tokens"], result["output_tokens"], cost)
        except Exception as exc:
            log.warning("narrative: spend record failed: %s", exc)
        stats["generated"] += 1
    return stats
