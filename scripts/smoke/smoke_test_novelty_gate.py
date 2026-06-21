"""Smoke test for the confidence-floor gate on novelty-based escalation.

Standalone — no ES, no LLM, no pytest. Hand-crafts inputs to
`reasons_to_escalate` and asserts the `novel_embedding` reason fires only
when the local model's self-rated confidence is at or above
`cloud.triage.novel_confidence_min`. Exits non-zero on first failure.

Covers ROADMAP issue #3 (the cheap fix): a confidence-1 enrichment with
novelty=1.0 (typical of raw-byte / encoding artifacts) must not trigger
`novel_embedding` even when novelty exceeds the threshold.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_novelty_gate.py
"""
from __future__ import annotations

import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import CloudConfig
from enrich.llm.schemas import CommandEnrichment, IOCs
from enrich.triage import reasons_to_escalate


def _load_cloud_cfg() -> CloudConfig:
    """Load only the cloud block from default.yaml — that's all triage needs."""
    import yaml
    cfg_path = Path(__file__).resolve().parents[2] / "config" / "default.yaml"
    raw = yaml.safe_load(cfg_path.read_text())
    return CloudConfig.model_validate(raw.get("cloud") or {})


def _enrichment(confidence: int) -> CommandEnrichment:
    """Build a minimally-valid CommandEnrichment with the given confidence."""
    return CommandEnrichment(
        intent="host_recon",
        confidence=confidence,
        description="synthetic test enrichment",
        iocs=IOCs(ips=[], domains=[], urls=[], hashes=[], files=[]),
    )


def _unit(*v: float) -> list[float]:
    n = math.sqrt(sum(x * x for x in v))
    return [x / n for x in v]


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


cloud = _load_cloud_cfg()
floor = cloud.triage.novel_confidence_min
upper = cloud.triage.confidence_max
escalate_cap = cloud.triage.escalate_confidence_max
nov_thr = cloud.triage.novel_embedding_threshold

print(
    f"Loaded config: novel_confidence_min={floor}, confidence_max={upper}, "
    f"novel_embedding_threshold={nov_thr}"
)
assert floor >= 1, "novel_confidence_min should be sane"
assert floor < 10, "novel_confidence_min should be sane"

# A simple centroid setup: one centroid pointing at +x. Query embedding
# orthogonal to it → cosine=0 → novelty=1.0 (well above threshold).
centroid = _unit(1.0, 0.0, 0.0)
high_novelty_embedding = _unit(0.0, 1.0, 0.0)
# Aligned with the centroid → novelty≈0
low_novelty_embedding = _unit(1.0, 0.0, 0.0)


# -------------------------------------------------------------------------
# [1] confidence below the floor + high novelty → novel_embedding SUPPRESSED
# -------------------------------------------------------------------------
print(f"\n[1] confidence < {floor} + high novelty → novel_embedding NOT fired")
parsed_low = _enrichment(confidence=1)
reasons = reasons_to_escalate(
    command="harmless command",
    parsed=parsed_low,
    local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[centroid],
    rng=random.Random(0),
)
check("novel_embedding suppressed at confidence=1", "novel_embedding" not in reasons,
      f"got reasons={reasons!r}")
# But low_confidence still fires (existing safety net).
check("low_confidence still fires at confidence=1",
      any(r.startswith("low_confidence") for r in reasons),
      f"got reasons={reasons!r}")


# -------------------------------------------------------------------------
# [2] confidence right at the floor + high novelty → novel_embedding FIRES
# -------------------------------------------------------------------------
print(f"\n[2] confidence = {floor} + high novelty → novel_embedding fires")
parsed_at = _enrichment(confidence=floor)
reasons = reasons_to_escalate(
    command="harmless command",
    parsed=parsed_at,
    local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[centroid],
    rng=random.Random(0),
)
check("novel_embedding fires at confidence==floor", "novel_embedding" in reasons,
      f"got reasons={reasons!r}")


# -------------------------------------------------------------------------
# [3] high confidence + high novelty → novel_embedding FIRES (sanity)
# -------------------------------------------------------------------------
print("\n[3] confidence=8 + high novelty → novel_embedding fires")
parsed_hi = _enrichment(confidence=8)
reasons = reasons_to_escalate(
    command="harmless command",
    parsed=parsed_hi,
    local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[centroid],
    rng=random.Random(0),
)
check("novel_embedding fires at confidence=8", "novel_embedding" in reasons,
      f"got reasons={reasons!r}")
check("low_confidence does NOT fire at confidence=8",
      not any(r.startswith("low_confidence") for r in reasons),
      f"got reasons={reasons!r}")


# -------------------------------------------------------------------------
# [4] confidence high but novelty BELOW threshold → no novel_embedding
# -------------------------------------------------------------------------
print("\n[4] confidence=8 + low novelty → no novel_embedding")
reasons = reasons_to_escalate(
    command="harmless command",
    parsed=parsed_hi,
    local_failed=False,
    cfg=cloud,
    embedding=low_novelty_embedding,
    centroids=[centroid],
    rng=random.Random(0),
)
check("novel_embedding absent when novelty < threshold",
      "novel_embedding" not in reasons,
      f"got reasons={reasons!r}")


# -------------------------------------------------------------------------
# [5] parsed=None (local LLM crashed) + high novelty → no novel_embedding
#     We expect `local_failed` to drive escalation instead. Without the
#     parsed-None guard, this path used to read parsed.confidence on None.
# -------------------------------------------------------------------------
print("\n[5] parsed=None + high novelty → novel_embedding NOT fired (parsed guard)")
reasons = reasons_to_escalate(
    command="harmless command",
    parsed=None,
    local_failed=True,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[centroid],
    rng=random.Random(0),
)
check("novel_embedding absent when parsed=None",
      "novel_embedding" not in reasons,
      f"got reasons={reasons!r}")
check("local_failed fires when parsed=None",
      "local_failed" in reasons,
      f"got reasons={reasons!r}")


# -------------------------------------------------------------------------
# [6] No embedding / no centroids → rule never even reaches the confidence
#     check (regression guard — must not crash on empty inputs).
# -------------------------------------------------------------------------
print("\n[6] missing embedding or centroids → rule skipped without error")
reasons = reasons_to_escalate(
    command="harmless command",
    parsed=parsed_hi,
    local_failed=False,
    cfg=cloud,
    embedding=None,
    centroids=[centroid],
    rng=random.Random(0),
)
check("no embedding → no novel_embedding (no crash)",
      "novel_embedding" not in reasons,
      f"got reasons={reasons!r}")
reasons = reasons_to_escalate(
    command="harmless command",
    parsed=parsed_hi,
    local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=None,
    rng=random.Random(0),
)
check("no centroids → no novel_embedding (no crash)",
      "novel_embedding" not in reasons,
      f"got reasons={reasons!r}")


# -------------------------------------------------------------------------
# [7] External-centroid preference (brutal-review 5.6) — when
# `centroids_external` is provided AND non-empty, the rule scores
# against IT instead of the in-corpus `centroids`. A doc that is novel
# vs in-corpus but FAMILIAR vs the external catalog stops firing
# `novel_embedding`.
# -------------------------------------------------------------------------
print("\n[7] external centroids preferred when present")

# In-corpus centroid points opposite to docs (novelty against in-corpus
# is HIGH). External centroid points SAME direction as the doc
# (novelty against external is LOW).
in_corpus_centroid_far = _unit(0.0, -1.0, 0.0)  # opposite to high_novelty_embedding
external_centroid_near = high_novelty_embedding  # exact match → score ≈ 0

# (a) With ONLY in-corpus: fires (matches old behavior).
reasons = reasons_to_escalate(
    command="harmless command", parsed=parsed_hi, local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[in_corpus_centroid_far],
    rng=random.Random(0),
)
check("in-corpus only: novel_embedding fires when local is novel",
      "novel_embedding" in reasons, f"got reasons={reasons!r}")

# (b) With BOTH refs and external is close: external wins → score ≈ 0 → don't fire.
reasons = reasons_to_escalate(
    command="harmless command", parsed=parsed_hi, local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[in_corpus_centroid_far],
    centroids_external=[external_centroid_near],
    rng=random.Random(0),
)
check("dual: novel_embedding SUPPRESSED when external says familiar",
      "novel_embedding" not in reasons, f"got reasons={reasons!r}")

# (c) Empty external list → falls back to in-corpus (same as case a).
reasons = reasons_to_escalate(
    command="harmless command", parsed=parsed_hi, local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[in_corpus_centroid_far],
    centroids_external=[],
    rng=random.Random(0),
)
check("empty external list: falls back to in-corpus and fires",
      "novel_embedding" in reasons, f"got reasons={reasons!r}")

# (d) None external → falls back to in-corpus (same as case a).
reasons = reasons_to_escalate(
    command="harmless command", parsed=parsed_hi, local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[in_corpus_centroid_far],
    centroids_external=None,
    rng=random.Random(0),
)
check("None external: falls back to in-corpus and fires",
      "novel_embedding" in reasons, f"got reasons={reasons!r}")

# (e) Both refs say familiar → don't fire.
reasons = reasons_to_escalate(
    command="harmless command", parsed=parsed_hi, local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[high_novelty_embedding],          # in-corpus close
    centroids_external=[external_centroid_near], # external close
    rng=random.Random(0),
)
check("both refs say familiar: no novel_embedding",
      "novel_embedding" not in reasons, f"got reasons={reasons!r}")

# (f) Inverse — external says novel, in-corpus says familiar.
# External wins, so we fire (the analyst-visible "this looks novel vs
# documented adversary catalog even though we've seen it locally"
# case).
reasons = reasons_to_escalate(
    command="harmless command", parsed=parsed_hi, local_failed=False,
    cfg=cloud,
    embedding=high_novelty_embedding,
    centroids=[high_novelty_embedding],          # in-corpus close → score 0
    centroids_external=[in_corpus_centroid_far], # external far → score 1
    rng=random.Random(0),
)
check("external says novel + in-corpus says familiar: fires",
      "novel_embedding" in reasons, f"got reasons={reasons!r}")


# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
