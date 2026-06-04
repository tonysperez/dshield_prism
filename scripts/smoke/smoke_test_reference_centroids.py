"""ROADMAP P1 — Global novelty baseline. Reference-centroid loader behavior.

Verifies `load_reference_centroids` end-to-end against a stub ES:
  - Picks the maximum `reference_generation`.
  - Returns both pure and augmented centroid lists when present.
  - Returns pure-only when augmented is absent (IP-layer shape).
  - Computes `age_days` from `reference_minted_at`.
  - Returns {} on missing index / no ref docs / no generation field.
  - Defensive against ES exceptions.

Also verifies `_validate_reference`:
  - Accepts a fresh ref against matching dims + scalar_weight.
  - Rejects on dim mismatch (pure or augmented).
  - Rejects on missing augmented when caller expects it.
  - Rejects on scalar_weight delta beyond tolerance.

Standalone — no real ES, no pytest.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_reference_centroids.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.clustering import _validate_reference, load_reference_centroids


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


class _StubIndicesClient:
    def __init__(self, *, exists: bool = True) -> None:
        self.exists_val = exists

    def exists(self, *, index: str) -> bool:
        return self.exists_val


class _StubES:
    def __init__(
        self,
        *,
        gen_lookup_hits: list[dict] | None = None,
        fetch_hits: list[dict] | None = None,
        exists: bool = True,
    ) -> None:
        self.indices = _StubIndicesClient(exists=exists)
        self.gen_lookup_hits = gen_lookup_hits or []
        self.fetch_hits = fetch_hits or []
        self.calls: list[dict] = []
        self._n = 0

    def search(self, **kwargs):
        self.calls.append(kwargs)
        self._n += 1
        return {"hits": {"hits": self.gen_lookup_hits if self._n == 1 else self.fetch_hits}}


# -----------------------------------------------------------------------------
# [1] Full payload: pure + augmented, generation picked, age computed.
# -----------------------------------------------------------------------------
print("\n[1] full reference payload (pure + augmented)")
minted = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
es = _StubES(
    gen_lookup_hits=[{"_source": {"reference_generation": 7}}],
    fetch_hits=[
        {"_source": {
            "centroid": [0.1] * 4,
            "centroid_augmented": [0.1] * 8,
            "source_run_id": "run-A",
            "embedding_dims": 4,
            "augmented_dims": 8,
            "scalar_weight": 0.05,
            "reference_minted_at": minted,
        }},
        {"_source": {
            "centroid": [0.2] * 4,
            "centroid_augmented": [0.2] * 8,
            "source_run_id": "run-A",
            "embedding_dims": 4,
            "augmented_dims": 8,
            "scalar_weight": 0.05,
            "reference_minted_at": minted,
        }},
    ],
)
ref = load_reference_centroids(es, "clusters-x")
check("generation == 7", ref.get("generation") == 7, f"got {ref.get('generation')}")
check("2 pure centroids returned", len(ref.get("pure") or []) == 2, f"got {len(ref.get('pure') or [])}")
check("2 augmented centroids returned", len(ref.get("augmented") or []) == 2)
check("embedding_dims == 4", ref.get("embedding_dims") == 4)
check("augmented_dims == 8", ref.get("augmented_dims") == 8)
check("scalar_weight == 0.05", ref.get("scalar_weight") == 0.05)
check("source_run_id == 'run-A'", ref.get("source_run_id") == "run-A")
age = ref.get("age_days")
check("age_days ~ 10", age is not None and 9.9 < age < 10.1, f"got {age}")


# -----------------------------------------------------------------------------
# [2] Pure-only (IP-layer shape): no centroid_augmented field.
# -----------------------------------------------------------------------------
print("\n[2] pure-only reference (IP-layer shape)")
es = _StubES(
    gen_lookup_hits=[{"_source": {"reference_generation": 1}}],
    fetch_hits=[
        {"_source": {
            "centroid": [0.5] * 4,
            "source_run_id": "run-B",
            "embedding_dims": 4,
            "scalar_weight": 0.05,
            "reference_minted_at": (datetime.now(timezone.utc)).isoformat(),
        }},
    ],
)
ref = load_reference_centroids(es, "clusters-y")
check("pure centroids present", ref.get("pure") == [[0.5] * 4])
check("augmented absent (empty list)", ref.get("augmented") == [])


# -----------------------------------------------------------------------------
# [3] Missing index → {}
# -----------------------------------------------------------------------------
print("\n[3] missing index → {}")
es = _StubES(exists=False)
ref = load_reference_centroids(es, "clusters-missing")
check("missing index returns {}", ref == {}, f"got {ref}")


# -----------------------------------------------------------------------------
# [4] No reference docs at all → {}
# -----------------------------------------------------------------------------
print("\n[4] no reference_centroid docs → {}")
es = _StubES(gen_lookup_hits=[], fetch_hits=[])
ref = load_reference_centroids(es, "clusters-noref")
check("no ref docs returns {}", ref == {}, f"got {ref}")


# -----------------------------------------------------------------------------
# [5] Hit without `reference_generation` → {}
# -----------------------------------------------------------------------------
print("\n[5] hit without reference_generation → {}")
es = _StubES(
    gen_lookup_hits=[{"_source": {"something_else": True}}],
    fetch_hits=[{"_source": {"centroid": [0.0]}}],
)
ref = load_reference_centroids(es, "clusters-nogen")
check("missing gen returns {}", ref == {}, f"got {ref}")


# -----------------------------------------------------------------------------
# [6] ES exception → {} (defensive).
# -----------------------------------------------------------------------------
print("\n[6] ES exception → {} (defensive)")
class _BoomES:
    indices = _StubIndicesClient(exists=True)
    def search(self, **kwargs):
        raise RuntimeError("boom")
ref = load_reference_centroids(_BoomES(), "clusters-boom")
check("ES exception returns {}", ref == {}, f"got {ref}")


# -----------------------------------------------------------------------------
# [7] _validate_reference: accept matching ref.
# -----------------------------------------------------------------------------
print("\n[7] _validate_reference accepts matching ref")
ref_good = {
    "pure": [[0.1, 0.2]],
    "augmented": [[0.1, 0.2, 0.3, 0.4]],
    "embedding_dims": 2,
    "augmented_dims": 4,
    "scalar_weight": 0.05,
}
reason = _validate_reference(
    ref_good,
    current_embedding_dims=2,
    current_augmented_dims=4,
    current_scalar_weight=0.05,
    expects_augmented=True,
)
check("matching ref accepted", reason == "", f"got reason={reason!r}")


# -----------------------------------------------------------------------------
# [8] _validate_reference: reject on pure-embedding dim mismatch.
# -----------------------------------------------------------------------------
print("\n[8] _validate_reference rejects embedding_dims mismatch")
reason = _validate_reference(
    {**ref_good, "embedding_dims": 3},
    current_embedding_dims=2,
    current_augmented_dims=4,
    current_scalar_weight=0.05,
    expects_augmented=True,
)
check("dim mismatch rejected", reason == "dim_mismatch_pure", f"got reason={reason!r}")


# -----------------------------------------------------------------------------
# [9] _validate_reference: reject when augmented expected but absent.
# -----------------------------------------------------------------------------
print("\n[9] _validate_reference rejects missing augmented when expected")
reason = _validate_reference(
    {**ref_good, "augmented": [], "augmented_dims": None},
    current_embedding_dims=2,
    current_augmented_dims=4,
    current_scalar_weight=0.05,
    expects_augmented=True,
)
check("missing augmented rejected", reason == "missing_augmented", f"got reason={reason!r}")


# -----------------------------------------------------------------------------
# [10] _validate_reference: reject on augmented_dims mismatch.
# -----------------------------------------------------------------------------
print("\n[10] _validate_reference rejects augmented_dims mismatch")
reason = _validate_reference(
    {**ref_good, "augmented_dims": 5},
    current_embedding_dims=2,
    current_augmented_dims=4,
    current_scalar_weight=0.05,
    expects_augmented=True,
)
check("augmented dim mismatch rejected", reason == "dim_mismatch_augmented", f"got reason={reason!r}")


# -----------------------------------------------------------------------------
# [11] _validate_reference: reject on scalar_weight delta.
# -----------------------------------------------------------------------------
print("\n[11] _validate_reference rejects scalar_weight delta")
reason = _validate_reference(
    {**ref_good, "scalar_weight": 0.10},
    current_embedding_dims=2,
    current_augmented_dims=4,
    current_scalar_weight=0.05,
    expects_augmented=True,
)
check("scalar_weight delta rejected", reason == "scalar_weight_mismatch", f"got reason={reason!r}")


# -----------------------------------------------------------------------------
# [12] _validate_reference: when augmented not expected (scalar_weight==0),
# pure-only ref is accepted even without augmented metadata.
# -----------------------------------------------------------------------------
print("\n[12] _validate_reference accepts pure-only when augmented not expected")
reason = _validate_reference(
    {"pure": [[0.1]], "augmented": [], "embedding_dims": 1, "scalar_weight": 0.0},
    current_embedding_dims=1,
    current_augmented_dims=1,
    current_scalar_weight=0.0,
    expects_augmented=False,
)
check("pure-only accepted when augmented not expected", reason == "", f"got reason={reason!r}")


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
