#!/usr/bin/env python
"""Item 72 rare-behaviour minting policy (offline).

Covers the novel-pool-only min-cluster-size override and the identity helpers a
synthetic 3-session rare group would use after producing a normal cluster doc.
No Elasticsearch, no LLM, no live corpus reads.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.config import SessionConfig
from enrich.sources.cowrie.sessions import (
    _assign_playbook_id,
    _compute_seed_id,
    _mint_playbook_id,
    _playbook_anchor_doc,
    _playbook_group_centroid,
    _unit_vector,
    effective_novel_pool_min_cluster_size,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASSED.append(name) if cond else FAILED.append((name, detail)))


def _expect_config_error(name: str, fn) -> None:
    try:
        fn()
    except (ValueError, ValidationError):
        PASSED.append(name)
    except Exception as exc:
        FAILED.append((name, f"wrong exception: {type(exc).__name__}: {exc}"))
    else:
        FAILED.append((name, "expected config validation error"))


normal = SessionConfig(cluster_min_cluster_size=5, novel_pool_cluster_min_cluster_size=3)
check(
    "novel-pool-only uses rare floor",
    effective_novel_pool_min_cluster_size(normal, novel_pool_only=True) == 3,
)
check(
    "normal session clustering uses normal floor",
    effective_novel_pool_min_cluster_size(normal, novel_pool_only=False) == 5,
)
disabled_none = SessionConfig(cluster_min_cluster_size=5, novel_pool_cluster_min_cluster_size=None)
disabled_zero = SessionConfig(cluster_min_cluster_size=5, novel_pool_cluster_min_cluster_size=0)
floor_two = SessionConfig(cluster_min_cluster_size=5, novel_pool_cluster_min_cluster_size=2)
check(
    "unset rare floor falls back to normal",
    effective_novel_pool_min_cluster_size(disabled_none, novel_pool_only=True) == 5,
)
check(
    "zero rare floor falls back to normal",
    effective_novel_pool_min_cluster_size(disabled_zero, novel_pool_only=True) == 5,
)
check(
    "floor two is accepted as the smallest rare group",
    effective_novel_pool_min_cluster_size(floor_two, novel_pool_only=True) == 2,
)

_expect_config_error(
    "singleton rare floor is rejected",
    lambda: SessionConfig(cluster_min_cluster_size=5, novel_pool_cluster_min_cluster_size=1),
)
_expect_config_error(
    "rare floor above normal floor is rejected",
    lambda: SessionConfig(cluster_min_cluster_size=5, novel_pool_cluster_min_cluster_size=6),
)
_expect_config_error(
    "normal floor below HDBSCAN minimum is rejected",
    lambda: SessionConfig(cluster_min_cluster_size=1, novel_pool_cluster_min_cluster_size=None),
)
_expect_config_error(
    "fractional rare floor is rejected instead of truncated",
    lambda: SessionConfig(cluster_min_cluster_size=5, novel_pool_cluster_min_cluster_size=2.9),
)
_expect_config_error(
    "fractional normal floor is rejected instead of truncated",
    lambda: SessionConfig(cluster_min_cluster_size=5.9, novel_pool_cluster_min_cluster_size=3),
)

members = ["sid-a", "sid-b", "sid-c"]
seed = _compute_seed_id(members)
centroid = _playbook_group_centroid([
    {"centroid": _unit_vector(np.asarray([1.0, 0.00, 0.0])).tolist(), "size": 1},
    {"centroid": _unit_vector(np.asarray([1.0, 0.01, 0.0])).tolist(), "size": 1},
    {"centroid": _unit_vector(np.asarray([1.0, 0.02, 0.0])).tolist(), "size": 1},
])
fresh_id = _assign_playbook_id(centroid, [], 0.96, seed)
check(
    "synthetic 3-session group mints deterministic spb id",
    fresh_id == _mint_playbook_id(seed),
    fresh_id,
)
doc = _playbook_anchor_doc(fresh_id, centroid, seed, "run-item-72")
check(
    "fresh rare group uses normal anchor doc shape",
    doc["playbook_id"].startswith("spb-")
    and doc["seed_playbook_id"] == seed
    and doc["first_run_id"] == "run-item-72"
    and len(doc["anchor_centroid"]) == len(centroid)
    and "predicate_signature" in doc,
    str(doc),
)

for n in PASSED:
    print(f"  PASS {n}")
for n, d in FAILED:
    print(f"  FAIL {n}: {d}")
print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
sys.exit(1 if FAILED else 0)
