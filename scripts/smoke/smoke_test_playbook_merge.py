"""Smoke test for `merge_clusters_into_playbooks`.

Standalone — no ES, no LLM, no pytest. Runs the pure function with
hand-crafted centroid inputs and asserts the resulting cluster→playbook
mapping. Exits non-zero on the first failure.

Run from the repo root via the console venv (matches the project's other
one-shot scripts):
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.sessions import (
    _compute_seed_id,
    merge_clusters_into_playbooks,
)


def _unit(*components: float) -> list[float]:
    """Return a unit vector pointing in the given direction (any length)."""
    n = math.sqrt(sum(c * c for c in components))
    return [c / n for c in components]


def _almost_eq_dict(a: dict[str, str], b: dict[str, str]) -> bool:
    return a == b


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# -------------------------------------------------------------------------
# Case 1: empty input -> empty dict
# -------------------------------------------------------------------------
print("\n[1] Empty input")
out = merge_clusters_into_playbooks({}, 0.96)
check("empty in → empty out", out == {}, f"got {out!r}")


# -------------------------------------------------------------------------
# Case 2: single cluster -> one playbook group
# -------------------------------------------------------------------------
print("\n[2] Single cluster")
out = merge_clusters_into_playbooks({"cluster_0": _unit(1, 0, 0)}, 0.96)
check("singleton → one pg0", out == {"cluster_0": "pg0"}, f"got {out!r}")


# -------------------------------------------------------------------------
# Case 3: three near-identical centroids -> one playbook
# -------------------------------------------------------------------------
print("\n[3] Three near-identical centroids")
centroids = {
    "cluster_0": _unit(1.0, 0.0, 0.0),
    "cluster_1": _unit(0.999, 0.045, 0.0),     # ~0.999 cos sim with cluster_0
    "cluster_2": _unit(0.998, 0.06, 0.0),      # ~0.998 cos sim with both
}
out = merge_clusters_into_playbooks(centroids, 0.96)
distinct_groups = set(out.values())
check("3 near-identical → 1 playbook", len(distinct_groups) == 1, f"got groups={distinct_groups}, map={out!r}")
check("all mapped to pg0", out == {"cluster_0": "pg0", "cluster_1": "pg0", "cluster_2": "pg0"},
      f"got {out!r}")


# -------------------------------------------------------------------------
# Case 4: 2 near-identical + 1 distant -> two playbooks
# -------------------------------------------------------------------------
print("\n[4] 2 near-identical + 1 distant")
centroids = {
    "cluster_0": _unit(1.0, 0.0, 0.0),
    "cluster_1": _unit(0.999, 0.045, 0.0),
    "cluster_2": _unit(0.0, 1.0, 0.0),
}
out = merge_clusters_into_playbooks(centroids, 0.96)
check("2+1 → 2 playbooks", len(set(out.values())) == 2, f"got {out!r}")
check("cluster_0 == cluster_1 group", out["cluster_0"] == out["cluster_1"], f"got {out!r}")
check("cluster_2 alone", out["cluster_2"] != out["cluster_0"], f"got {out!r}")
# Group numbering rule: groups sorted by lex-smallest member.
# Group {cluster_0, cluster_1} (smallest = cluster_0) → pg0
# Group {cluster_2}             (smallest = cluster_2) → pg1
check("pg0 is the 0/1 group", out["cluster_0"] == "pg0" and out["cluster_2"] == "pg1",
      f"got {out!r}")


# -------------------------------------------------------------------------
# Case 5: transitive chain — complete linkage keeps the worst pair apart.
#   A~B at 0.971, B~C at 0.971, but A~C only 0.887. Under complete
#   linkage the two endpoints can't share a group because their direct
#   pair fails the threshold; only one of the adjacent pairs merges
#   (scipy picks one deterministically), the other endpoint stays alone.
#   This is the desirable behaviour: keep the pairwise-supportable merge,
#   drop only the genuinely sub-threshold endpoint.
# -------------------------------------------------------------------------
print("\n[5] Transitive chain — complete linkage splits worst endpoint apart")
import math as _m
theta = 0.24
A = _unit(_m.cos(0 * theta),       _m.sin(0 * theta),       0.0)
B = _unit(_m.cos(1 * theta),       _m.sin(1 * theta),       0.0)
C = _unit(_m.cos(2 * theta),       _m.sin(2 * theta),       0.0)
centroids = {"cluster_A": A, "cluster_B": B, "cluster_C": C}
out = merge_clusters_into_playbooks(centroids, 0.96)
groups = set(out.values())
check(
    "transitive chain → 2 playbooks (worst endpoint isolated)",
    len(groups) == 2,
    f"got {out!r}",
)
# A and C are the endpoints (sim 0.887 < threshold); they must NOT share
# a playbook regardless of which adjacent pair scipy fused first.
check(
    "endpoints A and C are never in the same playbook",
    out["cluster_A"] != out["cluster_C"],
    f"got {out!r}",
)


# -------------------------------------------------------------------------
# Case 5b: complete-linkage preserves tight groups.
#   A, B, C all near (1, 0, 0). Pairwise sims all comfortably above the
#   threshold. Merging should not be inhibited.
# -------------------------------------------------------------------------
print("\n[5b] Tight cluster — guard does not break legitimate merges")
A = _unit(1.0, 0.02, 0.0)
B = _unit(1.0, 0.0,  0.0)
C = _unit(1.0, -0.02, 0.0)
centroids = {"cluster_A": A, "cluster_B": B, "cluster_C": C}
out = merge_clusters_into_playbooks(centroids, 0.96)
check(
    "tight A/B/C (all pairwise ≥ 0.999) → 1 playbook",
    len(set(out.values())) == 1,
    f"got {out!r}",
)


# -------------------------------------------------------------------------
# Case 5c: mixed — one tight subgroup + one chain. The tight subgroup
# survives; the chain is split. Renumbering stays deterministic.
# -------------------------------------------------------------------------
print("\n[5c] Mixed: tight group survives; chain endpoints stay apart")
tight1 = _unit(1.0, 0.02, 0.0)
tight2 = _unit(1.0, 0.0,  0.0)
chainA = _unit(_m.cos(0.0 * 0.24),  _m.sin(0.0 * 0.24),  0.0)
chainB = _unit(_m.cos(1.0 * 0.24),  _m.sin(1.0 * 0.24),  0.0)
chainC = _unit(_m.cos(2.0 * 0.24),  _m.sin(2.0 * 0.24),  0.0)
# Use a fourth dimension to keep the tight pair away from the chain.
tight1.append(1.0); tight1 = _unit(*tight1)
tight2.append(1.0); tight2 = _unit(*tight2)
chainA.append(0.0); chainB.append(0.0); chainC.append(0.0)
centroids = {
    "cluster_chainA": chainA,
    "cluster_chainB": chainB,
    "cluster_chainC": chainC,
    "cluster_tight1": tight1,
    "cluster_tight2": tight2,
}
out = merge_clusters_into_playbooks(centroids, 0.96)
# tight pair → same playbook.
check(
    "tight pair stays merged",
    out["cluster_tight1"] == out["cluster_tight2"],
    f"got {out!r}",
)
# Chain endpoints A and C (sim 0.887 < threshold) must NOT share a
# playbook. One adjacent pair (A-B or B-C, picked deterministically by
# scipy) may merge.
check(
    "chain endpoints A and C are not in the same playbook",
    out["cluster_chainA"] != out["cluster_chainC"],
    f"got {out!r}",
)
check(
    "tight pair does not absorb any chain member",
    out["cluster_tight1"] not in (out["cluster_chainA"],
                                  out["cluster_chainB"],
                                  out["cluster_chainC"]),
    f"got {out!r}",
)
check(
    "total: 1 tight group + 2 chain groups = 3 playbooks",
    len(set(out.values())) == 3,
    f"got {out!r}",
)


# -------------------------------------------------------------------------
# Case 5d: live-corpus regression — a tight clique survives a weak-edge
# bridge that single-linkage would have chained in.
#
# Fingerprint: six unit vectors mutually within ≈0.99 cosine (the
# `cluster_26..31` SSH-spray clique that the old single-linkage + guard
# code shattered into six singletons), plus two "bridge" vectors that
# sit at ≈0.97 to one clique member but well below 0.93 to the rest.
# Under single-linkage they'd pull the clique into a 8-member group that
# the post-validation guard then rejects whole-cloth. Under complete-
# linkage the clique merges and the two bridges stay separate.
# -------------------------------------------------------------------------
print("\n[5d] Tight clique survives weak chain bridge (live-corpus regression)")
# Six clique members all near (1, 0, 0): pairwise cosine ≥ 0.995. This is
# the SSH-spray clique fingerprint that the old single-linkage + guard code
# shattered into six singletons on the live corpus.
clique = [_unit(1.0, eps, 0.0) for eps in (0.0, 0.02, 0.04, 0.06, 0.08, 0.10)]
# A "bridge" centroid at sim ≈ 0.963 to clique[0] but only ≈ 0.958 to
# clique[5]. Single-linkage would pick the edge to clique[0] and chain
# the bridge into the clique; complete-linkage refuses because the worst
# bridge↔clique pair is below threshold.
bridge_close = _unit(1.0, 0.0, 0.28)
# A second, fully-unrelated centroid in an orthogonal subspace — should
# never participate in any merge.
bridge_far = _unit(0.0, 0.0, 1.0)
centroids = {
    "cluster_c0": clique[0], "cluster_c1": clique[1], "cluster_c2": clique[2],
    "cluster_c3": clique[3], "cluster_c4": clique[4], "cluster_c5": clique[5],
    "cluster_z_bridge_close": bridge_close,
    "cluster_z_bridge_far":   bridge_far,
}
out = merge_clusters_into_playbooks(centroids, 0.96)
clique_pids = {out[f"cluster_c{i}"] for i in range(6)}
check(
    "six clique members share one playbook",
    len(clique_pids) == 1,
    f"got clique_pids={clique_pids}, full map={out!r}",
)
bridge_close_pid = out["cluster_z_bridge_close"]
bridge_far_pid   = out["cluster_z_bridge_far"]
check(
    "borderline bridge does NOT fold into the clique",
    bridge_close_pid not in clique_pids,
    f"clique={clique_pids}, bridge_close={bridge_close_pid}",
)
check(
    "orthogonal bridge stays its own playbook",
    bridge_far_pid not in clique_pids and bridge_far_pid != bridge_close_pid,
    f"got {out!r}",
)
check(
    "total: 1 clique group + 2 bridge singletons = 3 playbooks",
    len(set(out.values())) == 3,
    f"got {out!r}",
)


# -------------------------------------------------------------------------
# Case 6: threshold = 1.0 → only literal-duplicate centroids merge
# -------------------------------------------------------------------------
print("\n[6] threshold=1.0")
centroids = {
    "cluster_0": _unit(1.0, 0.0, 0.0),
    "cluster_1": _unit(1.0, 0.0, 0.0),         # identical
    "cluster_2": _unit(0.999, 0.045, 0.0),     # very close but not identical
}
out = merge_clusters_into_playbooks(centroids, 1.0)
# cluster_0 and cluster_1 should merge (sim=1.0 exactly); cluster_2 stays separate.
groups = set(out.values())
check("τ=1.0: 2 groups", len(groups) == 2, f"got {out!r}")
check("τ=1.0: 0+1 merged", out["cluster_0"] == out["cluster_1"], f"got {out!r}")
check("τ=1.0: 2 alone",     out["cluster_2"] != out["cluster_0"], f"got {out!r}")


# -------------------------------------------------------------------------
# Case 7: determinism — same input twice → same output
# -------------------------------------------------------------------------
print("\n[7] Determinism")
import random
rng = random.Random(42)
n = 30
dim = 8
# Some random unit vectors with a few duplicates to force merging.
centroids = {}
for i in range(n):
    if i in (5, 6, 15):
        # Duplicate one of the earlier ones to ensure merges happen.
        src = centroids[f"cluster_{i - 1:02d}"]
        centroids[f"cluster_{i:02d}"] = list(src)
    else:
        v = [rng.gauss(0, 1) for _ in range(dim)]
        nv = math.sqrt(sum(c * c for c in v))
        centroids[f"cluster_{i:02d}"] = [c / nv for c in v]

out1 = merge_clusters_into_playbooks(centroids, 0.96)
out2 = merge_clusters_into_playbooks(centroids, 0.96)
check("same input twice → same map", out1 == out2, f"diff: {set(out1.items()) ^ set(out2.items())!r}")

# Also: shuffling input dict order MUST NOT change the output (dict
# iteration order shouldn't leak in).
shuffled_keys = list(centroids.keys())
rng.shuffle(shuffled_keys)
shuffled = {k: centroids[k] for k in shuffled_keys}
out3 = merge_clusters_into_playbooks(shuffled, 0.96)
check("shuffled input → same map", out1 == out3, f"diff: {set(out1.items()) ^ set(out3.items())!r}")


# -------------------------------------------------------------------------
# Case 8: membership-seed helper (sescl-<16hex>) — internal seed for the
# cosine-anchor assignment in src/enrich/sources/cowrie/sessions.py.
# Stable across runs when membership matches; sensitive to membership
# changes. Note: this seed is NOT the public playbook_id (which is
# spb-<16hex>, cosine-anchored); it's only the input to a fresh-mint
# when no anchor matches.
# -------------------------------------------------------------------------
print("\n[8] Membership seed is content-addressed and stable")
pid1 = _compute_seed_id(["a1", "b2", "c3"])
check("seed format: sescl- + 16 hex",
      pid1.startswith("sescl-") and len(pid1) == len("sescl-") + 16
      and all(ch in "0123456789abcdef" for ch in pid1[len("sescl-"):]),
      f"got {pid1!r}")

pid2 = _compute_seed_id(["c3", "a1", "b2"])
pid3 = _compute_seed_id(["a1", "b2", "c3", "a1"])
check("same membership → same seed (order-insensitive)", pid1 == pid2,
      f"{pid1!r} != {pid2!r}")
check("same membership → same seed (dedup)", pid1 == pid3,
      f"{pid1!r} != {pid3!r}")

pid_superset = _compute_seed_id(["a1", "b2", "c3", "d4"])
pid_subset   = _compute_seed_id(["a1", "b2"])
pid_disjoint = _compute_seed_id(["x9", "y8", "z7"])
check("superset → different seed", pid_superset != pid1, f"got {pid_superset!r}")
check("subset → different seed",   pid_subset   != pid1, f"got {pid_subset!r}")
check("disjoint → different seed", pid_disjoint != pid1, f"got {pid_disjoint!r}")

try:
    _compute_seed_id([])
    check("empty input raises", False, "no exception raised")
except ValueError:
    check("empty input raises", True)

import importlib
mod = importlib.import_module("enrich.sources.cowrie.sessions")
check("module-reloaded seed matches", mod._compute_seed_id(["a1", "b2", "c3"]) == pid1)


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
