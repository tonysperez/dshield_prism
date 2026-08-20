"""Smoke test for E4 (Finding 76) — the mint-time predicate split.

Covers the pure split rule, the re-pin doc builder, and the `_maybe_split_mint`
orchestration against a fake ES. No live ES, no network.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from enrich.config import SessionConfig
from enrich.sources.cowrie.sessions import (
    _maybe_split_mint,
    _repin_anchor_doc,
    split_part_is_coherent,
    split_sids_by_predicate_activity,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


def vec(fires: bool) -> dict[str, bool]:
    return {"multi_arch_targeting": fires, "c2_launch_arg": False, "self_spread": False,
            "appliance_menu_only": False, "host_info_gather": False,
            "key_write_immutability": False, "hetero_target_fallback": False}


# --- the pure split rule ---
print("--- split_sids_by_predicate_activity ---")
mixed = {f"q{i}": vec(False) for i in range(5)} | {f"l{i}": vec(True) for i in range(3)}
got = split_sids_by_predicate_activity(mixed, 3)
check("majority is returned first", got is not None and got[0] == [f"q{i}" for i in range(5)], str(got))
check("minority is the smaller side", got is not None and got[1] == [f"l{i}" for i in range(3)], str(got))

flipped = {f"q{i}": vec(False) for i in range(3)} | {f"l{i}": vec(True) for i in range(9)}
got2 = split_sids_by_predicate_activity(flipped, 3)
check("majority/minority follow size, not quiet/loud",
      got2 is not None and len(got2[0]) == 9 and len(got2[1]) == 3, str(got2))

check("no split when the minority is below the floor",
      split_sids_by_predicate_activity(
          {f"q{i}": vec(False) for i in range(9)} | {"l0": vec(True), "l1": vec(True)}, 3) is None)
check("no split when every session is quiet",
      split_sids_by_predicate_activity({f"q{i}": vec(False) for i in range(9)}, 3) is None)
check("no split when every session is loud",
      split_sids_by_predicate_activity({f"l{i}": vec(True) for i in range(9)}, 3) is None)
check("empty membership never splits", split_sids_by_predicate_activity({}, 3) is None)
check("a nonsensical floor never splits", split_sids_by_predicate_activity(mixed, 0) is None)
check("split is deterministic across dict orderings",
      split_sids_by_predicate_activity(dict(reversed(list(mixed.items()))), 3) == got)

# --- re-pin doc ---
print("\n--- _repin_anchor_doc ---")
existing = {"playbook_id": "spb-A", "anchor_centroid": [1.0, 0.0], "seed_playbook_id": "seed",
            "first_run_id": "r0", "first_seen": "2026-01-01T00:00:00+00:00",
            "predicate_signature": {}, "is_satellite": False}
doc = _repin_anchor_doc(existing, np.array([0.0, 1.0], dtype=np.float32), "r1")
check("identity is preserved", doc["playbook_id"] == "spb-A")
check("first_seen and seed survive the re-pin",
      doc["first_seen"] == existing["first_seen"] and doc["seed_playbook_id"] == "seed")
check("centroid is replaced", doc["anchor_centroid"] == [0.0, 1.0], str(doc["anchor_centroid"]))
check("the prior centroid is kept for reversal",
      doc["repinned_from_centroid"] == [1.0, 0.0], str(doc.get("repinned_from_centroid")))
check("re-pin is attributed to its run", doc["repinned_run_id"] == "r1")
check("repin_count starts at 1", doc["repin_count"] == 1, str(doc["repin_count"]))
check("repin_count increments, so churn is visible",
      _repin_anchor_doc(doc, np.array([1.0, 0.0], dtype=np.float32), "r2")["repin_count"] == 2)
check("the source doc is not mutated", existing["anchor_centroid"] == [1.0, 0.0])


# --- orchestration against a fake ES ---
print("\n--- _maybe_split_mint ---")
QUIET = [f"q{i}" for i in range(6)]
LOUD = [f"l{i}" for i in range(4)]
_S = "dshield.cowrie.enrichment.session"


class FakeES:
    def __init__(self, *, anchor_doc: dict | None, scatter_loud: bool = False):
        self.anchor_doc = anchor_doc
        self.scatter_loud = scatter_loud
        self.indexed: list[tuple[str, dict]] = []

    def search(self, index=None, **kw):
        src = kw.get("_source") or []
        sids = kw["query"]["terms"]["cowrie.session_id"]
        hits = []
        for sid in sids:
            body: dict = {"cowrie": {"session_id": sid}}
            if f"{_S}.embedding" in src:
                if sid.startswith("q"):
                    emb = [1.0, 0.0]
                elif self.scatter_loud:
                    # Mutually distant loud members: their mean is far from all of them,
                    # so none clears tau against the centroid they would be pinned at.
                    emb = [0.0, 1.0] if int(sid[1:]) % 2 else [0.0, -1.0]
                else:
                    emb = [0.0, 1.0]
                body["dshield"] = {"cowrie": {"enrichment": {"session": {
                    "embedding": emb}}}}
            else:
                body["dshield"] = {"cowrie": {"enrichment": {"session": {
                    "command_set": [f"h-{sid}"]}}}}
            hits.append({"_id": sid, "_source": body})
        return {"hits": {"hits": hits}}

    indices = SimpleNamespace(exists=lambda index=None: True)

    def mget(self, index=None, ids=None, **kw):
        docs = []
        for h in (ids or []):
            fires = h.startswith("h-l")
            docs.append({"_id": h, "found": True, "_source": {"dshield": {"cowrie": {
                "enrichment": {"predicates": {"has_self_spread": fires}}}}}})
        return {"docs": docs}

    def get(self, index=None, id=None):
        if self.anchor_doc is None:
            raise KeyError("missing")
        return {"_source": dict(self.anchor_doc)}

    def index(self, index=None, id=None, document=None):
        self.indexed.append((id, document))


def run(*, enabled: bool, anchor_doc: dict | None, sids=None, scatter_loud: bool = False):
    cfg = SimpleNamespace(session=SessionConfig(
        cluster_min_cluster_size=5, novel_pool_cluster_min_cluster_size=3,
        mint_predicate_split=enabled))
    es = FakeES(anchor_doc=anchor_doc, scatter_loud=scatter_loud)
    from collections import Counter
    stats: Counter = Counter()
    anchors = [(np.array([0.7, 0.7], dtype=np.float32), "spb-A")]
    _maybe_split_mint(es, cfg, "sessions", "commands", "anchors", "spb-A",
                      list(sids if sids is not None else QUIET + LOUD),
                      "run-1", anchors, {"spb-A"}, stats)
    return es, stats, anchors


PINNED = {"playbook_id": "spb-A", "anchor_centroid": [0.7, 0.7], "seed_playbook_id": "s",
          "first_run_id": "r0", "first_seen": "2026-01-01T00:00:00+00:00"}

es, stats, anchors = run(enabled=False, anchor_doc=PINNED)
check("feature-off writes nothing", es.indexed == [] and not stats, f"{es.indexed} {dict(stats)}")

es, stats, anchors = run(enabled=True, anchor_doc=PINNED)
check("enabled: two anchor writes (re-pin + minority mint)", len(es.indexed) == 2,
      str([i for i, _ in es.indexed]))
check("the parent is re-pinned, not duplicated",
      es.indexed[0][0] == "spb-A" and "repinned_from_centroid" in es.indexed[0][1],
      str(es.indexed[0][1].keys()))
check("the parent's new centroid is the majority (quiet) side",
      np.allclose(es.indexed[0][1]["anchor_centroid"], [1.0, 0.0]),
      str(es.indexed[0][1]["anchor_centroid"]))
check("the minority mints a NEW id, not the parent's",
      es.indexed[1][0] != "spb-A" and es.indexed[1][0].startswith("spb-"),
      str(es.indexed[1][0]))
check("the minority anchor is the loud side's centroid",
      np.allclose(es.indexed[1][1]["anchor_centroid"], [0.0, 1.0]),
      str(es.indexed[1][1]["anchor_centroid"]))
check("split is counted", stats["split_minted"] == 1, str(dict(stats)))
check("the in-run anchor cache is updated so later groups match the narrowed parent",
      any(aid == "spb-A" and np.allclose(v, [1.0, 0.0]) for v, aid in anchors),
      str([(aid, v.tolist()) for v, aid in anchors]))
check("the minority anchor joins the in-run cache", len(anchors) == 2, str(len(anchors)))

es, stats, _ = run(enabled=True, anchor_doc=None)
check("no pinned parent -> decline the whole split, write nothing",
      es.indexed == [] and stats["split_parent_not_repinned"] == 1, str(dict(stats)))

es, stats, _ = run(enabled=True, anchor_doc={"playbook_id": "spb-A"})
check("parent doc without a centroid -> decline, write nothing",
      es.indexed == [] and stats["split_parent_not_repinned"] == 1, str(dict(stats)))

es, stats, _ = run(enabled=True, anchor_doc=PINNED, sids=QUIET + LOUD[:2])
check("minority below the floor -> no split, no write",
      es.indexed == [] and stats["split_not_applicable"] == 1, str(dict(stats)))

es, stats, _ = run(enabled=True, anchor_doc=PINNED, sids=QUIET)
check("homogeneous group -> no split, no write",
      es.indexed == [] and stats["split_not_applicable"] == 1, str(dict(stats)))

# --- geometric coherence guard (the live anchor that would have been damaged) ---
print("\n--- split_part_is_coherent ---")
unit = np.array([1.0, 0.0], dtype=np.float32)
tight = np.array([[1.0, 0.0]] * 10, dtype=np.float32)
scattered = np.array([[0.86, 0.51]] * 10, dtype=np.float32)  # ~0.86 cos, all below tau
check("a part its own members can reach is coherent",
      split_part_is_coherent(tight, unit, 0.94))
check("a part none of its members can reach is refused",
      not split_part_is_coherent(scattered, unit, 0.94))
half = np.vstack([tight[:5], scattered[:5]])
check("exactly half reachable still passes (majority rule is >=)",
      split_part_is_coherent(half, unit, 0.94))
check("below half is refused",
      not split_part_is_coherent(np.vstack([tight[:4], scattered[:6]]), unit, 0.94))
check("an empty part is never coherent",
      not split_part_is_coherent(np.zeros((0, 2), dtype=np.float32), unit, 0.94))

es, stats, _ = run(enabled=True, anchor_doc=PINNED, scatter_loud=True)
check("an incoherent minority declines the whole split, writes nothing",
      es.indexed == [] and stats["split_incoherent"] == 1, f"{es.indexed} {dict(stats)}")

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
