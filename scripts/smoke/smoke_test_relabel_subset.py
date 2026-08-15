"""Smoke test for the blind re-label subset builder.

`scripts/build_relabel_subset.py` emits the two skeleton files an
annotator-agreement run needs. Three properties are load-bearing and easy to
break silently:

  * **No leakage.** Every emitted block must be empty. A first-pass label
    surviving into the second-pass skeleton would make the agreement number
    meaningless (the annotator would be copying, not deciding).
  * **Core is representative; supplement is the rare tail.** The core draw is
    uniform over the whole pool, and the supplement holds exactly the members
    of under-populated categories that core didn't already take. The two are
    disjoint, so pooling them would double-count nothing — but the *core* file
    alone is what may be quoted.
  * **Deterministic.** Same seed reproduces the same subsets and the same
    shuffled order; a different seed does not.

Covers, with a synthetic label set (no ES/LLM/network):

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_relabel_subset.py
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import build_relabel_subset as brs


def _pool() -> dict[str, str]:
    """40 sessions: two big categories (n=15 each), three rare (n=3, n=4, n=3)."""
    cats: dict[str, str] = {}
    for i in range(15):
        cats[f"big_a{i:02d}"] = "host_recon"
    for i in range(15):
        cats[f"big_b{i:02d}"] = "single_command_probe"
    for i in range(3):
        cats[f"rare_a{i}"] = "scp_upload"
    for i in range(4):
        cats[f"rare_b{i}"] = "inband_payload_drop"
    for i in range(3):
        cats[f"rej{i}"] = brs.REJECT
    return cats


def test_category_of() -> None:
    assert brs.category_of({"annotated": True, "is_real": True,
                            "playbook_label": "host_recon"}) == "host_recon"
    assert brs.category_of({"annotated": True, "is_real": False,
                            "playbook_label": None}) == brs.REJECT
    # Not annotated -> not re-labelable, so it never enters the pool.
    assert brs.category_of({"annotated": False, "is_real": True,
                            "playbook_label": "host_recon"}) is None
    assert brs.category_of({}) is None
    print("  ok: category_of maps label / __reject__ / unannotated correctly")


def test_core_and_supplement_are_disjoint_and_sized() -> None:
    cats = _pool()
    core, supp = brs.select(cats, core_n=20, rare_threshold=10, seed=0)
    assert len(core) == 20, len(core)
    assert not (set(core) & set(supp)), set(core) & set(supp)
    # Supplement == every member of a rare category, minus those core took.
    sizes = Counter(cats.values())
    rare = {sid for sid, c in cats.items() if sizes[c] < 10}
    assert set(supp) == rare - set(core), (set(supp), rare - set(core))
    print("  ok: core/supplement disjoint; supplement is exactly the rare tail")


def test_every_rare_category_is_covered() -> None:
    """The point of the supplement: no rare category may be invisible."""
    cats = _pool()
    core, supp = brs.select(cats, core_n=20, rare_threshold=10, seed=0)
    sizes = Counter(cats.values())
    covered = {cats[s] for s in core} | {cats[s] for s in supp}
    for cat, n in sizes.items():
        if n < 10:
            assert cat in covered, cat
    print("  ok: every rare category appears in core or supplement")


def test_deterministic_under_seed() -> None:
    cats = _pool()
    a = brs.select(cats, core_n=20, rare_threshold=10, seed=7)
    b = brs.select(cats, core_n=20, rare_threshold=10, seed=7)
    c = brs.select(cats, core_n=20, rare_threshold=10, seed=8)
    assert a == b, "same seed must reproduce subsets AND order"
    assert a[0] != c[0], "different seed must redraw"
    print("  ok: deterministic under seed, redraws on a different seed")


def test_core_n_clamps_to_pool() -> None:
    cats = _pool()
    core, _ = brs.select(cats, core_n=10_000, rare_threshold=10, seed=0)
    assert len(core) == len(cats), len(core)
    print("  ok: core_n larger than the pool clamps instead of raising")


def test_skeleton_leaks_nothing() -> None:
    skel = brs._skeleton(["s1", "s2"])
    assert list(skel) == ["s1", "s2"], "order must be preserved (shuffled walk)"
    for block in skel.values():
        assert block["annotated"] is False, block
        assert block["playbook_label"] is None, block
        assert block["notes"] == "", block
        assert block["expected_findings"] == [], block
        assert block["annotator"] is None and block["rubric_version"] is None, block
    # Distinct dicts — a shared reference would make one edit affect every block.
    skel["s1"]["notes"] = "x"
    assert skel["s2"]["notes"] == "", "blocks must not share a dict"
    print("  ok: emitted blocks are empty, ordered, and independent")


def test_staleness_note() -> None:
    import datetime
    today = datetime.datetime.now(datetime.UTC).date().isoformat()
    fresh = {"a": {"labeled_at": today}}
    assert brs._staleness_note(fresh), "a same-day first pass must warn"
    old = {"a": {"labeled_at": (datetime.datetime.now(datetime.UTC).date()
                               - datetime.timedelta(days=40)).isoformat()}}
    assert brs._staleness_note(old) is None, "a 40-day-old first pass must not warn"
    assert brs._staleness_note({"a": {"labeled_at": "not-a-date"}}) is None
    assert brs._staleness_note({}) is None
    print("  ok: staleness warning fires only on a too-recent first pass")


def main() -> int:
    print("smoke_test_relabel_subset:")
    test_category_of()
    test_core_and_supplement_are_disjoint_and_sized()
    test_every_rare_category_is_covered()
    test_deterministic_under_seed()
    test_core_n_clamps_to_pool()
    test_skeleton_leaks_nothing()
    test_staleness_note()
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
