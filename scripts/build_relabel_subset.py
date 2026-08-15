"""Build a blind re-label subset for an annotator-agreement run.

`eval_agreement.py` needs a second labeling pass over the same sessions.
Producing one by hand over all ~160 blocks is a big ask, and a casually-chosen
subset biases the headline number — so this emits **two** skeleton files with
different jobs:

  * **core** (default 60) — a uniform random draw over every annotated session.
    This is the only file whose agreement number is quotable as *the*
    reliability estimate, because its sample is representative. At n=60 and a
    true agreement near 0.85 the 95% CI half-width is roughly ±0.09 — enough to
    separate "already at the label ceiling" from "real headroom".
  * **supplement** — every session belonging to a category with fewer than
    `--rare-threshold` members, minus whatever core already drew. Rare labels
    are invisible in a 60-session random draw (four of them have n<=3), so
    per-label agreement for them needs its own pass. Score it separately and
    report it as per-label detail — **never pool it into the core number**,
    which would over-weight the hard tail and understate reliability.

Both files are plain `labels.yaml`-schema skeletons with every label field
empty, so nothing from the first pass leaks in. Blocks are written in shuffled
order: walking the file top-to-bottom is already a randomized walk, which
matters because following the original labeling order primes recall of the
original decisions.

Deterministic under `--seed`: same seed, same subsets, same order.

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/build_relabel_subset.py
"""
from __future__ import annotations

import argparse
import datetime
import random
import sys
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from render_eval_set import _EMPTY_LABEL_BLOCK, _write_labels_yaml  # noqa: E402

REJECT = "__reject__"


def category_of(block: dict) -> str | None:
    """The agreement unit for one block: the playbook label, or `__reject__`.
    None when the block isn't annotated (it can't be re-labeled against
    nothing). Mirrors `eval_agreement.category_of`."""
    if not isinstance(block, dict) or not block.get("annotated"):
        return None
    if block.get("is_real") is False:
        return REJECT
    lb = block.get("playbook_label")
    return lb if isinstance(lb, str) and lb else None


def select(categories: dict[str, str], *, core_n: int, rare_threshold: int,
           seed: int) -> tuple[list[str], list[str]]:
    """(core, supplement) session-id lists, both in shuffled order.

    Core is a uniform draw so it stays representative; supplement is
    rule-based (every member of an under-populated category not already in
    core), so it is fully determined once core is drawn."""
    sizes = Counter(categories.values())
    rng = random.Random(seed)
    pool = sorted(categories)  # sort first so the draw doesn't inherit dict order
    core = sorted(rng.sample(pool, min(core_n, len(pool))))
    core_set = set(core)
    supplement = sorted(
        sid for sid, cat in categories.items()
        if sizes[cat] < rare_threshold and sid not in core_set
    )
    rng.shuffle(core)
    rng.shuffle(supplement)
    return core, supplement


def _skeleton(session_ids: list[str]) -> dict:
    """Empty-label blocks in the given order. Every field the first pass filled
    is reset — the second pass must not see a prior decision."""
    return {sid: dict(_EMPTY_LABEL_BLOCK) for sid in session_ids}


def _staleness_note(labels: dict) -> str | None:
    """Warn when the first pass is too recent for a *blind* re-label. A
    self-relabel measures reproducibility only once the specifics are
    forgotten; run too soon it measures memory and reads far too high."""
    dates = []
    for block in labels.values():
        d = block.get("labeled_at") if isinstance(block, dict) else None
        if isinstance(d, str):
            try:
                dates.append(datetime.date.fromisoformat(d))
            except ValueError:
                continue
    if not dates:
        return None
    age = (datetime.date.today() - max(dates)).days
    if age >= 14:
        return None
    return (f"most recent first-pass label is {age} day(s) old — a blind "
            "re-label needs enough delay to forget the specifics (~2 weeks+). "
            "Run now and the number measures recall, not reproducibility.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--labels", type=Path, default=Path("eval/labels.yaml"),
                    help="First-pass labels — read for the session pool and "
                         "category sizes only; never copied into the output.")
    ap.add_argument("--out-core", type=Path, default=Path("eval/labels-relabel-core.yaml"))
    ap.add_argument("--out-supplement", type=Path,
                    default=Path("eval/labels-relabel-supplement.yaml"))
    ap.add_argument("--unlabeled", type=Path, default=Path("eval/sessions.unlabeled.jsonl.gz"),
                    help="Recorded in the output header for the validator command.")
    ap.add_argument("--core-n", type=int, default=60)
    ap.add_argument("--rare-threshold", type=int, default=10,
                    help="Categories with fewer members than this go to the supplement.")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--force", action="store_true",
                    help="Overwrite existing output files. Refused by default — "
                         "they may hold in-progress labeling.")
    args = ap.parse_args()

    if not args.labels.exists():
        print(f"[ERROR] missing labels file: {args.labels}", file=sys.stderr)
        return 1
    raw = yaml.safe_load(args.labels.read_text(encoding="utf-8")) or {}
    categories = {sid: c for sid, b in raw.items()
                  if (c := category_of(b if isinstance(b, dict) else {}))}
    if not categories:
        print(f"[ERROR] no annotated blocks in {args.labels}", file=sys.stderr)
        return 1

    for p in (args.out_core, args.out_supplement):
        if p.exists() and not args.force:
            print(f"[ERROR] {p} exists — refusing to overwrite in-progress "
                  "labeling. Pass --force to replace it.", file=sys.stderr)
            return 1

    core, supplement = select(categories, core_n=args.core_n,
                              rare_threshold=args.rare_threshold, seed=args.seed)
    _write_labels_yaml(args.out_core, _skeleton(core), args.unlabeled)
    _write_labels_yaml(args.out_supplement, _skeleton(supplement), args.unlabeled)

    sizes = Counter(categories.values())
    print(f"pool              : {len(categories)} annotated sessions, "
          f"{len(sizes)} categories")
    print(f"core              : {len(core)} -> {args.out_core}  (uniform draw, seed {args.seed})")
    print(f"supplement        : {len(supplement)} -> {args.out_supplement}  "
          f"(categories with n < {args.rare_threshold})")
    rare = sorted(c for c, n in sizes.items() if n < args.rare_threshold)
    if rare:
        print(f"  rare categories : {', '.join(rare)}")
    print("\nBlind-labeling protocol:")
    print("  1. Do NOT open eval/labels.yaml, the rendered session markdown's")
    print("     rollup playbook_id, or any investigation notes while labeling.")
    print("  2. Walk each output file top-to-bottom — block order is already")
    print("     shuffled, so you won't retrace the original labeling sequence.")
    print("  3. Label against eval/RUBRIC.md v2 only. Set rubric_version: v2.")
    print("  4. Score core FIRST and alone — that is the quotable number:")
    print(f"       scripts/eval_agreement.py --labels-a {args.labels} \\")
    print(f"         --labels-b {args.out_core}")
    print("     Then the supplement separately, read as per-label detail only.")
    note = _staleness_note(raw)
    if note:
        print(f"\n[WARN] {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
