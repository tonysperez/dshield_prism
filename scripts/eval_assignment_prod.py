"""Production-scale assignment eval — scores the analyst-labelled sessions against the
REAL pinned anchor library (a captured snapshot), the counterpart to
`eval_production_scale.py` for the assignment era.

Where `eval_assignment.py` builds coarse per-label prototypes (tests the algorithm),
this assigns the labelled sessions to the *actual* 155-ish anchors and checks they cover
and separate the analyst behaviours:

  * **assigned_rate** — labelled (all known-behaviour) sessions should mostly assign at
    the production τ; a high novel rate would mean anchor-coverage gaps.
  * **homogeneity** — each anchor a labelled session lands on should be behaviour-pure
    (one analyst label), via sklearn `homogeneity_score(labels, anchor_partition)`.
  * **anchor_label_purity** — fraction of assigned sessions whose nearest anchor's modal
    analyst-label equals their true label (prod-scale classification accuracy).

Needs `eval/anchor-snapshot-v1.jsonl.gz` (capture + commit via
`scripts/capture_anchor_snapshot.py`). Offline once captured. Gate like the others:
metric fails when current < baseline - tolerance.
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # scripts/

from enrich.sources.cowrie.assignment import ASSIGNED, assign_batch

from eval_assignment import _l2, load_labeled


def load_anchor_snapshot(path: Path) -> tuple[list[str], np.ndarray]:
    ids, vecs = [], []
    with gzip.open(path, "rt") as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            c = r.get("anchor_centroid")
            if c:
                ids.append(r["playbook_id"])
                vecs.append(c)
    if not vecs:  # empty snapshot (untagged corpus → no public anchors yet)
        return ids, np.zeros((0, 0), dtype=np.float32)
    return ids, _l2(np.array(vecs, dtype=np.float32))


def score_against_anchors(embs, labels, anchor_ids, anchor_mat, *,
                          tau: float, confident_tau: float) -> dict:
    """Pure: assign labelled sessions to the real anchors; report coverage + anchor
    purity wrt the analyst labels."""
    from sklearn.metrics import homogeneity_score
    res = assign_batch(embs, anchor_mat, anchor_ids, tau=tau, confident_tau=confident_tau)
    n = len(res)
    a = [(i, r) for i, r in enumerate(res) if r.status == ASSIGNED]
    if not a:
        return {"n": n, "n_assigned": 0, "assigned_rate": 0.0, "novel_rate": 1.0,
                "homogeneity": None, "anchor_label_purity": None}
    a_anchor = [r.playbook_id for _i, r in a]
    a_label = [labels[i] for i, _r in a]
    by_anchor: dict[str, list[str]] = defaultdict(list)
    for anc, lb in zip(a_anchor, a_label):
        by_anchor[anc].append(lb)
    modal = {anc: Counter(lbs).most_common(1)[0][0] for anc, lbs in by_anchor.items()}
    purity = sum(1 for anc, lb in zip(a_anchor, a_label) if modal[anc] == lb) / len(a)
    return {
        "n": n, "n_assigned": len(a),
        "assigned_rate": round(len(a) / n, 4),
        "novel_rate": round((n - len(a)) / n, 4),
        "homogeneity": round(float(homogeneity_score(a_label, a_anchor)), 4),
        "anchor_label_purity": round(purity, 4),
    }


_GATED = ("assigned_rate", "homogeneity", "anchor_label_purity")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", default="eval/labels-v1.yaml")
    ap.add_argument("--unlabeled", default="eval/sessions-v1.unlabeled.jsonl")
    ap.add_argument("--snapshot", default="eval/anchor-snapshot-v1.jsonl.gz")
    ap.add_argument("--baseline", default="eval/baseline-assignment-prod.json")
    ap.add_argument("--tau", type=float, default=0.94)
    ap.add_argument("--confident-tau", type=float, default=0.98)
    ap.add_argument("--tolerance", type=float, default=0.05)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--no-json", action="store_true")
    args = ap.parse_args()

    snap = Path(args.snapshot)
    if not snap.exists():
        print(f"Anchor snapshot {snap} not found — capture it first with "
              "scripts/capture_anchor_snapshot.py (operator, against live ES), then "
              "commit it. Skipping.", file=sys.stderr)
        return 0  # not a failure: the snapshot is operator-provided, like prod-scale
    anchor_ids, anchor_mat = load_anchor_snapshot(snap)
    if not anchor_ids:
        print(f"Anchor snapshot {snap} is empty (no public anchors yet — re-tag with "
              "scripts/backfill_classification.py, then re-capture). Skipping.", file=sys.stderr)
        return 0
    labels, embs = load_labeled(Path(args.labels), Path(args.unlabeled))
    report = score_against_anchors(embs, labels, anchor_ids, anchor_mat,
                                   tau=args.tau, confident_tau=args.confident_tau)
    report["n_anchors"] = len(anchor_ids)

    if args.write_baseline:
        Path(args.baseline).write_text(json.dumps(
            {"metrics": {k: report[k] for k in _GATED}, "tolerance": args.tolerance,
             "n_anchors": len(anchor_ids)}, indent=2))
        print(f"wrote baseline {args.baseline}")
        return 0

    if not args.no_json:
        print(json.dumps(report, indent=2))
    base = json.loads(Path(args.baseline).read_text()) if Path(args.baseline).exists() else None
    print(f"\n  {'metric':22}{'baseline':>10}{'current':>10}{'tol':>8}{'delta':>9}  status")
    ok = True
    for m in _GATED:
        cur = report.get(m)
        if base is None:
            print(f"  {m:22}{'(none)':>10}{cur!s:>10}")
            continue
        bl, tol = base["metrics"].get(m), base.get("tolerance", args.tolerance)
        if cur is None or bl is None:
            print(f"  {m:22}{bl!s:>10}{cur!s:>10}  SKIP")
            continue
        passed = cur >= bl - tol
        ok = ok and passed
        print(f"  {m:22}{bl:>10.4f}{cur:>10.4f}{tol:>8.3f}{cur - bl:>+9.4f}  "
              f"{'PASS' if passed else 'FAIL'}")
    print(f"\nGATE: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
