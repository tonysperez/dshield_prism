"""G0.1 — cross-arm clustering comparison.

Every Phase-G commit asks the same question: does an alternative
representation (Arm B bag-of-command-clusters, Arm C deterministic
fingerprint) produce a *different* partition than the production baseline,
and are the differences real? This harness measures the "different"
half — cross-arm ARI/NMI between two clustering runs over the same corpus,
plus a bounded **disagreement manifest** (the sessions the two arms place
differently) that the F2.0 inspect harness renders for the analyst
go/no-go (G4).

Low cross-arm ARI is *interesting*, not bad: it means the arm sees
structure the baseline doesn't. ARI ≈ 1.0 means the arm is effectively the
baseline — no signal, G nulls there (G3 stop condition).

Inputs are two run JSONs from ``eval_production_scale.py --dump-assignments``
(each carries a full-corpus ``{session_id: cluster_id}`` map). The
disagreement set is *baseline-anchored*: for each baseline cluster, the
arm cluster most of its members landed in is the "agreeing" cell; members
the arm placed elsewhere are disagreements, grouped by ``(base, arm)`` cell
and capped to ``--top-k`` sessions per cell so the output stays bounded.

Read-only. Run from the repo root via the console venv:
    console/.venv/bin/python scripts/compare_clusterings.py \\
      eval/results/prod-scale-BASE.json eval/results/cluster-bag-prod-ARM.json
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score


def _load_assignments(path: Path) -> dict[str, int]:
    rec = json.loads(path.read_text(encoding="utf-8"))
    a = rec.get("assignments")
    if not a:
        raise SystemExit(
            f"{path} has no `assignments` block — re-run the producing script "
            "with --dump-assignments (eval_production_scale.py) so the full "
            "{session_id: cluster_id} map is in the JSON."
        )
    return {str(k): int(v) for k, v in a.items()}


def disagreement_sessions(
    base: dict[str, int], arm: dict[str, int],
) -> list[tuple[str, int, int]]:
    """Baseline-anchored disagreements over the common session_ids: each
    ``(session_id, base_cluster, arm_cluster)`` where the arm placed the
    session outside its base cluster's *dominant* arm cell (where most of
    its base-cluster-mates went). Shared by ``compare`` + the inspect
    harness's ``--compare`` render."""
    common = sorted(set(base) & set(arm))
    members: dict[int, list[str]] = defaultdict(list)
    for s in common:
        members[base[s]].append(s)
    dominant_arm = {
        bc: Counter(arm[s] for s in sids).most_common(1)[0][0]
        for bc, sids in members.items()
    }
    return [
        (s, base[s], arm[s]) for s in common if arm[s] != dominant_arm[base[s]]
    ]


def compare(base: dict[str, int], arm: dict[str, int], top_k: int) -> dict:
    common = sorted(set(base) & set(arm))
    if not common:
        raise SystemExit("no overlapping session_ids between the two runs")
    lb = [base[s] for s in common]
    la = [arm[s] for s in common]

    cells: dict[tuple[int, int], list[str]] = defaultdict(list)
    for s, bc, ac in disagreement_sessions(base, arm):
        cells[(bc, ac)].append(s)
    n_disagree = sum(len(v) for v in cells.values())

    cell_rows = [
        {
            "base_cluster": bc,
            "arm_cluster": ac,
            "n_sessions": len(sids),
            "sample_session_ids": sids[:top_k],
        }
        for (bc, ac), sids in sorted(cells.items(), key=lambda kv: -len(kv[1]))
    ]

    return {
        "n_common_sessions": len(common),
        "n_clusters_base": len({c for c in lb if c >= 0}),
        "n_clusters_arm": len({c for c in la if c >= 0}),
        "cross_arm_ari": round(float(adjusted_rand_score(lb, la)), 4),
        "cross_arm_nmi": round(float(normalized_mutual_info_score(lb, la)), 4),
        "n_disagreements": n_disagree,
        "disagreement_rate": round(n_disagree / len(common), 4),
        "disagreement_cells": cell_rows,
    }


def _render(res: dict, base_label: str, arm_label: str) -> str:
    out = [f"# Cross-arm clustering comparison — {base_label} vs {arm_label}", ""]
    out.append(f"_Captured {datetime.now(UTC).isoformat()}_")
    out.append("")
    out.append(f"- **Common sessions:** {res['n_common_sessions']}")
    out.append(f"- **Clusters:** base {res['n_clusters_base']} · arm {res['n_clusters_arm']}")
    out.append(f"- **Cross-arm ARI:** {res['cross_arm_ari']}  ·  **NMI:** {res['cross_arm_nmi']}")
    out.append(f"- **Disagreements:** {res['n_disagreements']} "
               f"({res['disagreement_rate']:.1%} of common sessions)")
    out.append("")
    out.append("> ARI ≈ 1.0 → arm == baseline (no signal, G nulls). Lower ARI → "
               "the arm sees different structure; whether it's *better* is the "
               "G4 analyst call over the disagreement cells below.")
    out.append("")
    if res["disagreement_cells"]:
        out.append("Disagreement cells (base cluster → arm cluster), largest first:")
        out.append("")
        out.append("| base_cluster | arm_cluster | n_sessions | sample session_ids |")
        out.append("|---:|---:|---:|---|")
        for c in res["disagreement_cells"]:
            sids = ", ".join(f"`{s}`" for s in c["sample_session_ids"])
            out.append(f"| {c['base_cluster']} | {c['arm_cluster']} | "
                       f"{c['n_sessions']} | {sids} |")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("base_json", type=Path, help="baseline run JSON (with assignments)")
    ap.add_argument("arm_json", type=Path, help="arm run JSON (with assignments)")
    ap.add_argument("--base-label", default="baseline")
    ap.add_argument("--arm-label", default="arm")
    ap.add_argument("--top-k", type=int, default=8,
                    help="Max sample session_ids per (base, arm) disagreement cell.")
    ap.add_argument("--output-dir", type=Path, default=Path("eval/results"))
    ap.add_argument("--no-md", action="store_true")
    args = ap.parse_args()

    base = _load_assignments(args.base_json)
    arm = _load_assignments(args.arm_json)
    res = compare(base, arm, args.top_k)
    res.update({
        "base_json": str(args.base_json), "arm_json": str(args.arm_json),
        "base_label": args.base_label, "arm_label": args.arm_label,
        "generated_at": datetime.now(UTC).isoformat(),
    })
    md = _render(res, args.base_label, args.arm_label)
    print(md)

    if not args.no_md:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"clustering-compare-{args.base_label}-vs-{args.arm_label}-{ts}"
        (args.output_dir / f"{stem}.md").write_text(md, encoding="utf-8")
        (args.output_dir / f"{stem}.json").write_text(
            json.dumps(res, indent=2), encoding="utf-8")
        print(f"\nwrote {args.output_dir / stem}.{{md,json}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
