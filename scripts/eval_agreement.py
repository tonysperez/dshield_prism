"""Annotator-agreement scorer for the eval label set (quality-metrics Slice B).

Publishes the *reliability ceiling* of `eval/labels-v1.yaml`: how consistently
the same behavior is labeled. The number bounds how good any downstream metric
(assignment macro-F1, novel P/R) can honestly claim to be — a model at 0.84
against labels that agree 0.80 is at ceiling, and chasing higher is chasing
noise.

Two workflows, one command:

  * **intra-annotator (headline)** — the single operator re-labels a blind
    subset after a delay; pass the original file and the re-label file. Scores
    self-consistency, the only path with near-term data.
  * **inter-annotator** — pass two annotators' files. Identical machinery.

Reports Cohen's κ, PABAK (prevalence-adjusted), and overall + per-label percent
agreement, each with a bootstrap CI, over the annotated *overlap* of the two
files. κ alone misreads on this prevalence-skewed label set (the κ paradox:
high agreement, deflated κ), so PABAK and the per-label breakdown keep the
number honest; κ stays for comparability with the literature.

Diagnostic only: it grades the labels, not the code, so it never fails a build
(exit 0). The one non-zero exit is a usage error — empty overlap or an
unreadable file.

Offline, no ES / LLM / network — the label files are the already-vetted eval
set, so no public-only filter applies.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

# Distinct annotator decisions — must never share a bucket, or a genuine
# disagreement (one says "novel behavior", one says "noise, drop it") would
# score as agreement.
NOVEL = "__novel__"
REJECT = "__reject__"


# ---------------------------------------------------------------------------
# Loading — three-way category (pure Python; no numpy)
# ---------------------------------------------------------------------------
def category_of(block: object) -> str | None:
    """The annotator's decision for one label block, or None if not annotated.

    playbook_label (real, matched) | __novel__ (real, no playbook) |
    __reject__ (not real behavior).
    """
    if not (isinstance(block, dict) and block.get("annotated")):
        return None
    # A present playbook_label IS a real matched behavior — it wins regardless of
    # is_real, so a hand-edited block that dropped is_real is never silently
    # mis-scored as a reject. is_real only disambiguates the no-label case.
    label = block.get("playbook_label")
    if label:
        return label
    return NOVEL if block.get("is_real") else REJECT


def load_categories(path: Path) -> dict[str, str]:
    """`session_id -> category` for every annotated block in a labels YAML."""
    raw = yaml.safe_load(path.read_text()) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} is not a mapping of session_id to label block")
    out: dict[str, str] = {}
    for sid, block in raw.items():
        cat = category_of(block)
        if cat is not None:
            out[sid] = cat
    return out


def overlap_pairs(a: dict[str, str], b: dict[str, str]) -> list[tuple[str, str]]:
    """(cat_a, cat_b) for every session_id annotated in BOTH files, sorted by id
    for determinism."""
    return [(a[sid], b[sid]) for sid in sorted(a.keys() & b.keys())]


# ---------------------------------------------------------------------------
# Metric cores (pure Python) — each maps a pair-list -> scalar (or None)
# ---------------------------------------------------------------------------
def percent_agreement(pairs: list[tuple[str, str]]) -> float | None:
    """Observed agreement `po` = fraction of pairs where both raters match."""
    if not pairs:
        return None
    return sum(1 for x, y in pairs if x == y) / len(pairs)


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Cohen's κ = (po - pe) / (1 - pe). None when empty or single-category
    (pe == 1, κ undefined) — the caller reports PABAK/pct instead."""
    n = len(pairs)
    if n == 0:
        return None
    po = sum(1 for x, y in pairs if x == y) / n
    ca = Counter(x for x, _ in pairs)
    cb = Counter(y for _, y in pairs)
    pe = sum((ca.get(c, 0) / n) * (cb.get(c, 0) / n) for c in ca.keys() | cb.keys())
    if abs(1.0 - pe) < 1e-12:
        return None
    return (po - pe) / (1.0 - pe)


def pabak(pairs: list[tuple[str, str]]) -> float | None:
    """Prevalence-adjusted bias-adjusted kappa = 2·po - 1. Always defined
    (unless empty), so it survives the single-category case κ can't."""
    po = percent_agreement(pairs)
    return None if po is None else 2.0 * po - 1.0


def per_label_agreement(pairs: list[tuple[str, str]]) -> dict[str, dict]:
    """Positive specific agreement per category: 2·n_both / (n_a + n_b)."""
    ca = Counter(x for x, _ in pairs)
    cb = Counter(y for _, y in pairs)
    both = Counter(x for x, y in pairs if x == y)
    out: dict[str, dict] = {}
    for c in sorted(ca.keys() | cb.keys()):
        n_a, n_b, n_both = ca.get(c, 0), cb.get(c, 0), both.get(c, 0)
        denom = n_a + n_b
        out[c] = {
            "n_a": n_a, "n_b": n_b, "n_both": n_both,
            "specific_agreement": (2.0 * n_both / denom) if denom else None,
        }
    return out


def disagreements(pairs: list[tuple[str, str]]) -> list[dict]:
    """Distinct (a, b) mismatches with counts, most frequent first."""
    counts = Counter((x, y) for x, y in pairs if x != y)
    return [{"a": a, "b": b, "count": n}
            for (a, b), n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def evaluate(a: dict[str, str], b: dict[str, str], *, bootstrap: int, seed: int) -> dict:
    pairs = overlap_pairs(a, b)
    kappa = cohen_kappa(pairs)
    report: dict = {
        "n_overlap": len(pairs),
        "n_only_a": len(a.keys() - b.keys()),
        "n_only_b": len(b.keys() - a.keys()),
        "metrics": {
            "percent_agreement": percent_agreement(pairs),
            "cohen_kappa": kappa,
            "pabak": pabak(pairs),
        },
        "kappa_undefined": kappa is None and len(pairs) > 0,
        "per_label_agreement": per_label_agreement(pairs),
        "disagreements": disagreements(pairs),
    }
    report["ci_half_width"] = _bootstrap_cis(pairs, n=bootstrap, seed=seed)
    return report


def _bootstrap_cis(pairs: list[tuple[str, str]], *, n: int, seed: int) -> dict | None:
    """Bootstrap CI half-widths, reusing the deterministic helper from the
    operational gate. Returns None (with a printed hint) when the `[cluster]`
    extra — numpy — isn't installed, so point estimates still print."""
    if not pairs:
        return {"percent_agreement": 0.0, "cohen_kappa": 0.0, "pabak": 0.0}
    try:
        scripts_dir = str(Path(__file__).resolve().parent)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from eval_operational import bootstrap_half_width
    except ImportError:
        print("note: numpy not installed (pip install -e '.[cluster]') — "
              "CIs skipped, point estimates only.", file=sys.stderr)
        return None
    return {
        "percent_agreement": bootstrap_half_width(pairs, percent_agreement, n=n, seed=seed),
        "cohen_kappa": bootstrap_half_width(pairs, cohen_kappa, n=n, seed=seed),
        "pabak": bootstrap_half_width(pairs, pabak, n=n, seed=seed),
    }


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def _fmt(v: float | None, w: int = 8) -> str:
    return f"{'—':>{w}}" if v is None else f"{v:>{w}.4f}"


def render(report: dict) -> list[str]:
    hw = report.get("ci_half_width") or {}
    m = report["metrics"]
    lines = [
        f"  overlap: {report['n_overlap']} sessions "
        f"(annotated only in A: {report['n_only_a']}, only in B: {report['n_only_b']})",
        f"  {'metric':20}{'value':>10}{'±ci':>10}",
    ]
    for name in ("percent_agreement", "cohen_kappa", "pabak"):
        lines.append(f"  {name:20}{_fmt(m[name], 10)}{_fmt(hw.get(name), 10)}")
    if report["kappa_undefined"]:
        lines.append("  (κ undefined — single category in overlap; read PABAK + percent agreement)")
    lines.append("  per-label positive specific agreement:")
    for cat, s in report["per_label_agreement"].items():
        lines.append(f"    {cat:34}{_fmt(s['specific_agreement'], 8)}"
                     f"  (A:{s['n_a']} B:{s['n_b']} both:{s['n_both']})")
    if report["disagreements"]:
        lines.append("  top disagreements (a -> b : count):")
        for d in report["disagreements"][:10]:
            lines.append(f"    {d['a']} -> {d['b']} : {d['count']}")
    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--labels-a", default="eval/labels-v1.yaml",
                    help="first labels YAML (original, or annotator A)")
    ap.add_argument("--labels-b", required=True,
                    help="second labels YAML (delayed re-label, or annotator B)")
    ap.add_argument("--min-overlap", type=int, default=10,
                    help="warn when the annotated overlap is smaller than this")
    ap.add_argument("--bootstrap-n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-json", action="store_true")
    args = ap.parse_args()

    for path in (args.labels_a, args.labels_b):
        if not Path(path).is_file():
            print(f"error: labels file not found: {path}", file=sys.stderr)
            return 1

    try:
        a = load_categories(Path(args.labels_a))
        b = load_categories(Path(args.labels_b))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    report = evaluate(a, b, bootstrap=args.bootstrap_n, seed=args.seed)

    if report["n_overlap"] == 0:
        print("error: no overlapping annotated sessions between the two files.",
              file=sys.stderr)
        return 1
    if report["n_overlap"] < args.min_overlap:
        print(f"warning: overlap {report['n_overlap']} < --min-overlap "
              f"{args.min_overlap}; agreement estimates are unstable.", file=sys.stderr)

    if not args.no_json:
        print(json.dumps(report, indent=2))
    print()
    for line in render(report):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
