"""Annotator-agreement scorer for the eval label set (quality-metrics Slice B).

Publishes the *reliability ceiling* of `eval/labels.yaml`: how consistently
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


def _expected_findings_of(block: object) -> set[str] | None:
    """The analyst's `expected_findings` set for one block, or None if the
    block isn't annotated / doesn't carry the field."""
    if not (isinstance(block, dict) and block.get("annotated")):
        return None
    ef = block.get("expected_findings")
    return set(ef) if isinstance(ef, list) else None


def load_expected_findings(path: Path) -> dict[str, set[str]]:
    """`session_id -> {finding_kind, ...}` for every annotated block that
    carries `expected_findings` (CAP-5)."""
    raw = yaml.safe_load(path.read_text()) or {}
    out: dict[str, set[str]] = {}
    for sid, block in raw.items():
        ef = _expected_findings_of(block)
        if ef is not None:
            out[sid] = ef
    return out


def expected_findings_precision_recall(a: dict[str, set[str]], b: dict[str, set[str]]) -> dict:
    """CAP-5 — the `expected_findings` axis was inert (recorded, never scored).
    Treats A as reference and B as the comparison pass, micro-averaged over
    every (session, finding_kind) pair in the overlap. Diagnostic only: this
    scores *labeling* consistency, not the findings pipeline against ES, so it
    stays offline and never gates."""
    overlap = sorted(a.keys() & b.keys())
    if not overlap:
        return {"n_overlap": 0, "precision": None, "recall": None, "tp": 0, "fp": 0, "fn": 0}
    tp = fp = fn = 0
    for sid in overlap:
        ref, cmp_ = a[sid], b[sid]
        tp += len(ref & cmp_)
        fp += len(cmp_ - ref)
        fn += len(ref - cmp_)
    return {
        "n_overlap": len(overlap),
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "recall": tp / (tp + fn) if (tp + fn) else None,
        "tp": tp, "fp": fp, "fn": fn,
    }


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
# Vocabulary alignment — separates renaming from disagreement
# ---------------------------------------------------------------------------
def _best_matching(cost: dict[tuple[str, str], int],
                   rows: list[str], cols: list[str]) -> list[tuple[str, str]]:
    """Max-weight 1:1 matching over `rows` x `cols`. Exact via scipy when the
    `[cluster]` extra is installed; otherwise a greedy fallback (take the
    largest remaining cell, strike its row and column). Greedy is not
    guaranteed optimal, so it can only *understate* the recovered agreement —
    the metric stays conservative either way."""
    if not rows or not cols:
        return []
    try:
        import numpy as np
        from scipy.optimize import linear_sum_assignment
    except ImportError:
        out, used_r, used_c = [], set(), set()
        for (r, c), n in sorted(cost.items(), key=lambda kv: (-kv[1], kv[0])):
            if n <= 0 or r in used_r or c in used_c:
                continue
            used_r.add(r); used_c.add(c); out.append((r, c))
        return out
    M = np.zeros((len(rows), len(cols)), dtype=float)
    for i, r in enumerate(rows):
        for j, c in enumerate(cols):
            M[i, j] = cost.get((r, c), 0)
    ri, ci = linear_sum_assignment(-M)
    return [(rows[i], cols[j]) for i, j in zip(ri, ci) if M[i, j] > 0]


def vocabulary_alignment(pairs: list[tuple[str, str]]) -> dict:
    """Diagnostic separating *label-vocabulary drift* from real disagreement.

    `eval_agreement.py` compares label strings, so when two annotators name the
    same behavior differently the pair scores as a total mismatch. This finds
    the best 1:1 renaming and reports agreement under it.

    A category present in **both** vocabularies is locked to itself: both
    annotators knew the term and chose differently, which is genuine
    disagreement, not a rename. Only one-sided categories are candidates for
    matching. So `aligned_percent_agreement - percent_agreement` is an upper
    bound on how much of the raw disagreement is naming, and the residual is
    behavioral.
    """
    if not pairs:
        return {"aligned_percent_agreement": None, "alignment": [],
                "n_vocab_a": 0, "n_vocab_b": 0, "n_vocab_shared": 0,
                "vocab_only_a": [], "vocab_only_b": []}
    va = {x for x, _ in pairs}
    vb = {y for _, y in pairs}
    shared = va & vb
    only_a, only_b = sorted(va - vb), sorted(vb - va)
    counts = Counter(pairs)
    matched = _best_matching({k: v for k, v in counts.items()
                              if k[0] in set(only_a) and k[1] in set(only_b)},
                             only_a, only_b)
    mapping = {a: a for a in shared}
    mapping.update(dict(matched))
    agreed = sum(n for (x, y), n in counts.items() if mapping.get(x) == y)
    return {
        "aligned_percent_agreement": agreed / len(pairs),
        "alignment": [{"a": a, "b": b, "count": counts.get((a, b), 0)}
                      for a, b in sorted(matched)],
        "n_vocab_a": len(va), "n_vocab_b": len(vb), "n_vocab_shared": len(shared),
        "vocab_only_a": only_a, "vocab_only_b": only_b,
    }


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
        "vocabulary_alignment": vocabulary_alignment(pairs),
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
    va = report.get("vocabulary_alignment") or {}
    if va.get("aligned_percent_agreement") is not None:
        raw = m["percent_agreement"] or 0.0
        aligned = va["aligned_percent_agreement"]
        lines.append(
            f"  vocabulary: A={va['n_vocab_a']} B={va['n_vocab_b']} "
            f"shared={va['n_vocab_shared']} categories")
        lines.append(
            f"  {'aligned_agreement':20}{_fmt(aligned, 10)}"
            f"{'':>10}  (+{aligned - raw:.4f} vs raw = naming, not disagreement)")
        if va["alignment"]:
            lines.append("  1:1 renames recovered (a == b):")
            for r in va["alignment"]:
                lines.append(f"    {r['a']} == {r['b']} : {r['count']}")
        if va["vocab_only_a"] or va["vocab_only_b"]:
            lines.append(f"    unmatched in A: {', '.join(va['vocab_only_a']) or '—'}")
            lines.append(f"    unmatched in B: {', '.join(va['vocab_only_b']) or '—'}")
    lines.append("  per-label positive specific agreement:")
    for cat, s in report["per_label_agreement"].items():
        lines.append(f"    {cat:34}{_fmt(s['specific_agreement'], 8)}"
                     f"  (A:{s['n_a']} B:{s['n_b']} both:{s['n_both']})")
    if report["disagreements"]:
        lines.append("  top disagreements (a -> b : count):")
        for d in report["disagreements"][:10]:
            lines.append(f"    {d['a']} -> {d['b']} : {d['count']}")
    ef = report.get("expected_findings_diagnostic")
    if ef and ef["n_overlap"]:
        lines.append(
            "  expected_findings diagnostic (A=reference, B=comparison; "
            "never gates):"
        )
        lines.append(
            f"    overlap:{ef['n_overlap']}  precision:{_fmt(ef['precision'], 6)}"
            f"  recall:{_fmt(ef['recall'], 6)}"
            f"  (tp:{ef['tp']} fp:{ef['fp']} fn:{ef['fn']})"
        )
    return lines


# ---------------------------------------------------------------------------
# Baseline (CAP-3) — diagnostic snapshot only: no tolerance/direction/gating
# fields, unlike eval_operational's baseline shape. Never read to fail a
# build; `render_baseline_diff` is informational.
# ---------------------------------------------------------------------------
def build_baseline(report: dict, *, sources: dict | None = None) -> dict:
    """Diagnostic snapshot. `sources` records WHICH pair produced it — without
    that, a bare agreement number is uninterpretable: intra-annotator (same
    person, delayed) and inter-annotator (two annotators, one possibly an LLM)
    answer different questions, and a number captured under one rubric version
    says nothing about another."""
    out: dict = {
        "n_overlap": report["n_overlap"],
        "metrics": report["metrics"],
        "captured_from": "eval_agreement.py --write-baseline",
    }
    if sources:
        out["sources"] = sources
    va = report.get("vocabulary_alignment") or {}
    if va.get("aligned_percent_agreement") is not None:
        out["vocabulary"] = {
            "n_vocab_a": va["n_vocab_a"], "n_vocab_b": va["n_vocab_b"],
            "n_vocab_shared": va["n_vocab_shared"],
            "aligned_percent_agreement": va["aligned_percent_agreement"],
        }
    return out


def _provenance(path: Path) -> dict:
    """Annotator + rubric version actually present in a labels file, so the
    baseline records what produced it rather than what someone intended."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {"path": str(path)}
    ann: Counter = Counter()
    rub: Counter = Counter()
    for block in raw.values():
        if isinstance(block, dict) and block.get("annotated"):
            ann[block.get("annotator")] += 1
            rub[block.get("rubric_version")] += 1
    return {
        "path": str(path),
        "annotators": {str(k): v for k, v in ann.most_common()},
        "rubric_versions": {str(k): v for k, v in rub.most_common()},
    }


def render_baseline_diff(report: dict, baseline: dict) -> list[str]:
    lines = ["  vs committed baseline (diagnostic only — never gates):"]
    bm = baseline.get("metrics", {})
    m = report["metrics"]
    lines.append(f"  {'metric':20}{'baseline':>10}{'current':>10}{'delta':>10}")
    for name in ("percent_agreement", "cohen_kappa", "pabak"):
        cur, bl = m.get(name), bm.get(name)
        delta = None if cur is None or bl is None else cur - bl
        lines.append(f"  {name:20}{_fmt(bl, 10)}{_fmt(cur, 10)}{_fmt(delta, 10)}")
    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--labels-a", default="eval/labels.yaml",
                    help="first labels YAML (original, or annotator A)")
    ap.add_argument("--labels-b", required=True,
                    help="second labels YAML (delayed re-label, or annotator B)")
    ap.add_argument("--min-overlap", type=int, default=10,
                    help="warn when the annotated overlap is smaller than this")
    ap.add_argument("--bootstrap-n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--baseline", default="eval/baseline-agreement.json",
                    help="reliability baseline JSON to write, or diff current against")
    ap.add_argument("--write-baseline", action="store_true",
                    help="write --baseline from this run's point estimates and exit")
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
    ef_a = load_expected_findings(Path(args.labels_a))
    ef_b = load_expected_findings(Path(args.labels_b))
    report["expected_findings_diagnostic"] = expected_findings_precision_recall(ef_a, ef_b)

    if report["n_overlap"] == 0:
        print("error: no overlapping annotated sessions between the two files.",
              file=sys.stderr)
        return 1
    if report["n_overlap"] < args.min_overlap:
        print(f"warning: overlap {report['n_overlap']} < --min-overlap "
              f"{args.min_overlap}; agreement estimates are unstable.", file=sys.stderr)

    if args.write_baseline:
        baseline_path = Path(args.baseline)
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        sources = {"labels_a": _provenance(Path(args.labels_a)),
                   "labels_b": _provenance(Path(args.labels_b))}
        baseline_path.write_text(
            json.dumps(build_baseline(report, sources=sources), indent=2) + "\n")
        print(f"wrote baseline {args.baseline}")
        return 0

    if not args.no_json:
        print(json.dumps(report, indent=2))
    print()
    for line in render(report):
        print(line)
    if Path(args.baseline).is_file():
        baseline = json.loads(Path(args.baseline).read_text())
        print()
        for line in render_baseline_diff(report, baseline):
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
