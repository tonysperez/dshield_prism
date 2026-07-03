"""Smoke test for the annotator-agreement pure cores
(`scripts/eval_agreement.py`): category_of, overlap_pairs, percent_agreement,
cohen_kappa, pabak, per_label_agreement, evaluate. No ES, no eval files, no
network.

Guards the load-bearing properties:
  * the three-way category never collapses __novel__ and __reject__, so a
    novel-vs-reject pair is a DISAGREEMENT, not agreement.
  * perfect agreement -> κ=1, PABAK=1, pct=1; chance-level -> κ≈0.
  * single category in the overlap -> κ undefined (None), PABAK still finite.
  * empty overlap -> evaluate reports n_overlap=0 (the main() exit-1 path).
  * bootstrap CI is deterministic (same seed -> identical half-width), when numpy
    is available.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

import tempfile

from eval_agreement import (
    NOVEL,
    REJECT,
    category_of,
    cohen_kappa,
    evaluate,
    load_categories,
    overlap_pairs,
    pabak,
    per_label_agreement,
    percent_agreement,
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


# --- category_of: the three-way rule ----------------------------------------
check("annotated real + label -> the label",
      category_of({"annotated": True, "is_real": True, "playbook_label": "host_recon"})
      == "host_recon")
check("annotated real, no label -> __novel__",
      category_of({"annotated": True, "is_real": True, "playbook_label": None}) == NOVEL)
check("annotated, not real -> __reject__",
      category_of({"annotated": True, "is_real": False, "playbook_label": None}) == REJECT)
check("__novel__ != __reject__ (distinct decisions)", NOVEL != REJECT)
check("not annotated -> None (excluded)",
      category_of({"annotated": False, "is_real": True, "playbook_label": "x"}) is None)
# a present playbook_label wins even if is_real was dropped — never a silent reject
check("label present + is_real missing -> the label (not __reject__)",
      category_of({"annotated": True, "playbook_label": "botnet_loader"}) == "botnet_loader")
check("no label + is_real missing -> __reject__",
      category_of({"annotated": True, "playbook_label": None}) == REJECT)


# --- overlap: only sessions annotated in BOTH -------------------------------
a = {"s1": "host_recon", "s2": NOVEL, "s3": "botnet_loader"}
b = {"s1": "host_recon", "s2": REJECT, "s4": "botnet_loader"}
pairs = overlap_pairs(a, b)
check("overlap is the shared keys only", {p for p in ("s1", "s2")} and len(pairs) == 2, str(pairs))
check("novel-vs-reject counts as DISAGREEMENT",
      percent_agreement(pairs) == 0.5, str(pairs))  # s1 agree, s2 (novel vs reject) disagree


# --- perfect agreement -------------------------------------------------------
perfect = [("x", "x"), ("y", "y"), ("x", "x"), (NOVEL, NOVEL)]
check("perfect: pct == 1.0", percent_agreement(perfect) == 1.0)
check("perfect: κ == 1.0", cohen_kappa(perfect) == 1.0)
check("perfect: PABAK == 1.0", pabak(perfect) == 1.0)


# --- chance-level agreement -> κ ≈ 0 ----------------------------------------
# Two raters each split 50/50 but independently arranged so po == pe.
chance = [("x", "x"), ("x", "y"), ("y", "x"), ("y", "y")]
k = cohen_kappa(chance)
check("chance: κ ≈ 0", k is not None and abs(k) < 1e-9, str(k))


# --- single category -> κ undefined, PABAK finite ---------------------------
mono = [("x", "x"), ("x", "x"), ("x", "x")]
check("single category: κ is None (undefined, no div-by-zero)", cohen_kappa(mono) is None)
check("single category: PABAK == 1.0 (still finite)", pabak(mono) == 1.0)


# --- κ paradox: high agreement, deflated κ (why PABAK is reported) -----------
# 9/10 of one class + a lone minority; raters agree on 9, differ on the last.
skew = [("x", "x")] * 9 + [("x", "y")]
kp, pb = cohen_kappa(skew), pabak(skew)
check("paradox: high pct but κ < PABAK",
      kp is not None and pb is not None and kp < pb, f"κ={kp} PABAK={pb}")


# --- per-label specific agreement -------------------------------------------
pl = per_label_agreement([("x", "x"), ("x", "y"), ("y", "y")])
check("per-label x: 2*both/(n_a+n_b) = 2*1/(2+1)",
      abs(pl["x"]["specific_agreement"] - (2 * 1 / 3)) < 1e-9, str(pl["x"]))


# --- load_categories: non-dict top-level YAML is a clean ValueError ---------
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as _fh:
    _fh.write("- a\n- b\n")  # a list, not a session_id -> block mapping
    _bad = _fh.name
try:
    load_categories(Path(_bad))
    check("non-dict YAML -> ValueError (not a traceback)", False, "no error raised")
except ValueError:
    check("non-dict YAML -> ValueError (not a traceback)", True)
finally:
    Path(_bad).unlink()


# --- empty overlap -> n_overlap 0 (main's exit-1 trigger) -------------------
empty = evaluate({"s1": "x"}, {"s2": "y"}, bootstrap=50, seed=0)
check("empty overlap: n_overlap == 0", empty["n_overlap"] == 0, str(empty["n_overlap"]))


# --- bootstrap determinism (only if numpy is available) ---------------------
r1 = evaluate(a, b, bootstrap=200, seed=7)
r2 = evaluate(a, b, bootstrap=200, seed=7)
if r1["ci_half_width"] is None:
    print("  SKIP  bootstrap determinism (numpy not installed)")
else:
    check("bootstrap deterministic (same seed -> identical CIs)",
          r1["ci_half_width"] == r2["ci_half_width"], str(r1["ci_half_width"]))


print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
