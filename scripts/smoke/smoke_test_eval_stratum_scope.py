"""Smoke test for the two-stratum scoping in `scripts/eval_operational.py`.

`eval/labels.yaml` mixes the original variety-first draw with rows added by a targeted
pass. Label-weighted metrics use everything; session-weighted ones must scope to the
variety-first rows or they report a deliberate over-sample as a system change. No ES.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/

from eval_operational import evaluate, variety_first_mask

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  ({detail})")


print("--- variety_first_mask ---")
check("an all-original set scopes to everything",
      variety_first_mask([None, None, None]) == [0, 1, 2])
check("targeted rows are excluded",
      variety_first_mask([None, "structural", None, "random"]) == [0, 2])
check("the empty string counts as original, not a channel",
      variety_first_mask([None, "", "anchor"]) == [0, 1])
check("an all-targeted set falls back to every row rather than an empty scope",
      variety_first_mask(["structural", "random"]) == [0, 1])
check("an empty set is empty", variety_first_mask([]) == [])
check("order is preserved", variety_first_mask([None, "x", None, "y", None]) == [0, 2, 4])


print("\n--- evaluate() scopes the session-weighted metrics ---")
rng = np.random.default_rng(0)


# Wide spread on purpose. Tight, well-separated blobs pin every metric at 1.0, and a
# fixture where nothing can move cannot demonstrate that scoping prevents a move.
_SPREAD = 0.25


def blob(center: np.ndarray, n: int) -> np.ndarray:
    v = center + rng.normal(0, _SPREAD, size=(n, center.shape[0]))
    return v / np.linalg.norm(v, axis=1, keepdims=True)


# `gamma` sits CLOSE to `alpha`, not orthogonal to it. Perfectly separated blobs
# saturate every metric at 1.0, and a fixture where nothing can move cannot show that
# scoping prevents a move. Overlap is also the realistic case: the labels a targeted
# pass grows are the confusable ones.
a, b = np.array([1.0, 0.0, 0.0]), np.array([0.0, 1.0, 0.0])
c = np.array([0.97, 0.24, 0.0])
base_labels = ["alpha"] * 12 + ["beta"] * 12 + ["gamma"] * 3
base_embs = np.vstack([blob(a, 12), blob(b, 12), blob(c, 3)])
base_channels: list[str | None] = [None] * 27

# A targeted pass floods the thin, confusable label — the exact shape that moves a
# session-weighted metric without anything about the system changing.
tgt_labels = base_labels + ["gamma"] * 24
tgt_embs = np.vstack([base_embs, blob(c, 24)])
tgt_channels = base_channels + ["structural"] * 24

kw = {"tau": 0.94, "confident_tau": 0.98, "holdout_k": 1, "bootstrap": 20,
      "per_label_floor": 0.3, "k_folds": 3, "repeats": 2, "seed": 0}
base = evaluate(base_labels, base_embs, channels=base_channels, **kw)
grown = evaluate(tgt_labels, tgt_embs, channels=tgt_channels, **kw)
unscoped = evaluate(tgt_labels, tgt_embs, channels=[None] * len(tgt_labels), **kw)

check("label-weighted family sees every row",
      grown["scope"]["label_weighted_n"] == 51, str(grown["scope"]))
check("session-weighted family sees only the variety-first rows",
      grown["scope"]["session_weighted_n"] == 27, str(grown["scope"]))
check("the channel census is reported",
      grown["scope"]["selection_channels"] == {"variety-first": 27, "structural": 24},
      str(grown["scope"]["selection_channels"]))

for m in ("novel_precision", "novel_recall"):
    check(f"{m} is unchanged by the targeted pass",
          grown["metrics"][m] == base["metrics"][m],
          f"base={base['metrics'][m]} grown={grown['metrics'][m]}")
    check(f"{m} WOULD have moved unscoped (the bug this prevents)",
          unscoped["metrics"][m] != base["metrics"][m],
          f"base={base['metrics'][m]} unscoped={unscoped['metrics'][m]}")

check("macro_f1 DOES respond to the added rows — it is label-weighted, not scoped",
      grown["metrics"]["macro_f1"] != base["metrics"]["macro_f1"],
      f"base={base['metrics']['macro_f1']} grown={grown['metrics']['macro_f1']}")

no_chan = evaluate(base_labels, base_embs, **kw)
check("omitting channels entirely is identical to all-original (back-compat)",
      no_chan["metrics"] == base["metrics"], "channels=None must not change a number")

print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
