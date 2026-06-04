"""Smoke test for #22 follow-on: infrastructure miner now uses IDF-weighted
top-N selection instead of a hard 50% frequency cutoff.

Pre-fix: artifacts appearing in >50% of in-window sessions were dropped
as "too generic" before campaign construction. That filter treated a
high-specificity artifact like a shared SSH public key — which can
legitimately appear in 70-90% of sessions when a botnet adopts it — as
noise, killing entire legitimate campaigns. The #21 30-day window
exacerbated this by shrinking the denominator.

Post-fix:
  - Filter only drops singletons (df < 2 — can't join anything).
  - Per-artifact `idf = log((N+1)/(df+1))` is computed; commodity
    artifacts (df ≈ N) get idf ≈ 0 and sink to the bottom of top-N
    without being categorically excluded.
  - Top-N sort key is `(-count * idf, (kind, value))`. The lex
    secondary key preserves #17's rotation guard.

This test reproduces the sort+score logic against synthetic inputs and
asserts:
  1. The IDF formula matches expected log values.
  2. A commodity artifact (df=N) has weight 0 and sinks last.
  3. A rare artifact (df=2) outranks a common one with higher in-component
     count once its idf is applied.
  4. The headline scenario: ssh_key at 73% + URL at 2% — under the new
     code, BOTH appear in top-N (ssh_key not dropped); the URL outranks
     the ssh_key on a small component where the ssh_key contributes few
     occurrences but its idf is small.
  5. Insertion-order stability is preserved (#17 lex tie-break still active).

Standalone — no real ES, no pytest. Replicates the in-function formula
the way `smoke_test_campaign_fingerprint.py` does.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke_test_infra_idf_weighting.py
"""
from __future__ import annotations

import itertools
import math
import sys
from collections import OrderedDict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# Mirror of the in-function formula. The point of testing it here is to
# assert *behavioural* properties — that the chosen scoring scheme
# produces the expected top-N ordering — rather than to re-test the
# implementation's correctness (which is single-line and stable).
def _idf(N: int, df: int) -> float:
    return math.log(N + 1) - math.log(df + 1)


def _top_arts(art_counts: dict, df_by_art: dict, N: int, top_n: int = 30) -> list:
    return sorted(
        art_counts.items(),
        key=lambda kv: (
            -(kv[1] * _idf(N, df_by_art.get(kv[0], 1))),
            kv[0],
        ),
    )[:top_n]


# -----------------------------------------------------------------------------
# [1] IDF formula sanity.
# -----------------------------------------------------------------------------
print("\n[1] IDF formula sanity")
N = 100
# Rare: df=2 → log(101/3) ≈ 3.52
check(
    "df=2, N=100 → idf ≈ log(101/3)",
    abs(_idf(N, 2) - math.log(101.0 / 3.0)) < 1e-9,
    f"got {_idf(N, 2)}",
)
# Middling: df=50 (50%) → log(101/51) ≈ 0.685
check(
    "df=50, N=100 → idf > 0 (still nonzero at 50%, would have been DROPPED pre-fix)",
    _idf(N, 50) > 0,
    f"got {_idf(N, 50)}",
)
# Commodity: df=N → log(1) = 0
check(
    "df=N → idf == 0 (commodity, weight-zero in top-N)",
    abs(_idf(N, N)) < 1e-12,
    f"got {_idf(N, N)}",
)
# Monotonic: rarer → higher idf
check(
    "idf strictly decreases as df increases",
    _idf(N, 2) > _idf(N, 10) > _idf(N, 50) > _idf(N, 100),
    f"got {_idf(N, 2)} > {_idf(N, 10)} > {_idf(N, 50)} > {_idf(N, 100)}",
)


# -----------------------------------------------------------------------------
# [2] A commodity artifact sinks to the bottom of top-N regardless of count.
# -----------------------------------------------------------------------------
print("\n[2] commodity artifact (df=N) sinks regardless of high count")
N = 100
art_commodity = ("url", "http://everyone-runs-this.example/")
art_rare     = ("url", "http://only-this-campaign.example/")
art_counts = {
    art_commodity: 95,    # in nearly every session of this component
    art_rare:      3,     # only 3 occurrences but specific to this campaign
}
df_by_art = {
    art_commodity: 100,   # appears in ALL 100 in-window sessions
    art_rare:      3,     # appears in 3 in-window sessions total
}
top = _top_arts(art_counts, df_by_art, N)
check(
    "rare artifact (count=3, idf high) outranks commodity (count=95, idf=0)",
    top[0][0] == art_rare and top[1][0] == art_commodity,
    f"got order: {[t[0] for t in top]}",
)
# Confirm the commodity didn't get *dropped* — it's still in top-N.
check(
    "commodity artifact kept in top-N (not categorically rejected)",
    art_commodity in {t[0] for t in top},
    f"got {top}",
)


# -----------------------------------------------------------------------------
# [3] Headline scenario: ssh_key at 73% of sessions + URL at 2%.
# Pre-fix, the ssh_key would have been DROPPED entirely (>50% threshold).
# Post-fix, both survive; the URL outranks the ssh_key when both are present
# in a small component where each contributes the same in-component count.
# -----------------------------------------------------------------------------
print("\n[3] headline: ssh_key at 73% + URL at 2% — both survive, IDF reorders")
N = 200
ssh_key = ("ssh_key", "ssh-rsa AAAAB3...")
url     = ("url",     "http://47.242.58.84:60109/linux")
# In a component with 4 sessions, both artifacts could appear in all 4.
art_counts = {ssh_key: 4, url: 4}
df_by_art  = {ssh_key: 146, url: 4}   # 73% vs 2%
top = _top_arts(art_counts, df_by_art, N)
score_ssh = 4 * _idf(N, 146)
score_url = 4 * _idf(N, 4)
print(f"      score(ssh_key) = 4 * log(201/147) ≈ {score_ssh:.3f}")
print(f"      score(url)     = 4 * log(201/5)   ≈ {score_url:.3f}")
check(
    "URL outranks ssh_key on equal counts (URL is much rarer)",
    top[0][0] == url,
    f"got order: {[t[0] for t in top]}",
)
check(
    "ssh_key still appears in top-N (not dropped — fixes the regression)",
    ssh_key in {t[0] for t in top},
    f"got {top}",
)


# -----------------------------------------------------------------------------
# [4] When the ssh_key dominates by raw count (giant component), it leads.
# Demonstrates that count and idf BOTH matter — neither alone wins.
# -----------------------------------------------------------------------------
print("\n[4] giant ssh_key component: high count overcomes lower idf")
N = 200
# In a 146-session component, the ssh_key is present in all 146, URL in 4.
art_counts = {ssh_key: 146, url: 4}
df_by_art  = {ssh_key: 146, url: 4}
top = _top_arts(art_counts, df_by_art, N)
score_ssh = 146 * _idf(N, 146)
score_url = 4 * _idf(N, 4)
print(f"      score(ssh_key) = 146 * log(201/147) ≈ {score_ssh:.3f}")
print(f"      score(url)     = 4 * log(201/5)     ≈ {score_url:.3f}")
check(
    "ssh_key leads on count even though URL has higher per-occurrence idf",
    top[0][0] == ssh_key,
    f"got order: {[t[0] for t in top]}",
)


# -----------------------------------------------------------------------------
# [5] #17 lex tie-break still active — same total score → lex ordering.
# -----------------------------------------------------------------------------
print("\n[5] tied-score artifacts resolve lexically on (kind, value) — #17 preserved")
N = 100
# Two artifacts with identical count and df → identical score.
a = ("url", "http://b-name.example/")
b = ("url", "http://a-name.example/")
art_counts = {a: 5, b: 5}
df_by_art  = {a: 5, b: 5}
# Order through every permutation of insertion (Counter-order risk).
ids_seen = set()
for perm in itertools.permutations([(a, 5), (b, 5)]):
    d = OrderedDict()
    for k, v in perm:
        d[k] = v
    df = OrderedDict()
    for k, v in perm:
        df[k] = v
    top = _top_arts(d, df, N)
    ids_seen.add(tuple(t[0] for t in top))
check(
    "exactly 1 ordering across all permutations",
    len(ids_seen) == 1,
    f"got {len(ids_seen)} orderings: {ids_seen}",
)
# Lex smaller value wins ('a-name' < 'b-name').
check(
    "lex tie-break: 'a-name' < 'b-name'",
    next(iter(ids_seen))[0] == b,
    f"got {next(iter(ids_seen))}",
)


# -----------------------------------------------------------------------------
# [6] Singletons (df=1) excluded by the joinable filter — verified by the
# integration: they wouldn't be in df_by_art / art_counts at all.
# This is a structural assertion that the filter logic correctly drops them.
# -----------------------------------------------------------------------------
print("\n[6] singleton artifacts excluded from joinable set")
art_to_sessions = {
    ("url", "http://a.example/"): {"sid_A"},                # df=1 — singleton
    ("url", "http://b.example/"): {"sid_A", "sid_B"},       # df=2 — minimal join
    ("url", "http://c.example/"): {"sid_A", "sid_B", "sid_C"},   # df=3
}
joinable = {a: sids for a, sids in art_to_sessions.items() if len(sids) >= 2}
check(
    "singleton dropped, df>=2 kept",
    set(joinable.keys()) == {("url", "http://b.example/"), ("url", "http://c.example/")},
    f"got {set(joinable.keys())}",
)


# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
