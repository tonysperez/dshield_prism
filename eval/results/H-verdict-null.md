# Phase H verdict — abandoned at H0 (canonicalisation viability)

_Captured 2026-06-02._

## TL;DR

**H abandoned at the viability gate.** It *passes* the hard gate
(3,010 shapes ≤ 20,000) but the canonicalisation premise it rests on does
not hold on this corpus, and the deeper problem it surfaces — sessions
don't amortize — makes the per-shape LLM-summary mechanism a standing
liability rather than a cheap cache. Not worth the H1–H5 production build.

## What H0 measured (`scripts/probe_canonical_session_count.py`)

| | value |
|---|---|
| total sessions | 223,561 |
| command-bearing | 4,078 |
| **unique shapes** (command_signature) | **3,010** |
| **dedup ratio** (sessions / shape) | **1.35×** |
| top-50 shapes cover | 27.4% of command-bearing |
| shapes with ≥10 members | 10 |
| **singletons (1 member)** | **2,983 = 73.1%** |

The distribution is a tiny head (shape #1 = 526 sessions, the SSH-key
dropper; top-10 ≈ 25%) and a massive long tail of unique sessions.

## Why abandoned (passes the gate, still not worth it)

1. **The canonicalisation premise is false here.** H assumed copy-paste
   dominance → a low shape count where "sessions inherit" a cached summary.
   Reality: 73% of command-bearing sessions are their own unique shape;
   caching saves ~26% (1.35×), not the order-of-magnitude collapse assumed.

2. **Sessions don't amortize, so re-enrichment cost scales with the
   corpus.** Commands re-enrich cheaply on a config change because they
   dedup to a *fixed* ~3,000 forms regardless of corpus size. Sessions
   dedup ~1:1, so a session-summary prompt/model change re-summarises
   *every* shape, and that count grows with the corpus — today ~3,010
   (fine), at fleet scale (~50k command-bearing → ~37k shapes) over the 20k
   affordability gate. Same re-enrichment cadence as commands, a cost that
   doesn't stay flat. A standing maintenance liability on the layer that
   doesn't amortize.

3. **A cascade dependency to get right for no payoff.** The summary reads
   per-command intent, so its config hash would have to fold in the
   upstream command `llm_config_hash` (else a command-prompt edit silently
   leaves stale summaries) — extra machinery for a mechanism that already
   isn't pulling its weight.

4. **The cheap reframe is a non-test.** Capping to the top-K shapes bounds
   the budget but leaves the singleton tail on the baseline fallback — and
   dp-008's divergent members (textually different → different shapes) live
   in exactly that tail. So the affordable version of H wouldn't test the
   thing H exists to test.

## What's left on the semantic-not-textual table

With E, F, G nulled and H abandoned, the remaining options are **upstream
or project-level**, not another clustering/representation/summarisation
tweak:

- **Cowrie-side instrumentation** to capture honeypot response state /
  fake-filesystem outcomes / attacker reactions — the signal dp-009 (and
  much of the missing behavioural distinction) actually needs. A separate,
  larger workstream.
- **Project-level reframe** — accept session clustering as
  instrumentation-grade and lead with the campaign / hunts / operations
  layers that already deliver value.

The honest closing line across E → F → G → H: on this single-sensor corpus,
**the session-level semantic structure is signal-limited at the input, not
method-limited.** The shipped wins (0.94 merge consolidation, command-layer
rescue) came from fixing fragmentation and outliers; no amount of
re-clustering, re-representing, or re-summarising the same command-stream
signal recovered structure the signal doesn't carry.
