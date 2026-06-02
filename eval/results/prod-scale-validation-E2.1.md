# E2.1 back-validation at production scale

_Captured 2026-06-01 via the E6 production-scale gate._

## TL;DR

E2.1's `cooccurrence.embed_cooccurrence: false` adoption (eval-scale
sweep result) is **confirmed** at production scale. Re-embedding
production under `cooccurrence.embed_cooccurrence: true` and measuring
the eval-labeled subset against fresh cluster ids:

| Config | ARI | Completeness | Homogeneity | NMI | v2 pair rate |
|---|---|---|---|---|---|
| cooc=false (E2.1 adoption, current prod) | **0.3906** | 0.5478 | 0.8640 | 0.6705 | 0.6667 |
| cooc=true (pre-adoption baseline) | 0.3370 | 0.5227 | 0.8383 | 0.6439 | 0.6667 |
| **Δ (cooc=false − cooc=true)** | **+0.0536** | +0.0251 | +0.0257 | +0.0266 | 0.0000 |

cooc=false wins **+0.0536 ARI** at production scale. The E2.1 sweep
measured **+0.0897 ARI** at eval scale; the smaller production-scale
delta is consistent with the project's measured eval-vs-prod scale gap
(−0.067 ARI), not a sign of weakening signal.

**Per-label fragmentation** — only `single_command_probe` regressed
under cooc=true (3 → 4 clusters; +1, at the gate's ceiling). All five
other analyst labels held their cluster count. No collapse,
no label disappeared.

**Verdict: keep `cooccurrence.embed_cooccurrence: false` in
`config/default.yaml`.** E2.1's eval-scale conclusion holds at
production scale.

## How the measurement was done

The cooc=false numbers are the production-scale baseline captured at
2026-06-01T18:36 against [eval/production-snapshot-v1.jsonl.gz](../production-snapshot-v1.jsonl.gz)
(the snapshot the E6.2 CI gate scores against). Source:
[eval/results/prod-scale-20260601T183636Z.json](prod-scale-20260601T183636Z.json).

The cooc=true numbers come from a deliberate revert cycle:

1. Operator added the override to the production host's `config/local.yaml`:
   ```yaml
   cooccurrence:
     embed_cooccurrence: true
   ```
2. Ran `enrich backward` on the production host. The `embed_config_hash`
   changed from `5399ddfcd1e0a803` (cooc=false projection) to
   `567a3835549591d3` (cooc=true projection), invalidating every cached
   command embedding. The reembed step re-embedded all 4571 enriched
   commands; downstream `rollup sessions` re-pooled session embeddings;
   `cluster sessions` re-ran HDBSCAN.
3. The post-backward production state was snapshotted at 2026-06-01T19:24
   via [scripts/refresh_production_snapshot.py](../../scripts/refresh_production_snapshot.py),
   then scored via [scripts/eval_production_scale.py](../../scripts/eval_production_scale.py).
   Source: [eval/results/prod-scale-20260601T192504Z.json](prod-scale-20260601T192504Z.json).

The cooc=true snapshot was a transient measurement artifact — not
committed. Production is now being reverted to cooc=false per the
operator runbook below.

## Why most session embeddings didn't change between the two states

A side observation: comparing the cooc=false snapshot and the cooc=true
snapshot byte-for-byte showed ~90% of session-rollup embeddings
identical. That's not measurement noise; it reflects how the
cooccurrence prelude works on this corpus. `fetch_cooccurring_commands`
only returns siblings that meet a minimum-session threshold; many
production commands have zero qualifying siblings, so the embed-text
delta between cooc=on and cooc=off is empty for those commands, and
their per-command embeddings come out byte-identical. The corpus-wide
ARI drop comes from the ~10% of commands that DO have siblings: in
those cases, cooc=true adds noise that pushes the pool toward
sibling-shape rather than command-shape, fragmenting clusters.

This explains why the E2.1 eval-scale sweep result generalizes
directionally but compresses in magnitude: most sessions weren't
sensitive to the toggle either way, and the +0.0897 → +0.0536 ARI
reduction reflects how diluted the signal is at production scale.

## Action items

- **Keep `cooccurrence.embed_cooccurrence: false`** in
  `config/default.yaml`. No change required.
- **No update to `eval/baseline.json` or `eval/baseline-prod-scale.json`**
  — current values reflect the (correct) cooc=false production state.
- **Revert the production host's `config/local.yaml`** — remove the
  `cooccurrence: embed_cooccurrence: true` block, then run
  `enrich backward` again to restore cooc=false embeddings. The
  reembed will invalidate the cache (hash flips back from
  `567a3835549591d3` to `5399ddfcd1e0a803`) and rebuild every command
  embedding. After the backward completes, the production-scale gate
  should drop right back to ARI 0.3906 against the existing
  [eval/baseline-prod-scale.json](../baseline-prod-scale.json).
- **Refresh `eval/production-snapshot-v1.jsonl.gz`** once the revert
  backward completes, so the committed snapshot reflects the post-revert
  production state (not strictly necessary; the existing 18:35 snapshot
  is also cooc=false, but the refresh ties the snapshot timestamp to
  the post-validation revert for an unambiguous git blame trail).

## Lessons (E6 framework working as intended)

This is the first time the production-scale gate has been used to
back-validate an existing adoption (rather than gate a new one). It
worked exactly as the E4 postmortem motivated:

- The eval-scale +0.0897 ARI signal had a direction and a sign at
  production scale.
- The magnitude compressed by ~40% — useful calibration data the
  eval-isolated gate alone can't supply.
- The per-label table caught `single_command_probe` fragmenting under
  cooc=true. That single +1 in the cluster count is the kind of
  "ARI moved but one label collapsed" signal that originally motivated
  the E0.1 per-label add.

Subsequent E-phase adoptions (E8.4, E9.3) should run through the same
back-validation pattern before landing in `config/default.yaml`. The
operational cost is real (one full backward cycle per candidate config),
but the validation is decisive and cheap to interpret.
