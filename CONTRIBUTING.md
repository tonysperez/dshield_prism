# Contributing

Thank you for your interest. DShield Prism is currently a personal research and portfolio
project. As such, focused bug reports, correctness fixes, and documentation improvements
are welcome, but if you're thinking of something bigger than a small fix, please open an issue
first so we can align on your idea before you proceed.

For anything security-related, follow [SECURITY.md](SECURITY.md) instead of
opening a public issue.

## Dev setup

The pipeline and the console are separate installs. For most work you want the
console venv, which does an editable install of both:

```bash
python -m venv console/.venv
console/.venv/bin/pip install -e '.[cluster]' -e console/
```

Copy `.env.example` to `.env` and fill in ES credentials (use a dedicated
least-privilege ES user, not the admin). See
[docs/operations.md](docs/operations.md) for standing up the full stack.

## Tests

Correctness is guarded by two layers, neither of which is pytest. That is a
deliberate choice, so it's worth stating the reasoning before you add to it.

**Layer 1 — offline smoke tests** (`scripts/smoke/smoke_test_*.py`, ~130 of
them, run by `scripts/run_smoke.py`). Each is a standalone script with a `main`,
a hand-rolled `check(name, ok)` helper, and a non-zero exit on failure. No test
framework, no fixtures, no conftest. Why:

- **They run anywhere, including on a live deploy.** A smoke test is a plain
  script against the installed package, so an operator debugging a production
  box can run the exact assertion CI runs without installing a test toolchain.
- **Subprocess-per-test gives real isolation.** These touch module-level config
  singletons, a SQLite state DB, and numpy RNG. One process per test means no
  cross-test state bleed and no fixture-teardown ordering to reason about.
- **The assertions stay readable as documentation.** Most of these encode a
  behavioral contract (the classification gate's truth table, the novelty
  confidence floor, ID stability across re-runs). A flat script that prints each
  named check reads as a spec; parametrized pytest cases read as a diff.

The cost, stated plainly: **there is no coverage measurement**, no
parametrization, and no shared fixture layer, so overlap between tests is
unmeasured and a new module can ship with no test and nothing will say so. If
that trade stops paying — mainly if the count keeps climbing — porting to pytest
while keeping the scripts runnable standalone is the exit.

**Layer 2 — eval quality gates** (`scripts/eval_*.py`). These grade
clustering/labeling quality against the hand-labeled answer key in `eval/` and
diff against committed baselines. They catch what smoke tests structurally
cannot: a change that is correct line-by-line and worse in aggregate.

`eval_assignment_faithful.py` is the production-decision-path diagnostic: it
replays TF-IDF band confirmation and cascade at the deployed thresholds and a
fixed operating curve. Run it with `--no-json`. It intentionally has no
baseline and is non-blocking until a representative public production-anchor
snapshot replaces its broad analyst-label prototypes; if a baseline is supplied
explicitly, identity and metrics fail closed.

### What to run

```bash
console/.venv/bin/ruff check src scripts
console/.venv/bin/python scripts/run_smoke.py
```

Both must be green. If your change has a runtime surface, add or extend a smoke
test in `scripts/smoke/`. If it can move a quality metric, run the gates listed
in [docs/evaluation.md](docs/evaluation.md#the-gates) and put the current-vs-
baseline deltas in your PR description.

**Never re-capture a baseline to make a gate pass.** Baselines move only for an
intentional, explained production change; a red gate is the system working.
