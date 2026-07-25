# Contributing

Thanks for the interest. DShield Prism is currently a personal research and portfolio
project rather than a community-driven product. As such, focused bug reports, 
correctness fixes, and documentation improvements are welcome. If you're thinking of 
something bigger than a small fix, open an issue first so we can agree on scope 
before you write code.

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

There's no heavy unit-test suite; correctness is guarded mainly by the offline
smoke tests (`scripts/run_smoke.py`) and the eval gates run in CI, which grade
clustering/labeling quality against a hand-labeled answer key on every change.
If your change has a runtime surface, add or extend a smoke test; if it can move
a quality metric, run the gates and note the deltas in your PR.
