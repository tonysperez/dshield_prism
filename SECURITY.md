# Security Policy

DShield Prism processes adversarial honeypot capture and can call out to a
cloud LLM and external threat-intel feeds. Its security model is therefore part
of the product. This document states that model,the known limits,
and how to report a problem.

## Reporting a vulnerability

Please report privately. Do not open a public issue for a security bug.

- Preferred: GitHub's **"Report a vulnerability"** (Security → Advisories) on
  this repository.

Include a description, affected version/commit, and reproduction steps or a PoC.
This is a solo research/portfolio project, so there is no formal SLA. I aim to
acknowledge within a few days and fix credible issues as time allows. I'll
credit reporters who want it.

## Security model

The design invariant is that **data leaving the box is a default-deny
boundary**, enforced in code, not in operator discipline.

- **Classification at ingest.** Every per-sensor record carries
  `dshield.classification` (`public` | `confidential`). Sensors marked
  confidential never have their data forwarded off-box.
- **Fail-safe filter.** The releasable filter
  ([`releasable_filter` / `is_releasable`](src/enrich/classification.py))
  matches *only* explicitly-`public` records. Untagged data is treated as
  confidential, so a missing tag cannot leak.
- **Egress is opt-in and capped.** The local pipeline is self-contained. Cloud
  LLM escalation and external CTI lookups are off by default; when enabled, all
  egress is hard-capped per day (LLM by token cost, CTI by query count).
- **One enforced boundary.** Every egress path; intel queue, command
  escalation, and finding narratives all route through the single releasable check
  above to keep the surface auditable.

If you find a path that forwards confidential or untagged data off-box, or that
bypasses the daily caps, treat it as a security bug and report it as above.

## Known limitations — read before deploying

- **The console has no built-in authentication.** The systemd unit binds it to
  `127.0.0.1` (loopback) for this reason. Do not expose it on a network
  directly. To serve analysts, front it with a reverse proxy that terminates
  auth (see "Exposing the console on the LAN" in
  [docs/operations.md](docs/operations.md)). Binding the app to `0.0.0.0` makes
  honeypot-derived data readable by anyone who can reach the port.
- **Secrets live in `.env`.** ES credentials and provider API keys are read
  from `.env`, which is gitignored. Use a dedicated least-privilege ES user for
  the worker, not the Elasticsearch admin. Never commit `.env` or
  `config/local.yaml`.
- **The interactive/analyst path is not classification-gated.** Ad-hoc ES
  queries and the eval labeling workflow use broad credentials and can read
  confidential data by design; only the automated pipeline's egress paths are
  gated. This is documented and deliberate — see `CLAUDE.md`.

