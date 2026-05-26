<p align="center">
  <img src=".github/logo.png" alt="DShield Prism logo" width="200">
</p>

<h1 align="center">DShield Prism</h1>

<p align="center"><em>Refract the noise. Resolve the behavior.</em></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue.svg" alt="License: GPL-3.0"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.9%2B-blue.svg" alt="Python 3.9+"></a>
  <a href="https://github.com/tonysperez/dshield_vector_analysis/commits/main"><img src="https://img.shields.io/github/last-commit/tonysperez/dshield_vector_analysis" alt="Last commit"></a>
</p>

<p align="center">
  <a href="docs/reference.md">Documentation</a> •
  <a href="console/">Investigation Console</a> •
  <a href="docs/ROADMAP.md">Roadmap</a>
</p>

---

Honeypots see a *lot* of attacker activity. Content-focused analysis buries the interesting stuff (new techniques, quiet attack drift, emerging campaigns) under the noise of commodity internet scanning. Prism is the enrichment, correlation, and analysis layer that turns this blinding light of logs into a rainbow of behavior.

**See behavior, not mountains of logs.** Prism reads DShield logs and turns them into a structured view of how attackers are behaving, not just what IPs ran what. Every unique command, session, and source IP becomes a behavioral fingerprint with a semantic vector, intent, MITRE TTP IDs, and extracted IOCs.

**Watch behavior change over time.** Recurring activity gets named as a playbook. Coordinated multi-session activity gets grouped as a campaign. Both keep stable identities across re-analysis runs, so when their behavior drifts, their infrastructure shifts, or a new pattern emerges, Prism surfaces it as a finding in a curated inbox — with a confirm / reject workflow that turns your decisions into a growing knowledge base.

**Grounded in real-world threat intel.** Most artifacts (IP, file hash, URL, domain) can be checked against freely available threat-intel feeds. A consensus engine collates the responses across all CTI feeds and knows the difference between one feed shouting and everyone agreeing. Intel verdicts feed back into the pipeline: known-good scanners get quieted, commodity-malicious IPs get cheaper triage, and every artifact you open carries its external label next to its locally-observed behavior.

**Private by default.** A local LLM does the cognitive work. Optional cloud escalation is budget-capped and opt-in. CTI feeds are integrated but disabled by default. Nothing about your honeypot traffic leaves your environment unless you say so.

## Why?
As part of an internship with the SANS Internet Storm Center, I was tasked with identifying and analyzing attacks observed by my DShield honeypot. I was not content with identifying just any attack; I wanted to look at the *interesting*, the *novel*, things I could analyze which could provide actual value to the community. To achieve this, I decided that I needed to transform my DShield logs into behavior so I could answer questions like:

- What IPs are behaving similarly (IP clusters)?
- Which commands are being chained together (called Playbooks)? What is the intent of that playbook?
- Which IP clusters are running what playbooks?
- Which Playbooks and which IP clusters are associated with what artifacts?
- What behavior has changed over time? How has it changed?
- What activity is novel? (vector-based long-tail analysis)

## Status & roadmap

- [x] Cowrie ingestion + full enrichment pipeline
- [ ] Make project setup documented, easy, and reproducible *(planned)*
- [ ] Webhoneypot ingestion *(planned)*
- [ ] DShield firewall ingestion *(TBD, pending value decision)*

Everything else lives in [docs/ROADMAP.md](docs/ROADMAP.md).

## Install

```bash
sudo bash setup/setup.sh
```

Idempotent. Requires `.env` + `config/local.yaml` filled in, and a reachable
LLM server. See [docs/reference.md](docs/reference.md) for setup details,
configuration, and operational workflows.

## Run

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli healthcheck
sudo -u dshield_prism .venv/bin/python -m enrich.cli enrich
```

The systemd timers (`dshield_prism-forward.timer` every 30 min;
`dshield_prism-backward.timer` every 6 h) handle steady-state. See
[docs/reference.md](docs/reference.md#systemd-cadence).


## Documentation

| Doc | What's in it |
|---|---|
| [docs/reference.md](docs/reference.md) | Operational notes, CLI, ECS schemas, tunables, intel subsystem, deploy recipes |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Open work |
| [docs/history/](docs/history/) | Per-phase shipped behaviour + design archive |

## License

Licensed under [GPL-3.0](LICENSE).