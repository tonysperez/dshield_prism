<p align="center">
  <img src=".github/logo.png" alt="DShield Prism logo" width="200">
</p>

<h1 align="center">DShield Prism</h1>

<p align="center"><em>Refract the noise. Resolve the behavior.</em></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue.svg" alt="License: GPL-3.0"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"></a>
  <a href="https://github.com/tonysperez/dshield_prism/commits/main"><img src="https://img.shields.io/github/last-commit/tonysperez/dshield_prism" alt="Last commit"></a>
  <a href="https://github.com/tonysperez/dshield_prism/actions/workflows/ci.yml"><img src="https://github.com/tonysperez/dshield_prism/actions/workflows/ci.yml/badge.svg" alt="Lint"></a>
  <a href="https://github.com/tonysperez/dshield_prism/actions/workflows/eval.yml"><img src="https://github.com/tonysperez/dshield_prism/actions/workflows/eval.yml/badge.svg" alt="Clustering Quality"></a>
</p>

<p align="center">
  <a href="docs/reference.md">Documentation</a> •
  <a href="console/">Investigation Console</a> •
  <a href="docs/ROADMAP.md">Roadmap</a>
</p>

---

A dashboard over honeypot logs tells you which IPs and commands are loudest, where they originate from, and the raw content of their actions. It can't tell you what an attacker is actually doing, or who else is doing the same thing: the new techniques, quiet drift, and emerging campaigns that matter stay buried under the noise of commodity internet scanning. Prism is the enrichment, correlation, and analysis layer that refracts that blinding light of logs into a rainbow of behavior.

Built during my internship with the SANS Internet Storm Center to enable faster and more impactful analysis of the activity my DShield sensor sees.

## A behavioral subset of a broader shared-key campaign

Behavioral campaign mining surfaces the chattr+cron *subset* of a broader shared-key infra campaign. `cmp-inf-cd57092a675b30ea` is a **1,251-IP infrastructure campaign** sharing one RSA public key (`SHA256:c2c1e9557c5abc30b71f1aae0b896e57ac16aba3add335ceebcc1701ae6cbb57`) across the corpus. Inside that pool, `cmp-beh-e6e6e5569e56d396` isolates **73 source IPs across 35 countries and 57 ASNs** — the subset that runs the same combination of two playbooks over 275 sessions and 12 days:

- **SSH Key Injection with chattr Locking** (T1098.004, T1222.002) — installs an `authorized_keys` entry, then sets the immutable bit on `.ssh` so the key can't be removed without first unsetting it.
- **SSH Key Installer: Crontab list** (T1098.004, T1222.002, T1053.003) — installs the same `authorized_keys` entry, plus reconnaissance and `crontab -l` for cron-based re-installation.

The combination is defense-in-depth persistence: install the key, lock it with chattr, re-install via cron if it disappears. Two campaign axes (behavior and infrastructure) corroborate the same finding from different angles: the infra axis names the shared-key pool; the behavior axis names the chattr+cron sub-population *inside* that pool. Frequent-itemset mining (FP-growth) over each IP's playbook set is what surfaces *"these 73 IPs run this exact combination"* — and the playbooks themselves only exist because session embeddings clustered into stable named behaviors. That manual two-axis corroboration is now detected automatically: when a behavior campaign and an infrastructure campaign overlap, Prism promotes the intersection to an **Operation** (`cmp-ope-…`).

## What the clustering actually does — measured

The campaign above only means something if the clustering underneath it groups sessions by *behavior*, not by text. The honest answer from a 108-session analyst-labeled eval set (100 stratified + 12 divergent-pair stress cases):

- **Cluster quality vs. analyst labels.** At the production HDBSCAN config (`min_cluster_size=5`), the embedding-only pipeline scores ARI 0.44 on the eval-isolated 108 sessions and ARI 0.39 when those same sessions are scored against production cluster ids running on the full ~4,000-session corpus ([eval/results/prod-scale-validation-E2.1.md](eval/results/prod-scale-validation-E2.1.md)). Homogeneity holds above 0.80 at both scales; completeness sits at 0.55–0.60. Clusters are internally pure; labels fragment across a moderate number of clusters. The −0.05 ARI gap between eval-isolated and production-scale measurement is a corpus-size property, not a regression — covered in [docs/handoff-embedding-quality-plan.md](docs/handoff-embedding-quality-plan.md).
- **Copy/paste dominance.** Per [`scripts/eval_cluster_purity.py`](scripts/eval_cluster_purity.py), 5 of the top 20 corpus clusters are copy/paste tight — every member runs the *exact same* command set (`modal_signature_share` ≥ 0.8). One cluster (`cluster_20`, SSH Key Dropper) holds 526 sessions at `modal_signature_share = 0.99`. On this corpus, copy/paste-script lineage drives most clustering signal regardless of representation.
- **Embedding vs. TF-IDF baseline.** A TF-IDF + truncated-SVD baseline ([eval/results/embedding-ablation.md](eval/results/embedding-ablation.md), [eval/results/embed-input-sweep-20260601T144733Z.md](eval/results/embed-input-sweep-20260601T144733Z.md)) ties the embedding on overall ARI within ~0.07 either direction depending on HDBSCAN config and which eval slice you score on: at `mcs=5`, TF-IDF wins the v1 slice by +0.06 ARI but loses the merged v1+v2 slice by −0.07. On the v2 divergent-pair stress test specifically — pairs hand-picked to look textually different while sharing the same underlying behavior — TF-IDF resolves **6 of 6** while the embedding resolves **5 of 6**. The embedding's value-add is real but narrow: it doesn't beat literal-token overlap on copy/paste-heavy corpus structure, and on the cases designed to stress the "behavior-not-text" claim, TF-IDF happens to clear them all on this corpus.

`cluster_7` below is the kind of case where the embedding mechanism *is* doing work that TF-IDF can't: 39 commands across 19 distinct leading binaries, grouped together as host/environment fingerprinting despite near-zero textual overlap.

```
w        uname -m      whoami      hostname      ifconfig      top
nproc || grep -c processor /proc/cpuinfo          lscpu | grep Model
free -m | grep Mem | awk '{print $2,$3,$4,$5,$6,$7}'
ls -la ~/.local/share/TelegramDesktop/tdata ...   /ip cloud print
```

Three properties hold at once in this example:

- **Maximal textual divergence** — members run from one character (`w`) to 90+; they share no common tokens.
- **Cross-dialect membership** — `/ip cloud print` is MikroTik RouterOS syntax, clustered alongside Linux coreutils.
- **Semantic coherence** — every member is host recon: CPU, memory, OS/arch, identity, network, competing miners (`ps | grep '[Mm]iner'`), and high-value loot (`ls … TelegramDesktop/tdata`).

The same invariance shows up over shell-wrapping: `echo "…" | sh` and the bare command sequence cluster together because the embedding sees through the wrapper to the underlying behavior. **At the level of individual cases the mechanism works.** What the corpus-wide ablation also shows is that the wins are mostly drowned out by copy/paste traffic, where literal-token overlap already does the heavy lifting. The v2 divergent-pair eval set was built to surface exactly the textually-divergent same-behavior cases the embedding should excel at; on this corpus it cleared 5 of 6 while TF-IDF cleared 6 of 6. The mechanism is real, and Prism's downstream value (cross-session IP-cluster groupings, campaign mining, novelty scoring) leans on it, but the framing this README originally pitched — that semantic embedding generally beats text matching on honeypot logs — over-claimed what's measurable today on a single sensor's corpus.

## How it works

**See behavior, not individual actions.** Every unique command, session, and source IP becomes a behavioral fingerprint with a semantic vector, intent, extracted IOCs, and MITRE TTP IDs.

**Grounded in threat intel.** Artifacts (IP, URL, and file hash today; domain planned) are checked against freely available CTI feeds. A consensus engine collates verdicts and feeds them back into the pipeline: known-good scanners get quieted, commodity-malicious IPs get cheaper triage. Novelty is scored twice: against the sensor's own corpus *and* against an external reference corpus of documented adversary tradecraft (Atomic Red Team).

**Watch behavior change over time.** Recurring activity gets named as a playbook; coordinated multi-session activity gets grouped as a campaign — by shared behavior, by shared infrastructure, or (when those two overlap) as an Operation. All keep stable identities across re-analysis runs, so drift and emergence surface as findings in a curated inbox with a confirm/reject workflow that turns analyst decisions into a growing knowledge base.

**Private by default.** A local LLM does the cognitive work; cloud escalation is budget-capped and opt-in; CTI feeds are integrated but disabled by default. Nothing about your honeypot traffic leaves your environment unless you say so.

## Live deployment

Prism has been running continuously against my home DShield sensor. Each analysis layer collapses a flood of raw activity into a handful of behaviors:

| Layer | Volume | Behaviors surfaced | Outliers |
|---|---:|---:|---:|
| Commands | ~3,000 distinct | 8 clusters | 39 |
| Sessions | 200,000 processed | 27 playbooks | 30 |
| Source IPs | 10,000 distinct | 171 clusters | 260 |

*Most of those 200,000 sessions are credential brute-force that never reach a shell. The ones that do dedup to ~3,000 distinct command forms, which in turn cluster into 8 behaviors. That reduction — a flood of raw activity down to a couple dozen named behaviors an analyst can actually reason about — is the point.*

> **A few things running this in production taught me** ([more below](#lessons-learned)):
> - Built a per-day cloud LLM cost cap on day one. This saved me when a bug later
>   caused an endless query loop that would otherwise have burned my entire
>   Anthropic balance.
> - Small LLMs cheerfully invent MITRE TTP IDs that don't exist. Every
>   LLM-emitted TTP is schema-validated against the real ATT&CK corpus.
> - Shipped a finding kind that produced 2,000 findings on one corpus.
>   Retired it after one cycle. Not a bug, just a bad detection.

Caveat worth stating plainly: this is one home DShield sensor — a single vantage point and a single corpus. The pipeline is built to be sensor-agnostic, but I haven't yet validated it against a second deployment. So read the cluster and campaign counts as evidence the method works on real adversarial traffic, not as a claim about how it behaves at fleet scale.

## Pipeline

```mermaid
flowchart TD
    A[DShield events] --> B[Command enrichment]
    M[Local LLM + embeddings] --> B
    B -.-> X[Cloud LLM, opt-in]
    B --> C[Session rollup]
    C --> D[IP rollup]
    C -- HDBSCAN --> E[Playbooks]
    D -- HDBSCAN --> F[IP clusters]
    E --> G[Campaign mining]
    B -.-> H[Threat intel]
    D -.-> H
    E --> LC[Lifecycle tracking]
    G --> LC
    D --> LC
    C --> DC[Discovery mining]
    F --> DC
    LC --> I[Findings inbox]
    DC --> I
    H --> I
    I --> J[Analyst console]
```

*Solid lines: always-on local pipeline. Dashed lines: opt-in cloud LLM and external CTI feeds.*

A local LLM + embedding model drives per-command enrichment, with optional escalation to a cloud LLM for the hardest cases. Session and IP rollups are HDBSCAN-clustered into named playbooks and IP clusters, then cross-IP campaign mining. Two streams reach the findings inbox: lifecycle tracking watches each playbook, campaign, and source IP over time so drift becomes a finding, while discovery mining surfaces outlier sessions and previously-unseen edges. A parallel intel pipeline grounds artifacts (URLs from commands, IPs from the rollup) against external feeds. The findings inbox is the analyst's curated triage queue, viewed through the console.

## Console

Seven pages, one analyst workflow: **Inbox · Graph · Browse · Hunts · Rules · Curation · Health**.

**Findings inbox.** Every drift, novel pattern, and coverage gap surfaces here. The facet rail narrows on score, age, IP-count band, intent, or intel verdict; status flows from new → ack → confirmed as the analyst works the queue.

<p align="center"><img src=".github/screenshots/inbox.png" alt="Findings inbox with facet rail" width="900"></p>

**Investigation pivot.** Click any IOC and follow it through a graph of its behavioral neighborhood — linked IP clusters, session clusters, and constituent commands, with a side panel of overview details for whatever's selected. Right from that detail pane you can pick a peer for an **inline comparison** that shows what makes two clusters, playbooks, or campaigns separate: cosine similarity vs. the merge threshold, scalar-by-scalar deltas, and a plain-language explanation alongside the math.

<p align="center"><img src=".github/screenshots/graph.png" alt="Graph-based investigation pivot" width="900"></p>

**Report tool.** Gather every in-view artifact — IPs, commands, credentials, file hashes, MITRE chain, session sequences — into a copy-ready writeup, with IOCs defanged by default and a choice of plain / markdown / CSV / JSON output.

<p align="center"><img src=".github/screenshots/report.png" alt="Report tool with category and format options" width="900"></p>

**Hunts.** Hypothesis-driven, YAML-defined session filters (AND-combined) that turn a hunch — "sessions that touched `/proc/cpuinfo` and were classified as non-recon intent" — into a repeatable, run-now finding stream. Ships with a preconfigured set. A parallel **Tradecraft Matches** view ranks sessions by how closely they mirror documented adversary tradecraft from the external reference corpus (Atomic Red Team).

<p align="center"><img src=".github/screenshots/hunt.png" alt="Hypothesis-driven hunts" width="900"></p>

## Why I built this

My internship brief was simple: identify and analyze the attacks my DShield honeypot saw. I was not content with just any attack though, I wanted the *novel*, the *interesting*. Not the commodity internet scanning that dominates the logs.

Like most people, I started by ingesting the logs into Elastic and building dashboards. They work as a map: where attacks come from, the loudest and quietest attackers and commands, dropped files, user agents. But the moment I found something interesting, building a complete picture fell apart. I had a command and the IP that ran it. I could pivot to every other IP that ran that exact command, and every other command that IP ran, but I was limited to pivoting by concrete, pre-existing artifacts. This means I could never pivot on behavior like 'What other IPs behave like this one?'. 

Existing tooling either treats DShield logs as terminal output (parsers, dashboards) or analyzes individual artifacts (sandboxes). I didn't find a layer that does cross-session behavioral clustering on commodity honeypot input, so I built one: pipelines that turn raw events into meaningful behavioral signals, rather than another way to view them.

Prism is built to answer:
- Which commands are functionally similar to this one?
- What commands are typically run alongside this one, and what's the intent of the sequence?
- How does this IP behave, and what other IPs behave like it?
- What IPs don't behave like anything else in the corpus?
- Is this activity novel relative to my own corpus *and* relative to documented adversary tradecraft? Novelty is scored against both the sensor's own clusters and an external reference corpus (Atomic Red Team's per-MITRE-technique adversary emulation manifests); CTI feeds layer on top as a separate verdict signal.

## Status & roadmap

- [x] Cowrie ingestion + full enrichment pipeline
- [ ] Webhoneypot ingestion *(planned)*
- [ ] DShield firewall ingestion *(TBD, pending value decision)*

Everything else lives in [docs/ROADMAP.md](docs/ROADMAP.md).

## Install

```bash
sudo bash setup/setup.sh
```

Idempotent. Requires `.env` + `config/local.yaml` filled in, and a reachable LLM server. See [docs/reference.md](docs/reference.md) for setup details, configuration, and operational workflows.

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
| [docs/history/](docs/history/) | Per-phase shipped behavior + design archive |

## License

Licensed under [GPL-3.0](LICENSE).

## Lessons Learned

### Production Lessons
- I had unintentionally used an ES index which was owned and managed by Elastic Fleet. This was fine, until Fleet decided to wipe all the indices it controls. I now have the setup script manually create the index to ensure Fleet does not manage it and cannot wipe it.
- Originally, I had manually set LLM and embed config versioning. Like all manual things, this sounds fine until it hits ops and gets forgotten. Moved to a hash-based auto-invalidation system, so now I can't forget.
- Initially, every command's LLM enrichment was independent. This worked fine until my sensor started getting hammered with 1,000s of mostly identical commands, which started eating up all my local LLM cycles. I extended the command parsing system to run pre-enrichment, and skip local LLM enrichment for commands which are functionally identical to commands which have already been LLM enriched.
- My first version dropped any campaign artifact that appeared in >50% of sessions as 'too generic.' That killed real campaigns where everyone shared the same staging URL. Replaced with IDF weighting. Common artifacts still contribute, just less.
- I shipped a finding kind that produced 2,000 findings on one corpus and retired it after one cycle. There wasn't a bug in the code, the finding kind itself was just too noisy to be useful.

### Internet Observations
- Quite a significant piece of the general internet scanning is just a handful of the same copy/paste scripts.
- Cargo-cult code within scripts exists as a result of the above. This has funnily enough resulted in some pretty good IOCs, because literally nobody else will run a non-existent command except a script whose operator copy/pasted without bothering to understand it.

### AI in Production
- Validation, validation, validation. With a small 8B model, I had to: give it heavy context + grounding; validate its output against my schema (it cheerfully made up MITRE TTP IDs); track output against a known baseline. Even when escalating the same query to a frontier model, I found this extra grounding and validation helped get its output just the way I wanted it.
- Cloud LLM costs can balloon, fast. I built cost-tracking and a per-day budget cap from day one — which saved me later when a bug caused an endless cloud-LLM query loop. Without the cap, that bug would have burned through my entire Anthropic balance in hours.

### Operational Lessons
- Dashboards seem a lot more useful than they are. I've found that they can make you feel like you have a handle on things, but don't survive 'What was this attacker actually doing?'. This project's goal is to close that gap.
- Known good is often more valuable than known bad. GreyNoise, while very limited on its free / Community plan, was one of the most important CTI feeds because they maintain a list of known researcher IPs, known as RIOT. This is an invaluable signal, since I found very quickly that I need to try as best I can to quiet the noise for the valuable activity to shine through.
- If you know behavior, you can keep up with rotating artifacts. One of my main drivers for this project was to be able to get a sense of how widely a particular attack is being used. Are we seeing one threat actor cycling through 100 IPs, or 100 threat actors each using 1 IP? If you can determine a threat actor's behavior, you can see through any particular attribute.