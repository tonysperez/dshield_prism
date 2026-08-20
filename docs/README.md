# DShield Prism documentation

Start here. Each doc answers one question; pick the one that matches what you
need.

| Doc | Read it when you want to know… | Audience |
|---|---|---|
| [architecture.md](architecture.md) | **How it works** — the pipeline, the command→session→IP→playbook→campaign model, how sessions get labeled, how intel and findings fit in | anyone |
| [operations.md](operations.md) | **How to run it** — install, configure, the systemd cadence, CLI verbs, backfilling a sensor, troubleshooting | operators |
| [reference.md](reference.md) | **The exact contract** — indices, ECS field schemas, stable ids, every tunable knob, intel internals, CI gates | agents working on the code |
| [evaluation.md](evaluation.md) | **How well it works** — the labeled eval set, the quality gates, and what the measurements found | anyone |
| [decisions.md](decisions.md) | **Why it's built this way** — the load-bearing design choices and the dead-ends that were measured and rejected | anyone |
| [roadmap.md](roadmap.md) | **What's next** — open work, forward-only | anyone |
| [release-readiness.md](release-readiness.md) | **What must be fixed before release** — security, privacy, install, and blockers from the pre-release review | maintainers |

Two more docs live next to the code they describe:

- [`../console/README.md`](../console/README.md) — the investigation console
  (install, search syntax, pages, API).
- [`../eval/README.md`](../eval/README.md) — the eval-set mechanics and labeling
  workflow; the rubric is [`../eval/RUBRIC.md`](../eval/RUBRIC.md).

The project overview and install one-liner are in the top-level
[`../README.md`](../README.md).
