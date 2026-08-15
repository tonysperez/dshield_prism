# Roadmap

Open work, forward-only. Shipped behavior is described in
[architecture.md](architecture.md) / [reference.md](reference.md); the durable
"why" and the dead-ends-not-to-retry are in [decisions.md](decisions.md).

Remove an item from this file when it ships; add new open items as they surface.

## Ingestion sources

- **Webhoneypot ingestion** — second data source past cowrie. The pipeline is
  built source-agnostic (`prism.*.cowrie.*` naming, per-source loaders).
- **DShield firewall ingestion** — TBD, pending a value decision. Scaffolding for
  it exists but is parked.

## Enrichment + correlation

- **Domain artifact kind** + domain-age / passive-DNS grounding. Adds a `domain` artifact
  end-to-end alongside the existing ip/url/hash kinds.
- **Embedding-based functional clustering** — follow-up to the exact-shape dedup:
  group commands that are functionally equivalent but not shape-identical.
- **Near-neighbor grounding** for command enrichment — feed an enriched command's
  nearest neighbors into its LLM prompt as additional grounding.
- **Command lineage / sequence features** in the session embedding — today's
  IDF mean-pool is bag-of-unique-commands; command order is lost.
- **IP-layer IDF weighting** — revisit if boilerplate dilution shows up in the IP
  mean-pool.
- **IP-layer clustering window / incremental re-cluster** — unlike sessions
  (`--window-days`), the IP HDBSCAN fit re-clusters the whole embedded
  (command-bearing) IP set every 6-hourly backward cycle, and it's O(n²) at
  ~800-d (sklearn can't tree-partition, so brute force). Projection from the real
  anchor: ~25 min at ~250K distinct IPs, paid 4×/day — the structural wall at
  backlog scale. Needs an IP-layer window or incremental re-cluster escape valve.
  Note: an `ip.cluster_svd_dim` (fit-only SVD like commands=128 / sessions=96;
  the core `run_layer_clustering` already accepts `svd_dim`, the IP caller just
  doesn't pass one) is a cheap ~6–8× constant-factor palliative but doesn't change
  the O(n²) shape — the window/incremental path is the real fix. Measured by
  `scripts/loadtest_ip_recluster.py` (writes to the gitignored `eval/results/`;
  re-run it for current numbers).
- **Behavior↔infrastructure campaign convergence** flag — when the two miners
  start overlapping, that overlap is itself signal (the Operation promotion is
  the first cut; a standing convergence finding is the follow-up).

## Detection sharing

- **Rule exporter** — campaigns / playbooks / session clusters → YARA / Sigma, so
  the behavioral signals Prism mines can feed other tooling.

## Attribution + tradecraft

- **Offline attribution scaffolding** (non-LLM) — citation-bearing signals that
  don't burn LLM budget. HASSH is captured and queryable; this would build the
  correlation surface on top.
- **Keystroke-timing attribution** from Cowrie TTY replay logs — inter-keystroke
  intervals and **paste detection** (human vs. scripted). Cheap near-term proxy
  available without ttylogs (command entropy already approximates it).
- **Second external reference corpus** — MITRE CALDERA stockpile, alongside
  Atomic Red Team, for the "novel vs documented tradecraft" axis. The reference
  subsystem is already source-agnostic.

## Analyst authoring

- **Session-pattern annotations** — analyst-authored rules over *multi-command*
  patterns (the existing analyst-artifact and grounding-note systems operate one
  command line at a time).
- **Deployment-local override layer** — let analysts edit the runtime-mutable
  data files under `src/enrich/data/commands/` outside version control, so a
  deploy's local edits don't fight the tracked defaults.

## Intel

- **Pass-3 LLM web-search attribution** (M6) — for the hardest unresolved
  artifacts, after the cheaper provider tiers.
- **Deferred providers** — additional CTI feeds behind the existing
  consensus/independence framework.

## Security + hardening

- **Security posture review** of Prism's own attack surface — the headline input
  is adversarial by design (attacker-controlled command text reaching an LLM and
  a browser). Prompt-injection fencing + output-schema validation are in place;
  this is the standing review of everything around them.
- **One shared HTML escaper in the console front-end.** `escapeHtml` is currently
  redefined per-file (`app.js`, `artifact_ip.js`, `artifact_rule_modal.js`,
  `explore.js`), which means the invariant "attacker-controlled text is escaped
  before it reaches `innerHTML`" is enforced by convention across ~90 `innerHTML`
  sites rather than by construction. Hoist one escaper into a shared module, have
  every renderer use it, and prefer `textContent` where no markup is needed. Two
  known stragglers to fix in the same pass: the `drawer-body` error paths in
  `findings.js` interpolate raw server response text, and `app.js` truncates
  *after* escaping so a slice can land mid-entity. Neither is known-exploitable
  today — this is about removing the class, not patching instances.

## Console UX

A backlog of smaller console improvements (historical-run investigation, ASN/
country fan-out pagination, richer free-text command search). Tracked
incrementally; none blocks the core workflow.

## Open audit items

Smaller correctness/quality follow-ups surfaced by code review and the eval
diagnostics — e.g. per-centroid cohesion stats, `_URL_RE` query-string
normalization. These live next to the code they touch; `scripts/diagnose_*.py`
track several of them against the live corpus. (The IP-layer noise-rescue gap —
70% of command-bearing IPs flagged as noise with no rescue — shipped: augmented-
space rescue, `scripts/diagnose_ip_rescue.py` tunes the percentile.)
- **Retire `eval_clustering.py`'s CLI/CI surface** — diagnostic-only since the
  Option-A cutover (raw HDBSCAN-vs-label ARI/NMI, a geometry the shipped
  nearest-prototype assign path doesn't use); already demoted out of every
  "the gate" framing in docs (`eval/README.md`, `docs/evaluation.md`). Full
  removal isn't a doc fix, though: 6 scripts (`sweep_hdbscan.py`,
  `sweep_embedding_model_prod.py`, `eval_production_scale.py`,
  `prod_corpus.py`, `sweep_embed_input_order.py`,
  `inspect_small_clusters.py`) import its metric-core functions as shared
utilities, and it's wired into `.github/workflows/eval.yml:37` +
  CLAUDE.md's CI checklist. Split the reusable cores out before deleting the
  CLI/report/baseline/CI step, so the 6 dependents don't break.
- **Activate the production-path assignment gate with representative public
  anchors** — `eval_assignment_faithful.py` now exercises TF-IDF confirmation,
  cascade, whole-behavior novelty, grouped uncertainty, and protected
  provenance, but label-derived prototypes do not match production anchor
  geometry. Commit a representative public anchor/sample snapshot with capture
  identity, then establish the new baseline without retuning the shipped
  thresholds to the eval set.
- **Make the structural predicates discriminative** — the rescue tier is measured
  and stays off (`docs/decisions.md`); the blocker is that three of the seven
  predicates fire on 71-87% of sessions, so set-overlap is nearly unconditional.
  Unmeasured options: weight overlap by corpus rarity (IDF-like), require >=2
  overlapping predicates, or split the saturated predicates into finer
  sub-behaviours. The four rare predicates are the discriminative ones and already
  separate the confusable label pairs at 0.9091-1.0000
  (`scripts/eval_predicate_falsification.py`) — the separation signal exists, the
  unweighted overlap rule dilutes it. Re-run
  `eval_assignment_faithful.py --anchors ... --rescue-tau-sweep` to score any
  candidate rule; the bar is a gated arm that rescues *correctly*, which today it
  never does.
- **Prompt paths are CWD-relative, not install-root-anchored** — `cfg.prompts.*`
  (`playbook_name`, `command_deep_dive`, `cluster_pair_explanation`,
  `playbook_disambiguate`) are bare relative strings, loaded via plain
  `Path(...).read_text()` with no anchor to the install dir. Works when CWD is
  the install dir (every scripted call `cd`s first — systemd units,
  `install.sh`'s `run_cli`), but a manual verb invocation from any other CWD
  raises `FileNotFoundError` on the first prompt load. Fix: resolve these paths
  at config-load time relative to the config file's directory (or the package
  install root) instead of leaving them CWD-relative — one change in the config
  loader instead of four call sites. Surfaced by a "no playbooks after
  reinstall" investigation: the reinstall left CWD elsewhere, so
  `name-playbooks` died on its first prompt read.
