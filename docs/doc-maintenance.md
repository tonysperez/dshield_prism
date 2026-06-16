# Doc-maintenance rules

The granular rules for keeping the docs lean and consistent. The high-level
routing (which doc owns what, the "when work ships" steps) lives in the repo
`CLAUDE.md`; this file holds the detail it points to.

## What to prune (every edit)

Cut anything that doesn't have meaningful impact going forward. Specifically:

- **Smoke-test case counts** (`14 cases`, `verified offline against 21
  cases`) — the test file is the source of truth.
- **Dated corpus snapshots** ("Live impact on the 2026-XX-XX corpus",
  "5,861 IPs covered"). These rot in days.
- **Decision postmortems** ("Fix landed option (a) IDF-weighted because
  option (b) would have…"). Keep *what* the algorithm does in architecture /
  reference; the load-bearing *why* (and rejected dead-ends) go in
  `decisions.md`, terse — nowhere else.
- **Phase tags + internal milestone codes** (`P3.1`, `B0.5`, `E4.4`, "Phase
  K") — meaningless to a reader who didn't live the development. State the
  behavior, not which sprint shipped it.
- **"Lesson learned" / "pattern that worked well" / "recording them
  explicitly here so future-me…"** — meta-commentary.
- **Multi-paragraph "what landed" / "what shipped"** — collapse to one or
  two sentences plus a file pointer.
- **Verbose deploy narratives.** If the deploy is one `init-indexes
  --update-mapping` call, write that line. Don't explain why mapping
  updates are additive.
- **`Status: fix already in place`** entries that didn't change anything —
  delete entirely.

## What to keep

- What ships now (terse).
- File pointers (`src/enrich/sources/cowrie/sessions.py`) so an agent can
  find the code.
- Stable IDs and formats (`playbook_id = spb-<16hex>`,
  `cmp-bhv-<hash>`) — these are contracts.
- Constants and defaults that matter (`session.playbook_merge_threshold`
  default `0.94`; GreyNoise `50/week`).
- Design choices that still constrain future work (content-addressed
  playbook ids; strict-dynamic intel mappings; IDF weighting on session
  mean-pool) — in `decisions.md`.
- Cross-references to `roadmap.md` for open follow-ups.

## Cross-reference conventions

- Use relative markdown links. From `docs/`: `[link](file.md)`; to code:
  `[link](../src/...)`. From the repo root: `[link](docs/file.md)`.
- Use `code` for file paths and CLI commands.
- After any doc edit, verify links resolve:
  ```bash
  for f in README.md docs/*.md console/README.md eval/README.md; do
    grep -oE '\]\(([^)#h][^)]*)' "$f" 2>/dev/null | sed 's/^](//' | while read link; do
      dir=$(dirname "$f")
      target="${dir}/${link%%#*}"
      [ ! -e "$target" ] && echo "BROKEN: $link (from $f)"
    done
  done
  ```

## Size targets

If a doc grows past these, you're probably keeping bloat:

| Doc | Target | Hard ceiling |
|---|---|---|
| `README.md` | 120–200 lines (showcase: screenshots + lessons) | 250 |
| `docs/architecture.md` | 150–250 | 320 |
| `docs/operations.md` | 200–320 | 420 |
| `docs/reference.md` | 500–700 | 900 |
| `docs/evaluation.md` | 120–200 | 280 |
| `docs/decisions.md` | 100–180 | 250 |
| `docs/roadmap.md` | 100–200 | 320 |

When a doc approaches the ceiling, the usual fix is pruning postmortem detail
and phase-tag noise rather than splitting the file.
