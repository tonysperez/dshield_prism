"""Render divergent-candidate pairs into per-pair triage markdown.

Slots between ``mine_divergent_candidates.py`` and
``build_eval_set.py --mode picks``. Each candidate pair gets one file
under ``eval/divergent-pairs/<pair_id>.md`` carrying:

  * A YAML frontmatter block with the **triage decision** —
    ``decision: pending`` on first render, edited to ``keep`` or
    ``skip`` by the analyst (or the ``picks-triage-prompt.md`` LLM
    agent) with a 1-2 sentence ``notes:`` justification.
  * The rendered body — bucket summary, triage rules, then both
    sessions in full (command stream, login attempts, intel) using
    the same ``_render_session`` template ``render_eval_set.py`` uses
    for v1.

The MD file is the **source of truth** for the triage decision. There
is no separate picks YAML — ``build_eval_set.py --mode picks`` scans
this directory directly and builds the v2 JSONL from pairs whose
frontmatter says ``decision: keep``.

Workflow position:

    mine_divergent_candidates.py
       │
       └─→ eval/divergent-candidates.jsonl   (each pair stamped with pair_id)
              │
              ▼
    render_divergent_candidates.py  (this script)
       │
       └─→ eval/divergent-pairs/<pair_id>.md  (frontmatter: decision=pending)
              │
              ▼
    [analyst, or LLM via eval/picks-triage-prompt.md]
       edits each MD's frontmatter: decision → keep|skip, notes → …
              │
              ▼
    build_eval_set.py --mode picks
       │   (reads MD frontmatter, builds v2 JSONL from kept pairs)
       ▼
    eval/sessions-v2.unlabeled.jsonl
       │
       ▼
    render_eval_set.py  +  labels-v2.yaml  (existing v1 pipeline)

**Idempotency.** Re-running this script:
  * preserves the ``decision`` and ``notes`` of any existing MD whose
    frontmatter is intact (analyst / agent edits survive corpus
    re-renders);
  * refreshes the body (intel updates, new file events, etc.);
  * deletes MDs for pair_ids that are no longer in
    ``divergent-candidates.jsonl`` — those are stale candidates the
    miner dropped on the next pass.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/render_divergent_candidates.py
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

# Sibling-script imports. These scripts live next to each other in
# scripts/ and share the eval-set pipeline contract; re-using their
# helpers keeps the rendered pair markdown byte-identical to what the
# downstream v2 labeling step (render_eval_set.py) produces.
from build_eval_set import (  # type: ignore
    _build_record,
    _load_playbook_sizes,
    _fetch_rollups_by_session_id,
)
from render_eval_set import _render_session  # type: ignore

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Frontmatter handling
# ---------------------------------------------------------------------------

# Matches a YAML frontmatter block at the top of a markdown file.
# Greedy `.*?` + `re.DOTALL` so the block boundary is the first `\n---\n`
# (or end-of-file `---`). Single source of truth for parsing the agent's
# edits — the build step uses the same regex.
_FRONTMATTER_RE = re.compile(
    r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)",
    re.DOTALL,
)

_ALLOWED_DECISIONS = ("pending", "keep", "skip")


def _parse_frontmatter(text: str) -> dict | None:
    """Return the parsed frontmatter dict, or None when the file has no
    leading frontmatter block (corrupt MD, hand-deleted, etc.)."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return None
    try:
        blob = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        return None
    return blob if isinstance(blob, dict) else None


def _load_existing_decision(md_path: Path) -> tuple[str, str]:
    """When an MD already exists on disk, return its preserved
    ``(decision, notes)`` so re-rendering doesn't clobber the analyst's
    work. Falls back to ``("pending", "")`` on first render."""
    if not md_path.exists():
        return ("pending", "")
    fm = _parse_frontmatter(md_path.read_text(encoding="utf-8"))
    if not fm:
        return ("pending", "")
    decision = fm.get("decision")
    if decision not in _ALLOWED_DECISIONS:
        log.warning(
            "%s: decision=%r is not one of %s — resetting to 'pending'",
            md_path, decision, _ALLOWED_DECISIONS,
        )
        decision = "pending"
    notes = fm.get("notes")
    if not isinstance(notes, str):
        notes = ""
    return (decision, notes)


def _format_frontmatter(meta: dict, decision: str, notes: str) -> str:
    """Emit the YAML frontmatter block. Field order is fixed — humans
    scan top-to-bottom: pair id first, decision (the editable bit)
    second, notes third, contract fields after."""
    body = {
        "pair_id":       meta["pair_id"],
        "decision":      decision,
        "notes":         notes,
        "bucket_kind":   meta["bucket_kind"],
        "bucket_value":  meta["bucket_value"],
        "jaccard":       meta["jaccard"],
        "sessions":      [meta["sessions_a_id"], meta["sessions_b_id"]],
    }
    dumped = yaml.safe_dump(
        body,
        sort_keys=False, allow_unicode=True, default_flow_style=False,
    )
    return f"---\n{dumped}---\n"


# ---------------------------------------------------------------------------
# Body rendering
# ---------------------------------------------------------------------------

def _iter_candidates(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _pair_meta(p: dict) -> dict:
    """Flat-keys pre-compute from one row of divergent-candidates.jsonl."""
    a_set = set(p["session_a"]["command_set"])
    b_set = set(p["session_b"]["command_set"])
    return {
        "pair_id":          p["pair_id"],
        "bucket_kind":      p["bucket_kind"],
        "bucket_value":     p["bucket_value"],
        "jaccard":          float(p["jaccard"]),
        "sessions_a_id":    p["session_a"]["session_id"],
        "sessions_b_id":    p["session_b"]["session_id"],
        "a_unique_commands": p["session_a"]["unique_commands"],
        "b_unique_commands": p["session_b"]["unique_commands"],
        "shared_commands":   len(a_set & b_set),
        "union_commands":    len(a_set | b_set),
    }


def _pair_header_body(meta: dict) -> str:
    """The markdown body's leading block — bucket / jaccard summary
    plus the triage rules. Stable across re-renders so the agent's
    Edit calls only ever touch the frontmatter."""
    pid = meta["pair_id"]
    a = meta["sessions_a_id"]
    shared = meta["shared_commands"]
    union = meta["union_commands"]

    out: list[str] = []
    out.append(f"# Pair {pid} — Triage")
    out.append("")
    out.append(
        "> **The keep/skip decision lives in the YAML frontmatter above.** "
        "Edit `decision:` to `keep` or `skip` and add a 1-2 sentence "
        "justification in `notes:`. Do **not** modify any other "
        "frontmatter field — `build_eval_set.py --mode picks` validates them."
    )
    out.append("")
    out.append(f"- **Bucket:** `{meta['bucket_kind']}` = `{meta['bucket_value']}`")
    out.append(
        f"- **Jaccard:** {meta['jaccard']:.3f} "
        f"(sessions share {shared} of {union} unique commands "
        f"— A has {meta['a_unique_commands']}, "
        f"B has {meta['b_unique_commands']})"
    )
    out.append("")
    out.append("## Triage decision rules")
    out.append("")
    out.append(
        "Read both sessions below cold. Ignore the bucket label — it's "
        "what the miner used as the gate, and the gate is too coarse to "
        "trust on its own. Then answer: **are these two sessions the "
        "same underlying attacker behavior expressed in different text?**"
    )
    out.append("")
    out.append(
        "- **YES** → set `decision: keep`. Positive test case for the "
        "v2 metric (the embedding *should* cluster them together)."
    )
    out.append(
        "- **NO, but they share an intent** → set `decision: keep`. "
        "Negative test case: the embedding is *correct* to split them."
    )
    out.append(
        "- **JUNK** (single-command probes, corrupted session, login-"
        "only, etc.) → set `decision: skip`. Don't burn labeling budget."
    )
    out.append("")
    out.append(
        "`notes:` is required when you set `decision`. One or two "
        "sentences — the next person reading this directory six months "
        "from now will thank you."
    )
    out.append("")
    out.append("---")
    out.append("")
    out.append(f"## Session A — `{a}`")
    out.append("")
    return "\n".join(out)


def _strip_session_h1(body: str) -> str:
    """Drop ``_render_session``'s leading ``# <session_id>\\n`` so the
    per-pair markdown has a single H1 (``# Pair dp-NNN — Triage``)
    rather than three nested ones."""
    lines = body.splitlines()
    if lines and lines[0].startswith("# "):
        cut = 2 if len(lines) > 1 and lines[1] == "" else 1
        lines = lines[cut:]
    return "\n".join(lines)


def _separator_b(b_sid: str) -> str:
    return "\n".join([
        "",
        "---",
        "",
        f"## Session B — `{b_sid}`",
        "",
    ])


def _build_pair_markdown(
    meta: dict, rec_a: dict, rec_b: dict, decision: str, notes: str,
) -> str:
    fm = _format_frontmatter(meta, decision, notes)
    header = _pair_header_body(meta)
    body_a = _strip_session_h1(_render_session(rec_a))
    body_b = _strip_session_h1(_render_session(rec_b))
    return "\n".join([
        fm,
        header,
        body_a,
        _separator_b(rec_b["session_id"]),
        body_b,
    ])


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--candidates", type=Path,
                    default=Path("eval/divergent-candidates.jsonl"))
    ap.add_argument("--out-dir", type=Path,
                    default=Path("eval/divergent-pairs"))
    ap.add_argument("--no-prune", action="store_true",
                    help=(
                        "Don't delete MDs for pair_ids that are no "
                        "longer in --candidates. Useful when iterating "
                        "on the miner config without losing in-progress "
                        "triage work."
                    ))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.candidates.exists():
        print(f"[ERROR] missing {args.candidates} — run "
              f"scripts/mine_divergent_candidates.py first.", file=sys.stderr)
        return 1

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)
    cowrie_idx = cfg.elasticsearch.indexes.cowrie
    rollup_idx = cowrie_idx.sessions_rollup
    raw_idx    = cowrie_idx.sessions_raw
    cmd_idx    = cowrie_idx.commands
    hash_intel_idx = cfg.intel.indexes.hash
    url_intel_idx  = cfg.intel.indexes.url

    pairs = list(_iter_candidates(args.candidates))
    if not pairs:
        print(f"[ERROR] {args.candidates} is empty", file=sys.stderr)
        return 1

    expected_pair_ids: set[str] = set()
    unique_sids: set[str] = set()
    for p in pairs:
        pid = p.get("pair_id")
        if not isinstance(pid, str) or not pid:
            print(
                f"[ERROR] candidate without pair_id encountered "
                f"(re-run mine_divergent_candidates.py): {p!r}",
                file=sys.stderr,
            )
            return 1
        expected_pair_ids.add(pid)
        unique_sids.add(p["session_a"]["session_id"])
        unique_sids.add(p["session_b"]["session_id"])

    log.info(
        "rendering %d pair(s), %d unique sessions",
        len(pairs), len(unique_sids),
    )

    # Fetch every candidate session's rollup once, then per-session
    # build_record fills in raw_events + command_enrichments + intel.
    playbook_sizes = _load_playbook_sizes(es, rollup_idx)
    rollups = _fetch_rollups_by_session_id(es, rollup_idx, sorted(unique_sids))
    missing = [sid for sid in unique_sids if sid not in rollups]
    if missing:
        log.warning(
            "%d session(s) referenced by candidates.jsonl are missing from %s "
            "(skipped on render): %s",
            len(missing), rollup_idx,
            ", ".join(missing[:5]) + (" …" if len(missing) > 5 else ""),
        )

    records: dict[str, dict] = {}
    for sid in unique_sids:
        rollup = rollups.get(sid)
        if rollup is None:
            continue
        rec = _build_record(
            es,
            raw_index=raw_idx,
            cmd_index=cmd_idx,
            hash_intel_index=hash_intel_idx,
            url_intel_index=url_intel_idx,
            rollup=rollup,
            playbook_sizes=playbook_sizes,
        )
        if rec is not None:
            records[sid] = rec

    args.out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped_missing = 0
    preserved = 0
    fresh = 0
    decision_counts = {"pending": 0, "keep": 0, "skip": 0}
    for p in pairs:
        meta = _pair_meta(p)
        rec_a = records.get(meta["sessions_a_id"])
        rec_b = records.get(meta["sessions_b_id"])
        if rec_a is None or rec_b is None:
            log.warning(
                "pair %s: missing session record for %s — skipping markdown",
                meta["pair_id"],
                meta["sessions_a_id"] if rec_a is None else meta["sessions_b_id"],
            )
            skipped_missing += 1
            continue
        md_path = args.out_dir / f"{meta['pair_id']}.md"
        decision, notes = _load_existing_decision(md_path)
        if decision == "pending" and not notes:
            fresh += 1
        else:
            preserved += 1
        body = _build_pair_markdown(meta, rec_a, rec_b, decision, notes)
        md_path.write_text(body, encoding="utf-8")
        written += 1
        decision_counts[decision] = decision_counts.get(decision, 0) + 1

    # Prune stale MDs. Pair ids dp-NNN are deterministic per (corpus,
    # seed), but a miner re-run with different config can drop pairs
    # from the candidate pool — those MDs would mislead the agent.
    pruned = 0
    if not args.no_prune:
        for stale_md in args.out_dir.glob("*.md"):
            if stale_md.stem not in expected_pair_ids:
                stale_md.unlink()
                pruned += 1

    print(f"rendered  : {written} pair markdown files -> {args.out_dir}/")
    print(f"           ({fresh} fresh, {preserved} preserved decisions)")
    print(
        f"decisions : pending={decision_counts['pending']}  "
        f"keep={decision_counts['keep']}  "
        f"skip={decision_counts['skip']}"
    )
    if skipped_missing:
        print(f"skipped   : {skipped_missing} pair(s) (missing rollups)")
    if pruned:
        print(f"pruned    : {pruned} stale MD(s) no longer in candidates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
