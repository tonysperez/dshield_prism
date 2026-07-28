"""Render the unlabeled eval set into per-session markdown for human labeling.

Companion to `scripts/build_eval_set.py` (brutal-review phase 1.2). The
JSONL file the build script emits is dense and not analyst-readable;
this script turns it into one markdown file per session under
``eval/sessions/<session_id>.md`` plus an index and a fresh-or-
preserved ``eval/labels.yaml`` skeleton the analyst fills in.

Idempotent: re-rendering preserves any labels already present in
``labels.yaml`` and only adds empty blocks for newly-introduced
session ids. Re-rendering overwrites the markdown files (cheap; they
are pure projections of the JSONL).

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/render_eval_set.py
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


# ---------------------------------------------------------------------------
# Field accessors
# ---------------------------------------------------------------------------

def _dig(d: Any, *path: str) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _enrichment_section(rollup: dict) -> dict:
    return _dig(rollup, "dshield", "cowrie", "enrichment", "session") or {}


def _parse_ts(ts: str | None) -> datetime | None:
    if not isinstance(ts, str):
        return None
    s = ts.rstrip("Z")
    # ES emits "...Z" or "...+00:00"; tolerate both.
    try:
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc) \
            if "+" not in s else datetime.fromisoformat(s)
    except ValueError:
        return None


def _fmt_offset(start: datetime | None, ts: datetime | None) -> str:
    if start is None or ts is None:
        return "      ?"
    delta = (ts - start).total_seconds()
    if delta < 0:
        delta = 0.0
    m, s = divmod(delta, 60)
    return f"+{int(m):02d}:{s:05.2f}"


def _md_cell(s: object) -> str:
    """Escape a string for a markdown table cell. No length truncation —
    the analyst needs the full text to label honestly. Cells get pipe
    and newline escapes; literal backticks are doubled so an embedded
    backtick doesn't close the inline-code span."""
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _fmt_intel(doc: dict | None) -> str:
    """Render an intel doc (prism.intel.{ip,url,hash}) into a one-cell
    summary: consensus label + provider counts + override + tags.
    Returns empty string when no doc / no signal."""
    if not isinstance(doc, dict):
        return ""
    derived = doc.get("derived") or {}
    if not derived:
        return ""
    label = derived.get("consensus_label") or (
        "malicious" if derived.get("consensus_malicious") else None
    ) or "—"
    mc = derived.get("malicious_provider_count", 0)
    cc = derived.get("clean_provider_count", 0)
    override = derived.get("override_applied")
    tags = derived.get("tags") or []
    parts = [f"`{label}`", f"mal={mc}", f"clean={cc}"]
    if override:
        parts.append(f"override=`{override}`")
    if tags:
        parts.append("tags: " + ", ".join(f"`{t}`" for t in tags[:5]))
        if len(tags) > 5:
            parts.append(f"(+{len(tags)-5})")
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _bucket_raw_events(raw_events: list[dict]) -> dict[str, list[dict]]:
    """Split raw_events by ``event.action`` so each render section pulls
    from the exact subset it needs."""
    by_action: dict[str, list[dict]] = defaultdict(list)
    for e in raw_events:
        action = _dig(e, "event", "action")
        if isinstance(action, str):
            by_action[action].append(e)
    return by_action


def _render_session(rec: dict) -> str:
    sid = rec.get("session_id") or "?"
    # Stratum lives in the JSONL + the index page, but is intentionally
    # NOT rendered into per-session views — the (size_band / intent /
    # intel) bucket is partially pipeline-derived and would lead the
    # analyst toward a label before they've read the session.

    rollup = rec.get("rollup_doc") or {}
    enrichment = _enrichment_section(rollup)
    raw_events = rec.get("raw_events") or []
    by_action = _bucket_raw_events(raw_events)

    cmd_events = by_action.get("cowrie.command.input", []) \
        + by_action.get("cowrie.command.failed", [])
    cmd_events.sort(key=lambda e: _dig(e, "@timestamp") or "")
    login_success = by_action.get("cowrie.login.success", [])
    login_failed  = by_action.get("cowrie.login.failed", [])
    file_dl = by_action.get("cowrie.session.file_download", [])
    file_ul = by_action.get("cowrie.session.file_upload", [])
    client_ver = by_action.get("cowrie.client.version", [])

    ts_values = [_parse_ts(_dig(e, "@timestamp")) for e in raw_events]
    ts_values = [t for t in ts_values if t is not None]
    start = min(ts_values) if ts_values else None
    end = max(ts_values) if ts_values else None
    duration = (end - start).total_seconds() if start and end else None

    src_ip = _dig(rollup, "source", "ip") or "?"
    geo_country = _dig(rollup, "source", "geo", "country_name") or ""
    geo_city = _dig(rollup, "source", "geo", "city_name") or ""
    asn = _dig(rollup, "source", "as", "number")
    asn_org = _dig(rollup, "source", "as", "organization", "name") or ""
    hassh = _dig(rollup, "cowrie", "hassh")
    ssh_banner = _dig(client_ver[0], "user_agent", "original") if client_ver else None

    out: list[str] = []

    # ----- header ----------------------------------------------------------
    out.append(f"# {sid}")
    out.append("")
    geo_bits: list[str] = []
    if geo_city:    geo_bits.append(geo_city)
    if geo_country: geo_bits.append(geo_country)
    geo_str = ", ".join(geo_bits) if geo_bits else "(unknown)"
    asn_str = f"AS{asn} {asn_org}".strip() if asn else (asn_org or "(unknown)")
    out.append(f"- **Source IP:** `{src_ip}` — {geo_str} — {asn_str}")
    if ssh_banner:
        out.append(f"- **SSH client banner:** `{ssh_banner}`")
    if hassh:
        out.append(f"- **HASSH:** `{hassh}`")
    if start:
        win = f"`{start.isoformat()}`"
        if end and end != start:
            win = f"`{start.isoformat()}` → `{end.isoformat()}`"
            if duration is not None:
                win += f"  (~{duration:.1f}s)"
        out.append(f"- **Window:** {win}")
    out.append("")

    # ----- rollup (structural only, no LLM-derived intent/etc) ------
    # playbook_id is also omitted: it's the clustering output, which is
    # exactly what the eval set grades. Showing it would let the analyst
    # ride the pipeline's grouping instead of forming an independent
    # judgement on the session's contents.
    out.append("## Rollup")
    out.append("")
    cc = enrichment.get("command_count") or 0
    uc = enrichment.get("unique_commands") or 0
    entropy = enrichment.get("command_entropy")
    cmd_line = f"- **commands:** {cc} total ({uc} unique)"
    if entropy is not None:
        cmd_line += f" · entropy {entropy:.2f}"
    out.append(cmd_line)
    mn = enrichment.get("mean_novelty_score")
    mx = enrichment.get("max_novelty_score")
    if mn is not None:
        nov = f"- **novelty_score:** mean {mn:.3f}"
        if mx is not None:
            nov += f" · max {mx:.3f}"
        nov += "  *(corpus-relative; limited use disconnected from source corpus)*"
        out.append(nov)

    intel_block = enrichment.get("source_ip_intel") or {}
    if intel_block:
        label = intel_block.get("consensus_label") or "—"
        out.append(
            f"- **intel:** `{label}` · "
            f"malicious={intel_block.get('malicious_provider_count', 0)} · "
            f"clean={intel_block.get('clean_provider_count', 0)} · "
            f"override={intel_block.get('override_applied') or '—'}"
        )
    else:
        out.append("- **intel:** *(no source_ip_intel block on rollup)*")
    out.append("")

    # ----- login attempts (credentials) -----------------------------------
    out.append("## Login attempts")
    out.append("")
    out.append(f"{len(login_success)} successful · {len(login_failed)} failed")
    if login_success or login_failed:
        out.append("")
        out.append("| outcome | user | password |")
        out.append("|---|---|---|")
        for e in login_success:
            out.append(
                f"| success | `{_md_cell(_dig(e, 'user', 'name') or '')}` "
                f"| `{_md_cell(_dig(e, 'cowrie', 'password') or '')}` |"
            )
        for e in login_failed:
            out.append(
                f"| failed | `{_md_cell(_dig(e, 'user', 'name') or '')}` "
                f"| `{_md_cell(_dig(e, 'cowrie', 'password') or '')}` |"
            )
    out.append("")

    # ----- command stream — raw text, no enrichment, no truncation --------
    out.append("## Command stream")
    out.append("")
    if not cmd_events:
        out.append("*(no command activity — login attempts only)*")
        out.append("")
    else:
        out.append("| # | offset | action | command_line |")
        out.append("|---:|---|---|---|")
        for i, ev in enumerate(cmd_events, start=1):
            cmd = _dig(ev, "process", "command_line") or ""
            ts = _parse_ts(_dig(ev, "@timestamp"))
            offset = _fmt_offset(start, ts)
            action = (_dig(ev, "event", "action") or "").replace("cowrie.command.", "")
            out.append(
                f"| {i} | `{offset}` | `{action}` | `{_md_cell(cmd)}` |"
            )
        out.append("")

    # ----- file events (uploads + downloads from raw stream) --------------
    file_events = sorted(
        file_dl + file_ul,
        key=lambda e: _dig(e, "@timestamp") or "",
    )
    hash_intel = rec.get("hash_intel") or {}
    url_intel = rec.get("url_intel") or {}
    if file_events:
        out.append("## File events")
        out.append("")
        out.append(
            "| offset | action | sha256 | destfile | source url "
            "| hash intel | url intel |"
        )
        out.append("|---|---|---|---|---|---|---|")
        for ev in file_events:
            action = (_dig(ev, "event", "action") or "") \
                .replace("cowrie.session.", "")
            ts = _parse_ts(_dig(ev, "@timestamp"))
            offset = _fmt_offset(start, ts)
            sha = _dig(ev, "file", "hash", "sha256") \
                or _dig(ev, "cowrie", "shasum") or ""
            destfile = _dig(ev, "cowrie", "destfile") \
                or _dig(ev, "file", "name") or ""
            url = _dig(ev, "cowrie", "url") or _dig(ev, "url", "full") or ""
            hi = _fmt_intel(hash_intel.get((sha or "").lower()))
            ui = _fmt_intel(url_intel.get(url)) if url else ""
            out.append(
                f"| `{offset}` | `{action}` | `{_md_cell(sha)}` "
                f"| `{_md_cell(destfile)}` | `{_md_cell(url)}` "
                f"| {_md_cell(hi)} | {_md_cell(ui)} |"
            )
        out.append("")

    # ----- artifact_set from rollup (structural IOCs only) ---------------
    # `analyst:<kind>:<value>` entries are dropped here — they get a
    # dedicated section below with rule notes joined in. Listing them in
    # both places would just duplicate the analyst-rule hits.
    artifacts = [
        a for a in (enrichment.get("artifact_set") or [])
        if not (isinstance(a, str) and a.startswith("analyst:"))
    ]
    if artifacts:
        out.append(f"## Artifacts ({len(artifacts)})")
        out.append("")
        out.append("| kind | value |")
        out.append("|---|---|")
        for a in artifacts:
            if isinstance(a, str) and ":" in a:
                kind, _, value = a.partition(":")
            else:
                kind, value = "(unknown)", a if isinstance(a, str) else ""
            out.append(f"| `{_md_cell(kind)}` | `{_md_cell(value)}` |")
        out.append("")

    # ----- analyst-authored artifacts (rule matches; not LLM-derived) -----
    # Aggregate from both sources:
    #   - rollup.analyst_artifacts (session-level; often empty — the
    #     session-aggregator unions hits into the flat artifact_set
    #     strings, not this nested array)
    #   - each command_enrichments[].dshield.cowrie.enrichment.analyst_artifacts
    #     (per-command; this IS where the structured rule_id lives)
    # Dedup by (kind, value, rule_id) so a rule that fires on N commands
    # in the same session shows up once.
    rules = rec.get("rules") or {}
    analyst_arts_session = enrichment.get("analyst_artifacts") or []
    analyst_arts_all: list[dict] = list(analyst_arts_session)
    for cmd_doc in rec.get("command_enrichments") or []:
        for a in (
            ((cmd_doc.get("dshield") or {}).get("cowrie") or {})
            .get("enrichment") or {}
        ).get("analyst_artifacts") or []:
            analyst_arts_all.append(a)
    seen_keys: set[tuple] = set()
    deduped: list[dict] = []
    for a in analyst_arts_all:
        key = (a.get("kind"), a.get("value"), a.get("rule_id"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(a)
    if deduped:
        out.append("## Analyst artifacts")
        out.append("")
        out.append("| kind | value | rule kind | rule notes |")
        out.append("|---|---|---|---|")
        for a in deduped:
            rule = rules.get(a.get("rule_id") or "") or {}
            rule_kind = rule.get("kind") or ""
            notes     = rule.get("notes") or ""
            out.append(
                f"| `{_md_cell(a.get('kind') or '?')}` "
                f"| `{_md_cell(a.get('value') or '')}` "
                f"| `{_md_cell(rule_kind)}` "
                f"| {_md_cell(notes)} |"
            )
        out.append("")

    return "\n".join(out)


def _render_index(records: list[dict]) -> str:
    """Index page grouped by stratum so the analyst can plan coverage."""
    by_band: dict[str, list[dict]] = {}
    for r in records:
        band = (r.get("stratum") or {}).get("size_band") or "unknown"
        by_band.setdefault(band, []).append(r)
    bands_order = ["large", "medium", "small", "solo", "unattributed"]
    out = ["# Eval set index", "",
           f"Total sessions: **{len(records)}**.",
           "", "Click a session_id to open its rendered view; label "
           "decisions go into [`labels.yaml`](labels.yaml) "
           "per [`RUBRIC.md`](RUBRIC.md).", ""]
    seen_bands = set(by_band.keys())
    for band in bands_order + [b for b in seen_bands if b not in bands_order]:
        if band not in by_band:
            continue
        bucket = by_band[band]
        out.append(f"## `{band}` — {len(bucket)} sessions")
        out.append("")
        out.append("| session_id | intent | intel | cmds | files | artifacts |")
        out.append("|---|---|---|---:|---:|---:|")
        for r in sorted(bucket, key=lambda x: x.get("session_id", "")):
            sid = r.get("session_id") or "?"
            strat = r.get("stratum") or {}
            enr = _enrichment_section(r.get("rollup_doc") or {})
            cc = enr.get("command_count") or 0
            fe = len(enr.get("file_events") or [])
            art = len(enr.get("artifact_set") or [])
            out.append(
                f"| [{sid}](sessions/{sid}.md) "
                f"| `{strat.get('intent') or '?'}` "
                f"| `{strat.get('intel') or '?'}` "
                f"| {cc} | {fe} | {art} |"
            )
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# labels.yaml round-trip
# ---------------------------------------------------------------------------

# Default skeleton block. Order matters: `annotated` is first so the
# analyst's eye lands on the flag to flip; `is_real` next because that's
# the gating decision; labels follow. Once `annotated: true`, the
# validator enforces the full schema.
_EMPTY_LABEL_BLOCK = {
    "annotated":        False,
    "is_real":          True,
    "playbook_label":   None,
    "campaign_label":   None,
    "expected_findings": [],
    "notes":            "",
}


def _merge_labels(
    session_ids: list[str], existing_path: Path,
) -> tuple[dict, int, int]:
    """Return (merged_yaml_dict, n_new_blocks, n_orphan_blocks).

    Idempotent: preserves any existing label blocks verbatim, adds empty
    blocks for new session_ids, and reports orphan blocks (session_ids
    in the yaml that no longer appear in the unlabeled JSONL) without
    deleting them — the analyst decides.
    """
    existing: dict = {}
    if existing_path.exists():
        text = existing_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(text) or {}
        if isinstance(parsed, dict):
            existing = parsed

    merged: dict = {}
    new = 0
    for sid in session_ids:
        if sid in existing and isinstance(existing[sid], dict):
            # Backfill any fields the existing block is missing (e.g. an
            # old file from before `annotated` was added). User-set values
            # always win — we only fill where the key is absent.
            block = dict(_EMPTY_LABEL_BLOCK)
            block.update(existing[sid])
            # Re-key in canonical order so the file reads consistently
            # after every render. Unknown extra keys at the tail are kept.
            ordered = {k: block[k] for k in _EMPTY_LABEL_BLOCK if k in block}
            for k, v in block.items():
                if k not in ordered:
                    ordered[k] = v
            merged[sid] = ordered
        else:
            merged[sid] = dict(_EMPTY_LABEL_BLOCK)
            new += 1

    orphans = [s for s in existing if s not in set(session_ids)]
    for s in orphans:
        merged[s] = existing[s]
    return merged, new, len(orphans)


def _write_labels_yaml(path: Path, data: dict) -> None:
    """Write a stable, human-friendly YAML — one blank line between entries."""
    parts: list[str] = []
    parts.append(
        "# Eval-set labels. One block per session_id. Edit by hand and\n"
        "# flip `annotated: false -> true` when you've labeled the block.\n"
        "# The renderer preserves your edits and backfills any new fields.\n"
        "# Validate every ~25 entries with:\n"
        "#   console/.venv/bin/python scripts/validate_eval_labels.py \\\n"
        "#     --labels eval/labels.yaml \\\n"
        "#     --unlabeled eval/sessions.unlabeled.jsonl\n"
        "# Rubric: ./RUBRIC.md\n"
    )
    for sid, block in data.items():
        body = yaml.safe_dump(
            {sid: block},
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )
        parts.append(body.rstrip() + "\n")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _read_jsonl(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--input", type=Path,
        default=Path("eval/sessions.unlabeled.jsonl"),
        help="Unlabeled JSONL from scripts/build_eval_set.py",
    )
    ap.add_argument(
        "--out-dir", type=Path,
        default=Path("eval/sessions-v1"),
        help="Per-session markdown destination",
    )
    ap.add_argument(
        "--index", type=Path,
        default=Path("eval/sessions-v1.index.md"),
        help="Where to write the index page",
    )
    ap.add_argument(
        "--labels-yaml", type=Path,
        default=Path("eval/labels.yaml"),
        help="Round-tripped YAML labels file (idempotent merge)",
    )
    args = ap.parse_args()

    if not args.input.exists():
        print(f"[ERROR] missing input: {args.input}", file=sys.stderr)
        print("Run `scripts/build_eval_set.py` first.", file=sys.stderr)
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)

    records = list(_read_jsonl(args.input))
    if not records:
        print(f"[ERROR] {args.input} is empty", file=sys.stderr)
        return 1
    session_ids = [r.get("session_id") for r in records if r.get("session_id")]

    written = 0
    for rec in records:
        sid = rec.get("session_id")
        if not sid:
            continue
        body = _render_session(rec)
        (args.out_dir / f"{sid}.md").write_text(body, encoding="utf-8")
        written += 1

    args.index.write_text(_render_index(records), encoding="utf-8")

    merged, n_new, n_orphan = _merge_labels(session_ids, args.labels_yaml)
    _write_labels_yaml(args.labels_yaml, merged)

    print(f"rendered  : {written} sessions -> {args.out_dir}/")
    print(f"index     : {args.index}")
    print(f"labels    : {args.labels_yaml} "
          f"(new blocks: {n_new}, orphan blocks preserved: {n_orphan})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
