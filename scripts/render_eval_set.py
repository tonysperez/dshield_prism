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
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from eval_jsonl import open_jsonl

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
    try:
        return datetime.fromisoformat(s).replace(tzinfo=UTC) \
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
    and newline escapes."""
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
    # Stratum lives in the JSONL for downstream eval scripts but is
    # intentionally NOT rendered into per-session views — the
    # (size_band / intent / intel) bucket is partially pipeline-derived
    # and would lead the analyst toward a label before they've read
    # the session.

    # divergent_pair_id (E1.2): when present, surfaces the v2 pair id so
    # the analyst can label both members consistently. The pair_id is
    # NOT considered analyst-biasing because it carries no semantic
    # content — it's an opaque label assigned at mine-time, and both
    # members of the pair already share the same coarse behavior bucket
    # by construction (the miner's input filter).
    divergent_pair_id = rec.get("divergent_pair_id")

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
    if divergent_pair_id:
        out.append(f"- **Divergent pair:** `{divergent_pair_id}` *(label both sides consistently)*")
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

    # Analyst-rule hits are intentionally NOT rendered. The signal they
    # carry (the matched substring) is already in the command stream,
    # which both the analyst and the embedding model see. Rendering the
    # analyst's rule notes would smuggle out-of-band attribution into
    # the eval — the analyst would label on signal the embedding can't
    # use, making the pipeline look artificially bad on clustering.

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
    "expected_findings": [],
    "notes":            "",
    # Optional provenance + rare-class re-weighting (label-schema v2).
    # These MUST live in the skeleton: `_merge_labels` projects each block
    # to skeleton keys only (see the `{k: block[k] for k in skel}` merge
    # below), so a field absent here would be silently stripped on
    # re-render. The validator type-checks them only when present, so the
    # committed file (which has none) keeps validating clean until an
    # operator deliberately re-renders to backfill these defaults.
    "annotator":        None,
    "labeled_at":       None,
    "rubric_version":   None,
    "boost_weight":     1.0,
}


def _skeleton_for_record(rec: dict) -> dict:
    """Per-record label skeleton. Identical to ``_EMPTY_LABEL_BLOCK``
    for v1; for v2 records (those carrying ``divergent_pair_id``)
    appends a pre-populated ``divergent_pair_id`` field so the analyst
    doesn't have to copy the pair id from the markdown header. The
    field is part of the canonical schema for that record, so the
    merge logic round-trips it instead of dropping it as unknown."""
    skel = dict(_EMPTY_LABEL_BLOCK)
    pid = rec.get("divergent_pair_id")
    if isinstance(pid, str) and pid:
        skel["divergent_pair_id"] = pid
    return skel


def _merge_labels(
    records: list[dict], existing_path: Path,
) -> tuple[dict, int, int]:
    """Return (merged_yaml_dict, n_new_blocks, n_orphan_blocks).

    Idempotent: preserves any existing label blocks verbatim, adds empty
    blocks for new session_ids, and reports orphan blocks (session_ids
    in the yaml that no longer appear in the unlabeled JSONL) without
    deleting them — the analyst decides.

    Per-record skeleton is computed by ``_skeleton_for_record`` so the
    v2 records' ``divergent_pair_id`` becomes a canonical field for those
    blocks and survives the merge round-trip.
    """
    existing: dict = {}
    if existing_path.exists():
        text = existing_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(text) or {}
        if isinstance(parsed, dict):
            existing = parsed

    skeletons: dict[str, dict] = {}
    for rec in records:
        sid = rec.get("session_id")
        if isinstance(sid, str) and sid:
            skeletons[sid] = _skeleton_for_record(rec)

    # Contract fields are sourced from the JSONL (via the skeleton),
    # never preserved from the existing YAML — they're validated against
    # the JSONL downstream and a stale value would just fail the gate.
    # Adding to this set is how a new field joins the "always synced
    # from the JSONL" contract.
    _CONTRACT_FIELDS = ("divergent_pair_id",)

    merged: dict = {}
    new = 0
    for sid, skel in skeletons.items():
        if sid in existing and isinstance(existing[sid], dict):
            # Backfill any fields the existing block is missing (e.g.
            # `annotated` added later) and re-key in canonical order.
            # Fields outside the canonical skeleton are dropped — that's
            # how schema removals (e.g. retiring `campaign_label`) flow
            # through existing labeled blocks without manual scrubbing.
            block = dict(skel)
            block.update(existing[sid])
            # Re-apply contract fields from the skeleton after the merge
            # so a v2 rebuild with new pair_ids cleanly carries over the
            # analyst's labels without leaving stale divergent_pair_id
            # values that would fail the validator.
            for f in _CONTRACT_FIELDS:
                if f in skel:
                    block[f] = skel[f]
            merged[sid] = {k: block[k] for k in skel}
        else:
            merged[sid] = dict(skel)
            new += 1

    orphans = [s for s in existing if s not in skeletons]
    for s in orphans:
        merged[s] = existing[s]
    return merged, new, len(orphans)


def _write_labels_yaml(path: Path, data: dict, unlabeled_path: Path) -> None:
    """Write a stable, human-friendly YAML — one blank line between entries.

    The header documents the *actual* labels + unlabeled paths so the
    validator command is correct in both v1 and v2 outputs.
    """
    parts: list[str] = []
    parts.append(
        "# Eval-set labels. One block per session_id. Edit by hand and\n"
        "# flip `annotated: false -> true` when you've labeled the block.\n"
        "# The renderer preserves your edits and backfills any new fields.\n"
        "# Validate every ~25 entries with:\n"
        "#   console/.venv/bin/python scripts/validate_eval_labels.py \\\n"
        f"#     --labels {path} \\\n"
        f"#     --unlabeled {unlabeled_path}\n"
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
    with open_jsonl(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--input", type=Path,
        default=Path("eval/sessions.unlabeled.jsonl.gz"),
        help="Unlabeled JSONL from scripts/build_eval_set.py",
    )
    ap.add_argument(
        "--out-dir", type=Path,
        default=Path("eval/sessions-v1"),
        help="Per-session markdown destination",
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

    written = 0
    for rec in records:
        sid = rec.get("session_id")
        if not sid:
            continue
        body = _render_session(rec)
        (args.out_dir / f"{sid}.md").write_text(body, encoding="utf-8")
        written += 1

    merged, n_new, n_orphan = _merge_labels(records, args.labels_yaml)
    _write_labels_yaml(args.labels_yaml, merged, args.input)

    print(f"rendered  : {written} sessions -> {args.out_dir}/")
    print(f"labels    : {args.labels_yaml} "
          f"(new blocks: {n_new}, orphan blocks preserved: {n_orphan})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
