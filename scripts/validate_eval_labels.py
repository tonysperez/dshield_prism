"""Schema validator for `eval/labels.yaml`.

Companion to `eval/RUBRIC.md` (brutal-review phase 1.2). Reads the
hand-edited YAML labels file, enforces the schema, and cross-references
against the unlabeled JSONL so missing labels and orphan labels are
caught. Run after every ~25 labels to catch drift early.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/validate_eval_labels.py \\
      --labels eval/labels.yaml \\
      --unlabeled eval/sessions.unlabeled.jsonl.gz
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

import yaml
from eval_jsonl import open_jsonl

# Closed vocabulary for `expected_findings`. Mirrors the kinds emitted
# by src/enrich/findings/{discovery,drift}.py at the time the rubric
# was written. Keep this in sync when new finding kinds ship — the
# validator is the single source of truth for the eval set.
KNOWN_FINDING_KINDS = frozenset({
    # discovery.py
    "new_playbook",
    "intel_verdict_flip",
    "ip_behavior_shift",
    "outlier_burst",
    "campaign_convergence",
    # drift.py
    "playbook_command_drift",
    "playbook_sequence_drift",
    "playbook_artifact_drift",
    "playbook_geo_drift",
    "playbook_size_drift",
    "playbook_resurgence",
    "campaign_growth",
})

REQUIRED_LABEL_FIELDS = (
    "annotated", "is_real", "playbook_label",
    "expected_findings", "notes",
)


# Closed vocabulary for `playbook_label` (rubric v2). Mirrors the canonical
# table in eval/RUBRIC.md — keep the two in sync; the rubric is the prose,
# this is the enforcement. Closed because an open vocabulary let two
# compliant labeling passes over the same 160 sessions produce 11 and 12
# labels with only 5 shared, which `eval_agreement.py` scores as total
# disagreement even where the behavior calls matched. Adding a label is a
# rubric change (bump `rubric_version`), never a labeling decision.
KNOWN_PLAYBOOK_LABELS = frozenset({
    "host_recon",
    "single_command_probe",
    "iot_cli_probe",
    "credential_spray",
    "payload_fetch_exec",
    "botnet_loader",
    "cryptominer_staging",
    "inband_payload_drop",
    "dropped_binary_exec",
    "scp_upload",
    "ssh_key_chattr_persistence",
    "ssh_key_cron_persistence",
    "account_backdoor_persistence",
})

# Synonyms and form-labels observed in prior labeling passes, mapped to the
# canonical label. Used only to make the validator's error message
# actionable — none of these are accepted values.
RETIRED_LABEL_ALIASES = {
    "uploaded_payload_staging": "scp_upload",
    "uploaded_payload_execution": "dropped_binary_exec",
    "inline_payload_staging": "inband_payload_drop",
    "file_staging": "inband_payload_drop",
    "shell_escape_probe": "iot_cli_probe",
    "shell_wrapper_only": (
        "the label for whatever the wrapped commands do (it names the "
        "delivery form, not the behavior)"
    ),
}


# Strict calendar-date shape: exactly `YYYY-MM-DD`, zero-padded. We anchor
# the format with a regex *and* then parse for real-date validity, because
# `datetime.date.fromisoformat` on Python 3.11+ also accepts ISO week dates
# (`2026-W27-3`) and the compact form (`20260703`) — both of which would slip
# a non-`YYYY-MM-DD` string past a bare `fromisoformat` guard.
_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _check_provenance(sid: str, block: dict, errors: list[str]) -> None:
    """Validate the label-schema v2 fields on an annotated block.

    Called only once the caller has already confirmed ``annotated: true``
    (see ``_check_block``). ``annotator``, ``labeled_at``, and
    ``rubric_version`` are required-if-annotated (CAP-2) — a missing/null
    value here means provenance was never captured at label time, so it
    fails closed. ``boost_weight`` stays optional: absent/``None`` is fine,
    well-typed when present. Appends to ``errors``; never raises.
    """
    def err(msg: str) -> None:
        errors.append(f"{sid}: {msg}")

    bw = block.get("boost_weight")
    if bw is not None:
        # bool first: isinstance(True, int) is True, so an unguarded numeric
        # check would let `boost_weight: true` slip through as 1.0.
        if isinstance(bw, bool):
            err("boost_weight must be a number, not a boolean")
        elif not isinstance(bw, (int, float)):
            err(f"boost_weight must be a number, got {bw!r}")
        # isfinite only on float: an int is always finite, and passing a huge
        # YAML int to math.isfinite raises OverflowError (int too big to cast
        # to float) — which would escape this "never raises" helper.
        elif isinstance(bw, float) and not math.isfinite(bw):
            err(f"boost_weight must be finite, got {bw!r}")
        elif bw <= 0:
            err(f"boost_weight must be > 0 (a weight of 0 drops the sample), got {bw!r}")

    labeled_at = block.get("labeled_at")
    if labeled_at is None:
        err("labeled_at is required when annotated is true, got null/missing")
    elif not isinstance(labeled_at, str) or not _ISO_DATE_RE.fullmatch(labeled_at):
        err(f"labeled_at must be a YYYY-MM-DD date string, got {labeled_at!r}")
    else:
        try:
            datetime.date.fromisoformat(labeled_at)
        except ValueError:
            err(f"labeled_at must be a real calendar date (YYYY-MM-DD), got {labeled_at!r}")

    for f in ("annotator", "rubric_version"):
        v = block.get(f)
        if v is None:
            err(f"{f} is required when annotated is true, got null/missing")
        # str check short-circuits before .strip(), so a non-string errors
        # cleanly; .strip() rejects whitespace-only ("   ") as effectively empty.
        elif not isinstance(v, str) or not v.strip():
            err(f"{f} must be a non-empty string, got {v!r}")


def _check_block(sid: str, block: object, errors: list[str]) -> tuple[bool, str | None]:
    """Validate one label block. Returns (counts_as_filled, playbook_label_value).

    Blocks with `annotated: false` are skipped (counted as todo). When
    `annotated: true`, the full schema is enforced.
    """
    def err(msg: str) -> None:
        errors.append(f"{sid}: {msg}")

    if not isinstance(block, dict):
        err("label block must be a YAML mapping")
        return False, None

    for f in REQUIRED_LABEL_FIELDS:
        if f not in block:
            err(f"missing field {f!r}")
    if any(f"{sid}: missing field" in e for e in errors[-len(REQUIRED_LABEL_FIELDS):]):
        return False, None

    annotated = block.get("annotated")
    if not isinstance(annotated, bool):
        err("annotated must be a boolean")
        return False, None
    if annotated is False:
        # Not yet labeled — leave the rest alone. The analyst flips this
        # flag to true after filling in the block.
        return False, None

    # Provenance (required-if-annotated, CAP-2) + rare-class re-weighting
    # (boost_weight, still optional) — label-schema v2. These append errors
    # but do not change the (filled, playbook_label) return contract.
    _check_provenance(sid, block, errors)

    is_real = block.get("is_real")
    if not isinstance(is_real, bool):
        err("is_real must be a boolean")
        return False, None

    pb = block.get("playbook_label")
    notes = block.get("notes")
    ef = block.get("expected_findings")

    if not isinstance(notes, str):
        err("notes must be a string (empty string is fine)")
        return False, None

    if not isinstance(ef, list):
        err("expected_findings must be a list")
        return False, None
    seen: set[str] = set()
    for i, k in enumerate(ef):
        if not isinstance(k, str) or not k:
            err(f"expected_findings[{i}] must be a non-empty string")
            continue
        if k not in KNOWN_FINDING_KINDS:
            err(
                f"expected_findings[{i}]={k!r} is not a known finding "
                "kind (see scripts/validate_eval_labels.py "
                "KNOWN_FINDING_KINDS)"
            )
        if k in seen:
            err(f"expected_findings has duplicate entry {k!r}")
        seen.add(k)

    if is_real:
        if not isinstance(pb, str) or not pb:
            err("playbook_label must be a non-empty string when is_real=true")
        elif pb not in KNOWN_PLAYBOOK_LABELS:
            alias = RETIRED_LABEL_ALIASES.get(pb)
            if alias:
                err(f"playbook_label={pb!r} is retired — use {alias!r} "
                    "(see eval/RUBRIC.md 'Do not mint these')")
            else:
                err(f"playbook_label={pb!r} is not in the closed vocabulary "
                    "(see eval/RUBRIC.md 'Canonical labels'). Adding a label "
                    "is a rubric change: label with the closest canonical "
                    "value, explain the misfit in notes, and raise it.")
    else:
        if pb not in (None, ""):
            err("playbook_label must be null when is_real=false")
        if ef:
            err("expected_findings must be [] when is_real=false")
        if not notes.strip():
            err("notes must explain why a record is rejected (is_real=false)")
        return True, None

    return True, pb if isinstance(pb, str) else None


def _load_jsonl_session_ids(path: Path) -> set[str]:
    out: set[str] = set()
    with open_jsonl(path) as f:
        for _lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = rec.get("session_id") if isinstance(rec, dict) else None
            if isinstance(sid, str) and sid:
                out.add(sid)
    return out


def _load_jsonl_divergent_pair_ids(path: Path) -> dict[str, str]:
    """Return {session_id: divergent_pair_id} for v2 JSONLs. Empty dict
    for v1 records — they carry no pair id, so the validator's
    cross-check is a no-op there."""
    out: dict[str, str] = {}
    with open_jsonl(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            sid = rec.get("session_id")
            pid = rec.get("divergent_pair_id")
            if isinstance(sid, str) and sid and isinstance(pid, str) and pid:
                out[sid] = pid
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--labels", type=Path,
        default=Path("eval/labels.yaml"),
        help="Hand-edited YAML labels file",
    )
    ap.add_argument(
        "--unlabeled", type=Path,
        default=Path("eval/sessions.unlabeled.jsonl.gz"),
        help=(
            "Unlabeled JSONL — used to detect orphan labels (in YAML "
            "but not in JSONL) and missing labels (in JSONL but not "
            "in YAML). Omit to skip the cross-check."
        ),
    )
    ap.add_argument(
        "--min-records", type=int, default=0,
        help=(
            "Fail if the count of *filled* label blocks (is_real=false, "
            "or is_real=true + non-empty playbook_label) is below this."
        ),
    )
    args = ap.parse_args()

    if not args.labels.exists():
        print(f"[ERROR] missing labels file: {args.labels}", file=sys.stderr)
        return 1

    data = yaml.safe_load(args.labels.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        print("[ERROR] labels YAML must be a top-level mapping "
              "{session_id: {…}}", file=sys.stderr)
        return 1

    errors: list[str] = []
    pb_counts: Counter = Counter()
    finding_counts: Counter = Counter()
    filled = 0
    todo = 0

    for sid, block in data.items():
        if not isinstance(sid, str) or not sid:
            errors.append(f"top-level key {sid!r} must be a non-empty string")
            continue
        was_filled, pb = _check_block(sid, block, errors)
        if was_filled:
            filled += 1
            if isinstance(block, dict):
                if pb:
                    pb_counts[pb] += 1
                elif block.get("is_real") is False:
                    pb_counts["__rejected__"] += 1
                for k in block.get("expected_findings") or []:
                    finding_counts[k] += 1
        else:
            todo += 1

    orphans: list[str] = []
    missing: list[str] = []
    divergent_pair_ids: dict[str, str] = {}
    if args.unlabeled and args.unlabeled.exists():
        sid_jsonl = _load_jsonl_session_ids(args.unlabeled)
        sid_yaml = set(data)
        orphans = sorted(sid_yaml - sid_jsonl)
        missing = sorted(sid_jsonl - sid_yaml)
        if missing:
            errors.append(
                f"{len(missing)} session(s) present in {args.unlabeled.name} "
                "have no block in the YAML; re-run scripts/render_eval_set.py "
                "to add the missing skeletons. First few: "
                + ", ".join(missing[:5])
            )

        # v2 cross-check: every session that carries `divergent_pair_id`
        # in the unlabeled JSONL must have an identical id in its label
        # block. Catches drift between the picks-driven build and the
        # hand-edited YAML.
        divergent_pair_ids = _load_jsonl_divergent_pair_ids(args.unlabeled)
        for sid, expected_pid in divergent_pair_ids.items():
            block = data.get(sid)
            if not isinstance(block, dict):
                continue
            yaml_pid = block.get("divergent_pair_id")
            if yaml_pid is None:
                errors.append(
                    f"{sid}: JSONL carries divergent_pair_id={expected_pid!r} "
                    f"but the YAML block is missing the field — re-run "
                    f"scripts/render_eval_set.py to repopulate it."
                )
                continue
            if not isinstance(yaml_pid, str) or not yaml_pid:
                errors.append(
                    f"{sid}: divergent_pair_id must be a non-empty string, "
                    f"got {yaml_pid!r}"
                )
                continue
            if yaml_pid != expected_pid:
                errors.append(
                    f"{sid}: divergent_pair_id mismatch — JSONL "
                    f"{expected_pid!r} vs YAML {yaml_pid!r}"
                )

    if errors:
        print("Errors:", file=sys.stderr)
        for e in errors[:50]:
            print(f"  {e}", file=sys.stderr)
        if len(errors) > 50:
            print(f"  ... and {len(errors) - 50} more", file=sys.stderr)

    total = len(data)
    print(f"\nlabels file       : {args.labels}")
    print(f"total blocks      : {total}")
    print(f"filled            : {filled}")
    print(f"todo (skeleton)   : {todo}")
    print(f"rejected          : {pb_counts.get('__rejected__', 0)}")
    print(f"distinct labels   : {len([k for k in pb_counts if k != '__rejected__'])}")
    if orphans:
        print(f"orphan blocks     : {len(orphans)} (in YAML, not in JSONL)")
        print(f"  first few       : {', '.join(orphans[:5])}")
    if finding_counts:
        print("expected findings :")
        for k, v in sorted(finding_counts.items(), key=lambda kv: -kv[1]):
            print(f"  {v:4d}  {k}")

    if divergent_pair_ids:
        # v2-only summary: how many pairs are fully labeled (both members
        # annotated). Pair-incomplete blocks don't fail the gate — the
        # analyst may be mid-labeling — but the count surfaces progress.
        members_by_pair: dict[str, list[bool]] = {}
        for sid, pid in divergent_pair_ids.items():
            block = data.get(sid) or {}
            annotated = bool(block.get("annotated"))
            members_by_pair.setdefault(pid, []).append(annotated)
        complete = sum(1 for vs in members_by_pair.values() if all(vs) and len(vs) == 2)
        partial = sum(
            1 for vs in members_by_pair.values()
            if any(vs) and not (all(vs) and len(vs) == 2)
        )
        print(
            f"divergent pairs   : {len(members_by_pair)} total, "
            f"{complete} fully annotated, {partial} partially annotated"
        )

    if errors:
        return 1
    if args.min_records and filled < args.min_records:
        print(
            f"\n[ERROR] {filled} filled blocks < required minimum {args.min_records}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
