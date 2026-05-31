"""Schema validator for `eval/labels-v1.yaml`.

Companion to `eval/RUBRIC.md` (brutal-review phase 1.2). Reads the
hand-edited YAML labels file, enforces the schema, and cross-references
against the unlabeled JSONL so missing labels and orphan labels are
caught. Run after every ~25 labels to catch drift early.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/validate_eval_labels.py \\
      --labels eval/labels-v1.yaml \\
      --unlabeled eval/sessions-v1.unlabeled.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import yaml


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
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--labels", type=Path,
        default=Path("eval/labels-v1.yaml"),
        help="Hand-edited YAML labels file",
    )
    ap.add_argument(
        "--unlabeled", type=Path,
        default=Path("eval/sessions-v1.unlabeled.jsonl"),
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
