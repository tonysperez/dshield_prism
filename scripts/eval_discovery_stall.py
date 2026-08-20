#!/usr/bin/env python
"""Track whether corpus discovery (new-playbook minting) has stalled.

A read-only, aggregate-only wrapper around ``eval_novel_pool.py``'s deployed-τ
row. It extracts five scalar fields (``generated_at``, ``n_sessions``,
``n_anchors``, ``novel_rate``, ``playbook_groups``), optionally appends them as
one JSONL line to an operator-owned local history file, and compares the
current sample against a trailing window of prior samples to flag
``anchor_growth_stalled``: corpus size growing while anchor/group counts stay
flat.

This script never touches Elasticsearch directly. Live mode delegates to
``eval_novel_pool.load_config`` / ``make_client`` / ``load_public_inputs`` /
``analyze``, which already own the public-only filter and the
``--confirm-mixed-derived-anchors`` gate. Offline mode reads a saved
``eval_novel_pool.py`` JSON report from disk, so smoke tests need no ES.

    console/.venv/bin/python scripts/eval_discovery_stall.py \
      --live --confirm-mixed-derived-anchors \
      --history eval/discovery-stall-history.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Sibling-script import; path prepended above (precedent: eval_novel_pool.py).
import eval_novel_pool
from eval_jsonl import iter_jsonl, open_jsonl

DEFAULT_STALL_WINDOW = 4
STATUS_INSUFFICIENT_HISTORY = "insufficient_history"
STATUS_ANCHOR_GROWTH_STALLED = "anchor_growth_stalled"
STATUS_OK = "ok"


def extract_snapshot(report: dict) -> dict:
    """Pull the 5-field aggregate-only snapshot out of an ``eval_novel_pool``
    report: ``generated_at``/``n_sessions``/``n_anchors`` from the report
    itself, plus ``novel_rate``/``playbook_groups`` from the single deployed
    row. Raises ``ValueError`` (never a raw ``KeyError``) on any missing
    field so callers can catch one exception type uniformly.
    """
    if not isinstance(report, dict):
        raise ValueError(f"report must be a JSON object, got {type(report).__name__}")
    rows = report.get("rows")
    if not rows:
        raise ValueError("report has no 'rows'")
    deployed = [row for row in rows if row.get("deployed")]
    if len(deployed) != 1:
        raise ValueError(f"report must have exactly one deployed row, found {len(deployed)}")
    row = deployed[0]
    try:
        return {
            "generated_at": report["generated_at"],
            "n_sessions": report["n_sessions"],
            "n_anchors": report["n_anchors"],
            "novel_rate": row["novel_rate"],
            "playbook_groups": row["novel_pool_shape"]["playbook_groups"],
        }
    except KeyError as exc:
        raise ValueError(f"report missing field {exc}") from exc


def append_snapshot(current: dict, history_path: Path) -> None:
    """Append one JSON line to the operator-owned local history file."""
    with open_jsonl(history_path, "at") as fh:
        fh.write(json.dumps(current, sort_keys=True) + "\n")


def evaluate_history(
    current: dict, history_path: Path | None, *, stall_window: int,
) -> str:
    """Compare ``current`` against a trailing window of prior history entries.

    Fewer than 2 prior entries: ``insufficient_history`` (the frozen matrix's
    "zero or one comparable prior snapshot"). Otherwise the baseline is the
    oldest entry inside the trailing ``stall_window``-entry window of prior
    entries -- not the all-time-first entry -- so the detector can re-arm
    after any period of healthy growth.
    """
    if history_path is None:
        return STATUS_INSUFFICIENT_HISTORY
    prior_entries = list(iter_jsonl(history_path)) if history_path.exists() else []
    if len(prior_entries) < 2:
        return STATUS_INSUFFICIENT_HISTORY
    window = prior_entries[-min(stall_window, len(prior_entries)):]
    oldest = window[0]
    stalled = (
        current["n_sessions"] > oldest["n_sessions"]
        and current["n_anchors"] <= oldest["n_anchors"]
        and current["playbook_groups"] <= 2
    )
    return STATUS_ANCHOR_GROWTH_STALLED if stalled else STATUS_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="run eval_novel_pool live")
    mode.add_argument("--report", type=str, help="path to a saved eval_novel_pool JSON report")
    parser.add_argument(
        "--confirm-mixed-derived-anchors",
        action="store_true",
        help="required with --live; confirms use of mixed-classification-derived anchors",
    )
    parser.add_argument("--history", type=str, default=None, help="path to the JSONL history file")
    parser.add_argument(
        "--stall-window",
        type=int,
        default=DEFAULT_STALL_WINDOW,
        help=f"trailing-window size for the stall comparison (default {DEFAULT_STALL_WINDOW})",
    )
    parser.add_argument("--config", default=None, help="passed through to eval_novel_pool in --live mode")
    return parser


def _validate_stall_window(parser: argparse.ArgumentParser, stall_window: int) -> None:
    # Python slices `list[-0:]` as the *whole* list, not an empty window, so
    # `--stall-window 0` would silently compare against the all-time-first
    # entry again -- exactly the bug this window was built to fix.
    if stall_window < 1:
        parser.error("--stall-window must be >= 1")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _validate_stall_window(parser, args.stall_window)

    if args.live and not args.confirm_mixed_derived_anchors:
        parser.error(
            "live execution requires operator confirmation: "
            "--confirm-mixed-derived-anchors",
        )

    if args.live:
        try:
            cfg = eval_novel_pool.load_config(args.config)
            es = eval_novel_pool.make_client(
                cfg.elasticsearch, eval_novel_pool.load_secrets(args.config),
            )
            inputs = eval_novel_pool.load_public_inputs(es, cfg)
            report = eval_novel_pool.analyze(inputs, cfg, eval_novel_pool.DEFAULT_TAUS)
        except (RuntimeError, ValueError) as exc:
            print(f"eval_discovery_stall: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            report = json.loads(Path(args.report).read_text())
        except (json.JSONDecodeError, OSError) as exc:
            print(f"eval_discovery_stall: {exc}", file=sys.stderr)
            return 2

    try:
        current = extract_snapshot(report)
    except ValueError as exc:
        print(f"eval_discovery_stall: {exc}", file=sys.stderr)
        return 2

    history_path = Path(args.history) if args.history else None
    status = evaluate_history(current, history_path, stall_window=args.stall_window)

    print(json.dumps({"current": current, "status": status}, indent=2, sort_keys=True))

    if history_path is not None:
        try:
            append_snapshot(current, history_path)
        except OSError as exc:
            print(f"eval_discovery_stall: could not append history snapshot: {exc}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
