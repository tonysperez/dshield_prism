"""Audit a labelling pass for selection-channel bias (E3).

A targeted growth pass draws candidates for a thin label using a structural or
lexical proxy. If the labeller works out which behaviour it was shown — from the
proxy's own fingerprint in the session, or by noticing a run of similar files — it
starts confirming the proxy instead of judging independently, and the eval then
measures the selection rule rather than the pipeline.

The `random` channel is the control: an unconditioned draw over the same corpus. A
label's share among `structural` rows will legitimately exceed its share among
`random` rows — that is what targeting is FOR. What the control catches is the
degenerate case: a structural draw that comes back almost purely as its target
label while the random draw shows the behaviour is not that common.

This reports the per-channel label distribution and flags labels whose structural
share is extreme. It is a prompt for human judgement, not a pass/fail gate — a rare
behaviour really can be nearly absent from a random draw.

Also reports provenance integrity, the failure a whole-file rewrite causes:
blocks that lost a `selection_channel`, and previously-annotated blocks that changed.

    console/.venv/bin/python scripts/audit_label_channels.py
    console/.venv/bin/python scripts/audit_label_channels.py --baseline HEAD
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

# A structural draw returning this share or more of one label, when the random
# control shows the behaviour is not that prevalent, is worth a human look.
_SUSPICIOUS_SHARE = 0.80
# Below this the random control is too small to compare against and the flag is
# suppressed rather than fired on noise.
_MIN_CONTROL_N = 10


def channel_label_counts(blocks: dict) -> dict[str, Counter]:
    """{selection_channel: Counter(playbook_label)} over annotated, real blocks.

    Pure. `variety-first` is the original draw (no channel recorded); `is_real:
    false` rows carry no label and are counted separately by the caller.
    """
    out: dict[str, Counter] = defaultdict(Counter)
    for block in blocks.values():
        if not isinstance(block, dict) or not block.get("annotated"):
            continue
        channel = block.get("selection_channel") or "variety-first"
        label = block.get("playbook_label")
        out[channel][label or "<rejected>"] += 1
    return dict(out)


def suspicious_labels(
    counts: dict[str, Counter], *, share: float = _SUSPICIOUS_SHARE,
    min_control: int = _MIN_CONTROL_N,
) -> list[tuple[str, float, float]]:
    """Labels whose `structural` share is extreme against the `random` control.

    Returns (label, structural_share, random_share). Empty when there is no
    structural channel, or when the control is too small to say anything.
    """
    structural, control = counts.get("structural"), counts.get("random")
    if not structural or not control:
        return []
    n_s, n_c = sum(structural.values()), sum(control.values())
    if n_s == 0 or n_c < min_control:
        return []
    flagged = []
    for label, n in structural.items():
        s_share = n / n_s
        c_share = control.get(label, 0) / n_c
        if s_share >= share and s_share > c_share:
            flagged.append((label, round(s_share, 4), round(c_share, 4)))
    return sorted(flagged, key=lambda row: -row[1])


def provenance_diff(current: dict, previous: dict) -> dict[str, list[str]]:
    """What a rewrite broke: channels dropped or altered, and previously-annotated
    blocks whose label or annotator changed. Pure; `previous` is the prior file."""
    lost, changed_channel, altered = [], [], []
    for sid, before in previous.items():
        if not isinstance(before, dict):
            continue
        now = current.get(sid)
        if not isinstance(now, dict):
            continue
        if before.get("selection_channel") and not now.get("selection_channel"):
            lost.append(sid)
        elif (before.get("selection_channel")
              and before["selection_channel"] != now.get("selection_channel")):
            changed_channel.append(sid)
        if before.get("annotated") and (
            before.get("playbook_label") != now.get("playbook_label")
            or before.get("annotator") != now.get("annotator")
        ):
            altered.append(sid)
    return {"channel_lost": sorted(lost),
            "channel_changed": sorted(changed_channel),
            "prior_label_altered": sorted(altered)}


def _git_show(rev: str, path: str) -> dict | None:
    try:
        out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True,
                             text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return yaml.safe_load(out) or {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", type=Path, default=Path("eval/labels.yaml"))
    ap.add_argument("--baseline", default=None,
                    help="git rev to compare provenance against, e.g. HEAD")
    args = ap.parse_args()

    blocks = yaml.safe_load(args.labels.read_text()) or {}
    counts = channel_label_counts(blocks)
    if not counts:
        print("no annotated blocks", file=sys.stderr)
        return 0

    channels = sorted(counts, key=lambda c: -sum(counts[c].values()))
    labels = sorted({lb for c in counts.values() for lb in c})
    width = max(len(lb) for lb in labels) + 2
    print(f"{'label':<{width}}" + "".join(f"{c:>16}" for c in channels))
    for lb in labels:
        row = f"{lb:<{width}}"
        for c in channels:
            n = counts[c].get(lb, 0)
            total = sum(counts[c].values())
            row += f"{f'{n} ({n / total:.0%})':>16}" if total else f"{'-':>16}"
        print(row)
    print(f"{'TOTAL':<{width}}" + "".join(
        f"{sum(counts[c].values()):>16}" for c in channels))

    flagged = suspicious_labels(counts)
    print()
    if flagged:
        print("FLAGGED — structural share is extreme against the random control.")
        print("Read a few of these sessions yourself before trusting the pass:")
        for lb, s_share, c_share in flagged:
            print(f"  {lb}: structural {s_share:.0%} vs random {c_share:.0%}")
    else:
        print("No label's structural share is extreme against the random control.")
    if "random" not in counts or sum(counts["random"].values()) < _MIN_CONTROL_N:
        print(f"  (control channel under {_MIN_CONTROL_N} rows — comparison suppressed)")

    if args.baseline:
        previous = _git_show(args.baseline, str(args.labels))
        if previous is None:
            print(f"\ncould not read {args.labels} at {args.baseline}", file=sys.stderr)
            return 0
        diff = provenance_diff(blocks, previous)
        print(f"\nprovenance vs {args.baseline}:")
        for key, sids in diff.items():
            mark = "OK" if not sids else f"{len(sids)} — {sids[:5]}"
            print(f"  {key:<22}{mark}")
        if any(diff.values()):
            print("\n  A rewrite lost provenance. Restore from the baseline rather than "
                  "re-rendering: re-rendering restores the channel but not a lost label.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
