"""Structural-predicate falsification test (backlog item 29).

Two label-prototype pairs sit above the shipped assignment threshold
tau=0.94 (`botnet_loader` <-> `payload_fetch_exec` at cosine 0.9703,
`iot_cli_probe` <-> `single_command_probe` at 0.9432), so the embedding alone
cannot separate them. `eval/RUBRIC.md` v2 separates these pairs (and two
other confused pairs found in the model's own fold errors, Finding 22) using
structural evidence in the command stream, not embedding cosine. This script
computes that evidence directly as boolean predicates and measures whether it
separates each pair on the 148 labelled, real eval sessions.

No live ES, no production code change. Diagnostic only: prints per-pair
predicted-vs-actual accuracy and a confusion count, never gates a build (like
`eval_clustering.py`). Separates -> feeds backlog item 30 (wire the surviving
predicate into the assignment geometry). Doesn't separate -> feeds item 32
(merge the labels; no available evidence distinguishes them on this corpus).

Run from the repo root via the console venv:
    console/.venv/bin/python scripts/eval_predicate_falsification.py
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from eval_jsonl import open_jsonl
from validate_eval_labels import KNOWN_PLAYBOOK_LABELS

# ---------------------------------------------------------------------------
# Evidence loading
# ---------------------------------------------------------------------------


def _load_labeled_ids(labels_path: Path) -> dict[str, str]:
    """session_id -> playbook_label for annotated, real, known-vocabulary blocks."""
    raw = yaml.safe_load(labels_path.read_text()) or {}
    out: dict[str, str] = {}
    for sid, block in raw.items():
        if not isinstance(block, dict) or not block.get("annotated"):
            continue
        if block.get("is_real") is False:
            continue
        label = block.get("playbook_label")
        if label in KNOWN_PLAYBOOK_LABELS:
            out[str(sid)] = label
    return out


def _command_lines(rec: dict) -> list[str]:
    """Ordered `process.command_line` strings from `command_enrichments`."""
    lines: list[str] = []
    for command in rec.get("command_enrichments") or []:
        if not isinstance(command, dict):
            continue
        line = ((command.get("process") or {}).get("command_line"))
        if isinstance(line, str) and line:
            lines.append(line)
    return lines


def load_command_text(labels_path: Path, jsonl_path: Path) -> dict[str, tuple[str, list[str]]]:
    """session_id -> (playbook_label, command_lines) for labelled sessions.

    Mirrors `eval_assignment.load_records_detailed`'s duplicate-id handling: a
    session_id seen more than once in the JSONL is dropped rather than
    silently letting the last occurrence win.
    """
    labeled = _load_labeled_ids(labels_path)
    seen: Counter[str] = Counter()
    candidates: dict[str, dict] = {}
    with open_jsonl(jsonl_path) as fh:
        lines = fh.read().splitlines()
    for line in lines:
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(rec, dict):
            continue
        sid = str(rec.get("session_id") or "")
        if sid in labeled:
            seen[sid] += 1
            candidates[sid] = rec
    out: dict[str, tuple[str, list[str]]] = {}
    for sid, rec in candidates.items():
        if seen[sid] != 1:
            continue
        out[sid] = (labeled[sid], _command_lines(rec))
    return out


# ---------------------------------------------------------------------------
# Structural predicates — taken directly from RUBRIC.md v2's "Distinguishing
# test" column. These are diagnostic regexes over raw (defanged) command
# text, not the production decision path; false positives/negatives here are
# a measurement question, not a correctness bug.
# ---------------------------------------------------------------------------

_ARCH_TOKENS = (
    "x86_64", "x86", "i386", "i686", "aarch64", "arm64",
    "arm5", "arm6", "arm7", "armv4", "armv5", "armv6", "armv7",
    "mipsel", "mips64", "mips", "powerpc", "ppc", "sparc", "sh4", "m68k",
)
_APPLIANCE_MENU_VERBS = {"sh", "shell", "enable", "system", "linuxshell", "help", "busybox"}
# RUBRIC.md's host_recon row lists: uname, /proc/cpuinfo, hostname, whoami, w,
# id, netstat, free, ls /, lscpu.
_HOST_RECON_RE = re.compile(
    r"\buname\b|/proc/cpuinfo|\bhostname\b|\bwhoami\b|\bnetstat\b|\bfree\b|\blscpu\b"
    r"|\bls\s+/|\bw\b|\bid\b",
    re.IGNORECASE,
)
_ARCH_CASE_RE = re.compile(r"\bcase\b", re.IGNORECASE)
_IP = r"\d{1,3}(?:\[?\.\]?\d{1,3}){3}"
# Any path prefix, not just `./` — a dropper as often invokes the absolute path
# it just wrote (`/tmp/bot <ip> 1338 &`). Requiring `./` missed those.
_C2_LAUNCH_RE = re.compile(rf"(?:\./|/)\S+\s+{_IP}[\s:]+\d{{2,5}}\b")
# Two forms of self-spread: starting a listener, and handing a propagation
# transport to the staged payload (`… | sh -s telnet`). The second is how the
# redtail-family loaders in this corpus spread; matching only listeners missed
# them.
_SELF_SPREAD_RE = re.compile(
    r"telnetd\s+[^&\n]*-l|\bnc\s+[^&\n]*-l|\bsh\s+-s\s+(?:telnet|ssh)\b",
    re.IGNORECASE,
)
# Heterogeneous-target fallback: walking several writable directories AND
# several fetch tools in one chain. Same motivation as multi-arch targeting —
# the operator does not know what the target looks like — expressed for
# embedded devices rather than CPUs. Measured on the committed eval set: fires
# on 5/10 `botnet_loader` and 0 of the other 138 sessions.
_MULTI_DIR_RE = re.compile(r"cd\s+\S+\s*\|\|\s*cd\s+\S+\s*\|\|\s*cd\s+", re.IGNORECASE)
_MULTI_TOOL_RE = re.compile(r"busybox\s+wget|wget[^|]*\|\||curl[^|]*\|\|", re.IGNORECASE)
_KEY_WRITE_RE = re.compile(r"authorized_keys", re.IGNORECASE)
_IMMUTABILITY_RE = re.compile(r"chattr\s+[+-]?ia?\b|\blockr\s+-ia\b", re.IGNORECASE)


def multi_arch_targeting(text: str) -> bool:
    if re.search(r"uname\s+-m", text, re.IGNORECASE):
        return True
    found = {tok for tok in _ARCH_TOKENS if re.search(rf"\b{re.escape(tok)}\b", text, re.IGNORECASE)}
    if _ARCH_CASE_RE.search(text) and found:
        return True
    return len(found) >= 2


def c2_launch_arg(text: str) -> bool:
    return bool(_C2_LAUNCH_RE.search(text))


def self_spread(text: str) -> bool:
    return bool(_SELF_SPREAD_RE.search(text))


def appliance_menu_only(lines: list[str]) -> bool:
    if not lines:
        return False
    return all(line.strip().lower() in _APPLIANCE_MENU_VERBS for line in lines)


def host_info_gather(text: str) -> bool:
    return bool(_HOST_RECON_RE.search(text))


def key_write_immutability(text: str) -> bool:
    return bool(_KEY_WRITE_RE.search(text) and _IMMUTABILITY_RE.search(text))


def hetero_target_fallback(text: str) -> bool:
    """Multi-directory AND multi-tool fallback in the same session."""
    return bool(_MULTI_DIR_RE.search(text) and _MULTI_TOOL_RE.search(text))


def compute_predicates(lines: list[str]) -> dict[str, bool]:
    text = " ".join(lines)
    return {
        "multi_arch_targeting": multi_arch_targeting(text),
        "c2_launch_arg": c2_launch_arg(text),
        "self_spread": self_spread(text),
        "appliance_menu_only": appliance_menu_only(lines),
        "host_info_gather": host_info_gather(text),
        "key_write_immutability": key_write_immutability(text),
        "hetero_target_fallback": hetero_target_fallback(text),
    }


# ---------------------------------------------------------------------------
# Pair classifiers — one precedence rule per confused pair, straight from
# RUBRIC.md v2's canonical table + precedence rules 1, 3, 5, 6.
# ---------------------------------------------------------------------------


def classify_botnet_vs_fetch(pred: dict[str, bool]) -> str:
    if (pred["multi_arch_targeting"] or pred["c2_launch_arg"] or pred["self_spread"]
            or pred["hetero_target_fallback"]):
        return "botnet_loader"
    return "payload_fetch_exec"


def classify_iot_vs_single(pred: dict[str, bool]) -> str:
    return "iot_cli_probe" if pred["appliance_menu_only"] else "single_command_probe"


def classify_sshkey_vs_hostrecon(pred: dict[str, bool]) -> str:
    return "ssh_key_chattr_persistence" if pred["key_write_immutability"] else "host_recon"


def classify_single_vs_hostrecon(pred: dict[str, bool]) -> str:
    return "host_recon" if pred["host_info_gather"] else "single_command_probe"


# Operationalized from the investigation's two named above-tau prototype pairs
# (botnet_loader<->payload_fetch_exec, iot_cli_probe<->single_command_probe)
# plus Finding 22's two other clean two-label confusion rows.
PAIRS: tuple[tuple[str, str, Callable[[dict[str, bool]], str]], ...] = (
    ("botnet_loader", "payload_fetch_exec", classify_botnet_vs_fetch),
    ("iot_cli_probe", "single_command_probe", classify_iot_vs_single),
    ("ssh_key_chattr_persistence", "host_recon", classify_sshkey_vs_hostrecon),
    ("single_command_probe", "host_recon", classify_single_vs_hostrecon),
)
assert all(a in KNOWN_PLAYBOOK_LABELS and b in KNOWN_PLAYBOOK_LABELS for a, b, _ in PAIRS), (  # noqa: S101
    "PAIRS references a label outside KNOWN_PLAYBOOK_LABELS -- check for a typo"
)


def evaluate_pair(
    label_a: str,
    label_b: str,
    classifier: Callable[[dict[str, bool]], str],
    evidence: dict[str, tuple[str, list[str]]],
) -> dict:
    members = {sid: (label, lines) for sid, (label, lines) in evidence.items()
               if label in (label_a, label_b)}
    confusion: Counter[tuple[str, str]] = Counter()
    no_evidence = 0
    for (actual, lines) in members.values():
        if not lines:
            no_evidence += 1
        predicted = classifier(compute_predicates(lines))
        confusion[(actual, predicted)] += 1
    n = len(members)
    correct = confusion[(label_a, label_a)] + confusion[(label_b, label_b)]
    return {
        "label_a": label_a, "label_b": label_b, "n": n,
        "accuracy": (correct / n) if n else None,
        "confusion": {f"{a}->{p}": c for (a, p), c in confusion.items()},
        "no_evidence": no_evidence,
    }


def evaluate(evidence: dict[str, tuple[str, list[str]]]) -> list[dict]:
    return [evaluate_pair(a, b, clf, evidence) for a, b, clf in PAIRS]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", default="eval/labels.yaml")
    ap.add_argument("--unlabeled", default="eval/sessions.unlabeled.jsonl.gz")
    args = ap.parse_args()

    evidence = load_command_text(Path(args.labels), Path(args.unlabeled))
    if not evidence:
        print("No labelled real sessions with known playbook_label found.", file=sys.stderr)
        return 1

    results = evaluate(evidence)
    print(f"\n  {'pair':46}{'n':>5}{'accuracy':>10}{'no_evidence':>13}")
    for r in results:
        pair = f"{r['label_a']} <-> {r['label_b']}"
        acc = f"{r['accuracy']:.4f}" if r["accuracy"] is not None else "(n=0)"
        print(f"  {pair:46}{r['n']:>5}{acc:>10}{r['no_evidence']:>13}")
        for k, v in sorted(r["confusion"].items()):
            print(f"      {k}: {v}")

    print("\nDIAGNOSTIC — not gating (backlog item 29). Rule of thumb: accuracy >= 0.9 "
          "reads as SEPARATES (feeds item 30); lower reads as DOES-NOT-SEPARATE (feeds item 32).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
