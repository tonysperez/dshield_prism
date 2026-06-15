"""I4 entrypoint — run the authoritative (or shadow) assignment over a session window.

Thin wrapper over `enrich.sources.cowrie.assign_runner.run_assignment`. Whether it
writes `playbook_id` authoritatively or only the shadow fields is governed by
`session.assignment_authoritative` in config (NOT a CLI flag) — so the behaviour is the
same whether run here or wired into the backward service. **Dry-run by default**; writes
need `--apply --yes`.

This is what replaces `cluster sessions` + `name playbooks` in the backward service at
cutover (operator swaps the ExecStart). Novel sessions still feed the HDBSCAN clusterer
to mint new anchors. Reversal: set `assignment_authoritative: false` and re-run the
HDBSCAN steps.

Privacy: assignment must cover every session in the window (all classifications) to be
coherent — blind server-side writes that surface no per-record data. public-only filter
BY DEFAULT; `--allow-unclassified` is an OPERATOR decision. The agent does not run the
write path.

    console/.venv/bin/python scripts/assign_sessions.py --window-days 30
    console/.venv/bin/python scripts/assign_sessions.py --window-days 30 --apply --yes
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client
from enrich.sources.cowrie.assign_runner import run_assignment

_S = "dshield.cowrie.enrichment.session"
_EMB_EXISTS = {"exists": {"field": f"{_S}.embedding"}}
_PB_EXISTS = {"exists": {"field": f"{_S}.playbook_id"}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--window-days", type=int, default=30, help="0 = whole corpus")
    ap.add_argument("--per-anchor", type=int, default=300)
    ap.add_argument("--apply", action="store_true", help="write (default: dry-run, no writes)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    ap.add_argument("--allow-unclassified", action="store_true",
                    help="OPERATOR ONLY: drop the public-only filter. Agent never sets it.")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))

    cls = [] if args.allow_unclassified else [releasable_filter(cfg)]
    if args.allow_unclassified:
        print("WARNING: --allow-unclassified set; assigning/writing WITHOUT the public-only "
              "filter (operator-authorised).", file=sys.stderr)
    window = list(cls) + [_EMB_EXISTS]
    if args.window_days > 0:
        window.append({"range": {"@timestamp": {"gte": f"now-{args.window_days}d"}}})
    anchor_sample = list(cls) + [_EMB_EXISTS, _PB_EXISTS]

    authoritative = bool(getattr(cfg.session, "assignment_authoritative", False))
    mode = "AUTHORITATIVE (writes playbook_id)" if authoritative else "shadow-only"
    print(f"assign_sessions: mode={mode}, window_days={args.window_days}")

    if args.apply and not args.yes:
        try:
            resp = input(f"\nApply {mode} assignment over the window? [y/N] ").strip().lower()
        except EOFError:
            resp = "n"
        if resp not in ("y", "yes"):
            print("Aborted.")
            return 1

    summary = run_assignment(es, cfg, window_filter=window, anchor_sample_filter=anchor_sample,
                             per_anchor=args.per_anchor, apply=args.apply)
    print(json.dumps(summary, indent=2))
    if not args.apply and not summary.get("error"):
        print("\nDRY-RUN — no writes. Re-run with --apply --yes to write.")
    return 0 if not summary.get("errors") else 1


if __name__ == "__main__":
    raise SystemExit(main())
