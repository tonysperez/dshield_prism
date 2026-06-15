"""Retroactively stamp `dshield.classification` on already-ingested cowrie data.

The per-sensor ingest *wrapper* pipeline tags new events at ingest; data ingested before
that wrapper existed is untagged → the fail-safe gate treats it as confidential. This
backfills the tag onto the DERIVED indices the gate actually reads (session rollup, IP
rollup, commands), so existing data becomes releasable without a re-ingest or re-rollup.

Two modes (one required):
  * `--whole-corpus` — single-sensor deploys: every untagged doc → the classification.
    Correct when ALL data is from one sensor (your case). Stickiness still protects any
    doc already tagged.
  * `--sensor <observer.name>` — multi-sensor: scope to that sensor on indices that carry
    `observer.name` (session rollup, commands). IP rollups aggregate across sensors and
    carry no single `observer.name`, so they are skipped in `--sensor` mode (use
    `--whole-corpus`, or re-derive after tagging the sessions).

**Confidential-sticky** (mirrors `classification.stickier`): setting `public` only touches
*untagged* docs (never downgrades a `confidential`); setting `confidential` upgrades
anything not already confidential.

**Dry-run by default** (counts what WOULD change); writes need `--apply --yes`. A
corpus-wide classification write is the operator's call — the agent does not run it.

    console/.venv/bin/python scripts/backfill_classification.py --whole-corpus --classification public
    console/.venv/bin/python scripts/backfill_classification.py --whole-corpus --classification public --apply --yes
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import CLASSIFICATION_KEYWORD, CONFIDENTIAL, PUBLIC
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_SET_SCRIPT = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "ctx._source.dshield.classification = params.cls;"
)


def build_backfill_query(classification: str, *, sensor: str | None, has_observer: bool) -> dict:
    """ES query selecting the docs to (re)tag. Pure — smoke-tested.

    Stickiness: `public` only matches UNTAGGED docs (never overwrites public/confidential);
    `confidential` matches anything not already confidential. `sensor` scopes by
    `observer.name` only when the index carries it."""
    filters: list[dict] = []
    if classification == PUBLIC:
        filters.append({"bool": {"must_not": {"exists": {"field": CLASSIFICATION_KEYWORD}}}})
    else:  # confidential — most-restrictive wins
        filters.append({"bool": {"must_not": {"term": {CLASSIFICATION_KEYWORD: CONFIDENTIAL}}}})
    if sensor and has_observer:
        filters.append({"term": {"observer.name": sensor}})
    return {"bool": {"filter": filters}}


def _poll_task(es, task_id: str, idx: str, interval: float) -> int:
    """Poll an async update_by_query task to completion, printing progress. Returns 0 on
    success, 1 on reported failures. The task keeps running server-side even if this poll
    is interrupted (Ctrl-C / SSH drop) — re-running the script is idempotent."""
    try:
        while True:
            time.sleep(interval)
            t = es.tasks.get(task_id=task_id)
            status = (t.get("task") or {}).get("status") or {}
            print(f"    {idx}: {status.get('updated', 0)}/{status.get('total', 0)} updated, "
                  f"{status.get('version_conflicts', 0)} conflicts…    ", end="\r")
            if t.get("completed"):
                resp = t.get("response") or {}
                fails = resp.get("failures") or []
                print(f"\n  {idx}: done — updated {resp.get('updated')}, "
                      f"conflicts {resp.get('version_conflicts')}, failures {len(fails)}")
                if fails:
                    print(f"    first failure: {str(fails[0])[:300]}")
                    return 1
                return 0
    except KeyboardInterrupt:
        print(f"\n  {idx}: polling interrupted — task {task_id} CONTINUES server-side "
              f"(GET _tasks/{task_id}); re-run this script later, it is idempotent.")
        raise


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--classification", choices=[PUBLIC, CONFIDENTIAL], required=True)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--whole-corpus", action="store_true",
                      help="single-sensor: tag every untagged doc (no observer filter)")
    mode.add_argument("--sensor", default=None, help="multi-sensor: scope to observer.name")
    ap.add_argument("--apply", action="store_true", help="write (default: dry-run)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    # Scale: a multi-million-doc update_by_query must run async (server-side task) or the
    # client connection times out. Submit with wait_for_completion=false + slices, poll.
    ap.add_argument("--slices", default="auto", help="parallel slices (default: auto = one/shard)")
    ap.add_argument("--requests-per-second", type=float, default=None,
                    help="throttle (docs/s); default unlimited. Lower it if ES is under load")
    ap.add_argument("--poll-seconds", type=float, default=5.0, help="task poll interval")
    ap.add_argument("--no-wait", action="store_true",
                    help="submit the tasks and exit (print task ids); check later via GET _tasks/<id>")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    cw = cfg.elasticsearch.indexes.cowrie
    # (index, has_observer)
    targets = [
        (cw.sessions_rollup, True),
        (cw.commands, True),
        (cw.ips_rollup, False),   # IP rollups aggregate across sensors → no observer
    ]

    plan = []
    for idx, has_obs in targets:
        if args.sensor and not has_obs:
            print(f"  {idx}: SKIP (no observer.name — use --whole-corpus or re-derive)")
            continue
        q = build_backfill_query(args.classification, sensor=args.sensor, has_observer=has_obs)
        try:
            n = es.count(index=idx, query=q)["count"]
        except Exception as e:  # noqa: BLE001
            print(f"  {idx}: count failed: {e}")
            continue
        plan.append((idx, has_obs, q, n))
        print(f"  {idx}: {n} docs to set {args.classification}")

    total = sum(n for _i, _h, _q, n in plan)
    scope = "whole corpus" if args.whole_corpus else f"observer.name={args.sensor}"
    print(f"\n  total: {total} docs → {args.classification} ({scope})")
    if not args.apply:
        print("\nDRY-RUN — no writes. Re-run with --apply --yes to tag.")
        return 0
    if not args.yes:
        try:
            resp = input(f"\nTag {total} docs {args.classification} ({scope})? [y/N] ").strip().lower()
        except EOFError:
            resp = "n"
        if resp not in ("y", "yes"):
            print("Aborted.")
            return 1

    rps = args.requests_per_second if args.requests_per_second is not None else -1.0
    slices = int(args.slices) if str(args.slices).isdigit() else args.slices  # "auto" or N
    script = {"source": _SET_SCRIPT, "params": {"cls": args.classification}}
    errors = 0
    for idx, _h, q, n in plan:
        if n == 0:
            continue
        try:
            submit = es.update_by_query(
                index=idx, query=q, script=script, conflicts="proceed",
                slices=slices, requests_per_second=rps,
                wait_for_completion=False, refresh=False,
            )
        except Exception as e:  # noqa: BLE001
            print(f"  {idx}: submit failed: {e}")
            errors += 1
            continue
        task_id = submit.get("task")
        print(f"  {idx}: submitted task {task_id} ({n} docs)")
        if args.no_wait:
            continue
        errors += _poll_task(es, task_id, idx, args.poll_seconds)

    if args.no_wait:
        print("\nSubmitted (async). Watch with: GET _tasks/<id> — or "
              "`GET _tasks?actions=*byquery&detailed`. Re-running this script is idempotent.")
    else:
        print("\nDone." + (f" {errors} index error(s)." if errors else ""))
        print("Next: re-capture the public anchor snapshot — "
              "`python scripts/capture_anchor_snapshot.py` now returns public data.")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
