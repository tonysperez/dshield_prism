"""Retire INACTIVE playbook anchors — ones with no sessions currently assigned to them.

Post-Option-A-cutover the anchor library accumulates dead weight: anchors whose sessions
all migrated to a nearer/confirmed twin during assignment, leaving the anchor with 0
assigned sessions. The consolidation engine can't reach these (no sessions → no TF-IDF
centroid → it won't blind-merge them), so this prunes them directly: an anchor with
`assigned-session count < --min-sessions` (default 1 = truly zero) is retired.

Retirement reuses the consolidation mechanism — move `anchor_centroid → retired_centroid`
+ stamp `retired_at`/`retired_reason='inactive'` — so `_load_playbook_anchors` (filters on
`exists: anchor_centroid`) drops it from assignment, and it's **reversible** (`--unretire`
restores every anchor retired with reason `inactive`).

Judgment call this encodes: a retired inactive anchor means a future matching session goes
to the *novel pool* instead of that anchor — correct, since its prior sessions already
preferred a nearer anchor. `--window-days N` scopes "inactive" to "no sessions in the last
N days" (default 0 = all-time, the safest: only truly-dead anchors).

Dry-run by default; writes need `--apply --yes`. The count must reflect ALL sessions to be
correct (an anchor active only in confidential data is NOT inactive), so the operator runs
with `--allow-unclassified`; the agent's public-only default is exact only once the corpus
is fully public-tagged.

    console/.venv/bin/python scripts/prune_inactive_anchors.py
    console/.venv/bin/python scripts/prune_inactive_anchors.py --apply --yes --allow-unclassified
    console/.venv/bin/python scripts/prune_inactive_anchors.py --unretire --apply --yes
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_PB = "dshield.cowrie.enrichment.session.playbook_id"
_REASON = "inactive"

_RETIRE_SRC = (
    "if (ctx._source.anchor_centroid != null) {"
    "  ctx._source.retired_centroid = ctx._source.anchor_centroid;"
    "  ctx._source.remove('anchor_centroid');"
    "  ctx._source.retired_at = params.now;"
    "  ctx._source.retired_reason = params.reason;"
    "} else { ctx.op = 'noop'; }"
)
_RESTORE_SRC = (
    "if (ctx._source.retired_centroid != null && ctx._source.retired_reason == params.reason) {"
    "  ctx._source.anchor_centroid = ctx._source.retired_centroid;"
    "  ctx._source.remove('retired_centroid');"
    "  ctx._source.remove('retired_at');"
    "  ctx._source.remove('retired_reason');"
    "} else { ctx.op = 'noop'; }"
)


# ---------------------------------------------------------------------------
# Pure (smoke-tested)
# ---------------------------------------------------------------------------
def select_inactive(anchor_ids: list[str], active_counts: dict, min_sessions: int) -> list[str]:
    """Anchors whose assigned-session count is below `min_sessions` (absent = 0)."""
    return [a for a in anchor_ids if active_counts.get(a, 0) < min_sessions]


# ---------------------------------------------------------------------------
def _active_anchor_ids(es, anch_idx) -> list[str]:
    r = es.search(index=anch_idx, size=10000, _source=["playbook_id"],
                  query={"exists": {"field": "anchor_centroid"}})
    return [h["_source"].get("playbook_id") or h["_id"] for h in r["hits"]["hits"]]


def _session_counts(es, idx, filt) -> dict:
    r = es.search(index=idx, size=0, query={"bool": {"filter": filt}},
                  aggs={"pb": {"terms": {"field": _PB, "size": 20000}}})
    return {b["key"]: b["doc_count"] for b in r["aggregations"]["pb"]["buckets"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--min-sessions", type=int, default=1,
                    help="retire anchors with fewer assigned sessions than this (1 = only 0-session)")
    ap.add_argument("--window-days", type=int, default=0, help="0 = all-time (safest)")
    ap.add_argument("--unretire", action="store_true",
                    help="reverse: restore every anchor retired with reason 'inactive'")
    ap.add_argument("--apply", action="store_true", help="write (default: dry-run)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    ap.add_argument("--allow-unclassified", action="store_true",
                    help="OPERATOR: count ALL sessions (correct inactivity); agent never sets it")
    args = ap.parse_args()

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    anch_idx = cfg.elasticsearch.indexes.cowrie.playbook_anchors
    now = datetime.now(UTC).isoformat()

    if args.unretire:
        n = es.count(index=anch_idx, query={"term": {"retired_reason": _REASON}})["count"]
        print(f"{n} anchors retired as inactive.")
        if not args.apply:
            print("DRY-RUN — re-run with --apply --yes to restore them.")
            return 0
        if not args.yes and input(f"Restore {n} inactive-retired anchors? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1
        r = es.update_by_query(index=anch_idx, query={"term": {"retired_reason": _REASON}},
                               script={"source": _RESTORE_SRC, "params": {"reason": _REASON}},
                               conflicts="proceed", refresh=True)
        print(f"restored {r.get('updated')} anchors")
        return 0

    if args.allow_unclassified:
        print("WARNING: --allow-unclassified — counting ALL sessions (operator-authorised).", file=sys.stderr)
        filt = []
    else:
        filt = [releasable_filter(cfg)]
    if args.window_days > 0:
        filt = [*filt, {"range": {"@timestamp": {"gte": f"now-{args.window_days}d"}}}]

    anchor_ids = _active_anchor_ids(es, anch_idx)
    counts = _session_counts(es, idx, filt)
    inactive = select_inactive(anchor_ids, counts, args.min_sessions)
    scope = "all-time" if args.window_days == 0 else f"last {args.window_days}d"
    print(f"anchors: {len(anchor_ids)} active in library; "
          f"{len(anchor_ids) - len(inactive)} keep, {len(inactive)} inactive "
          f"(< {args.min_sessions} sessions, {scope})")
    for a in inactive[:25]:
        print(f"  retire {a}  ({counts.get(a, 0)} sessions)")
    if len(inactive) > 25:
        print(f"  … and {len(inactive) - 25} more")

    if not inactive:
        print("Nothing to prune.")
        return 0
    if not args.apply:
        print("\nDRY-RUN — no writes. Re-run with --apply --yes to retire.")
        return 0
    if not args.yes and input(f"\nRetire {len(inactive)} inactive anchors? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Aborted.")
        return 1

    errors = 0
    for a in inactive:
        try:
            es.update(index=anch_idx, id=a,
                      script={"source": _RETIRE_SRC, "params": {"now": now, "reason": _REASON}})
        except Exception as e:
            print(f"  {a}: retire failed: {e}")
            errors += 1
    print(f"\nretired {len(inactive) - errors} anchors" + (f", {errors} errors" if errors else ""))
    print("Reversible: `prune_inactive_anchors.py --unretire --apply --yes`.")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
