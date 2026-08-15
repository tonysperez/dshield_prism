"""Consolidation apply — the write path for the consolidation plan (Option A,
first destructive mutation of production identity).

Consumes a FROZEN, operator-reviewed plan JSON (a specific
`consolidation-plan-*.json` from `consolidation_engine.py`) and merges each alias
anchor into its canonical. **Dry-run by default**; the destructive path needs
`--apply --yes`. See docs/decisions.md §5e.

Two idempotent core mutations per alias:
  1. Re-point sessions (`update_by_query`, playbook_id == alias) → canonical
     playbook_id/name, stamp `playbook_merged_from = alias` (reversal key), bump
     `playbook_named_at = now` (so the next forward `rollup ips` re-rolls the
     affected IPs — IP rollups self-heal).
  2. Retire the alias anchor: move `anchor_centroid` → `retired_centroid`, set
     `merged_into`/`retired_at`. `_load_playbook_anchors` filters on
     `exists: anchor_centroid`, so the alias drops out of assignment with no src
     change; the centroid is preserved for reversal. Noop if already retired.

Privacy: re-point/count operate on ALL classifications by necessity (a merge must
move every session of the alias) — blind server-side mutations that surface no
per-record data; no public-only filter (filtering would make the merge incomplete).
The agent does not run the destructive path.

Reversal: re-point where `playbook_merged_from == alias`; restore `retired_centroid`.
An audit JSON is written on apply.

Run from repo root via the console venv:
    console/.venv/bin/python scripts/consolidation_apply.py --plan eval/results/consolidation-plan-<ts>.json
    console/.venv/bin/python scripts/consolidation_apply.py --plan <plan> --apply --yes
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_PB_FIELD = f"{_S}.playbook_id"
_PB_NAME_FIELD = f"{_S}.playbook_name"

_REPOINT_SRC = (
    "if (ctx._source.dshield == null) { ctx._source.dshield = [:]; }"
    "if (ctx._source.dshield.cowrie == null) { ctx._source.dshield.cowrie = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment == null) { ctx._source.dshield.cowrie.enrichment = [:]; }"
    "if (ctx._source.dshield.cowrie.enrichment.session == null) { ctx._source.dshield.cowrie.enrichment.session = [:]; }"
    "def s = ctx._source.dshield.cowrie.enrichment.session;"
    "s.playbook_id = params.canonical_id;"
    "s.playbook_name = params.canonical_name;"
    "s.playbook_merged_from = params.alias_id;"
    "s.playbook_named_at = params.now;"
)

# Retire = strip anchor_centroid (loader filters on its presence) but keep it under
# retired_centroid for reversal. Noop when already retired (idempotent).
_RETIRE_SRC = (
    "if (ctx._source.anchor_centroid != null) {"
    "  ctx._source.retired_centroid = ctx._source.anchor_centroid;"
    "  ctx._source.remove('anchor_centroid');"
    "  ctx._source.merged_into = params.canonical;"
    "  ctx._source.retired_at = params.now;"
    "} else { ctx.op = 'noop'; }"
)


# ---------------------------------------------------------------------------
# Pure helpers (smoke-tested)
# ---------------------------------------------------------------------------
def plan_to_operations(report: dict) -> list[dict]:
    """Flatten a plan report's merge groups into {alias, canonical} ops."""
    ops = []
    for g in report.get("merge_groups", []):
        canon = g["canonical"]
        for m in g.get("members", []):
            if m != canon:
                ops.append({"alias": m, "canonical": canon})
    return ops


def build_repoint_request(index: str, alias: str, canonical_id: str,
                          canonical_name, now: str) -> dict:
    """kwargs for `es.update_by_query` that re-points an alias's sessions."""
    return {
        "index": index,
        "query": {"term": {_PB_FIELD: alias}},
        "script": {"source": _REPOINT_SRC, "params": {
            "canonical_id": canonical_id, "canonical_name": canonical_name,
            "alias_id": alias, "now": now}},
        "conflicts": "proceed",
        "refresh": True,
    }


def build_retire_request(index: str, alias: str, canonical: str, now: str) -> dict:
    """kwargs for `es.update` that retires an alias anchor (idempotent)."""
    return {
        "index": index,
        "id": alias,
        "script": {"source": _RETIRE_SRC, "params": {"canonical": canonical, "now": now}},
    }


# ---------------------------------------------------------------------------
# Live-ES IO
# ---------------------------------------------------------------------------
def _session_block(src: dict) -> dict:
    return (((src.get("dshield") or {}).get("cowrie") or {})
            .get("enrichment", {}).get("session", {}))


def canonical_name(es, idx: str, canonical_id: str):
    r = es.search(index=idx, size=1, _source=[_PB_NAME_FIELD],
                  query={"term": {_PB_FIELD: canonical_id}})
    hits = r["hits"]["hits"]
    return _session_block(hits[0]["_source"]).get("playbook_name") if hits else None


def _anchor_active(es, anch_idx: str, alias: str):
    """(exists, active) — active means it still has anchor_centroid."""
    try:
        doc = es.get(index=anch_idx, id=alias)
    except Exception:
        return False, False
    src = doc.get("_source", {})
    return True, ("anchor_centroid" in src)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--plan", required=True, help="path to a consolidation-plan-*.json")
    ap.add_argument("--apply", action="store_true",
                    help="perform the writes (default: dry-run, no writes)")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    ap.add_argument("--out-dir", default="eval/results")
    args = ap.parse_args()

    plan = json.loads(Path(args.plan).read_text())
    report = plan.get("report", plan)
    ops = plan_to_operations(report)
    if not ops:
        print("No merge groups in the plan — nothing to apply.")
        return 0

    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    anch_idx = cfg.elasticsearch.indexes.cowrie.playbook_anchors
    now = datetime.now(UTC).isoformat()

    # resolve canonical names + per-op preview
    names: dict[str, str] = {}
    preview = []
    for op in ops:
        c = op["canonical"]
        if c not in names:
            names[c] = canonical_name(es, idx, c)
        n_sessions = es.count(index=idx, query={"term": {_PB_FIELD: op["alias"]}})["count"]
        exists, active = _anchor_active(es, anch_idx, op["alias"])
        preview.append({"alias": op["alias"], "canonical": c,
                        "canonical_name": names[c], "n_sessions": n_sessions,
                        "anchor": "active" if active else ("retired" if exists else "absent")})

    print(f"Consolidation plan: {len(ops)} alias→canonical merge(s)\n")
    for p in preview:
        print(f"  {p['alias']} → {p['canonical']} ({p['canonical_name']}): "
              f"{p['n_sessions']} sessions to re-point; anchor {p['anchor']}")
    total = sum(p["n_sessions"] for p in preview)
    print(f"\n  total sessions to re-point: {total}")

    if not args.apply:
        print("\nDRY-RUN — no writes. Re-run with --apply --yes to execute.")
        return 0

    if not args.yes:
        try:
            resp = input(f"\nApply {len(ops)} merge(s), re-point {total} sessions? [y/N] ").strip().lower()
        except EOFError:
            resp = "n"
        if resp not in ("y", "yes"):
            print("Aborted.")
            return 1

    applied = []
    for op in ops:
        rep = build_repoint_request(idx, op["alias"], op["canonical"],
                                    names[op["canonical"]], now)
        r = es.update_by_query(**rep)
        ret = build_retire_request(anch_idx, op["alias"], op["canonical"], now)
        try:
            ares = es.update(**ret)
            anchor_result = ares.get("result")
        except Exception as e:
            anchor_result = f"error: {e}"
        applied.append({"alias": op["alias"], "canonical": op["canonical"],
                        "sessions_repointed": r.get("updated"),
                        "version_conflicts": r.get("version_conflicts"),
                        "anchor_result": anchor_result})
        print(f"  applied {op['alias']} → {op['canonical']}: "
              f"{r.get('updated')} re-pointed, anchor {anchor_result}")

    audit = {"applied_at": now, "plan_file": str(args.plan),
             "reverse_map": {op["alias"]: op["canonical"] for op in ops},
             "results": applied}
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    audit_path = out_dir / f"consolidation-applied-{ts}.json"
    audit_path.write_text(json.dumps(audit, indent=2))
    print(f"\nwrote audit {audit_path}")
    print("Downstream: IP rollups self-heal on next `rollup ips` (playbook_named_at "
          "bumped); campaigns/findings on next `mine`; alias lifecycle docs orphan "
          "(clean up by id). Reversal: re-point where playbook_merged_from==alias + "
          "restore retired_centroid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
