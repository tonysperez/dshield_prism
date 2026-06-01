"""Mine textually-divergent same-behavior session pairs for E1 eval expansion.

Per the embedding-quality plan E1.1: walk the production session-rollup
index and surface session pairs that satisfy all of:

  * **same dominant_intent OR same playbook_id** — both members agree
    on the analyst-coarsed behavior label.
  * **command-set Jaccard ≤ --jaccard-max** — measured on the
    persisted hash-set ``command_set`` (16-hex normalized command
    hashes). A Jaccard of 0 means the two sessions share zero
    canonicalised commands; 0.2 means at most 20% overlap. Low Jaccard
    = lexically divergent.
  * **each session has at least --min-unique-commands** — filters out
    one-command probes whose Jaccard is dominated by short-sequence
    noise.

Output: JSONL, one pair per line, sorted by Jaccard ascending (most
divergent first). Each line is self-contained for an analyst — both
sessions' rollup summary plus the actual command text fetched from
``prism.enriched.cowrie.command``. The analyst then picks ≥20 pairs
(~40 sessions) for E1.2's hand-labelling into ``eval/sessions-v2.jsonl``.

Why bucket by both playbook_id and dominant_intent:
  - playbook_id is the strongest "same behavior" signal but only ~17%
    of sessions carry one (3919 / 229K at this writing).
  - dominant_intent covers the rest — looser but still a behavior
    grouping. Pairs surfaced via dominant_intent buckets but not
    playbook_id are exactly the cases where production clustering
    failed to group same-behavior sessions, which is the bias we want
    the eval to test against.

Pairs that appear in both buckets are deduped, preferring the tighter
playbook_id annotation.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/mine_divergent_candidates.py
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

log = logging.getLogger(__name__)

_BASE = "dshield.cowrie.enrichment.session"


# ---------------------------------------------------------------------------
# ES iteration
# ---------------------------------------------------------------------------

def _iter_session_rollups(
    es, sessions_index: str, page_size: int,
) -> Iterator[dict]:
    """Stream sessions that carry both a command_set and at least one of
    (playbook_id, dominant_intent). search_after pagination so we can
    walk the full population without scroll-cursor bookkeeping."""
    body = {
        "size": page_size,
        "_source": [
            "@timestamp",
            "source.ip",
            "cowrie.session_id",
            f"{_BASE}.command_set",
            f"{_BASE}.command_count",
            f"{_BASE}.unique_commands",
            f"{_BASE}.dominant_intent",
            f"{_BASE}.playbook_id",
            f"{_BASE}.playbook_name",
        ],
        "query": {"bool": {
            "must": [
                {"exists": {"field": f"{_BASE}.command_set"}},
            ],
            "should": [
                {"exists": {"field": f"{_BASE}.playbook_id"}},
                {"exists": {"field": f"{_BASE}.dominant_intent"}},
            ],
            "minimum_should_match": 1,
        }},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    search_after = None
    while True:
        if search_after is not None:
            body["search_after"] = search_after
        resp = es.search(index=sessions_index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            src = h["_source"]
            enr = (
                (((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
                .get("session") or {}
            )
            sid = (src.get("cowrie") or {}).get("session_id") or h["_id"]
            yield {
                "session_id":       sid,
                "source_ip":        (src.get("source") or {}).get("ip"),
                "timestamp":        src.get("@timestamp"),
                "command_set":      set(enr.get("command_set") or ()),
                "command_count":    enr.get("command_count") or 0,
                "unique_commands":  enr.get("unique_commands") or 0,
                "dominant_intent":  enr.get("dominant_intent"),
                "playbook_id":      enr.get("playbook_id"),
                "playbook_name":    enr.get("playbook_name"),
            }
        search_after = hits[-1].get("sort")
        if search_after is None:
            return


def _fetch_command_lines(
    es, commands_index: str, hashes: set[str], page_size: int,
) -> dict[str, str]:
    """Bulk-resolve {16-hex hash → command_line text} via mget. The
    enriched-command index uses ``sha256[:16]`` as the doc ``_id``."""
    out: dict[str, str] = {}
    if not hashes:
        return out
    hash_list = sorted(hashes)
    for i in range(0, len(hash_list), page_size):
        batch = hash_list[i : i + page_size]
        resp = es.mget(
            index=commands_index,
            body={"ids": batch},
            _source=["process.command_line"],
        )
        for doc in resp.get("docs") or []:
            if not doc.get("found"):
                continue
            src = doc.get("_source") or {}
            cmd_line = (src.get("process") or {}).get("command_line")
            if cmd_line:
                out[doc["_id"]] = cmd_line
    return out


# ---------------------------------------------------------------------------
# Pair mining
# ---------------------------------------------------------------------------

def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _mine_bucket_pairs(
    bucket_kind: str,
    bucket_value: str,
    members: list[dict],
    rng: random.Random,
    sample_cap: int,
    jaccard_max: float,
    min_unique_cmd_ratio: float,
) -> list[tuple]:
    """Generate (jaccard, bucket_kind, bucket_value, a_id, b_id) tuples
    for every pair in ``members`` whose Jaccard is ≤ ``jaccard_max`` and
    whose unique-command counts aren't structurally lopsided.

    Sample down to ``sample_cap`` members when the bucket is big — the
    pair count is O(N²) and a few large playbooks would otherwise
    dominate the global heap.

    The structural-symmetry filter rejects pairs where
    ``min(a.unique_commands, b.unique_commands) /
    max(a.unique_commands, b.unique_commands) < min_unique_cmd_ratio``.
    Set ratio to 0.0 to disable. Catches "3-command probe vs 12-command
    persistence playbook" pairs that aren't a meaningful "same
    behavior?" comparison — the triage step always rejects these and
    they waste pair-cap budget.
    """
    pop = list(members)
    if len(pop) > sample_cap:
        pop = rng.sample(pop, sample_cap)
    out: list[tuple] = []
    for a, b in combinations(pop, 2):
        if min_unique_cmd_ratio > 0.0:
            a_uc = max(int(a["unique_commands"]), 1)
            b_uc = max(int(b["unique_commands"]), 1)
            lo, hi = (a_uc, b_uc) if a_uc <= b_uc else (b_uc, a_uc)
            if lo / hi < min_unique_cmd_ratio:
                continue
        # Both members guaranteed to have non-empty command_set (filter
        # applied upstream), so Jaccard denominator is never zero.
        j = _jaccard(a["command_set"], b["command_set"])
        if j > jaccard_max:
            continue
        # Pair key is sorted session ids so the same pair from two
        # different buckets dedupes correctly later.
        a_id, b_id = sorted((a["session_id"], b["session_id"]))
        out.append((j, bucket_kind, bucket_value, a_id, b_id))
    return out


def _dedupe_keep_best(pairs: list[tuple]) -> list[tuple]:
    """For pairs that appear in multiple buckets, keep the strongest
    annotation: playbook_id > dominant_intent. Tie-break stays first-seen."""
    _PRIORITY = {"playbook_id": 0, "dominant_intent": 1}
    by_pair: dict[tuple[str, str], tuple] = {}
    for p in pairs:
        j, kind, val, a_id, b_id = p
        key = (a_id, b_id)
        existing = by_pair.get(key)
        if existing is None:
            by_pair[key] = p
            continue
        if _PRIORITY[kind] < _PRIORITY[existing[1]]:
            by_pair[key] = p
    return list(by_pair.values())


# ---------------------------------------------------------------------------
# Build + render
# ---------------------------------------------------------------------------

def _build(args, cfg, secrets) -> dict:
    es = make_client(cfg.elasticsearch, secrets)
    sessions_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
    commands_idx = cfg.elasticsearch.indexes.cowrie.commands

    rng = random.Random(args.seed)

    # Pull and bucket. Cap total pulled sessions so a runaway index
    # doesn't OOM the box; the per-bucket sample is the real per-pair
    # cost control, but we still need an outer ceiling.
    by_playbook: dict[str, list[dict]] = {}
    by_intent:   dict[str, list[dict]] = {}
    pulled = 0
    skipped_short = 0
    for sess in _iter_session_rollups(es, sessions_idx, page_size=args.es_page_size):
        if sess["unique_commands"] < args.min_unique_commands:
            skipped_short += 1
            continue
        pid = sess.get("playbook_id")
        if pid:
            by_playbook.setdefault(pid, []).append(sess)
        intent = sess.get("dominant_intent")
        if intent:
            by_intent.setdefault(intent, []).append(sess)
        pulled += 1
        if pulled >= args.max_sessions:
            log.warning("hit --max-sessions=%d, stopping early", args.max_sessions)
            break

    log.info(
        "pulled %d sessions (skipped %d as < %d unique commands); "
        "%d playbook buckets, %d intent buckets",
        pulled, skipped_short, args.min_unique_commands,
        len(by_playbook), len(by_intent),
    )

    # Mine each bucket type. Eligibility = at least 2 members in the
    # bucket (otherwise no pairs are possible).
    raw_pairs: list[tuple] = []
    for pid, members in by_playbook.items():
        if len(members) < 2:
            continue
        # Intra-playbook (positive-case) pairs use the higher jaccard
        # cap. Same-playbook sessions are the positive test of the
        # 'behavior-not-text' thesis; surfacing more of them shifts the
        # v2 metric's denominator toward something statistically usable
        # without diluting the lexical-divergence claim.
        raw_pairs.extend(_mine_bucket_pairs(
            "playbook_id", pid, members, rng,
            sample_cap=args.max_bucket_sample,
            jaccard_max=args.jaccard_max_intra_playbook,
            min_unique_cmd_ratio=args.min_unique_cmd_ratio,
        ))
    for intent, members in by_intent.items():
        if len(members) < 2:
            continue
        # Cross-playbook (negative-case) pairs use the stricter cap.
        # Two genuinely different behaviors sharing 20% of commands
        # is already on the edge of meaningfully-textually-divergent.
        raw_pairs.extend(_mine_bucket_pairs(
            "dominant_intent", intent, members, rng,
            sample_cap=args.max_bucket_sample,
            jaccard_max=args.jaccard_max,
            min_unique_cmd_ratio=args.min_unique_cmd_ratio,
        ))

    log.info("raw candidate pairs (pre-dedup): %d", len(raw_pairs))
    n_raw = len(raw_pairs)
    pairs = _dedupe_keep_best(raw_pairs)
    n_deduped = len(pairs)
    log.info("deduped pairs: %d", n_deduped)

    # Sort by Jaccard ascending (most divergent first). Within ties,
    # prefer playbook_id-tagged pairs over dominant_intent — same
    # priority as the dedup, so the strongest behavior signal floats up.
    _BUCKET_PRIORITY = {"playbook_id": 0, "dominant_intent": 1}
    pairs.sort(key=lambda p: (p[0], _BUCKET_PRIORITY[p[1]], p[3], p[4]))

    # Comparison-axis key per session: the playbook the session belongs
    # to (strongest behavioral signal), or a synthetic "intent:X" axis
    # for unattributed sessions. Two pairs with the same sorted-pair-of-
    # axis-keys test the same behavior comparison even when the session
    # ids differ. The per-axis cap below uses this to enforce *axis*
    # diversity, not just session diversity — the per-session cap can't
    # see "all 19 of these pairs are short-SSH-persist vs Mirai-probe."
    sid_to_axis: dict[str, str] = {}
    for src in (by_playbook, by_intent):
        for members in src.values():
            for m in members:
                sid = m["session_id"]
                if sid in sid_to_axis:
                    continue
                pid = m.get("playbook_id")
                if pid:
                    sid_to_axis[sid] = pid
                else:
                    intent = m.get("dominant_intent") or "_unknown_"
                    sid_to_axis[sid] = f"_intent:{intent}_"

    # Walk sorted pairs once and apply two caps in sequence:
    #   * per-session: bounds how often any one session_id appears
    #   * per-axis:    bounds how often any one behavior-comparison
    #                  (axis_a, axis_b) appears
    # The per-axis cap is the diversity-load-bearing one in this
    # corpus; the per-session cap is a safety valve for magnet sessions.
    per_sid: dict[str, int] = {}
    per_axis: dict[tuple, int] = {}
    capped: list[tuple] = []
    n_dropped_session = 0
    n_dropped_axis = 0
    for p in pairs:
        _, _, _, a_id, b_id = p
        axis = tuple(sorted([sid_to_axis[a_id], sid_to_axis[b_id]]))
        if (per_sid.get(a_id, 0) >= args.max_pairs_per_session or
                per_sid.get(b_id, 0) >= args.max_pairs_per_session):
            n_dropped_session += 1
            continue
        if per_axis.get(axis, 0) >= args.max_pairs_per_comparison_axis:
            n_dropped_axis += 1
            continue
        capped.append(p)
        per_sid[a_id] = per_sid.get(a_id, 0) + 1
        per_sid[b_id] = per_sid.get(b_id, 0) + 1
        per_axis[axis] = per_axis.get(axis, 0) + 1
        if len(capped) >= args.target_pairs:
            break
    pairs = capped
    log.info(
        "kept %d pairs after caps (session=%d, axis=%d, target=%d); "
        "dropped %d on session cap, %d on axis cap",
        len(pairs), args.max_pairs_per_session,
        args.max_pairs_per_comparison_axis, args.target_pairs,
        n_dropped_session, n_dropped_axis,
    )

    # Build session index for quick lookup.
    sid_to_sess: dict[str, dict] = {}
    needed_hashes: set[str] = set()
    for j, kind, val, a_id, b_id in pairs:
        for sid in (a_id, b_id):
            if sid in sid_to_sess:
                continue
            # The same session may appear in either bucket. Pick from
            # whichever map we find it in.
            cand = None
            for src in (by_playbook, by_intent):
                for members in src.values():
                    for m in members:
                        if m["session_id"] == sid:
                            cand = m
                            break
                    if cand:
                        break
                if cand:
                    break
            if cand is None:
                log.warning("pair references unknown session %s — skipping", sid)
                continue
            sid_to_sess[sid] = cand
            needed_hashes |= cand["command_set"]

    log.info(
        "fetching command text for %d unique hashes from %s",
        len(needed_hashes), commands_idx,
    )
    cmd_lines = _fetch_command_lines(es, commands_idx, needed_hashes, page_size=512)
    log.info("resolved %d / %d command lines", len(cmd_lines), len(needed_hashes))

    def _render_session(sess: dict) -> dict:
        return {
            "session_id":      sess["session_id"],
            "source_ip":       sess.get("source_ip"),
            "timestamp":       sess.get("timestamp"),
            "dominant_intent": sess.get("dominant_intent"),
            "playbook_id":     sess.get("playbook_id"),
            "playbook_name":   sess.get("playbook_name"),
            "command_count":   sess["command_count"],
            "unique_commands": sess["unique_commands"],
            "command_set":     sorted(sess["command_set"]),
            "command_lines":   {
                h: cmd_lines[h] for h in sorted(sess["command_set"]) if h in cmd_lines
            },
        }

    # Pair ids are dp-NNN in jaccard-ascending output order. Stable
    # within a (corpus, seed) draw — re-runs against the same corpus
    # produce identical ids — but they are NOT durable across corpus
    # changes. Downstream tools (the per-pair markdown renderer +
    # build_eval_set.py --mode picks) treat them as opaque strings.
    rendered: list[dict] = []
    next_idx = 1
    for j, kind, val, a_id, b_id in pairs:
        if a_id not in sid_to_sess or b_id not in sid_to_sess:
            continue
        rendered.append({
            "pair_id":       f"dp-{next_idx:03d}",
            "jaccard":       round(j, 4),
            "bucket_kind":   kind,
            "bucket_value":  val,
            "session_a":     _render_session(sid_to_sess[a_id]),
            "session_b":     _render_session(sid_to_sess[b_id]),
        })
        next_idx += 1

    return {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "config": {
            "jaccard_max":                    args.jaccard_max,
            "jaccard_max_intra_playbook":     args.jaccard_max_intra_playbook,
            "target_pairs":                   args.target_pairs,
            "max_bucket_sample":              args.max_bucket_sample,
            "max_sessions":                   args.max_sessions,
            "min_unique_commands":            args.min_unique_commands,
            "min_unique_cmd_ratio":           args.min_unique_cmd_ratio,
            "max_pairs_per_session":          args.max_pairs_per_session,
            "max_pairs_per_comparison_axis":  args.max_pairs_per_comparison_axis,
            "seed":                           args.seed,
        },
        "stats": {
            "sessions_pulled":             pulled,
            "sessions_skipped_short":      skipped_short,
            "playbook_buckets":            len(by_playbook),
            "intent_buckets":              len(by_intent),
            "raw_pairs":                   n_raw,
            "deduped_pairs":               n_deduped,
            "dropped_by_session_cap":      n_dropped_session,
            "dropped_by_axis_cap":         n_dropped_axis,
            "kept_pairs":                  len(rendered),
            "unique_comparison_axes":      len(per_axis),
            "unique_hashes_resolved":      len(cmd_lines),
            "unique_hashes_total":         len(needed_hashes),
        },
        "pairs":  rendered,
    }


def _render_stdout(report: dict) -> str:
    out: list[str] = []
    out.append("=" * 78)
    out.append("E1.1 — divergent candidate pairs")
    out.append("=" * 78)
    s = report["stats"]
    c = report["config"]
    out.append(
        f"pulled sessions     {s['sessions_pulled']}  "
        f"(skipped {s['sessions_skipped_short']} as <{c['min_unique_commands']} unique cmds)"
    )
    out.append(
        f"buckets             playbook={s['playbook_buckets']}  "
        f"dominant_intent={s['intent_buckets']}"
    )
    out.append(
        f"pairs               raw={s['raw_pairs']}  kept={s['kept_pairs']}  "
        f"({s['unique_comparison_axes']} unique comparison axes; "
        f"jaccard ≤ {c['jaccard_max']} cross / "
        f"≤ {c['jaccard_max_intra_playbook']} intra, "
        f"target {c['target_pairs']})"
    )
    out.append(
        f"dropped by caps     session={s['dropped_by_session_cap']}  "
        f"axis={s['dropped_by_axis_cap']}  "
        f"(per-session max {c['max_pairs_per_session']}, "
        f"per-axis max {c['max_pairs_per_comparison_axis']}, "
        f"min ratio {c['min_unique_cmd_ratio']})"
    )
    out.append(
        f"command-line fetch  {s['unique_hashes_resolved']} / {s['unique_hashes_total']} hashes resolved"
    )
    out.append("")
    out.append("Top 10 most-divergent pairs (analyst preview):")
    for p in report["pairs"][:10]:
        a, b = p["session_a"], p["session_b"]
        out.append(
            f"  j={p['jaccard']:.3f}  {p['bucket_kind']}={p['bucket_value']}"
        )
        out.append(
            f"    A {a['session_id']}  ip={a['source_ip']}  "
            f"pb={a['playbook_name']!r}  intent={a['dominant_intent']}"
        )
        ac = " | ".join(
            f"{a['command_lines'][h][:60]}" for h in a["command_set"] if h in a["command_lines"]
        )[:200]
        out.append(f"      cmds: {ac or '(unresolved)'}")
        out.append(
            f"    B {b['session_id']}  ip={b['source_ip']}  "
            f"pb={b['playbook_name']!r}  intent={b['dominant_intent']}"
        )
        bc = " | ".join(
            f"{b['command_lines'][h][:60]}" for h in b["command_set"] if h in b["command_lines"]
        )[:200]
        out.append(f"      cmds: {bc or '(unresolved)'}")
        out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path,
                    default=Path("eval/divergent-candidates.jsonl"),
                    help="Where to write the per-pair JSONL.")
    ap.add_argument("--jaccard-max", type=float, default=0.2,
                    help=(
                        "Reject pairs whose command-set Jaccard exceeds "
                        "this. Applies to cross-playbook (dominant_intent "
                        "bucket) pairs — the negative-case half of the "
                        "candidate pool. The intra-playbook positive "
                        "half uses --jaccard-max-intra-playbook instead."
                    ))
    ap.add_argument("--jaccard-max-intra-playbook", type=float, default=0.3,
                    help=(
                        "Jaccard cap for intra-playbook (playbook_id "
                        "bucket) pairs — the positive-case half. Defaults "
                        "slightly higher than --jaccard-max because the "
                        "'behavior-not-text' thesis still holds at 30%% "
                        "command overlap (the pair tests whether the "
                        "embedding groups same-playbook sessions whose "
                        "commands differ by a clear margin), and the "
                        "small-corpus positive-case pool is thin enough "
                        "that an extra 10%% headroom typically surfaces "
                        "an extra axis or two."
                    ))
    ap.add_argument("--target-pairs", type=int, default=100,
                    help="Keep this many most-divergent pairs after dedupe.")
    ap.add_argument("--max-bucket-sample", type=int, default=300,
                    help="Sample this many members per bucket when generating pairs.")
    ap.add_argument("--max-pairs-per-session", type=int, default=1,
                    help=(
                        "Each session can appear in at most this many "
                        "surfaced pairs. Default 1 matches the build "
                        "step's hard constraint (each session may belong "
                        "to exactly one kept pair after triage). Raising "
                        "above 1 surfaces extra candidates the triage "
                        "must mechanically skip — only useful on much "
                        "larger corpora where the analyst genuinely "
                        "wants to choose between competing pairs for the "
                        "same magnet session."
                    ))
    ap.add_argument("--max-pairs-per-comparison-axis", type=int, default=2,
                    help=(
                        "Each *behavior comparison axis* — sorted tuple of "
                        "both members' playbook_id (or `_intent:X_` for "
                        "unattributed sessions) — can appear in at most "
                        "this many surfaced pairs. This is the diversity "
                        "control; the per-session cap above is a safety "
                        "valve. Lower this when the triage step is mostly "
                        "rejecting pairs as 'redundant with dp-NNN'."
                    ))
    ap.add_argument("--min-unique-cmd-ratio", type=float, default=0.3,
                    help=(
                        "Reject pairs whose "
                        "min(unique_commands) / max(unique_commands) is "
                        "below this. Catches '3-command probe vs 12-command "
                        "persistence' pairs that aren't a meaningful 'same "
                        "behavior?' comparison. 0 = disabled."
                    ))
    ap.add_argument("--max-sessions", type=int, default=50000,
                    help="Hard outer ceiling on rollup docs pulled from ES.")
    ap.add_argument("--min-unique-commands", type=int, default=3,
                    help="Skip sessions with fewer than this many unique commands.")
    ap.add_argument("--es-page-size", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=20260601)
    ap.add_argument("--config", type=str, default=None,
                    help="Optional override config path passed to load_config.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config(args.config) if args.config else load_config()
    secrets = load_secrets(args.config) if args.config else load_secrets()

    report = _build(args, cfg, secrets)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for pair in report["pairs"]:
            f.write(json.dumps(pair, sort_keys=True))
            f.write("\n")
    print(f"wrote {len(report['pairs'])} candidate pairs to {args.output}")

    summary_path = args.output.with_suffix(".summary.json")
    summary = {k: v for k, v in report.items() if k != "pairs"}
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"wrote summary to {summary_path}")

    print()
    print(_render_stdout(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
