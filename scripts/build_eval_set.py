"""Export a stratified sample of cowrie sessions for offline labeling.

Companion to brutal-review phase 1: builds the unlabeled side of
`eval/sessions-v1.unlabeled.jsonl`, which an analyst then labels into
`eval/sessions-v1.jsonl` per `eval/RUBRIC.md`.

Stratification axes (per the handoff plan):
  * playbook size band (`solo`, `small`, `medium`, `large`, `unattributed`)
  * `dominant_intent` (LLM-assigned per-session intent)
  * intel-verdict label (`malicious`, `clean`, `unknown`)

Per session we emit one JSON record:

    {
      "session_id":          "<cowrie session_id>",
      "stratum":             {"size_band": ..., "intent": ..., "intel": ...},
      "rollup_doc":          {...},            # the rollup doc verbatim
      "raw_events":          [{...}, ...],     # cowrie.session.* events
      "command_enrichments": [{...}, ...]      # one per unique command line
    }

No embeddings — those get recomputed at eval time from the embedding model
of the day. Output file is gitignored; the analyst-labeled version
(`eval/sessions-v1.jsonl`) is the one that ships.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/build_eval_set.py --n 300
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets
from enrich.es_client import make_client


_WS_RE = re.compile(r"\s+")


def _normalize_command(cmd: str, max_chars: int = 8192) -> str:
    """Mirror enrich.sources.cowrie.commands.normalize so the short hash we
    compute here matches the ES `_id` written by `enrich`."""
    s = _WS_RE.sub(" ", (cmd or "").strip())
    return s[:max_chars]


def _short_command_hash(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _intel_label(rollup: dict) -> str:
    """Pull the IP-intel verdict bucket off a rollup doc."""
    enrichment = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    intel = enrichment.get("source_ip_intel") or {}
    label = intel.get("consensus_label")
    if isinstance(label, str) and label:
        return label
    if intel.get("consensus_malicious") is True:
        return "malicious"
    if intel.get("override_applied") == "authoritative_clean":
        return "clean"
    return "unknown"


def _dominant_intent(rollup: dict) -> str:
    enrichment = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    intent = enrichment.get("dominant_intent")
    return intent if isinstance(intent, str) and intent else "intent_unknown"


def _playbook_id(rollup: dict) -> str | None:
    enrichment = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    pid = enrichment.get("playbook_id")
    return pid if isinstance(pid, str) and pid else None


def _size_band(member_count: int | None) -> str:
    if member_count is None:
        return "unattributed"
    if member_count <= 1:
        return "solo"
    if member_count <= 9:
        return "small"
    if member_count <= 99:
        return "medium"
    return "large"


def _stratum_key(rollup: dict, playbook_sizes: dict[str, int]) -> tuple[str, str, str]:
    """Display stratum recorded on every JSONL record for downstream
    eval consumers; NOT used as the sampling axis any more."""
    pid = _playbook_id(rollup)
    size = playbook_sizes.get(pid) if pid else None
    return (_size_band(size), _dominant_intent(rollup), _intel_label(rollup))


def _sampling_key(rollup: dict) -> tuple[str, str]:
    """Sampling axis: one bucket per behaviour. Each named ``playbook_id``
    is one bucket; unattributed sessions (HDBSCAN noise / pre-cluster)
    each get their own synthetic bucket so the per-bucket cap lets every
    distinct outlier through. Without this each unattributed session
    would share a single bucket and lose all its variety."""
    pid = _playbook_id(rollup)
    if pid:
        return ("pb", pid)
    sid = (rollup.get("cowrie") or {}).get("session_id") or "?"
    return ("unattributed", sid)


def _has_commands(rollup: dict) -> bool:
    """True when the session executed at least one command. Login-only
    sessions (credential sprays that never reached a shell) carry no
    command-stream signal, so the eval set drops them at the gate."""
    enr = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    return (enr.get("command_count") or 0) > 0


def _load_playbook_sizes(es, index: str) -> dict[str, int]:
    """Return {playbook_id: rollup-session count} via a terms agg.

    Sessions without a playbook_id (HDBSCAN noise / pre-cluster sessions)
    are intentionally absent — they bucket as `unattributed` upstream."""
    field = "dshield.cowrie.enrichment.session.playbook_id"
    body = {
        "size": 0,
        "aggs": {
            "playbooks": {
                "terms": {"field": field, "size": 10000, "min_doc_count": 1}
            }
        },
    }
    resp = es.search(index=index, **body)
    buckets = (resp.get("aggregations") or {}).get("playbooks", {}).get("buckets", [])
    return {b["key"]: int(b["doc_count"]) for b in buckets}


def _iter_random_rollups(
    es, index: str, seed: int, page_size: int = 500,
) -> Iterator[dict]:
    """Yield rollup `_source` dicts in random_score order, restricted to
    sessions that executed at least one command. ``function_score`` with
    a fixed seed makes the (corpus, seed) draw repeatable; the inner
    range filter on ``command_count > 0`` keeps ES from streaming back
    login-only rollups that the sampler would just drop anyway."""
    body = {
        "size": page_size,
        "query": {
            "function_score": {
                "query": {
                    "bool": {
                        "filter": [{
                            "range": {
                                "dshield.cowrie.enrichment.session.command_count": {
                                    "gt": 0
                                }
                            }
                        }]
                    }
                },
                "random_score": {"seed": seed, "field": "_seq_no"},
            }
        },
        # `_id` fielddata sorts are rejected on modern ES — use `_doc` as the
        # tiebreaker, matching every other backfill verb in the project (see
        # the ROADMAP analyst-artifact-rules scan postmortem).
        "sort": [{"_score": "desc"}, {"_doc": "asc"}],
    }
    search_after: list | None = None
    while True:
        if search_after is not None:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return
        for h in hits:
            yield h["_source"]
        last = hits[-1]
        search_after = last.get("sort")
        if search_after is None:
            return


def _fetch_raw_events(es, raw_index: str, session_id: str) -> list[dict]:
    """All raw cowrie.session.* events for a given session_id, asc by time."""
    body = {
        "size": 5000,
        "query": {"term": {"cowrie.session_id": session_id}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }
    resp = es.search(index=raw_index, **body)
    return [h["_source"] for h in resp["hits"]["hits"]]


def _unique_command_lines(raw_events: Iterable[dict]) -> list[str]:
    seen: dict[str, None] = {}
    for ev in raw_events:
        if (ev.get("event") or {}).get("action") != "cowrie.command.input":
            continue
        cmd = (ev.get("process") or {}).get("command_line")
        if isinstance(cmd, str) and cmd and cmd not in seen:
            seen[cmd] = None
    return list(seen)


def _fetch_command_enrichments(
    es, cmd_index: str, command_lines: Iterable[str],
) -> list[dict]:
    """`mget` enrichments keyed by the short hash of the normalized command."""
    ids = [_short_command_hash(_normalize_command(c)) for c in command_lines]
    ids = list(dict.fromkeys(i for i in ids if i))
    if not ids:
        return []
    resp = es.mget(index=cmd_index, ids=ids)
    return [d["_source"] for d in resp.get("docs", []) if d.get("found")]


def _mget_by_id(es, index: str, ids: Iterable[str]) -> dict[str, dict]:
    """`mget` against `index` by doc `_id`. Returns ``{id: _source}`` for
    every doc found; missing ids are silently dropped (caller may rely
    on dict.get(id, None) for the not-found case)."""
    ids = [i for i in dict.fromkeys(ids) if i]
    if not ids:
        return {}
    try:
        resp = es.mget(index=index, ids=ids)
    except Exception:
        # Intel/rule indices may not exist on every deploy (e.g. fresh
        # install before `intel refresh` ever ran). Treat as no-hits.
        return {}
    out: dict[str, dict] = {}
    for d in resp.get("docs", []):
        if d.get("found") and isinstance(d.get("_source"), dict):
            out[d["_id"]] = d["_source"]
    return out


def _collect_session_hashes(
    rollup_enrichment: dict, raw_events: list[dict],
) -> list[str]:
    """Every sha256 we can join to file-hash intel: from rollup's
    `file_events[]`, from raw `cowrie.session.file_{download,upload}`
    events, and from each session-level threat.indicator.file.hash."""
    out: list[str] = []
    for fe in rollup_enrichment.get("file_events") or []:
        sha = fe.get("sha256")
        if sha:
            out.append(sha.lower())
    for ev in raw_events:
        action = ((ev.get("event") or {}).get("action") or "")
        if action in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            sha = ((ev.get("file") or {}).get("hash") or {}).get("sha256") \
                or (ev.get("cowrie") or {}).get("shasum")
            if sha:
                out.append(sha.lower())
    return list(dict.fromkeys(out))


def _collect_session_urls(
    rollup_enrichment: dict, raw_events: list[dict],
) -> list[str]:
    """Every URL we can join to url intel: from rollup file_events and
    raw cowrie.session.file_download events that carry a source URL."""
    out: list[str] = []
    for fe in rollup_enrichment.get("file_events") or []:
        url = fe.get("url")
        if url:
            out.append(url)
    for ev in raw_events:
        action = ((ev.get("event") or {}).get("action") or "")
        if action in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            url = (ev.get("cowrie") or {}).get("url") \
                or ((ev.get("url") or {}).get("full"))
            if url:
                out.append(url)
    return list(dict.fromkeys(out))


# NOTE: analyst rule docs are intentionally NOT prefetched. They were
# previously surfaced in the rendered session view, but doing so let
# the analyst label on out-of-band attribution the embedding model
# can't use — biasing the eval against the pipeline. The matched
# substring is still in the command text, which both sides see.


def _sample_stratified(
    rollups: Iterator[dict],
    playbook_sizes: dict[str, int],
    target_n: int,
    per_playbook_cap: int,
) -> tuple[list[dict], dict]:
    """Variety-first sampler keyed on ``playbook_id``.

    Single pass: drop login-only rollups, then bucket each remaining
    rollup by its sampling key (``playbook_id`` when assigned; otherwise
    a per-session synthetic bucket — see ``_sampling_key``). Walk
    buckets smallest-to-largest and take ``min(pool, per_playbook_cap)``
    from each. Unattributed sessions live in singleton buckets so they
    always pass through; named playbooks are capped so a single
    behaviour can't dominate the eval set.

    With many distinct unattributed sessions the sampler will fill to
    ``target_n``; with few, the result is naturally short of target —
    which is the intended trade-off when variety beats volume.
    """
    by_stratum: dict[tuple, list[dict]] = defaultdict(list)
    scanned = 0
    skipped_no_commands = 0
    for rollup in rollups:
        scanned += 1
        if not _has_commands(rollup):
            skipped_no_commands += 1
            continue
        by_stratum[_sampling_key(rollup)].append(rollup)
    if not by_stratum:
        return [], {
            "scanned":             scanned,
            "skipped_no_commands": skipped_no_commands,
            "active_strata":       0,
            "named_playbooks":     0,
            "unattributed":        0,
        }

    # Smallest buckets first so unattributed singletons pass through
    # completely; named-playbook buckets at the tail absorb whatever
    # the cap allows.
    strata = sorted(by_stratum.items(), key=lambda kv: len(kv[1]))
    out: list[dict] = []
    for key, pool in strata:
        if len(out) >= target_n:
            break
        take = min(len(pool), per_playbook_cap, target_n - len(out))
        if take <= 0:
            continue
        out.extend(pool[:take])

    named = sum(1 for k in by_stratum if k[0] == "pb")
    unattr = sum(1 for k in by_stratum if k[0] == "unattributed")
    stats = {
        "scanned":             scanned,
        "skipped_no_commands": skipped_no_commands,
        "active_strata":       len(by_stratum),
        "named_playbooks":     named,
        "unattributed":        unattr,
        "per_playbook_cap":    per_playbook_cap,
    }
    return out, stats


def _build_record(es, *, raw_index: str, cmd_index: str,
                  hash_intel_index: str, url_intel_index: str,
                  rollup: dict,
                  playbook_sizes: dict[str, int]) -> dict | None:
    cowrie = rollup.get("cowrie") or {}
    session_id = cowrie.get("session_id")
    if not session_id:
        return None
    raw_events = _fetch_raw_events(es, raw_index, session_id)
    command_lines = _unique_command_lines(raw_events)
    enrichments = _fetch_command_enrichments(es, cmd_index, command_lines)

    # Pre-join external CTI verdicts for every file hash + URL the
    # session touched. Intel is treated as fair-game context for the
    # eval: it's the same public-feed verdict the pipeline's own intel
    # subsystem consumes, not analyst attribution.
    rollup_enrichment = (
        (((rollup.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {})
        .get("session") or {}
    )
    hash_intel = _mget_by_id(
        es, hash_intel_index,
        _collect_session_hashes(rollup_enrichment, raw_events),
    )
    url_intel = _mget_by_id(
        es, url_intel_index,
        _collect_session_urls(rollup_enrichment, raw_events),
    )

    band, intent, intel = _stratum_key(rollup, playbook_sizes)
    return {
        "session_id":          session_id,
        "stratum":             {"size_band": band, "intent": intent, "intel": intel},
        "rollup_doc":          rollup,
        "raw_events":          raw_events,
        "command_enrichments": enrichments,
        "hash_intel":          hash_intel,
        "url_intel":           url_intel,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=300,
                    help="Target number of sampled sessions (default: 300)")
    ap.add_argument("--per-playbook-cap", type=int, default=5,
                    help=(
                        "Max sessions kept per playbook_id. Unattributed "
                        "sessions (no playbook_id assigned) each get "
                        "their own singleton bucket so the cap doesn't "
                        "throttle outliers. Default 5 — keeps variety "
                        "high; lower it for tighter variety at the cost "
                        "of total count."
                    ))
    ap.add_argument("--seed", type=int, default=20260531,
                    help="random_score seed; reproducible per (corpus, seed)")
    ap.add_argument("--output", type=Path,
                    default=Path("eval/sessions-v1.unlabeled.jsonl"),
                    help="Output path (gitignored by convention)")
    ap.add_argument("--scan-cap", type=int, default=20000,
                    help=(
                        "Hard ceiling on rollup docs scanned to fill the "
                        "sample. Stops early on tiny corpora."
                    ))
    args = ap.parse_args()

    cfg = load_config()
    sec = load_secrets()
    es = make_client(cfg.elasticsearch, sec)

    cowrie_idx = cfg.elasticsearch.indexes.cowrie
    rollup_index = cowrie_idx.sessions_rollup
    raw_index = cowrie_idx.sessions_raw
    cmd_index = cowrie_idx.commands
    hash_intel_index = cfg.intel.indexes.hash
    url_intel_index = cfg.intel.indexes.url

    print(f"rollup index      : {rollup_index}", file=sys.stderr)
    print(f"raw events idx    : {raw_index}", file=sys.stderr)
    print(f"commands idx      : {cmd_index}", file=sys.stderr)
    print(f"target N          : {args.n}", file=sys.stderr)
    print(f"scan cap          : up to {args.scan_cap} rollups", file=sys.stderr)
    print(f"per-playbook cap  : {args.per_playbook_cap}", file=sys.stderr)
    print(f"seed              : {args.seed}", file=sys.stderr)

    playbook_sizes = _load_playbook_sizes(es, rollup_index)
    print(f"playbooks seen    : {len(playbook_sizes)}", file=sys.stderr)

    def _stream() -> Iterator[dict]:
        seen = 0
        for rollup in _iter_random_rollups(es, rollup_index, args.seed):
            yield rollup
            seen += 1
            if seen >= args.scan_cap:
                return

    # Variety-first sampling: bucket by playbook_id (with each
    # unattributed session as its own bucket) and cap per playbook so
    # one behaviour can't dominate. Login-only rollups are dropped at
    # the gate — they have no command-stream signal.
    sampled, sample_stats = _sample_stratified(
        _stream(), playbook_sizes, args.n, args.per_playbook_cap,
    )
    if not sampled:
        print("[ERROR] no rollup docs scanned — is the index empty?",
              file=sys.stderr)
        return 1
    print(
        f"sampled           : {len(sampled)} rollups "
        f"(scanned {sample_stats['scanned']}, "
        f"skipped {sample_stats['skipped_no_commands']} login-only, "
        f"{sample_stats['named_playbooks']} named playbooks + "
        f"{sample_stats['unattributed']} unattributed sessions)",
        file=sys.stderr,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    stratum_counts: dict[str, int] = defaultdict(int)
    written = 0
    with args.output.open("w", encoding="utf-8") as f:
        for rollup in sampled:
            rec = _build_record(
                es,
                raw_index=raw_index,
                cmd_index=cmd_index,
                hash_intel_index=hash_intel_index,
                url_intel_index=url_intel_index,
                rollup=rollup,
                playbook_sizes=playbook_sizes,
            )
            if rec is None:
                continue
            f.write(json.dumps(rec, default=str) + "\n")
            written += 1
            stratum_counts[str(rec["stratum"])] += 1

    print(f"wrote           : {written} records -> {args.output}", file=sys.stderr)
    print("stratum counts (top 12):", file=sys.stderr)
    for k, v in sorted(stratum_counts.items(), key=lambda kv: -kv[1])[:12]:
        print(f"  {v:4d}  {k}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
