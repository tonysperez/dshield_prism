"""Export cowrie sessions for offline labeling.

Stratified random sample of cowrie sessions → ``eval/sessions.unlabeled.jsonl.gz``,
the labeled-clustering eval set (`eval_clustering.py`).

Stratification axes (recorded on every record):
  * playbook size band (`solo`, `small`, `medium`, `large`, `unattributed`)
  * `dominant_intent` (LLM-assigned per-session intent)
  * intel-verdict label (`malicious`, `clean`, `unknown`)

Per session we emit one JSON record:

    {
      "session_id":          "<cowrie session_id>",
      "stratum":             {"size_band": ..., "intent": ..., "intel": ...},
      "rollup_doc":          {...},            # the rollup doc verbatim
      "raw_events":          [{...}, ...],     # cowrie.session.* events
      "command_enrichments": [{...}, ...],     # one per unique command line
    }

The session ``embedding`` field, when present on the rollup doc, is written
into ``rollup_doc`` verbatim and frozen in the JSONL — it is NOT recomputed at
eval time. ``scripts/refresh_eval_embeddings.py`` is the only supported way to
refresh a stale embedding after a production re-embed. Output file is
gitignored; the analyst-labeled YAML sibling (``eval/labels.yaml``) is the
deliverable that ships.

Only sessions whose rollup carries ``dshield.classification: public`` are
sampled (``is_releasable`` gate); confidential and untagged rollups are
skipped. Attacker-side artifacts (IPs, file hashes, URL schemes) are defanged
in place and ``cowrie.password`` is masked before write — see
``_defang_record``.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/build_eval_set.py --n 300
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eval_jsonl import open_jsonl

from enrich.classification import is_releasable
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


# Top-level keys carrying sensor / Filebeat / Elastic-agent fingerprints
# that must NEVER reach the public eval set. Stripped wholesale from every
# ES _source dict before the record is written. Notably absent: `source`
# (the attacker — the data point we want), `cowrie`, `process`, `user`,
# `user_agent`, `threat`, `dshield`, `observer`, `event`, `@timestamp`,
# `file`, `network`, `destination` (port kept; see below).
_REDACT_TOP_LEVEL_KEYS = frozenset({
    "agent",          # Filebeat agent ID / hostname
    "container",      # ingest container hint
    "data_stream",    # ingest pipeline name
    "ecs",            # ECS version (harmless but unnecessary)
    "elastic_agent",  # agent UUID
    "host",           # SENSOR host: name, id, MAC, internal IPs
    "input",          # filestream input metadata
    "log",            # SENSOR filesystem path / inode / fingerprint
    "metadata",       # ingest pipeline metadata, beats host IP
    "related",        # related.ip duplicates source.ip but includes dst
    "tags",           # ingest tags
    "type",           # input type ("redis-input")
    "@version",       # logstash artifact
    "message",        # often quotes dst_ip inline (e.g. "New connection: x → dst")
})


def _redact_event(ev: dict) -> dict:
    """Strip sensor / Filebeat / Elastic-agent metadata from an ES
    _source dict. Operates in place and returns the same dict.

    Specifically removes:
      - Every top-level key in ``_REDACT_TOP_LEVEL_KEYS`` (sensor host
        identity, ingest pipeline metadata, etc.).
      - ``destination.ip`` (the sensor's internal honeypot bind IP).
        ``destination.port`` is kept — 2222 is the standard cowrie
        listen port and not sensitive.
      - ``event.original`` (the duplicated raw cowrie JSON; it inlines
        ``dst_ip`` again and adds nothing the structured fields don't
        already carry).
    """
    if not isinstance(ev, dict):
        return ev
    for k in list(ev):
        if k in _REDACT_TOP_LEVEL_KEYS:
            del ev[k]
    dst = ev.get("destination")
    if isinstance(dst, dict):
        dst.pop("ip", None)
    # observer.ip is the SENSOR's listen IP — strip. observer.type
    # (honeypot) and observer.vendor (Cowrie) are kept as ECS context.
    obs = ev.get("observer")
    if isinstance(obs, dict):
        obs.pop("ip", None)
    event = ev.get("event")
    if isinstance(event, dict):
        event.pop("original", None)
    return ev


def _redact_record(rec: dict) -> dict:
    """Redact every ES _source carried by an eval-set record: the
    rollup_doc, every raw event, and every command enrichment. The
    intel docs (``hash_intel`` / ``url_intel``) are pure CTI-feed
    output written by `intel refresh` directly (not via Filebeat) and
    don't carry sensor metadata, so they pass through unmodified."""
    if isinstance(rec.get("rollup_doc"), dict):
        _redact_event(rec["rollup_doc"])
    for ev in rec.get("raw_events") or []:
        _redact_event(ev)
    for ev in rec.get("command_enrichments") or []:
        _redact_event(ev)
    return rec


def _is_releasable_rollup(rollup: dict, cfg) -> bool:
    """Gate a rollup on `dshield.classification` before it's ever sampled.
    Fail-safe: confidential AND untagged rollups are excluded (mirrors
    `is_releasable`'s default posture — see `src/enrich/classification.py`)."""
    classification = (rollup.get("dshield") or {}).get("classification")
    return is_releasable(classification, cfg)


# --- Defang: neuter attacker-side artifacts so the eval set is safe to
# publish. Distinct from `_redact_record` above, which strips sensor/ingest
# metadata — this targets the attacker's own IPs/hashes/URLs/credentials.
# Bracket/scheme substitution only: no whitespace or token is added or
# removed, so command-text token structure survives unchanged (asserted by
# smoke_test_build_eval_set.py). No repo precedent for a defang convention
# existed before this, so the form below is new and documented here:
#   IPv4      1.2.3.4       -> 1[.]2[.]3[.]4
#   URL       http://...    -> hxxp://...   (https -> hxxps)
#   hash      <hex string>  -> first half + "[.]" + second half
#   password  <any>         -> "<redacted>"  (masked outright, not defanged)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_URL_SCHEME_RE = re.compile(r"\bhttps?://", re.IGNORECASE)
_PASSWORD_MASK = "<redacted>"


def _defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def _defang_hash(h: str) -> str:
    mid = len(h) // 2
    return f"{h[:mid]}[.]{h[mid:]}"


def _defang_text(s: str) -> str:
    """Defang every inline IP / hash / URL-scheme occurrence in free text
    (command lines, IOC values). Structure-preserving — substitution only,
    never adds/removes whitespace, so token count is unchanged."""
    s = _URL_SCHEME_RE.sub(lambda m: m.group(0).replace("http", "hxxp"), s)
    s = _IPV4_RE.sub(lambda m: _defang_ip(m.group(0)), s)
    return _HASH_RE.sub(lambda m: _defang_hash(m.group(0)), s)


def _defang_walk(obj):
    """Recursively defang every string value in place — including bare
    strings inside a list (e.g. `artifact_set: ["ip:1.2.3.4", "url:http://..."]`,
    an LLM-extracted IOC summary; a naive dict-only walk misses these).
    `cowrie.password` is masked outright (not pattern-defanged) regardless of
    its value shape."""
    if isinstance(obj, dict):
        for k in list(obj):
            v = obj[k]
            if k == "password" and isinstance(v, str):
                obj[k] = _PASSWORD_MASK
            elif isinstance(v, (dict, list)):
                _defang_walk(v)
            elif isinstance(v, str):
                obj[k] = _defang_text(v)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                _defang_walk(item)
            elif isinstance(item, str):
                obj[i] = _defang_text(item)
    return obj


def _defang_keyed_iocs(d: dict) -> dict:
    """`hash_intel` / `url_intel` are dicts keyed by the raw IOC value
    itself (sha256 or URL) — rekey to the defanged form, and defang the
    joined intel doc's own fields (e.g. `artifact.value` duplicates the key)."""
    out: dict = {}
    for k, v in d.items():
        _defang_walk(v)
        out[_defang_text(k)] = v
    return out


def _defang_record(rec: dict) -> dict:
    """Neuter attacker-side artifacts across every part of an eval record:
    the rollup doc, raw events, command enrichments, and the joined
    hash/URL intel. Applied alongside `_redact_record`, not in place of it."""
    if isinstance(rec.get("rollup_doc"), dict):
        _defang_walk(rec["rollup_doc"])
    for ev in rec.get("raw_events") or []:
        _defang_walk(ev)
    for ev in rec.get("command_enrichments") or []:
        _defang_walk(ev)
    if isinstance(rec.get("hash_intel"), dict):
        rec["hash_intel"] = _defang_keyed_iocs(rec["hash_intel"])
    if isinstance(rec.get("url_intel"), dict):
        rec["url_intel"] = _defang_keyed_iocs(rec["url_intel"])
    return rec


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
    # Exclude the per-command embedding: nothing reads it back out of the
    # JSONL (the sweeps that pool per-command vectors go to live ES), and
    # persisting it was 79% of the artifact's bytes.
    resp = es.mget(
        index=cmd_index, ids=ids,
        _source_excludes=["dshield.cowrie.enrichment.embedding"],
    )
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
    cfg,
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
    skipped_non_releasable = 0
    for rollup in rollups:
        scanned += 1
        if not _is_releasable_rollup(rollup, cfg):
            skipped_non_releasable += 1
            continue
        if not _has_commands(rollup):
            skipped_no_commands += 1
            continue
        by_stratum[_sampling_key(rollup)].append(rollup)
    if not by_stratum:
        return [], {
            "scanned":                scanned,
            "skipped_no_commands":    skipped_no_commands,
            "skipped_non_releasable": skipped_non_releasable,
            "active_strata":          0,
            "named_playbooks":        0,
            "unattributed":           0,
        }

    # Smallest buckets first so unattributed singletons pass through
    # completely; named-playbook buckets at the tail absorb whatever
    # the cap allows.
    strata = sorted(by_stratum.items(), key=lambda kv: len(kv[1]))
    out: list[dict] = []
    for _key, pool in strata:
        if len(out) >= target_n:
            break
        take = min(len(pool), per_playbook_cap, target_n - len(out))
        if take <= 0:
            continue
        out.extend(pool[:take])

    named = sum(1 for k in by_stratum if k[0] == "pb")
    unattr = sum(1 for k in by_stratum if k[0] == "unattributed")
    stats = {
        "scanned":                scanned,
        "skipped_no_commands":    skipped_no_commands,
        "skipped_non_releasable": skipped_non_releasable,
        "active_strata":          len(by_stratum),
        "named_playbooks":        named,
        "unattributed":           unattr,
        "per_playbook_cap":       per_playbook_cap,
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
    rec = {
        "session_id":          session_id,
        "stratum":             {"size_band": band, "intent": intent, "intel": intel},
        "rollup_doc":          rollup,
        "raw_events":          raw_events,
        "command_enrichments": enrichments,
        "hash_intel":          hash_intel,
        "url_intel":           url_intel,
    }
    # Strip sensor / Filebeat / Elastic-agent metadata, then neuter
    # attacker-side artifacts (IP/hash/URL/password). The eval set ships
    # publicly; these are the last two gates before write.
    return _defang_record(_redact_record(rec))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=300,
                    help="Target sampled-session count.")
    ap.add_argument("--per-playbook-cap", type=int, default=5,
                    help=(
                        "Max sessions kept per playbook_id. Unattributed "
                        "sessions each get their own singleton bucket so the "
                        "cap doesn't throttle outliers."
                    ))
    ap.add_argument("--seed", type=int, default=20260531,
                    help="random_score seed; reproducible per (corpus, seed)")
    ap.add_argument("--output", type=Path,
                    default=Path("eval/sessions.unlabeled.jsonl.gz"),
                    help="Output JSONL path.")
    ap.add_argument("--scan-cap", type=int, default=20000,
                    help="Hard ceiling on rollup docs scanned to fill the sample.")
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
    print(f"output            : {args.output}", file=sys.stderr)

    print(f"target N          : {args.n}", file=sys.stderr)
    print(f"scan cap          : up to {args.scan_cap} rollups", file=sys.stderr)
    print(f"per-playbook cap  : {args.per_playbook_cap}", file=sys.stderr)
    print(f"seed              : {args.seed}", file=sys.stderr)

    playbook_sizes = _load_playbook_sizes(es, rollup_index)
    print(f"playbooks seen    : {len(playbook_sizes)}", file=sys.stderr)

    def _stream() -> Iterator[dict]:
        for seen, rollup in enumerate(_iter_random_rollups(es, rollup_index, args.seed), 1):
            yield rollup
            if seen >= args.scan_cap:
                return

    # Variety-first sampling: bucket by playbook_id (with each
    # unattributed session as its own bucket) and cap per playbook so
    # one behaviour can't dominate. Login-only rollups are dropped at
    # the gate — they have no command-stream signal.
    sampled, sample_stats = _sample_stratified(
        _stream(), playbook_sizes, args.n, args.per_playbook_cap, cfg,
    )
    if not sampled:
        scanned = sample_stats.get("scanned", 0)
        skipped_non_releasable = sample_stats.get("skipped_non_releasable", 0)
        if scanned and skipped_non_releasable == scanned:
            print(
                f"[ERROR] scanned {scanned} rollups, all {skipped_non_releasable} "
                "were non-releasable (no dshield.classification=public tag). "
                "The classification gate is fail-safe: untagged rollups are "
                "treated as confidential and excluded. Backfill/re-ingest with "
                "classification tagging before sampling.", file=sys.stderr,
            )
        else:
            print("[ERROR] no rollup docs scanned — is the index empty?",
                  file=sys.stderr)
        return 1
    print(
        f"sampled           : {len(sampled)} rollups "
        f"(scanned {sample_stats['scanned']}, "
        f"skipped {sample_stats['skipped_no_commands']} login-only, "
        f"skipped {sample_stats['skipped_non_releasable']} non-releasable, "
        f"{sample_stats['named_playbooks']} named playbooks + "
        f"{sample_stats['unattributed']} unattributed sessions)",
        file=sys.stderr,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    stratum_counts: dict[str, int] = defaultdict(int)
    written = 0
    with open_jsonl(args.output, "wt") as f:
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
