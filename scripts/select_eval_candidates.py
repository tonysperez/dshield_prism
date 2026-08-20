"""Select targeted eval-set candidates for the thin analyst labels (E3).

`build_eval_set.py`'s variety-first draw buckets by `playbook_id` under
`--per-playbook-cap`, so a rare behaviour sharing an anchor with a common one is
crowded out — which is why four labels sit at n<=3 while the corpus holds hundreds of
candidates. This picks candidates for those labels directly and writes a
`session_id<TAB>channel` file for `build_eval_set.py --session-ids ... --append`.

**Never selects by embedding similarity.** Drawing eval candidates as nearest
neighbours of known examples builds the test set out of the system under test, and
every coverage number measured afterwards is circular. Selection here is structural or
lexical only.

**Two channels per label, plus a random control.** A tight structural proxy
(`structural`) has high yield but is correlated with the very signals some mechanisms
read — sampling `iot_cli_probe` by the appliance-verb sub-signal guarantees every new
example fires `appliance_menu_only`, which would inflate any predicate-based
mechanism's apparent value. The `anchor` channel draws from the anchors that already
carry the label, which is uncorrelated with the predicates but lower-yield. The
`random` control is an unconditioned draw over the whole public corpus and is what
tells you afterwards whether the bias mattered. Every candidate carries its channel
into the label block so the analysis can condition on it.

Read-only. Public-only filter throughout (`releasable_filter`), so a confidential or
untagged session can never enter the candidate list.

    console/.venv/bin/python scripts/select_eval_candidates.py \\
        --out eval/candidates-e3.txt
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eval_jsonl import open_jsonl

from enrich.classification import releasable_filter
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

_S = "dshield.cowrie.enrichment.session"
_P = "dshield.cowrie.enrichment.predicates"
_SID = "cowrie.session_id"

# The corpus is ~87% one behaviour (SSH-key persistence with chattr). Any recall-first
# proxy therefore returns that behaviour, which is how the first pass hit 0 of 4 targets.
# Every pool is subtracted by this signature before drawing.
MODE_SIGNATURE: dict[str, dict] = {
    "key_write": {"match_phrase": {"process.command_line": "authorized_keys"}},
    "immutability": {"query_string": {"query": "chattr OR lockr",
                                      "default_field": "process.command_line"}},
}

# Per thin label: how to find candidates without asking the embedding.
#   `event`     — a cowrie event type on the raw index
#   `command`   — a query against the enriched command index, joined via `command_set`
#   `exclude_event` — sessions carrying this event are removed from the pool
#   `folded_predicate` — a SESSION-level predicate from `predicates.fold_session_predicates`
#
# Precision below is measured against the labels already in hand, not guessed. The first
# pass guessed and every guess was wrong by ~100%.
STRUCTURAL: dict[str, dict] = {
    # `cowrie.session.file_upload` does NOT mean SCP — cowrie emits it for any file it
    # captures, including an inline `echo ... >> authorized_keys`, so it returned the
    # corpus mode at 0% precision. The transfer verbs themselves are 100% precise and
    # almost exhausted: 5 sessions corpus-wide, 3 already labelled.
    "scp_upload": {
        "command": {"query_string": {"query": "scp OR sftp",
                                     "default_field": "process.command_line"}},
        "measured_precision": 1.00,
    },
    # The label requires the appliance CLI to be the WHOLE session (rubric precedence
    # rule 6), which is the FOLDED `appliance_menu_only` — an AND over every command.
    # The per-command `is_appliance_verb` sub-signal fires on any appliance verb, so it
    # returns sessions that walked a menu and then did something else: 10% precision.
    # The correct predicate matches 2 sessions corpus-wide, both already labelled.
    "iot_cli_probe": {
        "folded_predicate": "appliance_menu_only",
        "measured_precision": 0.50,
    },
    "account_backdoor_persistence": {
        "command": {"query_string": {
            "query": "useradd OR adduser OR chpasswd",
            "default_field": "process.command_line"}},
        "measured_precision": None,  # 9 candidates after mode subtraction, none labelled
    },
    # `chmod` WITHOUT a download in the same session — a fetch makes it
    # `payload_fetch_exec` by rubric precedence rule 4.
    "dropped_binary_exec": {
        "command": {"match_phrase": {"process.command_line": "chmod"}},
        "exclude_event": "cowrie.session.file_download",
        "measured_precision": 0.25,
    },
}


def allocate(total: int, structural_share: float) -> tuple[int, int]:
    """Split a per-label draw between the structural and anchor channels.

    Pure. The anchor channel is the bias control, so it is never allowed to round to
    zero when any budget exists at all — a label sampled only through its structural
    proxy has no uncorrelated examples to check the proxy against.
    """
    if total <= 0:
        return (0, 0)
    if total == 1:
        return (1, 0)
    n_struct = int(round(total * structural_share))
    n_struct = max(1, min(total - 1, n_struct))
    return (n_struct, total - n_struct)


def _scroll_ids(es, index: str, query: dict, field: str, page: int = 2000) -> set[str]:
    out: set[str] = set()
    body = {"size": page, "_source": [field], "sort": [{"_doc": "asc"}], "query": query}
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=index, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            return out
        for h in hits:
            src = h["_source"]
            for part in field.split("."):
                src = (src or {}).get(part) if isinstance(src, dict) else None
            if src:
                out.add(str(src))
        search_after = hits[-1]["sort"]


def _sessions_for_command_query(es, ix, filt, query: dict) -> set[str]:
    """Sessions whose `command_set` references any command matching `query`."""
    # A command hash is the doc `_id`, not a `_source` field, so this scrolls
    # directly rather than going through `_scroll_ids`.
    hashes: set[str] = set()
    body = {"size": 2000, "_source": False, "sort": [{"_doc": "asc"}],
            "query": {"bool": {"filter": [*filt, query]}}}
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=ix.commands, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        hashes.update(h["_id"] for h in hits)
        search_after = hits[-1]["sort"]
    if not hashes:
        return set()
    return _scroll_ids(
        es, ix.sessions_rollup,
        {"bool": {"filter": [*filt, {"exists": {"field": f"{_S}.embedding"}},
                             {"terms": {f"{_S}.command_set": list(hashes)[:65000]}}]}},
        _SID,
    )


def _sessions_for_event(es, ix, filt, action: str) -> set[str]:
    sids = _scroll_ids(
        es, ix.sessions_raw,
        {"bool": {"filter": [*filt, {"term": {"event.action": action}}]}}, _SID,
    )
    if not sids:
        return set()
    keep: set[str] = set()
    sl = list(sids)
    for start in range(0, len(sl), 1000):
        keep |= _scroll_ids(
            es, ix.sessions_rollup,
            {"bool": {"filter": [*filt, {"exists": {"field": f"{_S}.embedding"}},
                                 {"terms": {_SID: sl[start:start + 1000]}}]}}, _SID,
        )
    return keep


def _mode_sessions(es, ix, filt) -> set[str]:
    """Sessions carrying the corpus's modal behaviour signature.

    Subtracted from every candidate pool. On a corpus where one behaviour is ~87% of
    sessions, a recall-first proxy returns that behaviour and nothing else — measured:
    the first pass drew 121 candidates across four targets and 121 of them came back as
    the mode or its neighbours, hitting 0 of 4. Subtracting it is what makes a loose
    proxy usable at all.
    """
    pools = [_sessions_for_command_query(es, ix, filt, q)
             for q in MODE_SIGNATURE.values()]
    if not pools:
        return set()
    out = pools[0]
    for p in pools[1:]:
        out &= p
    return out


def _folded_predicate_sessions(es, ix, filt, name: str) -> set[str]:
    """Sessions whose SESSION-level folded predicate `name` is true.

    Distinct from querying a per-command sub-signal: `fold_session_predicates` applies
    each predicate's own fold, and `appliance_menu_only` in particular is an AND over
    every command in the session. A label defined as "the whole session is X" can only
    be matched by the fold, never by the sub-signal.
    """
    from enrich.sources.cowrie.lexical import (
        build_session_predicate_vectors,
        pull_hash_to_predicates,
    )
    hash_to_predicates = pull_hash_to_predicates(es, ix.commands, filt=filt)
    sids: list[str] = []
    command_sets: list[list[str]] = []
    body = {"size": 2000, "_source": [f"{_S}.command_set", _SID],
            "sort": [{"_doc": "asc"}],
            "query": {"bool": {"filter": [*filt, {"exists": {"field": f"{_S}.embedding"}}]}}}
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=ix.sessions_rollup, **body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for hit in hits:
            sid = (hit["_source"].get("cowrie") or {}).get("session_id")
            session = (((hit["_source"].get("dshield") or {}).get("cowrie") or {})
                       .get("enrichment", {}).get("session", {}))
            sids.append(str(sid))
            command_sets.append(list(session.get("command_set") or []))
        search_after = hits[-1]["sort"]
    vectors = build_session_predicate_vectors(command_sets, hash_to_predicates)
    return {sid for sid, vec in zip(sids, vectors, strict=True) if vec.get(name)}


def _anchor_channel(es, ix, filt, labelled_sids: set[str]) -> set[str]:
    """Sessions sharing a `playbook_id` with an already-labelled example.

    Uncorrelated with the structural predicates — the bias control for the
    `structural` channel. Lower yield: an anchor carrying the label may be mostly
    other behaviours, which is exactly what the analyst pass is for.
    """
    if not labelled_sids:
        return set()
    pbs: set[str] = set()
    sl = list(labelled_sids)
    for start in range(0, len(sl), 1000):
        resp = es.search(
            index=ix.sessions_rollup, size=1000, _source=[f"{_S}.playbook_id"],
            query={"bool": {"filter": [*filt, {"terms": {_SID: sl[start:start + 1000]}}]}},
        )
        for h in resp["hits"]["hits"]:
            pb = (((h["_source"].get("dshield") or {}).get("cowrie") or {})
                  .get("enrichment", {}).get("session", {}).get("playbook_id"))
            if pb:
                pbs.add(pb)
    if not pbs:
        return set()
    return _scroll_ids(
        es, ix.sessions_rollup,
        {"bool": {"filter": [*filt, {"exists": {"field": f"{_S}.embedding"}},
                             {"terms": {f"{_S}.playbook_id": list(pbs)}}]}}, _SID,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=None)
    ap.add_argument("--labels", type=Path, default=Path("eval/labels.yaml"))
    ap.add_argument("--unlabeled", type=Path,
                    default=Path("eval/sessions.unlabeled.jsonl.gz"))
    ap.add_argument("--out", type=Path, default=Path("eval/candidates-e3.txt"))
    ap.add_argument("--per-label", type=int, default=25,
                    help="candidates drawn per thin label, split across both channels")
    ap.add_argument("--structural-share", type=float, default=0.6,
                    help="fraction of each label's draw from its structural proxy")
    ap.add_argument("--random-n", type=int, default=30,
                    help="unconditioned control draw over the whole public corpus")
    ap.add_argument("--no-mode-subtraction", action="store_true",
                    help="keep the corpus's modal behaviour in every pool (diagnostic; "
                         "the first pass ran this way and hit 0 of 4 targets)")
    ap.add_argument("--seed", type=int, default=20260820)
    args = ap.parse_args()
    if not 0.0 <= args.structural_share <= 1.0:
        ap.error("--structural-share must be in [0, 1]")

    import yaml
    cfg = load_config(args.config)
    es = make_client(cfg.elasticsearch, load_secrets(args.config))
    ix = cfg.elasticsearch.indexes.cowrie
    filt = [releasable_filter(cfg)]
    rng = random.Random(args.seed)

    labels = yaml.safe_load(args.labels.read_text()) or {}
    by_label: dict[str, set[str]] = {}
    for sid, v in labels.items():
        if isinstance(v, dict) and v.get("annotated") and v.get("playbook_label"):
            by_label.setdefault(v["playbook_label"], set()).add(str(sid))
    already = {str(s) for s in labels}
    if args.unlabeled.exists():
        with open_jsonl(args.unlabeled, "rt") as fh:
            for line in fh:
                if line.strip():
                    sid = json.loads(line).get("session_id")
                    if sid:
                        already.add(str(sid))
    print(f"{len(already)} sessions already in the eval set", file=sys.stderr)

    picked: dict[str, str] = {}
    summary: Counter = Counter()

    def take(pool: set[str], n: int, channel: str) -> None:
        fresh = sorted(pool - already - set(picked))
        rng.shuffle(fresh)
        for sid in fresh[:n]:
            picked[sid] = channel
            summary[channel] += 1

    mode = set() if args.no_mode_subtraction else _mode_sessions(es, ix, filt)
    if mode:
        print(f"corpus mode signature: {len(mode)} sessions (subtracted from every pool)",
              file=sys.stderr)

    for label, spec in STRUCTURAL.items():
        n_struct, n_anchor = allocate(args.per_label, args.structural_share)
        if "folded_predicate" in spec:
            pool = _folded_predicate_sessions(es, ix, filt, spec["folded_predicate"])
        elif "event" in spec:
            pool = _sessions_for_event(es, ix, filt, spec["event"])
        else:
            pool = _sessions_for_command_query(es, ix, filt, spec["command"])
        if spec.get("require_event"):
            pool &= _sessions_for_event(es, ix, filt, spec["require_event"])
        if spec.get("exclude_event"):
            pool -= _sessions_for_event(es, ix, filt, spec["exclude_event"])
        pool -= mode
        before = len(picked)
        take(pool, n_struct, "structural")
        got_struct = len(picked) - before
        anchor_pool = _anchor_channel(es, ix, filt, by_label.get(label, set()))
        take(anchor_pool, n_anchor, "anchor")
        got_anchor = len(picked) - before - got_struct
        # The measured precision belongs to the STRUCTURAL proxy only. The anchor
        # channel is a different selection rule with its own (unmeasured) precision, so
        # folding both into one estimate overstates the yield.
        prec = spec.get("measured_precision")
        yield_hint = (f" -> ~{round(got_struct * prec)} true from the {got_struct} "
                      f"structural" if prec is not None
                      else " structural precision unmeasured")
        print(f"  {label:<30} pool={len(pool):<6} anchor_pool={len(anchor_pool):<6} "
              f"drew {got_struct}+{got_anchor} (want {n_struct}+{n_anchor}){yield_hint}",
              file=sys.stderr)

    if args.random_n > 0:
        control = _scroll_ids(
            es, ix.sessions_rollup,
            {"bool": {"filter": [*filt, {"exists": {"field": f"{_S}.embedding"}}]}}, _SID,
        )
        take(control, args.random_n, "random")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# E3 targeted eval candidates — seed {args.seed}",
             "# session_id<TAB>selection_channel",
             *(f"{sid}\t{ch}" for sid, ch in sorted(picked.items()))]
    args.out.write_text("\n".join(lines) + "\n")
    print(f"\nwrote {len(picked)} candidates -> {args.out}", file=sys.stderr)
    for ch, n in summary.most_common():
        print(f"  {ch:<12}{n}", file=sys.stderr)
    print("\nNext: build_eval_set.py --session-ids "
          f"{args.out} --append, then render_eval_set.py", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
