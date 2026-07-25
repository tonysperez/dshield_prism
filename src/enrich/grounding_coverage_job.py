"""Command-grounding coverage job (spec-grounding-precompute).

Precomputes what the retired Curation page used to scan on every page load:
walks the full `cowrie.commands` index, classifies every parsed command token
against the curated/tldr/denylist data in `enrich.command_grounding`
(`needs_def` / `tldr_only` / `curated` / `denied`), weights each by
`occurrence_count`, and writes a **single** summary doc (fixed id, overwritten
each run) to `cfg.grounding_coverage.indexes.default`. The console then reads
that one doc in O(1) instead of re-scanning.

See `docs/decisions.md` ("Computing command-grounding coverage on the console
request path") for why this moved off the request path, and the old
console-side scan this rebuilds (`git show de42736^ --
console/src/console/health.py`).

**Privacy gate (load-bearing):** `count` aggregates every doc regardless of
`dshield.classification` (matches the old scan's semantics — the coverage
*stats* are corpus-wide). `samples` are literal per-sensor command lines, so
each candidate sample is gated through `classification.is_releasable` before
it's added to the written doc — only explicit `public` docs may contribute a
sample. Untagged/confidential docs still count toward `count` but never
contribute a `samples` entry. This is pipeline code (the operator runs it via
`track grounding-coverage`), not an interactive query — see CLAUDE.md's
three-surfaces distinction.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from elasticsearch import Elasticsearch

from .classification import is_releasable
from .command_grounding import (
    _load_command_data,
    list_denied_commands,
    parse_shell_line,
)
from .config import AppConfig

log = logging.getLogger(__name__)


def compute_grounding_coverage(es: Elasticsearch, cfg: AppConfig) -> dict[str, Any]:
    """Scan `cowrie.commands` and return the report-doc payload (no write).

    Shape:
        {
          "generated_at": "<iso>",
          "stats": {total_unique_cmds, curated, tldr_only, needs_def, denied,
                     total_corpus_occurrences},
          "needs_def": [{name, count, samples}, ...],
          "tldr_only": [{name, count, samples}, ...],
          "denied":    [{name, count, samples, rationale}, ...],
        }

    `needs_def`/`tldr_only`/`denied` are sorted by count descending and
    capped at `cfg.grounding_coverage.max_list_len`. `curated` is omitted
    from the response body (same as the retired page) — it's the largest
    list and not actionable; only its count is surfaced.
    """
    gc_cfg = cfg.grounding_coverage
    sample_limit = gc_cfg.samples_per_entry
    max_list_len = gc_cfg.max_list_len

    data = _load_command_data()
    denylist = list_denied_commands()

    cmds_idx = cfg.elasticsearch.indexes.cowrie.commands

    body: dict[str, Any] = {
        "size": gc_cfg.scan_batch_size,
        "_source": [
            "process.command_line",
            "dshield.cowrie.enrichment.occurrence_count",
            "dshield.classification",
        ],
        "query": {"exists": {"field": "process.command_line"}},
        "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
    }

    counts: dict[str, int] = defaultdict(int)
    samples: dict[str, list[str]] = defaultdict(list)
    total_corpus_occurrences = 0

    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        try:
            resp = es.search(index=cmds_idx, **body)
        except Exception as exc:  # noqa: BLE001 — hard failure: propagate so
            # the caller (write_grounding_coverage) does NOT overwrite the
            # last-good report doc with a truncated result, and the CLI/ops
            # telemetry reports this run as failed rather than successful.
            log.warning(
                "grounding-coverage: commands scan on %s failed after %d "
                "distinct commands seen; aborting run (last-good doc left "
                "untouched): %s", cmds_idx, len(counts), exc,
            )
            raise
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            # Fix 2: a single malformed document must not crash the whole
            # (potentially multi-hour) scan — skip just that hit's
            # contribution and keep going. This is distinct from the
            # es.search failure above, which is a hard, whole-run failure.
            src = h.get("_source") or {}
            cmd_line = (src.get("process") or {}).get("command_line")
            if not isinstance(cmd_line, str) or not cmd_line:
                continue
            enrichment = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment") or {}
            occ_raw = enrichment.get("occurrence_count")
            if occ_raw is None:
                occ = 1
            else:
                try:
                    occ = int(occ_raw)
                except (TypeError, ValueError):
                    log.debug(
                        "grounding-coverage: skipping hit %r with malformed "
                        "occurrence_count=%r", h.get("_id"), occ_raw,
                    )
                    continue
            classification = (src.get("dshield") or {}).get("classification")
            releasable = is_releasable(classification, cfg)
            # Fix 3: weight the corpus-occurrence total once per source
            # record, not once per parsed sub-command — a compound line
            # (pipes, `&&`, `;`-chains, busybox multi-call) can yield
            # several (cmd, flags) tuples from `parse_shell_line` for the
            # SAME record, which would otherwise multiply this stat.
            total_corpus_occurrences += occ
            for cmd, _flags in parse_shell_line(cmd_line):
                counts[cmd] += occ
                # Privacy gate: only a releasable (public) doc's command line
                # may contribute a sample — counts above are corpus-wide,
                # samples are not.
                truncated = cmd_line[:200]
                if (
                    releasable
                    and len(samples[cmd]) < sample_limit
                    and truncated not in samples[cmd]
                ):
                    samples[cmd].append(truncated)
        last_hit = hits[-1]
        next_search_after = last_hit.get("sort")
        if not next_search_after:
            log.warning(
                "grounding-coverage: last hit on %s missing a sort cursor; "
                "ending scan early (page had %d hits)", cmds_idx, len(hits),
            )
            break
        search_after = next_search_after

    needs_def: list[dict] = []
    tldr_only: list[dict] = []
    denied: list[dict] = []
    curated_count = 0
    for cmd, cnt in counts.items():
        item = {"name": cmd, "count": cnt, "samples": samples[cmd]}
        if cmd in denylist:
            item["rationale"] = denylist[cmd]
            denied.append(item)
            continue
        entry = data.get(cmd)
        if entry is None:
            needs_def.append(item)
        elif entry.get("curated_description"):
            curated_count += 1
        else:
            tldr_only.append(item)

    needs_def.sort(key=lambda x: -x["count"])
    tldr_only.sort(key=lambda x: -x["count"])
    denied.sort(key=lambda x: -x["count"])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_unique_cmds": len(counts),
            "curated": curated_count,
            "tldr_only": len(tldr_only),
            "needs_def": len(needs_def),
            "denied": len(denied),
            "total_corpus_occurrences": total_corpus_occurrences,
        },
        "needs_def": needs_def[:max_list_len],
        "tldr_only": tldr_only[:max_list_len],
        "denied": denied[:max_list_len],
    }


def write_grounding_coverage(es: Elasticsearch, cfg: AppConfig) -> dict[str, Any]:
    """Compute + persist the single report doc. Returns
    `{written, doc_id, index, stats, error?}` for the CLI to print.

    Skips (best-effort, matches the `ops.py` / `write_threshold_distributions`
    posture) when the target index doesn't exist yet — the operator runs
    `init-indexes --source metrics` first.
    """
    idx = cfg.grounding_coverage.indexes.default
    doc_id = cfg.grounding_coverage.doc_id
    if not es.indices.exists(index=idx):
        log.warning(
            "grounding-coverage: index %s does not exist; run "
            "`init-indexes --source metrics` first", idx,
        )
        return {"written": False, "index": idx, "doc_id": doc_id,
                "error": "grounding_coverage_index_missing"}
    try:
        doc = compute_grounding_coverage(es, cfg)
    except Exception as exc:  # noqa: BLE001 — a scan failure is a hard job
        # failure: do NOT index anything, so the last-good report doc is
        # left untouched. The caller (CLI `track grounding-coverage`) treats
        # a non-empty `error` as failure and reports a non-zero exit /
        # ops.run_finish(status="failed"), matching this module's own I/O
        # contract (see the module docstring).
        log.warning(
            "grounding-coverage: scan failed; leaving last-good doc at "
            "%s/%s untouched: %s", idx, doc_id, exc,
        )
        return {"written": False, "index": idx, "doc_id": doc_id,
                "error": f"{type(exc).__name__}: {exc}"}
    try:
        es.index(index=idx, id=doc_id, document=doc)
    except Exception as exc:  # noqa: BLE001
        log.warning("grounding-coverage: write failed: %s", exc)
        return {"written": False, "index": idx, "doc_id": doc_id,
                "error": f"{type(exc).__name__}: {exc}"}
    return {"written": True, "index": idx, "doc_id": doc_id, "stats": doc["stats"]}
