"""CLI entry points.

Verb shape: ``<verb> [<layer>] --source <source>``

Multi-source-ready: every layer-bearing verb accepts ``--source`` (default
``cowrie``). New sources slot in as ``sources/<source>/<layer>.py`` modules
with the same ``run_*`` callables; this dispatcher routes by name.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from .__about__ import CLI_NAME
from .config import load_config, load_secrets
from . import healthcheck as hc_mod

# Module-level logger. The root config in `_setup_log` attaches a stderr
# StreamHandler (always) + the cli.log RotatingFileHandler, so `log.*` reaches
# both the journal/terminal AND the durable file — unlike `print()`, which only
# hits stdout. Dispatch-level operator errors go through `log.error` (P4.1) so a
# failed run is reconstructable from cli.log, not just journald.
log = logging.getLogger(__name__)


def _setup_log(level: str, log_dir: str | None = None) -> None:
    """Configure root logging.

    Always installs a stderr handler so systemd's journal capture and
    interactive shell sessions both see live output. When `log_dir` is
    non-empty AND writable, additionally installs a RotatingFileHandler
    on `<log_dir>/cli.log` (10 MB × 5 backups) so historical CLI runs
    are durable independent of journald rotation.

    File-handler failures (missing directory, no write permission, etc.)
    fall back to stderr-only with a single warning printed; never raise,
    so the CLI works on dev workstations where /var/log/dshield_prism
    doesn't exist.
    """
    import os
    fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
    lvl = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    # PRISM_LOG_DIR env var wins over config so operators can redirect
    # ad-hoc without editing config.
    env_dir = os.environ.get("PRISM_LOG_DIR")
    resolved = env_dir if env_dir is not None else (log_dir or "")
    if resolved:
        try:
            os.makedirs(resolved, exist_ok=True)
            from logging.handlers import RotatingFileHandler
            log_path = os.path.join(resolved, "cli.log")
            handlers.append(
                RotatingFileHandler(
                    log_path, maxBytes=10 * 1024 * 1024, backupCount=5,
                    encoding="utf-8",
                )
            )
        except Exception as exc:
            # Single stderr line, no traceback — file logging is a nicety.
            print(
                f"[warn] file logging disabled: {resolved}/cli.log unwritable ({exc})",
                file=__import__("sys").stderr, flush=True,
            )
    logging.basicConfig(level=lvl, format=fmt, handlers=handlers, force=True)


# --- per-source dispatch ----------------------------------------------------
# Each (source, layer) -> module that exposes the named run_* entry points.

def _load_source_layer(source: str, layer: str):
    """Return the module that owns this (source, layer) pair."""
    if source == "cowrie":
        from .sources.cowrie import commands, sessions, ips, campaigns
        return {
            "commands":  commands,
            "sessions":  sessions,
            "ips":       ips,
            "campaigns": campaigns,
        }.get(layer)
    return None


def _commands_layer(source: str):
    """Commands-layer module for a source (used by enrich/escalate/reembed)."""
    return _load_source_layer(source, "commands")


# Default cluster-run retention (scale-hardening P2.1). Only the latest run is
# ever read; the rest is rollback buffer. Shared by the `prune-clusters` verb
# default and the `pipeline`/backward prune step so the two can't drift.
_DEFAULT_CLUSTER_KEEP_RUNS = 5


# Backlog B2 — pipeline steps dropped in --backfill mode. Both stamp backfill
# wall-clock onto historical activity (lifecycle snapshots) or flood the inbox
# (findings), so they run only in a normal pipeline pass AFTER the backfill.
_BACKFILL_SKIP_STEPS = ("track lifecycles", "mine findings")


def _apply_backfill_mode(steps, replacements):
    """Adjust the pipeline step list for `--backfill`: drop the temporally-
    corrupting steps (`_BACKFILL_SKIP_STEPS`), and for any step whose name is a
    key in `replacements`, swap its fn for the backfill variant.

    Together the swaps make a backfill a true full-corpus pass — enrich →
    re-pool → cluster the whole archive — instead of one that silently skips
    everything older than the last run's watermarks:
      - `enrich` → full-rescan: re-enrich commands in older-than-watermark
        history (the per-command cache skips re-LLM on already-enriched ones).
      - `reset rollup watermarks` → force-clear the session+IP watermarks so the
        rollups re-pool the full history.
      - `cluster sessions` → full-corpus cluster (`--window-days 0`).

    `replacements` maps step name → replacement callable. Pure list transform —
    unit-tested."""
    out = []
    for name, fn, optional in steps:
        if name in _BACKFILL_SKIP_STEPS:
            continue
        out.append((name, replacements.get(name, fn), optional))
    return out


def _backfill_session_plan(authoritative: bool, has_anchors: bool) -> str:
    """Which backfill `cluster sessions` path to take (Option A cutover). Pure —
    unit-tested. Authoritative assignment owns labelling only once an anchor library
    exists; with no anchors (fresh bootstrap) fall back to the legacy full HDBSCAN that
    mints the initial library."""
    return "assign_then_novel" if (authoritative and has_anchors) else "legacy_full"


def _backfill_cluster_sessions(cfg, secrets, sessions_mod, dry: bool) -> dict:
    """Backfill `cluster sessions` step. With assignment_authoritative on (and anchors
    present), label the FULL corpus by assignment, then HDBSCAN only the novel pool to
    mint new-behaviour anchors — keeping the backfilled history consistent with the
    steady-state assignment pipeline. Falls back to the legacy full-corpus HDBSCAN when
    assignment is off, or to bootstrap the very first anchor library."""
    authoritative = bool(getattr(cfg.session, "assignment_authoritative", False))
    if not authoritative:
        return sessions_mod.run_cluster(cfg, secrets, dry_run=dry, window_days=0)
    from .es_client import make_client
    from .sources.cowrie.assign_runner import run_assignment
    es = make_client(cfg.elasticsearch, secrets)
    base = "dshield.cowrie.enrichment.session"
    emb = {"exists": {"field": f"{base}.embedding"}}
    pb = {"exists": {"field": f"{base}.playbook_id"}}
    # Full corpus, all classifications (server-side label write, no egress).
    assign = run_assignment(es, cfg, window_filter=[emb], anchor_sample_filter=[emb, pb],
                            apply=not dry)
    has_anchors = assign.get("error") != "no anchors"
    if _backfill_session_plan(authoritative, has_anchors) == "legacy_full":
        return sessions_mod.run_cluster(cfg, secrets, dry_run=dry, window_days=0)
    novel = sessions_mod.run_cluster(cfg, secrets, dry_run=dry, window_days=0,
                                     novel_pool_only=True)
    return {"assignment": assign, "novel_pool_cluster": novel}


def _ip_full_recluster_skipped(cfg, window_days) -> bool:
    """Backlog B0.5 IP-layer cadence gate. True when the 6-hourly backward
    `cluster ips` should skip its full O(n^2) HDBSCAN because the operator has
    moved the full pass onto the weekly `dshield_prism-recluster-full` timer.

    Skipped when ``ip.full_recluster_weekly`` is set AND the run is not the
    forced full pass (``--window-days 0``, which the weekly unit passes). With
    the default (flag False) nothing is skipped — legacy full-every-run."""
    return bool(getattr(cfg.ip, "full_recluster_weekly", False)) and window_days != 0


def _cluster_indices_for_source(cfg, source: str):
    """[(layer_label, index), ...] of the cluster-centroid indices for a
    source, or None if the source has none. Used by `prune-clusters`."""
    if source == "cowrie":
        c = cfg.elasticsearch.indexes.cowrie
        return [
            ("command", c.command_clusters),
            ("session", c.session_clusters),
            ("ip",      c.ip_clusters),
        ]
    return None


# --- mapping files for init-indexes ----------------------------------------

_LAYER_MAPPINGS = {
    "cowrie": {
        "commands":          "setup/es-mappings/cowrie/commands.json",
        "command_clusters":  "setup/es-mappings/cowrie/command_clusters.json",
        "sessions":          "setup/es-mappings/cowrie/sessions.json",
        "session_clusters":  "setup/es-mappings/cowrie/session_clusters.json",
        "ips":               "setup/es-mappings/cowrie/ips.json",
        "ip_clusters":       "setup/es-mappings/cowrie/ip_clusters.json",
        "campaigns":         "setup/es-mappings/cowrie/campaigns.json",
        "playbook_anchors":  "setup/es-mappings/cowrie/playbook_anchors.json",
        "reference_session": "setup/es-mappings/cowrie/reference_session.json",
        "operations":        "setup/es-mappings/cowrie/operations.json",
        "file_command_crossref": "setup/es-mappings/cowrie/file_command_crossref.json",
    },
    # DShield-firewall source (Phase I3). `firewall` is the raw per-batch
    # event index the Elastic Agent + `prism.dshield.firewall` pipeline write;
    # `firewall_ip` (the per-source rollup) lands with I3.3.
    "dshield": {
        "firewall": "setup/es-mappings/dshield/firewall.json",
    },
    # External threat-intel — cross-source per-artifact indices.
    # `init-indexes --source intel` creates these. M1 shipped `ip`,
    # M4 added `url`, #2 added `hash` (MalwareBazaar / ThreatFox);
    # `domain` lands with #7.
    "intel": {
        "ip":     "setup/es-mappings/intel/ip.json",
        "url":    "setup/es-mappings/intel/url.json",
        "hash":   "setup/es-mappings/intel/hash.json",
    },
    # Persisted findings index — M5. Cross-source: the miner reads
    # IP rollups + intel-{ip,url}, writes one findings index.
    "findings": {
        "default": "setup/es-mappings/findings/default.json",
    },
    # Lifecycle indices — Findings v2 step 1. `track lifecycles` writes
    # one doc per (playbook_id | campaign_id | source.ip) with rolling
    # snapshots; drift detectors (step 4) read confirm_anchors[].
    "lifecycle": {
        "playbook":  "setup/es-mappings/lifecycle/playbook.json",
        "campaign":  "setup/es-mappings/lifecycle/campaign.json",
        "source_ip": "setup/es-mappings/lifecycle/source_ip.json",
    },
    # Analyst-authored artifact extraction rules (ROADMAP #5). One doc
    # per rule; soft-delete via active=false. CRUD via the console.
    "analyst": {
        "artifact_rules": "setup/es-mappings/analyst/artifact_rules.json",
    },
    # Threshold-distribution snapshots (brutal-review phase 4). Writers
    # land per-commit alongside the miners that consume them; the index +
    # mapping ship first so reader code can fall through to the
    # hardcoded bands when no metrics doc exists yet.
    "metrics": {
        "default": "setup/es-mappings/metrics/default.json",
    },
    # Per-run pipeline telemetry (P4.2). `init-indexes --source ops` creates it;
    # tracked verbs write one started→finished/failed doc per invocation.
    "ops": {
        "default": "setup/es-mappings/ops/default.json",
    },
}


def _purge_lifecycles(cfg, secrets) -> dict:
    """Wipe the full lifecycle/findings stack and the anchor index, then
    re-create each from its mapping file. Used to drop accumulated state
    after id-scheme migrations or any other corruption that's cheaper to
    rebuild from upstream than to repair in place.

    Scope:
      - lifecycle-dshield.cowrie.{playbook,campaign,source_ip}-default
      - prism.findings (one finding per playbook/campaign/discovery hit)
      - prism.campaign.cowrie (campaign mining output)
      - prism.identity.cowrie.playbook_anchor (pinned playbook centroids)

    Out of scope: session_clusters, sessions_rollup, ips_rollup. Those
    re-stamp themselves on the next backward cycle and rebuilding them is
    hours of compute; leave them.
    """
    from .es_client import init_index, make_client

    es = make_client(cfg.elasticsearch, secrets)
    cowrie = cfg.elasticsearch.indexes.cowrie
    f_idx = cfg.findings.indexes

    targets: list[tuple[str, str]] = [
        (f_idx.playbook_lifecycle,  "setup/es-mappings/lifecycle/playbook.json"),
        (f_idx.campaign_lifecycle,  "setup/es-mappings/lifecycle/campaign.json"),
        (f_idx.source_ip_lifecycle, "setup/es-mappings/lifecycle/source_ip.json"),
        (f_idx.default,             "setup/es-mappings/findings/default.json"),
        (cowrie.campaigns,          "setup/es-mappings/cowrie/campaigns.json"),
        (cowrie.playbook_anchors,   "setup/es-mappings/cowrie/playbook_anchors.json"),
    ]

    out: dict = {"deleted": [], "created": [], "errors": []}
    for idx, mapping_path in targets:
        try:
            if es.indices.exists(index=idx):
                es.indices.delete(index=idx)
                out["deleted"].append(idx)
        except Exception as exc:
            out["errors"].append({"index": idx, "action": "delete", "error": str(exc)})
            continue
        try:
            init_index(es, mapping_path, idx)
            out["created"].append(idx)
        except Exception as exc:
            out["errors"].append({"index": idx, "action": "create", "error": str(exc)})
    return out


def _run_reference_heal(cfg, secrets) -> dict:
    """Self-heal the external reference baseline (console "Tradecraft Matches")
    using LOCAL steps only — never clones GitHub.

    The GitHub import (`scripts/import_reference_corpus.py`) stays a setup/manual
    concern; this recovers the cases where the corpus was imported but the
    install-time bootstrap didn't finish (LLM down at setup) or the external
    centroids were later lost. State-gated + idempotent: cheap when healthy
    (just count queries), so it's safe to run every backward cycle.

      1. reference corpus present but un-embedded → `enrich --reference`
         (local LLM only, never cloud — a reference baseline doesn't warrant
         cloud budget).
      2. corpus embedded but no `external` reference centroids → `cluster
         sessions --bootstrap-from external`.

    Best-effort throughout: every step is guarded so a failure logs and the
    verb still returns. No corpus at all → no-op with a hint (needs the import).
    """
    import logging
    from .es_client import make_client
    log = logging.getLogger(__name__)
    es = make_client(cfg.elasticsearch, secrets)
    ref_idx = cfg.elasticsearch.indexes.cowrie.reference_sessions
    scl_idx = cfg.elasticsearch.indexes.cowrie.session_clusters
    emb_field = "dshield.cowrie.enrichment.session.embedding"
    ext_q = {"bool": {"must": [
        {"term": {"doc_type": "reference_centroid"}},
        {"term": {"reference_source.keyword": "external"}},
    ]}}
    out: dict = {"status": "healthy", "actions": []}

    try:
        if not es.indices.exists(index=ref_idx) or int(es.count(index=ref_idx)["count"]) == 0:
            log.info("[reference-heal] no reference corpus — import it once with "
                     "scripts/import_reference_corpus.py (needs GitHub); skipping")
            return {"status": "no_corpus", "actions": []}
        n_ref = int(es.count(index=ref_idx)["count"])
        n_emb = int(es.count(index=ref_idx, query={"exists": {"field": emb_field}})["count"])
    except Exception as exc:  # noqa: BLE001
        log.warning("[reference-heal] state check failed (%s); skipping", exc)
        return {"status": "error", "error": str(exc), "actions": []}

    # 1. Embed the reference corpus if needed (local LLM only).
    if n_emb < n_ref:
        log.info("[reference-heal] %d/%d reference sessions un-embedded → enrich --reference",
                 n_ref - n_emb, n_ref)
        try:
            mod = _commands_layer("cowrie")
            if mod is not None:
                mod.run_enrich(cfg, secrets, dry_run=False, no_cloud=True, reference_mode=True)
                out["actions"].append("enriched_reference")
                es.indices.refresh(index=ref_idx)
                n_emb = int(es.count(index=ref_idx, query={"exists": {"field": emb_field}})["count"])
        except Exception as exc:  # noqa: BLE001
            log.warning("[reference-heal] enrich --reference failed (%s)", exc)

    # 2. Mint external centroids when the corpus is embedded but they're absent.
    try:
        n_ext = int(es.count(index=scl_idx, query=ext_q)["count"]) if es.indices.exists(index=scl_idx) else 0
    except Exception as exc:  # noqa: BLE001
        log.warning("[reference-heal] centroid check failed (%s); skipping bootstrap", exc)
        n_ext = 1  # transient error — don't risk a spurious re-bootstrap
    if n_ext == 0 and n_emb > 0:
        log.info("[reference-heal] no external reference centroids → cluster sessions --bootstrap-from external")
        try:
            smod = _load_source_layer("cowrie", "sessions")
            if smod is not None:
                smod.run_cluster(cfg, secrets, dry_run=False, refresh_reference=False,
                                 use_reference=True, bootstrap_from="external")
                out["actions"].append("bootstrapped_external_centroids")
        except Exception as exc:  # noqa: BLE001
            log.warning("[reference-heal] external bootstrap failed (%s)", exc)

    out["status"] = "healed" if out["actions"] else "healthy"
    return out


def _wipe_processed(cfg, secrets, source: str) -> dict:
    """Destroy every processed ES index for this source and recreate them
    from their mapping files; clear the SQLite cache + watermark. The raw
    `sessions_raw` (cowrie source-of-truth) index is intentionally not
    touched — this only wipes derived/computed data so the pipeline can be
    rebuilt from scratch.

    Returns a dict of per-index actions and per-state-table row counts.
    """
    from .es_client import init_index, make_client
    from .cache import StateDB

    es = make_client(cfg.elasticsearch, secrets)
    mappings = _LAYER_MAPPINGS.get(source) or {}
    # All layers except `sessions` (which is sessions_raw alias-bearing for
    # other sources; for cowrie source it maps to sessions_rollup which IS
    # processed) — and we explicitly EXCLUDE the raw source-of-truth.
    #
    # For cowrie: processed layers are everything in the mapping table.
    # `sessions_raw` is NOT in the mapping table (it's an external index
    # produced by Filebeat/Elastic agent) — so iterating mappings.keys() is
    # already the right set.
    out: dict = {"deleted": [], "created": [], "errors": []}
    for layer in mappings.keys():
        idx = _resolve_index_for_layer(cfg, source, layer)
        # Delete (idempotent).
        try:
            if es.indices.exists(index=idx):
                es.indices.delete(index=idx)
                out["deleted"].append(idx)
        except Exception as exc:
            out["errors"].append({"layer": layer, "action": "delete", "error": str(exc)})
            continue
        # Recreate from mapping file.
        try:
            r = init_index(es, mappings[layer], idx)
            out["created"].append(r)
        except Exception as exc:
            out["errors"].append({"layer": layer, "action": "init", "error": str(exc)})

    # SQLite state.
    try:
        db = StateDB(cfg.worker.state_db)
        out["sqlite_cache_rows_deleted"]     = db.clear_cache()
        out["sqlite_watermark_rows_deleted"] = db.clear_watermark()
        db.close()
    except Exception as exc:
        out["errors"].append({"action": "sqlite_clear", "error": str(exc)})
    return out


def _acquire_pipeline_lock(cfg, *, no_lock: bool, print_args):
    """Acquire the same flock the systemd units use, so manual `pipeline`
    invocations serialise with the forward / backward / mine-findings
    timers. Returns the open file descriptor (caller keeps it alive for
    the duration of the run; closing releases the lock).

    Lock path mirrors the systemd units: `<state_db parent>/.lock`. With
    the default config that's `/var/lib/dshield_prism/.lock`.

    --no-lock skips acquisition entirely. Pre-emptive escape hatch for
    test environments or ad-hoc runs where you've already stopped the
    systemd timers and don't want the lock dance.
    """
    if no_lock:
        print_args("[pipeline] --no-lock: skipping flock acquisition (caller responsible for serialisation)")
        return None
    import fcntl
    from pathlib import Path
    lock_path = Path(cfg.worker.state_db).parent / ".lock"
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    # Open for append (creates if missing). The file's content is
    # irrelevant — the OS-level advisory lock is what serialises us.
    lock_fd = open(lock_path, "a")
    try:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        print_args(f"[pipeline] acquired lock {lock_path}")
    except BlockingIOError:
        print_args(f"[pipeline] waiting for lock {lock_path} (held by another process — likely forward/backward/mine-findings)")
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
        print_args(f"[pipeline] acquired lock {lock_path}")
    return lock_fd


def _maybe_reset_rollup_watermarks(cfg, secrets, *, force: bool = False) -> dict:
    """P1.1 — clear the session + IP rollup watermarks (forcing a full re-pool)
    only when there's something to absorb: a command-level rewrite happened
    (dirty flag, set by re-enrich-stale/reembed) or the rollup builder changed
    (`rollup_schema_hash`). `force` overrides the gate. When it resets it stamps
    the current schema hash and clears the dirty flag; a downstream rollup that
    fails self-corrects because the watermark stays cleared (→ full re-pool next
    run). Mirrors `reset --session-watermark --ip-watermark`, conditionally."""
    from .cache import StateDB
    from .rollup_gate import (
        ROLLUP_DIRTY_KEY, ROLLUP_SCHEMA_HASH_KEY, rollup_repool_decision,
    )
    from .sources.cowrie.sessions import rollup_schema_hash
    db = StateDB(cfg.worker.state_db)
    try:
        cur = rollup_schema_hash(cfg)
        stored = db.get_watermark(ROLLUP_SCHEMA_HASH_KEY)
        dirty = bool(db.get_watermark(ROLLUP_DIRTY_KEY))
        if force:
            do_reset, reason = True, "force"
        else:
            do_reset, reason = rollup_repool_decision(dirty, cur, stored)
        if not do_reset:
            logging.getLogger(__name__).info(
                "rollup re-pool gate: SKIP (reason=%s) — rollups stay incremental",
                reason,
            )
            return {"reset": False, "reason": reason}
        sess = db.clear_watermark("session_last_processed_at")
        ipw = db.clear_watermark("ip_rollup_last_processed_at")
        db.set_watermark(cur, ROLLUP_SCHEMA_HASH_KEY)
        db.clear_watermark(ROLLUP_DIRTY_KEY)
        logging.getLogger(__name__).info(
            "rollup re-pool gate: RESET (reason=%s) — next rollup is a full re-pool",
            reason,
        )
        return {
            "reset": True, "reason": reason,
            "session_watermark_rows_deleted": sess,
            "ip_watermark_rows_deleted": ipw,
        }
    finally:
        db.close()


def _run_pipeline(cfg, secrets, args) -> int:
    """End-to-end runner: each verb is invoked in dependency order via the
    same `run_*` entry points the individual CLI verbs call. Steps marked
    `optional=True` won't halt the chain on failure (mirrors the analytics
    systemd unit's leading `-` semantics). `--continue-on-error` extends
    that tolerance to every step.

    The whole run is serialised with the systemd timers via an exclusive
    flock on `<state_db_parent>/.lock`. Use `--no-lock` to skip if the
    timers are already stopped and you want a fast manual iteration.
    """
    print_args = lambda *a, **kw: print(*a, **{**kw, "flush": True})

    # Hold the flock for the entire run. `_pipeline_lock_fd` stays alive
    # in this scope; closing on function exit releases the lock.
    _pipeline_lock_fd = _acquire_pipeline_lock(
        cfg, no_lock=getattr(args, "no_lock", False), print_args=print_args,
    )

    # ---- Optional fresh-start wipe ---------------------------------------
    # `--force` wipes every processed index across ALL sources (cowrie +
    # intel + findings) plus the SQLite cache + watermark. The only thing
    # preserved is the raw `sessions_raw` index — that's the source of
    # truth ingested by Filebeat/Elastic-agent and is intentionally not
    # touched. Re-running the pipeline rebuilds everything else from raw.
    wipe_sources = ["cowrie", "intel", "findings"]
    if args.force:
        if not args.yes:
            try:
                resp = input(
                    "[pipeline] --force will DELETE every processed ES index "
                    f"across all sources ({', '.join(wipe_sources)}):\n"
                    f"  cowrie:   {', '.join(_LAYER_MAPPINGS.get('cowrie', {}))}\n"
                    "  intel:    prism.intel.ip, prism.intel.url\n"
                    "  findings: prism.finding\n"
                    "and clear the SQLite cache + watermark. The raw "
                    "sessions_raw index is NOT touched.\n"
                    "NOTE: this includes reference_session (the imported "
                    "Atomic Red Team / Tradecraft corpus) and playbook_anchors "
                    "— the reference corpus must be re-bootstrapped afterward "
                    "(setup/3-bootstrap-reference-corpus.sh; reference-heal does "
                    "NOT re-clone it).\n"
                    "Proceed? [y/N] "
                ).strip().lower()
            except EOFError:
                resp = ""
            if resp not in ("y", "yes"):
                print_args("Aborted.")
                return 1
        if args.dry_run:
            print_args(
                "[pipeline] DRY-RUN: would wipe every processed index across "
                f"{wipe_sources}, clear SQLite, then run every step."
            )
        else:
            wipe_summary: dict = {}
            for src in wipe_sources:
                wipe_summary[src] = _wipe_processed(cfg, secrets, src)
            print_args("[pipeline] wipe:")
            print_args(json.dumps(wipe_summary, indent=2, default=str))

    # ---- Step plan -------------------------------------------------------
    # Each step is (name, callable, optional). `optional=True` mirrors the
    # systemd unit's leading-dash semantics: a failure logs but doesn't
    # break the chain. Order is the same as the systemd ingest + analytics
    # services chained together.
    cmds_mod      = _commands_layer(args.source)
    sessions_mod  = _load_source_layer(args.source, "sessions")
    ips_mod       = _load_source_layer(args.source, "ips")
    campaigns_mod = _load_source_layer(args.source, "campaigns")
    if cmds_mod is None or sessions_mod is None or ips_mod is None or campaigns_mod is None:
        log.error("Source %r is missing one or more pipeline layers.", args.source)
        return 1

    dry = args.dry_run
    if getattr(args, "ignore_config_hash", False):
        cfg.worker.cache_auto_invalidate = False

    # Lazy imports so a missing optional dep (e.g. intel disabled in
    # local.yaml) doesn't break the dispatcher import path.
    def _run_intel_refresh():
        from .intel.refresh import run_refresh
        return run_refresh(cfg, secrets, dry_run=dry)

    def _run_mine_findings():
        from .findings.miner import run_mine as _rm
        return _rm(cfg, secrets, dry_run=dry)

    def _run_track_lifecycles():
        from .findings.lifecycle import run_track_lifecycles
        return run_track_lifecycles(cfg, secrets, dry_run=dry)

    def _prune_clusters():
        """Cap each cluster index to the newest _DEFAULT_CLUSTER_KEEP_RUNS runs
        (scale-hardening P2.1). reference_centroid generations are preserved.
        Runs after clustering so the newest run is always in the keep set."""
        from .es_client import make_client
        from .clustering import prune_cluster_runs
        es = make_client(cfg.elasticsearch, secrets)
        targets = _cluster_indices_for_source(cfg, args.source) or []
        results = [
            prune_cluster_runs(
                es, idx, keep_runs=_DEFAULT_CLUSTER_KEEP_RUNS,
                dry_run=dry, layer_label=label,
            )
            for label, idx in targets
        ]
        return {"indices": results}

    def _reset_rollup_watermarks():
        """P1.1 — conditionally clear the session + IP rollup watermarks so the
        next rollup re-pools, but only when there's something to absorb (command
        rewrite or rollup-schema change); `--force` always resets. Returns the
        gate decision + reason for the step summary."""
        return _maybe_reset_rollup_watermarks(cfg, secrets, force=args.force)

    steps: list[tuple[str, callable, bool]] = [
        # ---- pre-enrich catch-up: re-LLM and re-embed any rows whose
        # cache hashes drifted since the last run. Both are no-ops in
        # steady state and on fresh deploys; they only do work when a
        # prompt edit, embed_context change, or model swap has happened.
        # Optional: shouldn't halt the chain if the LLM is down.
        ("re-enrich-stale",            lambda: cmds_mod.run_reenrich_stale(cfg, secrets, dry_run=dry),                    True),
        ("reembed",                    lambda: cmds_mod.run_reembed(cfg, secrets, dry_run=dry),                           True),

        # ---- ingest: raw events → enriched commands
        ("enrich",                     lambda: cmds_mod.run_enrich(cfg, secrets, dry_run=dry, no_cloud=args.no_cloud), False),

        # ---- force a full rollup re-pool. The rollup verbs are
        # watermark-driven; after re-enrich-stale or reembed may have
        # rewritten command-level data, we want the session/IP rollups
        # to incorporate those changes rather than only processing rows
        # whose source ts is newer than the watermark. SQLite-only;
        # cheap and idempotent. Mirrors backward systemd step 3.
        ("reset rollup watermarks",    _reset_rollup_watermarks,                                                          True),

        # ---- session rollup + command clustering + cloud escalation
        ("rollup sessions",            lambda: sessions_mod.run_rollup(cfg, secrets, dry_run=dry),                       False),
        ("cluster commands",           lambda: cmds_mod.run_cluster(cfg, secrets, dry_run=dry),                           False),
        ("escalate",                   lambda: cmds_mod.run_escalate(cfg, secrets, dry_run=dry),                          True),

        # ---- self-heal the external reference baseline (Tradecraft Matches)
        # before scoring live sessions against it. Local-only + state-gated;
        # cheap no-op when healthy. Never clones GitHub (import stays setup-time).
        ("reference-heal",             lambda: _run_reference_heal(cfg, secrets) if not dry else {"dry_run": True}, True),

        # ---- session clustering + LLM naming (playbooks = named session clusters)
        ("cluster sessions",           lambda: sessions_mod.run_cluster(cfg, secrets, dry_run=dry),                       False),
        ("name playbooks",             lambda: sessions_mod.run_name_playbooks(cfg, secrets, dry_run=dry, force=False),   True),

        # ---- IP rollup + clustering. `rollup ips` MUST come after
        # `name playbooks` because session rollups carry playbook_id
        # only after naming runs, and `name ip-clusters` reads those
        # session rollups to derive dominant_playbook per IP cluster.
        # ROADMAP #24.
        ("rollup ips",                 lambda: ips_mod.run_rollup(cfg, secrets, dry_run=dry),                             False),
        ("cluster ips",                lambda: ips_mod.run_cluster(cfg, secrets, dry_run=dry),                            False),
        ("name ip-clusters",           lambda: ips_mod.run_name_ip_clusters(cfg, secrets, dry_run=dry),                   True),

        # ---- cap the cluster indices (P2.1): keep newest K runs per layer,
        # delete dead per-run state. reference_centroid generations preserved.
        # After all clustering so the newest run is always in the keep set.
        ("prune clusters",             _prune_clusters,                                                                   True),

        # ---- multi-session campaign mining (frequent-itemset + shared-artifact)
        ("mine campaigns",             lambda: campaigns_mod.run_mine(cfg, secrets, kind="all", dry_run=dry),             True),

        # ---- lifecycle snapshot pass (Findings v2 step 1) — must run after
        # `name playbooks` (playbook ids exist) and `mine campaigns`
        # (campaign ids exist); feeds the drift detectors that ship in
        # Findings v2 step 4 once anchors are populated.
        ("track lifecycles",           _run_track_lifecycles,                                                              True),

        # ---- external threat-intel refresh — must run AFTER `rollup ips`
        # (uses IP rollup for discovery) and AFTER `enrich` (uses
        # LLM-extracted URL indicators in the commands index). No-op
        # when intel is disabled in config; the run_refresh entry
        # point gates on cfg.intel.enabled.
        ("intel refresh",              _run_intel_refresh,                                                                True),

        # ---- findings miner — populates prism.finding with one card
        # per playbook + per campaign. Reads everything above;
        # intentionally last in the chain so the inbox reflects this
        # pipeline's output.
        ("mine findings",              _run_mine_findings,                                                                True),
    ]

    # Backlog B2 / problem #1 — historical-backfill safe mode. Replaying 2-year
    # data through a few backfill runs would (a) leave old sessions unclustered
    # under the 30d window and (b) corrupt the temporal layer: lifecycle
    # snapshots stamped at backfill wall-clock, and a `new_playbook` /
    # `intel_verdict_flip` inbox flood. So force full-corpus session clustering
    # and drop the temporally-corrupting steps. The forward findings/lifecycle
    # layer is built by a normal `pipeline` run AFTER the backfill completes
    # (B3/B4). intel + cloud should be off for the historical phase.
    if getattr(args, "backfill", False):
        steps = _apply_backfill_mode(steps, {
            # full-corpus session labelling. Option A cutover: assignment over the whole
            # corpus + novel-pool HDBSCAN when assignment_authoritative is on (keeps the
            # backfilled history consistent with steady state); legacy full HDBSCAN
            # otherwise / to bootstrap the first anchor library.
            "cluster sessions": lambda: _backfill_cluster_sessions(
                cfg, secrets, sessions_mod, dry),
            # clear session+IP watermarks so the rollups re-pool the full history
            # (force=True bypasses the schema/dirty gate the steady-state runs use)
            "reset rollup watermarks": lambda: _maybe_reset_rollup_watermarks(
                cfg, secrets, force=True),
            # re-enrich commands in the older-than-watermark history; the
            # per-command cache skips re-LLM on already-enriched commands
            "enrich": lambda: cmds_mod.run_enrich(
                cfg, secrets, dry_run=dry, no_cloud=args.no_cloud, full_rescan=True),
        })
        on = [n for n, e in (("intel", cfg.intel.enabled), ("cloud", cfg.cloud.enabled)) if e]
        if on:
            log.warning(
                "[pipeline --backfill] %s enabled — recommend disabling for the "
                "historical phase (verdicts are anachronistic; cloud budget is "
                "spent on backfill novelty). See backlog #5/#6.", " + ".join(on),
            )
        _bf_session = ("assignment (full corpus) + novel-pool HDBSCAN"
                       if getattr(cfg.session, "assignment_authoritative", False)
                       else "full-corpus HDBSCAN (--window-days 0)")
        print_args(
            "[pipeline] BACKFILL mode: full-rescan enrich + session+IP rollup "
            "watermarks cleared for a full re-pool of the historical corpus; "
            f"session labelling = {_bf_session}; "
            "'track lifecycles' + 'mine findings' skipped"
        )
        if not dry and sys.stdout.isatty():
            print_args(
                "[pipeline] tip: a bulk backfill can run for hours/days — start it "
                "detached so an SSH disconnect can't kill it:\n"
                "    sudo systemctl start dshield_prism-backfill   "
                "# watch: journalctl -fu dshield_prism-backfill"
            )

    if dry:
        print_args("[pipeline] DRY-RUN — step plan:")
        for i, (name, _fn, optional) in enumerate(steps, 1):
            tag = " (optional)" if optional else ""
            print_args(f"  {i:2}. {name}{tag}")
        # Still call each so dry-run telemetry from the steps that support it
        # is exposed (most do).
    print_args(f"[pipeline] running {len(steps)} step(s){' (dry-run)' if dry else ''}")

    # Inter-step ES capacity gate (backpressure): a heap-spiking step (e.g. the
    # cluster-assignment write+refresh) can leave the node's parent circuit
    # breaker near its limit. Before each step, pause until heap drains so the
    # next step doesn't pile on and trip the breaker. Best-effort and skipped
    # when disabled or unreachable; the per-call client wrapper handles the rest.
    from .es_client import make_client
    from .es_health import wait_for_capacity
    _bp = getattr(cfg.elasticsearch, "backpressure", None)
    try:
        _gate_es = make_client(cfg.elasticsearch, secrets) if (_bp and not dry) else None
    except Exception:  # noqa: BLE001 — the gate is a nicety, never fatal
        _gate_es = None

    summary: dict = {"force_wipe": bool(args.force), "dry_run": dry, "steps": []}
    failed_hard = False
    for i, (name, fn, optional) in enumerate(steps, 1):
        print_args(f"\n=== [{i}/{len(steps)}] {name}" + (" (optional)" if optional else "") + " ===")
        if _gate_es is not None:
            try:
                wait_for_capacity(_gate_es, _bp, label=f"pipeline step '{name}'")
            except Exception as exc:  # noqa: BLE001 — never let the gate fail a run
                log.debug("[pipeline] capacity gate skipped for %s: %s", name, exc)
        try:
            stats = fn()
            summary["steps"].append({"name": name, "ok": True, "stats": stats})
            print_args(json.dumps(stats, indent=2, default=str))
        except Exception as exc:
            summary["steps"].append({"name": name, "ok": False, "error": str(exc)})
            # Step failure is operator-actionable → logger (durable in cli.log +
            # leveled), P4.1. The json summary below still records it on stdout.
            log.error("[pipeline] step %s failed: %s", name, exc)
            if optional or args.continue_on_error:
                continue
            failed_hard = True
            break

    print_args("\n[pipeline] summary:")
    print_args(json.dumps(
        {"force_wipe": summary["force_wipe"],
         "dry_run":    summary["dry_run"],
         "steps":      [{"name": s["name"], "ok": s["ok"]} for s in summary["steps"]]},
        indent=2,
    ))
    return 1 if failed_hard else 0


def _resolve_index_for_layer(cfg, source: str, layer: str) -> str:
    """Map (source, layer) -> the configured index name on cfg."""
    if source == "cowrie":
        c = cfg.elasticsearch.indexes.cowrie
        return {
            "commands":          c.commands,
            "command_clusters":  c.command_clusters,
            "sessions":          c.sessions_rollup,
            "session_clusters":  c.session_clusters,
            "ips":               c.ips_rollup,
            "ip_clusters":       c.ip_clusters,
            "campaigns":         c.campaigns,
            "playbook_anchors":  c.playbook_anchors,
            "reference_session": c.reference_sessions,
            "operations":        c.operations,
            "file_command_crossref": c.file_command_crossref,
        }[layer]
    if source == "dshield":
        d = cfg.elasticsearch.indexes.dshield
        return {
            "firewall":    d.firewall,
            "firewall_ip": d.firewall_ip,
        }[layer]
    if source == "intel":
        i = cfg.intel.indexes
        return {
            "ip":     i.ip,
            "url":    i.url,
            "domain": i.domain,
            "hash":   i.hash,
        }[layer]
    if source == "findings":
        return {"default": cfg.findings.indexes.default}[layer]
    if source == "lifecycle":
        f = cfg.findings.indexes
        return {
            "playbook":  f.playbook_lifecycle,
            "campaign":  f.campaign_lifecycle,
            "source_ip": f.source_ip_lifecycle,
        }[layer]
    if source == "analyst":
        return {"artifact_rules": cfg.analyst.indexes.artifact_rules}[layer]
    if source == "metrics":
        return {"default": cfg.metrics.indexes.default}[layer]
    if source == "ops":
        return {"default": cfg.ops.indexes.default}[layer]
    raise ValueError(f"Unknown source: {source}")


# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=CLI_NAME)
    p.add_argument("--config", default=None, help="Path to YAML config")
    sub = p.add_subparsers(dest="verb", required=True)

    # healthcheck
    p_hc = sub.add_parser("healthcheck", help="Verify ES/LLM/SQLite/cloud connectivity")
    p_hc.add_argument(
        "--scope",
        default="all",
        help=(
            "Comma-separated subset of scopes: "
            f"{','.join(hc_mod.VALID_SCOPES)} (or 'all'). "
            "Example: --scope llm,cloud."
        ),
    )

    # enrich (commands-layer only for now; multi-layer future opens this up)
    p_enrich = sub.add_parser("enrich", help="Enrich command events from a source")
    p_enrich.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_enrich.add_argument("--dry-run", action="store_true", help="Read events but skip LLM + writes")
    p_enrich.add_argument("--no-cloud", action="store_true", help="Force-disable cloud escalation for this run")
    p_enrich.add_argument(
        "--ignore-config-hash", action="store_true",
        help=(
            "Override worker.cache_auto_invalidate=true for this run only — "
            "treat the cache as if prompt/cooccurrence config didn't change. "
            "Use when LLM budget is tight and you'd rather keep current "
            "enrichments through a config drift."
        ),
    )
    p_enrich.add_argument(
        "--reference", action="store_true",
        help=(
            "Enrich commands in the reference-corpus rollup "
            "(`prism.reference.cowrie.session`) instead of the live "
            "cowrie events stream. One-shot pass; no watermark; "
            "co-occurrence disabled. Pair with `--budget N` to cap "
            "LLM cycles. brutal-review phase 5.3."
        ),
    )
    p_enrich.add_argument(
        "--budget", type=int, default=None,
        help=(
            "Cap the number of cache-miss LLM calls in this run. "
            "Subsequent cache-miss commands are deferred to a future "
            "invocation (the cache means they resume cleanly). Useful "
            "with `--reference` for incremental enrichment of large "
            "reference corpora."
        ),
    )

    # budget
    sub.add_parser("budget", help="Show today's cloud-LLM spend vs daily cap")

    # reset
    p_reset = sub.add_parser(
        "reset",
        help="Clear local SQLite state (cache and/or watermarks). Does NOT touch ES.",
    )
    p_reset.add_argument("--cache", action="store_true",
                         help="Clear the enrichment cache")
    p_reset.add_argument("--watermark", action="store_true",
                         help="Clear ALL watermarks (command + session + IP)")
    p_reset.add_argument("--all", action="store_true",
                         help="Clear cache and all watermarks (default when no flag given)")
    p_reset.add_argument("--session-watermark", action="store_true",
                         help=(
                             "Clear only the session-rollup watermark "
                             "(forces a full re-rollup of sessions). "
                             "Combinable with other flags."
                         ))
    p_reset.add_argument("--ip-watermark", action="store_true",
                         help=(
                             "Clear only the IP-rollup watermark "
                             "(forces a full re-rollup of IPs). "
                             "Combinable with other flags."
                         ))
    p_reset.add_argument(
        "--if-stale", action="store_true",
        help=(
            "P1.1 — gate the session+IP rollup-watermark reset: clear them "
            "(forcing a full re-pool) ONLY when a command rewrite happened since "
            "the last re-pool or the rollup builder changed; otherwise no-op. "
            "Used by the backward chain so steady-state stops re-pooling the "
            "whole corpus every cycle. Ignores the other --*-watermark flags."
        ),
    )
    p_reset.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    # purge — destructive ES-index wipes scoped by subject. Currently the
    # only subject is `lifecycles`, which wipes the three lifecycle indices,
    # the findings index, the campaigns index, and the playbook anchor
    # index — then re-creates each from its mapping file. Used to recover
    # from id-scheme migrations or any other state corruption where the
    # cheap fix is to rebuild from upstream on the next backward cycle.
    p_purge = sub.add_parser(
        "purge",
        help="Destructive wipe of an ES-index subject. Subjects: lifecycles.",
    )
    p_purge.add_argument(
        "subject",
        choices=["lifecycles"],
        help=(
            "lifecycles: wipe lifecycle/{playbook,campaign,source_ip}, "
            "findings, campaigns, and playbook_anchor indices."
        ),
    )
    p_purge.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    # init-indexes
    p_init = sub.add_parser(
        "init-indexes",
        help="Create ES indexes from mapping JSON. Defaults to all layers for the source.",
    )
    p_init.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_init.add_argument(
        "--layer",
        default=None,
        help=(
            "Specific layer to init (e.g. commands, sessions, ips, command_clusters, "
            "session_clusters, ip_clusters). Omit to init all layers."
        ),
    )
    p_init.add_argument(
        "--update-mapping",
        action="store_true",
        help="If an index exists, push additive mapping changes instead of noop",
    )

    # reference-heal — self-heal the external reference baseline (Tradecraft
    # Matches) using local steps only. State-gated + idempotent; runs in the
    # backward chain. Never clones GitHub (the import stays setup/manual).
    sub.add_parser(
        "reference-heal",
        help=(
            "Finish/repair the external reference baseline (Tradecraft Matches) "
            "with LOCAL steps only: enrich --reference if the imported corpus is "
            "un-embedded, then mint external centroids if missing. No-op when "
            "healthy or when no corpus has been imported."
        ),
    )

    # bootstrap-es — apply project-owned ES templates + ingest pipelines from
    # the setup/ tree. Idempotent. Runs from the install dir; reuses the
    # same ES client (TLS + auth) as everything else. Setup script calls
    # this after healthcheck and before init-indexes so the data-stream
    # template exists when the cowrie ingest pipeline first reroutes into
    # `prism.raw.cowrie.session`.
    p_boot = sub.add_parser(
        "bootstrap-es",
        help="Apply setup/*.yaml + setup/es-pipelines/*.yml to ES (templates + ingest pipelines)",
    )
    p_boot.add_argument(
        "--dry-run", action="store_true",
        help="Parse + list what would be applied without contacting ES",
    )

    # escalate
    p_escalate = sub.add_parser(
        "escalate",
        help="Re-triage novel locally-enriched docs via cloud LLM. Run after cluster.",
    )
    p_escalate.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_escalate.add_argument("--dry-run", action="store_true", help="Count candidates without making cloud calls")

    # reembed
    p_reembed = sub.add_parser(
        "reembed",
        help="Re-embed enrichment docs using stored fields. No LLM generation calls.",
    )
    p_reembed.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_reembed.add_argument(
        "--dry-run", action="store_true",
        help="Count docs that would be re-embedded without calling the embed model or writing to ES",
    )
    p_reembed.add_argument(
        "--ignore-config-hash", action="store_true",
        help="See `enrich --ignore-config-hash`.",
    )

    # re-enrich-stale — LLM-side mirror of `reembed`. Walks the commands
    # index, finds cache rows whose llm_config_hash is stale (e.g. after
    # a prompt edit), re-calls the local LLM, and patches the doc.
    p_reenrich = sub.add_parser(
        "re-enrich-stale",
        help=(
            "Re-run the local LLM on every doc whose cached llm_config_hash "
            "is stale. The LLM-side counterpart of `reembed`. Skips rows "
            "whose hash already matches live (cheap no-op when nothing has "
            "changed). Burns LLM time per stale doc when prompts or "
            "LLM-side cooccurrence config have drifted. ROADMAP issue #7.5."
        ),
    )
    p_reenrich.add_argument("--source", default="cowrie",
                            help="Source name (default: cowrie)")
    p_reenrich.add_argument("--dry-run", action="store_true",
                            help="Count stale rows without calling LLM or writing.")

    # backfill-shape — one-shot admin op. Stamps shape.hash + role on
    # every existing command doc so the functional-duplicate gate in
    # `enrich` (ROADMAP #9) can find canonicals among historically-
    # enriched commands. No LLM. No embedding.
    p_backfill_shape = sub.add_parser(
        "backfill-shape",
        help=(
            "Stamp shape.hash + role on every enriched command doc. "
            "Run once after the mapping deploy that adds the shape "
            "block. No LLM. Idempotent — re-running only touches docs "
            "whose recomputed hash differs from what's stored. "
            "ROADMAP issue #9."
        ),
    )
    p_backfill_shape.add_argument(
        "--source", default="cowrie", help="Source name (default: cowrie)")
    p_backfill_shape.add_argument(
        "--dry-run", action="store_true",
        help="Count docs that would be stamped without writing.")

    # prune-clusters — scale-hardening P2.1. Cap each cluster index by keeping
    # only the newest --keep-runs runs' cluster + run_summary docs; delete the
    # rest. reference_centroid generations are always preserved. Also wired
    # into the backward chain so the indices stay bounded automatically.
    p_prune_clusters = sub.add_parser(
        "prune-clusters",
        help=(
            "Delete dead per-run cluster + run_summary docs, keeping only the "
            "newest --keep-runs runs per cluster index. reference_centroid "
            "generations are always preserved. Caps the otherwise unbounded "
            "cluster indices. Scale-hardening P2.1."
        ),
    )
    p_prune_clusters.add_argument(
        "--source", default="cowrie", help="Source name (default: cowrie)")
    p_prune_clusters.add_argument(
        "--keep-runs", type=int, default=_DEFAULT_CLUSTER_KEEP_RUNS,
        help=(
            f"Most-recent runs to retain per cluster index "
            f"(default: {_DEFAULT_CLUSTER_KEEP_RUNS}). Only the latest run is "
            "ever read; the remainder is rollback buffer."
        ),
    )
    p_prune_clusters.add_argument(
        "--dry-run", action="store_true",
        help="Count would-be deletions per index without deleting.")

    # apply-artifact-rules — retroactive scan for analyst-authored rules
    # (ROADMAP #5). Walks the commands index, stamps
    # `dshield.cowrie.enrichment.analyst_artifacts` for every match.
    # Idempotent. Wired into the backward systemd cycle so a rule created
    # from the console between cycles converges on the next run.
    p_apply_rules = sub.add_parser(
        "apply-artifact-rules",
        help=(
            "Apply analyst-authored artifact rules retroactively to the "
            "commands index. With --rule-id, scans only that rule; "
            "otherwise scans every active rule. Idempotent. ROADMAP #5."
        ),
    )
    p_apply_rules.add_argument(
        "--source", default="cowrie", help="Source name (default: cowrie)")
    p_apply_rules.add_argument(
        "--rule-id", default=None, action="append",
        help="Scan only this rule (repeatable). Default: all active rules.")
    p_apply_rules.add_argument(
        "--dry-run", action="store_true",
        help="Count matches without stamping docs.")

    # re-triage — re-evaluate stored `triage_reasons` against current rules.
    # No LLM/cloud calls. Closes the gap that `re-enrich-stale` doesn't cover:
    # triage.py changes (e.g. ROADMAP #23) don't affect llm_config_hash, so
    # stored triage_reasons on already-enriched docs go stale silently.
    p_retriage = sub.add_parser(
        "re-triage",
        help=(
            "Re-evaluate stored `triage_reasons` on every enriched command "
            "using the current triage rules. No LLM or cloud calls. Useful "
            "after a triage-rule change (e.g. #23) that re-enrich-stale "
            "won't pick up. Preserves runtime-only reasons "
            "(budget_exhausted/cloud_failed/sample). ROADMAP #23 follow-on."
        ),
    )
    p_retriage.add_argument("--source", default="cowrie",
                            help="Source name (default: cowrie)")
    p_retriage.add_argument(
        "--backward", action="store_true",
        help="Required. Scan every already-enriched doc and rewrite "
             "triage_reasons. Required flag so the verb has room for a "
             "future --forward mode without breaking call sites.",
    )
    p_retriage.add_argument(
        "--window-days", type=int, default=None,
        help="Only re-evaluate docs whose @timestamp is within the last N "
             "days. Default: all docs. Matches the #21 pattern.",
    )
    p_retriage.add_argument("--dry-run", action="store_true",
                            help="Report what would change without writing.")

    # bless-cache — stamp existing cache rows with the current config hash so
    # they're treated as fresh after a #7-style auto-invalidating config change.
    # The user opts into this when they know existing enrichments are
    # consistent with the current cooccurrence config + prompts.
    p_bless = sub.add_parser(
        "bless-cache",
        help=(
            "Stamp all legacy cache rows (config_hash='') with the current "
            "config hash so they're treated as fresh. Use after deploying a "
            "config-affecting change when you know the cached enrichments are "
            "still correct under the new config. ROADMAP issue #7."
        ),
    )
    p_bless.add_argument(
        "--dry-run", action="store_true",
        help="Report how many rows would be stamped without writing to the cache.",
    )

    # cluster <layer>
    p_cluster = sub.add_parser("cluster", help="Run HDBSCAN over a layer's embeddings")
    cluster_sub = p_cluster.add_subparsers(dest="layer", required=True)
    # The `all` layer runs commands → sessions → ips in sequence with the
    # same flag set applied to each. Per-layer verbs remain available and
    # unchanged; `all` is the convenience wrapper for backward-cycle runs.
    cluster_layer_help = {
        "commands": "Cluster commands",
        "sessions": "Cluster sessions",
        "ips":      "Cluster ips",
        "all":      "Cluster commands → sessions → ips in sequence (one --source / --dry-run / --refresh-reference flag set applies to all three)",
    }
    for layer_name in ("commands", "sessions", "ips", "all"):
        cl = cluster_sub.add_parser(layer_name, help=cluster_layer_help[layer_name])
        cl.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
        cl.add_argument("--dry-run", action="store_true", help="Fetch + cluster but skip all ES writes")
        cl.add_argument(
            "--accept-fallback", action="store_true",
            help=(
                "Session layer + clustering_mode=late_fusion only: when the doc "
                "count exceeds session.fusion_max_docs, cluster with plain "
                "HDBSCAN instead of hard-refusing the O(N^2) fusion path (P1.3)."
            ),
        )
        cl.add_argument(
            "--window-days", type=int, default=None,
            help=(
                "Session layer only (scale-hardening P1.2): cluster only sessions "
                "whose @timestamp is within the last N days, instead of the "
                "all-time rollup. Overrides session.cluster_window_days. Pass 0 "
                "to force a full re-cluster (use for the weekly full pass). "
                "Identity stays stable — playbook ids re-match by centroid anchor."
            ),
        )
        cl.add_argument(
            "--novel-pool", action="store_true",
            help=(
                "Session layer only (Option A cutover, I4d): cluster ONLY the novel "
                "pool (cluster.assignment_status=novel) — the sessions the authoritative "
                "`assign_sessions` runner left unassigned — to mint new anchors, instead "
                "of re-clustering the whole corpus. Use this once assignment is the "
                "labeller, or HDBSCAN fights assignment over playbook_id. No-op until the "
                "shadow field is populated."
            ),
        )
        # ROADMAP P1: stable across-run novelty scoring.
        ref_group = cl.add_mutually_exclusive_group()
        ref_group.add_argument(
            "--refresh-reference", action="store_true",
            help=(
                "Snapshot this run's centroids as the new reference_centroid set "
                "(bumps reference_generation). Score this run against the new ref."
            ),
        )
        ref_group.add_argument(
            "--no-reference", action="store_true",
            help=(
                "Escape hatch: score per-doc novelty against this run's centroids "
                "only (legacy intra-run behavior). Reference docs are neither "
                "read nor written."
            ),
        )
        ref_group.add_argument(
            "--bootstrap-from", choices=("external",), default=None,
            help=(
                "Read from a reference corpus (rather than the live rollup) "
                "and mint its centroids as a NEW reference generation tagged "
                "with the matching `reference_source`. `external` reads "
                "`prism.reference.cowrie.session` — populated by "
                "`import_reference_corpus.py` (5.2) + `enrich --reference` "
                "(5.3). Brutal-review phase 5.4; session layer only."
            ),
        )

    # rollup <layer>
    p_rollup = sub.add_parser("rollup", help="Aggregate one layer up from raw events")
    rollup_sub = p_rollup.add_subparsers(dest="layer", required=True)
    for layer_name in ("sessions", "ips"):
        rl = rollup_sub.add_parser(layer_name, help=f"Rollup to {layer_name}")
        rl.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
        rl.add_argument("--dry-run", action="store_true", help="Count without writing docs")

    # name playbooks — LLM-name each non-outlier session cluster. The cluster
    # is the "playbook" (a recurring routine); the LLM picks a short label.
    p_name = sub.add_parser("name", help="LLM-name clusters")
    name_sub = p_name.add_subparsers(dest="subject", required=True)
    p_pb = name_sub.add_parser("playbooks", help="Name session-cluster playbooks")
    p_pb.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_pb.add_argument("--dry-run", action="store_true", help="Show candidates without calling LLM")
    p_pb.add_argument("--force", action="store_true", help="Rename clusters that already have a name")

    # name ip-clusters — annotate each IP-cluster centroid with its modal
    # playbook across member IPs' sessions. Must run AFTER `name playbooks`
    # (depends on session.playbook_id being populated). ROADMAP #24.
    p_ipc = name_sub.add_parser(
        "ip-clusters",
        help="Annotate IP-cluster centroids with dominant_playbook (#24)",
    )
    p_ipc.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_ipc.add_argument("--dry-run", action="store_true", help="No-op")

    # mine campaigns — multi-session campaign discovery. Runs frequent-itemset
    # mining over per-IP playbook bags (kind=behaviour) and/or shared-artifact
    # graph mining over raw events (kind=infrastructure). Distinct from
    # playbooks (which are per-session-cluster). See docs/PLAYBOOKS_AND_CAMPAIGNS.md.
    p_mine = sub.add_parser("mine", help="Discover multi-session campaigns")
    mine_sub = p_mine.add_subparsers(dest="subject", required=True)
    p_mc = mine_sub.add_parser("campaigns", help="Mine multi-session campaigns")
    p_mc.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_mc.add_argument(
        "--kind",
        choices=["behaviour", "infrastructure", "all"],
        default="all",
        help="Which miner(s) to run (default: all)",
    )
    p_mc.add_argument("--dry-run", action="store_true",
                      help="Mine without writing campaign docs")
    p_mc.add_argument(
        "--window-days",
        type=int,
        default=None,
        help="Only consider sessions/events from the last N days. "
             "Default (None) uses the miner's built-in default (currently 30); "
             "pass 0 to disable windowing and scan the entire corpus (legacy "
             "unbounded behaviour — slower and memory-hungrier on large "
             "corpora). ROADMAP #21.",
    )

    # mine findings — M5 persisted findings index. Cross-source: reads IP
    # rollup + intel-{ip,url}, writes prism.finding. Status
    # workflow on each doc is preserved across re-mines (writer merges
    # analyst-owned fields back in). Hourly via systemd timer.
    p_mf = mine_sub.add_parser("findings", help="Mine likely_discovery + axis_disagreement findings (M5)")
    p_mf.add_argument("--dry-run", action="store_true",
                      help="Score + rank without writing finding docs")

    # mine operations — brutal-review phase 7.1. Promote merged
    # (bhv-campaign × inf-campaign) pairs whose IP overlap clears the
    # corpus-p75 percentile to first-class operation docs in
    # `prism.operations`. Same signal as `campaign_convergence` finding
    # but stable across re-mines via `op-<sha16>` ids content-addressed
    # on the (bhv, inf) pair.
    p_mo = mine_sub.add_parser("operations", help="Mine operations (bhv×inf merges)")
    p_mo.add_argument("--dry-run", action="store_true",
                      help="Evaluate pairs without writing operation docs")

    # mine hunts — brutal-review phase 6.1. Analyst-authored YAML
    # queries against the session rollup; matches emit
    # `kind=analyst_hunt` into prism.findings. Loads from
    # `cfg.findings.hunts.config_dir` (default: config/hunts).
    p_mh = mine_sub.add_parser(
        "hunts",
        help="Run analyst-authored hunt YAMLs and emit analyst_hunt findings",
    )
    p_mh.add_argument("--dry-run", action="store_true",
                      help="Load + execute but don't write findings")

    # mine file-crossref — brutal-review phase 7.6. Cross-session
    # file -> command attribution. One doc per (sha256, source.ip)
    # in `prism.crossref.file_command` carrying first_seen + first_executed
    # session pointers; `cross_session=true` marks pairs where the
    # exec happened in a DIFFERENT session than the drop.
    p_mfx = mine_sub.add_parser(
        "file-crossref",
        help="Mine cross-session file -> command attribution (sha256 x source.ip)",
    )
    p_mfx.add_argument("--dry-run", action="store_true",
                       help="Compute pairs without writing crossref docs")

    # track lifecycles — Findings v2 step 1. Walks session_clusters /
    # campaigns / ips_rollup; upserts one doc per playbook_id /
    # campaign_id / source.ip into the lifecycle indices, appending a
    # this-run snapshot and bumping `silent_runs_current` on artifacts
    # not seen this run. Wired into the backward chain between
    # `mine campaigns` and `intel refresh`.
    p_track = sub.add_parser("track", help="Findings v2 lifecycle tracking")
    track_sub = p_track.add_subparsers(dest="subject", required=True)
    p_tl = track_sub.add_parser("lifecycles", help="Upsert playbook / campaign / source-ip lifecycle docs")
    p_tl.add_argument("--dry-run", action="store_true",
                      help="Enumerate artifacts without writing lifecycle docs")
    # brutal-review phase 4.1 — corpus-distribution writer feeding the
    # percentile-based threshold migrations in 4.2-4.4.
    p_td = track_sub.add_parser(
        "threshold-distributions",
        help="Snapshot per-thresholded-quantity percentile distributions into prism.metrics",
    )
    p_td.add_argument("--dry-run", action="store_true",
                      help="Compute distributions without writing to prism.metrics")

    # intel — external threat-intel subsystem. `refresh` runs one pass:
    # discovers artifacts, priority-queues them, dispatches to every
    # enabled provider, writes intel-*-default docs. `backfill` forces a
    # full re-scan (currently identical to refresh; reserved for future
    # scoping). See docs/roadmap.md "Research-mode strategic gaps" A.
    p_intel = sub.add_parser("intel", help="External threat-intel subsystem (ROADMAP A)")
    intel_sub = p_intel.add_subparsers(dest="subject", required=True)
    p_intel_refresh = intel_sub.add_parser(
        "refresh",
        help="One refresh pass — discover, queue, lookup, write",
    )
    p_intel_refresh.add_argument(
        "--dry-run", action="store_true",
        help="Discover + queue without calling providers or writing intel docs",
    )
    p_intel_refresh.add_argument(
        "--force", action="store_true",
        help="Ignore the per-kind cache TTL (intel.refresh_ttl_days) and "
             "re-query every artifact, not just new/aged-out ones",
    )
    p_intel_backfill = intel_sub.add_parser(
        "backfill",
        help="Re-query every artifact, ignoring the per-kind cache TTL "
             "(use after wiring a new provider)",
    )
    p_intel_backfill.add_argument("--dry-run", action="store_true")
    # intel reapply-rules — re-derive each intel doc's verdicts from its
    # already-persisted per-provider structured data. No upstream calls,
    # so no budget burn. Use after deploying a consensus-rule change
    # (e.g. the 2026-05-17 authoritative_clean refinement).
    p_intel_reapply = intel_sub.add_parser(
        "reapply-rules",
        help="Recompute verdicts on existing intel docs without re-fetching",
    )
    p_intel_reapply.add_argument(
        "--dry-run", action="store_true",
        help="Walk every doc + report would-be changes without writing",
    )

    # pipeline — run every processing stage in order, raw → fully processed.
    # Mirrors the analytics + ingest systemd units but in one verb so a
    # human can rebuild from scratch (with --force) or top up incrementally
    # (without --force). Order matters: each step's inputs come from the
    # previous step's outputs.
    p_pipe = sub.add_parser(
        "pipeline",
        help=(
            "Run every processing step end-to-end: re-enrich-stale → reembed → "
            "enrich → reset rollup watermarks → rollup sessions → cluster commands → "
            "escalate → cluster sessions → name playbooks → rollup ips → cluster ips → "
            "name ip-clusters → prune clusters → mine campaigns → intel refresh → "
            "mine findings. "
            "Serialised with the systemd timers via an exclusive flock; pass "
            "--no-lock to skip when the timers are already stopped."
        ),
    )
    p_pipe.add_argument("--source", default="cowrie", help="Source name (default: cowrie)")
    p_pipe.add_argument(
        "--force", action="store_true",
        help=(
            "Wipe ALL processed data first, across every source, then "
            "recreate each index from its mapping and clear the SQLite "
            "cache + watermark. Targets: cowrie (commands, command_clusters, "
            "sessions_rollup, session_clusters, ips_rollup, ip_clusters, "
            "campaigns), intel (prism.intel.{ip,url}), findings "
            "(prism.finding). The raw `sessions_raw` index is "
            "NOT touched. Requires --yes to skip the confirmation prompt."
        ),
    )
    p_pipe.add_argument(
        "--yes", action="store_true",
        help="Skip the confirmation prompt for --force",
    )
    p_pipe.add_argument(
        "--dry-run", action="store_true",
        help="Print the step list (and pass --dry-run to each step) without writing data",
    )
    p_pipe.add_argument(
        "--continue-on-error", action="store_true",
        help=(
            "Don't halt if a step fails. By default the LLM-dependent steps "
            "(escalate, name playbooks, mine campaigns) already tolerate "
            "failure; this flag extends that to every step."
        ),
    )
    p_pipe.add_argument(
        "--ignore-config-hash", action="store_true",
        help="See `enrich --ignore-config-hash`. Applies to enrich/reembed steps.",
    )
    p_pipe.add_argument(
        "--no-cloud", action="store_true",
        help="Pass --no-cloud through to `enrich` (skip cloud escalation paths)",
    )
    p_pipe.add_argument(
        "--backfill", action="store_true",
        help=(
            "Historical-backfill safe mode (backlog B2 / problem #1). Forces "
            "`cluster sessions` to the full corpus (--window-days 0) and DROPS "
            "the two temporally-corrupting steps — `track lifecycles` and "
            "`mine findings` — which would stamp backfill wall-clock time onto "
            "old activity and flood the inbox. Recommends intel + cloud "
            "disabled (warns if enabled). Use for the 2-year historical phase; "
            "run a normal pipeline once after to build the forward findings."
        ),
    )
    p_pipe.add_argument(
        "--no-lock", action="store_true",
        help=(
            "Skip the flock acquisition that serialises with the forward / "
            "backward / mine-findings systemd timers. Default behaviour is "
            "to wait for the lock; pass --no-lock when you've already "
            "stopped the timers and want to iterate without the wait."
        ),
    )

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    secrets = load_secrets(args.config)
    _setup_log(cfg.worker.log_level, log_dir=cfg.worker.log_dir)
    return _dispatch_with_ops(args, cfg, secrets)


# Verbs that aren't a pipeline "run" — pure read-only status checks that would
# only add noise to prism.ops (healthcheck fires on every systemd ExecStartPre).
_OPS_SKIP_VERBS = {"healthcheck", "budget"}


def _dispatch_with_ops(args, cfg, secrets) -> int:
    """Wrap the verb dispatch with prism.ops run telemetry (P4.2): a
    started→finished/failed doc per invocation, including systemd-driven steps.
    Best-effort — a telemetry failure never changes the verb's outcome."""
    from . import ops
    handle = (
        None if args.verb in _OPS_SKIP_VERBS
        else ops.run_start(cfg, secrets, args.verb)
    )
    try:
        rc = _dispatch_verb(args, cfg, secrets)
    except Exception as exc:
        ops.run_finish(cfg, secrets, handle, status="failed", error=str(exc))
        raise
    ops.run_finish(
        cfg, secrets, handle,
        status="finished" if rc == 0 else "failed", rc=rc,
    )
    return rc


def _dispatch_verb(args, cfg, secrets) -> int:
    if args.verb == "healthcheck":
        raw_scope = (args.scope or "all").strip().lower()
        scopes = None if raw_scope == "all" else [s.strip() for s in raw_scope.split(",") if s.strip()]
        return hc_mod.check(cfg, secrets, scopes=scopes)

    if args.verb == "budget":
        from .cache import StateDB
        from . import triage as triage_mod
        db = StateDB(cfg.worker.state_db)
        today = triage_mod.utc_today()
        spent = db.get_spend(today)
        remaining = max(0.0, cfg.cloud.daily_budget_usd - spent["cost_usd"])
        out = {
            "date": today,
            "daily_budget_usd": cfg.cloud.daily_budget_usd,
            "spent_usd": round(spent["cost_usd"], 4),
            "remaining_usd": round(remaining, 4),
            "calls": spent["calls"],
            "input_tokens": spent["input_tokens"],
            "output_tokens": spent["output_tokens"],
            "cloud_enabled": cfg.cloud.enabled,
            "model": cfg.cloud.model,
        }
        db.close()
        print(json.dumps(out, indent=2))
        return 0

    if args.verb == "reset":
        if args.if_stale:
            # P1.1 — conditional rollup-watermark reset (gate decides). Ignores
            # the other selectors; this is the backward chain's re-pool gate.
            result = _maybe_reset_rollup_watermarks(cfg, secrets, force=False)
            print(json.dumps(result, indent=2))
            return 0
        from .cache import StateDB
        # Explicit selectors. Specific-watermark flags don't imply --all.
        explicit_specific = args.session_watermark or args.ip_watermark
        explicit_broad    = args.cache or args.watermark or args.all
        # No flag at all = clear everything (legacy default behaviour).
        default_all = not (explicit_specific or explicit_broad)

        do_cache       = args.cache or args.all or default_all
        do_all_wm      = args.watermark or args.all or default_all
        do_session_wm  = args.session_watermark and not do_all_wm
        do_ip_wm       = args.ip_watermark and not do_all_wm

        targets: list[str] = []
        if do_cache:      targets.append("cache")
        if do_all_wm:     targets.append("watermarks (all)")
        if do_session_wm: targets.append("session watermark only")
        if do_ip_wm:      targets.append("IP watermark only")
        msg = f"About to clear: {', '.join(targets)} from {cfg.worker.state_db}"
        print(msg)
        if not args.yes:
            try:
                resp = input("Proceed? [y/N] ").strip().lower()
            except EOFError:
                resp = ""
            if resp not in ("y", "yes"):
                print("Aborted.")
                return 1
        db = StateDB(cfg.worker.state_db)
        result: dict = {}
        if do_cache:
            result["cache_rows_deleted"] = db.clear_cache()
        if do_all_wm:
            result["watermark_rows_deleted"] = db.clear_watermark()
        else:
            if do_session_wm:
                # Key matches sessions._SESSION_WATERMARK_KEY — duplicated
                # rather than imported to avoid pulling in the LLM-dep
                # sessions module just for a string constant.
                result["session_watermark_deleted"] = db.clear_watermark(
                    "session_last_processed_at"
                )
            if do_ip_wm:
                result["ip_watermark_deleted"] = db.clear_watermark(
                    "ip_rollup_last_processed_at"
                )
        db.close()
        print(json.dumps(result, indent=2))
        return 0

    if args.verb == "purge":
        if args.subject != "lifecycles":
            print(f"Unknown purge subject: {args.subject!r}")
            return 1
        cowrie = cfg.elasticsearch.indexes.cowrie
        f_idx = cfg.findings.indexes
        targets = [
            f_idx.playbook_lifecycle,
            f_idx.campaign_lifecycle,
            f_idx.source_ip_lifecycle,
            f_idx.default,
            cowrie.campaigns,
            cowrie.playbook_anchors,
        ]
        print("About to wipe and recreate:")
        for t in targets:
            print(f"  - {t}")
        print(
            "\nWARNING: the playbook_anchor index will be wiped. Historical "
            "playbook ids (spb-<hex>) cannot be recovered; the next "
            "`name playbooks` pass will mint fresh anchors and the new "
            "ids will not match the pre-purge ids unless cluster membership "
            "is identical."
        )
        if not args.yes:
            try:
                resp = input("Proceed? [y/N] ").strip().lower()
            except EOFError:
                resp = ""
            if resp not in ("y", "yes"):
                print("Aborted.")
                return 1
        stats = _purge_lifecycles(cfg, secrets)
        print(json.dumps(stats, indent=2, default=str))
        return 0 if not stats.get("errors") else 1

    if args.verb == "bootstrap-es":
        from .bootstrap import run_bootstrap
        stats = run_bootstrap(cfg, secrets, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, default=str))
        return 0 if not stats.get("errors") else 1

    if args.verb == "reference-heal":
        print(json.dumps(_run_reference_heal(cfg, secrets), indent=2, default=str))
        return 0

    if args.verb == "init-indexes":
        from .es_client import init_index, make_client, update_mapping
        es = make_client(cfg.elasticsearch, secrets)
        mappings = _LAYER_MAPPINGS.get(args.source)
        if mappings is None:
            log.error("Unknown source: %s", args.source)
            return 1
        layers = [args.layer] if args.layer else list(mappings.keys())
        unknown = [l for l in layers if l not in mappings]
        if unknown:
            log.error("Unknown layer(s) for source %s: %s", args.source, unknown)
            return 1
        results: list[dict] = []
        for layer in layers:
            mapping_path = mappings[layer]
            idx = _resolve_index_for_layer(cfg, args.source, layer)
            r = init_index(es, mapping_path, idx)
            if args.update_mapping and r.get("action") == "noop":
                r = update_mapping(es, mapping_path, idx)
            r["layer"] = layer
            results.append(r)
        print(json.dumps(results, indent=2))
        return 0

    if args.verb == "enrich":
        mod = _commands_layer(args.source)
        if mod is None:
            log.error("Source %r has no commands layer", args.source)
            return 1
        if getattr(args, "ignore_config_hash", False):
            cfg.worker.cache_auto_invalidate = False
        stats = mod.run_enrich(
            cfg, secrets,
            dry_run=args.dry_run, no_cloud=args.no_cloud,
            reference_mode=getattr(args, "reference", False),
            budget=getattr(args, "budget", None),
        )
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "escalate":
        mod = _commands_layer(args.source)
        if mod is None:
            log.error("Source %r has no commands layer", args.source)
            return 1
        try:
            stats = mod.run_escalate(cfg, secrets, dry_run=args.dry_run)
        except RuntimeError as exc:
            log.error("%s", exc)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "reembed":
        mod = _commands_layer(args.source)
        if mod is None:
            log.error("Source %r has no commands layer", args.source)
            return 1
        if getattr(args, "ignore_config_hash", False):
            cfg.worker.cache_auto_invalidate = False
        stats = mod.run_reembed(cfg, secrets, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "re-enrich-stale":
        mod = _commands_layer(args.source)
        if mod is None:
            log.error("Source %r has no commands layer", args.source)
            return 1
        stats = mod.run_reenrich_stale(cfg, secrets, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "backfill-shape":
        mod = _commands_layer(args.source)
        if mod is None:
            log.error("Source %r has no commands layer", args.source)
            return 1
        stats = mod.run_backfill_shape(cfg, secrets, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "prune-clusters":
        from .es_client import make_client
        from .clustering import prune_cluster_runs
        targets = _cluster_indices_for_source(cfg, args.source)
        if targets is None:
            log.error("Source %r has no cluster indices", args.source)
            return 1
        es = make_client(cfg.elasticsearch, secrets)
        out: dict = {
            "source": args.source, "keep_runs": args.keep_runs,
            "dry_run": args.dry_run, "indices": [],
        }
        for label, idx in targets:
            out["indices"].append(prune_cluster_runs(
                es, idx, keep_runs=args.keep_runs,
                dry_run=args.dry_run, layer_label=label,
            ))
        print(json.dumps(out, indent=2, default=str))
        return 0

    if args.verb == "apply-artifact-rules":
        # Source-agnostic — the rule index is cross-source, but today the
        # only commands layer is cowrie. The scanner module hardcodes that
        # path; revisit when a second source ships.
        from .analyst.scan import run_apply_artifact_rules
        stats = run_apply_artifact_rules(
            cfg, secrets,
            rule_ids=list(args.rule_id or []) or None,
            dry_run=args.dry_run,
        )
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "re-triage":
        if not args.backward:
            log.error(
                "re-triage requires --backward. Forward mode isn't "
                "implemented yet; --backward signals 'rewrite triage_reasons "
                "on every already-enriched doc using current rules.'"
            )
            return 1
        mod = _commands_layer(args.source)
        if mod is None:
            log.error("Source %r has no commands layer", args.source)
            return 1
        stats = mod.run_retriage(
            cfg, secrets,
            dry_run=args.dry_run,
            window_days=args.window_days,
        )
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "bless-cache":
        from .cache import StateDB
        from .config import compute_embed_config_hash, compute_llm_config_hash
        db = StateDB(cfg.worker.state_db)
        try:
            legacy = db.legacy_cache_row_count()
            llm_hash = compute_llm_config_hash(cfg)
            embed_hash = compute_embed_config_hash(cfg)
            if args.dry_run:
                print(json.dumps({
                    "dry_run": True,
                    "legacy_rows": legacy,
                    "would_stamp_llm_hash": llm_hash,
                    "would_stamp_embed_hash": embed_hash,
                }, indent=2))
            else:
                stamped = db.bless_legacy_cache_rows(llm_hash, embed_hash)
                print(json.dumps({
                    "stamped_rows": stamped,
                    "llm_config_hash": llm_hash,
                    "embed_config_hash": embed_hash,
                }, indent=2))
        finally:
            db.close()
        return 0

    if args.verb == "cluster":
        # `cluster all` runs each per-layer clusterer in production order
        # (commands → sessions → ips) with the same flags. Per-layer
        # verbs are still available and behave identically; this is a
        # convenience wrapper for backward-cycle runs.
        bootstrap_from = getattr(args, "bootstrap_from", None)
        if bootstrap_from and args.layer != "sessions":
            log.error(
                "--bootstrap-from is sessions-layer only "
                "(got layer=%r). Brutal-review phase 5.4.", args.layer,
            )
            return 1
        layers = ("commands", "sessions", "ips") if args.layer == "all" else (args.layer,)
        all_stats: dict[str, object] = {}
        for layer in layers:
            mod = _load_source_layer(args.source, layer)
            if mod is None:
                log.error("Source %r has no %r layer", args.source, layer)
                return 1
            # B0.5 — IP-layer re-cluster cadence gate. When the operator has
            # moved the full IP fit onto the weekly recluster-full timer, the
            # 6-hourly backward `cluster ips` runs the cheap incremental assign
            # (Option B) instead of the full O(n^2) HDBSCAN: new IPs land on the
            # nearest existing centroid, existing IPs keep their weekly id (via
            # the forward rollup's _preserve_ip_cluster), and the weekly pass —
            # forced with `--window-days 0` — does the real fit + reference
            # refresh.
            if layer == "ips" and _ip_full_recluster_skipped(cfg, args.window_days):
                log.info(
                    "[cluster ips] ip.full_recluster_weekly=true and not the "
                    "forced full pass: running incremental nearest-centroid "
                    "assign instead of the full HDBSCAN (backlog B0.5 Option B)."
                )
                all_stats[layer] = mod.run_assign(cfg, secrets, dry_run=args.dry_run)
                continue
            try:
                kwargs = dict(
                    dry_run=args.dry_run,
                    refresh_reference=args.refresh_reference,
                    use_reference=not args.no_reference,
                )
                if bootstrap_from and layer == "sessions":
                    kwargs["bootstrap_from"] = bootstrap_from
                if layer == "sessions":
                    # P1.3 — only the session layer has the O(N^2) late-fusion path.
                    kwargs["accept_fallback"] = args.accept_fallback
                    # P1.2 — windowed session clustering (None = use config default).
                    kwargs["window_days"] = args.window_days
                    # I4d — novel-pool-only clustering (Option A cutover).
                    kwargs["novel_pool_only"] = getattr(args, "novel_pool", False)
                stats = mod.run_cluster(cfg, secrets, **kwargs)
            except (ImportError, RuntimeError) as exc:
                log.error("cluster %s: %s", layer, exc)
                return 1
            all_stats[layer] = stats
        if args.layer == "all":
            print(json.dumps(all_stats, indent=2, default=str))
        else:
            # Preserve the old one-layer output shape (un-wrapped) so
            # downstream tools that parse stdout don't break.
            print(json.dumps(all_stats[args.layer], indent=2, default=str))
        return 0

    if args.verb == "rollup":
        mod = _load_source_layer(args.source, args.layer)
        if mod is None:
            log.error("Source %r has no %r layer", args.source, args.layer)
            return 1
        try:
            stats = mod.run_rollup(cfg, secrets, dry_run=args.dry_run)
        except RuntimeError as exc:
            log.error("%s", exc)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "name":
        if args.subject == "playbooks":
            mod = _load_source_layer(args.source, "sessions")
            if mod is None:
                log.error("Source %r has no `sessions` layer", args.source)
                return 1
            try:
                stats = mod.run_name_playbooks(
                    cfg, secrets, dry_run=args.dry_run, force=args.force,
                )
            except RuntimeError as exc:
                log.error("%s", exc)
                return 1
            print(json.dumps(stats, indent=2, default=str))
            return 0
        if args.subject == "ip-clusters":
            mod = _load_source_layer(args.source, "ips")
            if mod is None:
                log.error("Source %r has no `ips` layer", args.source)
                return 1
            try:
                stats = mod.run_name_ip_clusters(cfg, secrets, dry_run=args.dry_run)
            except RuntimeError as exc:
                log.error("%s", exc)
                return 1
            print(json.dumps(stats, indent=2, default=str))
            return 0
        log.error("Unknown `name` subject: %r", args.subject)
        return 1

    if args.verb == "mine":
        if args.subject == "findings":
            # Cross-source: reads IP rollup + intel-{ip,url}, writes findings-*.
            from .findings.miner import run_mine as run_mine_findings
            stats = run_mine_findings(cfg, secrets, dry_run=args.dry_run)
            print(json.dumps(stats, indent=2, default=str))
            return 0
        if args.subject == "operations":
            # Brutal-review phase 7.1.
            from .findings.operations import run_mine_operations
            stats = run_mine_operations(cfg, secrets, dry_run=args.dry_run)
            print(json.dumps(stats, indent=2, default=str))
            return 0 if stats.get("bulk_errors", 0) == 0 else 1
        if args.subject == "file-crossref":
            # Brutal-review phase 7.6.
            from .sources.cowrie.file_crossref import run_mine_file_crossref
            stats = run_mine_file_crossref(cfg, secrets, dry_run=args.dry_run)
            print(json.dumps(stats, indent=2, default=str))
            return 0
        if args.subject == "hunts":
            # Hypothesis-driven hunts (brutal-review phase 6.1). Reads
            # YAML from cfg.findings.hunts.config_dir, executes each
            # against the session rollup, writes one
            # `kind=analyst_hunt` finding per matching session.
            from .findings.hunts import run_hunts
            from .findings.writer import bulk_upsert_findings
            from .es_client import init_index, make_client
            import uuid as _uuid
            es = make_client(cfg.elasticsearch, secrets)
            findings_idx = cfg.findings.indexes.default
            init_index(es, "setup/es-mappings/findings/default.json", findings_idx)
            run_id = str(_uuid.uuid4())
            result = run_hunts(es, cfg, run_id)
            written = 0
            if not args.dry_run:
                for hunt_id, findings in (result.get("by_hunt") or {}).items():
                    if findings:
                        written += bulk_upsert_findings(es, findings_idx, findings)
            # Build a per-hunt summary for the console.
            per_hunt = {
                hid: {"matched": len(rows), "wrote": (0 if args.dry_run else len(rows))}
                for hid, rows in (result.get("by_hunt") or {}).items()
            }
            print(json.dumps({
                "run_id":    run_id,
                "dry_run":   args.dry_run,
                "loaded":    result.get("loaded", 0),
                "by_hunt":   per_hunt,
                "total_written": written,
                "errors":    result.get("errors", []),
            }, indent=2, default=str))
            return 0 if not result.get("errors") else 1
        mod = _load_source_layer(args.source, "campaigns")
        if mod is None:
            log.error("Source %r has no `campaigns` miner", args.source)
            return 1
        try:
            stats = mod.run_mine(
                cfg, secrets,
                kind=args.kind, dry_run=args.dry_run,
                window_days=args.window_days,
            )
        except RuntimeError as exc:
            log.error("%s", exc)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "track":
        if args.subject == "lifecycles":
            from .findings.lifecycle import run_track_lifecycles
            stats = run_track_lifecycles(cfg, secrets, dry_run=args.dry_run)
            print(json.dumps(stats, indent=2, default=str))
            return 0
        if args.subject == "threshold-distributions":
            from .es_client import make_client
            from .findings.metrics import (
                compute_threshold_distributions,
                write_threshold_distributions,
            )
            es = make_client(cfg.elasticsearch, secrets)
            if args.dry_run:
                docs = compute_threshold_distributions(es, cfg)
                stats = {
                    "dry_run": True,
                    "computed": len(docs),
                    "kinds":    [d["kind"] for d in docs],
                    # Pull p50/p99/n out of each doc as a sanity check on the
                    # distribution shape without writing anything.
                    "summary": [
                        {"kind": d["kind"], "p50": d["p50"],
                         "p99": d["p99"], "n": d["n"]}
                        for d in docs
                    ],
                }
            else:
                stats = write_threshold_distributions(es, cfg)
            print(json.dumps(stats, indent=2, default=str))
            return 0
        log.error("Unknown `track` subject: %r", args.subject)
        return 1

    if args.verb == "intel":
        from .intel.refresh import run_backfill, run_refresh
        if args.subject == "refresh":
            stats = run_refresh(cfg, secrets, dry_run=args.dry_run, force=args.force)
        elif args.subject == "backfill":
            stats = run_backfill(cfg, secrets, dry_run=args.dry_run)
        elif args.subject == "reapply-rules":
            from .intel.migrate import run_reapply_rules
            stats = run_reapply_rules(cfg, secrets, dry_run=args.dry_run)
        else:
            log.error("Unknown `intel` subject: %r", args.subject)
            return 1
        print(json.dumps(stats, indent=2, default=str))
        return 0

    if args.verb == "pipeline":
        return _run_pipeline(cfg, secrets, args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
