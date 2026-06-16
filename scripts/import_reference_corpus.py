"""Atomic Red Team -> reference-corpus session ingest (brutal-review phase 5.2).

Walks `atomics/T<technique>/T<technique>.yaml` in a checkout of Red
Canary's Atomic Red Team repo. For each test that targets Linux with
sh/bash, resolves `#{var}` placeholders against `input_arguments`
defaults, splits the multi-line `executor.command` block, and emits a
single rollup-shaped doc into `prism.reference.cowrie.session`.

See docs/architecture.md for the schema mapping and why this
particular corpus.

Usage:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/import_reference_corpus.py \\
        [--repo-dir /path/to/atomic-red-team] \\
        [--max-sessions N] \\
        [--dry-run] \\
        [--config config/default.yaml]

If `--repo-dir` is not supplied the script clones
https://github.com/redcanaryco/atomic-red-team into a temp directory
for the run and removes it on exit. `--max-sessions` caps the import
for verification / smoke runs; omit for a full pass.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml  # PyYAML — already in the deps for cowrie config parsing.

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from enrich.config import load_config, load_secrets  # noqa: E402
from enrich.es_client import init_index, make_client  # noqa: E402
from enrich.sources.cowrie.commands import (  # noqa: E402
    hash_command, normalize,
)

log = logging.getLogger("import_reference_corpus")

_REPO_URL = "https://github.com/redcanaryco/atomic-red-team.git"
_MAPPING_PATH = "setup/es-mappings/cowrie/reference_session.json"
_SOURCE_LABEL = "atomic-red-team"

# Per the schema mapping in docs/architecture.md.
_LINUX_PLATFORMS = frozenset({"linux"})
_SHELL_EXECUTORS = frozenset({"sh", "bash"})

# `#{var_name}` style placeholders. The default-resolver only touches
# the simple `#{ident}` form; tests that use complex nested expansions
# get skipped (logged at debug).
_PLACEHOLDER_RE = re.compile(r"#\{([A-Za-z0-9_]+)\}")


def _clone_atomic_red_team(target: Path) -> None:
    """Shallow-clone the upstream Atomic Red Team repo into `target`."""
    log.info("cloning %s into %s", _REPO_URL, target)
    subprocess.run(
        ["git", "clone", "--depth", "1", _REPO_URL, str(target)],
        check=True,
    )


def _git_head_sha(repo_dir: Path) -> str:
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True, capture_output=True, cwd=repo_dir, text=True,
    )
    return out.stdout.strip()


def _iter_atomic_yamls(repo_dir: Path) -> Iterable[Path]:
    atomics = repo_dir / "atomics"
    if not atomics.is_dir():
        raise FileNotFoundError(
            f"{atomics} not found — is {repo_dir} a valid Atomic Red Team checkout?"
        )
    # T<id>/T<id>.yaml. Sort for deterministic import order.
    return sorted(atomics.glob("T*/T*.yaml"))


def _resolve_placeholders(
    command_block: str, input_args: dict[str, Any],
) -> Optional[str]:
    """Replace `#{var}` with `input_arguments.<var>.default`. Returns
    None when any placeholder has no default — those tests aren't
    runnable without operator-supplied args and don't belong in a
    reference corpus."""
    defaults: dict[str, str] = {}
    for var, spec in (input_args or {}).items():
        if not isinstance(spec, dict):
            continue
        d = spec.get("default")
        if d is None:
            continue
        # Defaults can themselves embed placeholders ("PathToAtomicsFolder"
        # is the canonical one). Atomic Red Team uses a runtime resolver
        # for these; for the static corpus we substitute a literal token
        # that downstream embedding/clustering treats as just text.
        defaults[var] = str(d)
    out_parts: list[str] = []
    pos = 0
    for m in _PLACEHOLDER_RE.finditer(command_block):
        var = m.group(1)
        if var not in defaults:
            return None
        out_parts.append(command_block[pos:m.start()])
        out_parts.append(defaults[var])
        pos = m.end()
    out_parts.append(command_block[pos:])
    return "".join(out_parts)


def _split_commands(block: str) -> list[str]:
    """Split multi-line `executor.command` into per-line commands.
    Drops blank lines and `#`-prefixed comments. Lines with embedded
    sub-shells / multi-statement chains are kept as one logical command
    (consistent with how cowrie observes a single shell input)."""
    lines: list[str] = []
    for raw in block.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines


def _build_session_doc(
    *, atomic_id: str, test: dict, commit_sha: str,
    imported_at: str, max_chars: int,
) -> Optional[dict]:
    """Build one reference-corpus session doc from one atomic test.
    Returns None when the test isn't eligible (wrong platform,
    non-shell executor, unresolved placeholders, no resolvable
    commands)."""
    platforms = set(test.get("supported_platforms") or [])
    if not (platforms & _LINUX_PLATFORMS):
        return None
    executor = (test.get("executor") or {})
    name = executor.get("name") or ""
    if name not in _SHELL_EXECUTORS:
        return None
    raw_block = executor.get("command") or ""
    if not raw_block.strip():
        return None
    resolved = _resolve_placeholders(raw_block, test.get("input_arguments") or {})
    if resolved is None:
        return None
    command_lines = _split_commands(resolved)
    if not command_lines:
        return None
    guid = test.get("auto_generated_guid") or ""
    if not guid:
        # Without a stable GUID we'd reindex the same test as a new
        # doc on every rebuild — the corpus would never converge.
        return None
    # Compute the rollup-shaped derived fields. The clusterer + writer
    # don't run on this index at import time; we precompute what we
    # can so downstream code doesn't need a separate "reference rollup"
    # step.
    norm_lines: list[str] = []
    hashes: list[str] = []
    unique_hashes: set[str] = set()
    for cmd in command_lines:
        n, _ = normalize(cmd, max_chars)
        if not n:
            continue
        norm_lines.append(n)
        h = hash_command(n)
        hashes.append(h)
        unique_hashes.add(h)
    if not hashes:
        return None
    return {
        "_id": guid,
        "@timestamp": imported_at,
        "event": {
            "kind":     "event",
            "category": "intrusion_detection",
            "dataset":  "dshield.reference.cowrie.session",
        },
        "cowrie": {"session_id": guid},
        "dshield": {
            "reference": {
                "atomic_id":        atomic_id,
                "atomic_test_name": test.get("name") or "",
                "atomic_guid":      guid,
                "executor":         name,
                "platforms":        sorted(platforms),
                "source":           _SOURCE_LABEL,
                "commit_sha":       commit_sha,
                "imported_at":      imported_at,
                "command_lines":    norm_lines,
            },
            "cowrie": {"enrichment": {"session": {
                "command_count":   len(hashes),
                "unique_commands": len(unique_hashes),
                "command_set":     sorted(unique_hashes),
            }}},
        },
    }


def _iter_test_docs(
    repo_dir: Path, commit_sha: str, imported_at: str, *,
    max_sessions: Optional[int], max_chars: int,
) -> Iterable[dict]:
    """Yield session docs from every eligible atomic test. Caps the
    yield count when `max_sessions` is set (verification path)."""
    yielded = 0
    for yaml_path in _iter_atomic_yamls(repo_dir):
        atomic_id = yaml_path.parent.name  # e.g. "T1059.004"
        try:
            with yaml_path.open(encoding="utf-8") as fh:
                manifest = yaml.safe_load(fh) or {}
        except Exception as exc:
            log.warning("yaml parse failed for %s: %s", yaml_path, exc)
            continue
        tests = manifest.get("atomic_tests") or []
        for test in tests:
            doc = _build_session_doc(
                atomic_id=atomic_id, test=test, commit_sha=commit_sha,
                imported_at=imported_at, max_chars=max_chars,
            )
            if doc is None:
                continue
            yield doc
            yielded += 1
            if max_sessions is not None and yielded >= max_sessions:
                return


def _bulk_index(es, idx: str, docs: list[dict]) -> tuple[int, int]:
    """Bulk-index `docs` into `idx`. Returns (indexed, errored)."""
    from elasticsearch.helpers import bulk
    actions = [{"_op_type": "index", "_index": idx,
                "_id": d.pop("_id"), "_source": d} for d in docs]
    if not actions:
        return 0, 0
    n_ok, errors = bulk(es, actions, raise_on_error=False, stats_only=False)
    return n_ok, len(errors) if isinstance(errors, list) else 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--repo-dir", default=None,
                        help="Existing Atomic Red Team checkout; shallow-clone "
                             "to a tempdir when omitted")
    parser.add_argument("--max-sessions", type=int, default=None,
                        help="Cap the number of imported sessions (verification)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Build the docs but don't write to ES")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    cfg = load_config(args.config)
    secrets = load_secrets()

    # Resolve checkout. Self-cleaning tempdir when --repo-dir wasn't given.
    cleanup: Optional[Path] = None
    if args.repo_dir:
        repo_dir = Path(args.repo_dir)
        if not repo_dir.is_dir():
            log.error("--repo-dir %s does not exist", repo_dir)
            return 1
    else:
        cleanup = Path(tempfile.mkdtemp(prefix="art-import-"))
        repo_dir = cleanup
        _clone_atomic_red_team(repo_dir)

    try:
        commit_sha = _git_head_sha(repo_dir)
        imported_at = datetime.now(timezone.utc).isoformat()
        log.info("commit %s; imported_at %s", commit_sha, imported_at)

        docs = list(_iter_test_docs(
            repo_dir, commit_sha, imported_at,
            max_sessions=args.max_sessions,
            max_chars=cfg.worker.command_max_chars,
        ))
        log.info("built %d eligible session docs", len(docs))

        if not docs:
            log.warning("no eligible tests found; nothing to import")
            return 1

        executor_counts: Counter[str] = Counter()
        platform_counts: Counter[str] = Counter()
        cmd_counts: list[int] = []
        for d in docs:
            r = d["dshield"]["reference"]
            executor_counts[r["executor"]] += 1
            for p in r["platforms"]:
                platform_counts[p] += 1
            cmd_counts.append(d["dshield"]["cowrie"]["enrichment"]["session"]["command_count"])
        log.info("by executor:   %s", dict(executor_counts))
        log.info("by platform:   %s", dict(platform_counts))
        log.info("commands/test: min=%d p50=%d max=%d total=%d",
                 min(cmd_counts), sorted(cmd_counts)[len(cmd_counts)//2],
                 max(cmd_counts), sum(cmd_counts))

        if args.dry_run:
            log.info("dry-run: skipping ES writes")
            print(json.dumps({"built": len(docs), "indexed": 0, "errored": 0,
                              "dry_run": True, "commit_sha": commit_sha}))
            return 0

        es = make_client(cfg.elasticsearch, secrets)
        idx = cfg.elasticsearch.indexes.cowrie.reference_sessions
        init_index(es, _MAPPING_PATH, idx)
        n_ok, n_err = _bulk_index(es, idx, docs)
        es.indices.refresh(index=idx)
        log.info("indexed %d into %s (errors=%d)", n_ok, idx, n_err)
        print(json.dumps({"built": len(docs), "indexed": n_ok,
                          "errored": n_err, "index": idx,
                          "commit_sha": commit_sha}))
        return 0 if n_err == 0 else 1
    finally:
        if cleanup and cleanup.exists():
            shutil.rmtree(cleanup, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
