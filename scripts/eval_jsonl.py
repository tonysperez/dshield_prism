"""Shared opener for the eval session JSONL, which is committed gzipped.

``eval/sessions.unlabeled.jsonl.gz`` is the committed artifact. The plain
``.jsonl`` spelling is ~23x larger (186 MB) and exceeded GitHub's 100 MB
blob ceiling, so the set is stored gzipped alongside its siblings
(``production-snapshot-v1.jsonl.gz``, ``command-snapshot-v1.jsonl.gz``).

Callers keep using whichever spelling reads best at the call site:
``resolve`` maps a plain ``.jsonl`` path onto its ``.gz`` sibling when the
plain file is absent, so an explicit ``--unlabeled eval/sessions.unlabeled.jsonl``
still works against the committed artifact. ``iter_jsonl`` streams rather
than materialising the whole file, which the previous
``read_text().splitlines()`` callers did not.
"""
from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any


def resolve(path: Path | str) -> Path:
    """The path that actually exists, preferring an exact match.

    A plain ``.jsonl`` request falls back to ``<path>.gz``; a ``.gz`` request
    falls back to the un-suffixed plain file. Neither present: return the
    requested path unchanged so the caller raises its own ``FileNotFoundError``
    naming what it asked for.
    """
    path = Path(path)
    if path.exists():
        return path
    if path.suffix == ".gz":
        plain = path.with_suffix("")
        return plain if plain.exists() else path
    gz = path.with_suffix(path.suffix + ".gz")
    return gz if gz.exists() else path


def open_jsonl(path: Path | str, mode: str = "rt") -> IO[Any]:
    """Open a JSONL path, transparently gzipped when it ends in ``.gz``.

    Read modes resolve the plain/``.gz`` spelling first; write modes never
    resolve, so a caller asking to write ``.jsonl.gz`` always gets gzip.
    """
    path = resolve(path) if "r" in mode else Path(path)
    if str(path).endswith(".gz"):
        return gzip.open(path, mode, encoding="utf-8")
    return open(path, mode, encoding="utf-8")


def iter_jsonl(path: Path | str) -> Iterator[dict]:
    """Stream decoded records, skipping blank lines."""
    with open_jsonl(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def exists(path: Path | str) -> bool:
    """True when either spelling of ``path`` is present on disk."""
    return resolve(path).exists()
