"""Vendored HASSH-to-tooling lookup (brutal-review 7.5).

Resolves an SSH client fingerprint (HASSH md5) to a curated `(family, tool)`
attribution. Pure read of `hassh_known.json` next to this module — loaded
once at import, fail-soft when the file is missing or malformed. The IP
rollup builder (`_build_ip_doc`) calls `lookup(dominant_hassh)` and stamps
the result onto each IP rollup doc; the console reads the stamped fields.

The map is empty by default; entries are operator-curated against the live
corpus's `hassh_cluster_id` aggregation (see the JSON file's `_README`).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

_DATA_PATH = Path(__file__).resolve().parent / "hassh_known.json"

try:
    _blob = json.loads(_DATA_PATH.read_text())
    _ENTRIES: dict[str, dict] = dict(_blob.get("entries") or {})
    VERSION: str = str(_blob.get("version") or "")
except (OSError, ValueError):
    # Fail-soft: missing/malformed file => empty map. No false-positive
    # attributions; the console silently hides the chip.
    _ENTRIES = {}
    VERSION = ""


def lookup(hassh: Optional[str]) -> Optional[dict]:
    """Return the curated entry for `hassh` (or None if unknown / not supplied).

    Entry shape: `{family, tool, confidence, source, notes}`. Callers should
    treat the dict as read-only.
    """
    if not hassh:
        return None
    return _ENTRIES.get(hassh)


def entry_count() -> int:
    """How many curated HASSH attributions are loaded."""
    return len(_ENTRIES)
