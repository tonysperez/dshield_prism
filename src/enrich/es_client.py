"""Elasticsearch client + queries + bulk writer."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from elasticsearch import Elasticsearch, helpers

from .config import ESConfig, Secrets

log = logging.getLogger(__name__)


def _load_mapping(mapping_path: str) -> dict:
    """Load mapping JSON, stripping comment-style top-level keys (e.g. _comment)."""
    raw = json.loads(Path(mapping_path).read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def init_index(es: Elasticsearch, mapping_path: str, index_name: str) -> dict:
    """Create the enrichment index with explicit settings + mappings.

    Idempotent: if the index already exists, leaves it alone (no mapping diff).
    To change mappings on an existing index, use update_mapping() or recreate.
    """
    if es.indices.exists(index=index_name):
        return {"index_exists": index_name, "action": "noop"}
    es.indices.create(index=index_name, **_load_mapping(mapping_path))
    return {"index_created": index_name, "action": "created"}


def update_mapping(es: Elasticsearch, mapping_path: str, index_name: str) -> dict:
    """Apply additive mapping changes (new fields only).

    ES does NOT allow modifying existing field types. For destructive changes,
    delete + recreate the index manually.
    """
    mappings = _load_mapping(mapping_path).get("mappings", {})
    if not mappings:
        return {"action": "noop", "reason": "no mappings in file"}
    es.indices.put_mapping(index=index_name, **mappings)
    return {"action": "mapping_updated", "index": index_name}


def make_client(cfg: ESConfig, secrets: Secrets) -> Elasticsearch:
    # Suppress the chatter from urllib3 + the elasticsearch client when the
    # user has explicitly opted into unverified TLS via `verify_certs:
    # false`. The user already made the trade-off in the config file; the
    # per-request urllib3 warning + the one-shot elasticsearch SecurityWarning
    # are unhelpful noise in interactive CLI output. Only silenced when
    # verification is *explicitly* disabled — verified-cert deployments
    # still see whatever warnings their stack chooses to emit.
    if not cfg.verify_certs:
        import warnings
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        # `elasticsearch.SecurityWarning` exists in the modern elasticsearch
        # client; older versions used the generic UserWarning. Filter both
        # ways defensively.
        try:
            from elasticsearch import SecurityWarning as _ESSecurityWarning
            warnings.filterwarnings("ignore", category=_ESSecurityWarning)
        except Exception:
            pass
        warnings.filterwarnings("ignore", message=r".*verify_certs=False.*")
    kwargs: dict = {
        "hosts": cfg.hosts,
        "verify_certs": cfg.verify_certs,
        "request_timeout": cfg.request_timeout,
    }
    if cfg.ca_certs:
        kwargs["ca_certs"] = cfg.ca_certs
    if secrets.es_api_key:
        kwargs["api_key"] = secrets.es_api_key
    elif secrets.es_username and secrets.es_password:
        kwargs["basic_auth"] = (secrets.es_username, secrets.es_password)
    else:
        raise RuntimeError(
            "No ES credentials. Set ES_USERNAME/ES_PASSWORD or ES_API_KEY in .env "
            "(or export them in the environment). The .env file is searched in this order: "
            "$PRISM_ENV, alongside-config-file's parent, alongside-config-file, CWD."
        )
    return Elasticsearch(**kwargs)


def bulk_write(es: Elasticsearch, index: str, actions: list[dict]) -> tuple[int, list]:
    """Run bulk; return (success_count, errors)."""
    if not actions:
        return 0, []
    success, errors = helpers.bulk(
        es,
        actions,
        index=index,
        raise_on_error=False,
        raise_on_exception=False,
        stats_only=False,
    )
    return success, errors


def deep_get(d: Optional[dict], dotted_path: str) -> Any:
    """Walk a dotted path through nested dicts; None if any hop is missing."""
    cur: Any = d
    for key in dotted_path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def fetch_source_subset(
    es: Elasticsearch,
    index: str,
    ids: list[str],
    source_paths: list[str],
    chunk_size: int = 1000,
) -> dict[str, dict]:
    """Return ``{doc_id: _source pruned to source_paths}`` for found docs only.

    A chunked ``mget`` with a ``_source`` filter. Use it for read-modify-write
    rollups that must preserve a cross-writer sub-block — e.g. cluster ids a
    later pipeline step stamps onto the rollup doc — across a full-document
    re-index. Tolerates a missing index (returns ``{}`` rather than raising).
    """
    if not ids:
        return {}
    if not es.indices.exists(index=index):
        return {}
    out: dict[str, dict] = {}
    for start in range(0, len(ids), chunk_size):
        chunk = ids[start:start + chunk_size]
        resp = es.mget(index=index, ids=chunk, _source=source_paths)
        for d in resp.get("docs", []):
            if d.get("found") and d.get("_source"):
                out[d["_id"]] = d["_source"]
    return out
