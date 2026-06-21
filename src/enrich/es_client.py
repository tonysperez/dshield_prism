"""Elasticsearch client + queries + bulk writer."""
from __future__ import annotations

import functools
import json
import logging
from pathlib import Path
from typing import Any, Optional

from elasticsearch import Elasticsearch, helpers

from .config import ESConfig, Secrets
from .es_health import run_resilient

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Backpressure-aware client wrapper
# ---------------------------------------------------------------------------
# Every ES read/write in the pipeline goes through the client `make_client`
# returns. Wrapping that one object routes *all* requests — direct `es.*`
# calls, namespaced calls (`es.indices.*`), and the `elasticsearch.helpers`
# bulk/scan loops (which call methods on whatever client they're handed) —
# through `run_resilient`: on a 429/circuit-breaker rejection, wait for heap to
# drain then retry. No per-call-site changes, full coverage on small nodes.
#
# Happy path adds only a try/except per call; the heap probe inside
# `run_resilient` fires only after an overload error, never on every request.


def _is_namespace(attr: Any) -> bool:
    """True for an elasticsearch-py namespace client (`IndicesClient`,
    `NodesClient`, …) — non-callable objects whose type name ends in `Client`.
    The root `Elasticsearch` / `Transport` don't match, so they pass through."""
    return (not callable(attr)) and type(attr).__name__.endswith("Client")


def _wrap_call(method: Any, label: str, root: Any, bp: Any) -> Any:
    """Wrap a bound ES API method so each invocation retries on overload."""
    @functools.wraps(method)
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        return run_resilient(lambda: method(*args, **kwargs), root, bp, label=label)
    return _wrapped


class _ResilientNamespace:
    """Proxy for a namespace client (`es.indices`, `es.cluster`, …). Wraps its
    API methods in `run_resilient`, probing pressure via the root client."""

    __slots__ = ("_ns", "_bp", "_root")

    def __init__(self, ns: Any, bp: Any, root: Any) -> None:
        object.__setattr__(self, "_ns", ns)
        object.__setattr__(self, "_bp", bp)
        object.__setattr__(self, "_root", root)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._ns, name)
        if _is_namespace(attr):
            return _ResilientNamespace(attr, self._bp, self._root)
        if callable(attr):
            return _wrap_call(attr, name, self._root, self._bp)
        return attr


class ResilientClient:
    """Transparent proxy over an `Elasticsearch` client that routes every API
    call through `run_resilient` (heap/circuit-breaker backpressure).

    `._raw` exposes the unwrapped client (used to probe breaker stats without
    recursive retry); `._bp` is the backpressure config."""

    __slots__ = ("_raw", "_bp")

    def __init__(self, raw: Elasticsearch, bp: Any) -> None:
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_bp", bp)

    def __setattr__(self, name: str, value: Any) -> None:
        # `elasticsearch.helpers` mutates the client it's handed (e.g.
        # `client._client_meta = ...`). Forward such sets to the underlying
        # client so the helper's behaviour — and the meta header — are preserved.
        if name in ("_raw", "_bp"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._raw, name, value)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._raw, name)
        # `options()` returns a *new* client — re-wrap it so helpers that do
        # `client.options(...).bulk(...)` stay covered end to end.
        if name == "options":
            bp = self._bp
            def _options(*args: Any, **kwargs: Any) -> "ResilientClient":
                return ResilientClient(attr(*args, **kwargs), bp)
            return _options
        if _is_namespace(attr):
            return _ResilientNamespace(attr, self._bp, self)
        if callable(attr):
            return _wrap_call(attr, name, self, self._bp)
        return attr


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
    raw = Elasticsearch(**kwargs)
    bp = getattr(cfg, "backpressure", None)
    # Wrap so every read/write inherits heap/circuit-breaker backpressure.
    # `helpers.bulk`/`helpers.scan` operate on this client, so their per-chunk
    # `.bulk()`/`.search()`/`.scroll()` calls are covered too. When disabled,
    # the wrapper still forwards transparently (run_resilient is a no-op).
    return ResilientClient(raw, bp)


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
