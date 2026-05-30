"""FastAPI server.

Exposes the JSON API used by the browser UI and serves the static frontend
from `web/`.

The app is read-only against Elasticsearch.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from ._config import load_config, load_secrets
from ._es import make_client
from . import findings as findings_mod, graph, intel as intel_mod, ioc, queries
# Imported as a renamed local to avoid shadowing the `health()` function
# below that's registered as the `/api/health` system-check route.
from . import health as health_mod
from .models import (
    GraphResponse, HealthResponse, IOCDetail, SearchCandidate,
    SearchResponse, TableResponse,
)

log = logging.getLogger(__name__)

WEB_DIR = Path(__file__).parent / "web"
TEMPLATES_DIR = Path(__file__).parent / "templates"

# Shared navigation. Order is the single source of truth; every page
# renders the same items in the same positions and the active page is
# marked with aria-current rather than dropped, so neighbouring links
# don't shift as the analyst tabs around.
NAV_ITEMS: list[dict[str, str]] = [
    {"id": "inbox",     "label": "Inbox",    "href": "/inbox"},
    {"id": "graph",     "label": "Graph",    "href": "/graph"},
    {"id": "browse",    "label": "Browse",   "href": "/browse"},
    {"id": "compare",   "label": "Compare",  "href": "/compare"},
    {"id": "rules",     "label": "Rules",    "href": "/artifact-rules"},
    {"id": "health",    "label": "Health",   "href": "/health"},
]


class AskRequest(BaseModel):
    question: str
    context: dict = {}


class DenylistAddRequest(BaseModel):
    """POST body for /api/health/commands/denylist (ROADMAP #11.5)."""
    token: str
    rationale: str = ""


class FindingStatusRequest(BaseModel):
    """POST body for /api/finding/{id}/status (M5)."""
    status: str
    note: str = ""


class ArtifactRuleRequest(BaseModel):
    """POST body for /api/artifact-rule (ROADMAP #5)."""
    kind: str
    match_type: str           # literal | substring | regex
    pattern: str
    case_sensitive: bool = False
    notes: str = ""


def build_app(config_path: str | None = None) -> FastAPI:
    cfg = load_config(config_path)
    secrets = load_secrets(config_path)
    es = make_client(cfg.elasticsearch, secrets)
    run_cache = queries.RunCache()

    app = FastAPI(title="DShield Console", version="0.1.0")

    # ------------------------------------------------------------------
    # Static frontend
    # ------------------------------------------------------------------
    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.globals["nav_items"] = NAV_ITEMS

    def _render(request: Request, name: str, *, active_nav: str,
                ctx: dict[str, Any] | None = None):
        page = TEMPLATES_DIR / name
        if not page.exists():
            raise HTTPException(500, f"templates/{name} missing")
        return templates.TemplateResponse(
            request, name,
            {"active_nav": active_nav, **(ctx or {})},
        )

    # `/` lands on the analyst inbox. `/findings` and `/insights` remain
    # as 302 redirects so bookmarks and deep links (with query strings)
    # continue to resolve after the rename.
    from fastapi.responses import RedirectResponse

    def _preserve_qs(request: Request, target: str) -> str:
        qs = request.url.query
        return f"{target}?{qs}" if qs else target

    @app.get("/")
    def root() -> RedirectResponse:
        return RedirectResponse(url="/inbox", status_code=302)

    @app.get("/inbox")
    def inbox_page(request: Request):
        return _render(request, "findings.html", active_nav="inbox")

    @app.get("/findings")
    def findings_page_redirect(request: Request) -> RedirectResponse:
        return RedirectResponse(_preserve_qs(request, "/inbox"), status_code=302)

    @app.get("/graph")
    def graph_page(request: Request):
        return _render(request, "index.html", active_nav="graph")

    @app.get("/browse")
    def browse_page(request: Request):
        return _render(request, "insights.html", active_nav="browse")

    @app.get("/insights")
    def insights_page_redirect(request: Request) -> RedirectResponse:
        return RedirectResponse(_preserve_qs(request, "/browse"), status_code=302)

    @app.get("/compare")
    def compare_page(request: Request):
        return _render(request, "compare.html", active_nav="compare")

    @app.get("/health")
    def health_page(request: Request):
        return _render(request, "health.html", active_nav="health")

    @app.get("/artifact/ip/{value}")
    def artifact_ip_page(request: Request, value: str):
        # Page is the same for every IP; the JS fetches the API.
        # Path-parametric so the URL itself encodes the artifact and
        # browser back/forward / linking work.
        return _render(request, "artifact_ip.html", active_nav="")

    @app.get("/artifact/url")
    def artifact_url_page(request: Request):
        # URL artifact pane (M4). The URL value rides as a `?value=`
        # query-string parameter rather than a path parameter — raw
        # URLs contain `://`, `/`, `?`, `#` which collide with path
        # semantics and get mangled by browser path normalisation.
        # The JS reads from `window.location.search`.
        return _render(request, "artifact_url.html", active_nav="")

    @app.get("/artifact/hash")
    def artifact_hash_page(request: Request):
        # File-hash artifact pane (#2). Hash rides as `?value=<sha>` for
        # consistency with the URL pane.
        return _render(request, "artifact_hash.html", active_nav="")

    @app.get("/artifact-rules")
    def artifact_rules_page(request: Request):
        # Analyst-authored artifact-rule management page (ROADMAP #5).
        return _render(request, "artifact_rules.html", active_nav="rules")

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------
    _insights_cache: dict[str, Any] = {"ts": 0.0, "data": None}
    _INSIGHTS_TTL = 60.0  # seconds — data changes slowly

    @app.get("/api/timeline")
    def timeline_api(
        kind:             str  = Query(...),
        id:               str  = Query(...),
        limit:            int  = Query(500, ge=1, le=2000),
        require_login:    bool = Query(False),
        require_commands: bool = Query(False),
    ) -> JSONResponse:
        if kind not in ("ip", "session_cluster", "playbook"):
            raise HTTPException(400, f"unknown timeline kind: {kind}")
        sf = _session_filter(require_login, require_commands)
        data = queries.timeline_sessions(es, cfg, kind=kind, id_=id, limit=limit, sf=sf)
        return JSONResponse(data)

    @app.get("/api/insights")
    def insights_api() -> JSONResponse:
        now = time.monotonic()
        if _insights_cache["data"] and now - _insights_cache["ts"] < _INSIGHTS_TTL:
            return JSONResponse(_insights_cache["data"])
        try:
            data = queries.insights_summary(es, cfg, run_cache)
            _insights_cache["ts"] = now
            _insights_cache["data"] = data
            return JSONResponse(data)
        except Exception as e:
            log.exception("insights_summary failed")
            raise HTTPException(500, f"insights query failed: {e}")

    # Health page — command-grounding coverage report (ROADMAP #11.5).
    # Same 60s in-memory cache pattern as /api/insights; the underlying
    # data changes only when curated YAMLs / the tldr bundle / the
    # corpus drift, none of which happen sub-minute.
    _health_cmds_cache: dict[str, Any] = {"ts": 0.0, "data": None}
    _HEALTH_CMDS_TTL = 60.0

    @app.get("/api/health/commands")
    def health_commands_api() -> JSONResponse:
        now = time.monotonic()
        if _health_cmds_cache["data"] and now - _health_cmds_cache["ts"] < _HEALTH_CMDS_TTL:
            return JSONResponse(_health_cmds_cache["data"])
        try:
            data = health_mod.health_commands(es, cfg)
            _health_cmds_cache["ts"] = now
            _health_cmds_cache["data"] = data
            return JSONResponse(data)
        except Exception as e:
            log.exception("health_commands failed")
            raise HTTPException(500, f"health_commands query failed: {e}")

    def _invalidate_health_cache() -> None:
        _health_cmds_cache["data"] = None
        _health_cmds_cache["ts"] = 0.0

    @app.post("/api/cache/purge")
    def purge_caches() -> JSONResponse:
        """Wipe every in-memory cache so the next request reads from ES.

        The console layers a few caches on top of ES for query throughput:
          - _insights_cache         (60 s TTL on the /api/insights payload)
          - _health_cmds_cache      (60 s TTL on /api/health/commands)
          - run_cache._cache        (5 min TTL on `latest run_id` per
                                     centroid index — RunCache in queries.py)

        After a fresh pipeline run, these caches can hold stale results
        until their TTLs expire. The settings modal exposes a button
        that POSTs here so operators don't have to restart the process.
        """
        cleared: list[str] = []
        _insights_cache["data"] = None
        _insights_cache["ts"] = 0.0
        cleared.append("insights")
        _invalidate_health_cache()
        cleared.append("health_commands")
        try:
            # RunCache holds {index: (ts, run_id)}; clearing forces the
            # next .latest() call to re-query ES.
            run_cache._cache.clear()
            cleared.append("run_cache")
        except Exception:                                # pragma: no cover
            pass
        return JSONResponse({"ok": True, "cleared": cleared})

    @app.post("/api/health/commands/denylist")
    def denylist_add_api(body: DenylistAddRequest) -> JSONResponse:
        ok, msg = health_mod.add_token_to_denylist(body.token, body.rationale)
        if not ok:
            raise HTTPException(400, msg)
        _invalidate_health_cache()
        return JSONResponse({"ok": True, "message": msg})

    @app.delete("/api/health/commands/denylist/{token}")
    def denylist_remove_api(token: str) -> JSONResponse:
        ok, msg = health_mod.remove_token_from_denylist(token)
        if not ok:
            # "not present" is a benign no-op for idempotent UI clicks;
            # truly malformed input would have been rejected earlier.
            raise HTTPException(404, msg)
        _invalidate_health_cache()
        return JSONResponse({"ok": True, "message": msg})

    # ------------------------------------------------------------------
    # Findings (M5) — list / filter / status mutation / calibration scatter
    # ------------------------------------------------------------------
    @app.get("/api/findings")
    def findings_list_api(
        status: str = Query("new", description="Comma-separated list of statuses, or 'all'"),
        kind: Optional[str] = Query(None, description="Single finding kind to filter on"),
        stream: Optional[str] = Query(None, description="drift | discovery | coverage"),
        # P1c facet rail — each accepts a single bucket key per dimension.
        score_band:    Optional[str] = Query(None, description="low | medium | high"),
        age_band:      Optional[str] = Query(None, description="today | week | older"),
        ip_band:       Optional[str] = Query(None, description="small | medium | large"),
        intent:        Optional[str] = Query(None, description="dominant_intent value"),
        intel_verdict: Optional[str] = Query(None, description="clean | malicious | mixed | no_data"),
        size: int = Query(50, ge=1, le=500),
        frm: int = Query(0, ge=0),
        sort: str = Query("score", description="score | last_seen | first_seen"),
    ) -> JSONResponse:
        status_list: Optional[list[str]]
        if status == "all":
            status_list = []
        else:
            status_list = [s.strip() for s in status.split(",") if s.strip()]
        facets = {
            "score_band":    score_band,
            "age_band":      age_band,
            "ip_band":       ip_band,
            "intent":        intent,
            "intel_verdict": intel_verdict,
        }
        facets = {k: v for k, v in facets.items() if v}
        try:
            data = findings_mod.list_findings(
                es, cfg,
                status=status_list, kind=kind, stream=stream,
                facets=facets,
                size=size, frm=frm, sort=sort,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        # Pair with per-bucket aggregates so the page header shows counts
        # without a second roundtrip.
        data["status_counts"] = findings_mod.status_counts(es, cfg)
        data["kind_counts"] = findings_mod.kind_counts(
            es, cfg, status=status_list if status_list else None,
        )
        # Findings v2 step 3 — three-section page header relies on this.
        data["stream_counts"] = findings_mod.stream_counts(
            es, cfg, status=status_list if status_list else None,
        )
        # Findings v2 P1c — left facet rail bucket counts.
        data["facet_counts"] = findings_mod.facet_counts(
            es, cfg,
            status=status_list if status_list else None,
            stream=stream, facets=facets,
        )
        return JSONResponse(data)

    @app.get("/api/finding/{finding_id}")
    def finding_detail_api(finding_id: str) -> JSONResponse:
        data = findings_mod.get_finding(es, cfg, finding_id)
        if data is None:
            raise HTTPException(404, f"finding not found: {finding_id}")
        return JSONResponse(data)

    @app.get("/api/finding/{finding_id}/detail")
    def finding_detail_drawer_api(finding_id: str) -> JSONResponse:
        """Findings v2 step 6 — payload for the slide-in drawer.

        Adds server-side joins to the base finding: lifecycle doc
        snapshot history + anchors, top-3 novel commands, top-5 member
        IPs with intel pills, convergent campaigns.

        Falls back to the base finding (with a `detail_error` field) if
        the join step raises — covers the partial-deploy case where the
        venv's FindingsIndexes is stale relative to the route code.
        """
        try:
            data = findings_mod.get_finding_detail(es, cfg, finding_id)
        except Exception as exc:
            log.exception("finding_detail_drawer_api failed for %s", finding_id)
            try:
                base = findings_mod.get_finding(es, cfg, finding_id)
            except Exception:
                base = None
            if base is None:
                raise HTTPException(500, f"detail load failed: {exc}")
            base["detail_error"] = str(exc)
            return JSONResponse(base)
        if data is None:
            raise HTTPException(404, f"finding not found: {finding_id}")
        return JSONResponse(data)

    @app.post("/api/finding/{finding_id}/status")
    def finding_status_api(finding_id: str, body: FindingStatusRequest) -> JSONResponse:
        # The mutation logic + history-append lives in the parent
        # package's writer so the upsert contract has one canonical
        # implementation. Cross-package import mirrors the pattern
        # used by /api/compare.
        from enrich.findings.writer import mutate_status
        try:
            updated = mutate_status(
                es, cfg.findings.indexes.default, finding_id,
                new_status=body.status, note=body.note,
                cfg=cfg,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except LookupError as exc:
            raise HTTPException(404, str(exc))
        except Exception as exc:                            # pragma: no cover
            log.exception("finding_status_api failed")
            raise HTTPException(500, f"status mutation failed: {exc}")
        return JSONResponse(updated)

    # ------------------------------------------------------------------
    # Per-artifact pane — intel + local-observations join
    # ------------------------------------------------------------------
    @app.get("/api/artifact/ip/{value}")
    def artifact_ip_api(value: str) -> JSONResponse:
        try:
            data = intel_mod.fetch_intel_ip(es, cfg, value)
        except Exception as exc:                       # pragma: no cover
            log.exception("artifact_ip_api failed")
            raise HTTPException(500, f"artifact lookup failed: {exc}")
        return JSONResponse(data)

    @app.get("/api/artifact/url")
    def artifact_url_api(value: str = Query(..., description="URL artifact value")) -> JSONResponse:
        # URL via `?value=<percent-encoded URL>` for the same reason
        # the page route uses a query parameter.
        try:
            data = intel_mod.fetch_intel_url(es, cfg, value)
        except Exception as exc:                       # pragma: no cover
            log.exception("artifact_url_api failed")
            raise HTTPException(500, f"artifact lookup failed: {exc}")
        return JSONResponse(data)

    @app.get("/api/artifact/hash")
    def artifact_hash_api(value: str = Query(..., description="file hash (md5/sha1/sha256)")) -> JSONResponse:
        try:
            data = intel_mod.fetch_intel_hash(es, cfg, value)
        except Exception as exc:                       # pragma: no cover
            log.exception("artifact_hash_api failed")
            raise HTTPException(500, f"artifact lookup failed: {exc}")
        return JSONResponse(data)

    # ------------------------------------------------------------------
    # Analyst-authored artifact rules (ROADMAP #5)
    # ------------------------------------------------------------------
    # Pipeline cfg cached so the rule subsystem's threshold knobs read from
    # the same config object the worker uses. Re-uses the lazy loader
    # established for /api/compare.
    #
    # POST scans synchronously when affected_estimate < threshold; otherwise
    # returns scan_status=queued and the next backward cycle finishes the
    # work (the systemd unit runs `apply-artifact-rules` after `mine
    # findings`).

    @app.post("/api/artifact-rule", status_code=201)
    def create_artifact_rule_api(body: ArtifactRuleRequest) -> JSONResponse:
        from enrich.analyst import artifact_rules as ar
        from enrich.analyst.scan import run_apply_artifact_rules
        pipeline_cfg = _get_pipeline_cfg()
        # Compile + sample probe BEFORE writing the doc so a catastrophic
        # regex (e.g. `.*`) is rejected without polluting the index.
        try:
            sample_size, matched = ar.sample_probe(es, pipeline_cfg, rule_dict={
                "kind": body.kind, "match_type": body.match_type,
                "pattern": body.pattern, "case_sensitive": body.case_sensitive,
            })
        except ValueError as exc:
            raise HTTPException(400, f"pattern rejected: {exc}")
        if ar.is_catastrophic(sample_size, matched):
            raise HTTPException(400, (
                f"pattern matches {matched}/{sample_size} sample commands "
                f"(>50%) — likely catastrophic, refusing to store."
            ))
        try:
            rule = ar.create_rule(
                es, pipeline_cfg,
                kind=body.kind, match_type=body.match_type,
                pattern=body.pattern, case_sensitive=body.case_sensitive,
                notes=body.notes, created_by="console",
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except Exception as exc:                          # pragma: no cover
            log.exception("create_artifact_rule failed")
            raise HTTPException(500, f"rule store failed: {exc}")

        # Sync-cap-then-queue scan.
        affected = ar.estimate_affected(es, pipeline_cfg, rule_dict=rule)
        threshold = int(pipeline_cfg.analyst.sync_scan_doc_threshold)
        scan_payload: dict[str, Any] = {
            "rule": rule, "affected_estimate": affected,
        }
        if affected < threshold:
            try:
                from enrich.config import load_secrets as _load_secrets
                pipeline_secrets = _load_secrets(config_path)
            except Exception:
                pipeline_secrets = None
            if pipeline_secrets is not None:
                try:
                    stats = run_apply_artifact_rules(
                        pipeline_cfg, pipeline_secrets,
                        rule_ids=[rule["rule_id"]], dry_run=False,
                    )
                    if stats.get("error"):
                        # Iteration aborted (e.g. an ES query rejection). Don't
                        # advertise a "matched 0" result that's actually a
                        # silent failure.
                        scan_payload["scan_status"] = "failed"
                        scan_payload["scan_error"] = stats["error"]
                        scan_payload["scan_stats"] = stats
                    else:
                        scan_payload["scan_status"] = "complete"
                        scan_payload["scan_stats"] = stats
                except Exception as exc:                  # pragma: no cover
                    log.exception("inline scan failed")
                    scan_payload["scan_status"] = "failed"
                    scan_payload["scan_error"] = str(exc)
            else:
                scan_payload["scan_status"] = "queued"
        else:
            scan_payload["scan_status"] = "queued"
        return JSONResponse(scan_payload, status_code=201)

    @app.get("/api/artifact-rules")
    def list_artifact_rules_api(
        active: Optional[bool] = Query(None),
        kind: Optional[str] = Query(None),
        created_by: Optional[str] = Query(None),
        size: int = Query(100, ge=1, le=500),
        frm: int = Query(0, ge=0),
    ) -> JSONResponse:
        from enrich.analyst import artifact_rules as ar
        data = ar.list_rules(
            es, _get_pipeline_cfg(),
            active=active, kind=kind, created_by=created_by,
            size=size, frm=frm,
        )
        return JSONResponse(data)

    @app.get("/api/artifact-rule/{rule_id}")
    def get_artifact_rule_api(rule_id: str) -> JSONResponse:
        from enrich.analyst import artifact_rules as ar
        rule = ar.get_rule(es, _get_pipeline_cfg(), rule_id)
        if rule is None:
            raise HTTPException(404, f"rule not found: {rule_id}")
        return JSONResponse(rule)

    @app.delete("/api/artifact-rule/{rule_id}")
    def soft_delete_artifact_rule_api(rule_id: str) -> JSONResponse:
        from enrich.analyst import artifact_rules as ar
        try:
            updated = ar.set_active(es, _get_pipeline_cfg(), rule_id, False)
        except LookupError as exc:
            raise HTTPException(404, str(exc))
        return JSONResponse(updated)

    @app.post("/api/artifact-rule/{rule_id}/reactivate")
    def reactivate_artifact_rule_api(rule_id: str) -> JSONResponse:
        from enrich.analyst import artifact_rules as ar
        try:
            updated = ar.set_active(es, _get_pipeline_cfg(), rule_id, True)
        except LookupError as exc:
            raise HTTPException(404, str(exc))
        return JSONResponse(updated)

    @app.get("/api/artifact-kinds")
    def list_artifact_kinds_api() -> JSONResponse:
        """Terms agg on `kind.keyword` for the modal's kind selector
        (kind-sprawl pressure: existing kinds show as suggestions)."""
        idx = _get_pipeline_cfg().analyst.indexes.artifact_rules
        try:
            r = es.search(
                index=idx, size=0,
                aggs={"kinds": {"terms": {"field": "kind.keyword", "size": 50}}},
            )
            buckets = (r.get("aggregations") or {}).get("kinds", {}).get("buckets") or []
            kinds = [{"kind": b["key"], "count": int(b["doc_count"])} for b in buckets]
        except Exception:
            kinds = []
        return JSONResponse({"kinds": kinds})

    # ------------------------------------------------------------------
    # Compare clusters (interactive: "why didn't these two playbooks merge?")
    # ------------------------------------------------------------------
    #
    # These endpoints reach into the parent `enrich` package — the
    # only place in this console where we cross-package import. The pipeline
    # owns the analysis primitives (`analyze_cluster_pair`) and the LLM
    # client; duplicating either here would mean keeping two implementations
    # of cluster math + LLM transport in sync. The pipeline `AppConfig` is
    # loaded lazily on first call so vanilla pages don't pay the import
    # cost, and `analyze` works even when LLM/prompts aren't configured.
    _pipeline_cfg: dict[str, Any] = {"value": None}

    def _get_pipeline_cfg():
        if _pipeline_cfg["value"] is None:
            from enrich.config import load_config as _load_pipeline_cfg
            _pipeline_cfg["value"] = _load_pipeline_cfg(config_path)
        return _pipeline_cfg["value"]

    @app.get("/api/compare/clusters")
    def compare_list_clusters() -> JSONResponse:
        """Latest session-cluster centroids — populates the picker dropdowns."""
        idx = cfg.elasticsearch.indexes.cowrie.session_clusters
        try:
            run_id = run_cache.latest(es, idx)
            if not run_id:
                return JSONResponse({"run_id": None, "clusters": []})
            r = es.search(
                index=idx, size=1000,
                query={"bool": {"must": [
                    {"term": {"doc_type": "cluster"}},
                    {"term": {"run_id": run_id}},
                ]}},
                _source=["cluster_id", "size", "playbook_id", "playbook_name"],
                sort=[{"playbook_name": "asc"}, {"cluster_id": "asc"}],
            )
            clusters = [h["_source"] for h in r["hits"]["hits"]]
        except Exception as exc:
            raise HTTPException(500, f"list clusters failed: {exc}")
        return JSONResponse({"run_id": run_id, "clusters": clusters})

    @app.get("/api/compare")
    def compare_analyze(
        a: str = Query(..., description="cluster_id A"),
        b: str = Query(..., description="cluster_id B"),
    ) -> JSONResponse:
        """Structured analysis of why two HDBSCAN clusters didn't merge.
        Fast (ES-only); no LLM call."""
        if a == b:
            raise HTTPException(400, "a and b must be different cluster_ids")
        from enrich.sources.cowrie.explain import analyze_cluster_pair
        try:
            data = analyze_cluster_pair(es, _get_pipeline_cfg(), a, b)
        except RuntimeError as exc:
            raise HTTPException(404, str(exc))
        except Exception as exc:
            log.exception("compare_analyze failed for %s vs %s", a, b)
            raise HTTPException(500, f"analyze failed: {exc}")
        return JSONResponse(data)

    @app.post("/api/compare/explain")
    def compare_explain(payload: dict) -> JSONResponse:
        """Take a previously-computed analysis dict and ask the local LLM
        for a verdict + evidence + recommendation. Slow (10-30s); fires only
        when the user clicks 'Explain' on the compare page."""
        from enrich.sources.cowrie.explain import explain_cluster_pair_with_llm
        analysis = payload.get("analysis") if isinstance(payload, dict) else None
        if not analysis or not isinstance(analysis, dict):
            raise HTTPException(400, "request body must include {'analysis': <dict>}")
        try:
            narrative = explain_cluster_pair_with_llm(_get_pipeline_cfg(), analysis)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc))
        except Exception as exc:
            log.exception("compare_explain LLM call failed")
            raise HTTPException(502, f"LLM call failed: {exc}")
        return JSONResponse(narrative)

    @app.get("/api/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        try:
            h = queries.health(es, cfg)
            return HealthResponse(ok=True, **h)
        except Exception as e:  # pragma: no cover -- depends on ES state
            return HealthResponse(
                ok=False, indexes={}, doc_counts={},
                error=f"{e.__class__.__name__}: {e}",
            )

    @app.get("/api/config/ui")
    def config_ui() -> JSONResponse:
        """UI-facing config values, fetched once at frontend boot. Distinct
        from /api/health so widening it stays a no-op for the health route's
        typed schema. ROADMAP #4 — the spotlight threshold lives here."""
        return JSONResponse({
            "specificity_threshold": cfg.session.specificity_threshold,
        })

    @app.get("/api/search", response_model=SearchResponse)
    def search(q: str = Query(..., min_length=1)) -> SearchResponse:
        refs = ioc.detect(q)
        candidates: list[SearchCandidate] = []
        for ref in refs:
            if ref.type == "freetext":
                candidates.extend(SearchCandidate(**c) for c in queries.freetext_search(es, cfg, ref.id))
            elif ref.type == "command_hash":
                # A 64-hex sha is also offered as a `file` candidate; only keep
                # the command one if a command with that hash actually exists.
                if queries.lookup_command(es, cfg, ref.id) is not None:
                    candidates.append(SearchCandidate(type=ref.type, id=ref.id, label=ref.label or ref.id))
            elif ref.type == "file":
                if queries.file_hash_exists(es, cfg, ref.id):
                    candidates.append(SearchCandidate(type=ref.type, id=ref.id, label=ref.label or ref.id))
            else:
                candidates.append(SearchCandidate(
                    type=ref.type, id=ref.id, label=ref.label or ref.id,
                ))
        return SearchResponse(query=q, candidates=candidates)

    # Specific suffix routes are registered BEFORE the catch-all detail route
    # so FastAPI matches them first. None of our IOC ids legitimately contain
    # '/', so plain {ident} (no :path converter) is enough.

    def _session_filter(require_login: bool, require_commands: bool) -> queries.SessionFilter:
        return queries.SessionFilter(
            require_login=require_login,
            require_commands=require_commands,
        )

    @app.get("/api/ioc/{ioc_type}/{ident}/neighbors", response_model=GraphResponse)
    def ioc_neighbors(
        ioc_type: str, ident: str,
        limit: int = Query(50, ge=1, le=500),
        require_login: bool = Query(True),
        require_commands: bool = Query(True),
    ) -> GraphResponse:
        if not ioc.is_known_type(ioc_type):
            raise HTTPException(400, f"unknown ioc_type: {ioc_type}")
        sf = _session_filter(require_login, require_commands)
        g = graph.neighbors(es, cfg, ioc_type, ident, limit=limit,
                            run_cache=run_cache, sf=sf)
        return GraphResponse(nodes=g["nodes"], edges=g["edges"],
                             anchor={"type": ioc_type, "id": ident})

    @app.get("/api/ioc/ip/{ip}/sessions", response_model=TableResponse)
    def table_sessions_for_ip(
        ip: str, size: int = Query(50, ge=1, le=500),
        frm: int = Query(0, ge=0),
        require_login: bool = Query(True),
        require_commands: bool = Query(True),
    ) -> TableResponse:
        sf = _session_filter(require_login, require_commands)
        r = queries.sessions_for_ip(es, cfg, ip, size=size, frm=frm, sf=sf)
        return _table(r, frm, size)

    @app.get("/api/ioc/session/{sid}/commands", response_model=TableResponse)
    def table_commands_for_session(sid: str, size: int = Query(50, ge=1, le=500)) -> TableResponse:
        r = queries.commands_for_session(es, cfg, sid, size=size)
        return TableResponse(total=r["total"], rows=r["rows"],
                             page={"from": 0, "size": size})

    @app.get("/api/ioc/command/{sha}/sessions", response_model=TableResponse)
    def table_sessions_for_command(
        sha: str, size: int = Query(50, ge=1, le=500),
        require_login: bool = Query(True),
        require_commands: bool = Query(True),
    ) -> TableResponse:
        sf = _session_filter(require_login, require_commands)
        r = queries.sessions_for_command(es, cfg, sha.lower(), size=size, sf=sf)
        return TableResponse(total=r["total"], rows=r["rows"],
                             page={"from": 0, "size": size})

    @app.get("/api/ioc/command/{sha}/shape-siblings", response_model=TableResponse)
    def table_shape_siblings(
        sha: str, size: int = Query(50, ge=1, le=500),
    ) -> TableResponse:
        """List every doc sharing this command's shape signature.

        Drives the "expand N variants" affordance on the command detail
        page (ROADMAP #9). The pivot command itself is excluded from the
        result. Ordered by occurrence_count desc so the most-prevalent
        siblings surface first.
        """
        idx = cfg.elasticsearch.indexes.cowrie.commands
        try:
            pivot = es.get(index=idx, id=sha.lower())
        except Exception:
            raise HTTPException(404, "command not found")
        psrc = pivot["_source"]
        penr = (psrc.get("dshield") or {}).get("cowrie", {}).get("enrichment") or {}
        shape_hash = (penr.get("shape") or {}).get("hash") or ""
        if not shape_hash:
            return TableResponse(total=0, rows=[], page={"from": 0, "size": size})
        body = {
            "size": size,
            "query": {
                "bool": {
                    "filter": [{"term": {"dshield.cowrie.enrichment.shape.hash": shape_hash}}],
                    "must_not": [{"term": {"_id": sha.lower()}}],
                }
            },
            "sort": [{"dshield.cowrie.enrichment.occurrence_count": "desc"}],
        }
        r = es.search(index=idx, **body)
        return _table(r, 0, size)

    @app.get("/api/cluster/{kind}/{cid}/members", response_model=TableResponse)
    def table_cluster_members(
        kind: str, cid: str, size: int = Query(50, ge=1, le=500),
        require_login: bool = Query(True),
        require_commands: bool = Query(True),
    ) -> TableResponse:
        if kind not in ("command", "session", "ip"):
            raise HTTPException(400, "kind must be one of command|session|ip")
        sf = _session_filter(require_login, require_commands) if kind == "session" else None
        r = queries.members_of_cluster(es, cfg, kind, cid, size=size, sf=sf)
        return _table(r, 0, size)

    # --- Cluster-anchored investigation pivots (ROADMAP #4) ---------------
    @app.get("/api/ip/{ip}/activity")
    def ip_activity_api(ip: str) -> JSONResponse:
        """Cross-cluster footprint for an IP — playbooks, campaigns, totals,
        intel verdict. Drives the drawer's click-to-pivot sub-panel."""
        return JSONResponse(queries.ip_activity(es, cfg, ip))

    @app.get("/api/command/{sha}/activity")
    def command_activity_api(sha: str) -> JSONResponse:
        """Cross-cluster footprint for a command (16-hex short id) — sessions,
        playbooks, IPs that ran it."""
        return JSONResponse(queries.command_activity(es, cfg, sha.lower()))

    @app.get("/api/playbook/{playbook_id}/distinctive")
    def playbook_distinctive_api(
        playbook_id: str, top_n: int = Query(20, ge=1, le=200),
    ) -> JSONResponse:
        """Top-N most cluster-specific IPs + commands for a playbook, from the
        persisted specificity maps."""
        return JSONResponse(queries.playbook_distinctive(es, cfg, playbook_id, top_n=top_n))

    @app.get("/api/ioc/{ioc_type}/{ident}", response_model=IOCDetail)
    def ioc_detail(ioc_type: str, ident: str) -> IOCDetail:
        if not ioc.is_known_type(ioc_type):
            raise HTTPException(400, f"unknown ioc_type: {ioc_type}")

        if ioc_type == "ip":
            doc = queries.lookup_ip(es, cfg, ident)
            if not doc:
                raise HTTPException(404, "ip not found")
            return _detail_ip_with_playbooks(es, cfg, ident, doc)
        if ioc_type == "session":
            doc = queries.lookup_session(es, cfg, ident)
            if not doc:
                raise HTTPException(404, "session not found")
            return _detail_session(ident, doc)
        if ioc_type in ("command", "command_hash"):
            doc = queries.lookup_command(es, cfg, ident.lower())
            if not doc:
                raise HTTPException(404, "command not found")
            return _detail_command(ident.lower(), doc)
        if ioc_type in ("command_cluster", "session_cluster", "ip_cluster"):
            kind = ioc_type.replace("_cluster", "")
            doc = queries.lookup_cluster(es, cfg, kind, ident, run_cache)
            return _detail_cluster(kind, ident, doc)
        if ioc_type == "playbook":
            data = queries.lookup_playbook(es, cfg, ident)
            title = (data.get("name") or ident) if isinstance(data, dict) else ident
            return IOCDetail(
                type="playbook", id=ident, title=f"playbook: {title}",
                summary=data, raw=None,
            )
        if ioc_type == "campaign":
            # Multi-session campaign — mined into its own index by
            # `dshield_prism mine campaigns`. Distinct from playbook (which
            # is a named session cluster).
            doc = queries.lookup_campaign(es, cfg, ident)
            if not doc:
                raise HTTPException(404, f"campaign not found: {ident}")
            title = doc.get("name") or ident
            return IOCDetail(
                type="campaign", id=ident, title=f"campaign: {title}",
                summary=doc, raw=None,
            )
        if ioc_type == "asn":
            return IOCDetail(type="asn", id=ident, title=f"AS{ident}",
                             summary={"asn": ident}, raw=None)
        if ioc_type == "country":
            return IOCDetail(type="country", id=ident.upper(),
                             title=f"country {ident.upper()}",
                             summary={"country_iso_code": ident.upper()}, raw=None)
        if ioc_type in ("mitre_technique", "mitre_tactic"):
            return IOCDetail(type=ioc_type, id=ident.upper(),
                             title=ident.upper(), summary={"id": ident.upper()}, raw=None)
        if ioc_type in ("file", "hash"):
            data = intel_mod.fetch_intel_hash(es, cfg, ident)
            sha = data["artifact"]["value"]
            intel = data.get("intel")
            derived = (intel or {}).get("derived") or {}
            if derived.get("consensus_malicious"):
                verdict = "malicious"
            elif intel is None:
                verdict = "no intel yet"
            else:
                verdict = "no provider flag"
            return IOCDetail(
                type="file", id=sha, title=f"file {sha[:12]}… ({verdict})",
                summary={
                    "sha256": sha,
                    "verdict": verdict,
                    "consensus_label": derived.get("consensus_label"),
                    "dropper_count": len(data.get("droppers") or []),
                    "droppers": data.get("droppers") or [],
                    "intel": intel,
                    "artifact_page": f"/artifact/hash?value={sha}",
                },
                raw=None,
            )
        raise HTTPException(400, f"detail not implemented for {ioc_type}")

    # ------------------------------------------------------------------
    # Ask AI
    # ------------------------------------------------------------------
    llm_cfg = cfg.llm

    @app.post("/api/ask")
    def ask_llm(body: AskRequest) -> JSONResponse:
        if not llm_cfg:
            raise HTTPException(503, "LLM not configured — add an llm: block to local.yaml")
        if not body.question.strip():
            raise HTTPException(400, "question is required")
        from enrich.llm.fencing import FENCE_NOTICE, make_nonce
        nonce = make_nonce()
        prompt = _build_ask_prompt(body.question, body.context, nonce)
        try:
            headers = {"Content-Type": "application/json"}
            if llm_cfg.api_key:
                headers["Authorization"] = f"Bearer {llm_cfg.api_key}"
            base = llm_cfg.base_url.rstrip("/").removesuffix("/v1")
            payload = {
                "model": llm_cfg.generation_model,
                "messages": [
                    {"role": "system", "content": (
                        "You are a cybersecurity analyst assistant helping investigate "
                        "honeypot intrusion data from DShield sensors. "
                        "Be concise and actionable. Refer specifically to the data provided. "
                        + FENCE_NOTICE
                    )},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 2048,
                "stream": False,
            }
            r = httpx.post(
                f"{base}/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=llm_cfg.request_timeout,
            )
            if r.status_code != 200:
                raise HTTPException(502, f"LLM returned {r.status_code}: {r.text[:300]}")
            data = r.json()
            answer = data["choices"][0]["message"]["content"] or ""
            return JSONResponse({"answer": answer, "model": llm_cfg.generation_model})
        except HTTPException:
            raise
        except Exception as e:
            log.exception("ask_llm failed")
            raise HTTPException(500, f"LLM request failed: {e}")

    return app


def _build_ask_prompt(question: str, context: dict, nonce: str | None = None) -> str:
    lines: list[str] = []

    anchor = context.get("anchor")
    if anchor:
        lines.append(f"Focus IOC: {anchor.get('type')} — {anchor.get('id')}")

    detail = context.get("detail")
    if detail and detail.get("summary"):
        lines.append("Selected node detail:")
        for k, v in detail["summary"].items():
            if v is not None and v != "" and v != []:
                lines.append(f"  {k}: {v}")

    playbooks = context.get("playbooks", [])
    if playbooks:
        lines.append(f"Playbooks in view: {', '.join(str(p) for p in playbooks)}")
    campaigns = context.get("campaigns", [])
    if campaigns:
        lines.append(f"Campaigns in view: {', '.join(str(c) for c in campaigns)}")

    nc = context.get("node_counts", {})
    lines.append(
        f"Graph contains {nc.get('ips', 0)} IPs, "
        f"{nc.get('sessions', 0)} sessions, "
        f"{nc.get('commands', 0)} commands."
    )

    nodes = context.get("nodes", [])
    ips      = [n for n in nodes if n.get("type") == "ip"]
    sessions = [n for n in nodes if n.get("type") == "session"]
    commands = [n for n in nodes if n.get("type") == "command"]

    if ips:
        lines.append(f"\nIPs ({len(ips)} shown):")
        for n in ips[:25]:
            parts = [n.get("label") or n.get("id", "?")]
            if n.get("country"):   parts.append(f"cc={n['country']}")
            if n.get("asn"):       parts.append(f"AS{n['asn']}")
            if n.get("playbook_name"):  parts.append(f"playbook={n['playbook_name']}")
            if n.get("novelty") is not None:
                parts.append(f"novelty={float(n['novelty']):.2f}")
            if n.get("is_outlier"): parts.append("OUTLIER")
            lines.append("  " + "  ".join(parts))

    if sessions:
        lines.append(f"\nSessions: {len(sessions)} total.")
        outliers = [n for n in sessions if n.get("is_outlier")]
        if outliers:
            lines.append(f"  {len(outliers)} outlier session(s).")
        intents: dict[str, int] = {}
        for n in sessions:
            intent = n.get("intent") or n.get("dominant_intent")
            if intent:
                intents[intent] = intents.get(intent, 0) + 1
        if intents:
            lines.append("  Intent breakdown: " +
                         ", ".join(f"{k}={v}" for k, v in sorted(intents.items(), key=lambda x: -x[1])))

    if commands:
        lines.append(f"\nCommands ({min(len(commands), 25)} of {len(commands)} shown):")
        for n in commands[:25]:
            parts = [n.get("label") or (n.get("id") or "?")[:40]]
            if n.get("intent"):  parts.append(f"intent={n['intent']}")
            if n.get("novelty") is not None:
                parts.append(f"novelty={float(n['novelty']):.2f}")
            if n.get("is_outlier"): parts.append("OUTLIER")
            lines.append("  " + "  ".join(parts))

    # The graph context above is built from node data (command text, IP
    # labels, descriptions) that is attacker-controlled — fence it so the
    # model treats it as data. The analyst's question rides outside the fence.
    data_block = "\n".join(lines)
    if nonce:
        from enrich.llm.fencing import fence
        data_block = fence("graph_context", data_block, nonce)
    return f"{data_block}\n\nQuestion: {question}"


# ---------------------------------------------------------------------------
# Detail builders (pull out the headline fields a human wants to see first)
# ---------------------------------------------------------------------------

def _detail_ip(ip: str, doc: dict) -> IOCDetail:
    src = doc["_source"]
    geo = (src.get("source") or {}).get("geo") or {}
    asn = (src.get("source") or {}).get("as") or {}
    enr = src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("ip", {})
    total_sessions = enr.get("total_sessions")
    successful_sessions = enr.get("successful_sessions")
    # Failed-login sessions: connections that didn't successfully authenticate.
    # Computed from the rollup's totals rather than counted separately so the
    # number reflects whatever the worker's most recent rollup produced.
    failed_login_sessions = None
    if isinstance(total_sessions, (int, float)) and isinstance(successful_sessions, (int, float)):
        failed_login_sessions = max(0, int(total_sessions) - int(successful_sessions))
    summary: dict[str, Any] = {
        "ip": ip,
        "country": geo.get("country_iso_code"),
        "region": geo.get("region_name"),
        "city": geo.get("city_name"),
        "asn": asn.get("number"),
        "asn_org": (asn.get("organization") or {}).get("name"),
        "total_sessions": total_sessions,
        "successful_sessions": successful_sessions,
        "failed_login_sessions": failed_login_sessions,
        "command_sessions": enr.get("command_sessions"),
        "total_commands": enr.get("total_commands"),
        "file_download_count": enr.get("file_download_count"),
        "dominant_intent": enr.get("dominant_intent"),
        "mean_novelty_score": enr.get("mean_novelty_score"),
        "first_seen": enr.get("first_seen"),
        "last_seen": enr.get("last_seen"),
        "cluster_id": (enr.get("cluster") or {}).get("id"),
        "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
        # An IP's playbook membership is derived from its sessions, not
        # stored on the IP doc — see `_detail_ip_with_playbooks` below.
    }
    return IOCDetail(type="ip", id=ip, title=ip, summary=summary, raw=src)


def _detail_ip_with_playbooks(es, cfg, ip: str, doc: dict) -> IOCDetail:
    """Wrap `_detail_ip` with a derived list of playbooks this IP ran.

    The list is derived through this IP's sessions, each tagged with its
    session-cluster's id+name.
    """
    detail = _detail_ip(ip, doc)
    try:
        pbs = queries.playbooks_for_ip(es, cfg, ip)
    except Exception:
        pbs = []
    detail.summary["playbooks"]      = pbs
    detail.summary["playbook_count"] = len(pbs)
    return detail


def _detail_session(sid: str, doc: dict) -> IOCDetail:
    src = doc["_source"]
    senr = src.get("dshield", {}).get("cowrie", {}).get("enrichment", {}).get("session", {})
    ev = src.get("event") or {}
    summary: dict[str, Any] = {
        "session_id": sid,
        "src_ip": (src.get("source") or {}).get("ip"),
        "user": (src.get("user") or {}).get("name"),
        "password": (src.get("cowrie") or {}).get("password"),
        "start": ev.get("start"),
        "end": ev.get("end"),
        "duration_ms": ev.get("duration"),
        "command_count": senr.get("command_count"),
        "unique_commands": senr.get("unique_commands"),
        "login_success_count": senr.get("login_success_count"),
        "login_fail_count": senr.get("login_fail_count"),
        "file_download_count": senr.get("file_download_count"),
        "file_upload_count": senr.get("file_upload_count"),
        "dominant_intent": senr.get("dominant_intent"),
        "mean_novelty_score": senr.get("mean_novelty_score"),
        "max_novelty_score": senr.get("max_novelty_score"),
        "playbook_id":   senr.get("playbook_id"),
        "playbook_name": senr.get("playbook_name"),
        "cluster_id": (senr.get("cluster") or {}).get("id"),
        "is_outlier": (senr.get("cluster") or {}).get("is_outlier"),
        # Session-level artifact union. Rendered as a chip section in the
        # drawer with `analyst:` entries grouped first. Populated by
        # `rollup sessions`; until next rollup pass, analyst stamps on
        # member commands aren't reflected here.
        "artifact_set": senr.get("artifact_set") or [],
    }
    return IOCDetail(type="session", id=sid, title=f"session {sid}", summary=summary, raw=src)


def _detail_command(sha: str, doc: dict) -> IOCDetail:
    src = doc["_source"]
    enr = src.get("dshield", {}).get("cowrie", {}).get("enrichment") or {}
    fb = enr.get("local_fallback") or {}
    threat = src.get("threat") or {}
    shape = enr.get("shape") or {}
    summary: dict[str, Any] = {
        "sha256": sha,
        "command_line": (src.get("process") or {}).get("command_line"),
        "intent": enr.get("intent") or fb.get("intent"),
        "confidence": enr.get("confidence") or fb.get("confidence"),
        "description": fb.get("description"),
        "tactics": fb.get("tactics") or [t.get("id") for t in (threat.get("tactic") if isinstance(threat.get("tactic"), list) else [threat.get("tactic")]) if t],
        "techniques": fb.get("techniques") or [t.get("id") for t in (threat.get("technique") if isinstance(threat.get("technique"), list) else [threat.get("technique")]) if t],
        "occurrence_count": enr.get("occurrence_count"),
        "unique_sessions": enr.get("unique_sessions"),
        "unique_source_ips": enr.get("unique_source_ips"),
        "triage_reasons": enr.get("triage_reasons"),
        "cluster_id": (enr.get("cluster") or {}).get("id"),
        "novelty_score": (enr.get("cluster") or {}).get("novelty_score"),
        "is_outlier": (enr.get("cluster") or {}).get("is_outlier"),
        "model": enr.get("model"),
        # Functional-duplicate gating (ROADMAP #9). `shape_role` is one
        # of canonical/standalone/child; `functional_parent` is the
        # canonical's _id when role=child. `inherited_from_model`
        # records which LLM produced the inherited text.
        "shape_hash": shape.get("hash"),
        "shape_role": shape.get("role"),
        "functional_parent": shape.get("functional_parent"),
        "inherited_from_model": shape.get("inherited_from_model"),
        "confidence_at_link": shape.get("confidence_at_link"),
        # Analyst-authored artifact hits (ROADMAP #5). Rendered as a chip
        # section above the kv table; the kv loop skips this key.
        "analyst_artifacts": enr.get("analyst_artifacts") or [],
    }
    return IOCDetail(type="command", id=sha, title=f"command {sha[:12]}…", summary=summary, raw=src)


def _detail_cluster(kind: str, cid: str, doc: dict | None) -> IOCDetail:
    if not doc:
        return IOCDetail(
            type=f"{kind}_cluster", id=cid, title=f"{kind} cluster {cid}",
            summary={"note": "centroid doc not found in latest run", "kind": kind, "id": cid},
            raw=None,
        )
    src = doc["_source"]
    summary: dict[str, Any] = {
        "kind": kind,
        "cluster_id": cid,
        "size": src.get("size"),
        "run_id": src.get("run_id"),
        # Session-cluster centroids carry playbook_id/playbook_name; other
        # centroid kinds simply have these as None.
        "playbook_id":   src.get("playbook_id"),
        "playbook_name": src.get("playbook_name"),
        "sample_commands": src.get("sample_commands"),
        "sample_session_ids": src.get("sample_session_ids"),
        "sample_ips": src.get("sample_ips"),
    }
    return IOCDetail(type=f"{kind}_cluster", id=cid,
                     title=f"{kind} cluster {cid}", summary=summary, raw=src)


def _table(r: dict, frm: int, size: int) -> TableResponse:
    rows = [{"_id": h["_id"], **h["_source"]} for h in r["hits"]["hits"]]
    return TableResponse(total=r["hits"]["total"]["value"], rows=rows,
                         page={"from": frm, "size": size})
