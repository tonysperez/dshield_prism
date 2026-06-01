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
from fastapi.responses import JSONResponse
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
    {"id": "hunts",     "label": "Hunts",    "href": "/hunts"},
    {"id": "rules",     "label": "Rules",    "href": "/artifact-rules"},
    {"id": "curation",  "label": "Curation", "href": "/curation"},
    {"id": "health",    "label": "Health",   "href": "/health"},
]


class AskRequest(BaseModel):
    question: str
    context: dict = {}


class WriteupRequest(BaseModel):
    """POST body for /api/writeup — Item #2 of the analyst-first UX push.

    `anchor` carries the focus of the writeup
    (`{type, id, name?, kind?, evidence?, window?}`); the client
    typically pulls these from state.currentDetail so the writeup is
    grounded on the same anchor metadata the orientation card shows.

    `scope` carries the in-view artifact aggregates the analyst
    selected in the Report modal — same payload shape `copy.js`
    already builds for the existing data-dump tab, plus optional
    `mitre` (aggregate technique chain) and `intel`
    ({ip,url,hash} → verdict counts).

    `evidence_quality` is the pre-computed one-line verdict from
    Item #5. Optional — the server falls back to the empty string
    when the client didn't pre-compute it.

    `escalate` opts into cloud LLM use, gated by
    `cloud.writeup_daily_budget_usd`. Default False = local LLM.
    """
    anchor:           dict = {}
    scope:            dict = {}
    evidence_quality: str = ""
    escalate:         bool = False


class DenylistAddRequest(BaseModel):
    """POST body for /api/health/commands/denylist (ROADMAP #11.5)."""
    token: str
    rationale: str = ""


class FindingStatusRequest(BaseModel):
    """POST body for /api/finding/{id}/status (M5)."""
    status: str
    note: str = ""


class FindingStatusBulkRequest(BaseModel):
    """POST body for /api/findings/status — bulk path used by the
    inbox multi-select bar (ROADMAP #17.4)."""
    ids: list[str]
    status: str
    note: str = ""


class FindingNoteRequest(BaseModel):
    """POST body for /api/finding/{id}/note (ROADMAP #17.4 amended).
    Appends a free-text annotation to the finding's status_history
    without changing the status."""
    note: str


class ArtifactRuleRequest(BaseModel):
    """POST body for /api/artifact-rule (ROADMAP #5)."""
    kind: str
    match_type: str           # literal | substring | regex
    pattern: str
    case_sensitive: bool = False
    notes: str = ""


class ArtifactsDetailRequest(BaseModel):
    """POST body for /api/graph/artifacts-detail (ROADMAP #6, Phase H).
    Bulk-resolves the data the graph doesn't keep in memory by default —
    full command_line + threat indicators for each command sha, plus
    credentials + file-event URLs + analyst artifacts for each session,
    plus analyst-authored lifecycle notes for each anchor in view
    (playbook / campaign / IP).
    """
    session_ids:   list[str] = []
    command_shas:  list[str] = []
    playbook_ids:  list[str] = []
    campaign_ids:  list[str] = []
    ips:           list[str] = []


def _build_cmd_artifact(src: dict) -> dict:
    """Project a command doc's _source down to the fields the Copy modal
    cares about. Centralised so both the mget path and the field-search
    fallback in /api/graph/artifacts-detail emit the same shape."""
    proc = src.get("process") or {}
    threat = src.get("threat") or {}
    enr = ((src.get("dshield") or {}).get("cowrie") or {}).get("enrichment", {}) or {}
    indicators = threat.get("indicator") or []
    urls:   list[str] = []
    ips:    list[str] = []
    hashes: list[str] = []
    domains: list[str] = []
    for ind in indicators:
        if not isinstance(ind, dict):
            continue
        u = ((ind.get("url") or {}).get("full"))
        if u: urls.append(u)
        ip_v = ind.get("ip")
        if ip_v: ips.append(ip_v)
        h = ((ind.get("file") or {}).get("hash") or {}).get("sha256")
        if h: hashes.append(h)
        d = ind.get("domain")
        if d: domains.append(d)
    return {
        "command_line": proc.get("command_line") or "",
        "sha256_full":  (proc.get("hash") or {}).get("sha256") or "",
        "intent":       enr.get("intent"),
        "indicator_urls":    sorted(set(urls)),
        "indicator_ips":     sorted(set(ips)),
        "indicator_hashes":  sorted(set(hashes)),
        "indicator_domains": sorted(set(domains)),
        "analyst_artifacts": enr.get("analyst_artifacts") or [],
    }


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

    # /compare folded into the graph as an inline compare panel
    # (ROADMAP #17.11 amended, G.2). The standalone page is gone; any
    # surviving deep-link drops the analyst on the graph landing.
    @app.get("/compare", include_in_schema=False)
    def compare_page_redirect(request: Request) -> RedirectResponse:
        return RedirectResponse(_preserve_qs(request, "/graph"), status_code=302)

    @app.get("/health")
    def health_page(request: Request):
        return _render(request, "health.html", active_nav="health")

    @app.get("/curation")
    def curation_page(request: Request):
        return _render(request, "curation.html", active_nav="curation")

    @app.get("/hunts")
    def hunts_page(request: Request):
        return _render(request, "hunts.html", active_nav="hunts")

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
    # Hunts (brutal-review phase 6.3) — read-only list view + run-now.
    # ------------------------------------------------------------------
    @app.get("/api/hunts")
    def hunts_list_api() -> JSONResponse:
        """List every hunt loaded from `config/hunts/` along with its
        last-run finding count (queried from `prism.findings`). Read-only.
        """
        from enrich.findings.hunts import load_hunts
        hunts_dir = getattr(getattr(cfg.findings, "hunts", None),
                            "config_dir", "config/hunts")
        try:
            hunts = load_hunts(hunts_dir)
        except Exception as exc:
            log.warning("hunts list: load failed: %s", exc)
            return JSONResponse({"hunts": [], "error": str(exc)})
        # One agg pulls per-hunt counts in a single round-trip.
        counts_by_id: dict[str, int] = {}
        try:
            findings_idx = cfg.findings.indexes.default
            if es.indices.exists(index=findings_idx):
                r = es.search(
                    index=findings_idx, size=0,
                    query={"term": {"kind": "analyst_hunt"}},
                    aggs={"by_hunt": {"terms": {
                        "field": "evidence.hunt_id.keyword", "size": 100,
                    }}},
                )
                for b in (r.get("aggregations", {}).get("by_hunt", {}).get("buckets") or []):
                    counts_by_id[b["key"]] = b["doc_count"]
        except Exception as exc:
            log.warning("hunts list: count agg failed: %s", exc)
        out: list[dict] = []
        for h in hunts:
            out.append({
                "id":           h["id"],
                "name":         h["name"],
                "description":  h.get("description") or "",
                "filters":      h.get("filters") or [],
                "enabled":      h.get("enabled", True),
                "finding_count": int(counts_by_id.get(h["id"], 0)),
            })
        return JSONResponse({"hunts": out, "hunts_dir": hunts_dir})

    @app.post("/api/hunts/run")
    def hunts_run_api() -> JSONResponse:
        """Trigger `mine hunts` on demand — same logic the backward
        chain runs at Step 13. Read-only effects on the cluster /
        rollup indexes; just upserts new analyst_hunt findings.
        """
        from enrich.findings.hunts import run_hunts
        from enrich.findings.writer import bulk_upsert_findings
        from enrich.es_client import init_index
        import uuid as _uuid
        findings_idx = cfg.findings.indexes.default
        init_index(es, "setup/es-mappings/findings/default.json", findings_idx)
        run_id = str(_uuid.uuid4())
        try:
            result = run_hunts(es, cfg, run_id)
        except Exception as exc:
            log.exception("hunts run failed")
            raise HTTPException(500, f"hunts run failed: {exc}")
        written_by_hunt: dict[str, int] = {}
        for hid, findings in (result.get("by_hunt") or {}).items():
            if findings:
                n = bulk_upsert_findings(es, findings_idx, findings)
                written_by_hunt[hid] = n
        try:
            es.indices.refresh(index=findings_idx)
        except Exception:
            pass
        return JSONResponse({
            "run_id":         run_id,
            "loaded":         result.get("loaded", 0),
            "written_by_hunt": written_by_hunt,
            "errors":         result.get("errors") or [],
        })

    # ------------------------------------------------------------------
    # Findings (M5) — list / filter / status mutation / calibration scatter
    # ------------------------------------------------------------------
    @app.get("/api/findings")
    def findings_list_api(
        status: str = Query("new", description="Comma-separated list of statuses, or 'all'"),
        kind: Optional[str] = Query(None, description="Single finding kind to filter on"),
        stream: Optional[str] = Query(None, description="drift | discovery | coverage | hunt"),
        hunt_id: Optional[str] = Query(None, description="filter to a single analyst_hunt id (click-through from /hunts)"),
        # P1c facet rail — each accepts a single bucket key per dimension.
        score_band:    Optional[str] = Query(None, description="low | medium | high"),
        age_band:      Optional[str] = Query(None, description="today | week | older"),
        ip_band:       Optional[str] = Query(None, description="small | medium | large"),
        intent:        Optional[str] = Query(None, description="dominant_intent value"),
        intel_verdict: Optional[str] = Query(None, description="clean | malicious | mixed | no_data"),
        since:         Optional[str] = Query(None, description="ISO timestamp — filter to findings touched since (ROADMAP #17.17)"),
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
                facets=facets, since=since, hunt_id=hunt_id,
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

    @app.get("/api/findings/since-summary")
    def findings_since_summary_api(
        ts: str = Query(..., description="ISO timestamp of the analyst's last visit"),
    ) -> JSONResponse:
        """Counts of findings touched since `ts`. Drives the inbox
        "what changed since I last looked" strip (ROADMAP #17.17)."""
        return JSONResponse(findings_mod.since_summary(es, cfg, ts=ts))

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

    @app.post("/api/finding/{finding_id}/note")
    def finding_note_api(finding_id: str, body: FindingNoteRequest) -> JSONResponse:
        from enrich.findings.writer import add_note
        try:
            updated = add_note(
                es, cfg.findings.indexes.default, finding_id,
                note=body.note,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except LookupError as exc:
            raise HTTPException(404, str(exc))
        except Exception as exc:                            # pragma: no cover
            log.exception("finding_note_api failed")
            raise HTTPException(500, f"note append failed: {exc}")
        return JSONResponse(updated)

    @app.post("/api/findings/status")
    def findings_bulk_status_api(body: FindingStatusBulkRequest) -> JSONResponse:
        """Apply the same status (and optional note) to many findings in
        one round-trip. Drives the inbox multi-select bar. Per-id
        failures are collected and reported alongside the success
        count rather than aborting the batch."""
        from enrich.findings.writer import mutate_status
        if not body.ids:
            raise HTTPException(400, "no ids supplied")
        n_updated = 0
        errors: list[dict] = []
        for fid in body.ids:
            try:
                mutate_status(
                    es, cfg.findings.indexes.default, fid,
                    new_status=body.status, note=body.note,
                    cfg=cfg,
                )
                n_updated += 1
            except ValueError as exc:
                errors.append({"id": fid, "error": str(exc)})
            except LookupError as exc:
                errors.append({"id": fid, "error": str(exc)})
            except Exception as exc:                        # pragma: no cover
                log.exception("findings_bulk_status_api failed for %s", fid)
                errors.append({"id": fid, "error": f"{exc.__class__.__name__}: {exc}"})
        return JSONResponse({"n_updated": n_updated, "errors": errors})

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
        # Stamp the activity verdict (Active / Light / Single-point · counts
        # · window) so the artifact page carries the same one-line
        # confidence surface the inbox + graph orientation card do.
        try:
            from enrich.findings.evidence_quality import format_anchor_evidence_quality
            rollup = (data or {}).get("rollup") or {}
            enr = (((rollup.get("dshield") or {}).get("cowrie") or {})
                   .get("enrichment") or {}).get("ip") or {}
            if enr:
                v = format_anchor_evidence_quality("ip", {
                    "total_sessions": enr.get("total_sessions"),
                    "total_commands": enr.get("total_commands"),
                    "first_seen":     enr.get("first_seen"),
                    "last_seen":      enr.get("last_seen"),
                })
                if v:
                    data["evidence_quality"] = v
        except Exception:
            pass
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

    @app.get("/api/compare/nearest")
    def compare_nearest(
        kind: str = Query("session_cluster",
                          description="session_cluster | ip_cluster | command_cluster | playbook | campaign"),
        id: str   = Query(..., description="anchor id"),
        top_n: int = Query(8, ge=1, le=25),
    ) -> JSONResponse:
        """Inline-compare entrypoint (ROADMAP #17.11). Returns the top-N
        nearest peers within `kind` so the graph can offer a picker
        instead of forcing the analyst into a single auto-pick.

        For session_cluster, peers sharing the target's playbook_id are
        excluded (the merge layer already considers them the same playbook;
        comparing to a sibling is wasted clicks)."""
        from enrich.sources.cowrie.explain import nearest_peers
        try:
            data = nearest_peers(es, _get_pipeline_cfg(), kind, id, top_n=top_n)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except Exception as exc:
            log.exception("compare_nearest failed for %s %s", kind, id)
            raise HTTPException(500, f"nearest failed: {exc}")
        return JSONResponse(data)

    @app.get("/api/compare")
    def compare_analyze(
        kind: str = Query("session_cluster",
                          description="session_cluster | ip_cluster | command_cluster | playbook | campaign"),
        a: str = Query(..., description="anchor A"),
        b: str = Query(..., description="anchor B"),
    ) -> JSONResponse:
        """Per-kind compare analysis. session_cluster runs the full
        analyzer (centroid + scalar + top-K commands + sequences);
        ip_cluster / command_cluster return a centroid-only summary;
        playbook composes a mean centroid over member session-clusters;
        campaign uses Jaccard over member playbooks. Fast (ES-only);
        the LLM-narrative path is still /api/compare/explain."""
        from enrich.sources.cowrie.explain import analyze_pair
        try:
            data = analyze_pair(es, _get_pipeline_cfg(), kind, a, b)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except RuntimeError as exc:
            raise HTTPException(404, str(exc))
        except Exception as exc:
            log.exception("compare_analyze failed for %s %s vs %s", kind, a, b)
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

    @app.get("/api/health/freshness")
    def health_freshness_api() -> JSONResponse:
        """Per-index doc count + max(@timestamp). Drives the data-
        freshness panel on /health."""
        try:
            return JSONResponse({"rows": queries.health_freshness(es, cfg)})
        except Exception as e:  # pragma: no cover -- depends on ES state
            return JSONResponse({"rows": [], "error": f"{e.__class__.__name__}: {e}"})

    @app.get("/api/health/runs")
    def health_runs_api() -> JSONResponse:
        """Latest run_summary doc per cluster index. Drives the recent-
        pipeline-runs panel on /health."""
        try:
            return JSONResponse({"rows": queries.health_runs(es, cfg)})
        except Exception as e:  # pragma: no cover -- depends on ES state
            return JSONResponse({"rows": [], "error": f"{e.__class__.__name__}: {e}"})

    @app.get("/api/health/ttp-rates")
    def health_ttp_rates_api() -> JSONResponse:
        """Top-N MITRE-technique application rates from the latest
        enrich-run snapshot. Drives the TTP-rates panel on /health
        (brutal-review phase 2.3). Rows with `warning=true` are
        applied to >=5% of LLM-enriched commands and likely over-
        applied — a soft warning, not an error."""
        try:
            return JSONResponse(queries.health_ttp_rates(es, cfg))
        except Exception as e:  # pragma: no cover -- depends on ES state
            return JSONResponse(
                {"rows": [], "error": f"{e.__class__.__name__}: {e}"}
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

    @app.post("/api/graph/artifacts-detail")
    def graph_artifacts_detail(body: ArtifactsDetailRequest) -> JSONResponse:
        """Bulk artifact resolution for the Copy modal (ROADMAP #6, Phase H).
        Returns full command_line + threat indicators for each command sha,
        and credentials + file-event URLs + analyst artifacts for each
        session. Pure read — no LLM, no upstream calls.

        Designed to be called once when the analyst opens the modal, so
        we use mget for both indexes (single round-trip per kind) plus a
        small fallback search for command shas that don't resolve by _id."""
        out_sessions: dict[str, dict] = {}
        out_commands: dict[str, dict] = {}

        sess_idx = cfg.elasticsearch.indexes.cowrie.sessions_rollup
        cmd_idx  = cfg.elasticsearch.indexes.cowrie.commands

        sess_ids = list({s for s in (body.session_ids or []) if s})
        cmd_shas = list({c for c in (body.command_shas or []) if c})

        if sess_ids:
            try:
                resp = es.mget(index=sess_idx, ids=sess_ids,
                               _source=[
                                   "cowrie.session_id",
                                   "dshield.cowrie.enrichment.session.credentials",
                                   "dshield.cowrie.enrichment.session.file_events",
                                   "dshield.cowrie.enrichment.session.artifact_set",
                                   "dshield.cowrie.enrichment.session.analyst_artifacts",
                               ])
                for d in resp.get("docs", []):
                    if not d.get("found"):
                        continue
                    sid = d["_id"]
                    src = d.get("_source") or {}
                    senr = (((src.get("dshield") or {}).get("cowrie") or {})
                            .get("enrichment", {}).get("session", {}))
                    fe = senr.get("file_events") or []
                    file_event_urls = sorted({
                        f.get("url") for f in fe if isinstance(f, dict) and f.get("url")
                    })
                    # File hashes keep the filename / path alongside the
                    # hash so the Report can render the analyst-facing
                    # name next to the sha. De-dup on (sha, name) so the
                    # same drop with different filenames still shows up.
                    seen_fh: set[tuple[str, str, str]] = set()
                    file_event_files: list[dict] = []
                    for f in fe:
                        if not isinstance(f, dict):
                            continue
                        sha = f.get("sha256") or ""
                        nm  = f.get("filename") or ""
                        ch  = f.get("command_hash") or ""
                        attr = f.get("command_attribution") or ""
                        action = f.get("action") or ""
                        if not sha:
                            continue
                        # Dedup on (sha, filename, command_hash) — same hash
                        # dropped from different commands or with different
                        # filenames is meaningful provenance the analyst
                        # report should keep.
                        key = (sha, nm, ch)
                        if key in seen_fh:
                            continue
                        seen_fh.add(key)
                        file_event_files.append({
                            "sha256": sha, "filename": nm,
                            "action": action,
                            "command_hash": ch,
                            "command_attribution": attr,
                        })
                    out_sessions[sid] = {
                        "credentials":        senr.get("credentials") or [],
                        "file_event_urls":    file_event_urls,
                        "file_event_files":   file_event_files,
                        "artifact_set":       senr.get("artifact_set") or [],
                        "analyst_artifacts":  senr.get("analyst_artifacts") or [],
                    }
            except Exception as exc:
                log.exception("artifacts-detail mget(session) failed")
                raise HTTPException(500, f"session mget failed: {exc}")

        if cmd_shas:
            try:
                resp = es.mget(index=cmd_idx, ids=cmd_shas,
                               _source=[
                                   "process.command_line",
                                   "process.hash.sha256",
                                   "threat.indicator",
                                   "dshield.cowrie.enrichment.intent",
                                   "dshield.cowrie.enrichment.analyst_artifacts",
                               ])
                resolved: set[str] = set()
                for d in resp.get("docs", []):
                    if not d.get("found"):
                        continue
                    sha = d["_id"]
                    resolved.add(sha)
                    out_commands[sha] = _build_cmd_artifact(d.get("_source") or {})
                missing = [s for s in cmd_shas if s not in resolved]
                # 64-hex shas (full process.hash.sha256) don't match the
                # 16-hex doc _id. Fall back to a field-term lookup for any
                # that missed; mget is the common case, this is the long tail.
                if missing:
                    fb = es.search(
                        index=cmd_idx,
                        size=len(missing),
                        query={"terms": {"process.hash.sha256": missing}},
                        _source=[
                            "process.command_line",
                            "process.hash.sha256",
                            "threat.indicator",
                            "dshield.cowrie.enrichment.intent",
                            "dshield.cowrie.enrichment.analyst_artifacts",
                        ],
                    )
                    for h in fb.get("hits", {}).get("hits", []):
                        src = h.get("_source") or {}
                        full = ((src.get("process") or {}).get("hash") or {}).get("sha256")
                        if full and full in missing:
                            out_commands[full] = _build_cmd_artifact(src)
            except Exception as exc:
                log.exception("artifacts-detail mget(command) failed")
                raise HTTPException(500, f"command mget failed: {exc}")

        # Resolve dropping-command hashes to their command_line text so
        # the Report shows the analyst-readable command instead of an
        # opaque 16-hex doc id. File events with no command_hash are
        # typically SFTP/SCP uploads — those carry an empty value here
        # and the frontend distinguishes them by `action`.
        dropping_command_lines: dict[str, str] = {}
        dropping_shas: set[str] = set()
        for s in out_sessions.values():
            for fe in s.get("file_event_files") or []:
                ch = fe.get("command_hash") or ""
                if ch:
                    dropping_shas.add(ch)
        # Many dropping_command_hashes will already have been resolved by
        # the commands mget above (when the command was also a graph node);
        # only fetch the residual.
        residual = [h for h in dropping_shas if h not in out_commands]
        if residual:
            try:
                resp = es.mget(index=cmd_idx, ids=residual,
                               _source=["process.command_line"])
                for d in resp.get("docs", []):
                    if not d.get("found"):
                        continue
                    src = d.get("_source") or {}
                    line = ((src.get("process") or {}).get("command_line") or "")
                    if line:
                        dropping_command_lines[d["_id"]] = line
            except Exception as exc:
                log.warning("artifacts-detail dropping-cmd mget failed: %s", exc)
        # Fold the in-band commands' lines in too (free lookup).
        for sha, art in out_commands.items():
            if sha in dropping_shas and art.get("command_line"):
                dropping_command_lines[sha] = art["command_line"]

        # Lifecycle notes — pull analyst-authored notes off finding docs
        # for any playbook / campaign / IP currently on the graph. Notes
        # live as `status_history[].note` entries; we ignore the empty
        # ones (which are status-flip-only audit records).
        lifecycle_notes: list[dict] = []
        kind_to_values: list[tuple[str, list[str]]] = []
        if body.playbook_ids: kind_to_values.append(("playbook", [v for v in body.playbook_ids if v]))
        if body.campaign_ids: kind_to_values.append(("campaign", [v for v in body.campaign_ids if v]))
        if body.ips:          kind_to_values.append(("ip",       [v for v in body.ips          if v]))
        kind_to_values = [(k, v) for k, v in kind_to_values if v]
        if kind_to_values:
            findings_idx = cfg.findings.indexes.default
            should: list[dict] = []
            for kind, values in kind_to_values:
                should.append({"bool": {"must": [
                    {"term":  {"artifact.kind":  kind}},
                    {"terms": {"artifact.value": values}},
                ]}})
            try:
                resp = es.search(
                    index=findings_idx,
                    size=500,
                    query={"bool": {"should": should, "minimum_should_match": 1}},
                    _source=["finding_id", "artifact", "status_history"],
                )
                for h in resp.get("hits", {}).get("hits", []):
                    src = h.get("_source") or {}
                    art = src.get("artifact") or {}
                    fid = src.get("finding_id") or h.get("_id")
                    for ev in src.get("status_history") or []:
                        if not isinstance(ev, dict):
                            continue
                        note = (ev.get("note") or "").strip()
                        if not note:
                            continue
                        lifecycle_notes.append({
                            "finding_id":     fid,
                            "artifact_kind":  art.get("kind"),
                            "artifact_value": art.get("value"),
                            "ts":             ev.get("ts"),
                            "status":         ev.get("to") or ev.get("from"),
                            "note":           note,
                        })
                # Newest first within the response — matches the analyst's
                # reading order in the inbox drawer.
                lifecycle_notes.sort(key=lambda r: r.get("ts") or "", reverse=True)
            except Exception as exc:
                log.exception("artifacts-detail findings search failed")
                # Notes are best-effort; surface the error in the payload
                # rather than failing the whole bulk fetch.
                return JSONResponse({
                    "sessions": out_sessions,
                    "commands": out_commands,
                    "lifecycle_notes": [],
                    "lifecycle_notes_error": str(exc),
                })

        # Analyst-rule notes — each analyst_artifacts entry on a session/
        # command doc carries a `rule_id`; the rule's analyst-authored
        # `notes` field is the "why" of the rule. Surface them so the
        # Report carries the rule rationale alongside each match.
        rule_notes: dict[str, str] = {}
        seen_rule_ids: set[str] = set()
        for blob in list(out_sessions.values()) + list(out_commands.values()):
            for a in blob.get("analyst_artifacts") or []:
                if not isinstance(a, dict):
                    continue
                rid = a.get("rule_id")
                if rid:
                    seen_rule_ids.add(rid)
        if seen_rule_ids:
            # The analyst-rule config lives on the pipeline-side AppConfig
            # (the console's lighter cfg model doesn't carry it). Use the
            # same lazy pipeline-cfg accessor the artifact-rule routes use.
            rules_idx = _get_pipeline_cfg().analyst.indexes.artifact_rules
            try:
                resp = es.mget(index=rules_idx, ids=list(seen_rule_ids),
                               _source=["rule_id", "notes"])
                for d in resp.get("docs", []):
                    if not d.get("found"):
                        continue
                    src = d.get("_source") or {}
                    rid = src.get("rule_id") or d.get("_id")
                    note = (src.get("notes") or "").strip()
                    if rid and note:
                        rule_notes[rid] = note
            except Exception as exc:
                # Notes are best-effort — surface the error but don't kill
                # the whole response.
                log.warning("artifacts-detail rule-notes mget failed: %s", exc)

        # IP rollup extras — HASSH today, expand later if other per-IP
        # attribution signals (e.g. JA3) become useful in the Report.
        ip_extras: dict[str, dict] = {}
        if body.ips:
            ip_rollup_idx = cfg.elasticsearch.indexes.cowrie.ips_rollup
            try:
                resp = es.mget(index=ip_rollup_idx, ids=[v for v in body.ips if v],
                               _source=["dshield.cowrie.enrichment.ip.hassh"])
                for d in resp.get("docs", []):
                    if not d.get("found"):
                        continue
                    src = d.get("_source") or {}
                    ipenr = (((src.get("dshield") or {}).get("cowrie") or {})
                             .get("enrichment", {}).get("ip", {}))
                    ip_extras[d["_id"]] = {"hassh": ipenr.get("hassh") or ""}
            except Exception as exc:
                log.warning("artifacts-detail ip-extras mget failed: %s", exc)

        # Intel verdicts — minimal shape (verdict + family + counts) across
        # all three intel indexes. We mget by id (the artifact value).
        intel = {"ip": {}, "url": {}, "hash": {}}
        intel_targets: list[tuple[str, str, list[str]]] = []
        if body.ips:
            intel_targets.append(("ip", cfg.intel.indexes.ip,
                                  [v for v in body.ips if v]))
        # URL + hash inputs come from the bulk-resolved details, so we
        # collect them after the session/command passes have run.
        url_values: set[str] = set()
        hash_values: set[str] = set()
        for s in out_sessions.values():
            for u in s.get("file_event_urls") or []: url_values.add(u)
            for fe in s.get("file_event_files") or []:
                if fe.get("sha256"): hash_values.add(fe["sha256"])
        for c in out_commands.values():
            for u in c.get("indicator_urls") or []:    url_values.add(u)
            for h in c.get("indicator_hashes") or []:  hash_values.add(h)
        if url_values:
            intel_targets.append(("url",  cfg.intel.indexes.url,
                                  sorted(url_values)))
        if hash_values:
            intel_targets.append(("hash", cfg.intel.indexes.hash,
                                  sorted(hash_values)))
        for kind, idx, values in intel_targets:
            if not values:
                continue
            try:
                resp = es.mget(index=idx, ids=values,
                               _source=["derived", "family", "tags"])
                for d in resp.get("docs", []):
                    if not d.get("found"):
                        continue
                    src = d.get("_source") or {}
                    derived = src.get("derived") or {}
                    cons_mal  = bool(derived.get("consensus_malicious"))
                    cons_cln  = bool(derived.get("consensus_clean"))
                    override  = derived.get("override_applied") or ""
                    mc = derived.get("malicious_provider_count")
                    cc = derived.get("clean_provider_count")
                    pc = (mc or 0) + (cc or 0) if (mc is not None or cc is not None) else None
                    verdict = "malicious" if cons_mal else ("clean" if cons_cln else "unknown")
                    fam = src.get("family") or ""
                    intel[kind][d["_id"]] = {
                        "verdict":          verdict,
                        "family":           fam,
                        "override":         override,
                        "malicious_count":  mc,
                        "provider_count":   pc,
                    }
            except Exception as exc:
                log.warning("artifacts-detail intel mget(%s) failed: %s", kind, exc)

        # Ordered command sequences per session — events index, sorted by
        # @timestamp. Bounded msearch so a tab with hundreds of sessions
        # in view doesn't blow up the request, though analysts rarely
        # report on more than a few sessions at a time.
        session_sequences: dict[str, list[dict]] = {}
        if body.session_ids:
            events_idx = cfg.elasticsearch.indexes.cowrie.sessions_raw
            try:
                body_parts: list = []
                for sid in body.session_ids:
                    body_parts.append({"index": events_idx})
                    body_parts.append({
                        "size": 300,
                        "_source": ["process.command_line", "process.hash.sha256", "@timestamp"],
                        "query": {"bool": {"must": [
                            {"term": {"cowrie.session_id": sid}},
                            {"term": {"event.action": "cowrie.command.input"}},
                        ]}},
                        "sort": [{"@timestamp": {"order": "asc"}}],
                    })
                if body_parts:
                    msr = es.msearch(body=body_parts)
                    for sid, resp in zip(body.session_ids, msr.get("responses", [])):
                        cmds: list[dict] = []
                        for h in (resp.get("hits") or {}).get("hits", []):
                            src = h.get("_source") or {}
                            cmd = (src.get("process") or {}).get("command_line")
                            sha = ((src.get("process") or {}).get("hash") or {}).get("sha256") or ""
                            if not cmd:
                                continue
                            cmds.append({"ts": src.get("@timestamp"),
                                         "command_line": cmd, "sha256": sha})
                        if cmds:
                            session_sequences[sid] = cmds
            except Exception as exc:
                log.warning("artifacts-detail session sequences msearch failed: %s", exc)

        return JSONResponse({
            "sessions": out_sessions,
            "commands": out_commands,
            "lifecycle_notes": lifecycle_notes,
            "rule_notes": rule_notes,
            "ip_extras": ip_extras,
            "intel": intel,
            "session_sequences": session_sequences,
            "dropping_command_lines": dropping_command_lines,
        })

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
            return _attach_anchor_evidence_quality(IOCDetail(
                type="playbook", id=ident, title=f"playbook: {title}",
                summary=data, raw=None,
            ), es=es, cfg=cfg)
        if ioc_type == "operation":
            # brutal-review 7.2 — operations are bhv × inf campaign pair
            # mergers minted by 7.1 into prism.operations. Read-only
            # entity; no status workflow attached. Detail pane shows
            # the two parent campaign ids + IP overlap stats so the
            # analyst can pivot back to either campaign view.
            data = queries.lookup_operation(es, cfg, ident)
            if not data:
                raise HTTPException(404, f"operation not found: {ident}")
            bhv_name = data.get("behaviour_name") or data.get("behaviour_id")
            inf_name = data.get("infrastructure_name") or data.get("infrastructure_id")
            title = f"operation: {bhv_name} ↔ {inf_name}"
            return IOCDetail(
                type="operation", id=ident,
                title=title, summary=data, raw=None,
            )
        if ioc_type == "campaign":
            # Multi-session campaign — mined into its own index by
            # `dshield_prism mine campaigns`. Distinct from playbook (which
            # is a named session cluster).
            #
            # Tour-mode synthetic campaign: when the analyst is following
            # the onboarding tour, the campaign id matches the in-repo
            # tour fixture. The graph builder emits a synthetic neighbor
            # payload from the same emit helpers as live data; here we
            # return a matching synthetic IOCDetail so the lookup
            # doesn't 404. Drives the same orientation card / detail
            # pane / write-up flow with no ES dependency.
            from console.graph import TOUR_CAMPAIGN_ID
            if ident == TOUR_CAMPAIGN_ID:
                doc = {
                    "campaign_id":         TOUR_CAMPAIGN_ID,
                    "name":                "Defense-in-depth SSH persistence",
                    "kind":                "behaviour",
                    "session_count":       275,
                    "ip_count":            73,
                    "first_seen":          "2026-04-29T00:00:00Z",
                    "last_seen":           "2026-05-11T00:00:00Z",
                    "support":             0.93,
                    "member_playbook_ids": ["spb-tour-keylock", "spb-tour-cronlist"],
                    "rationale": (
                        "Two distinct playbooks consistently co-occur across the "
                        "same source IPs, both installing the same RSA key with "
                        "overlapping persistence tactics."
                    ),
                    "_tour": True,
                }
                return _attach_anchor_evidence_quality(IOCDetail(
                    type="campaign", id=ident,
                    title="campaign: Defense-in-depth SSH persistence",
                    summary=doc, raw=None,
                ), es=es, cfg=cfg)
            doc = queries.lookup_campaign(es, cfg, ident)
            if not doc:
                raise HTTPException(404, f"campaign not found: {ident}")
            title = doc.get("name") or ident
            return _attach_anchor_evidence_quality(IOCDetail(
                type="campaign", id=ident, title=f"campaign: {title}",
                summary=doc, raw=None,
            ), es=es, cfg=cfg)
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

    # ------------------------------------------------------------------
    # Write-up (Item #2 of the analyst-first UX push). The Report modal's
    # Write-up tab calls /api/writeup to produce LLM-written prose for
    # four sections (anchor / evidence / MITRE / confidence). Local LLM
    # by default; cloud opt-in gated by cloud.writeup_daily_budget_usd
    # (separate bucket from enrichment escalation).
    # ------------------------------------------------------------------

    def _load_pipeline_state():
        """Lazy-load the parent enrich/ config + secrets + state DB.

        Returns (parent_cfg, parent_secrets, db). Any element may be
        None when the parent config / DB isn't reachable from the
        process running the console (the `dshield_prism` system user
        owns the StateDB path; a console run as a different user can't
        touch it). The local-LLM write-up path doesn't need *any* of
        these, so the caller decides whether a partial load is fatal.
        """
        parent_cfg = parent_secrets = db = None
        try:
            from enrich.config import load_config as _parent_load_config
            from enrich.config import load_secrets as _parent_load_secrets
            parent_cfg = _parent_load_config(config_path)
            parent_secrets = _parent_load_secrets(config_path)
        except Exception as exc:
            log.debug("parent config load failed (non-fatal): %s", exc)
        if parent_cfg is not None:
            try:
                from enrich.cache import StateDB
                db = StateDB(parent_cfg.worker.state_db)
            except Exception as exc:
                log.debug("StateDB open failed (non-fatal): %s", exc)
        return parent_cfg, parent_secrets, db

    @app.get("/api/writeup/budget")
    def writeup_budget() -> JSONResponse:
        """Cloud-budget snapshot for the modal's opt-in checkbox UI.

        Degrades gracefully when the pipeline state isn't reachable —
        the local-LLM path doesn't need the budget at all, so a missing
        StateDB is reported as `cloud_enabled=false` rather than a 500.
        """
        from console.writeup import writeup_budget_status
        parent_cfg, _, db = _load_pipeline_state()
        if parent_cfg is None or db is None:
            return JSONResponse({
                "cap_usd": 0.0, "spent_usd": 0.0, "remaining_usd": 0.0,
                "enabled": False, "available": False, "cloud_enabled": False,
            })
        try:
            return JSONResponse(writeup_budget_status(db, parent_cfg))
        except Exception as exc:
            log.warning("writeup_budget status failed: %s", exc)
            return JSONResponse({
                "cap_usd": 0.0, "spent_usd": 0.0, "remaining_usd": 0.0,
                "enabled": False, "available": False, "cloud_enabled": False,
                "error": str(exc),
            })
        finally:
            try: db.close()
            except Exception: pass

    @app.post("/api/writeup")
    def write_writeup(body: WriteupRequest) -> JSONResponse:
        if not llm_cfg and not body.escalate:
            raise HTTPException(503, "local LLM not configured — add an llm: block to local.yaml")
        parent_cfg, parent_secrets, db = _load_pipeline_state()
        # Cloud escalation strictly requires the parent state (config +
        # secrets + writeup_spend bucket). The local path doesn't.
        if body.escalate and (parent_cfg is None or db is None):
            raise HTTPException(
                503,
                "cloud escalation needs the pipeline's state DB; "
                "run the console as the dshield_prism user or "
                "expose cfg.worker.state_db read+write to this user",
            )
        try:
            from console.writeup import generate_writeup
            result = generate_writeup(
                cfg=parent_cfg,
                secrets=parent_secrets,
                db=db,
                llm_cfg=llm_cfg,
                anchor=body.anchor or {},
                scope=body.scope or {},
                evidence_quality=body.evidence_quality or "",
                escalate=body.escalate,
            )
            return JSONResponse(result)
        except RuntimeError as exc:
            # Budget exhausted / cloud disabled / parse failure — all
            # surface as 400 with the actual reason so the modal can
            # render an honest error to the analyst.
            raise HTTPException(400, str(exc))
        except HTTPException:
            raise
        except Exception as exc:
            log.exception("writeup failed")
            raise HTTPException(500, f"writeup failed: {exc}")
        finally:
            if db is not None:
                try: db.close()
                except Exception: pass

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

def _attach_anchor_evidence_quality(
    detail: IOCDetail, *, es=None, cfg=None,
) -> IOCDetail:
    """Stamp the one-line evidence-quality verdict on an IOCDetail.

    Called by every anchor-detail builder that benefits from a confidence
    surface (playbook / campaign / *_cluster / ip). Empty for kinds where
    a verdict doesn't apply (asn / country / mitre_* / session / command).

    When ``es`` + ``cfg`` are supplied (playbook / campaign anchors),
    the Strong-band cutoff is fetched from `prism.metrics` so the
    verdict scales with the corpus (brutal-review 4.2). Anchors
    without a band shape (ip / *_cluster) ignore thresholds harmlessly.

    Consumed by the graph orientation card via `state.currentDetail.
    evidence_quality` and by /browse + per-IOC artifact pages.
    """
    try:
        from enrich.findings.evidence_quality import (
            band_thresholds, format_anchor_evidence_quality,
        )
        thresholds = None
        if es is not None and cfg is not None:
            try:
                thresholds = band_thresholds(es, cfg)
            except Exception:
                thresholds = None
        verdict = format_anchor_evidence_quality(
            detail.type, detail.summary or {}, thresholds=thresholds,
        )
        if verdict:
            detail.evidence_quality = verdict
    except Exception:
        pass
    return detail


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
    return _attach_anchor_evidence_quality(
        IOCDetail(type="ip", id=ip, title=ip, summary=summary, raw=src)
    )


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
        # Brutal-review 5.7: dual novelty — `novelty_score_external`
        # is populated by the 5.5 writer when an external reference
        # set exists at this layer. Null when no external ref is
        # available (e.g. command layer pre-bootstrap).
        "novelty_score_external": (enr.get("cluster") or {}).get("novelty_score_external"),
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
    return _attach_anchor_evidence_quality(
        IOCDetail(type=f"{kind}_cluster", id=cid,
                  title=f"{kind} cluster {cid}", summary=summary, raw=src)
    )


def _table(r: dict, frm: int, size: int) -> TableResponse:
    rows = [{"_id": h["_id"], **h["_source"]} for h in r["hits"]["hits"]]
    return TableResponse(total=r["hits"]["total"]["value"], rows=rows,
                         page={"from": frm, "size": size})
