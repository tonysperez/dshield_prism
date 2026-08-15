"""Console Tune page wiring (spec-tune-page-rules + spec-grounding-precompute).

Verifies the merge/retire wiring without a live ES:

  * NAV carries a single "tune" item; the old "rules" / "curation" items
    are gone.
  * `build_app` registers `/tune`, and `/curation` + `/artifact-rules`
    are 302 redirects to `/tune` (old bookmarks survive).
  * The retired full-scan surface (`/api/health/commands` and its old
    denylist routes) is no longer registered.
  * The spec-grounding-precompute routes ARE registered: the O(1)
    `/api/health/grounding-coverage` + `/api/tune/grounding-coverage` reads,
    and the POST/DELETE denylist write routes at their new `/api/tune/...`
    paths.
  * The Tune template exists and the retired templates are gone.

Offline — the ES client factory is stubbed so `build_app` constructs
without touching a cluster; route registration never calls ES.

Run from the repo root via the console venv:
    /home/styx/git/dshield_prism/console/.venv/bin/python \\
      scripts/smoke/smoke_test_tune_page.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "src"))
sys.path.insert(0, str(REPO / "src"))

from console import server

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name if ok else (name, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if not ok else ""))


# --- NAV_ITEMS -------------------------------------------------------------
nav_ids = {i["id"] for i in server.NAV_ITEMS}
check("nav has 'tune'", "tune" in nav_ids, str(nav_ids))
check("nav dropped 'rules' + 'curation'",
      "rules" not in nav_ids and "curation" not in nav_ids, str(nav_ids))
tune_item = next((i for i in server.NAV_ITEMS if i["id"] == "tune"), {})
check("tune nav href is /tune", tune_item.get("href") == "/tune", str(tune_item))

# --- Route wiring (ES stubbed) ---------------------------------------------
server.make_client = lambda *a, **k: object()  # type: ignore[assignment]
app = server.build_app(str(REPO / "config" / "default.yaml"))
paths = {r.path for r in app.routes}

check("/tune registered", "/tune" in paths, str(sorted(p for p in paths if 'tune' in p)))
check("/curation still registered (redirect)", "/curation" in paths)
check("/artifact-rules still registered (redirect)", "/artifact-rules" in paths)
check("/api/health/commands removed", "/api/health/commands" not in paths)
check("old denylist routes removed",
      not any(p.startswith("/api/health/commands/denylist") for p in paths))

# --- spec-grounding-precompute routes ---------------------------------------
check("/api/health/grounding-coverage registered",
      "/api/health/grounding-coverage" in paths, str(sorted(p for p in paths if 'grounding' in p)))
check("/api/tune/grounding-coverage registered",
      "/api/tune/grounding-coverage" in paths, str(sorted(p for p in paths if 'grounding' in p)))
check("POST denylist route registered",
      "/api/tune/grounding-coverage/denylist" in paths, str(sorted(p for p in paths if 'grounding' in p)))
check("DELETE denylist/{token} route registered",
      "/api/tune/grounding-coverage/denylist/{token}" in paths,
      str(sorted(p for p in paths if 'grounding' in p)))

# --- Redirect behaviour ----------------------------------------------------
def _endpoint(path: str):
    return next(r.endpoint for r in app.routes if r.path == path)


for legacy in ("/curation", "/artifact-rules"):
    resp = _endpoint(legacy)(None)  # redirect handlers ignore the request
    ok = getattr(resp, "status_code", None) == 302 and \
        resp.headers.get("location") == "/tune"
    check(f"{legacy} → 302 /tune", ok,
          f"status={getattr(resp, 'status_code', None)} loc={resp.headers.get('location')}")

# --- Templates -------------------------------------------------------------
tpl = REPO / "console" / "src" / "console" / "templates"
check("tune.html exists", (tpl / "tune.html").exists())
check("curation.html removed", not (tpl / "curation.html").exists())
check("artifact_rules.html removed", not (tpl / "artifact_rules.html").exists())

# --- health module gone ----------------------------------------------------
check("console.health module deleted",
      not (REPO / "console" / "src" / "console" / "health.py").exists())

# --- pipeline-cfg resolution is cwd-robust ---------------------------------
# Regression: the artifact-rule endpoints 500'd with FileNotFoundError when
# `serve` was launched from inside console/ (its cwd) — the pipeline loader
# defaulted to the cwd-relative `config/default.yaml`. `_get_pipeline_cfg` now
# falls back to the console's `_default_config_path()`, which also probes
# `../config/default.yaml`. Offline: reads YAML only, no ES.
import os

from console._config import _default_config_path

from enrich.config import load_config as _pipeline_load_config

_prev_cwd = os.getcwd()
try:
    os.chdir(REPO / "console")
    _cfg = _pipeline_load_config(_default_config_path())
    check("pipeline cfg loads from console/ cwd",
          bool(_cfg.analyst.indexes.artifact_rules),
          "artifact_rules index resolved")
except Exception as exc:  # FileNotFoundError would be the regression
    check("pipeline cfg loads from console/ cwd", False, f"{type(exc).__name__}: {exc}")
finally:
    os.chdir(_prev_cwd)


# ---------------------------------------------------------------------------
print()
print(f"=== {len(PASSED)} passed, {len(FAILED)} failed ===")
if FAILED:
    for name, detail in FAILED:
        print(f"  - {name}: {detail}")
    sys.exit(1)
sys.exit(0)
