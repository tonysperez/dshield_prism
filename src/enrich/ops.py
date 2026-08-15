"""prism.ops — per-run pipeline telemetry (P4.2).

Each tracked CLI verb writes a ``started`` doc on entry and patches it to
``finished``/``failed`` on exit, so operators and the console (P4.3) can see
what ran, when, how long, and whether it failed — including the systemd-driven
forward/backward steps, each of which is its own verb process.

Best-effort by design: a telemetry failure must never affect the verb it
observes, so every entry point swallows exceptions and returns/does nothing on
error. Skips silently when the ``prism.ops`` index doesn't exist yet (deploys
that haven't run ``init-indexes --source ops``) — no auto-create.
"""
from __future__ import annotations

import logging
import os
import socket
import time
import uuid
from datetime import UTC, datetime

from .__about__ import CLI_NAME, ENV_PREFIX
from .config import AppConfig, Secrets

log = logging.getLogger(__name__)

# Mirrors `console.queries._ADHOC_UNIT`. Only used to reject it as a literal
# env-var value — the console, not the writer, owns the bucket itself.
_ADHOC_UNIT_LABEL = "manual / ad-hoc"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def run_start(cfg: AppConfig, secrets: Secrets, verb: str) -> dict | None:
    """Write a ``started`` ops doc and return a handle for `run_finish`.

    Returns ``None`` (a no-op handle) on any failure or when the index is
    absent — never raises.
    """
    try:
        from .es_client import make_client
        es = make_client(cfg.elasticsearch, secrets)
        idx = cfg.ops.indexes.default
        if not es.indices.exists(index=idx):
            return None
        run_id = str(uuid.uuid4())
        doc = {
            "kind":       "verb_run",
            "run_id":     run_id,
            "verb":       verb,
            "host":       socket.gethostname(),
            "status":     "started",
            "started_at": _now_iso(),
        }
        # Owning systemd unit, if any. Each unit file sets this to `%n`, which
        # systemd expands to the full unit name — so attribution follows the
        # unit files without a hand-maintained unit->verb map. Absent for a
        # manual CLI run; the console groups those as "manual / ad-hoc". The
        # key is omitted rather than set to None because `prism.ops` is
        # `dynamic: strict` and a null adds nothing the console can group on.
        # The console's own bucket label is rejected so a stray export can't
        # merge real unit runs into the manual bucket.
        unit = (os.environ.get(f"{ENV_PREFIX}SYSTEMD_UNIT") or "").strip()
        if unit and unit != _ADHOC_UNIT_LABEL:
            doc["unit"] = unit
        try:
            es.index(index=idx, id=run_id, document=doc)
        except Exception:
            # `prism.ops` is `dynamic: strict`, so a deploy that adds a field
            # before `init-indexes --update-mapping --source ops` is applied
            # gets EVERY doc rejected — and with it the console's run panel,
            # the running banner and the health badge, silently. Retry once
            # without the new field so telemetry degrades to pre-`unit`
            # behaviour instead of vanishing.
            if "unit" not in doc:
                raise
            log.warning(
                "ops: %s rejected the `unit` field — retrying without it. "
                "Run `%s init-indexes --update-mapping --source ops` to "
                "restore unit attribution.", idx, CLI_NAME,
            )
            doc.pop("unit", None)
            es.index(index=idx, id=run_id, document=doc)
        return {"es": es, "index": idx, "run_id": run_id, "t0": time.monotonic()}
    except Exception as exc:
        log.debug("ops run_start(%s) failed: %s", verb, exc)
        return None


def run_finish(
    cfg: AppConfig,
    secrets: Secrets,
    handle: dict | None,
    *,
    status: str,
    rc: int | None = None,
    error: str | None = None,
) -> None:
    """Patch the started doc to ``finished``/``failed`` with timing. No-op on a
    ``None`` handle. Best-effort, never raises."""
    if not handle:
        return
    try:
        doc: dict = {
            "status":      status,
            "finished_at": _now_iso(),
            "duration_s":  round(time.monotonic() - handle["t0"], 3),
        }
        if rc is not None:
            doc["rc"] = int(rc)
        if error:
            doc["error"] = error[:2000]
        handle["es"].update(index=handle["index"], id=handle["run_id"], doc=doc)
    except Exception as exc:
        log.debug("ops run_finish failed: %s", exc)
