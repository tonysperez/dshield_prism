#!/usr/bin/env bash
# destroy.sh — full uninstall.
#
# Removes every piece of state setup.sh installs, EXCEPT raw cowrie data.
# The destination data stream Filebeat ships into (the value of
# `cfg.elasticsearch.indexes.cowrie.sessions_raw`, default
# `prism.raw.cowrie.session`) is preserved so a subsequent `setup.sh`
# can rebuild every derived index from raw without re-ingesting from
# the honeypot.
#
# Always prompts. No --yes bypass — re-read what you're about to nuke
# every time.
#
# Removes:
#   - systemd timers + services (stopped, disabled, unit files deleted),
#     including dshield_prism-console.service
#   - EVERY project index except the raw data stream — discovered dynamically
#     (all prism.* + lifecycle-* indices, minus prism.raw.*), so the wipe can't
#     drift as new layers ship
#   - ES ingest pipelines — discovered dynamically (every prism.* pipeline,
#     incl. per-sensor wrappers prism.cowrie.session.<sensor>, + the legacy
#     dshield.webhoneypot)
#   - SQLite cache + watermark + intel cache files (the state dir contents)
#   - the install dir (/opt/dshield_prism by default) — this also drops
#     the console venv at /opt/dshield_prism/console/.venv
#
# Preserves:
#   - cfg.elasticsearch.indexes.cowrie.sessions_raw (the raw data stream)
#   - the `prism.raw` index template (load-bearing for the data stream's
#     mappings + rollover; ES refuses to delete templates that are in
#     use anyway)
#   - service user account (run with --remove-user to also remove it)
#   - Filebeat / elastic-agent integration policies in Kibana
#     (you'll want to point them away from the now-missing pipeline
#     before re-running setup.sh)
#
# Usage:
#   sudo bash setup/destroy.sh [--no-es] [--no-systemd] [--no-files]
#                              [--remove-user] [--purge-raw-logs]
#                              [--purge-logs]
#
# Default behavior preserves:
#   - the raw cowrie data stream + its `prism.raw` template (so setup.sh
#     can rebuild without re-ingesting)
#   - everything under LOG_DIR (so post-mortem analysis of a failed run
#     survives the teardown)
#
# --no-* flags skip individual phases (cleanup half the install).
# --remove-user also deletes the dshield_prism system account.
# --purge-raw-logs ALSO deletes:
#     - the `prism.raw.cowrie.session` data stream (raw cowrie history)
#     - the `prism.raw` index template
#   "absolutely nothing remains in ES" mode.
# --purge-logs ALSO deletes:
#     - the LOG_DIR contents (setup.log, destroy.log, cli.log + rotated
#       backups, anything else under /var/log/dshield_prism)
#   Use when decommissioning entirely; skip when you might want forensic
#   logs from a failed pipeline run.
#
# Environment overrides (same as setup.sh):
#   SERVICE_USER   default: dshield_prism
#   INSTALL_DIR    default: /opt/dshield_prism
#   STATE_DIR      default: /var/lib/dshield_prism
#   LOG_DIR        default: /var/log/dshield_prism
#   SYSTEMD_DIR    default: /etc/systemd/system

set -euo pipefail

# ---- configurable ----------------------------------------------------------

SERVICE_USER="${SERVICE_USER:-dshield_prism}"
INSTALL_DIR="${INSTALL_DIR:-/opt/dshield_prism}"
STATE_DIR="${STATE_DIR:-/var/lib/dshield_prism}"
LOG_DIR="${LOG_DIR:-/var/log/dshield_prism}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

DO_ES=1
DO_SYSTEMD=1
DO_FILES=1
REMOVE_USER=0
PURGE_RAW_LOGS=0
PURGE_LOGS=0

# ---- argv ------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-es)            DO_ES=0 ;;
        --no-systemd)       DO_SYSTEMD=0 ;;
        --no-files)         DO_FILES=0 ;;
        --remove-user)      REMOVE_USER=1 ;;
        --purge-raw-logs)   PURGE_RAW_LOGS=1 ;;
        --purge-logs)       PURGE_LOGS=1 ;;
        -h|--help)
            sed -n '1,55p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
    shift
done

# ---- helpers ---------------------------------------------------------------

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

log()  { echo -e "${GREEN}==>${RESET} $*"; }
warn() { echo -e "${YELLOW}WARN:${RESET} $*" >&2; }
die()  { echo -e "${RED}ERROR:${RESET} $*" >&2; exit 1; }

# ---- sanity ----------------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    die "destroy.sh must run as root (touches systemd + system paths)."
fi

# Tee everything from this point onwards into the log dir so a failed
# destroy is auditable later. If LOG_DIR doesn't exist yet (first
# install ever?) create it; if --purge-logs is set we'll remove it
# again in phase 3.
mkdir -p "${LOG_DIR}"
chmod 750 "${LOG_DIR}" 2>/dev/null || true
exec > >(tee -a "${LOG_DIR}/destroy.log") 2>&1
log "Tee'ing output to ${LOG_DIR}/destroy.log"

# ---- confirmation ----------------------------------------------------------

echo "${RED}destroy.sh${RESET} — about to remove:"
(( DO_SYSTEMD )) && echo "  - systemd timers + services + unit files"
if (( DO_ES )); then
    if [[ -x "${INSTALL_DIR}/.venv/bin/python" ]]; then
        echo "  - every project index EXCEPT raw (all prism.*/lifecycle-*, discovered dynamically)"
        echo "  - every project ingest pipeline (prism.*, incl. per-sensor wrappers; + dshield.webhoneypot)"
        if (( PURGE_RAW_LOGS )); then
            echo "  ${RED}- ES raw cowrie data stream (prism.raw.cowrie.session)${RESET}"
            echo "  ${RED}- ES index template (prism.raw)${RESET}"
            echo "    ${RED}EVERY project artifact in ES will be gone after this run.${RESET}"
        else
            echo "    (raw data stream + prism.raw template PRESERVED — pass --purge-raw-logs to also remove)"
        fi
    else
        echo "  - ES wipe: ${YELLOW}SKIPPED${RESET} (no installed venv at ${INSTALL_DIR}/.venv — pass --no-es to silence)"
    fi
fi
(( DO_FILES )) && echo "  - ${INSTALL_DIR} (install dir)"
(( DO_FILES )) && echo "  - ${STATE_DIR} (state dir, SQLite, intel cache files)"
if (( DO_FILES && PURGE_LOGS )); then
    echo "  ${RED}- ${LOG_DIR} (every log file, including this run's destroy.log)${RESET}"
elif (( DO_FILES )); then
    echo "    (${LOG_DIR} PRESERVED — pass --purge-logs to also remove)"
fi
(( REMOVE_USER )) && echo "  - service user ${SERVICE_USER}"

echo
read -rp "Type 'destroy' to confirm: " CONFIRM
if [[ "${CONFIRM}" != "destroy" ]]; then
    echo "Aborted."
    exit 1
fi

# ---- phase 1: systemd -------------------------------------------------------

if (( DO_SYSTEMD )); then
    log "Phase 1 — systemd"
    for unit in \
        dshield_prism-mine-findings.timer \
        dshield_prism-mine-findings.service \
        dshield_prism-backward.timer \
        dshield_prism-backward.service \
        dshield_prism-forward.timer \
        dshield_prism-forward.service \
        dshield_prism-console.service
    do
        # Stop + disable, even if not currently enabled (systemctl is
        # idempotent and returns 0 in the absence-of-unit case as long
        # as we suppress its stderr).
        systemctl stop    "${unit}" 2>/dev/null || true
        systemctl disable "${unit}" 2>/dev/null || true
        if [[ -f "${SYSTEMD_DIR}/${unit}" ]]; then
            rm -f "${SYSTEMD_DIR}/${unit}"
            log "  removed ${unit}"
        fi
    done
    systemctl daemon-reload
fi

# ---- phase 2: Elasticsearch ------------------------------------------------

if (( DO_ES )); then
    log "Phase 2 — Elasticsearch"
    if [[ ! -x "${INSTALL_DIR}/.venv/bin/python" ]]; then
        warn "  no venv at ${INSTALL_DIR}/.venv — skipping ES wipe."
        warn "  if you need to delete ES state too, restore the install dir or"
        warn "  delete the indices manually in Kibana DevTools."
    else
        # Inline Python that uses the project's own ES client (TLS +
        # auth identical to the rest of the pipeline). Lists exactly what
        # it deletes, swallows 404s. The `PURGE_RAW_LOGS` env var
        # (sourced from --purge-raw-logs) opts into deleting the raw
        # data stream + template too; default leaves them in place.
        PURGE_RAW_LOGS="${PURGE_RAW_LOGS}" \
        "${INSTALL_DIR}/.venv/bin/python" - <<'PYEOF'
import os
import sys
sys.path.insert(0, "/opt/dshield_prism/src")
from enrich.config import load_config, load_secrets
from enrich.es_client import make_client

cfg = load_config("/opt/dshield_prism/config/default.yaml")
sec = load_secrets("/opt/dshield_prism/config/default.yaml")
es = make_client(cfg.elasticsearch, sec)

purge_raw = os.environ.get("PURGE_RAW_LOGS") == "1"


def _is_raw(name):
    # Raw source-of-truth lives under prism.raw.* (cowrie + firewall); the
    # data streams' backing indices are .ds-prism.raw.*. Never deleted unless
    # --purge-raw-logs. Substring match covers both forms.
    return "prism.raw" in name


# Indices: discovered dynamically so the wipe can't drift as new layers ship.
# Everything the project owns is prism.* or lifecycle-*; the only thing kept by
# default is the raw (prism.raw.*). expand_wildcards excludes hidden so the raw
# data-stream backing (.ds-prism.raw.*) never even enters the candidate set;
# the _is_raw guard is belt-and-suspenders.
try:
    rows = es.cat.indices(index="prism.*,lifecycle-*", format="json", h="index",
                          expand_wildcards="open,closed")
    found = sorted(r["index"] for r in rows if r.get("index"))
except Exception as exc:
    found = []
    print(f"  index discovery ERROR: {exc}", file=sys.stderr)

n_deleted = 0
for idx in found:
    if _is_raw(idx):
        print(f"  index skip (raw):  {idx}")
        continue
    try:
        es.indices.delete(index=idx)
        print(f"  index deleted: {idx}")
        n_deleted += 1
    except Exception as exc:
        print(f"  index ERROR:   {idx}: {exc}", file=sys.stderr)
print(f"  ({n_deleted} processed index(es) deleted, raw left intact)")

# Raw data streams — deleted only with --purge-raw-logs. Must come BEFORE the
# template delete; ES refuses to drop a template a data stream still references.
try:
    ds = es.indices.get_data_stream(name="prism.raw.*").get("data_streams", [])
    raw_streams = sorted(d["name"] for d in ds)
except Exception:
    raw_streams = []
raw_label = ", ".join(raw_streams) if raw_streams else "prism.raw.* (none present)"
if purge_raw:
    for raw_ds in raw_streams:
        try:
            es.indices.delete_data_stream(name=raw_ds)
            print(f"  data stream deleted: {raw_ds}")
        except Exception as exc:
            print(f"  data stream ERROR:   {raw_ds}: {exc}", file=sys.stderr)
else:
    print(f"  data stream skip:    {raw_label} (preserved; --purge-raw-logs to delete)")

# Ingest pipelines: discover the project's (prism.* incl. per-sensor wrappers,
# plus the legacy dshield.webhoneypot) rather than a hardcoded list. Fleet /
# system pipelines (1000s of them) are left untouched.
try:
    proj_pipes = sorted(
        p for p in es.ingest.get_pipeline()
        if p.startswith("prism.") or p == "dshield.webhoneypot"
    )
except Exception as exc:
    proj_pipes = []
    print(f"  pipeline discovery ERROR: {exc}", file=sys.stderr)
for pip in proj_pipes:
    try:
        es.ingest.delete_pipeline(id=pip)
        print(f"  pipeline deleted: {pip}")
    except Exception as exc:
        print(f"  pipeline ERROR:   {pip}: {exc}", file=sys.stderr)
if not proj_pipes:
    print("  pipelines: none matching prism.* / dshield.webhoneypot")

# Index template — only deletable once the data stream that uses it is gone, so
# only with --purge-raw-logs.
if purge_raw:
    try:
        es.indices.delete_index_template(name="prism.raw")
        print("  template deleted: prism.raw")
    except Exception as exc:
        msg = str(exc).lower()
        if "404" in msg or "missing" in msg or "not found" in msg:
            print("  template absent:  prism.raw")
        else:
            print(f"  template ERROR:   prism.raw: {exc}", file=sys.stderr)
else:
    print("  template skip:    prism.raw (in use by preserved data stream)")

if purge_raw:
    print("\n  EVERYTHING in ES is gone — no project artifacts remain.")
else:
    print(f"\n  PRESERVED raw: {raw_label} (+ prism.raw template)")
PYEOF
    fi
fi

# ---- phase 3: filesystem ---------------------------------------------------

if (( DO_FILES )); then
    log "Phase 3 — filesystem"
    if [[ -d "${STATE_DIR}" ]]; then
        rm -rf "${STATE_DIR}"
        log "  removed ${STATE_DIR}"
    fi
    if [[ -d "${INSTALL_DIR}" ]]; then
        rm -rf "${INSTALL_DIR}"
        log "  removed ${INSTALL_DIR}"
    fi
    # Log dir is preserved by default (forensic value after a failed run).
    # --purge-logs nukes it. Note: this also removes the destroy.log we
    # just wrote to, so output beyond this point is journal-only.
    if (( PURGE_LOGS )) && [[ -d "${LOG_DIR}" ]]; then
        rm -rf "${LOG_DIR}"
        log "  removed ${LOG_DIR}"
    elif [[ -d "${LOG_DIR}" ]]; then
        log "  ${LOG_DIR}: preserved (pass --purge-logs to remove)"
    fi
fi

# ---- phase 4: user account (opt-in) ----------------------------------------

if (( REMOVE_USER )); then
    log "Phase 4 — service user"
    if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
        # Remove the user. --remove would also delete the home dir, but
        # we already deleted INSTALL_DIR above, so plain userdel is enough.
        userdel "${SERVICE_USER}" 2>/dev/null || warn "  userdel ${SERVICE_USER} returned non-zero"
        log "  removed ${SERVICE_USER}"
    else
        log "  ${SERVICE_USER}: not present"
    fi
fi

# ---- done ------------------------------------------------------------------

cat <<EOF

${GREEN}destroy.sh complete.${RESET}

What survives:
EOF
if (( PURGE_RAW_LOGS && DO_ES )); then
cat <<EOF
  - nothing in Elasticsearch — every project artifact (indices, data
    stream, template, pipelines) has been removed.
  - Filebeat will auto-recreate an empty data stream on its next event,
    but WITHOUT mapping settings until bootstrap-es runs again.
EOF
else
cat <<EOF
  - raw cowrie data stream in Elasticsearch (Filebeat keeps writing into it)
  - the prism.raw index template (load-bearing for the data stream's mappings)
EOF
fi
cat <<EOF
  - the cowrie integration policy in Kibana / Fleet — its 'pipeline:' field
    still references a now-deleted pipeline name. Repoint it before the
    next setup.sh, or expect indexing failures.
  - the repository source on this box (this script lives in it)

To reinstall from scratch:
  sudo bash setup/setup.sh
EOF
if (( ! PURGE_RAW_LOGS && DO_ES )); then
cat <<EOF

The raw data the honeypot has shipped since destroy.sh ran is still in ES,
so the next pipeline run will pick up where the corpus left off.
EOF
fi
