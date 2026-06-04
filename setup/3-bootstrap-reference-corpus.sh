#!/usr/bin/env bash
# 3-bootstrap-reference-corpus.sh — (re)build the external reference baseline that
# drives the console "Tradecraft Matches" panel + the external-novelty surface.
#
# Three steps:
#   1. import the Atomic Red Team corpus into prism.reference.cowrie.session
#      (scripts/import_reference_corpus.py — clones ATR from GitHub).
#   2. enrich --reference: LLM-enrich + embed the ATR-derived commands. Reads the
#      reference index ONLY (never your live corpus) and dedups against
#      already-enriched commands, so it costs LLM calls only for ATR commands not
#      already in prism.enriched.cowrie.command.
#   3. cluster sessions --bootstrap-from external: mint the `external`
#      reference_centroids that `cluster sessions` scores live sessions against.
#
# When to run it:
#   - automatically: setup.sh calls this (best-effort) on install.
#   - by hand: after a `pipeline --force` (which wipes reference_session), or for
#     the operator-driven (~quarterly) refresh. See docs/reference-corpus.md.
#
# Needs GitHub egress (the ATR clone) + the embedding model reachable. Safe to
# re-run (idempotent: re-imports, and enrich/cluster are cache-gated).
#
# Usage:  [sudo] bash setup/3-bootstrap-reference-corpus.sh
# Env overrides (same names/defaults as setup.sh):
#   SERVICE_USER   default: dshield_prism
#   INSTALL_DIR    default: /opt/dshield_prism
#   VENV           default: ${INSTALL_DIR}/.venv
#   CONFIG         default: ${INSTALL_DIR}/config/default.yaml
set -euo pipefail

SERVICE_USER="${SERVICE_USER:-dshield_prism}"
INSTALL_DIR="${INSTALL_DIR:-/opt/dshield_prism}"
VENV="${VENV:-${INSTALL_DIR}/.venv}"
CONFIG="${CONFIG:-${INSTALL_DIR}/config/default.yaml}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
log()  { echo -e "${GREEN}==>${RESET} $*"; }
warn() { echo -e "${YELLOW}WARN:${RESET} $*" >&2; }
die()  { echo -e "${RED}ERROR:${RESET} $*" >&2; exit 1; }

[[ -x "${VENV}/bin/python" ]] \
    || die "venv python not found at ${VENV}/bin/python — is the project installed at ${INSTALL_DIR}? (run setup.sh first)"
[[ -f "${INSTALL_DIR}/scripts/import_reference_corpus.py" ]] \
    || die "import_reference_corpus.py not found under ${INSTALL_DIR}/scripts"

# Run a command as the service user. If we're already that user, run directly;
# otherwise (e.g. root) drop privileges with sudo -u.
as_service_user() {
    if [[ "$(id -un)" == "${SERVICE_USER}" ]]; then
        env PRISM_ENV="${INSTALL_DIR}/.env" "$@"
    else
        sudo -u "${SERVICE_USER}" env PRISM_ENV="${INSTALL_DIR}/.env" "$@"
    fi
}
run_cli() { as_service_user "${VENV}/bin/python" -m enrich.cli --config "${CONFIG}" "$@"; }

cd "${INSTALL_DIR}"

log "Bootstrapping external reference corpus (Tradecraft Matches)"
log "  1/3 import Atomic Red Team corpus (clones from GitHub) ..."
as_service_user "${VENV}/bin/python" "${INSTALL_DIR}/scripts/import_reference_corpus.py" --config "${CONFIG}"
log "  2/3 enrich --reference (LLM-enrich + embed the ATR commands; reference index only) ..."
run_cli enrich --reference
log "  3/3 mint external reference centroids ..."
run_cli cluster sessions --bootstrap-from external
log "Done — 'Tradecraft Matches' populates after the next 'cluster sessions'."
