#!/usr/bin/env bash
# 2-setup.sh — one-shot Security Onion-side installer for enrich.
#
# Idempotent. Safe to re-run on a fresh node OR an existing deploy to upgrade.
# Requires root (or sudo).
#
# Prerequisites BEFORE running:
#   1. This repo is on the SO box (any path; the script will rsync to INSTALL_DIR).
#   2. config/local.yaml (or local.yml) is filled in with your LLM + ES settings.
#   3. .env is filled in with ES credentials (and optionally ANTHROPIC_API_KEY).
#   4. The GPU-side LLM server is reachable from this box (Ollama / LM Studio).
#
# Steps performed (each is a no-op if already done):
#   A. Sanity checks (root, python >= 3.11, source files, .env + local config)
#   B. Create system user + state directory
#   C. Rsync source → INSTALL_DIR
#   D. Create venv + pip install (base package + [cluster] extra)
#   D2. (opt-in via --ufw) Add UFW rules for outbound traffic:
#        - allow out to ES host:port (parsed from local.yaml, skipped if loopback)
#        - allow out to LLM host:port (parsed from local.yaml, skipped if loopback)
#        - allow out 443/tcp (intel feeds + Anthropic cloud API)
#        - (opt-in via --ufw-console) allow in 8765/tcp for console web UI
#       No-op if ufw is not installed or not active. Idempotent — ufw skips
#       rules that already exist.
#   E. Apply ES templates + ingest pipelines + raw data stream from setup/:
#        prism.raw index template (data stream + ILM for raw event store)
#        prism.cowrie.session ingest pipeline (ECS normalization + reroute)
#        prism.raw.cowrie.session data stream (pre-created empty so the
#          healthcheck's raw-index existence check passes on first deploy)
#   F. Init project-owned processed indices, additive-mapping safe:
#        cowrie    (commands, sessions, ips + their cluster centroids + campaigns)
#        intel     (prism.intel.{ip,url} — populated by `intel refresh`)
#        findings  (prism.finding — populated by `mine findings`)
#   G. Run healthcheck (ES + local LLM + SQLite + cloud connectivity)
#   H. Install + enable systemd timers:
#        dshield_prism-forward.timer
#          → healthcheck + enrich + rollup sessions + rollup ips
#            (every 30 min; watermark-driven forward pass)
#        dshield_prism-backward.timer
#          → re-enrich-stale + reembed + reset rollup watermarks
#            + re-rollup + cluster commands/sessions/ips
#            + escalate + name playbooks + name ip-clusters
#            + mine campaigns + track lifecycles + intel refresh
#            + mine findings
#            (every 6h; `cluster sessions` windows to the last 30 days
#             per session.cluster_window_days — P1.2. `cluster ips` self-gates
#             on ip.full_recluster_weekly — runs the incremental nearest-centroid
#             assign here when set, B0.5)
#        dshield_prism-recluster-full.timer
#          → weekly full `cluster sessions --window-days 0
#            --refresh-reference` + `cluster ips --window-days 0
#            --refresh-reference` (B0.5 — the only full IP fit when
#            ip.full_recluster_weekly=true; also the IP reference's only
#            periodic refresh) + prune-clusters (re-pools the long tail
#            and refreshes the reference_centroid set the windowed 6h runs
#            score against)
#        All timers serialise on /var/lib/dshield_prism/.lock via flock.
#        `mine findings` is inlined into the backward chain so it always
#        runs after `name playbooks` — the legacy
#        dshield_prism-mine-findings.{service,timer} are removed by this
#        script if present from a prior install.
#   I. Install /usr/local/bin/prism wrapper. Lets operators run e.g.
#        `prism healthcheck` from any cwd in any shell — same as
#        `sudo -u dshield_prism ${VENV}/bin/python -m enrich.cli ...`.
#
# Console install (default on; opt out with --no-console):
#   - Builds a separate venv at /opt/dshield_prism/console/.venv
#     (FastAPI/uvicorn/jinja2 — not in the parent package).
#   - Installs dshield_prism-console.service from setup/../systemd/.
#   - Enables + starts the unit. Binds 0.0.0.0:8765 — make sure your
#     perimeter firewall blocks WAN, or use --no-console and run it
#     manually with --host 127.0.0.1 behind an ssh tunnel.
#
# Skipped on purpose (first run can take hours on a backlog):
#   - Initial enrichment + clustering pass. Trigger manually after setup:
#       sudo systemctl start dshield_prism-forward.service
#       sudo systemctl start dshield_prism-backward.service
#     Or via the CLI:
#       sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/.venv/bin/python" \
#         -m enrich.cli enrich
#
# Usage:
#   sudo bash setup/2-setup.sh [--no-systemd] [--skip-healthcheck] [--skip-init-index]
#                            [--no-console] [--ufw] [--ufw-console]
#
# Environment overrides:
#   SERVICE_USER   default: dshield_prism
#   INSTALL_DIR    default: /opt/dshield_prism
#   STATE_DIR      default: /var/lib/dshield_prism
#   LOG_DIR        default: /var/log/dshield_prism
#   SYSTEMD_DIR    default: /etc/systemd/system
#   PYTHON_BIN     default: python3

set -euo pipefail

# ---- configurable ----------------------------------------------------------

SERVICE_USER="${SERVICE_USER:-dshield_prism}"
INSTALL_DIR="${INSTALL_DIR:-/opt/dshield_prism}"
STATE_DIR="${STATE_DIR:-/var/lib/dshield_prism}"
LOG_DIR="${LOG_DIR:-/var/log/dshield_prism}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

INSTALL_SYSTEMD=1
RUN_HEALTHCHECK=1
RUN_INIT_INDEX=1
INSTALL_CONSOLE=1
INSTALL_UFW=0
OPEN_CONSOLE_PORT=0
CONSOLE_PORT="${CONSOLE_PORT:-8765}"

# ---- argv ------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-systemd)       INSTALL_SYSTEMD=0 ;;
        --skip-healthcheck) RUN_HEALTHCHECK=0 ;;
        --skip-init-index)  RUN_INIT_INDEX=0 ;;
        --no-console)       INSTALL_CONSOLE=0 ;;
        --ufw)              INSTALL_UFW=1 ;;
        --ufw-console)      INSTALL_UFW=1; OPEN_CONSOLE_PORT=1 ;;
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

# When both --ufw is enabled AND the console is being installed, auto-open
# the console port. The systemd-managed console binds 0.0.0.0:8765, so
# closing UFW on that port would silently break LAN access — make the
# rule track the install rather than requiring a second flag. Users who
# want the rule WITHOUT the service can still pass --no-console + --ufw-console.
if (( INSTALL_UFW && INSTALL_CONSOLE )); then
    OPEN_CONSOLE_PORT=1
fi

# ---- helpers ---------------------------------------------------------------

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

log()  { echo -e "${GREEN}==>${RESET} $*"; }
warn() { echo -e "${YELLOW}WARN:${RESET} $*" >&2; }
die()  { echo -e "${RED}ERROR:${RESET} $*" >&2; exit 1; }

trap 'die "command failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# ---- A. sanity checks -------------------------------------------------------

log "Sanity checks"

if [[ "${EUID}" -ne 0 ]]; then
    die "This script must run as root (use sudo)."
fi

# Create the log dir + start teeing stdout/stderr into it as early as
# possible (right after the root check, before any heavier work). The
# tee lives via a file-redirection process-substitution so all
# subsequent log/warn/die output is captured. Use --append so re-running
# 2-setup.sh appends to a single audit-trail log file rather than
# truncating each invocation.
mkdir -p "${LOG_DIR}"
chmod 750 "${LOG_DIR}"
exec > >(tee -a "${LOG_DIR}/setup.log") 2>&1
log "Tee'ing output to ${LOG_DIR}/setup.log"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    die "${PYTHON_BIN} not found in PATH. Install Python 3.11+ first."
fi
PY_VER="$("${PYTHON_BIN}" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER##*.}"
if (( PY_MAJOR < 3 )) || { (( PY_MAJOR == 3 )) && (( PY_MINOR < 11 )); }; then
    die "Python ${PY_VER} too old; need >= 3.11."
fi
log "  python: ${PY_VER}"

REQUIRED_FILES=(
    "${SRC_DIR}/pyproject.toml"
    "${SRC_DIR}/src/enrich/cli.py"
    "${SRC_DIR}/src/enrich/sources/cowrie/commands.py"
    "${SRC_DIR}/src/enrich/sources/cowrie/sessions.py"
    "${SRC_DIR}/src/enrich/sources/cowrie/ips.py"
    "${SRC_DIR}/config/default.yaml"
    "${SRC_DIR}/config/prompts/command_enrichment.txt"
    "${SRC_DIR}/config/prompts/command_deep_dive.txt"
    "${SRC_DIR}/config/prompts/playbook_name.txt"
    "${SRC_DIR}/setup/es-mappings/cowrie/commands.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/command_clusters.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/sessions.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/session_clusters.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/ips.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/ip_clusters.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/campaigns.json"
    "${SRC_DIR}/setup/es-mappings/intel/ip.json"
    "${SRC_DIR}/setup/es-mappings/intel/url.json"
    "${SRC_DIR}/setup/es-mappings/findings/default.json"
    "${SRC_DIR}/setup/prism.raw_template.yaml"
    "${SRC_DIR}/setup/es-pipelines/cowrie-pipeline.yml"
    "${SRC_DIR}/systemd/dshield_prism-forward.service"
    "${SRC_DIR}/systemd/dshield_prism-forward.timer"
    "${SRC_DIR}/systemd/dshield_prism-backward.service"
    "${SRC_DIR}/systemd/dshield_prism-backward.timer"
    "${SRC_DIR}/systemd/dshield_prism-recluster-full.service"
    "${SRC_DIR}/systemd/dshield_prism-recluster-full.timer"
    "${SRC_DIR}/systemd/dshield_prism-backfill.service"
    "${SRC_DIR}/setup/3-bootstrap-reference-corpus.sh"
)
for required in "${REQUIRED_FILES[@]}"; do
    [[ -f "${required}" ]] || die "Missing source file: ${required}"
done

if [[ ! -s "${SRC_DIR}/.env" ]]; then
    die "Missing or empty .env at ${SRC_DIR}/.env. Copy .env.example and fill it in."
fi
# Lock down the source .env too (it holds ES creds, the cloud LLM key, and
# intel-provider keys). The deployed copy is chmodded after rsync below; this
# covers the working copy so it isn't left world-readable.
chmod 600 "${SRC_DIR}/.env" 2>/dev/null || true
if ! grep -qE '^(ES_API_KEY|ES_USERNAME)=' "${SRC_DIR}/.env"; then
    die ".env must define ES_API_KEY or ES_USERNAME/ES_PASSWORD."
fi

LOCAL_CFG=""
for f in "${SRC_DIR}/config/local.yaml" "${SRC_DIR}/config/local.yml"; do
    [[ -f "${f}" ]] && LOCAL_CFG="${f}" && break
done
if [[ -z "${LOCAL_CFG}" ]]; then
    die "No config/local.yaml or config/local.yml. Copy config/local.yaml.example and edit."
fi
log "  local config: ${LOCAL_CFG}"

if grep -q 'CHANGE_ME' "${SRC_DIR}/config/default.yaml" "${LOCAL_CFG}" 2>/dev/null \
   && ! grep -qE '^[^#]*base_url:' "${LOCAL_CFG}"; then
    die "llm.base_url not set in ${LOCAL_CFG} (still 'CHANGE_ME')."
fi

command -v rsync >/dev/null 2>&1 || die "rsync not found; please install it."

# ---- B. user + state dir ---------------------------------------------------

log "Service user: ${SERVICE_USER}"
if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    log "  user already exists"
else
    useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
    log "  user created"
fi

log "State directory: ${STATE_DIR}"
mkdir -p "${STATE_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${STATE_DIR}"
chmod 750 "${STATE_DIR}"

# Now that the service user exists, hand the log dir over so the CLI
# (running as that user under systemd) can rotate cli.log there.
# setup.log itself stays root-owned — root wrote it via tee — but the
# group is set to the service user so the CLI can append if needed.
log "Log directory: ${LOG_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
chmod 750 "${LOG_DIR}"

# ---- C. deploy source ------------------------------------------------------

log "Deploying source to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

rsync -a --delete \
    --exclude='.venv/' \
    --exclude='__pycache__/' \
    --exclude='*.egg-info/' \
    --exclude='*.pyc' \
    --exclude='.git/' \
    "${SRC_DIR}/" "${INSTALL_DIR}/"

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
chmod 600 "${INSTALL_DIR}/.env" 2>/dev/null || true
chmod 600 "${INSTALL_DIR}/config/local.yaml" 2>/dev/null || true
chmod 600 "${INSTALL_DIR}/config/local.yml"  2>/dev/null || true

# ---- D. venv + install -----------------------------------------------------

VENV="${INSTALL_DIR}/.venv"
if [[ -x "${VENV}/bin/python" ]]; then
    log "Reusing existing venv at ${VENV}"
else
    log "Creating venv at ${VENV}"
    sudo -u "${SERVICE_USER}" "${PYTHON_BIN}" -m venv "${VENV}"
fi

log "Installing project (base package + [cluster] extra)"
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet --upgrade pip
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet -e "${INSTALL_DIR}[cluster]"

if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'import enrich' >/dev/null 2>&1
then
    die "Post-install import failed. Check pip output above."
fi
if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'from sklearn.cluster import HDBSCAN' >/dev/null 2>&1
then
    die "Cluster deps import failed (sklearn.cluster.HDBSCAN not found)."
fi
if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'from enrich.sources.cowrie import commands, sessions, ips' >/dev/null 2>&1
then
    die "Cowrie source modules failed to import. Check pip output above."
fi

# Helper: run the CLI as the service user with the right env + cwd.
run_cli() {
    sudo -u "${SERVICE_USER}" env \
        PRISM_ENV="${INSTALL_DIR}/.env" \
        "${VENV}/bin/python" -m enrich.cli \
        --config "${INSTALL_DIR}/config/default.yaml" "$@"
}

# ---- D2. UFW rules (opt-in via --ufw / --ufw-console) ----------------------
# Add outbound allows for the endpoints this deploy actually talks to:
#   - ES host:port            (parsed from local.yaml; skipped if loopback)
#   - LLM host:port           (parsed from local.yaml; skipped if loopback)
#   - 443/tcp                 (intel feeds + Anthropic cloud API)
# And, only if --ufw-console was passed, allow inbound on the console port.
# Idempotent: `ufw allow` is a no-op when the rule already exists.

if (( INSTALL_UFW )); then
    log "Configuring UFW rules"

    if ! command -v ufw >/dev/null 2>&1; then
        warn "  ufw not installed; skipping UFW configuration"
    elif ! ufw status 2>/dev/null | grep -q "^Status: active"; then
        warn "  ufw is installed but inactive; skipping (enable with 'ufw enable' and re-run with --ufw)"
    else
        # Parse ES + LLM endpoints from default.yaml + local.yaml overlay,
        # then resolve any hostnames to IPs so we emit one rule per A/AAAA
        # record. UFW doesn't reliably accept hostnames in rules (some
        # versions reject them, others snapshot the IP without re-checking),
        # so doing the resolution here keeps the failure mode visible and
        # supports multi-IP clusters.
        # Uses the venv's PyYAML (declared in pyproject.toml). Emits one
        # line per (endpoint, resolved IP):
        #   KIND <ip> <port> <original-host>
        # or, when DNS resolution fails:
        #   UNRESOLVED KIND <host> <port>
        # Loopback IPs (including hostnames that resolve to 127.0.0.0/8 via
        # /etc/hosts) are filtered out in Python so bash just iterates.
        ENDPOINTS="$(sudo -u "${SERVICE_USER}" "${VENV}/bin/python" - <<'PYEOF'
import ipaddress, socket, sys, urllib.parse, yaml

def parse(url):
    p = urllib.parse.urlparse(url)
    if not p.hostname:
        return None, None
    port = p.port
    if port is None:
        port = 443 if p.scheme == "https" else (80 if p.scheme == "http" else None)
    if port is None:
        return None, None
    return p.hostname, port

def is_loopback(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_loopback
    except ValueError:
        return False

def resolve(host):
    # IP literal -> use as-is.
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    if host == "localhost":
        return ["127.0.0.1"]  # caught by is_loopback below
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return None  # signals unresolved
    seen, ips = set(), []
    for _, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips

def merge(a, b):
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            merge(a[k], v)
        else:
            a[k] = v

with open("/opt/dshield_prism/config/default.yaml") as f:
    cfg = yaml.safe_load(f) or {}
for lp in ("/opt/dshield_prism/config/local.yaml", "/opt/dshield_prism/config/local.yml"):
    try:
        with open(lp) as f:
            merge(cfg, yaml.safe_load(f) or {})
        break
    except FileNotFoundError:
        continue

def emit(kind, url):
    host, port = parse(url)
    if not host:
        return
    ips = resolve(host)
    if ips is None:
        print(f"UNRESOLVED {kind} {host} {port}")
        return
    for ip in ips:
        if is_loopback(ip):
            continue
        print(f"{kind} {ip} {port} {host}")

for h in (cfg.get("elasticsearch") or {}).get("hosts") or []:
    emit("ES", h)
llm_url = (cfg.get("llm") or {}).get("base_url")
if llm_url:
    emit("LLM", llm_url)
PYEOF
)"

        # Idempotency note: `ufw allow` is a no-op when an identical rule
        # already exists — it prints "Skipping adding existing rule" and
        # exits 0. We rely on that here rather than diffing `ufw status`
        # ourselves.

        # Targeted outbound allows for ES + LLM (one rule per resolved IP).
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            read -r kind a b c <<< "${line}"
            if [[ "${kind}" == "UNRESOLVED" ]]; then
                warn "  ${a} host did not resolve via DNS; skipping rule (host=${a} port=${b})"
                continue
            fi
            ip="${a}"; port="${b}"; host="${c}"
            if [[ "${ip}" == "${host}" ]]; then
                log "  ${kind}: out to ${ip} port ${port}/tcp"
            else
                log "  ${kind}: out to ${ip} port ${port}/tcp  (${host})"
            fi
            ufw allow out to "${ip}" port "${port}" proto tcp
        done <<< "${ENDPOINTS}"

        # Intel feeds + Anthropic cloud — all HTTPS, hosts not stable enough
        # to pin by IP.
        log "  intel + cloud: out 443/tcp"
        ufw allow out 443/tcp

        if (( OPEN_CONSOLE_PORT )); then
            log "  console: in ${CONSOLE_PORT}/tcp"
            ufw allow in "${CONSOLE_PORT}"/tcp
            warn "  console will be reachable from any host that can route to this box on ${CONSOLE_PORT}/tcp — ensure your perimeter firewall blocks WAN"
        fi
    fi
fi

# ---- D3. Console venv + install (opt-out via --no-console) -----------------
# The browser console is a separate package under console/. It needs its own
# venv because its pinned deps (FastAPI/uvicorn/jinja2) aren't in the parent
# package. The systemd unit at H. starts it; this section just gets the
# venv + editable install in place.
# The rsync above excluded `.venv/` so the source-side console/.venv (if
# any) doesn't clobber the deployed venv across re-runs. Idempotent.

if (( INSTALL_CONSOLE )); then
    CONSOLE_DIR="${INSTALL_DIR}/console"
    CONSOLE_VENV="${CONSOLE_DIR}/.venv"

    if [[ ! -d "${CONSOLE_DIR}" ]]; then
        die "Console package missing at ${CONSOLE_DIR}; rsync of console/ failed?"
    fi

    if [[ -x "${CONSOLE_VENV}/bin/python" && -x "${CONSOLE_VENV}/bin/pip" ]]; then
        log "Reusing existing console venv at ${CONSOLE_VENV}"
    else
        log "Creating console venv at ${CONSOLE_VENV}"
        # Wipe a half-built venv so the create succeeds and the bin/python
        # check on re-run isn't a false reuse.
        rm -rf "${CONSOLE_VENV}"
        sudo -u "${SERVICE_USER}" "${PYTHON_BIN}" -m venv "${CONSOLE_VENV}"
    fi

    log "Installing console package"
    sudo -u "${SERVICE_USER}" "${CONSOLE_VENV}/bin/pip" install --quiet --upgrade pip
    # Parent package first — the console imports from `enrich.findings` and
    # `enrich.llm` (e.g. evidence_quality, fencing). Base install only; the
    # `[cluster]` extra (scikit-learn/scipy) isn't needed for read-only UI.
    sudo -u "${SERVICE_USER}" "${CONSOLE_VENV}/bin/pip" install --quiet -e "${INSTALL_DIR}"
    sudo -u "${SERVICE_USER}" "${CONSOLE_VENV}/bin/pip" install --quiet -e "${CONSOLE_DIR}"

    # `if` puts the command in a test position, so the ERR trap above
    # doesn't fire on a non-zero exit and we can keep stderr for the die
    # message.
    if ! CONSOLE_IMPORT_ERR=$(sudo -u "${SERVICE_USER}" "${CONSOLE_VENV}/bin/python" -c \
        'import console.cli, console.server' 2>&1); then
        die "Console install failed (console.cli / console.server not importable):
${CONSOLE_IMPORT_ERR}"
    fi
else
    warn "Skipping console install (--no-console)"
fi

# ---- E. bootstrap ES (templates + ingest pipelines + raw data stream) ------

if (( RUN_INIT_INDEX )); then
    # Apply project-owned templates, ingest pipelines, and the
    # `prism.raw.cowrie.session` data stream BEFORE healthcheck so the
    # post-install checks (which expect the raw index to exist) pass on
    # a fresh deploy too. Idempotent: PUTs on templates + pipelines
    # overwrite; data-stream creation hits a "resource_already_exists"
    # branch that's treated as a no-op.
    log "Applying ES templates + ingest pipelines from setup/"
    ( cd "${INSTALL_DIR}" && run_cli bootstrap-es )
else
    warn "Skipping bootstrap-es (--skip-init-index)"
fi

# ---- F. init project-owned processed indices -------------------------------

if (( RUN_INIT_INDEX )); then
    # Idempotent across every source: creates missing indexes, additive
    # mapping update on existing ones. Order matters when an index doesn't
    # exist yet — cowrie indexes are read by the intel + findings miners,
    # so we init the source-of-truth indexes first.
    log "Initializing cowrie indexes (commands, sessions, ips, clusters, campaigns)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source cowrie )
    log "Initializing intel indexes (prism.intel.ip, prism.intel.url)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source intel )
    log "Initializing findings index (prism.finding)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source findings )
    # Findings v2 — lifecycle subsystem. Three strict-dynamic indices that
    # the `track lifecycles` verb upserts into every backward pass.
    log "Initializing lifecycle indexes (playbook / campaign / source_ip)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source lifecycle )
    # Run telemetry (P4.2) — tracked verbs write started→finished/failed docs
    # here; the writer skips silently until this exists.
    log "Initializing ops index (prism.ops — run telemetry)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source ops )
    # MITRE TTP application-rate snapshot (phase 2.3) — `enrich` writes a
    # per-corpus snapshot here, but skips silently until this exists, so a
    # fresh install never populates the Health page's TTP-rate panel without it.
    log "Initializing metrics index (prism.metrics — MITRE TTP application rates)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source metrics )
else
    warn "Skipping init-indexes (--skip-init-index)"
fi

# ---- G. healthcheck --------------------------------------------------------
# Moved after bootstrap-es + init-indexes so the raw-index existence check
# (hard-fails when the data stream is missing — every other invocation, in
# production, the raw stream needs to be there) passes on a fresh deploy.

if (( RUN_HEALTHCHECK )); then
    log "Running healthcheck"
    set +e
    ( cd "${INSTALL_DIR}" && run_cli healthcheck )
    HC_RC=$?
    set -e
    if (( HC_RC != 0 )); then
        die "Healthcheck failed (rc=${HC_RC}). Fix the failures above before continuing. Re-run this script when ready, or pass --skip-healthcheck."
    fi
else
    warn "Skipping healthcheck (--skip-healthcheck)"
fi

# ---- G2. external reference corpus (Tradecraft Matches) — best-effort -------
# One-time external baseline: import the Atomic Red Team corpus, embed it, and
# mint the `external` reference centroids that `cluster sessions` scores live
# sessions against — this is what populates the console "Tradecraft Matches"
# panel + the external-novelty surface. Runs AFTER the healthcheck so the
# embedding model is verified reachable before `enrich --reference`.
#
# NON-FATAL by design: it needs GitHub egress (clones Atomic Red Team) and the
# embedding model up, neither guaranteed on every box (air-gapped installs,
# LLM not yet configured). A failure here only means the Tradecraft panel stays
# empty until you run setup/3-bootstrap-reference-corpus.sh by hand later. Refresh
# is operator-driven (~quarterly), not scheduled — see docs/reference-corpus.md.
# The three steps live in setup/3-bootstrap-reference-corpus.sh so the same path
# can be re-run standalone (e.g. after a `pipeline --force` wipes the corpus).

log "Bootstrapping external reference corpus (Tradecraft Matches) — best-effort"
set +e
SERVICE_USER="${SERVICE_USER}" INSTALL_DIR="${INSTALL_DIR}" VENV="${VENV}" \
    bash "${SRC_DIR}/setup/3-bootstrap-reference-corpus.sh"
REF_RC=$?
set -e
if (( REF_RC != 0 )); then
    warn "Reference-corpus bootstrap failed (rc=${REF_RC}) — install continues. The"
    warn "  'Tradecraft Matches' panel stays empty until you run it by hand (with the"
    warn "  embedding model up + GitHub reachable):"
    warn "    sudo bash ${INSTALL_DIR}/setup/3-bootstrap-reference-corpus.sh"
    warn "  See docs/reference-corpus.md."
else
    log "  reference corpus imported + external centroids minted (Tradecraft Matches live after next 'cluster sessions')"
fi

# ---- H. systemd ------------------------------------------------------------

if (( INSTALL_SYSTEMD )); then
    log "Syncing systemd units"

    # Best-effort cleanup of removed units. Idempotent — silently ignores
    # absence on a fresh box. `dshield_prism-mine-findings` was the
    # standalone hourly miner; mining is now inlined into the backward
    # chain so the unit + timer are deleted from disk and forgotten by
    # systemd.
    for legacy in dshield_prism-ingest dshield_prism-analytics dshield_prism-mine-findings; do
        if [[ -f "${SYSTEMD_DIR}/${legacy}.timer" ]] \
        || [[ -f "${SYSTEMD_DIR}/${legacy}.service" ]] \
        || systemctl list-unit-files 2>/dev/null | grep -q "^${legacy}\."; then
            log "  ${legacy}.*: removing legacy units"
            systemctl disable --now "${legacy}.timer"   2>/dev/null || true
            systemctl disable --now "${legacy}.service" 2>/dev/null || true
            rm -f "${SYSTEMD_DIR}/${legacy}.timer" "${SYSTEMD_DIR}/${legacy}.service"
        fi
    done

    UNITS=(
        dshield_prism-forward.service
        dshield_prism-forward.timer
        dshield_prism-backward.service
        dshield_prism-backward.timer
        dshield_prism-recluster-full.service
        dshield_prism-recluster-full.timer
        # Installed but NOT enabled — a manual one-shot for historical backfill,
        # started on demand (`systemctl start dshield_prism-backfill`). No timer.
        dshield_prism-backfill.service
    )
    if (( INSTALL_CONSOLE )); then
        UNITS+=(dshield_prism-console.service)
    fi

    UNITS_CHANGED=0
    CONSOLE_UNIT_CHANGED=0
    for unit in "${UNITS[@]}"; do
        src="${INSTALL_DIR}/systemd/${unit}"
        dst="${SYSTEMD_DIR}/${unit}"
        if [[ ! -f "${dst}" ]]; then
            log "  ${unit}: installing (missing)"
            install -m 0644 "${src}" "${dst}"
            UNITS_CHANGED=1
            [[ "${unit}" == "dshield_prism-console.service" ]] && CONSOLE_UNIT_CHANGED=1
        elif ! cmp -s "${src}" "${dst}"; then
            log "  ${unit}: updating (outdated)"
            install -m 0644 "${src}" "${dst}"
            UNITS_CHANGED=1
            [[ "${unit}" == "dshield_prism-console.service" ]] && CONSOLE_UNIT_CHANGED=1
        else
            log "  ${unit}: up-to-date"
        fi
    done

    if (( UNITS_CHANGED )); then
        log "Reloading systemd"
        systemctl daemon-reload
    fi

    # Enable (boot persistence) + start the TIMERS so they schedule future runs.
    # `enable --now` is a no-op on an already-running timer, so it never re-fires a
    # service. We deliberately do NOT `restart` the timers on a unit change: a timer
    # reads its *.service unit at fire time, so a changed service is picked up at the
    # next scheduled run with no restart needed — and `restart` on a `Persistent=true`
    # timer makes systemd run an immediate catch-up activation, which would START the
    # services on every setup run. They must only run when the timer fires.
    # `daemon-reload` above already applies any changed *.timer schedule to the running
    # timer; to force a one-off run, the operator starts the .service by hand (printed
    # in the closing instructions).
    systemctl enable --now dshield_prism-forward.timer
    systemctl enable --now dshield_prism-backward.timer
    systemctl enable --now dshield_prism-recluster-full.timer

    if (( INSTALL_CONSOLE )); then
        # `enable --now` starts it on a fresh install and is a no-op when
        # already running. Only force a restart when the unit file itself
        # changed — restarting on every setup run would needlessly interrupt
        # in-flight analyst sessions.
        systemctl enable --now dshield_prism-console.service
        if (( CONSOLE_UNIT_CHANGED )); then
            systemctl restart dshield_prism-console.service
        fi
    fi

    log "Timer status:"
    systemctl --no-pager list-timers \
        dshield_prism-forward.timer \
        dshield_prism-backward.timer || true
    if (( INSTALL_CONSOLE )); then
        log "Console service status:"
        systemctl --no-pager --lines=0 status dshield_prism-console.service || true
    fi
else
    warn "Skipping systemd install (--no-systemd)"
fi

# ---- I. CLI wrapper --------------------------------------------------------
# Install a /usr/local/bin/prism wrapper so operators can type:
#     prism healthcheck
# instead of:
#     sudo -u dshield_prism /opt/dshield_prism/.venv/bin/python -m enrich.cli ...
# Wrapper script (not a shell alias) so it works in any shell, in scripts,
# in cron, and over non-interactive ssh. Idempotent: re-running 2-setup.sh
# rewrites the file with identical content.

PRISM_WRAPPER="/usr/local/bin/prism"
log "Installing CLI wrapper at ${PRISM_WRAPPER}"
cat > "${PRISM_WRAPPER}" <<EOF
#!/usr/bin/env bash
# Auto-generated by ${BASH_SOURCE[0]##*/}. Edits will be overwritten on re-run.
# Runs the enrich CLI as ${SERVICE_USER} with the deployed config + env.
exec sudo -u "${SERVICE_USER}" env \\
    PRISM_ENV="${INSTALL_DIR}/.env" \\
    "${VENV}/bin/python" -m enrich.cli \\
    --config "${INSTALL_DIR}/config/default.yaml" "\$@"
EOF
chmod 0755 "${PRISM_WRAPPER}"

# ---- done ------------------------------------------------------------------

cat <<EOF

${GREEN}Setup complete.${RESET}

Scheduled services installed:

  dshield_prism-forward.timer           (every 30 min)
    → healthcheck --scope llm   (hard fail = skip the pass)
    → enrich                    (command enrichment + cloud escalation)
    → rollup sessions           (session aggregation)
    → rollup ips                (IP aggregation)

  dshield_prism-backward.timer          (every 6h at 00,06,12,18 UTC)
    → healthcheck --scope llm   (soft check; most steps don't need LLM)
    → re-enrich-stale           (LLM-side cache drift; near-no-op when fresh)
    → reembed                   (embed-side cache drift; near-no-op when fresh)
    → reset --if-stale          (re-pool only if a command rewrite/schema change warrants it — P1.1)
    → rollup sessions / ips     (incremental in steady state; full re-pool when the gate fires)
    → cluster commands          (HDBSCAN; refreshes novelty)
    → cluster sessions / ips    (HDBSCAN)
    → escalate                  (cloud rescue for novel commands)
    → name playbooks            (local LLM names each session cluster)
    → name ip-clusters          (annotate IP centroids with dominant playbook)
    → mine campaigns            (FP-growth + shared-artifact miners)
    → track lifecycles          (playbook/campaign/source_ip snapshots)
    → intel refresh             (external threat-intel providers)
    → mine findings             (one card per playbook + per campaign;
                                 powers the console /findings page)

  Both timers serialise on /var/lib/dshield_prism/.lock via flock.

The first forward pass will fire within 30 min. To kick off a run now:

  sudo systemctl start dshield_prism-forward.service
  sudo systemctl start dshield_prism-backward.service

Tail live logs:

  journalctl -fu dshield_prism-forward.service
  journalctl -fu dshield_prism-backward.service

Useful CLI commands (the 'prism' wrapper at /usr/local/bin/prism handles
sudo + service-user + config; works from any cwd in any shell):

  prism healthcheck                  # ES + LLM + SQLite + cloud + intel
  prism enrich --dry-run             # show what would be enriched
  prism budget                       # today's cloud-LLM spend
  prism cluster commands --dry-run   # command-level cluster stats
  prism name playbooks --dry-run     # preview playbook naming candidates
  prism mine campaigns --dry-run     # preview multi-session campaign mining
  prism mine findings --dry-run      # preview the findings inbox refresh
  prism intel refresh --dry-run      # preview intel queue + provider dispatch

Browser console:

  dshield_prism-console.service        (binds 0.0.0.0:8765 on boot)
    journalctl -fu dshield_prism-console.service   # tail logs
    systemctl restart dshield_prism-console.service
  open  http://<this-host>:8765/        (redirects to /findings)

  To skip the console install / unit, re-run 2-setup.sh with --no-console.
  To bind loopback only, drop in /etc/systemd/system/dshield_prism-console.service.d/override.conf
  with [Service] / ExecStart= overriding the --host flag.

Import the Kibana dashboards (Saved Objects → Import):
  ${INSTALL_DIR}/es-dashboards/session-analysis.ndjson
  ${INSTALL_DIR}/es-dashboards/command-enrichment-dashboard.ndjson

Re-running this script is safe — every step is idempotent.
EOF
