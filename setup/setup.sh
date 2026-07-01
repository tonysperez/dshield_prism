#!/usr/bin/env bash
# setup.sh — DShield Prism one-command installer (front door).
#
# Interactive wizard that writes .env + config/local.yaml (no hand-editing) and
# validates them live — checks the ES credentials authenticate and that the
# chosen LLM models are actually loaded on the GPU box — then orchestrates the
# underlying scripts under setup/scripts/. Idempotent: re-running keeps existing
# config (unless --reconfigure) and every downstream step is a no-op when done.
#
# The live checks use the system python3 (stdlib only) — no venv needed. If
# python3 is absent they warn and skip; install.sh's healthcheck re-validates.
#
# Usage:
#   sudo bash setup/setup.sh [--reconfigure] [--no-verify] [install.sh flags...]
#   bash setup/setup.sh --configure-only        # just write .env + local.yaml
#
# Flags:
#   --configure-only  Write .env + config/local.yaml and exit (no root, no install).
#   --reconfigure     Re-run the wizard even if .env/local.yaml exist (backs up *.bak).
#   --no-verify       Skip the live ES-credential + model-availability checks.
#   -h, --help        Show this help.
#   (any other flag)  Forwarded to setup/scripts/install.sh (e.g. --no-console, --ufw).
#
# Env overrides (mainly for --configure-only / tests — the install phase always
# reads the repo-root .env + config/local.yaml regardless of these):
#   ENV_FILE       default: <repo>/.env
#   LOCAL_CONFIG   default: <repo>/config/local.yaml

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_CONFIG="${REPO_ROOT}/config/default.yaml"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"
LOCAL_CONFIG="${LOCAL_CONFIG:-${REPO_ROOT}/config/local.yaml}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
log()  { echo -e "${GREEN}==>${RESET} $*"; }
warn() { echo -e "${YELLOW}WARN:${RESET} $*" >&2; }
die()  { echo -e "${RED}ERROR:${RESET} $*" >&2; exit 1; }

usage() {
    # Print the header comment block only (line 2 to the first blank line),
    # stripping the leading '# '. Stops before the code so it can't leak.
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

# ---- argv ------------------------------------------------------------------

CONFIGURE_ONLY=0
RECONFIGURE=0
SKIP_VERIFY=0
PASSTHROUGH=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --configure-only) CONFIGURE_ONLY=1 ;;
        --reconfigure)    RECONFIGURE=1 ;;
        --no-verify)      SKIP_VERIFY=1 ;;
        -h|--help)        usage; exit 0 ;;
        *)                PASSTHROUGH+=("$1") ;;
    esac
    shift
done

# ---- prompt helpers --------------------------------------------------------

ask() {  # $1 var, $2 prompt, $3 default (optional)
    local __in
    if [[ -n "${3:-}" ]]; then
        read -rp "$2 [$3]: " __in || true
    else
        read -rp "$2: " __in || true
    fi
    printf -v "$1" '%s' "${__in:-${3:-}}"
}

ask_secret() {  # $1 var, $2 prompt  (no echo; blank allowed)
    local __in
    read -rsp "$2: " __in || true
    echo
    printf -v "$1" '%s' "$__in"
}

yaml_default() {  # $1 key -> stdout: that key's value from default.yaml (best-effort)
    # `|| true`: a missing key makes grep exit non-zero, which under
    # `set -euo pipefail` would otherwise abort the whole wizard. Best-effort —
    # an absent default just means we prompt with no pre-filled value.
    { grep -E "^[[:space:]]*$1:" "$DEFAULT_CONFIG" 2>/dev/null | head -n1 \
        | sed -E "s/^[^:]*:[[:space:]]*//; s/[\"']//g; s/[[:space:]]*#.*\$//; s/[[:space:]]*\$//"; } || true
}

# ---- live verification (python3 stdlib; no venv) ---------------------------

have_python3() { command -v python3 >/dev/null 2>&1; }

# On a failed check, ask what to do. Returns 0 to retry (re-enter), 1 to
# continue anyway; aborts the whole run on 'a'. Called in `if` context so
# `set -e` doesn't fire on the continue-anyway (return 1) path.
confirm_retry() {
    local ans
    ask ans "  [r]etry / [c]ontinue anyway / [a]bort" "r"
    case "$ans" in
        [Cc]*) return 1 ;;
        [Aa]*) die "aborted by operator" ;;
        *)     return 0 ;;
    esac
}

# verify_es <url> <verify_certs> <mode:apikey|userpass>  (creds via env)
#   rc 0=ok  2=auth rejected(401/403)  3=other/TLS  4=unreachable
verify_es() {
    local url="$1" verify="$2" mode="$3"
    V_USER="${4:-}" V_PASS="${5:-}" V_APIKEY="${6:-}" \
    python3 - "$url" "$verify" "$mode" <<'PY'
import os, sys, ssl, base64, urllib.request, urllib.error
url, verify, mode = sys.argv[1:4]
req = urllib.request.Request(url.rstrip('/') + '/_security/_authenticate')
if mode == 'apikey':
    req.add_header('Authorization', 'ApiKey ' + os.environ.get('V_APIKEY', ''))
else:
    tok = base64.b64encode(
        f"{os.environ.get('V_USER','')}:{os.environ.get('V_PASS','')}".encode()).decode()
    req.add_header('Authorization', 'Basic ' + tok)
ctx = ssl.create_default_context()
if verify != 'true':
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
try:
    with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
        sys.exit(0 if getattr(r, 'status', 200) == 200 else 3)
except urllib.error.HTTPError as e:
    sys.exit(2 if e.code in (401, 403) else 3)
except Exception:
    sys.exit(4)
PY
}

# verify_llm <provider> <base_url> <gen_model> <emb_model>
#   rc 0=both present  4=unreachable  5=missing (prints missing names to stdout)
verify_llm() {
    python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys, json, ssl, urllib.request
provider, base, gen, emb = sys.argv[1:5]
base = base.rstrip('/')
if provider == 'ollama':
    path = '/api/tags'
elif base.endswith('/v1'):
    path = '/models'
else:
    path = '/v1/models'
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    with urllib.request.urlopen(base + path, timeout=8, context=ctx) as r:
        data = json.load(r)
except Exception:
    sys.exit(4)
names = set()
if provider == 'ollama':
    for m in data.get('models', []):
        n = m.get('name') or m.get('model') or ''
        if n:
            names.add(n)
            names.add(n.split(':')[0])
else:
    for m in data.get('data', []):
        if m.get('id'):
            names.add(m['id'])
missing = [x for x in (gen, emb) if x and x not in names]
if missing:
    print(' '.join(missing))
    sys.exit(5)
sys.exit(0)
PY
}

# ---- config wizard ---------------------------------------------------------

write_config() {
    [[ -f "$ENV_FILE" ]]     && cp -p "$ENV_FILE"     "${ENV_FILE}.bak"     && warn "backed up ${ENV_FILE##*/} -> ${ENV_FILE##*/}.bak"
    [[ -f "$LOCAL_CONFIG" ]] && cp -p "$LOCAL_CONFIG" "${LOCAL_CONFIG}.bak" && warn "backed up ${LOCAL_CONFIG##*/} -> ${LOCAL_CONFIG##*/}.bak"

    log "Elasticsearch"
    local es_hosts es_verify verify_certs auth es_user es_pass es_apikey es_rc
    while true; do
        ask es_hosts  "  ES URL" "https://localhost:9200"
        ask es_verify "  Verify TLS certs? (y/N)" "N"
        verify_certs="false"; [[ "$es_verify" =~ ^[Yy] ]] && verify_certs="true"
        echo "  ES auth:  1) API key   2) username + password"
        ask auth "  choice" "2"
        es_user=""; es_pass=""; es_apikey=""
        if [[ "$auth" == "1" ]]; then
            while [[ -z "$es_apikey" ]]; do
                read -rsp "  ES_API_KEY: " es_apikey || die "aborted: EOF while reading ES_API_KEY"
                echo
                [[ -z "$es_apikey" ]] && warn "  ES_API_KEY is required"
            done
        else
            ask es_user "  ES_USERNAME" "dshield_prism"
            while [[ -z "$es_pass" ]]; do
                read -rsp "  ES_PASSWORD: " es_pass || die "aborted: EOF while reading ES_PASSWORD"
                echo
                [[ -z "$es_pass" ]] && warn "  ES_PASSWORD is required"
            done
        fi
        if (( SKIP_VERIFY )); then break; fi
        have_python3 || { warn "  python3 not found — skipping ES credential check"; break; }
        log "  checking ES credentials at ${es_hosts} ..."
        es_rc=0
        if [[ "$auth" == "1" ]]; then
            verify_es "$es_hosts" "$verify_certs" apikey "" "" "$es_apikey" || es_rc=$?
        else
            verify_es "$es_hosts" "$verify_certs" userpass "$es_user" "$es_pass" "" || es_rc=$?
        fi
        case "$es_rc" in
            0) log "  ES credentials OK"; break ;;
            2) warn "  ES rejected the credentials (HTTP 401/403)." ;;
            4) warn "  ES unreachable at ${es_hosts} (timeout / connection refused)." ;;
            *) warn "  ES check failed (TLS or unexpected response). For a self-signed SO cert answer 'N' to verify certs." ;;
        esac
        if confirm_retry; then continue; else break; fi
    done

    log "Local LLM (embeddings + enrichment)"
    local prov_choice provider example base_url gen_def emb_def gen emb llm_rc missing
    gen_def="$(yaml_default generation_model)"
    emb_def="$(yaml_default embedding_model)"
    while true; do
        echo "  provider:  1) ollama (http://host:11434)   2) openai_compat (LM Studio http://host:1234)"
        ask prov_choice "  choice" "1"
        if [[ "$prov_choice" == "2" ]]; then
            provider="openai_compat"; example="http://gpu-host:1234"
        else
            provider="ollama"; example="http://gpu-host:11434"
        fi
        base_url=""
        while [[ -z "$base_url" ]]; do
            read -rp "  LLM base_url (e.g. $example): " base_url || die "aborted: EOF while reading required base_url"
            [[ -z "$base_url" ]] && warn "  base_url is required"
        done
        ask gen "  generation model" "$gen_def"
        ask emb "  embedding model" "$emb_def"
        if (( SKIP_VERIFY )); then break; fi
        have_python3 || { warn "  python3 not found — skipping model-availability check"; break; }
        log "  checking models on ${base_url} ..."
        llm_rc=0; missing=""
        missing="$(verify_llm "$provider" "$base_url" "$gen" "$emb")" || llm_rc=$?
        case "$llm_rc" in
            0) log "  selected models present on the LLM server"; break ;;
            5) warn "  model(s) not loaded on ${base_url}: ${missing}" ;;
            4) warn "  LLM server unreachable at ${base_url} (timeout / connection refused)." ;;
            *) warn "  model check failed (unexpected response)." ;;
        esac
        if confirm_retry; then continue; else break; fi
    done

    log "Cloud escalation (optional — blank to skip)"
    local anthropic
    ask_secret anthropic "  ANTHROPIC_API_KEY"

    log "Threat-intel provider keys (optional — blank to skip)"
    local abuse_ch greynoise abuseipdb
    ask_secret abuse_ch  "  ABUSE_CH_AUTH_KEY"
    ask_secret greynoise "  GREYNOISE_API_KEY"
    ask_secret abuseipdb "  ABUSEIPDB_API_KEY"

    # ---- write .env (only non-empty values; mode 600) ----
    umask 077
    {
        echo "# Generated by setup.sh — secrets. Keep out of git."
        if [[ "$auth" == "1" ]]; then
            echo "ES_API_KEY=${es_apikey}"
        else
            echo "ES_USERNAME=${es_user}"
            echo "ES_PASSWORD=${es_pass}"
        fi
        [[ -n "$anthropic" ]] && echo "ANTHROPIC_API_KEY=${anthropic}"
        [[ -n "$abuse_ch"  ]] && echo "ABUSE_CH_AUTH_KEY=${abuse_ch}"
        [[ -n "$greynoise" ]] && echo "GREYNOISE_API_KEY=${greynoise}"
        [[ -n "$abuseipdb" ]] && echo "ABUSEIPDB_API_KEY=${abuseipdb}"
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    # ---- write minimal local.yaml (models omitted when defaults accepted) ----
    {
        echo "# Generated by setup.sh — per-deploy overrides. Keep this minimal;"
        echo "# anything omitted tracks config/default.yaml."
        echo "elasticsearch:"
        echo "  hosts:"
        echo "    - ${es_hosts}"
        echo "  verify_certs: ${verify_certs}"
        echo "llm:"
        echo "  provider: ${provider}"
        echo "  base_url: ${base_url}"
        [[ -n "$gen" && "$gen" != "$gen_def" ]] && echo "  generation_model: ${gen}"
        [[ -n "$emb" && "$emb" != "$emb_def" ]] && echo "  embedding_model: ${emb}"
        if [[ -n "$anthropic" ]]; then
            echo "cloud:"
            echo "  enabled: true"
        fi
        if [[ -n "${abuse_ch}${greynoise}${abuseipdb}" ]]; then
            echo "intel:"
            echo "  enabled: true"
        fi
    } > "$LOCAL_CONFIG"

    # Keep repo files owned by the invoking user when run via sudo.
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        chown "${SUDO_USER}" "$ENV_FILE" "$LOCAL_CONFIG" 2>/dev/null || true
    fi
    log "Wrote ${ENV_FILE} (mode 600) + ${LOCAL_CONFIG}"
}

# ---- config phase ----------------------------------------------------------

if (( RECONFIGURE )) || [[ ! -f "$ENV_FILE" || ! -f "$LOCAL_CONFIG" ]]; then
    write_config
else
    log "Existing .env + config/local.yaml found — keeping them (pass --reconfigure to redo)."
fi

if (( CONFIGURE_ONLY )); then
    (( ${#PASSTHROUGH[@]} )) && warn "ignoring install flags under --configure-only: ${PASSTHROUGH[*]}"
    log "Config-only run complete."
    exit 0
fi

# ---- orchestration phase (needs root) --------------------------------------

[[ "${EUID}" -eq 0 ]] || die "Install phase needs root. Re-run: sudo bash setup/setup.sh   (or use --configure-only to just write config)."

log "Sensor pipelines"
shopt -s nullglob
existing_pipes=( "${SCRIPT_DIR}/es-pipelines/"cowrie-pipeline-sensor-*.yml )
shopt -u nullglob
hint="e.g. honey-eu-1:public honey-lab:confidential"
sensors=()
while true; do
    if (( ${#existing_pipes[@]} > 0 )); then
        read -rp "  Sensor(s) as name:classification ($hint) [blank = keep existing]: " -a sensors \
            || die "aborted: EOF while reading sensor list"
        break
    fi
    read -rp "  Sensor(s) as name:classification ($hint): " -a sensors \
        || die "aborted: EOF — at least one sensor is required on a fresh install"
    (( ${#sensors[@]} > 0 )) && break
    warn "  at least one sensor is required on a fresh install"
done

if (( ${#sensors[@]} > 0 )); then
    bash "${SCRIPT_DIR}/scripts/create-sensor-pipelines.sh" "${sensors[@]}"
else
    log "  keeping existing sensor pipelines"
fi

# Guard: create-sensor-pipelines skips malformed specs (bad name / missing or
# invalid classification) and still exits 0, so a fresh install with only
# malformed entries would otherwise proceed with zero pipelines. Re-count and
# hard-fail rather than install a sensor-less pipeline.
shopt -s nullglob
pipes_now=( "${SCRIPT_DIR}/es-pipelines/"cowrie-pipeline-sensor-*.yml )
shopt -u nullglob
if (( ${#pipes_now[@]} == 0 )); then
    die "No sensor pipelines exist — every entry was invalid. Use name:public or name:classification (public|confidential) and re-run."
fi

log "Running installer"
bash "${SCRIPT_DIR}/scripts/install.sh" "${PASSTHROUGH[@]}"

cat <<EOF

${GREEN}setup.sh complete.${RESET}

Final manual step (Security Onion / Fleet — not scriptable from here):
  In Kibana -> Fleet, set each sensor's Cowrie integration 'pipeline:' field to
  its per-sensor id (printed above by create-sensor-pipelines.sh), e.g.
    prism.cowrie.session.<sensor-name>

Re-running 'sudo bash setup/setup.sh' is safe — every step is idempotent.
EOF
