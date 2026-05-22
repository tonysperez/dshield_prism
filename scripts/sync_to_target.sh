#!/usr/bin/env bash
# Copy all VCS-eligible files in this repo to <user@host>:/opt/dshield_prism.
#
# "VCS-eligible" = tracked files + untracked-but-not-gitignored files.
# (Everything that would be considered for `git add`. Excludes .venv,
# __pycache__, anything in .gitignore.)
#
# Two-stage push (works when /opt is root-only and root can't SSH in):
#   Stage 1: rsync VCS-eligible files to <home>/dshield_prism_staging/ on
#            the remote. No sudo needed — staging lives in the SSH user's $HOME.
#   Stage 2: ssh -t and run `sudo rsync` on the remote to copy staging into
#            /opt/dshield_prism. Interactive sudo prompt; no NOPASSWD needed.
#
# Usage:
#   scripts/sync_to_target.sh [-n] [-d] [-D <dest>] [-S <staging>] <user@host>
#
# Options:
#   -n            Dry-run on BOTH stages (show what would change, write nothing).
#   -d            Mirror /opt/dshield_prism: --delete extraneous files in stage 2.
#                 (Stage 1 always mirrors staging, since the script owns it.)
#   -D <dest>     Override final destination path (default: /opt/dshield_prism).
#   -S <staging>  Override remote staging path (default: ~/dshield_prism_staging).
#                 Must be a path the SSH user can write without sudo.
#   -O <user[:group]>  Owner to chown the destination to after stage 2
#                 (default: dshield_prism:dshield_prism). Pass an empty string
#                 to skip chown.
#   -h            Help.
#
# Examples:
#   scripts/sync_to_target.sh -n deploy@honeypot.example.org
#   scripts/sync_to_target.sh deploy@honeypot.example.org
#   scripts/sync_to_target.sh -d deploy@honeypot.example.org

set -euo pipefail

DEST="/opt/dshield_prism"
STAGING='~/dshield_prism_staging'   # literal ~; expanded by remote shell
OWNER="dshield_prism:dshield_prism" # chown -R applied to $DEST after stage 2
DRY=()
DRY_FLAG=""        # "--dry-run" for ssh-side rsync command (string, not array)
DELETE_OPT=""      # "--delete" for stage-2

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

while getopts ":ndD:S:O:h" opt; do
    case "$opt" in
        n) DRY=(--dry-run --itemize-changes); DRY_FLAG="--dry-run --itemize-changes" ;;
        d) DELETE_OPT="--delete" ;;
        D) DEST="$OPTARG" ;;
        S) STAGING="$OPTARG" ;;
        O) OWNER="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

if [ $# -ne 1 ]; then
    usage >&2
    exit 2
fi
TARGET="$1"

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

FILE_LIST="$(mktemp)"
trap 'rm -f "$FILE_LIST"' EXIT

# Tracked + untracked-but-not-ignored. -z preserves whitespace in paths;
# consumed via rsync --from0.
{
    git ls-files -z
    git ls-files -z --others --exclude-standard
} > "$FILE_LIST"

N="$(tr -cd '\0' < "$FILE_LIST" | wc -c | tr -d ' ')"
if [ "$N" -eq 0 ]; then
    echo "No VCS-eligible files found under $REPO_ROOT" >&2
    exit 1
fi

echo "=== Stage 1/2: $N file(s) -> ${TARGET}:${STAGING}/ ==="
[ "${#DRY[@]}" -gt 0 ] && echo "  (dry-run; nothing written on either stage)"

# Stage 1: rsync to the SSH user's $HOME staging dir. Always --delete inside
# staging — it's owned by this script, so prior-push leftovers should not
# accumulate or leak into stage 2.
rsync \
    --archive \
    --human-readable \
    --compress \
    --from0 \
    --files-from="$FILE_LIST" \
    --delete \
    --rsync-path="mkdir -p ${STAGING} && rsync" \
    "${DRY[@]}" \
    ./ "${TARGET}:${STAGING}/"

echo
echo "=== Stage 2/2: sudo rsync ${STAGING}/ -> ${DEST}/ on ${TARGET} ==="
[ -n "$DELETE_OPT" ] && echo "  (mirror: extraneous files in ${DEST} will be removed)"
[ -n "$OWNER" ] && echo "  (will chown -R ${OWNER} ${DEST} after rsync)"
echo "  (sudo will prompt on the remote)"

# Stage 2: ssh -t to allocate a TTY so sudo can prompt for the password.
# The remote command:
#   1. sudo mkdir -p the destination (handles fresh deploy).
#   2. sudo rsync from staging to destination. Preserves perms with -a.
#   3. sudo chown -R the destination to $OWNER (skipped if -O '' or dry-run).
CHOWN_CMD=""
if [ -n "$OWNER" ] && [ "${#DRY[@]}" -eq 0 ]; then
    CHOWN_CMD=" && sudo chown -R ${OWNER} ${DEST}"
fi
ssh -t "$TARGET" "sudo mkdir -p ${DEST} && sudo rsync -a --human-readable ${DRY_FLAG} ${DELETE_OPT} ${STAGING}/ ${DEST}/${CHOWN_CMD}"
