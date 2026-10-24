#!/bin/sh
# Move an older Helium profile into the default profile, with a backup.
# Run as the desktop user, with Helium closed.

set -eu

usage() {
    cat <<'EOF'
usage: doorman-migrate-profile --from PATH [--to PATH] [--dry-run]

Moves a Helium profile into the default profile and keeps a timestamped
backup of whatever was in the default. Refuses while Helium is running.
The default target is ~/.config/net.imput.helium.
EOF
}

if [ "$(id -u)" -eq 0 ]; then
    echo "doorman-migrate-profile: run this as your desktop user, not root." >&2
    exit 1
fi

FROM=""
TO="${XDG_CONFIG_HOME:-$HOME/.config}/net.imput.helium"
DRY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM="${2:-}"; shift 2 ;;
        --to) TO="${2:-}"; shift 2 ;;
        --dry-run) DRY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done
[ -n "$FROM" ] || { usage; exit 2; }

case "$FROM" in "~/"*) FROM="$HOME/${FROM#\~/}" ;; esac
case "$TO" in "~/"*) TO="$HOME/${TO#\~/}" ;; esac

if command -v pgrep >/dev/null 2>&1; then
    if pgrep -u "$(id -u)" -x helium >/dev/null 2>&1; then
        echo "Helium is running. Close it completely and try again." >&2
        exit 1
    fi
elif ps -u "$(id -u)" -o comm= 2>/dev/null | grep -qx helium; then
    echo "Helium is running. Close it completely and try again." >&2
    exit 1
fi

[ -d "$FROM" ] || { echo "source profile not found: $FROM" >&2; exit 1; }
[ "$(readlink -f "$FROM")" = "$FROM" ] || { echo "source is a symlink: $FROM" >&2; exit 1; }
[ -d "$FROM/Default" ] || { echo "source does not look like a Helium profile: $FROM" >&2; exit 1; }

if [ -d "$TO" ] && [ "$(readlink -f "$TO")" = "$(readlink -f "$FROM")" ]; then
    echo "source and target are the same profile; nothing to do."
    exit 0
fi
[ ! -L "$TO" ] || { echo "target is a symlink: $TO" >&2; exit 1; }

if [ "$DRY" = 1 ]; then
    echo "would move: $FROM"
    echo "to:         $TO"
    if [ -d "$TO" ]; then
        echo "would back up the old target first"
    fi
    exit 0
fi

mkdir -p "$(dirname "$TO")"
ts=$(date +%Y%m%d-%H%M%S)
BACKUP=""
if [ -d "$TO" ]; then
    BACKUP="$TO.before-migrate-$ts"
    [ ! -e "$BACKUP" ] || { echo "backup already exists: $BACKUP" >&2; exit 1; }
    mv "$TO" "$BACKUP"
fi

if ! mv "$FROM" "$TO"; then
    if [ -n "$BACKUP" ]; then
        mv "$BACKUP" "$TO"
    fi
    echo "move failed; restored the old target" >&2
    exit 1
fi

rm -f "$TO"/Singleton*
echo "profile moved into the default location."
echo "source: $FROM"
echo "target: $TO"
if [ -n "$BACKUP" ]; then
    echo "backup of the old default: $BACKUP"
fi
echo "Start Helium with doorman-browser; your logins should be there."
