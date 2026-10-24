#!/bin/sh
# Run one app through the strict proxy with an optional per-app allowlist.
#
# The first run creates /etc/doorman/apps/<app>.txt. Hosts added there are
# added to the global allowlist for this app only. The file is used only once
# it contains at least one host, so an empty auto-created file does not change
# behaviour for apps that cannot send proxy credentials.

set -eu

if [ $# -lt 1 ]; then
    echo "usage: doorman-run <steam|command> [args...]" >&2
    exit 2
fi

APPS_DIR="${DOORMAN_APPS_DIR:-/etc/doorman/apps}"
PROXY_PORT="${DOORMAN_PROXY_PORT:-8081}"
PROXY_URL="http://127.0.0.1:$PROXY_PORT"

app="$1"
shift
case "$app" in
    steam) cmd="${DOORMAN_STEAM_CMD:-steam}" ;;
    *) cmd="$app" ;;
esac

raw_name="${DOORMAN_APP_NAME:-$app}"
if [ -z "${DOORMAN_APP_NAME:-}" ] && [ "$raw_name" != "steam" ]; then
    raw_name="$(basename -- "$raw_name" 2>/dev/null || printf '%s' "$raw_name")"
fi
name="$(printf '%s' "$raw_name" | LC_ALL=C tr '[:upper:]' '[:lower:]')"
name="$(printf '%s' "$name" | LC_ALL=C sed 's/[^a-z0-9._-]/_/g; s/^[._-]*//')"
name="$(printf '%.64s' "$name")"
[ -n "$name" ] || name="app"

file="$APPS_DIR/$name.txt"

created=0
if [ -d "$APPS_DIR" ] && [ -w "$APPS_DIR" ]; then
    if [ ! -e "$file" ]; then
        (
            umask 022
            {
                echo "# Hosts allowed only for doorman-run $name."
                echo "# One host per line; a host also covers its subdomains."
                echo "# '#' starts a comment. Restart the app after editing."
            } > "$file"
        ) || true
        if [ -f "$file" ]; then
            chmod 644 "$file" 2>/dev/null || true
            created=1
            echo "doorman-run: created per-app allowlist $file" >&2
        else
            echo "doorman-run: could not create $file; using the global allowlist" >&2
        fi
    fi
elif [ ! -d "$APPS_DIR" ]; then
    echo "doorman-run: $APPS_DIR is missing; using the global allowlist" >&2
    echo "            rerun the installer to create it." >&2
elif [ ! -f "$file" ]; then
    echo "doorman-run: $APPS_DIR is not writable; using the global allowlist" >&2
fi

if [ -f "$file" ]; then
    chmod 644 "$file" 2>/dev/null || true
fi

use_app=0
if [ -f "$file" ] && [ -r "$file" ]; then
    if grep -qEv '^[[:space:]]*(#|$)' "$file"; then
        use_app=1
    fi
fi

proxy_url="$PROXY_URL"
if [ "$use_app" = 1 ]; then
    proxy_url="http://$name:doorman@127.0.0.1:$PROXY_PORT"
    echo "doorman-run: using per-app allowlist $file" >&2
elif [ "$created" = 1 ]; then
    echo "doorman-run: add hosts to $file, then restart the app." >&2
fi

export http_proxy="$proxy_url"
export https_proxy="$http_proxy"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$http_proxy"
export all_proxy="$http_proxy"
export ALL_PROXY="$http_proxy"
export no_proxy="localhost,127.0.0.1,::1"
export NO_PROXY="$no_proxy"

exec "$cmd" "$@"
