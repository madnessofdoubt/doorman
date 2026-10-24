#!/bin/sh
# Launch Helium through the doorman browser proxy.
#
# By default Helium's normal profile is used: a dedicated profile would
# isolate cookies and force a fresh login on every site. A profile can be
# selected explicitly with BROWSER_PROFILE in /etc/doorman/doorman.conf.
#
# A second launch joins the already-running Helium instance, and that
# instance does not have --proxy-server, so refuse while Helium is running.

set -eu

if [ "$(id -u)" -eq 0 ]; then
    echo "doorman-browser: start this as your desktop user, not root." >&2
    exit 1
fi

APP="${DOORMAN_HELIUM_APPIMAGE:-/opt/doorman/Helium.AppImage}"
NSSDIR="${DOORMAN_NSSDB:-$HOME/.config/doorman/nssdb}"
PROXY_URL="http://127.0.0.1:8080"
CONF="${DOORMAN_CONF:-/etc/doorman/doorman.conf}"

helium_running() {
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -u "$(id -u)" -x helium >/dev/null 2>&1
    else
        ps -u "$(id -u)" -o comm= 2>/dev/null | grep -qx helium
    fi
}

if helium_running; then
    msg="Helium is already running. Close it completely, then start doorman-browser again so the doorman proxy applies."
    echo "doorman-browser: $msg" >&2
    if command -v notify-send >/dev/null 2>&1 &&
       notify-send "doorman-browser" "$msg" 2>/dev/null; then
        :
    elif command -v zenity >/dev/null 2>&1; then
        zenity --error --title="doorman-browser" --text="$msg" 2>/dev/null || true
    fi
    exit 1
fi

# An empty BROWSER_PROFILE means Helium's normal profile.
PROFILE=""
if [ -r "$CONF" ]; then
    PROFILE="$(sed -n 's/^BROWSER_PROFILE=//p' "$CONF" | tail -n 1)"
fi
case "$PROFILE" in
    "~/"*) PROFILE="$HOME/${PROFILE#\~/}" ;;
esac
if [ -n "$PROFILE" ] && [ ! -d "$PROFILE" ]; then
    echo "doorman-browser: profile $PROFILE does not exist yet; Helium will create it." >&2
fi

# If the installer created a doorman-owned NSS store (--nss own), point
# Helium at it so the profile trusts the mitmproxy CA.
if [ -d "$NSSDIR" ]; then
    export NSS_DEFAULT_DB_TYPE=sql
    export NSS_LIB_PARAMS="configdir=$NSSDIR"
fi

if [ -n "$PROFILE" ]; then
    exec "$APP" --user-data-dir="$PROFILE" --proxy-server="$PROXY_URL" "$@"
fi
exec "$APP" --proxy-server="$PROXY_URL" "$@"
