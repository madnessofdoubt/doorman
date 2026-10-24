#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$HOME/Projects/doorman}"
export DOORMAN_CONFIG_DIR="$PROJECT_DIR"
REAL_HELIUM="${REAL_HELIUM:-$HOME/app-images/helium}"
PROXY_HOST="127.0.0.1"
PROXY_PORT="8080"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
# Use Helium's normal profile so logins carry over, like doorman-browser.
# Do not add --user-data-dir here: that creates a separate profile.
LOCAL_BIN="${LOCAL_BIN:-$HOME/.local/bin}"
SELF="$(readlink -f "${BASH_SOURCE[0]}")"

LOG_DIR="$PROJECT_DIR/logs"
PROXY_LOG="$LOG_DIR/mitmdump.log"
PROXY_PIDFILE="$LOG_DIR/mitmdump.pid"
MITMDUMP="$PROJECT_DIR/.venv/bin/mitmdump"
ADDON="$PROJECT_DIR/addon.py"

STARTUP_TIMEOUT=10
STOP_PROXY_ON_EXIT=1
MAX_LOG_BYTES=5000000

mkdir -p "$LOG_DIR"
die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" -ne 0 ] || die "run this as your desktop user, not root"

install_launcher() {
  local link="$LOCAL_BIN/helium"
  [ "$(readlink -f "$link" 2>/dev/null || true)" = "$SELF" ] && return 0
  mkdir -p "$LOCAL_BIN"
  if [ -e "$link" ] && [ ! -L "$link" ]; then
    echo "warning: $link exists and is not a symlink, leaving it alone" >&2
    return 1
  fi
  ln -sfn "$SELF" "$link"
  echo "installed $link -> $SELF" >&2
}

port_open() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH "sport = :${PROXY_PORT}" 2>/dev/null | grep -q .
  else
    (exec 3<>"/dev/tcp/${PROXY_HOST}/${PROXY_PORT}") 2>/dev/null
  fi
}

[ -x "$REAL_HELIUM" ] || die "$REAL_HELIUM not found - set REAL_HELIUM=/path/to/helium"
[ -f "$ADDON" ]       || die "$ADDON not found"
[ -x "$MITMDUMP" ]    || die "$MITMDUMP not found. Create the venv first:
  python3 -m venv $PROJECT_DIR/.venv && $PROJECT_DIR/.venv/bin/pip install mitmproxy"

if pgrep -u "$(id -u)" -x helium >/dev/null 2>&1; then
  die "Helium is already running. Close it completely, then start it again so the proxy applies."
fi

# Use the same optional profile as doorman-browser; empty means the normal
# Helium profile.
CONF="${DOORMAN_CONF:-/etc/doorman/doorman.conf}"
PROFILE=""
if [ -r "$CONF" ]; then
  PROFILE="$(sed -n 's/^BROWSER_PROFILE=//p' "$CONF" | tail -n 1)"
fi
case "$PROFILE" in
  "~/"*) PROFILE="$HOME/${PROFILE#\~/}" ;;
esac
PROFILE_ARGS=()
if [ -n "$PROFILE" ]; then
  PROFILE_ARGS=(--user-data-dir="$PROFILE")
fi

install_launcher

PROXY_STARTED=0

start_proxy() {
  if [ -f "$PROXY_LOG" ] && [ "$(stat -c %s "$PROXY_LOG")" -gt "$MAX_LOG_BYTES" ]; then
    mv -f "$PROXY_LOG" "$PROXY_LOG.1"
  fi

  echo "starting proxy on ${PROXY_URL}..." >&2
  nohup "$MITMDUMP" -s "$ADDON" -p "$PROXY_PORT" >>"$PROXY_LOG" 2>&1 &
  local pid=$!
  echo "$pid" >"$PROXY_PIDFILE"

  local tries=$((STARTUP_TIMEOUT * 5)) i=0
  while [ "$i" -lt "$tries" ]; do
    if port_open; then
      echo "proxy ready (pid $pid). logs: $PROXY_LOG" >&2
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "proxy exited during startup. last lines of $PROXY_LOG:" >&2
      tail -n 20 "$PROXY_LOG" >&2
      rm -f "$PROXY_PIDFILE"
      exit 1
    fi
    sleep 0.2
    i=$((i + 1))
  done

  echo "proxy did not listen within ${STARTUP_TIMEOUT}s. see $PROXY_LOG" >&2
  kill "$pid" 2>/dev/null || true
  rm -f "$PROXY_PIDFILE"
  exit 1
}

cleanup() {
  local status=$?
  if [ "$PROXY_STARTED" = "1" ] && [ "$STOP_PROXY_ON_EXIT" = "1" ] && [ -f "$PROXY_PIDFILE" ]; then
    local pid
    pid="$(cat "$PROXY_PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      echo "stopping proxy (pid $pid)" >&2
      kill "$pid" 2>/dev/null || true
      local i=0
      while [ "$i" -lt 10 ] && kill -0 "$pid" 2>/dev/null; do
        sleep 0.2
        i=$((i + 1))
      done
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PROXY_PIDFILE"
  fi
  exit $status
}
trap cleanup EXIT

if port_open; then
  echo "reusing proxy already listening on ${PROXY_URL}" >&2
else
  start_proxy
  PROXY_STARTED=1
fi

"$REAL_HELIUM" "${PROFILE_ARGS[@]}" --proxy-server="$PROXY_URL" "$@"
