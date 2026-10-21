#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$HOME/Projects/doorman}"
REAL_CHROMIUM="${REAL_CHROMIUM:-/usr/bin/chromium}"
PROXY_HOST="127.0.0.1"
PROXY_PORT="8080"
PROXY_URL="http://${PROXY_HOST}:${PROXY_PORT}"
PROFILE="$HOME/.config/chromium-blocker-profile"

LOG_DIR="$PROJECT_DIR/logs"
PROXY_LOG="$LOG_DIR/mitmdump.log"
PROXY_PIDFILE="$LOG_DIR/mitmdump.pid"
MITMDUMP="$PROJECT_DIR/.venv/bin/mitmdump"
ADDON="$PROJECT_DIR/addon.py"

STARTUP_TIMEOUT=10     # seconds to wait for the proxy to start listening
STOP_PROXY_ON_EXIT=1
MAX_LOG_BYTES=5000000

mkdir -p "$LOG_DIR"
die() { echo "error: $*" >&2; exit 1; }

port_open() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH "sport = :${PROXY_PORT}" 2>/dev/null | grep -q .
  else
    (exec 3<>"/dev/tcp/${PROXY_HOST}/${PROXY_PORT}") 2>/dev/null
  fi
}

[ -x "$REAL_CHROMIUM" ] || die "$REAL_CHROMIUM not found - set REAL_CHROMIUM=/usr/bin/chromium"
[ -f "$ADDON" ]        || die "$ADDON not found"
[ -x "$MITMDUMP" ]     || die "$MITMDUMP not found. Create the venv first:
  python3 -m venv $PROJECT_DIR/.venv && $PROJECT_DIR/.venv/bin/pip install mitmproxy"

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

"$REAL_CHROMIUM" "$@" \
  --user-data-dir="$PROFILE" \
  --proxy-server="$PROXY_URL"
