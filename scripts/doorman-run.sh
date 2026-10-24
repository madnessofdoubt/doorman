#!/usr/bin/env bash
# Run an app with its traffic sent to the strict proxy.
#
#   scripts/doorman-run.sh steam
#   scripts/doorman-run.sh --allowlist steam_allowlist.txt --default deny steam
#   scripts/doorman-run.sh --restart -- steam --some-flag
#
# The proxy is started if it is not already listening, and stopped on exit.
# Set DOORMAN_KEEP_PROXY=1 to leave a running proxy alone.

set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
PYTHON="$PROJECT_DIR/.venv/bin/python"
PROXY="$PROJECT_DIR/strict_proxy.py"
LOG_DIR="$PROJECT_DIR/logs"
PROXY_LOG="$LOG_DIR/strict-proxy.log"
PROXY_PIDFILE="$LOG_DIR/strict-proxy.pid"
HOST=127.0.0.1
PORT=8081
ALLOWLIST="$PROJECT_DIR/strict_allowlist.txt"
DEFAULT_ORDER=deny
STARTUP_TIMEOUT=5

usage() {
    cat <<'EOF'
usage: doorman-run.sh [options] -- command [args...]

options:
  --allowlist FILE   host list for the proxy (default: strict_allowlist.txt)
  --default deny|allow  policy for hosts not on the allowlist (default: deny)
  --port N           proxy port (default: 8081)
  --restart          restart the proxy even if one is already running
  -h, --help         show this help

environment:
  DOORMAN_KEEP_PROXY=1  do not stop the proxy when the command exits
EOF
}

PROXY_STARTED=0
RESTART=0

while [ $# -gt 0 ]; do
    case "$1" in
        --allowlist) ALLOWLIST="$2"; shift 2 ;;
        --default) DEFAULT_ORDER="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --restart) RESTART=1; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*) echo "unknown option: $1" >&2; usage; exit 2 ;;
        *) break ;;
    esac
done

[ $# -gt 0 ] || { usage; exit 2; }
[ -x "$PYTHON" ] || { echo "missing $PYTHON; create the venv first" >&2; exit 1; }
[ -f "$PROXY" ] || { echo "missing $PROXY" >&2; exit 1; }
[ -f "$ALLOWLIST" ] || { echo "missing allowlist: $ALLOWLIST" >&2; exit 1; }

mkdir -p "$LOG_DIR"

port_open() {
    if command -v ss >/dev/null 2>&1; then
        ss -ltnH "sport = :${PORT}" 2>/dev/null | grep -q .
    else
        (exec 3<>"/dev/tcp/${HOST}/${PORT}") 2>/dev/null
    fi
}

stop_existing() {
    [ -f "$PROXY_PIDFILE" ] || return 0
    local pid
    pid="$(cat "$PROXY_PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        local i=0
        while [ "$i" -lt 25 ] && kill -0 "$pid" 2>/dev/null; do
            sleep 0.2
            i=$((i + 1))
        done
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PROXY_PIDFILE"
}

start_proxy() {
    echo "starting proxy on ${HOST}:${PORT} (default ${DEFAULT_ORDER})..." >&2
    PROXY_ARGS=(--allowlist "$ALLOWLIST" --default "$DEFAULT_ORDER")
    nohup "$PYTHON" "$PROXY" "${PROXY_ARGS[@]}" --listen-host "$HOST" \
        --listen-port "$PORT" >>"$PROXY_LOG" 2>&1 &
    local pid=$!
    echo "$pid" >"$PROXY_PIDFILE"

    local tries=$((STARTUP_TIMEOUT * 5)) i=0
    while [ "$i" -lt "$tries" ]; do
        if port_open; then
            echo "proxy ready (pid $pid). log: $PROXY_LOG" >&2
            PROXY_STARTED=1
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "proxy exited during startup. last lines:" >&2
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
    if [ "$PROXY_STARTED" = "1" ] && [ "${DOORMAN_KEEP_PROXY:-0}" != "1" ]; then
        stop_existing
    fi
    exit "$status"
}
trap cleanup EXIT

if [ "$RESTART" = "1" ]; then
    stop_existing
elif port_open; then
    echo "reusing proxy already listening on ${HOST}:${PORT}" >&2
else
    start_proxy
fi

# Most CEF/Electron/libcurl apps read these. The app still decides for itself;
# this is why the firewall step exists.
export http_proxy="http://${HOST}:${PORT}"
export https_proxy="$http_proxy"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$http_proxy"
export no_proxy="localhost,127.0.0.1,::1"
export NO_PROXY="$no_proxy"

"$@"
