#!/usr/bin/env bash
set -euo pipefail

REAL_CHROMIUM="${REAL_CHROMIUM:-/usr/bin/chromium}"
PROXY="http://127.0.0.1:8080"
PROFILE="$HOME/.config/chromium-blocker-profile"

if [ ! -x "$REAL_CHROMIUM" ]; then
  echo "error: $REAL_CHROMIUM not found - set REAL_CHROMIUM=/usr/bin/chromium" >&2
  exit 1
fi

if command -v ss >/dev/null 2>&1; then
  if ! ss -ltnH 'sport = :8080' | grep -q .; then
    echo "error: nothing listening on 127.0.0.1:8080. Start the blocker first:" >&2
    echo "  mitmdump -s $HOME/internet-blocker/addon.py -p 8080" >&2
    echo "(to bypass the blocker entirely, run $REAL_CHROMIUM directly)" >&2
    exit 1
  fi
fi

exec "$REAL_CHROMIUM" "$@" \
  --user-data-dir="$PROFILE" \
  --proxy-server="$PROXY"
