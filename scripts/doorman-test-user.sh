#!/usr/bin/env bash
# Create the throwaway account used by the firewall tests.
# It has no home directory and no login shell; commands are run with sudo -u.

set -euo pipefail

NAME="${1:-doorman-test}"

if id "$NAME" >/dev/null 2>&1; then
    echo "user already exists: $NAME (uid $(id -u "$NAME"))"
    exit 0
fi

sudo useradd --system --no-create-home --shell /usr/bin/nologin "$NAME"
echo "created $NAME (uid $(id -u "$NAME"))"
