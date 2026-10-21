#!/usr/bin/env bash
set -euo pipefail
sudo mkdir -p /etc/chromium/policies/managed
sudo install -m 644 "$(dirname "$0")/policy/internet-blocker.json" \
  /etc/chromium/policies/managed/internet-blocker.json
echo "Policy installed. Restart Chromium and check chrome://policy"
