#!/usr/bin/env bash
# Apply a test-only nftables policy for one UID.
#
#   sudo scripts/doorman-firewall.sh apply --user doorman-test
#   scripts/doorman-firewall.sh print --user doorman-test
#   sudo scripts/doorman-firewall.sh status
#   sudo scripts/doorman-firewall.sh revert
#
# The policy redirects TCP 80/443 from that UID to the strict proxy and drops
# all other TCP/UDP, except DNS to the resolver and loopback to the proxy.

set -euo pipefail

TABLE="${DOORMAN_TABLE:-doorman_test}"
PORT=8081
MODE=redirect
PROXY_PORTS=8080-8099
TARGET_UID=""
TARGET_USER="${DOORMAN_TEST_USER:-doorman-test}"
ACTION=""
DNS=()

usage() {
    cat <<'EOF'
usage: doorman-firewall.sh <apply|status|revert|print> [options]

options:
  --user NAME        user to restrict (default: doorman-test)
  --uid N            numeric uid instead of --user
  --proxy-port PORT  strict proxy port for redirect mode (default: 8081)
  --proxy-ports RANGE loopback ports allowed in drop mode (default: 8080-8099)
  --mode MODE        redirect (transparent) or drop (explicit proxies)
  --dns ADDR         resolver to allow; repeatable
  --table NAME       nftables table name (default: doorman_test)
  -h, --help         show this help

print does not need root. apply/status/revert do.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        apply|status|revert|print) ACTION="$1"; shift ;;
        --user) TARGET_USER="$2"; shift 2 ;;
        --uid) TARGET_UID="$2"; shift 2 ;;
        --proxy-port) PORT="$2"; shift 2 ;;
        --proxy-ports) PROXY_PORTS="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --dns) DNS+=("$2"); shift 2 ;;
        --table) TABLE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[ -n "$ACTION" ] || { usage; exit 2; }

if ! [[ "$TABLE" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "invalid table name: $TABLE" >&2
    exit 2
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "invalid proxy port: $PORT" >&2
    exit 2
fi
if [ "$MODE" != "redirect" ] && [ "$MODE" != "drop" ]; then
    echo "invalid mode: $MODE (use redirect or drop)" >&2
    exit 2
fi
if ! [[ "$PROXY_PORTS" =~ ^[0-9]+(-[0-9]+)?$ ]]; then
    echo "invalid proxy port range: $PROXY_PORTS" >&2
    exit 2
fi

if [ "$ACTION" = "apply" ] || [ "$ACTION" = "print" ]; then
    if [ -z "$TARGET_UID" ]; then
        if ! TARGET_UID="$(id -u "$TARGET_USER" 2>/dev/null)"; then
            echo "user does not exist: $TARGET_USER" >&2
            echo "create it with: scripts/doorman-test-user.sh" >&2
            exit 2
        fi
    fi
    if ! [[ "$TARGET_UID" =~ ^[0-9]+$ ]]; then
        echo "invalid uid: $TARGET_UID" >&2
        exit 2
    fi
fi

if [ "$ACTION" = "apply" ] || [ "$ACTION" = "print" ]; then
    if [ ${#DNS[@]} -eq 0 ]; then
        while read -r ns; do
            [ -n "$ns" ] && DNS+=("$ns")
        done < <(awk '/^[[:space:]]*nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null || true)
    fi
    if [ ${#DNS[@]} -eq 0 ]; then
        echo "no resolver found; pass --dns ADDR" >&2
        exit 2
    fi
    for ns in "${DNS[@]}"; do
        if ! [[ "$ns" =~ ^[0-9a-fA-F:.]+$ ]]; then
            echo "invalid resolver: $ns" >&2
            exit 2
        fi
    done
fi

rules() {
    cat <<EOF
table inet $TABLE {
EOF
    if [ "$MODE" = "redirect" ]; then
        cat <<EOF
    chain output_nat {
        type nat hook output priority -100; policy accept;
        meta skuid $TARGET_UID meta nfproto ipv4 tcp dport { 80, 443 } redirect to :$PORT
    }
EOF
    fi
    cat <<EOF
    chain output_filter {
        type filter hook output priority 0; policy accept;

        # The sandbox may reach the local proxies and its resolver.
EOF
    if [ "$MODE" = "drop" ]; then
        echo "        meta skuid $TARGET_UID ip daddr 127.0.0.1 tcp dport $PROXY_PORTS accept"
        echo "        meta skuid $TARGET_UID ip6 daddr ::1 tcp dport $PROXY_PORTS accept"
    else
        echo "        meta skuid $TARGET_UID ip daddr 127.0.0.1 tcp dport $PORT accept"
        echo "        meta skuid $TARGET_UID ip6 daddr ::1 tcp dport $PORT accept"
    fi
    for ns in "${DNS[@]}"; do
        if [[ "$ns" == *:* ]]; then
            echo "        meta skuid $TARGET_UID ip6 daddr $ns udp dport 53 accept"
            echo "        meta skuid $TARGET_UID ip6 daddr $ns tcp dport 53 accept"
        else
            echo "        meta skuid $TARGET_UID ip daddr $ns udp dport 53 accept"
            echo "        meta skuid $TARGET_UID ip daddr $ns tcp dport 53 accept"
        fi
    done
    cat <<EOF

        # Everything else from this user is dropped.
        meta skuid $TARGET_UID meta l4proto { tcp, udp } counter drop
    }
}
EOF
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "this action needs root: sudo $0 $ACTION" >&2
        exit 1
    fi
}

case "$ACTION" in
    print)
        rules
        ;;
    apply)
        require_root
        if [ "$MODE" = "redirect" ] && command -v ss >/dev/null 2>&1 \
            && ! ss -ltnH "sport = :$PORT" | grep -q .; then
            echo "warning: nothing is listening on port $PORT; start strict_proxy.py first" >&2
        fi
        nft delete table inet "$TABLE" 2>/dev/null || true
        rules | nft -f -
        echo "applied table inet $TABLE for uid $TARGET_UID mode $MODE" >&2
        echo "verify with: sudo $0 status --table $TABLE" >&2
        ;;
    status)
        require_root
        if ! nft list table inet "$TABLE" 2>/dev/null; then
            echo "table inet $TABLE is not present" >&2
        fi
        ;;
    revert)
        require_root
        nft delete table inet "$TABLE" 2>/dev/null || true
        echo "removed table inet $TABLE" >&2
        ;;
esac
