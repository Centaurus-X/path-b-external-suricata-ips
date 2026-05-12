#!/usr/bin/env bash
# Path-B v5.12 — compact diagnostics for proxy or ICAP role
set -euo pipefail

ROLE="auto"
CONFIG="deployment.env"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --role) ROLE="$2"; shift 2 ;;
        --config|--env) CONFIG="$2"; shift 2 ;;
        -h|--help)
            cat <<'HELP'
Usage:
  bash scripts/doctor.sh --role icap  --config deployment.env
  bash scripts/doctor.sh --role proxy --config deployment.env
HELP
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="$CONFIG"
[[ "$CONFIG_PATH" = /* ]] || CONFIG_PATH="$ROOT_DIR/$CONFIG_PATH"
[[ -r "$CONFIG_PATH" ]] || { echo "Configuration file is not readable: $CONFIG_PATH" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONFIG_PATH"

is_auto() { case "${1:-}" in ""|auto|AUTO|detect|DETECT) return 0 ;; *) return 1 ;; esac; }
local_ips() { ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1; }
detect_role() {
    local ip
    for ip in $(local_ips); do
        if [[ -n "${PATHB_PROXY_IP:-}" && "$ip" == "$PATHB_PROXY_IP" ]]; then printf 'proxy'; return 0; fi
        if [[ -n "${PATHB_SURICATA_IP:-}" && "$ip" == "$PATHB_SURICATA_IP" ]]; then printf 'icap'; return 0; fi
    done
    return 1
}

if [[ "$ROLE" == "auto" ]]; then
    ROLE="$(detect_role || true)"
    [[ -n "$ROLE" ]] || ROLE="unknown"
fi

icap_host="${ICAP_SURICATA_HOST:-${PATHB_SURICATA_IP:-127.0.0.1}}"
if is_auto "$icap_host"; then icap_host="${PATHB_SURICATA_IP:-127.0.0.1}"; fi
icap_port="${ICAP_SURICATA_PORT:-${ICAP_PORT:-1345}}"
proxy_host="${PATHB_PROXY_IP:-127.0.0.1}"
proxy_port="${OUTBOUND_HTTP_PORT:-3128}"
health_host="${PATHB_SURICATA_IP:-127.0.0.1}"
health_port="${HEALTH_PORT:-2345}"

section() { printf '\n==> %s\n' "$*"; }
run_or_true() { "$@" || true; }

section "role and configuration"
echo "Role:        $ROLE"
echo "Config:      $CONFIG_PATH"
echo "Proxy:       ${proxy_host}:${proxy_port}"
echo "ICAP:        ${icap_host}:${icap_port}"
echo "Health:      ${health_host}:${health_port}"

section "Netzwerk"
run_or_true ip -br addr
run_or_true ip route show default

section "Listener"
run_or_true ss -ltnp

section "ICAP OPTIONS"
if command -v nc >/dev/null 2>&1; then
    printf 'OPTIONS icap://%s:%s/options ICAP/1.0\r\nHost: %s\r\nEncapsulated: null-body=0\r\n\r\n' "$icap_host" "$icap_port" "$icap_host" \
        | timeout 8 nc -q 1 "$icap_host" "$icap_port" || true
else
    echo "nc missing"
fi

section "Health"
if command -v curl >/dev/null 2>&1; then
    run_or_true curl -sS "http://${health_host}:${health_port}/healthz"
    echo
else
    echo "curl missing"
fi

case "$ROLE" in
    icap|suricata)
        section "ICAP/Suricata Services"
        run_or_true systemctl --no-pager --full status icap-suricata-engine.service
        run_or_true systemctl --no-pager --full status icap-suricata-server.service
        section "Letzte ICAP/Suricata Logs"
        run_or_true journalctl -u icap-suricata-engine.service -n 40 --no-pager
        run_or_true journalctl -u icap-suricata-server.service -n 40 --no-pager
        ;;
    proxy)
        section "Proxy Services"
        run_or_true systemctl --no-pager --full status squid.service
        section "Letzte Squid Logs"
        run_or_true journalctl -u squid.service -n 40 --no-pager
        ;;
esac
