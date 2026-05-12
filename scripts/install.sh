#!/usr/bin/env bash
# Path-B v5.12 — central role installer.
set -euo pipefail

ROLE="auto"
CONFIG="deployment.env"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role) ROLE="$2"; shift 2 ;;
        --config|--env) CONFIG="$2"; shift 2 ;;
        --with-clamav|--without-clamav|--no-clamav|--no-firewall|--install-suricata-repo) EXTRA_ARGS+=("$1"); shift ;;
        -h|--help)
            cat <<'HELP'
Usage:
  sudo bash scripts/install.sh --role icap  --config deployment.env
  sudo bash scripts/install.sh --role proxy --config deployment.env
  sudo bash scripts/install.sh --role proxy --with-clamav

The auto role tries to detect the local role from PATHB_PROXY_IP or PATHB_SURICATA_IP.
Create deployment.env first:
  bash scripts/init-config.sh --proxy-ip <PROXY_IP> --icap-ip <ICAP_IP> --gateway-ip <GATEWAY_IP> --client-ip <CLIENT_IP>
HELP
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="$CONFIG"
[[ "$CONFIG_PATH" = /* ]] || CONFIG_PATH="$ROOT_DIR/$CONFIG_PATH"
if [[ ! -r "$CONFIG_PATH" ]]; then
    cat >&2 <<ERR
Configuration file is not readable: $CONFIG_PATH
Create it first, for example:
  bash scripts/init-config.sh --proxy-ip <PROXY_IP> --icap-ip <ICAP_IP> --gateway-ip <GATEWAY_IP> --client-ip <CLIENT_IP>
ERR
    exit 1
fi
# shellcheck disable=SC1090
. "$CONFIG_PATH"

local_ips() {
    ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
}

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
    [[ -n "$ROLE" ]] || { echo "Role could not be detected automatically. Use --role proxy or --role icap." >&2; exit 1; }
fi

case "$ROLE" in
    icap|suricata)
        exec bash "$ROOT_DIR/icap-vm/scripts/install-icap-suricata.sh" --env "$CONFIG_PATH" "${EXTRA_ARGS[@]}"
        ;;
    proxy)
        exec bash "$ROOT_DIR/proxy-vm/scripts/install-proxy-vm.sh" --env "$CONFIG_PATH" "${EXTRA_ARGS[@]}"
        ;;
    *) echo "Invalid role: $ROLE" >&2; exit 2 ;;
esac
