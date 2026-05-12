#!/usr/bin/env bash
# Path-B v5.12 — compact deployment configuration overview.
set -euo pipefail
CONFIG="deployment.env"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config|--env) CONFIG="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: bash scripts/show-config.sh [--config deployment.env]"; exit 0 ;;
        *) CONFIG="$1"; shift ;;
    esac
done
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="$CONFIG"
[[ "$CONFIG_PATH" = /* ]] || CONFIG_PATH="$ROOT_DIR/$CONFIG_PATH"
if [[ ! -r "$CONFIG_PATH" ]]; then
    cat >&2 <<ERR
Configuration file is not readable: $CONFIG_PATH
Create one first, for example:
  bash scripts/init-config.sh --proxy-ip <PROXY_IP> --icap-ip <ICAP_IP> --gateway-ip <GATEWAY_IP> --client-ip <CLIENT_IP>
ERR
    exit 1
fi
# shellcheck disable=SC1090
. "$CONFIG_PATH"
cat <<CONF
Path-B v5.12 deployment configuration

Gateway/DNS:          ${PATHB_GATEWAY_IP:-auto}
Lab network:          ${PATHB_NET_CIDR:-auto}
Test client:          ${PATHB_TEST_CLIENT_IP:-auto}
Proxy VM:             ${PATHB_PROXY_IP:-auto}:3128
ICAP/Suricata VM:     ${PATHB_SURICATA_IP:-auto}:${ICAP_PORT:-1345}
Interface:            ${PATHB_INTERFACE:-auto}
Write netplan:        ${APPLY_NETPLAN:-0}
Local ClamAV ICAP:    ${ENABLE_CLAMAV_ICAP:-0}
ICAP Preview:         ${ICAP_PREVIEW_ENABLE:-off} / ${ICAP_PREVIEW_SIZE:-8192} bytes
ICAP Workers/Conn:    ${ICAP_WORKERS:-32} / ${ICAP_SURICATA_MAX_CONN:-32}
Suricata pipeline:    ${SURICATA_PIPELINE_CONCURRENCY:-6}, poll ${SURICATA_QUEUE_POLL_MS:-10} ms
REQMOD static bypass: ${REQMOD_STATIC_BYPASS_ENABLED:-1}
Latency sampling:     every ${LATENCY_SAMPLE_EVERY:-200} objects, slow >= ${SLOW_REQUEST_LOG_MS:-350} ms
RESPMOD scan:         ${RESPMOD_ENABLED:-1}, max ${RESPMOD_MAX_SCAN_BYTES:-262144} bytes
Small download scan:  ${RESPMOD_SCAN_SMALL_BODIES_BYTES:-131072} bytes
Inbound enabled:      ${ENABLE_INBOUND:-0}
CONF
