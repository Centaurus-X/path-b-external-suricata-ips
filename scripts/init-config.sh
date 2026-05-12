#!/usr/bin/env bash
# Path-B v5.12 — deployment.env generator for public lab deployments.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT_DIR/deployment.env.example"
OUTPUT="$ROOT_DIR/deployment.env"

PROXY_IP=""
ICAP_IP=""
CLIENT_IP=""
GATEWAY_IP=""
DNS_SERVERS=""
NET_CIDR=""
NET_PREFIX="24"
INTERFACE="auto"
OVERWRITE=0

usage() {
    cat <<'HELP'
Usage:
  bash scripts/init-config.sh \
    --proxy-ip <PROXY_VM_IP> \
    --icap-ip <ICAP_SURICATA_VM_IP> \
    --gateway-ip <GATEWAY_IP> \
    --client-ip <TEST_CLIENT_IP>

Optional:
  --dns "<DNS1 DNS2>"       Default: gateway IP
  --net-cidr <CIDR>         Default: inferred /24 from gateway IP
  --net-prefix <PREFIX>     Default: 24
  --interface <IFACE|auto>  Default: auto
  --output <FILE>           Default: deployment.env
  --force                   Overwrite existing output file

Example:
  bash scripts/init-config.sh \
    --proxy-ip 10.10.10.20 \
    --icap-ip 10.10.10.30 \
    --gateway-ip 10.10.10.1 \
    --client-ip 10.10.10.40 \
    --force
HELP
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxy-ip) PROXY_IP="$2"; shift 2 ;;
        --icap-ip|--suricata-ip) ICAP_IP="$2"; shift 2 ;;
        --client-ip|--test-client-ip) CLIENT_IP="$2"; shift 2 ;;
        --gateway-ip|--gateway) GATEWAY_IP="$2"; shift 2 ;;
        --dns|--dns-servers) DNS_SERVERS="$2"; shift 2 ;;
        --net-cidr) NET_CIDR="$2"; shift 2 ;;
        --net-prefix) NET_PREFIX="$2"; shift 2 ;;
        --interface) INTERFACE="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --force) OVERWRITE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

prompt_if_empty() {
    local var_name="$1"
    local label="$2"
    local default_value="${3:-}"
    local value="${!var_name:-}"
    if [[ -n "$value" ]]; then
        return 0
    fi
    if [[ -t 0 ]]; then
        if [[ -n "$default_value" ]]; then
            read -r -p "$label [$default_value]: " value
            value="${value:-$default_value}"
        else
            read -r -p "$label: " value
        fi
        printf -v "$var_name" '%s' "$value"
    fi
}

infer_cidr_from_gateway() {
    local gateway="$1"
    local prefix="$2"
    if [[ "$gateway" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.[0-9]+$ ]]; then
        printf '%s.%s.%s.0/%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "$prefix"
        return 0
    fi
    printf '10.10.10.0/%s' "$prefix"
}

prompt_if_empty GATEWAY_IP "Gateway/DNS IP" "10.10.10.1"
prompt_if_empty PROXY_IP "Proxy VM IP" "10.10.10.20"
prompt_if_empty ICAP_IP "ICAP/Suricata VM IP" "10.10.10.30"
prompt_if_empty CLIENT_IP "Test client IP" "10.10.10.40"

if [[ -z "$DNS_SERVERS" ]]; then
    DNS_SERVERS="$GATEWAY_IP"
fi
if [[ -z "$NET_CIDR" ]]; then
    NET_CIDR="$(infer_cidr_from_gateway "$GATEWAY_IP" "$NET_PREFIX")"
fi

[[ -r "$TEMPLATE" ]] || { echo "Template not found: $TEMPLATE" >&2; exit 1; }
if [[ -e "$OUTPUT" && "$OVERWRITE" != "1" ]]; then
    echo "Output file already exists: $OUTPUT" >&2
    echo "Use --force to overwrite it." >&2
    exit 1
fi

cp "$TEMPLATE" "$OUTPUT"

python3 - "$OUTPUT" <<PY
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
updates = {
    "PATHB_GATEWAY_IP": "$GATEWAY_IP",
    "PATHB_DNS_SERVERS": "\"$DNS_SERVERS\"",
    "PATHB_NET_CIDR": "$NET_CIDR",
    "PATHB_NET_PREFIX": "$NET_PREFIX",
    "PATHB_PROXY_IP": "$PROXY_IP",
    "PATHB_SURICATA_IP": "$ICAP_IP",
    "PATHB_TEST_CLIENT_IP": "$CLIENT_IP",
    "PATHB_INTERFACE": "$INTERFACE",
}
lines = path.read_text(encoding="utf-8").splitlines()
out = []
seen = set()
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        key = line.split("=", 1)[0]
        if key in updates:
            out.append(f"{key}={updates[key]}")
            seen.add(key)
            continue
    out.append(line)
for key, value in updates.items():
    if key not in seen:
        out.append(f"{key}={value}")
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY

cat <<OUT
Path-B deployment configuration created:
  $OUTPUT

Summary:
  Gateway/DNS:        $GATEWAY_IP
  Lab network:        $NET_CIDR
  Proxy VM:           $PROXY_IP:3128
  ICAP/Suricata VM:   $ICAP_IP:1345
  Test client:        $CLIENT_IP
  Interface:          $INTERFACE

Next steps:
  bash scripts/show-config.sh --config $OUTPUT
  sudo bash scripts/install.sh --role icap --config $OUTPUT
  sudo bash scripts/install.sh --role proxy --config $OUTPUT
OUT
