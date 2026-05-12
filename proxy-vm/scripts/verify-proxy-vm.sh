#!/usr/bin/env bash
# Path-B v5.12 — Proxy-VM Verification
set -uo pipefail

ENV_FILE=""
RUN_CURL_TEST=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env|--config) ENV_FILE="$2"; shift 2 ;;
        --curl-test) RUN_CURL_TEST=1; shift ;;
        -h|--help) sed -n '1,110p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ -z "$ENV_FILE" && -r "$ROOT_DIR/deployment.env" ]]; then ENV_FILE="$ROOT_DIR/deployment.env"; fi
if [[ -n "$ENV_FILE" ]]; then
    [[ -r "$ENV_FILE" ]] || { echo "ENV file is not readable: $ENV_FILE" >&2; exit 1; }
    # shellcheck disable=SC1090
    . "$ENV_FILE"
fi

is_true() { case "${1:-}" in 1|yes|YES|true|TRUE|on|ON) return 0 ;; *) return 1 ;; esac; }
is_auto() { case "${1:-}" in ""|auto|AUTO|detect|DETECT) return 0 ;; *) return 1 ;; esac; }
detect_primary_if() { ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'; }
detect_ip_for_if() { ip -o -4 addr show dev "$1" scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1; }
detect_prefix_for_if() { ip -o -4 addr show dev "$1" scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f2; }

primary_if="$(detect_primary_if || true)"; [[ -n "$primary_if" ]] || primary_if="eth0"
PATHB_INTERFACE="${PATHB_INTERFACE:-auto}"; if is_auto "$PATHB_INTERFACE"; then PATHB_INTERFACE="$primary_if"; fi
prefix="$(detect_prefix_for_if "$PATHB_INTERFACE" || true)"; [[ -n "$prefix" ]] || prefix="${PATHB_NET_PREFIX:-24}"
proxy_candidate="${PATHB_PROXY_IP:-auto}"
if is_auto "$proxy_candidate"; then proxy_candidate="$(detect_ip_for_if "$PATHB_INTERFACE" || true)"; fi
[[ -n "$proxy_candidate" ]] || proxy_candidate="127.0.0.1"
PROXY_IP="${PROXY_IP:-auto}"
if is_auto "$PROXY_IP"; then
    if [[ "$proxy_candidate" == */* ]]; then PROXY_IP="$proxy_candidate"; else PROXY_IP="${proxy_candidate}/${prefix}"; fi
fi
OUTBOUND_HTTP_PORT="${OUTBOUND_HTTP_PORT:-3128}"
OUTBOUND_HTTPS_INTERCEPT_PORT="${OUTBOUND_HTTPS_INTERCEPT_PORT:-3129}"
ICAP_SURICATA_HOST="${ICAP_SURICATA_HOST:-auto}"
if is_auto "$ICAP_SURICATA_HOST"; then
    if is_auto "${PATHB_SURICATA_IP:-auto}"; then ICAP_SURICATA_HOST="127.0.0.1"; else ICAP_SURICATA_HOST="$PATHB_SURICATA_IP"; fi
fi
ICAP_SURICATA_PORT="${ICAP_SURICATA_PORT:-1345}"
ENABLE_CLAMAV_ICAP="${ENABLE_CLAMAV_ICAP:-0}"
ENABLE_INBOUND="${ENABLE_INBOUND:-0}"
INBOUND_HTTPS_PORT="${INBOUND_HTTPS_PORT:-443}"

GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0
ok() { printf "  ${GREEN}OK${NC}   %s\n" "$*"; PASS=$((PASS+1)); }
bad() { printf "  ${RED}FAIL${NC} %s\n" "$*"; FAIL=$((FAIL+1)); }
warn() { printf "  ${YELLOW}WARN${NC} %s\n" "$*"; WARN=$((WARN+1)); }
sec() { printf "\n==> %s\n" "$*"; }
proxy_addr() { printf '%s' "${PROXY_IP%/*}"; }

check_pkg() {
    if dpkg -s "$1" >/dev/null 2>&1; then ok "Paket $1"; else bad "Paket $1 missing"; fi
}
check_service() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then ok "Service $1 active"; else bad "Service $1 inactive"; fi
}
check_listener() {
    local port="$1" label="$2"
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "(:|\])${port}$"; then ok "$label listens on TCP/$port"; else warn "$label does not listen on TCP/$port"; fi
}
icap_options() {
    local host="$1" port="$2"
    printf 'OPTIONS icap://%s:%s/options ICAP/1.0\r\nHost: %s\r\nEncapsulated: null-body=0\r\n\r\n' "$host" "$port" "$host" \
        | timeout 8 nc -q 1 "$host" "$port" 2>/dev/null
}

sec "L1 — packages"
if dpkg -s squid-openssl >/dev/null 2>&1; then
    ok "Paket squid-openssl"
elif dpkg -s squid >/dev/null 2>&1; then
    ok "Paket squid (Fallback)"
else
    bad "Paket squid-openssl/squid missing"
fi
check_pkg nftables
check_pkg netcat-openbsd
if is_true "$ENABLE_CLAMAV_ICAP"; then
    check_pkg c-icap
    check_pkg clamav-daemon
else
    warn "local c-ICAP/ClamAV disabled; package check skipped"
fi

sec "L2 — Squid Build + configuration"
if command -v squid >/dev/null 2>&1; then
    if squid -v | grep -q -- '--enable-icap-client'; then ok "Squid ICAP client present"; else bad "Squid without ICAP client support"; fi
    if squid -v | grep -q -- '--enable-ssl-crtd'; then ok "Squid ssl-crtd present"; else warn "Squid does not report --enable-ssl-crtd"; fi
    if squid -k parse >/tmp/pathb-squid-verify-parse.log 2>&1; then ok "squid -k parse"; else bad "squid -k parse failed: $(tail -n 2 /tmp/pathb-squid-verify-parse.log | tr '\n' ' ')"; fi
else
    bad "squid Binary missing"
fi

if grep -qE '^adaptation_service_chain pathb_req_chain' /etc/squid/squid.conf 2>/dev/null; then ok "REQMOD Service-Chain konfiguriert"; else bad "REQMOD Service-Chain missing"; fi
if grep -qE '^adaptation_service_chain pathb_resp_chain' /etc/squid/squid.conf 2>/dev/null; then ok "RESPMOD Service-Chain konfiguriert"; else bad "RESPMOD Service-Chain missing"; fi
if grep -qE '^adaptation_send_client_ip on' /etc/squid/squid.conf 2>/dev/null; then ok "X-Client-IP forwarding enabled"; else warn "adaptation_send_client_ip not found"; fi
if grep -q "icap://${ICAP_SURICATA_HOST}:${ICAP_SURICATA_PORT}" /etc/squid/squid.conf 2>/dev/null; then ok "external Suricata ICAP VM configured"; else bad "external Suricata ICAP VM missing in squid.conf"; fi

sec "L3 — CA + SSL-DB"
[[ -f /etc/squid/ssl_cert/myCA.crt ]] && ok "myCA.crt present" || bad "myCA.crt missing"
[[ -f /etc/squid/ssl_cert/myCA.pem ]] && ok "myCA.pem present" || bad "myCA.pem missing"
[[ -d /var/lib/ssl_db ]] && ok "ssl_db present" || bad "ssl_db missing"
if [[ -f /etc/squid/ssl_cert/myCA.crt ]]; then
    not_after=$(openssl x509 -in /etc/squid/ssl_cert/myCA.crt -noout -enddate 2>/dev/null | cut -d= -f2)
    [[ -n "$not_after" ]] && ok "CA valid until: $not_after" || warn "CA date not readable"
fi
[[ -f "$ROOT_DIR/certs/proxy/myCA.crt" ]] && ok "CA exported: $ROOT_DIR/certs/proxy/myCA.crt" || warn "CA not exported to project directory"

sec "L4 — Services"
check_service squid
if is_true "$ENABLE_CLAMAV_ICAP"; then
    check_service c-icap
    check_service clamav-daemon
fi
check_service nftables

sec "L5 — Listener"
check_listener "$OUTBOUND_HTTP_PORT" "Squid explicit/outbound"
check_listener "$OUTBOUND_HTTPS_INTERCEPT_PORT" "Squid HTTPS intercept"
if is_true "$ENABLE_INBOUND"; then check_listener "$INBOUND_HTTPS_PORT" "Squid inbound reverse HTTPS"; fi
if is_true "$ENABLE_CLAMAV_ICAP"; then check_listener 1344 "local c-ICAP"; fi

sec "L6 — Externer ICAP/Suricata-Kontakt"
if command -v nc >/dev/null 2>&1; then
    response="$(icap_options "$ICAP_SURICATA_HOST" "$ICAP_SURICATA_PORT")"
    if printf '%s' "$response" | grep -q 'ICAP/1.0 200'; then ok "ICAP OPTIONS external Suricata-VM"; else bad "ICAP OPTIONS external Suricata-VM failed"; fi
else
    warn "nc missing — ICAP OPTIONS not getestet"
fi

sec "L7 — routing and firewall"
default_route=$(ip route show default 2>/dev/null | head -1)
[[ -n "$default_route" ]] && ok "Default-Route: $default_route" || bad "no default route"
if nft list ruleset >/dev/null 2>&1; then ok "nftables ruleset readable"; else bad "nftables ruleset not readable"; fi

sec "L8 — Optionaler End-to-End Proxy-Test"
if [[ "$RUN_CURL_TEST" -eq 1 ]]; then
    proxy_url="http://$(proxy_addr):${OUTBOUND_HTTP_PORT}"

    result=$(curl -sS -m 20 -x "$proxy_url" -o /tmp/pathb-proxy-http-allow.out -w '%{http_code}' http://example.com/ 2>/tmp/pathb-proxy-http-allow.err)
    if [[ "$result" != "000" && "$result" != "500" ]]; then
        ok "HTTP baseline test through Squid/ICAP without trigger"
    else
        bad "HTTP baseline test returned status $result; details: $(tr '\n' ' ' </tmp/pathb-proxy-http-allow.err)"
    fi

    result=$(curl -sS -m 20 -x "$proxy_url" -H 'X-Proxylab-Test: icap-suricata-trigger' -o /tmp/pathb-proxy-http-block.out -w '%{http_code}' http://example.com/ 2>/tmp/pathb-proxy-http-block.err)
    if [[ "$result" == "403" ]]; then
        ok "HTTP block test through Squid was blocked by Suricata ICAP"
    else
        warn "HTTP-Blocktest ergab Status $result; details: $(tr '\n' ' ' </tmp/pathb-proxy-http-block.err)"
    fi

    result=$(curl -k -sS -m 30 -x "$proxy_url" -o /tmp/pathb-proxy-https-allow.out -w '%{http_code}' https://example.com/ 2>/tmp/pathb-proxy-https-allow.err)
    if [[ "$result" != "000" && "$result" != "500" ]]; then
        ok "HTTPS SSL-Bump test through Squid/ICAP without CA verification"
    else
        bad "HTTPS SSL-Bump Test ergab Status $result; details: $(tr '\n' ' ' </tmp/pathb-proxy-https-allow.err)"
    fi
else
    warn "End-to-end curl test not executed; optional: --curl-test"
fi

printf "\n============================================================\n"
printf "Proxy-VM Verification: PASS=%d WARN=%d FAIL=%d\n" "$PASS" "$WARN" "$FAIL"
printf "============================================================\n"
[[ "$FAIL" -eq 0 ]] || exit 1
