#!/usr/bin/env bash
# Path-B v5.12 — ICAP/Suricata-VM Verification
set -uo pipefail

ENV_FILE=""
ARG_HOST=""
ARG_PORT=""
ARG_HEALTH_PORT=""
RUN_PAYLOAD_TESTS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env|--config) ENV_FILE="$2"; shift 2 ;;
        --host) ARG_HOST="$2"; shift 2 ;;
        --port) ARG_PORT="$2"; shift 2 ;;
        --health-port) ARG_HEALTH_PORT="$2"; shift 2 ;;
        --no-payload-tests) RUN_PAYLOAD_TESTS=0; shift ;;
        -h|--help) sed -n '1,110p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ -z "$ENV_FILE" ]]; then
    if [[ -r /etc/icap-suricata/icap-server.env ]]; then ENV_FILE="/etc/icap-suricata/icap-server.env"; elif [[ -r "$ROOT_DIR/deployment.env" ]]; then ENV_FILE="$ROOT_DIR/deployment.env"; fi
fi
if [[ -n "$ENV_FILE" ]]; then
    [[ -r "$ENV_FILE" ]] || { echo "ENV file is not readable: $ENV_FILE" >&2; exit 1; }
    # shellcheck disable=SC1090
    . "$ENV_FILE"
fi

is_auto() { case "${1:-}" in ""|auto|AUTO|detect|DETECT) return 0 ;; *) return 1 ;; esac; }
resolve_host() {
    local value="$1" fallback="$2"
    if is_auto "$value"; then printf '%s' "$fallback"; else printf '%s' "$value"; fi
}
byte_len() { LC_ALL=C printf '%s' "$1" | wc -c | tr -d ' '; }

fallback_suri="${PATHB_SURICATA_IP:-127.0.0.1}"
if is_auto "$fallback_suri"; then fallback_suri="127.0.0.1"; fi
HOST="${ARG_HOST:-$(resolve_host "${ICAP_BIND:-auto}" "$fallback_suri")}"
PORT="${ARG_PORT:-${ICAP_PORT:-1345}}"
HEALTH_HOST="$(resolve_host "${HEALTH_BIND:-${ICAP_BIND:-auto}}" "$HOST")"
HEALTH_PORT="${ARG_HEALTH_PORT:-${HEALTH_PORT:-2345}}"
EVE_PATH="${EVE_PATH:-/var/log/suricata-icap/eve.json}"
SURICATA_SOCKET="${SURICATA_SOCKET:-/run/suricata-icap/suricata-cmd.socket}"
[[ "$HOST" == "0.0.0.0" ]] && HOST="127.0.0.1"
[[ "$HEALTH_HOST" == "0.0.0.0" ]] && HEALTH_HOST="127.0.0.1"

GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0
ok() { printf "  ${GREEN}OK${NC}   %s\n" "$*"; PASS=$((PASS+1)); }
bad() { printf "  ${RED}FAIL${NC} %s\n" "$*"; FAIL=$((FAIL+1)); }
warn() { printf "  ${YELLOW}WARN${NC} %s\n" "$*"; WARN=$((WARN+1)); }
sec() { printf "\n==> %s\n" "$*"; }

send_icap_stream() {
    timeout 15 nc -q 1 "$HOST" "$PORT" 2>/dev/null
}

icap_options() {
    printf 'OPTIONS icap://%s:%s/options ICAP/1.0\r\nHost: %s\r\nEncapsulated: null-body=0\r\n\r\n' "$HOST" "$PORT" "$HOST" \
        | send_icap_stream
}

icap_reqmod_trigger() {
    local http req_len
    http=$'GET http://example.test/pathb-icap-test HTTP/1.1\r\nHost: example.test\r\nUser-Agent: pathb-verify\r\nX-Proxylab-Test: icap-suricata-trigger\r\n\r\n'
    req_len="$(byte_len "$http")"
    {
        printf 'REQMOD icap://%s:%s/reqmod ICAP/1.0\r\nHost: %s\r\nX-Client-IP: 10.10.10.40\r\nX-Server-IP: 198.51.100.10\r\nAllow: 204\r\nEncapsulated: req-hdr=0, null-body=%s\r\n\r\n' "$HOST" "$PORT" "$HOST" "$req_len"
        printf '%s' "$http"
    } | send_icap_stream
}

icap_respmod_trigger() {
    python3 - "$HOST" "$PORT" <<'PYCODE' | send_icap_stream
import sys

host = sys.argv[1]
port = sys.argv[2]
request = b"GET http://example.test/response-test HTTP/1.1\r\nHost: example.test\r\nUser-Agent: pathb-verify\r\n\r\n"
body = b"PROXYLAB-ICAP-RESPONSE-TRIGGER"
response_header = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n"
)
req_len = len(request)
res_body_off = req_len + len(response_header)
chunked = (format(len(body), "x").encode("ascii") + b"\r\n" + body + b"\r\n0\r\n\r\n")
header = (
    b"RESPMOD icap://" + host.encode("ascii") + b":" + port.encode("ascii") + b"/respmod ICAP/1.0\r\n"
    b"Host: " + host.encode("ascii") + b"\r\n"
    b"X-Client-IP: 10.10.10.40\r\n"
    b"X-Server-IP: 198.51.100.10\r\n"
    b"Allow: 204\r\n"
    b"Encapsulated: req-hdr=0, res-hdr=" + str(req_len).encode("ascii") + b", res-body=" + str(res_body_off).encode("ascii") + b"\r\n\r\n"
)
sys.stdout.buffer.write(header + request + response_header + chunked)
PYCODE
}

icap_respmod_preview_partial() {
    python3 - "$HOST" "$PORT" <<'PYCODE'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
request = b"GET http://example.test/preview-test HTTP/1.1\r\nHost: example.test\r\nUser-Agent: pathb-preview-verify\r\n\r\n"
body = b"A" * 65536
response_header = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    + b"Content-Length: " + str(len(body) + 100000).encode("ascii") + b"\r\n\r\n"
)
req_len = len(request)
res_body_off = req_len + len(response_header)
# Intentionally without final CRLF/0-chunk: simulates Squid Preview,
# where Squid waits for an ICAP response after the preview probe.
chunked_preview = b"10000\r\n" + body
message = (
    b"RESPMOD icap://" + host.encode("ascii") + b":" + str(port).encode("ascii") + b"/respmod ICAP/1.0\r\n"
    b"Host: " + host.encode("ascii") + b"\r\n"
    b"X-Client-IP: 10.10.10.40\r\n"
    b"X-Server-IP: 198.51.100.10\r\n"
    b"Allow: 204\r\n"
    b"Preview: 65536\r\n"
    b"Encapsulated: req-hdr=0, res-hdr=" + str(req_len).encode("ascii") + b", res-body=" + str(res_body_off).encode("ascii") + b"\r\n\r\n"
    + request + response_header + chunked_preview
)
with socket.create_connection((host, port), timeout=5.0) as sock:
    sock.settimeout(5.0)
    sock.sendall(message)
    response = sock.recv(4096)
    sys.stdout.buffer.write(response)
PYCODE
}

sec "L1 — packages/Binaries"
for bin in suricata python3 nc curl; do
    if command -v "$bin" >/dev/null 2>&1; then ok "$bin present"; else bad "$bin missing"; fi
done
if command -v suricatasc >/dev/null 2>&1; then ok "suricatasc present"; else warn "suricatasc missing/not im PATH"; fi

sec "L2 — Services"
for svc in icap-suricata-engine.service icap-suricata-server.service nftables.service; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then ok "$svc active"; else bad "$svc inactive"; fi
done

sec "L3 — Suricata configuration"
[[ -f /etc/suricata-icap/suricata-icap.yaml ]] && ok "suricata-icap.yaml present" || bad "suricata-icap.yaml missing"
[[ -f /etc/suricata-icap/rules/icap-cleartext.rules ]] && ok "icap-cleartext.rules present" || bad "icap-cleartext.rules missing"
[[ -S "$SURICATA_SOCKET" ]] && ok "Suricata unix socket: $SURICATA_SOCKET" || bad "Suricata unix socket missing: $SURICATA_SOCKET"
[[ -r "$EVE_PATH" ]] && ok "eve.json readable: $EVE_PATH" || warn "eve.json not readable/present yet: $EVE_PATH"
if command -v suricata >/dev/null 2>&1 && [[ -f /etc/suricata-icap/suricata-icap.yaml ]]; then
    if suricata -T -c /etc/suricata-icap/suricata-icap.yaml -l /var/log/suricata-icap >/tmp/pathb-suricata-test.log 2>&1; then ok "suricata -T"; else bad "suricata -T failed: $(tail -n 2 /tmp/pathb-suricata-test.log | tr '\n' ' ')"; fi
fi

sec "L4 — listeners and health"
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "(:|\])${PORT}$"; then ok "ICAP Listener TCP/$PORT"; else bad "ICAP Listener TCP/$PORT missing"; fi
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "(:|\])${HEALTH_PORT}$"; then ok "Health Listener TCP/$HEALTH_PORT"; else bad "Health Listener TCP/$HEALTH_PORT missing"; fi
if curl -fsS "http://${HEALTH_HOST}:${HEALTH_PORT}/healthz" 2>/dev/null | grep -q '"healthy":true'; then ok "Healthcheck healthy=true"; else bad "Healthcheck not healthy"; fi

sec "L5 — ICAP Protokoll"
options_response="$(icap_options)"
if printf '%s' "$options_response" | grep -q 'ICAP/1.0 200'; then ok "ICAP OPTIONS"; else bad "ICAP OPTIONS failed"; fi
if printf '%s' "$options_response" | grep -q 'Methods: REQMOD, RESPMOD'; then ok "REQMOD/RESPMOD advertised"; else warn "Methods header not clear"; fi
if printf '%s' "$options_response" | grep -q '^Preview:'; then ok "ICAP Preview advertised"; else warn "ICAP Preview not advertised"; fi
preview_response="$(icap_respmod_preview_partial)"
if printf '%s' "$preview_response" | grep -qE 'ICAP/1.0 (200|204)'; then ok "ICAP preview cutoff responds without timeout"; else bad "ICAP Preview-Cutoff failed"; fi

sec "L6 — cleartext-Detection via ICAP"
if [[ "$RUN_PAYLOAD_TESTS" -eq 1 ]]; then
    req_response="$(icap_reqmod_trigger)"
    if printf '%s' "$req_response" | grep -q 'HTTP/1.1 403'; then ok "REQMOD test header was blocked"; else bad "REQMOD test header was not blocked"; fi

    resp_response="$(icap_respmod_trigger)"
    if printf '%s' "$resp_response" | grep -q 'HTTP/1.1 403'; then ok "RESPMOD test body was blocked"; else bad "RESPMOD test body was not blocked"; fi

    sleep 2
    if [[ -r "$EVE_PATH" ]]; then
        if tail -n 5000 "$EVE_PATH" | grep -q '9100599'; then ok "EVE contains SID 9100599"; else warn "SID 9100599 not found in tail(eve.json)"; fi
        if tail -n 5000 "$EVE_PATH" | grep -q '9100598'; then ok "EVE contains SID 9100598"; else warn "SID 9100598 not found in tail(eve.json)"; fi
    fi
else
    warn "payload tests disabled"
fi

sec "L7 — Firewall"
if nft list ruleset >/dev/null 2>&1; then ok "nftables ruleset readable"; else bad "nftables ruleset not readable"; fi

printf "\n============================================================\n"
printf "ICAP/Suricata Verification: PASS=%d WARN=%d FAIL=%d\n" "$PASS" "$WARN" "$FAIL"
printf "============================================================\n"
[[ "$FAIL" -eq 0 ]] || exit 1
