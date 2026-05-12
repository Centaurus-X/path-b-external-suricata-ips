#!/usr/bin/env bash
# =============================================================================
# Path-B v5.12 — installer for the external ICAP/Suricata VM
# Squid SSL-Bump/Reverse-Proxy-cleartext -> ICAP -> Suricata pcap-file Analyse
# =============================================================================
set -euo pipefail

ENV_FILE=""
ACTION="install"
INSTALL_REPO="${INSTALL_SURICATA_REPO:-0}"
ENABLE_FIREWALL="${ENABLE_FIREWALL:-1}"
FORCE_FIREWALL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env|--config) ENV_FILE="$2"; shift 2 ;;
        --install-suricata-repo) INSTALL_REPO="1"; shift ;;
        --no-firewall) FORCE_FIREWALL="0"; shift ;;
        --uninstall) ACTION="uninstall"; shift ;;
        -h|--help) sed -n '1,120p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$ENV_FILE" ]]; then
    SCRIPT_PRE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    ROOT_PRE_DIR="$(cd "$SCRIPT_PRE_DIR/../.." && pwd)"
    if [[ -r "$ROOT_PRE_DIR/deployment.env" ]]; then
        ENV_FILE="$ROOT_PRE_DIR/deployment.env"
    fi
fi

if [[ -n "$ENV_FILE" ]]; then
    [[ -r "$ENV_FILE" ]] || { echo "ENV file is not readable: $ENV_FILE" >&2; exit 1; }
    # shellcheck disable=SC1090
    . "$ENV_FILE"
fi
if [[ -n "$FORCE_FIREWALL" ]]; then ENABLE_FIREWALL="$FORCE_FIREWALL"; fi

C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_END='\033[0m'
log() { printf "${C_OK}[pathb-icap]${C_END} %s\n" "$*"; }
warn() { printf "${C_WARN}[warn]${C_END} %s\n" "$*" >&2; }
die() { printf "${C_ERR}[fail]${C_END} %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run this command as root"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$BASE_DIR/.." && pwd)"
SRC_DIR="$BASE_DIR/src"
CONFIG_DIR="$BASE_DIR/configs"
RULES_DIR="$BASE_DIR/rules"
CERT_EXPORT_DIR="$ROOT_DIR/certs/suricata"

ETC_SURI="/etc/suricata-icap"
ETC_ICAP="/etc/icap-suricata"
LIB_DIR="/usr/local/lib/icap-suricata"
LOG_SURI="/var/log/suricata-icap"
LOG_ICAP="/var/log/icap-suricata"
RUN_ICAP="/run/icap-suricata"
RUN_SURI="/run/suricata-icap"
NFT_INCLUDE="/etc/nftables.d/98-pathb-icap-vm.nft"

is_auto() {
    case "${1:-}" in ""|auto|AUTO|detect|DETECT) return 0 ;; *) return 1 ;; esac
}

is_true() {
    case "${1:-}" in 1|yes|YES|true|TRUE|on|ON) return 0 ;; *) return 1 ;; esac
}

detect_primary_if() {
    ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

detect_ip_for_if() {
    local iface="$1"
    ip -o -4 addr show dev "$iface" scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1
}

detect_prefix_for_if() {
    local iface="$1"
    ip -o -4 addr show dev "$iface" scope global 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f2
}

detect_gateway() {
    ip route show default 2>/dev/null | awk '/default/ {print $3; exit}'
}

cidr_from_ip_prefix() {
    local ip="$1" prefix="$2"
    command -v python3 >/dev/null 2>&1 || return 1
    python3 - "$ip" "$prefix" <<'PYCODE'
import ipaddress
import sys
try:
    ip = sys.argv[1]
    prefix = int(sys.argv[2])
    print(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
except Exception:
    raise SystemExit(1)
PYCODE
}

join_csv_unique() {
    awk -v RS=',' 'NF {gsub(/^ +| +$/,"",$0); if ($0 && !seen[$0]++) out=(out?out ",":"") $0} END {print out}' <<<"$1"
}

derive_network_config() {
    local primary_if detected_ip detected_prefix
    primary_if="$(detect_primary_if || true)"
    [[ -n "$primary_if" ]] || primary_if="eth0"

    PATHB_INTERFACE="${PATHB_INTERFACE:-auto}"
    if is_auto "$PATHB_INTERFACE"; then
        MGMT_IF="${MGMT_IF:-auto}"
        if is_auto "$MGMT_IF"; then MGMT_IF="$primary_if"; fi
    else
        MGMT_IF="${MGMT_IF:-$PATHB_INTERFACE}"
        if is_auto "$MGMT_IF"; then MGMT_IF="$PATHB_INTERFACE"; fi
    fi

    detected_ip="$(detect_ip_for_if "$MGMT_IF" || true)"
    detected_prefix="$(detect_prefix_for_if "$MGMT_IF" || true)"
    [[ -n "$detected_prefix" ]] || detected_prefix="${PATHB_NET_PREFIX:-24}"

    ICAP_BIND="${ICAP_BIND:-auto}"
    if is_auto "$ICAP_BIND"; then
        if is_auto "${PATHB_SURICATA_IP:-auto}"; then ICAP_BIND="${detected_ip:-10.10.99.30}"; else ICAP_BIND="$PATHB_SURICATA_IP"; fi
    fi

    ICAP_PORT="${ICAP_PORT:-1345}"
    HEALTH_BIND="${HEALTH_BIND:-auto}"
    if is_auto "$HEALTH_BIND"; then HEALTH_BIND="$ICAP_BIND"; fi
    HEALTH_PORT="${HEALTH_PORT:-2345}"
    ICAP_WORKERS="${ICAP_WORKERS:-32}"

    ALLOWED_CIDR="${ALLOWED_CIDR:-auto}"
    if is_auto "$ALLOWED_CIDR"; then
        if ! is_auto "${PATHB_NET_CIDR:-auto}"; then
            ALLOWED_CIDR="$PATHB_NET_CIDR"
        else
            ALLOWED_CIDR="$(cidr_from_ip_prefix "${detected_ip:-$ICAP_BIND}" "$detected_prefix" 2>/dev/null || printf '0.0.0.0/0')"
        fi
    fi

    ALLOWED_CLIENTS="${ALLOWED_CLIENTS:-auto}"
    if is_auto "$ALLOWED_CLIENTS"; then
        if is_auto "${PATHB_PROXY_IP:-auto}"; then
            ALLOWED_CLIENTS="127.0.0.1,${ICAP_BIND}"
        else
            ALLOWED_CLIENTS="127.0.0.1,${PATHB_PROXY_IP},${ICAP_BIND}"
        fi
    fi
    ALLOWED_CLIENTS="$(join_csv_unique "$ALLOWED_CLIENTS")"

    SURICATA_SOCKET="${SURICATA_SOCKET:-/run/suricata-icap/suricata-cmd.socket}"
    SURICATA_OUTPUT_DIR="${SURICATA_OUTPUT_DIR:-/var/log/suricata-icap}"
    EVE_PATH="${EVE_PATH:-/var/log/suricata-icap/eve.json}"
    PCAP_TMPDIR="${PCAP_TMPDIR:-/run/icap-suricata/pcaps}"
    FAIL_CLOSED="${FAIL_CLOSED:-0}"
    WAIT_TIMEOUT_MS="${WAIT_TIMEOUT_MS:-900}"
    REQMOD_WAIT_TIMEOUT_MS="${REQMOD_WAIT_TIMEOUT_MS:-500}"
    RESPMOD_WAIT_TIMEOUT_MS="${RESPMOD_WAIT_TIMEOUT_MS:-400}"
    ALERT_POST_DRAIN_GRACE_MS="${ALERT_POST_DRAIN_GRACE_MS:-60}"
    SURICATA_QUEUE_POLL_MS="${SURICATA_QUEUE_POLL_MS:-10}"
    MAX_REQUEST_BYTES="${MAX_REQUEST_BYTES:-33554432}"
    ICAP_READ_TIMEOUT_S="${ICAP_READ_TIMEOUT_S:-0.8}"
    ICAP_PREVIEW_ENABLE="${ICAP_PREVIEW_ENABLE:-1}"
    PCAP_RETENTION_SECONDS="${PCAP_RETENTION_SECONDS:-300}"
    ICAP_PREVIEW_SIZE="${ICAP_PREVIEW_SIZE:-32768}"
    RESPMOD_ENABLED="${RESPMOD_ENABLED:-1}"
    RESPMOD_PREVIEW_SCAN="${RESPMOD_PREVIEW_SCAN:-1}"
    RESPMOD_MAX_SCAN_BYTES="${RESPMOD_MAX_SCAN_BYTES:-262144}"
    RESPMOD_SKIP_COMPRESSED="${RESPMOD_SKIP_COMPRESSED:-1}"
    RESPMOD_SCAN_ALL_CONTENT_TYPES="${RESPMOD_SCAN_ALL_CONTENT_TYPES:-0}"
    RESPMOD_SCAN_SMALL_BODIES_BYTES="${RESPMOD_SCAN_SMALL_BODIES_BYTES:-131072}"
    RESPMOD_FORCE_SCAN_MARKERS="${RESPMOD_FORCE_SCAN_MARKERS:-EICAR-STANDARD-ANTIVIRUS-TEST-FILE,PROXYLAB-ICAP-RESPONSE-TRIGGER}"
    BLOCK_SID_RANGES="${BLOCK_SID_RANGES:-9100500-9100999}"
    BLOCK_ON_ANY_ALERT="${BLOCK_ON_ANY_ALERT:-0}"
    SURICATA_PIPELINE_CONCURRENCY="${SURICATA_PIPELINE_CONCURRENCY:-6}"
    SURICATA_SUBMIT_RETRIES="${SURICATA_SUBMIT_RETRIES:-3}"
    SURICATA_SUBMIT_RETRY_SLEEP_MS="${SURICATA_SUBMIT_RETRY_SLEEP_MS:-40}"
    PCAP_TCP_MSS="${PCAP_TCP_MSS:-1400}"
    LOG_PATH="${LOG_PATH:-/var/log/icap-suricata/server.log}"
    LOG_CLIENT_ABORTS="${LOG_CLIENT_ABORTS:-0}"
    LOG_INCOMPLETE_READS="${LOG_INCOMPLETE_READS:-0}"
    LOG_MONITOR_ALERTS="${LOG_MONITOR_ALERTS:-0}"
    REQMOD_STATIC_BYPASS_ENABLED="${REQMOD_STATIC_BYPASS_ENABLED:-1}"
    REQMOD_STATIC_BYPASS_EXTENSIONS="${REQMOD_STATIC_BYPASS_EXTENSIONS:-css,js,mjs,map,png,jpg,jpeg,gif,webp,svg,ico,avif,bmp,woff,woff2,ttf,otf,eot,mp4,webm,mp3,m4a,m4v,ogg,wav,wasm,json}"
    REQMOD_STATIC_BYPASS_LOG_SAMPLE_RATE="${REQMOD_STATIC_BYPASS_LOG_SAMPLE_RATE:-0}"
    LATENCY_SAMPLE_EVERY="${LATENCY_SAMPLE_EVERY:-200}"
    SLOW_REQUEST_LOG_MS="${SLOW_REQUEST_LOG_MS:-350}"

    log "Configuration: IF=${MGMT_IF} ICAP=${ICAP_BIND}:${ICAP_PORT} HEALTH=${HEALTH_BIND}:${HEALTH_PORT} ALLOWED_CLIENTS=${ALLOWED_CLIENTS}"
}

install_packages() {
    log "Step 1/11 — install packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y ca-certificates curl gnupg lsb-release software-properties-common >/dev/null || true
    if [[ "$INSTALL_REPO" == "1" ]]; then
        if command -v add-apt-repository >/dev/null 2>&1; then
            add-apt-repository -y ppa:oisf/suricata-stable || warn "Suricata PPA could not be added"
            apt-get update -qq
        else
            warn "add-apt-repository missing — nutze Distribution-Suricata"
        fi
    fi
    apt-get install -y suricata suricata-update python3 jq curl netcat-openbsd nftables logrotate
    command -v suricata >/dev/null 2>&1 || die "suricata is not installed"
    command -v python3 >/dev/null 2>&1 || die "python3 is not installed"
    log "Suricata: $(suricata -V 2>/dev/null | head -1)"
}

create_users() {
    log "Step 2/11 — system users"
    if ! id suricata >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin suricata
    fi
    if ! id icap-suricata >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin icap-suricata
    fi
    usermod -aG suricata icap-suricata 2>/dev/null || true
    usermod -aG icap-suricata suricata 2>/dev/null || true
    usermod -aG adm icap-suricata 2>/dev/null || true
}

create_dirs() {
    log "Step 3/11 — directories"
    install -d -m 0755 "$ETC_SURI" "$ETC_SURI/rules" "$ETC_ICAP" "$LIB_DIR" /etc/nftables.d "$CERT_EXPORT_DIR"
    install -d -m 0750 -o suricata -g suricata "$LOG_SURI" /var/lib/suricata-icap
    install -d -m 0750 -o icap-suricata -g icap-suricata "$LOG_ICAP"
    install -d -m 2770 -o suricata -g icap-suricata "$RUN_SURI"
    install -d -m 2770 -o icap-suricata -g icap-suricata "$RUN_ICAP" "$RUN_ICAP/pcaps"
}

write_runtime_env() {
    cat > "$ETC_ICAP/icap-server.env" <<CONF
# Path-B v5.12 — generated by install-icap-suricata.sh
ICAP_BIND=${ICAP_BIND}
ICAP_PORT=${ICAP_PORT}
HEALTH_BIND=${HEALTH_BIND}
HEALTH_PORT=${HEALTH_PORT}
ICAP_WORKERS=${ICAP_WORKERS}
ALLOWED_CLIENTS=${ALLOWED_CLIENTS}
SURICATA_SOCKET=${SURICATA_SOCKET}
SURICATA_OUTPUT_DIR=${SURICATA_OUTPUT_DIR}
EVE_PATH=${EVE_PATH}
PCAP_TMPDIR=${PCAP_TMPDIR}
FAIL_CLOSED=${FAIL_CLOSED}
WAIT_TIMEOUT_MS=${WAIT_TIMEOUT_MS}
REQMOD_WAIT_TIMEOUT_MS=${REQMOD_WAIT_TIMEOUT_MS}
RESPMOD_WAIT_TIMEOUT_MS=${RESPMOD_WAIT_TIMEOUT_MS}
ALERT_POST_DRAIN_GRACE_MS=${ALERT_POST_DRAIN_GRACE_MS}
SURICATA_QUEUE_POLL_MS=${SURICATA_QUEUE_POLL_MS}
SURICATA_PIPELINE_CONCURRENCY=${SURICATA_PIPELINE_CONCURRENCY:-6}
SURICATA_SUBMIT_RETRIES=${SURICATA_SUBMIT_RETRIES:-3}
SURICATA_SUBMIT_RETRY_SLEEP_MS=${SURICATA_SUBMIT_RETRY_SLEEP_MS:-40}
MAX_REQUEST_BYTES=${MAX_REQUEST_BYTES}
ICAP_READ_TIMEOUT_S=${ICAP_READ_TIMEOUT_S}
PCAP_TCP_MSS=${PCAP_TCP_MSS:-1400}
PCAP_RETENTION_SECONDS=${PCAP_RETENTION_SECONDS}
ICAP_PREVIEW_ENABLE=${ICAP_PREVIEW_ENABLE}
ICAP_PREVIEW_SIZE=${ICAP_PREVIEW_SIZE}
RESPMOD_ENABLED=${RESPMOD_ENABLED}
RESPMOD_PREVIEW_SCAN=${RESPMOD_PREVIEW_SCAN}
RESPMOD_MAX_SCAN_BYTES=${RESPMOD_MAX_SCAN_BYTES}
RESPMOD_SKIP_COMPRESSED=${RESPMOD_SKIP_COMPRESSED}
RESPMOD_SCAN_ALL_CONTENT_TYPES=${RESPMOD_SCAN_ALL_CONTENT_TYPES}
RESPMOD_SCAN_SMALL_BODIES_BYTES=${RESPMOD_SCAN_SMALL_BODIES_BYTES}
RESPMOD_FORCE_SCAN_MARKERS=${RESPMOD_FORCE_SCAN_MARKERS}
BLOCK_SID_RANGES=${BLOCK_SID_RANGES}
BLOCK_ON_ANY_ALERT=${BLOCK_ON_ANY_ALERT}
LOG_PATH=${LOG_PATH}
LOG_CLIENT_ABORTS=${LOG_CLIENT_ABORTS}
LOG_INCOMPLETE_READS=${LOG_INCOMPLETE_READS}
LOG_MONITOR_ALERTS=${LOG_MONITOR_ALERTS}
REQMOD_STATIC_BYPASS_ENABLED=${REQMOD_STATIC_BYPASS_ENABLED}
REQMOD_STATIC_BYPASS_EXTENSIONS=${REQMOD_STATIC_BYPASS_EXTENSIONS}
REQMOD_STATIC_BYPASS_LOG_SAMPLE_RATE=${REQMOD_STATIC_BYPASS_LOG_SAMPLE_RATE}
LATENCY_SAMPLE_EVERY=${LATENCY_SAMPLE_EVERY}
SLOW_REQUEST_LOG_MS=${SLOW_REQUEST_LOG_MS}
CONF
    chown icap-suricata:icap-suricata "$ETC_ICAP/icap-server.env"
    chmod 0640 "$ETC_ICAP/icap-server.env"
}

deploy_configs() {
    log "Step 4/11 — deploy configurations"
    install -m 0644 "$CONFIG_DIR/suricata-icap.yaml" "$ETC_SURI/suricata-icap.yaml"
    install -m 0644 "$RULES_DIR/icap-cleartext.rules" "$ETC_SURI/rules/icap-cleartext.rules"
    cat > "$ETC_SURI/threshold.config" <<'CONF'
# Path-B v5.12 threshold.config
# Beispiel: threshold gen_id 1, sig_id 9100530, type limit, track by_src, count 1, seconds 300
CONF
    write_runtime_env
    for py in "$SRC_DIR"/*.py; do
        install -m 0755 "$py" "$LIB_DIR/$(basename "$py")"
    done
    python3 -m py_compile "$LIB_DIR"/*.py
}

lint_suricata_rules() {
    local rules_file="$1"
    python3 - "$rules_file" <<'PYCODE'
import sys
from pathlib import Path

rules_path = Path(sys.argv[1])
errors = []


def find_content_errors(line, lineno):
    pos = 0
    while True:
        idx = line.find("content:", pos)
        if idx < 0:
            return
        quote = line.find('"', idx)
        if quote < 0:
            errors.append(f"{rules_path}:{lineno}: content without opening quote")
            return
        cursor = quote + 1
        in_hex = False
        while cursor < len(line):
            char = line[cursor]
            prev = line[cursor - 1] if cursor > 0 else ""
            if char == "|" and prev != "\\":
                in_hex = not in_hex
            elif char == '"' and not in_hex and prev != "\\":
                break
            elif char == ";" and not in_hex:
                errors.append(
                    f"{rules_path}:{lineno}: raw semicolon in content; use |3B| or split content"
                )
            cursor += 1
        if cursor >= len(line):
            errors.append(f"{rules_path}:{lineno}: content without closing quote")
            return
        pos = cursor + 1


for lineno, raw in enumerate(rules_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if not line.endswith(";") and not line.endswith(";)"):
        errors.append(f"{rules_path}:{lineno}: rule does not end cleanly with semicolon/parenthesis")
    find_content_errors(line, lineno)

if errors:
    for item in errors:
        print(item, file=sys.stderr)
    raise SystemExit(1)
PYCODE
}

validate_suricata() {
    log "Step 5/11 — validate Suricata configuration"
    lint_suricata_rules "$ETC_SURI/rules/icap-cleartext.rules" || die "Suricata Rule-Lint failed"
    if ! suricata -T -c "$ETC_SURI/suricata-icap.yaml" -l "$LOG_SURI" >/tmp/pathb-suricata-icap-test.log 2>&1; then
        cat /tmp/pathb-suricata-icap-test.log >&2
        die "suricata -T failed"
    fi
    chown -R suricata:suricata "$LOG_SURI" /var/lib/suricata-icap
    if command -v runuser >/dev/null 2>&1; then
        if ! runuser -u suricata -- suricata -T -c "$ETC_SURI/suricata-icap.yaml" -l "$LOG_SURI" >/tmp/pathb-suricata-icap-test-user.log 2>&1; then
            cat /tmp/pathb-suricata-icap-test-user.log >&2
            die "suricata -T as user suricata failed"
        fi
    fi
    chown -R suricata:suricata "$LOG_SURI" /var/lib/suricata-icap
}

deploy_units() {
    log "Step 6/11 — systemd units"
    install -m 0644 "$CONFIG_DIR/icap-suricata-engine.service" /etc/systemd/system/icap-suricata-engine.service
    install -m 0644 "$CONFIG_DIR/icap-suricata-server.service" /etc/systemd/system/icap-suricata-server.service
    systemctl daemon-reload
    systemctl disable --now suricata.service 2>/dev/null || true
}

deploy_firewall() {
    log "Step 7/11 — nftables ICAP VM firewall"
    if ! is_true "$ENABLE_FIREWALL"; then
        warn "ENABLE_FIREWALL=0 — nftables will not be managed"
        return 0
    fi
    local tmp
    tmp="$(mktemp)"
    sed \
        -e "s|__MGMT_IF__|${MGMT_IF}|g" \
        -e "s|__ALLOWED_CIDR__|${ALLOWED_CIDR}|g" \
        -e "s|__ICAP_PORT__|${ICAP_PORT}|g" \
        -e "s|__HEALTH_PORT__|${HEALTH_PORT}|g" \
        "$CONFIG_DIR/icap-suricata.nft" > "$tmp"
    install -m 0644 "$tmp" "$NFT_INCLUDE"
    rm -f "$tmp"

    cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset
include "$NFT_INCLUDE"
EOF
    nft -c -f /etc/nftables.conf || die "nftables syntax error"
    systemctl enable --now nftables
    nft -f /etc/nftables.conf
}

wait_for_socket() {
    local socket_path="$1" tries="${2:-30}"
    local i
    for i in $(seq 1 "$tries"); do
        [[ -S "$socket_path" ]] && return 0
        sleep 1
    done
    return 1
}

reset_runtime_dirs() {
    pkill -f '/usr/bin/suricata .*suricata-icap.yaml' 2>/dev/null || true
    rm -rf "$RUN_SURI" "$RUN_ICAP"
    install -d -m 2770 -o suricata -g icap-suricata "$RUN_SURI"
    install -d -m 2770 -o icap-suricata -g icap-suricata "$RUN_ICAP" "$RUN_ICAP/pcaps"
    install -d -m 0750 -o suricata -g suricata "$LOG_SURI" /var/lib/suricata-icap
    install -d -m 0750 -o icap-suricata -g icap-suricata "$LOG_ICAP"
    rm -f "$SURICATA_SOCKET" "$RUN_SURI/suricata-icap.pid"
    chown -R suricata:suricata "$LOG_SURI" /var/lib/suricata-icap
    chown -R icap-suricata:icap-suricata "$LOG_ICAP" "$RUN_ICAP"
    chown -R suricata:icap-suricata "$RUN_SURI"
}

print_service_diagnostics() {
    local unit="$1"
    systemctl status "$unit" --no-pager >&2 || true
    journalctl -u "$unit" -n 120 --no-pager >&2 || true
    if [[ "$unit" == "icap-suricata-engine.service" ]]; then
        tail -n 120 "$LOG_SURI/suricata.log" >&2 2>/dev/null || true
    fi
}

start_services() {
    log "Step 8/11 — start services"
    systemctl stop icap-suricata-server.service icap-suricata-engine.service suricata.service 2>/dev/null || true
    systemctl disable --now suricata.service 2>/dev/null || true
    pkill -TERM -f 'suricata.*suricata-icap.yaml' 2>/dev/null || true
    sleep 1
    pkill -KILL -f 'suricata.*suricata-icap.yaml' 2>/dev/null || true
    systemctl reset-failed icap-suricata-server.service icap-suricata-engine.service suricata.service 2>/dev/null || true
    reset_runtime_dirs
    systemctl daemon-reload
    systemctl enable icap-suricata-engine.service >/dev/null
    if ! systemctl start icap-suricata-engine.service; then
        print_service_diagnostics icap-suricata-engine.service
        die "icap-suricata-engine Start failed"
    fi
    wait_for_socket "$SURICATA_SOCKET" 50 || {
        print_service_diagnostics icap-suricata-engine.service
        die "Suricata unix socket is not ready: $SURICATA_SOCKET"
    }
    systemctl enable icap-suricata-server.service >/dev/null
    if ! systemctl start icap-suricata-server.service; then
        print_service_diagnostics icap-suricata-server.service
        die "icap-suricata-server Start failed"
    fi
    sleep 2
    systemctl is-active --quiet icap-suricata-engine.service || { print_service_diagnostics icap-suricata-engine.service; die "icap-suricata-engine inactive"; }
    systemctl is-active --quiet icap-suricata-server.service || { print_service_diagnostics icap-suricata-server.service; die "icap-suricata-server inactive"; }
}

icap_options_host() {
    if [[ "$ICAP_BIND" == "0.0.0.0" ]]; then printf '127.0.0.1'; else printf '%s' "$ICAP_BIND"; fi
}

health_check_host() {
    if [[ "$HEALTH_BIND" == "0.0.0.0" ]]; then printf '127.0.0.1'; else printf '%s' "$HEALTH_BIND"; fi
}

smoke_test() {
    log "Step 9/11 — smoke test"
    local opt_host health_host
    opt_host="$(icap_options_host)"
    health_host="$(health_check_host)"
    if command -v nc >/dev/null 2>&1; then
        printf 'OPTIONS icap://%s:%s/options ICAP/1.0\r\nHost: %s\r\nEncapsulated: null-body=0\r\n\r\n' "$opt_host" "$ICAP_PORT" "$opt_host" \
            | timeout 8 nc -q 1 "$opt_host" "$ICAP_PORT" | grep -q 'ICAP/1.0 200' \
            || die "ICAP OPTIONS Test failed"
    fi
    curl -fsS "http://${health_host}:${HEALTH_PORT}/healthz" | grep -q '"healthy":true' \
        || die "Healthcheck failed"
}

export_artifacts() {
    log "Step 10/11 — local artifact storage"
    install -d -m 0755 "$CERT_EXPORT_DIR"
    cat > "$CERT_EXPORT_DIR/README.txt" <<CONF
Path-B v5.12 Suricata/ICAP VM

This role does not create a client CA. The Squid inspection CA is created on the proxy VM and exported to certs/proxy/myCA.crt.

ICAP Endpoint:
  icap://${ICAP_BIND}:${ICAP_PORT}/reqmod
  icap://${ICAP_BIND}:${ICAP_PORT}/respmod
Health:
  http://${HEALTH_BIND}:${HEALTH_PORT}/healthz
CONF
}

final_notes() {
    log "Step 11/11 — installation completed"
    cat <<EOF

Path-B ICAP/Suricata VM v5.12 is ready.

Endpoint:
  icap://${ICAP_BIND}:${ICAP_PORT}/reqmod
  icap://${ICAP_BIND}:${ICAP_PORT}/respmod
  http://${HEALTH_BIND}:${HEALTH_PORT}/healthz

Important files:
  /etc/icap-suricata/icap-server.env
  /etc/suricata-icap/suricata-icap.yaml
  /etc/suricata-icap/rules/icap-cleartext.rules

Verify:
  sudo bash $SCRIPT_DIR/verify-icap-suricata.sh --env ${ENV_FILE:-/etc/icap-suricata/icap-server.env}
  sudo journalctl -u icap-suricata-server -f
  sudo tail -F /var/log/suricata-icap/eve.json
EOF
}

uninstall_all() {
    log "Uninstall"
    systemctl disable --now icap-suricata-server.service icap-suricata-engine.service 2>/dev/null || true
    rm -f /etc/systemd/system/icap-suricata-server.service /etc/systemd/system/icap-suricata-engine.service
    rm -f "$NFT_INCLUDE"
    systemctl daemon-reload
    warn "Configuration and logs are kept: $ETC_ICAP $ETC_SURI $LOG_ICAP $LOG_SURI"
}

derive_network_config
case "$ACTION" in
    install)
        install_packages
        create_users
        create_dirs
        deploy_configs
        validate_suricata
        deploy_units
        deploy_firewall
        start_services
        smoke_test
        export_artifacts
        final_notes
        ;;
    uninstall)
        uninstall_all
        ;;
    *) die "invalid action: $ACTION" ;;
esac
