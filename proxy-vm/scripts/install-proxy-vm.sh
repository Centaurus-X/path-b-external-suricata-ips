#!/usr/bin/env bash
# =============================================================================
# Path-B v5.12 — Proxy-VM Installer
# Squid SSL-Bump / inbound HTTPS-Termination -> ICAP Chain -> external Suricata
# Optional: local c-ICAP/ClamAV as an additional AV service.
# =============================================================================
set -euo pipefail

ENV_FILE=""
ACTION="install"
ENABLE_FIREWALL="${ENABLE_FIREWALL:-1}"
FORCE_CLAMAV=""
FORCE_FIREWALL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env|--config) ENV_FILE="$2"; shift 2 ;;
        --with-clamav) FORCE_CLAMAV="1"; shift ;;
        --without-clamav|--no-clamav) FORCE_CLAMAV="0"; shift ;;
        --no-firewall) FORCE_FIREWALL="0"; shift ;;
        --uninstall) ACTION="uninstall"; shift ;;
        -h|--help) sed -n '1,130p' "$0"; exit 0 ;;
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
if [[ -n "$FORCE_CLAMAV" ]]; then ENABLE_CLAMAV_ICAP="$FORCE_CLAMAV"; fi
if [[ -n "$FORCE_FIREWALL" ]]; then ENABLE_FIREWALL="$FORCE_FIREWALL"; fi

C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_END='\033[0m'
log() { printf "${C_OK}[pathb-proxy]${C_END} %s\n" "$*"; }
warn() { printf "${C_WARN}[warn]${C_END} %s\n" "$*" >&2; }
die() { printf "${C_ERR}[fail]${C_END} %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run this command as root"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$BASE_DIR/.." && pwd)"
CERT_EXPORT_DIR="${CERT_EXPORT_DIR:-$ROOT_DIR/certs/proxy}"

SQUID_DIR="/etc/squid"
SQUID_CA_DIR="${SQUID_DIR}/ssl_cert"
SQUID_DB_DIR="/var/lib/ssl_db"
ICAP_CONF="/etc/c-icap/c-icap.conf"

is_true() {
    case "${1:-}" in 1|yes|YES|true|TRUE|on|ON) return 0 ;; *) return 1 ;; esac
}

is_auto() {
    case "${1:-}" in ""|auto|AUTO|detect|DETECT) return 0 ;; *) return 1 ;; esac
}

as_on_off() {
    case "${1:-off}" in 1|yes|YES|true|TRUE|on|ON) printf 'on' ;; *) printf 'off' ;; esac
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

squid_user() {
    if id proxy >/dev/null 2>&1; then printf 'proxy'; return 0; fi
    if id squid >/dev/null 2>&1; then printf 'squid'; return 0; fi
    printf 'proxy'
}

proxy_addr() { printf '%s' "${PROXY_IP%/*}"; }
clear_addr() { printf '%s' "${CLEAR_IP%/*}"; }
mgmt_addr() { printf '%s' "${MGMT_IP%/*}"; }

certgen_bin() {
    for path in \
        /usr/lib/squid/security_file_certgen \
        /usr/lib64/squid/security_file_certgen \
        /lib/squid/security_file_certgen; do
        [[ -x "$path" ]] && { printf '%s' "$path"; return 0; }
    done
    command -v security_file_certgen 2>/dev/null || return 1
}

cicap_module_dir() {
    for path in \
        /usr/lib/x86_64-linux-gnu/c_icap \
        /usr/lib/aarch64-linux-gnu/c_icap \
        /usr/lib/arm-linux-gnueabihf/c_icap \
        /usr/lib/c_icap \
        /usr/local/lib/c_icap; do
        [[ -d "$path" ]] && { printf '%s' "$path"; return 0; }
    done
    return 1
}

cicap_av_module() {
    local dir="$1"
    for mod in virus_scan.so srv_clamav.so squidclamav.so; do
        [[ -f "$dir/$mod" ]] && { printf '%s' "$mod"; return 0; }
    done
    find "$dir" -maxdepth 1 -type f \( -name 'virus_scan.so' -o -name 'srv_clamav.so' -o -name 'squidclamav.so' \) -printf '%f\n' 2>/dev/null | head -1
}

derive_network_config() {
    local primary_if detected_ip detected_prefix ip_with_prefix
    primary_if="$(detect_primary_if || true)"
    [[ -n "$primary_if" ]] || primary_if="eth0"

    PATHB_INTERFACE="${PATHB_INTERFACE:-auto}"
    if is_auto "$PATHB_INTERFACE"; then
        PATHB_INTERFACE="$primary_if"
    fi

    PROXY_IF="${PROXY_IF:-auto}"; CLEAR_IF="${CLEAR_IF:-auto}"; MGMT_IF="${MGMT_IF:-auto}"
    if is_auto "$PROXY_IF"; then PROXY_IF="$PATHB_INTERFACE"; fi
    if is_auto "$CLEAR_IF"; then CLEAR_IF="$PATHB_INTERFACE"; fi
    if is_auto "$MGMT_IF"; then MGMT_IF="$PATHB_INTERFACE"; fi

    detected_ip="$(detect_ip_for_if "$PROXY_IF" || true)"
    detected_prefix="$(detect_prefix_for_if "$PROXY_IF" || true)"
    [[ -n "$detected_prefix" ]] || detected_prefix="${PATHB_NET_PREFIX:-24}"

    local proxy_candidate
    proxy_candidate="${PATHB_PROXY_IP:-auto}"
    if is_auto "$proxy_candidate"; then proxy_candidate="${detected_ip:-10.10.10.2}"; fi
    if [[ "$proxy_candidate" == */* ]]; then
        ip_with_prefix="$proxy_candidate"
    else
        ip_with_prefix="${proxy_candidate}/${detected_prefix}"
    fi

    PROXY_IP="${PROXY_IP:-auto}"; CLEAR_IP="${CLEAR_IP:-auto}"; MGMT_IP="${MGMT_IP:-auto}"
    if is_auto "$PROXY_IP"; then PROXY_IP="$ip_with_prefix"; fi
    if is_auto "$CLEAR_IP"; then CLEAR_IP="$PROXY_IP"; fi
    if is_auto "$MGMT_IP"; then MGMT_IP="$PROXY_IP"; fi

    DEFAULT_GW="${DEFAULT_GW:-auto}"
    if is_auto "$DEFAULT_GW"; then
        if is_auto "${PATHB_GATEWAY_IP:-auto}"; then DEFAULT_GW="$(detect_gateway || true)"; else DEFAULT_GW="$PATHB_GATEWAY_IP"; fi
    fi
    PATHB_DNS_SERVERS="${PATHB_DNS_SERVERS:-auto}"
    if is_auto "$PATHB_DNS_SERVERS"; then PATHB_DNS_SERVERS="${DEFAULT_GW:-$(detect_gateway || true)}"; fi

    ENABLE_OUTBOUND="${ENABLE_OUTBOUND:-1}"
    OUTBOUND_HTTP_PORT="${OUTBOUND_HTTP_PORT:-3128}"
    OUTBOUND_HTTPS_INTERCEPT_PORT="${OUTBOUND_HTTPS_INTERCEPT_PORT:-3129}"
    LOCAL_NETS="${LOCAL_NETS:-auto}"
    if is_auto "$LOCAL_NETS"; then
        local nets=()
        # Lab default: allow only the test client and the proxy VM itself. This avoids
        # Squid ACL warnings caused by overlapping /32 and /24 networks.
        if ! is_auto "${PATHB_TEST_CLIENT_IP:-auto}"; then nets+=("${PATHB_TEST_CLIENT_IP}/32"); fi
        nets+=("$(proxy_addr)/32")
        LOCAL_NETS="${nets[*]:-$(proxy_addr)/32}"
    fi

    ICAP_SURICATA_HOST="${ICAP_SURICATA_HOST:-auto}"
    if is_auto "$ICAP_SURICATA_HOST"; then
        if is_auto "${PATHB_SURICATA_IP:-auto}"; then die "PATHB_SURICATA_IP must be set for the proxy role"; else ICAP_SURICATA_HOST="$PATHB_SURICATA_IP"; fi
    fi
    ICAP_SURICATA_PORT="${ICAP_SURICATA_PORT:-1345}"
    ICAP_SURICATA_BYPASS="${ICAP_SURICATA_BYPASS:-off}"
    ICAP_SURICATA_MAX_CONN="${ICAP_SURICATA_MAX_CONN:-32}"
    ICAP_PERSISTENT_CONNECTIONS="$(as_on_off "${ICAP_PERSISTENT_CONNECTIONS:-off}")"
    ICAP_PREVIEW_ENABLE="$(as_on_off "${ICAP_PREVIEW_ENABLE:-on}")"
    ICAP_PREVIEW_SIZE="${ICAP_PREVIEW_SIZE:-32768}"

    ENABLE_CLAMAV_ICAP="${ENABLE_CLAMAV_ICAP:-0}"
    CLAMAV_BYPASS="${CLAMAV_BYPASS:-on}"
    LOCAL_CLAMAV_SERVICE_NAME="${LOCAL_CLAMAV_SERVICE_NAME:-pathb_avscan}"

    CA_SUBJECT="${CA_SUBJECT:-/CN=Proxylab Path-B Inspection CA/O=Proxylab/C=DE}"
    CA_VALID_DAYS="${CA_VALID_DAYS:-3650}"
    SSL_BYPASS_REGEX="${SSL_BYPASS_REGEX:-/etc/squid/ssl-bypass.regex}"
    EXPORT_PRIVATE_CA_KEY="${EXPORT_PRIVATE_CA_KEY:-0}"

    ENABLE_INBOUND="${ENABLE_INBOUND:-0}"
    INBOUND_BIND_IP="${INBOUND_BIND_IP:-auto}"
    if is_auto "$INBOUND_BIND_IP"; then INBOUND_BIND_IP="$(proxy_addr)"; fi
    INBOUND_HTTPS_PORT="${INBOUND_HTTPS_PORT:-443}"
    INBOUND_DOMAIN="${INBOUND_DOMAIN:-app-test.local}"
    INBOUND_CERT="${INBOUND_CERT:-/etc/squid/inbound/app.fullchain.pem}"
    INBOUND_KEY="${INBOUND_KEY:-/etc/squid/inbound/app.privkey.pem}"
    INBOUND_ORIGIN_HOST="${INBOUND_ORIGIN_HOST:-192.168.1.50}"
    INBOUND_ORIGIN_PORT="${INBOUND_ORIGIN_PORT:-443}"
    INBOUND_ORIGIN_TLS="${INBOUND_ORIGIN_TLS:-1}"
    INBOUND_ORIGIN_VERIFY="${INBOUND_ORIGIN_VERIFY:-0}"
    APPLY_NETPLAN="${APPLY_NETPLAN:-0}"

    log "Configuration: IF=${PROXY_IF} PROXY=$(proxy_addr):${OUTBOUND_HTTP_PORT} ICAP=${ICAP_SURICATA_HOST}:${ICAP_SURICATA_PORT} CLAMAV=${ENABLE_CLAMAV_ICAP}"
}

install_packages() {
    log "Step 1/11 — install packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    local squid_pkg="squid-openssl"
    if ! apt-cache show squid-openssl >/dev/null 2>&1; then
        squid_pkg="squid"
        warn "squid-openssl not found — using squid; SSL-Bump support will be checked afterwards"
    fi
    local packages
    packages=(
        "$squid_pkg" nftables openssl ca-certificates curl jq netcat-openbsd iproute2
    )
    if is_true "$ENABLE_CLAMAV_ICAP"; then
        packages+=(c-icap libc-icap-mod-virus-scan clamav-daemon clamav-freshclam)
    fi
    apt-get install -y "${packages[@]}"
    command -v squid >/dev/null 2>&1 || die "squid is not installed"
    squid -v | grep -q -- '--enable-icap-client' || die "Squid was built without ICAP client support"
    squid -v | grep -q -- '--enable-ssl-crtd' || warn "Squid does not report --enable-ssl-crtd; squid -k parse will check final configuration"
}

configure_sysctl() {
    log "Step 2/11 — sysctl"
    cat > /etc/sysctl.d/90-pathb-proxy.conf <<'CONF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
CONF
    sysctl --system >/dev/null || warn "sysctl --system reported issues"
}

create_squid_ca() {
    log "Step 3/11 — Squid inspection CA and SSL database"
    local user
    user="$(squid_user)"
    install -d -m 0750 -o "$user" -g "$user" "$SQUID_CA_DIR"
    if [[ ! -f "$SQUID_CA_DIR/myCA.pem" ]]; then
        openssl req -x509 -newkey rsa:4096 -sha256 -days "$CA_VALID_DAYS" -nodes \
            -keyout "$SQUID_CA_DIR/myCA.key" \
            -out "$SQUID_CA_DIR/myCA.crt" \
            -subj "$CA_SUBJECT" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "subjectKeyIdentifier=hash"
        cat "$SQUID_CA_DIR/myCA.key" "$SQUID_CA_DIR/myCA.crt" > "$SQUID_CA_DIR/myCA.pem"
    else
        warn "CA already exists — generation skipped"
    fi
    chown -R "$user:$user" "$SQUID_CA_DIR"
    chmod 0640 "$SQUID_CA_DIR/myCA.key" "$SQUID_CA_DIR/myCA.pem" 2>/dev/null || true
    chmod 0644 "$SQUID_CA_DIR/myCA.crt" 2>/dev/null || true

    if [[ ! -d "$SQUID_DB_DIR" ]]; then
        local certgen
        certgen="$(certgen_bin)" || die "security_file_certgen not found"
        "$certgen" -c -s "$SQUID_DB_DIR" -M 64MB
    fi
    chown -R "$user:$user" "$SQUID_DB_DIR"
}

append_bypass_entry() {
    local pattern="$1"
    grep -qxF "$pattern" "$SSL_BYPASS_REGEX" 2>/dev/null || printf '%s\n' "$pattern" >> "$SSL_BYPASS_REGEX"
}

write_bypass_list() {
    if [[ ! -f "$SSL_BYPASS_REGEX" ]]; then
        cat > "$SSL_BYPASS_REGEX" <<'CONF'
# Domains that should not be bumped for legal, organizational, or compatibility reasons.
\.bank\.
\.sparkasse\.
\.paypal\.com$
\.elster\.de$
\.bund\.de$
\.gesundheit\.
CONF
    fi

    # v5.12: Legacy/security test sites are spliced. These servers are intentionally
    # Some legacy test domains are TLS-fragile and often fail with active bumping.
    append_bypass_entry '# v5.12 legacy/security test sites: splice instead of bump'
    append_bypass_entry '\.csm-testcenter\.org$'
    append_bypass_entry '\.badssl\.com$'
    append_bypass_entry '\.expired\.badssl\.com$'
    append_bypass_entry '\.wrong-host\.badssl\.com$'
    append_bypass_entry '\.self-signed\.badssl\.com$'
    append_bypass_entry '\.untrusted-root\.badssl\.com$'

    chmod 0644 "$SSL_BYPASS_REGEX"
}

build_icap_config_block() {
    local suri_bypass clam_bypass chain_req chain_resp
    suri_bypass="$(as_on_off "$ICAP_SURICATA_BYPASS")"
    clam_bypass="$(as_on_off "$CLAMAV_BYPASS")"

    chain_req="pathb_suricata_req"
    chain_resp="pathb_suricata_resp"
    if is_true "$ENABLE_CLAMAV_ICAP"; then
        chain_req="pathb_clamav_req pathb_suricata_req"
        chain_resp="pathb_clamav_resp pathb_suricata_resp"
    fi

    cat <<CONF

# --- ICAP Adaptation Chain: external Suricata and optional ClamAV -------------
# v5.12: persistent ICAP connections are intentionally disabled because the external
# Python ICAP server answers exactly one transaction per connection
# and then closes cleanly with Connection: close.
icap_enable on
adaptation_send_client_ip on
adaptation_send_username on
icap_client_username_header X-Authenticated-User
icap_persistent_connections ${ICAP_PERSISTENT_CONNECTIONS}
icap_preview_enable ${ICAP_PREVIEW_ENABLE}
icap_preview_size ${ICAP_PREVIEW_SIZE}
CONF

    if is_true "$ENABLE_CLAMAV_ICAP"; then
        cat <<CONF
icap_service pathb_clamav_req reqmod_precache icap://127.0.0.1:1344/${LOCAL_CLAMAV_SERVICE_NAME} bypass=${clam_bypass}
icap_service pathb_clamav_resp respmod_precache icap://127.0.0.1:1344/${LOCAL_CLAMAV_SERVICE_NAME} bypass=${clam_bypass}
CONF
    fi

    cat <<CONF
icap_service pathb_suricata_req reqmod_precache icap://${ICAP_SURICATA_HOST}:${ICAP_SURICATA_PORT}/reqmod bypass=${suri_bypass} max-conn=${ICAP_SURICATA_MAX_CONN} on-overload=wait
icap_service pathb_suricata_resp respmod_precache icap://${ICAP_SURICATA_HOST}:${ICAP_SURICATA_PORT}/respmod bypass=${suri_bypass} max-conn=${ICAP_SURICATA_MAX_CONN} on-overload=wait
adaptation_service_chain pathb_req_chain ${chain_req}
adaptation_service_chain pathb_resp_chain ${chain_resp}
adaptation_access pathb_req_chain allow all
adaptation_access pathb_resp_chain allow all
CONF
}

build_inbound_config_block() {
    is_true "$ENABLE_INBOUND" || return 0
    [[ -r "$INBOUND_CERT" ]] || die "INBOUND_CERT missing/not readable: $INBOUND_CERT"
    [[ -r "$INBOUND_KEY" ]] || die "INBOUND_KEY missing/not readable: $INBOUND_KEY"

    local origin_opts
    origin_opts=""
    if is_true "$INBOUND_ORIGIN_TLS"; then
        if is_true "$INBOUND_ORIGIN_VERIFY"; then
            origin_opts="ssl sslcafile=/etc/ssl/certs/ca-certificates.crt"
        else
            origin_opts="ssl sslflags=DONT_VERIFY_PEER"
        fi
    fi

    cat <<CONF

# --- Inbound Reverse-Proxy-Inspection ---------------------------------------
https_port ${INBOUND_BIND_IP}:${INBOUND_HTTPS_PORT} accel vhost cert=${INBOUND_CERT} key=${INBOUND_KEY} tls-min-version=1.2 options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TICKET
acl inbound_domains dstdomain ${INBOUND_DOMAIN}
cache_peer ${INBOUND_ORIGIN_HOST} parent ${INBOUND_ORIGIN_PORT} 0 no-query originserver name=pathb_inbound_origin ${origin_opts}
cache_peer_access pathb_inbound_origin allow inbound_domains
cache_peer_access pathb_inbound_origin deny all
never_direct allow inbound_domains
CONF
}

build_inbound_http_access_block() {
    is_true "$ENABLE_INBOUND" || return 0
    cat <<CONF
http_access allow inbound_domains
CONF
}

write_squid_config() {
    log "Step 4/11 — write Squid configuration"
    write_bypass_list

    local proxy_ip clear_ip ssl_ports safe_ports outbound_block certgen
    proxy_ip="$(proxy_addr)"
    clear_ip="$(clear_addr)"
    certgen="$(certgen_bin)" || die "security_file_certgen not found"
    ssl_ports="443 8443 ${OUTBOUND_HTTPS_INTERCEPT_PORT} ${INBOUND_HTTPS_PORT}"
    safe_ports="80 443 8080 8443 1025-65535 ${OUTBOUND_HTTP_PORT} ${OUTBOUND_HTTPS_INTERCEPT_PORT} ${INBOUND_HTTPS_PORT}"
    outbound_block=""

    if is_true "$ENABLE_OUTBOUND"; then
        outbound_block=$(cat <<CONF
http_port ${proxy_ip}:${OUTBOUND_HTTP_PORT} ssl-bump cert=${SQUID_CA_DIR}/myCA.pem generate-host-certificates=on dynamic_cert_mem_cache_size=64MB tls-min-version=1.2 options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TICKET
https_port ${proxy_ip}:${OUTBOUND_HTTPS_INTERCEPT_PORT} intercept ssl-bump cert=${SQUID_CA_DIR}/myCA.pem generate-host-certificates=on dynamic_cert_mem_cache_size=64MB tls-min-version=1.2 options=NO_SSLv3,NO_TLSv1,NO_TLSv1_1,NO_TICKET
CONF
)
    fi

    cat > "$SQUID_DIR/squid.conf" <<CONF
# Path-B v5.12 — Squid SSL-Inspection Proxy
# Generated by install-proxy-vm.sh. Track local changes in version control.

visible_hostname pathb-proxy-vm

acl localnet src ${LOCAL_NETS}
acl localhost src 127.0.0.1/32 ::1
acl SSL_ports port ${ssl_ports}
acl Safe_ports port ${safe_ports}
acl CONNECT method CONNECT
acl step1 at_step SslBump1
acl no_bump ssl::server_name_regex -i ${SSL_BYPASS_REGEX}

${outbound_block}

ssl_bump peek step1
ssl_bump splice no_bump
ssl_bump bump all

sslcrtd_program ${certgen} -s ${SQUID_DB_DIR} -M 64MB
sslcrtd_children 32 startup=8 idle=2

$(build_icap_config_block)

$(build_inbound_config_block)

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow manager localhost
http_access deny manager
$(build_inbound_http_access_block)
http_access allow localnet
http_access allow localhost
http_access deny all

tcp_outgoing_address ${clear_ip}
cache deny all
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
shutdown_lifetime 3 seconds
CONF

    if ! squid -k parse >/tmp/pathb-squid-parse.log 2>&1; then
        cat /tmp/pathb-squid-parse.log >&2
        die "squid.conf has syntax errors"
    fi
}

configure_squid_systemd() {
    log "Step 5/11 — Squid systemd hardening"
    install -d -m 0755 /etc/systemd/system/squid.service.d
    cat > /etc/systemd/system/squid.service.d/override.conf <<'CONF'
[Service]
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
LimitNOFILE=65535
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
CONF
    systemctl daemon-reload
}

configure_cicap_clamav() {
    log "Step 6/11 — optional c-ICAP/ClamAV"
    if ! is_true "$ENABLE_CLAMAV_ICAP"; then
        warn "ENABLE_CLAMAV_ICAP=0 — local c-ICAP/ClamAV is skipped"
        systemctl disable --now c-icap clamav-daemon clamav-freshclam 2>/dev/null || true
        return 0
    fi

    local modules_dir av_module cicap_user
    modules_dir="$(cicap_module_dir)" || die "c-ICAP module directory not found"
    av_module="$(cicap_av_module "$modules_dir")"
    [[ -n "$av_module" ]] || die "no c-ICAP AV module found in $modules_dir"
    cicap_user="c-icap"
    id "$cicap_user" >/dev/null 2>&1 || cicap_user="c_icap"
    usermod -aG clamav "$cicap_user" 2>/dev/null || true

    install -d -m 0755 /var/log/c-icap /var/run/c-icap /var/tmp
    cat > "$ICAP_CONF" <<CONF
PidFile /var/run/c-icap/c-icap.pid
CommandsSocket /var/run/c-icap/c-icap.ctl
Timeout 300
MaxKeepAliveRequests 100
KeepAliveTimeout 600
StartServers 3
MaxServers 20
MinSpareThreads 10
MaxSpareThreads 40
ThreadsPerChild 10
MaxRequestsPerChild 0
Port 1344
User ${cicap_user}
Group ${cicap_user}
ServerAdmin admin@example.local
ServerName pathb-proxy-vm
TmpDir /var/tmp
MaxMemObject 262144
DebugLevel 1
ServerLog /var/log/c-icap/server.log
AccessLog /var/log/c-icap/access.log
ModulesDir ${modules_dir}
ServicesDir ${modules_dir}
TemplateDir /usr/share/c_icap/templates
TemplateDefaultLanguage en
LoadMagicFile /etc/c-icap/c-icap.magic
RemoteProxyUsers off
acl localnet src 127.0.0.1/32 ${LOCAL_NETS}
acl all src 0.0.0.0/0
icap_access allow localnet
icap_access deny all
CONF
    for include_file in /etc/c-icap/clamd_mod.conf /etc/c-icap/clamav_mod.conf /etc/c-icap/virus_scan.conf; do
        [[ -f "$include_file" ]] && printf 'Include %s\n' "$include_file" >> "$ICAP_CONF"
    done
    printf 'Service %s %s\n' "$LOCAL_CLAMAV_SERVICE_NAME" "$av_module" >> "$ICAP_CONF"

    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam --quiet || warn "freshclam reported issues — signatures may be outdated or locked"
    systemctl enable --now clamav-freshclam || warn "clamav-freshclam could not be started"
    systemctl enable --now clamav-daemon || warn "clamav-daemon could not be started"
    systemctl restart clamav-daemon || warn "clamav-daemon restart meldet issues"
    systemctl enable --now c-icap
    systemctl restart c-icap || {
        journalctl -u c-icap -n 80 --no-pager >&2 || true
        die "c-icap could not be started"
    }
}

configure_routing() {
    log "Step 7/11 — routing/netplan"
    if ! is_true "$APPLY_NETPLAN"; then
        warn "APPLY_NETPLAN=0 — network configuration will not be written automatically"
        return 0
    fi
    [[ -n "$DEFAULT_GW" ]] || die "DEFAULT_GW could not be detected"
    if [[ -d /etc/netplan ]]; then
        if [[ "$PROXY_IF" == "$CLEAR_IF" && "$PROXY_IF" == "$MGMT_IF" ]]; then
            cat > /etc/netplan/90-pathb-proxy.yaml <<CONF
network:
  version: 2
  ethernets:
    ${PROXY_IF}:
      addresses: [${PROXY_IP}]
      routes:
        - to: 0.0.0.0/0
          via: ${DEFAULT_GW}
          metric: 100
      nameservers:
        addresses: [${PATHB_DNS_SERVERS:-${DEFAULT_GW}}]
CONF
        else
            cat > /etc/netplan/90-pathb-proxy.yaml <<CONF
network:
  version: 2
  ethernets:
    ${PROXY_IF}:
      addresses: [${PROXY_IP}]
    ${CLEAR_IF}:
      addresses: [${CLEAR_IP}]
      routes:
        - to: 0.0.0.0/0
          via: ${DEFAULT_GW}
          metric: 100
    ${MGMT_IF}:
      addresses: [${MGMT_IP}]
CONF
        fi
        chmod 0600 /etc/netplan/90-pathb-proxy.yaml
        netplan generate || die "netplan generate failed"
        netplan apply || warn "netplan apply meldet issues — Interface-Namen pruefen"
    else
        warn "Netplan not found — set the default route manually: ip route replace default via ${DEFAULT_GW} dev ${CLEAR_IF}"
    fi
}

configure_firewall() {
    log "Step 8/11 — nftables"
    if ! is_true "$ENABLE_FIREWALL"; then
        warn "ENABLE_FIREWALL=0 — nftables will not be managed"
        return 0
    fi
    local inbound_rule=""
    if is_true "$ENABLE_INBOUND"; then
        inbound_rule="tcp dport ${INBOUND_HTTPS_PORT} accept"
    fi
    cat > /etc/nftables.conf <<CONF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0;
        policy drop;

        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        ip protocol icmp accept

        iifname "${MGMT_IF}" tcp dport 22 accept
        iifname "${PROXY_IF}" tcp dport { ${OUTBOUND_HTTP_PORT}, ${OUTBOUND_HTTPS_INTERCEPT_PORT} } accept
        ${inbound_rule}
        iifname "lo" tcp dport 1344 accept

        counter log prefix "[pathb-proxy drop] " level info limit rate 5/second drop
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}
CONF
    nft -c -f /etc/nftables.conf || die "nftables syntax error"
    systemctl enable --now nftables
    nft -f /etc/nftables.conf
}

start_services() {
    log "Step 9/11 — start services"
    systemctl enable --now squid
    systemctl restart squid
    sleep 2
    systemctl is-active --quiet squid || { systemctl status squid --no-pager >&2 || true; journalctl -u squid -n 80 --no-pager >&2 || true; die "Squid does not start"; }
    if is_true "$ENABLE_CLAMAV_ICAP"; then
        systemctl is-active --quiet c-icap || { journalctl -u c-icap -n 80 --no-pager >&2 || true; die "c-icap inactive"; }
        systemctl is-active --quiet clamav-daemon || warn "clamav-daemon inactive — c-icap may lose AV scanning capability"
    fi
}

smoke_test() {
    log "Step 10/11 — smoke tests"
    if command -v nc >/dev/null 2>&1; then
        printf 'OPTIONS icap://%s:%s/options ICAP/1.0\r\nHost: %s\r\nEncapsulated: null-body=0\r\n\r\n' "$ICAP_SURICATA_HOST" "$ICAP_SURICATA_PORT" "$ICAP_SURICATA_HOST" \
            | timeout 8 nc -q 1 "$ICAP_SURICATA_HOST" "$ICAP_SURICATA_PORT" | grep -q 'ICAP/1.0 200' \
            || warn "external ICAP/Suricata OPTIONS test failed — install/verify the ICAP VM first"
    fi
    squid -k parse >/dev/null 2>&1 || die "squid -k parse after start failed"
}

export_proxy_certs() {
    log "Step 11/11 — export certificates/artifacts"
    install -d -m 0755 "$CERT_EXPORT_DIR"
    install -m 0644 "$SQUID_CA_DIR/myCA.crt" "$CERT_EXPORT_DIR/myCA.crt"
    if is_true "$EXPORT_PRIVATE_CA_KEY"; then
        install -m 0600 "$SQUID_CA_DIR/myCA.key" "$CERT_EXPORT_DIR/myCA.key"
        install -m 0600 "$SQUID_CA_DIR/myCA.pem" "$CERT_EXPORT_DIR/myCA.pem"
    fi

    local windows_kit_dir
    windows_kit_dir="$CERT_EXPORT_DIR/windows-client-kit"
    install -d -m 0755 "$windows_kit_dir"
    install -m 0644 "$SQUID_CA_DIR/myCA.crt" "$windows_kit_dir/myCA.crt"
    if [[ -d "$ROOT_DIR/client-tools/windows" ]]; then
        find "$ROOT_DIR/client-tools/windows" -maxdepth 1 -type f -print0 | while IFS= read -r -d '' tool_file; do
            install -m 0644 "$tool_file" "$windows_kit_dir/$(basename "$tool_file")"
        done
    fi
    cat > "$windows_kit_dir/PathB-Client-Settings.txt" <<CONF
ProxyHost=${PROXY_IP%/*}
ProxyPort=${OUTBOUND_HTTP_PORT}
SuricataICAP=${ICAP_SURICATA_HOST}:${ICAP_SURICATA_PORT}
TestClient=${PATHB_TEST_CLIENT_IP:-auto}
CONF
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$CERT_EXPORT_DIR" "$windows_kit_dir" <<'PYCODE' || true
import sys
import zipfile
from pathlib import Path

export_dir = Path(sys.argv[1])
kit_dir = Path(sys.argv[2])
zip_path = export_dir / "pathb-windows-client-kit.zip"
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for item in sorted(kit_dir.rglob("*")):
        if item.is_file():
            archive.write(item, item.relative_to(kit_dir.parent))
PYCODE
    fi

    cat > "$CERT_EXPORT_DIR/README-WINDOWS-IMPORT.txt" <<CONF
Path-B v5.12 Squid Inspection CA

For the Windows test client, copy this generated kit:
  pathb-windows-client-kit.zip

It already contains:
  windows-client-kit\myCA.crt
  windows-client-kit\Install-PathB-CA.ps1
  windows-client-kit\Start-PathB-Browser-Test.ps1
  windows-client-kit\Test-PathB-Proxy.ps1

Recommended with RustDesk, inside the extracted windows-client-kit folder:
  powershell -ExecutionPolicy Bypass -File .\Install-PathB-CA.ps1
  powershell -ExecutionPolicy Bypass -File .\Start-PathB-Browser-Test.ps1

Noch kompakter:
  powershell -ExecutionPolicy Bypass -File .\Start-PathB-Browser-Test.ps1 -InstallCAFirst

This starts only an isolated Edge/Chrome profile through the proxy.
Global Windows proxy settings remain unchanged.

Proxy for Windows:
  ${PROXY_IP%/*}:${OUTBOUND_HTTP_PORT}

Note:
  myCA.key and myCA.pem are NOT exported by default.
  For testing, EXPORT_PRIVATE_CA_KEY=1 can be set; not recommended for production.
CONF

    # The installer runs with sudo. Without correction, the exported
    # Windows kit files may be root-owned, causing normal rm -rf/update operations to fail.
    # Therefore, artifacts in the project directory are returned to the invoking user.
    if [[ -n "${SUDO_USER:-}" ]] && id "${SUDO_USER}" >/dev/null 2>&1; then
        chown -R "${SUDO_USER}:${SUDO_USER}" "$CERT_EXPORT_DIR" 2>/dev/null || true
    fi
}

final_notes() {
    cat <<CONF

Path-B Proxy VM v5.12 is ready.

CA for clients:
  ${SQUID_CA_DIR}/myCA.crt
  ${CERT_EXPORT_DIR}/myCA.crt

Windows Client Kit:
  ${CERT_EXPORT_DIR}/windows-client-kit
  ${CERT_EXPORT_DIR}/pathb-windows-client-kit.zip

Outbound Listener:
  HTTP/explicit proxy: ${PROXY_IP%/*}:${OUTBOUND_HTTP_PORT}
  HTTPS intercept:     ${PROXY_IP%/*}:${OUTBOUND_HTTPS_INTERCEPT_PORT}

External ICAP/Suricata VM:
  icap://${ICAP_SURICATA_HOST}:${ICAP_SURICATA_PORT}/reqmod
  icap://${ICAP_SURICATA_HOST}:${ICAP_SURICATA_PORT}/respmod

Verification:
  sudo bash $SCRIPT_DIR/verify-proxy-vm.sh --env ${ENV_FILE:-$ROOT_DIR/deployment.env}
CONF
}

uninstall_all() {
    log "Uninstall"
    systemctl disable --now squid c-icap clamav-daemon clamav-freshclam 2>/dev/null || true
    rm -f /etc/systemd/system/squid.service.d/override.conf
    rm -f /etc/netplan/90-pathb-proxy.yaml
    rm -f /etc/sysctl.d/90-pathb-proxy.conf
    systemctl daemon-reload
    warn "CA material and logs are kept: ${SQUID_CA_DIR}, /var/log/squid"
}

derive_network_config
case "$ACTION" in
    install)
        install_packages
        configure_sysctl
        create_squid_ca
        write_squid_config
        configure_squid_systemd
        configure_cicap_clamav
        configure_routing
        configure_firewall
        start_services
        smoke_test
        export_proxy_certs
        final_notes
        ;;
    uninstall)
        uninstall_all
        ;;
    *) die "invalid action: $ACTION" ;;
esac
