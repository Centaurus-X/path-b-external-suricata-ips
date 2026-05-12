#!/usr/bin/env bash
# Path-B v5.12 — robuster ICAP/Suricata Runtime-Hotfix
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR="/usr/local/lib/icap-suricata"
RULE_DIR="/etc/suricata-icap/rules"
CONF_DIR="/etc/suricata-icap"
ENV_FILE="/etc/icap-suricata/icap-server.env"
RUN_SURI="/run/suricata-icap"
RUN_ICAP="/run/icap-suricata"
LOG_SURI="/var/log/suricata-icap"
LOG_ICAP="/var/log/icap-suricata"
STAMP="$(date +%Y%m%d-%H%M%S)"

log() { printf '[pathb-hotfix-v5.12] %s\n' "$*"; }
fail() { printf '[pathb-hotfix-v5.12][fail] %s\n' "$*" >&2; exit 1; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail "Please run with sudo"
[[ -d "$ROOT_DIR/icap-vm/src" ]] || fail "Package structure not found: $ROOT_DIR/icap-vm/src"
[[ -d "$LIB_DIR" ]] || fail "$LIB_DIR does not exist; install the ICAP role first or run install.sh --role icap"

set_env_value() {
    local key="$1"
    local value="$2"
    local file="$3"
    if [[ ! -f "$file" ]]; then
        return 0
    fi
    if grep -q "^${key}=" "$file"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

print_unit_diagnostics() {
    local unit="$1"
    systemctl status "$unit" --no-pager -l >&2 || true
    journalctl -u "$unit" -n 160 --no-pager >&2 || true
    if [[ "$unit" == "icap-suricata-engine.service" ]]; then
        tail -n 160 /var/log/suricata-icap/suricata.log >&2 2>/dev/null || true
    fi
}

wait_for_socket() {
    local socket_path="$1"
    local tries="${2:-50}"
    local i
    for i in $(seq 1 "$tries"); do
        [[ -S "$socket_path" ]] && return 0
        sleep 1
    done
    return 1
}

log "Stop services and clean runtime state"
systemctl stop icap-suricata-server.service 2>/dev/null || true
systemctl stop icap-suricata-engine.service 2>/dev/null || true
systemctl stop suricata.service 2>/dev/null || true
pkill -TERM -f 'suricata.*suricata-icap.yaml' 2>/dev/null || true
sleep 1
pkill -KILL -f 'suricata.*suricata-icap.yaml' 2>/dev/null || true
systemctl reset-failed icap-suricata-server.service icap-suricata-engine.service suricata.service 2>/dev/null || true

log "Backups erstellen"
install -d -m 0750 /var/backups/pathb-v5.12-hotfix
for file in pcap_builder.py icap_suricata_server.py suricata_client.py icap_parser.py eve_correlator.py community_id.py; do
    if [[ -f "$LIB_DIR/$file" ]]; then
        cp -a "$LIB_DIR/$file" "/var/backups/pathb-v5.12-hotfix/$file.$STAMP"
    fi
done
if [[ -f "$RULE_DIR/icap-cleartext.rules" ]]; then
    cp -a "$RULE_DIR/icap-cleartext.rules" "/var/backups/pathb-v5.12-hotfix/icap-cleartext.rules.$STAMP"
fi
if [[ -f /etc/systemd/system/icap-suricata-engine.service ]]; then
    cp -a /etc/systemd/system/icap-suricata-engine.service "/var/backups/pathb-v5.12-hotfix/icap-suricata-engine.service.$STAMP"
fi
if [[ -f /etc/systemd/system/icap-suricata-server.service ]]; then
    cp -a /etc/systemd/system/icap-suricata-server.service "/var/backups/pathb-v5.12-hotfix/icap-suricata-server.service.$STAMP"
fi

log "Runtime-fileen patchen"
for file in community_id.py pcap_builder.py icap_parser.py suricata_client.py eve_correlator.py icap_suricata_server.py; do
    install -m 0755 "$ROOT_DIR/icap-vm/src/$file" "$LIB_DIR/$file"
done
install -d -m 0755 "$RULE_DIR"
install -m 0644 "$ROOT_DIR/icap-vm/rules/icap-cleartext.rules" "$RULE_DIR/icap-cleartext.rules"
install -m 0644 "$ROOT_DIR/icap-vm/configs/suricata-icap.yaml" "$CONF_DIR/suricata-icap.yaml"
install -m 0644 "$ROOT_DIR/icap-vm/configs/icap-suricata-engine.service" /etc/systemd/system/icap-suricata-engine.service
install -m 0644 "$ROOT_DIR/icap-vm/configs/icap-suricata-server.service" /etc/systemd/system/icap-suricata-server.service

log "Runtime-Parameter setzen"
if [[ "$(nproc 2>/dev/null || echo 2)" -ge 4 ]]; then
    set_env_value SURICATA_PIPELINE_CONCURRENCY 6 "$ENV_FILE"
else
    set_env_value SURICATA_PIPELINE_CONCURRENCY 4 "$ENV_FILE"
fi
set_env_value SURICATA_SUBMIT_RETRIES 3 "$ENV_FILE"
set_env_value SURICATA_SUBMIT_RETRY_SLEEP_MS 40 "$ENV_FILE"
set_env_value SURICATA_RETRY_SLEEP_MS 40 "$ENV_FILE"
set_env_value WAIT_TIMEOUT_MS 900 "$ENV_FILE"
set_env_value REQMOD_WAIT_TIMEOUT_MS 500 "$ENV_FILE"
set_env_value RESPMOD_WAIT_TIMEOUT_MS 400 "$ENV_FILE"
set_env_value ALERT_POST_DRAIN_GRACE_MS 60 "$ENV_FILE"
set_env_value SURICATA_QUEUE_POLL_MS 10 "$ENV_FILE"
set_env_value ICAP_PREVIEW_ENABLE 1 "$ENV_FILE"
set_env_value ICAP_PREVIEW_SIZE 32768 "$ENV_FILE"
set_env_value RESPMOD_ENABLED 1 "$ENV_FILE"
set_env_value RESPMOD_PREVIEW_SCAN 1 "$ENV_FILE"
set_env_value RESPMOD_MAX_SCAN_BYTES 262144 "$ENV_FILE"
set_env_value RESPMOD_SKIP_COMPRESSED 1 "$ENV_FILE"
set_env_value RESPMOD_SCAN_ALL_CONTENT_TYPES 0 "$ENV_FILE"
set_env_value RESPMOD_SCAN_SMALL_BODIES_BYTES 131072 "$ENV_FILE"
set_env_value RESPMOD_FORCE_SCAN_MARKERS EICAR-STANDARD-ANTIVIRUS-TEST-FILE,PROXYLAB-ICAP-RESPONSE-TRIGGER "$ENV_FILE"
set_env_value ICAP_READ_TIMEOUT_S 0.8 "$ENV_FILE"
set_env_value ICAP_WORKERS 32 "$ENV_FILE"
set_env_value PCAP_TCP_MSS 1400 "$ENV_FILE"
set_env_value LOG_CLIENT_ABORTS 0 "$ENV_FILE"
set_env_value LOG_INCOMPLETE_READS 0 "$ENV_FILE"
set_env_value LOG_MONITOR_ALERTS 0 "$ENV_FILE"
set_env_value REQMOD_STATIC_BYPASS_ENABLED 1 "$ENV_FILE"
set_env_value REQMOD_STATIC_BYPASS_EXTENSIONS css,js,mjs,map,png,jpg,jpeg,gif,webp,svg,ico,avif,bmp,woff,woff2,ttf,otf,eot,mp4,webm,mp3,m4a,m4v,ogg,wav,wasm,json "$ENV_FILE"
set_env_value REQMOD_STATIC_BYPASS_LOG_SAMPLE_RATE 0 "$ENV_FILE"
set_env_value LATENCY_SAMPLE_EVERY 200 "$ENV_FILE"
set_env_value SLOW_REQUEST_LOG_MS 350 "$ENV_FILE"

log "Runtime-directories neu aufbauen"
rm -rf "$RUN_SURI" "$RUN_ICAP"
install -d -m 2770 -o suricata -g icap-suricata "$RUN_SURI"
install -d -m 2770 -o icap-suricata -g icap-suricata "$RUN_ICAP" "$RUN_ICAP/pcaps"
install -d -m 0750 -o suricata -g suricata "$LOG_SURI" /var/lib/suricata-icap
install -d -m 0750 -o icap-suricata -g icap-suricata "$LOG_ICAP"
chown -R suricata:suricata "$LOG_SURI" /var/lib/suricata-icap
chown -R icap-suricata:icap-suricata "$LOG_ICAP" "$RUN_ICAP"
chown -R suricata:icap-suricata "$RUN_SURI"

log "Check syntax and Suricata configuration"
python3 -m py_compile "$LIB_DIR"/*.py
suricata -T -c "$CONF_DIR/suricata-icap.yaml" -l "$LOG_SURI" >/tmp/pathb-hotfix-suricata-test.log 2>&1 || {
    cat /tmp/pathb-hotfix-suricata-test.log >&2
    fail "suricata -T as root failed"
}
if command -v runuser >/dev/null 2>&1 && id suricata >/dev/null 2>&1; then
    runuser -u suricata -- suricata -T -c "$CONF_DIR/suricata-icap.yaml" -l "$LOG_SURI" >/tmp/pathb-hotfix-suricata-test-user.log 2>&1 || {
        cat /tmp/pathb-hotfix-suricata-test-user.log >&2
        fail "suricata -T as user suricata failed"
    }
fi

log "reload systemd and start engine"
systemctl daemon-reload
systemctl disable --now suricata.service 2>/dev/null || true
systemctl enable icap-suricata-engine.service >/dev/null 2>&1 || true
systemctl enable icap-suricata-server.service >/dev/null 2>&1 || true
if ! systemctl start icap-suricata-engine.service; then
    print_unit_diagnostics icap-suricata-engine.service
    fail "icap-suricata-engine Start failed"
fi

if ! wait_for_socket /run/suricata-icap/suricata-cmd.socket 50; then
    print_unit_diagnostics icap-suricata-engine.service
    fail "Suricata Unix socket is not ready"
fi

log "ICAP-Server starten"
if ! systemctl start icap-suricata-server.service; then
    print_unit_diagnostics icap-suricata-server.service
    fail "icap-suricata-server Start failed"
fi
sleep 2
systemctl is-active --quiet icap-suricata-engine.service || { print_unit_diagnostics icap-suricata-engine.service; fail "icap-suricata-engine inactive"; }
systemctl is-active --quiet icap-suricata-server.service || { print_unit_diagnostics icap-suricata-server.service; fail "icap-suricata-server inactive"; }

log "Fertig"
printf '\nNaechster Test:\n'
printf '  sudo bash %s/scripts/verify.sh --role icap --config %s/deployment.env\n' "$ROOT_DIR" "$ROOT_DIR"
