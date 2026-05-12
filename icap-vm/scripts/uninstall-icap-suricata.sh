#!/usr/bin/env bash
# Path-B v5.12 — Wrapper for cleanen ICAP/Suricata-Uninstall
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/install-icap-suricata.sh" --uninstall "$@"
