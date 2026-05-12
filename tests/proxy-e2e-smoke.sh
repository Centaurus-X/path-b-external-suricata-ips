#!/usr/bin/env bash
# Path-B v5.12 — Proxy -> external ICAP/Suricata end-to-end smoke test
set -euo pipefail
CONFIG="${1:-deployment.env}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT_DIR/scripts/verify.sh" --role proxy --config "$CONFIG" --curl-test
