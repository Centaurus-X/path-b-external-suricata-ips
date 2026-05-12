#!/usr/bin/env bash
# Path-B v5.12 — direkter ICAP/Suricata smoke test
set -euo pipefail
CONFIG="${1:-deployment.env}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$ROOT_DIR/scripts/verify.sh" --role icap --config "$CONFIG"
