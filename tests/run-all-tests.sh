#!/usr/bin/env bash
# Path-B v5.12 — central test orchestration for ICAP/Suricata and proxy roles
set -euo pipefail

ROLE="auto"
CONFIG="deployment.env"
CURL_TEST=0
NO_PAYLOAD_TESTS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role) ROLE="$2"; shift 2 ;;
        --config|--env) CONFIG="$2"; shift 2 ;;
        --curl-test) CURL_TEST=1; shift ;;
        --no-payload-tests) NO_PAYLOAD_TESTS=1; shift ;;
        -h|--help)
            cat <<'HELP'
Usage:
  bash tests/run-all-tests.sh --role icap  --config deployment.env
  bash tests/run-all-tests.sh --role proxy --config deployment.env --curl-test
  bash tests/run-all-tests.sh --role auto  --config deployment.env
HELP
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="$CONFIG"
[[ "$CONFIG_PATH" = /* ]] || CONFIG_PATH="$ROOT_DIR/$CONFIG_PATH"
[[ -r "$CONFIG_PATH" ]] || { echo "Configuration file is not readable: $CONFIG_PATH" >&2; exit 1; }

EXTRA=()
if [[ "$CURL_TEST" -eq 1 ]]; then EXTRA+=(--curl-test); fi
if [[ "$NO_PAYLOAD_TESTS" -eq 1 ]]; then EXTRA+=(--no-payload-tests); fi

exec bash "$ROOT_DIR/scripts/verify.sh" --role "$ROLE" --config "$CONFIG_PATH" "${EXTRA[@]}"
