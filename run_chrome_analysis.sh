#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}"
BINARY_PATH="${ROOT_DIR}/TLSKeyHunter/binary/chrome"
OUTPUT_JSON="${ROOT_DIR}/results/143_auto.json"

exec "${ROOT_DIR}/run_binary_analysis.sh" \
    "$BINARY_PATH" \
    "$OUTPUT_JSON" \
    --meta "browser=chrome,version=143.0.7499.169,platform=linux,arch=x86_64,tls_lib=boringssl" \
    "$@"
