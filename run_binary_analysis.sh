#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <binary_path> <output_json> [options]

Options:
  --meta KEY=VAL[,KEY=VAL...]   Metadata: browser,version,platform,arch,tls_lib
  --tag STRING                  Human-readable run tag (default: timestamp)
  --background                  Run in background, writes .pid/.log next to output
  --image TAG                   Override docker image tag
  --rebuild                     Force docker image rebuild before running
EOF
    exit 1
}

[[ $# -lt 2 ]] && usage
BINARY="$1"; shift
OUTPUT_JSON="$1"; shift

META=""
TAG=""
BACKGROUND=0
IMAGE_TAG="tlshunter:0.5.0"
REBUILD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --meta) META="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --background) BACKGROUND=1; shift ;;
        --image) IMAGE_TAG="$2"; shift 2 ;;
        --rebuild) REBUILD=1; shift ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

[[ -f "$BINARY" ]] || { echo "Binary not found: $BINARY" >&2; exit 1; }
mkdir -p "$(dirname "$OUTPUT_JSON")"

parse_meta() {
    local keyvals="$1"
    local browser="" version="" platform="" arch="" tls_lib=""
    [[ -z "$keyvals" ]] && return 0
    IFS=',' read -ra items <<< "$keyvals"
    for item in "${items[@]}"; do
        key="${item%%=*}"
        value="${item#*=}"
        case "$key" in
            browser) browser="$value" ;;
            version) version="$value" ;;
            platform) platform="$value" ;;
            arch) arch="$value" ;;
            tls_lib) tls_lib="$value" ;;
        esac
    done
    [[ -n "$browser" ]] && META_ARGS+=(--browser "$browser")
    [[ -n "$version" ]] && META_ARGS+=(--version "$version")
    [[ -n "$platform" ]] && META_ARGS+=(--platform "$platform")
    [[ -n "$arch" ]] && META_ARGS+=(--arch "$arch")
    [[ -n "$tls_lib" ]] && META_ARGS+=(--tls-lib "$tls_lib")
}

META_ARGS=()
parse_meta "$META"

RUN_ARGS=(python3 "/home/palm/TLSHunter/run.py" --binary "$BINARY" --output "$OUTPUT_JSON" --image "$IMAGE_TAG")
RUN_ARGS+=("${META_ARGS[@]}")

if [[ $REBUILD -eq 1 ]]; then
    RUN_ARGS+=(--rebuild)
fi

if [[ $BACKGROUND -eq 1 ]]; then
    RUN_TAG="${TAG:-$(date +%Y%m%d_%H%M%S)}"
    LOG_FILE="${OUTPUT_JSON%.json}_${RUN_TAG}.log"
    PID_FILE="${OUTPUT_JSON%.json}_${RUN_TAG}.pid"
    nohup "${RUN_ARGS[@]}" >"$LOG_FILE" 2>&1 &
    BG_PID=$!
    echo "$BG_PID" > "$PID_FILE"
    echo "[*] Background analysis started"
    echo "[*] PID      : $BG_PID"
    echo "[*] PID file : $PID_FILE"
    echo "[*] Log file : $LOG_FILE"
    echo "[*] Output   : $OUTPUT_JSON"
    exit 0
fi

exec "${RUN_ARGS[@]}"
