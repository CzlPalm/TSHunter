#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/home/palm/TLSHunter"
RESULTS_DIR="${ROOT_DIR}/results"
BINARY_PATH="${ROOT_DIR}/TLSKeyHunter/binary/chrome"
IMAGE_TAG="tlshunter-integrated:phase2"
DOCKERFILE_PATH="${ROOT_DIR}/integrated/Dockerfile"
JSON_OUT="${RESULTS_DIR}/143_auto.json"

mkdir -p "${RESULTS_DIR}"

if [[ "${1:-}" == "--worker" ]]; then
    TS="${2:?missing timestamp}"
    LOG_FILE="${3:?missing log file}"

    exec >>"${LOG_FILE}" 2>&1

    START_EPOCH="$(date +%s)"
    START_HUMAN="$(date '+%Y-%m-%d %H:%M:%S %z')"

    echo "============================================================"
    echo "[*] TLShunter Chrome analysis started"
    echo "[*] Start time      : ${START_HUMAN}"
    echo "[*] Host            : $(hostname)"
    echo "[*] Root dir        : ${ROOT_DIR}"
    echo "[*] Binary          : ${BINARY_PATH}"
    echo "[*] Image tag       : ${IMAGE_TAG}"
    echo "[*] Log file        : ${LOG_FILE}"
    echo "[*] JSON output     : ${JSON_OUT}"
    echo "[*] Worker PID      : $$"
    echo "============================================================"

    rm -f "${RESULTS_DIR}/ANALYSIS_DONE"

    BUILD_RC=0
    RUN_RC=0

    if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
        echo "[*] Docker image not found, building..."
        set +e
        docker build -t "${IMAGE_TAG}" -f "${DOCKERFILE_PATH}" "${ROOT_DIR}"
        BUILD_RC=$?
        set -e
        if [[ ${BUILD_RC} -ne 0 ]]; then
            echo "[!] Docker build failed with exit code ${BUILD_RC}"
        fi
    else
        echo "[*] Docker image already exists, skipping build."
    fi

    if [[ ${BUILD_RC} -eq 0 ]]; then
        echo "[*] Starting Docker analysis..."
        set +e
        docker run --rm \
            --name "tlshunter_chrome_${TS}" \
            -v "${ROOT_DIR}/TLSKeyHunter/binary:/usr/local/src/binaries" \
            -v "${RESULTS_DIR}:/host_output" \
            "${IMAGE_TAG}"
        RUN_RC=$?
        set -e
        echo "[*] Docker run finished with exit code ${RUN_RC}"
    else
        RUN_RC=${BUILD_RC}
    fi

    echo "[*] Parsing [RESULT] lines into JSON..."
    python3 - "${LOG_FILE}" "${JSON_OUT}" <<'PY'
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

log_file = Path(sys.argv[1])
json_out = Path(sys.argv[2])
results_dir = log_file.parent

sources = [
    log_file,
    results_dir / "analysis.log",
    results_dir / "docker_run_output.log",
]

text_parts = []
for src in sources:
    if src.exists():
        try:
            text_parts.append(src.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass

combined = "\n".join(text_parts)

result_re = re.compile(r"\[RESULT\]\s+type=(\S+)\s+function=(\S+)\s+rva=(\S+)\s+fingerprint=(.+?)(?:\s+note=(\S+))?$", re.MULTILINE)

role_map = {
    "HKDF": "TLS 1.3 Derive-Secret",
    "SSL_LOG_SECRET": "BoringSSL keylog output",
    "PRF": "TLS 1.2 master secret derivation",
    "KEY_EXPANSION": "TLS 1.2 key block derivation",
}
json_key_map = {
    "HKDF": "hkdf",
    "SSL_LOG_SECRET": "ssl_log_secret",
    "PRF": "prf",
    "KEY_EXPANSION": "key_expansion",
}

parsed = {}
for m in result_re.finditer(combined):
    result_type, function_name, rva, fingerprint, note = m.groups()
    parsed[result_type] = {
        "function": function_name,
        "rva": rva,
        "fingerprint": fingerprint.strip(),
        "fingerprint_len": len([b for b in fingerprint.strip().split(" ") if b]),
        "role": role_map.get(result_type, result_type),
    }
    if note:
        parsed[result_type]["note"] = note.replace("_", " ")

hook_points = {}
for result_type, key in json_key_map.items():
    if result_type in parsed:
        hook_points[key] = parsed[result_type]

data = {
    "meta": {
        "binary": "chrome",
        "analysis_tool": "TLShunter phase2",
        "analysis_date": datetime.now(timezone.utc).isoformat(),
    },
    "hook_points": hook_points,
}

json_out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"[*] JSON written to {json_out}")
print(f"[*] Parsed hook points: {', '.join(hook_points.keys()) if hook_points else '(none)'}")
PY

    END_EPOCH="$(date +%s)"
    END_HUMAN="$(date '+%Y-%m-%d %H:%M:%S %z')"
    DURATION_SEC="$((END_EPOCH - START_EPOCH))"

    echo "============================================================"
    echo "[*] End time        : ${END_HUMAN}"
    echo "[*] Total duration  : ${DURATION_SEC} seconds"
    echo "[*] Final exit code : ${RUN_RC}"
    echo "============================================================"

    {
        echo "finished_at=${END_HUMAN}"
        echo "duration_seconds=${DURATION_SEC}"
        echo "exit_code=${RUN_RC}"
        echo "log_file=${LOG_FILE}"
        echo "json_out=${JSON_OUT}"
    } > "${RESULTS_DIR}/ANALYSIS_DONE"

    printf '\a' || true

    exit "${RUN_RC}"
fi

TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${RESULTS_DIR}/chrome_analysis_${TS}.log"
PID_FILE="${RESULTS_DIR}/chrome_analysis_${TS}.pid"

if [[ ! -f "${BINARY_PATH}" ]]; then
    echo "[!] Binary not found: ${BINARY_PATH}" >&2
    exit 1
fi

setsid nohup "${BASH_SOURCE[0]}" --worker "${TS}" "${LOG_FILE}" >/dev/null 2>&1 &
BG_PID=$!

echo "${BG_PID}" > "${PID_FILE}"

echo "[*] Background analysis started"
echo "[*] PID       : ${BG_PID}"
echo "[*] PID file  : ${PID_FILE}"
echo "[*] Log file  : ${LOG_FILE}"
echo "[*] JSON file : ${JSON_OUT}"
echo
echo "[*] Monitor examples:"
echo "    ps -p ${BG_PID} -o pid,ppid,stat,etime,cmd"
echo "    tail -f ${LOG_FILE}"
echo "    cat ${RESULTS_DIR}/ANALYSIS_DONE"
