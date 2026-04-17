#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/home/palm/TLSHunter"
RESULTS_DIR="${ROOT_DIR}/results"
IMAGE_TAG="tlshunter-integrated:phase2"

pick_log() {
    local latest=""
    latest="$(ls -1t "${RESULTS_DIR}"/chrome_analysis_*.log 2>/dev/null | head -n1 || true)"
    if [[ -n "${latest}" ]]; then
        echo "${latest}"
        return
    fi
    if [[ -f "${RESULTS_DIR}/analysis.log" ]]; then
        echo "${RESULTS_DIR}/analysis.log"
        return
    fi
    echo ""
}

while true; do
    clear
    echo "================ TLShunter Monitor ================"
    date '+%Y-%m-%d %H:%M:%S %z'
    echo

    echo "=== Docker containers ==="
    docker ps --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}'
    echo

    echo "=== Docker stats (target image only) ==="
    CONTAINER_IDS="$(docker ps --filter "ancestor=${IMAGE_TAG}" --format '{{.ID}}' || true)"
    if [[ -n "${CONTAINER_IDS}" ]]; then
        docker stats --no-stream --format 'table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}' ${CONTAINER_IDS}
    else
        echo "No running container for image ${IMAGE_TAG}"
    fi
    echo

    echo "=== Disk usage ==="
    df -h / "${ROOT_DIR}" /var/lib/docker 2>/dev/null || df -h
    echo

    LOG_FILE="${1:-$(pick_log)}"
    echo "=== Current analysis log ==="
    if [[ -n "${LOG_FILE}" && -f "${LOG_FILE}" ]]; then
        echo "Log file: ${LOG_FILE}"
        tail -n 20 "${LOG_FILE}"
    else
        echo "No analysis log found yet."
    fi
    echo

    echo "=== /host_output analysis.log ==="
    if [[ -f "${RESULTS_DIR}/analysis.log" ]]; then
        tail -n 20 "${RESULTS_DIR}/analysis.log"
    else
        echo "No ${RESULTS_DIR}/analysis.log yet."
    fi
    echo

    if [[ -f "${RESULTS_DIR}/ANALYSIS_DONE" ]]; then
        echo "=== ANALYSIS_DONE ==="
        cat "${RESULTS_DIR}/ANALYSIS_DONE"
        echo
    fi

    echo "[*] Refreshing in 60 seconds... (Ctrl+C to stop monitor)"
    sleep 60
done
