#!/bin/bash
set -euo pipefail

shopt -s nullglob

binaries=(/usr/local/src/binaries/*)
if [ ${#binaries[@]} -eq 0 ]; then
    echo "[-] No binaries found in /usr/local/src/binaries"
    exit 1
fi

selected_bin=""
if [ -n "${SELECT_BINARY:-}" ] && [ -f "/usr/local/src/binaries/${SELECT_BINARY}" ]; then
    selected_bin="/usr/local/src/binaries/${SELECT_BINARY}"
fi

if [ -z "$selected_bin" ]; then
    for bin in "${binaries[@]}"; do
        if file "$bin" | grep -Eiq 'elf|mach-o|pe32'; then
            selected_bin="$bin"
            break
        fi
    done
fi

if [ -z "$selected_bin" ]; then
    echo "[-] No supported binary found in /usr/local/src/binaries"
    exit 1
fi

bin_name=$(basename "$selected_bin")
if command -v sha256sum >/dev/null 2>&1; then
    bin_sha256=$(sha256sum "$selected_bin" | awk '{print $1}')
else
    bin_sha256="unavailable"
fi

echo "[*] Analyzing $bin_name"
echo "[*] SHA256: $bin_sha256"

SCRIPT_PATHS="/usr/local/src;/usr/local/src/common;/usr/local/src/stacks;/usr/local/src/detect"

export MAXMEM=16G
export _JAVA_OPTIONS="-Xmx16G"
/opt/ghidra_12.0.3_PUBLIC/support/analyzeHeadless /tmp "tlshunter_$(date +%s)" \
    -import "$selected_bin" \
    -scriptPath "$SCRIPT_PATHS" \
    -prescript MinimalAnalysisOption.java \
    -postScript TLShunterAnalyzer.java \
    -maxMem 16G | tee /host_output/analysis.log
