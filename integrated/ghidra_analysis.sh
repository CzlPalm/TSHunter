#!/bin/bash
set -euo pipefail

shopt -s nullglob

binaries=(/usr/local/src/binaries/*)
if [ ${#binaries[@]} -eq 0 ]; then
    echo "[-] No binaries found in /usr/local/src/binaries"
    exit 1
fi

selected_bin=""
for bin in "${binaries[@]}"; do
    if file "$bin" | grep -Eiq 'elf|mach-o|pe32'; then
        selected_bin="$bin"
        break
    fi
done

if [ -z "$selected_bin" ]; then
    echo "[-] No supported binary found in /usr/local/src/binaries"
    exit 1
fi

bin_name=$(basename "$selected_bin")
echo "[*] Analyzing $bin_name"

export MAXMEM=16G
export _JAVA_OPTIONS="-Xmx16G"
/opt/ghidra_12.0.3_PUBLIC/support/analyzeHeadless /tmp "tlshunter_$(date +%s)" \
    -import "$selected_bin" \
    -scriptPath /usr/local/src \
    -prescript MinimalAnalysisOption.java \
    -postScript TLShunterAnalyzer.java \
    -maxMem 16G | tee /host_output/analysis.log
