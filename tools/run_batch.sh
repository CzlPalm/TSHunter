#!/usr/bin/env bash
# tools/run_batch.sh — P6 Phase 2 批量生成 Chrome 版本 hooks JSON
#
# 流程：
#   1. 读取 configs/chrome_versions.txt（一行一个 milestone）
#   2. chrome_downloader.py 下载 artifacts/chrome/<ver>/chrome + metadata.json
#   3. 优先读取 artifacts/chrome/<ver>/auto.json（由外部 TSHunter 放入）：
#        有 → merge_analysis.py 生成 hooks/chrome_<ver>_linux_x86_64.json
#        无 → 回退 fingerprint_scan.py（用 baseline 143 指纹扫描）
#   4. 汇总每个版本的状态
#
# 约定：
#   - TSHunter 分析在容器内跑，完成后把结果 JSON 放到 artifacts/chrome/<ver>/auto.json
#     （本脚本不直接调 Ghidra）
#   - baseline 固定为 hooks/chrome_143.0.7499.169_linux_x86_64.json
#   - 入库策略：成功生成的 JSON 由人工 git add + commit
#
# 用法：
#   bash tools/run_batch.sh
#   BASELINE=... MILESTONES_FILE=... bash tools/run_batch.sh
 
set -euo pipefail
 
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
 
BASELINE="${BASELINE:-hooks/chrome_143.0.7499.169_linux_x86_64.json}"
MILESTONES_FILE="${MILESTONES_FILE:-configs/chrome_versions.txt}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-artifacts/chrome}"
HOOKS_DIR="${HOOKS_DIR:-hooks}"
SUBTRACT_IMAGE_BASE="${SUBTRACT_IMAGE_BASE:-}"  # 留空：TSHunter 已返回 RVA；填 0x100000：TSHunter 返回 Ghidra 绝对地址
 
if [[ ! -f "$BASELINE" ]]; then
    echo "[ERR] baseline 不存在: $BASELINE" >&2
    exit 2
fi
if [[ ! -f "$MILESTONES_FILE" ]]; then
    echo "[ERR] milestones 文件不存在: $MILESTONES_FILE" >&2
    exit 2
fi
 
milestones=()
while IFS= read -r line; do
    line="${line%%#*}"
    line="${line//[[:space:]]/}"
    [[ -z "$line" ]] && continue
    milestones+=("$line")
done < "$MILESTONES_FILE"
 
if [[ ${#milestones[@]} -eq 0 ]]; then
    echo "[ERR] milestones 列表为空" >&2
    exit 2
fi
 
echo "[*] baseline        = $BASELINE"
echo "[*] milestones      = ${milestones[*]}"
echo "[*] artifacts dir   = $ARTIFACTS_DIR"
echo "[*] hooks dir       = $HOOKS_DIR"
echo
 
# ── 步骤 1：下载 ─────────────────────────────────────────────
python3 tools/chrome_downloader.py \
    --milestones "$(IFS=,; echo "${milestones[*]}")" \
    --output-dir "$ARTIFACTS_DIR"
 
echo
 
# ── 步骤 2 & 3：逐版本合成 JSON ──────────────────────────────
declare -a ok_list
declare -a scan_list
declare -a fail_list
 
for m in "${milestones[@]}"; do
    ver_dir=$(find "$ARTIFACTS_DIR" -mindepth 1 -maxdepth 1 -type d -name "${m}.*" | head -n1 || true)
    if [[ -z "$ver_dir" ]]; then
        echo "[SKIP] milestone=$m: 未找到 artifacts 目录"
        fail_list+=("$m")
        continue
    fi
    ver="$(basename "$ver_dir")"
    bin="$ver_dir/chrome"
    auto="$ver_dir/auto.json"
    meta="$ver_dir/metadata.json"
    out="$HOOKS_DIR/chrome_${ver}_linux_x86_64.json"
 
    echo "=== milestone=$m  version=$ver ==="
 
    sub_args=()
    if [[ -n "$SUBTRACT_IMAGE_BASE" ]]; then
        sub_args=(--subtract-image-base "$SUBTRACT_IMAGE_BASE")
    fi
    meta_args=()
    [[ -f "$meta" ]] && meta_args=(--metadata "$meta")
 
    if [[ -f "$auto" ]]; then
        if python3 tools/merge_analysis.py \
            --auto "$auto" \
            --baseline "$BASELINE" \
            --version "$ver" \
            --out "$out" \
            "${meta_args[@]}" \
            "${sub_args[@]}"; then
            ok_list+=("$ver")
            continue
        fi
        echo "[WARN] merge 失败，回退 fingerprint_scan"
    else
        echo "[INFO] 无 auto.json，使用 fingerprint_scan 回退"
    fi
 
    if python3 tools/fingerprint_scan.py \
        --binary "$bin" \
        --baseline "$BASELINE" \
        --version "$ver" \
        --out "$out" \
        "${meta_args[@]}"; then
        scan_list+=("$ver")
    else
        fail_list+=("$ver")
    fi
done
 
echo
echo "======== 汇总 ========"
echo "merge 成功 : ${#ok_list[@]}  (${ok_list[*]:-})"
echo "fp_scan 回退: ${#scan_list[@]}  (${scan_list[*]:-})"
echo "失败        : ${#fail_list[@]}  (${fail_list[*]:-})"
 
[[ ${#fail_list[@]} -eq 0 ]]
