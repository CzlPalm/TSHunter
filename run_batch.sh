#!/bin/bash
# TLSHunter batch 批量分析脚本
# 用法: nohup bash run_batch.sh > logs/batch_$(date +%Y%m%d_%H%M%S).log 2>&1 &
#
# 可选环境变量:
#   VENV_PATH   - 虚拟环境路径（默认自动检测 fritap-env 或 palm）
#   VERSIONS_FILE - 版本清单文件（不指定则扫描 binaries-dir 全部版本）

set -euo pipefail

# 自动检测虚拟环境
if [ -n "${VENV_PATH:-}" ]; then
    source "$VENV_PATH/bin/activate"
elif [ -d "$HOME/fritap-env" ]; then
    source ~/fritap-env/bin/activate
elif [ -d "$HOME/palm" ]; then
    source ~/palm/bin/activate
else
    echo "ERROR: 未找到虚拟环境，请设置 VENV_PATH 环境变量" >&2
    exit 1
fi

# 进入脚本所在目录（即项目根目录）
cd "$(dirname "$0")"

# 创建日志目录
mkdir -p logs

# 构建 batch 命令
BATCH_ARGS=(
    --browser chrome
    --binaries-dir binaries/Chrome
    --platform linux
    --arch x86_64
    --db data/fingerprints.db
    --cleanup-binary
)

# 如果指定了版本清单文件，使用它
if [ -n "${VERSIONS_FILE:-}" ]; then
    BATCH_ARGS+=(--versions-file "$VERSIONS_FILE")
fi

# 运行 batch
tshunter batch -- "${BATCH_ARGS[@]}"
