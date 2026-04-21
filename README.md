# TLShunter

单仓化后的 `TLShunter` 用于对静态链接或内嵌 BoringSSL 的目标二进制做一次性 Ghidra headless 分析，自动输出以下 Hook 点的 `RVA + fingerprint`：

- `HKDF`：TLS 1.3 Derive-Secret
- `SSL_LOG_SECRET`：BoringSSL keylog 输出函数
- `PRF`：TLS 1.2 master secret 派生
- `KEY_EXPANSION`：TLS 1.2 key block 派生

## 快速开始

### 1. 构建镜像

```bash
docker build -f Dockerfile -t tlshunter:0.5.0 .
```

### 2. 分析单个二进制

```bash
python3 run.py \
  --binary /path/to/chrome \
  --output /path/to/result.json
```

### 3. 启动 Chrome 长跑分析

```bash
bash run_chrome_analysis.sh
```

### 4. 监控运行状态

```bash
bash monitor_analysis.sh
```

## 核心文件

- `scripts/TLShunterAnalyzer.java`：统一的 Ghidra 分析脚本
- `MinimalAnalysisOption.java`：关闭不必要分析器
- `Dockerfile`：Ghidra 12.0.3 + JDK 21 分析环境
- `ghidra_analysis.sh`：容器内 headless 执行入口
- `run.py`：本地 Python 入口

## 指纹标准

统一指纹提取规则见：`docs/fingerprint_standard.md`

HKDF 的 next-CALL 投票识别策略见：`docs/hkdf_identification.md`

## 依赖

- Docker
- Python 3
- Ghidra 12.0.3（已内置于 Docker）
- JDK 21（已内置于 Docker）

