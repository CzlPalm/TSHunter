# P6 Phase 2：Chrome 多版本二进制采集 + 指纹数据库构建 — 详细执行步骤

**起始条件**: Phase 1 ✅（ssl_log_secret 集成完成，98.3% 捕获率，12 条结构性漏捕已记录为 known limitation）  
**目标**: 从"单版本可用"到"多版本可复制"，产出跨版本指纹稳定性评估表  
**预计周期**: 2-3 周

---

## 一、整体流程概览

```
Step 1: 版本来源确认 + 下载脚本 (2d)
    ↓
Step 2: 批量下载 10-15 个版本二进制 (1d，主要是下载等待)
    ↓
Step 3: 手动分析 2-3 个版本建立信心 (2d)
    ↓
Step 4: 批处理流水线实现 (2-3d)
    ↓
Step 5: PRF 识别补充方案 (1-2d)
    ↓
Step 6: 指纹稳定性评估表 + 数据库产出 (2d)
    ↓
Step 7: 多版本实测验证 (1-2d)
```

---

## 二、Step 1：版本来源确认 + 下载脚本（2d）

### 1.1 主要来源：Chrome for Testing API

Google 官方提供了 Chrome for Testing（CfT）下载服务，覆盖 milestone 113 起的所有稳定版本。

**关键 API 端点**：

```bash
# 获取每个大版本（milestone）的最新可下载版本
curl -s https://googlechromelabs.github.io/chrome-for-testing/latest-versions-per-milestone-with-downloads.json \
  | python3 -m json.tool > milestones.json

# 获取某个具体 milestone 的最新版本号
curl -s https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_140

# 直接下载 linux64 二进制
wget https://storage.googleapis.com/chrome-for-testing-public/{VERSION}/linux64/chrome-linux64.zip
```

**下载 URL 模式**：
```
https://storage.googleapis.com/chrome-for-testing-public/{version}/linux64/chrome-linux64.zip
```

### 1.2 建议覆盖的版本范围

优先级从高到低：

```
第一梯队（必须，近 1 年稳定版，每个大版本选最新补丁）:
  135.x, 136.x, 137.x, 138.x, 139.x, 140.x, 141.x, 142.x, 143.x (当前基线)

第二梯队（推荐，验证更长时间跨度的指纹稳定性）:
  130.x, 125.x, 120.x, 115.x

第三梯队（可选，CfT 起始版本）:
  113.x, 114.x
```

目标：**10-15 个版本**，覆盖约 2 年的 Chrome 发布历史。

### 1.3 下载脚本实现

在项目 `tools/` 目录下创建 `chrome_downloader.py`：

```python
#!/usr/bin/env python3
"""
tools/chrome_downloader.py — 批量下载 Chrome for Testing 二进制

用法:
  python3 tools/chrome_downloader.py --milestones 135,136,137,138,139,140,141,142,143
  python3 tools/chrome_downloader.py --all          # 下载所有可用 milestone
  python3 tools/chrome_downloader.py --list          # 仅列出可用版本，不下载

输出目录结构:
  artifacts/chrome/{version}/
    ├── chrome              ← 解压后的二进制
    ├── metadata.json       ← 版本号、SHA256、下载时间、平台
    └── chrome-linux64.zip  ← 原始下载包（可选保留）
"""
```

核心逻辑：

1. 请求 `latest-versions-per-milestone-with-downloads.json` 获取版本列表
2. 过滤出 `linux64` 平台的 `chrome` 下载链接
3. 下载 zip → 解压 → 提取 `chrome` 二进制
4. 计算 SHA256，写入 `metadata.json`
5. 用 `strings chrome | grep -c "master secret"` 快速验证 BoringSSL 代码存在

**验收标准**：
- 脚本能一键下载指定 milestone 的 Chrome 二进制
- `artifacts/chrome/` 下有 10+ 个版本目录
- 每个目录包含 `chrome` 二进制和 `metadata.json`

---

## 三、Step 2：批量下载（1d）

执行下载：

```bash
python3 tools/chrome_downloader.py \
  --milestones 115,120,125,130,135,136,137,138,139,140,141,142,143 \
  --output-dir artifacts/chrome

# 验证
ls artifacts/chrome/*/chrome | wc -l   # 应 >= 10
```

每个 Chrome 二进制约 250-300MB，总下载量约 3-4GB。

下载完成后，对每个版本做快速 sanity check：

```bash
for d in artifacts/chrome/*/; do
  version=$(basename "$d")
  has_tls=$(strings "$d/chrome" | grep -c "master secret")
  has_hkdf=$(strings "$d/chrome" | grep -c "c hs traffic")
  echo "$version: master_secret=$has_tls, c_hs_traffic=$has_hkdf"
done
```

所有版本都应该有这两个字符串，否则说明 BoringSSL 代码不在主二进制中（极不可能但需要确认）。

---

## 四、Step 3：手动分析 2-3 个版本建立信心（2d）

**这一步的意义**：在构建自动化流水线之前，先手动验证假设——"TLSKeyHunter/BoringSecretHunter 对不同版本的 Chrome 是否能稳定工作"。

### 3.1 选择版本

建议选：
- **当前版本 143.x**（已有结果，作为基准对比）
- **一个近期版本**（如 140.x 或 141.x，预期变化小）
- **一个较老版本**（如 130.x 或 125.x，预期可能有变化）

### 3.2 对每个版本执行

```bash
# 1. TLSKeyHunter — 提取 HKDF 指纹
cp artifacts/chrome/{version}/chrome ~/BoringSecretHunter/TLSKeyHunter/binary/
sudo docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  tlskeyhunter

# 2. BoringSecretHunter — 提取 ssl_log_secret 指纹
cp artifacts/chrome/{version}/chrome ~/BoringSecretHunter/BoringSecretHunter/binary/
sudo docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecretHunter
```

### 3.3 记录关键数据

对每个版本手动填表：

| 字段 | 143.x (基线) | 140.x | 130.x |
|------|-------------|-------|-------|
| HKDF RVA | 0x048837E0 | ? | ? |
| HKDF 指纹前 32B | 55 48 89 E5... | ? | ? |
| HKDF 指纹完全相同？ | 基准 | ? | ? |
| TLSKeyHunter PRF 识别 | ❌ 失败 | ? | ? |
| ssl_log_secret RVA | 0x04883520 | ? | ? |
| ssl_log_secret 指纹 | 55 48 89 E5 41 57... | ? | ? |
| Ghidra 分析耗时 | ~20h | ? | ? |

### 3.4 关键观察点

- **指纹是否相同？** 如果前 32 字节完全一致，说明函数序言稳定，指纹可跨版本复用
- **RVA 变化幅度？** 如果 RVA 只是小幅偏移（几千字节），说明回退扫描的搜索范围可以控制在合理范围
- **TLSKeyHunter PRF 是否继续失败？** 如果所有版本都失败，确认需要 Step 5 的补充方案
- **分析耗时？** 评估批处理流水线的总时间成本

**验收标准**：
- 2-3 个版本的对比表完成
- 对"指纹稳定性"有初步定量判断
- 知道 TLSKeyHunter/BSH 在不同版本上的行为

---

## 五、Step 4：批处理流水线实现（2-3d）

### 4.1 流水线脚本

在 `tools/` 目录下创建 `batch_analyze.sh`：

```bash
#!/bin/bash
# tools/batch_analyze.sh — 对 artifacts/chrome/ 下的每个版本运行分析

ARTIFACTS_DIR="artifacts/chrome"
RESULTS_DIR="results"
HOOKS_DIR="hooks"

for version_dir in "$ARTIFACTS_DIR"/*/; do
  version=$(basename "$version_dir")
  chrome_bin="$version_dir/chrome"
  result_file="$RESULTS_DIR/$version.json"
  
  # 跳过已分析版本
  if [ -f "$result_file" ]; then
    echo "[SKIP] $version — 已有结果"
    continue
  fi
  
  echo "[ANALYZE] $version"
  
  # 1. TLSKeyHunter
  echo "  [1/3] TLSKeyHunter ..."
  cp "$chrome_bin" /tmp/tlskh_binary/chrome
  sudo docker run --rm \
    -v /tmp/tlskh_binary:/usr/local/src/binaries \
    -v /tmp/tlskh_results:/host_output \
    tlskeyhunter 2>&1 | tee "$RESULTS_DIR/${version}_tlskh.log"
  
  # 2. BoringSecretHunter
  echo "  [2/3] BoringSecretHunter ..."
  cp "$chrome_bin" /tmp/bsh_binary/chrome
  sudo docker run --rm \
    -v /tmp/bsh_binary:/usr/local/src/binaries \
    -v /tmp/bsh_results:/host_output \
    boringsecretHunter 2>&1 | tee "$RESULTS_DIR/${version}_bsh.log"
  
  # 3. 合并结果 → JSON
  echo "  [3/3] 生成 JSON ..."
  python3 tools/merge_analysis.py \
    --version "$version" \
    --tlskh-log "$RESULTS_DIR/${version}_tlskh.log" \
    --bsh-log "$RESULTS_DIR/${version}_bsh.log" \
    --output "$HOOKS_DIR/chrome_${version}_linux_x86_64.json"
  
  echo "[DONE] $version"
done
```

### 4.2 结果合并脚本

`tools/merge_analysis.py`：从 TLSKeyHunter 和 BoringSecretHunter 的日志中提取关键数据，生成与 `chrome_143.0.7499.169_linux_x86_64.json` 同格式的 JSON 配置。

需要解析的关键信息：

```
从 TLSKeyHunter 日志:
  - HKDF function: FUN_XXXXXXXX
  - Function offset (IDA with base 0x0): XXXXXXXX
  - Byte pattern for frida: XX XX XX ...

从 BoringSecretHunter 日志:
  - Function label: FUN_XXXXXXXX
  - Function offset (IDA with base 0x0): XXXXXXXX
  - Byte pattern for frida (friTap): XX XX XX ...
```

### 4.3 注意事项

- Ghidra headless 分析 Chrome ~250MB 二进制需要 **~20 小时/版本**
- 如果有 10 个版本需要分析，串行需要 ~200 小时（~8 天）
- 建议：如果有多核机器，用 `parallel` 或后台 `&` 并行跑多个 Docker 容器
- 每个容器需要 ~8GB RAM，4 并行需要 ~32GB

**验收标准**：
- `batch_analyze.sh` 能自动化跑完一个版本
- `merge_analysis.py` 能从日志解析出正确的 RVA 和指纹
- 生成的 JSON 格式与现有模板一致

---

## 六、Step 5：PRF 识别补充方案（1-2d）

TLSKeyHunter 对 Chrome 的 PRF 识别失败（P2 已确认），需要补充方案。

### 方案 B（推荐，最轻量）：独立 Ghidra 脚本

在 `tools/` 下创建 `FindPRF.java`（Ghidra 脚本）：

```java
// 搜索 "master secret" 字符串的 XREF，定位 PRF 函数
// 逻辑：
// 1. 在 .rodata 中搜索 "master secret" 的十六进制 (6d 61 73 74 65 72 20 73 65 63 72 65 74)
// 2. 找到所有引用该地址的指令
// 3. 向上追溯到所在函数的入口点
// 4. 提取函数入口的字节指纹
```

这个脚本可以在 Ghidra headless 模式下运行，与 TLSKeyHunter 分析同一个项目文件。

### 方案 C（备选）：跨版本指纹扫描

利用 143.x 已知的 PRF 指纹前 16-20 字节，在新版本二进制中搜索：

```bash
# 已知 PRF 指纹前 20 字节（函数序言，跨版本通常稳定）
PATTERN="55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 58 64 48 8B 04"

python3 tools/fingerprint_scan.py \
  --binary artifacts/chrome/140.x/chrome \
  --pattern "$PATTERN" \
  --section .text
```

如果命中 1 个结果，就是 PRF 函数入口，直接记录 RVA。

### 实施建议

先在 Step 3 的手动分析中验证方案 C 是否可行（成功率和误报率），如果可行则直接集成到批处理流水线中，省去 Ghidra headless 分析 PRF 的时间。

**验收标准**：
- 至少一种方案能对 3+ 个版本正确定位 PRF 函数
- PRF RVA 和指纹能写入 JSON 配置

---

## 七、Step 6：指纹稳定性评估表 + 数据库产出（2d）

### 6.1 核心评估表

这是**项目最重要的产出之一**，直接对应论文的数据贡献。

对所有已分析版本生成对比表：

```markdown
| 版本 | Milestone | HKDF RVA | HKDF 指纹前32B | PRF RVA | PRF 指纹前20B | ssl_log RVA | 指纹变化？ | RVA 偏移量 |
|------|-----------|----------|---------------|---------|-------------|-------------|-----------|-----------|
| 115.0.5790.170 | 115 | 0x04321E0 | 55 48 89 E5... | 0x08F2D4B0 | 55 48 89 E5... | 0x04321520 | 基准 | — |
| 120.0.xxxx.xx | 120 | ? | ? | ? | ? | ? | ? | ? |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |
| 143.0.7499.169 | 143 | 0x048837E0 | 55 48 89 E5... | 0x0A22D4B0 | 55 48 89 E5... | 0x04883520 | 参考 | — |
```

### 6.2 需要回答的关键问题

1. **指纹复用率**：N 个版本中，有多少个版本的 HKDF 函数序言（前 32 字节）完全相同？
2. **RVA 变化模式**：RVA 是线性增长还是有跳变？变化幅度范围？
3. **断裂点**：哪些大版本之间指纹发生了变化？变化原因猜测（BoringSSL 版本升级？编译器变化？）
4. **回退扫描可行性**：如果用前 20 字节指纹做内存扫描，在 250MB chrome 二进制的 .text 段中是否能唯一命中？

### 6.3 数据库产出

确保 `hooks/` 目录下每个版本都有对应的 JSON 文件：

```
hooks/
├── chrome_hooks.js                              ← 参数化模板（不变）
├── chrome_115.0.5790.170_linux_x86_64.json
├── chrome_120.0.xxxx.xx_linux_x86_64.json
├── chrome_125.0.xxxx.xx_linux_x86_64.json
├── chrome_130.0.xxxx.xx_linux_x86_64.json
├── chrome_135.0.xxxx.xx_linux_x86_64.json
├── chrome_136.0.xxxx.xx_linux_x86_64.json
├── ...
├── chrome_143.0.7499.169_linux_x86_64.json      ← 现有基线
└── fingerprint_stability_report.md               ← 评估表
```

**验收标准**：
- 指纹稳定性评估表完成，覆盖 8+ 个版本
- 每个版本有对应的 JSON 配置文件
- `fingerprint_stability_report.md` 回答了上述 4 个关键问题

---

## 八、Step 7：多版本实测验证（1-2d）

### 7.1 选择 2-3 个非当前版本进行实测

**前提**：需要能在本地运行这些版本的 Chrome。Chrome for Testing 的二进制可以直接运行（不需要安装），但可能需要额外的依赖库。

```bash
# 运行 CfT Chrome
./artifacts/chrome/140.x/chrome-linux64/chrome \
  --no-sandbox \
  --user-data-dir=/tmp/chrome_test_140 \
  --disable-extensions
```

### 7.2 对每个测试版本

1. 修改 `version_detect.py` 或手动指定配置文件
2. 运行 `tls_capture.py --auto --chrome-bin <path-to-old-chrome>`
3. 访问几个 HTTPS 站点
4. 检查密钥是否成功捕获
5. 如果可能，做 SSLKEYLOGFILE diff

### 7.3 预期可能的问题

- **CfT 二进制的 BoringSSL 版本与官方 Chrome 不同？** 不太可能，但需要确认 `strings | grep "boringssl"` 的输出
- **结构体偏移变化？** 如果 client_random 路径或 key_len_offsets 变了，密钥会读取错误
- **CfT 二进制不支持 SSLKEYLOGFILE？** 有些编译配置可能禁用 keylog 回调

### 7.4 问题处理

如果某个版本实测失败：
1. 检查 Frida 是否成功 attach
2. 检查 Hook 是否触发（看 DBG 日志）
3. 如果 Hook 触发但密钥错误，可能是偏移量变化——需要对该版本单独分析偏移

**验收标准**：
- 至少 2 个非 143.x 版本实测成功捕获密钥
- 或者明确记录失败原因和需要调整的偏移量

---

## 九、时间估算

```
Week 1:
  Day 1-2: Step 1 (下载脚本) + Step 2 (批量下载)
  Day 3-4: Step 3 (手动分析 2-3 版本)
  Day 5:   Step 4 开始 (批处理流水线)

Week 2:
  Day 1-2: Step 4 完成 + 流水线运行（后台跑 Docker）
  Day 3:   Step 5 (PRF 补充方案)
  Day 4:   Step 6 (评估表)
  Day 5:   Step 7 (多版本实测)

Week 3 (Buffer):
  流水线补跑 + 问题修复 + 文档完善
```

**关键路径瓶颈**：Ghidra headless 分析时间（~20h/版本）。建议 Step 2 下载完成后立即启动第一批分析任务后台运行。

---

## 十、Phase 2 验收标准汇总

| # | 标准 | 验证方式 |
|---|------|---------|
| 1 | 本地有 10+ 个 Chrome 版本二进制 | `ls artifacts/chrome/*/chrome \| wc -l` |
| 2 | 下载脚本可重复执行 | `python3 tools/chrome_downloader.py --list` |
| 3 | 每个版本有 HKDF RVA + 指纹 | JSON 文件中 `hook_points.hkdf.rva` 非空 |
| 4 | 每个版本有 ssl_log_secret RVA + 指纹 | JSON 文件中 `hook_points.ssl_log_secret.rva` 非空 |
| 5 | PRF RVA 至少覆盖 80% 版本 | 评估表统计 |
| 6 | 指纹稳定性评估表完成 | `fingerprint_stability_report.md` |
| 7 | 至少 2 个非当前版本实测通过 | 运行日志 |
| 8 | 批处理流水线可自动执行 | `bash tools/batch_analyze.sh` |

---

## 十一、Phase 2 产出物清单

```
新增文件:
  tools/chrome_downloader.py          ← 版本下载脚本
  tools/batch_analyze.sh              ← 批处理流水线
  tools/merge_analysis.py             ← 分析结果合并
  tools/fingerprint_scan.py           ← 指纹内存扫描（PRF 补充）
  tools/FindPRF.java                  ← Ghidra PRF 定位脚本（可选）
  artifacts/chrome/*/                 ← 各版本二进制
  hooks/chrome_{version}_*.json       ← 各版本配置（8+个）
  hooks/fingerprint_stability_report.md ← 核心评估数据

更新文件:
  learn/P6/known_limitations.md       ← 追加 Phase 1 的 12 条 diff 记录
  README.md                           ← 新增多版本支持说明
```

---

## 十二、与后续阶段的衔接

Phase 2 完成后，项目具备：
- 一个覆盖 10+ 版本的指纹数据库
- 一套可重复的分析流水线
- 量化的指纹稳定性数据

这直接支撑：
- **Phase 3 / P7**：指纹内存扫描 + 未知版本自动适配（用评估表确定扫描策略）
- **P8**：多浏览器扩展（Firefox/Edge，复用流水线框架）
- **论文撰写**：评估表是最核心的实验数据
