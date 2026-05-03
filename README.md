# TLShunter 项目使用说明

`TLShunter` 是一个面向 TLS 关键函数定位的分析工程，核心目标是：

1. 对目标二进制做静态分析，识别 TLS 关键 hook 点
2. 输出稳定的 `RVA + fingerprint`
3. 将分析结果写入 SQLite 指纹数据库
4. 在相邻小版本之间优先使用指纹重定位，减少重复长跑分析

当前重点支持 BoringSSL 场景，主要识别以下 4 类 hook 点：

- `hkdf`：TLS 1.3 Derive-Secret
- `ssl_log_secret`：BoringSSL keylog 输出函数
- `prf`：TLS 1.2 master secret 派生
- `key_expansion`：TLS 1.2 key block 派生

---

## 1. 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

安装后统一入口为 `tshunter`：

```bash
tshunter --help
```

子命令：`analyze` / `capture` / `ingest` / `query` / `relocate` / `merge` / `download` / `batch`

---

## 2. `--` 转发规则

`tshunter` 的每个子命令都是**转发型**入口：它将参数原样传递给下层实现脚本。  
`--` 分隔符可选——有无均可，下层都能正确解析：

```bash
# 两种写法等价
tshunter ingest --json results/x.json --db data/fingerprints.db
tshunter ingest -- --json results/x.json --db data/fingerprints.db
```

`relocate` 子命令比较特殊，它本身还有二级子命令（`scan` / `probe`），必须在转发参数里指定：

```bash
tshunter relocate -- scan --binary /path/chrome --source-browser chrome ...
tshunter relocate -- probe --binary /path/chrome --fingerprint "55 48 89 E5 ..." --old-rva 0x1000
```

---

## 3. 常用工作流

### 3.1 静态分析（Ghidra）

```bash
tshunter analyze \
  --binary /path/to/chrome \
  --output results/chrome_143.0.7499.169_linux_x86_64.json \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --tls-lib boringssl
```

### 3.2 入库

```bash
# 从静态分析 JSON 入库
tshunter ingest \
  --json results/chrome_143.0.7499.169_linux_x86_64.json \
  --db data/fingerprints.db

# 如果 JSON 本身缺少 browser/version/platform/arch 字段，可通过 CLI 补充
tshunter ingest \
  --json results/chrome_143.0.7499.169_linux_x86_64.json \
  --browser chrome --version 143.0.7499.169 \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db

# 从 relocate 结果入库（--from-relocate 而不是 --json）
tshunter ingest \
  --from-relocate results/relocate_192.json \
  --browser chrome --version 143.0.7499.192 \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db --upsert
```

注意：
- 默认拒绝空 `hook_points` 入库；需要时显式加 `--allow-empty`
- `--upsert` 允许覆盖已有条目

### 3.3 查询

```bash
# 精确版本
tshunter query \
  --browser chrome --version 143.0.7499.169 \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db

# 输出 Frida hooks JSON
tshunter query \
  --browser chrome --version 143.0.7499.169 \
  --platform linux --arch x86_64 \
  --format frida --db data/fingerprints.db

# 按 major.minor 列版本
tshunter query --browser chrome --major-minor 143.0 --db data/fingerprints.db

# 查统计报告
tshunter query --report --db data/fingerprints.db
```

---

## 4. Relocate 测试：用 143.0.7499.169 定位 143.0.7499.192

### 前提条件

1. **143.0.7499.169 已在数据库中且有 hook_points**（当前 `data/fingerprints.db` 已满足）：

```bash
sqlite3 data/fingerprints.db \
  "SELECT hp.kind, hp.rva, hp.fingerprint_len \
   FROM hook_points hp \
   JOIN versions v ON v.id=hp.version_id \
   JOIN browsers b ON b.id=v.browser_id \
   WHERE b.name='chrome' AND v.version='143.0.7499.169';"
```

预期：出现 `hkdf`、`key_expansion`、`prf`、`ssl_log_secret` 4 行。

2. **目标二进制存在**：

```bash
ls -lh binaries/Chrome/143.0.7499.192/chrome
```

### 步骤一：执行 scan

```bash
tshunter relocate -- scan \
  --binary binaries/Chrome/143.0.7499.192/chrome \
  --db data/fingerprints.db \
  --source-browser chrome \
  --source-version 143.0.7499.169 \
  --source-platform linux \
  --source-arch x86_64 \
  --output results/relocate_143.0.7499.192_from_169.json
```

输出示例：

```
[*] Relocate verdict: OK        ← 或 PARTIAL / FAIL
[*] Output written to results/relocate_143.0.7499.192_from_169.json
```

### 步骤二：核查 JSON 结果

```bash
python3 -c "
import json
d = json.load(open('results/relocate_143.0.7499.192_from_169.json'))
print('verdict:', d['verdict'])
print('summary:', json.dumps(d['relocation_summary'], indent=2))
for h in d['hooks']:
    print(h['kind'], h['match_type'], 'new_rva:', h.get('new_rva'), 'delta:', h.get('delta'))
"
```

verdict 含义：
- `OK`：所有 hook 均命中，且 delta 一致（版本间整体偏移稳定）
- `PARTIAL`：部分命中，或 delta 不一致（各函数偏移不同）
- `FAIL`：无任何命中

### 步骤三：将结果入库（仅 verdict=OK 或可接受 PARTIAL 时）

```bash
tshunter ingest \
  --from-relocate results/relocate_143.0.7499.192_from_169.json \
  --browser chrome --version 143.0.7499.192 \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db --upsert
```

### 步骤四：验证入库成功

```bash
tshunter query \
  --browser chrome --version 143.0.7499.192 \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db
```

### 步骤五（可选）：单指纹探针测试（不依赖 DB）

当你想单独验证某个指纹是否能在目标二进制中找到：

```bash
# 先取出源版本某个 hook 的指纹
sqlite3 data/fingerprints.db \
  "SELECT rva, fingerprint FROM hook_points hp \
   JOIN versions v ON v.id=hp.version_id \
   JOIN browsers b ON b.id=v.browser_id \
   WHERE b.name='chrome' AND v.version='143.0.7499.169' AND hp.kind='hkdf';"

# 用 probe 子命令探测
tshunter relocate -- probe \
  --binary binaries/Chrome/143.0.7499.192/chrome \
  --fingerprint "55 48 89 E5 41 57 41 56 ..." \
  --old-rva 0x048837E0 \
  --output results/probe_hkdf.json
```

### 当前数据库状态参考

```
版本                  platform  arch    verified  hook_points
143.0.7499.169        linux     x86_64  1         hkdf / key_expansion / prf / ssl_log_secret
```

`verified=1` 表示该版本是合法的 relocate source，`VersionConfigLoader` 会自动选取它。

---

## 5. Batch 测试准备

### 5.1 binaries-dir 结构要求

`batch` 扫描 `--binaries-dir` 下每个子目录，目录名即版本号，目录内必须有名为 `chrome` 的文件：

```
binaries/Chrome/
├── 143.0.7499.169/
│   └── chrome          ← 真实 ELF 或占位文件
├── 143.0.7499.192/
│   └── chrome
└── 149.0.7791.1/
    └── chrome
```

当前 `binaries/Chrome/` 已包含上述版本，可直接使用。

### 5.2 基本 batch 命令

```bash
# dry-run：只列版本计划，不写 DB
tshunter batch -- --browser chrome --binaries-dir binaries/Chrome --platform linux --arch x86_64 --dry-run

# 真实运行（DB hit → 跳过；DB miss → relocate JSON + 完整 Ghidra 入 DB）
# 日志自动写入 results/{timestamp}-batch.log
tshunter batch -- --browser chrome --binaries-dir binaries/Chrome --platform linux --arch x86_64 --db data/fingerprints.db

# 只处理指定 milestone（按 major 版本号过滤）
tshunter batch -- --browser chrome --binaries-dir binaries/Chrome --milestones 143 --platform linux --arch x86_64 --db data/fingerprints.db

# 用 --versions-file 指定版本列表（替代 --milestones）
tshunter batch -- --browser chrome --versions-file chrome_versions.txt --binaries-dir binaries/Chrome --platform linux --arch x86_64 --db data/fingerprints.db

# 从中断点续跑（使用上次输出的 run_id）
tshunter batch -- --resume 20260428-120000-abcd1234 --browser chrome --binaries-dir binaries/Chrome --platform linux --arch x86_64 --db data/fingerprints.db
```

### 5.3 查看 batch 任务状态

```bash
sqlite3 data/fingerprints.db \
  "SELECT run_id, version, status, method, error_msg \
   FROM batch_jobs ORDER BY id DESC LIMIT 20;"
```

method 字段说明：
- `db_hit`：直接命中数据库，秒级返回
- `relocate`：通过指纹重定位成功
- `analyze`：回退到完整 Ghidra 分析（耗时 ~17h）
- `dry_run`：dry-run 模式下的占位标记

### 5.4 用现有 binaries/ 做最小 batch 验证

以下测试序列验证 DB hit、relocate、dry-run 三条路径均正常：

```bash
# 1. dry-run 验证版本发现正常
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --platform linux --arch x86_64 \
  --dry-run

# 2. 实际运行（143.0.7499.169 应 db_hit，143.0.7499.192 应走 relocate）
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --milestones 143 \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db

# 3. 确认结果
sqlite3 data/fingerprints.db \
  "SELECT version, status, method FROM batch_jobs ORDER BY id DESC LIMIT 10;"
```

---

## 6. 运行测试套件

```bash
python3 -m pytest tests/ -q
```

测试文件说明：
- `tests/test_relocate.py`：relocate 核心逻辑单元测试（mock ELF，不需要真实二进制）
- `tests/test_batch.py`：batch 状态机测试（fixture DB + 空占位 chrome 文件）
- `tests/test_ingest_guards.py`：ingest 守卫（空 hook_points 拒绝等）
- `tests/test_config_loader.py`：VersionConfigLoader 三层加载
- `tests/test_cli.py`：CLI smoke tests（8 个子命令 `--help`）

Mock ELF 工具：

```bash
# 生成一个可被 pyelftools 解析的最小 ELF，用于本地 relocate 调试
python3 tests/fixtures/build_mock_elf.py
```

---

## 7. 监控长跑分析

```bash
bash monitor_analysis.sh
```

---

## 8. 关键文件索引

### 统一 CLI
- `tshunter/cli.py`：argparse dispatcher（主入口）
- `tshunter/analyze.py`：Ghidra 静态分析
- `tshunter/capture.py`：运行时抓包（委托 tls_capture/tls_capture.py）
- `tshunter/relocate.py`：指纹重定位（`scan` / `probe` 子命令）
- `tshunter/ingest.py`：入库（`--json` / `--from-relocate` / `--batch`）
- `tshunter/query.py`：查询工具
- `tshunter/batch.py`：批量分析调度（B1）
- `tshunter/config_loader.py`：VersionConfigLoader 三层合并加载器

### Java 分析逻辑
- `ghidra_scripts/TLShunterAnalyzer.java`：统一 analyzer 入口
- `ghidra_scripts/stacks/BoringSslAnalyzer.java`：BoringSSL hook 识别

### 数据
- `data/schema.sql`：数据库 schema
- `data/migrations/`：增量 schema 迁移（自动应用）
- `data/fingerprints.db`：当前指纹数据库
- `profiles/`：跨版本稳定的运行时模板

### 文档
- `docs/fingerprint_standard.md`
- `docs/hkdf_identification.md`
- `docs/relocation.md`

---

## 9. Download：批量下载 Chrome 二进制

> **环境前提**：激活 fritap venv 后运行 tshunter。
>
> ```bash
> source ~/fritap-env/bin/activate
> ```

快速示例：

```bash
# 列出 milestone 143 的所有历史 stable 版本
tshunter download -- --source cft-all --milestones 143 --list

# 按版本范围筛选并下载
tshunter download --source cft-all \
    --version-range 143.0.7499.0..143.0.7499.169 \
    --output-dir binaries/Chrome \
    --discard-zip

# 只下载几个离散版本
tshunter download --source cft-all \
    --versions 143.0.7499.42,143.0.7499.169 \
    --output-dir binaries/Chrome \
    --discard-zip
```


### 9.1 默认模式（每 milestone 最新一个版本）

```bash
# 下载 milestone 143 的最新版本（cft-latest，默认）
tshunter download -- \
  --milestones 143 \
  --output-dir binaries/Chrome

# 支持逗号列表与范围混合
tshunter download -- \
  --milestones 143-149 \
  --output-dir binaries/Chrome
```

输出示例：

```
[*] 输出目录: binaries/Chrome
[*] 目标 milestone: 143
[DOWN] milestone=143 version=143.0.7499.169
       url=https://storage.googleapis.com/.../chrome-linux64.zip
[OK] 143.0.7499.169 -> binaries/Chrome/143.0.7499.169/chrome
```

### 9.2 全量历史版本模式（cft-all）

CfT 的 `known-good-versions-with-downloads.json` 端点列出每个 milestone 所有历史 stable 版本（每 major 通常 30–80 条）。

```bash
# 下载 milestone 143 的所有历史 stable 版本（≥30 个小版本）
tshunter download -- \
  --source cft-all \
  --milestones 143 \
  --output-dir binaries/Chrome \
  --discard-zip

# 先列出有哪些版本，不实际下载
tshunter download -- \
  --source cft-all \
  --milestones 143 \
  --list
```

输出示例（`--list`）：

```
143    143.0.7499.1    https://storage.googleapis.com/.../chrome-linux64.zip
143    143.0.7499.10   https://...
...
143    143.0.7499.169  https://...
```

### 9.3 磁盘布局

下载后二进制布局与 `batch` 期望的结构完全一致：

```
binaries/Chrome/
├── 143.0.7499.169/
│   ├── chrome          ← ELF 可执行文件
│   └── metadata.json   ← 版本/SHA256/下载时间
├── 143.0.7499.170/
│   └── ...
└── 143.0.7499.192/
    └── ...
```

### 9.4 chrome_versions.txt — 版本清单文件

根目录的 `chrome_versions.txt` 可作为 `batch --versions-file` 的输入，每行一个完整版本号，`#` 开头为注释：

```
# 示例内容
143.0.7499.169
143.0.7499.192
```

配合 batch 使用：

```bash
tshunter batch \
  --browser chrome \
  --versions-file chrome_versions.txt \
  --binaries-dir binaries/Chrome \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db
```



### 9.5 `data/` 目录结构

```
data/
├── fingerprints.db          ← 主指纹数据库（SQLite，gitignore）
├── schema.sql               ← 数据库 schema 定义
├── migrations/              ← 增量 schema 迁移（自动应用）
│   ├── 001_relocate_fields.sql
│   ├── 002_batch_jobs.sql
│   ├── 003_three_layer.sql
│   ├── 004_batch_jobs.sql
│   ├── 005_partial_relocate.sql
│   └── 006_batch_metrics.sql
├── relocate/                ← batch 产生的 relocate 扫描 JSON（审查用）
│   ├── relocate_chrome_143.0.7499.192_from_143.0.7499.169.json
│   └── ...
└── .gitignore               ← 忽略 *.db 和 relocate/*.json
```

说明：
- `fingerprints.db` 是唯一数据源（SoT），只保存**完整 Ghidra 分析**的结果
- `relocate/` 下的 JSON 是 batch 自动产生的 relocate 扫描结果，用于人工审查，**不入库**
- 审查后如需入库，使用 `tshunter ingest --from-relocate data/relocate/xxx.json --upsert`

### 9.6 观察正在运行的 Batch

Batch 运行时会自动写日志到 `results/{timestamp}-batch.log`。用 `monitor_analysis.sh` 或 `tail -f` 观察：

```bash
# 方法 1：用 monitor_analysis.sh（自动发现 results/ 下最新的 .log）
bash monitor_analysis.sh

# 方法 2：直接 tail 最新 batch 日志
tail -f $(ls -1t results/*-batch.log | head -1)

# 方法 3：手动指定日志文件
bash monitor_analysis.sh /root/Palm/TLSHunter/results/20260502-154529-batch.log
```

### 9.7 检查 Batch 运行结果

#### 查看服务器上已完成的 batch 运行（`--db data/fingerprints.db`）

```bash
# 查看 batch_jobs 表中的所有 run
sqlite3 data/fingerprints.db "
SELECT run_id, COUNT(*) total,
       SUM(status='done') done,
       SUM(status='failed') failed,
       SUM(status='skipped') skipped,
       MIN(started_at), MAX(finished_at)
FROM batch_jobs
GROUP BY run_id
ORDER BY MAX(COALESCE(started_at, finished_at, '')) DESC
LIMIT 5;"

# 查看某个 RUN_ID 的进度和方法分布
RUN_ID='填这里'

sqlite3 data/fingerprints.db "
SELECT status, method, COUNT(*) count,
       ROUND(SUM(COALESCE(method_duration_sec,0))/60.0, 2) minutes
FROM batch_jobs
WHERE run_id='$RUN_ID'
GROUP BY status, method
ORDER BY status, method;"

# 查看每个版本的详情
sqlite3 data/fingerprints.db "
SELECT id, version, status, method, started_at, finished_at,
       method_duration_sec, relocate_max_outlier_delta, error_msg
FROM batch_jobs
WHERE run_id='$RUN_ID'
ORDER BY id DESC
LIMIT 30;"

# 查看失败项
sqlite3 data/fingerprints.db "
SELECT version, status, method, error_msg
FROM batch_jobs
WHERE run_id='$RUN_ID' AND status='failed'
ORDER BY id;"

# 查看 DB 中已入库的版本和 hook 数量
sqlite3 data/fingerprints.db "
SELECT b.name, v.version, v.platform, v.arch, v.verified,
       COUNT(hp.id) as hooks
FROM versions v
JOIN browsers b ON b.id = v.browser_id
LEFT JOIN hook_points hp ON hp.version_id = v.id
GROUP BY v.id
ORDER BY v.version;"

# 查看 relocate JSON 文件（batch 自动保存的审查文件）
ls -lh data/relocate/
```

#### 如果 batch 中断，用 `--resume` 继续

```bash
tshunter batch -- --resume "$RUN_ID" --browser chrome --binaries-dir binaries/Chrome --platform linux --arch x86_64 --db data/fingerprints.db --cleanup-binary
```

---

## 10. 部署与 Batch 运行完整流程

### 10.1 Docker 镜像构建

TLSHunter 使用 Docker 容器运行 Ghidra 静态分析。镜像需要在运行 batch 的机器上构建。

```bash
# 进入项目根目录
cd /home/palm/TLSHunter        # 本机
# cd /root/Palm/TLSHunter      # 服务器

# 构建镜像（首次或代码更新后必须执行）
docker build -t tlshunter:0.6.0 -f docker/Dockerfile .

# 验证镜像
docker images | grep tlshunter
# 预期输出: tlshunter   0.6.0   ...   ...
```

> **重要**：每次更新 `ghidra_scripts/` 下的 Java 文件后，必须重新构建镜像，否则容器内运行的仍是旧版分析脚本。

### 10.2 本机环境（指定版本 batch）

本机虚拟环境：`fritap-env`，只 batch 指定的两个版本。

```bash
# 激活虚拟环境
source ~/fritap-env/bin/activate

# 进入项目目录
cd /home/palm/TLSHunter

# 确认 Docker 镜像已构建
docker images | grep tlshunter:0.6.0

# 创建版本清单（只包含要分析的两个版本）
cat > chrome_versions_local.txt << 'EOF'
143.0.7499.192
143.0.7499.169
EOF

# dry-run 验证
tshunter batch -- --browser chrome --versions-file chrome_versions_local.txt --binaries-dir binaries/Chrome --platform linux --arch x86_64 --db data/fingerprints.db --dry-run

# 正式运行（前台，可观察 Ghidra 实时输出）
tshunter batch -- --browser chrome --versions-file chrome_versions_local.txt --binaries-dir binaries/Chrome --platform linux --arch x86_64 --db data/fingerprints.db --cleanup-binary

# 或后台运行
nohup bash run_batch.sh > logs/batch_$(date +%Y%m%d_%H%M%S).log 2>&1 &
```

### 10.3 服务器环境（全量 batch）

服务器虚拟环境：`palm`，全量 batch 所有已下载版本。

```bash
# 激活虚拟环境
source ~/palm/bin/activate

# 进入项目目录
cd /root/Palm/TLSHunter

# 确认 Docker 镜像已构建
docker images | grep tlshunter:0.6.0

# 停止旧容器（如果还在运行）
docker ps | grep tlshunter
# docker stop <旧容器名>

# dry-run 验证版本发现
tshunter batch -- --browser chrome --binaries-dir binaries/Chrome --platform linux --arch x86_64 --dry-run

# 正式运行（后台）
nohup bash run_batch.sh > logs/batch_$(date +%Y%m%d_%H%M%S).log 2>&1 &

# 观察 Ghidra 实时输出
tail -f $(ls -1t results/*-batch.log | head -1)

# 或用 monitor 脚本
bash monitor_analysis.sh
```

### 10.4 Batch 流程说明

每个版本的处理流程：

```
DB hit（已有 hook_points）→ 跳过，0.0s
     ↓ DB miss
Relocate scan → 写 JSON 到 data/relocate/（审查用，不入库）
     ↓
Full Ghidra 分析（~17h/个，Docker 容器内运行）
     ↓
Ingest 入 DB + 标记 verified=1
     ↓
后续同 milestone 版本可使用此版本作为 relocate baseline（分钟级）
```

**关键点**：
- 第一个版本需要完整 Ghidra 分析（~17h），完成后自动标记 `verified=1`
- 后续同 milestone 版本通过 relocate 定位（分钟级），大幅缩短总耗时
- Relocate 结果保存为 JSON 供审查，不直接入 DB
- 只有完整 Ghidra 分析的结果才写入 `fingerprints.db`

### 10.5 检查运行状态

```bash
# 查看最新 batch run 的汇总
sqlite3 data/fingerprints.db "
SELECT run_id, COUNT(*) total,
       SUM(status='done') done,
       SUM(status='failed') failed,
       SUM(status='skipped') skipped,
       MIN(started_at), MAX(finished_at)
FROM batch_jobs
GROUP BY run_id
ORDER BY MAX(COALESCE(started_at, finished_at, '')) DESC
LIMIT 5;"

# 查看某个 run 的详情
sqlite3 data/fingerprints.db "
SELECT id, version, status, method, method_duration_sec, error_msg
FROM batch_jobs WHERE run_id='YOUR_RUN_ID'
ORDER BY id;"

# 查看 DB 中已入库的版本和 hook 数量
sqlite3 data/fingerprints.db "
SELECT b.name, v.version, v.verified, COUNT(hp.id) as hooks
FROM versions v
JOIN browsers b ON b.id = v.browser_id
LEFT JOIN hook_points hp ON hp.version_id = v.id
GROUP BY v.id ORDER BY v.version;"
```
