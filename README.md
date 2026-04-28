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
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --platform linux \
  --arch x86_64 \
  --dry-run

# 真实运行（DB hit → relocate → 完整 Ghidra，按需自动回退）
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --platform linux \
  --arch x86_64 \
  --db data/fingerprints.db

# 只处理指定 milestone（按 major 版本号过滤）
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --milestones 143 \
  --platform linux --arch x86_64

# 从中断点续跑（使用上次输出的 run_id）
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --platform linux --arch x86_64 \
  --resume 20260428-120000-abcd1234
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
