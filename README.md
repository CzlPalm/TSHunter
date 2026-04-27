# TLShunter 项目使用说明

`TLShunter` 是一个面向 TLS 关键函数定位的分析工程，核心目标是：

1. 对目标二进制做静态分析，识别 TLS 关键 hook 点
2. 输出稳定的 `RVA + fingerprint`
3. 将分析结果写入 SQLite 指纹数据库
4. 在相邻小版本之间优先使用指纹重定位，减少重复长跑分析

当前重点支持 BoringSSL 场景，主要识别以下 4 类 hook 点：

- `HKDF`：TLS 1.3 Derive-Secret
- `SSL_LOG_SECRET`：BoringSSL keylog 输出函数
- `PRF`：TLS 1.2 master secret 派生
- `KEY_EXPANSION`：TLS 1.2 key block 派生

---

## 1. 项目能力概览

当前项目包含 3 条主要能力链路：

### 1.1 完整静态分析链路
输入一个目标二进制，调用 Docker 中的 Ghidra headless 分析环境，运行 `TLShunterAnalyzer`，输出 JSON 结果。

适用于：
- 首次分析未知版本
- relocate 失败后的兜底路径
- 构建新的基线版本

### 1.2 指纹数据库链路
将静态分析得到的 hook 点入库到 SQLite，用于后续：
- 精确版本查询
- 前缀指纹查询
- 同 major.minor 版本查找 relocation source

### 1.3 Fingerprint Relocation 链路
当目标版本未命中数据库，但同 `browser + major.minor + platform + arch` 下已有 verified source 时，优先用 source 的函数指纹在新版本 `.text` 段中扫描定位。

适用于：
- Chrome 小版本漂移
- 避免重复 17h+ 的完整静态分析

---

## 2. 环境依赖

### 2.1 系统依赖
- Docker
- Python 3.10+
- SQLite3

### 2.2 安装

```bash
# 推荐：在虚拟环境中以 editable 模式安装
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

安装后可用统一入口：

```bash
tshunter --help
```

### 2.3 分析环境
Ghidra 12.0.3 和 JDK 21 已通过 Dockerfile 内置，无需单独本机安装。

---

## 3. 常见入口

### 3.1 静态分析

```bash
tshunter analyze \
  --binary /path/to/target_binary \
  --output /path/to/result.json \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --tls-lib boringssl
```

适合：
- 直接验证 analyzer 结果
- 生成单个 JSON
- 和历史 ground truth 做 compare

---

## 4. 数据库工作流

### 4.1 初始化数据库

数据库 schema 与 migrations 会在第一次 `tshunter ingest` 时自动应用。也可手动初始化：

```bash
sqlite3 data/fingerprints.db < data/schema.sql
```

---

### 4.2 将分析结果入库

```bash
tshunter ingest \
  --json results/chrome_143.0.7499.169_linux_x86_64.json \
  --db data/fingerprints.db
```

如果 JSON 缺少 `browser/version/platform/arch`，可通过 CLI 补充：

```bash
tshunter ingest \
  --json results/chrome_143.0.7499.169_linux_x86_64.json \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --db data/fingerprints.db
```

注意：
- 默认拒绝空 `hook_points` 入库
- 如确实需要，可显式加 `--allow-empty`

---

### 4.3 查询数据库

#### 精确版本查询

```bash
tshunter query \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --db data/fingerprints.db
```

#### 输出 Frida 风格 hooks JSON

```bash
tshunter query \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --format frida \
  --db data/fingerprints.db
```

#### 按 major.minor 查版本

```bash
tshunter query \
  --browser chrome \
  --major-minor 143.0 \
  --db data/fingerprints.db
```

#### 按指纹前 20B 查询

```bash
tshunter query \
  --fingerprint "55 48 89 E5 41 57 41 56 ..." \
  --db data/fingerprints.db
```

---

## 5. 统一 CLI：`tshunter`

`tshunter` 是当前项目的统一工作流入口，负责：
- DB hit 直接返回 hooks
- DB miss 后先尝试 relocate
- relocate 失败再回退完整分析
- 必要时自动入库

### 5.1 `capture`

```bash
tshunter capture \
  --chrome-bin /path/to/chrome \
  --tshunter-browser chrome \
  --tshunter-platform linux \
  --tshunter-arch x86_64
```

行为：
1. 通过 `VersionConfigLoader` 三层合并加载 hook 配置（DB + profiles + verified）
2. DB 命中则秒级返回 hooks
3. DB miss 时自动内联 relocate（同 major.minor 已有 verified 基线）
4. relocate 成功则自动入库并返回 hooks
5. 否则抛出异常（或设 `TSHUNTER_ALLOW_JSON_FALLBACK=1` 降级到旧 JSON）

---

### 5.2 `relocate`

```bash
tshunter relocate \
  --binary /path/to/chrome_143.0.7499.192 \
  --browser chrome \
  --version 143.0.7499.192 \
  --platform linux \
  --arch x86_64 \
  --source-version 143.0.7499.169 \
  --db data/fingerprints.db \
  --output results/relocate_192.json
```

加上 `--auto-ingest` 则在 verdict=`OK` 时自动入库。

---

### 5.3 `batch`（B1 批量分析模式）

```bash
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --platform linux \
  --arch x86_64
```

对 `binaries-dir` 下每个版本子目录：
1. 优先查 DB（秒级命中）
2. DB miss → 自动尝试同 major.minor relocate
3. 仍 miss → 调用完整 Ghidra 分析（`tshunter analyze`）

常用开关：
- `--dry-run`：只列版本计划，不写 DB
- `--resume RUN_ID`：从中断点续跑
- `--milestones 142,143`：按 milestone 下载并分析

---

## 6. Fingerprint Relocation

详细说明见：`docs/relocation.md`

当前实现支持：
- ELF
- PE

当前未实现：
- Mach-O

判定结果：
- `OK`
- `PARTIAL`
- `FAIL`

选择规则：
1. 前 20B 扫描所有命中
2. 前 40B 扩展校验
3. 优先扩展匹配更多者
4. 同级时优先离旧 RVA 最近者

---

## 7. 监控长跑分析

```bash
bash monitor_analysis.sh
```

周期性显示当前 Docker 容器、资源占用、磁盘使用、最新日志尾部。

---

## 8. 测试

```bash
python3 -m pytest tests/ -q
```

当前覆盖：
- `tests/test_cli.py`：CLI smoke tests（8 个子命令 `--help`、batch 行为、robustness）
- `tests/test_relocate.py`：relocate 单元测试
- `tests/test_ingest_guards.py`：ingest 守卫测试
- `tests/test_config_loader.py`：VersionConfigLoader 三层加载测试
- `tests/test_batch.py`：B1 批量分析状态机测试

---

## 9. 关键文件说明

### 统一 CLI
- `tshunter/cli.py`：argparse dispatcher（主入口 `tshunter <cmd>`）
- `tshunter/analyze.py`：Ghidra 静态分析
- `tshunter/capture.py`：Frida 运行时抓包（委托 tls_capture/tls_capture.py）
- `tshunter/relocate.py`：指纹重定位
- `tshunter/ingest.py`：入库工具
- `tshunter/query.py`：查询工具
- `tshunter/batch.py`：批量分析调度（B1）
- `tshunter/config_loader.py`：VersionConfigLoader 三层合并加载器
- `tshunter/downloader.py`：Chrome for Testing 下载工具
- `tshunter/merge.py`：auto JSON + baseline 合成
- `monitor_analysis.sh`：长跑分析监控脚本

### Java 分析逻辑
- `ghidra_scripts/TLShunterAnalyzer.java`：统一 analyzer 入口
- `ghidra_scripts/detect/TlsStackDetector.java`：TLS 栈识别
- `ghidra_scripts/stacks/BoringSslAnalyzer.java`：BoringSSL 关键 hook 识别
- `ghidra_scripts/common/StringXrefUtil.java`：字符串定位与 XREF 收集
- `ghidra_scripts/common/FingerprintExtractor.java`：函数指纹提取
- `ghidra_scripts/common/ResultEmitter.java`：输出 `[RESULT]`

### 数据与工具
- `data/schema.sql`：数据库 schema
- `data/migrations/`：增量 schema 迁移（自动应用）
- `profiles/`：跨版本稳定的运行时模板（boringssl_chrome.json 等）

### 文档
- `docs/fingerprint_standard.md`
- `docs/hkdf_identification.md`
- `docs/relocation.md`

---

## 10. 推荐工作顺序

### 首次分析某版本
1. `tshunter analyze --binary <bin> --output results/X.json ...`
2. 检查结果 JSON
3. `tshunter ingest --json results/X.json --db data/fingerprints.db`
4. 标记 verified 版本

### 相邻小版本分析
1. `tshunter batch --browser chrome --binaries-dir binaries/Chrome`
2. 优先命中 DB 或 relocate，全自动无需干预
3. 如果某版本 failed，查看 batch_jobs.error_msg 再决定是否补跑完整分析

### 长跑回归（全量 Ghidra）
1. `tshunter analyze --binary <bin> ... &`（后台运行）
2. `bash monitor_analysis.sh` 监控
3. 完成后 `tshunter ingest --json results/X.json --upsert`
