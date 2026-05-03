# TSHunter Agent 自动化实现规划书（交给 Claude Code）

## 0. 背景与目标

当前 TSHunter 已基本实现 Chrome 批量分析能力，服务器 B1 批量任务仍在运行，结果未完全产出。本阶段目标不是立即实现完整“自动抓取 TLS 密钥”闭环，而是在 B1 结果出来之前，先完成 Agent 层的基础设施：

```text
浏览器版本源监听
    ↓
版本去重
    ↓
下载官方二进制 / 安装包
    ↓
解包并定位真实分析目标
    ↓
计算 sha256 / 记录元数据
    ↓
创建 agent_tasks
    ↓
等待 analyzer / verifier worker 后续消费
```

本规划要求支持：

- Chrome：优先使用 Chrome for Testing，即 CfT。
- Edge：使用 Microsoft Edge Linux 官方下载页 / packages.microsoft.com deb 仓库。
- Firefox：暂不进入 hook / NSS 分析阶段，但要预留 Firefox 数据源模块、下载源接口和任务类型。
- 后续可扩展 Electron / Chromium snapshots。

安全原则：

- 只面向授权环境、实验环境和取证环境。
- Agent 不做隐蔽采集。
- Agent 不自动 hook 用户浏览器。
- 未验证 hook 结果不能进入正式可用状态。
- keylog / pcap / verification report 属于敏感数据，后续必须做权限控制和清理机制。

---

## 1. 本阶段边界

### 1.1 现在要实现

本阶段实现 Agent 基础设施和数据源下载能力：

```text
A0-pre：B1 报告脚本骨架
A1：多浏览器数据源 Agent MVP
A2：任务编排层 / 状态机 / retry / resume
A3-pre：Analyzer Worker dry-run
```

### 1.2 现在不要实现

以下能力先保留接口，不做真实闭环：

```text
不自动 verified=1
不自动 hook 用户浏览器
不自动启动 Frida 捕获真实用户浏览器
不自动发布 fingerprint DB
不做 Firefox NSS hook 分析
不做前端 Capture 页面
不让 PARTIAL relocate 直接进入正式 hook_points
```

---

## 2. 目标架构

```text
数据源层
  - ChromeCfTSource
  - EdgeDebRepoSource
  - FirefoxReleaseSource, 暂时预留
        ↓
监听 / 采集 Agent 层
  - poll
  - download
  - unpack
  - checksum
        ↓
任务编排层
  - agent_tasks
  - retry / resume
  - 状态机
        ↓
TSHunter 分析层
  - dry-run first
  - later: relocate / full analyze / ingest
        ↓
验证层
  - later: SSLKEYLOGFILE baseline vs TSHunter keylog
        ↓
数据库层
  - source_artifacts
  - agent_tasks
  - hook_candidates
  - verification_runs
```

---

## 3. 目录结构要求

在现有项目中新增如下结构，尽量不破坏已有批量分析逻辑：

```text
tshunter/
  agent/
    __init__.py
    cli.py
    config.py
    logging.py

    db/
      __init__.py
      migrations.py
      task_store.py
      artifact_store.py

    sources/
      __init__.py
      base.py
      chrome_cft.py
      edge_repo.py
      firefox_release.py

    downloader/
      __init__.py
      http.py
      unpack.py
      checksum.py
      paths.py

    scheduler/
      __init__.py
      state_machine.py
      planner.py

    workers/
      __init__.py
      analyze_worker.py
      verify_worker.py

    reports/
      __init__.py
      b1_report.py

tests/
  test_agent_chrome_cft.py
  test_agent_edge_repo.py
  test_agent_firefox_release.py
  test_agent_task_store.py
  test_agent_state_machine.py
  test_agent_unpack.py
```

如果当前项目已有 CLI 框架，应将 `tshunter-agent` 作为子命令接入，而不是另起完全无关的入口。

---

## 4. 配置文件

新增配置文件示例：`configs/agent.yaml`

```yaml
agent:
  enabled: true
  poll_interval_minutes: 60
  download_dir: ./artifacts/downloads
  binary_dir: ./artifacts/binaries
  metadata_dir: ./artifacts/metadata
  max_parallel_downloads: 2
  max_retries: 3
  timeout_seconds: 1800

policy:
  auto_analyze: false
  auto_verify: false
  auto_publish: false
  require_explicit_capture: true
  allow_unverified_runtime_use: false

platform:
  os: linux
  arch: x86_64

sources:
  chrome_cft:
    enabled: true
    channels:
      - Stable
      - Beta
      - Dev
      - Canary
    platforms:
      - linux64
    known_good_url: https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json
    last_known_good_url: https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json

  edge:
    enabled: true
    channels:
      - stable
      - beta
      - dev
    platforms:
      - linux_amd64
    stable_pool_url: https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-stable/
    beta_pool_url: https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-beta/
    dev_pool_url: https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-dev/

  firefox:
    enabled: true
    planning_only: true
    channels:
      - release
      - beta
      - nightly
    platforms:
      - linux-x86_64
    product_details_url: https://product-details.mozilla.org/1.0/firefox_versions.json
    releases_url: https://ftp.mozilla.org/pub/firefox/releases/
```

注意：

- Firefox 本阶段只实现 source / metadata / download skeleton，不进入 NSS hook 分析。
- Edge 先以 stable 为主，beta/dev 可做接口，失败不阻塞 MVP。
- 所有 URL 必须可配置，不能硬编码散落在逻辑中。

---

## 5. 数据库 Migration

### 5.1 `source_artifacts`

用于记录下载源、包路径、真实二进制路径和 sha256。

```sql
CREATE TABLE IF NOT EXISTS source_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    channel TEXT,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,

    source TEXT NOT NULL,
    package_url TEXT,
    package_path TEXT,
    binary_path TEXT,
    binary_sha256 TEXT NOT NULL,
    version_output TEXT,

    source_metadata_json TEXT,
    downloaded_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT,

    UNIQUE(browser, version, channel, platform, arch, binary_sha256)
);

CREATE INDEX IF NOT EXISTS idx_source_artifacts_lookup
ON source_artifacts(browser, version, platform, arch);

CREATE INDEX IF NOT EXISTS idx_source_artifacts_sha256
ON source_artifacts(binary_sha256);
```

### 5.2 `agent_tasks`

用于任务编排、状态恢复和错误追踪。

```sql
CREATE TABLE IF NOT EXISTS agent_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT UNIQUE NOT NULL,

    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    channel TEXT,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,

    source TEXT,
    source_artifact_id INTEGER,
    binary_path TEXT,
    binary_sha256 TEXT,

    task_type TEXT NOT NULL DEFAULT 'analyze_candidate',
    status TEXT NOT NULL,
    priority INTEGER DEFAULT 100,

    created_at TEXT NOT NULL,
    started_at TEXT,
    updated_at TEXT,
    finished_at TEXT,

    error_stage TEXT,
    error_msg TEXT,
    retry_count INTEGER DEFAULT 0,

    FOREIGN KEY(source_artifact_id) REFERENCES source_artifacts(id)
);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_status
ON agent_tasks(status, priority, created_at);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_target
ON agent_tasks(browser, version, platform, arch);
```

### 5.3 `hook_candidates`

用于保存未验证 hook 候选结果。即使后续 analyzer worker 接入，也必须先写 candidates，不得直接污染正式 `hook_points`。

```sql
CREATE TABLE IF NOT EXISTS hook_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    task_id TEXT NOT NULL,
    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,

    kind TEXT NOT NULL,
    rva TEXT,
    fingerprint TEXT,
    fingerprint_len INTEGER,

    source_method TEXT NOT NULL,
    confidence REAL DEFAULT 0,
    status TEXT NOT NULL,

    created_at TEXT NOT NULL,
    updated_at TEXT,
    error_msg TEXT
);

CREATE INDEX IF NOT EXISTS idx_hook_candidates_target
ON hook_candidates(browser, version, platform, arch);

CREATE INDEX IF NOT EXISTS idx_hook_candidates_task
ON hook_candidates(task_id);
```

### 5.4 `verification_runs`

本阶段可建表，但 verify worker 只做 stub。

```sql
CREATE TABLE IF NOT EXISTS verification_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    version_id INTEGER,
    task_id TEXT,

    browser TEXT,
    version TEXT,
    platform TEXT,
    arch TEXT,

    started_at TEXT,
    finished_at TEXT,
    status TEXT,

    keylog_capture_rate REAL,
    client_random_match_rate REAL,
    five_tuple_hit_rate REAL,
    wireshark_decrypt_rate REAL,

    total_baseline_lines INTEGER,
    total_captured_lines INTEGER,

    error_msg TEXT,
    report_path TEXT,
    created_at TEXT NOT NULL
);
```

---

## 6. 状态机设计

### 6.1 状态集合

```python
TASK_STATES = {
    "pending",
    "downloading",
    "downloaded",
    "queued_analyze",
    "relocating",
    "analyzing",
    "ingesting",
    "queued_verify",
    "verifying",
    "verified",
    "failed",
    "needs_manual_review",
    "skipped",
}
```

### 6.2 合法状态流转

```text
pending
  -> downloading
  -> downloaded
  -> queued_analyze
  -> skipped
  -> failed

queued_analyze
  -> relocating
  -> analyzing
  -> ingesting
  -> queued_verify
  -> needs_manual_review
  -> failed

queued_verify
  -> verifying
  -> verified
  -> needs_manual_review
  -> failed
```

### 6.3 dry-run analyzer 决策

Analyzer worker 当前只做 dry-run 决策，不实际调用 Ghidra。

```text
如果 DB 已有 browser/version/platform/arch verified hook：
    task.status = skipped

如果已有 hook_candidates：
    task.status = queued_verify

如果同 browser + milestone 有 verified anchor：
    task.status = queued_analyze
    plan.next_action = relocate

否则：
    task.status = queued_analyze
    plan.next_action = full_analyze
```

所有决策写入日志，必要时写入 `source_metadata_json` 或独立 report 文件。

---

## 7. 数据源实现要求

### 7.1 Source 接口

实现统一抽象类：`BrowserSource`

```python
from dataclasses import dataclass
from typing import Iterable, Optional, Mapping, Any

@dataclass(frozen=True)
class BrowserArtifact:
    browser: str
    version: str
    channel: str
    platform: str
    arch: str
    source: str
    package_url: str
    package_type: str
    expected_binary_relpath: Optional[str]
    metadata: Mapping[str, Any]

class BrowserSource:
    name: str

    def poll(self) -> Iterable[BrowserArtifact]:
        raise NotImplementedError

    def normalize_platform(self, raw_platform: str) -> tuple[str, str]:
        raise NotImplementedError
```

---

## 8. Chrome CfT 数据源

### 8.1 目标

实现 `ChromeCfTSource`。

### 8.2 输入

- `known-good-versions-with-downloads.json`
- `last-known-good-versions-with-downloads.json`

### 8.3 行为

```text
1. 请求 CfT JSON
2. 解析 versions 数组
3. 提取 downloads.chrome 中 platform == linux64 的项
4. 构造 BrowserArtifact
5. 对比 source_artifacts / agent_tasks 去重
6. 下载 zip
7. 解包 chrome-linux64/chrome
8. 执行 chrome --version 记录 version_output
9. 计算 sha256
10. 写 source_artifacts
11. 创建 agent_tasks
```

### 8.4 Chrome 解包路径

Linux CfT zip 解包后真实目标通常为：

```text
chrome-linux64/chrome
```

不要把 zip 或 wrapper 当作 Ghidra 分析目标。

### 8.5 Chrome task 字段

```json
{
  "browser": "chrome",
  "version": "147.0.xxxx.xx",
  "channel": "stable",
  "platform": "linux",
  "arch": "x86_64",
  "source": "chrome-for-testing",
  "task_type": "analyze_candidate",
  "status": "downloaded"
}
```

---

## 9. Edge 数据源

### 9.1 目标

实现 `EdgeDebRepoSource`。

Edge 当前先支持 Linux amd64 deb 包，优先 stable channel。

### 9.2 数据源

配置项中使用：

```text
https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-stable/
https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-beta/
https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-dev/
```

### 9.3 行为

```text
1. 请求 pool index HTML
2. 解析 microsoft-edge-stable_<version>-1_amd64.deb
3. 提取 version
4. 构造 BrowserArtifact
5. 下载 deb
6. 解包 deb
7. 定位真实二进制
8. 执行 --version 记录 version_output
9. 计算 sha256
10. 写 source_artifacts
11. 创建 agent_tasks
```

### 9.4 Edge 解包路径

deb 解包后优先查找：

```text
/opt/microsoft/msedge/microsoft-edge
/opt/microsoft/msedge/msedge
/usr/bin/microsoft-edge
```

实际 Ghidra 分析目标应优先选择 `/opt/microsoft/msedge/msedge` 或真实 ELF，而不是 `/usr/bin/microsoft-edge` shell wrapper。

实现时必须：

```text
file <candidate>
readelf -h <candidate>
```

确认是 ELF 后才能写 `binary_path`。

### 9.5 Edge 和 Chrome 的关系

Edge 基于 Chromium / BoringSSL，但不能直接假设 Chrome RVA 可复用。实现策略：

```text
Edge artifact 可下载、可入 task
Edge analyzer worker 暂时 dry-run
Edge hook_candidates 不能从 Chrome 自动复制
后续需要 Edge 自己的 verified anchor
```

---

## 10. Firefox 数据源预留

### 10.1 目标

本阶段不做 Firefox hook 分析，但要实现 source skeleton，方便后续接 NSS。

### 10.2 数据源

优先预留：

```text
https://product-details.mozilla.org/1.0/firefox_versions.json
https://ftp.mozilla.org/pub/firefox/releases/
```

### 10.3 行为

MVP 阶段可以只做：

```text
1. 拉取 firefox_versions.json
2. 记录 latest release / beta / nightly metadata
3. 构造 Firefox BrowserArtifact
4. 可选下载 linux-x86_64 tar.xz
5. 解包后定位：
   firefox/firefox
   firefox/libnss3.so
   firefox/libssl3.so
6. 写 source_artifacts
7. 创建 agent_tasks，但 task_type = firefox_planning_only
8. analyze_worker 对 Firefox 默认 skipped 或 needs_manual_review
```

### 10.4 Firefox 不允许做的事

```text
不接入 Chrome/BoringSSL analyzer
不生成 BoringSSL hook_candidates
不 verified=1
不自动运行 firefox_hooks.js
```

---

## 11. Downloader / Unpack 要求

### 11.1 下载器

实现：

```python
download_file(url, dest, *, retries=3, timeout=1800) -> DownloadResult
```

要求：

- 支持临时 `.partial` 文件。
- 下载完成后原子 rename。
- 支持断点续传可选，不强制。
- 记录 HTTP status、content-length、elapsed。
- 失败时保留错误，不写 artifact。

### 11.2 解包器

支持：

```text
.zip      Chrome CfT
.deb      Edge
.tar.xz   Firefox
.tar.bz2  Firefox 可选
```

实现函数：

```python
unpack_archive(package_path, dest_dir) -> UnpackResult
find_real_binary(unpacked_dir, browser) -> Path
```

### 11.3 ELF 校验

对 Linux 分析目标必须检查：

```text
文件存在
可执行
不是 shell script wrapper
readelf -h 成功
ELF class 与 arch 匹配
```

---

## 12. CLI 命令设计

### 12.1 总入口

```bash
tshunter-agent --config configs/agent.yaml <command>
```

### 12.2 数据源命令

```bash
tshunter-agent source poll --browser chrome
tshunter-agent source poll --browser edge
tshunter-agent source poll --browser firefox
tshunter-agent source poll --all

tshunter-agent source download --browser chrome --version <version>
tshunter-agent source download --browser edge --version <version>
tshunter-agent source download --browser firefox --version <version>
```

### 12.3 任务命令

```bash
tshunter-agent task list
tshunter-agent task show <task_id>
tshunter-agent task retry <task_id>
tshunter-agent task reset <task_id> --status pending
```

### 12.4 Worker 命令

```bash
tshunter-agent worker analyze --dry-run
tshunter-agent worker analyze --once --dry-run
tshunter-agent worker verify --stub
```

### 12.5 报告命令

```bash
tshunter-agent report b1 --db tshunter.db --out reports/B1_report.md
```

---

## 13. B1 报告脚本

实现 `reports/b1_report.py`。

输出文件：

```text
reports/B1_report.md
reports/hook_coverage.csv
reports/failed_versions.csv
reports/relocate_success.csv
reports/verification_summary.csv
```

报告至少包含：

```text
版本总数
入库成功率
每版本 hook 数
4 hook 齐全率
relocate OK / PARTIAL / FAIL 统计
full analyze 失败率
verification 成功率，如果已有
失败阶段分布
needs_manual_review 列表
```

如果现有 DB schema 和新 schema 不完全匹配，报告脚本必须 graceful degradation：缺少表时给出“未发现该表”，不能崩溃。

---

## 14. 实现阶段拆分

### Phase 1：基础骨架

交付：

```text
agent 目录
config loader
logging
CLI skeleton
migrations
task_store
artifact_store
```

验收：

```bash
tshunter-agent --help
tshunter-agent db migrate
tshunter-agent task list
```
结果：
```
Phase 1 完成。所有 44 个已有测试通过，新增的 agent 基础设施已就绪。           
                                                                                
  已交付：                                                                      
                                                                                
  ┌──────────┬───────────────────────────────────────────────────────────────┐  
  │   模块   │                             文件                              │  
  ├──────────┼───────────────────────────────────────────────────────────────┤  
  │ 目录结构 │ tshunter/agent/ + 6 个子包 (db, sources, downloader,          │  
  │          │ scheduler, workers, reports)                                  │  
  ├──────────┼───────────────────────────────────────────────────────────────┤  
  │ 迁移     │ data/migrations/007_agent_tables.sql — source_artifacts,      │
  │          │ agent_tasks, hook_candidates, verification_runs               │  
  ├──────────┼───────────────────────────────────────────────────────────────┤
  │ 配置     │ tshunter/agent/config.py + configs/agent.yaml                 │  
  ├──────────┼───────────────────────────────────────────────────────────────┤  
  │ 日志     │ tshunter/agent/logging.py — 结构化日志、StageTimer            │
  ├──────────┼───────────────────────────────────────────────────────────────┤  
  │ 数据层   │ tshunter/agent/db/artifact_store.py (CRUD) + task_store.py    │
  │          │ (CRUD + 状态机)                                               │  
  ├──────────┼───────────────────────────────────────────────────────────────┤
  │ CLI      │ tshunter/agent/cli.py — db/source/task/worker/report          │  
  │          │ 子命令，已集成到 tshunter agent                               │  
  └──────────┴───────────────────────────────────────────────────────────────┘
  
```

### Phase 2：Chrome CfT

交付：

```text
ChromeCfTSource
zip downloader
Chrome unpack
sha256
source_artifacts upsert
agent_tasks create
```

验收：

```bash
tshunter-agent source poll --browser chrome
tshunter-agent source download --browser chrome --version <known-version>
tshunter-agent task list
```
结果：
```
新建文件：                                                                    
  - tshunter/agent/downloader/checksum.py — sha256_file (1MB chunked)           
  - tshunter/agent/downloader/http.py — download_file (partial .part file,
  atomic rename, exponential backoff retries)                                   
  - tshunter/agent/downloader/unpack.py — unpack_archive, find_real_binary
  (well-known paths + fallback search)                                          
  - tshunter/agent/sources/base.py — BrowserSource ABC + BrowserArtifact      
  dataclass                                                                     
  - tshunter/agent/sources/chrome_cft.py — ChromeCfTSource (poll known-good API,
   download/unpack/checksum)                                                    
  - tshunter/agent/sources/__init__.py — exports                                
                                                                                
  修改文件：                                                                    
  - tshunter/agent/cli.py — _poll_chrome_cft 实现（poll → upsert artifact →     
  create task），_cmd_source_download 实现（find version → download → upsert）  
                                                                                
  验证结果：                                                                    
  - 44 个既有测试全部通过                                                       
  - source poll --browser chrome 成功发现 2224 个版本，创建 2224 条 artifact +  
  task                                                                          
  - 幂等性验证：第二次 poll 发现 0 条新记录                                     
  - DB status 显示 source_artifacts: 2224, agent_tasks: 2224 (all pending)
```

### Phase 3：Edge

交付：

```text
EdgeDebRepoSource
HTML index parser
deb downloader
deb unpack
real ELF locator
source_artifacts upsert
agent_tasks create
```

验收：

```bash
tshunter-agent source poll --browser edge
tshunter-agent source download --browser edge --version <known-version>
file artifacts/binaries/edge/<version>/msedge
readelf -h artifacts/binaries/edge/<version>/msedge
```
```
新建文件：                                                                    
  - tshunter/agent/sources/edge.py — EdgeDebRepoSource（解析 HTML 目录列表，提取
   .deb 文件名和版本，下载 .deb，dpkg-deb 解压 msedge 二进制）                  
                                                                                
  修改文件：                                                                    
  - tshunter/agent/downloader/unpack.py — 新增 unpack_deb() 函数（dpkg-deb -x   
  提取），find_real_binary() 增加 archive_type 参数区分 zip/deb 路径表          
  - tshunter/agent/sources/__init__.py — 导出 EdgeDebRepoSource                 
  - tshunter/agent/cli.py — _poll_edge 实现（poll → upsert → create             
  task），_cmd_source_download 重构为通用分发（支持 chrome + edge）             
                                                                                
  验证结果：                                                                    
  - 44 个既有测试全部通过                                                       
  - source poll --browser edge 成功发现 447 个版本（stable 161 + beta 168 + dev
  118）                                                                         
  - 幂等性验证：第二次 poll 发现 0 条新记录                                     
  - DB 总计：source_artifacts 2671, agent_tasks 2671 (all pending)
```

### Phase 4：Firefox skeleton

交付：

```text
FirefoxReleaseSource
product-details metadata parser
release URL builder
tar.xz unpack optional
firefox/libnss3.so/libssl3.so locator
planning_only task
```

验收：

```bash
tshunter-agent source poll --browser firefox
tshunter-agent source download --browser firefox --version <known-version>
tshunter-agent task list
```

```
新建文件: tshunter/agent/sources/firefox.py                                   
  - FirefoxReleaseSource — 通过 product-details.mozilla.org API 发现 Firefox    
  版本                                                                          
  - _CHANNEL_MAP: FIREFOX_RELEASE→release, FIREFOX_BETA→beta,                 
  FIREFOX_NIGHTLY→nightly, FIREFOX_ESR→release                                  
  - _build_download_url() 构造 ftp.mozilla.org 下载链接 (.tar.bz2)              
  - _unpack_tarball() 使用 Python tarfile 提取，定位 firefox/firefox 二进制     
                                                                                
  修改文件:                                                                     
  - tshunter/agent/sources/__init__.py — 导出 FirefoxReleaseSource              
  - tshunter/agent/cli.py — _poll_firefox 从 stub 改为完整实现（poll → dedup →  
  upsert → create task），source_map 增加 firefox 下载支持                      
                                                                                
  验证结果:                                                                     
  - 44 个测试全部通过                                                           
  - Firefox poll 发现 3 个版本（140.10.1esr release, 151.0b5 beta, 152.0a1      
  nightly）                                                                     
  - 幂等确认：第二次 poll 发现 0 个新版本                                       
  - 数据库总计：2674 artifacts, 2674 pending tasks
```

### Phase 5：任务编排和 dry-run worker

交付：

```text
state_machine
planner
analyze_worker --dry-run
retry / resume
错误分类
```

验收：

```bash
tshunter-agent worker analyze --once --dry-run
tshunter-agent task show <task_id>
```
结果：
```
新建文件:                                   
  - tshunter/agent/workers/download.py — DownloadWorker：完整的下载             
  worker，claim pending → 下载二进制 → 更新 DB → 转换到 downloaded              
  - tshunter/agent/workers/analyze.py — AnalyzeWorker：dry-run 骨架，检查
  relocate baseline（通过 browsers FK 查询 verified 版本），记录分析计划，转换到
   needs_manual_review                                                          
  - tshunter/agent/workers/verify.py — VerifyWorker：dry-run                    
  骨架，检查分析结果是否存在，记录验证计划，转换到 needs_manual_review          
  - tshunter/agent/workers/__init__.py — 导出三个 worker 类                     
                                                                                
  修改文件:                                                                     
  - tshunter/agent/cli.py — 新增 worker download 子命令，worker analyze 和      
  worker verify 从 stub 改为真实实现                                            
                                                                                
  状态机修复:                                                                   
  - 分析 worker 遵循正确路径：downloaded → queued_analyze → analyzing（而非直接 
  downloaded → analyzing）                                                     
  - 查询 versions 表时使用 browsers FK join（v.browser_id = b.id）而非不存在的  
  v.browser 列                                                                
                                                                                
  验证结果:
  - 44 个测试全部通过                                                           
  - worker download --once — 成功下载 Chrome 113.0.5672.0，状态 → downloaded    
  - worker analyze --dry-run --once — 找到 relocate baseline（chrome            
  143.0.7499.169, 4 hooks），状态 → needs_manual_review                         
  - worker verify --once — 检测到无分析结果，状态 → needs_manual_review         
  - 数据库：2674 tasks，2673 pending + 1 needs_manual_review
```

### Phase 6：B1 report

交付：

```text
B1_report.md
hook_coverage.csv
failed_versions.csv
relocate_success.csv
verification_summary.csv
```

验收：

```bash
tshunter-agent report b1 --db tshunter.db --out reports/B1_report.md
```
结果：
```
新建文件:                   
  - tshunter/agent/reports/b1_report.py — 完整的 B1 报告生成器，包含：
    - 14 个 SQL 查询函数（安全处理缺失表）                                      
    - 4 个 CSV 写入函数                   
    - Markdown 报告渲染（summary + hook coverage + failed + relocate + analyzer 
  + verification + manual review）                                              
    - 4 项指标的 pass/fail 判定（ingestion >= 95%, 4-hook >= 95%, analyze       
  failure <= 5%, verification >= 95%）                                          
  - tshunter/agent/reports/__init__.py — 导出 generate_b1_report                
                                                                
  修改文件:                                                                     
  - tshunter/agent/cli.py — _cmd_report_b1 从 stub 改为真实实现，输出指标摘要   
                                                                                
  验证结果:                                                                     
  - 44 个测试全部通过                                                           
  - report b1 生成 5 个文件：B1_report.md + 4 个 CSV                            
  - 当前数据：2 个版本（均有 4 hooks），2675 个 source artifacts，ingestion     
  0.1%（FAIL — 符合预期，agent 层只做了发现，未做全量分析）                     
  - Relocate 统计：ghidra_full 50%, exact_scan_partial 50%                      
  - Analyzer: 2 个 SUCCESS，0 失败                                              
  - 1 个任务需要 manual review（Chrome 113.0.5672.0）
```

---

## 15. 代码质量要求

### 15.1 幂等性

以下命令重复运行不能重复创建无意义记录：

```bash
tshunter-agent source poll --browser chrome
tshunter-agent source poll --browser edge
tshunter-agent source poll --browser firefox
```

去重键：

```text
browser + version + channel + platform + arch + binary_sha256
```

如果 binary_sha256 未知，下载前去重使用：

```text
browser + version + channel + platform + arch + source + package_url
```

### 15.2 错误记录

所有失败必须记录：

```text
error_stage
error_msg
retry_count
updated_at
```

错误阶段枚举：

```text
poll
download
unpack
binary_locate
checksum
version_probe
db_write
task_create
planner
analyze
verify
```

### 15.3 日志

日志至少包含：

```text
task_id
browser
version
channel
platform
arch
stage
elapsed
result
```

### 15.4 测试

最低测试要求：

```text
Chrome CfT JSON 解析测试
Edge repo index HTML 解析测试
Firefox versions JSON 解析测试
zip/deb/tar 解包路径测试
state transition 测试
artifact upsert 幂等测试
task create 幂等测试
```

---

## 16. Claude Code 实施提示

请按以下顺序执行，不要跳步：

```text
1. 先阅读现有项目 CLI / DB / migrations / batch 代码
2. 找到现有 DB 连接方式，复用，不要另造 DB 层
3. 新增 migrations
4. 新增 agent package
5. 先实现 task_store / artifact_store
6. 再实现 BrowserSource 抽象类
7. 再实现 ChromeCfTSource
8. 再实现 EdgeDebRepoSource
9. 再实现 FirefoxReleaseSource skeleton
10. 最后接 CLI
11. 写测试
12. 跑 lint / pytest
```

关键约束：

```text
不要改动现有 analyzer 核心逻辑
不要让 Agent 直接调用 Frida
不要让 Agent 自动 hook 用户浏览器
不要把未验证结果写成 verified
不要将 Chrome hook 结果直接套到 Edge
不要将 BoringSSL 分析逻辑套到 Firefox/NSS
```

---

## 17. 最小验收清单

完成后必须能做到：

```bash
# 初始化
tshunter-agent db migrate

# Chrome
tshunter-agent source poll --browser chrome
tshunter-agent source download --browser chrome --version <version>

# Edge
tshunter-agent source poll --browser edge
tshunter-agent source download --browser edge --version <version>

# Firefox skeleton
tshunter-agent source poll --browser firefox

# 任务
tshunter-agent task list
tshunter-agent worker analyze --once --dry-run

# 报告
tshunter-agent report b1 --db tshunter.db --out reports/B1_report.md
```

数据库中应能看到：

```text
source_artifacts 有 chrome / edge / firefox planning 记录
agent_tasks 有对应任务
重复 poll 不重复创建任务
download 失败有 error_stage / error_msg
analyze dry-run 不调用 Ghidra
所有自动产生结果默认 verified=0
```

---

## 18. 后续 B1 出结果后的接入策略

如果 B1 结果满足：

```text
版本入库成功率 >= 95%
4 hook 齐全率 >= 95%
full analyze 失败率 <= 5%
验证样本成功率 >= 95%
```

则下一步接入：

```text
analyze_worker real mode
    ↓
relocate 优先
    ↓
full Ghidra analyze fallback
    ↓
hook_candidates
    ↓
verify_worker
    ↓
verified hook_points
```

如果 B1 不满足：

```text
Agent 保持 poll / download / task_create
暂停 auto analyze
先修 downloader / relocate / analyzer / batch resume / verification probe
```

---

## 19. 最终交付物

Claude Code 完成后应提交：

```text
新增 agent 代码
新增 migrations
新增 config
新增 tests
新增 docs/agent_automation.md
新增 reports/B1_report.md 生成器
README 中加入 tshunter-agent 用法
```
