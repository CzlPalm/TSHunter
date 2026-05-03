
> **2026-04-24 修订**：结合 Cursor 的 P7-0 / P7-1 / P7-plan 三份文档和 Chrome 143.169 第二次长跑结果（F1 验证通过）重构。原 F1/F2 阶段已完成，进入 pre-merge 阶段。
>
> 本文件将被 Claude Code 按顺序执行。分为三个连续 Part：
> - **Part 1（本文前半）**：Context · 用户决策 · 长跑结果 vs ground truth · Cursor 互补要点 · 新增 S1 / S2 阶段
> - **Part 2（本文中段）**：Phase U0 / U1 / U2 / U3（带三层分离架构）+ VersionConfigLoader 细节
> - **Part 3（本文后段）**：Phase B1 / B2 / E1 / V1 + 验证策略 + 关键文件清单 + 论文映射 + 风险兜底

---
## 2026-04-28 状态更新（B1 启动前的硬化清单）

### Context

S1 / S2 / SC1 / U0–U3 的工程改造已经在 `claude/tls-key-fingerprint-db-mdMIO` 分支上完成（详见三个 audit 结论：CLI / batch.py / config_loader / migrations 001–004 / profiles / annotate_verified / fail-fast 全部 PRESENT）。用户已用 169 → 192 跑了第一次 relocate，verdict = **PARTIAL**，说明：
- relocate 主链路工程上能跑；
- 但 verdict 阈值在"正常 Chrome 周更级版本漂移"上偏严，B1 批量真跑后会把绝大多数 minor jump 都踢回 17h 完整分析，**B1 节省时长的核心价值会被吞掉**。

同时 audit 还暴露了三个非阻塞但 B1 启动前应该解决的问题：
- **Downloader 单源**：只用 CfT `latest-versions-per-milestone-with-downloads.json`，每个 major 只能拿一个版本，**根本下不到"143 之后多个连续小版本"**。
- **Chrome 二进制不自动清理**：500MB / 版本 × 50 版本 ≈ 25GB，服务器盘容易撑爆。
- **S1/S2 设计文档缺失**：`docs/consumption_audit.md` / `docs/unified_schema.md` 计划里有列、实际未产出（不影响代码运行，但论文 §3/§4 引用会找不到 anchor）。

本节给出 B1 启动前的硬化清单，按优先级排序。每一项都标了"是否阻塞 B1 启动"。

---

### H1【阻塞 B1】扩展 Downloader 版本源

**当前状态**：`tshunter/downloader.py` 仅支持 `--milestones` + CfT `latest-versions-per-milestone-with-downloads.json`，每 major 1 条。9 milestones 的 `chrome_versions.txt` 在 `runtime/` 下是历史文档不是输入清单。

**目标**：能下到 50+ 个连续 Chrome 版本作 B1 输入。

**改动**：

1. **新增 CfT 全量源**（最低成本、立即可用）：
   - 端点：`https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json`
   - 该端点列出 CfT **历史发布的所有 stable**（每 major 通常 30–80 条），不只是当前 latest
   - 在 `downloader.py` 增加 `--source` 参数：
     - `cft-latest`（默认，保持现状）
     - `cft-all`（新增，按 milestone 过滤后批量下）
     - `chromium-snapshots`（H1b，可选）
   - 对应新增函数：`_fetch_cft_known_good()` 解析全量 JSON，按 `--milestones 143-149` 过滤
   - 新 CLI：`tshunter download -- --source cft-all --milestones 143-149` → 应能下出 ≥ 30 条 Chrome 143–149 binaries

2. **【可选】Chromium 持续快照源**（H1b）：
   - 端点：`https://commondatastorage.googleapis.com/chromium-browser-snapshots/Linux_x64/<rev>/chrome-linux.zip`
   - LATEST_CHANGE 文件给出当前 trunk revision
   - 适用场景：论文需要"50–200 builds per minor"做 relocate 密度评估
   - **风险**：snapshot 是 dev build，并非 release build；指纹与 stable 有偏差
   - **建议**：B1 第一轮只用 CfT 全量；snapshot 留到 E1 论文数据采集阶段再加

3. **`runtime/chrome_versions.txt` 处理**：
   - 移到根目录 `chrome_versions.txt`（与 plan 主体描述一致）
   - 内容改为机读格式（每行一个版本号），作为 batch.py 的可选输入清单：`tshunter batch -- --versions-file chrome_versions.txt`
   - 当前 `--milestones` 参数继续保留

**关键文件**：
- `tshunter/downloader.py`（主改）
- `tshunter/batch.py`（增加 `--versions-file` / `--source` 透传）
- `chrome_versions.txt`（新建/移动）

**验收**：`tshunter download -- --source cft-all --milestones 143-149 --output-dir binaries/Chrome` 下出 ≥ 25 个不同版本的 chrome 可执行文件，磁盘布局保持 `binaries/Chrome/<version>/chrome`。

---

### H2【阻塞 B1】Relocate Verdict 软化 + B1 引入 PARTIAL 自动入库通道

**当前状态**：
- `tshunter/relocate.py::determine_verdict` 的 PARTIAL 条件：任一 hook miss、或全部命中但 deltas 超过 `max(median × 10%, 1024B)` 容差。
- `tshunter/config_loader.py::load` 看到非 OK → `raise RelocateFailed`，**没有任何 force/auto-ingest-partial 通道**。
- 169 → 192（仅 23 个 patch）就已经 PARTIAL，说明 Chrome 周更级 PGO 重排会让 4 个 hook 的 delta 不一致超过当前阈值。

**目标**：让 B1 在 PARTIAL 上有"可控可追溯的自动入库"路径，不一刀切回退完整分析；同时不污染高置信基线。

**改动（推荐组合：保守 verdict + B1 层 opt-in 接受）**：

1. **保留 `relocate.py` 的 verdict 逻辑不动**——它对外仍只产出 OK/PARTIAL/FAIL，论文 §3 引用稳定。

2. **`config_loader.py` 增加 `accept_partial` 行为**：
   - 新增 `__init__` 参数 `accept_partial: bool = False`、`partial_min_confidence: float = 0.8`
   - 在原来的 `if verdict != 'OK'` 分支前加判断：当 `verdict == 'PARTIAL'` 且 `accept_partial` 且每个 hook 的 `confidence ≥ partial_min_confidence` 且无 not_found → 走入库路径，但**写库时**：
     - `hook_points.relocation_method = 'exact_scan_partial'`（migration 005 给 CHECK 约束加这个枚举值）
     - `hook_points.relocation_confidence = min(per_hook_confidences)`
     - `versions.verified = 0`（永远不会被自动标 verified）
     - `versions.note` JSON 加 `{"partial_relocate": true, "median_delta": ..., "max_outlier_delta": ...}`
   - 关键文件：`tshunter/config_loader.py`、`data/migrations/005_partial_relocate.sql`

3. **`batch.py` 默认 `accept_partial=True`**（B1 场景）：
   - CLI 加 `--strict-relocate`（关掉 partial 接受，回到当前行为）
   - 默认行为：PARTIAL with confidence ≥ 0.8 → ingest as `exact_scan_partial`，写入 `batch_jobs.method = 'relocate_partial'`
   - **`tshunter capture` 默认仍 strict**——运行时不能消费 partial relocate 结果除非显式 `--allow-partial` 或经过 annotate_verified

4. **后处理：partial 结果的可信度回填**：
   - B1 跑完后，从 `versions WHERE note LIKE '%partial_relocate%'` 拉一个清单
   - 选 5–10 个抽样跑真实 Frida capture（用 `tools/annotate_verified.py`）
   - 命中率 ≥ 95% → 可以考虑下一轮把 `partial_min_confidence` 降到 0.7
   - 命中率 < 95% → 反向收紧 verdict 阈值，论文 §5 的 relocate_success_rate 用真实数据而非纸面

**关键文件**：
- `tshunter/config_loader.py`
- `tshunter/batch.py`
- `data/migrations/005_partial_relocate.sql`
- `tests/test_config_loader.py`（新增 partial 接受测试）

**验收**：
- `tshunter relocate -- scan --binary 192/chrome --source-version 143.0.7499.169` 输出 verdict 仍为 PARTIAL（行为不变）
- `python -c "from tshunter.config_loader import VersionConfigLoader; VersionConfigLoader(accept_partial=True).load('chrome', '143.0.7499.192', ...)"` 成功返回 config 而非 raise
- DB 中 `SELECT version, relocation_method, verified FROM versions JOIN hook_points ...` 看到 `192` 标 `exact_scan_partial` + `verified=0`
- `tshunter capture --auto` 在没有 `--allow-partial` 时拒绝消费 192（因为 verified=0 + partial）

---

### H3【非阻塞，建议 B1 之前做】磁盘清理 hook

**当前状态**：`batch.py` 用 `tempfile.TemporaryDirectory` 自动清 analyze 的临时目录，但**不清理 `binaries/Chrome/<version>/` 下的 chrome 可执行文件**。50 版本 × 500MB ≈ 25GB。

**改动**：
- `batch.py` 加 `--cleanup-binary` flag，默认 `False`
- 真值时：每个版本 ingest 完成后立即 `shutil.rmtree(binary_dir)`，但保留 `metadata.json`
- B1 服务器跑长批时建议开启；本地调试默认关闭以利于复跑

**关键文件**：`tshunter/batch.py`、`tests/test_batch.py`（cleanup 测试）

**验收**：dry-run + `--cleanup-binary` 跑 3 个版本，`du -sh binaries/Chrome/` 在最后一个版本完成后下降到 metadata-only（每版本 < 1KB）。

---

### H4【非阻塞，论文写作前必做】补 S1 / S2 文档

**当前状态**：plan 里 S1 / S2 列了 `docs/consumption_audit.md` / `docs/unified_schema.md` 作为产出，实际仓库里**没有**这两个文件。代码已经跑通三层架构，但设计文档缺位会导致后续 review / 论文 §3 / §4 找不到 anchor。

**改动**（不影响 B1 跑，但建议在 B1 启动后并行写）：
- `docs/consumption_audit.md`：从 `tshunter/capture.py` + `frida_scripts/chrome_hooks.js` + `tshunter/correlator.py` 反向 grep 字段消费清单，固化"哪些字段是 MUST / NICE / UNUSED"
- `docs/unified_schema.md`：从 `data/schema.sql` + 4 个 migrations + `profiles/boringssl_chrome.json` 合成统一 schema 规范，含字段语义、来源层（DB / profile / verified）、必填性
- `docs/migration.md`：U0 的 cherry-pick 路径，TSHunter ⊕ p_t_c → 当前布局的演变记录

**优先级**：B1 第一轮跑完后再写。论文 §3/§4 写作之前必须有。

---

### H5【非阻塞】B1 启动前的 dry-run 顺序

为避免 17h Ghidra 跑完发现配置错误，建议按以下顺序逐级放大：

1. **dry-run** 单纯打印计划：
   ```
   tshunter batch --browser chrome --milestones 143 --dry-run
   ```
   验证 `_enumerate_versions` 找出预期版本，`batch_jobs` 没有真插入。

2. **2 个版本试跑（已有基线 + 1 partial 邻居）**：
   ```
   tshunter batch --browser chrome --versions 143.0.7499.169,143.0.7499.192 --accept-partial
   ```
   预期：169 命中 DB 直接跳过（`db_hit`），192 走 partial relocate（`relocate_partial`），无 17h Ghidra。
   总耗时：< 5 min。

3. **跨 minor 拉一个真触发完整分析的样本**：
   ```
   tshunter batch --browser chrome --milestones 144 --accept-partial
   ```
   预期：144 找不到同 major.minor 基线 → 走完整 Ghidra → ~17h。完成后 144 的 `analysis.json` 字段完整，验证 SC1 闭环逻辑。

4. **B1 主战**：
   ```
   tshunter batch --browser chrome --milestones 143-149 --source cft-all \
     --accept-partial --cleanup-binary --workers 1
   ```
   预期：每个 milestone 第一个版本走完整分析（17h），后续同 milestone 内的 patch 走 relocate（< 1min/版本）。
   总耗时：~7 × 17h ≈ 5 天。

---

### H6【建议】B1 同步采集的论文级指标

B1 跑的过程中应直接把以下数据落到 DB 表，避免事后回算：

- `batch_jobs.method` 已有，覆盖 `db_hit / relocate / relocate_partial / analyze`
- `batch_jobs.method_duration_sec`（新增列）：单版本耗时
- `batch_jobs.relocate_max_outlier_delta`（新增列）：partial 时的最大异常 delta，用于事后校准 verdict 阈值
- `versions.binary_sha256` 已有，用于去重

**migration 006**：给 `batch_jobs` 加这两列。

E1 阶段直接 SQL 出图：
- relocate 成功率 vs. patch-version 距离（OK / partial / fail / analyze 比例随 delta 变化）
- 单 minor 内"首版完整分析 + 后续 relocate"的总耗时节省

---

### 增量执行顺序

```
H1（downloader 扩源）           ← 1 天，必做
   ↓
H2（PARTIAL 自动入库通道）       ← 1 天，必做
   ↓
H3（磁盘清理）                   ← 0.5 天，建议
   ↓
H5 dry-run + 2 版本试跑           ← 半小时
   ↓
H5 144 milestone 完整分析         ← ~17h
   ↓
B1 主战 143-149                   ← ~5 天
   ↓（并行）
H4 补 S1/S2 文档 + H6 metrics 采集
   ↓
E1 论文数据
```

---

---

---

## Context（为什么做这次整改）

**起因**：经过 P1–P6 的迭代，项目演化出两个独立仓库：

- **TSHunter**（`github.com/CzlPalm/TSHunter`，分支 `claude/tls-key-fingerprint-db-mdMIO`）—— Ghidra 静态分析器 + SQLite 指纹数据库。模块化 Java（`scripts/common/detect/stacks/`）+ Python CLI（`tshunter.py capture`, `run.py`, `tools/ingest.py`）。
- **p_t_c**（`github.com/CzlPalm/p_t_c`）—— Frida 运行时 TLS 密钥抓取 + eBPF 五元组关联。`tls_capture.py` + `lib/correlator.py` + `ebpf/fd_tracker.bpf.c`。**已自带 `tools/fingerprint_scan.py`（小版本偏移 ELF 扫描）+ `tools/merge_analysis.py`（auto JSON + baseline 合成）。**

**最近一次长跑回归**（Chrome 143.0.7499.169）失败：Ghidra 未建立 XREF，4 个 identifier 全部 0 hit，JSON 空集被 ingest 静默吞下。现在用户正在重跑（第二次尝试）。

**核心发现**：p_t_c 已经实现了 TSHunter Phase 4A 计划要做的 relocate 工具。**不应重复造轮子**。整合后 TSHunter 的 Phase 4A 不做，改用 p_t_c 的 `fingerprint_scan.py` 内联到 `capture` 子命令。

**预期产出**：单一 `tshunter-unified` 仓库，拥有统一 CLI（`tshunter {analyze, relocate, capture, ingest, query, batch, merge, download}`），SQLite 为唯一数据源（Single Source of Truth, SoT），Frida/eBPF 运行时走 DB 查询而非 JSON 文件。三条论文创新可写：(a) canonical fingerprint rule；(b) 版本索引指纹数据库；(c) 小版本偏移 relocate。

---

## 用户已定决策

| # | 决策点 | 用户选择 | 对实施的影响 |
|---|--------|---------|-------------|
| D1 | Git 合并策略 | **新建仓库 + cherry-pick 关键 commits** | Phase U0 交给用户手工完成；Claude Code 从已合并的仓库开始做 U1 |
| D2 | DB-miss 时 `tshunter capture` 行为 | **自动内联 relocate，成功则继续抓密钥** | Phase U2 的 `VersionConfigLoader` 要集成 relocate；失败时才抛异常 |

**其它默认值**（无需再确认）：
- 合并目标仓库名：`tshunter-unified`（由用户在 GitHub 新建）
- Python 包名：`tshunter`
- `hooks/*.json` 保留在 `tests/golden/` 作 DB 导出回归基准，不进主运行路径
- 批量分析调度：内置顺序循环 + SQLite `analyzer_runs` 状态表
- JSON fallback：临时 env `TSHUNTER_ALLOW_JSON_FALLBACK=1`，6 个月后移除

---

## 统一仓库最终布局

```
tshunter-unified/
├── tshunter/                       # Python 包
│   ├── __init__.py
│   ├── cli.py                      # argparse dispatcher（入口）
│   ├── analyze.py                  # 原 TSHunter run.py + tshunter.py 中 capture 的 DB-miss 分支
│   ├── capture.py                  # 原 p_t_c/tls_capture.py（重构为调用 VersionConfigLoader）
│   ├── relocate.py                 # 原 p_t_c/tools/fingerprint_scan.py（整体迁入）
│   ├── merge.py                    # 原 p_t_c/tools/merge_analysis.py（整体迁入）
│   ├── ingest.py                   # 原 TSHunter tools/ingest.py + fail-fast guard
│   ├── query.py                    # 原 TSHunter tools/query.py + --format frida 导出
│   ├── batch.py                    # 新：批处理驱动（B1）
│   ├── correlator.py               # 原 p_t_c/lib/correlator.py
│   ├── net_lookup.py               # 原 p_t_c/lib/net_lookup.py
│   ├── output_writer.py            # 原 p_t_c/lib/output_writer.py
│   ├── version_detect.py           # 原 p_t_c/lib/version_detect.py（薄化，委托给 config_loader）
│   ├── config_loader.py            # 新：VersionConfigLoader（U2 核心）
│   └── downloader.py               # 原 p_t_c/tools/chrome_downloader.py
├── ghidra_scripts/                 # 原 TSHunter/scripts/ 整体迁入
│   ├── TLShunterAnalyzer.java
│   ├── MinimalAnalysisOption.java  # ★ F1 要修
│   ├── custom_log4j.xml
│   ├── common/  detect/  stacks/   # 子目录保持原名
├── frida_scripts/                  # 原 p_t_c/hooks/*.js
├── ebpf/                           # 原 p_t_c/ebpf/（as-is）
├── data/
│   ├── schema.sql                  # 原 TSHunter/tools/schema.sql
│   ├── migrations/
│   └── fingerprints.db             # gitignore
├── docker/Dockerfile               # 仅 analyze 需要
├── tests/
│   ├── smoke_libssl/               # 原 TSHunter/smoke_test
│   ├── golden/                     # 原 p_t_c/hooks/*.json 作黄金样本
│   ├── test_config_loader.py
│   ├── test_relocate.py
│   └── test_ingest_guards.py
├── docs/
│   ├── paper_outline.md
│   ├── migration.md                # U0 cherry-pick 记录
│   └── fingerprint_standard.md
├── chrome_versions.txt
├── pyproject.toml
├── .github/workflows/weekly-chrome.yml  # V1
└── README.md
```

---

## Phase S1：p_t_c 消费端字段审计（新增，Cursor "先消费端后生产端"建议）

**前置**：F1/F2 已完成（本 plan 修订前提）。**执行方**：Claude Code。**耗时**：~1-2h。

**目标**：在动 TSHunter schema 之前，先明确 p_t_c 运行时实际消费哪些字段，反推出统一 schema 的最小必要集合。

**产出**：`docs/consumption_audit.md`，包含：

1. **p_t_c 浏览器识别入口的需求清单**
   - `lib/version_detect.py::detect_chrome_version()` 当前用什么字段来找对应 hook 配置
   - 期望的 key：`(browser, version, platform, arch)` 还是别的组合
2. **hooks JSON 的字段消费清单**（逐字段 grep）
   - 哪些字段被 `chrome_hooks.js` 用（Frida 注入层面）
   - 哪些字段被 `lib/correlator.py` 用（五元组关联）
   - 哪些字段被 `lib/output_writer.py` 用（keylog 生成）
   - 哪些字段**从未被运行时代码读过**（纯文档字段）
3. **数据库驱动化改造点**
   - 若让 `tls_capture.py` 改读 SQLite，需要暴露的 query 接口是什么
   - 哪些字段应该来自数据库 `hook_points` 表
   - 哪些字段应该来自 `profiles/` 模板
4. **最小必要字段清单**（`MUST HAVE`）
   - 每个 hook：`rva` / `fingerprint` / `read_on` / `params`
   - 每个版本：`tls13_label_map` / `struct_offsets` / `client_random.path`
5. **可选字段清单**（`NICE TO HAVE`）
   - `ghidra_name`、`boringssl_commit`、`verified_method` 等追溯字段

**验收**：
- `docs/consumption_audit.md` 存在
- 每个字段都标注 `[MUST/NICE/UNUSED] + [运行时/文档]`
- 给出"p_t_c 现状 → 数据库驱动化改造" 的最小 diff 预估

---

## Phase S2：统一 JSON Schema 定义（新增）

**前置**：S1 完成。**执行方**：Claude Code。**耗时**：~2-3h。

**目标**：产出一份**三方对齐**的统一 schema，覆盖自动分析输出、DB 存储、p_t_c 消费三种形态。

**产出**：`docs/unified_schema.md` + `data/schema.sql` 字段对齐。

### S2 的统一 Schema 设计（三层架构）

```
┌─────────────────────────────────────────────────────────────┐
│                  单个 Hook 点运行时加载路径                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ① 分析层（版本相关）          ② 运行时模板层（跨版本稳定）   │
│  ┌─────────────────┐         ┌──────────────────────────┐  │
│  │ hook_points 表   │         │ profiles/                │  │
│  │ ─ rva            │  +      │ ─ boringssl_chrome.json │  │
│  │ ─ fingerprint    │         │   · client_random path  │  │
│  │ ─ role           │         │   · tls13_label_map     │  │
│  │ ─ params         │         │   · struct_offsets      │  │
│  │ ─ read_on        │         │   · five_tuple_strategy │  │
│  │ ─ note           │         │                          │  │
│  └─────────────────┘         │ ─ nss_firefox.json (B2)  │  │
│           │                   │ ─ openssl_generic.json   │  │
│           ▼                   └──────────────────────────┘  │
│                                          │                  │
│           └─────────┐   ┌────────────────┘                  │
│                     ▼   ▼                                   │
│              ┌─────────────────┐                            │
│              │VersionConfigLoader│  ③ 验证层                │
│              │  merge → dict    │◄──(verified / p3_rate    │
│              └─────────────────┘    注入自独立 annotate     │
│                     │                  脚本)                │
│                     ▼                                       │
│              传给 p_t_c capture.py                          │
└─────────────────────────────────────────────────────────────┘
```

### 新增数据库字段

```sql
-- data/migrations/003_three_layer.sql

-- 版本指向运行时模板
ALTER TABLE versions ADD COLUMN profile_ref TEXT
    DEFAULT NULL;  -- e.g. 'boringssl_chrome' 指向 profiles/boringssl_chrome.json

-- hook_points 补语义字段
ALTER TABLE hook_points ADD COLUMN params_json TEXT
    DEFAULT NULL;  -- '{"ssl_ptr":"args[0] (RDI)", "output_buf":"args[1] (RSI)", ...}'
ALTER TABLE hook_points ADD COLUMN read_on TEXT
    DEFAULT 'onLeave';
ALTER TABLE hook_points ADD COLUMN output_len INTEGER DEFAULT NULL;

-- versions 补追溯字段
ALTER TABLE versions ADD COLUMN tls_lib_commit TEXT DEFAULT NULL;
ALTER TABLE versions ADD COLUMN ghidra_image_base TEXT DEFAULT NULL;
```

### `run.py` 输出改造（新 schema 对齐）

`run.py` 只需产出：

```json
{
  "meta": {
    "browser": "chrome",
    "version": "143.0.7499.169",
    "platform": "linux",
    "arch": "x86_64",
    "tls_lib": "boringssl",
    "analysis_tool": "TLShunter",
    "analyzer_version": "0.6.0-modular",
    "analysis_date": "2026-04-24T...",
    "binary_sha256": "...",
    "binary_size": 261831896,
    "ghidra_image_base": "0x00100000",   // ★ 新增，不再是 null
    "profile_ref": "boringssl_chrome"    // ★ 新增
  },
  "hook_points": {
    "hkdf": {
      "function_name": null,              // ★ 拆开：人类语义名（auto 阶段留 null）
      "ghidra_name": "FUN_049837e0",      // ★ 显式字段
      "rva": "0x048837E0",
      "fingerprint": "55 48 89 E5 ...",
      "fingerprint_len": 106,
      "role": "TLS 1.3 Derive-Secret",
      "note": "post-label CALL voting"
      // 注意：params / read_on / output_len 不在 run.py 输出里，来自 profile
    },
    ...
  }
}
```

### 与 ground truth 兼容性

Ground truth 的冗余字段归位：
- `client_random` / `tls13_key_len_offsets` / `tls13_label_map` / `struct_offsets` / `five_tuple_strategy` → **归入 `profiles/boringssl_chrome.json`**，全 Chrome/BoringSSL 共用
- `hook_points.*.params` / `read_on` / `output_len` → **归入 profile 的 `hook_template` 节**，仅手工维护
- `verified` / `verified_method` / `p3_capture_rate` → **独立 `tools/annotate_verified.py` 产出**，合并到 DB `versions` 表

### 产出的三个文件

1. `docs/unified_schema.md` —— 完整 schema 规范，含字段含义 / 必填 / 来源层次
2. `data/migrations/003_three_layer.sql` —— 数据库字段迁移
3. `profiles/boringssl_chrome.json` —— 第一个模板，从 ground truth JSON 的共用部分提炼

**验收**：
- `docs/unified_schema.md` 可被 Claude Code 或你在 review 时一眼看懂
- `sqlite3 data/fingerprints.db < data/migrations/003_three_layer.sql` 零错误
- `profiles/boringssl_chrome.json` 含 `client_random` / `tls13_key_len_offsets` / `tls13_label_map` / `struct_offsets` / `five_tuple_strategy` 五个块
- `run.py` 输出的新 143 分析结果带 `ghidra_image_base`、`profile_ref`、`ghidra_name`

---

## Phase F1：修复 Ghidra XREF 构建 Bug（阻塞性前置）[已完成]

> **状态**：✅ 2026-04-24 已验证通过。用户昨天的 bug fix + 今天完成的长跑 → 4 hook 的 RVA/fingerprint 与 ground truth 逐字节一致。保留此章节作审计记录。

**前置**：无（当前问题）。**执行方**：Claude Code（在原 TSHunter 仓库做完）。

**根因**：`MinimalAnalysisOption.java` 禁用了 `Scalar Operand References` / `Decompiler Switch Analysis` / `Basic Constant Reference Analyzer`，导致 Chrome 143（PIC，261MB）的 `LEA RAX, [RIP+off]` 字符串引用不被识别，ReferenceManager 空 → 4 个 identifier 全 0 hit。

**改动**：
1. `MinimalAnalysisOption.java`（在原 TSHunter 根目录 / 合并后的 `ghidra_scripts/`）删 3 行 `disableIfPresent`：
   - `SCALAR_OPERAND_ANALYZER`、`DECOMPILER_SWITCH_ANALYSIS`、`CONSTANT_PROPAGATION_ANALYSIS`
   - 保留：FUNCTION_ID / LIBRARY_IDENTIFICATION / DEMANGLER_MS / DEMANGLER_GNU / STACK / DWARF
2. `scripts/common/StringXrefUtil.java`：扩展 `findFunctionsUsingString(String)`，走 `Listing.getDefinedData(true)` + `"string"` 类型过滤作为防御性二次路径。
3. `scripts/stacks/BoringSslAnalyzer.java`：`identifyHKDF / analyzeSslLogSecret / identifyPRF / identifyKeyExpansion` 先调 `findFunctionsUsingString`，失败再落回 `findAllStringsInReadonlyData + refMgr`。

**验收**：
- 先跑 `smoke_test/libssl.so.3`（<2min）确认无回退
- 再跑 Chrome 143 全量（~20h，仅此一次）→ `grep -c "\[RESULT\]" results/analysis.log ≥ 4`
- 分析日志出现 `[*] HKDF: label="c hs traffic" LEA@... inside FUN_...`
- 4 条 hook 的 RVA/fingerprint 与 `p_t_c/hooks/chrome_143.0.7499.169_linux_x86_64.json` 逐字节匹配

---

## Phase F2：静默失败守卫 [已完成]

> **状态**：✅ 2026-04-24 已验证。`tools/ingest.py:252-256` + `tshunter.py:318-320` 的 FATAL 守卫都在 remote 上。保留审计记录。

<details>
<summary>F2 原任务书（存档）</summary>

**前置**：F1 完成。**执行方**：Claude Code。

**改动**：
1. `tools/ingest.py`：`hook_points` 为空 → 退出码 2 + 诊断；写 `analyzer_runs.status` 字段（`SUCCESS | FAILED_EMPTY | FAILED_GHIDRA`）；新增 `--allow-empty` 仅调试用。
2. `tshunter.py capture`：`run_subprocess(analyze)` 后强校验 result JSON 的 `hook_points` 非空，空则 `raise SystemExit("[FATAL] analysis produced no hooks")`；`query_exact` 返回 0 行时不再印 "Analysis complete"，改抛异常。

**验收**：
- 新测试 `tests/test_ingest_guards.py::test_rejects_empty_hook_points` 通过
- 手工构造空 JSON 灌给 `tshunter ingest` → 退出码 2，analyzer_runs 留 `FAILED_EMPTY`

</details>

---

## Phase SC1：TSHunter 单版本闭环验证（新增，Cursor P7-plan Phase 3）

**前置**：S2 schema 落地 + `run.py` 按新 schema 产出。**执行方**：Claude Code + 用户。

**目标**：在**原 TSHunter 仓库内**（U0 合并之前）把 Chrome 143 单版本端到端跑通：
`二进制 → run.py → DB → tshunter query --format frida → p_t_c tls_capture.py 真实 Hook → 抓 keylog → 对比 SSLKEYLOGFILE`

**子任务**：
1. 把 143 用新 schema 重跑一次 `run.py`（或直接重灌 DB，不需要再 17h）
2. `tshunter query --browser chrome --version 143.0.7499.169 --format frida > /tmp/hooks_143_from_db.json`
3. diff `/tmp/hooks_143_from_db.json` vs `hooks/chrome_143.0.7499.169_linux_x86_64.json`（ground truth）——字段级应该一致或是 superset
4. 把 `/tmp/hooks_143_from_db.json` 喂给 p_t_c 的 `tls_capture.py --config /tmp/hooks_143_from_db.json`
5. 启动 Chrome 143 + 打若干 HTTPS 流量
6. 对比 capture 输出和 `SSLKEYLOGFILE=` 基准

**验收**：
- p_t_c 能消费 TSHunter DB 导出的配置
- keylog 捕获率 ≥ P4 历史水平（96%）
- 五元组命中率保持 100%（P4 基线）

**意义**：这一步是**不做仓库合并前就证明两仓能闭环**的关键。通过了才值得做 U0/U1。

---

## Phase U0：新建统一仓库并 cherry-pick 关键 commits（用户手工完成）

**前置**：F1 + F2 完成并 merge 进 TSHunter 原仓库。**执行方**：**用户**（Claude Code 不做此步，因为 cherry-pick 需要人工判断、解决冲突、决定历史粒度）。

**Claude Code 会给出的辅助产物**（在 F2 PR 里附带）：

1. `docs/migration_cherry_pick_list.md` —— 建议保留的关键 commit 列表，分两份：
   - TSHunter 侧（从 `claude/tls-key-fingerprint-db-mdMIO` 分支）：阶段 A–D 各一个 squash commit + F1/F2 修复 commit，约 6–8 条
   - p_t_c 侧（从 `main`）：P1 逆向分析 / P3 Frida 集成 / P4 eBPF 五元组 / P5 自动化 / P6 ssl_log_secret / tools/fingerprint_scan.py 与 merge_analysis.py 的首次引入 commit，约 8–12 条
2. `docs/migration_fileplacement.md` —— 每个文件从旧路径搬到新路径的 map 表，含 `git mv` 命令串（让用户复制粘贴执行）
3. `README_MIGRATION.md` 草稿 —— 新仓库首屏 README，写明"本仓库由 TSHunter + p_t_c 合并而来，见 migration.md 追溯"

**用户操作步骤（参考，由用户自己在 shell 执行）**：
```bash
# 1. 在 GitHub 建新仓库 CzlPalm/tshunter-unified
# 2. 本地：
git init tshunter-unified && cd tshunter-unified
git remote add origin https://github.com/CzlPalm/tshunter-unified.git
git remote add tshunter ../TSHunter
git remote add ptc ../p_t_c
git fetch --all

# 3. 从 TSHunter 挑 commit
git cherry-pick <tshunter-commit-a> <tshunter-commit-b> ...
# 4. 从 p_t_c 挑 commit
git cherry-pick <ptc-commit-a> <ptc-commit-b> ...

# 5. 按 migration_fileplacement.md 的 git mv 把文件挪到新路径
# 6. 初始 push
git push -u origin main
```

**验收**：新仓库 `tshunter-unified` 可 clone，`git log --oneline | wc -l ≥ 15`（保留双方关键演进），`git log --graph` 图谱可读，**任何源代码文件尚未按新路径挪动**（挪动留给 U1）。

---

## Phase U1：结构性重构（新仓库内部）

**前置**：U0 完成，新仓库已建。**执行方**：Claude Code。

**目标**：按统一布局把所有文件搬到新路径，配置 Python 打包，确保 `pip install -e .` 可用。

**改动清单**（`git mv` 为主，不改代码逻辑）：

1. **Java 侧搬迁**：
   - `scripts/` → `ghidra_scripts/`（TSHunter 的所有 .java 文件 + 子目录）
   - 根目录 `MinimalAnalysisOption.java` → `ghidra_scripts/MinimalAnalysisOption.java`
   - `custom_log4j.xml` → `ghidra_scripts/custom_log4j.xml`

2. **Python 侧搬迁**：
   - `p_t_c/tls_capture.py` → `tshunter/capture.py`
   - `p_t_c/lib/correlator.py` → `tshunter/correlator.py`
   - `p_t_c/lib/net_lookup.py` → `tshunter/net_lookup.py`
   - `p_t_c/lib/output_writer.py` → `tshunter/output_writer.py`
   - `p_t_c/lib/version_detect.py` → `tshunter/version_detect.py`
   - `p_t_c/tools/chrome_downloader.py` → `tshunter/downloader.py`
   - `p_t_c/tools/fingerprint_scan.py` → `tshunter/relocate.py`
   - `p_t_c/tools/merge_analysis.py` → `tshunter/merge.py`
   - 原 TSHunter `tshunter.py`（顶层 CLI）→ 拆分：argparse dispatcher 放 `tshunter/cli.py`，capture 子命令逻辑放 `tshunter/capture.py` 新函数
   - 原 TSHunter `run.py` → `tshunter/analyze.py`
   - 原 TSHunter `tools/ingest.py` → `tshunter/ingest.py`
   - 原 TSHunter `tools/query.py` → `tshunter/query.py`

3. **数据/资源搬迁**：
   - `p_t_c/hooks/*.json` → `tests/golden/hooks/*.json`
   - `p_t_c/hooks/*.js` → `frida_scripts/`
   - `p_t_c/ebpf/` → `ebpf/`（整体）
   - 原 TSHunter `tools/schema.sql` → `data/schema.sql`
   - 原 TSHunter `smoke_test/` → `tests/smoke_libssl/`

4. **import 更新**：
   - 所有 `from lib.xxx import ...` → `from tshunter.xxx import ...`
   - `tls_capture.py` 内原读 `hooks/chrome_*.json` 的路径改为先走 `config_loader`（U2 做），本阶段只改 import 不改逻辑
   - relocate.py 内的 `REQUIRED_HOOKS` 常量保留

5. **打包文件**：
   - 新建 `pyproject.toml`：
     - `[project] name="tshunter"`, `requires-python=">=3.10"`
     - 依赖：`frida-tools>=12.0.0`, `pyelftools>=0.29`（relocate.py 原本手写 ELF 解析，保留不引入新依赖也可，但加 pyelftools 为未来 PE/Mach-O 扩展铺路）
     - `[project.scripts] tshunter = "tshunter.cli:main"`
   - `.gitignore`：`data/fingerprints.db`, `results/`, `__pycache__`, `*.pyc`, `.venv`, `artifacts/`

6. **Dockerfile 迁移**：`TSHunter/Dockerfile` → `docker/Dockerfile`，内部 `COPY scripts/` 改为 `COPY ghidra_scripts/`，`COPY tools/*.py` 改为 `COPY tshunter/*.py`。

**验收**：
- `pip install -e .` 在干净 venv 中成功
- `tshunter --help` 显示所有 8 个子命令（占位实现即可）
- `pytest tests/smoke_libssl/ -q` 通过既有 smoke 测试
- `docker build -f docker/Dockerfile -t tshunter:dev .` 成功

---

## Phase U2：DB 作 SoT，运行时迁移（VersionConfigLoader）

**前置**：U1 完成；Chrome 143.169 数据已在 DB 中（通过 `tshunter ingest --from-json tests/golden/hooks/` 一次性回填）。**执行方**：Claude Code。

**目标**：让 `tshunter capture` 不再直接读 `hooks/*.json`，改为"**三层 merge**"：① DB `hook_points` 行（版本相关 rva/fingerprint/role/ghidra_name/note）+ ② `profiles/<profile_ref>.json`（跨版本模板 params/read_on/struct_offsets/tls13_label_map/client_random.path/five_tuple_strategy）+ ③ DB `versions.verified` 列（验证层）→ 合成 p_t_c 期望的 legacy shape。DB miss 时**自动内联 relocate**（D2 决策）；relocate 失败才抛异常。

**新增文件 `tshunter/config_loader.py`**（三层合并版）：

```python
class VersionNotInDB(Exception): ...
class RelocateFailed(Exception): ...
class ProfileMissing(Exception): ...

class VersionConfigLoader:
    def __init__(self,
                 db_path="data/fingerprints.db",
                 profiles_dir="profiles",
                 allow_json_fallback=False,
                 auto_relocate=True):
        self.db_path = db_path
        self.profiles_dir = Path(profiles_dir)
        self.allow_json_fallback = allow_json_fallback
        self.auto_relocate = auto_relocate

    def load(self, browser, version, platform, arch, binary_path=None) -> dict:
        # ① 分析层
        row = self._query_db(browser, version, platform, arch)
        if not row:
            # DB miss → 尝试 relocate
            if self.auto_relocate and binary_path:
                baseline = self._find_same_major_minor_baseline(browser, version, platform, arch)
                if baseline:
                    try:
                        relocated = self._run_inline_relocate(binary_path, baseline)
                        self._ingest_relocated(relocated, browser, version, platform, arch,
                                               derived_from_version_id=baseline['id'])
                        row = self._query_db(browser, version, platform, arch)
                    except Exception as e:
                        if self.allow_json_fallback:
                            return self._load_json_legacy(...)
                        raise RelocateFailed(str(e))
            if not row:
                if self.allow_json_fallback:
                    return self._load_json_legacy(...)
                raise VersionNotInDB(f"{browser} {version} {platform}/{arch}")

        # ② 运行时模板层
        profile_ref = row['meta'].get('profile_ref') or self._infer_profile(row['meta']['tls_lib'])
        profile = self._load_profile(profile_ref)
        # 合并规则：hook_points.<kind> 优先用 DB 的 rva/fingerprint，
        #            params/read_on/output_len 从 profile 的 hook_templates.<kind> 继承
        merged_hooks = self._merge_hook_layer(row['hook_points'], profile['hook_templates'])

        # ③ 验证层
        verified_block = self._load_verified_block(row['meta'])

        # 合成 p_t_c legacy shape
        return {
            "meta": {**row['meta'], **verified_block},
            "hook_points": merged_hooks,
            "client_random": profile['client_random'],
            "tls13_key_len_offsets": profile['tls13_key_len_offsets'],
            "tls13_label_map": profile['tls13_label_map'],
            "struct_offsets": profile['struct_offsets'],
            "five_tuple_strategy": profile['five_tuple_strategy'],
        }

    def _infer_profile(self, tls_lib: str) -> str:
        # 按 tls_lib 默认 profile（boringssl → 'boringssl_chrome', nss → 'nss_firefox', ...）
        return {'boringssl': 'boringssl_chrome', 'nss': 'nss_firefox',
                'openssl': 'openssl_generic', 'rustls': 'rustls_generic'}[tls_lib]

    def _merge_hook_layer(self, db_rows, template_hooks):
        out = {}
        for kind, row in db_rows.items():
            base = template_hooks.get(kind, {})
            out[kind] = {
                **base,                          # params / read_on / output_len (模板)
                'rva': row['rva'],               # DB 覆盖
                'fingerprint': row['fingerprint'],
                'fingerprint_len': row['fingerprint_len'],
                'ghidra_name': row.get('function_name'),  # DB function_name 实为 Ghidra 名
                'function_name': base.get('function_name'),  # 模板提供的语义名
                'role': base.get('role') or row.get('role'),
                'note': row.get('note'),
            }
        return out
```

**新增文件 `tools/annotate_verified.py`**（验证层独立后处理脚本）：
```python
# 用法:
# python3 tools/annotate_verified.py \
#     --browser chrome --version 143.0.7499.169 --platform linux --arch x86_64 \
#     --verified-method 'SSLKEYLOGFILE diff + Wireshark decryption' \
#     --p3-capture-rate 0.96 --p4-tuple-hit-rate 1.0 \
#     --boringssl-commit 992dfa0b56f98b8decaf82cd8df44aa714675d99 \
#     --db data/fingerprints.db
# 直接更新 versions 表的 verified=1 + 配套字段，不碰 hook_points
```

**辅助方法**：
- `_query_db`：SELECT hook_points + versions JOIN，返回 dict
- `_to_legacy_shape`：把 DB rows 转成原 `version_detect.load_config()` 的字段结构（`{"hook_points": {"prf": {"rva": ..., "fingerprint": ...}, ...}, "tls13_label_map": ..., "struct_offsets": ...}`），调用方零感知
- `_find_same_major_minor_baseline`：查 DB 里同 browser + 同 `version LIKE '143.0.%'` + `verified=1` 的最新一条作 relocate 源
- `_run_inline_relocate`：import `tshunter.relocate`，复用 `scan_binary(Path, fingerprints)` 函数，不再新写
- `_ingest_relocated`：把 relocate 产物写入 DB（`hook_points.relocation_method='exact_scan'`，`derived_from_version_id`，`rva_delta`，`relocation_confidence`）

**Schema 扩展**（`data/migrations/001_relocate_fields.sql`）：

```sql
ALTER TABLE hook_points ADD COLUMN derived_from_version_id INTEGER
    REFERENCES versions(id);
ALTER TABLE hook_points ADD COLUMN rva_delta INTEGER DEFAULT NULL;
ALTER TABLE hook_points ADD COLUMN relocation_method TEXT
    DEFAULT 'ghidra_full'
    CHECK(relocation_method IN ('ghidra_full','exact_scan','manual','imported'));
ALTER TABLE hook_points ADD COLUMN relocation_confidence REAL DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_hook_derived_from ON hook_points(derived_from_version_id);
```

`tshunter/ingest.py` 首次启动时检查 `schema_migrations` 表，缺失就逐条 apply migrations/*.sql。

**修改 `tshunter/capture.py`**：
- 删除原 `from lib.version_detect import load_config`
- 改为 `from tshunter.config_loader import VersionConfigLoader, VersionNotInDB, RelocateFailed`
- 顶部实例化：`loader = VersionConfigLoader(auto_relocate=True, allow_json_fallback=os.getenv("TSHUNTER_ALLOW_JSON_FALLBACK") == "1")`
- 调用处：`config = loader.load(browser, version, platform, arch, binary_path=args.chrome_bin)`

**验收**：
- `tests/test_config_loader.py` 覆盖：DB 命中 / DB miss 触发 relocate 成功 / relocate 失败抛 `RelocateFailed` / fallback 开关生效 / **三层 merge 后字段完整**（params / client_random / tls13_label_map / verified 都齐全）
- 删掉 `tests/golden/hooks/chrome_143.0.7499.169_linux_x86_64.json`（移到备份目录）后，`tshunter capture --auto` 仍成功（走 DB + profile + verified 三层）
- `tshunter query --browser chrome --version 143.0.7499.169 --format frida` 输出与原 ground truth JSON **字段级 diff 为空**（key 可顺序不同），即能**完整重建**手工基线
- `profiles/boringssl_chrome.json` 的字段对同一 tls_lib 的所有 Chrome 版本通用，不要再跟版本耦合

---

## Phase U3：统一 CLI

**前置**：U2 完成。**执行方**：Claude Code。

**改动**：`tshunter/cli.py` 建立 argparse dispatcher：

```
tshunter analyze   --binary PATH --browser X --version Y --platform linux --arch x86_64
tshunter relocate  --binary PATH --source-version Y --db ... [--auto-ingest]
tshunter capture   --auto | --pid N [其他 p_t_c 原有 flag 保持]
tshunter ingest    --json PATH | --legacy DIR | --from-json DIR | --upsert
tshunter query     --browser X --version Y [--format frida | --report]
tshunter batch     --browser X --milestones 135-149 [--workers N --resume]
tshunter merge     --auto PATH --baseline PATH --version Y --out PATH
tshunter download  --milestones LIST [--out-dir PATH]
```

**删除**：根目录的 `run_binary_analysis.sh` / `run_chrome_analysis.sh` / `run.py` / `tshunter.py` / `tls_capture.py` 全部移除（功能已进 `tshunter.cli`）。Shell 用户改用 `tshunter <cmd>` 调用。

**验收**：
- 每个子命令 `--help` 成功输出
- `tshunter capture --auto` 对已运行 Chrome 抓出 keylog
- `tshunter analyze --binary <bin>` 走 Docker + Ghidra 链路
- `tshunter relocate --binary <new_chrome>` 产出 new RVAs

---

## Phase B1：批量分析模式

**前置**：U3 完成。**执行方**：Claude Code（先实现），用户（上服务器实跑）。

**新文件 `tshunter/batch.py` + Schema 扩展**：

```sql
-- data/migrations/002_batch_jobs.sql
CREATE TABLE IF NOT EXISTS batch_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','downloading','analyzing','ingesting','done','failed','skipped')),
    started_at TEXT, finished_at TEXT,
    error_msg TEXT,
    binary_sha256 TEXT,
    analyzer_runs_id INTEGER REFERENCES analyzer_runs(id)
);
CREATE INDEX IF NOT EXISTS idx_batch_run ON batch_jobs(run_id, status);
```

**CLI**：
```
tshunter batch --browser chrome --milestones 135-149 [--workers 1] [--resume RUN_ID] [--dry-run]
```

**流程**（`batch.py::run_batch()`）：
1. `run_id = timestamp-uuid`；`--resume` 走已有 run_id
2. 对每个 milestone：
   - 插 `batch_jobs` pending 行
   - **尝试 relocate**（利用 `VersionConfigLoader` 的内联能力）：如果同 major.minor 已有 verified 基线，先 relocate。成功则 status=`done`，跳过 Ghidra 17h。
   - relocate 失败 / 无基线 → 走 full analyze：`download → analyze → ingest`
   - 任一步骤失败 → status=`failed`，记 error_msg，继续下一版本
   - **入库时自动填 `versions.profile_ref`**（按 tls_lib 推断，`boringssl` → `boringssl_chrome`），`verified=0`
3. 全部完成 → 打印 `tshunter query --report` 风格汇总
4. **验证跟进**（B1 不强制，用户按需做）：对 relocate 命中的版本跑一次真实 Frida capture → 成功则 `tools/annotate_verified.py` 标 `verified=1`。未 verified 的版本在 E1 指标里单独列。

**验收**：
- 先 `--milestones 142-143` 跑通两版本（~34h）
- 中断后 `--resume <run_id>` 能从失败点继续
- `batch_jobs` 所有 row 最终状态为 `done` 或 `failed`
- `versions` 表每 milestone ≥ 1 条 `hook_points`

---

## Phase B2：Firefox / NSS 扩展

**前置**：B1 能稳定处理单浏览器。**执行方**：Claude Code（算法部分）+ 用户（Firefox 取样验证）。

**改动**：

1. **`ghidra_scripts/stacks/NssAnalyzer.java`**（从 stub 补齐）：
   - `detectConfidence`：检查 `.rodata` 中 `mozilla/nss` / `NSS_GetVersion` / `SSL_SecretCallback` / `ssl3_HandshakeCallback` / `tls13_DeriveSecret`
   - `analyze`：实现 4 个 identify：
     - `identifyNssKeylogCallback` → `SSL_SecretCallback` 路径
     - `identifySsl3Prf` → TLS 1.2 PRF on NSS
     - `identifyTls13DeriveSecret` → TLS 1.3 HKDF-Expand-Label（对应 chrome 的 hkdf）
     - `identifyKeyExpansion` → NSS 的 `ssl3_GenerateKeyBlock` 等价物
   - fingerprint 规则继续用 canonical rule（`common/FingerprintExtractor.java`）
2. **`tshunter/version_detect.py`**：加 `detect_firefox_version()` 分支（扫 `/usr/bin/firefox` / `/opt/firefox/firefox`，再去找 `libnss3.so` / `libssl3.so`）
3. **`tshunter/capture.py`**：`--browser firefox` 分支，Frida attach 的 module 从 chrome 换成 `libnss3.so`（实际需要枚举 Firefox process 的 loaded modules）
4. **`frida_scripts/firefox_hooks.js`**（新）：参考 `chrome_hooks.js` 结构，替换为 NSS 的 struct offsets 和参数约定
5. **`profiles/nss_firefox.json`**（新 profile，与 Chrome 同架构）：NSS 自己的 `client_random.path` / `tls13_label_map` / `struct_offsets` / `five_tuple_strategy` —— 手工提炼一次即可跨所有 Firefox 版本复用，这是三层架构的核心收益

**验收**：
- Firefox 125 ESR 下 `tshunter analyze --binary /opt/firefox/libnss3.so --browser firefox --version 125.0.0esr --tls-lib nss` 产出 4 个 hook
- `tshunter capture --auto --browser firefox` 抓出 keylog
- 与 Firefox 原生 `SSLKEYLOGFILE=` 机制的输出**逐行**一致（允许 CLIENT_RANDOM 顺序不同）

---

## Phase E1：论文数据自动采集

**前置**：B1 已入库 ≥ 10 个 Chrome 版本。**执行方**：Claude Code。

**新模块 `tshunter/metrics.py`**（或并入 `query.py`）：

```python
def stability_score(kind: str, browser: str, major_minor: str) -> float:
    """某个 hook 类型在同 major.minor 版本集合中，fingerprint 前 N 字节相同的比例。"""

def relocate_success_rate(browser: str, major_minor: str) -> dict:
    """relocation_method='exact_scan' 的条目在该 minor 下的占比 + 平均 delta + confidence 分布。"""

def version_coverage_matrix(browser: str) -> List[dict]:
    """每个版本的 4 hook 是否齐全，关联 capture_rate（若有 capture_sessions 数据）。"""

def friTap_comparison(browser: str) -> dict:
    """维护成本 vs friTap 的估算表：新增版本耗时 / 已支持版本数 / relocate 节省时长。"""
```

**CLI**：`tshunter report --paper --out docs/paper_data/`，一次性产出：
- `stability.csv` / `relocate.csv` / `coverage.csv` / `comparison.csv`
- `stability_plot.py`（matplotlib 脚本，手动补运行）

**验收**：
- 针对已入库的 Chrome 143.x 系列，CSV 数值与手工 SQL 核对一致
- `golden/` 下放 3 条合成 CSV 作回归黄金样本，`tests/test_metrics.py` 覆盖

---

## Phase V1：CI/CD 周期拉新

**前置**：B1 稳定。**执行方**：Claude Code。

**`.github/workflows/weekly-chrome.yml`**：

```yaml
on:
  schedule: [{cron: '0 6 * * MON'}]  # 每周一 06:00 UTC
  workflow_dispatch:
jobs:
  analyze:
    runs-on: self-hosted  # 因为要跑 Docker + Ghidra 17h，不能用 GitHub hosted
    steps:
      - checkout
      - 查询 Chrome Stable 最新版本（用 tshunter/downloader.py 内部的 release API）
      - 查 DB，如果已有该版本 → exit 0
      - tshunter batch --browser chrome --milestones <major>.<minor> --workers 1
      - 产出 docs/paper_data/*.csv 更新
      - gh pr create --draft（带新 fingerprint 差异摘要）
```

**验收**：连续 4 周自动化运行成功；relocate 命中率（E1 的 `relocate_success_rate`）≥ 70%。

---

## 端到端验证策略（避免每阶段都跑 17h）

| 阶段 | 验证方式 | 预期耗时 |
|------|---------|---------|
| F1 | 先 smoke libssl.so.3（<2min），通过后再跑 Chrome 143 全量（**唯一必须的 17h 投资**） | 17h 一次 |
| F2 | 人造空 JSON + `pytest tests/test_ingest_guards.py` | <1min |
| U0 | 用户手工；Claude Code 不验证 | — |
| U1 | `pip install -e .` + `pytest tests/smoke_libssl/` + `docker build` | <5min |
| U2 | 从 `tests/golden/hooks/` 灌库 → 删 JSON → `tshunter capture --auto` 对已运行 Chrome 成功 | ~5min |
| U3 | 黑盒 `tshunter <cmd> --help` + 端到端 capture（143 已在库） | ~10min |
| B1 | 先 142+143 跑通（≈34h），确认 resume → 再扩 135-149 | 首轮 34h |
| B2 | Firefox SSLKEYLOGFILE 对照组 | ~30min |
| E1 | 合成 DB + golden CSV 对比 | <5min |
| V1 | staging 仓库 dry-run 一次 workflow | ~1h |

**核心原则**：17h Ghidra 分析**只在 F1 验证、B1 首版本、新浏览器 B2 首版本**做。所有结构/接口性改动用已入库的 143 回放。

---

## 关键现有文件与工具（必须复用，不得重写）

| 现有文件 | 作用 | 合并后位置 | 复用方式 |
|---------|------|-----------|---------|
| `p_t_c/tools/fingerprint_scan.py` | ELF 解析 + 唯一字节匹配 relocate | `tshunter/relocate.py` | 算法整体保留，CLI 薄包装接入 `cli.py`，`scan_binary()` 被 `config_loader._run_inline_relocate` 复用 |
| `p_t_c/tools/merge_analysis.py` | auto JSON + baseline → 生产 hook JSON | `tshunter/merge.py` | 完整保留；`tshunter merge` 子命令直接暴露 |
| `p_t_c/lib/correlator.py` | eBPF fd-tracker 事件解析 + 五元组关联（P4 验证 100%） | `tshunter/correlator.py` | 不动 |
| `p_t_c/ebpf/fd_tracker.bpf.c` | eBPF tracepoint | `ebpf/fd_tracker.bpf.c` | 不动 |
| `p_t_c/hooks/chrome_hooks.js` | Frida hook 模板 | `frida_scripts/chrome_hooks.js` | 不动；`capture.py` 注入时用 `VersionConfigLoader` 提供的字段 |
| `TSHunter/scripts/common/FingerprintExtractor.java` | canonical 指纹规则 | `ghidra_scripts/common/FingerprintExtractor.java` | ⚠️ **冻结不改**，论文 §3 引用 |
| `TSHunter/scripts/stacks/BoringSslAnalyzer.java` | BoringSSL 4 hook 识别 | `ghidra_scripts/stacks/BoringSslAnalyzer.java` | F1 加 findFunctionsUsingString fallback；U1 不改 |
| `TSHunter/tools/schema.sql` | DB schema | `data/schema.sql` | U2 加 4 列 relocate 字段；B1 加 batch_jobs 表 |
| `TSHunter/Dockerfile` | Ghidra 12.0.3 + JDK 21 | `docker/Dockerfile` | U1 改 COPY 路径 |

---

## 论文章节映射

- **§3 Design**：
  - canonical fingerprint rule（`ghidra_scripts/common/FingerprintExtractor.java` 算法）
  - SQLite schema（`data/schema.sql`）+ relocation lineage 四字段
  - 三路径运行时状态机：DB hit → relocate hit → full analyze（`VersionConfigLoader.load()` 流程图）
- **§4 Implementation**：
  - Ghidra 模块化分析器（`TLShunterAnalyzer` 编排 + `stacks/*Analyzer` 插件）
  - Frida 运行时（`tshunter/capture.py` + `frida_scripts/chrome_hooks.js`）
  - eBPF 五元组关联（`ebpf/fd_tracker.bpf.c` + `tshunter/correlator.py`）
- **§5 Evaluation**：Phase E1 的 CSV 支撑：
  1. 版本覆盖（Chrome 135–149 × Firefox 125 ESR）
  2. Keylog 抓取成功率（同 P3/P4 方法）
  3. 5-tuple 关联命中率（目标维持 100%）
  4. Relocate 成功率（同 major.minor ≥ 70%）
  5. 与 friTap 在覆盖率 / 维护成本 / forensic metadata 三维度对比
- **§6 Deployment**：Phase V1 的 6 个月周运行数据（成功/失败 PR 计数、平均 relocate 耗时、DB 条目累积曲线）

---

## 风险与兜底

1. **F1 修复后 Chrome 143 仍返回 0 hooks**：回退到 Ghidra GUI 单步定位；确认是 xref / 标签检索 / FingerprintExtractor 哪一步断链。
2. **U2 迁移期间 DB schema 不够表达 JSON 字段**：`hook_points.params_json` / `versions.metadata` 预留 JSON 列兜底，避免频繁 migration。
3. **relocate 在 PIC 二进制误匹配**：沿用 `fingerprint_scan.py` 的唯一字节匹配约束；U2 内联 relocate 严格要求 `find_unique` 成功，非唯一就降级到 raise。
4. **批量模式磁盘占用**：Chrome 单版本解包 ~500MB，B1 必须 analyze 完自动清理解包目录，仅保留 DB 行（`batch.py` 负责）。
5. **Frida / Chrome 版本漂移**：capture 启动时校验 Frida 版本，DB 中记 `capture_sessions.frida_version` 便于论文数据追溯。

---

## Claude Code 顺序执行路径（2026-04-24 修订）

```
[F1/F2 已完成]
   ↓
S1 (p_t_c 消费端审计, ~1-2h)
   ↓
S2 (统一 schema + profile 模板第一版 + run.py 输出微调, ~2-3h)
   ↓
SC1 (原仓库内单版本闭环: 143 重灌 DB → p_t_c Frida 抓 keylog → 对齐 SSLKEYLOGFILE)
   ↓
─── 证明两仓能闭环后，才启动仓库合并 ───
   ↓
[U0 用户手工 cherry-pick 新仓库]
   ↓
U1 (结构性文件搬迁 + pyproject.toml)
   ↓
U2 (三层 VersionConfigLoader + annotate_verified)
   ↓
U3 (统一 CLI)
   ↓
B1(先 142+143 两版本试跑) → B1(完整 135-149 批量)
   ↓
B2 (Firefox/NSS 扩展 + profiles/nss_firefox.json)
   ↓
E1 (论文数据: stability_score / relocate_success_rate / profile_reuse_rate)
   ↓
V1 (CI/CD 周期拉新)
```

每阶段结束提交独立 PR，附本 plan 对应章节链接 + 验收清单。

---

## 相对原版 plan 的主要修订（diff summary）

| 变更 | 原版 | 修订版 | 原因 |
|---|---|---|---|
| F1/F2 状态 | pending | **完成** | 2026-04-24 长跑通过 |
| S1 / S2 | 无 | **新增** | Cursor 建议"先消费端后生产端" |
| SC1 | 无 | **新增** | Cursor 建议在 U0 合并前先证明两仓闭环 |
| U2 架构 | 单层 DB-as-SoT | **三层 merge**：DB + profile + verified | Cursor 建议分析/模板/验证分离 |
| `profiles/` 目录 | 无 | **新增** | 跨版本稳定字段（client_random path 等）抽离 |
| `tools/annotate_verified.py` | 无 | **新增** | 验证层独立，不污染 run.py |
| B1 入库动作 | 只 insert hook_points | **加 profile_ref 字段** | 配合三层架构 |
| E1 指标 | stability / relocate / coverage / comparison | **加 profile_reuse_rate** | 证明三层抽象的工程价值 |
| p_t_c 的 fingerprint_scan.py | 迁至 `tshunter/relocate.py` | **不迁入**（TSHunter 自有 fingerprint_relocate.py 更强） | 2026-04-24 发现 TSHunter 已有 349 行独立实现 |

---

**END OF PLAN**


## Q1：下载更多 Chrome 历史版本（特别是 143 之后的连续小版本）

**问题根因**：当前 [`tshunter/downloader.py`](https://github.com/CzlPalm/p_t_c/blob/claude/tls-key-fingerprint-db-mdMIO/tshunter/downloader.py) 只对接了 CfT 的 `latest-versions-per-milestone-with-downloads.json`，每个 major **只能拿 1 个** stable。所以即使你写 `--milestones 143-149`，也只下到 7 个版本，根本"连续"不起来。

**最低成本的扩源方案**（详见 plan H1）：

- 切到 CfT 的 `known-good-versions-with-downloads.json` 端点 → 列出**全部历史 stable**（每 major 通常 30–80 条）
- `downloader.py` 加 `--source` 参数：`cft-latest`（默认）/ `cft-all`（新）/ `chromium-snapshots`（可选）
- 配合 `--milestones 143-149` 过滤后批量下，应能拿到 ≥ 25 个 Chrome 143-149 版本
- Chromium 持续快照（每 major 100+ dev build）建议**留到 E1 论文阶段**再加，不要在 B1 就引入 dev/stable 混合的复杂度

这一步可以让 Claude Code 直接帮你改 `downloader.py`（150 行内的改动）。

## Q2：B1 启动前还有哪些问题？PARTIAL 怎么办？

**3 个真问题**（按阻塞程度）：

### 阻塞问题 1：PARTIAL 在 B1 里会被一刀切回退（H2，必修）

`config_loader.py` 看到非 OK 直接 `raise RelocateFailed`，**没有 partial 自动入库通道**。169→192 才 23 个 patch 就 PARTIAL，意味着 B1 跑起来后，**几乎所有 minor jump 都会触发 17h Ghidra**，relocate 节省时长的核心价值被吞掉。

**推荐方案**（保守 verdict + B1 层 opt-in 接受）：

- `relocate.py` 的 verdict 逻辑**不动**（论文 §3 的 anchor 稳定）
- `config_loader.py` 加 `accept_partial` 参数 + `partial_min_confidence=0.8` 门控
- PARTIAL 入库时强制：`relocation_method='exact_scan_partial'` + `verified=0` + `note` JSON 记 `median_delta` / `max_outlier_delta`
- `batch.py` 默认 `accept_partial=True`，`tshunter capture` 默认仍 strict（运行时不会消费未验证的 partial 结果）
- B1 跑完后抽样 5–10 个 partial 做真实 Frida 验证 → 用实证数据校准 verdict 阈值

这样 PARTIAL 既不污染高置信基线，又不阻塞批量。

### 阻塞问题 2：Downloader 单源（H1，同上）

### 非阻塞问题 3：磁盘不自动清理（H3，建议修）

50 版本 × 500MB ≈ 25GB。`batch.py` 加个 `--cleanup-binary` flag，ingest 完立刻 rmtree binary 目录、保留 metadata.json。

### 非阻塞问题 4（捎带）

- S1/S2 设计文档（[`docs/consumption_audit.md`](https://github.com/CzlPalm/p_t_c/blob/claude/tls-key-fingerprint-db-mdMIO/docs/consumption_audit.md) / [`docs/unified_schema.md`](https://github.com/CzlPalm/p_t_c/blob/claude/tls-key-fingerprint-db-mdMIO/docs/unified_schema.md)）plan 里列了，仓库里没有 → 论文写作前必补，不影响 B1 跑
- [`runtime/chrome_versions.txt`](https://github.com/CzlPalm/p_t_c/blob/claude/tls-key-fingerprint-db-mdMIO/runtime/chrome_versions.txt) 跟 plan 描述的根目录位置不一致 → 顺手挪一下

## Q3：其它建议

1. **B1 启动顺序请按 H5 渐进放大**，不要一上来就 `--milestones 143-149`：
    - dry-run → 2 版本（169 + 192）partial 验证 → 1 个跨 minor 完整分析（144，~17h）→ B1 主战 ~5 天
2. **B1 跑的过程中同步采集论文级指标**（H6，零成本）：
    - 给 `batch_jobs` 加 2 列：`method_duration_sec` + `relocate_max_outlier_delta`
    - E1 出图时直接 SQL 算"relocate 成功率随 patch 距离衰减"，不用事后捞 log
3. **anchor 策略**：每个新 milestone 第一个版本必须走完整 Ghidra（成为锚点 verified 基线），后续同 milestone patch 走 relocate。当前 DB 只有 169 一个 anchor，**无法跨 minor relocate**（config_loader 只在同 major.minor 里找基线）。
4. **PARTIAL 不要急着改 verdict 算法**——等 B1 第一轮跑完拿到真实 partial 命中率再说。当前 10% 容差是经验值，没数据支撑改不动。

---

## 下一步建议

你可以挑下面任一动作，我直接帮你做：

- **A**：让我去 TSHunter 仓库实现 H1（downloader 扩源）+ H2（PARTIAL 自动入库）+ H3（磁盘清理），三个一起开 PR
- **B**：只做 H1（先解决"下不到版本"的卡点），其余等你看完真跑数据再说
- **C**：不实现，只把 plan 翻成更详细的 task spec 喂给服务器侧的 Claude Code