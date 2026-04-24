# TSHunter 统一项目总体实施计划（TSHunter ⊕ p_t_c → Unified）

> 本文件将被 Claude Code 按顺序执行。分为三个连续 Part：
> - **Part 1（本文前半）**：Context · 用户决策 · 统一仓库布局 · Phase F1 / F2
> - **Part 2（本文中段）**：Phase U0 / U1 / U2 / U3 + VersionConfigLoader 细节
> - **Part 3（本文后段）**：Phase B1 / B2 / E1 / V1 + 验证策略 + 关键文件清单 + 论文映射 + 风险兜底

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

## Phase F1：修复 Ghidra XREF 构建 Bug（阻塞性前置）

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

## Phase F2：静默失败守卫

**前置**：F1 完成。**执行方**：Claude Code。

**改动**：
1. `tools/ingest.py`：`hook_points` 为空 → 退出码 2 + 诊断；写 `analyzer_runs.status` 字段（`SUCCESS | FAILED_EMPTY | FAILED_GHIDRA`）；新增 `--allow-empty` 仅调试用。
2. `tshunter.py capture`：`run_subprocess(analyze)` 后强校验 result JSON 的 `hook_points` 非空，空则 `raise SystemExit("[FATAL] analysis produced no hooks")`；`query_exact` 返回 0 行时不再印 "Analysis complete"，改抛异常。

**验收**：
- 新测试 `tests/test_ingest_guards.py::test_rejects_empty_hook_points` 通过
- 手工构造空 JSON 灌给 `tshunter ingest` → 退出码 2，analyzer_runs 留 `FAILED_EMPTY`

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

**目标**：让 `tshunter capture` 不再直接读 `hooks/*.json`，改为从 `data/fingerprints.db` 查 hook 数据；DB miss 时**自动内联 relocate**（D2 决策）；relocate 也失败才抛异常。

**新增文件 `tshunter/config_loader.py`**：

```python
class VersionNotInDB(Exception): ...
class RelocateFailed(Exception): ...

class VersionConfigLoader:
    def __init__(self, db_path="data/fingerprints.db",
                 allow_json_fallback=False,
                 auto_relocate=True):
        ...

    def load(self, browser, version, platform, arch, binary_path=None) -> dict:
        # Step 1: 精确命中
        row = self._query_db(browser, version, platform, arch)
        if row:
            return self._to_legacy_shape(row)

        # Step 2: auto-relocate（D2）
        if self.auto_relocate and binary_path:
            baseline_row = self._find_same_major_minor_baseline(browser, version, platform, arch)
            if baseline_row:
                try:
                    relocated = self._run_inline_relocate(binary_path, baseline_row)
                    self._ingest_relocated(relocated, browser, version, platform, arch,
                                          relocation_method='exact_scan',
                                          derived_from_version_id=baseline_row['id'])
                    return self._to_legacy_shape(self._query_db(browser, version, platform, arch))
                except Exception as e:
                    if self.allow_json_fallback:
                        pass  # 继续 Step 3
                    else:
                        raise RelocateFailed(str(e))

        # Step 3: JSON 回退（过渡期）
        if self.allow_json_fallback:
            return self._load_json_legacy(browser, version, platform, arch)

        raise VersionNotInDB(f"{browser} {version} {platform}/{arch}")
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
- `tests/test_config_loader.py` 覆盖：DB 命中 / DB miss 触发 relocate 成功 / relocate 失败抛 `RelocateFailed` / fallback 开关生效
- 删掉 `tests/golden/hooks/chrome_143.0.7499.169_linux_x86_64.json`（移到备份目录）后，`tshunter capture --auto` 仍成功（走 DB）
- `tshunter query --browser chrome --version 143.0.7499.169 --format frida` 输出与原 JSON 字段级 diff（key 可顺序不同）为空

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
3. 全部完成 → 打印 `tshunter query --report` 风格汇总

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

## Claude Code 顺序执行路径

```
F1 → F2 → [U0 用户手工] → U1 → U2 → U3 → B1(先 142+143) → B1(完整 135-149) → B2 → E1 → V1
```

每阶段结束提交独立 PR，附本 plan 对应章节链接 + 验收清单。

---

**END OF PLAN**