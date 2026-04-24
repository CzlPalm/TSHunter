# P6 Phase 2（修订版）：整合分析工具 + 多版本指纹数据库构建

**起始条件**: Phase 1 ✅ + Step 1 ✅（chrome_downloader.py 已完成，130/140/142/143/149 已下载）  
**核心变更**: 不走手动分析路线，先整合 TLSKeyHunter + BoringSecretHunter 为统一自动化分析工具，修复 PRF 识别，再批量产出  
**预计周期**: 3-4 周  

---

## 一、修订后的整体流程

```
Step A: 整合分析工具 + 修复 PRF (1-1.5 周)
  A.1  分析 TLSKeyHunter/BSH 源码结构，确定整合方案
  A.2  实现整合：单次 Ghidra 预处理，一次性提取 HKDF + ssl_log_secret + PRF
  A.3  修复 PRF 识别（.rodata 回退 + 子串处理）
  A.4  补充手动分析步骤的自动化（key_expansion、client_random 路径、结构体偏移）
    ↓
Step B: 用 143.x ground truth 回归验证 (2-3d)
  B.1  对 143.0.7499.169 运行整合工具
  B.2  将输出与现有 JSON 逐字段比对
  B.3  修复差异直到完全一致
    ↓
Step C: 多版本分析 + 指纹稳定性评估 (1-1.5 周)
  C.1  分析 143 大版本的其他小版本，验证小版本指纹复用假设
  C.2  分析 130-149 各大版本（每个取最新稳定版）
  C.3  对 149（当前发行版）细分小版本分析
  C.4  生成指纹稳定性评估表
    ↓
Step D: 构建密钥指纹数据库 (3-5d)
  D.1  设计数据库 Schema（SQLite）
  D.2  实现入库工具
  D.3  修改 version_detect.py 从数据库查询
  D.4  多版本实测验证
```

---

## 二、Step A：整合分析工具 + 修复 PRF（1-1.5 周）

### A.1 分析源码结构，确定整合方案（1d）

**当前状态**：
- TLSKeyHunter：Ghidra Java 脚本，通过 Docker 运行 Ghidra headless，输出 HKDF 指纹/RVA
- BoringSecretHunter：同上，输出 ssl_log_secret 指纹/RVA
- 两者独立运行 = 对同一个 Chrome 二进制做**两次** Ghidra 预处理（各 ~20h）

**整合目标**：
- 合并为单个 Ghidra 脚本（或脚本套件），一次预处理后顺序执行所有分析
- 输出统一的 JSON 结果文件，格式与现有 `chrome_143.0.7499.169_linux_x86_64.json` 兼容

**具体工作**：
1. 拉取 TLSKeyHunter 和 BoringSecretHunter 源码，阅读核心 Java 文件
2. 理清 Ghidra headless 的调用方式（`analyzeHeadless` 参数、脚本加载顺序）
3. 确定整合形式：
   - **方案 A**：合并为单个 `.java` 脚本，内部分模块执行
   - **方案 B**：保持独立脚本，用一个 wrapper 脚本顺序调用，共享同一个 Ghidra 项目
   - 方案 B 更安全（改动小），推荐先用 B，稳定后再考虑 A

**产出**：整合方案设计文档 + Docker/脚本原型

### A.2 实现整合：单次预处理，一次性提取（2-3d）

**核心实现**：

```bash
# 目标：一条命令，一次 Ghidra 分析，输出所有 Hook 点
python3 tools/analyze_chrome.py \
  --binary artifacts/chrome/143.0.7499.169/chrome \
  --output results/143.0.7499.169.json
```

内部流程：
```
1. Ghidra headless 导入 + 完整分析（~20h，只做一次）
2. 运行 TLSKeyHunter 脚本 → 提取 HKDF 指纹/RVA
3. 运行 BoringSecretHunter 脚本 → 提取 ssl_log_secret 指纹/RVA
4. 运行 PRF 定位脚本（新增）→ 提取 PRF 指纹/RVA
5. 运行补充分析脚本（新增）→ 提取 key_expansion、结构体偏移等
6. 合并所有结果 → 输出 JSON
```

**Ghidra 项目复用**：
- 第一次运行后保存 Ghidra 项目文件（`.gpr` + `.rep`）
- 后续可跳过预处理阶段，直接加载项目运行脚本
- 这对调试迭代非常重要——改了脚本后不需要重新等 20 小时

**验收**：能对一个 Chrome 二进制一次性输出包含 HKDF + ssl_log_secret RVA/指纹的 JSON

### A.3 修复 PRF 识别（2-3d）

**P2 已确认的三个失败原因及修复方案**：

#### 原因 1：缺少 .rodata 字节模式回退

HKDF 识别有 `.rodata` 十六进制模式扫描回退（这就是为什么 HKDF 成功了），PRF 没有。

**修复**：将 HKDF 识别中的 `.rodata` 回退逻辑复制到 PRF 识别路径：

```java
// 伪代码：在 PRF 识别失败后，启动 .rodata 扫描
if (prfFunctionNotFound) {
    // 搜索 "master secret" 的十六进制: 6d 61 73 74 65 72 20 73 65 63 72 65 74
    byte[] pattern = "master secret".getBytes(StandardCharsets.US_ASCII);
    Address rodataMatch = searchRodata(pattern);
    if (rodataMatch != null) {
        // 找到 .rodata 中的地址后，搜索引用该地址的指令
        Reference[] refs = getReferencesTo(rodataMatch);
        for (Reference ref : refs) {
            Function func = getFunctionContaining(ref.getFromAddress());
            // 验证是否是 PRF 函数（而非 wrapper）
            if (validatePRF(func)) {
                extractFingerprint(func);
            }
        }
    }
}
```

#### 原因 2："master secret" 是 "extended master secret" 的子串

在 .rodata 中这两个字符串相邻存储（`0x019091a5` 和 `0x019091ae`），搜索 "master secret" 会命中子串位置。

**修复**：搜索时检查前一个字节是否是 `\0`（字符串终止符），只接受独立的 "master secret" 字符串：

```java
// 确认命中的是独立字符串而非子串
Address match = ...;
byte prevByte = getByte(match.subtract(1));
if (prevByte != 0x00 && prevByte != 0x20) {
    // 这是子串，跳过
    continue;
}
```

或者更稳妥：同时搜索 "master secret" 和 "extended master secret"，对两者的 XREF 取交集——它们都指向同一个 Unified PRF 函数。

#### 原因 3：14 参数函数超出 wrapper 验证启发式

TLSKeyHunter 的 wrapper 检测逻辑可能把 BoringSSL 的 Unified PRF（参数多、含 XMM 寄存器）误判为 wrapper。

**修复**：对 BoringSSL 放宽 wrapper 判定条件，或直接跳过 wrapper 验证——因为通过 .rodata XREF 找到的函数已经有足够高的置信度（TLS 标签字符串被作为参数传入 = 极大概率是 KDF 函数）。

**验收**：对 143.x Chrome 运行修复后的脚本，PRF 识别成功，输出的 RVA 和指纹与手动分析结果 `0x0A22D4B0` 一致

### A.4 补充自动化分析（1-2d）

将 P1 手动分析中确认的以下信息也纳入自动化提取：

#### key_expansion 定位

搜索 "key expansion" 字符串的 XREF，与 "master secret" 的 XREF 交叉——如果两者指向同一个函数说明是 Unified PRF，如果不同则 key_expansion 需要单独记录。

```java
// 搜索 "key expansion" → XREF → 函数入口
// 对 BoringSSL，预期结果是 FUN_0a32d130（与 PRF 不同函数，但共享底层 P_hash）
```

#### client_random 路径提取（可选自动化）

这个比较难完全自动化，因为需要理解 ssl_st 结构体布局。两种策略：

- **策略 1（推荐）**：在 JSON 中标记为"需要运行时验证"，由 tls_capture.py 首次运行时用探针脚本自动校准
- **策略 2**：从反编译代码中搜索 `readPointer().add(0x30)` 模式链——复杂度高，收益不确定

建议 Phase 2 用策略 1，记录当前已知路径 `*(*(ssl+0x30)+0x30)` 作为默认值，标注 `"verified_on": "143.0.7499.169"`。

#### 结构体偏移（ssl_st_rbio, bio_st_num）

同样标记为"需要运行时探测"，复用 P4 的动态探测逻辑。在 JSON 中保留默认值但标注版本。

**产出**：
- 整合后的分析工具能输出与现有 JSON 格式完全兼容的结果
- 包含 HKDF、PRF、key_expansion、ssl_log_secret 四个 Hook 点的 RVA + 指纹
- client_random 和结构体偏移标记为"默认值 + 需运行时验证"

---

## 三、Step B：143.x Ground Truth 回归验证（2-3d）

### B.1 对 143.0.7499.169 运行整合工具

```bash
python3 tools/analyze_chrome.py \
  --binary artifacts/chrome/143.0.7499.169/chrome \
  --output results/143.0.7499.169_auto.json
```

### B.2 与现有 JSON 逐字段比对

```bash
python3 tools/compare_analysis.py \
  --baseline hooks/chrome_143.0.7499.169_linux_x86_64.json \
  --generated results/143.0.7499.169_auto.json
```

比对项：

| 字段 | 基线值 | 自动输出 | 一致？ |
|------|--------|---------|--------|
| hook_points.hkdf.rva | 0x048837E0 | ? | ? |
| hook_points.hkdf.fingerprint (前32B) | 55 48 89 E5... | ? | ? |
| hook_points.prf.rva | 0x0A22D4B0 | ? | ? |
| hook_points.prf.fingerprint (前20B) | 55 48 89 E5... | ? | ? |
| hook_points.ssl_log_secret.rva | 0x04883520 | ? | ? |
| hook_points.key_expansion.rva | 0x0A22D130 | ? | ? |

### B.3 修复差异

如果有不一致，分析原因并修复。常见可能：
- imageBase 计算差异（0x100000 偏移）
- 指纹长度差异（停止条件不同）
- PRF 识别到了 wrapper 而非真正函数

**验收标准**：所有 RVA 完全一致，指纹前 32 字节完全一致

---

## 四、Step C：多版本分析 + 指纹稳定性评估（1-1.5 周）

### C.1 143 大版本小版本复用验证（1d）

**目标**：验证"同大版本不同小版本的指纹和 RVA 是否完全相同"

从 Chrome for Testing API 获取 143.x 的其他小版本（如果可用），对比分析结果。

预期结论：小版本（patch）通常只修安全漏洞，不触及 BoringSSL KDF 代码，因此 RVA 和指纹应完全一致。如果确认，数据库中只需存储大版本级别的记录，小版本可直接复用。

### C.2 130-149 各大版本分析（5-7d，含 Ghidra 等待时间）

```bash
# 批量分析所有已下载版本
for version_dir in artifacts/chrome/*/; do
  version=$(cat "$version_dir/metadata.json" | python3 -c "import sys,json; print(json.load(sys.stdin)['version'])")
  echo "[*] 分析 $version ..."
  python3 tools/analyze_chrome.py \
    --binary "$version_dir/chrome" \
    --output "results/${version}.json" \
    --save-project  # 保存 Ghidra 项目，后续可跳过预处理
done
```

**并行策略**：
- 每个 Ghidra 实例需要 ~8GB RAM
- 如果有 32GB RAM，可以 4 并行
- 10 个版本 × 20h / 4 并行 ≈ 50h ≈ 2 天

**关键**：Ghidra 预处理是瓶颈，脚本执行本身只需要分钟级。建议白天启动分析任务，隔天检查结果。

### C.3 149（当前发行版）小版本细分（0.5d）

如果 149 是当前最新稳定版且你的用户可能使用，对其最近 2-3 个小版本做分析，验证小版本复用假设在最新版上也成立。

### C.4 生成指纹稳定性评估表（1d）

```bash
python3 tools/generate_stability_report.py \
  --results-dir results/ \
  --output results/fingerprint_stability_report.md
```

产出核心表格：

```markdown
| Milestone | Version | HKDF RVA | HKDF FP[0:32] | PRF RVA | PRF FP[0:20] | ssl_log RVA | FP Same? | RVA Δ |
|-----------|---------|----------|--------------|---------|-------------|-------------|----------|-------|
| 113 | 113.0.5672.63 | ? | ? | ? | ? | ? | baseline | — |
| 115 | 115.0.5790.170 | ? | ? | ? | ? | ? | ? | ? |
| ... | ... | ... | ... | ... | ... | ... | ... | ... |
| 143 | 143.0.7499.169 | 0x048837E0 | 55 48 89 E5... | 0x0A22D4B0 | 55 48 89 E5... | 0x04883520 | ref | — |
| 149 | 149.0.xxxx.xx | ? | ? | ? | ? | ? | ? | ? |
```

**需要回答的关键问题**：
1. 指纹复用率——多少个版本的函数序言（前 32B）完全相同？
2. RVA 变化模式——线性增长还是跳变？每大版本的偏移量范围？
3. 断裂点——哪些版本之间指纹发生了变化？
4. 回退扫描可行性——用前 20B 指纹在 .text 段做 Boyer-Moore 搜索能否唯一命中？

---

## 五、Step D：构建密钥指纹数据库（3-5d）

### D.1 数据库 Schema（SQLite）

```sql
CREATE TABLE browser_fingerprints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- 浏览器标识
    browser         TEXT NOT NULL,           -- 'chrome' / 'firefox' / 'edge'
    version         TEXT NOT NULL,           -- '143.0.7499.169'
    milestone       INTEGER NOT NULL,        -- 143
    platform        TEXT NOT NULL,           -- 'linux'
    arch            TEXT NOT NULL,           -- 'x86_64'
    tls_lib         TEXT NOT NULL,           -- 'BoringSSL' / 'NSS'
    
    -- Hook 点
    hkdf_rva        TEXT,                    -- '0x048837E0'
    hkdf_fingerprint TEXT,                   -- hex string
    hkdf_fp_len     INTEGER,
    
    prf_rva         TEXT,
    prf_fingerprint TEXT,
    prf_fp_len      INTEGER,
    
    key_exp_rva     TEXT,
    key_exp_fingerprint TEXT,
    
    ssl_log_rva     TEXT,
    ssl_log_fingerprint TEXT,
    
    -- 结构体偏移（JSON 存储，因为不同版本可能有不同字段）
    struct_offsets   TEXT,                    -- JSON: {"ssl_st_rbio": "0x240", ...}
    client_random_path TEXT,                 -- JSON: {"steps": [...], "verified_on": "143.x"}
    tls13_key_len_offsets TEXT,              -- JSON: {"c_hs_traffic": "0xb2", ...}
    
    -- 元数据
    analysis_tool   TEXT,                    -- 'integrated_v1'
    analysis_date   TEXT NOT NULL,
    chrome_sha256   TEXT,
    boringssl_commit TEXT,
    verified        INTEGER DEFAULT 0,       -- 0=未验证 1=指纹验证 2=运行时验证
    verified_method TEXT,
    
    -- 指纹稳定性标记
    fp_same_as      TEXT,                    -- 指纹与哪个版本相同（如 '143.0.7499.169'）
    rva_delta_from  TEXT,                    -- RVA 相对于哪个版本的偏移量
    
    notes           TEXT,
    
    UNIQUE(browser, version, platform, arch)
);

-- 索引：按版本号查询
CREATE INDEX idx_version ON browser_fingerprints(browser, version);
-- 索引：按大版本查询（回退匹配）
CREATE INDEX idx_milestone ON browser_fingerprints(browser, milestone, platform, arch);
-- 索引：按指纹查询（未知版本扫描匹配）
CREATE INDEX idx_hkdf_fp ON browser_fingerprints(hkdf_fingerprint);
CREATE INDEX idx_prf_fp ON browser_fingerprints(prf_fingerprint);
```

**与现有 JSON 的关系**：
- 数据库是**主存储**，包含所有版本的完整数据
- JSON 文件变为**导出产物**，由数据库导出给 tls_capture.py 使用
- 这样查询、统计、对比都在数据库中完成，JSON 只是运行时消费格式

### D.2 入库工具

```bash
# 从分析结果 JSON 导入数据库
python3 tools/db_import.py \
  --results-dir results/ \
  --database fingerprints.db

# 从数据库导出某个版本的运行时 JSON
python3 tools/db_export.py \
  --database fingerprints.db \
  --version 143.0.7499.169 \
  --output hooks/chrome_143.0.7499.169_linux_x86_64.json

# 查询数据库
python3 tools/db_query.py --database fingerprints.db --list
python3 tools/db_query.py --database fingerprints.db --milestone 143
python3 tools/db_query.py --database fingerprints.db --fp-stability  # 输出稳定性报告
```

### D.3 修改 version_detect.py

```python
# 当前逻辑：从 hooks/ 目录扫描 JSON 文件
# 新增逻辑：优先从数据库查询

def load_config(version, config_dir=None, database=None):
    # 1. 如果提供了数据库路径，优先从数据库查询
    if database and os.path.exists(database):
        config = _load_from_db(database, version)
        if config:
            return config
    
    # 2. 回退到 JSON 文件（兼容现有行为）
    return _load_from_json(version, config_dir)
```

### D.4 多版本实测验证（1-2d）

从已下载的版本中选 2-3 个，用 Chrome for Testing 的二进制实际运行 + tls_capture.py 验证：

```bash
# 运行旧版本 Chrome
./artifacts/chrome/140.0.xxxx.xx/chrome \
  --no-sandbox --user-data-dir=/tmp/chrome_test_140 \
  --disable-extensions

# 用对应版本的配置运行捕获
sudo python3 tls_capture.py --pid <PID> --database fingerprints.db
```

**注意**：Chrome for Testing 二进制可能缺少某些系统依赖，如果无法启动：
- 检查 `ldd chrome` 缺失的库
- 或者只做"指纹验证"（确认自动分析输出正确）而不做"运行时验证"（实际捕获密钥）

---

## 六、时间估算

```
Week 1:
  Day 1:     A.1 源码分析 + 整合方案
  Day 2-3:   A.2 整合实现（单次预处理框架）
  Day 4-5:   A.3 PRF 修复

Week 2:
  Day 1:     A.4 补充自动化 + B.1 对 143.x 回归
  Day 2:     B.2-B.3 比对修复
  Day 3-5:   C.1-C.2 启动批量分析（后台跑 Ghidra）

Week 3:
  Day 1-2:   C.2 继续（等分析完成 + 检查结果）
  Day 3:     C.3-C.4 指纹稳定性评估表
  Day 4-5:   D.1-D.2 数据库设计 + 入库工具

Week 4 (Buffer):
  Day 1:     D.3 version_detect.py 数据库支持
  Day 2-3:   D.4 多版本实测
  Day 4-5:   文档 + 收尾
```

**关键路径瓶颈**：Ghidra 分析时间。建议 A.3 PRF 修复完成后立即启动第一批版本的后台分析，与 B 步骤并行。

---

## 七、验收标准

| # | 标准 | 验证方式 |
|---|------|---------|
| 1 | 整合工具一次运行输出 4 个 Hook 点 | `analyze_chrome.py` 输出 JSON 含 hkdf/prf/key_exp/ssl_log |
| 2 | PRF 识别对 143.x 成功 | 输出 RVA = 0x0A22D4B0 |
| 3 | 143.x 回归完全一致 | `compare_analysis.py` 零差异 |
| 4 | 10+ 版本分析完成 | `results/` 目录有 10+ 个 JSON |
| 5 | 指纹稳定性评估表完成 | `fingerprint_stability_report.md` |
| 6 | SQLite 数据库包含所有版本 | `db_query.py --list` 输出 10+ 行 |
| 7 | version_detect.py 支持数据库查询 | 从数据库加载配置成功 |
| 8 | 至少 2 个非 143.x 版本指纹验证通过 | 分析结果与手动抽检一致 |

---

## 八、整合工具的目录结构

```
tools/
├── chrome_downloader.py              ← 已完成
├── analyze_chrome.py                 ← 新增：整合分析入口
├── ghidra_scripts/
│   ├── FindHKDF.java                 ← 基于 TLSKeyHunter，可能直接复用
│   ├── FindSSLLogSecret.java         ← 基于 BoringSecretHunter，可能直接复用
│   ├── FindPRF.java                  ← 新增：修复后的 PRF 识别
│   ├── FindKeyExpansion.java         ← 新增：key_expansion 定位
│   └── ExtractFingerprint.java       ← 已有：通用指纹提取
├── merge_analysis.py                 ← 新增：合并各脚本输出为统一 JSON
├── compare_analysis.py               ← 新增：与 ground truth 比对
├── generate_stability_report.py      ← 新增：生成评估表
├── db_import.py                      ← 新增：JSON → SQLite
├── db_export.py                      ← 新增：SQLite → JSON
├── db_query.py                       ← 新增：数据库查询
└── batch_analyze.sh                  ← 新增：批量分析 wrapper
```

---

## 九、与后续阶段的衔接

Phase 2 完成后的项目能力：

| 能力 | Phase 1 | Phase 2 完成后 |
|------|---------|---------------|
| 支持版本数 | 1（143.x） | 10-15+ |
| 分析方式 | 手动 Ghidra | 自动化工具 |
| 数据存储 | JSON 文件 | SQLite 数据库 |
| PRF 识别 | 手动 | 自动（含 .rodata 回退） |
| 新版本适配 | 需要重做 P1 | 运行 `analyze_chrome.py` + 入库 |
| 指纹稳定性 | 假设 | 量化数据 |

**后续路线**：
- **P7 / Phase 3**：指纹内存扫描 + 未知版本自动适配（用评估表确定扫描策略）
- **P8**：Firefox (NSS) 扩展——整合工具框架可复用，只需增加 NSS 特定的 Ghidra 脚本
- **P9**：GUI + 论文——数据库直接作为论文的实验数据源

---

## 十、风险与应对

| 风险 | 影响 | 应对 |
|------|------|------|
| TLSKeyHunter/BSH 源码耦合 Ghidra 版本 | 整合时 API 不兼容 | 统一使用 Ghidra 11.x，两个项目都支持 |
| PRF .rodata 回退在某些版本上仍失败 | 部分版本 PRF 缺失 | 回退到方案 C（指纹扫描），已知指纹搜索新二进制 |
| Ghidra 并行分析 OOM | 分析中断 | 限制并行数 ≤ RAM/8GB，或串行跑 |
| 旧版本 BoringSSL 结构体布局变化 | client_random 路径失效 | JSON 中标记 verified_on，运行时首次使用时探针校准 |
| Chrome for Testing 二进制与官方版差异 | 指纹不匹配 | 同时下载部分官方 .deb 包做交叉验证 |
