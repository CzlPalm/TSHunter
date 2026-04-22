# 总原则

- **阶段 A/B/C 全程用 mock/静态测试自证**（无需 Ghidra 17h），直到阶段 D 才跑真实回归
- 每阶段结束都做一次 git commit + push，保留回滚点
- Java 侧模块化不改外部接口（Dockerfile、`run.py --binary` 调用方式保持兼容）
- SQLite 数据库作为可选产物，不强依赖；失败时回退到 JSON 文件存储

暂时的结构可以设置为：
```
TLShunter/
├── analyzers/
│   ├── boringssl.py / java
│   ├── nss.py / java
│   ├── openssl.py / java
│   └── ...
├── scripts/
│   ├── TLShunterAnalyzer.java
│   ├── BoringSSLAnalyzer.java
│   ├── NSSAnalyzer.java
│   └── ...
├── binaries/
│   ├── chrome/
│   ├── firefox/
│   ├── edge/
│   └── samples/
├── hooks/
│   ├── chrome/
│   ├── firefox/
│   └── ...
├── results/
├── docs/
└── run.py
```

---

# 阶段 A — 通用化：Chrome 专用 → 任意单二进制分析器

## A.1 目标

任何 ELF/PE/Mach-O 单二进制都能通过一条命令跑完：

```bash
# 入口统一
python3 run.py --binary /path/to/any/binary --output /path/to/result.json \
    [--browser chrome] [--version 143.0.7499.169] [--platform linux] [--arch x86_64]

# Shell 等价
bash run_binary_analysis.sh /path/to/binary /path/to/output.json \
    [--meta browser=chrome,version=143.0.7499.169,platform=linux,arch=x86_64]
```

## A.2 文件改动清单

|动作|路径|说明|
|---|---|---|
|新建|`run_binary_analysis.sh`|通用 shell 入口，替代 `run_chrome_analysis.sh`|
|保留|`run_chrome_analysis.sh`|改为 `run_binary_analysis.sh` 的 thin wrapper（向后兼容），内部只固定 Chrome 的 metadata + 路径，然后 exec 通用脚本|
|修改|`run.py`|`--binary/--output` 已支持，新增 `--browser --version --platform --arch` 传递 metadata；写入输出 JSON 的 `meta` 段|
|修改|`ghidra_analysis.sh`|支持多二进制：若 `/usr/local/src/binaries/` 有多个文件，按 `SELECT_BINARY` 环境变量选，否则选第一个 ELF/PE/Mach-O（当前已这样，补环境变量覆盖）|
|新建|`binaries/`|空目录 + `.gitkeep`，作为本地分析暂存区（gitignore 内容）|

## A.3 CLI 契约（Cursor 照做）

**`run_binary_analysis.sh`** 核心逻辑：

```bash
#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <binary_path> <output_json> [options]

Options:
  --meta KEY=VAL[,KEY=VAL...]   Metadata: browser, version, platform, arch, tls_lib
  --tag STRING                  Human-readable run tag (default: timestamp)
  --background                  Run in background (nohup), writes .pid/.log
  --image TAG                   Override docker image tag (default: tlshunter:0.5.0)
  --rebuild                     Force docker rmi + rebuild
EOF
    exit 1
}

[[ $# -lt 2 ]] && usage
BINARY="$1"; shift
OUTPUT_JSON="$1"; shift

META=""; TAG=""; BACKGROUND=0; IMAGE_TAG="tlshunter:0.5.0"; REBUILD=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --meta) META="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --background) BACKGROUND=1; shift ;;
        --image) IMAGE_TAG="$2"; shift 2 ;;
        --rebuild) REBUILD=1; shift ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done
# ... 委托给 python3 run.py 或直接调用 docker run
```

**`run.py`** 新增参数（保持向后兼容，旧调用方式不破）：

```python
parser.add_argument("--browser", help="Browser name (chrome/firefox/edge/...)")
parser.add_argument("--version", help="Browser version (e.g. 143.0.7499.169)")
parser.add_argument("--platform", help="linux/windows/macos/android")
parser.add_argument("--arch", help="x86_64/aarch64/armv7")
parser.add_argument("--tls-lib", help="Expected TLS library: boringssl/openssl/nss/rustls")
```

**输出 JSON 扩展**（`build_output_json` 需要改）：

```json
{
  "meta": {
    "binary": "chrome",
    "binary_sha256": "<sha256 of input file>",
    "binary_size": 268435456,
    "browser": "chrome",
    "version": "143.0.7499.169",
    "platform": "linux",
    "arch": "x86_64",
    "tls_lib": "boringssl",
    "tls_lib_detected": "boringssl",
    "tls_lib_confidence": 0.95,
    "analysis_tool": "TLShunter v0.6.0",
    "analysis_date": "2026-04-21T10:00:00Z",
    "analyzer_version": "0.6.0-modular",
    "image_base": "0x00100000"
  },
  "hook_points": { ... }
}
```

`binary_sha256` / `binary_size` / `image_base` 都由 Python 或 Ghidra 脚本自动填写。`tls_lib_detected` / `tls_lib_confidence` 在阶段 C 由 detector 填入。

## A.4 要从代码里铲掉的 Chrome 硬编码

|位置|现状|改为|
|---|---|---|
|`run_chrome_analysis.sh:4`|`BINARY_PATH="${ROOT_DIR}/TLSKeyHunter/binary/chrome"`|wrapper 内部变量，通过参数注入|
|`run_chrome_analysis.sh:7`|`JSON_OUT="${RESULTS_DIR}/143_auto.json"`|通过参数注入|
|`run_chrome_analysis.sh` Docker 挂载 `TLSKeyHunter/binary`|已耦合|改挂 `$(dirname $BINARY)`，并把单文件 copy 到临时 staging 目录|
|`run.py::build_output_json` `"binary": binary.name`|只有名字|加 sha256/size/metadata|
|`ghidra_analysis.sh:19` "echo" 里只写 binary 名|—|追加 sha256 打印方便审计|

## A.5 Claude 验收清单（我在你跑之前静态检查）

- [ ]  `grep -r "chrome" --include="*.sh" --include="*.py"` 只在 wrapper 脚本里出现（或注释里出现示例）
- [ ]  `grep -r "143_auto\|TLSKeyHunter/binary"` 为 0 或仅在 docs/
- [ ]  `python3 run.py --help` 输出包含新的 `--browser/--version/--platform/--arch`
- [ ]  `bash run_binary_analysis.sh` 无参数时打印 usage 并退出码 1
- [ ]  `bash run_chrome_analysis.sh` 仍然能工作（向后兼容），但内部调用 `run_binary_analysis.sh`

---

# 阶段 B — 指纹数据库：schema + 入库/查询工具

## B.1 SQLite schema（`tools/schema.sql`）

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS tls_stacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,                     -- 'boringssl' | 'openssl' | 'nss' | 'rustls'
    description TEXT
);

CREATE TABLE IF NOT EXISTS browsers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,                     -- 'chrome' | 'firefox' | 'edge' | 'electron_app'
    vendor TEXT,
    default_tls_stack_id INTEGER,
    FOREIGN KEY (default_tls_stack_id) REFERENCES tls_stacks(id)
);

CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    browser_id INTEGER NOT NULL,
    version TEXT NOT NULL,                         -- '143.0.7499.169'
    platform TEXT NOT NULL,                        -- 'linux' | 'windows' | 'macos' | 'android'
    arch TEXT NOT NULL,                            -- 'x86_64' | 'aarch64' | ...
    tls_stack_id INTEGER,
    tls_lib_commit TEXT,                           -- BoringSSL commit sha (from source)
    image_base TEXT,                               -- hex, e.g. '0x00100000'
    binary_sha256 TEXT,
    binary_size INTEGER,
    analysis_date TEXT,                            -- ISO 8601
    analyzer_version TEXT,                         -- 'TLShunter 0.6.0'
    verified INTEGER DEFAULT 0,                    -- 1 when manually cross-checked
    note TEXT,
    UNIQUE(browser_id, version, platform, arch),
    FOREIGN KEY (browser_id) REFERENCES browsers(id) ON DELETE CASCADE,
    FOREIGN KEY (tls_stack_id) REFERENCES tls_stacks(id)
);

CREATE TABLE IF NOT EXISTS hook_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('prf','key_expansion','hkdf','ssl_log_secret')),
    function_name TEXT,
    rva TEXT NOT NULL,                             -- '0x048837E0'
    fingerprint TEXT NOT NULL,                     -- space-separated hex
    fingerprint_len INTEGER NOT NULL,
    fingerprint_prefix20 TEXT NOT NULL,            -- first 20 bytes, for fast lookup
    role TEXT,
    params_json TEXT,                              -- JSON of args mapping
    source TEXT,                                   -- 'auto' | 'manual' | 'migrated'
    verified INTEGER DEFAULT 0,
    UNIQUE(version_id, kind),
    FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hook_fp_prefix ON hook_points(fingerprint_prefix20);
CREATE INDEX IF NOT EXISTS idx_hook_kind ON hook_points(kind);
CREATE INDEX IF NOT EXISTS idx_versions_browser ON versions(browser_id, version);

CREATE TABLE IF NOT EXISTS analyzer_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds INTEGER,
    analyzer_version TEXT,
    exit_code INTEGER,
    log_path TEXT,
    json_path TEXT,
    FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS capture_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER,
    captured_at TEXT NOT NULL,
    pid INTEGER,
    tid INTEGER,
    five_tuple TEXT,                               -- 'TCP 10.0.0.1:54321->203.0.113.1:443'
    key_type TEXT,                                 -- 'CLIENT_RANDOM' | 'CLIENT_HANDSHAKE_TRAFFIC_SECRET' | ...
    client_random TEXT,                            -- 32-byte hex
    secret TEXT,                                   -- secret hex
    FOREIGN KEY (version_id) REFERENCES versions(id) ON DELETE SET NULL
);

INSERT OR IGNORE INTO tls_stacks(name, description) VALUES
    ('boringssl', 'Google BoringSSL (Chrome, Edge, Electron)'),
    ('openssl',   'OpenSSL 1.1.x / 3.x'),
    ('nss',       'Mozilla NSS (Firefox, Thunderbird)'),
    ('rustls',    'Rust TLS implementation');

INSERT OR IGNORE INTO browsers(name, vendor, default_tls_stack_id) VALUES
    ('chrome',   'Google',    (SELECT id FROM tls_stacks WHERE name='boringssl')),
    ('edge',     'Microsoft', (SELECT id FROM tls_stacks WHERE name='boringssl')),
    ('firefox',  'Mozilla',   (SELECT id FROM tls_stacks WHERE name='nss')),
    ('electron', 'Various',   (SELECT id FROM tls_stacks WHERE name='boringssl'));
```

## B.2 入库/查询工具（`tools/ingest.py` + `tools/query.py`）

### `tools/ingest.py`

```bash
# 从单次分析结果入库
python3 tools/ingest.py \
    --json results/chrome_143.json \
    --db data/fingerprints.db

# 批量导入历史（用于冷启动）
python3 tools/ingest.py --batch results/ --db data/fingerprints.db

# 从 p_t_c/hooks/*.json 迁移老格式
python3 tools/ingest.py --legacy ../p_t_c/hooks/ --db data/fingerprints.db

# 强制覆盖已存在的条目
python3 tools/ingest.py --json results/chrome_143.json --db data/fingerprints.db --upsert
```

关键行为：

- 读 JSON 的 `meta` 段取 browser/version/platform/arch
- `meta` 缺字段时从 CLI `--browser/--version/...` 补
- 三者都缺 → 报错退出（1）
- 写入时计算 `fingerprint_prefix20`（前 20 字节）
- 唯一冲突时：默认 skip 并打 warning；`--upsert` 覆盖并在 `analyzer_runs` 留痕

### `tools/query.py`

```bash
# 1. 精确版本查询
python3 tools/query.py --db data/fingerprints.db \
    --browser chrome --version 143.0.7499.169 --platform linux --arch x86_64

# 2. 指纹反查（给 Frida 用）
python3 tools/query.py --db data/fingerprints.db \
    --fingerprint "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 58 64 48 8B"

# 3. 列出 major.minor 下所有候选版本（用于小版本 fallback）
python3 tools/query.py --db data/fingerprints.db \
    --browser chrome --major-minor 143.0

# 4. 导出为 Frida-消费格式
python3 tools/query.py --db data/fingerprints.db \
    --browser chrome --version 143.0.7499.169 --format frida > hooks.json

# 5. 数据库健康报告
python3 tools/query.py --db data/fingerprints.db --report
```

## B.3 数据库位置与 gitignore

|项|位置|纳入 git|
|---|---|---|
|schema DDL|`tools/schema.sql`|✓|
|运行期数据库|`data/fingerprints.db`|✗（gitignore）|
|种子数据|`data/seed_fingerprints.json`|✓（首次 bootstrap 用）|
|迁移脚本|`tools/migrations/*.sql`|✓（后续 schema 演进）|

**种子数据**：把 `p_t_c/hooks/chrome_143.0.7499.169_linux_x86_64.json` 转换后放进 `data/seed_fingerprints.json`，`ingest.py` 首次启动自动导入，保证 DB 非空。

## B.4 Claude 验收清单

- [ ]  `sqlite3 data/fingerprints.db < tools/schema.sql` 零错误
- [ ]  `python3 tools/ingest.py --legacy ../p_t_c/hooks/` 能把 143 的 JSON 导入
- [ ]  `python3 tools/query.py --browser chrome --version 143.0.7499.169 --platform linux --arch x86_64` 返回 4 个 hook points
- [ ]  `tools/query.py --fingerprint "..."` 对 20B 前缀命中返回正确版本
- [ ]  再次 ingest 同一 JSON 默认不报错但不重复写（`--upsert` 覆盖）
- [ ]  `tools/query.py --report` 输出至少包含：版本总数 / hook 点总数 / 各 TLS 栈分布

---

# 阶段 C — TLS 栈插件化

## C.1 目录结构

```
scripts/
├── TLShunterAnalyzer.java          (主编排器 / entry point for Ghidra headless)
├── common/
│   ├── FingerprintExtractor.java   (getLengthUntilStop + extractFingerprint)
│   ├── StringXrefUtil.java         (findAllStringsInReadonlyData etc.)
│   ├── FunctionRef.java
│   ├── ResultRecord.java
│   └── ResultEmitter.java          ([RESULT] 行打印)
├── detect/
│   └── TlsStackDetector.java       (识别 boringssl/openssl/nss/rustls)
└── stacks/
    ├── StackAnalyzer.java          (interface: List<ResultRecord> analyze(Program))
    ├── BoringSslAnalyzer.java      (当前 identify* 方法迁移至此)
    ├── OpenSslAnalyzer.java        (stub, throws NotImplemented + logs)
    ├── NssAnalyzer.java            (stub)
    └── RustlsAnalyzer.java         (stub)
```

> **Java package 注意**：Ghidra headless 要求脚本在 scriptPath 下直接可见，**不能**用 `package` 声明。三种解法：
> 
> 1. 把所有类做成 `TLShunterAnalyzer` 的 **static inner class**（最简单，单文件膨胀）
> 2. 所有 `.java` 放 scripts/ 平铺，**不用 package**，只用 `class` 访问修饰
> 3. 打包成 jar 放到 Ghidra extensions 下（最重）
> 
> **推荐方案 2**：Ghidra headless scriptPath 允许多文件平铺，没有 package 语句即可相互引用。Cursor 按这个做。

## C.2 关键接口

**`StackAnalyzer.java`**（抽象基类，非接口，因为要继承 `GhidraScript` 的上下文工具方法）：

```java
public abstract class StackAnalyzer {
    protected GhidraScript script;
    protected ghidra.program.model.listing.Program program;

    public StackAnalyzer(GhidraScript script) {
        this.script = script;
        this.program = script.getCurrentProgram();
    }

    /** 返回该 analyzer 对当前 binary 的匹配置信度 [0.0, 1.0] */
    public abstract double detectConfidence();

    /** 识别并输出 hook points；调用方负责 emit */
    public abstract List<ResultRecord> analyze();

    /** 给出 analyzer 名称，用于日志和 meta 字段 */
    public abstract String getName();
}
```

**`TlsStackDetector.java`**：

```java
public class TlsStackDetector {
    public static class Detection {
        public String stackName;
        public double confidence;
        public StackAnalyzer analyzer;
    }

    public static Detection detect(GhidraScript script) {
        List<StackAnalyzer> candidates = List.of(
            new BoringSslAnalyzer(script),
            new OpenSslAnalyzer(script),
            new NssAnalyzer(script),
            new RustlsAnalyzer(script)
        );

        Detection best = null;
        for (StackAnalyzer a : candidates) {
            double c = a.detectConfidence();
            script.println(String.format("[*] Detector: %s → confidence %.2f", a.getName(), c));
            if (best == null || c > best.confidence) {
                best = new Detection();
                best.stackName = a.getName();
                best.confidence = c;
                best.analyzer = a;
            }
        }
        return best;
    }
}
```

**`BoringSslAnalyzer.detectConfidence()`** 判据：

- 在 `.rodata` 搜 `"BoringSSL"` / `"boringssl"` / `"EXPORTER_SECRET"` / `"CLIENT_RANDOM"` 各一次
- 命中 2 个 → 0.7，命中 3+ → 0.95
- 额外命中 `"c hs traffic"` / `"key expansion"` → 到 0.99

**OpenSSL** 判据（stub 但判据先占位）：

- `"OpenSSL"` + `"tls13_derive_secret"` 符号 / `"SSLv3"` 等

**NSS** 判据：

- `"mozilla/nss"` / `"NSS_GetVersion"` / `"tls13_DeriveSecret"` 等

**Rustls** 判据：

- Rust mangled `_ZN6rustls` / `"rustls"` 字符串

## C.3 主编排器 `TLShunterAnalyzer.run()` 新流程

```java
@Override
protected void run() throws Exception {
    println("TLShunter integrated analyzer v" + VERSION);
    println("[*] Binary: " + currentProgram.getName());

    // 1) 识别 TLS 栈
    TlsStackDetector.Detection det = TlsStackDetector.detect(this);
    println(String.format("[*] Selected: %s (confidence=%.2f)", det.stackName, det.confidence));
    println("[DETECT] stack=" + det.stackName + " confidence=" + det.confidence);  // 供 run.py 解析

    // 2) 调用对应 analyzer
    List<ResultRecord> records;
    try {
        records = det.analyzer.analyze();
    } catch (UnsupportedOperationException e) {
        println("[!] " + det.stackName + " analyzer not yet implemented: " + e.getMessage());
        records = List.of();
    }

    // 3) 统一 emit
    ResultEmitter emitter = new ResultEmitter(this);
    for (ResultRecord r : records) emitter.emit(r);

    println("[*] Analysis finished. Hook points: " + records.size());
}
```

## C.4 `run.py` 消费侧改动

解析 `[DETECT]` 行，填入输出 JSON 的 `meta.tls_lib_detected / tls_lib_confidence`。如果 CLI 传了 `--tls-lib` 且与检测不一致 → 打 warning，以 CLI 为准（用户 override 优先）。

## C.5 Stub analyzer 行为

`OpenSslAnalyzer / NssAnalyzer / RustlsAnalyzer` 三个现在都返回：

- `detectConfidence()`：真实判据（因为要参与最佳匹配选择）
- `analyze()`：抛 `UnsupportedOperationException("OpenSSL analyzer pending implementation — see docs/roadmap.md Phase E")` 并返回 `List.of()`

这样**不会破坏当前 Chrome/BoringSSL 流程**，同时为后续扩展留好槽位。

## C.6 Claude 验收清单

- [ ]  `scripts/` 下 Java 文件数 ≤10，无 `package` 声明
- [ ]  `scripts/stacks/BoringSslAnalyzer.java` 的 `analyze()` 字节级等同原 `TLShunterAnalyzer.java` 的 `identifyHKDF + analyzeSslLogSecret + identifyPRF + identifyKeyExpansion` 输出
- [ ]  `TLShunterAnalyzer.java` 文件行数从 ~500 降到 <100（纯编排）
- [ ]  Docker 镜像能 build（`COPY scripts/*.java /usr/local/src/` + 其子目录）
- [ ]  `ghidra_analysis.sh` 用 `-scriptPath /usr/local/src:/usr/local/src/common:/usr/local/src/stacks:/usr/local/src/detect` 多目录扫描（Ghidra 支持冒号分隔）
- [ ]  输出 JSON `meta.tls_lib_detected` 字段对 Chrome 143 二进制等于 `"boringssl"`，`tls_lib_confidence >= 0.9`

---

# 阶段 D — 端到端闭环回归

## D.1 顶层命令

```bash
python3 tshunter.py capture \
    --binary /path/to/chrome \
    --browser chrome --version 143.0.7499.169 --platform linux --arch x86_64 \
    --db data/fingerprints.db
```

新增 `tshunter.py` 作为 **CLI 前门**（薄包装 `run.py` + `tools/query.py` + `tools/ingest.py`），阶段 D 的主脚本。

## D.2 决策流程（状态机）

```
┌───────────────────────────────────────────────────┐
│  tshunter.py capture --binary X --browser chrome  │
│                      --version 143.0...169        │
└───────────────────┬───────────────────────────────┘
                    ▼
         ┌──────────────────────┐
         │ 1) DB 查询 (browser, │
         │    version, plat,    │
         │    arch)             │
         └──────┬───────────────┘
        命中 ◀──┤         ◀─ 未命中 ─▶
        ▼                               ▼
 ┌─────────────┐              ┌───────────────────┐
 │ 2a) 指纹校验:│              │ 2b) staging:      │
 │  扫描 bin 验 │              │  cp bin → binaries/
 │  证 DB 指纹   │              │  _pending/        │
 │  仍在预期位   │              └───────┬───────────┘
 └──────┬──────┘                      ▼
  pass  │  fail     ┌─────────────────────────┐
   ▼    ▼           │ 3) Analyzer 选择:       │
 输出    │            │  run.py --binary...     │
 hooks  ▼            │  (detect → BoringSSL)   │
 给Frida│            └────────┬────────────────┘
        ▼                     ▼
 [进入2b]               ┌──────────────────┐
                        │ 4) ingest.py     │
                        │  写 DB + 标 unverified│
                        └────────┬─────────┘
                                 ▼
                        ┌───────────────────┐
                        │ 5) 提示用户:      │
                        │  "新版本已入库,   │
                        │   请人工核对 X 个 │
                        │   hook"           │
                        └────────┬──────────┘
                                 ▼
                        ┌───────────────────┐
                        │ 6) 用户手动比对,  │
                        │  调 verify 标正确 │
                        └───────────────────┘
```

## D.3 `tshunter.py` 骨架

```python
# tshunter.py
import argparse, sys, subprocess, hashlib, json
from pathlib import Path

def cmd_capture(args):
    # 1) DB 查询
    hit = query_db(args.db, args.browser, args.version, args.platform, args.arch)
    if hit:
        # 2a) 指纹校验
        if verify_fingerprint_in_binary(args.binary, hit):
            print(f"[OK] DB hit + fingerprint verified, {len(hit['hook_points'])} hooks")
            emit_frida_config(hit, args.output or "hooks.json")
            return 0
        else:
            print(f"[!] DB hit but fingerprint verification FAILED → re-analyzing")

    # 2b) staging
    staging = stage_binary(args.binary)

    # 3) analyzer
    result_json = Path(f"results/{args.browser}_{args.version}_{args.platform}_{args.arch}.json")
    subprocess.run([
        "python3", "run.py",
        "--binary", str(staging),
        "--output", str(result_json),
        "--browser", args.browser,
        "--version", args.version,
        "--platform", args.platform,
        "--arch", args.arch,
    ], check=True)

    # 4) ingest
    subprocess.run([
        "python3", "tools/ingest.py",
        "--json", str(result_json),
        "--db", args.db,
    ], check=True)

    # 5) 用户提示
    print(f"""
[✓] Analysis complete, inserted into DB as unverified.
    Version: {args.browser} {args.version} {args.platform}/{args.arch}
    JSON:    {result_json}
    DB:      {args.db}

Next steps (manual verification):
  1. Inspect {result_json} RVAs and fingerprints
  2. Compare against Ghidra GUI if available
  3. Mark verified:
     python3 tools/query.py --db {args.db} \\
         --verify {args.browser}:{args.version}:{args.platform}:{args.arch}
""")
    return 0

def cmd_verify(args): ...
def cmd_forensic(args): ...  # 五元组查询（Phase 5）

if __name__ == "__main__":
    p = argparse.ArgumentParser(prog="tshunter")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture", help="End-to-end capture flow")
    c.add_argument("--binary", required=True)
    c.add_argument("--browser", required=True)
    c.add_argument("--version", required=True)
    c.add_argument("--platform", default="linux")
    c.add_argument("--arch", default="x86_64")
    c.add_argument("--db", default="data/fingerprints.db")
    c.add_argument("--output", help="Emit Frida hooks config to this path")
    c.set_defaults(func=cmd_capture)

    args = p.parse_args()
    sys.exit(args.func(args))
```

## D.4 指纹校验（`verify_fingerprint_in_binary`）

不跑 Ghidra，用纯 Python + 读 ELF/PE：

- 从 DB 取 hook 的 `rva` 和 `fingerprint`
- 读二进制 ELF/PE 的 image_base（用 `pyelftools` 或 `pefile`）
- 计算 `file_offset = rva - image_base + section_offset`（其实就是虚拟地址 → 文件偏移）
- 读前 20 字节与 `fingerprint_prefix20` 比对

> 这一步让**DB 命中路径**也能**快速 sanity check**，不必每次都跑 17h 分析。

## D.5 回归测试编排（你执行）

### 测试用例 T1：DB 命中 + 验证通过

```bash
# 0. 准备 DB（种子 143 数据）
rm -f data/fingerprints.db
sqlite3 data/fingerprints.db < tools/schema.sql
python3 tools/ingest.py --legacy ../p_t_c/hooks/ --db data/fingerprints.db

# 1. 触发 capture
python3 tshunter.py capture \
    --binary ~/TLSHunter/TLSKeyHunter/binary/chrome \
    --browser chrome --version 143.0.7499.169 \
    --platform linux --arch x86_64 \
    --db data/fingerprints.db \
    --output /tmp/hooks_143.json

# 期望：秒级返回 "DB hit + fingerprint verified"
# /tmp/hooks_143.json 含 4 个 hook 点
```

### 测试用例 T2：DB miss → 触发完整分析（~17h）

```bash
# 1. 故意改坏 DB 里的版本号，模拟"未知版本"
sqlite3 data/fingerprints.db \
    "UPDATE versions SET version='143.0.7499.999' WHERE version='143.0.7499.169';"

# 2. 用真实版本号发起 capture
python3 tshunter.py capture \
    --binary ~/TLSHunter/TLSKeyHunter/binary/chrome \
    --browser chrome --version 143.0.7499.169 \
    --platform linux --arch x86_64 \
    --db data/fingerprints.db

# 期望：
#  - 1 分钟内：打印"DB miss, staging binary..."
#  - 1 小时内：docker build（若首次）
#  - 17h：Ghidra 分析完成
#  - 完成后：自动 ingest → DB 中多一条 143.0.7499.169 记录（unverified）
#  - 提示你手动验证
```

### 测试用例 T3：人工比对 + verified 标记

```bash
# 1. 对比 T2 结果和 ground truth
python3 run.py \
    --output results/chrome_143.0.7499.169_linux_x86_64.json \
    --compare ../p_t_c/hooks/chrome_143.0.7499.169_linux_x86_64.json

# 期望：PASS compare ... + All hook points match

# 2. 标记 verified
python3 tools/query.py --db data/fingerprints.db \
    --verify chrome:143.0.7499.169:linux:x86_64

# 3. 再次 capture，确认走 T1 路径
python3 tshunter.py capture ... (同 T1 命令)
# 期望：秒级返回 "DB hit + fingerprint verified"
```

### 测试用例 T4（可选）：指纹漂移检测

```bash
# 模拟小版本偏移：把 hook 的 RVA +0x1000
sqlite3 data/fingerprints.db \
    "UPDATE hook_points SET rva='0x048847E0' WHERE kind='hkdf';"

# 重新 capture
python3 tshunter.py capture ... (同 T1 命令)
# 期望：
#   - "DB hit but fingerprint verification FAILED"
#   - 自动走 T2 完整分析路径
```

## D.6 Claude 验收清单

- [ ]  `tshunter.py capture --help` 显示 browser/version/platform/arch/db/binary/output 参数
- [ ]  `python3 -c "import ast; ast.parse(open('tshunter.py').read())"` 零语法错误
- [ ]  把 DB 清空后跑 T1 等价命令 → 正确走 T2 分支打印出"DB miss"
- [ ]  对 `chrome_143.0.7499.169_linux_x86_64.json` 预先 ingest 后 → `python3 tools/query.py --browser chrome --version 143.0.7499.169 --platform linux --arch x86_64` 返回 4 个 hook 的 JSON
- [ ]  `verify_fingerprint_in_binary` 对 143 二进制返回 True（前 20 字节可在文件内找到，无需 Ghidra）
- [ ]  在 T4 情境（手动改错 RVA）下返回 False

---

# 总执行顺序

```
Day 0  Cursor 领任务书
         ↓
Day 1-2  阶段 A 编码 → Claude 验收 → Cursor 修 bug → 静态测试通过
         ↓
Day 3-4  阶段 B 编码 + 种子数据迁移 → Claude 验收 → Cursor 修 → ingest/query 能跑
         ↓
Day 5-8  阶段 C 编码（Java 模块化最重）→ Claude 验收 → Docker build 成功
         ↓
Day 9-10 阶段 D 编码 → Claude 验收 → T1/T4 静态通过
         ↓
Day 11   你执行 T2 真实回归（~17h）+ T3 人工比对
         ↓
Day 12   根据 T2/T3 结果决定：
           (a) 通过 → 合并到 main, 开始 Phase 2 多版本扩展
           (b) 失败 → 按 diff 回到对应阶段修复
```

## 给 Cursor 的总任务书入口（一次性贴给它）

```
请严格按 4 个阶段顺序执行，每阶段结束 git commit + push 一次：

- 阶段 A: see docs/roadmap/phase_A.md （用上面 A.1–A.5 的内容新建）
- 阶段 B: see docs/roadmap/phase_B.md
- 阶段 C: see docs/roadmap/phase_C.md
- 阶段 D: see docs/roadmap/phase_D.md

每个阶段完成后，在 PR 描述里 @我 用上面的 "Claude 验收清单" 做自检。
不要跑 17h Ghidra 回归；用 mock / 静态 / 小样本测试。
不要触碰 scripts/TLShunterAnalyzer.java 的 getLengthUntilStop() / extractFingerprint() — 已经是 canonical。
```

---

## 最后几点提醒

1. **不要把 Phase 2 多版本下载糅进阶段 A–D**；阶段 D 回归用的仍是当前的 Chrome 143。多版本是阶段 A–D 稳定之后再做。
2. **BoringSecretHunter / TLSKeyHunter 两个子目录**在阶段 A–D 期间**继续保留**；它们只是历史参考物。等 D 通过后再做仓库瘦身 + git filter-repo。
3. **`data/fingerprints.db` 别进 git**；只把 `data/seed_fingerprints.json` 进 git 作为版本化真值。
4. **五元组关联**（Phase 5）和**Firefox/OpenSSL 真实实现**（扩展 Phase C）都在阶段 D 通过之后再上。不要贪多。