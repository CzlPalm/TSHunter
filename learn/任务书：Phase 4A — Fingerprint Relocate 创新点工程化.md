
## 总体目标

在回归测试开跑之前，为 TSHunter 补齐**指纹重定位（fingerprint-based RVA relocation）**能力。完成后，后续遇到未知小版本二进制时，先秒级尝试 relocate，失败才回退到 17h Ghidra 完整分析。

## 交付物总览

```
新增文件 (5):
  tools/fingerprint_relocate.py         ← 核心算法
  tools/migrations/001_relocate_fields.sql   ← schema 扩展
  tests/__init__.py
  tests/test_relocate.py                ← 单元测试
  tests/fixtures/build_mock_elf.py      ← 测试 fixture 生成器

修改文件 (5):
  tools/schema.sql                      ← 合并新字段 + schema_migrations 表
  tools/ingest.py                       ← 写入新字段 (默认 relocation_method='ghidra_full')
  tools/query.py                        ← --format frida 输出携带 derived_from/delta
  tshunter.py                           ← 新增 relocate 子命令 + capture DB-miss 优先走 relocate
  run_binary_analysis.sh                ← --background 模式下写 *_DONE 文件

删除 (2):
  integrated/                           ← 空目录清理
  (清理 libssl.so.3 metadata 走另外的路径，见 §6)
```

---

## 1. `tools/fingerprint_relocate.py` — 核心算法

### 1.1 CLI 接口

```bash
# 单个 binary 的 relocate（所有 hook 一次性处理）
python3 tools/fingerprint_relocate.py scan \
    --binary /path/to/chrome_143.0.7499.192 \
    --db data/fingerprints.db \
    --source-browser chrome \
    --source-version 143.0.7499.169 \
    --source-platform linux \
    --source-arch x86_64 \
    --output /tmp/relocate_192_from_169.json

# 直接给指纹 + old_rva (脱离 DB 的单点调试)
python3 tools/fingerprint_relocate.py probe \
    --binary /path/to/chrome \
    --fingerprint "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC 98 00 00 00" \
    --old-rva 0x048837E0 \
    --old-image-base 0x00100000

# 批量：同时 relocate 从多个参考版本 (找最佳 source)
python3 tools/fingerprint_relocate.py scan \
    --binary /path/to/chrome_143.0.7499.192 \
    --db data/fingerprints.db \
    --source-browser chrome \
    --auto-source   # 自动从同 major.minor 的所有 version 中挑最佳
    --output /tmp/relocate_192.json
```

### 1.2 输出 JSON Schema

```json
{
  "target": {
    "path": "/path/to/chrome_143.0.7499.192",
    "sha256": "abc...",
    "size": 286331153,
    "image_base": "0x00100000",
    "text_start_rva": "0x00003000",
    "text_size": 83886080
  },
  "source_version": {
    "browser": "chrome",
    "version": "143.0.7499.169",
    "platform": "linux",
    "arch": "x86_64"
  },
  "relocation_summary": {
    "total_hooks": 4,
    "relocated": 4,
    "exact_match": 0,
    "shifted_match": 4,
    "not_found": 0,
    "delta_consistent": true,
    "median_delta": "0x1820",
    "all_deltas": ["0x1820", "0x1820", "0x1820", "0x1820"]
  },
  "hooks": [
    {
      "kind": "hkdf",
      "source_rva": "0x048837E0",
      "source_fingerprint_prefix": "55 48 89 E5 ... (20 bytes)",
      "new_rva": "0x04885000",
      "delta": "0x1820",
      "confidence": 0.98,
      "match_type": "shifted_match",
      "scan_hits": [
        {"rva": "0x04885000", "bytes_matched_prefix": 20, "bytes_matched_extended": 40, "distance_from_source": 6176},
        {"rva": "0x05FF1234", "bytes_matched_prefix": 20, "bytes_matched_extended": 0, "distance_from_source": 19256372}
      ],
      "selected_hit_index": 0,
      "selection_reason": "nearest_to_source_rva_with_extended_verification"
    },
    ...
  ],
  "verdict": "OK",
  "timestamp": "2026-04-21T12:00:00Z",
  "tool_version": "0.1.0"
}
```

`verdict` 取值：

- `"OK"` — 所有 hook 都 relocated 且 delta 一致
- `"PARTIAL"` — 部分 relocated，或 delta 不一致（建议回退到完整分析）
- `"FAIL"` — 所有 hook 都未找到

### 1.3 算法规范

```python
# 伪代码（让 Cursor 按这个实现）

def scan(binary_path, hooks_from_db):
    """
    hooks_from_db: [{kind, rva, fingerprint, fingerprint_len}, ...] (来自 DB)
    """
    text_section = load_text_section(binary_path)  # 用 pyelftools / pefile
    image_base = get_image_base(binary_path)

    results = []
    all_deltas = []

    for hook in hooks_from_db:
        prefix_20 = first_n_bytes(hook['fingerprint'], 20)
        extended_40 = first_n_bytes(hook['fingerprint'], 40)

        # Step 1: 扫前 20 字节所有命中
        hits = scan_bytes(text_section, prefix_20)
        if not hits:
            results.append({kind: ..., match_type: "not_found"})
            continue

        # Step 2: 对每个命中做扩展校验 (前 40 字节)
        scored_hits = []
        for hit_offset in hits:
            extended_match = count_matching_bytes(text_section, hit_offset, extended_40)
            new_rva = hit_offset + text_section.virt_addr - image_base
            old_rva_int = int(hook['rva'], 16)
            distance = abs(new_rva - old_rva_int)
            scored_hits.append({
                'rva': new_rva, 
                'bytes_matched_prefix': 20,
                'bytes_matched_extended': extended_match,
                'distance_from_source': distance
            })

        # Step 3: 选择规则
        # 优先级: 扩展字节匹配数 ≥ 32 → 取 distance 最小
        # 否则 扩展字节匹配数 ≥ 20 → 取 distance 最小 (confidence 降权)
        # 都不满足 → 取 prefix-only 最近的那个 (confidence 更低)
        selected = select_best(scored_hits)

        delta = selected['rva'] - int(hook['rva'], 16)
        all_deltas.append(delta)

        results.append({
            'kind': hook['kind'],
            'source_rva': hook['rva'],
            'new_rva': hex(selected['rva']),
            'delta': hex(delta),
            'confidence': compute_confidence(selected),
            'match_type': 'exact_match' if delta == 0 else 'shifted_match',
            'scan_hits': scored_hits,
            'selected_hit_index': scored_hits.index(selected),
        })

    verdict = determine_verdict(results, all_deltas)
    return {..., "hooks": results, "verdict": verdict}


def compute_confidence(hit):
    # 基准: extended 匹配率
    conf = hit['bytes_matched_extended'] / 40.0
    # 惩罚: 距离过大
    if hit['distance_from_source'] > 16 * 1024 * 1024:  # 16 MB
        conf *= 0.7
    return round(conf, 3)


def determine_verdict(results, all_deltas):
    if all(r['match_type'] == 'not_found' for r in results):
        return "FAIL"
    if any(r['match_type'] == 'not_found' for r in results):
        return "PARTIAL"
    # delta consistency: 中位数 ± 10% 内的视为一致
    if not all_deltas:
        return "PARTIAL"
    median_delta = sorted(all_deltas)[len(all_deltas) // 2]
    tolerance = max(abs(median_delta) * 0.1, 1024)
    if all(abs(d - median_delta) <= tolerance for d in all_deltas):
        return "OK"
    return "PARTIAL"  # delta 不一致也返回 PARTIAL
```

### 1.4 Binary Loader 规范

**ELF** (Linux Chrome)：用 `pyelftools`

- 读 `.text` 段的 `sh_addr`（virtual address）和文件内容
- `image_base` 对 ELF 可执行文件读 `PT_PHDR` 最低虚拟地址；对 PIE/shared object 通常是 0

**PE** (Windows Chrome)：用 `pefile`

- 读 `.text` 的 `VirtualAddress` + `ImageBase`

**Mach-O** (macOS Chrome)：用 `macholib` 或 `lief`

- 暂时只实现 ELF + PE，Mach-O 留 `NotImplementedError`

**依赖声明**：新建 `requirements.txt`（如仓库没有）：

```
pyelftools>=0.29
pefile>=2023.2.7
```

### 1.5 关键实现细节（Cursor 必读）

1. **fingerprint 字符串解析**：DB 里存的是 `"55 48 89 E5 ..."` 空格分隔大写十六进制。解析时 `bytes(int(h, 16) for h in fp.split())`。
    
2. **扫描性能**：Chrome 二进制 `.text` 段约 80–200MB。Python `bytes.find()` 在单次搜索下完全足够，不要引入 Boyer-Moore。但要循环找**所有**命中（`find` 返回第一个，用 `while` + `start += 1` 继续）。
    
3. **false positive 防护**：前 20 字节 `55 48 89 E5 41 57 41 56 ...` 是 x86-64 通用函数序言，Chrome 里可能有**上千个**命中。这就是为什么必须用扩展 40 字节二次校验 + 距离择优。
    
4. **distance 的含义**：假设小版本漂移 < 16MB，用 `abs(new_rva - old_rva)` 作为距离度量。超出阈值打低 confidence。
    
5. **image_base 优先级**：
    
    - CLI 传的 `--old-image-base`（最高）
    - binary 自身提供的
    - 默认 `0x00100000`（Ghidra 默认，但对 PIE 其实无意义）
6. **错误处理**：binary 不是 ELF/PE → 抛明确错误。`.text` 找不到 → 回退扫描所有可执行段。
    

---

## 2. Schema 扩展

### 2.1 `tools/migrations/001_relocate_fields.sql`（新建）

```sql
-- Phase 4A: add relocation lineage fields to hook_points

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
    VALUES ('001_relocate_fields', datetime('now'));

ALTER TABLE hook_points ADD COLUMN derived_from_version_id INTEGER
    REFERENCES versions(id);

ALTER TABLE hook_points ADD COLUMN rva_delta INTEGER DEFAULT NULL;

ALTER TABLE hook_points ADD COLUMN relocation_method TEXT
    DEFAULT 'ghidra_full'
    CHECK(relocation_method IN ('ghidra_full','exact_scan','manual','imported'));

ALTER TABLE hook_points ADD COLUMN relocation_confidence REAL DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_hook_derived_from 
    ON hook_points(derived_from_version_id);
```

### 2.2 `tools/schema.sql` 同步更新

在现有 `hook_points` 的 `CREATE TABLE` 里加上这 4 个字段 + 索引。同时建 `schema_migrations` 表。**保持幂等**：用 `IF NOT EXISTS` 和 `ALTER TABLE ADD COLUMN`（SQLite 不支持 `IF NOT EXISTS` 在 `ADD COLUMN`，所以改用"先查 PRAGMA table_info 再决定是否 ALTER"的 Python 辅助逻辑）。

> **给 Cursor 的提示**：`schema.sql` 面向全新库；`migrations/001_*.sql` 面向已有库升级。`ingest.py` 启动时检查 `schema_migrations` 表，缺失的 migration 逐个 apply。

### 2.3 `tools/ingest.py` 改动

写入 `hook_points` 时默认填：

```python
relocation_method = 'ghidra_full'   # 完整分析得到的
derived_from_version_id = None
rva_delta = None
relocation_confidence = None
```

`fingerprint_relocate.py` 将来通过 `tools/ingest.py --from-relocate <json>` 写入时：

```python
relocation_method = 'exact_scan'
derived_from_version_id = <source version id>
rva_delta = <delta in int>
relocation_confidence = <0.0–1.0>
```

`ingest.py` 新增 `--from-relocate <relocate_json>` 参数专门处理 relocate 产物。

---

## 3. `tshunter.py` 改动

### 3.1 新增 `relocate` 子命令

```bash
# 手动触发 relocate
python3 tshunter.py relocate \
    --binary /path/to/chrome_143.0.7499.192 \
    --browser chrome \
    --version 143.0.7499.192 \
    --platform linux --arch x86_64 \
    --source-version 143.0.7499.169 \
    --db data/fingerprints.db \
    --output /tmp/relocate_192.json \
    --auto-ingest   # 若 verdict=OK 直接入库
```

### 3.2 `capture` DB-miss 分支增强

原流程：

```
DB query → miss → 完整 Ghidra 分析
```

新流程：

```
DB query (精确)
  miss → DB query (同 browser+同 major.minor) 取最近版本作 source
           ├─ 找到 source → 跑 relocate
           │                 ├─ verdict=OK → auto-ingest + 返回 hooks (秒级)
           │                 ├─ verdict=PARTIAL → 打印报告 + fallback 完整分析
           │                 └─ verdict=FAIL → fallback 完整分析
           └─ 无 source → 完整 Ghidra 分析 (17h)
```

新增 CLI 开关：

- `--no-relocate`：关闭 relocate，直接走完整分析（用于论文对照实验）
- `--force-relocate`：即使 relocate 给 PARTIAL 也用它的结果（不推荐，仅调试）

### 3.3 `capture` 新增内部函数

```python
def find_relocation_source(conn, browser, version, platform, arch):
    """
    在 DB 里找同 browser + 同 major.minor + 同 platform + 同 arch 的最近版本作为 source。
    返回 None 或 source_version_row。
    """
    major_minor = ".".join(version.split(".")[:2])   # '143.0.7499.192' -> '143.0'
    rows = conn.execute("""
        SELECT v.* FROM versions v
        JOIN browsers b ON b.id = v.browser_id
        WHERE b.name=? AND v.version LIKE ? 
              AND v.platform=? AND v.arch=? 
              AND v.verified=1
        ORDER BY v.version DESC
    """, (browser, f"{major_minor}.%", platform, arch)).fetchall()
    return rows[0] if rows else None
```

### 3.4 `tshunter.py capture` 输出变更

对 DB-miss + relocate 成功的情况，输出：

```
[*] DB miss: chrome 143.0.7499.192 linux/x86_64
[*] Searching relocation source in same major.minor...
[*] Found candidate: chrome 143.0.7499.169 (verified)
[*] Running fingerprint relocate...
[OK] Relocate verdict: OK
     hooks relocated: 4/4
     median delta:    +0x1820
[*] Auto-ingesting relocated hooks...
[✓] Complete. Database now has chrome 143.0.7499.192 
    (relocation_method=exact_scan, source=143.0.7499.169)
    Frida hooks written to /tmp/hooks.json
```

---

## 4. 测试（`tests/`）

### 4.1 `tests/fixtures/build_mock_elf.py`

生成两个 mock ELF 二进制：

- `mock_v1.elf`：`.text` 段有 4 个"函数"，分别在 RVA 0x1000/0x2000/0x3000/0x4000，每个函数前 40 字节是已知字节序列 + 随后 ret (`C3`) 填充
- `mock_v2.elf`：同样 4 个函数，但整体向后 shift 0x80 bytes（模拟 `delta=+0x80` 的小版本漂移），前 40 字节字节内容与 v1 完全一致

用 `pyelftools` 读比较复杂，推荐用最简方式：

```python
# 手写一个最小 ELF64 文件，.text 段可控
def make_minimal_elf(text_content, text_virt_addr=0x400000, text_file_offset=0x1000):
    # ELF header + Program header + Section header for .text
    # 几十行即可
    ...
```

或者更省事：**用 `objcopy` + 手工 binary patch** 造两个测试样本，直接放 `tests/fixtures/` 纳入 git。

### 4.2 `tests/test_relocate.py`

测试点：

1. `test_exact_match_when_fingerprint_at_same_offset` → 期望 delta=0
2. `test_shifted_match_small_drift` → v1 → v2，期望 delta=+0x80，所有 hook 都命中
3. `test_not_found_when_fingerprint_absent` → 改坏一个 hook 的指纹，期望该 hook `not_found`
4. `test_multi_hit_disambiguation_by_distance` → `.text` 里植入一个远距离的重复指纹，验证选的是近的那个
5. `test_multi_hit_disambiguation_by_extended` → 前 20 字节相同但后 20 字节不同的两个命中，验证选 extended 匹配多的
6. `test_verdict_ok_when_deltas_consistent` → 4 个 hook delta 相同
7. `test_verdict_partial_when_deltas_inconsistent` → 4 个 hook delta 分散
8. `test_scan_reads_from_db` → 从 mock SQLite 读 source hooks 然后 scan

**测试框架**：直接用 `unittest` 或 `pytest`，Cursor 二选一。我建议 `pytest`（更简洁），在 `requirements.txt` 加 `pytest>=7.0`。

### 4.3 运行方式

```bash
cd tests/
python3 -m pytest -v test_relocate.py
# 或
python3 -m unittest test_relocate
```

---

## 5. 清理任务（同 PR 里一起做）

### 5.1 删除 `integrated/` 空目录

```bash
git rm -r integrated/
```

### 5.2 `run_binary_analysis.sh --background` 补 `ANALYSIS_DONE` 标记

在背景任务完成处加一个 trap，仿照旧 `run_chrome_analysis.sh` 的行为：

```bash
# 修改 background 分支
if [[ $BACKGROUND -eq 1 ]]; then
    RUN_TAG="${TAG:-$(date +%Y%m%d_%H%M%S)}"
    LOG_FILE="${OUTPUT_JSON%.json}_${RUN_TAG}.log"
    PID_FILE="${OUTPUT_JSON%.json}_${RUN_TAG}.pid"
    DONE_FILE="${OUTPUT_JSON%.json}_${RUN_TAG}.done"
    
    # 用子 shell 包裹以捕获完成事件
    (
        START_EPOCH=$(date +%s)
        "${RUN_ARGS[@]}" >"$LOG_FILE" 2>&1
        EXIT_CODE=$?
        END_EPOCH=$(date +%s)
        {
            echo "finished_at=$(date '+%Y-%m-%d %H:%M:%S %z')"
            echo "duration_seconds=$((END_EPOCH - START_EPOCH))"
            echo "exit_code=${EXIT_CODE}"
            echo "log_file=${LOG_FILE}"
            echo "json_out=${OUTPUT_JSON}"
        } > "$DONE_FILE"
    ) &
    BG_PID=$!
    echo "$BG_PID" > "$PID_FILE"
    echo "[*] Background analysis started"
    echo "[*] PID      : $BG_PID"
    echo "[*] PID file : $PID_FILE"
    echo "[*] Done file: $DONE_FILE (检查此文件判断是否完成)"
    echo "[*] Log file : $LOG_FILE"
    echo "[*] Output   : $OUTPUT_JSON"
    exit 0
fi
```

### 5.3 seed 数据补 metadata

`data/seed_fingerprints.json` 里 libssl.so.3 的条目（如果有）或 libssl 入库时添加：

- `browser: "openssl_lib"`（特殊占位）
- `version: "3.x"`（粗粒度）
- `tls_lib: "openssl"`

**但如果你不打算把 libssl 作为正式 DB 条目**，则**不要修改 seed**，只在 `docs/known_baselines.md` 里说明"libssl.so.3 仅作 smoke 基线，不入库"。**我推荐后者**。

---

## 6. 文档更新

新增 `docs/relocation.md`：

```markdown
# Fingerprint Relocation

## 概念
小版本浏览器漂移时，利用已入库版本的指纹在新二进制上扫描重定位。
典型场景：chrome 143.0.7499.169 → 143.0.7499.192 的 hook RVA 偏移 <1MB。

## 使用
  tshunter.py relocate --binary <new.bin> --source-version <old.version>

## 原理
  1. DB 读 source 版本的 hook fingerprint
  2. 新 binary 的 .text 段扫前 20B
  3. 扩展 40B 二次校验 + 距离最近择优
  4. 4 个 hook 的 delta 一致则判 OK

## Verdict 三档
  - OK:      所有 hook 都 relocated 且 delta 一致 → 可直接用
  - PARTIAL: 部分成功或 delta 发散       → 建议完整分析
  - FAIL:    无命中                        → 必须完整分析

## 数据库溯源字段
  hook_points.relocation_method ∈ {ghidra_full, exact_scan, manual, imported}
  hook_points.derived_from_version_id → versions.id
  hook_points.rva_delta
  hook_points.relocation_confidence
```

---

## 7. 我的验收清单（Cursor 推完我检查）

### 7.1 文件存在性 + 语法

- [ ]  `tools/fingerprint_relocate.py` 存在、`python3 -c "import ast; ast.parse(open('...').read())"` 通过
- [ ]  `python3 tools/fingerprint_relocate.py --help` 显示 `scan` / `probe` 两个子命令
- [ ]  `tools/migrations/001_relocate_fields.sql` 存在
- [ ]  `tests/test_relocate.py` 存在
- [ ]  `integrated/` 目录已删除

### 7.2 Schema 正确

- [ ]  对空库：`sqlite3 new.db < tools/schema.sql` 零错误
- [ ]  对已有库：`sqlite3 existing.db < tools/migrations/001_relocate_fields.sql` 零错误
- [ ]  `PRAGMA table_info(hook_points);` 包含 `derived_from_version_id / rva_delta / relocation_method / relocation_confidence`

### 7.3 算法正确

- [ ]  `cd tests && pytest test_relocate.py -v` 全部通过
- [ ]  `test_shifted_match_small_drift` 明确验证 delta 一致性
- [ ]  `test_multi_hit_disambiguation_by_distance` 明确验证近优先

### 7.4 集成正确

- [ ]  `tshunter.py capture --help` 含 `--no-relocate / --force-relocate`
- [ ]  `tshunter.py relocate --help` 完整
- [ ]  `tshunter.py capture` 对 DB-miss + 有 source 场景打印 `[*] Searching relocation source...`
- [ ]  `run_binary_analysis.sh --background` 完成后写 `*_DONE` 文件

### 7.5 文档

- [ ]  `docs/relocation.md` 存在且提到 OK/PARTIAL/FAIL 三档
- [ ]  `README.md` 新增一节 "Fingerprint Relocation" 引用上面的文档

---

## 8. 你的测试顺序

Phase 4A 改完后，你按这个顺序测：

### Stage 1 — 静态单元测试（几分钟）

```bash
cd ~/TLSHunter
git pull
pip install -r requirements.txt
cd tests && pytest -v
# 期望：全部通过
```

### Stage 2 — CLI 冒烟（秒级）

```bash
python3 tshunter.py capture --help
python3 tshunter.py relocate --help
python3 tools/fingerprint_relocate.py --help
python3 tools/fingerprint_relocate.py probe \
    --binary TLSKeyHunter/binary/chrome \
    --fingerprint "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC" \
    --old-rva 0x048837E0 \
    --old-image-base 0x00100000
# 期望：即使 169 的 binary 就是 source 自身，能找到 exact_match (delta=0)
```

### Stage 3 — T1 DB hit（秒级）

```bash
# 前置：ingest 143.169 到 DB
rm -f data/fingerprints.db
sqlite3 data/fingerprints.db < tools/schema.sql
# 临时把 chrome_143.0.7499.169_linux_x86_64.json 的 meta 补全后 ingest
python3 tools/ingest.py --json chrome_143.0.7499.169_linux_x86_64.json \
    --browser chrome --version 143.0.7499.169 \
    --platform linux --arch x86_64 \
    --db data/fingerprints.db

# 然后 capture (期望 DB hit)
python3 tshunter.py capture \
    --binary TLSKeyHunter/binary/chrome \
    --browser chrome --version 143.0.7499.169 \
    --platform linux --arch x86_64 \
    --db data/fingerprints.db \
    --output /tmp/hooks_169.json
# 期望：秒级打印 "DB hit"，/tmp/hooks_169.json 含 4 个 hook
```

### Stage 4 — T2 完整分析（17h）

```bash
# 清库模拟未知版本
sqlite3 data/fingerprints.db \
    "UPDATE versions SET version='143.0.7499.999' WHERE version='143.0.7499.169';"

# 用 169 binary + 真实版本号发起 capture（DB 里没有 .169 了，只有 .999，major.minor=143.0 有候选）
python3 tshunter.py capture \
    --binary TLSKeyHunter/binary/chrome \
    --browser chrome --version 143.0.7499.169 \
    --platform linux --arch x86_64 \
    --db data/fingerprints.db \
    --no-relocate    # 强制走完整分析路径
# 期望：17h 后完成，DB 多一条 143.0.7499.169 (unverified, relocation_method=ghidra_full)
```

### Stage 5 — 回归比对

```bash
python3 run.py \
    --output results/chrome_143.0.7499.169_linux_x86_64.json \
    --compare chrome_143.0.7499.169_linux_x86_64.json
# 期望：PASS + All hook points match
```

### Stage 6 — T4 小版本偏移（你创新点的第一个实验）

需要下载 Chrome 143.0.7499.192 二进制，然后：

```bash
# DB 此时有 143.0.7499.169 verified
python3 tshunter.py capture \
    --binary /path/to/chrome_143.0.7499.192 \
    --browser chrome --version 143.0.7499.192 \
    --platform linux --arch x86_64 \
    --db data/fingerprints.db \
    --output /tmp/hooks_192.json
# 期望：
#   [*] DB miss: chrome 143.0.7499.192
#   [*] Searching relocation source in same major.minor...
#   [*] Found candidate: chrome 143.0.7499.169 (verified)
#   [*] Running fingerprint relocate...
#   [OK] Relocate verdict: OK
#        hooks relocated: 4/4
#        median delta: +0x????
#   [*] Auto-ingesting...
#   [✓] Complete. (relocation_method=exact_scan)
# 秒级完成，DB 新增 143.0.7499.192
```

### Stage 7 — Frida 实捕验证（你创新点的第二个实验）

```bash
# 用 /tmp/hooks_192.json 的 new_rva 去 Hook 实际跑的 Chrome 192
cd ~/p_t_c
python3 tls_capture.py \
    --hooks /tmp/hooks_192.json \
    --browser-binary /path/to/chrome_143.0.7499.192 \
    --duration 60 \
    --keylog-out /tmp/relocated_keylog.txt

# 对比 SSLKEYLOGFILE 基准
diff <(sort /tmp/relocated_keylog.txt) <(sort /tmp/sslkeylogfile_baseline.txt)
# 期望：捕获率 ≥ 95%，这就是论文创新点的核心数据
```

---

## 9. 一次性给 Cursor 的任务 prompt

建议直接贴给 Cursor：

```
请按以下任务书在分支 claude/tls-key-fingerprint-db-mdMIO 上做 Phase 4A:
[贴入本文 §1-§6 的完整内容]

约束:
- 不改 scripts/TLShunterAnalyzer.java 及其子模块 (Java 侧已冻结)
- 不改 ExtractKDFFingerprint.java 的 canonical fingerprint 规则
- 所有 Python 代码通过 pytest 测试 + mypy --strict (如已启用)
- 提交: git add -A && git commit -m "phase-4a: fingerprint relocation + schema migration + cleanup"
- 推送: git push -u origin claude/tls-key-fingerprint-db-mdMIO
- 不要跑 17h Ghidra 分析, 只做静态和 mock 测试

完成后在 PR 描述里:
1. 贴上 pytest 全绿输出
2. 列出 §7 验收清单逐条勾选
3. @claude 我做仓库侧验收
```

---

## 10. 时间估算

|阶段|估时|
|---|---|
|Cursor 完成 Phase 4A 代码|1–2 天|
|我做仓库验收（§7）+ 来回修|0.5 天|
|Stage 1–3 静态测试|1 小时|
|Stage 4 完整分析 169|17 小时|
|Stage 5 回归比对|10 分钟|
|并行：下载 192 + 升级 p_t_c|Stage 4 期间同时做|
|Stage 6 relocate 192|秒级|
|Stage 7 Frida 实捕|2 小时|
|**合计**|**~3.5 天工程 + 17h 等待**|

**创新点实证数据**在 Stage 7 完成时就有了。

---

有两个问题要你决策：

1. **libssl.so.3 入库策略**：纳入正式 DB（补 metadata）还是保留为独立 smoke 基线（`docs/known_baselines.md` 说明）？我倾向后者。
2. **下载 Chrome 143.192 的来源**：从 Google Storage 的 snapshot 拉还是从 `chrome_downloader.py`（p_t_c/tools 已有的工具）拉？建议后者，可以顺便测试 p_t_c 的升级。

等你确认后 Cursor 就可以开工。