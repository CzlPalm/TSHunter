## 一、三方提取逻辑差异（代码级）

|维度|① TLSKeyHunter `getLengthUntilBranch` (64-bit path)|② BoringSecretHunter `getLengthUntilBranch`|③ 当前 TLShunterAnalyzer `getLengthUntilStop`|
|---|---|---|---|
|CALL 行为|**遇到即停**（含 CALL 本身字节）|**遇到即停**（若 CALL 目标在函数内且偏移<10B 视为 PIC thunk，跳过；其它情形即停）|若 CALL 目标在函数 body 内则继续，否则**停**|
|JMP / Jcc 行为|遇到即停（含字节）|同 CALL 规则（允许 <10B 内部短跳）|目标在函数 body 内则继续，否则停|
|兜底长度|前缀无任何 branch 返回 `(length, null)`；上层有特殊 `-42/-43/-44` 异常码回切 wrapper|无 branch 返回 `-42`，上层尝试 `getFirstCaller()`|未遇到 stop → `min(length, 64)`|
|输出格式|`"%02X "` 空格分隔，`.trim()`|同上|`"%02X"` 中间空格（等价）|
|PIC/thunk 适配|无|有 `<10B` 内部短跳过 + `call $+` 过滤|无明确处理|



对 `chrome_143.0.7499.169_linux_x86_64.json` 4 条 fingerprint 末尾反汇编：

|点|末尾字节|末尾指令|关键观察|
|---|---|---|---|
|`prf` (40B)|`... 0F 85 1A 01 00 00`|`JNZ rel32`|无 CALL，首个 Jcc 停|
|`key_expansion` (81B)|`... E8 37 02 00 00 · 84 C0 · 0F 84 CB 00 00 00`|`CALL; TEST; JZ rel32`|**CALL 穿过**，首个 Jcc 停|
|`hkdf` (106B)|`... E8 6E DB A5 FF · 84 C0 · 0F 84 C9 00 00 00`|`CALL; TEST; JZ rel32`|**CALL 穿过**，首个 Jcc 停|
|`ssl_log_secret` (34B)|`... 75 12`|`JNZ rel8`|无 CALL，首个 Jcc 停|

**唯一一致的规则**：

> 从函数入口线性累加字节。**CALL 不是停点**（字节全部计入）。在**第一个 JMP / Jcc**处停下，并**包含**该条跳转的完整字节。

—— 这就是手动 `ExtractKDFFingerprint.java` 的实际行为，跟三个脚本都**不完全一致**。三者最接近的是 ①TLSKeyHunter，但它把 CALL 当停点，所以在 HKDF/key_expansion 上比 ground truth 少约 11 字节（停在 `E8 xx xx xx xx`，没拿到后面的 `84 C0 0F 84 xx xx xx xx`）。

## 二次确认 — 源码比对

**`ExtractKDFFingerprint.java` 的停止规则**（63–82 行）：

```java
boolean isJump = mnemonic.startsWith("J")    // JZ, JNZ, JMP, JG, ...
              || mnemonic.equals("RET") || mnemonic.equals("RETN") || mnemonic.equals("RETF");
boolean isUnconditionalJump = mnemonic.equals("JMP");

if (isUnconditionalJump) {
    done = true;                                        // JMP 无条件停
} else if (isJump && totalBytes >= MIN_FINGERPRINT_BYTES) {
    done = true;                                        // 其它 J* / RET 需满足 ≥32 字节
}
```

**与我上一版方案的 diff：**

|维度|我上一版|ExtractKDFFingerprint.java (真值)|需修正|
|---|---|---|---|
|停点判定|`FlowType.isJump() / isConditional()`|**mnemonic 前缀 "J"** + 显式 RET 列表|✅ 改 mnemonic|
|最小长度保护|无|**32 字节下限**（JMP 除外）|✅ 加 MIN_FP=32|
|JMP 处理|同 Jcc|**不受 32B 下限约束，遇即停**|✅ 单独分支|
|RET 处理|走 FlowType|**显式枚举 RET/RETN/RETF** + 32B 下限|✅ 加|
|CALL|穿过|穿过|✓ 一致|

**ground truth 4 条回归自验**：

- PRF：40B 停在 JNZ（40 ≥ 32 ✓）
- key_expansion：81B 停在 JZ（走过 CALL+TEST，81 ≥ 32 ✓）
- hkdf：106B 停在 JZ（走过 CALL+TEST，106 ≥ 32 ✓）
- ssl_log_secret：34B 停在 JNZ rel8（34 ≥ 32 ✓ — 踩着下限）

全部自洽。**结论：以 `ExtractKDFFingerprint.java` 为权威模板**。

## 二、Cursor 应该执行的 Patch（修正版）

目标文件：`TSHunter/integrated/scripts/TLShunterAnalyzer.java`（分支 `claude/tls-key-fingerprint-db-mdMIO`）

**1) 把版本号改成 `0.5.0-fp-canonical`**

**2) 整体替换 `getLengthUntilStop(Function)` 方法体**为：

```java
    /**
     * Canonical fingerprint length policy — 1:1 mirror of
     * ExtractKDFFingerprint.java (the manual ground-truth tool).
     *
     * Rules:
     *   - Walk instructions linearly from function entry.
     *   - Bytes of each instruction are accumulated BEFORE the stop test,
     *     so the stopping instruction is included in the fingerprint.
     *   - CALL never stops (mnemonic starts with 'C', not matched).
     *   - JMP (unconditional) stops immediately, ignoring MIN_FP.
     *   - Any other mnemonic starting with 'J' (JZ/JNZ/JG/JLE/…) OR
     *     RET/RETN/RETF stops only if length >= MIN_FP (32 bytes).
     *   - Fall off function body → return accumulated length (capped).
     *   - MAX_CAP protects against pathological stop-less runs.
     *
     * Rationale: produced the P3/P4-validated fingerprints (96% capture,
     * 100% 5-tuple hit rate in chrome_143.0.7499.169 ground truth).
     */
    private int getLengthUntilStop(Function function) {
        final int MIN_FP = 32;
        final int MAX_CAP = 256;
        final int DEFAULT_ON_ERROR = 32;

        Listing listing = currentProgram.getListing();
        Address entry = function.getEntryPoint();
        Instruction instruction = listing.getInstructionAt(entry);
        if (instruction == null) {
            return DEFAULT_ON_ERROR;
        }

        int length = 0;
        while (instruction != null && function.getBody().contains(instruction.getAddress())) {
            length += instruction.getLength();

            String mnemonic = instruction.getMnemonicString().toUpperCase();
            boolean isJmpUncond = mnemonic.equals("JMP");
            boolean isBranchLike =
                   mnemonic.startsWith("J")
                || mnemonic.equals("RET")
                || mnemonic.equals("RETN")
                || mnemonic.equals("RETF");

            if (isJmpUncond) {
                return Math.min(length, MAX_CAP);
            }
            if (isBranchLike && length >= MIN_FP) {
                return Math.min(length, MAX_CAP);
            }
            if (length >= MAX_CAP) {
                return MAX_CAP;
            }

            instruction = instruction.getNext();
        }

        return length > 0 ? Math.min(length, MAX_CAP) : DEFAULT_ON_ERROR;
    }
```

**3) `extractFingerprint` 不动**（`%02X` 空格分隔、trimmed tail 已跟 `ExtractKDFFingerprint.java` 第 93 行 `hexBuilder.toString().trim()` 的输出格式一致）。

**通过标准**：对 `chrome_143.0.7499.169` 重跑 `run.py` 后，4 个 hook 的 `fingerprint` 和 `fingerprint_len` **逐字节等于** `p_t_c/hooks/chrome_143.0.7499.169_linux_x86_64.json` 的 ground truth。

---

## 三、项目整合：TSHunter 单仓化

## 三、项目整合方案（让 Cursor 执行）

### 3.1 现状盘点

```
TSHunter/  (仓库根)
├── BoringSecretHunter/    (269K  — 上游克隆，已被 integrated/ 吸收)
├── TLSKeyHunter/          (870M — 上游克隆 + 测试产物，已被吸收)
├── integrated/            ( 34K  — 真正的当前代码)
│   ├── scripts/TLShunterAnalyzer.java
│   ├── Dockerfile / ghidra_analysis.sh / run.py / README.md
├── smoke_test/            (682K)
├── learn/                 ( 58K)
├── results/               ( 11M)
├── run_chrome_analysis.sh / monitor_analysis.sh
└── TLShunter_cursor_instructions.md
```

### 3.2 目标布局（单一 TSHunter）

```
TSHunter/
├── README.md                      ← 合并 integrated/README.md + 项目总览
├── Dockerfile                     ← 从 integrated/ 上提
├── ghidra_analysis.sh             ← 从 integrated/ 上提
├── run.py                         ← 从 integrated/ 上提
├── run_chrome_analysis.sh         (保留)
├── monitor_analysis.sh            (保留)
├── custom_log4j.xml               ← 从 integrated/ 上提（若有）
├── scripts/
│   └── TLShunterAnalyzer.java     ← 从 integrated/scripts/ 上提（唯一分析脚本）
├── tools/
│   └── findBoringSSLLibsOnAndroid.py  ← 从 BoringSecretHunter/ 挑出的工具
├── docs/
│   ├── TLShunter_cursor_instructions.md   (原根目录同名文件移入)
│   ├── fingerprint_standard.md    ← 新增：记录本次统一的指纹规则（canonical）
│   ├── hkdf_identification.md     ← 新增：记录 HKDF next-CALL voting 策略
│   └── reference/                 ← 只保留关键上游算法说明
│       ├── TLSKeyHunter_README.md   (上游 TLSKeyHunter/README.md)
│       └── BoringSecretHunter_README.md (上游 README 摘要)
├── .gitignore                     (补充 results/, *.log, *.pid, .venv)
└── results/                       (保留目录，内容 gitignored)
```

### 3.3 删除清单（硬删，保留 git 历史中可追溯）

|路径|大小|理由|
|---|---|---|
|`BoringSecretHunter/`|269K|全部功能已被 `scripts/TLShunterAnalyzer.java` 中 `findSslLogSecretCandidate` + `findFirstCalledFunctionAfterReference` 吸收|
|`TLSKeyHunter/`|**870M**|PRF/HKDF 识别已在 integrated 用 cross-validation + next-CALL voting 重新实现；ground_truth(825M) 是上游测试二进制，不需要跟到我们仓库|
|`TLSKeyHunter/ground_truth/`|825M|**必须删**，否则仓库膨胀|
|`TLSKeyHunter/real_world_examples/`|45M|同上|
|`integrated/`|—|内容上提后目录删除|
|`smoke_test/`|682K|若 integrated 已覆盖，建议移入 `docs/reference/legacy_smoke_test/` 或直接删|

> **可选历史清理**：870M 的二进制样本还在 `.git/objects` 里。如果仓库要公开，用 `git filter-repo --path TLSKeyHunter/ground_truth --invert-paths` 清历史；否则只是 push/clone 慢，不影响功能。这一步要由你手工决策，我建议**先留，等验证通过再清**。

### 3.4 新增/修改的关键文件内容（让 Cursor 照做）

**`README.md`**（项目根，覆盖型）需包含：

- 项目目标：Chrome BoringSSL TLS 指纹数据库生成与运行时 Hook
- 核心能力一览：RVA+fingerprint 自动化提取（PRF / HKDF / key_expansion / ssl_log_secret）
- 快速开始：`bash run_chrome_analysis.sh` 流程
- 指纹规范指向 `docs/fingerprint_standard.md`
- 关键依赖：Ghidra 12.0.3 + JDK 21（via Docker）

**`docs/fingerprint_standard.md`**（新建，将本轮讨论固化下来）：

```markdown
# TSHunter Canonical Fingerprint Standard

## Stopping rule
- Linear walk from function entry.
- Each instruction's bytes are accumulated BEFORE the stop test
  → stopping instruction is INCLUDED in fingerprint.
- CALL passes through.
- JMP (unconditional) stops immediately.
- Any other J* / RET / RETN / RETF stops iff length >= MIN_FP (32 bytes).
- MAX_CAP = 256 bytes safety.

## Output format
- Uppercase hex, space-separated, no trailing space.
- Frida ByteArrayMatcher-compatible.

## Authority
Source of truth: `ExtractKDFFingerprint.java` (manual tool used for
ground-truth generation on chrome_143.0.7499.169).

## Implementation
`scripts/TLShunterAnalyzer.java :: getLengthUntilStop()` — 1:1 mirror.
```

**`Dockerfile` 调整**（因为文件位置从 `integrated/scripts/TLShunterAnalyzer.java` 变为 `scripts/TLShunterAnalyzer.java`）：

```dockerfile
# 原：COPY integrated/scripts/TLShunterAnalyzer.java /opt/ghidra_scripts/
# 改：
COPY scripts/TLShunterAnalyzer.java /opt/ghidra_scripts/
```

**`run.py` / `ghidra_analysis.sh` 里所有对 `integrated/` 的路径引用** 需同步去掉前缀，特别是：

- `docker build -f integrated/Dockerfile` → `docker build -f Dockerfile .`
- `integrated/scripts/...` → `scripts/...`

**`run_chrome_analysis.sh`** 里调用 `python3 integrated/run.py` → `python3 run.py`。

**`.gitignore`** 追加：

```
results/
*.log
*.pid
.venv/
__pycache__/
*.pyc
# 保留 results 目录但忽略内容
!results/.gitkeep
```

### 3.5 给 Cursor 的完整执行清单

```
切到分支 claude/tls-key-fingerprint-db-mdMIO，按顺序做：

A. 指纹标准（本轮讨论的核心修复）
  1. 修改 scripts/TLShunterAnalyzer.java（位置变更后）：
     a) VERSION → "0.5.0-fp-canonical"
     b) 整体替换 getLengthUntilStop 方法为上面给出的 canonical 版本
     c) 其它方法不动

B. 目录重组
  1. git mv integrated/Dockerfile ./Dockerfile
  2. git mv integrated/ghidra_analysis.sh ./ghidra_analysis.sh
  3. git mv integrated/run.py ./run.py
  4. git mv integrated/README.md docs/integrated_README.md  (后续合入 README.md)
  5. mkdir -p scripts docs/reference tools
  6. git mv integrated/scripts/TLShunterAnalyzer.java scripts/TLShunterAnalyzer.java
  7. git rm -r integrated/
  8. git mv TLSKeyHunter/README.md docs/reference/TLSKeyHunter_README.md
  9. git mv BoringSecretHunter/README.md docs/reference/BoringSecretHunter_README.md  (若有)
 10. git mv BoringSecretHunter/findBoringSSLLibsOnAndroid.py tools/findBoringSSLLibsOnAndroid.py
 11. git rm -r BoringSecretHunter/ TLSKeyHunter/
 12. (可选) git rm -r smoke_test/
 13. git mv TLShunter_cursor_instructions.md docs/TLShunter_cursor_instructions.md

C. 路径引用修正
  1. sed -i 's|integrated/||g' Dockerfile ghidra_analysis.sh run.py run_chrome_analysis.sh monitor_analysis.sh
     （完成后目视检查，Dockerfile 里的 COPY 路径要看清楚）
  2. 根目录新建 README.md（内容按 3.4 要求撰写）
  3. 新建 docs/fingerprint_standard.md、docs/hkdf_identification.md
  4. 更新 .gitignore 按 3.4

D. 本地自检
  1. docker build -f Dockerfile -t tlshunter:0.5.0 .
     （确保 COPY 路径全改对）
  2. python3 run.py --help   （import 路径无残留 integrated.x 即可）

E. 提交 & 推送
  1. git add -A
  2. git commit -m "refactor: consolidate into single TSHunter tree
     - fingerprint policy aligned with ExtractKDFFingerprint.java canonical rules
     - remove vendored BoringSecretHunter/ TLSKeyHunter/ (absorbed into scripts/)
     - flatten integrated/ contents to repo root
     - add docs/fingerprint_standard.md as single source of truth"
  3. git push -u origin claude/tls-key-fingerprint-db-mdMIO

F. 验证（~17-20h）
  1. 删除旧镜像：docker rmi tlshunter-integrated:phase2 tlshunter:0.5.0 || true
  2. bash run_chrome_analysis.sh
  3. 完成后对比 results/143_auto.json 与 p_t_c/hooks/chrome_143.0.7499.169_linux_x86_64.json
     通过标准：4 条 fingerprint 逐字节相等，fingerprint_len 相等
```