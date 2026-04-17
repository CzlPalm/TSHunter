# TLShunter 整合指令集

> 本文件是给 Cursor AI 的分步指令。请严格按顺序执行每个阶段，每完成一个阶段后暂停，向用户汇报结果并等待确认后再继续下一阶段。

---

## 背景

本项目要整合两个开源 Ghidra 分析工具：

1. **TLSKeyHunter** (https://github.com/monkeywave/TLSKeyHunter)
   - 功能：定位 TLS 库中的 HKDF 和 PRF 密钥派生函数，提取字节指纹和 RVA
   - 核心文件：`TLSKeyHunter.java`（Ghidra 脚本）
   - 运行方式：Docker + Ghidra headless
   - 已知问题：PRF 识别对 Chrome/BoringSSL 失败（子串问题 + 缺 .rodata 回退）

2. **BoringSecretHunter** (https://github.com/monkeywave/BoringSecretHunter)
   - 功能：定位 BoringSSL 中的 `ssl_log_secret()` 函数，提取字节指纹和 RVA
   - 核心文件：也是 Ghidra Java 脚本
   - 运行方式：Docker + Ghidra headless，另有 pip 安装方式
   - 特点：支持 ELF/PE/MachO/APK/IPA 多格式输入

**整合目标**：产出一个统一项目 `TLShunter`，对一个 Chrome 二进制文件一次 Ghidra 分析，输出以下全部 Hook 点的 RVA + 字节指纹：
- HKDF（TLS 1.3 Derive-Secret）
- PRF（TLS 1.2 master secret 派生）— 修复当前失败问题
- key_expansion（TLS 1.2 key block 派生）
- ssl_log_secret（NSS keylog 输出函数）

**最终输出格式**：JSON 文件，与以下模板兼容（见本仓库 `hooks/chrome_143.0.7499.169_linux_x86_64.json`）

两个源项目都在本仓库的 `TLShunter/` 目录下，分别位于 `TLShunter/TLSKeyHunter/` 和 `TLShunter/BoringSecretHunter/`。

---

## 阶段 0：阅读源码，建立理解

### 指令 0.1：阅读 TLSKeyHunter 核心代码

请完整阅读以下文件，理解其架构：

```
TLShunter/TLSKeyHunter/TLSKeyHunter.java
TLShunter/TLSKeyHunter/Dockerfile
TLShunter/TLSKeyHunter/ghidra_analysis.sh
TLShunter/TLSKeyHunter/MinimalAnalysisOption.java
```

重点理解并记录：
1. HKDF 识别流程：如何搜索 "s hs traffic" 字符串 → 如何回退到 .rodata 扫描 → 如何从 XREF 追溯到函数
2. PRF 识别流程：如何搜索 "master secret" 字符串 → 失败时的回退路径（注意：当前**没有** .rodata 回退）
3. 指纹提取逻辑：从函数入口开始提取字节，停止条件是什么
4. RVA 计算逻辑：如何处理 Ghidra imageBase
5. 输出格式：最终打印了什么信息（函数名、Ghidra 偏移、IDA 偏移、Frida 字节模式）

### 指令 0.2：阅读 BoringSecretHunter 核心代码

请完整阅读 BoringSecretHunter 的核心 Ghidra 脚本文件（在 `TLShunter/BoringSecretHunter/` 下找到主 `.java` 文件）。

重点理解并记录：
1. 如何定位 ssl_log_secret：搜索了什么字符串（如 "EXPORTER_SECRET"）？通过什么调用链追溯到目标函数？
2. 指纹提取逻辑：与 TLSKeyHunter 的方式相同还是不同？
3. 输出格式：打印了什么信息？
4. Docker 配置：与 TLSKeyHunter 的 Dockerfile 有何异同？

### 指令 0.3：对比分析，确定整合策略

基于阅读结果，回答以下问题（直接写在汇报中）：

1. 两个项目的 Ghidra 脚本在代码结构上有多少共享逻辑？（字符串搜索、XREF 追踪、指纹提取）
2. **哪个项目更适合作为基础项目被扩展？** 判断标准：
   - 代码组织更清晰
   - 字符串搜索 + XREF 追踪逻辑更健壮（特别是 .rodata 回退）
   - 更容易添加新的搜索目标
   - Docker/运行环境更完善
3. 推荐的整合方案是什么？给出具体理由。

**暂停点**：完成阶段 0 后，向用户汇报对比分析结果和推荐的整合策略，等待确认。

---

## 阶段 1：基础整合

### 指令 1.1：创建整合后的项目结构

在 `TLShunter/` 下创建新的整合项目（不修改原始两个项目目录）：

```
TLShunter/
├── TLSKeyHunter/          ← 原始项目，保持不动
├── BoringSecretHunter/    ← 原始项目，保持不动
├── integrated/            ← 新整合项目
│   ├── scripts/
│   │   └── TLShunterAnalyzer.java    ← 整合后的 Ghidra 脚本
│   ├── Dockerfile
│   ├── ghidra_analysis.sh
│   ├── run.py                         ← Python 入口（调用 Docker，解析输出）
│   └── README.md
```

### 指令 1.2：实现整合 Ghidra 脚本

以阶段 0 确定的基础项目为起点，将另一个项目的核心功能合并进来。

`TLShunterAnalyzer.java` 应该：

1. **单次执行，顺序完成所有分析**：
   - 先执行 HKDF 识别（来自 TLSKeyHunter 的逻辑）
   - 再执行 ssl_log_secret 识别（来自 BoringSecretHunter 的逻辑）
   - 再执行 PRF 识别（来自 TLSKeyHunter 的逻辑，暂时保持原始版本，修复在阶段 2）
   - 最后执行 key_expansion 识别（新增，逻辑类似 PRF）

2. **统一输出格式**：所有结果以一致的格式打印到控制台：
   ```
   [RESULT] type=HKDF function=FUN_049837e0 rva=0x048837E0 fingerprint=55 48 89 E5 ...
   [RESULT] type=SSL_LOG_SECRET function=FUN_04983520 rva=0x04883520 fingerprint=55 48 89 E5 ...
   [RESULT] type=PRF function=FUN_0a32d4b0 rva=0x0A22D4B0 fingerprint=55 48 89 E5 ...
   [RESULT] type=KEY_EXPANSION function=FUN_0a32d130 rva=0x0A22D130 fingerprint=55 48 89 E5 ...
   ```

3. **共享基础设施**：字符串搜索、XREF 查找、指纹提取等通用逻辑抽取为共享方法

### 指令 1.3：实现 Docker 环境

合并两个项目的 Dockerfile，确保：
- 使用相同版本的 Ghidra
- 一次 `analyzeHeadless` 预处理 + 运行整合脚本
- 输入：`/usr/local/src/binaries/` 下的二进制文件
- 输出：控制台打印 `[RESULT]` 行 + `/host_output/` 下的 JSON 文件

### 指令 1.4：实现 Python 入口脚本

`run.py` 负责：
1. 调用 Docker 运行分析
2. 解析控制台输出中的 `[RESULT]` 行
3. 组装成与 `hooks/chrome_*.json` 兼容的 JSON 格式
4. 写入输出文件

```bash
# 用法
python3 TLShunter/integrated/run.py \
  --binary artifacts/chrome/143.0.7499.169/chrome \
  --output results/143.0.7499.169.json
```

**暂停点**：完成阶段 1 后，向用户汇报整合结果。此时 PRF 对 Chrome 仍然会失败，这是预期的，将在阶段 2 修复。

---

## 阶段 2：修复 PRF 识别

### 指令 2.1：理解 PRF 失败的根因

从项目文档中获取的诊断信息（不需要你重新分析，直接采用）：

**失败原因 1：缺少 .rodata 字节模式回退**
- HKDF 识别有 `.rodata` 十六进制模式扫描回退路径（这是 HKDF 在 Chrome 上成功的原因）
- PRF 识别没有这个回退，直接字符串搜索失败后就放弃了

**失败原因 2："master secret" 是 "extended master secret" 的子串**
- 在 Chrome 的 .rodata 中，"extended master secret" 在地址 `0x019091a5`，"master secret" 紧随其后在 `0x019091ae`
- `0x019091ae` 实际上是 "extended master secret" 字符串内部的偏移 +9 处
- 搜索 "master secret" 时可能命中子串位置，导致 XREF 追踪失败

**失败原因 3：新版 BoringSSL 的 PRF 函数有 14 个参数（含 XMM 寄存器）**
- TLSKeyHunter 的 wrapper 检测启发式可能将其误判为 wrapper 函数
指令 2.1：升级 findStringInReadonlyData 为返回所有命中
将当前方法拆分为两个版本：
java// 保留原方法作为兼容接口（HKDF/ssl_log_secret 继续用它）
private Address findStringInReadonlyData(String target) {
    List<Address> all = findAllStringsInReadonlyData(target);
    return all.isEmpty() ? null : all.get(0);
}

// 新增：返回所有命中位置
private List<Address> findAllStringsInReadonlyData(String target) {
    List<Address> results = new ArrayList<>();
    Memory memory = currentProgram.getMemory();
    byte[] needle = target.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    byte[] needleWithNull = appendByte(needle, (byte) 0x00);

    for (MemoryBlock block : getReadonlyDataBlocks()) {
        // 优先搜带 \0 终止符的（独立字符串）
        findAllPatternInBlock(memory, block, needleWithNull, results);
    }
    if (!results.isEmpty()) {
        return results;
    }
    // 回退：不带 \0
    for (MemoryBlock block : getReadonlyDataBlocks()) {
        findAllPatternInBlock(memory, block, needle, results);
    }
    return results;
}

// 新增：在一个 block 中找出所有命中位置
private void findAllPatternInBlock(Memory memory, MemoryBlock block,
                                    byte[] pattern, List<Address> results) {
    Address current = block.getStart();
    Address end = block.getEnd();
    try {
        while (current.compareTo(end) <= 0) {
            byte[] bytes = new byte[pattern.length];
            int read = memory.getBytes(current, bytes);
            if (read == pattern.length && matches(bytes, pattern)) {
                results.add(current);
                current = current.add(pattern.length); // 跳过已命中区域
            } else {
                current = current.add(1);
            }
        }
    } catch (Exception ex) {
        // 到达内存边界
    }
}

### 指令 2.2：实现 .rodata 回退

在 `TLShunterAnalyzer.java` 的 PRF 识别流程中，添加与 HKDF 相同的 .rodata 回退逻辑：

```
PRF 识别流程（修复后）：
1. 尝试直接字符串搜索 "master secret"
2. 如果失败 → 在 .rodata 段搜索字节模式 6D 61 73 74 65 72 20 73 65 63 72 65 74
3. 找到后 → 获取该地址的所有 XREF
4. 对每个 XREF → 追溯到所在函数 → 验证是否是 KDF 函数
5. 提取指纹
```
指令 2.2：新增独立字符串判定方法
java/**
 * 判断 addr 处的字符串是否是独立的（前一个字节是 \0 或位于段起始）
 * 用于排除 "master secret" 作为 "extended master secret" 子串的情况
 */
private boolean isStandaloneString(Address addr) {
    if (addr.getOffset() == 0) return true;
    try {
        Address prev = addr.subtract(1);
        byte prevByte = currentProgram.getMemory().getByte(prev);
        return prevByte == 0x00;
    } catch (Exception e) {
        return true; // 无法读取前一字节时保守认为独立
    }
}

### 指令 2.3：处理子串问题

在 .rodata 扫描中，需要区分独立的 "master secret" 和作为子串的 "master secret"：

**方法**：搜索 "master secret" 时，同时搜索 "extended master secret"。如果两者的 XREF 都指向同一个函数，那就是 Unified PRF（BoringSSL 的情况），直接确认。

具体逻辑：
1. 搜索 "master secret"（13 字节）在 .rodata 中的所有出现位置
2. 对每个命中位置，检查前一个字节是否是 `\0`（判断是否是独立字符串起始）
3. 同时搜索 "extended master secret"（22 字节）
4. 收集两组 XREF 指向的函数集合
5. 取并集中出现次数最多的函数作为 PRF 候选
指令 2.3：实现 PRF 识别的核心修复方法
替换当前 PRF 识别入口为以下逻辑：
javaprivate void identifyPRF() {
    println("[*] PRF: 开始识别...");

    // === 策略 1：双标签交叉验证（最高置信度）===
    List<Address> masterSecretAddrs = findAllStringsInReadonlyData("master secret");
    List<Address> extMasterSecretAddrs = findAllStringsInReadonlyData("extended master secret");

    Set<Function> msFuncs = new HashSet<>();
    Set<Function> emsFuncs = new HashSet<>();

    for (Address addr : masterSecretAddrs) {
        msFuncs.addAll(getReferencingFunctions(addr));
    }
    for (Address addr : extMasterSecretAddrs) {
        emsFuncs.addAll(getReferencingFunctions(addr));
    }

    // 取交集：同时被 "master secret" 和 "extended master secret" 引用的函数
    Set<Function> intersection = new HashSet<>(msFuncs);
    intersection.retainAll(emsFuncs);

    if (!intersection.isEmpty()) {
        // 高置信度命中——Unified PRF
        Function prfFunc = intersection.iterator().next();
        println("[*] PRF: 双标签交叉验证命中 → " + prfFunc.getName());
        emitResult("PRF", prfFunc, "TLS 1.2 Unified PRF (cross-validated)");
        return;
    }

    // === 策略 2：仅 "master secret" 独立字符串的 XREF ===
    for (Address addr : masterSecretAddrs) {
        if (isStandaloneString(addr)) {
            Set<Function> funcs = getReferencingFunctions(addr);
            if (!funcs.isEmpty()) {
                Function prfFunc = funcs.iterator().next();
                println("[*] PRF: 独立字符串 XREF 命中 → " + prfFunc.getName());
                emitResult("PRF", prfFunc, "TLS 1.2 PRF (standalone string XREF)");
                return;
            }
        }
    }

    // === 策略 3：所有 "master secret" 命中位置的 XREF，取非 wrapper 的 ===
    if (!msFuncs.isEmpty()) {
        // 按 XREF 数量排序，取引用最多的函数（更可能是真正的 KDF 而非 wrapper）
        Function best = msFuncs.stream()
            .max((a, b) -> countXrefsTo(a) - countXrefsTo(b))
            .orElse(null);
        if (best != null) {
            println("[*] PRF: fallback XREF 命中 → " + best.getName());
            emitResult("PRF", best, "TLS 1.2 PRF (fallback, may need verification)");
            return;
        }
    }

    println("[-] PRF: 所有策略均未命中");
}
其中 getReferencingFunctions 是从地址的所有 XREF 中收集引用它的函数的方法——这个应该在当前共享基础设施中已经存在，Cursor 检查一下签名是否匹配即可。

### 指令 2.4：放宽 wrapper 验证

对通过 .rodata XREF 找到的 PRF 候选函数，放宽 wrapper 判定条件：
- 不要因为参数数量多就判定为 wrapper
- 不要因为函数内部有字符串操作就判定为 wrapper（BoringSSL 的 Unified PRF 确实在内部处理 label 字符串）
- 核心判断标准改为：该函数是否调用了底层 HMAC/hash 函数（看是否有 CALL 指令调用较小的子函数）
指令 2.4：key_expansion 识别
javaprivate void identifyKeyExpansion() {
    println("[*] KEY_EXPANSION: 开始识别...");

    List<Address> addrs = findAllStringsInReadonlyData("key expansion");
    for (Address addr : addrs) {
        Set<Function> funcs = getReferencingFunctions(addr);
        for (Function f : funcs) {
            String note = "TLS 1.2 key block derivation";
            // 检查是否与 PRF 共享函数
            // （如果之前 PRF 已识别，可以比对函数地址）
            emitResult("KEY_EXPANSION", f, note);
            return;
        }
    }
    println("[-] KEY_EXPANSION: 未找到");
}

### 指令 2.5：添加 key_expansion 识别

逻辑与 PRF 类似，搜索 "key expansion" 字符串：
1. 在 .rodata 搜索 `6B 65 79 20 65 78 70 61 6E 73 69 6F 6E`（"key expansion"）
2. 找 XREF → 追溯到函数
3. 提取指纹
指令 2.5：验证要求
完成修改后，不要急着跑 Docker。先让 Cursor 做以下静态检查：

findAllStringsInReadonlyData("master secret") 和 findStringInReadonlyData("s hs traffic") 是否走同一套 getReadonlyDataBlocks() + searchForPattern() 基础设施——确保 HKDF 路径没被破坏
isStandaloneString() 对地址 0x019091ae 应返回 true（因为 0x019091ad 处是 "extended master secret" 的 \0 终止符），对 0x019091a5+9=0x019091ae 这个计算也是同一个地址——所以这个方法在这种特殊情况下天然正确
原有的 HKDF 和 ssl_log_secret 识别路径必须完全不变——它们仍然走 findStringInReadonlyData（单返回版本），行为不受影响

注意：在 BoringSSL 中，"key expansion" 可能与 "master secret" 指向不同的函数（key_expansion 函数独立于 PRF），也可能在 Unified PRF 内部使用。如果 XREF 指向的函数与 PRF 相同，在输出中标注 `"note": "shared with PRF"`。

**暂停点**：完成阶段 2 后，向用户汇报修复结果。此时应该能对 Chrome 143.x 成功识别 PRF 了。

---

## 阶段 3：回归验证

### 指令 3.1：对 Chrome 143.0.7499.169 运行整合工具

```bash
python3 TLShunter/integrated/run.py \
  --binary artifacts/chrome/143.0.7499.169/chrome \
  --output results/143_auto.json
```

### 指令 3.2：与 ground truth 比对

将自动分析结果与已验证的 ground truth 进行逐字段比对。

Ground truth 数据（来自项目已有的手动分析 + P3/P4 实测验证）：

```json
{
  "hkdf": {
    "rva": "0x048837E0",
    "fingerprint_first_32": "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC 98 00 00 00 4C 89 45 88 49 89 CC 49 89 D7 48 89 F3"
  },
  "prf": {
    "rva": "0x0A22D4B0",
    "fingerprint_first_20": "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 58 64 48 8B 04"
  },
  "key_expansion": {
    "rva": "0x0A22D130",
    "fingerprint_first_20": "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 58 4C 89 4D C0"
  },
  "ssl_log_secret": {
    "rva": "0x04883520",
    "fingerprint_first_20": "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 48 48 8B 47 68"
  }
}
```

比对要求：
- 所有 RVA **必须完全一致**
- 指纹前 20 字节 **必须完全一致**
- 指纹总长度可以不同（不同的停止条件策略），但不影响使用

### 指令 3.3：修复差异

如果有任何不一致，分析原因并修复。常见问题：
- imageBase 偏移计算错误（Ghidra 默认基址 vs ELF 实际加载地址）
- 指纹提取的停止条件差异
- .rodata 搜索命中了错误的字符串实例

**暂停点**：完成阶段 3 后，向用户汇报比对结果。只有全部一致才能继续。

---

## 阶段 4：输出格式完善

### 指令 4.1：完善 JSON 输出格式

确保 `run.py` 输出的 JSON 格式与 `hooks/chrome_143.0.7499.169_linux_x86_64.json` 完全兼容。

JSON 应包含以下顶层字段：
- `meta`：browser, version, platform, arch, tls_lib, analysis_date, analysis_tool
- `hook_points`：prf, key_expansion, hkdf, ssl_log_secret（每个含 rva, fingerprint, fingerprint_len, role）
- `tls13_label_map`：固定值，所有 BoringSSL 版本通用
- `tls13_key_len_offsets`：标记为 `"default_from": "143.0.7499.169"`，需运行时验证
- `client_random`：标记为 `"default_from": "143.0.7499.169"`，需运行时验证
- `struct_offsets`：标记为 `"default_from": "143.0.7499.169"`，需运行时验证
- `five_tuple_strategy`：固定值

其中 `tls13_label_map` 是 TLS 标准定义的固定映射，所有版本通用：
```json
{
  "c e traffic": "CLIENT_EARLY_TRAFFIC_SECRET",
  "c hs traffic": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
  "s hs traffic": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
  "c ap traffic": "CLIENT_TRAFFIC_SECRET_0",
  "s ap traffic": "SERVER_TRAFFIC_SECRET_0",
  "exp master": "EXPORTER_SECRET"
}
```

### 指令 4.2：添加批量分析支持

在 `run.py` 中添加 `--batch` 模式：

```bash
# 批量分析所有已下载版本
python3 TLShunter/integrated/run.py \
  --batch artifacts/chrome/ \
  --output-dir results/
```

逻辑：
1. 扫描输入目录下所有包含 `chrome` 二进制的子目录
2. 跳过已有结果的版本（`results/{version}.json` 已存在）
3. 依次分析每个版本
4. 输出汇总统计

### 指令 4.3：添加指纹稳定性报告生成

在 `run.py` 中添加 `--report` 模式：

```bash
python3 TLShunter/integrated/run.py \
  --report results/ \
  --output results/fingerprint_stability_report.md
```

读取所有已分析版本的 JSON，生成 Markdown 对比表：

```markdown
| Version | HKDF RVA | HKDF FP[0:20] | PRF RVA | ssl_log RVA | FP Changed? |
|---------|----------|--------------|---------|-------------|-------------|
| 130.x   | ...      | ...          | ...     | ...         | baseline    |
| ...     | ...      | ...          | ...     | ...         | ...         |
```

**暂停点**：完成阶段 4 后，向用户汇报最终的项目结构和功能清单。

---

## 阶段 5：文档 + 收尾

### 指令 5.1：编写 README.md

覆盖：
- 项目用途
- 依赖（Docker、Ghidra 版本）
- 单版本分析用法
- 批量分析用法
- 输出格式说明
- 与 tls_capture.py 的对接方式
- 已知限制（PRF 修复的适用范围、分析耗时）

### 指令 5.2：清理代码

- 删除调试打印
- 添加必要注释
- 确保错误处理完善（二进制文件不存在、Ghidra 分析失败、字符串未找到等）

---

## 关键约束

1. **不要修改原始 TLSKeyHunter 和 BoringSecretHunter 目录**——它们作为参考保留
2. **Ghidra 脚本必须是 Java**——这是 Ghidra headless 模式的要求
3. **输出 JSON 必须与现有 `hooks/*.json` 格式兼容**——因为 `tls_capture.py` 的 `version_detect.py` 会消费这些文件
4. **imageBase 处理**——Chrome 的 ELF 文件 imageBase 通常是 `0x00100000`，RVA = Ghidra 地址 - imageBase。在输出中使用 IDA 格式（base 0x0 的偏移），即 `Function offset (IDA with base 0x0)`
5. **PRF 修复是核心任务**——如果 HKDF 和 ssl_log_secret 能工作但 PRF 不能，整个阶段 2 就不算完成
