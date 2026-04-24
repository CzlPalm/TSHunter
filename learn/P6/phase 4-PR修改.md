# 出现的问题：
```bash
这次回归性测试得到的结果日志为： [_] DB miss: chrome 143.0.7499.169 linux/x86_64 [_] Running analyzer... [_] Wrote analysis JSON to /home/palm/TLSHunter/results/chrome_143.0.7499.169_linux_x86_64.json [!] No [RESULT] lines were parsed [_] Ingesting analysis result into database... [*] Imported 1 JSON file(s) into /home/palm/TLSHunter/data/fingerprints.db [✓] Analysis complete, inserted into DB as unverified. Version: chrome 143.0.7499.169 linux/x86_64 JSON: /home/palm/TLSHunter/results/chrome_143.0.7499.169_linux_x86_64.json DB: /home/palm/TLSHunter/data/fingerprints.db Hooks: /home/palm/TLSHunter/results/hooks_143.json 查看之前的results/143_auto.json 进行对比发现，缺少了函数说明，并且除了hkdf其它的密钥指纹均少了大半，这会影响hook和后面的小版本偏移测试
```

```bash
palm@palm-Dell-Pro-Tower-QCT1250:~/TLSHunter$ grep -c "[RESULT]" results/analysis.log 0 palm@palm-Dell-Pro-Tower-QCT1250:~/TLSHunter$ grep -E "[DETECT]|Selected:" results/analysis.log TLShunterAnalyzer.java> [_] Selected: boringssl (confidence=0.99) TLShunterAnalyzer.java> [DETECT] stack=boringssl confidence=0.99 palm@palm-Dell-Pro-Tower-QCT1250:~/TLSHunter$ grep -E "HKDF:|SSL_LOG_SECRET|PRF:|KEY_EXPANSION" results/analysis.log | head -30 TLShunterAnalyzer.java> [_] HKDF: 开始识别（next-CALL 投票策略）... TLShunterAnalyzer.java> [_] HKDF: label "c hs traffic" rodata hits = 1 TLShunterAnalyzer.java> [_] HKDF: label "s hs traffic" rodata hits = 1 TLShunterAnalyzer.java> [_] HKDF: label "c ap traffic" rodata hits = 1 TLShunterAnalyzer.java> [_] HKDF: label "s ap traffic" rodata hits = 1 TLShunterAnalyzer.java> [-] HKDF: 所有策略均未命中 TLShunterAnalyzer.java> [WARN] type=SSL_LOG_SECRET status=not_found TLShunterAnalyzer.java> [_] PRF: 开始识别... TLShunterAnalyzer.java> [-] PRF: 所有策略均未命中 TLShunterAnalyzer.java> [_] KEY_EXPANSION: 开始识别... TLShunterAnalyzer.java> [-] KEY_EXPANSION: 未找到 palm@palm-Dell-Pro-Tower-QCT1250:~/TLSHunter$ grep -iE "compile|error|exception|class.*not.*found" results/analysis.log /opt/ghidra_12.0.3_PUBLIC/Ghidra/Features/Decompiler/ghidra_scripts /opt/ghidra_12.0.3_PUBLIC/Ghidra/Features/DecompilerDependent/ghidra_scripts Using Language/Compiler: x86:LE:64:default:gcc GCC Exception Handlers 14.142 secs palm@palm-Dell-Pro-Tower-QCT1250:~/TLSHunter$ sqlite3 data/fingerprints.db <<EOF .headers on SELECT v.id, v.version, v.platform, v.arch, v.analyzer_version, v.analysis_date, COUNT(hp.id) AS hook_count FROM versions v LEFT JOIN hook_points hp ON hp.version_id = v.id GROUP BY v.id ORDER BY v.analysis_date; SELECT hp.version_id, hp.kind, hp.function_name, hp.rva, hp.relocation_method, hp.fingerprint_len FROM hook_points hp ORDER BY hp.version_id, hp.kind; EOF id|version|platform|arch|analyzer_version|analysis_date|hook_count 1|143.0.7499.169|linux|x86_64||2026-03-31|4 Parse error near line 6: no such column: hp.relocation_method on_id, hp.kind, hp.function_name, hp.rva, hp.relocation_method, hp.fin error here ---^ 
```
# 病根定位：`MinimalAnalysisOption.java` 禁用了建引用的分析器

## 一、核心病灶

看 `MinimalAnalysisOption.java` 第 30 行：

```java
disableIfPresent(options, SCALAR_OPERAND_ANALYZER);   // ← 元凶
disableIfPresent(options, DECOMPILER_SWITCH_ANALYSIS); // ← 帮凶
disableIfPresent(options, CONSTANT_PROPAGATION_ANALYSIS); // ← 帮凶
```

**"Scalar Operand References"** 分析器的职责就是：把 `LEA RAX, [RIP + 0x12345]` 这类指令里的标量偏移**识别成数据引用**，然后写进 ReferenceManager。

Chrome 143 是 **PIC 编译的 261MB 二进制**，所有字符串引用都是 RIP-relative scalar operand。你把这个分析器关了，Ghidra 就**压根没建立字符串 XREF**。

所以：

- ✅ 字节搜索能找到 `"c hs traffic"` 在 rodata 的位置（这走 Memory，不依赖 ReferenceManager）
- ❌ `refMgr.getReferencesTo(strAddr)` 返回 0（因为 REF 从没建）
- ❌ 4 个 identifier 全部返回空 → `analyze()` 返回空 list → `ResultEmitter` 一次 `[RESULT]` 都没 emit
- ❌ `run.py` 正则一条都没匹到 → "No [RESULT] lines were parsed"

**为什么 libssl.so.3 smoke test 能跑出 4 个 hook？**

- 小的 .so 文件：~1MB 的 libssl 里有 PLT / GOT 等更传统的引用形式，Ghidra 无需 Scalar Operand References 也能通过其它分析器（如 Data Reference Analyzer）把字符串 XREF 建起来。
- Chrome 是 **stripped + LTO + PIC + 261MB 单体二进制**，所有字符串引用只有 RIP-relative LEA 一种形式，**必须**靠 Scalar Operand References 才能识别。

## 二、为什么 `143_auto.json` (v0.4.0) 能跑出来（你可能疑惑）

那次跑的是**另一套 Ghidra 分析设置**，且 v0.4.0 代码里保留了一条 fallback：`findFunctionsUsingString()` 走 `Listing.getDefinedData()`（读已定义的 String 数据 + 其内置 XREF），不完全依赖 ReferenceManager。

你在 v0.6.0-modular 重构时，**把这条 fallback 从 BoringSslAnalyzer 里删了**，只剩纯 ReferenceManager 路径，所以对着 MinimalAnalysisOption 的"关 Scalar Operand"踩了个死角。

## 三、修复方案（给 Cursor 的最小补丁）

### 补丁 1：修 `MinimalAnalysisOption.java`（关键，秒改）

**删除 3 行**（即不再禁用它们）：

```java
// 删掉:
disableIfPresent(options, SCALAR_OPERAND_ANALYZER);
disableIfPresent(options, DECOMPILER_SWITCH_ANALYSIS);
disableIfPresent(options, CONSTANT_PROPAGATION_ANALYSIS);

// 保留 (这几个才是真 heavy、对我们没用):
disableIfPresent(options, FUNCTION_ID_ANALYZER);
disableIfPresent(options, LIBRARY_IDENTIFICATION);
disableIfPresent(options, DEMANGLER_MS_ANALYZER);   // Linux 二进制用不到
disableIfPresent(options, DEMANGLER_GNU_ANALYZER);
disableIfPresent(options, STACK_ANALYSIS);
disableIfPresent(options, DWARF_ANALYZER);
```

**代价**：分析时间可能从 17h 增加到 ~20–22h（多那 3 个分析器要跑），换来**正确性**。值。

### 补丁 2：BoringSslAnalyzer 加双路径 fallback（防御性加固）

在 `scripts/common/StringXrefUtil.java` 里补一个 `findDataRefsViaListing(String target)` 方法，优先走 Ghidra 的已定义字符串 Data iterator，空了再回退到字节搜索 + ReferenceManager：

```java
// StringXrefUtil.java 新增
public List<FunctionRef> findFunctionsUsingString(String target) {
    List<FunctionRef> matches = new ArrayList<>();
    Listing listing = script.getCurrentProgram().getListing();
    DataIterator dataIterator = listing.getDefinedData(true);
    while (dataIterator.hasNext()) {
        Data data = dataIterator.next();
        if (!"string".equalsIgnoreCase(data.getDataType().getName())) continue;
        Object value = data.getValue();
        if (value == null) continue;
        String s = value.toString();
        if (!target.equals(s)) continue;
        matches.addAll(collectReferencingFunctions(data.getAddress()));
    }
    return dedupe(matches);
}
```

然后 `BoringSslAnalyzer.identifyHKDF` 先调这个：

```java
for (String label : HKDF_TLS13_LABELS) {
    // 优先 Data iterator 路径（依赖 Ghidra 已定义的 string）
    List<FunctionRef> refsViaData = xrefs.findFunctionsUsingString(label);
    // 兼容路径：字节搜索（对 Data 没定义的情况）
    List<Address> addrs = xrefs.findAllStringsInReadonlyData(label);
    // 两路合并
    ...
}
```

这样即使将来 MinimalAnalysisOption 再被改错，也有第二条腿。

### 补丁 3：在 `ingest.py` / `tshunter.py` 加"空结果拒入库"护栏

参考我上次说的，防止"静默假成功"再出现：

```python
# ingest.py
if not hook_points:
    raise SystemExit(
        f"[FATAL] Refusing to ingest empty hook_points from {json_path}. "
        f"If analysis genuinely found nothing, pass --allow-empty."
    )

# tshunter.py capture 在 run_subprocess(run_cmd) 之后:
parsed = json.loads(result_json.read_text())
if not parsed.get("hook_points"):
    raise SystemExit(
        "[FATAL] Analysis produced empty hook_points — aborting capture flow. "
        "Check results/analysis.log for root cause."
    )
```

### 补丁 4：Phase 4A 的 schema migration 还要做（独立事项）

`hp.relocation_method` 字段不存在是因为我上次给你的 Phase 4A 任务书**还没让 Cursor 动工**。这跟本次 bug **独立**。你现在看到的 schema 是 A/B/C/D 阶段的版本。Phase 4A 可以等修完当前 bug 再做，**不阻塞**。


```
任务: 修复 Chrome 大二进制场景下 XREF 缺失导致 analyzer 吃空的严重 bug

改动:
1. MinimalAnalysisOption.java: 移除对 
   SCALAR_OPERAND_ANALYZER / DECOMPILER_SWITCH_ANALYSIS / CONSTANT_PROPAGATION_ANALYSIS 的禁用
2. scripts/common/StringXrefUtil.java: 新增 findFunctionsUsingString(String)，走 Ghidra Listing 
   Data iterator + 内置 XREF（文末完整签名见 Claude 建议）
3. scripts/stacks/BoringSslAnalyzer.java: identifyHKDF / analyzeSslLogSecret / identifyPRF / 
   identifyKeyExpansion 优先用 findFunctionsUsingString，失败再回退 findAllStringsInReadonlyData
4. tools/ingest.py: hook_points 为空时默认 raise SystemExit，除非 --allow-empty
5. tshunter.py: cmd_capture 在 run_subprocess 之后校验 JSON 的 hook_points 非空
```
将结果生成fix.md