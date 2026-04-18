## Context（为什么现在要做这件事）

项目整体目标是：基于 TLSKeyHunter + BoringSecretHunter 的逆向分析能力，为每个浏览器版本批量提取 `PRF / HKDF / key_expansion / ssl_log_secret` 的 RVA + 字节指纹，写入版本指纹数据库；运行时先按版本精确命中，命中失败时用指纹扫描做小版本回退；每条抓到的密钥再做五元组关联供事后取证。

P6 把两个之前分离的主线合并：

- **主线 A**：Chrome 多版本二进制采集 → 批量自动化分析 → 指纹数据库（替代当前"每版本一份 JSON"的手工扩展方式）
- **主线 B**：`ssl_log_secret` 集成到 Frida Hook 链路，解决 P5 遗留的 TLS 1.2 `CLIENT_RANDOM` 漏捕（79 条缺失）

当前进度：

- **主线 B（ssl_log_secret 集成）已基本完成**。三次测试确认 Hook 稳定，`*(ssl+0x30)+0x30` 路径读 `client_random` 已对齐 `SSLKEYLOGFILE`，最终捕获率 692/704 ≈ **98.3%**，剩余 12 条为 PSK/Session Ticket 复用 + attach 窗口问题（已标记为 known limitation）。
- **主线 A** 推进到 Phase 2 修订版 Step A/B：`TSHunter/integrated/` 已把 TLSKeyHunter + BoringSecretHunter 整合为单次 Ghidra headless 执行、统一 `[RESULT]` 输出、通过 `run.py` 生成 JSON。
- **最近一次运行**（`results/analysis.log` + `results/143_auto.json`，2026-04-18 完成）的结果需要与 ground truth 对齐后才能进入批量。

---

## 最新运行结果 vs Ground Truth — 关键发现

对照 `TLShunter_cursor_instructions.md` 中的 ground truth 与 `hooks/chrome_143.0.7499.169_linux_x86_64.json` 手动数据，`143_auto.json` 的状况是：

|Hook 点|Ground truth RVA|自动分析 RVA|状态|备注|
|---|---|---|---|---|
|HKDF|`0x048837E0`|`0x04EE8210`|❌ **不一致**|识别到了 wrapper 而非核心 `derive_secret`|
|PRF|`0x0A22D4B0`|`0x0A22D4B0`|✅ 一致|cross-validated 策略命中，note=`TLS 1.2 Unified PRF (cross-validated)`|
|key_expansion|`0x0A22D130`|`0x0A22D130`|✅ 一致|—|
|ssl_log_secret|`0x04883520`|`0x04883520`|✅ 一致|—|

**重要结论**：你一直担心的"PRF 识别失败"已经被 `identifyPRF()` 里的**双标签交叉验证**（`master secret` ∩ `extended master secret` XREF）**修好了**。真正阻挡批量自动化的不再是 PRF，而是 **HKDF 现在识别错了 wrapper**。

### HKDF 错在哪儿

`TLShunterAnalyzer.java::analyzeKdfLike()` 的实现是：

java

```java
List<FunctionRef> refs = findFunctionsUsingString("s hs traffic");
...
FunctionRef selected = refs.get(0);   // 直接取第一个，未做 wrapper 过滤
```

但 BoringSSL 里 `"s hs traffic"` 被多个层级引用：

- 外层：`derive_app_secrets` / `derive_handshake_secrets` 等 wrapper
- 内层：`derive_secret`（真正的核心 KDF）

wrapper 把 label 作为字符串常量传给 `derive_secret`，所以字符串 XREF 既指向 wrapper 又间接关联到核心 KDF。当前代码取 `refs.get(0)` 恰好拿到 wrapper（`FUN_04fe8210`，栈帧 0x198，fingerprint 第17字节为 `01`），而非 ground truth 的 `FUN_049837e0`（栈帧 0x98，第17字节为 `00`）。

两个函数序言高度相似，只在栈帧大小等细节上不同，所以 fingerprint 前 16 字节看起来"像对的"，但整体 155 字节与 ground truth 完全不同。

---

## 本轮 Plan 的执行范围（本次 plan 只做 Step 1 + Step 2）

### Step 1 — 修复 HKDF 识别（核心修复）

**目标**：让 `analyzeKdfLike("HKDF", ...)` 对 143.x 的自动分析返回核心 `derive_secret` (`0x048837E0`)，与 ground truth 一致，而不是 wrapper `0x04EE8210`。

**修改文件**（仅一个）：`TSHunter/integrated/scripts/TLShunterAnalyzer.java`（位于 TSHunter 仓库 `claude/tls-key-fingerprint-db-mdMIO` 分支）

**具体改动**：

1. 把当前 `analyzeKdfLike(String type, String needle)` 改造为接收**标签列表**的 `analyzeHkdfWithCrossValidation(List<String> needles)`，或者新增一个专用方法，保留 `analyzeKdfLike` 的通用签名以备他用。
2. 新方法的逻辑（完全对称 `identifyPRF()` 的设计）：

text

```text
   对 ["c hs traffic", "s hs traffic", "c ap traffic", "s ap traffic"] 每个标签：
     a) findAllStringsInReadonlyData(label)
     b) 对每个命中地址，getReferencingFunctions(addr)，累加进 funcsPerLabel[label]
   
   取 intersection = funcsPerLabel["c hs traffic"] ∩ ["s hs traffic"] ∩ ["c ap traffic"] ∩ ["s ap traffic"]
   若 intersection 非空 → pickBestFunctionByXrefs(intersection)，记为 HKDF，note="TLS 1.3 Derive-Secret (cross-validated)"
   若为空 → 取 2 个标签交集（"c hs traffic" ∩ "s hs traffic"），fallback note 记录
   再空 → 对所有候选 pickBestFunctionByXrefs 取入度最大的，note="(fallback)"
```

3. 把 `run()` 里对 HKDF 的调用从 `analyzeKdfLike("HKDF", "s hs traffic")` 替换为新的交叉验证方法。其他三个 Hook 点（SSL_LOG_SECRET / PRF / KEY_EXPANSION）保持不动——它们已验证正确。
4. 复用 `TLShunterAnalyzer.java` 里已有的 `findAllStringsInReadonlyData`、`getReferencingFunctions`、`pickBestFunctionByXrefs`、`emitResult`、`extractFingerprint` —— 不要新建重复基础设施。
5. 不改 `run.py`、`Dockerfile`、`ghidra_analysis.sh`、`run_chrome_analysis.sh`，不新建文件。

### Step 2 — 回归验证（~20 小时 Ghidra，自动等待）

1. 在 TSHunter 仓库 commit + push `claude/tls-key-fingerprint-db-mdMIO` 分支，并创建 draft PR。
2. 提示你在本机运行：

bash

```bash
   bash run_chrome_analysis.sh        # 后台约 20h
   tail -f results/chrome_analysis_*.log
   cat results/ANALYSIS_DONE
```

3. 跑完后执行比对：

bash

```bash
   python3 integrated/run.py \
     --output results/143_auto.json \
     --compare <ground truth json>
```

4. **本轮 plan 到此结束**。通过标准：4 个 Hook 点全部 `rva exact and fingerprint first 20 bytes match`。

### 本轮不做（留给下一轮 plan）

- 批量分析其他已下载版本（130 / 140 / 142 / 149）
- 并行容器改造
- 指纹稳定性评估表扩展
- SQLite schema 设计与入库工具
- known_limitations.md 整理

这些都依赖"143.x 自动分析与 ground truth 一致"这个前提。确认 Step 2 通过后再启动下一轮 plan。

---

## 关键文件清单

|路径|作用|状态|
|---|---|---|
|`TSHunter/integrated/scripts/TLShunterAnalyzer.java`|统一 Ghidra 分析脚本|**待修 HKDF**|
|`TSHunter/integrated/run.py`|Python 入口，`--binary / --batch / --compare / --report`|已完成|
|`TSHunter/integrated/Dockerfile`|Ghidra 12.0.3 + JDK 21 分析容器|已完成|
|`TSHunter/integrated/ghidra_analysis.sh`|容器内 `analyzeHeadless` 包装|已完成|
|`TSHunter/run_chrome_analysis.sh`|宿主机后台启动器（worker 模式 + JSON 解析）|已完成|
|`TSHunter/results/143_auto.json`|最近一次 143.x 自动分析结果|⚠️ HKDF 字段错，其余 OK|
|`p_t_c/hooks/chrome_143.0.7499.169_linux_x86_64.json`|Ground truth（手动分析 + P3/P4 实测验证）|基准|

---

## 验证方式（端到端）

**本地编译检查**（可选，Java 脚本无独立编译步骤，Ghidra headless 会在 Docker 构建阶段报语法问题）：

- Docker 镜像 `tlshunter-integrated:phase2` 已存在时可跳过重新 build
- 第一次跑会重新 build Docker 镜像（约 3-5 分钟）

**最小回归**（你本地执行，我会在 PR 描述里写清楚）：

bash

```bash
# 1) 拉取修改后的分支
cd ~/TLSHunter   # 或你的 TSHunter 仓库本地路径
git fetch origin claude/tls-key-fingerprint-db-mdMIO
git checkout claude/tls-key-fingerprint-db-mdMIO

# 2) 重建 Docker 镜像（Java 源码变更，必须重建）
docker rmi tlshunter-integrated:phase2 || true

# 3) 后台启动分析
bash run_chrome_analysis.sh
echo "PID: $(cat results/chrome_analysis_*.pid)"

# 4) 监控
tail -f results/chrome_analysis_*.log

# 5) 完成后比对
cat results/ANALYSIS_DONE
python3 integrated/run.py \
  --output results/143_auto.json \
  --compare <path-to-chrome_143.0.7499.169_linux_x86_64.json>
```

**通过标准**：

- `analysis.log` 里出现 `[*] HKDF: 交叉验证命中 → FUN_049837e0`（或类似）
- `143_auto.json` 中 `hook_points.hkdf.rva == "0x048837E0"`
- `run.py --compare` 输出 `PASS compare ...` + 全部 4 点 `rva exact and fingerprint first 20 bytes match`

---

## 给你的几点想法 / 建议

1. **你当前的"PRF 识别失败"判断可能已经过时** — `identifyPRF()` 里双标签交叉验证已经让 143.x 的 PRF 成功命中。当前真正阻挡批量的是 HKDF。建议先把修复目标从 PRF 换到 HKDF（策略几乎可完全复用 PRF 的交叉验证）。
2. **HKDF 修好的同时最好也给 ssl_log_secret 加一道完整性校验**。当前 `findSslLogSecretCandidate` 用 `"EXPORTER_SECRET"` / `"CLIENT_RANDOM"` 搜索 + 查最近的 CALL，对 143.x 正好命中 `FUN_04983520`，但其他版本可能命中失败——建议在 Step 4 评估表里专门列出 ssl_log_secret 的跨版本命中情况，若有版本失败则准备备选策略。
3. **Phase 1（ssl_log_secret 漏补）的 12 条缺失现在被框为"结构性漏捕"** — 建议在正式进入批量前，简要把这 12 条的 root cause（PSK/Session Ticket + attach 窗口）写进 `known_limitations.md`，避免后续多版本测试把这 12 条再当新 bug 查一遍。
4. **Ghidra 分析 20h/版本是真瓶颈**。5 个版本串行就是 100 小时。如果你的机器 RAM ≥ 32GB，建议把 `run_chrome_analysis.sh` 改造成支持多容器并行（每容器 ~8GB），可压到 25 小时。
5. **五元组关联的目标已基本满足**（Phase 1 的 119×5 + 67 条导出 100% 五元组命中），P6 阶段不必再动这条链路，重心应放在版本数据库扩展上。