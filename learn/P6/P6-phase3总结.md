# P6 Phase3 总结

本文档总结当前仓库相对 `learn/P6-Phase3数据库构建规划.md` 的实际落地情况、已验证结果、遗留问题与下一步建议。

---

## 一、总体进展结论

当前项目整体进度可概括为：

- **阶段 A：已完成**
- **阶段 B：已完成**
- **阶段 C：主体已完成，消费侧已补齐关键缺口**
- **阶段 D：前段最小闭环已实现**

也就是说，P6 Phase3 已经从“规划阶段”进入了“可实际跑通单次分析 + 入库 + 查询 + 最小闭环”的状态。

---

## 二、阶段 A 落地情况：通用化单二进制分析入口

### 已完成项

#### 1. `run.py` 已支持通用单二进制分析

当前已支持：

- `--binary`
- `--output`
- `--browser`
- `--version`
- `--platform`
- `--arch`
- `--tls-lib`
- `--image`
- `--rebuild`

这意味着分析入口已经从 Chrome 专用逻辑，扩展为可面向任意单一 ELF/PE/Mach-O 二进制。

#### 2. `run_binary_analysis.sh` 已成为通用 shell 入口

已实现：

- 通用参数解析
- metadata 透传
- `--image`/`--rebuild` 透传到底层 `run.py`
- `--background` 后台运行支持

#### 3. `run_chrome_analysis.sh` 已降级为 thin wrapper

当前 `run_chrome_analysis.sh` 只负责：

- 固定 Chrome 路径
- 固定 Chrome metadata
- 调用 `run_binary_analysis.sh`

这符合规划里“保留向后兼容 wrapper”的设计。

#### 4. 已去除绝对路径耦合

之前存在：

- `python3 "/home/palm/TLSHunter/run.py"`
- `ROOT_DIR="/home/palm/TLSHunter"`

现已改为基于脚本目录自动推导：

- `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`

这解决了：

- 换机器路径失效
- CI 环境不可复现
- 多人协作目录不同导致的错误

#### 5. `ghidra_analysis.sh` 已支持 `SELECT_BINARY`

容器内分析逻辑已实现：

- 优先读取 `SELECT_BINARY`
- 否则回退到扫描第一个支持的二进制

这与阶段 A 规划一致。

---

## 三、阶段 C 关键修复：Ghidra 脚本路径问题

### 现象

在 `libssl.so.3` 冒烟测试初期，出现：

- `No [RESULT] lines were parsed`
- `MinimalAnalysisOption.java` 找不到
- `TLShunterAnalyzer.java` 找不到

### 根因

不是分析逻辑错误，也不是正则解析错误，而是 **Ghidra 没有正确加载脚本目录**。

原先 `ghidra_analysis.sh` 使用多个 `-scriptPath` 参数，实际运行中 Ghidra 只识别到了最后一个路径，导致：

- `/usr/local/src` 未被正确扫描
- `MinimalAnalysisOption.java` 未加载
- `TLShunterAnalyzer.java` 未加载

### 修复

已改为单个合并路径参数：

- `/usr/local/src;/usr/local/src/common;/usr/local/src/stacks;/usr/local/src/detect`

### 修复结果

`libssl.so.3` 冒烟测试已成功输出 4 个 hook：

- `HKDF`
- `SSL_LOG_SECRET`
- `PRF`
- `KEY_EXPANSION`

说明 Java 分析脚本链路已打通。

---

## 四、阶段 C 落地情况：TLS 栈模块化

### Java 侧模块化结构已存在

当前 `scripts/` 已具备完整模块化结构：

- `scripts/TLShunterAnalyzer.java`
- `scripts/common/`
  - `FingerprintExtractor.java`
  - `FunctionRef.java`
  - `ResultEmitter.java`
  - `ResultRecord.java`
  - `StringXrefUtil.java`
- `scripts/detect/`
  - `TlsStackDetector.java`
- `scripts/stacks/`
  - `BoringSslAnalyzer.java`
  - `OpenSslAnalyzer.java`
  - `NssAnalyzer.java`
  - `RustlsAnalyzer.java`
  - `StackAnalyzer.java`
  - `UnknownTlsAnalyzer.java`

这说明阶段 C 的 Java 主体已经不是“待实现”，而是**已经完成结构化拆分**。

### Python 消费侧已补齐

为匹配阶段 C 的输出，`run.py` 已补上：

- `[DETECT] stack=... confidence=...` 解析
- `tls_lib_detected`
- `tls_lib_confidence`
- `image_base`
- `binary_sha256`
- `binary_size`
- `analysis_tool`
- `analyzer_version`

这使 `run.py` 不再停留在旧的 phase2 输出模型，而能够消费模块化分析器的附加元数据。

---

## 五、阶段 B 落地情况：SQLite 指纹数据库

### 已完成项

当前仓库中已存在：

- `tools/schema.sql`
- `tools/ingest.py`
- `tools/query.py`
- `data/seed_fingerprints.json`

说明阶段 B 的主要构件已经齐全。

### `tools/schema.sql`

已包含核心表：

- `tls_stacks`
- `browsers`
- `versions`
- `hook_points`
- `analyzer_runs`
- `capture_sessions`

并包含关键索引：

- `idx_hook_fp_prefix`
- `idx_hook_kind`
- `idx_versions_browser`

### `tools/ingest.py`

已支持：

- `--json`
- `--batch`
- `--legacy`
- `--upsert`
- 从 `meta` 或 CLI 填充 `browser/version/platform/arch`
- 自动计算 `fingerprint_prefix20`
- 写入 `analyzer_runs`

### `tools/query.py`

已支持：

- 精确版本查询
- 指纹前缀查询
- major.minor 查询
- Frida 格式输出
- 数据库报告输出

### 现状判断

阶段 B 已不是“规划中”，而是**基本可用**。

---

## 六、阶段 D 前段：最小闭环已实现

### 新增入口

已新增：

- `tshunter.py`

### 当前已实现子命令

- `tshunter.py capture`

### 最小闭环行为

#### 1. 先查 DB
按以下维度查询：

- `browser`
- `version`
- `platform`
- `arch`

#### 2. 如果 DB hit
直接输出 hooks，并可导出 Frida 配置。

#### 3. 如果 DB miss
自动执行：

1. 调用 `run.py`
2. 产出结果 JSON
3. 调用 `tools/ingest.py`
4. 写入 SQLite
5. 再查数据库
6. 输出 hooks

### 当前边界

为了保持“最小闭环”，当前**尚未实现**：

- 二进制内 fingerprint 快速验证
- DB hit 但 fingerprint 校验失败时自动 fallback
- `verify` 子命令
- `forensic` 子命令
- 更复杂的 staging/缓存策略

这部分属于阶段 D 后续增强项。

---

## 七、本轮实际验证结果

### 1. `libssl.so.3` 冒烟分析已成功

执行：

```bash
python3 run.py \
  --binary smoke_test/binary/libssl.so.3 \
  --output smoke_test/results/libssl.so.3.json \
  --platform linux \
  --arch x86_64 \
  --rebuild
```

成功输出：

- `HKDF: 0x0004F1E0`
- `SSL_LOG_SECRET: 0x0003B6E0`
- `PRF: 0x00045A80`
- `KEY_EXPANSION: 0x000456D0`

说明：

- Docker 构建/运行链路正常
- Ghidra 脚本加载正常
- Java 模块化分析器已能实际产出 `[RESULT]`
- `run.py` 的结果解析链路正常

### 2. 结果已固化为基线文件

已新增：

- `libssl.so.3_linux_x86_64.json`

作为当前 OpenSSL 样本分析结果的稳定基线。

### 3. `TLSKeyHunter/ground_truth` 当前不能直接 compare

原因不是 compare 逻辑缺失，而是 `TLSKeyHunter/ground_truth` 目录中目前缺少可直接用于 `run.py --compare` 的标准化 JSON 基线。

当前该目录更偏向：

- 源码资产
- 编译样本
- ground truth 原始材料

而不是可直接喂给 compare 的标准结果库。

---

## 八、当前未完成项 / 风险点

### 1. `tshunter.py capture` 仍是最小版

还没有实现：

- fingerprint in binary 校验
- DB hit 校验失败后的自动重分析
- `verify` 标记流程
- `forensic` 扩展

### 2. compare 基线资产仍不统一

虽然项目已有：

- `chrome_143.0.7499.169_linux_x86_64.json`
- `results/143_auto.json`
- `libssl.so.3_linux_x86_64.json`

但尚未形成统一的“可 compare 基线目录规范”。

### 3. 部分新基线尚缺完整 metadata

例如 `libssl.so.3_linux_x86_64.json` 当前尚无：

- `browser`
- `version`

因此可作为样本结果基线，但暂不适合作为标准 DB 版本记录直接入库。

---

## 九、相对规划文档的阶段判断

### 当前最准确的判断

- 阶段 A：完成
- 阶段 B：完成
- 阶段 C：完成主体并已打通消费侧
- 阶段 D：已实现前段最小闭环，**可以进入真实长跑回归测试**

换句话说，当前已不是“是否开始做 Phase3”的问题，而是：

> **Phase3 的核心骨架已经立起来了，现在应进入阶段 D 的真实回归与迭代完善。**

---

## 十、建议的下一步

### 短期建议（回归前）

1. 使用 `tshunter.py capture` 作为统一入口跑 Chrome 长跑分析
2. 明确本次回归是验证：
   - DB miss 分支
   - 分析成功后自动 ingest
   - hooks 导出成功
3. 观察生成：
   - `results/chrome_143.0.7499.169_linux_x86_64.json`
   - `data/fingerprints.db`
   - Frida hooks 输出文件

### 中期建议（回归后）

1. 给 `tshunter.py` 增加 fingerprint 校验路径
2. 增加 `verify` 子命令
3. 整理统一的 compare baseline 目录
4. 把 `libssl.so.3` 这类样本结果补齐 metadata 后纳入可管理资产

---

## 十一、总结

P6 Phase3 当前已经完成了从规划到可运行骨架的跃迁：

- 单二进制分析入口已通用化
- Ghidra 模块化分析器已能实际运行
- SQLite 指纹数据库已具备入库与查询能力
- 最小端到端闭环 `tshunter.py capture` 已落地
- 关键基础设施问题（脚本路径、绝对路径耦合、metadata 透传）已修复

因此，当前最重要的工作已经不是继续堆规划，而是：

> **进入真实 Chrome 长跑回归，验证阶段 D 的第一版闭环在真实长耗时分析场景下是否稳定。**

