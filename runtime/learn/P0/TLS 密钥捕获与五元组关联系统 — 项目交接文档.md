## 一、项目概述（一段话版本）

本项目基于 TLSKeyHunter 论文（Baier & Lambertz, DFRWS APAC 2025），构建一套多浏览器 TLS 密钥自动捕获与网络五元组关联系统。核心思路：离线对各版本浏览器二进制进行静态分析（Ghidra），提取密钥派生函数（PRF/HKDF/ssl_log_secret）的字节指纹和 RVA，构建持久化指纹数据库。运行时通过精确版本号命中数据库直接 Hook（零延迟），或回退至大版本指纹内存扫描。使用 Frida+eBPF 混合架构进行密钥捕获+TCP 五元组关联，输出可直接导入 Wireshark 的带五元组注释 NSS Key Log 格式文件。

---

## 二、必须给新 AI 的核心文件清单（按优先级排序）

### 第一优先级：项目总览 + 当前状态

| 文件                            | 内容                                               | 为什么必须给                         |
| ----------------------------- | ------------------------------------------------ | ------------------------------ |
| **项目阶段性总结_2026-03-28.md**     | P1-P5 全量 Hook 点、RVA、指纹、参数布局、结构体偏移、已验证数据、bug 修复记录 | **最关键的单文件**，包含了所有已确认的技术参数和关键教训 |
| **P6_execution_plan_v2.md**   | P6 阶段规划：ssl_log_secret 集成 + 多版本数据库构建             | 了解当前阶段目标                       |
| **P6_Phase2_revised_plan.md** | P6 Phase 2 修订版：整合分析工具 + 批量分析 + 数据库 Schema        | 了解正在执行的具体计划（Step A-D）          |
|                               |                                                  |                                |

### 第二优先级：TLShunter 整合项目（当前正在进行的工作）

| 文件                                      | 内容                                                | 为什么必须给                           |
| --------------------------------------- | ------------------------------------------------- | -------------------------------- |
| **TLShunter_cursor_instructions.md**    | 整合项目的完整 5 阶段指令集（阶段 0-5）                           | 了解整合项目的完整设计意图和验收标准               |
| **阶段0.md**                              | 源码阅读分析：TLSKeyHunter vs BoringSecretHunter 对比、整合策略 | 了解为什么选择重写式整合                     |
| **阶段1.md**                              | 基础整合完成：统一 Ghidra 脚本 + Docker + run.py             | 了解当前代码结构                         |
| **阶段2.md**                              | PRF 修复（.rodata 回退 + 子串判定 + 交叉验证）                  | 了解 PRF 修复的具体实现                   |
| **ghidra_analysis.sh** + **Dockerfile** | 容器内执行脚本和镜像定义                                      | 了解运行环境（**注意：需要加 `-maxMem 16G`**） |
| **run_chrome_analysis.sh**              | 后台分析入口脚本                                          | 了解如何启动分析                         |

### 第三优先级：P6 Phase 1 验证记录

|文件|内容|为什么必须给|
|---|---|---|
|**T6.1_ssl_log_secret_参数探针验证.md**|ssl_log_secret 参数布局确认 + fd 恢复测试|了解参数顺序和 fd 可用性|
|**T6.2_第一阶段第一次测试判断总结.md**|ssl_log_secret 保守集成 3 轮测试|了解集成验证过程|
|**T6.2_第二阶段测试文档.md**|ssl_log_secret 的 client_random 路径确认|**关键发现**：ssl_log_secret 的 CR 路径与 HKDF 不同|

### 第四优先级：P5 架构文档

|文件|内容|为什么必须给|
|---|---|---|
|**T5.8_README_ARCHITECTURE.md**|完整系统架构：四层设计、模块职责、数据流|了解 tls_capture 工具的架构|
|**P5_execution_plan_v2.md**|P5 执行规划 + 版本配置模板说明|了解 JSON 配置格式|

### 第五优先级：历史调试记录（有问题时参考）

|文件|内容|何时需要|
|---|---|---|
|**比对.md**|TLSKeyHunter 运行日志 + PRF 失败原因分析 + 手动分析 JSON|PRF 相关问题时参考|
|**密钥验证.md**|P3 验证流程：diff 命令、Wireshark 验证步骤|需要验证密钥正确性时参考|
|**P4执行日志.md**|fd 偏移探测过程 + eBPF 环境搭建 + ssl_log_secret 定位|五元组关联或 fd 问题时参考|
|**daily_summary_T4.0.3.md**|ssl_st→rbio→fd 完整探测实验|结构体偏移相关问题时参考|
|**watchdog_v13.py**|P4 最终单文件版本（P5 模块化前的基线）|需要理解原始 Hook 逻辑时参考|

### 第六优先级：原始分析过程

|文件|内容|何时需要|
|---|---|---|
|**寻找chrome的HKDF函数过程.md**|Ghidra 逆向分析完整记录|需要理解如何手动定位函数时参考|
|**补充.md**|TLS 1.3 所有 label 的 XREF + 函数签名|需要查原始 Ghidra 数据时参考|
|**TLS密钥捕获技术实现与TLSKeyHu_2026.md**|P3 bug 排查全过程（client_random 偏移修正）|类似问题复现时参考|
|**tlskeyhunter.pdf**|原始论文|需要理解理论基础时参考|

---

## 三、交接 Prompt 模板

以下是给新 AI 的开场 prompt，可以直接复制使用：

---

> **背景**：我正在构建一个多浏览器 TLS 密钥自动捕获与五元组关联系统，基于 TLSKeyHunter 论文（DFRWS APAC 2025）。
> 
> **核心技术路线**：
> 
> 1. 离线用 Ghidra 分析浏览器二进制，通过 TLS 标签字符串（"master secret"/"c hs traffic" 等）的 XREF 定位密钥派生函数，提取字节指纹和 RVA
> 2. 构建覆盖多版本浏览器的指纹数据库（SQLite）
> 3. 运行时用 Frida Hook 密钥派生函数提取密钥 + eBPF 监听 connect() 做五元组关联
> 4. 输出 NSS Key Log 格式，支持 Wireshark 解密
> 
> **目标平台**：Linux x86-64，Chrome（BoringSSL），后续扩展 Firefox（NSS）/ Edge
> 
> **当前进度**：P1-P5 已完成（单版本 Chrome 143.x 自动化密钥捕获+五元组关联），P6 Phase 1 已完成（ssl_log_secret 集成，覆盖率 98.3%），**P6 Phase 2 正在进行**（TLShunter 整合项目阶段 3：对 Chrome 143.x 运行整合工具做 ground truth 回归验证）。
> 
> **当前卡点**：TLShunter Docker 容器运行 Ghidra headless 分析 Chrome 二进制时需要 `-maxMem 16G` 参数（已确认缺失导致 OOM exit 137），同时 Docker build 过程中下载 Ghidra 可能因网络问题超时，需要改用本地文件 COPY。
> 
> 请阅读以下文件了解项目全貌，然后协助我继续推进。

---

## 四、关键技术参数速查表（新 AI 必须知道的）


```text
Chrome 版本：143.0.7499.169 (Linux x86-64)BoringSSL commit：992dfa0b56f98b8decaf82cd8df44aa714675d99Ghidra imageBase：0x00100000=== Hook 点 ===HKDF (TLS 1.3):       RVA=0x048837E0  指纹=55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC 98 00 00 00...PRF (TLS 1.2):         RVA=0x0A22D4B0  指纹=55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 58...key_expansion:         RVA=0x0A22D130ssl_log_secret:        RVA=0x04883520  指纹=55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 48 48 8B 47...=== 参数布局（Frida args[] = 整数寄存器 RDI/RSI/RDX/RCX/R8/R9）===HKDF:           args[0]=ssl_ptr, args[1]=output_buf, args[3]=label, args[4]=label_lenPRF:            args[0]=ssl_ptr, args[1]=output_buf(48B master_secret)ssl_log_secret: args[0]=ssl_st*, args[1]=label_str, args[2]=secret_ptr, args[3]=secret_len=== client_random 读取路径（⚠️ 不同 Hook 点路径不同）===HKDF/PRF:       *(*(*(ssl_ptr) + 0x30) + 0x30)   // 三级解引用ssl_log_secret: *(*(ssl + 0x30) + 0x30)            // 两级解引用（args[0] 是真正的 ssl_st*）=== 结构体偏移 ===ssl_st.rbio:    ssl_ptr + 0x240bio_st.num(fd): BIO* + 0x03cfd 精确关联：   HKDF args[0] ≠ ssl_st*，故 fd=-1，搁置五元组关联：    时序关联（eBPF connect 事件），100% 命中率=== 已知限制 ===- Session Ticket/PSK 漏捕 ~2%（协议限制）- TLSKeyHunter PRF 自动识别对 Chrome 失败（子串+缺 .rodata 回退），整合项目阶段 2 已修复但未验证- Ghidra headless 分析 Chrome 需要 -maxMem 16G，耗时 10-20 小时
```

## 五、项目阶段全貌

```text
P1  ✅  逆向分析 Chrome，确认全量 Hook 点P2  ✅  TLSKeyHunter 交叉验证（HKDF 一致，PRF 失败已知）P3  ✅  Frida Hook + Wireshark 验证（96% 捕获率）P4  ✅  eBPF + 五元组关联（混合架构，718/718=100%）P5  ✅  模块化 CLI 工具（tls_capture.py）P6  🔄  Phase 1 ✅ ssl_log_secret 集成（98.3% 覆盖率）        Phase 2 🔄 TLShunter 整合项目（阶段 0-2 ✅，阶段 3 进行中：ground truth 回归）P7  ❌  指纹内存扫描 + 未知版本自动适配P8  ❌  多浏览器扩展（Firefox NSS / Edge）P9  ❌  GUI + 论文 + 开源发布
```

## 六、当前阻塞问题

1. **ghidra_analysis.sh 缺少 `-maxMem 16G`** → Ghidra OOM (exit 137)，已确认修复方法
2. **Docker build 下载 Ghidra 超时** → 需要手动下载或用代理，改 Dockerfile 用 `COPY` 本地文件
3. 以上两个问题解决后，阶段 3 运行预计 10-20 小时，完成后需与 ground truth 比对 4 个 Hook 点的 RVA 和指纹