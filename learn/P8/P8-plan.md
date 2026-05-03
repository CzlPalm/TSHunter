# TSHunter Agent 自动化总体计划草案

> 目标：在现有 TSHunter 批量分析能力基础上，构建一个“自动监听浏览器版本更新 → 下载二进制 → 静态分析 / relocate → 运行时验证 → 入库 → 用户监控与取证”的自动化系统。  
> 原则：**只面向授权环境、实验环境和取证环境，不做隐蔽采集，不绕过用户授权。**

## 0. 当前状态判断

根据你上传的计划，当前项目已经进入 **B1 批量分析阶段**，并且 B1 还在服务器上执行中。plan-2 中已经明确：B1 的目标是实现 `tshunter batch`，批量执行 `download → analyze/relocate → ingest`，并记录 `batch_jobs` 状态。plan-3 又补充了 B1 启动前的硬化清单，特别指出了 downloader 单源、PARTIAL relocate、磁盘清理、S1/S2 文档缺失等问题。

所以现在不能盲目进入下一阶段，需要根据 B1 结果分两种路径：

|B1 结果|后续路径|
|---|---|
|hook 成功率 ≥ 95%，批量入库稳定|进入 Agent 自动化系统设计与实现|
|hook 成功率 < 95%，或大量版本失败|暂停自动化，先做失败归因和 analyzer / relocate 修正|

---

# 1. B1 批量分析可能出现的问题预测

## 1.1 下载与版本源问题

|风险|表现|原因|处理建议|
|---|---|---|---|
|下载不到足够版本|每个 milestone 只有 1 个版本|只使用 CfT latest endpoint|改用 `known-good-versions-with-downloads.json`|
|下载的是 wrapper 不是真正 binary|Ghidra 分析结果为空或异常|`.deb` 解包路径不对|明确定位真实 `chrome` ELF|
|版本号与 binary 不匹配|DB 中 version 与实际二进制不一致|包名、metadata、browser 输出不一致|记录 `--version` 输出和 sha256|
|下载源失效 / 限速|batch 中途失败|官方源或 GitHub API 限制|加 mirror/cache/retry|

---

## 1.2 Relocate 问题

|风险|表现|原因|处理建议|
|---|---|---|---|
|大量 PARTIAL|169 → 192 已出现 PARTIAL|Chrome PGO / LTO 导致 delta 不一致|B1 层允许 `accept_partial`，但标记为 unverified|
|误匹配|hook RVA 错，Frida attach 失败或抓不到 key|fingerprint 太短或非唯一|必须要求 unique match + confidence|
|跨 minor relocate 失败|143 seed 不能推 144/145|代码布局变化较大|每个 milestone 至少一个 full analyze anchor|
|PARTIAL 污染数据库|未验证结果被运行时使用|verified 与 partial 状态不区分|partial 永远 `verified=0`，capture 默认拒绝|

---

## 1.3 Ghidra 分析问题

|风险|表现|原因|处理建议|
|---|---|---|---|
|0 hook 输出|JSON 空、ingest 失败|XREF / 字符串 / 分析选项异常|保留 F2 fail-fast，不允许静默入库|
|单版本耗时过长|17h 以上|服务器资源不足或 analyzer 卡住|加 timeout、日志心跳、任务状态|
|内存不足|Docker 被 kill|Chrome binary 大|限制并发，记录 OOM，增加 swap|
|某 hook 缺失|4 个 hook 不全|版本内部实现变化|降级为 partial_analyze，进入人工 review|

---

## 1.4 运行时验证问题

|风险|表现|原因|处理建议|
|---|---|---|---|
|hook 成功率低|Frida attach 成功但 keylog 不完整|RVA 错、参数错、read_on 错|对失败版本做 probe|
|SSLKEYLOGFILE 对比不一致|TSHunter key 与环境变量 key 不一致|QUIC、缓存连接、TLS 版本差异|验证时禁用 QUIC，清 profile|
|五元组命中率低|key 无法关联连接|eBPF 事件丢失或 NetworkService 进程变化|记录 pid/fd/time window，调大关联窗口|
|Chrome 进程模型变化|attach 到错误进程|NetworkService 进程变化|枚举 module + 进程名双重确认|

---

## 1.5 数据库与状态管理问题

|风险|表现|原因|处理建议|
|---|---|---|---|
|重复入库|同版本多条记录冲突|upsert 策略不一致|browser/version/platform/arch 唯一约束|
|migration 不一致|服务器 DB schema 缺字段|本地/服务器版本不同步|启动时自动检查 migrations|
|batch 中断不可恢复|任务跑一半丢状态|无 resume 或状态不完整|`batch_jobs` 必须记录阶段、错误、耗时|
|verified 语义混乱|partial 和 full analyze 混用|缺少信任等级|增加 `verified_status` / `confidence` / `source_method`|

---

# 2. B1 结果分支策略

## 分支 A：B1 顺利

条件：

|指标|阈值|
|---|---|
|每个版本 4 hook 齐全率|≥ 95%|
|Frida hook key 捕获率|≥ 95%|
|SSLKEYLOGFILE diff|通过|
|五元组命中率|≥ 95%|
|DB 入库失败率|≤ 5%|
|batch 可 resume|通过|

下一步：

```
进入 Agent 自动化系统设计与实现    ↓先做 Chrome 自动更新 agent    ↓再扩展 Firefox/NSS    ↓最后做前端监控与归档
```

---

## 分支 B：B1 出现问题

处理顺序：

```
先分类失败版本    ↓区分 download / relocate / analyze / ingest / capture / verify 问题    ↓优先修复批量共性问题    ↓再处理单版本特殊问题    ↓重新跑小范围 B1
```

建议不要在 B1 不稳定时直接做 Agent 自动化，否则会把“批量分析的不稳定性”放大成“自动化系统的不稳定性”。

---
# 3. Agent 自动化总体架构

你提出的六层设计方向是合理的，但我建议把它改成 **七层**，增加一个“任务编排层 / 状态层”。否则 agent、TSHunter、验证层、数据库层之间会互相耦合。

## 总体架构

```
数据源层  
 ↓
监听 / 采集 Agent 层  
 ↓
任务编排层
 ↓
TSHunter 分析层
  ↓
验证层
  ↓
数据库层
 ↓
用户监控与取证层
```



---
# 4. 各层详细设计

## 第一层：数据源层

### 目标

负责提供浏览器版本信息、安装包、二进制文件和元数据。

### 数据源

|浏览器|数据源|内容|
|---|---|---|
|Chrome|Chrome for Testing / Google apt repo|stable/canary/dev binary|
|Edge|Microsoft apt repo / 官方下载|edge binary|
|Firefox|Mozilla release / apt / GitHub mirror|firefox + libssl3.so/libnss3.so|
|Electron|GitHub Releases|electron binary|
|Chromium|snapshots|高频 dev build，可选|

### 数据源层输出

```
{  "browser": "chrome",  "version": "143.0.7499.192",  "platform": "linux",  "arch": "x86_64",  "source": "chrome-for-testing",  "package_url": "...",  "binary_path": "binaries/chrome/143.0.7499.192/chrome",  "sha256": "...",  "downloaded_at": "..."}
```

### 注意事项

|问题|要求|
|---|---|
|版本真实性|必须记录官方 metadata|
|二进制唯一性|必须记录 sha256|
|可复现性|下载 URL 和解包路径必须入库|
|多源冲突|同版本不同来源不能混淆|

---

## 第二层：监听 / 采集 Agent 层

### 目标

周期性监听数据源，看是否有新版本发布。

### Agent 职责

|职责|说明|
|---|---|
|监听版本更新|定时查询官方版本源|
|去重|检查 DB 是否已有该版本|
|下载|下载 `.deb`、`.zip` 或二进制|
|解包|提取真实分析目标|
|生成任务|将任务提交给任务编排层|
|通知|通知用户或后台有新版本|

### Agent 不应该做的事

|不应该做|原因|
|---|---|
|不直接写 hook_points|避免绕过 TSHunter 分析逻辑|
|不直接标 verified|验证必须由验证层完成|
|不直接 hook 用户浏览器|必须经过用户授权和明确任务|

---

## 第三层：任务编排层

这是我建议新增的一层。

### 为什么必须有

如果没有任务编排层，Agent 会直接调用 TSHunter、验证层和数据库，后期很难恢复失败任务。

### 任务状态

```
pending
downloading
downloaded
relocating
analyzing
ingesting
verifying
verified
failed
needs_manual_review
```

### 建议表结构

```
CREATE TABLE agent_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT UNIQUE NOT NULL,
    browser TEXT NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    source TEXT,
    binary_path TEXT,
    binary_sha256 TEXT,
    status TEXT NOT NULL,
    priority INTEGER DEFAULT 100,
    created_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    error_stage TEXT,
    error_msg TEXT,
    retry_count INTEGER DEFAULT 0
);
```

### 编排策略

|情况|行为|
|---|---|
|DB 已有 verified 版本|跳过|
|DB 有 unverified 版本|进入验证层|
|同 major.minor 有 verified anchor|优先 relocate|
|relocate OK|入库，进入验证|
|relocate PARTIAL|入库为 unverified，进入抽样验证|
|relocate FAIL|完整 Ghidra 分析|
|Ghidra 失败|needs_manual_review|

---

## 第四层：TSHunter 分析层

### 目标

接收任务编排层传来的二进制，生成 hook 点数据。

### 输入

```
{
  "browser": "chrome",
  "version": "143.0.7499.192",
  "binary_path": ".../chrome",
  "platform": "linux",
  "arch": "x86_64"
}
```

### 分析策略

```
先查 DB
    ↓
如果已有 verified：跳过
    ↓
如果同 minor 有 anchor：尝试 relocate
    ↓
relocate OK / acceptable PARTIAL：写入候选结果
    ↓
否则完整 Ghidra 分析
    ↓
结果写入 staging
```

### 注意

建议引入 **staging 表**，不要让所有结果直接进正式 hook_points。

```sql
CREATE TABLE hook_candidates (  
id INTEGER PRIMARY KEY AUTOINCREMENT,  
task_id TEXT,  
browser TEXT,  
version TEXT,  
kind TEXT,  
rva TEXT,  
fingerprint TEXT,  
fingerprint_len INTEGER,  
source_method TEXT,  
confidence REAL,  
status TEXT  
);
```

只有验证层通过后，再提升为正式 `hook_points` 或标记 `verified=1`。

---

## 第五层：验证层

### 目标

确认 hook 数据是否真的能抓到 TLS key。

### 你原计划是正确的

你提到：

> tshunter 负责进行 hook，将得到的密钥与环境变量产生的密钥进行比对，正确率在 95% 以上时传输到下一层。

这个思路正确，但要更细化。

### 验证流程

```
启动干净浏览器 profile
    ↓
设置 SSLKEYLOGFILE 环境变量
    ↓
启动 TSHunter Frida hook
    ↓
访问固定 HTTPS 测试集
    ↓
收集 TSHunter keylog
    ↓
收集 SSLKEYLOGFILE baseline
    ↓
对比 keylog 行
    ↓
统计 capture rate
    ↓
统计五元组命中率
    ↓
通过则标 verified
```

### 验证指标

|指标|建议阈值|
|---|---|
|keylog line capture rate|≥ 95%|
|client_random match rate|≥ 95%|
|Wireshark decrypt success|≥ 95%|
|五元组命中率|≥ 95%|
|Frida attach 成功率|100%|
|运行时崩溃次数|0|

### 必须控制的实验条件

|条件|要求|
|---|---|
|QUIC|关闭|
|浏览器 profile|使用干净临时 profile|
|缓存|关闭或清理|
|测试网站|固定集合|
|网络|尽量稳定|
|TLS 版本|分 TLS 1.2 / TLS 1.3 统计|
|进程|明确 attach 到正确进程|

---

## 第六层：数据库层

### 数据库不只是存 hook

数据库应分成几类数据：

|数据类型|表|
|---|---|
|浏览器版本|`versions`|
|hook 点|`hook_points`|
|分析任务|`analyzer_runs`|
|批量任务|`batch_jobs`|
|Agent 任务|`agent_tasks`|
|验证结果|`verification_runs`|
|捕获会话|`capture_sessions`|
|数据源元数据|`source_artifacts`|
### 建议新增 verification 表

```sql
CREATE TABLE verification_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER,
    task_id TEXT,
    started_at TEXT,
    finished_at TEXT,
    status TEXT,
    keylog_capture_rate REAL,
    client_random_match_rate REAL,
    five_tuple_hit_rate REAL,
    wireshark_decrypt_rate REAL,
    total_baseline_lines INTEGER,
    total_captured_lines INTEGER,
    error_msg TEXT,
    report_path TEXT,
    FOREIGN KEY(version_id) REFERENCES versions(id)
);
```

### 入库规则

|情况|入库状态|
|---|---|
|full analyze + 未验证|`verified=0`, `source=ghidra_full`|
|relocate OK + 未验证|`verified=0`, `source=exact_scan`|
|relocate PARTIAL|`verified=0`, `source=exact_scan_partial`|
|验证 ≥ 95%|`verified=1`|
|验证失败|`verified=0`, `note=verification_failed`|
|人工确认|`source=manual`, `verified=1`|

---

## 第七层：用户监控与取证层
### 目标

让用户通过前端查看数据库状态、分析任务、hook 结果、日志和密钥文件归档。

### 功能模块

|模块|功能|
|---|---|
|版本看板|查看各浏览器版本覆盖情况|
|任务看板|查看 Agent / batch / analyze / verify 状态|
|Hook 看板|查看每个版本 4 hook 是否齐全|
|验证看板|查看 capture rate / 五元组命中率|
|实时捕获|用户选择浏览器进程，启动 hook|
|日志显示|展示 Frida/eBPF/TSHunter 日志|
|文件归档|保存 keylog、pcap、verification report|
|告警|新版本失败、验证失败、hook 率低于阈值|

### 重要安全边界

|要求|说明|
|---|---|
|必须用户显式启动 hook|不做后台隐蔽 hook|
|每次捕获生成审计记录|包括时间、进程、版本、操作者|
|密钥文件加权限保护|keylog 属于敏感文件|
|前端必须有访问控制|防止未授权访问|
|支持一键清理敏感数据|实验结束后清理 keylog|

---

# 5. Agent 自动化系统阶段计划

## Phase A0：B1 结果评估

### 目标

确认是否可以进入 Agent 自动化。

### 输入

- B1 批量分析 DB
- batch_jobs
- hook_points
- verification results
- failed logs

### 输出
```
B1_report.md
relocate_success.csv
hook_coverage.csv
failed_versions.csv
```
### 输出

```
B1_report.mdrelocate_success.csvhook_coverage.csvfailed_versions.csv
```

### 通过条件

|指标|阈值|
|---|---|
|版本入库成功率|≥ 95%|
|4 hook 齐全率|≥ 95%|
|relocate 可用率|可量化|
|full analyze 失败率|≤ 5%|
|验证样本成功率|≥ 95%|

---

## Phase A1：数据源 Agent MVP

### 目标

只支持 Chrome。

### 功能

```
监听 CfT known-good versions
    ↓
发现新版本
    ↓
下载 binary
    ↓
写 source_artifacts
    ↓
创建 agent_tasks
```

### 不做

- 不自动验证
- 不支持 Firefox
- 不支持前端
- 不自动发布数据库

---

## Phase A2：任务编排层

### 目标

让 Agent 不直接操作 TSHunter，而是提交任务。

### 功能

|功能|说明|
|---|---|
|创建任务|新版本进入 pending|
|恢复任务|支持 resume|
|重试任务|支持 retry|
|错误分类|download/analyze/relocate/verify|
|优先级|stable > beta > dev|

---

## Phase A3：TSHunter 自动分析 Worker

### 目标

自动消费 `agent_tasks`，调用 TSHunter。

### 流程

```
读取 pending task
    ↓
查 DB
    ↓
relocate 或 analyze
    ↓
ingest
    ↓
更新 task 状态
```

### 验收

|项目|标准|
|---|---|
|单任务分析|通过|
|中断恢复|通过|
|错误记录|完整|
|重复版本去重|正确|

---

## Phase A4：自动验证 Worker

### 目标

实现你说的“hook 得到的密钥与环境变量密钥比对”。

### 流程
```
启动测试浏览器
    ↓
SSLKEYLOGFILE baseline
    ↓
TSHunter capture
    ↓
固定 HTTPS 测试
    ↓
diff keylog
    ↓
写 verification_runs
    ↓
通过则 verified=1
```

### 验收

|项目|标准|
|---|---|
|Chrome stable 单版本验证|≥ 95%|
|失败报告|可定位原因|
|verified 写回|正确|
|keylog 文件归档|正确|

---

## Phase A5：数据库发布与版本索引

### 目标

形成可持续维护的 fingerprint DB。

### 功能

|功能|说明|
|---|---|
|DB snapshot|定期导出|
|JSON export|导出某版本 runtime config|
|changelog|新增版本、失败版本、verified 状态|
|rollback|错误数据可回滚|
|signed metadata|可选，保证 DB 未被篡改|

---

## Phase A6：用户监控前端

### 目标

用户能看到全流程状态，并可启动授权捕获。

### 页面

|页面|内容|
|---|---|
|Dashboard|支持版本数、成功率、最新任务|
|Versions|浏览器版本矩阵|
|Tasks|Agent / Analyze / Verify 状态|
|Capture|选择本机浏览器进程并启动 hook|
|Logs|实时日志|
|Artifacts|keylog / report / pcap 归档|

---

## Phase A7：多浏览器扩展

### 顺序建议

```
Chrome/BoringSSL    ↓Edge/BoringSSL    ↓Firefox/NSS    ↓Electron/BoringSSL    ↓OpenSSL/Rustls 其他目标
```

Firefox 不建议和 Chrome Agent 同时推进。Firefox/NSS 目前还在手工 baseline 阶段，应先完成 `nss_firefox.json` 和 `firefox_hooks.js`。

---

# 6. 最终推荐架构图

```
┌─────────────────────────────────────────────┐
│ 1. 数据源层                                  │
│ Chrome / Firefox / Edge / GitHub / apt repo │
└───────────────────┬─────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 2. Agent 监听采集层                          │
│ 发现版本 / 下载 / 解包 / 计算 sha256          │
└───────────────────┬─────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 3. 任务编排层                                │
│ agent_tasks / retry / resume / 状态机        │
└───────────────────┬─────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 4. TSHunter 分析层                           │
│ DB hit → relocate → full Ghidra analyze      │
└───────────────────┬─────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 5. 验证层                                    │
│ Frida hook vs SSLKEYLOGFILE diff             │
│ capture rate / tuple hit rate / verified     │
└───────────────────┬─────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 6. 数据库层                                  │
│ versions / hook_points / verification_runs   │
│ source_artifacts / capture_sessions          │
└───────────────────┬─────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ 7. 用户监控与取证层                          │
│ 前端 / 实时日志 / keylog 归档 / 报告          │
└─────────────────────────────────────────────┘
```


---
# 7. 我对你原始六层计划的修改建议

|你的原始层|建议调整|原因|
|---|---|---|
|数据源层|保留|设计合理|
|Agent 层|拆成“监听采集 Agent”与“任务编排层”|避免 Agent 直接控制所有逻辑|
|TSHunter 层|保留|负责 analyze / relocate|
|检验层|保留，但要独立成 verification worker|验证结果必须可复现、可审计|
|数据库层|保留，但增加 staging 和 verification 表|防止未验证数据污染正式数据|
|用户监控层|保留，但要加权限和审计|keylog 是敏感数据|

---

# 8. 下一步执行建议

## 现在立即做

```
1. 等 B1 第一轮结果
2. 生成 B1_report
3. 统计失败版本
4. 判断是否达到 95% 阈值
```

## 如果 B1 通过

```
进入 A1：实现 Chrome 数据源 Agent MVP
```

## 如果 B1 不通过

```
暂停 Agent
先修：
- downloader
- PARTIAL relocate
- batch resume
- full analyze fail cases
- verification probe
```

---

# 9. 最终结论

你的总体方向是对的，但需要更谨慎地拆分职责。

**不要让 Agent 直接变成“下载 + 分析 + 验证 + 入库 + hook 用户浏览器”的大脚本。**  
它应该只是系统入口之一，真正核心应该是：

```
Agent 发现任务
    ↓
任务编排层管理任务
    ↓
TSHunter 分析
    ↓
验证层确认
    ↓
数据库发布
    ↓
用户前端授权消费
```

这样系统才可恢复、可审计、可扩展，也更适合后续论文或工程展示。