# Known Limitations

## 文档目的

本文件汇总 `tls_capture` 项目在当前实现阶段已经确认、且短期内不宜继续通过工程调试消除的限制。这些限制主要来自：

- Frida attach 时序
- BoringSSL 内部派生路径差异
- TLS 复用机制（PSK / Session Ticket）
- 进程/文件描述符可见性限制
- 当前实现有意采用的简单关联策略

该文件可直接作为后续论文中的 limitation 草稿基础。

---

## 1. 无法保证 100% 捕获所有环境变量 keylog

### 现象
当前与 `SSLKEYLOGFILE` 的正式 diff 结果为：

- `<` 行：`0`
- `>` 行：`12`
- 覆盖率：`692 / 704 ≈ 98.3%`

缺失被分解为 3 个独立会话：

1. `69f21abd...`：TLS 1.3 完整 5 条全缺，secret 长度 `48B (SHA-384)`
2. `ddd90526...`：TLS 1.3 完整 5 条全缺，secret 长度 `32B (SHA-256)`
3. `0e959266...`：TLS 1.2 `CLIENT_RANDOM` 缺失 1 条，secret 长度 `48B (SHA-384)`

### 判断
这些缺失都表现为：

> **整个 session 完整缺失，而不是单个 label 丢失。**

这基本排除了：

- 参数读取错误
- label 映射错误
- 单条去重逻辑 bug
- 输出写盘错误

当前最可信的原因只剩两类：

1. **attach 时序窗口**：Hook 就绪前，连接已经完成握手
2. **PSK / Session Ticket 复用**：复用会话跳过了当前依赖的 HKDF / PRF 派生路径

### 影响
这意味着在当前架构下，项目可以做到很高覆盖率，但**不能承诺与环境变量 keylog 永远逐条完全一致**。

---

## 2. `ssl_log_secret` 不能单独替代 `hkdf/prf`

### 现象
本轮统计结果显示：

- `hkdf = 625`
- `prf = 49`
- `ssl_log = 18`

最终输出文件中：

- TLS 1.3 五类标签各 `125` 条，共 `625` 条
- `CLIENT_RANDOM = 67` 条

其中 `CLIENT_RANDOM` 来源拆分为：

- `prf:CLIENT_RANDOM = 49`
- `ssl_log:CLIENT_RANDOM = 18`

### 判断
由此可以确认：

- TLS 1.3 主体仍由 `hkdf` 提供
- TLS 1.2 主体仍由 `prf` 提供
- `ssl_log_secret` 当前只承担**补漏源**角色

因此：

> **单独只靠 `ssl_log_secret`，无法输出全部 keylog。**

### 影响
第二阶段方案的正确定位不是“用 `ssl_log_secret` 替代主链”，而是：

- 保留 `hkdf/prf` 主链
- 用 `ssl_log_secret` 补齐主链漏项

---

## 3. attach 时序窗口无法从用户态彻底消除

### 现象
当前工具流程为：

1. 启动 Chrome
2. 等待 `NetworkService` 出现
3. attach 目标进程
4. 安装 Hook
5. 开始捕获握手派生信息

这意味着从 Chrome 启动到 Hook 真正就绪之间，天然存在一个时间窗口。

### 判断
如果某个连接在 Hook 安装前已经完成：

- TLS 1.3 的 HKDF 派生不会被本工具看到
- TLS 1.2 的 PRF 输出也不会被本工具看到
- 最终表现就是整个 session 完整缺失

这一类问题不是继续调某个 offset 或改一条 if 判断就能解决的，而是**attach 模式本身的时序限制**。

### 影响
在不改成更早期注入方式（例如进程启动前注入、浏览器级更底层插桩、内核侧能力扩展）的前提下，该限制将长期存在。

---

## 4. PSK / Session Ticket 复用会绕开当前主链路

### 现象
当前主链路依赖：

- TLS 1.2：`PRF` / `key_expansion`
- TLS 1.3：`HKDF`

但从 diff 缺失模式来看，已有明确证据说明部分 session 会完整跳过这些路径。

### 判断
这与 TLS 会话复用特征一致，尤其是：

- PSK
- Session Ticket
- Resume 场景

在这些场景下，BoringSSL 可能不会再次走到当前 Hook 所依赖的派生函数，因此：

- `hkdf` 不触发
- `prf` 不触发
- 只能寄希望于 `ssl_log_secret` 是否仍然可观测

### 影响
这类缺失属于协议/实现路径差异带来的**结构性限制**，不是简单修 bug 能彻底消掉的问题。

---

## 5. `ssl_log_secret` 的 fd 恢复不稳定

### 现象
第二阶段测试中，`ssl_log_secret` 命中时大多数 `fd` 仍为 `-1`。

### 判断
这说明在 `ssl_log_secret` 所处的调用上下文中：

- `ssl -> rbio -> fd` 路径并不总是稳定可读
- 或者该时点结构内容已经不适合恢复真实 socket fd

因此当前无法把 `ssl_log_secret` 作为可靠的 fd 精确关联来源。

### 影响
`ssl_log_secret` 能补 keylog，但**不能稳定补强五元组精确关联**。当前五元组更多仍依赖：

- `fd_tracker` connect 事件
- 时序回补

---

## 6. 五元组关联存在时序 fallback 误配风险

### 现象
当前 `Correlator` 只提供两种策略：

1. `fd` 精确匹配
2. 同 PID / 近时序 fallback

代码实现偏简单，且 `cache_hits` 实际固定为 `0`。

### 判断
当 `fd` 不可用时，系统会退回到“最近 connect 事件”的时序推断。该策略虽然实用，但不是严格证明型关联。

在高并发、连接突发或多个远端快速交错时，理论上可能出现：

- 目标连接被错配到相邻 connect 事件
- 五元组注释正确率下降

### 影响
当前的 keylog 行本身可以是正确的，但其前置的五元组注释**不保证在所有高并发情况下都绝对精确**。

---

## 7. 跨进程 / 跨网络命名空间反查存在可见性限制

### 现象
源地址反查依赖：

- `/proc/{pid}/net/tcp`
- 扫描 chrome 相关 PID

### 判断
该方法在当前 Linux + Chrome 场景下通常可用，但其正确性依赖：

- 进程仍然存活
- `/proc` 可访问
- 网络状态还未快速变化
- 目标连接仍能在内核 TCP 表中观察到

如果连接生命周期极短，或网络命名空间/权限环境更复杂，反查可能失败。

### 影响
五元组注释并不是协议栈级“真值源”，而是当前环境下的**最佳努力恢复**。

---

## 8. 版本适配依赖手工维护配置

### 现象
项目当前依赖版本配置 JSON 来提供：

- `prf`
- `key_expansion`
- `hkdf`
- `ssl_log_secret`

的 RVA。

### 判断
虽然 `version_detect.py` 支持：

- 精确版本匹配
- 大版本回退匹配

但这本质仍然依赖人工维护偏移配置。Chrome / BoringSSL 一旦升级、内联变化或函数布局变化，就可能导致：

- Hook 失效
- 命中率下降
- 需要重新适配

### 影响
该工具当前不具备“对未来版本天然鲁棒”的能力，存在持续维护成本。

---

## 9. `ssl_log_secret` 路径本身也是版本相关知识

### 现象
第二阶段确认的 `client_random` 读取路径为：

- `*(ssl + 0x30) + 0x30`

### 判断
这个路径是针对当前版本、当前结构布局实测确认的结果，不应直接假定适用于所有 Chrome / BoringSSL 版本。

### 影响
一旦结构布局变化：

- `ssl_log_secret` 仍然可能触发
- 但 `client_random` 读取路径可能失效
- 需要重新探测

因此这属于**已确认有效、但具版本耦合**的实现限制。

---

## 10. 当前没有系统化自动化测试覆盖这些边界场景

### 现象
`tests/` 目录目前为空。

### 判断
当前验证主要依赖：

- 手工运行
- 日志观察
- 与 `SSLKEYLOGFILE` diff

这足以支持研发迭代，但不足以形成严格自动回归保障，尤其对以下场景：

- attach 前握手完成
- Session Ticket / PSK resume
- fd 恢复失败
- 高并发五元组错配
- 新 Chrome 版本兼容性

### 影响
项目当前工程验证强，但自动化回归能力弱。这是实现成熟度上的限制，而不是单点 bug。

---

## 11. 当前已知“不是 bug、而是 limitation”的结论汇总

以下问题在当前阶段应归为 limitation，而不是继续按普通 bug 追查：

1. 与环境变量对比仍有极少数 session 完整缺失
2. `ssl_log_secret` 无法单独承担全部 keylog 输出
3. attach 时序窗口导致的早期握手漏抓
4. PSK / Session Ticket 复用导致主链路不触发
5. `ssl_log_secret` 中 fd 恢复不稳定
6. 五元组 fallback 关联在极端并发下可能误配
7. 版本升级带来的 RVA / 结构偏移维护成本
8. 缺少自动化回归测试体系

---

## 12. 论文可直接使用的 limitation 表述建议

如果后续要写入论文，可直接压缩成下面的正式表述：

### Limitations
1. The system relies on runtime attachment to Chrome NetworkService, so TLS sessions that complete before hooks are installed may be missed.
2. TLS session resumption mechanisms such as PSK or Session Ticket may bypass the HKDF/PRF derivation paths used by the current instrumentation, leading to whole-session omissions.
3. The `ssl_log_secret` path is effective as a supplementary source for missing secrets, but it cannot replace the primary HKDF/PRF-based extraction pipeline.
4. Five-tuple attribution is best-effort: when file descriptor recovery fails, the system falls back to timing-based correlation, which may introduce ambiguity under highly concurrent connection patterns.
5. The implementation is version-coupled to Chrome/BoringSSL internals and requires configuration maintenance for new browser versions.
6. The current validation workflow depends mainly on differential comparison against `SSLKEYLOGFILE`, and an automated regression test suite has not yet been established.

