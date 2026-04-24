# U1-pre：统一项目布局预整理结果

## 1. 文档目的

本文档记录 P7 阶段的 `U1-pre` 预整理工作。

本阶段目标不是一次性完成 `TSHunter + tls_capture` 的彻底统一，而是：

1. 先建立未来统一仓库需要的目录骨架；
2. 优先迁移低风险、低耦合文件；
3. 保留当前旧入口与旧路径，确保现有可运行链路不被破坏；
4. 为后续 `U1 / U2` 的真正整合打基础。

这属于“过渡性布局整理”，不是最终版重构。

---

## 2. 本阶段采用的原则

本次整理遵循以下原则：

### 2.1 低风险优先
优先处理：
- 公共库文件
- 工具脚本
- Ghidra 分析脚本
- Frida JS 资源
- eBPF 资源
- golden JSON 基线样本

暂不处理：
- 仍强依赖旧路径的运行时入口
- 仍直接读取 `hooks/*.json` 的逻辑
- 需要同时改 import + 改配置加载方式的高耦合模块

### 2.2 保留兼容，不破坏当前链路
当前 `tls_capture/tls_capture.py -> lib/version_detect.py -> hooks/*.json` 这条运行链路仍然有效，因此本阶段**不删除旧目录，不替换旧入口**。

本次操作采取的是：
- **复制到新布局**
- **保留旧文件不动**

这样可以同时满足：
- 新布局开始成型
- 旧功能仍可继续运行

### 2.3 先搭骨架，再收逻辑
当前最重要的是先形成未来统一仓库的结构轮廓，而不是立即完成 DB 作 SoT、config_loader、profile 模板层等逻辑整合。

---

## 3. 本次已建立的目录骨架

本次已在仓库根目录建立以下目录：

```text
/home/palm/TLSHunter/
├── tshunter/
├── ghidra_scripts/
├── frida_scripts/
├── ebpf/
├── profiles/
├── docker/
├── tests/golden/hooks/
└── learn/P7/
```

说明：
- `tshunter/`：未来统一 Python 包目录
- `ghidra_scripts/`：未来 Ghidra Java 分析脚本目录
- `frida_scripts/`：未来 Frida JS 目录
- `ebpf/`：未来 eBPF 目录
- `profiles/`：未来运行时模板层目录
- `docker/`：未来 Docker 相关目录
- `tests/golden/hooks/`：未来黄金样本与回归 JSON 存放目录
- `learn/P7/`：P7 阶段文档目录

---

## 4. 本次已迁移/复制的文件

注意：本阶段所有迁移均为**复制**，不是删除源文件的移动。

### 4.1 Python 公共库与工具脚本

已复制到 `tshunter/`：

| 旧路径 | 新路径 | 说明 |
|---|---|---|
| `tls_capture/lib/correlator.py` | `tshunter/correlator.py` | 五元组关联公共库 |
| `tls_capture/lib/net_lookup.py` | `tshunter/net_lookup.py` | 网络信息查询公共库 |
| `tls_capture/lib/output_writer.py` | `tshunter/output_writer.py` | 输出写入公共库 |
| `tls_capture/tools/fingerprint_scan.py` | `tshunter/relocate.py` | relocate 核心能力来源 |
| `tls_capture/tools/merge_analysis.py` | `tshunter/merge.py` | auto/baseline 合并工具 |
| `tls_capture/tools/chrome_downloader.py` | `tshunter/downloader.py` | Chrome 下载器 |

此外，已新增：
- `tshunter/__init__.py`

说明：
- 这一步只完成文件归位，不做 import 重写，不修改逻辑。
- 这些文件当前已具备“作为统一包成员存在”的基础，但尚未真正被统一 CLI 调用。

---

### 4.2 Ghidra 脚本侧

已复制到 `ghidra_scripts/`：

| 旧路径 | 新路径 |
|---|---|
| `scripts/common/` | `ghidra_scripts/common/` |
| `scripts/detect/` | `ghidra_scripts/detect/` |
| `scripts/stacks/` | `ghidra_scripts/stacks/` |
| `scripts/TLShunterAnalyzer.java` | `ghidra_scripts/TLShunterAnalyzer.java` |
| `ExtractKDFFingerprint.java` | `ghidra_scripts/ExtractKDFFingerprint.java` |
| `MinimalAnalysisOption.java` | `ghidra_scripts/MinimalAnalysisOption.java` |
| `custom_log4j.xml` | `ghidra_scripts/custom_log4j.xml` |

说明：
- 这一步让未来 `docker/Dockerfile`、`run.py`、Ghidra 容器路径迁移有了落点。
- 当前根目录和 `scripts/` 原路径仍保留，避免影响现有分析入口。

---

### 4.3 Frida 脚本侧

已复制到 `frida_scripts/`：

| 旧路径 | 新路径 |
|---|---|
| `tls_capture/hooks/chrome_hooks.js` | `frida_scripts/chrome_hooks.js` |
| `tls_capture/hooks/probe_ssl_log_secret.js` | `frida_scripts/probe_ssl_log_secret.js` |

说明：
- 这里只迁移 JS，不动当前 JSON 配置。
- 当前 `tls_capture/lib/version_detect.py` 仍默认从 `tls_capture/hooks/` 读取模板与 JSON，因此旧路径必须保留。

---

### 4.4 eBPF 侧

已复制到根目录 `ebpf/`：

- `fd_tracker`
- `fd_tracker.c`
- `fd_tracker.h`
- `fd_tracker.bpf.c`
- `fd_tracker.bpf.o`
- `fd_tracker.skel.h`
- `vmlinux.h`
- `Makefile`

说明：
- 未来统一目录将直接使用根目录 `ebpf/`。
- 当前 `tls_capture/ebpf/` 仍保留，用于不破坏旧入口。

---

### 4.5 Golden 基线样本

已复制到：

- `tests/golden/hooks/chrome_143.0.7499.169_linux_x86_64.json`

来源：
- `tls_capture/hooks/chrome_143.0.7499.169_linux_x86_64.json`

说明：
- 此目录未来作为数据库导出回归、baseline 对比、schema 对齐检查的黄金样本目录。
- 当前旧位置仍保留，避免影响旧运行链路。

---

## 5. 本次明确未迁移或仅保留原位的内容

以下内容本阶段**明确不做彻底迁移**：

### 5.1 `tls_capture/tls_capture.py`
原因：
- 它仍是现有运行时主入口；
- 依赖 `lib/`、`hooks/`、`ebpf/` 的旧路径；
- 未来应重构为 `tshunter/capture.py`，但当前还未接入 `VersionConfigLoader`。

结论：
- 本阶段不移动、不删除；
- 后续在 `U2` 阶段处理。

### 5.2 `tls_capture/lib/version_detect.py`
原因：
- 它目前实际上承担的是“版本检测 + JSON 配置加载 + Frida 模板注入”的职责；
- 后续应当被薄化，并委托给 `config_loader.py`；
- 现在直接搬过去会造成接口与职责混乱。

结论：
- 本阶段不移动、不删除；
- 未来会拆分为：
  - 浏览器版本检测逻辑
  - 配置加载逻辑（转给 DB + profile）
  - 模板注入逻辑

### 5.3 `tls_capture/hooks/*.json`
原因：
- 当前运行时仍直接从这里读取版本配置；
- 若本阶段直接搬走，会让 `tls_capture.py` 现有链路失效；
- 未来这些 JSON 应逐步退出“主运行路径”，转为：
  - `tests/golden/` 的回归样本
  - 或 DB 导出的中间验证材料

结论：
- 本阶段不删、不移走原文件；
- 等 `config_loader + DB SoT` 落地后再收口。

---

## 6. 本阶段后的仓库状态判断

### 已经实现的效果
当前仓库已经从“两个完全分裂的项目目录”进展到“一个带统一骨架的预整合工作区”。

也就是说，现在已经具备：
- 新布局骨架
- 新包目录起点
- Ghidra 脚本归位起点
- Frida/eBPF 资源归位起点
- golden 样本目录起点

### 尚未实现的部分
当前仍然没有完成：
- 统一 CLI
- `tshunter/capture.py`
- `tshunter/analyze.py`
- `tshunter/config_loader.py`
- `pyproject.toml`
- DB 作 SoT
- profiles 模板层实际内容
- 验证层注释脚本
- 旧入口收口

因此，本阶段结果应被视为：

**U1 之前的结构预整理（U1-pre），不是最终统一。**

---

## 7. 当前最重要的后续任务

### 7.1 下一步建议一：补消费端审计结论到文档
如果 `P7-plan-2` 中的 `S1` 已经通过人工阅读完成，建议把下面内容明确写成结构化文档：
- `p_t_c/tls_capture` 当前真正消费哪些字段；
- 哪些字段必须来自 DB；
- 哪些字段更适合作为 `profiles/` 模板；
- 哪些只是文档字段，不影响运行时。

### 7.2 下一步建议二：开始 S2 / schema 统一
重点不是大改逻辑，而是先定义：
- 统一 JSON schema
- DB 字段扩展点
- `hook_points` 与 `profiles` 的边界
- `run.py` 只负责哪些字段

### 7.3 下一步建议三：进入真正的 U1
等 schema 方向明确后，再做：
- `tshunter/cli.py`
- `tshunter/analyze.py`
- `tshunter/capture.py`
- `tshunter/query.py`
- `tshunter/ingest.py`
的真正归位与 import 改造。

### 7.4 下一步建议四：U2 再收旧 JSON 路径
只有当下列条件都满足时，才建议收掉旧 `tls_capture/hooks/*.json` 运行路径：
- `VersionConfigLoader` 已完成；
- DB 查询链路已完成；
- `profiles/` 模板层已完成；
- `capture.py` 已改为统一加载器；
- golden 回归样本已固定。

---

## 8. 本阶段一句话结论

本次 `U1-pre` 已经完成：

**先搭统一骨架，先归位低风险文件，保留旧入口兼容，为后续 schema 统一和 DB 驱动化整合创造了安全起点。**

这一步的价值不是“看起来已经统一完成”，而是：

**让后续真正的统一可以在不打断现有可运行链路的前提下继续推进。**

