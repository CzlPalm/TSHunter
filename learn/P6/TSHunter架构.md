# TSHunter 架构说明

## 1. 项目定位

`TSHunter` 是一个围绕 TLS 关键函数识别、指纹提取、数据库沉淀与跨版本重定位构建的分析工程。

项目目标不是做通用逆向框架，而是围绕一个非常明确的任务闭环：

1. 对目标浏览器或 TLS 相关二进制做静态分析
2. 找出关键 TLS hook 点
3. 提取稳定的函数指纹和 RVA
4. 将结果写入数据库
5. 对相邻小版本优先做指纹重定位
6. 为后续 hook、key capture、版本偏移实验提供基础数据

当前项目重点支持：
- Linux 平台
- x86_64 架构
- BoringSSL 场景

但整体架构已经为多 TLS 栈、多浏览器、多平台预留了扩展位置。

---

## 2. 总体架构

从功能上看，项目可以分成 5 层：

### 2.1 分析执行层
负责把目标二进制送入 Ghidra headless 环境，并把分析输出转成结构化 JSON。

主要文件：
- `run.py`
- `run_binary_analysis.sh`
- `run_chrome_analysis.sh`
- `Dockerfile`
- `ghidra_analysis.sh`

### 2.2 Ghidra 脚本分析层
负责在 Ghidra 中识别 TLS 栈、定位关键函数、提取指纹、输出统一结果。

主要目录：
- `scripts/`

### 2.3 数据库与工具层
负责把分析结果入库、查询、迁移 schema，并支撑后续版本比对和重定位。

主要目录：
- `tools/`

### 2.4 Relocate 层
负责在已知 source version 的前提下，通过 fingerprint 扫描新版本 `.text` 段，快速恢复新 RVA。

主要文件：
- `tools/fingerprint_relocate.py`
- `tshunter.py`

### 2.5 测试与文档层
负责保证 relocate 算法最小闭环正确，以及提供工程说明。

主要目录：
- `tests/`
- `docs/`

---

## 3. 代码目录结构

```text
TLShunter/
├── scripts/                  # Ghidra Java 脚本
│   ├── common/               # 通用工具：字符串/XREF/结果输出/指纹提取
│   ├── detect/               # TLS 栈识别
│   ├── stacks/               # 各 TLS 栈分析器
│   └── TLShunterAnalyzer.java
├── tools/                    # 数据库、查询、迁移、relocate 工具
├── tests/                    # relocate 单元测试
├── docs/                     # 项目文档
├── results/                  # 分析结果、日志、done 文件
├── data/                     # SQLite 数据库与 seed 数据
├── run.py                    # Python 分析入口
├── tshunter.py               # DB / relocate / analyze 总入口
├── run_binary_analysis.sh    # Shell 包装入口
├── run_chrome_analysis.sh    # Chrome 固定入口
├── monitor_analysis.sh       # 监控脚本
├── MinimalAnalysisOption.java
├── Dockerfile
└── ghidra_analysis.sh
```

---

## 4. 核心执行流程

## 4.1 完整静态分析流程

用户输入一个二进制后，典型流程是：

```text
run.py / run_binary_analysis.sh
    ↓
Docker 启动 Ghidra headless 环境
    ↓
ghidra_analysis.sh
    ↓
TLShunterAnalyzer.java
    ↓
TlsStackDetector.detect()
    ↓
对应 StackAnalyzer.analyze()
    ↓
ResultEmitter 输出 [RESULT]
    ↓
run.py 解析 [RESULT]
    ↓
生成结构化 JSON
```

### 4.1.1 `run.py`
`run.py` 是完整静态分析的 Python 主入口，主要职责：

1. 准备 Docker 镜像
2. 将目标 binary 拷入临时输入目录
3. 调用 Docker 运行 Ghidra 分析
4. 收集标准输出和错误输出
5. 解析 `[RESULT]` 行
6. 生成标准 JSON 结果

它本质上是“Docker + Ghidra + 日志解析器”的统一封装层。

### 4.1.2 `run_binary_analysis.sh`
这是一个 shell 包装入口，做的事情比较简单：

- 解析命令行参数
- 组装 metadata
- 调用 `run.py`
- 如使用 `--background`，则生成：
  - `.pid`
  - `.log`
  - `.done`

它适合长跑分析和批量实验时使用。

### 4.1.3 `run_chrome_analysis.sh`
这是一个固定路径的薄封装，用于你当前仓库内默认 Chrome 样本路径的快速调用。

---

## 5. Ghidra 脚本分析层

## 5.1 `TLShunterAnalyzer.java`
这是 Ghidra 侧统一总入口。

职责：
1. 打印 binary / image base
2. 调用 `TlsStackDetector`
3. 选择合适的 analyzer
4. 执行 `analyze()`
5. 将结果统一输出为 `[RESULT]`

它本身不承载复杂识别逻辑，而是一个调度器。

## 5.2 `TlsStackDetector`
负责根据目标二进制中的特征字符串、符号痕迹、TLS 相关常量等信息，判断当前更像：

- `boringssl`
- `openssl`
- `nss`
- `rustls`
- `unknown`

输出一个：
- `stackName`
- `confidence`
- `analyzer`

这让架构可以扩展到多 TLS 栈，而不把所有逻辑都塞在一个文件里。

## 5.3 `StackAnalyzer` 抽象层
`StackAnalyzer` 是各 TLS 栈分析器的抽象父类，具体子类包括：

- `BoringSslAnalyzer`
- `OpenSslAnalyzer`
- `NssAnalyzer`
- `RustlsAnalyzer`
- `UnknownTlsAnalyzer`

这部分设计的作用是：
- 分离不同 TLS 栈的分析方法
- 让检测逻辑与识别逻辑解耦
- 便于按 TLS 栈逐步扩展

---

## 6. BoringSSL 分析器

## 6.1 `BoringSslAnalyzer.java`
这是当前项目最核心的 analyzer。

它负责识别 4 类 hook 点：
- `HKDF`
- `SSL_LOG_SECRET`
- `PRF`
- `KEY_EXPANSION`

### 6.1.1 HKDF 识别
当前采用的是：
- TLS 1.3 label 字符串定位
- `next-CALL` 投票策略
- 握手标签交集 fallback

典型 label 包括：
- `c hs traffic`
- `s hs traffic`
- `c ap traffic`
- `s ap traffic`

识别流程大致是：
1. 找到字符串引用函数
2. 找到引用后最近的 call target
3. 给 target 投票
4. 票数最高者作为候选
5. 失败时再走交集策略

### 6.1.2 SSL_LOG_SECRET 识别
主要围绕：
- `EXPORTER_SECRET`
- `CLIENT_RANDOM`

先找字符串引用函数，再尝试找引用后的 call target。

### 6.1.3 PRF 识别
围绕：
- `master secret`
- `extended master secret`

先做双标签交集，再做 standalone string fallback，最后做 best-xref fallback。

### 6.1.4 KEY_EXPANSION 识别
围绕：
- `key expansion`

先走字符串函数定位，再回退 rodata 地址引用路径。

---

## 7. 字符串与 XREF 工具层

## 7.1 `StringXrefUtil.java`
这个文件是这次修复 Chrome 大二进制问题的关键之一。

它的主要职责：
- 在已定义字符串中查找目标文本
- 在只读数据段中按字节搜索字符串
- 收集引用某字符串的函数
- 在引用点之后寻找第一个 call 目标
- 统计函数被调用次数，用于投票/择优

### 7.1.1 为什么它重要
Chrome 这类：
- PIC
- stripped
- LTO
- 大体积单体二进制

字符串引用大多是 RIP-relative。若 Ghidra 没建好数据引用，单走 `ReferenceManager` 可能吃空。

当前实现采用：
1. 优先使用 `Listing.getDefinedData(true)` 的字符串路径
2. 若拿不到结果，再回退字节搜索 + 引用收集

这使得分析在复杂二进制上更稳健。

---

## 8. 指纹提取层

## 8.1 `FingerprintExtractor.java`
职责：
- 从函数入口开始提取 fingerprint
- 控制提取长度
- 遇到分支 / ret / jmp 适时停止
- 计算函数 RVA

设计目标是：
- 指纹足够稳定
- 对函数前缀敏感
- 适合跨小版本比对

这部分直接决定 relocate 的可用性。

---

## 9. 结果输出层

## 9.1 `ResultRecord.java`
是 Ghidra 侧的结果数据结构，记录：
- 类型
- 函数名
- RVA
- fingerprint
- note

## 9.2 `ResultEmitter.java`
将 `ResultRecord` 输出成标准格式的 `[RESULT]` 行。

`run.py` 正是依赖这个输出格式做解析。

因此这里是 Java 结果层与 Python 工具层之间的接口边界。

---

## 10. 数据库层

## 10.1 `tools/schema.sql`
定义了当前数据库核心结构，主要包含：
- `tls_stacks`
- `browsers`
- `versions`
- `hook_points`
- `analyzer_runs`
- `capture_sessions`
- `schema_migrations`

其中最重要的是：
- `versions`：描述一个版本实体
- `hook_points`：描述一个版本上的 hook 点

## 10.2 `hook_points` 的关键字段
核心字段包括：
- `kind`
- `function_name`
- `rva`
- `fingerprint`
- `fingerprint_len`
- `fingerprint_prefix20`

Phase 4A 新增字段：
- `derived_from_version_id`
- `rva_delta`
- `relocation_method`
- `relocation_confidence`

这样数据库不仅能存“结果”，还能存“结果来源与演化关系”。

---

## 11. 数据库工具层

## 11.1 `tools/ingest.py`
职责：
- 初始化 schema / migration
- 校验元数据
- 创建 browser / version
- 写入 hook_points
- 记录 analyzer_runs
- 支持 relocate 结果入库

它还承担了一个非常关键的保护逻辑：
- 默认拒绝空 `hook_points` 入库

这避免了“分析空结果却静默写库”的错误路径。

## 11.2 `tools/query.py`
职责：
- 精确版本查询
- 指纹前缀查询
- major.minor 查询
- 输出 Frida 风格 JSON
- 汇总报告

它是数据库的主要只读接口。

---

## 12. Relocate 层

## 12.1 `tools/fingerprint_relocate.py`
这是 Phase 4A 的核心工具，负责：
- 从数据库读取 source version 的 fingerprint
- 加载目标二进制 `.text`
- 扫描前 20B 前缀
- 用前 40B 做扩展校验
- 结合“离旧 RVA 的距离”做多命中消歧
- 输出 verdict 和每个 hook 的新 RVA

### 12.1.1 当前支持格式
- ELF
- PE

### 12.1.2 当前输出
- `OK`
- `PARTIAL`
- `FAIL`

### 12.1.3 当前限制
- Mach-O 未实现

---

## 13. 统一工作流层：`tshunter.py`

`tshunter.py` 是当前工程最重要的统一入口。

它把 3 类路径串起来了：
- DB hit
- relocate
- full analyzer

## 13.1 `capture` 工作流

```text
精确版本查询
  ├─ hit  → 直接输出 hooks
  └─ miss → 查同 major.minor verified source
             ├─ 找到 source → 跑 relocate
             │                ├─ OK      → 入库并返回 hooks
             │                ├─ PARTIAL → 可选 force-relocate
             │                └─ FAIL    → 回退完整分析
             └─ 无 source → 直接完整分析
```

## 13.2 `relocate` 子命令
提供一个显式的 relocate CLI，方便：
- 单独调试 relocate
- 在不跑完整分析的前提下做版本偏移验证
- 在实验阶段快速输出 JSON

---

## 14. 监控与长跑支持

## 14.1 `run_binary_analysis.sh --background`
后台执行时会生成：
- `.pid`
- `.log`
- `.done`

这为长跑分析提供了最基础的任务状态持久化。

## 14.2 `monitor_analysis.sh`
提供一个轮询式监控界面，显示：
- Docker 容器状态
- Docker 资源占用
- 磁盘使用
- 最新分析日志
- 最新 `.done`

这让长跑分析不必手工到处查日志。

---

## 15. 测试架构

## 15.1 `tests/test_relocate.py`
当前测试聚焦于 relocate 的算法正确性。

已覆盖：
- exact match
- shifted match
- not found
- 多命中距离消歧
- 多命中扩展匹配消歧
- delta 一致时 OK
- delta 发散时 PARTIAL
- 从 DB 读取 source hooks 的路径

## 15.2 `tests/fixtures/build_mock_elf.py`
这是一个最小 ELF fixture 生成器，用于构造可控 `.text` 内容。

它的存在意味着后续可以继续把更多 relocate 场景做成稳定单测，而不依赖真实 Chrome 二进制。

---

## 16. 当前架构的优点

### 16.1 模块边界清晰
- Java 负责识别与输出
- Python 负责编排、解析、入库、查询、relocate
- shell 负责包装和长跑管理

### 16.2 适合论文/实验推进
- 可以积累 version → hooks 数据
- 可以做跨版本偏移实验
- 可以把 full analysis 与 relocate 分开评估

### 16.3 具备工程化演进能力
- 已支持 schema migration
- 已支持 relocation lineage 字段
- 已支持测试
- 已支持后台运行与监控

---

## 17. 当前架构的局限

### 17.1 BoringSSL 以外仍然较弱
虽然架构支持 OpenSSL/NSS/Rustls，但当前最成熟的仍是 BoringSSL 分析链路。

### 17.2 `run.py` 仍然是日志解析式桥接
Java 结果通过 `[RESULT]` 输出，Python 再正则解析。这个方式够用，但严格来说不是最强类型化接口。

### 17.3 relocate 目前只做静态字节级扫描
它很适合小版本漂移，但不适合：
- 函数被大改
- 编译优化大幅重排
- 指纹稳定性显著下降

---

## 18. 当前推荐使用方式

### 18.1 未知版本首次构建基线
用完整分析：
- `run.py`
- 或 `tshunter.py capture --no-relocate`

### 18.2 已有邻近版本的相邻小版本
优先：
- `tshunter.py capture`

### 18.3 只想验证版本偏移能力
直接：
- `tshunter.py relocate`

### 18.4 长跑分析
配合：
- `run_binary_analysis.sh --background`
- `monitor_analysis.sh`

---

## 19. 总结

`TSHunter` 当前已经从“单次 Ghidra 脚本”演进成一个具备以下能力的完整工程：

- 静态分析
- 结果标准化输出
- 数据库存储
- 版本查询
- 小版本 fingerprint relocation
- 后台任务与监控
- 单元测试与文档

它当前最核心的价值在于：

> 将 TLS hook 点识别，从一次性逆向结果，变成可复用、可查询、可迁移、可验证的工程资产。

