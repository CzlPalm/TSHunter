# TLShunter 项目使用说明

`TLShunter` 是一个面向 TLS 关键函数定位的分析工程，核心目标是：

1. 对目标二进制做静态分析，识别 TLS 关键 hook 点
2. 输出稳定的 `RVA + fingerprint`
3. 将分析结果写入 SQLite 指纹数据库
4. 在相邻小版本之间优先使用指纹重定位，减少重复长跑分析

当前重点支持 BoringSSL 场景，主要识别以下 4 类 hook 点：

- `HKDF`：TLS 1.3 Derive-Secret
- `SSL_LOG_SECRET`：BoringSSL keylog 输出函数
- `PRF`：TLS 1.2 master secret 派生
- `KEY_EXPANSION`：TLS 1.2 key block 派生

---

## 1. 项目能力概览

当前项目包含 3 条主要能力链路：

### 1.1 完整静态分析链路
输入一个目标二进制，调用 Docker 中的 Ghidra headless 分析环境，运行 `TLShunterAnalyzer`，输出 JSON 结果。

适用于：
- 首次分析未知版本
- relocate 失败后的兜底路径
- 构建新的基线版本

### 1.2 指纹数据库链路
将静态分析得到的 hook 点入库到 SQLite，用于后续：
- 精确版本查询
- 前缀指纹查询
- 同 major.minor 版本查找 relocation source

### 1.3 Fingerprint Relocation 链路
当目标版本未命中数据库，但同 `browser + major.minor + platform + arch` 下已有 verified source 时，优先用 source 的函数指纹在新版本 `.text` 段中扫描定位。

适用于：
- Chrome 小版本漂移
- 避免重复 17h+ 的完整静态分析

---

## 2. 环境依赖

### 2.1 系统依赖
- Docker
- Python 3
- SQLite3

### 2.2 Python 依赖
先安装：

```bash
pip install -r requirements.txt
```

当前依赖包括：
- `pyelftools`
- `pefile`
- `pytest`

### 2.3 分析环境
Ghidra 12.0.3 和 JDK 21 已通过 Dockerfile 内置，无需单独本机安装。

---

## 3. 常见入口

### 3.1 直接运行静态分析

```bash
python3 run.py \
  --binary /path/to/target_binary \
  --output /path/to/result.json \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --tls-lib boringssl
```

适合：
- 直接验证 analyzer 结果
- 生成单个 JSON
- 和历史 ground truth 做 compare

---

### 3.2 使用通用 shell 包装入口

```bash
bash run_binary_analysis.sh /path/to/target_binary /path/to/result.json \
  --meta "browser=chrome,version=143.0.7499.169,platform=linux,arch=x86_64,tls_lib=boringssl"
```

支持：
- 前台执行
- `--background` 后台运行
- 自动写 `.pid` / `.log` / `.done`

示例：

```bash
bash run_binary_analysis.sh /path/to/chrome results/chrome.json \
  --meta "browser=chrome,version=143.0.7499.169,platform=linux,arch=x86_64,tls_lib=boringssl" \
  --background
```

---

### 3.3 兼容 Chrome 固定入口

```bash
bash run_chrome_analysis.sh
```

该脚本是针对仓库内默认 Chrome 路径的薄封装，底层仍调用 `run_binary_analysis.sh`。

---

## 4. 数据库工作流

### 4.1 初始化数据库

```bash
sqlite3 data/fingerprints.db < tools/schema.sql
```

或者直接调用：

```bash
python3 tools/query.py --db data/fingerprints.db --report
```

这会在需要时自动补 schema / migration。

---

### 4.2 将分析结果入库

```bash
python3 tools/ingest.py \
  --json results/chrome_143.0.7499.169_linux_x86_64.json \
  --db data/fingerprints.db
```

如果 JSON 缺少 `browser/version/platform/arch`，可通过 CLI 补充：

```bash
python3 tools/ingest.py \
  --json results/chrome_143.0.7499.169_linux_x86_64.json \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --db data/fingerprints.db
```

注意：
- 默认拒绝空 `hook_points` 入库
- 如确实需要，可显式加 `--allow-empty`

---

### 4.3 查询数据库

#### 精确版本查询

```bash
python3 tools/query.py \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --db data/fingerprints.db
```

#### 输出 Frida 风格 hooks JSON

```bash
python3 tools/query.py \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --format frida \
  --db data/fingerprints.db
```

#### 按 major.minor 查版本

```bash
python3 tools/query.py \
  --browser chrome \
  --major-minor 143.0 \
  --db data/fingerprints.db
```

#### 按指纹前 20B 查询

```bash
python3 tools/query.py \
  --fingerprint "55 48 89 E5 41 57 41 56 ..." \
  --db data/fingerprints.db
```

---

## 5. 统一 CLI：`tshunter.py`

`tshunter.py` 是当前项目的统一工作流入口，负责：
- DB hit 直接返回 hooks
- DB miss 后先尝试 relocate
- relocate 失败再回退完整分析
- 必要时自动入库

### 5.1 `capture`

```bash
python3 tshunter.py capture \
  --binary /path/to/chrome \
  --browser chrome \
  --version 143.0.7499.169 \
  --platform linux \
  --arch x86_64 \
  --db data/fingerprints.db \
  --output results/hooks_143.json
```

行为：
1. 先查精确版本 DB
2. 命中则秒级返回 hooks
3. miss 则先查 relocation source
4. 如果 relocate 成功则自动入库并返回 hooks
5. 否则执行完整 analyzer

常用开关：
- `--no-relocate`：关闭 relocate，直接完整分析
- `--force-relocate`：即使 verdict 为 `PARTIAL` 也强制使用 relocate 结果
- `--rebuild`：分析前强制重建 Docker 镜像

---

### 5.2 `relocate`

```bash
python3 tshunter.py relocate \
  --binary /path/to/chrome_143.0.7499.192 \
  --browser chrome \
  --version 143.0.7499.192 \
  --platform linux \
  --arch x86_64 \
  --source-version 143.0.7499.169 \
  --db data/fingerprints.db \
  --output results/relocate_192.json
```

如果加上：

```bash
--auto-ingest
```

则在 verdict=`OK` 时自动入库。

---

## 6. Fingerprint Relocation

详细说明见：`docs/relocation.md`

当前实现支持：
- ELF
- PE

当前未实现：
- Mach-O

判定结果：
- `OK`
- `PARTIAL`
- `FAIL`

选择规则：
1. 前 20B 扫描所有命中
2. 前 40B 扩展校验
3. 优先扩展匹配更多者
4. 同级时优先离旧 RVA 最近者

---

## 7. 监控长跑分析

可用：

```bash
bash monitor_analysis.sh
```

它会周期性显示：
- 当前 Docker 容器
- 资源占用
- 磁盘使用
- 最新日志尾部
- 最新 `.done` 文件内容

适合配合：

```bash
bash run_binary_analysis.sh ... --background
```

一起使用。

---

## 8. 测试

当前 relocate 单元测试位于：
- `tests/test_relocate.py`

运行：

```bash
cd tests
pytest -v test_relocate.py
```

当前已验证通过：`8 passed`

---

## 9. 关键文件说明

### 顶层入口
- `run.py`：直接调用 Docker + Ghidra 进行静态分析
- `run_binary_analysis.sh`：通用 shell 包装入口
- `run_chrome_analysis.sh`：Chrome 固定路径封装入口
- `tshunter.py`：DB / relocate / analyze 一体化主入口
- `monitor_analysis.sh`：长跑分析监控脚本

### Java 分析逻辑
- `scripts/TLShunterAnalyzer.java`：统一 analyzer 入口
- `scripts/detect/TlsStackDetector.java`：TLS 栈识别
- `scripts/stacks/BoringSslAnalyzer.java`：BoringSSL 关键 hook 识别
- `scripts/common/StringXrefUtil.java`：字符串定位与 XREF 收集
- `scripts/common/FingerprintExtractor.java`：函数指纹提取
- `scripts/common/ResultEmitter.java`：输出 `[RESULT]`

### 数据与工具
- `tools/schema.sql`：数据库 schema
- `tools/migrations/001_relocate_fields.sql`：Phase 4A migration
- `tools/ingest.py`：入库工具
- `tools/query.py`：查询工具
- `tools/fingerprint_relocate.py`：指纹重定位工具

### 文档
- `docs/fingerprint_standard.md`
- `docs/hkdf_identification.md`
- `docs/relocation.md`

---

## 10. 推荐工作顺序

### 首次分析某版本
1. 跑 `run.py` 或 `tshunter.py capture --no-relocate`
2. 检查结果 JSON
3. 用 `tools/ingest.py` 入库
4. 标记 verified 版本

### 相邻小版本分析
1. 先跑 `tshunter.py capture`
2. 优先命中 DB 或 relocate
3. 如果 relocate 失败，再回退完整分析

### 长跑回归
1. 后台运行 `run_binary_analysis.sh --background`
2. 用 `monitor_analysis.sh` 监控
3. 完成后检查 `.done` / JSON / DB
