# TLShunter integrated（阶段 1）

这是阶段 1 的整合版骨架工程。

当前包含：
- `scripts/TLShunterAnalyzer.java`：统一的 Ghidra headless 脚本
- `Dockerfile`：整合后的分析容器
- `ghidra_analysis.sh`：容器内启动脚本
- `run.py`：本地 Python 入口，用于构建 Docker、运行分析并解析 `[RESULT]` 输出

## 当前分析顺序

单次执行会顺序尝试输出以下 hook 点：
1. `HKDF`
2. `SSL_LOG_SECRET`
3. `PRF`
4. `KEY_EXPANSION`

## 统一输出格式

Ghidra 脚本会向控制台打印如下格式：

```text
[RESULT] type=HKDF function=FUN_xxx rva=0xXXXXXXXX fingerprint=55 48 89 E5 ...
```

`run.py` 会解析这些结果并输出 JSON。

## 用法

```bash
python3 integrated/run.py \
  --binary /path/to/chrome \
  --output /path/to/result.json
```

## 阶段 1 范围说明

当前版本完成的是“基础整合”：
- 已统一项目结构
- 已把 HKDF / ssl_log_secret / PRF / key_expansion 合并到单一脚本入口
- 已统一 `[RESULT]` 输出
- 已提供 Docker + Python 入口

尚未完成的内容：
- PRF 在 Chrome/BoringSSL 上的 `.rodata` 子串问题修复
- key_expansion 与 PRF 的共享函数细化判断
- 最终 `hooks/chrome_*.json` 的完整字段兼容输出

这些将在后续阶段继续完善。

