# Fingerprint Relocation

## 概念
浏览器小版本漂移时，直接复用已入库版本的函数指纹，在新二进制的 `.text` 段做快速扫描与 RVA 重定位。典型场景是 `chrome 143.0.7499.169 -> 143.0.7499.192`，无需立刻再次跑 17 小时级别的完整 Ghidra 分析。

## 使用方式

### 手动 relocate

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

### capture 中自动触发 relocate

```bash
python3 tshunter.py capture \
  --binary /path/to/chrome_143.0.7499.192 \
  --browser chrome \
  --version 143.0.7499.192 \
  --platform linux \
  --arch x86_64 \
  --db data/fingerprints.db \
  --output results/hooks_192.json
```

当 DB 精确版本 miss，但同 `browser + major.minor + platform + arch` 下存在 verified source 时，`capture` 会优先尝试 relocate。

## 原理
1. 从 DB 读取 source version 的 hook fingerprint。
2. 在目标二进制的 `.text` 段扫描前 20B 前缀。
3. 用前 40B 做扩展校验。
4. 多命中时优先扩展匹配更多、且距离旧 RVA 最近的结果。
5. 汇总 4 个 hook 的 delta，一致则判定为可直接使用。

## Verdict
- `OK`：全部 hook 均成功重定位，且 delta 一致，可直接使用并入库。
- `PARTIAL`：全部 hook 可命中但 delta 发散，或只有部分 hook 命中。默认不进入运行时 capture。
- `FAIL`：全部未命中，必须回退完整分析。

## PARTIAL 准入策略

PARTIAL 只允许在批量扩库阶段作为“待验证候选”入库，不能直接视为 verified baseline。

当前制度化规则：

1. `tshunter capture` 默认 strict：`VersionConfigLoader(accept_partial=False)`，遇到 `PARTIAL` 会抛 `RelocateFailed`，不会自动消费。
2. `tshunter batch` 默认允许候选入库：`accept_partial=True`，但必须满足所有 hook 都命中、没有 `not_found`、每个 hook 的 `confidence >= partial_min_confidence`，默认阈值是 `0.8`。
3. 接受的 PARTIAL 必须写成 `hook_points.relocation_method='exact_scan_partial'`，并且 `versions.verified=0`。
4. 接受的 PARTIAL 必须在 `versions.note` 写入 JSON 标记，至少包含 `partial_relocate=true`、`median_delta`、`max_outlier_delta`。
5. 如需保守运行 batch，使用 `--strict-relocate`，此时 PARTIAL 会回退完整 Ghidra 分析。

推荐流程：

```bash
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --milestones 143 \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db

# 保守模式：不接受 PARTIAL 候选
tshunter batch \
  --browser chrome \
  --binaries-dir binaries/Chrome \
  --milestones 143 \
  --platform linux --arch x86_64 \
  --db data/fingerprints.db \
  --strict-relocate
```

## 数据库溯源字段
`hook_points` 新增以下字段：

- `derived_from_version_id`
- `rva_delta`
- `relocation_method`
- `relocation_confidence`

其中：
- 完整分析产物默认 `relocation_method='ghidra_full'`
- relocate 入库产物使用 `relocation_method='exact_scan'`
- PARTIAL 候选入库产物使用 `relocation_method='exact_scan_partial'`，且版本级 `verified=0`

## 测试

```bash
pip install -r requirements.txt
cd tests
pytest -v test_relocate.py
```
