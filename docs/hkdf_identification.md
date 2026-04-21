# HKDF Identification Strategy

## Goal
在 BoringSSL/Chrome 中稳定定位 TLS 1.3 `derive_secret` 核心函数。

## Strategy
使用 4 个 TLS 1.3 label：

- `c hs traffic`
- `s hs traffic`
- `c ap traffic`
- `s ap traffic`

对每个 label：
1. 在只读数据段搜索字符串地址
2. 找到所有引用该字符串的 XREF
3. 在引用点所在函数中，继续向后走到第一条 `CALL`
4. 将该 `CALL` 的 target 作为候选核心函数投票

票数最高者即为 HKDF 核心函数。

## Fallback
若 next-CALL 投票完全失败，则回退到握手标签二重交集 wrapper 方案。

## Current implementation
见：`scripts/TLShunterAnalyzer.java` 中的 `identifyHKDF()`

