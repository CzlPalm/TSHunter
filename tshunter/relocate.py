#!/usr/bin/env python3
"""
tools/fingerprint_scan.py — 用 baseline fingerprint 在新 Chrome 二进制里定位 RVA
 
用途：
    当某个 Chrome 版本没跑通 TSHunter（或 Ghidra 不可用）时，拿 baseline
    (Chrome 143) 已验证的 4 条 fingerprint 在目标二进制 .text 段里做唯一匹配，
    把命中偏移换算成 RVA，合成完整的 hooks/chrome_<ver>_linux_x86_64.json。
 
用法：
    # 完整流程：从 baseline 指纹扫描 + 合并人工字段 → 输出新 JSON
    python3 tools/fingerprint_scan.py \\
        --binary artifacts/chrome/142.0.7339.185/chrome \\
        --baseline hooks/chrome_143.0.7499.169_linux_x86_64.json \\
        --version 142.0.7339.185 \\
        --out hooks/chrome_142.0.7339.185_linux_x86_64.json
 
    # 只打印 RVA（不写文件）
    python3 tools/fingerprint_scan.py \\
        --binary /opt/google/chrome/chrome \\
        --baseline hooks/chrome_143.0.7499.169_linux_x86_64.json \\
        --scan-only
"""
 
from __future__ import annotations
 
import argparse
import copy
import datetime as dt
import json
import re
import struct
import sys
from pathlib import Path
 
# ELF64 常量 —— 仅支持 x86_64 ELF
ELF_MAGIC = b'\x7fELF'
SHT_PROGBITS = 1
SHF_EXECINSTR = 0x4
 
REQUIRED_HOOKS = ('prf', 'key_expansion', 'hkdf', 'ssl_log_secret')
 
 
# ── ELF 最小解析 ─────────────────────────────────────────────────
 
 
def _read_elf64_text_section(binary_path: Path) -> tuple[int, int, bytes]:
    """返回 (.text sh_addr, sh_offset, section bytes)。仅支持 ELF64 LE x86_64。"""
    data = binary_path.read_bytes()
    if len(data) < 64 or data[:4] != ELF_MAGIC:
        raise ValueError(f'{binary_path} 不是有效 ELF 文件')
    if data[4] != 2:  # EI_CLASS: ELFCLASS64
        raise ValueError('仅支持 ELF64')
    if data[5] != 1:  # EI_DATA: ELFDATA2LSB
        raise ValueError('仅支持小端序 ELF')
 
    # ELF64 header: e_shoff @0x28 (8B), e_shentsize @0x3a (2B),
    #              e_shnum @0x3c (2B), e_shstrndx @0x3e (2B)
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
 
    if e_shentsize < 64 or e_shoff == 0 or e_shnum == 0:
        raise ValueError('ELF section header 表不可用')
 
    def shdr(i: int) -> dict:
        off = e_shoff + i * e_shentsize
        name_idx, sh_type = struct.unpack_from('<II', data, off)
        sh_flags = struct.unpack_from('<Q', data, off + 8)[0]
        sh_addr = struct.unpack_from('<Q', data, off + 16)[0]
        sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
        sh_size = struct.unpack_from('<Q', data, off + 32)[0]
        return {
            'name_idx': name_idx, 'sh_type': sh_type, 'sh_flags': sh_flags,
            'sh_addr': sh_addr, 'sh_offset': sh_offset, 'sh_size': sh_size,
        }
 
    shstr_hdr = shdr(e_shstrndx)
    shstrtab = data[shstr_hdr['sh_offset']:shstr_hdr['sh_offset'] + shstr_hdr['sh_size']]
 
    text_meta: tuple[int, int, int] | None = None
    for i in range(e_shnum):
        sh = shdr(i)
        if sh['sh_type'] != SHT_PROGBITS or not (sh['sh_flags'] & SHF_EXECINSTR):
            continue
        end = shstrtab.find(b'\x00', sh['name_idx'])
        name = shstrtab[sh['name_idx']:end].decode('ascii', errors='replace')
        if name == '.text':
            text_meta = (sh['sh_addr'], sh['sh_offset'], sh['sh_size'])
            break
 
    if text_meta is None:
        raise ValueError('未找到 .text 段')
 
    sh_addr, sh_offset, sh_size = text_meta
    section_bytes = data[sh_offset:sh_offset + sh_size]
    if len(section_bytes) != sh_size:
        raise ValueError(f'.text 段截断: 期望 {sh_size} B，实得 {len(section_bytes)} B')
    return sh_addr, sh_offset, section_bytes
 
 
# ── fingerprint 处理 ─────────────────────────────────────────────
 
 
def fingerprint_to_bytes(raw: str) -> bytes:
    cleaned = re.sub(r'[^0-9A-Fa-f]', '', raw or '')
    if not cleaned or len(cleaned) % 2 != 0:
        raise ValueError(f'非法 fingerprint: {raw!r}')
    return bytes.fromhex(cleaned)
 
 
def find_unique(haystack: bytes, needle: bytes) -> int:
    """在 haystack 中查找 needle，要求恰好命中一次；返回命中偏移。"""
    first = haystack.find(needle)
    if first < 0:
        raise LookupError('fingerprint 未命中')
    second = haystack.find(needle, first + 1)
    if second >= 0:
        raise LookupError(f'fingerprint 命中多次（至少 2 处：0x{first:x}, 0x{second:x}）')
    return first
 
 
# ── 扫描逻辑 ─────────────────────────────────────────────────────
 
 
def scan_binary(binary_path: Path, fingerprints: dict[str, str]) -> dict[str, dict]:
    """fingerprints: {hook_name: 'AA BB CC ...'}。返回 {hook_name: {rva, offset, fingerprint}}。"""
    sh_addr, sh_offset, section = _read_elf64_text_section(binary_path)
    results: dict[str, dict] = {}
    errors: dict[str, str] = {}
 
    for name, fp_str in fingerprints.items():
        try:
            needle = fingerprint_to_bytes(fp_str)
            off_in_text = find_unique(section, needle)
        except (ValueError, LookupError) as exc:
            errors[name] = str(exc)
            continue
        rva = sh_addr + off_in_text
        results[name] = {
            'rva': f'0x{rva:08X}',
            'offset_in_text': off_in_text,
            'fingerprint': ' '.join(f'{b:02X}' for b in needle),
            'fingerprint_len': len(needle),
        }
 
    if errors:
        results['_errors'] = errors  # type: ignore[assignment]
    results['_meta'] = {
        'text_sh_addr': f'0x{sh_addr:x}',
        'text_sh_offset': f'0x{sh_offset:x}',
        'text_size': len(section),
    }
    return results
 
 
# ── CLI ──────────────────────────────────────────────────────────
 
 
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Locate Chrome hook RVAs via baseline fingerprints')
    p.add_argument('--binary', required=True, help='目标 Chrome 二进制路径')
    p.add_argument('--baseline', required=True, help='baseline hooks JSON（提供 fingerprint 与人工字段）')
    p.add_argument('--version', default=None, help='目标 Chrome 版本号，组装输出 JSON 时必填')
    p.add_argument('--out', default=None, help='输出 hooks JSON；留空则仅打印扫描结果')
    p.add_argument('--metadata', default=None, help='可选 artifacts/chrome/<ver>/metadata.json')
    p.add_argument('--scan-only', action='store_true', help='只扫描 RVA，不组装 JSON')
    return p.parse_args()
 
 
def build_output(baseline: dict, scan: dict, version: str, metadata: dict | None) -> dict:
    merged = copy.deepcopy(baseline)
    merged.setdefault('meta', {})
    merged['meta']['version'] = version
    merged['meta']['source'] = 'fingerprint_scan+baseline143'
    merged['meta']['baseline_version'] = baseline.get('meta', {}).get('version')
    merged['meta']['generated_at'] = dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    merged['meta']['verified'] = False
    merged['meta'].pop('verified_method', None)
    merged['meta'].pop('p3_capture_rate', None)
    merged['meta'].pop('p4_tuple_hit_rate', None)
 
    if metadata:
        if metadata.get('chrome_sha256'):
            merged['meta']['chrome_sha256'] = metadata['chrome_sha256']
        if metadata.get('milestone'):
            merged['meta']['milestone'] = metadata['milestone']
 
    for name in REQUIRED_HOOKS:
        if name not in scan:
            raise KeyError(f'扫描结果缺少 {name}')
        merged.setdefault('hook_points', {}).setdefault(name, {})
        merged['hook_points'][name]['rva'] = scan[name]['rva']
        merged['hook_points'][name]['fingerprint'] = scan[name]['fingerprint']
        merged['hook_points'][name]['fingerprint_len'] = scan[name]['fingerprint_len']
 
    return merged
 
 
def main() -> int:
    args = parse_args()
    baseline = json.loads(Path(args.baseline).read_text(encoding='utf-8'))
 
    fingerprints = {}
    hp = baseline.get('hook_points', {})
    for name in REQUIRED_HOOKS:
        fp = hp.get(name, {}).get('fingerprint')
        if not fp:
            print(f'[ERR] baseline 缺少 hook_points.{name}.fingerprint', file=sys.stderr)
            return 2
        fingerprints[name] = fp
 
    scan = scan_binary(Path(args.binary), fingerprints)
    errors = scan.pop('_errors', None)
    meta = scan.pop('_meta')
 
    print(f'[*] .text sh_addr={meta["text_sh_addr"]}  size={meta["text_size"]} B')
    for name in REQUIRED_HOOKS:
        if name in scan:
            r = scan[name]
            print(f'[HIT] {name:15s} rva={r["rva"]} (offset_in_text=0x{r["offset_in_text"]:x})')
        else:
            err = (errors or {}).get(name, 'unknown')
            print(f'[MISS] {name:15s} {err}')
 
    if errors:
        print('[ERR] 有 fingerprint 未唯一命中，无法组装 JSON', file=sys.stderr)
        return 3
 
    if args.scan_only or not args.out:
        return 0
 
    if not args.version:
        print('[ERR] 写出 JSON 时必须提供 --version', file=sys.stderr)
        return 2
 
    metadata = json.loads(Path(args.metadata).read_text(encoding='utf-8')) if args.metadata else None
    merged = build_output(baseline, scan, args.version, metadata)
 
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(merged, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'[OK] 写出 {out}')
    return 0
 
 
if __name__ == '__main__':
    sys.exit(main())
