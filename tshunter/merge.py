#!/usr/bin/env python3
"""
tools/merge_analysis.py — 合并 TSHunter 自动字段 + baseline 人工字段
 
P6 Phase 2：TSHunter 自动产出 4 个 hook_points 的 rva + fingerprint；
本脚本把这些值与 baseline (Chrome 143) 的人工字段合并成完整的
hooks/chrome_<version>_linux_x86_64.json，可直接被 lib/version_detect.py 加载。
 
用法：
  python3 tools/merge_analysis.py \\
      --auto path/to/TSHunter_auto.json \\
      --baseline hooks/chrome_143.0.7499.169_linux_x86_64.json \\
      --version 142.0.7339.185 \\
      --out hooks/chrome_142.0.7339.185_linux_x86_64.json
 
可选：
  --metadata artifacts/chrome/<ver>/metadata.json  # 补 sha256
  --subtract-image-base 0x00100000                # TSHunter 若返回未减基址的
                                                   # 绝对地址，统一减掉
"""
 
from __future__ import annotations
 
import argparse
import copy
import datetime as dt
import json
import re
import sys
from pathlib import Path
 
REQUIRED_HOOKS = ('prf', 'key_expansion', 'hkdf', 'ssl_log_secret')
RVA_RE = re.compile(r'^0x[0-9A-Fa-f]+$')
FP_BYTE_RE = re.compile(r'^[0-9A-Fa-f]{2}(?:[ _-]?[0-9A-Fa-f]{2})*$')
 
 
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Merge TSHunter auto JSON with baseline hooks JSON')
    p.add_argument('--auto', required=True, help='TSHunter 自动分析输出 JSON')
    p.add_argument('--baseline', required=True, help='baseline hooks JSON（通常是 Chrome 143）')
    p.add_argument('--version', required=True, help='目标 Chrome 版本号，如 142.0.7339.185')
    p.add_argument('--out', required=True, help='输出 JSON 路径')
    p.add_argument('--metadata', default=None, help='可选 artifacts/chrome/<ver>/metadata.json，用于补 sha256')
    p.add_argument(
        '--subtract-image-base',
        default=None,
        help='若 TSHunter 返回绝对地址（如 Ghidra imageBase 0x00100000），统一减掉；留空表示 rva 已是相对偏移',
    )
    p.add_argument('--dry-run', action='store_true', help='只校验，不写文件')
    return p.parse_args()
 
 
def load_json(path: str | Path) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)
 
 
def parse_hex_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    v = value.strip()
    return int(v, 16) if v.lower().startswith('0x') else int(v)
 
 
def normalize_rva(raw_rva: str | int, subtract_base: int) -> str:
    n = parse_hex_int(raw_rva)
    if subtract_base:
        if n < subtract_base:
            raise ValueError(f'RVA {hex(n)} < subtract_base {hex(subtract_base)}')
        n -= subtract_base
    return f'0x{n:08X}'
 
 
def normalize_fingerprint(raw: str) -> tuple[str, int]:
    """统一 fingerprint 为 'AA BB CC' 格式；返回 (字符串, 字节数)。"""
    cleaned = re.sub(r'[^0-9A-Fa-f]', '', raw or '')
    if not cleaned or len(cleaned) % 2 != 0:
        raise ValueError(f'非法 fingerprint: {raw!r}')
    bytes_ = [cleaned[i:i + 2].upper() for i in range(0, len(cleaned), 2)]
    return ' '.join(bytes_), len(bytes_)
 
 
def extract_auto_hook(auto: dict, key: str) -> dict:
    hps = auto.get('hook_points') or {}
    node = hps.get(key)
    if not node:
        raise KeyError(f'TSHunter 输出缺少 hook_points.{key}')
    if 'rva' not in node or 'fingerprint' not in node:
        raise KeyError(f'hook_points.{key} 缺少 rva 或 fingerprint')
    return node
 
 
def schema_check(merged: dict) -> list[str]:
    errors: list[str] = []
    hp = merged.get('hook_points', {})
    for name in REQUIRED_HOOKS:
        if name not in hp:
            errors.append(f'missing hook_points.{name}')
            continue
        rva = hp[name].get('rva')
        if not isinstance(rva, str) or not RVA_RE.match(rva):
            errors.append(f'hook_points.{name}.rva 非法: {rva!r}')
        fp = hp[name].get('fingerprint')
        if not isinstance(fp, str) or not FP_BYTE_RE.match(fp):
            errors.append(f'hook_points.{name}.fingerprint 非法')
 
    for key in ('tls13_label_map', 'tls13_key_len_offsets', 'struct_offsets'):
        if not isinstance(merged.get(key), dict) or not merged[key]:
            errors.append(f'missing or empty {key}')
 
    so = merged.get('struct_offsets', {})
    for name in ('ssl_st_rbio', 'bio_st_num'):
        v = so.get(name)
        if not isinstance(v, str) or not RVA_RE.match(v):
            errors.append(f'struct_offsets.{name} 非法: {v!r}')
 
    return errors
 
 
def merge(auto: dict, baseline: dict, version: str, subtract_base: int, metadata: dict | None) -> dict:
    merged = copy.deepcopy(baseline)
 
    # meta
    merged.setdefault('meta', {})
    merged['meta']['version'] = version
    merged['meta']['source'] = 'TSHunter+baseline143'
    merged['meta']['baseline_version'] = baseline.get('meta', {}).get('version')
    merged['meta']['generated_at'] = dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    merged['meta']['verified'] = False
    merged['meta'].pop('verified_method', None)
    merged['meta'].pop('p3_capture_rate', None)
    merged['meta'].pop('p4_tuple_hit_rate', None)
 
    if metadata:
        if metadata.get('chrome_sha256'):
            merged['meta']['chrome_sha256'] = metadata['chrome_sha256']
        if metadata.get('zip_sha256'):
            merged['meta']['zip_sha256'] = metadata['zip_sha256']
        if metadata.get('milestone'):
            merged['meta']['milestone'] = metadata['milestone']
 
    # hook_points: 只覆盖 rva / fingerprint / fingerprint_len
    # 其余字段（role / params / read_on / output_len / function_name）保留 baseline
    for name in REQUIRED_HOOKS:
        auto_node = extract_auto_hook(auto, name)
        if name not in merged.setdefault('hook_points', {}):
            merged['hook_points'][name] = {}
        rva = normalize_rva(auto_node['rva'], subtract_base)
        fp_str, fp_len = normalize_fingerprint(auto_node['fingerprint'])
        merged['hook_points'][name]['rva'] = rva
        merged['hook_points'][name]['fingerprint'] = fp_str
        merged['hook_points'][name]['fingerprint_len'] = fp_len
        # 保留 auto 侧独有的补充字段（如 note / ghidra_name）
        for k in ('ghidra_name', 'note'):
            if auto_node.get(k):
                merged['hook_points'][name][k] = auto_node[k]
 
    return merged
 
 
def main() -> int:
    args = parse_args()
 
    auto = load_json(args.auto)
    baseline = load_json(args.baseline)
    metadata = load_json(args.metadata) if args.metadata else None
 
    subtract_base = parse_hex_int(args.subtract_image_base) if args.subtract_image_base else 0
 
    try:
        merged = merge(auto, baseline, args.version, subtract_base, metadata)
    except (KeyError, ValueError) as exc:
        print(f'[ERR] 合并失败: {exc}', file=sys.stderr)
        return 2
 
    errors = schema_check(merged)
    if errors:
        print('[ERR] schema 校验失败:', file=sys.stderr)
        for e in errors:
            print(f'  - {e}', file=sys.stderr)
        return 3
 
    if args.dry_run:
        print('[DRY] schema OK；未写文件')
        json.dump(merged, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
 
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(f'[OK] 写出 {out_path}')
    return 0
 
 
if __name__ == '__main__':
    sys.exit(main())
