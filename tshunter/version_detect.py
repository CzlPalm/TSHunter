#!/usr/bin/env python3
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHROME_BINARIES = [
    '/opt/google/chrome/chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
]


def detect_chrome_version(binary_path='/opt/google/chrome/chrome'):
    for candidate in _candidate_binaries(binary_path):
        version = _detect_from_binary(candidate)
        if version:
            return version
    for path in [os.path.expanduser('~/.config/google-chrome/Last Version'), '/tmp/chrome_p3_test/Last Version']:
        try:
            with open(path) as f:
                version = f.read().strip()
            if _is_version(version):
                return version
        except Exception:
            continue
    return None


def find_chrome_network_pid(user_data_dir):
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit():
            continue
        try:
            with open(f'/proc/{entry.name}/cmdline', 'rb') as f:
                cmd = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore')
            if 'NetworkService' in cmd and user_data_dir in cmd:
                return int(entry.name)
        except (PermissionError, FileNotFoundError, OSError):
            continue
    return None


def load_config(version, config_dir=None):
    if config_dir is None:
        config_dir = ROOT / 'tls_capture' / 'hooks'
    else:
        config_dir = Path(config_dir)
    if not config_dir.is_dir():
        return None
    configs = []
    for path in sorted(config_dir.glob('*.json')):
        try:
            cfg = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            continue
        cfg_version = cfg.get('meta', {}).get('version', '')
        if not _is_version(cfg_version):
            continue
        cfg['_config_path'] = str(path)
        configs.append(cfg)
    if not configs:
        return None
    for cfg in configs:
        if cfg['meta']['version'] == version:
            cfg['_match_type'] = 'exact'
            return cfg
    major = '.'.join(version.split('.')[:2])
    for cfg in configs:
        if cfg['meta']['version'].startswith(major + '.'):
            cfg['_match_type'] = 'major'
            return cfg
    return None


def build_hook_script(config, hooks_dir=None):
    if hooks_dir is None:
        hooks_dir = ROOT / 'tls_capture' / 'hooks'
    else:
        hooks_dir = Path(hooks_dir)
    template_path = hooks_dir / 'chrome_hooks.js'
    template = template_path.read_text(encoding='utf-8')
    if '%HOOK_CONFIG%' not in template:
        raise ValueError('chrome_hooks.js 缺少 %HOOK_CONFIG% 占位符')
    hook_config = _build_hook_config(config)
    injected = json.dumps(hook_config, ensure_ascii=False, indent=2)
    return template.replace('%HOOK_CONFIG%', injected)


def _build_hook_config(config):
    hook_points = config.get('hook_points', {})
    struct_offsets = config.get('struct_offsets', {})
    tls13_offsets = config.get('tls13_key_len_offsets', {})
    return {
        'meta': {
            'browser': config.get('meta', {}).get('browser'),
            'version': config.get('meta', {}).get('version'),
            'match_type': config.get('_match_type', 'unknown'),
        },
        'hook_points': {
            'prf': {'rva': hook_points.get('prf', {}).get('rva')},
            'key_expansion': {'rva': hook_points.get('key_expansion', {}).get('rva')},
            'hkdf': {'rva': hook_points.get('hkdf', {}).get('rva')},
            'ssl_log_secret': {'rva': hook_points.get('ssl_log_secret', {}).get('rva')},
        },
        'tls13_label_map': config.get('tls13_label_map', {}),
        'tls13_key_len_offsets': {
            'c e traffic': tls13_offsets.get('c_e_traffic'),
            'c hs traffic': tls13_offsets.get('c_hs_traffic'),
            's hs traffic': tls13_offsets.get('s_hs_traffic'),
            'c ap traffic': tls13_offsets.get('c_ap_traffic'),
            's ap traffic': tls13_offsets.get('s_ap_traffic'),
            'exp master': tls13_offsets.get('exp_master'),
        },
        'struct_offsets': {
            'ssl_st_rbio': struct_offsets.get('ssl_st_rbio', '0x240'),
            'bio_st_num': struct_offsets.get('bio_st_num', '0x03c'),
        },
    }


def _candidate_binaries(binary_path):
    seen = set()
    for candidate in [binary_path, *DEFAULT_CHROME_BINARIES]:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        yield candidate


def _detect_from_binary(binary_path):
    if not binary_path or not os.path.exists(binary_path):
        return None
    try:
        out = subprocess.check_output([binary_path, '--version'], timeout=5, stderr=subprocess.DEVNULL).decode().strip()
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def _is_version(value):
    return bool(re.fullmatch(r'\d+\.\d+\.\d+\.\d+', value or ''))

