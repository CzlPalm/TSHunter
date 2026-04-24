#!/usr/bin/env python3
"""
tools/chrome_downloader.py — 批量下载 Chrome for Testing 二进制

用法:
  python3 tools/chrome_downloader.py --milestones 135,136,137,138,139,140,141,142,143
  python3 tools/chrome_downloader.py --all
  python3 tools/chrome_downloader.py --list

输出目录结构:
  artifacts/chrome/{version}/
    ├── chrome              ← 解压后的二进制
    ├── metadata.json       ← 版本号、SHA256、下载时间、平台
    └── chrome-linux64.zip  ← 原始下载包（默认保留）
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

API_URL = (
    'https://googlechromelabs.github.io/chrome-for-testing/'
    'latest-versions-per-milestone-with-downloads.json'
)
DEFAULT_OUTPUT_DIR = Path('artifacts/chrome')
TARGET_PLATFORM = 'linux64'
TARGET_BINARY = 'chrome'
TARGET_ARCHIVE_NAME = 'chrome-linux64.zip'
TARGET_EXTRACTED_BINARY = 'chrome-linux64/chrome'
TIMEOUT = 60


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='批量下载 Chrome for Testing 二进制'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--milestones', help='逗号分隔的 milestone 列表，例如 135,136,143')
    group.add_argument('--all', action='store_true', help='下载所有可用 milestone 的最新版本')
    group.add_argument('--list', action='store_true', help='仅列出可用版本，不下载')
    parser.add_argument(
        '--output-dir',
        default=str(DEFAULT_OUTPUT_DIR),
        help='输出目录，默认 artifacts/chrome',
    )
    parser.add_argument(
        '--discard-zip',
        action='store_true',
        help='下载完成后删除原始 zip，仅保留 chrome 与 metadata.json',
    )
    return parser.parse_args()


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        return json.load(resp)


def normalize_milestones(raw: str) -> list[str]:
    milestones = []
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        if not item.isdigit():
            raise ValueError(f'非法 milestone: {item}')
        milestones.append(item)
    if not milestones:
        raise ValueError('milestones 不能为空')
    return milestones


def extract_records(data: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    milestones = data.get('milestones', {})
    for milestone, info in milestones.items():
        version = info.get('version')
        downloads = info.get('downloads', {}).get(TARGET_BINARY, [])
        linux_item = next((d for d in downloads if d.get('platform') == TARGET_PLATFORM), None)
        if not version or not linux_item:
            continue
        out[str(milestone)] = {
            'milestone': str(milestone),
            'version': version,
            'url': linux_item['url'],
            'platform': TARGET_PLATFORM,
            'binary': TARGET_BINARY,
        }
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def run_strings_check(binary_path: Path) -> dict[str, int | None]:
    patterns = {
        'master secret': None,
        'c hs traffic': None,
    }
    for pattern in patterns:
        try:
            proc = subprocess.run(
                ['strings', str(binary_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            patterns[pattern] = sum(1 for line in proc.stdout.splitlines() if pattern in line)
        except Exception:
            patterns[pattern] = None
    return patterns


def ensure_clean_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def download_file(url: str, target_path: Path) -> None:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp, target_path.open('wb') as f:
        shutil.copyfileobj(resp, f)


def extract_binary(zip_path: Path, version_dir: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmp_path)
        extracted = tmp_path / TARGET_EXTRACTED_BINARY
        if not extracted.exists():
            raise FileNotFoundError(f'解压后未找到二进制: {extracted}')
        target_binary = version_dir / 'chrome'
        shutil.copy2(extracted, target_binary)
        target_binary.chmod(0o755)
        return target_binary


def write_metadata(version_dir: Path, record: dict, zip_sha256: str, chrome_sha256: str, strings_check: dict) -> None:
    metadata = {
        'milestone': record['milestone'],
        'version': record['version'],
        'platform': record['platform'],
        'binary': record['binary'],
        'url': record['url'],
        'downloaded_at_utc': dt.datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'zip_sha256': zip_sha256,
        'chrome_sha256': chrome_sha256,
        'strings_check': strings_check,
    }
    with (version_dir / 'metadata.json').open('w', encoding='utf-8') as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)


def list_records(records: dict[str, dict], milestones: list[str] | None = None) -> int:
    selected = milestones if milestones is not None else sorted(records.keys(), key=int)
    missing = [m for m in selected if m not in records]
    for m in missing:
        print(f'[MISS] milestone {m}: API 中无 linux64 chrome 下载项')
    for m in selected:
        rec = records.get(m)
        if not rec:
            continue
        print(f'{m}\t{rec["version"]}\t{rec["url"]}')
    return 1 if missing else 0


def download_records(records: dict[str, dict], milestones: list[str], output_dir: Path, discard_zip: bool) -> int:
    exit_code = 0
    for milestone in milestones:
        rec = records.get(milestone)
        if not rec:
            print(f'[MISS] milestone {milestone}: API 中无 linux64 chrome 下载项', file=sys.stderr)
            exit_code = 1
            continue

        version_dir = output_dir / rec['version']
        ensure_clean_dir(version_dir)
        zip_path = version_dir / TARGET_ARCHIVE_NAME
        chrome_path = version_dir / 'chrome'

        if chrome_path.exists() and (version_dir / 'metadata.json').exists():
            print(f'[SKIP] {rec["version"]}: 已存在 chrome 与 metadata.json')
            continue

        print(f'[DOWN] milestone={milestone} version={rec["version"]}')
        print(f'       url={rec["url"]}')
        try:
            download_file(rec['url'], zip_path)
            zip_sha = sha256_file(zip_path)
            chrome_binary = extract_binary(zip_path, version_dir)
            chrome_sha = sha256_file(chrome_binary)
            strings_check = run_strings_check(chrome_binary)
            write_metadata(version_dir, rec, zip_sha, chrome_sha, strings_check)
            if discard_zip and zip_path.exists():
                zip_path.unlink()
            print(f'[OK] {rec["version"]} -> {chrome_binary}')
        except (urllib.error.URLError, TimeoutError, zipfile.BadZipFile, FileNotFoundError, OSError) as exc:
            print(f'[ERR] {rec["version"]}: {exc}', file=sys.stderr)
            exit_code = 1
    return exit_code


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        data = fetch_json(API_URL)
        records = extract_records(data)
    except Exception as exc:
        print(f'[ERR] 获取 Chrome for Testing 元数据失败: {exc}', file=sys.stderr)
        return 1

    if args.list:
        return list_records(records)

    try:
        if args.all:
            milestones = sorted(records.keys(), key=int)
        else:
            milestones = normalize_milestones(args.milestones)
    except ValueError as exc:
        print(f'[ERR] {exc}', file=sys.stderr)
        return 1

    print(f'[*] 输出目录: {output_dir}')
    print(f'[*] 目标 milestone: {", ".join(milestones)}')
    return download_records(records, milestones, output_dir, args.discard_zip)


if __name__ == '__main__':
    sys.exit(main())

