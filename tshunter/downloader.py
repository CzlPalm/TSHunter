#!/usr/bin/env python3
"""
tools/chrome_downloader.py — 批量下载 Chrome for Testing 二进制

用法:
  python3 tools/chrome_downloader.py --milestones 135,136,143
  python3 tools/chrome_downloader.py --milestones 143-149 --source cft-all
  python3 tools/chrome_downloader.py --source cft-all --version-range 143.0.7499.0..143.0.7499.146
  python3 tools/chrome_downloader.py --all
  python3 tools/chrome_downloader.py --list

--source 选项:
  cft-latest   （默认）每 milestone 只取最新一个版本
  cft-all      取该 milestone 的所有历史 stable 版本（每 major 通常 30-80 条）

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
API_URL_ALL = (
    'https://googlechromelabs.github.io/chrome-for-testing/'
    'known-good-versions-with-downloads.json'
)
DEFAULT_OUTPUT_DIR = Path('artifacts/chrome')
TARGET_PLATFORM = 'linux64'
TARGET_BINARY = 'chrome'
TARGET_ARCHIVE_NAME = 'chrome-linux64.zip'
TARGET_EXTRACTED_BINARY = 'chrome-linux64/chrome'
TIMEOUT = 60


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='批量下载 Chrome for Testing 二进制'
    )
    parser.add_argument('--milestones', help='逗号分隔的 milestone 或范围，例如 135,136,143 或 143-149')
    parser.add_argument('--versions', help='逗号分隔的完整版本号，例如 143.0.7499.0,143.0.7499.146')
    parser.add_argument('--version-range',
                        help='完整版本闭区间，例如 143.0.7499.0..143.0.7499.146')
    parser.add_argument('--all', action='store_true', help='选择所有可用 milestone')
    parser.add_argument('--list', action='store_true', help='仅列出可用版本，不下载；可与 --milestones 配合过滤')
    parser.add_argument(
        '--source',
        choices=['cft-latest', 'cft-all'],
        default='cft-latest',
        help='版本源：cft-latest（每 milestone 一个最新版，默认）/ cft-all（全部历史 stable）',
    )
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
    args = parser.parse_args(argv)
    selectors = [args.milestones, args.versions, args.version_range]
    if args.all and any(selectors):
        parser.error('--all cannot be used together with --milestones/--versions/--version-range')
    if not args.list and not args.all and not any(selectors):
        parser.error('one of --milestones, --versions, --version-range, or --all is required unless --list is used')
    return args


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        return json.load(resp)


def normalize_milestones(raw: str) -> list[str]:
    """Parse '135,136,143' or '143-149' or mixed '135,143-145' into sorted list."""
    milestones = []
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            lo, hi = part.split('-', 1)
            if not lo.isdigit() or not hi.isdigit():
                raise ValueError(f'非法 milestone 范围: {part}')
            for m in range(int(lo), int(hi) + 1):
                milestones.append(str(m))
        else:
            if not part.isdigit():
                raise ValueError(f'非法 milestone: {part}')
            milestones.append(part)
    if not milestones:
        raise ValueError('milestones 不能为空')
    # deduplicate, preserve order
    seen: set[str] = set()
    result = []
    for m in milestones:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def _version_tuple(value: str) -> tuple[int, int, int, int]:
    parts = value.split('.')
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        raise ValueError(f'非法版本号: {value}')
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def normalize_versions(raw: str) -> set[str]:
    versions: list[str] = []
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        _version_tuple(part)
        versions.append(part)
    if not versions:
        raise ValueError('versions 不能为空')
    return set(versions)


def parse_version_range(raw: str) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]:
    if '..' in raw:
        lo_raw, hi_raw = raw.split('..', 1)
    elif '-' in raw:
        lo_raw, hi_raw = raw.split('-', 1)
    else:
        raise ValueError(f'非法版本区间: {raw}，应使用 START..END')
    lo = _version_tuple(lo_raw.strip())
    hi = _version_tuple(hi_raw.strip())
    if lo > hi:
        raise ValueError(f'非法版本区间: start 大于 end: {raw}')
    return lo, hi


def filter_record_list(records: list[dict], versions: str | None = None,
                       version_range: str | None = None) -> list[dict]:
    wanted = normalize_versions(versions) if versions else None
    bounds = parse_version_range(version_range) if version_range else None

    filtered = []
    for rec in records:
        version = rec.get('version', '')
        if wanted is not None and version not in wanted:
            continue
        if bounds is not None:
            vt = _version_tuple(version)
            if not (bounds[0] <= vt <= bounds[1]):
                continue
        filtered.append(rec)
    return filtered


def extract_records(data: dict) -> dict[str, dict]:
    """Extract one record per milestone from latest-versions JSON (keyed by milestone)."""
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


def _fetch_cft_known_good(milestone_filter: set[str] | None = None) -> list[dict]:
    """Fetch all historical stable versions from known-good-versions-with-downloads.json.

    Returns list of record dicts, optionally filtered to the given milestone majors.
    """
    data = fetch_json(API_URL_ALL)
    versions_raw = data.get('versions', [])
    records: list[dict] = []
    for entry in versions_raw:
        version = entry.get('version', '')
        if not version:
            continue
        major = version.split('.')[0]
        if milestone_filter is not None and major not in milestone_filter:
            continue
        downloads = entry.get('downloads', {}).get(TARGET_BINARY, [])
        linux_item = next((d for d in downloads if d.get('platform') == TARGET_PLATFORM), None)
        if not linux_item:
            continue
        records.append({
            'milestone': major,
            'version': version,
            'url': linux_item['url'],
            'platform': TARGET_PLATFORM,
            'binary': TARGET_BINARY,
        })
    return records


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


def _download_record_list(records: list[dict], output_dir: Path, discard_zip: bool) -> int:
    """Download a flat list of records (used by cft-all path)."""
    exit_code = 0
    for rec in records:
        version_dir = output_dir / rec['version']
        ensure_clean_dir(version_dir)
        zip_path = version_dir / TARGET_ARCHIVE_NAME
        chrome_path = version_dir / 'chrome'

        if chrome_path.exists() and (version_dir / 'metadata.json').exists():
            print(f'[SKIP] {rec["version"]}: 已存在')
            continue

        print(f'[DOWN] milestone={rec["milestone"]} version={rec["version"]}')
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


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    source = getattr(args, 'source', 'cft-latest')

    # ── cft-all 路径：全量历史版本 ──────────────────────────────────────────
    if source == 'cft-all':
        try:
            milestone_filter: set[str] | None = None
            if args.milestones:
                try:
                    milestones = normalize_milestones(args.milestones)
                except ValueError as exc:
                    print(f'[ERR] {exc}', file=sys.stderr)
                    return 1
                milestone_filter = set(milestones)

            print('[*] 获取全量历史版本清单 (cft-all)…')
            all_records = _fetch_cft_known_good(milestone_filter)
            all_records = filter_record_list(
                all_records,
                versions=args.versions,
                version_range=args.version_range,
            )
        except Exception as exc:
            print(f'[ERR] 获取 cft-all 数据失败: {exc}', file=sys.stderr)
            return 1

        if args.list:
            for rec in all_records:
                print(f'{rec["milestone"]}\t{rec["version"]}\t{rec["url"]}')
            return 0

        print(f'[*] 输出目录: {output_dir}')
        print(f'[*] 找到 {len(all_records)} 个版本')
        return _download_record_list(all_records, output_dir, args.discard_zip)

    # ── cft-latest 路径（默认）：每 milestone 一个最新版 ────────────────────
    try:
        data = fetch_json(API_URL)
        records = extract_records(data)
    except Exception as exc:
        print(f'[ERR] 获取 Chrome for Testing 元数据失败: {exc}', file=sys.stderr)
        return 1

    if args.versions or args.version_range:
        selected_records = filter_record_list(
            list(records.values()),
            versions=args.versions,
            version_range=args.version_range,
        )
        if args.list:
            for rec in selected_records:
                print(f'{rec["milestone"]}\t{rec["version"]}\t{rec["url"]}')
            return 0
        print(f'[*] 输出目录: {output_dir}')
        print(f'[*] 找到 {len(selected_records)} 个版本')
        return _download_record_list(selected_records, output_dir, args.discard_zip)

    if args.list:
        if args.milestones:
            try:
                milestones = normalize_milestones(args.milestones)
            except ValueError as exc:
                print(f'[ERR] {exc}', file=sys.stderr)
                return 1
            return list_records(records, milestones)
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
