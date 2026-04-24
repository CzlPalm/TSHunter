"""VersionConfigLoader: U2 三层合并加载器.

加载优先级:
  1. DB `hook_points` (版本相关 rva/fingerprint/ghidra_name/role/...)
  2. `profiles/<profile_ref>.json` (跨版本稳定的 client_random / tls13_* / struct_offsets /
     five_tuple_strategy / hook_templates)
  3. `versions.verified` + `versions.note` (验证层)

DB miss 时:
  - auto_relocate=True 且提供 binary_path → 调用 `tshunter.relocate` 内联 relocate,
    成功则写回 DB 再重查
  - 仍然 miss → 若 allow_json_fallback 则退回旧 `tls_capture/hooks/*.json`,
    否则抛 `VersionNotInDB`
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / 'data' / 'fingerprints.db'
DEFAULT_PROFILES_DIR = ROOT / 'profiles'
LEGACY_JSON_DIR = ROOT / 'tls_capture' / 'hooks'

TLS_LIB_DEFAULT_PROFILE = {
    'boringssl': 'boringssl_chrome',
    'nss': 'nss_firefox',
    'openssl': 'openssl_generic',
    'rustls': 'rustls_generic',
}


def _parse_note(note: Any) -> Optional[dict]:
    if not note or not isinstance(note, str):
        return None
    stripped = note.strip()
    if not stripped.startswith('{'):
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _extract_verified_method(note: Any) -> Optional[str]:
    parsed = _parse_note(note)
    if parsed and 'verified_method' in parsed:
        return parsed['verified_method']
    return note if isinstance(note, str) else None


def _extract_verified_metrics(note: Any) -> Optional[dict]:
    parsed = _parse_note(note)
    if not parsed:
        return None
    metrics = {k: parsed[k] for k in ('p3_capture_rate', 'p4_tuple_hit_rate', 'annotated_at')
               if k in parsed}
    return metrics or None


class VersionNotInDB(Exception):
    """Raised when (browser, version, platform, arch) has no entry in DB and no relocate source."""


class RelocateFailed(Exception):
    """Raised when auto-relocate was attempted but did not yield a confident result."""


class ProfileMissing(Exception):
    """Raised when profile_ref points to a JSON file that does not exist."""


class VersionConfigLoader:
    def __init__(
        self,
        db_path: Optional[Path] = None,
        profiles_dir: Optional[Path] = None,
        allow_json_fallback: bool = False,
        auto_relocate: bool = True,
    ):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.profiles_dir = Path(profiles_dir) if profiles_dir else DEFAULT_PROFILES_DIR
        self.allow_json_fallback = allow_json_fallback
        self.auto_relocate = auto_relocate

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _query_version_row(self, conn, browser, version, platform, arch) -> Optional[sqlite3.Row]:
        return conn.execute(
            """
            SELECT v.id, v.browser_id, v.version, v.platform, v.arch, v.profile_ref,
                   v.verified, v.note, v.image_base, v.binary_sha256, v.binary_size,
                   v.analysis_date, v.analyzer_version, v.tls_lib_commit,
                   ts.name AS tls_lib, b.name AS browser
            FROM versions v
            JOIN browsers b ON b.id = v.browser_id
            LEFT JOIN tls_stacks ts ON ts.id = v.tls_stack_id
            WHERE b.name=? AND v.version=? AND v.platform=? AND v.arch=?
            """,
            (browser, version, platform, arch),
        ).fetchone()

    def _query_hook_rows(self, conn, version_id: int) -> list:
        rows = conn.execute(
            """
            SELECT kind, function_name, ghidra_name, rva, fingerprint, fingerprint_len,
                   role, params_json, read_on, output_len, source, verified,
                   derived_from_version_id, rva_delta, relocation_method, relocation_confidence,
                   note
            FROM hook_points WHERE version_id=?
            """,
            (version_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def _find_same_major_minor_baseline(self, conn, browser, version, platform, arch) -> Optional[dict]:
        major_minor = '.'.join(version.split('.')[:2])
        rows = conn.execute(
            """
            SELECT v.id, v.version, v.platform, v.arch, v.verified, b.name AS browser
            FROM versions v
            JOIN browsers b ON b.id = v.browser_id
            WHERE b.name=? AND v.version LIKE ? AND v.platform=? AND v.arch=? AND v.verified=1
            ORDER BY v.version DESC
            """,
            (browser, f"{major_minor}.%", platform, arch),
        ).fetchall()
        for row in rows:
            if row['version'] != version:
                return dict(row)
        return None

    def _run_inline_relocate(self, binary_path: Path, source_browser: str,
                             source_version: str, source_platform: str, source_arch: str) -> dict:
        # Lazy import to avoid mandatory pyelftools dep when loader is used purely for DB hits.
        from tshunter import relocate as relocate_mod  # type: ignore

        conn = self._connect()
        try:
            rows = relocate_mod.load_hooks_from_db(
                conn, source_browser, source_version, source_platform, source_arch,
            )
            if not rows:
                raise RelocateFailed(
                    f"baseline {source_browser} {source_version} has no hook_points to relocate"
                )
            result = relocate_mod.scan(
                binary_path, rows, source_browser, source_version, source_platform, source_arch,
            )
        finally:
            conn.close()
        return result

    def _ingest_relocated(self, result: dict, browser, version, platform, arch, source_row: dict):
        # Import lazily — ingest has sqlite side effects and its own migration stack.
        from tshunter import ingest as ingest_mod  # type: ignore
        from types import SimpleNamespace

        args = SimpleNamespace(
            browser=browser, version=version, platform=platform, arch=arch,
            tls_lib=None, upsert=True, allow_empty=False,
        )
        conn = ingest_mod.db_connect(self.db_path)
        ingest_mod.apply_schema(conn, DEFAULT_DB.parent / 'schema.sql')
        payload = dict(result)
        payload['source_version'] = {
            'browser': source_row['browser'],
            'version': source_row['version'],
            'platform': source_row['platform'],
            'arch': source_row['arch'],
        }
        ingest_mod.ingest_relocate_payload(conn, payload, args)
        conn.commit()
        conn.close()

    def _load_profile(self, profile_ref: Optional[str], tls_lib: Optional[str]) -> dict:
        if not profile_ref:
            profile_ref = TLS_LIB_DEFAULT_PROFILE.get((tls_lib or '').lower())
        if not profile_ref:
            raise ProfileMissing(f"no profile_ref and tls_lib={tls_lib!r} has no default profile")
        path = self.profiles_dir / f"{profile_ref}.json"
        if not path.is_file():
            raise ProfileMissing(f"profile file not found: {path}")
        return json.loads(path.read_text(encoding='utf-8'))

    def _merge_hooks(self, db_hooks: list, profile_templates: dict) -> Dict[str, dict]:
        merged: Dict[str, dict] = {}
        for hook in db_hooks:
            kind = hook['kind']
            template = dict(profile_templates.get(kind) or {})
            params = None
            if hook.get('params_json'):
                try:
                    params = json.loads(hook['params_json'])
                except json.JSONDecodeError:
                    params = None

            merged_hook = {
                # Template-provided (cross-version)
                **template,
                # DB-provided (version-specific) — override template
                'rva': hook['rva'],
                'fingerprint': hook['fingerprint'],
                'fingerprint_len': hook['fingerprint_len'],
                'ghidra_name': hook.get('ghidra_name') or hook.get('function_name'),
                'read_on': hook.get('read_on') or template.get('read_on') or 'onLeave',
                'output_len': hook.get('output_len') or template.get('output_len'),
                'role': hook.get('role') or template.get('role'),
                'source': hook.get('source'),
                'verified': bool(hook.get('verified')),
                'relocation_method': hook.get('relocation_method'),
                'rva_delta': hook.get('rva_delta'),
                'relocation_confidence': hook.get('relocation_confidence'),
                'derived_from_version_id': hook.get('derived_from_version_id'),
            }
            if params is not None:
                merged_hook['params'] = params
            merged_hook['function_name'] = (
                template.get('function_name') or hook.get('function_name')
            )
            if hook.get('note'):
                merged_hook['note'] = hook['note']
            merged[kind] = merged_hook
        return merged

    @staticmethod
    def _make_version_meta(version_row: sqlite3.Row) -> dict:
        return {
            'browser': version_row['browser'],
            'version': version_row['version'],
            'platform': version_row['platform'],
            'arch': version_row['arch'],
            'tls_lib': version_row['tls_lib'],
            'tls_lib_commit': version_row['tls_lib_commit'],
            'image_base': version_row['image_base'],
            'ghidra_image_base': version_row['image_base'],
            'binary_sha256': version_row['binary_sha256'],
            'binary_size': version_row['binary_size'],
            'analysis_date': version_row['analysis_date'],
            'analyzer_version': version_row['analyzer_version'],
            'profile_ref': version_row['profile_ref'],
            'verified': bool(version_row['verified']),
            'verified_method': _extract_verified_method(version_row['note']),
            'verified_metrics': _extract_verified_metrics(version_row['note']),
        }

    def _load_json_legacy(self, browser, version, platform, arch) -> Optional[dict]:
        if not LEGACY_JSON_DIR.is_dir():
            return None
        for path in LEGACY_JSON_DIR.glob('*.json'):
            try:
                cfg = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                continue
            meta = cfg.get('meta', {})
            if (meta.get('browser', '').lower() == browser.lower()
                    and meta.get('version') == version):
                cfg['_match_type'] = 'json_legacy'
                cfg['_config_path'] = str(path)
                return cfg
        return None

    def load(self, browser: str, version: str, platform: str, arch: str,
             binary_path: Optional[Path] = None) -> Dict[str, Any]:
        """Return a legacy-compatible config dict.

        Raises VersionNotInDB / RelocateFailed / ProfileMissing.
        """
        conn = self._connect()
        try:
            version_row = self._query_version_row(conn, browser, version, platform, arch)

            # Step 1: exact DB hit
            if not version_row and self.auto_relocate and binary_path:
                baseline = self._find_same_major_minor_baseline(
                    conn, browser, version, platform, arch,
                )
                if baseline:
                    try:
                        scan_result = self._run_inline_relocate(
                            Path(binary_path),
                            baseline['browser'], baseline['version'],
                            baseline['platform'], baseline['arch'],
                        )
                    except Exception as exc:
                        if self.allow_json_fallback:
                            legacy = self._load_json_legacy(browser, version, platform, arch)
                            if legacy:
                                return legacy
                        raise RelocateFailed(str(exc))
                    verdict = scan_result.get('verdict')
                    if verdict != 'OK':
                        if self.allow_json_fallback:
                            legacy = self._load_json_legacy(browser, version, platform, arch)
                            if legacy:
                                return legacy
                        raise RelocateFailed(
                            f"relocate verdict={verdict}, refusing to auto-ingest"
                        )
                    self._ingest_relocated(scan_result, browser, version, platform, arch, baseline)
                    version_row = self._query_version_row(conn, browser, version, platform, arch)

            if not version_row:
                if self.allow_json_fallback:
                    legacy = self._load_json_legacy(browser, version, platform, arch)
                    if legacy:
                        return legacy
                raise VersionNotInDB(f"{browser} {version} {platform}/{arch} not in DB")

            hooks = self._query_hook_rows(conn, version_row['id'])
        finally:
            conn.close()

        meta = self._make_version_meta(version_row)
        profile = self._load_profile(meta['profile_ref'], meta.get('tls_lib'))
        merged_hooks = self._merge_hooks(hooks, profile.get('hook_templates') or {})

        return {
            '_match_type': 'db',
            '_config_path': f"db:{self.db_path}",
            '_profile_id': profile.get('profile_id'),
            'meta': meta,
            'hook_points': merged_hooks,
            'client_random': profile.get('client_random'),
            'tls13_key_len_offsets': profile.get('tls13_key_len_offsets'),
            'tls13_label_map': profile.get('tls13_label_map'),
            'struct_offsets': profile.get('struct_offsets'),
            'five_tuple_strategy': profile.get('five_tuple_strategy'),
        }


def _cli(argv=None):
    """Small CLI for ad-hoc inspection: python -m tshunter.config_loader chrome 143.0.7499.169"""
    import argparse
    parser = argparse.ArgumentParser(description='Inspect VersionConfigLoader output')
    parser.add_argument('browser')
    parser.add_argument('version')
    parser.add_argument('--platform', default='linux')
    parser.add_argument('--arch', default='x86_64')
    parser.add_argument('--db')
    parser.add_argument('--profiles-dir')
    parser.add_argument('--allow-json-fallback', action='store_true')
    parser.add_argument('--no-relocate', action='store_true')
    parser.add_argument('--binary')
    args = parser.parse_args(argv)

    loader = VersionConfigLoader(
        db_path=args.db,
        profiles_dir=args.profiles_dir,
        allow_json_fallback=args.allow_json_fallback,
        auto_relocate=not args.no_relocate,
    )
    try:
        config = loader.load(
            args.browser, args.version, args.platform, args.arch,
            binary_path=Path(args.binary) if args.binary else None,
        )
    except (VersionNotInDB, RelocateFailed, ProfileMissing) as exc:
        print(f"[FAIL] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(config, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(_cli())
