from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / 'tests' / 'golden' / 'hooks' / 'chrome_143.0.7499.169_linux_x86_64.json'
SCHEMA = ROOT / 'data' / 'schema.sql'
PROFILES_DIR = ROOT / 'profiles'

from tshunter import ingest as ingest_mod  # noqa: E402
from tshunter import config_loader as cl  # noqa: E402


def _seed_golden(db_path: Path) -> None:
    """Ingest the Chrome 143 ground truth JSON into a fresh DB."""
    payload = json.loads(GOLDEN.read_text(encoding='utf-8'))
    payload['_source_path'] = str(GOLDEN)

    conn = ingest_mod.db_connect(db_path)
    ingest_mod.apply_schema(conn, SCHEMA)
    args = SimpleNamespace(
        browser=None, version=None, platform=None, arch=None,
        tls_lib=None, upsert=True, allow_empty=False,
    )
    ingest_mod.ingest_payload(conn, payload, args)
    conn.commit()
    conn.close()


def _make_loader(db_path: Path, **kwargs) -> cl.VersionConfigLoader:
    return cl.VersionConfigLoader(db_path=db_path, profiles_dir=PROFILES_DIR, **kwargs)


def test_db_hit_returns_legacy_shape(tmp_path):
    db = tmp_path / 'test.db'
    _seed_golden(db)

    config = _make_loader(db).load('chrome', '143.0.7499.169', 'linux', 'x86_64')
    assert config['_match_type'] == 'db'
    assert config['meta']['browser'] == 'chrome'
    assert config['meta']['version'] == '143.0.7499.169'
    assert config['meta']['profile_ref'] == 'boringssl_chrome'

    hooks = config['hook_points']
    assert set(hooks.keys()) == {'prf', 'key_expansion', 'hkdf', 'ssl_log_secret'}
    assert hooks['hkdf']['rva'] == '0x048837E0'
    # fingerprint should come through from DB
    assert hooks['hkdf']['fingerprint'].startswith('55 48 89 E5')


def test_three_layer_merge_has_profile_fields(tmp_path):
    db = tmp_path / 'test.db'
    _seed_golden(db)

    config = _make_loader(db).load('chrome', '143.0.7499.169', 'linux', 'x86_64')
    assert config['client_random']['length'] == 32
    assert 'c hs traffic' in config['tls13_label_map']
    assert config['tls13_label_map']['c hs traffic'] == 'CLIENT_HANDSHAKE_TRAFFIC_SECRET'
    assert config['tls13_key_len_offsets']['c_hs_traffic'] == '0xb2'
    assert config['struct_offsets']['ssl_st_rbio'] == '0x240'
    assert config['five_tuple_strategy']['primary'] == 'time_correlation'


def test_hook_points_carry_params_from_profile(tmp_path):
    db = tmp_path / 'test.db'
    _seed_golden(db)

    config = _make_loader(db).load('chrome', '143.0.7499.169', 'linux', 'x86_64')
    prf = config['hook_points']['prf']
    # DB-backed
    assert prf['rva'] == '0x0A22D4B0'
    # profile hook_template provides function_name + output_len + params
    assert prf['function_name'] == 'boringssl_tls1_prf'
    assert prf['output_len'] == 48
    assert prf['read_on'] == 'onLeave'
    assert 'ssl_ptr' in prf['params']


def test_verified_meta_reflects_ground_truth(tmp_path):
    db = tmp_path / 'test.db'
    _seed_golden(db)

    config = _make_loader(db).load('chrome', '143.0.7499.169', 'linux', 'x86_64')
    assert config['meta']['verified'] is True
    assert config['meta']['verified_method'] == 'SSLKEYLOGFILE diff + Wireshark decryption'


def test_db_miss_raises_version_not_in_db(tmp_path):
    db = tmp_path / 'empty.db'
    conn = ingest_mod.db_connect(db)
    ingest_mod.apply_schema(conn, SCHEMA)
    conn.close()

    with pytest.raises(cl.VersionNotInDB):
        _make_loader(db, auto_relocate=False).load('chrome', '999.0.0.0', 'linux', 'x86_64')


def test_db_miss_json_fallback_when_flag_set(tmp_path):
    db = tmp_path / 'empty.db'
    conn = ingest_mod.db_connect(db)
    ingest_mod.apply_schema(conn, SCHEMA)
    conn.close()

    loader = _make_loader(db, auto_relocate=False, allow_json_fallback=True)
    config = loader.load('chrome', '143.0.7499.169', 'linux', 'x86_64')
    assert config['_match_type'] == 'json_legacy'
    assert 'hook_points' in config


def test_profile_missing_raises(tmp_path):
    db = tmp_path / 'test.db'
    _seed_golden(db)

    empty_profiles = tmp_path / 'empty_profiles'
    empty_profiles.mkdir()

    loader = cl.VersionConfigLoader(db_path=db, profiles_dir=empty_profiles)
    with pytest.raises(cl.ProfileMissing):
        loader.load('chrome', '143.0.7499.169', 'linux', 'x86_64')


def test_db_miss_auto_relocate_success(tmp_path, monkeypatch):
    db = tmp_path / 'test.db'
    _seed_golden(db)

    # Fake relocate result — same major.minor, simulated exact match
    fake_binary = tmp_path / 'chrome_fake.bin'
    fake_binary.write_bytes(b'\x00' * 64)

    def fake_scan(binary, rows, browser, version, platform, arch):
        hooks = []
        for row in rows:
            hooks.append({
                'kind': row['kind'],
                'new_rva': row['rva'],  # pretend no drift
                'delta': '0x0',
                'match_type': 'exact_match',
                'confidence': 1.0,
            })
        return {
            'tool_version': 'test-relocate',
            'verdict': 'OK',
            'target': {'sha256': 'fake', 'size': fake_binary.stat().st_size, 'image_base': '0x0'},
            'hooks': hooks,
            'relocation_summary': {'relocated': len(hooks), 'total_hooks': len(hooks),
                                    'median_delta': '0x0', 'delta_consistent': True},
        }

    from tshunter import relocate as relocate_mod
    monkeypatch.setattr(relocate_mod, 'scan', fake_scan)

    config = _make_loader(db, auto_relocate=True).load(
        'chrome', '143.0.7499.192', 'linux', 'x86_64', binary_path=fake_binary,
    )
    assert config['meta']['version'] == '143.0.7499.192'
    # After auto-relocate the new version should point at the same profile
    assert config['meta']['profile_ref'] == 'boringssl_chrome'
    # hook_points should be inherited (rva matches the baseline since we mocked delta=0)
    assert config['hook_points']['hkdf']['rva'] == '0x048837E0'
    assert config['hook_points']['hkdf']['relocation_method'] == 'exact_scan'


def test_partial_relocate_rejected_by_default(tmp_path, monkeypatch):
    db = tmp_path / 'test.db'
    _seed_golden(db)
    fake_binary = tmp_path / 'chrome_fake.bin'
    fake_binary.write_bytes(b'\x00' * 64)

    def fake_scan(binary, rows, browser, version, platform, arch):
        hooks = []
        for i, row in enumerate(rows):
            hooks.append({
                'kind': row['kind'],
                'new_rva': row['rva'],
                'delta': hex(i * 0x100),
                'match_type': 'exact_match',
                'confidence': 0.95,
            })
        return {
            'tool_version': 'test-relocate',
            'verdict': 'PARTIAL',
            'target': {'sha256': 'fake', 'size': fake_binary.stat().st_size, 'image_base': '0x0'},
            'hooks': hooks,
            'relocation_summary': {'relocated': len(hooks), 'total_hooks': len(hooks),
                                    'median_delta': '0x100', 'delta_consistent': False},
        }

    from tshunter import relocate as relocate_mod
    monkeypatch.setattr(relocate_mod, 'scan', fake_scan)

    with pytest.raises(cl.RelocateFailed):
        _make_loader(db, auto_relocate=True).load(
            'chrome', '143.0.7499.192', 'linux', 'x86_64', binary_path=fake_binary,
        )


def test_partial_relocate_can_be_accepted_with_policy_marker(tmp_path, monkeypatch):
    db = tmp_path / 'test.db'
    _seed_golden(db)
    fake_binary = tmp_path / 'chrome_fake.bin'
    fake_binary.write_bytes(b'\x00' * 64)

    def fake_scan(binary, rows, browser, version, platform, arch):
        hooks = []
        for i, row in enumerate(rows):
            hooks.append({
                'kind': row['kind'],
                'new_rva': row['rva'],
                'delta': hex(i * 0x100),
                'match_type': 'exact_match',
                'confidence': 0.95,
            })
        return {
            'tool_version': 'test-relocate',
            'verdict': 'PARTIAL',
            'target': {'sha256': 'fake', 'size': fake_binary.stat().st_size, 'image_base': '0x0'},
            'hooks': hooks,
            'relocation_summary': {'relocated': len(hooks), 'total_hooks': len(hooks),
                                    'median_delta': '0x100', 'delta_consistent': False},
        }

    from tshunter import relocate as relocate_mod
    monkeypatch.setattr(relocate_mod, 'scan', fake_scan)

    config = _make_loader(
        db,
        auto_relocate=True,
        accept_partial=True,
        partial_min_confidence=0.8,
    ).load('chrome', '143.0.7499.192', 'linux', 'x86_64', binary_path=fake_binary)

    assert config['meta']['verified'] is False
    assert config['hook_points']['hkdf']['relocation_method'] == 'exact_scan_partial'

    conn = sqlite3.connect(db)
    row = conn.execute(
        """
        SELECT v.verified, v.note, COUNT(*)
        FROM versions v
        JOIN browsers b ON b.id = v.browser_id
        JOIN hook_points hp ON hp.version_id = v.id
        WHERE b.name='chrome' AND v.version='143.0.7499.192'
        GROUP BY v.id
        """
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] == 0
    assert row[2] == 4
    note = json.loads(row[1])
    assert note['partial_relocate'] is True
    assert note['median_delta'] == '0x100'
    assert note['max_outlier_delta'] == 512


def test_legacy_caller_import_gets_patched_function(tmp_path):
    """Simulate the capture.py flow: after _install_loader_patch, `from lib.version_detect
    import load_config` must yield the patched function."""
    db = tmp_path / 'test.db'
    _seed_golden(db)

    # Prevent contamination of real env + module cache
    import sys as _sys
    cached = {name: _sys.modules.pop(name) for name in list(_sys.modules)
              if name.startswith('lib.') or name == 'lib'}
    legacy_root = str(ROOT / 'tls_capture')
    if legacy_root not in _sys.path:
        _sys.path.insert(0, legacy_root)

    try:
        os.environ.pop('TSHUNTER_ALLOW_JSON_FALLBACK', None)
        # Override default DB to the tmp seeded one
        original_default = cl.DEFAULT_DB
        cl.DEFAULT_DB = db
        try:
            from tshunter.capture import _install_loader_patch
            _install_loader_patch(browser='chrome', platform='linux', arch='x86_64',
                                   binary_path=None)
            from lib.version_detect import load_config as patched
            result = patched('143.0.7499.169')
            assert result is not None
            assert result['_match_type'] == 'db'
            assert result['hook_points']['hkdf']['rva'] == '0x048837E0'
        finally:
            cl.DEFAULT_DB = original_default
    finally:
        # Restore cached modules
        for name, mod in cached.items():
            _sys.modules[name] = mod
