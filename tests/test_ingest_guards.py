from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INGEST = ROOT / "tools" / "ingest.py"
SCHEMA = ROOT / "data" / "schema.sql"


def _run_ingest(json_path: Path, db_path: Path, *extra: str) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable,
        str(INGEST),
        "--json", str(json_path),
        "--db", str(db_path),
        "--schema", str(SCHEMA),
        "--seed", str(json_path.parent / "_nonexistent_seed.json"),
        *extra,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _fingerprint(length: int = 40) -> str:
    return " ".join(f"{b:02X}" for b in range(length))


def test_rejects_empty_hook_points(tmp_path):
    payload = {
        "meta": {
            "browser": "chrome",
            "version": "99.0.0.1",
            "platform": "linux",
            "arch": "x86_64",
            "tls_lib": "boringssl",
            "analyzer_version": "0.0.0-test",
        },
        "hook_points": {},
    }
    json_path = tmp_path / "empty.json"
    _write_json(json_path, payload)
    db_path = tmp_path / "test.db"

    result = _run_ingest(json_path, db_path)
    assert result.returncode == 2, f"expected exit 2, got {result.returncode}: {result.stderr}"
    assert "FATAL" in (result.stderr + result.stdout)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT status, exit_code FROM analyzer_runs").fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == "FAILED_EMPTY"
    assert rows[0]["exit_code"] == 2


def test_allow_empty_flag_bypasses_guard(tmp_path):
    payload = {
        "meta": {
            "browser": "chrome",
            "version": "98.0.0.1",
            "platform": "linux",
            "arch": "x86_64",
            "tls_lib": "boringssl",
        },
        "hook_points": {},
    }
    json_path = tmp_path / "empty.json"
    _write_json(json_path, payload)
    db_path = tmp_path / "test.db"

    result = _run_ingest(json_path, db_path, "--allow-empty")
    assert result.returncode == 0, result.stderr


def test_successful_ingest_records_status_success(tmp_path):
    payload = {
        "meta": {
            "browser": "chrome",
            "version": "100.0.0.1",
            "platform": "linux",
            "arch": "x86_64",
            "tls_lib": "boringssl",
            "analyzer_version": "0.0.0-test",
        },
        "hook_points": {
            "hkdf": {
                "function": "FUN_test",
                "rva": "0x1000",
                "fingerprint": _fingerprint(40),
                "fingerprint_len": 40,
                "role": "TLS 1.3 Derive-Secret",
            }
        },
    }
    json_path = tmp_path / "ok.json"
    _write_json(json_path, payload)
    db_path = tmp_path / "test.db"

    result = _run_ingest(json_path, db_path)
    assert result.returncode == 0, result.stderr

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT status, exit_code FROM analyzer_runs").fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == "SUCCESS"
    assert rows[0]["exit_code"] == 0

    hook_rows = conn.execute("SELECT kind, rva FROM hook_points").fetchall()
    assert len(hook_rows) == 1
    assert hook_rows[0]["kind"] == "hkdf"
    assert hook_rows[0]["rva"] == "0x1000"


def test_empty_without_meta_still_exits_two(tmp_path):
    payload = {"hook_points": {}}
    json_path = tmp_path / "bare.json"
    _write_json(json_path, payload)
    db_path = tmp_path / "test.db"

    result = _run_ingest(json_path, db_path)
    assert result.returncode == 2
    assert "FATAL" in (result.stderr + result.stdout)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT status, exit_code, version_id FROM analyzer_runs").fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == "FAILED_EMPTY"
    assert rows[0]["version_id"] is None
