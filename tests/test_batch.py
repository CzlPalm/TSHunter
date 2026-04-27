"""Tests for Phase B1 batch analysis state machine.

No real Ghidra/Docker runs — uses fixture DBs and a fake binaries dir.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SQL = ROOT / "data" / "schema.sql"
MIGRATIONS_DIR = ROOT / "data" / "migrations"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db(tmp_path: Path) -> Path:
    """Create an empty DB with full schema applied."""
    db_path = tmp_path / "test.db"
    from tshunter import ingest as ingest_mod
    conn = ingest_mod.db_connect(db_path)
    ingest_mod.apply_schema(conn, SCHEMA_SQL)
    conn.close()
    return db_path


def _make_binaries_dir(tmp_path: Path, versions: list[str]) -> Path:
    """Create a fake binaries dir with empty 'chrome' files for each version."""
    bd = tmp_path / "binaries"
    for v in versions:
        d = bd / v
        d.mkdir(parents=True)
        (d / "chrome").touch()
    return bd


def _batch_args(tmp_path: Path, db_path: Path, binaries_dir: Path,
                extra: dict | None = None):
    """Build a minimal argparse.Namespace for run_batch."""
    import argparse
    args = argparse.Namespace(
        browser="chrome",
        platform="linux",
        arch="x86_64",
        tls_lib="boringssl",
        db=str(db_path),
        binaries_dir=str(binaries_dir),
        milestones=None,
        workers=1,
        resume=None,
        dry_run=False,
        allow_empty=False,
    )
    if extra:
        for k, v in extra.items():
            setattr(args, k, v)
    return args


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_batch_migration_creates_table(tmp_path):
    """apply_schema + _ensure_batch_table should create batch_jobs."""
    db_path = _make_db(tmp_path)
    from tshunter.batch import _db_connect, _ensure_batch_table
    conn = _db_connect(db_path)
    _ensure_batch_table(conn)
    conn.close()

    conn2 = sqlite3.connect(db_path)
    tables = {r[0] for r in conn2.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    conn2.close()
    assert "batch_jobs" in tables


def test_batch_dry_run_lists_versions(tmp_path):
    """dry-run should exit 0 and mark all versions as 'skipped'."""
    db_path = _make_db(tmp_path)
    versions = ["143.0.7499.169", "143.0.7499.192"]
    bd = _make_binaries_dir(tmp_path, versions)
    args = _batch_args(tmp_path, db_path, bd, {"dry_run": True})

    from tshunter.batch import run_batch
    rc = run_batch(args)
    assert rc == 0

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT version, status, method FROM batch_jobs").fetchall()
    conn.close()

    assert len(rows) == 2
    for version, status, method in rows:
        assert status == "skipped"
        assert method == "dry_run"


def test_batch_db_hit_marks_done(tmp_path):
    """If DB already has hook_points for a version, status should be 'done' with method='db_hit'."""
    db_path = _make_db(tmp_path)

    # Seed a version + hook_points into the DB so it counts as a hit
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT OR IGNORE INTO browsers(name) VALUES ('chrome')")
    browser_id = conn.execute("SELECT id FROM browsers WHERE name='chrome'").fetchone()[0]
    conn.execute(
        "INSERT INTO versions(browser_id, version, platform, arch) VALUES (?,?,?,?)",
        (browser_id, "143.0.7499.169", "linux", "x86_64"),
    )
    version_id = conn.execute(
        "SELECT id FROM versions WHERE version='143.0.7499.169'"
    ).fetchone()[0]
    conn.execute(
        """INSERT INTO hook_points(version_id, kind, rva, fingerprint, fingerprint_len,
                                    fingerprint_prefix20, relocation_method)
           VALUES (?,?,?,?,?,?,?)""",
        (version_id, "hkdf", "0x01000000", "55 48 89 E5", 4, "55 48 89 E5", "ghidra_full"),
    )
    conn.commit()
    conn.close()

    bd = _make_binaries_dir(tmp_path, ["143.0.7499.169"])
    args = _batch_args(tmp_path, db_path, bd)

    from tshunter.batch import run_batch
    rc = run_batch(args)
    assert rc == 0

    conn2 = sqlite3.connect(db_path)
    row = conn2.execute(
        "SELECT status, method FROM batch_jobs WHERE version='143.0.7499.169'"
    ).fetchone()
    conn2.close()

    assert row is not None
    assert row[0] == "done"
    assert row[1] == "db_hit"


def test_batch_resume_picks_up_failed(tmp_path):
    """--resume should retry failed rows, leaving done rows untouched."""
    db_path = _make_db(tmp_path)
    bd = _make_binaries_dir(tmp_path, ["143.0.7499.169"])

    # Seed a failed batch_jobs row with a known run_id
    run_id = "20260427-120000-testtest"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO batch_jobs(run_id, browser, version, platform, arch, status, error_msg)
           VALUES (?,?,?,?,?,?,?)""",
        (run_id, "chrome", "143.0.7499.169", "linux", "x86_64", "failed", "simulated failure"),
    )
    conn.commit()
    conn.close()

    # Also seed DB with real hook_points so the retry succeeds as db_hit
    conn2 = sqlite3.connect(db_path)
    conn2.execute("INSERT OR IGNORE INTO browsers(name) VALUES ('chrome')")
    browser_id = conn2.execute("SELECT id FROM browsers WHERE name='chrome'").fetchone()[0]
    conn2.execute(
        "INSERT OR IGNORE INTO versions(browser_id, version, platform, arch) VALUES (?,?,?,?)",
        (browser_id, "143.0.7499.169", "linux", "x86_64"),
    )
    version_id = conn2.execute(
        "SELECT id FROM versions WHERE version='143.0.7499.169'"
    ).fetchone()[0]
    conn2.execute(
        """INSERT OR IGNORE INTO hook_points(version_id, kind, rva, fingerprint,
                                              fingerprint_len, fingerprint_prefix20,
                                              relocation_method)
           VALUES (?,?,?,?,?,?,?)""",
        (version_id, "hkdf", "0x01000000", "55 48 89 E5", 4, "55 48 89 E5", "ghidra_full"),
    )
    conn2.commit()
    conn2.close()

    args = _batch_args(tmp_path, db_path, bd, {"resume": run_id})

    from tshunter.batch import run_batch
    rc = run_batch(args)
    assert rc == 0

    conn3 = sqlite3.connect(db_path)
    row = conn3.execute(
        "SELECT status, method FROM batch_jobs WHERE run_id=? AND version='143.0.7499.169'",
        (run_id,),
    ).fetchone()
    conn3.close()

    assert row is not None
    assert row[0] == "done"
    assert row[1] == "db_hit"
