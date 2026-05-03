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
        (d / "metadata.json").write_text('{"version": "%s"}' % v)
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
        versions_file=None,
        workers=1,
        resume=None,
        dry_run=False,
        allow_empty=False,
        cleanup_binary=False,
        source="cft-latest",
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
    columns = {r[1] for r in conn2.execute("PRAGMA table_info(batch_jobs)").fetchall()}
    conn2.close()
    assert "batch_jobs" in tables
    assert "method_duration_sec" in columns
    assert "relocate_max_outlier_delta" in columns


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
        "SELECT status, method, method_duration_sec FROM batch_jobs WHERE version='143.0.7499.169'"
    ).fetchone()
    conn2.close()

    assert row is not None
    assert row[0] == "done"
    assert row[1] == "db_hit"
    assert row[2] is not None


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


def test_batch_cleanup_binary_preserves_metadata(tmp_path):
    """--cleanup-binary should remove the chrome payload but keep metadata.json."""
    db_path = _make_db(tmp_path)
    version = "143.0.7499.169"
    bd = _make_binaries_dir(tmp_path, [version])

    conn = sqlite3.connect(db_path)
    conn.execute("INSERT OR IGNORE INTO browsers(name) VALUES ('chrome')")
    browser_id = conn.execute("SELECT id FROM browsers WHERE name='chrome'").fetchone()[0]
    conn.execute(
        "INSERT INTO versions(browser_id, version, platform, arch) VALUES (?,?,?,?)",
        (browser_id, version, "linux", "x86_64"),
    )
    version_id = conn.execute("SELECT id FROM versions WHERE version=?", (version,)).fetchone()[0]
    conn.execute(
        """INSERT INTO hook_points(version_id, kind, rva, fingerprint, fingerprint_len,
                                    fingerprint_prefix20, relocation_method)
           VALUES (?,?,?,?,?,?,?)""",
        (version_id, "hkdf", "0x01000000", "55 48 89 E5", 4, "55 48 89 E5", "ghidra_full"),
    )
    conn.commit()
    conn.close()

    args = _batch_args(tmp_path, db_path, bd, {"cleanup_binary": True})
    from tshunter.batch import run_batch
    rc = run_batch(args)
    assert rc == 0

    version_dir = bd / version
    assert version_dir.is_dir()
    assert not (version_dir / "chrome").exists()
    assert (version_dir / "metadata.json").is_file()


def test_batch_records_duration_for_analyze(tmp_path, monkeypatch):
    """analyze jobs should store method_duration_sec."""
    db_path = _make_db(tmp_path)
    version = "143.0.7499.192"
    bd = _make_binaries_dir(tmp_path, [version])

    from tshunter import analyze as analyze_mod
    from tshunter import ingest as ingest_mod
    from tshunter import batch as batch_mod

    def fake_analyze(argv):
        out_path = Path(argv[argv.index("--output") + 1])
        out_path.write_text('{"meta": {}, "hook_points": {}}')
        return 0

    def fake_ingest(argv):
        return 0

    monkeypatch.setattr(batch_mod, "_write_relocate_json", lambda *a, **kw: None)
    monkeypatch.setattr(analyze_mod, "main", fake_analyze)
    monkeypatch.setattr(ingest_mod, "main", fake_ingest)

    args = _batch_args(tmp_path, db_path, bd)
    rc = batch_mod.run_batch(args)
    assert rc == 0

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT method, method_duration_sec FROM batch_jobs WHERE version=?",
        (version,),
    ).fetchone()
    conn.close()

    assert row[0] == "analyze"
    assert row[1] is not None


def test_batch_relocate_json_on_db_miss(tmp_path, monkeypatch):
    """On DB miss, relocate JSON is written to data/relocate/ before full analyze."""
    db_path = _make_db(tmp_path)
    version = "143.0.7499.192"
    bd = _make_binaries_dir(tmp_path, [version])

    calls = {"relocate_json": 0, "analyze": 0, "ingest": 0}

    from tshunter import analyze as analyze_mod
    from tshunter import ingest as ingest_mod
    from tshunter import batch as batch_mod

    def fake_relocate_json(db_path_arg, args, version_arg, binary_path):
        calls["relocate_json"] += 1
        return tmp_path / "relocate.json"

    def fake_analyze(argv):
        calls["analyze"] += 1
        out_path = Path(argv[argv.index("--output") + 1])
        out_path.write_text('{"meta": {}, "hook_points": {}}')
        return 0

    def fake_ingest(argv):
        calls["ingest"] += 1
        return 0

    monkeypatch.setattr(batch_mod, "_write_relocate_json", fake_relocate_json)
    monkeypatch.setattr(analyze_mod, "main", fake_analyze)
    monkeypatch.setattr(ingest_mod, "main", fake_ingest)

    args = _batch_args(tmp_path, db_path, bd)
    rc = batch_mod.run_batch(args)
    assert rc == 0

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT status, method FROM batch_jobs WHERE version=?",
        (version,),
    ).fetchone()
    conn.close()

    assert calls == {"relocate_json": 1, "analyze": 1, "ingest": 1}
    assert row == ("done", "analyze")
