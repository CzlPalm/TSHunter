"""Tests for agent workers: AnalyzeWorker, VerifyWorker, DownloadWorker."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SQL = ROOT / "data" / "schema.sql"
MIGRATION_SQL = ROOT / "data" / "migrations" / "007_agent_tables.sql"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_agent_db(tmp_path: Path) -> Path:
    """Create a DB file with base schema + agent tables. Returns path."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA_SQL.read_text())
    conn.executescript(MIGRATION_SQL.read_text())
    conn.close()
    return db_path


def _connect(db_path: Path) -> sqlite3.Connection:
    """Open a fresh connection to the given DB."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _make_task(db_path, status="pending", browser="chrome", version="143.0.0.0",
               platform="linux", arch="x86_64", binary_path=None):
    """Create a task and force it to a specific status."""
    from tshunter.agent.db.task_store import create_task, transition, get_task_by_id_field
    conn = _connect(db_path)
    task = create_task(conn, browser, version, platform, arch, channel="stable")
    conn.commit()
    if status == "pending":
        if binary_path:
            conn.execute("UPDATE agent_tasks SET binary_path=? WHERE task_id=?",
                          (str(binary_path), task.task_id))
            conn.commit()
        result = get_task_by_id_field(conn, task.task_id)
        conn.close()
        return result
    path = {
        "downloading": ["downloading"],
        "downloaded": ["downloading", "downloaded"],
        "queued_analyze": ["downloading", "downloaded", "queued_analyze"],
        "analyzing": ["downloading", "downloaded", "queued_analyze", "analyzing"],
        "queued_verify": ["downloading", "downloaded", "queued_analyze", "ingesting", "queued_verify"],
        "verifying": ["downloading", "downloaded", "queued_analyze", "ingesting", "queued_verify", "verifying"],
    }
    for s in path.get(status, []):
        transition(conn, task.task_id, s)
    conn.commit()
    if binary_path:
        conn.execute("UPDATE agent_tasks SET binary_path=? WHERE task_id=?",
                      (str(binary_path), task.task_id))
        conn.commit()
    result = get_task_by_id_field(conn, task.task_id)
    conn.close()
    return result


def _seed_verified_version(db_path, browser="chrome", version="143.0.7499.169",
                            platform="linux", arch="x86_64"):
    """Seed a verified version with hook_points for baseline testing."""
    conn = _connect(db_path)
    conn.execute(
        "INSERT INTO browsers (name) VALUES (?) ON CONFLICT(name) DO NOTHING",
        (browser,),
    )
    browser_row = conn.execute("SELECT id FROM browsers WHERE name=?", (browser,)).fetchone()
    conn.execute(
        """INSERT INTO versions (browser_id, version, platform, arch, verified)
           VALUES (?, ?, ?, ?, 1)""",
        (browser_row["id"], version, platform, arch),
    )
    version_row = conn.execute(
        "SELECT id FROM versions WHERE version=? AND browser_id=?",
        (version, browser_row["id"]),
    ).fetchone()
    for kind in ("ssl_log_secret", "key_expansion", "prf", "hkdf"):
        conn.execute(
            """INSERT INTO hook_points
               (version_id, kind, rva, fingerprint, fingerprint_len, fingerprint_prefix20)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (version_row["id"], kind, "0x1234", "abcd", 4, "ab"),
        )
    conn.commit()
    conn.close()


def _get_task(db_path, task_id):
    """Get a task by task_id from a fresh connection."""
    from tshunter.agent.db.task_store import get_task_by_id_field
    conn = _connect(db_path)
    task = get_task_by_id_field(conn, task_id)
    conn.close()
    return task


# ---------------------------------------------------------------------------
# AnalyzeWorker
# ---------------------------------------------------------------------------

class TestAnalyzeWorker:
    def test_analyze_no_pending(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.analyze import AnalyzeWorker
        from tshunter.agent.config import AgentConfig
        db_path = _make_agent_db(tmp_path)
        monkeypatch.setattr("tshunter.agent.workers.analyze.connect",
                            lambda: _connect(db_path))
        worker = AnalyzeWorker(AgentConfig(raw={}), dry_run=True)
        assert worker.run(once=True) == 0

    def test_analyze_dry_run_transitions(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.analyze import AnalyzeWorker
        from tshunter.agent.config import AgentConfig

        db_path = _make_agent_db(tmp_path)
        binary = tmp_path / "chrome"
        binary.touch()
        task = _make_task(db_path, status="downloaded", binary_path=binary)
        monkeypatch.setattr("tshunter.agent.workers.analyze.connect",
                            lambda: _connect(db_path))

        worker = AnalyzeWorker(AgentConfig(raw={}), dry_run=True)
        processed = worker.run(once=True)
        assert processed == 1

        final = _get_task(db_path, task.task_id)
        assert final.status == "needs_manual_review"

    def test_analyze_missing_binary_fails(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.analyze import AnalyzeWorker
        from tshunter.agent.config import AgentConfig

        db_path = _make_agent_db(tmp_path)
        task = _make_task(db_path, status="downloaded",
                          binary_path="/nonexistent/chrome")
        monkeypatch.setattr("tshunter.agent.workers.analyze.connect",
                            lambda: _connect(db_path))

        AnalyzeWorker(AgentConfig(raw={}), dry_run=True).run(once=True)
        final = _get_task(db_path, task.task_id)
        assert final.status == "failed"
        assert final.error_stage == "analyze"

    def test_analyze_no_binary_path_fails(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.analyze import AnalyzeWorker
        from tshunter.agent.config import AgentConfig

        db_path = _make_agent_db(tmp_path)
        task = _make_task(db_path, status="downloaded")  # binary_path=None
        monkeypatch.setattr("tshunter.agent.workers.analyze.connect",
                            lambda: _connect(db_path))

        AnalyzeWorker(AgentConfig(raw={}), dry_run=True).run(once=True)
        final = _get_task(db_path, task.task_id)
        assert final.status == "failed"
        assert final.error_stage == "analyze"

    def test_analyze_finds_baseline(self, tmp_path):
        from tshunter.agent.workers.analyze import AnalyzeWorker
        from tshunter.agent.db.task_store import create_task

        db_path = _make_agent_db(tmp_path)
        _seed_verified_version(db_path)
        conn = _connect(db_path)
        task = create_task(conn, "chrome", "144.0.0.0", "linux", "x86_64")
        conn.commit()

        baseline = AnalyzeWorker._find_relocate_baseline(conn, task)
        conn.close()
        assert baseline is not None
        assert baseline["version"] == "143.0.7499.169"
        assert baseline["hook_count"] == 4

    def test_analyze_no_baseline(self, tmp_path):
        from tshunter.agent.workers.analyze import AnalyzeWorker
        from tshunter.agent.db.task_store import create_task

        db_path = _make_agent_db(tmp_path)
        conn = _connect(db_path)
        task = create_task(conn, "chrome", "144.0.0.0", "linux", "x86_64")
        conn.commit()

        baseline = AnalyzeWorker._find_relocate_baseline(conn, task)
        conn.close()
        assert baseline is None


# ---------------------------------------------------------------------------
# VerifyWorker
# ---------------------------------------------------------------------------

class TestVerifyWorker:
    def test_verify_no_queued(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.verify import VerifyWorker
        from tshunter.agent.config import AgentConfig
        db_path = _make_agent_db(tmp_path)
        monkeypatch.setattr("tshunter.agent.workers.verify.connect",
                            lambda: _connect(db_path))
        assert VerifyWorker(AgentConfig(raw={})).run(once=True) == 0

    def test_verify_no_results(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.verify import VerifyWorker
        from tshunter.agent.config import AgentConfig

        db_path = _make_agent_db(tmp_path)
        task = _make_task(db_path, status="queued_verify")
        monkeypatch.setattr("tshunter.agent.workers.verify.connect",
                            lambda: _connect(db_path))

        VerifyWorker(AgentConfig(raw={})).run(once=True)
        final = _get_task(db_path, task.task_id)
        assert final.status == "needs_manual_review"

    def test_verify_with_results(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.verify import VerifyWorker
        from tshunter.agent.config import AgentConfig

        db_path = _make_agent_db(tmp_path)
        _seed_verified_version(db_path, version="143.0.0.0")
        task = _make_task(db_path, status="queued_verify", version="143.0.0.0")
        monkeypatch.setattr("tshunter.agent.workers.verify.connect",
                            lambda: _connect(db_path))

        VerifyWorker(AgentConfig(raw={})).run(once=True)
        final = _get_task(db_path, task.task_id)
        assert final.status == "needs_manual_review"


# ---------------------------------------------------------------------------
# DownloadWorker
# ---------------------------------------------------------------------------

class TestDownloadWorker:
    def test_download_no_pending(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.download import DownloadWorker
        from tshunter.agent.config import AgentConfig
        db_path = _make_agent_db(tmp_path)
        monkeypatch.setattr("tshunter.agent.workers.download.connect",
                            lambda: _connect(db_path))
        assert DownloadWorker(AgentConfig(raw={})).run(once=True) == 0

    def test_download_unknown_browser_fails(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.download import DownloadWorker
        from tshunter.agent.config import AgentConfig

        db_path = _make_agent_db(tmp_path)
        task = _make_task(db_path, status="pending", browser="unknown_browser")
        monkeypatch.setattr("tshunter.agent.workers.download.connect",
                            lambda: _connect(db_path))

        DownloadWorker(AgentConfig(raw={})).run(once=True)
        final = _get_task(db_path, task.task_id)
        assert final.status == "failed"

    def test_download_no_artifact_fails(self, tmp_path, monkeypatch):
        from tshunter.agent.workers.download import DownloadWorker
        from tshunter.agent.config import AgentConfig

        db_path = _make_agent_db(tmp_path)
        task = _make_task(db_path, status="pending", browser="chrome",
                          version="999.0.0.0")
        monkeypatch.setattr("tshunter.agent.workers.download.connect",
                            lambda: _connect(db_path))

        DownloadWorker(AgentConfig(raw={})).run(once=True)
        final = _get_task(db_path, task.task_id)
        assert final.status == "failed"
