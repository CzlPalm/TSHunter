"""Tests for agent task_store: state machine transitions and CRUD operations."""

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

def _make_agent_db(tmp_path: Path) -> sqlite3.Connection:
    """Create an in-memory-like DB with base schema + agent tables."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA_SQL.read_text())
    conn.executescript(MIGRATION_SQL.read_text())
    return conn


# ---------------------------------------------------------------------------
# create_task
# ---------------------------------------------------------------------------

class TestCreateTask:
    def test_create_task_inserts(self, tmp_path):
        from tshunter.agent.db.task_store import create_task
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()
        assert task.status == "pending"
        assert task.browser == "chrome"
        assert task.version == "143.0.0.0"
        assert task.task_id  # non-empty

    def test_create_task_dedup(self, tmp_path):
        from tshunter.agent.db.task_store import create_task
        conn = _make_agent_db(tmp_path)
        # channel must be non-None for dedup to work (SQL NULL != NULL)
        t1 = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64", channel="stable")
        conn.commit()
        t2 = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64", channel="stable")
        conn.commit()
        assert t1.task_id == t2.task_id

    def test_create_task_allows_after_terminal(self, tmp_path):
        from tshunter.agent.db.task_store import create_task, transition
        conn = _make_agent_db(tmp_path)
        t1 = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64", channel="stable")
        conn.commit()
        # Move to terminal state
        transition(conn, t1.task_id, "failed")
        conn.commit()
        # Create again — should get a new task (failed is terminal, dedup skips it)
        t2 = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64", channel="stable")
        conn.commit()
        assert t2.task_id != t1.task_id
        assert t2.status == "pending"


# ---------------------------------------------------------------------------
# transition
# ---------------------------------------------------------------------------

class TestTransition:
    def test_transition_legal_path(self, tmp_path):
        from tshunter.agent.db.task_store import create_task, transition
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()

        transition(conn, task.task_id, "downloading")
        transition(conn, task.task_id, "downloaded")
        transition(conn, task.task_id, "queued_analyze")
        transition(conn, task.task_id, "analyzing")
        task = transition(conn, task.task_id, "needs_manual_review")
        conn.commit()
        assert task.status == "needs_manual_review"

    def test_transition_illegal_raises(self, tmp_path):
        from tshunter.agent.db.task_store import (
            create_task, transition, InvalidTransition,
        )
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()

        with pytest.raises(InvalidTransition):
            transition(conn, task.task_id, "analyzing")  # pending → analyzing illegal

    def test_transition_sets_started_at(self, tmp_path):
        from tshunter.agent.db.task_store import create_task, transition, get_task_by_id_field
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()
        assert task.started_at is None

        transition(conn, task.task_id, "downloading")
        conn.commit()
        task = get_task_by_id_field(conn, task.task_id)
        assert task.started_at is not None

    def test_transition_sets_finished_at(self, tmp_path):
        from tshunter.agent.db.task_store import (
            create_task, transition, get_task_by_id_field,
        )
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()

        transition(conn, task.task_id, "failed")
        conn.commit()
        task = get_task_by_id_field(conn, task.task_id)
        assert task.finished_at is not None

    def test_transition_with_error(self, tmp_path):
        from tshunter.agent.db.task_store import (
            create_task, fail_task, get_task_by_id_field,
        )
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()

        fail_task(conn, task.task_id, error_stage="download", error_msg="timeout")
        conn.commit()
        task = get_task_by_id_field(conn, task.task_id)
        assert task.status == "failed"
        assert task.error_stage == "download"
        assert task.error_msg == "timeout"

    def test_transition_verified_is_terminal(self, tmp_path):
        from tshunter.agent.db.task_store import (
            create_task, transition, InvalidTransition,
        )
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()
        # Walk to verified
        transition(conn, task.task_id, "downloading")
        transition(conn, task.task_id, "downloaded")
        transition(conn, task.task_id, "queued_analyze")
        transition(conn, task.task_id, "analyzing")
        transition(conn, task.task_id, "ingesting")
        transition(conn, task.task_id, "queued_verify")
        transition(conn, task.task_id, "verifying")
        transition(conn, task.task_id, "verified")
        conn.commit()

        with pytest.raises(InvalidTransition):
            transition(conn, task.task_id, "pending")


# ---------------------------------------------------------------------------
# retry_task
# ---------------------------------------------------------------------------

class TestRetryTask:
    def test_retry_task(self, tmp_path):
        from tshunter.agent.db.task_store import (
            create_task, fail_task, retry_task, get_task_by_id_field,
        )
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()
        fail_task(conn, task.task_id, "download", "timeout")
        conn.commit()

        task = retry_task(conn, task.task_id)
        conn.commit()
        assert task.status == "pending"
        assert task.retry_count == 1
        assert task.error_stage is None
        assert task.error_msg is None

    def test_retry_non_failed_raises(self, tmp_path):
        from tshunter.agent.db.task_store import (
            create_task, retry_task, InvalidTransition,
        )
        conn = _make_agent_db(tmp_path)
        task = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        conn.commit()

        with pytest.raises(InvalidTransition):
            retry_task(conn, task.task_id)  # pending, not failed


# ---------------------------------------------------------------------------
# list_tasks / find_task / count_tasks
# ---------------------------------------------------------------------------

class TestQueryTasks:
    def test_list_tasks_filter(self, tmp_path):
        from tshunter.agent.db.task_store import create_task, transition, list_tasks
        conn = _make_agent_db(tmp_path)
        t1 = create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        t2 = create_task(conn, "chrome", "144.0.0.0", "linux", "x86_64")
        transition(conn, t2.task_id, "downloading")
        conn.commit()

        pending = list_tasks(conn, status="pending")
        assert len(pending) == 1
        assert pending[0].task_id == t1.task_id

        downloading = list_tasks(conn, status="downloading")
        assert len(downloading) == 1
        assert downloading[0].task_id == t2.task_id

    def test_list_tasks_browser_filter(self, tmp_path):
        from tshunter.agent.db.task_store import create_task, list_tasks
        conn = _make_agent_db(tmp_path)
        create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        create_task(conn, "firefox", "140.0.0", "linux", "x86_64")
        conn.commit()

        chrome = list_tasks(conn, browser="chrome")
        assert len(chrome) == 1
        assert chrome[0].browser == "chrome"

        firefox = list_tasks(conn, browser="firefox")
        assert len(firefox) == 1
        assert firefox[0].browser == "firefox"

    def test_find_task(self, tmp_path):
        from tshunter.agent.db.task_store import create_task, find_task
        conn = _make_agent_db(tmp_path)
        create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64", channel="stable")
        conn.commit()

        found = find_task(conn, "chrome", "143.0.0.0", "linux", "x86_64", channel="stable")
        assert found is not None
        assert found.browser == "chrome"

        missing = find_task(conn, "chrome", "999.0.0.0", "linux", "x86_64")
        assert missing is None

    def test_count_tasks(self, tmp_path):
        from tshunter.agent.db.task_store import create_task, count_tasks
        conn = _make_agent_db(tmp_path)
        create_task(conn, "chrome", "143.0.0.0", "linux", "x86_64")
        create_task(conn, "chrome", "144.0.0.0", "linux", "x86_64")
        create_task(conn, "firefox", "140.0.0", "linux", "x86_64")
        conn.commit()

        assert count_tasks(conn) == 3
        assert count_tasks(conn, browser="chrome") == 2
        assert count_tasks(conn, browser="firefox") == 1
        assert count_tasks(conn, status="pending") == 3
