"""agent_tasks table CRUD operations and state machine transitions."""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# --- State definitions ---

TASK_STATES = {
    "pending",
    "downloading",
    "downloaded",
    "queued_analyze",
    "relocating",
    "analyzing",
    "ingesting",
    "queued_verify",
    "verifying",
    "verified",
    "failed",
    "needs_manual_review",
    "skipped",
}

# Legal transitions: from_state -> set of allowed to_states
_TRANSITIONS: Dict[str, set] = {
    "pending": {"downloading", "downloaded", "skipped", "failed"},
    "downloading": {"downloaded", "failed"},
    "downloaded": {"queued_analyze", "skipped", "failed"},
    "queued_analyze": {"relocating", "analyzing", "ingesting", "queued_verify", "needs_manual_review", "failed"},
    "relocating": {"analyzing", "ingesting", "queued_verify", "needs_manual_review", "failed"},
    "analyzing": {"ingesting", "queued_verify", "needs_manual_review", "failed"},
    "ingesting": {"queued_verify", "needs_manual_review", "failed"},
    "queued_verify": {"verifying", "verified", "needs_manual_review", "failed"},
    "verifying": {"verified", "needs_manual_review", "failed"},
    "verified": set(),
    "failed": {"pending"},  # allow retry by resetting to pending
    "needs_manual_review": {"pending", "failed"},
    "skipped": {"pending"},
}

# Error stage enumeration
ERROR_STAGES = {
    "poll", "download", "unpack", "binary_locate", "checksum",
    "version_probe", "db_write", "task_create", "planner",
    "analyze", "verify",
}


class InvalidTransition(Exception):
    """Raised when a state transition is not allowed."""


@dataclass
class AgentTask:
    id: Optional[int] = None
    task_id: str = ""
    browser: str = ""
    version: str = ""
    channel: Optional[str] = None
    platform: str = ""
    arch: str = ""
    source: Optional[str] = None
    source_artifact_id: Optional[int] = None
    binary_path: Optional[str] = None
    binary_sha256: Optional[str] = None
    task_type: str = "analyze_candidate"
    status: str = "pending"
    priority: int = 100
    created_at: str = ""
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    finished_at: Optional[str] = None
    error_stage: Optional[str] = None
    error_msg: Optional[str] = None
    retry_count: int = 0

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "AgentTask":
        return cls(**{k: row[k] for k in row.keys()})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_task_id() -> str:
    return uuid.uuid4().hex[:16]


def create_task(
    conn: sqlite3.Connection,
    browser: str,
    version: str,
    platform: str,
    arch: str,
    *,
    channel: Optional[str] = None,
    source: Optional[str] = None,
    source_artifact_id: Optional[int] = None,
    binary_path: Optional[str] = None,
    binary_sha256: Optional[str] = None,
    task_type: str = "analyze_candidate",
    priority: int = 100,
) -> AgentTask:
    """Create a new agent task. Returns the created AgentTask.

    Dedup: if a task with the same (browser, version, channel, platform, arch)
    already exists in a non-terminal state, returns the existing task.
    """
    now = _now()

    # Check for existing non-terminal task
    existing = conn.execute(
        """
        SELECT * FROM agent_tasks
        WHERE browser=? AND version=? AND channel=? AND platform=? AND arch=?
          AND status NOT IN ('verified', 'failed', 'skipped')
        """,
        (browser, version, channel, platform, arch),
    ).fetchone()
    if existing:
        return AgentTask.from_row(existing)

    task_id = _new_task_id()
    conn.execute(
        """
        INSERT INTO agent_tasks
            (task_id, browser, version, channel, platform, arch,
             source, source_artifact_id, binary_path, binary_sha256,
             task_type, status, priority, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            task_id, browser, version, channel, platform, arch,
            source, source_artifact_id, binary_path, binary_sha256,
            task_type, "pending", priority, now, now,
        ),
    )
    return get_task_by_id_field(conn, task_id)


def get_task_by_id_field(conn: sqlite3.Connection, task_id: str) -> Optional[AgentTask]:
    """Get a task by its task_id string."""
    row = conn.execute(
        "SELECT * FROM agent_tasks WHERE task_id=?", (task_id,)
    ).fetchone()
    return AgentTask.from_row(row) if row else None


def get_task_by_pk(conn: sqlite3.Connection, pk: int) -> Optional[AgentTask]:
    """Get a task by its integer primary key."""
    row = conn.execute(
        "SELECT * FROM agent_tasks WHERE id=?", (pk,)
    ).fetchone()
    return AgentTask.from_row(row) if row else None


def find_task(
    conn: sqlite3.Connection,
    browser: str,
    version: str,
    platform: str,
    arch: str,
    channel: Optional[str] = None,
) -> Optional[AgentTask]:
    """Find an existing task by target coordinates."""
    if channel is not None:
        row = conn.execute(
            """
            SELECT * FROM agent_tasks
            WHERE browser=? AND version=? AND platform=? AND arch=? AND channel=?
            ORDER BY created_at DESC LIMIT 1
            """,
            (browser, version, platform, arch, channel),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT * FROM agent_tasks
            WHERE browser=? AND version=? AND platform=? AND arch=?
            ORDER BY created_at DESC LIMIT 1
            """,
            (browser, version, platform, arch),
        ).fetchone()
    return AgentTask.from_row(row) if row else None


def transition(
    conn: sqlite3.Connection,
    task_id: str,
    new_status: str,
    *,
    error_stage: Optional[str] = None,
    error_msg: Optional[str] = None,
) -> AgentTask:
    """Transition a task to a new status.

    Raises InvalidTransition if the transition is not allowed.
    """
    if new_status not in TASK_STATES:
        raise InvalidTransition(f"unknown status: {new_status}")

    task = get_task_by_id_field(conn, task_id)
    if not task:
        raise InvalidTransition(f"task not found: {task_id}")

    allowed = _TRANSITIONS.get(task.status, set())
    if new_status not in allowed:
        raise InvalidTransition(
            f"cannot transition {task.status} -> {new_status} for task {task_id}"
        )

    now = _now()
    updates = {"status": new_status, "updated_at": now}
    if new_status in ("downloading", "relocating", "analyzing", "ingesting", "verifying"):
        if not task.started_at:
            updates["started_at"] = now
    if new_status in ("verified", "failed", "skipped", "needs_manual_review"):
        updates["finished_at"] = now
    if error_stage:
        updates["error_stage"] = error_stage
    if error_msg:
        updates["error_msg"] = error_msg

    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [task_id]
    conn.execute(
        f"UPDATE agent_tasks SET {set_clause} WHERE task_id=?",
        values,
    )
    return get_task_by_id_field(conn, task_id)


def fail_task(
    conn: sqlite3.Connection,
    task_id: str,
    error_stage: str,
    error_msg: str,
) -> AgentTask:
    """Convenience: transition a task to 'failed' with error info."""
    return transition(
        conn, task_id, "failed",
        error_stage=error_stage, error_msg=error_msg,
    )


def retry_task(conn: sqlite3.Connection, task_id: str) -> AgentTask:
    """Reset a failed task to pending, incrementing retry_count."""
    task = get_task_by_id_field(conn, task_id)
    if not task:
        raise InvalidTransition(f"task not found: {task_id}")
    if task.status != "failed":
        raise InvalidTransition(
            f"can only retry failed tasks, got {task.status}"
        )

    now = _now()
    conn.execute(
        """
        UPDATE agent_tasks SET
            status='pending', error_stage=NULL, error_msg=NULL,
            started_at=NULL, finished_at=NULL,
            retry_count=retry_count+1, updated_at=?
        WHERE task_id=?
        """,
        (now, task_id),
    )
    return get_task_by_id_field(conn, task_id)


def list_tasks(
    conn: sqlite3.Connection,
    status: Optional[str] = None,
    browser: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[AgentTask]:
    """List tasks with optional filters."""
    conditions = []
    params: list = []
    if status:
        conditions.append("status=?")
        params.append(status)
    if browser:
        conditions.append("browser=?")
        params.append(browser)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.extend([limit, offset])
    rows = conn.execute(
        f"SELECT * FROM agent_tasks {where} ORDER BY priority, created_at LIMIT ? OFFSET ?",
        params,
    ).fetchall()
    return [AgentTask.from_row(r) for r in rows]


def pending_tasks(conn: sqlite3.Connection, limit: int = 50) -> List[AgentTask]:
    """Get tasks in pending status, ordered by priority."""
    return list_tasks(conn, status="pending", limit=limit)


def count_tasks(
    conn: sqlite3.Connection,
    status: Optional[str] = None,
    browser: Optional[str] = None,
) -> int:
    """Count tasks with optional filters."""
    conditions = []
    params: list = []
    if status:
        conditions.append("status=?")
        params.append(status)
    if browser:
        conditions.append("browser=?")
        params.append(browser)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    row = conn.execute(f"SELECT COUNT(*) FROM agent_tasks {where}", params).fetchone()
    return row[0]
