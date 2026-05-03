"""Verify worker: claims queued_verify tasks and verifies analysis results.

Currently a dry-run skeleton — logs what would happen.
Full implementation requires result comparison logic (Phase 6+).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ..config import AgentConfig
from ..db import connect
from ..db.task_store import (
    AgentTask,
    InvalidTransition,
    fail_task,
    list_tasks,
    transition,
)
from ..logging import get_logger, task_logger

logger = get_logger("workers.verify")


class VerifyWorker:
    """Claims queued_verify tasks and verifies analysis results (dry-run for now)."""

    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg

    def run(self, once: bool = False) -> int:
        """Process queued_verify tasks. Returns count of tasks processed."""
        processed = 0
        conn = connect()
        try:
            while True:
                tasks = list_tasks(conn, status="queued_verify", limit=1)
                if not tasks:
                    break
                task = tasks[0]
                ok = self._process_task(conn, task)
                if ok:
                    processed += 1
                if once:
                    break
        finally:
            conn.close()
        return processed

    def _process_task(self, conn: sqlite3.Connection, task: AgentTask) -> bool:
        """Process a single queued_verify task."""
        log = task_logger(
            "workers.verify",
            browser=task.browser,
            version=task.version,
            stage="verify",
        )

        # Claim the task
        try:
            transition(conn, task.task_id, "verifying")
            conn.commit()
        except InvalidTransition as exc:
            log.debug("skip: %s", exc)
            return False

        try:
            self._do_verify(conn, task, log)
            return True
        except Exception as exc:
            log.error("verify failed: %s", exc)
            fail_task(conn, task.task_id, error_stage="verify", error_msg=str(exc))
            conn.commit()
            return False

    def _do_verify(self, conn, task: AgentTask, log) -> None:
        """Check if analysis results exist and log verification plan."""
        # Check if analysis results exist in the DB
        row = conn.execute(
            """
            SELECT v.id, v.version, COUNT(h.id) as hook_count
            FROM versions v
            JOIN browsers b ON v.browser_id = b.id
            JOIN hook_points h ON h.version_id = v.id
            WHERE b.name = ? AND v.version = ? AND v.platform = ? AND v.arch = ?
            GROUP BY v.id
            """,
            (task.browser, task.version, task.platform, task.arch),
        ).fetchone()

        if not row or row["hook_count"] == 0:
            log.warning(
                "no analysis results found for %s %s — cannot verify",
                task.browser,
                task.version,
            )
            transition(conn, task.task_id, "needs_manual_review")
            conn.commit()
            return

        log.info(
            "found %d hook points for %s %s — would run verification",
            row["hook_count"],
            task.browser,
            task.version,
        )

        # Full implementation (future):
        # from ...analyze import compare_results
        # result_path = self.cfg.metadata_dir / f"{task.browser}_{task.version}.json"
        # ground_truth = ...  # find ground truth for this browser/platform
        # match = compare_results(result_path, ground_truth)
        # if match:
        #     transition(conn, task.task_id, "verified")
        # else:
        #     fail_task(conn, task.task_id, "verify", "results do not match ground truth")

        # For now, mark as needing manual review
        transition(conn, task.task_id, "needs_manual_review")
        conn.commit()
