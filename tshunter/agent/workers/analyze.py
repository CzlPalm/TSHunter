"""Analyze worker: claims downloaded tasks and runs binary analysis.

Currently a dry-run skeleton — checks feasibility and logs what would happen.
Full implementation requires Docker-based Ghidra analysis (Phase 6+).
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

logger = get_logger("workers.analyze")


class AnalyzeWorker:
    """Claims downloaded tasks and drives analysis (dry-run for now)."""

    def __init__(self, cfg: AgentConfig, dry_run: bool = True):
        self.cfg = cfg
        self.dry_run = dry_run

    def run(self, once: bool = False) -> int:
        """Process downloaded tasks. Returns count of tasks processed."""
        processed = 0
        conn = connect()
        try:
            while True:
                # Claim downloaded → queued_analyze first
                downloaded = list_tasks(conn, status="downloaded", limit=1)
                if downloaded:
                    task = downloaded[0]
                    try:
                        transition(conn, task.task_id, "queued_analyze")
                        conn.commit()
                    except InvalidTransition:
                        pass

                # Now work on queued_analyze tasks
                tasks = list_tasks(conn, status="queued_analyze", limit=1)
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
        """Process a single downloaded task."""
        log = task_logger(
            "workers.analyze",
            browser=task.browser,
            version=task.version,
            stage="analyze",
        )

        # Claim the task
        try:
            transition(conn, task.task_id, "analyzing")
            conn.commit()
        except InvalidTransition as exc:
            log.debug("skip: %s", exc)
            return False

        try:
            self._do_analyze(conn, task, log)
            return True
        except Exception as exc:
            log.error("analyze failed: %s", exc)
            fail_task(conn, task.task_id, error_stage="analyze", error_msg=str(exc))
            conn.commit()
            return False

    def _do_analyze(self, conn, task: AgentTask, log) -> None:
        """Check analysis feasibility and perform (or stub) the analysis."""
        # Verify binary exists
        if not task.binary_path:
            raise FileNotFoundError("task has no binary_path")

        binary = Path(task.binary_path)
        if not binary.exists():
            raise FileNotFoundError(f"binary not found: {binary}")

        # Check for relocate baseline: is there a verified version with hooks
        # for the same browser/platform/arch?
        baseline = self._find_relocate_baseline(conn, task)

        if baseline:
            log.info(
                "relocate baseline found: %s %s (hooks=%d)",
                task.browser,
                baseline["version"],
                baseline["hook_count"],
            )
            analysis_mode = "relocate"
        else:
            log.info("no relocate baseline — would run full Docker analysis")
            analysis_mode = "full_docker"

        if self.dry_run:
            log.info(
                "[dry-run] would %s for %s %s → binary=%s",
                analysis_mode,
                task.browser,
                task.version,
                binary,
            )
            # In dry-run, mark for manual review
            transition(conn, task.task_id, "needs_manual_review")
            conn.commit()
            return

        # Full implementation (future):
        # if analysis_mode == "relocate":
        #     from ...relocate import scan, load_hooks_from_db
        #     hooks = load_hooks_from_db(conn, task.browser, baseline["version"], ...)
        #     result = scan(binary, hooks, ...)
        #     from ...ingest import ingest_relocate_payload
        #     ingest_relocate_payload(conn, result, args)
        # else:
        #     from ...analyze import analyze_binary
        #     result, _ = analyze_binary(binary, output, metadata, image_tag, rebuild)
        #     from ...ingest import ingest_payload
        #     ingest_payload(conn, result, args)

        # For now, transition to needs_manual_review
        transition(conn, task.task_id, "needs_manual_review")
        conn.commit()

    @staticmethod
    def _find_relocate_baseline(conn, task: AgentTask) -> dict | None:
        """Find a verified version with hook_points for the same browser/platform/arch.

        Returns dict with version and hook_count, or None.
        """
        row = conn.execute(
            """
            SELECT v.version, COUNT(h.id) as hook_count
            FROM versions v
            JOIN browsers b ON v.browser_id = b.id
            JOIN hook_points h ON h.version_id = v.id
            WHERE b.name = ? AND v.platform = ? AND v.arch = ?
              AND v.verified = 1
            GROUP BY v.id
            ORDER BY v.version DESC
            LIMIT 1
            """,
            (task.browser, task.platform, task.arch),
        ).fetchone()
        if row and row["hook_count"] > 0:
            return {"version": row["version"], "hook_count": row["hook_count"]}
        return None
