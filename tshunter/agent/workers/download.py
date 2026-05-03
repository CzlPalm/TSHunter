"""Download worker: claims pending tasks and downloads browser binaries."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import AgentConfig
from ..db import connect
from ..db.artifact_store import SourceArtifact, find_artifact, upsert_artifact
from ..db.task_store import (
    AgentTask,
    InvalidTransition,
    fail_task,
    list_tasks,
    transition,
)
from ..logging import get_logger, task_logger
from ..sources.chrome_cft import ChromeCfTSource
from ..sources.edge import EdgeDebRepoSource
from ..sources.firefox import FirefoxReleaseSource

logger = get_logger("workers.download")

_SOURCE_FACTORIES = {
    "chrome": lambda cfg: (ChromeCfTSource(cfg), cfg.download_dir / "chrome"),
    "edge": lambda cfg: (EdgeDebRepoSource(cfg), cfg.download_dir / "edge"),
    "firefox": lambda cfg: (FirefoxReleaseSource(cfg), cfg.download_dir / "firefox"),
}


class DownloadWorker:
    """Claims pending agent tasks and downloads browser binaries."""

    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg

    def run(self, once: bool = False) -> int:
        """Process pending download tasks. Returns count of tasks processed."""
        processed = 0
        conn = connect()
        try:
            while True:
                tasks = list_tasks(conn, status="pending", limit=1)
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
        """Process a single pending task. Returns True on success."""
        log = task_logger(
            "workers.download",
            browser=task.browser,
            version=task.version,
            stage="download",
        )

        # Claim the task
        try:
            transition(conn, task.task_id, "downloading")
            conn.commit()
        except InvalidTransition as exc:
            log.debug("skip: %s", exc)
            return False

        try:
            self._do_download(conn, task, log)
            return True
        except Exception as exc:
            log.error("download failed: %s", exc)
            fail_task(conn, task.task_id, error_stage="download", error_msg=str(exc))
            conn.commit()
            return False

    def _do_download(self, conn, task: AgentTask, log) -> None:
        """Resolve artifact, download binary, update DB."""
        # Resolve source artifact
        artifact = None
        if task.source_artifact_id:
            row = conn.execute(
                "SELECT * FROM source_artifacts WHERE id=?",
                (task.source_artifact_id,),
            ).fetchone()
            if row:
                artifact = SourceArtifact.from_row(row)

        if not artifact:
            artifact = find_artifact(
                conn, task.browser, task.version, task.platform, task.arch,
                channel=task.channel,
            )

        if not artifact:
            raise FileNotFoundError(
                f"No source_artifact for {task.browser} {task.version} "
                f"{task.platform} {task.arch}"
            )

        # Select source class
        factory = _SOURCE_FACTORIES.get(task.browser)
        if not factory:
            raise ValueError(f"Unknown browser: {task.browser}")

        source, output_dir = factory(self.cfg)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build BrowserArtifact for download
        from ..sources.base import BrowserArtifact

        dl_artifact = BrowserArtifact(
            browser=task.browser,
            version=task.version,
            channel=task.channel or "stable",
            platform=task.platform,
            arch=task.arch,
            download_url=artifact.package_url or "",
            source_metadata=json.loads(artifact.source_metadata_json or "{}"),
        )

        log.info("downloading %s %s", task.browser, task.version)
        result = source.download(dl_artifact, output_dir)

        # Update source_artifact with download results
        artifact.package_path = str(result.package_path) if result.package_path else None
        artifact.binary_path = str(result.binary_path) if result.binary_path else None
        artifact.binary_sha256 = result.binary_sha256
        artifact.package_sha256 = result.package_sha256
        artifact.downloaded_at = datetime.now(timezone.utc).isoformat()
        upsert_artifact(conn, artifact)

        # Update agent_task with binary info
        conn.execute(
            "UPDATE agent_tasks SET binary_path=?, binary_sha256=?, updated_at=datetime('now') WHERE task_id=?",
            (str(result.binary_path), result.binary_sha256, task.task_id),
        )

        # Transition to downloaded
        transition(conn, task.task_id, "downloaded")
        conn.commit()
        log.info("downloaded: %s", result.binary_path)
