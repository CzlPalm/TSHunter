"""Agent structured logging.

Provides a configured logger for agent operations with structured fields
for task_id, browser, version, stage, etc.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = ROOT / "results" / "agent"


def setup_agent_logging(
    log_dir: Optional[Path] = None,
    level: int = logging.INFO,
    run_id: Optional[str] = None,
) -> Path:
    """Configure logging for an agent run.

    Returns the path to the log file.
    """
    log_dir = log_dir or DEFAULT_LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = f"-{run_id}" if run_id else ""
    log_path = log_dir / f"{ts}-agent{suffix}.log"

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(fmt)
    console_handler.setLevel(level)

    root_logger = logging.getLogger("tshunter.agent")
    root_logger.setLevel(level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    return log_path


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the tshunter.agent namespace."""
    return logging.getLogger(f"tshunter.agent.{name}")


class AgentLogAdapter(logging.LoggerAdapter):
    """Logger adapter that injects structured fields into log messages."""

    def process(self, msg: str, kwargs: Any) -> tuple:
        extra_parts = []
        for key in ("task_id", "browser", "version", "stage", "elapsed"):
            val = self.extra.get(key)
            if val is not None:
                extra_parts.append(f"{key}={val}")
        if extra_parts:
            msg = f"[{' '.join(extra_parts)}] {msg}"
        return msg, kwargs


def task_logger(
    base_name: str,
    task_id: Optional[str] = None,
    browser: Optional[str] = None,
    version: Optional[str] = None,
    stage: Optional[str] = None,
) -> AgentLogAdapter:
    """Create a log adapter with task context fields."""
    logger = get_logger(base_name)
    return AgentLogAdapter(
        logger,
        {"task_id": task_id, "browser": browser, "version": version, "stage": stage},
    )


class StageTimer:
    """Context manager that logs stage duration."""

    def __init__(self, logger: AgentLogAdapter, stage: str):
        self._logger = logger
        self._stage = stage
        self._start: float = 0.0

    def __enter__(self) -> "StageTimer":
        self._start = time.monotonic()
        self._logger.debug("stage %s started", self._stage)
        return self

    def __exit__(self, *exc_info) -> None:
        elapsed = time.monotonic() - self._start
        self._logger.info(
            "stage %s finished in %.2fs", self._stage, elapsed
        )
