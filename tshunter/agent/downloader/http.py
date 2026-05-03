"""HTTP download with partial files, atomic rename, and retries."""

from __future__ import annotations

import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from ..logging import get_logger

logger = get_logger("downloader.http")

DEFAULT_TIMEOUT = 120
DEFAULT_RETRIES = 3
RETRY_BACKOFF = 2.0  # seconds, doubles each retry


def download_file(
    url: str,
    target_path: Path,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    backoff: float = RETRY_BACKOFF,
) -> Path:
    """Download a URL to target_path with retries and atomic rename.

    Writes to target_path.with_suffix('.part') first, then renames on success.
    Returns the final target_path on success.
    Raises the last exception after exhausting retries.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    part_path = target_path.with_suffix(target_path.suffix + ".part")

    last_exc: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            logger.debug("download attempt %d/%d: %s", attempt, retries, url)
            with urllib.request.urlopen(url, timeout=timeout) as resp, \
                 part_path.open("wb") as f:
                shutil.copyfileobj(resp, f)
            # Atomic rename
            part_path.rename(target_path)
            logger.debug("download complete: %s", target_path)
            return target_path
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            logger.warning(
                "download attempt %d/%d failed: %s", attempt, retries, exc
            )
            if attempt < retries:
                sleep_time = backoff * (2 ** (attempt - 1))
                time.sleep(sleep_time)

    # Clean up partial file on failure
    if part_path.exists():
        part_path.unlink()
    raise last_exc  # type: ignore[misc]
