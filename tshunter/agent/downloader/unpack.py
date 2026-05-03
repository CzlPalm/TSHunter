"""Archive unpacking and binary extraction.

Supports .zip (Chrome, Firefox) and .deb (Edge) archives.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from ..logging import get_logger

logger = get_logger("downloader.unpack")

# Well-known binary paths inside extracted archives
_CHROME_NESTED = "chrome-linux64/chrome"
_EDGE_DEB_NESTED = "opt/microsoft/msedge/msedge"
_FIREFOX_NESTED = "firefox/firefox"

# Platform-specific nested paths (zip archives)
_NESTED_PATHS = {
    "chrome": {"linux64": _CHROME_NESTED},
    "firefox": {"linux64": _FIREFOX_NESTED},
}

# Platform-specific nested paths (deb packages)
_DEB_NESTED_PATHS = {
    "edge": {"linux64": _EDGE_DEB_NESTED},
}


def find_real_binary(
    extract_root: Path,
    browser: str,
    platform: str = "linux64",
    *,
    archive_type: str = "zip",
) -> Optional[Path]:
    """Walk the extracted directory to find the real browser binary.

    Checks well-known nested paths first, then searches for executables.
    archive_type: 'zip' or 'deb' to select the right path table.
    Returns None if no binary is found.
    """
    path_table = _DEB_NESTED_PATHS if archive_type == "deb" else _NESTED_PATHS
    known = path_table.get(browser, {}).get(platform)
    if known:
        candidate = extract_root / known
        if candidate.exists():
            return candidate

    # Fallback: search for common binary names
    binary_names = {"chrome", "msedge", "firefox", "google-chrome"}
    for name in binary_names:
        for match in extract_root.rglob(name):
            if match.is_file() and not match.is_symlink():
                try:
                    if match.stat().st_mode & 0o111:
                        return match
                except OSError:
                    pass
    return None


def unpack_deb(
    deb_path: Path,
    output_dir: Path,
    browser: str,
    platform: str = "linux64",
    *,
    keep_archive: bool = True,
) -> Path:
    """Extract a .deb package and locate the browser binary.

    Uses dpkg-deb -x to extract into a temp directory, then finds
    the binary at the well-known path.
    Returns the path to the extracted binary.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        logger.debug("extracting deb %s to %s", deb_path, tmp_path)

        result = subprocess.run(
            ["dpkg-deb", "-x", str(deb_path), str(tmp_path)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"dpkg-deb extraction failed: {result.stderr.strip()}"
            )

        binary_source = find_real_binary(
            tmp_path, browser, platform, archive_type="deb",
        )
        if not binary_source:
            raise FileNotFoundError(
                f"Could not locate {browser} binary in extracted .deb"
            )

        binary_target = output_dir / "msedge"
        shutil.copy2(binary_source, binary_target)
        binary_target.chmod(0o755)
        logger.debug("extracted binary: %s", binary_target)

    if not keep_archive and deb_path.exists():
        deb_path.unlink()
        logger.debug("removed archive: %s", deb_path)

    return binary_target


def unpack_archive(
    archive_path: Path,
    output_dir: Path,
    browser: str,
    platform: str = "linux64",
    *,
    keep_archive: bool = True,
) -> Path:
    """Extract a zip archive and locate the browser binary.

    Returns the path to the extracted binary.
    Raises FileNotFoundError if the binary cannot be located.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        logger.debug("extracting %s to %s", archive_path, tmp_path)

        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(tmp_path)

        binary_source = find_real_binary(tmp_path, browser, platform)
        if not binary_source:
            raise FileNotFoundError(
                f"Could not locate {browser} binary in extracted archive"
            )

        binary_target = output_dir / binary_source.name
        shutil.copy2(binary_source, binary_target)
        binary_target.chmod(0o755)
        logger.debug("extracted binary: %s", binary_target)

    if not keep_archive and archive_path.exists():
        archive_path.unlink()
        logger.debug("removed archive: %s", archive_path)

    return binary_target
