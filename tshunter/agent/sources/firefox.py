"""Firefox release data source.

Polls the Mozilla product-details API to discover Firefox versions,
downloads tar.bz2 archives from ftp.mozilla.org, extracts the firefox binary.

Skeleton implementation — marked planning_only in config.
"""

from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import AgentConfig
from ..downloader.checksum import sha256_file
from ..downloader.http import download_file as http_download
from ..logging import StageTimer, get_logger, task_logger
from .base import BrowserArtifact, BrowserSource

logger = get_logger("sources.firefox")

DEFAULT_TIMEOUT = 120

_CHANNEL_MAP = {
    "FIREFOX_RELEASE": "release",
    "FIREFOX_BETA": "beta",
    "FIREFOX_NIGHTLY": "nightly",
    "FIREFOX_DEVEDITION": "beta",
    "FIREFOX_ESR": "release",
}


class FirefoxReleaseSource(BrowserSource):
    """Mozilla Firefox release source: polls product-details API."""

    def __init__(self, cfg: AgentConfig):
        super().__init__(cfg)
        src_cfg = cfg.source_config("firefox")
        self._channels: List[str] = src_cfg.get("channels", ["release", "beta", "nightly"])
        self._platforms: List[str] = src_cfg.get("platforms", ["linux-x86_64"])
        self._product_details_url: str = src_cfg.get("product_details_url", "")
        self._releases_url: str = src_cfg.get(
            "releases_url", "https://ftp.mozilla.org/pub/firefox/releases/"
        )
        self._timeout: int = src_cfg.get("timeout", DEFAULT_TIMEOUT)

    @property
    def name(self) -> str:
        return "firefox"

    @property
    def browser(self) -> str:
        return "firefox"

    def _fetch_json(self, url: str) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            return json.load(resp)

    def poll(self) -> List[BrowserArtifact]:
        """Fetch Firefox versions from the product-details API.

        Returns one BrowserArtifact per (version, channel) combination.
        """
        if not self._product_details_url:
            logger.warning("no product_details_url configured")
            return []

        logger.info("polling Firefox product-details: %s", self._product_details_url)
        try:
            data = self._fetch_json(self._product_details_url)
        except Exception as exc:
            logger.error("failed to fetch Firefox product details: %s", exc)
            return []

        artifacts: List[BrowserArtifact] = []
        for api_key, channel in _CHANNEL_MAP.items():
            if channel not in self._channels:
                continue

            version = data.get(api_key, "")
            if not version:
                continue

            # Nightly versions like "137.0a1" — use as-is but skip for stable-like queries
            milestone = version.split(".")[0]

            for platform in self._platforms:
                download_url = self._build_download_url(version, platform)
                artifacts.append(BrowserArtifact(
                    browser="firefox",
                    version=version,
                    channel=channel,
                    platform=platform,
                    arch="x86_64",
                    download_url=download_url,
                    milestone=milestone,
                    source_metadata={"api_key": api_key},
                ))

        logger.info("found %d Firefox version artifacts", len(artifacts))
        return artifacts

    @staticmethod
    def _build_download_url(version: str, platform: str) -> str:
        """Build the ftp.mozilla.org download URL for a Firefox release."""
        lang = "en-US"
        ext = "tar.bz2"
        base = "https://ftp.mozilla.org/pub/firefox/releases/"
        return f"{base}{version}/{platform}/{lang}/firefox-{version}.{ext}"

    def download(self, artifact: BrowserArtifact, output_dir: Path) -> BrowserArtifact:
        """Download and extract a Firefox tar.bz2 archive.

        output_dir layout:
            {output_dir}/{version}/firefox-{version}.tar.bz2
            {output_dir}/{version}/firefox/firefox
        """
        log = task_logger(
            "sources.firefox",
            browser="firefox",
            version=artifact.version,
            stage="download",
        )

        version_dir = output_dir / artifact.version
        version_dir.mkdir(parents=True, exist_ok=True)

        archive_name = f"firefox-{artifact.version}.tar.bz2"
        archive_path = version_dir / archive_name
        binary_path = version_dir / "firefox" / "firefox"

        # Skip if already downloaded
        if binary_path.exists() and archive_path.exists():
            log.info("already downloaded, skipping")
            artifact.package_path = archive_path
            artifact.binary_path = binary_path
            artifact.binary_sha256 = sha256_file(binary_path)
            artifact.package_sha256 = sha256_file(archive_path)
            return artifact

        with StageTimer(log, "http_download"):
            http_download(artifact.download_url, archive_path, timeout=self._timeout)

        artifact.package_path = archive_path
        artifact.package_sha256 = sha256_file(archive_path)

        with StageTimer(log, "unpack_tar"):
            _unpack_tarball(archive_path, version_dir)

        artifact.binary_path = binary_path
        artifact.binary_sha256 = sha256_file(binary_path)
        log.info("downloaded and extracted: %s", binary_path)
        return artifact


def _unpack_tarball(archive_path: Path, output_dir: Path) -> None:
    """Extract a .tar.bz2 archive into output_dir.

    Expects the archive to contain a top-level firefox/ directory.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        logger.debug("extracting tarball %s to %s", archive_path, tmp_path)

        with tarfile.open(archive_path, "r:bz2") as tf:
            tf.extractall(tmp_path, filter="data")

        # Find the extracted firefox directory (usually top-level)
        firefox_dir = None
        for entry in tmp_path.iterdir():
            if entry.is_dir() and entry.name == "firefox":
                firefox_dir = entry
                break

        if not firefox_dir:
            raise FileNotFoundError(
                "Could not locate firefox/ directory in extracted tarball"
            )

        binary = firefox_dir / "firefox"
        if not binary.exists():
            raise FileNotFoundError(
                "Could not locate firefox binary in extracted tarball"
            )

        # Copy to output
        target_dir = output_dir / "firefox"
        if target_dir.exists():
            shutil.rmtree(target_dir)
        shutil.copytree(firefox_dir, target_dir)
        target_binary = target_dir / "firefox"
        target_binary.chmod(0o755)
        logger.debug("extracted binary: %s", target_binary)
