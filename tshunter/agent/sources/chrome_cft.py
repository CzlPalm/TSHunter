"""Chrome for Testing data source.

Polls the CfT known-good-versions API to discover Chrome versions,
downloads and unpacks zip archives, computes SHA256 checksums.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import AgentConfig
from ..downloader.checksum import sha256_file
from ..downloader.http import download_file as http_download
from ..downloader.unpack import unpack_archive
from ..logging import StageTimer, get_logger, task_logger
from .base import BrowserArtifact, BrowserSource

logger = get_logger("sources.chrome_cft")

DEFAULT_TIMEOUT = 60


class ChromeCfTSource(BrowserSource):
    """Chrome for Testing source: polls the known-good-versions API."""

    def __init__(self, cfg: AgentConfig):
        super().__init__(cfg)
        src_cfg = cfg.source_config("chrome_cft")
        self._known_good_url: str = src_cfg.get("known_good_url", "")
        self._platforms: List[str] = src_cfg.get("platforms", ["linux64"])
        self._timeout: int = src_cfg.get("timeout", DEFAULT_TIMEOUT)

    @property
    def name(self) -> str:
        return "chrome_cft"

    @property
    def browser(self) -> str:
        return "chrome"

    def _fetch_json(self, url: str) -> dict:
        with urllib.request.urlopen(url, timeout=self._timeout) as resp:
            return json.load(resp)

    def poll(self) -> List[BrowserArtifact]:
        """Fetch all known-good Chrome versions from the CfT API.

        Returns one BrowserArtifact per (version, platform) pair.
        """
        logger.info("polling CfT known-good versions: %s", self._known_good_url)
        data = self._fetch_json(self._known_good_url)
        versions_raw = data.get("versions", [])

        artifacts: List[BrowserArtifact] = []
        for entry in versions_raw:
            version = entry.get("version", "")
            if not version:
                continue
            milestone = version.split(".")[0]
            downloads = entry.get("downloads", {}).get("chrome", [])
            for dl in downloads:
                platform = dl.get("platform", "")
                if platform not in self._platforms:
                    continue
                url = dl.get("url", "")
                if not url:
                    continue
                artifacts.append(BrowserArtifact(
                    browser="chrome",
                    version=version,
                    channel="stable",
                    platform=platform,
                    arch="x86_64",
                    download_url=url,
                    milestone=milestone,
                ))

        logger.info("found %d version/platform artifacts", len(artifacts))
        return artifacts

    def download(self, artifact: BrowserArtifact, output_dir: Path) -> BrowserArtifact:
        """Download, unpack, and checksum a single Chrome CfT artifact.

        output_dir layout:
            {output_dir}/{version}/chrome-linux64.zip
            {output_dir}/{version}/chrome
        """
        log = task_logger(
            "sources.chrome_cft",
            browser="chrome",
            version=artifact.version,
            stage="download",
        )

        version_dir = output_dir / artifact.version
        version_dir.mkdir(parents=True, exist_ok=True)

        archive_name = f"chrome-{artifact.platform}.zip"
        archive_path = version_dir / archive_name
        binary_path = version_dir / "chrome"

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

        with StageTimer(log, "unpack"):
            unpack_archive(
                archive_path,
                version_dir,
                browser="chrome",
                platform=artifact.platform,
                keep_archive=True,
            )

        artifact.binary_path = binary_path
        artifact.binary_sha256 = sha256_file(binary_path)
        log.info("downloaded and unpacked: %s", binary_path)
        return artifact
