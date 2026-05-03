"""Microsoft Edge deb repo data source.

Polls the Microsoft Edge apt repository pool to discover Edge versions,
downloads .deb packages, extracts the msedge binary.
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import AgentConfig
from ..downloader.checksum import sha256_file
from ..downloader.http import download_file as http_download
from ..downloader.unpack import unpack_deb
from ..logging import StageTimer, get_logger, task_logger
from .base import BrowserArtifact, BrowserSource

logger = get_logger("sources.edge")

DEFAULT_TIMEOUT = 60

# Pattern: microsoft-edge-{channel}_{version}-1_amd64.deb
_DEB_RE = re.compile(
    r"href=\"(microsoft-edge-(stable|beta|dev)_(.+?)-1_amd64\.deb)\""
)


def _parse_version_from_filename(filename: str) -> Optional[str]:
    """Extract version from an Edge .deb filename."""
    m = re.match(r"microsoft-edge-\w+_(.+)-1_amd64\.deb", filename)
    return m.group(1) if m else None


def _fetch_pool_html(url: str, timeout: int) -> str:
    """Fetch HTML listing from an Edge deb pool URL."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _parse_pool_html(html: str, channel: str) -> List[Dict[str, str]]:
    """Parse pool HTML to extract .deb filenames and URLs for a channel.

    Returns list of dicts with keys: filename, version, channel, url.
    """
    results = []
    for match in _DEB_RE.finditer(html):
        filename, ch, version = match.group(1), match.group(2), match.group(3)
        if ch != channel:
            continue
        results.append({
            "filename": filename,
            "version": version,
            "channel": ch,
        })
    return results


class EdgeDebRepoSource(BrowserSource):
    """Microsoft Edge deb repo source: scrapes the apt pool directory."""

    def __init__(self, cfg: AgentConfig):
        super().__init__(cfg)
        src_cfg = cfg.source_config("edge")
        self._channels: List[str] = src_cfg.get("channels", ["stable"])
        self._timeout: int = src_cfg.get("timeout", DEFAULT_TIMEOUT)
        self._pool_urls: Dict[str, str] = {}
        for ch in ("stable", "beta", "dev"):
            key = f"{ch}_pool_url"
            if key in src_cfg:
                self._pool_urls[ch] = src_cfg[key]

    @property
    def name(self) -> str:
        return "edge"

    @property
    def browser(self) -> str:
        return "edge"

    def poll(self) -> List[BrowserArtifact]:
        """Poll Edge deb pool URLs to discover available versions.

        Returns one BrowserArtifact per (version, channel) pair.
        """
        artifacts: List[BrowserArtifact] = []

        for channel in self._channels:
            pool_url = self._pool_urls.get(channel)
            if not pool_url:
                logger.warning("no pool_url configured for channel %s", channel)
                continue

            logger.info("polling Edge %s pool: %s", channel, pool_url)
            try:
                html = _fetch_pool_html(pool_url, self._timeout)
            except Exception as exc:
                logger.error("failed to fetch %s pool: %s", channel, exc)
                continue

            entries = _parse_pool_html(html, channel)
            for entry in entries:
                download_url = pool_url + entry["filename"]
                milestone = entry["version"].split(".")[0]
                artifacts.append(BrowserArtifact(
                    browser="edge",
                    version=entry["version"],
                    channel=channel,
                    platform="linux64",
                    arch="x86_64",
                    download_url=download_url,
                    milestone=milestone,
                    source_metadata={"filename": entry["filename"]},
                ))

        logger.info("found %d Edge version/channel artifacts", len(artifacts))
        return artifacts

    def download(self, artifact: BrowserArtifact, output_dir: Path) -> BrowserArtifact:
        """Download a .deb package and extract the msedge binary.

        output_dir layout:
            {output_dir}/{version}/microsoft-edge-{channel}_{version}-1_amd64.deb
            {output_dir}/{version}/msedge
        """
        log = task_logger(
            "sources.edge",
            browser="edge",
            version=artifact.version,
            stage="download",
        )

        version_dir = output_dir / artifact.version
        version_dir.mkdir(parents=True, exist_ok=True)

        filename = artifact.source_metadata.get("filename", "")
        if not filename:
            filename = f"microsoft-edge-{artifact.channel}_{artifact.version}-1_amd64.deb"
        deb_path = version_dir / filename
        binary_path = version_dir / "msedge"

        # Skip if already downloaded
        if binary_path.exists() and deb_path.exists():
            log.info("already downloaded, skipping")
            artifact.package_path = deb_path
            artifact.binary_path = binary_path
            artifact.binary_sha256 = sha256_file(binary_path)
            artifact.package_sha256 = sha256_file(deb_path)
            return artifact

        with StageTimer(log, "http_download"):
            http_download(artifact.download_url, deb_path, timeout=self._timeout)

        artifact.package_path = deb_path
        artifact.package_sha256 = sha256_file(deb_path)

        with StageTimer(log, "unpack_deb"):
            unpack_deb(
                deb_path,
                version_dir,
                browser="edge",
                platform=artifact.platform,
                keep_archive=True,
            )

        artifact.binary_path = binary_path
        artifact.binary_sha256 = sha256_file(binary_path)
        log.info("downloaded and extracted: %s", binary_path)
        return artifact
