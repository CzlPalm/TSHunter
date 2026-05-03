"""BrowserSource abstract base class and BrowserArtifact dataclass."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import AgentConfig


@dataclass
class BrowserArtifact:
    """Represents a discovered or downloaded browser binary."""

    browser: str
    version: str
    channel: str = "stable"
    platform: str = "linux64"
    arch: str = "x86_64"
    download_url: str = ""
    milestone: str = ""

    # Populated after download
    package_path: Optional[Path] = None
    binary_path: Optional[Path] = None
    binary_sha256: str = ""
    package_sha256: str = ""
    source_metadata: Dict[str, Any] = field(default_factory=dict)


class BrowserSource(abc.ABC):
    """Abstract base class for browser data sources."""

    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Source identifier (e.g. 'chrome_cft', 'edge')."""

    @property
    @abc.abstractmethod
    def browser(self) -> str:
        """Browser name (e.g. 'chrome', 'edge', 'firefox')."""

    @abc.abstractmethod
    def poll(self) -> List[BrowserArtifact]:
        """Poll the data source and return available artifacts.

        Returns a list of BrowserArtifact with download_url populated.
        The artifacts are NOT yet downloaded.
        """

    @abc.abstractmethod
    def download(self, artifact: BrowserArtifact, output_dir: Path) -> BrowserArtifact:
        """Download and unpack a single artifact.

        Populates package_path, binary_path, binary_sha256, package_sha256.
        Returns the updated artifact.
        """
