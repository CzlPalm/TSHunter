"""Browser data sources for the agent layer."""

from __future__ import annotations

from .base import BrowserArtifact, BrowserSource
from .chrome_cft import ChromeCfTSource
from .edge import EdgeDebRepoSource
from .firefox import FirefoxReleaseSource

__all__ = [
    "BrowserArtifact",
    "BrowserSource",
    "ChromeCfTSource",
    "EdgeDebRepoSource",
    "FirefoxReleaseSource",
]
