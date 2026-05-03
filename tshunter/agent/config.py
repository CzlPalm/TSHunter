"""Agent configuration loader.

Loads configs/agent.yaml and provides defaults for all settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = ROOT / "configs" / "agent.yaml"

_DEFAULTS: Dict[str, Any] = {
    "agent": {
        "enabled": True,
        "poll_interval_minutes": 60,
        "download_dir": "./artifacts/downloads",
        "binary_dir": "./artifacts/binaries",
        "metadata_dir": "./artifacts/metadata",
        "max_parallel_downloads": 2,
        "max_retries": 3,
        "timeout_seconds": 1800,
    },
    "policy": {
        "auto_analyze": False,
        "auto_verify": False,
        "auto_publish": False,
        "require_explicit_capture": True,
        "allow_unverified_runtime_use": False,
    },
    "platform": {
        "os": "linux",
        "arch": "x86_64",
    },
    "sources": {
        "chrome_cft": {
            "enabled": True,
            "channels": ["Stable", "Beta", "Dev", "Canary"],
            "platforms": ["linux64"],
            "known_good_url": (
                "https://googlechromelabs.github.io/chrome-for-testing/"
                "known-good-versions-with-downloads.json"
            ),
            "last_known_good_url": (
                "https://googlechromelabs.github.io/chrome-for-testing/"
                "last-known-good-versions-with-downloads.json"
            ),
        },
        "edge": {
            "enabled": True,
            "channels": ["stable", "beta", "dev"],
            "platforms": ["linux_amd64"],
            "stable_pool_url": (
                "https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-stable/"
            ),
            "beta_pool_url": (
                "https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-beta/"
            ),
            "dev_pool_url": (
                "https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-dev/"
            ),
        },
        "firefox": {
            "enabled": True,
            "planning_only": True,
            "channels": ["release", "beta", "nightly"],
            "platforms": ["linux-x86_64"],
            "product_details_url": (
                "https://product-details.mozilla.org/1.0/firefox_versions.json"
            ),
            "releases_url": "https://ftp.mozilla.org/pub/firefox/releases/",
        },
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


@dataclass
class AgentConfig:
    """Resolved agent configuration."""

    raw: Dict[str, Any]
    config_path: Optional[Path] = None

    @property
    def enabled(self) -> bool:
        return bool(self.raw.get("agent", {}).get("enabled", True))

    @property
    def poll_interval_minutes(self) -> int:
        return int(self.raw.get("agent", {}).get("poll_interval_minutes", 60))

    @property
    def download_dir(self) -> Path:
        p = self.raw.get("agent", {}).get("download_dir", "./artifacts/downloads")
        path = Path(p)
        if not path.is_absolute():
            path = ROOT / path
        return path

    @property
    def binary_dir(self) -> Path:
        p = self.raw.get("agent", {}).get("binary_dir", "./artifacts/binaries")
        path = Path(p)
        if not path.is_absolute():
            path = ROOT / path
        return path

    @property
    def metadata_dir(self) -> Path:
        p = self.raw.get("agent", {}).get("metadata_dir", "./artifacts/metadata")
        path = Path(p)
        if not path.is_absolute():
            path = ROOT / path
        return path

    @property
    def max_parallel_downloads(self) -> int:
        return int(self.raw.get("agent", {}).get("max_parallel_downloads", 2))

    @property
    def max_retries(self) -> int:
        return int(self.raw.get("agent", {}).get("max_retries", 3))

    @property
    def timeout_seconds(self) -> int:
        return int(self.raw.get("agent", {}).get("timeout_seconds", 1800))

    @property
    def auto_analyze(self) -> bool:
        return bool(self.raw.get("policy", {}).get("auto_analyze", False))

    @property
    def auto_verify(self) -> bool:
        return bool(self.raw.get("policy", {}).get("auto_verify", False))

    @property
    def auto_publish(self) -> bool:
        return bool(self.raw.get("policy", {}).get("auto_publish", False))

    @property
    def require_explicit_capture(self) -> bool:
        return bool(self.raw.get("policy", {}).get("require_explicit_capture", True))

    @property
    def allow_unverified_runtime_use(self) -> bool:
        return bool(self.raw.get("policy", {}).get("allow_unverified_runtime_use", False))

    @property
    def platform_os(self) -> str:
        return self.raw.get("platform", {}).get("os", "linux")

    @property
    def platform_arch(self) -> str:
        return self.raw.get("platform", {}).get("arch", "x86_64")

    def source_config(self, name: str) -> Dict[str, Any]:
        """Return config dict for a specific source (chrome_cft, edge, firefox)."""
        return self.raw.get("sources", {}).get(name, {})

    @property
    def enabled_sources(self) -> List[str]:
        """Return list of enabled source names."""
        sources = self.raw.get("sources", {})
        return [name for name, cfg in sources.items() if cfg.get("enabled", True)]


def load_config(path: Optional[Path] = None) -> AgentConfig:
    """Load agent config from YAML file, merged with defaults.

    If path is None, uses DEFAULT_CONFIG_PATH.
    If the file does not exist, returns defaults only.
    """
    config_path = path or DEFAULT_CONFIG_PATH
    raw = dict(_DEFAULTS)

    if config_path.is_file():
        with open(config_path, encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
        if isinstance(loaded, dict):
            raw = _deep_merge(raw, loaded)

    return AgentConfig(raw=raw, config_path=config_path)
