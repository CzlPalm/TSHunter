#!/usr/bin/env python3
"""Unified runtime capture entry (U2).

Before delegating to the legacy `tls_capture/tls_capture.py` runtime, we:
  1. import the legacy `lib.version_detect` module so that `from lib.version_detect
     import load_config, ...` inside the legacy script resolves to our patched
     loader attribute;
  2. replace `lib.version_detect.load_config` with a wrapper that talks to
     `VersionConfigLoader` (DB + profile + verified three-layer merge);
  3. fall back to the legacy JSON path only when `TSHUNTER_ALLOW_JSON_FALLBACK=1`
     is set (and the loader ended with `VersionNotInDB` / `RelocateFailed`).

The legacy script remains unmodified; this keeps the capture codebase usable by
external entry points that still call `tls_capture.py` directly (during the U2
transition window).
"""

from __future__ import annotations

import argparse
import json
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEGACY_ROOT = ROOT / 'tls_capture'
LEGACY_CAPTURE = LEGACY_ROOT / 'tls_capture.py'


def _install_loader_patch(browser: str, platform: str, arch: str,
                           binary_path: Path | None) -> None:
    """Monkey-patch `lib.version_detect.load_config` to use VersionConfigLoader."""
    # Make the legacy package resolvable as a top-level `lib` import.
    if str(LEGACY_ROOT) not in sys.path:
        sys.path.insert(0, str(LEGACY_ROOT))

    from tshunter.config_loader import (  # noqa: WPS433
        ProfileMissing,
        RelocateFailed,
        VersionConfigLoader,
        VersionNotInDB,
    )
    import lib.version_detect as vd  # noqa: WPS433

    allow_fallback = os.environ.get('TSHUNTER_ALLOW_JSON_FALLBACK') == '1'
    loader = VersionConfigLoader(
        allow_json_fallback=allow_fallback,
        auto_relocate=True,
    )
    original_load_config = vd.load_config

    def patched_load_config(version: str, config_dir: str | None = None):
        try:
            config = loader.load(
                browser=browser, version=version, platform=platform, arch=arch,
                binary_path=binary_path,
            )
            # Legacy callers expect these private keys.
            config.setdefault('_match_type', 'db')
            config.setdefault('_config_path', f"db:{loader.db_path}")
            return config
        except (VersionNotInDB, RelocateFailed, ProfileMissing) as exc:
            sys.stderr.write(f"[tshunter] loader miss: {type(exc).__name__}: {exc}\n")
            if allow_fallback:
                sys.stderr.write("[tshunter] falling back to tls_capture/hooks/*.json\n")
                return original_load_config(version, config_dir)
            return None

    vd.load_config = patched_load_config
    vd._tshunter_loader = loader  # expose for tests / debugging
    vd._tshunter_original_load_config = original_load_config


def _peek_target(argv: list[str]) -> tuple[str, Path | None]:
    """Extract (chrome_bin, binary_path) from argv without consuming legacy args."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--chrome-bin', default='/opt/google/chrome/chrome')
    parser.add_argument('--tshunter-browser', default='chrome')
    parser.add_argument('--tshunter-platform', default='linux')
    parser.add_argument('--tshunter-arch', default='x86_64')
    known, _ = parser.parse_known_args(argv)
    binary_path = Path(known.chrome_bin) if known.chrome_bin else None
    if binary_path and not binary_path.is_file():
        binary_path = None
    return known, binary_path


def _strip_tshunter_flags(argv: list[str]) -> list[str]:
    """Remove --tshunter-* flags before forwarding to the legacy script."""
    cleaned: list[str] = []
    skip_next = False
    for token in argv:
        if skip_next:
            skip_next = False
            continue
        if token.startswith('--tshunter-'):
            if '=' in token:
                continue
            skip_next = True
            continue
        cleaned.append(token)
    return cleaned


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv if argv is not None else sys.argv[1:])
    known, binary_path = _peek_target(raw_argv)
    forward_argv = _strip_tshunter_flags(raw_argv)

    _install_loader_patch(
        browser=known.tshunter_browser,
        platform=known.tshunter_platform,
        arch=known.tshunter_arch,
        binary_path=binary_path,
    )

    old_argv = sys.argv[:]
    try:
        sys.argv = [str(LEGACY_CAPTURE), *forward_argv]
        runpy.run_path(str(LEGACY_CAPTURE), run_name='__main__')
    finally:
        sys.argv = old_argv
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
