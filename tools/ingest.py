#!/usr/bin/env python3
"""Compat shim — forwards to tshunter.ingest.

Kept so existing scripts that call `python3 tools/ingest.py` keep working.
When invoked directly we prepend the project root to sys.path so the
`tshunter` package resolves without requiring `pip install -e .`.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tshunter.ingest import main  # noqa: E402


if __name__ == '__main__':
    raise SystemExit(main())
