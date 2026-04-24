#!/usr/bin/env python3
"""Compat shim — forwards to tshunter.query."""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tshunter.query import main  # noqa: E402


if __name__ == '__main__':
    raise SystemExit(main())
