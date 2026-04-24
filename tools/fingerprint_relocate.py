#!/usr/bin/env python3
"""Compat shim — forwards to tshunter.relocate.

Historical entry point used by run scripts and docs; the canonical
implementation now lives in `tshunter/relocate.py`.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tshunter.relocate import *  # noqa: F401,F403,E402
from tshunter.relocate import main  # noqa: E402


if __name__ == '__main__':
    main()
