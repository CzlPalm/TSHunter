"""Agent database access layer."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB = ROOT / "data" / "fingerprints.db"


def connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Open a connection to the fingerprint database.

    Reuses the same DB as the rest of TSHunter.
    """
    path = db_path or DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
