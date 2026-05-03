"""source_artifacts table CRUD operations."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SourceArtifact:
    id: Optional[int] = None
    browser: str = ""
    version: str = ""
    channel: Optional[str] = None
    platform: str = ""
    arch: str = ""
    source: str = ""
    package_url: Optional[str] = None
    package_path: Optional[str] = None
    binary_path: Optional[str] = None
    binary_sha256: str = ""
    version_output: Optional[str] = None
    source_metadata_json: Optional[str] = None
    downloaded_at: str = ""
    created_at: str = ""
    updated_at: Optional[str] = None

    def to_row(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("id", None)
        return d

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "SourceArtifact":
        return cls(**{k: row[k] for k in row.keys()})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_artifact(conn: sqlite3.Connection, artifact: SourceArtifact) -> int:
    """Insert or update a source_artifact. Returns the row id.

    Dedup key: (browser, version, channel, platform, arch, binary_sha256).
    """
    now = _now()
    if not artifact.created_at:
        artifact.created_at = now
    artifact.updated_at = now

    row = conn.execute(
        """
        SELECT id FROM source_artifacts
        WHERE browser=? AND version=? AND channel=? AND platform=? AND arch=?
          AND binary_sha256=?
        """,
        (
            artifact.browser, artifact.version, artifact.channel,
            artifact.platform, artifact.arch, artifact.binary_sha256,
        ),
    ).fetchone()

    if row:
        conn.execute(
            """
            UPDATE source_artifacts SET
                source=?, package_url=?, package_path=?, binary_path=?,
                version_output=?, source_metadata_json=?,
                downloaded_at=?, updated_at=?
            WHERE id=?
            """,
            (
                artifact.source, artifact.package_url, artifact.package_path,
                artifact.binary_path, artifact.version_output,
                artifact.source_metadata_json,
                artifact.downloaded_at, now, row["id"],
            ),
        )
        return row["id"]

    conn.execute(
        """
        INSERT INTO source_artifacts
            (browser, version, channel, platform, arch, source,
             package_url, package_path, binary_path, binary_sha256,
             version_output, source_metadata_json,
             downloaded_at, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            artifact.browser, artifact.version, artifact.channel,
            artifact.platform, artifact.arch, artifact.source,
            artifact.package_url, artifact.package_path, artifact.binary_path,
            artifact.binary_sha256, artifact.version_output,
            artifact.source_metadata_json,
            artifact.downloaded_at, artifact.created_at, now,
        ),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def find_artifact(
    conn: sqlite3.Connection,
    browser: str,
    version: str,
    platform: str,
    arch: str,
    channel: Optional[str] = None,
) -> Optional[SourceArtifact]:
    """Find an existing artifact by browser/version/platform/arch."""
    if channel is not None:
        row = conn.execute(
            """
            SELECT * FROM source_artifacts
            WHERE browser=? AND version=? AND platform=? AND arch=? AND channel=?
            """,
            (browser, version, platform, arch, channel),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT * FROM source_artifacts
            WHERE browser=? AND version=? AND platform=? AND arch=?
            """,
            (browser, version, platform, arch),
        ).fetchone()
    return SourceArtifact.from_row(row) if row else None


def find_by_sha256(
    conn: sqlite3.Connection,
    binary_sha256: str,
) -> List[SourceArtifact]:
    """Find all artifacts matching a given sha256."""
    rows = conn.execute(
        "SELECT * FROM source_artifacts WHERE binary_sha256=?",
        (binary_sha256,),
    ).fetchall()
    return [SourceArtifact.from_row(r) for r in rows]


def list_artifacts(
    conn: sqlite3.Connection,
    browser: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[SourceArtifact]:
    """List artifacts with optional browser filter."""
    if browser:
        rows = conn.execute(
            "SELECT * FROM source_artifacts WHERE browser=? ORDER BY downloaded_at DESC LIMIT ? OFFSET ?",
            (browser, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM source_artifacts ORDER BY downloaded_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [SourceArtifact.from_row(r) for r in rows]


def count_artifacts(
    conn: sqlite3.Connection,
    browser: Optional[str] = None,
) -> int:
    """Count artifacts, optionally filtered by browser."""
    if browser:
        row = conn.execute(
            "SELECT COUNT(*) FROM source_artifacts WHERE browser=?", (browser,)
        ).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) FROM source_artifacts").fetchone()
    return row[0]


def set_metadata_json(artifact: SourceArtifact, metadata: Dict[str, Any]) -> SourceArtifact:
    """Helper to set source_metadata_json from a dict."""
    artifact.source_metadata_json = json.dumps(metadata, ensure_ascii=False)
    return artifact
