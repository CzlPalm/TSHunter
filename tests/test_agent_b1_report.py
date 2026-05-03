"""Tests for agent B1 report generator."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SQL = ROOT / "data" / "schema.sql"
MIGRATION_SQL = ROOT / "data" / "migrations" / "007_agent_tables.sql"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_agent_db(tmp_path: Path) -> sqlite3.Connection:
    """Create a DB with base schema + agent tables."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA_SQL.read_text())
    conn.executescript(MIGRATION_SQL.read_text())
    return conn


def _seed_hook_data(conn, browser="chrome", version="143.0.7499.169",
                     platform="linux", arch="x86_64"):
    """Seed a browser, version, and 4 hook_points."""
    conn.execute(
        "INSERT INTO browsers (name) VALUES (?) ON CONFLICT(name) DO NOTHING",
        (browser,),
    )
    browser_row = conn.execute("SELECT id FROM browsers WHERE name=?", (browser,)).fetchone()
    conn.execute(
        """INSERT INTO versions (browser_id, version, platform, arch, verified)
           VALUES (?, ?, ?, ?, 1)""",
        (browser_row["id"], version, platform, arch),
    )
    version_row = conn.execute(
        "SELECT id FROM versions WHERE version=? AND browser_id=?",
        (version, browser_row["id"]),
    ).fetchone()
    for kind in ("ssl_log_secret", "key_expansion", "prf", "hkdf"):
        conn.execute(
            """INSERT INTO hook_points
               (version_id, kind, rva, fingerprint, fingerprint_len, fingerprint_prefix20)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (version_row["id"], kind, "0x1234", "abcd", 4, "ab"),
        )
    conn.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestB1Report:
    def test_empty_db(self, tmp_path):
        """Report generates with all zeros, no crashes."""
        from tshunter.agent.reports.b1_report import generate_b1_report
        conn = _make_agent_db(tmp_path)
        out_dir = tmp_path / "reports"

        metrics = generate_b1_report(conn, out_dir)
        conn.close()

        assert isinstance(metrics, dict)
        assert "overall_pass" in metrics
        assert metrics["overall_pass"] is False  # 0 versions = ingestion fails

    def test_with_hook_data(self, tmp_path):
        """With seeded versions+hook_points, hook_coverage.csv has rows."""
        from tshunter.agent.reports.b1_report import generate_b1_report
        conn = _make_agent_db(tmp_path)
        _seed_hook_data(conn)
        out_dir = tmp_path / "reports"

        generate_b1_report(conn, out_dir)
        conn.close()

        csv_path = out_dir / "hook_coverage.csv"
        assert csv_path.exists()
        lines = csv_path.read_text().strip().split("\n")
        # Header + at least 1 data row
        assert len(lines) >= 2
        assert "chrome" in lines[1]

    def test_csv_files_created(self, tmp_path):
        """All 4 CSV files are created in output_dir."""
        from tshunter.agent.reports.b1_report import generate_b1_report
        conn = _make_agent_db(tmp_path)
        out_dir = tmp_path / "reports"

        generate_b1_report(conn, out_dir)
        conn.close()

        for name in ("hook_coverage.csv", "failed_versions.csv",
                      "relocate_success.csv", "verification_summary.csv"):
            assert (out_dir / name).exists(), f"{name} not created"

    def test_markdown_created(self, tmp_path):
        """B1_report.md is created and contains expected sections."""
        from tshunter.agent.reports.b1_report import generate_b1_report
        conn = _make_agent_db(tmp_path)
        out_dir = tmp_path / "reports"

        generate_b1_report(conn, out_dir)
        conn.close()

        md_path = out_dir / "B1_report.md"
        assert md_path.exists()
        content = md_path.read_text()
        assert "TLSHunter B1 Batch Report" in content
        assert "Summary" in content

    def test_metrics_pass_fail(self, tmp_path):
        """Metrics dict has expected keys and correct pass/fail for 4-hook data."""
        from tshunter.agent.reports.b1_report import generate_b1_report
        conn = _make_agent_db(tmp_path)
        _seed_hook_data(conn)
        out_dir = tmp_path / "reports"

        metrics = generate_b1_report(conn, out_dir)
        conn.close()

        assert "four_hook_pct" in metrics
        assert "four_hook_pass" in metrics
        assert "ingestion_pct" in metrics
        assert "analyze_failure_pct" in metrics
        assert "overall_pass" in metrics
        # With 1 version having 4 hooks, four_hook should be 100%
        assert metrics["four_hook_pct"] == 100.0
        assert metrics["four_hook_pass"] == "PASS"
