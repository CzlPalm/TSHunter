"""B1 batch analysis report generator.

Queries the fingerprint database and produces:
- B1_report.md (main Markdown report)
- hook_coverage.csv (per-version hook completeness)
- failed_versions.csv (versions that failed, with error stage)
- relocate_success.csv (relocate OK/PARTIAL/FAIL statistics)
- verification_summary.csv (verification pass/fail rates)
"""

from __future__ import annotations

import csv
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logging import get_logger

logger = get_logger("reports.b1_report")

HOOK_KINDS = {"prf", "key_expansion", "hkdf", "ssl_log_secret"}

# Pass/fail thresholds
THRESHOLDS = {
    "ingestion_success": 0.95,
    "four_hook_completeness": 0.95,
    "analyze_failure_rate": 0.05,
    "verification_success": 0.95,
}


def _safe_query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
    """Execute a query, returning empty list if the table doesn't exist."""
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError as exc:
        logger.debug("query skipped: %s", exc)
        return []


def _pct(num: int, den: int) -> float:
    """Percentage as a float, 0.0 if denominator is zero."""
    return (num / den * 100) if den > 0 else 0.0


def _pass_fail(value: float, threshold: float, *, lower_is_better: bool = False) -> str:
    if lower_is_better:
        return "PASS" if value <= threshold else "FAIL"
    return "PASS" if value >= threshold else "FAIL"


# --- Query helpers ---

def _version_counts_by_browser(conn: sqlite3.Connection) -> Dict[str, int]:
    rows = _safe_query(conn, """
        SELECT b.name, COUNT(*) as cnt
        FROM versions v JOIN browsers b ON v.browser_id = b.id
        GROUP BY b.name
    """)
    return {r["name"]: r["cnt"] for r in rows}


def _total_versions(conn: sqlite3.Connection) -> int:
    row = _safe_query(conn, "SELECT COUNT(*) as cnt FROM versions")
    return row[0]["cnt"] if row else 0


def _total_source_artifacts(conn: sqlite3.Connection) -> int:
    row = _safe_query(conn, "SELECT COUNT(*) as cnt FROM source_artifacts")
    return row[0]["cnt"] if row else 0


def _hook_coverage(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Per-version hook coverage: browser, version, hook_count, kinds."""
    rows = _safe_query(conn, """
        SELECT b.name as browser, v.version, v.platform, v.arch,
               COUNT(h.kind) as hook_count,
               GROUP_CONCAT(h.kind) as kinds
        FROM versions v
        JOIN browsers b ON v.browser_id = b.id
        LEFT JOIN hook_points h ON h.version_id = v.id
        GROUP BY v.id
        ORDER BY b.name, v.version
    """)
    return [dict(r) for r in rows]


def _four_hook_completeness(conn: sqlite3.Connection) -> tuple:
    """Returns (complete_count, total_count)."""
    rows = _safe_query(conn, """
        SELECT v.id, COUNT(h.kind) as cnt
        FROM versions v
        JOIN hook_points h ON h.version_id = v.id
        GROUP BY v.id
    """)
    total = len(rows)
    complete = sum(1 for r in rows if r["cnt"] >= 4)
    return complete, total


def _relocate_stats(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Relocate method distribution from hook_points."""
    rows = _safe_query(conn, """
        SELECT relocation_method, COUNT(*) as cnt
        FROM hook_points
        WHERE relocation_method IS NOT NULL
        GROUP BY relocation_method
        ORDER BY cnt DESC
    """)
    total = sum(r["cnt"] for r in rows)
    result = []
    for r in rows:
        d = dict(r)
        d["percentage"] = _pct(r["cnt"], total)
        result.append(d)
    return result


def _analyzer_run_stats(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Analyzer run status distribution."""
    rows = _safe_query(conn, """
        SELECT status, COUNT(*) as cnt
        FROM analyzer_runs
        GROUP BY status
        ORDER BY cnt DESC
    """)
    total = sum(r["cnt"] for r in rows)
    result = []
    for r in rows:
        d = dict(r)
        d["percentage"] = _pct(r["cnt"], total)
        result.append(d)
    return result


def _batch_job_stats(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Batch job method/status distribution."""
    rows = _safe_query(conn, """
        SELECT method, status, COUNT(*) as cnt
        FROM batch_jobs
        GROUP BY method, status
        ORDER BY method, status
    """)
    return [dict(r) for r in rows]


def _failed_agent_tasks(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Agent tasks that failed, grouped by error_stage."""
    rows = _safe_query(conn, """
        SELECT browser, version, platform, arch, error_stage, error_msg
        FROM agent_tasks
        WHERE status = 'failed'
        ORDER BY browser, version
    """)
    return [dict(r) for r in rows]


def _failed_by_stage(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Failure distribution by error_stage."""
    rows = _safe_query(conn, """
        SELECT error_stage, COUNT(*) as cnt
        FROM agent_tasks
        WHERE status = 'failed' AND error_stage IS NOT NULL
        GROUP BY error_stage
        ORDER BY cnt DESC
    """)
    return [dict(r) for r in rows]


def _needs_manual_review(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Tasks needing manual review."""
    rows = _safe_query(conn, """
        SELECT browser, version, platform, arch, error_stage, error_msg
        FROM agent_tasks
        WHERE status = 'needs_manual_review'
        ORDER BY browser, version
    """)
    return [dict(r) for r in rows]


def _verification_stats(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Verification run status distribution."""
    rows = _safe_query(conn, """
        SELECT status, COUNT(*) as cnt
        FROM verification_runs
        GROUP BY status
        ORDER BY cnt DESC
    """)
    total = sum(r["cnt"] for r in rows)
    result = []
    for r in rows:
        d = dict(r)
        d["percentage"] = _pct(r["cnt"], total)
        result.append(d)
    return result


# --- CSV writers ---

def _write_hook_coverage_csv(path: Path, coverage: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["browser", "version", "platform", "arch", "hook_count", "kinds"])
        for row in coverage:
            w.writerow([
                row["browser"], row["version"], row["platform"], row["arch"],
                row["hook_count"], row["kinds"] or "",
            ])


def _write_failed_versions_csv(path: Path, failed: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["browser", "version", "platform", "arch", "error_stage", "error_msg"])
        for row in failed:
            w.writerow([
                row["browser"], row["version"], row["platform"], row["arch"],
                row["error_stage"] or "", row["error_msg"] or "",
            ])


def _write_relocate_csv(path: Path, stats: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "count", "percentage"])
        for row in stats:
            w.writerow([row["relocation_method"], row["cnt"], f"{row['percentage']:.1f}"])


def _write_verification_csv(path: Path, stats: List[Dict[str, Any]]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["status", "count", "percentage"])
        for row in stats:
            w.writerow([row["status"], row["cnt"], f"{row['percentage']:.1f}"])


# --- Markdown report ---

def _render_report_md(
    metrics: Dict[str, Any],
    coverage: List[Dict[str, Any]],
    failed: List[Dict[str, Any]],
    relocate: List[Dict[str, Any]],
    analyzer_runs: List[Dict[str, Any]],
    verification: List[Dict[str, Any]],
    failure_stages: List[Dict[str, Any]],
    manual_review: List[Dict[str, Any]],
) -> str:
    lines = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append("# TLSHunter B1 Batch Report")
    lines.append(f"\nGenerated: {ts}\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Metric | Value | Threshold | Status |")
    lines.append("|---|---|---|---|")

    m = metrics
    lines.append(
        f"| Total versions | {m['total_versions']} | — | — |"
    )
    lines.append(
        f"| Source artifacts | {m['total_artifacts']} | — | — |"
    )
    lines.append(
        f"| Ingestion success | {m['ingestion_pct']:.1f}% | >= 95% | "
        f"{m['ingestion_pass']} |"
    )
    lines.append(
        f"| 4-hook completeness | {m['four_hook_pct']:.1f}% | >= 95% | "
        f"{m['four_hook_pass']} |"
    )
    lines.append(
        f"| Analyze failure rate | {m['analyze_failure_pct']:.1f}% | <= 5% | "
        f"{m['analyze_failure_pass']} |"
    )
    if m["verification_total"] > 0:
        lines.append(
            f"| Verification success | {m['verification_pct']:.1f}% | >= 95% | "
            f"{m['verification_pass']} |"
        )
    lines.append(
        f"| **Overall** | | | **{m['overall_pass_str']}** |"
    )

    # Hook coverage (top 20)
    lines.append("\n## Hook Coverage\n")
    if coverage:
        lines.append("| Browser | Version | Hooks | Kinds |")
        lines.append("|---|---|---|---|")
        for row in coverage[:50]:
            kinds = row["kinds"] or "none"
            lines.append(
                f"| {row['browser']} | {row['version']} | {row['hook_count']} | {kinds} |"
            )
        if len(coverage) > 50:
            lines.append(f"\n*({len(coverage)} total versions, showing first 50)*")
    else:
        lines.append("No versions found in database.")

    # Failed versions
    lines.append("\n## Failed Versions\n")
    if failed:
        lines.append("| Browser | Version | Error Stage | Error |")
        lines.append("|---|---|---|---|")
        for row in failed[:50]:
            lines.append(
                f"| {row['browser']} | {row['version']} | "
                f"{row['error_stage'] or '—'} | {row['error_msg'] or '—'} |"
            )
        if len(failed) > 50:
            lines.append(f"\n*({len(failed)} total failures, showing first 50)*")
    else:
        lines.append("No failed tasks.")

    # Failure stage distribution
    if failure_stages:
        lines.append("\n### Failure Stage Distribution\n")
        lines.append("| Stage | Count |")
        lines.append("|---|---|")
        for row in failure_stages:
            lines.append(f"| {row['error_stage']} | {row['cnt']} |")

    # Relocate statistics
    lines.append("\n## Relocate Statistics\n")
    if relocate:
        lines.append("| Method | Count | Percentage |")
        lines.append("|---|---|---|")
        for row in relocate:
            lines.append(
                f"| {row['relocation_method']} | {row['cnt']} | {row['percentage']:.1f}% |"
            )
    else:
        lines.append("No relocation data found.")

    # Analyzer run statistics
    if analyzer_runs:
        lines.append("\n## Analyzer Run Statistics\n")
        lines.append("| Status | Count | Percentage |")
        lines.append("|---|---|---|")
        for row in analyzer_runs:
            lines.append(
                f"| {row['status']} | {row['cnt']} | {row['percentage']:.1f}% |"
            )

    # Verification summary
    lines.append("\n## Verification Summary\n")
    if verification:
        lines.append("| Status | Count | Percentage |")
        lines.append("|---|---|---|")
        for row in verification:
            lines.append(
                f"| {row['status']} | {row['cnt']} | {row['percentage']:.1f}% |"
            )
    else:
        lines.append("No verification runs found.")

    # Needs manual review
    lines.append("\n## Needs Manual Review\n")
    if manual_review:
        lines.append("| Browser | Version | Error Stage | Error |")
        lines.append("|---|---|---|---|")
        for row in manual_review[:30]:
            lines.append(
                f"| {row['browser']} | {row['version']} | "
                f"{row['error_stage'] or '—'} | {row['error_msg'] or '—'} |"
            )
        if len(manual_review) > 30:
            lines.append(f"\n*({len(manual_review)} total, showing first 30)*")
    else:
        lines.append("No tasks require manual review.")

    return "\n".join(lines) + "\n"


# --- Main entry point ---

def generate_b1_report(conn: sqlite3.Connection, output_dir: Path) -> Dict[str, Any]:
    """Generate all B1 report files. Returns metrics dict.

    Args:
        conn: Database connection (agent DB).
        output_dir: Directory to write report files into.

    Returns:
        Dict with computed metrics and pass/fail status.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Gather data
    total_versions = _total_versions(conn)
    total_artifacts = _total_source_artifacts(conn)
    coverage = _hook_coverage(conn)
    complete, hook_total = _four_hook_completeness(conn)
    relocate = _relocate_stats(conn)
    analyzer_runs = _analyzer_run_stats(conn)
    failed = _failed_agent_tasks(conn)
    failure_stages = _failed_by_stage(conn)
    manual_review = _needs_manual_review(conn)
    verification = _verification_stats(conn)

    # Compute metrics
    ingestion_pct = _pct(total_versions, total_artifacts)
    four_hook_pct = _pct(complete, hook_total)

    # Analyze failure rate: FAILED_* from analyzer_runs
    analyzer_total = sum(r["cnt"] for r in analyzer_runs)
    analyzer_failed = sum(
        r["cnt"] for r in analyzer_runs
        if r["status"] and r["status"].startswith("FAILED")
    )
    analyze_failure_pct = _pct(analyzer_failed, analyzer_total)

    # Verification success rate
    verification_total = sum(r["cnt"] for r in verification)
    verification_success = sum(
        r["cnt"] for r in verification if r["status"] == "SUCCESS"
    )
    verification_pct = _pct(verification_success, verification_total)

    # Pass/fail
    ingestion_pass = _pass_fail(ingestion_pct, THRESHOLDS["ingestion_success"] * 100)
    four_hook_pass = _pass_fail(four_hook_pct, THRESHOLDS["four_hook_completeness"] * 100)
    analyze_failure_pass = _pass_fail(
        analyze_failure_pct, THRESHOLDS["analyze_failure_rate"] * 100, lower_is_better=True
    )
    verification_pass = _pass_fail(verification_pct, THRESHOLDS["verification_success"] * 100)

    overall = all([
        ingestion_pass == "PASS",
        four_hook_pass == "PASS",
        analyze_failure_pass == "PASS",
    ])
    # Only check verification if there are verification runs
    if verification_total > 0:
        overall = overall and (verification_pass == "PASS")

    metrics = {
        "total_versions": total_versions,
        "total_artifacts": total_artifacts,
        "ingestion_pct": ingestion_pct,
        "ingestion_pass": ingestion_pass,
        "four_hook_pct": four_hook_pct,
        "four_hook_pass": four_hook_pass,
        "analyze_failure_pct": analyze_failure_pct,
        "analyze_failure_pass": analyze_failure_pass,
        "verification_total": verification_total,
        "verification_pct": verification_pct,
        "verification_pass": verification_pass,
        "overall_pass": overall,
        "overall_pass_str": "PASS" if overall else "FAIL",
    }

    # Write files
    md_path = output_dir / "B1_report.md"
    md_content = _render_report_md(
        metrics, coverage, failed, relocate, analyzer_runs,
        verification, failure_stages, manual_review,
    )
    md_path.write_text(md_content, encoding="utf-8")
    logger.info("wrote %s", md_path)

    _write_hook_coverage_csv(output_dir / "hook_coverage.csv", coverage)
    logger.info("wrote %s", output_dir / "hook_coverage.csv")

    _write_failed_versions_csv(output_dir / "failed_versions.csv", failed)
    logger.info("wrote %s", output_dir / "failed_versions.csv")

    _write_relocate_csv(output_dir / "relocate_success.csv", relocate)
    logger.info("wrote %s", output_dir / "relocate_success.csv")

    _write_verification_csv(output_dir / "verification_summary.csv", verification)
    logger.info("wrote %s", output_dir / "verification_summary.csv")

    return metrics
