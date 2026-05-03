"""Agent CLI: subcommand entry points for tshunter agent.

Provides: db, source, task, worker, report subcommands.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .config import AgentConfig, load_config


def _cmd_db_migrate(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Apply agent migrations to the database."""
    from ..ingest import apply_schema, db_connect, DEFAULT_DB, DEFAULT_SCHEMA

    db_path = Path(args.db) if args.db else DEFAULT_DB
    conn = db_connect(db_path)
    apply_schema(conn, DEFAULT_SCHEMA)
    conn.commit()
    conn.close()
    print(f"Migrations applied to {db_path}")
    return 0


def _cmd_db_status(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Show database status: table row counts."""
    from .db import connect
    from .db.artifact_store import count_artifacts
    from .db.task_store import count_tasks

    conn = connect()
    try:
        n_artifacts = count_artifacts(conn)
        n_tasks = count_tasks(conn)
        print(f"source_artifacts: {n_artifacts}")
        print(f"agent_tasks:      {n_tasks}")

        for status in ("pending", "downloading", "downloaded", "queued_analyze",
                        "analyzing", "ingesting", "verified", "failed",
                        "needs_manual_review", "skipped"):
            n = count_tasks(conn, status=status)
            if n:
                print(f"  {status}: {n}")
    finally:
        conn.close()
    return 0


def _build_db_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("db", help="Database operations")
    db_sub = p.add_subparsers(dest="db_cmd", required=True)

    migrate_p = db_sub.add_parser("migrate", help="Apply agent migrations")
    migrate_p.add_argument("--db", help="Database path (default: data/fingerprints.db)")
    migrate_p.set_defaults(func=_cmd_db_migrate)

    status_p = db_sub.add_parser("status", help="Show database status")
    status_p.add_argument("--db", help="Database path")
    status_p.set_defaults(func=_cmd_db_status)


# --- source subcommands ---

def _cmd_source_poll(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Poll data sources for new browser versions."""
    from .db import connect
    from .db.artifact_store import count_artifacts

    browser = args.browser
    conn = connect()
    try:
        existing = count_artifacts(conn, browser=browser if browser != "all" else None)
        print(f"Existing artifacts: {existing}")
        print(f"Polling source: {browser}")

        if browser in ("chrome", "all"):
            _poll_chrome_cft(conn, cfg)
        if browser in ("edge", "all"):
            _poll_edge(conn, cfg)
        if browser in ("firefox", "all"):
            _poll_firefox(conn, cfg)

        new_count = count_artifacts(conn, browser=browser if browser != "all" else None)
        print(f"Artifacts after poll: {new_count} (new: {new_count - existing})")
    finally:
        conn.close()
    return 0


def _poll_chrome_cft(conn, cfg: AgentConfig) -> None:
    """Poll Chrome CfT for new versions, upsert artifacts and create tasks."""
    from .db.artifact_store import SourceArtifact, upsert_artifact
    from .db.task_store import create_task
    from .sources.chrome_cft import ChromeCfTSource

    src_cfg = cfg.source_config("chrome_cft")
    if not src_cfg.get("enabled", True):
        print("  chrome_cft: disabled, skipping")
        return

    source = ChromeCfTSource(cfg)
    try:
        artifacts = source.poll()
    except Exception as exc:
        print(f"  chrome_cft: poll failed: {exc}")
        return

    new_count = 0
    for art in artifacts:
        # Upsert source_artifact (dedup on sha256, but we don't have it yet from poll)
        # Use version+platform as dedup key for poll-only artifacts
        existing = conn.execute(
            "SELECT id FROM source_artifacts WHERE browser=? AND version=? AND platform=? AND arch=?",
            (art.browser, art.version, art.platform, art.arch),
        ).fetchone()
        if existing:
            continue

        sa = SourceArtifact(
            browser=art.browser,
            version=art.version,
            channel=art.channel,
            platform=art.platform,
            arch=art.arch,
            source=source.name,
            package_url=art.download_url,
            source_metadata_json=json.dumps({"milestone": art.milestone}),
        )
        artifact_id = upsert_artifact(conn, sa)

        create_task(
            conn,
            browser=art.browser,
            version=art.version,
            platform=art.platform,
            arch=art.arch,
            channel=art.channel,
            source=source.name,
            source_artifact_id=artifact_id,
            task_type="analyze_candidate",
        )
        new_count += 1

    conn.commit()
    print(f"  chrome_cft: {len(artifacts)} versions found, {new_count} new")


def _poll_edge(conn, cfg: AgentConfig) -> None:
    """Poll Edge deb repo for new versions, upsert artifacts and create tasks."""
    from .db.artifact_store import SourceArtifact, upsert_artifact
    from .db.task_store import create_task
    from .sources.edge import EdgeDebRepoSource

    src_cfg = cfg.source_config("edge")
    if not src_cfg.get("enabled", True):
        print("  edge: disabled, skipping")
        return

    source = EdgeDebRepoSource(cfg)
    try:
        artifacts = source.poll()
    except Exception as exc:
        print(f"  edge: poll failed: {exc}")
        return

    new_count = 0
    for art in artifacts:
        existing = conn.execute(
            "SELECT id FROM source_artifacts WHERE browser=? AND version=? AND platform=? AND arch=? AND channel=?",
            (art.browser, art.version, art.platform, art.arch, art.channel),
        ).fetchone()
        if existing:
            continue

        sa = SourceArtifact(
            browser=art.browser,
            version=art.version,
            channel=art.channel,
            platform=art.platform,
            arch=art.arch,
            source=source.name,
            package_url=art.download_url,
            source_metadata_json=json.dumps(art.source_metadata),
        )
        artifact_id = upsert_artifact(conn, sa)

        create_task(
            conn,
            browser=art.browser,
            version=art.version,
            platform=art.platform,
            arch=art.arch,
            channel=art.channel,
            source=source.name,
            source_artifact_id=artifact_id,
            task_type="analyze_candidate",
        )
        new_count += 1

    conn.commit()
    print(f"  edge: {len(artifacts)} versions found, {new_count} new")


def _poll_firefox(conn, cfg: AgentConfig) -> None:
    """Poll Firefox product-details for new versions, upsert artifacts and create tasks."""
    from .db.artifact_store import SourceArtifact, upsert_artifact
    from .db.task_store import create_task
    from .sources.firefox import FirefoxReleaseSource

    src_cfg = cfg.source_config("firefox")
    if not src_cfg.get("enabled", True):
        print("  firefox: disabled, skipping")
        return

    source = FirefoxReleaseSource(cfg)
    try:
        artifacts = source.poll()
    except Exception as exc:
        print(f"  firefox: poll failed: {exc}")
        return

    new_count = 0
    for art in artifacts:
        existing = conn.execute(
            "SELECT id FROM source_artifacts WHERE browser=? AND version=? AND platform=? AND arch=? AND channel=?",
            (art.browser, art.version, art.platform, art.arch, art.channel),
        ).fetchone()
        if existing:
            continue

        sa = SourceArtifact(
            browser=art.browser,
            version=art.version,
            channel=art.channel,
            platform=art.platform,
            arch=art.arch,
            source=source.name,
            package_url=art.download_url,
            source_metadata_json=json.dumps(art.source_metadata),
        )
        artifact_id = upsert_artifact(conn, sa)

        create_task(
            conn,
            browser=art.browser,
            version=art.version,
            platform=art.platform,
            arch=art.arch,
            channel=art.channel,
            source=source.name,
            source_artifact_id=artifact_id,
            task_type="analyze_candidate",
        )
        new_count += 1

    conn.commit()
    print(f"  firefox: {len(artifacts)} versions found, {new_count} new")


def _cmd_source_download(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Download a specific browser version."""
    from .db import connect
    from .db.artifact_store import SourceArtifact, find_artifact, upsert_artifact
    from .sources.chrome_cft import ChromeCfTSource
    from .sources.edge import EdgeDebRepoSource
    from .sources.firefox import FirefoxReleaseSource

    source_map = {
        "chrome": lambda cfg: (ChromeCfTSource(cfg), cfg.download_dir / "chrome"),
        "edge": lambda cfg: (EdgeDebRepoSource(cfg), cfg.download_dir / "edge"),
        "firefox": lambda cfg: (FirefoxReleaseSource(cfg), cfg.download_dir / "firefox"),
    }

    factory = source_map.get(args.browser)
    if not factory:
        print(f"Download {args.browser}: not yet implemented")
        return 1

    conn = connect()
    try:
        source, output_dir = factory(cfg)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Poll to find the version
        print(f"Looking up {args.browser} {args.version}...")
        artifacts = source.poll()
        match = None
        for art in artifacts:
            if art.version == args.version:
                match = art
                break

        if not match:
            print(f"Version {args.version} not found in {source.name} API", file=sys.stderr)
            return 1

        # Check if already downloaded
        existing = find_artifact(
            conn, args.browser, args.version, match.platform, match.arch,
            channel=match.channel,
        )
        if existing and existing.binary_path and Path(existing.binary_path).exists():
            print(f"Already downloaded: {existing.binary_path}")
            return 0

        # Download
        print(f"Downloading {args.version}...")
        match = source.download(match, output_dir)

        # Upsert artifact with full info
        sa = SourceArtifact(
            browser=match.browser,
            version=match.version,
            channel=match.channel,
            platform=match.platform,
            arch=match.arch,
            source=source.name,
            package_url=match.download_url,
            package_path=str(match.package_path) if match.package_path else None,
            binary_path=str(match.binary_path) if match.binary_path else None,
            binary_sha256=match.binary_sha256,
            source_metadata_json=json.dumps({
                "milestone": match.milestone,
                "package_sha256": match.package_sha256,
            }),
        )
        upsert_artifact(conn, sa)
        conn.commit()
        print(f"OK: {match.binary_path}")
        return 0
    except Exception as exc:
        print(f"Download failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


def _build_source_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("source", help="Data source operations")
    src_sub = p.add_subparsers(dest="source_cmd", required=True)

    poll_p = src_sub.add_parser("poll", help="Poll sources for new versions")
    poll_p.add_argument(
        "--browser", required=True,
        choices=["chrome", "edge", "firefox", "all"],
        help="Browser to poll",
    )
    poll_p.set_defaults(func=_cmd_source_poll)

    dl_p = src_sub.add_parser("download", help="Download a specific version")
    dl_p.add_argument("--browser", required=True, choices=["chrome", "edge", "firefox"])
    dl_p.add_argument("--version", required=True, help="Version to download")
    dl_p.set_defaults(func=_cmd_source_download)


# --- task subcommands ---

def _cmd_task_list(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """List agent tasks."""
    from .db import connect
    from .db.task_store import list_tasks

    conn = connect()
    try:
        tasks = list_tasks(
            conn,
            status=args.status,
            browser=args.browser,
            limit=args.limit,
        )
        if not tasks:
            print("No tasks found.")
            return 0

        # Header
        print(f"{'task_id':<18} {'browser':<10} {'version':<22} {'status':<20} {'priority':<8} {'created_at'}")
        print("-" * 100)
        for t in tasks:
            print(
                f"{t.task_id:<18} {t.browser:<10} {t.version:<22} "
                f"{t.status:<20} {t.priority:<8} {t.created_at}"
            )
    finally:
        conn.close()
    return 0


def _cmd_task_show(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Show details of a specific task."""
    from .db import connect
    from .db.task_store import get_task_by_id_field

    conn = connect()
    try:
        task = get_task_by_id_field(conn, args.task_id)
        if not task:
            print(f"Task not found: {args.task_id}", file=sys.stderr)
            return 1
        for field in (
            "task_id", "browser", "version", "channel", "platform", "arch",
            "source", "source_artifact_id", "binary_path", "binary_sha256",
            "task_type", "status", "priority",
            "created_at", "started_at", "updated_at", "finished_at",
            "error_stage", "error_msg", "retry_count",
        ):
            val = getattr(task, field, None)
            if val is not None:
                print(f"  {field}: {val}")
    finally:
        conn.close()
    return 0


def _cmd_task_retry(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Retry a failed task."""
    from .db import connect
    from .db.task_store import retry_task, InvalidTransition

    conn = connect()
    try:
        try:
            task = retry_task(conn, args.task_id)
            conn.commit()
            print(f"Task {task.task_id} reset to pending (retry_count={task.retry_count})")
        except InvalidTransition as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    finally:
        conn.close()
    return 0


def _cmd_task_reset(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Reset a task to a specific status."""
    from .db import connect
    from .db.task_store import transition, InvalidTransition

    conn = connect()
    try:
        try:
            task = transition(conn, args.task_id, args.status)
            conn.commit()
            print(f"Task {task.task_id} reset to {task.status}")
        except InvalidTransition as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    finally:
        conn.close()
    return 0


def _build_task_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("task", help="Task management")
    task_sub = p.add_subparsers(dest="task_cmd", required=True)

    list_p = task_sub.add_parser("list", help="List tasks")
    list_p.add_argument("--status", help="Filter by status")
    list_p.add_argument("--browser", help="Filter by browser")
    list_p.add_argument("--limit", type=int, default=50, help="Max results")
    list_p.set_defaults(func=_cmd_task_list)

    show_p = task_sub.add_parser("show", help="Show task details")
    show_p.add_argument("task_id", help="Task ID")
    show_p.set_defaults(func=_cmd_task_show)

    retry_p = task_sub.add_parser("retry", help="Retry a failed task")
    retry_p.add_argument("task_id", help="Task ID")
    retry_p.set_defaults(func=_cmd_task_retry)

    reset_p = task_sub.add_parser("reset", help="Reset task status")
    reset_p.add_argument("task_id", help="Task ID")
    reset_p.add_argument("--status", required=True, choices=sorted({
        "pending", "downloading", "downloaded", "queued_analyze",
        "relocating", "analyzing", "ingesting", "queued_verify",
        "verifying", "verified", "failed", "needs_manual_review", "skipped",
    }))
    reset_p.set_defaults(func=_cmd_task_reset)


# --- worker subcommands ---

def _cmd_worker_download(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Run download worker: claim pending tasks and download binaries."""
    from .workers.download import DownloadWorker

    worker = DownloadWorker(cfg)
    count = worker.run(once=args.once)
    print(f"Download worker: processed {count} task(s)")
    return 0


def _cmd_worker_analyze(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Run analyze worker: claim downloaded tasks and run analysis."""
    from .workers.analyze import AnalyzeWorker

    worker = AnalyzeWorker(cfg, dry_run=args.dry_run)
    count = worker.run(once=args.once)
    print(f"Analyze worker: processed {count} task(s) (dry_run={args.dry_run})")
    return 0


def _cmd_worker_verify(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Run verify worker: claim queued_verify tasks and verify results."""
    from .workers.verify import VerifyWorker

    worker = VerifyWorker(cfg)
    count = worker.run(once=args.once)
    print(f"Verify worker: processed {count} task(s)")
    return 0


def _build_worker_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("worker", help="Worker operations")
    worker_sub = p.add_subparsers(dest="worker_cmd", required=True)

    dl_p = worker_sub.add_parser("download", help="Run download worker")
    dl_p.add_argument("--once", action="store_true", help="Process one task then exit")
    dl_p.set_defaults(func=_cmd_worker_download)

    analyze_p = worker_sub.add_parser("analyze", help="Run analyze worker")
    analyze_p.add_argument("--dry-run", action="store_true", help="Dry-run mode")
    analyze_p.add_argument("--once", action="store_true", help="Process one task then exit")
    analyze_p.set_defaults(func=_cmd_worker_analyze)

    verify_p = worker_sub.add_parser("verify", help="Run verify worker")
    verify_p.add_argument("--once", action="store_true", help="Process one task then exit")
    verify_p.set_defaults(func=_cmd_worker_verify)


# --- report subcommands ---

def _cmd_report_b1(args: argparse.Namespace, cfg: AgentConfig) -> int:
    """Generate B1 batch analysis report."""
    from .db import connect
    from .reports.b1_report import generate_b1_report

    out_path = Path(args.out)
    output_dir = out_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    conn = connect(Path(args.db) if args.db else None)
    try:
        metrics = generate_b1_report(conn, output_dir)
    finally:
        conn.close()

    print(f"B1 report: {out_path}")
    print(f"  Versions:           {metrics['total_versions']}")
    print(f"  Ingestion success:  {metrics['ingestion_pct']:.1f}% ({metrics['ingestion_pass']})")
    print(f"  4-hook completeness:{metrics['four_hook_pct']:.1f}% ({metrics['four_hook_pass']})")
    print(f"  Analyze failure:    {metrics['analyze_failure_pct']:.1f}% ({metrics['analyze_failure_pass']})")
    if metrics["verification_total"] > 0:
        print(f"  Verification:       {metrics['verification_pct']:.1f}% ({metrics['verification_pass']})")
    print(f"  Overall:            {metrics['overall_pass_str']}")
    return 0


def _build_report_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("report", help="Report generation")
    report_sub = p.add_subparsers(dest="report_cmd", required=True)

    b1_p = report_sub.add_parser("b1", help="Generate B1 batch analysis report")
    b1_p.add_argument("--db", help="Database path")
    b1_p.add_argument("--out", default="reports/B1_report.md", help="Output path")
    b1_p.set_defaults(func=_cmd_report_b1)


# --- main entry ---

def build_agent_parser() -> argparse.ArgumentParser:
    """Build the agent argument parser."""
    parser = argparse.ArgumentParser(
        prog="tshunter-agent",
        description="TSHunter Agent: browser version monitoring and task orchestration",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to agent.yaml config file",
    )

    sub = parser.add_subparsers(dest="cmd", required=True, metavar="command")
    _build_db_parser(sub)
    _build_source_parser(sub)
    _build_task_parser(sub)
    _build_worker_parser(sub)
    _build_report_parser(sub)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Agent CLI entry point."""
    parser = build_agent_parser()
    args = parser.parse_args(argv)
    cfg = load_config(args.config)
    return args.func(args, cfg)


if __name__ == "__main__":
    raise SystemExit(main())
