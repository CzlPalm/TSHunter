"""Phase B1: batch analysis mode.

Iterates a set of versions, resolving each via:
  1. DB exact hit  (method='db_hit')
  2. Relocate scan → write JSON to data/relocate/ (review artifact, not ingested)
  3. Full Ghidra analyze → ingest to DB  (method='analyze')

Relocate results are saved as JSON for later review and never written to the
fingerprint DB directly.  Only full Ghidra analysis produces DB rows.

State is persisted in the `batch_jobs` table so runs can be resumed.

Logging:
  Every run writes a log file to ``results/<timestamp>-batch.log`` which can be
  tailed with ``monitor_analysis.sh`` or ``tail -f``.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sqlite3
import sys
import tempfile
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "fingerprints.db"
DEFAULT_BINARIES_DIR = ROOT / "binaries" / "Chrome"
SCHEMA_SQL = ROOT / "data" / "schema.sql"

logger = logging.getLogger("tshunter.batch")


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(run_id: str) -> Path:
    """Configure logging to both console and a results/ log file.

    Returns the path to the log file.
    """
    results_dir = ROOT / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime('%Y%m%d-%H%M%S')
    log_path = results_dir / f"{ts}-batch.log"

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler — full detail
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    # Console handler — info and above
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    root = logging.getLogger("tshunter.batch")
    root.setLevel(logging.DEBUG)
    root.addHandler(fh)
    root.addHandler(ch)

    return log_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_run_id() -> str:
    return time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]


def _db_connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _apply_schema(conn: sqlite3.Connection) -> None:
    """Apply schema + all migrations idempotently."""
    from tshunter import ingest as ingest_mod
    ingest_mod.apply_schema(conn, SCHEMA_SQL)


def _ensure_batch_table(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS batch_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            browser TEXT NOT NULL,
            version TEXT NOT NULL,
            platform TEXT NOT NULL,
            arch TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN (
                'pending','downloading','analyzing','ingesting','done','failed','skipped')),
            started_at TEXT,
            finished_at TEXT,
            error_msg TEXT,
            binary_sha256 TEXT,
            analyzer_runs_id INTEGER,
            method TEXT,
            method_duration_sec REAL,
            relocate_max_outlier_delta INTEGER,
            FOREIGN KEY (analyzer_runs_id) REFERENCES analyzer_runs(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_batch_run ON batch_jobs(run_id, status);
        CREATE INDEX IF NOT EXISTS idx_batch_version ON batch_jobs(browser, version, platform, arch);
    """)
    _ensure_column(conn, "batch_jobs", "method_duration_sec",
                   "ALTER TABLE batch_jobs ADD COLUMN method_duration_sec REAL")
    _ensure_column(conn, "batch_jobs", "relocate_max_outlier_delta",
                   "ALTER TABLE batch_jobs ADD COLUMN relocate_max_outlier_delta INTEGER")
    conn.commit()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    if not any(row[1] == column for row in rows):
        conn.execute(ddl)


def _query_job(conn: sqlite3.Connection, run_id: str, browser: str,
               version: str, platform: str, arch: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM batch_jobs WHERE run_id=? AND browser=? AND version=? AND platform=? AND arch=?",
        (run_id, browser, version, platform, arch),
    ).fetchone()


def _insert_job(conn: sqlite3.Connection, run_id: str, browser: str,
                version: str, platform: str, arch: str) -> int:
    cur = conn.execute(
        """INSERT INTO batch_jobs(run_id, browser, version, platform, arch, status)
           VALUES (?, ?, ?, ?, ?, 'pending')""",
        (run_id, browser, version, platform, arch),
    )
    conn.commit()
    return cur.lastrowid


def _update_job(conn: sqlite3.Connection, job_id: int, **fields) -> None:
    if not fields:
        return
    sets = ", ".join(f"{k}=?" for k in fields)
    conn.execute(f"UPDATE batch_jobs SET {sets} WHERE id=?", (*fields.values(), job_id))
    conn.commit()


def _version_in_db(db_path: Path, browser: str, version: str,
                   platform: str, arch: str) -> bool:
    """Return True if this version already has hook_points in DB."""
    conn = _db_connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT v.id FROM versions v
            JOIN browsers b ON b.id = v.browser_id
            WHERE b.name=? AND v.version=? AND v.platform=? AND v.arch=?
            """,
            (browser, version, platform, arch),
        ).fetchone()
        if not row:
            return False
        hooks = conn.execute(
            "SELECT COUNT(*) FROM hook_points WHERE version_id=?", (row[0],)
        ).fetchone()[0]
        return hooks > 0
    finally:
        conn.close()


def _get_latest_analyzer_run_id(db_path: Path, browser: str, version: str,
                                 platform: str, arch: str) -> Optional[int]:
    conn = _db_connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT ar.id FROM analyzer_runs ar
            JOIN versions v ON v.id = ar.version_id
            JOIN browsers b ON b.id = v.browser_id
            WHERE b.name=? AND v.version=? AND v.platform=? AND v.arch=?
            ORDER BY ar.id DESC LIMIT 1
            """,
            (browser, version, platform, arch),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _find_verified_baseline(db_path: Path, browser: str, version: str,
                            platform: str, arch: str) -> Optional[dict]:
    major_minor = '.'.join(version.split('.')[:2])
    conn = _db_connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT v.id, v.version, v.platform, v.arch, b.name AS browser
            FROM versions v
            JOIN browsers b ON b.id = v.browser_id
            WHERE b.name=? AND v.version LIKE ? AND v.version<>?
              AND v.platform=? AND v.arch=? AND v.verified=1
            ORDER BY v.version DESC
            LIMIT 1
            """,
            (browser, f"{major_minor}.%", version, platform, arch),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _write_relocate_json(db_path: Path, args: argparse.Namespace, version: str,
                         binary_path: Path) -> Optional[Path]:
    """Run relocate scan and save the result as JSON to data/relocate/.

    Returns the path to the saved JSON, or None if no baseline was found.
    This never writes to the fingerprint DB.
    """
    baseline = _find_verified_baseline(
        db_path, args.browser, version, args.platform, args.arch,
    )
    if not baseline:
        logger.debug("  [relocate] %s: no verified baseline found, skipping relocate", version)
        return None

    from tshunter import relocate as relocate_mod

    conn = _db_connect(db_path)
    try:
        hooks = relocate_mod.load_hooks_from_db(
            conn,
            baseline['browser'],
            baseline['version'],
            baseline['platform'],
            baseline['arch'],
        )
    finally:
        conn.close()
    if not hooks:
        logger.debug("  [relocate] %s: baseline has no hooks, skipping", version)
        return None

    logger.info("  [relocate] %s: scanning against baseline %s ...", version, baseline['version'])
    payload = relocate_mod.scan(
        binary_path,
        hooks,
        baseline['browser'],
        baseline['version'],
        baseline['platform'],
        baseline['arch'],
    )
    payload['target_version'] = {
        'browser': args.browser,
        'version': version,
        'platform': args.platform,
        'arch': args.arch,
    }
    out_dir = ROOT / 'data' / 'relocate'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"relocate_{args.browser}_{version}_from_{baseline['version']}.json"
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding='utf-8')
    logger.info("  [relocate] %s: verdict=%s → %s", version, payload.get('verdict'), out_path.name)
    return out_path


def _cleanup_binary_dir(binary_path: Path) -> None:
    version_dir = binary_path.parent
    metadata_path = version_dir / 'metadata.json'
    metadata_bytes = metadata_path.read_bytes() if metadata_path.is_file() else None
    shutil.rmtree(version_dir)
    version_dir.mkdir(parents=True, exist_ok=True)
    if metadata_bytes is not None:
        metadata_path.write_bytes(metadata_bytes)


# ---------------------------------------------------------------------------
# Version enumeration
# ---------------------------------------------------------------------------

def _enumerate_versions(args: argparse.Namespace) -> List[dict]:
    """Return list of dicts with keys: version, binary_path."""
    versions: List[dict] = []

    binaries_dir = Path(args.binaries_dir) if args.binaries_dir else DEFAULT_BINARIES_DIR

    # --versions-file: read explicit version list, look up binaries in binaries_dir
    versions_file = getattr(args, 'versions_file', None)
    if versions_file:
        vf_path = Path(versions_file)
        if not vf_path.is_file():
            sys.exit(f'[tshunter batch] ERROR: --versions-file {versions_file} not found')
        explicit_versions: List[str] = []
        for line in vf_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                explicit_versions.append(line)
        for version in explicit_versions:
            binary = binaries_dir / version / 'chrome'
            if binary.is_file():
                versions.append({'version': version, 'binary_path': binary})
            else:
                logger.warning("binary not found for %s at %s", version, binary)
        return versions

    if binaries_dir.is_dir():
        milestone_filter: Optional[set] = None
        if args.milestones:
            milestone_filter = _parse_milestones(args.milestones)

        for subdir in sorted(binaries_dir.iterdir()):
            if not subdir.is_dir():
                continue
            version = subdir.name
            binary = subdir / "chrome"
            if not binary.is_file():
                continue
            if milestone_filter is not None:
                major = version.split('.')[0]
                if major not in milestone_filter:
                    continue
            versions.append({"version": version, "binary_path": binary})
        return versions

    # No binaries dir — require --milestones and download
    if not args.milestones:
        sys.exit("[tshunter batch] ERROR: neither --binaries-dir nor --milestones provided")

    milestones = _parse_milestones(args.milestones)
    artifacts_dir = ROOT / "artifacts" / "chrome"
    _download_milestones(milestones, artifacts_dir, args)

    for subdir in sorted(artifacts_dir.iterdir()):
        if not subdir.is_dir():
            continue
        version = subdir.name
        binary = subdir / "chrome"
        if not binary.is_file():
            continue
        major = version.split('.')[0]
        if major not in milestones:
            continue
        versions.append({"version": version, "binary_path": binary})

    return versions


def _parse_milestones(spec: str) -> set:
    """Parse '142,143,149' or '142-149' into a set of major-number strings."""
    result = set()
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = part.split('-', 1)
            for m in range(int(lo), int(hi) + 1):
                result.add(str(m))
        else:
            result.add(part)
    return result


def _download_milestones(milestones: set, output_dir: Path, args: argparse.Namespace) -> None:
    import subprocess
    milestone_list = ','.join(sorted(milestones))
    cmd = [
        sys.executable, '-m', 'tshunter.cli', 'download', '--',
        '--source', getattr(args, 'source', 'cft-latest'),
        '--milestones', milestone_list,
        '--output-dir', str(output_dir),
    ]
    logger.info("downloading milestones %s → %s", milestone_list, output_dir)
    subprocess.run(cmd, check=True)


# ---------------------------------------------------------------------------
# Per-version processing
# ---------------------------------------------------------------------------

def _process_version(conn: sqlite3.Connection, job_id: int,
                     args: argparse.Namespace, version: str,
                     binary_path: Path) -> str:
    """Process one version. Returns method string. Raises on unrecoverable error.

    Flow:
      1. DB hit → return immediately
      2. Relocate scan → save JSON to data/relocate/ (never ingested)
      3. Full Ghidra analyze → ingest to DB
    """
    db_path = Path(args.db)

    # Step 1: DB exact hit
    if _version_in_db(db_path, args.browser, version, args.platform, args.arch):
        return 'db_hit'

    # Step 2: Relocate scan → save JSON for review (not ingested to DB)
    _write_relocate_json(db_path, args, version, binary_path)

    # Step 3: Full analyze → ingest to DB
    _update_job(conn, job_id, status='analyzing')

    from tshunter import analyze as analyze_mod, ingest as ingest_mod

    with tempfile.TemporaryDirectory(prefix='tshunter_batch_') as tmpdir:
        out_json = Path(tmpdir) / f"{version}.json"
        rc = analyze_mod.main([
            '--binary', str(binary_path),
            '--output', str(out_json),
            '--browser', args.browser,
            '--version', version,
            '--platform', args.platform,
            '--arch', args.arch,
            '--tls-lib', getattr(args, 'tls_lib', 'boringssl'),
        ])
        if rc != 0 or not out_json.is_file():
            raise RuntimeError(f"analyze exited {rc}")

        _update_job(conn, job_id, status='ingesting')
        ingest_args = [
            '--json', str(out_json),
            '--db', str(db_path),
            '--upsert',
        ]
        if getattr(args, 'allow_empty', False):
            ingest_args.append('--allow-empty')
        rc2 = ingest_mod.main(ingest_args)
        if rc2 != 0:
            raise RuntimeError(f"ingest exited {rc2}")

    # Mark as verified=1 so it becomes a relocate baseline for same-milestone versions
    conn_update = _db_connect(db_path)
    try:
        conn_update.execute(
            """UPDATE versions SET verified=1
               WHERE browser_id=(SELECT id FROM browsers WHERE name=?)
               AND version=? AND platform=? AND arch=?""",
            (args.browser, version, args.platform, args.arch),
        )
        conn_update.commit()
    finally:
        conn_update.close()

    return 'analyze'


# ---------------------------------------------------------------------------
# Main batch loop
# ---------------------------------------------------------------------------

def run_batch(args: argparse.Namespace) -> int:
    db_path = Path(args.db)
    conn = _db_connect(db_path)
    _apply_schema(conn)
    _ensure_batch_table(conn)

    resume = getattr(args, 'resume', None)
    run_id = resume if resume else _new_run_id()
    dry_run = getattr(args, 'dry_run', False)

    log_path = _setup_logging(run_id)

    versions = _enumerate_versions(args)
    if not versions:
        logger.error("no versions found — check --binaries-dir or --milestones")
        return 1

    logger.info("run_id=%s  versions=%d  dry_run=%s  log=%s",
                run_id, len(versions), dry_run, log_path)
    logger.info("db=%s", db_path)

    total = len(versions)
    done_count = skipped_count = failed_count = 0
    failures: List[tuple] = []

    for entry in versions:
        version = entry['version']
        binary_path: Path = entry['binary_path']

        # Resume: check existing record
        existing = _query_job(conn, run_id, args.browser, version, args.platform, args.arch)
        if existing:
            if resume and existing['status'] == 'done':
                logger.info("  [skip] %s (already done)", version)
                skipped_count += 1
                continue
            job_id = existing['id']
            _update_job(conn, job_id, status='pending', error_msg=None,
                        started_at=_now_utc(), finished_at=None)
        else:
            job_id = _insert_job(conn, run_id, args.browser, version,
                                 args.platform, args.arch)

        if dry_run:
            _update_job(conn, job_id, status='skipped', method='dry_run',
                        started_at=_now_utc(), finished_at=_now_utc())
            logger.info("  [dry]  %s", version)
            skipped_count += 1
            continue

        _update_job(conn, job_id, status='analyzing', started_at=_now_utc())
        started_monotonic = time.monotonic()
        try:
            method = _process_version(conn, job_id, args, version, binary_path)
            duration = time.monotonic() - started_monotonic
            analyzer_runs_id = _get_latest_analyzer_run_id(
                db_path, args.browser, version, args.platform, args.arch
            ) if method == 'analyze' else None
            kw = dict(
                status='done',
                finished_at=_now_utc(),
                method=method,
                method_duration_sec=round(duration, 3),
            )
            if analyzer_runs_id:
                kw['analyzer_runs_id'] = analyzer_runs_id
            _update_job(conn, job_id, **kw)
            if getattr(args, 'cleanup_binary', False):
                _cleanup_binary_dir(binary_path)
            logger.info("  [done] %s  method=%s  duration=%.1fs", version, method, duration)
            done_count += 1
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            _update_job(conn, job_id, status='failed', finished_at=_now_utc(), error_msg=msg)
            logger.error("  [fail] %s  %s", version, msg)
            logger.debug(traceback.format_exc())
            failures.append((version, msg))
            failed_count += 1

    conn.close()

    logger.info("summary  total=%d done=%d skipped=%d failed=%d",
                total, done_count, skipped_count, failed_count)
    if failures:
        logger.error("failures:")
        for v, m in failures:
            logger.error("  %s: %s", v, m)

    logger.info("log saved to %s", log_path)
    return 0 if failed_count == 0 else 1


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

def main(argv: List[str] | None = None) -> int:
    if argv and argv[0] == '--':
        argv = argv[1:]
    parser = argparse.ArgumentParser(
        prog='tshunter batch',
        description='Batch analyze a milestone range or a binaries directory.',
        epilog='Example: tshunter batch --browser chrome --binaries-dir binaries/Chrome --dry-run',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--browser', default='chrome')
    parser.add_argument('--milestones',
                        help='Comma-separated majors or range, e.g. 142,143 or 142-149')
    parser.add_argument('--versions-file', dest='versions_file',
                        metavar='FILE',
                        help='Path to a text file listing one version per line (# comments ok); '
                             'used as alternative to --milestones')
    parser.add_argument('--binaries-dir',
                        help='Directory where each subdir is a version containing a chrome binary')
    parser.add_argument('--source', choices=['cft-latest', 'cft-all'], default='cft-latest',
                        help='Downloader source when --milestones must download binaries')
    parser.add_argument('--platform', default='linux')
    parser.add_argument('--arch', default='x86_64')
    parser.add_argument('--tls-lib', default='boringssl', dest='tls_lib')
    parser.add_argument('--db', default=str(DEFAULT_DB))
    parser.add_argument('--workers', type=int, default=1,
                        help='Reserved for future parallel execution (currently ignored)')
    parser.add_argument('--resume', metavar='RUN_ID',
                        help='Resume a previous run by its run_id')
    parser.add_argument('--dry-run', action='store_true',
                        help='List versions and plan without writing to DB')
    parser.add_argument('--allow-empty', action='store_true',
                        help='Pass --allow-empty to ingest (for debugging)')
    parser.add_argument('--cleanup-binary', action='store_true',
                        help='After a version is done, delete its chrome binary directory and restore metadata.json only')
    args = parser.parse_args(argv)
    return run_batch(args)


if __name__ == '__main__':
    raise SystemExit(main())
