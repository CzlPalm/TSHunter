"""Phase B1: batch analysis mode.

Iterates a set of versions, resolving each via:
  1. DB exact hit  (method='db_hit')
  2. Inline relocate via VersionConfigLoader  (method='relocate')
  3. Full Ghidra analyze → ingest  (method='analyze')

State is persisted in the `batch_jobs` table so runs can be resumed.
"""

from __future__ import annotations

import argparse
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
            FOREIGN KEY (analyzer_runs_id) REFERENCES analyzer_runs(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_batch_run ON batch_jobs(run_id, status);
        CREATE INDEX IF NOT EXISTS idx_batch_version ON batch_jobs(browser, version, platform, arch);
    """)
    conn.commit()


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


# ---------------------------------------------------------------------------
# Version enumeration
# ---------------------------------------------------------------------------

def _enumerate_versions(args: argparse.Namespace) -> List[dict]:
    """Return list of dicts with keys: version, binary_path."""
    versions: List[dict] = []

    binaries_dir = Path(args.binaries_dir) if args.binaries_dir else DEFAULT_BINARIES_DIR

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
    _download_milestones(milestones, artifacts_dir)

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


def _download_milestones(milestones: set, output_dir: Path) -> None:
    import subprocess
    milestone_list = ','.join(sorted(milestones))
    cmd = [
        sys.executable, '-m', 'tshunter.cli', 'download',
        '--milestones', milestone_list,
        '--output-dir', str(output_dir),
    ]
    print(f"[batch] downloading milestones {milestone_list} → {output_dir}")
    subprocess.run(cmd, check=True)


# ---------------------------------------------------------------------------
# Per-version processing
# ---------------------------------------------------------------------------

def _process_version(conn: sqlite3.Connection, job_id: int,
                     args: argparse.Namespace, version: str,
                     binary_path: Path) -> str:
    """Process one version. Returns method string. Raises on unrecoverable error."""
    db_path = Path(args.db)

    # Step 1: DB exact hit
    if _version_in_db(db_path, args.browser, version, args.platform, args.arch):
        return 'db_hit'

    # Step 2: Try VersionConfigLoader (inline relocate + write-back)
    from tshunter.config_loader import (
        VersionConfigLoader, VersionNotInDB, RelocateFailed, ProfileMissing,
    )
    loader = VersionConfigLoader(db_path=db_path, auto_relocate=True, allow_json_fallback=False)
    try:
        loader.load(
            args.browser, version, args.platform, args.arch,
            binary_path=binary_path if binary_path.is_file() else None,
        )
        return 'relocate'
    except (VersionNotInDB, RelocateFailed, ProfileMissing):
        pass  # fall through to full analyze

    # Step 3: Full analyze → ingest
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

    versions = _enumerate_versions(args)
    if not versions:
        print("[batch] no versions found — check --binaries-dir or --milestones")
        return 1

    print(f"[batch] run_id={run_id}  versions={len(versions)}  dry_run={dry_run}")

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
                print(f"  [skip] {version} (already done)")
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
            print(f"  [dry]  {version}")
            skipped_count += 1
            continue

        _update_job(conn, job_id, status='analyzing', started_at=_now_utc())
        try:
            method = _process_version(conn, job_id, args, version, binary_path)
            analyzer_runs_id = _get_latest_analyzer_run_id(
                db_path, args.browser, version, args.platform, args.arch
            ) if method == 'analyze' else None
            kw = dict(status='done', finished_at=_now_utc(), method=method)
            if analyzer_runs_id:
                kw['analyzer_runs_id'] = analyzer_runs_id
            _update_job(conn, job_id, **kw)
            print(f"  [done] {version}  method={method}")
            done_count += 1
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            _update_job(conn, job_id, status='failed', finished_at=_now_utc(), error_msg=msg)
            print(f"  [fail] {version}  {msg}")
            failures.append((version, msg))
            failed_count += 1

    conn.close()

    print(f"\n[batch] summary  total={total} done={done_count} "
          f"skipped={skipped_count} failed={failed_count}")
    if failures:
        print("[batch] failures:")
        for v, m in failures:
            print(f"  {v}: {m}")

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
    parser.add_argument('--binaries-dir',
                        help='Directory where each subdir is a version containing a chrome binary')
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
    args = parser.parse_args(argv)
    return run_batch(args)


if __name__ == '__main__':
    raise SystemExit(main())
