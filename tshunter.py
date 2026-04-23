#!/usr/bin/env python3
import argparse
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "data" / "fingerprints.db"
DEFAULT_SCHEMA = ROOT / "tools" / "schema.sql"
DEFAULT_RESULTS_DIR = ROOT / "results"
DEFAULT_IMAGE = "tlshunter:0.5.0"
MIGRATIONS_DIR = ROOT / "tools" / "migrations"


def connect_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_migrations_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )


def column_exists(conn, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row[1] == column for row in rows)


def ensure_relocate_columns(conn):
    additions = [
        ("derived_from_version_id", "ALTER TABLE hook_points ADD COLUMN derived_from_version_id INTEGER REFERENCES versions(id)"),
        ("rva_delta", "ALTER TABLE hook_points ADD COLUMN rva_delta INTEGER DEFAULT NULL"),
        ("relocation_method", "ALTER TABLE hook_points ADD COLUMN relocation_method TEXT DEFAULT 'ghidra_full' CHECK(relocation_method IN ('ghidra_full','exact_scan','manual','imported'))"),
        ("relocation_confidence", "ALTER TABLE hook_points ADD COLUMN relocation_confidence REAL DEFAULT NULL"),
    ]
    for column, sql in additions:
        if not column_exists(conn, "hook_points", column):
            conn.execute(sql)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hook_derived_from ON hook_points(derived_from_version_id)")


def ensure_migrations(conn):
    ensure_migrations_table(conn)
    if MIGRATIONS_DIR.exists():
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            version = path.stem
            row = conn.execute("SELECT 1 FROM schema_migrations WHERE version=?", (version,)).fetchone()
            if row:
                continue
            if version == "001_relocate_fields" and column_exists(conn, "hook_points", "derived_from_version_id"):
                conn.execute("INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))", (version,))
                continue
            conn.executescript(path.read_text(encoding="utf-8"))
            ensure_relocate_columns(conn)
            conn.execute("INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))", (version,))
    else:
        ensure_relocate_columns(conn)


def ensure_schema(conn: sqlite3.Connection, schema_path: Path) -> None:
    conn.executescript(schema_path.read_text(encoding="utf-8"))
    ensure_migrations(conn)
    conn.commit()


def query_exact(conn: sqlite3.Connection, browser: str, version: str, platform: str, arch: str):
    rows = conn.execute(
        """
        SELECT b.name AS browser, v.version, v.platform, v.arch, ts.name AS tls_stack,
               hp.kind, hp.function_name, hp.rva, hp.fingerprint, hp.fingerprint_len, hp.role,
               hp.derived_from_version_id, hp.rva_delta, hp.relocation_method, hp.relocation_confidence
        FROM versions v
        JOIN browsers b ON b.id = v.browser_id
        LEFT JOIN tls_stacks ts ON ts.id = v.tls_stack_id
        JOIN hook_points hp ON hp.version_id = v.id
        WHERE b.name=? AND v.version=? AND v.platform=? AND v.arch=?
        ORDER BY hp.kind
        """,
        (browser, version, platform, arch),
    ).fetchall()
    return [dict(row) for row in rows]


def format_frida(rows: list[dict]) -> dict:
    return {
        "hook_points": [
            {
                "kind": row["kind"],
                "function": row["function_name"],
                "rva": row["rva"],
                "fingerprint": row["fingerprint"],
                "fingerprint_len": row["fingerprint_len"],
                "derived_from_version_id": row.get("derived_from_version_id"),
                "rva_delta": row.get("rva_delta"),
                "relocation_method": row.get("relocation_method"),
                "relocation_confidence": row.get("relocation_confidence"),
            }
            for row in rows
        ]
    }


def emit_hooks(rows: list[dict], output: Path | None) -> None:
    if output is None:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(format_frida(rows), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def result_json_path(args) -> Path:
    return (DEFAULT_RESULTS_DIR / f"{args.browser}_{args.version}_{args.platform}_{args.arch}.json").resolve()


def relocate_json_path(args) -> Path:
    return (DEFAULT_RESULTS_DIR / f"relocate_{args.browser}_{args.version}_{args.platform}_{args.arch}.json").resolve()


def run_subprocess(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def find_relocation_source(conn, browser, version, platform, arch):
    major_minor = ".".join(version.split(".")[:2])
    rows = conn.execute(
        """
        SELECT v.id, v.version, v.platform, v.arch, b.name AS browser
        FROM versions v
        JOIN browsers b ON b.id = v.browser_id
        WHERE b.name=? AND v.version LIKE ? AND v.platform=? AND v.arch=? AND v.verified=1
        ORDER BY v.version DESC
        """,
        (browser, f"{major_minor}.%", platform, arch),
    ).fetchall()
    for row in rows:
        if row["version"] != version:
            return dict(row)
    return None


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def run_relocate(args, source_row: dict, db_path: Path) -> Path:
    out = relocate_json_path(args)
    cmd = [
        sys.executable,
        str((ROOT / "tools" / "fingerprint_relocate.py").resolve()),
        "scan",
        "--binary", str(Path(args.binary).resolve()),
        "--db", str(db_path),
        "--source-browser", source_row["browser"],
        "--source-version", source_row["version"],
        "--source-platform", source_row["platform"],
        "--source-arch", source_row["arch"],
        "--output", str(out),
    ]
    run_subprocess(cmd)
    return out


def cmd_relocate(args) -> int:
    db_path = Path(args.db).resolve()
    schema_path = Path(args.schema).resolve()
    binary_path = Path(args.binary).resolve()
    output_path = Path(args.output).resolve() if args.output else relocate_json_path(args)
    if not binary_path.is_file():
        raise SystemExit(f"Binary not found: {binary_path}")

    conn = connect_db(db_path)
    ensure_schema(conn, schema_path)

    source_version = args.source_version
    if not source_version:
        source_row = find_relocation_source(conn, args.browser, args.version, args.platform, args.arch)
        if not source_row:
            raise SystemExit("No relocation source found")
        source_version = source_row["version"]
    else:
        source_row = {
            "browser": args.browser,
            "version": source_version,
            "platform": args.platform,
            "arch": args.arch,
        }

    cmd = [
        sys.executable,
        str((ROOT / "tools" / "fingerprint_relocate.py").resolve()),
        "scan",
        "--binary", str(binary_path),
        "--db", str(db_path),
        "--source-browser", source_row["browser"],
        "--source-version", source_row["version"],
        "--source-platform", source_row["platform"],
        "--source-arch", source_row["arch"],
        "--output", str(output_path),
    ]
    run_subprocess(cmd)
    payload = load_json(output_path)
    print(f"[OK] Relocate verdict: {payload['verdict']}")
    if args.auto_ingest and payload["verdict"] == "OK":
        ingest_cmd = [
            sys.executable,
            str((ROOT / "tools" / "ingest.py").resolve()),
            "--from-relocate", str(output_path),
            "--db", str(db_path),
            "--browser", args.browser,
            "--version", args.version,
            "--platform", args.platform,
            "--arch", args.arch,
            "--upsert",
        ]
        run_subprocess(ingest_cmd)
        print("[*] Auto-ingested relocate result into database")
    return 0


def cmd_capture(args) -> int:
    db_path = Path(args.db).resolve()
    schema_path = Path(args.schema).resolve()
    binary_path = Path(args.binary).resolve()
    output_path = Path(args.output).resolve() if args.output else None

    if not binary_path.is_file():
        raise SystemExit(f"Binary not found: {binary_path}")

    conn = connect_db(db_path)
    ensure_schema(conn, schema_path)

    rows = query_exact(conn, args.browser, args.version, args.platform, args.arch)
    if rows:
        emit_hooks(rows, output_path)
        print(f"[OK] DB hit: {args.browser} {args.version} {args.platform}/{args.arch}")
        print(f"[OK] Hook points: {len(rows)}")
        if output_path:
            print(f"[OK] Frida hooks written to {output_path}")
        return 0

    print(f"[*] DB miss: {args.browser} {args.version} {args.platform}/{args.arch}")

    if not args.no_relocate:
        print("[*] Searching relocation source in same major.minor...")
        source_row = find_relocation_source(conn, args.browser, args.version, args.platform, args.arch)
        if source_row:
            print(f"[*] Found candidate: {source_row['browser']} {source_row['version']} (verified)")
            print("[*] Running fingerprint relocate...")
            relocate_path = run_relocate(args, source_row, db_path)
            relocate_payload = load_json(relocate_path)
            summary = relocate_payload.get("relocation_summary", {})
            print(f"[OK] Relocate verdict: {relocate_payload['verdict']}")
            print(f"     hooks relocated: {summary.get('relocated', 0)}/{summary.get('total_hooks', 0)}")
            print(f"     median delta:    {summary.get('median_delta')}")
            if relocate_payload["verdict"] == "OK" or args.force_relocate:
                print("[*] Auto-ingesting relocated hooks...")
                ingest_cmd = [
                    sys.executable,
                    str((ROOT / "tools" / "ingest.py").resolve()),
                    "--from-relocate", str(relocate_path),
                    "--db", str(db_path),
                    "--browser", args.browser,
                    "--version", args.version,
                    "--platform", args.platform,
                    "--arch", args.arch,
                    "--upsert",
                ]
                run_subprocess(ingest_cmd)
                rows = query_exact(conn, args.browser, args.version, args.platform, args.arch)
                if rows:
                    emit_hooks(rows, output_path)
                    print(f"[✓] Complete. Database now has {args.browser} {args.version}")
                    if output_path:
                        print(f"    Frida hooks written to {output_path}")
                    return 0
            else:
                print("[*] Relocate not sufficient, fallback to full analyzer...")
        else:
            print("[*] No relocation source found, fallback to full analyzer...")

    print("[*] Running analyzer...")
    result_json = result_json_path(args)
    run_cmd = [
        sys.executable,
        str((ROOT / "run.py").resolve()),
        "--binary",
        str(binary_path),
        "--output",
        str(result_json),
        "--browser",
        args.browser,
        "--version",
        args.version,
        "--platform",
        args.platform,
        "--arch",
        args.arch,
        "--image",
        args.image,
    ]
    if args.tls_lib:
        run_cmd.extend(["--tls-lib", args.tls_lib])
    if args.rebuild:
        run_cmd.append("--rebuild")
    run_subprocess(run_cmd)

    parsed = load_json(result_json)
    if not parsed.get("hook_points"):
        raise SystemExit(
            "[FATAL] Analysis produced empty hook_points — aborting capture flow. Check results/analysis.log for root cause."
        )

    print("[*] Ingesting analysis result into database...")
    ingest_cmd = [
        sys.executable,
        str((ROOT / "tools" / "ingest.py").resolve()),
        "--json",
        str(result_json),
        "--db",
        str(db_path),
    ]
    run_subprocess(ingest_cmd)

    rows = query_exact(conn, args.browser, args.version, args.platform, args.arch)
    if not rows:
        raise SystemExit("analysis finished, but no hook points were found in database")

    emit_hooks(rows, output_path)
    print("[✓] Analysis complete, inserted into DB as unverified.")
    print(f"    Version: {args.browser} {args.version} {args.platform}/{args.arch}")
    print(f"    JSON:    {result_json}")
    print(f"    DB:      {db_path}")
    if output_path:
        print(f"    Hooks:   {output_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tshunter", description="TLShunter minimal end-to-end CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    capture = sub.add_parser("capture", help="Query DB or analyze and ingest a binary")
    capture.add_argument("--binary", required=True, help="Path to target binary")
    capture.add_argument("--browser", required=True, help="Browser/app name")
    capture.add_argument("--version", required=True, help="Version string")
    capture.add_argument("--platform", default="linux", help="Target platform")
    capture.add_argument("--arch", default="x86_64", help="Target architecture")
    capture.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    capture.add_argument("--schema", default=str(DEFAULT_SCHEMA), help="Schema SQL path")
    capture.add_argument("--output", help="Path to write Frida hook config JSON")
    capture.add_argument("--tls-lib", help="Expected TLS library")
    capture.add_argument("--image", default=DEFAULT_IMAGE, help="Docker image tag")
    capture.add_argument("--rebuild", action="store_true", help="Force docker image rebuild before analysis")
    capture.add_argument("--no-relocate", action="store_true", help="Disable relocate and run full analysis on DB miss")
    capture.add_argument("--force-relocate", action="store_true", help="Use relocate result even if verdict is PARTIAL")
    capture.set_defaults(func=cmd_capture)

    relocate = sub.add_parser("relocate", help="Run fingerprint relocate against a binary")
    relocate.add_argument("--binary", required=True)
    relocate.add_argument("--browser", required=True)
    relocate.add_argument("--version", required=True)
    relocate.add_argument("--platform", default="linux")
    relocate.add_argument("--arch", default="x86_64")
    relocate.add_argument("--source-version")
    relocate.add_argument("--db", default=str(DEFAULT_DB))
    relocate.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    relocate.add_argument("--output")
    relocate.add_argument("--auto-ingest", action="store_true")
    relocate.set_defaults(func=cmd_relocate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
