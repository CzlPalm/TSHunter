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


def connect_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema(conn: sqlite3.Connection, schema_path: Path) -> None:
    conn.executescript(schema_path.read_text(encoding="utf-8"))
    conn.commit()


def query_exact(conn: sqlite3.Connection, browser: str, version: str, platform: str, arch: str):
    rows = conn.execute(
        """
        SELECT b.name AS browser, v.version, v.platform, v.arch, ts.name AS tls_stack,
               hp.kind, hp.function_name, hp.rva, hp.fingerprint, hp.fingerprint_len, hp.role
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


def run_subprocess(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


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
    capture.set_defaults(func=cmd_capture)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

