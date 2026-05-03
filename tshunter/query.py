#!/usr/bin/env python3
import argparse
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "fingerprints.db"
DEFAULT_SCHEMA = ROOT / "data" / "schema.sql"
MIGRATIONS_DIR = ROOT / "data" / "migrations"


def connect_db(db_path: Path) -> sqlite3.Connection:
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
        ("relocation_method", "ALTER TABLE hook_points ADD COLUMN relocation_method TEXT DEFAULT 'ghidra_full' CHECK(relocation_method IN ('ghidra_full','exact_scan','exact_scan_partial','manual','imported'))"),
        ("relocation_confidence", "ALTER TABLE hook_points ADD COLUMN relocation_confidence REAL DEFAULT NULL"),
    ]
    for column, sql in additions:
        if not column_exists(conn, "hook_points", column):
            conn.execute(sql)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hook_derived_from ON hook_points(derived_from_version_id)")


def ensure_schema(conn, schema_path: Path):
    from tshunter import ingest as ingest_mod
    ingest_mod.apply_schema(conn, schema_path)


def rows_to_dicts(rows):
    return [dict(row) for row in rows]


def query_exact(conn, browser, version, platform, arch):
    rows = conn.execute(
        """
        SELECT b.name AS browser, v.version, v.platform, v.arch, ts.name AS tls_stack,
               hp.kind, hp.function_name, hp.rva, hp.fingerprint, hp.fingerprint_len, hp.role,
               hp.params_json, hp.source, hp.derived_from_version_id, hp.rva_delta,
               hp.relocation_method, hp.relocation_confidence, v.image_base, v.note
        FROM versions v
        JOIN browsers b ON b.id = v.browser_id
        LEFT JOIN tls_stacks ts ON ts.id = v.tls_stack_id
        JOIN hook_points hp ON hp.version_id = v.id
        WHERE b.name=? AND v.version=? AND v.platform=? AND v.arch=?
        ORDER BY hp.kind
        """,
        (browser, version, platform, arch),
    ).fetchall()
    return rows_to_dicts(rows)


def query_prefix(conn, fp):
    prefix = " ".join(fp.split()[:20])
    rows = conn.execute(
        """
        SELECT b.name AS browser, v.version, v.platform, v.arch, hp.kind, hp.rva, hp.function_name,
               hp.relocation_method, hp.rva_delta, hp.relocation_confidence
        FROM hook_points hp
        JOIN versions v ON v.id = hp.version_id
        JOIN browsers b ON b.id = v.browser_id
        WHERE hp.fingerprint_prefix20=?
        ORDER BY b.name, v.version, hp.kind
        """,
        (prefix,),
    ).fetchall()
    return rows_to_dicts(rows)


def query_major_minor(conn, browser, major_minor):
    like_expr = f"{major_minor}%"
    rows = conn.execute(
        """
        SELECT DISTINCT b.name AS browser, v.version, v.platform, v.arch
        FROM versions v JOIN browsers b ON b.id=v.browser_id
        WHERE b.name=? AND v.version LIKE ?
        ORDER BY v.version
        """,
        (browser, like_expr),
    ).fetchall()
    return rows_to_dicts(rows)


def report(conn):
    totals = conn.execute("SELECT (SELECT COUNT(*) FROM versions) AS versions, (SELECT COUNT(*) FROM hook_points) AS hooks").fetchone()
    stacks = rows_to_dicts(conn.execute(
        """
        SELECT COALESCE(ts.name, 'unknown') AS tls_stack, COUNT(*) AS count
        FROM versions v LEFT JOIN tls_stacks ts ON ts.id=v.tls_stack_id
        GROUP BY COALESCE(ts.name, 'unknown') ORDER BY count DESC
        """
    ).fetchall())
    return {"versions_total": totals[0], "hook_points_total": totals[1], "tls_stacks": stacks}


def format_frida(rows):
    out = {"hook_points": []}
    for row in rows:
        out["hook_points"].append({
            "kind": row["kind"],
            "function": row["function_name"],
            "rva": row["rva"],
            "fingerprint": row["fingerprint"],
            "fingerprint_len": row["fingerprint_len"],
            "params_json": row.get("params_json"),
            "derived_from_version_id": row.get("derived_from_version_id"),
            "rva_delta": row.get("rva_delta"),
            "relocation_method": row.get("relocation_method"),
            "relocation_confidence": row.get("relocation_confidence"),
        })
    return out


def build_parser():
    parser = argparse.ArgumentParser(description="Query TLShunter fingerprint database")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    parser.add_argument("--browser")
    parser.add_argument("--version")
    parser.add_argument("--platform")
    parser.add_argument("--arch")
    parser.add_argument("--major-minor")
    parser.add_argument("--fingerprint")
    parser.add_argument("--format", choices=["json", "frida"], default="json")
    parser.add_argument("--report", action="store_true")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    conn = connect_db(Path(args.db))
    ensure_schema(conn, Path(args.schema))

    if args.report:
        print(json.dumps(report(conn), indent=2, ensure_ascii=False))
        return 0
    if args.fingerprint:
        print(json.dumps(query_prefix(conn, args.fingerprint), indent=2, ensure_ascii=False))
        return 0
    if args.browser and args.major_minor:
        print(json.dumps(query_major_minor(conn, args.browser, args.major_minor), indent=2, ensure_ascii=False))
        return 0
    if args.browser and args.version and args.platform and args.arch:
        rows = query_exact(conn, args.browser, args.version, args.platform, args.arch)
        if args.format == "frida":
            print(json.dumps(format_frida(rows), indent=2, ensure_ascii=False))
        else:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    raise SystemExit("must provide --report, --fingerprint, or exact version query arguments")


if __name__ == "__main__":
    raise SystemExit(main())
