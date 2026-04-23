#!/usr/bin/env python3
import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "fingerprints.db"
DEFAULT_SCHEMA = ROOT / "tools" / "schema.sql"
DEFAULT_SEED = ROOT / "data" / "seed_fingerprints.json"
MIGRATIONS_DIR = ROOT / "tools" / "migrations"


def db_connect(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
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
    if not MIGRATIONS_DIR.exists():
        ensure_relocate_columns(conn)
        return
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = path.stem
        row = conn.execute("SELECT 1 FROM schema_migrations WHERE version=?", (version,)).fetchone()
        if row:
            continue
        if version == "001_relocate_fields" and column_exists(conn, "hook_points", "derived_from_version_id"):
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))",
                (version,),
            )
            continue
        conn.executescript(path.read_text(encoding="utf-8"))
        ensure_relocate_columns(conn)
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))",
            (version,),
        )


def apply_schema(conn, schema: Path):
    conn.executescript(schema.read_text(encoding="utf-8"))
    ensure_migrations(conn)
    conn.commit()


def prefix20(fp: str) -> str:
    return " ".join(fp.split()[:20])


def norm_tls_lib(meta: dict):
    value = meta.get("tls_lib_detected") or meta.get("tls_lib")
    return value.lower() if isinstance(value, str) else None


def ensure_browser(conn, browser: str, tls_lib: str | None):
    browser = browser.lower()
    row = conn.execute("SELECT id FROM browsers WHERE name=?", (browser,)).fetchone()
    if row:
        return row[0]
    tls_stack_id = None
    if tls_lib:
        stack = conn.execute("SELECT id FROM tls_stacks WHERE name=?", (tls_lib,)).fetchone()
        tls_stack_id = stack[0] if stack else None
    conn.execute(
        "INSERT INTO browsers(name, vendor, default_tls_stack_id) VALUES (?, ?, ?)",
        (browser, None, tls_stack_id),
    )
    return conn.execute("SELECT id FROM browsers WHERE name=?", (browser,)).fetchone()[0]


def ensure_version(conn, meta: dict, upsert: bool):
    required = [meta.get("browser"), meta.get("version"), meta.get("platform"), meta.get("arch")]
    if not all(required):
        raise SystemExit("missing required meta fields: browser/version/platform/arch")

    tls_lib = norm_tls_lib(meta)
    browser_id = ensure_browser(conn, meta["browser"], tls_lib)
    tls_stack_id = None
    if tls_lib:
        stack = conn.execute("SELECT id FROM tls_stacks WHERE name=?", (tls_lib,)).fetchone()
        tls_stack_id = stack[0] if stack else None

    row = conn.execute(
        "SELECT id FROM versions WHERE browser_id=? AND version=? AND platform=? AND arch=?",
        (browser_id, meta["version"], meta["platform"], meta["arch"]),
    ).fetchone()

    values = {
        "browser_id": browser_id,
        "version": meta["version"],
        "platform": meta["platform"],
        "arch": meta["arch"],
        "tls_stack_id": tls_stack_id,
        "tls_lib_commit": meta.get("tls_lib_commit") or meta.get("boringssl_commit"),
        "image_base": meta.get("image_base") or meta.get("ghidra_image_base"),
        "binary_sha256": meta.get("binary_sha256"),
        "binary_size": meta.get("binary_size"),
        "analysis_date": meta.get("analysis_date"),
        "analyzer_version": meta.get("analyzer_version"),
        "verified": 1 if meta.get("verified") else 0,
        "note": meta.get("note") or meta.get("verified_method"),
    }

    if row and not upsert:
        return row[0]
    if row and upsert:
        conn.execute(
            """
            UPDATE versions SET tls_stack_id=:tls_stack_id, tls_lib_commit=:tls_lib_commit,
            image_base=:image_base, binary_sha256=:binary_sha256, binary_size=:binary_size,
            analysis_date=:analysis_date, analyzer_version=:analyzer_version,
            verified=:verified, note=:note WHERE id=:id
            """,
            values | {"id": row[0]},
        )
        return row[0]

    conn.execute(
        """
        INSERT INTO versions(
            browser_id, version, platform, arch, tls_stack_id, tls_lib_commit, image_base,
            binary_sha256, binary_size, analysis_date, analyzer_version, verified, note
        ) VALUES (
            :browser_id, :version, :platform, :arch, :tls_stack_id, :tls_lib_commit, :image_base,
            :binary_sha256, :binary_size, :analysis_date, :analyzer_version, :verified, :note
        )
        """,
        values,
    )
    return conn.execute(
        "SELECT id FROM versions WHERE browser_id=? AND version=? AND platform=? AND arch=?",
        (browser_id, meta["version"], meta["platform"], meta["arch"]),
    ).fetchone()[0]


def lookup_source_version_id(conn, source: dict | None):
    if not source:
        return None
    row = conn.execute(
        """
        SELECT v.id
        FROM versions v
        JOIN browsers b ON b.id = v.browser_id
        WHERE b.name=? AND v.version=? AND v.platform=? AND v.arch=?
        """,
        (source["browser"], source["version"], source["platform"], source["arch"]),
    ).fetchone()
    return row[0] if row else None


def upsert_hook(conn, version_id: int, kind: str, item: dict, upsert: bool, source_override: str | None,
                relocation_method: str = "ghidra_full", derived_from_version_id=None,
                rva_delta=None, relocation_confidence=None):
    fp = item["fingerprint"].strip()
    values = {
        "version_id": version_id,
        "kind": kind,
        "function_name": item.get("function") or item.get("function_name") or item.get("ghidra_name"),
        "rva": item["rva"],
        "fingerprint": fp,
        "fingerprint_len": item.get("fingerprint_len") or len(fp.split()),
        "fingerprint_prefix20": prefix20(fp),
        "role": item.get("role"),
        "params_json": json.dumps(item.get("params") or item.get("params_json")) if (item.get("params") or item.get("params_json")) else None,
        "source": source_override or item.get("source") or "auto",
        "verified": 1 if item.get("verified") else 0,
        "derived_from_version_id": derived_from_version_id,
        "rva_delta": rva_delta,
        "relocation_method": relocation_method,
        "relocation_confidence": relocation_confidence,
    }
    row = conn.execute(
        "SELECT id FROM hook_points WHERE version_id=? AND kind=?",
        (version_id, kind),
    ).fetchone()
    if row and not upsert:
        return
    if row and upsert:
        conn.execute(
            """
            UPDATE hook_points SET function_name=:function_name, rva=:rva, fingerprint=:fingerprint,
            fingerprint_len=:fingerprint_len, fingerprint_prefix20=:fingerprint_prefix20,
            role=:role, params_json=:params_json, source=:source, verified=:verified,
            derived_from_version_id=:derived_from_version_id, rva_delta=:rva_delta,
            relocation_method=:relocation_method, relocation_confidence=:relocation_confidence
            WHERE version_id=:version_id AND kind=:kind
            """,
            values,
        )
        return
    conn.execute(
        """
        INSERT INTO hook_points(version_id, kind, function_name, rva, fingerprint, fingerprint_len,
        fingerprint_prefix20, role, params_json, source, verified, derived_from_version_id,
        rva_delta, relocation_method, relocation_confidence)
        VALUES (:version_id, :kind, :function_name, :rva, :fingerprint, :fingerprint_len,
        :fingerprint_prefix20, :role, :params_json, :source, :verified, :derived_from_version_id,
        :rva_delta, :relocation_method, :relocation_confidence)
        """,
        values,
    )


def enrich_meta(meta: dict, args):
    for key in ("browser", "version", "platform", "arch"):
        cli = getattr(args, key)
        if cli and not meta.get(key):
            meta[key] = cli
    if args.tls_lib and not meta.get("tls_lib"):
        meta["tls_lib"] = args.tls_lib


def ingest_payload(conn, payload: dict, args, source_override: str | None = None):
    meta = payload.setdefault("meta", {})
    enrich_meta(meta, args)
    hook_points = payload.get("hook_points", {})
    if not hook_points and not args.allow_empty:
        raise SystemExit(
            f"[FATAL] Refusing to ingest empty hook_points from {payload.get('_source_path')}. If analysis genuinely found nothing, pass --allow-empty."
        )
    version_id = ensure_version(conn, meta, args.upsert)
    for kind, item in hook_points.items():
        upsert_hook(conn, version_id, kind, item, args.upsert, source_override)
    conn.execute(
        "INSERT INTO analyzer_runs(version_id, started_at, finished_at, duration_seconds, analyzer_version, exit_code, json_path) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            version_id,
            datetime.now(timezone.utc).isoformat(),
            datetime.now(timezone.utc).isoformat(),
            0,
            meta.get("analyzer_version"),
            0,
            payload.get("_source_path"),
        ),
    )


def ingest_relocate_payload(conn, payload: dict, args):
    summary = payload.get("relocation_summary", {})
    if summary.get("relocated", 0) == 0 and not args.allow_empty:
        raise SystemExit("[FATAL] Refusing to ingest relocate result with zero relocated hooks")

    target = payload.get("target", {})
    source = payload.get("source_version", {})
    meta = {
        "browser": args.browser,
        "version": args.version,
        "platform": args.platform,
        "arch": args.arch,
        "binary_sha256": target.get("sha256"),
        "binary_size": target.get("size"),
        "image_base": target.get("image_base"),
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "analyzer_version": payload.get("tool_version"),
        "verified": 0,
        "note": f"relocated from {source.get('version')}",
    }
    version_id = ensure_version(conn, meta, args.upsert)
    derived_from_version_id = lookup_source_version_id(conn, source)

    for item in payload.get("hooks", []):
        if item.get("match_type") == "not_found" or not item.get("new_rva"):
            continue
        kind = item["kind"]
        source_row = conn.execute(
            """
            SELECT hp.function_name, hp.fingerprint, hp.fingerprint_len, hp.role
            FROM hook_points hp
            WHERE hp.version_id=? AND hp.kind=?
            """,
            (derived_from_version_id, kind),
        ).fetchone() if derived_from_version_id else None
        if not source_row:
            continue
        hook_item = {
            "function_name": source_row["function_name"],
            "rva": item["new_rva"],
            "fingerprint": source_row["fingerprint"],
            "fingerprint_len": source_row["fingerprint_len"],
            "role": source_row["role"],
            "source": "relocate",
        }
        upsert_hook(
            conn,
            version_id,
            kind,
            hook_item,
            args.upsert,
            source_override="relocate",
            relocation_method="exact_scan",
            derived_from_version_id=derived_from_version_id,
            rva_delta=int(item["delta"], 16) if item.get("delta") else None,
            relocation_confidence=item.get("confidence"),
        )


def maybe_seed(conn, seed: Path, args):
    count = conn.execute("SELECT COUNT(*) FROM hook_points").fetchone()[0]
    if count != 0 or not seed.exists():
        return
    payload = json.loads(seed.read_text(encoding="utf-8"))
    for item in payload:
        item["_source_path"] = str(seed)
        ingest_payload(conn, item, args, source_override="seed")
    conn.commit()


def iter_payloads(args):
    if args.json:
        yield Path(args.json), None
        return
    if args.from_relocate:
        yield Path(args.from_relocate), "relocate"
        return
    if args.batch:
        for path in sorted(Path(args.batch).glob("*.json")):
            yield path, None
        return
    if args.legacy:
        for path in sorted(Path(args.legacy).glob("*.json")):
            yield path, "legacy"
        return
    raise SystemExit("must provide --json, --from-relocate, --batch, or --legacy")


def main():
    parser = argparse.ArgumentParser(description="Ingest TLShunter JSON results into SQLite")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--json")
    parser.add_argument("--from-relocate")
    parser.add_argument("--batch")
    parser.add_argument("--legacy")
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    parser.add_argument("--seed", default=str(DEFAULT_SEED))
    parser.add_argument("--browser")
    parser.add_argument("--version")
    parser.add_argument("--platform")
    parser.add_argument("--arch")
    parser.add_argument("--tls-lib")
    parser.add_argument("--upsert", action="store_true")
    parser.add_argument("--allow-empty", action="store_true")
    args = parser.parse_args()

    conn = db_connect(Path(args.db))
    apply_schema(conn, Path(args.schema))
    maybe_seed(conn, Path(args.seed), args)

    imported = 0
    for path, source_override in iter_payloads(args):
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["_source_path"] = str(path)
        if source_override == "relocate":
            ingest_relocate_payload(conn, payload, args)
        else:
            ingest_payload(conn, payload, args, source_override=source_override)
        imported += 1
    conn.commit()
    print(f"[*] Imported {imported} JSON file(s) into {args.db}")


if __name__ == "__main__":
    main()
