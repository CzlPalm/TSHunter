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


def db_connect(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def apply_schema(conn, schema: Path):
    conn.executescript(schema.read_text(encoding="utf-8"))
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


def upsert_hook(conn, version_id: int, kind: str, item: dict, upsert: bool, source_override: str | None):
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
            role=:role, params_json=:params_json, source=:source, verified=:verified
            WHERE version_id=:version_id AND kind=:kind
            """,
            values,
        )
        return
    conn.execute(
        """
        INSERT INTO hook_points(version_id, kind, function_name, rva, fingerprint, fingerprint_len,
        fingerprint_prefix20, role, params_json, source, verified)
        VALUES (:version_id, :kind, :function_name, :rva, :fingerprint, :fingerprint_len,
        :fingerprint_prefix20, :role, :params_json, :source, :verified)
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
    version_id = ensure_version(conn, meta, args.upsert)
    for kind, item in payload.get("hook_points", {}).items():
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
    if args.batch:
        for path in sorted(Path(args.batch).glob("*.json")):
            yield path, None
        return
    if args.legacy:
        for path in sorted(Path(args.legacy).glob("*.json")):
            yield path, "legacy"
        return
    raise SystemExit("must provide --json, --batch, or --legacy")


def main():
    parser = argparse.ArgumentParser(description="Ingest TLShunter JSON results into SQLite")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--json")
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
    args = parser.parse_args()

    conn = db_connect(Path(args.db))
    apply_schema(conn, Path(args.schema))
    maybe_seed(conn, Path(args.seed), args)

    imported = 0
    for path, source_override in iter_payloads(args):
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["_source_path"] = str(path)
        ingest_payload(conn, payload, args, source_override=source_override)
        imported += 1
    conn.commit()
    print(f"[*] Imported {imported} JSON file(s) into {args.db}")


if __name__ == "__main__":
    main()
