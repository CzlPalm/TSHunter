#!/usr/bin/env python3
"""annotate_verified.py — 验证层后处理脚本 (U2)

把独立的 P3/P4 实测结果写回 versions 表，不碰 hook_points。

用法:
    python3 tools/annotate_verified.py \
        --browser chrome --version 143.0.7499.169 \
        --platform linux --arch x86_64 \
        --verified-method 'SSLKEYLOGFILE diff + Wireshark decryption' \
        --p3-capture-rate 0.96 --p4-tuple-hit-rate 1.0 \
        --boringssl-commit 992dfa0b56f98b8decaf82cd8df44aa714675d99

Design:
  - versions.verified 是一个 bool 位；设为 1 表示该版本已经过人工/回归验证；
  - verified_method / p3_capture_rate / p4_tuple_hit_rate / tls_lib_commit 全部写到
    versions 表已有的字段或 note 里；
  - 不在 hook_points 级做验证注释，避免分析层被验证数据污染。

注意：这是 U2 的最小实现。论文 §5 需要的更细的 per-run metrics 会在 E1 阶段扩展
(capture_sessions / 新的 metrics 表)，目前先把“verified 基线标注”跑通。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tshunter.ingest import apply_schema, db_connect  # noqa: E402

DEFAULT_DB = _ROOT / 'data' / 'fingerprints.db'
DEFAULT_SCHEMA = _ROOT / 'data' / 'schema.sql'


def _find_version_id(conn: sqlite3.Connection, browser: str, version: str, platform: str, arch: str):
    row = conn.execute(
        """
        SELECT v.id
        FROM versions v JOIN browsers b ON b.id = v.browser_id
        WHERE b.name=? AND v.version=? AND v.platform=? AND v.arch=?
        """,
        (browser, version, platform, arch),
    ).fetchone()
    return row[0] if row else None


def _compose_note(existing_note: str | None, verified_method: str | None,
                   p3: float | None, p4: float | None) -> str | None:
    payload = {}
    if existing_note:
        # 如果原本就是 JSON，保留它的其他字段
        try:
            parsed = json.loads(existing_note)
            if isinstance(parsed, dict):
                payload.update(parsed)
        except (TypeError, json.JSONDecodeError):
            payload['prior_note'] = existing_note
    if verified_method:
        payload['verified_method'] = verified_method
    if p3 is not None:
        payload['p3_capture_rate'] = p3
    if p4 is not None:
        payload['p4_tuple_hit_rate'] = p4
    payload['annotated_at'] = datetime.now(timezone.utc).isoformat()
    return json.dumps(payload, ensure_ascii=False)


def annotate(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    version_id = _find_version_id(conn, args.browser, args.version, args.platform, args.arch)
    if not version_id:
        print(
            f"[FAIL] version not found in DB: {args.browser} {args.version} {args.platform}/{args.arch}",
            file=sys.stderr,
        )
        return 2

    row = conn.execute("SELECT note, tls_lib_commit FROM versions WHERE id=?", (version_id,)).fetchone()
    existing_note, existing_commit = row if row else (None, None)

    new_note = _compose_note(
        existing_note, args.verified_method, args.p3_capture_rate, args.p4_tuple_hit_rate,
    )
    new_commit = args.boringssl_commit or existing_commit

    conn.execute(
        """
        UPDATE versions SET verified=?, note=?, tls_lib_commit=?
        WHERE id=?
        """,
        (1 if not args.unverify else 0, new_note, new_commit, version_id),
    )
    conn.commit()
    print(
        f"[OK] {'unverified' if args.unverify else 'verified'} "
        f"{args.browser} {args.version} {args.platform}/{args.arch}"
    )
    if new_note:
        print(f"     note: {new_note}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Annotate verified-layer metadata on a DB version")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    parser.add_argument("--browser", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", default="linux")
    parser.add_argument("--arch", default="x86_64")
    parser.add_argument("--verified-method")
    parser.add_argument("--p3-capture-rate", type=float)
    parser.add_argument("--p4-tuple-hit-rate", type=float)
    parser.add_argument("--boringssl-commit")
    parser.add_argument("--unverify", action="store_true", help="Clear the verified flag instead of setting it")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    conn = db_connect(Path(args.db))
    apply_schema(conn, Path(args.schema))
    try:
        return annotate(conn, args)
    finally:
        conn.close()


if __name__ == '__main__':
    raise SystemExit(main())
