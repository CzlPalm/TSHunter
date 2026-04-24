#!/usr/bin/env python3
import argparse
import runpy
import sys
from pathlib import Path

from . import analyze as analyze_mod
from . import ingest as ingest_mod
from . import query as query_mod

ROOT = Path(__file__).resolve().parents[1]


def _run_script(path: Path, forward_args: list[str]):
    old_argv = sys.argv[:]
    try:
        sys.argv = [str(path), *forward_args]
        runpy.run_path(str(path), run_name='__main__')
    finally:
        sys.argv = old_argv


def build_parser():
    parser = argparse.ArgumentParser(prog='tshunter', description='TSHunter unified CLI (U1 stage)')
    sub = parser.add_subparsers(dest='cmd', required=True)

    analyze = sub.add_parser('analyze', help='Run static analyzer')
    analyze.add_argument('forward', nargs=argparse.REMAINDER)
    analyze.set_defaults(func=lambda args: analyze_mod.main(args.forward))

    capture = sub.add_parser('capture', help='Run runtime capture entry')
    capture.add_argument('forward', nargs=argparse.REMAINDER)
    capture.set_defaults(func=lambda args: _run_script(ROOT / 'tshunter' / 'capture.py', args.forward))

    ingest = sub.add_parser('ingest', help='Ingest analysis JSON into DB')
    ingest.add_argument('forward', nargs=argparse.REMAINDER)
    ingest.set_defaults(func=lambda args: ingest_mod.main(args.forward))

    query = sub.add_parser('query', help='Query fingerprint DB')
    query.add_argument('forward', nargs=argparse.REMAINDER)
    query.set_defaults(func=lambda args: query_mod.main(args.forward))

    relocate = sub.add_parser('relocate', help='Run relocate tool')
    relocate.add_argument('forward', nargs=argparse.REMAINDER)
    relocate.set_defaults(func=lambda args: _run_script(ROOT / 'tshunter' / 'relocate.py', args.forward))

    merge = sub.add_parser('merge', help='Merge auto analysis with baseline')
    merge.add_argument('forward', nargs=argparse.REMAINDER)
    merge.set_defaults(func=lambda args: _run_script(ROOT / 'tshunter' / 'merge.py', args.forward))

    download = sub.add_parser('download', help='Download Chrome binaries')
    download.add_argument('forward', nargs=argparse.REMAINDER)
    download.set_defaults(func=lambda args: _run_script(ROOT / 'tshunter' / 'downloader.py', args.forward))

    batch = sub.add_parser('batch', help='Reserved for batch pipeline')
    batch.add_argument('forward', nargs=argparse.REMAINDER)
    batch.set_defaults(func=lambda args: 0)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
