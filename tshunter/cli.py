#!/usr/bin/env python3
import argparse
import runpy
import sys
from pathlib import Path

from . import analyze as analyze_mod
from . import batch as batch_mod
from . import ingest as ingest_mod
from . import query as query_mod

ROOT = Path(__file__).resolve().parents[1]


CLI_OVERVIEW = (
    "Unified CLI for analyzer, database, relocate, merge, download, and runtime capture.\n"
    "U3-lite keeps legacy runtime compatibility: old wrappers and tls_capture/hooks remain intact."
)


def _run_script(path: Path, forward_args: list[str]):
    old_argv = sys.argv[:]
    try:
        sys.argv = [str(path), *forward_args]
        runpy.run_path(str(path), run_name='__main__')
    finally:
        sys.argv = old_argv


def _add_forwarding_subparser(sub, name: str, *, help_text: str, description: str, epilog: str, runner):
    parser = sub.add_parser(
        name,
        help=help_text,
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'forward',
        nargs=argparse.REMAINDER,
        help='Arguments forwarded to the underlying implementation. Use `--help` after the subcommand for detailed flags.',
    )
    parser.set_defaults(func=runner)
    return parser


def build_parser():
    parser = argparse.ArgumentParser(
        prog='tshunter',
        description=CLI_OVERVIEW,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='cmd', required=True, metavar='command')

    _add_forwarding_subparser(
        sub,
        'analyze',
        help_text='Run static analyzer against a binary or batch directory',
        description='Run the Ghidra-backed static analyzer and emit analysis JSON.',
        epilog='Example: tshunter analyze --binary /path/chrome --output results/chrome.json',
        runner=lambda args: analyze_mod.main(args.forward),
    )

    _add_forwarding_subparser(
        sub,
        'capture',
        help_text='Run runtime capture entry (legacy runtime preserved)',
        description='Launch the runtime capture entry. U3-lite keeps the existing runtime hook logic unchanged.',
        epilog='Example: tshunter capture -- --auto --chrome-bin /opt/google/chrome/chrome',
        runner=lambda args: _run_script(ROOT / 'tshunter' / 'capture.py', args.forward),
    )

    _add_forwarding_subparser(
        sub,
        'ingest',
        help_text='Ingest analysis JSON or relocate results into SQLite',
        description='Import analysis output into the fingerprint database.',
        epilog='Example: tshunter ingest --json results/chrome.json --db data/fingerprints.db --upsert',
        runner=lambda args: ingest_mod.main(args.forward),
    )

    _add_forwarding_subparser(
        sub,
        'query',
        help_text='Query the fingerprint database',
        description='Query exact versions, fingerprint prefixes, or report statistics from the DB.',
        epilog='Example: tshunter query --browser chrome --version 143.0.7499.169 --platform linux --arch x86_64',
        runner=lambda args: query_mod.main(args.forward),
    )

    _add_forwarding_subparser(
        sub,
        'relocate',
        help_text='Run fingerprint-based relocate scan',
        description='Use baseline fingerprints to relocate hook RVAs in a nearby browser binary.',
        epilog='Example: tshunter relocate --binary /path/chrome --baseline tests/golden/hooks/chrome_143...json --scan-only',
        runner=lambda args: _run_script(ROOT / 'tshunter' / 'relocate.py', args.forward),
    )

    _add_forwarding_subparser(
        sub,
        'merge',
        help_text='Merge auto-analysis output with baseline metadata',
        description='Combine auto-generated hook results with baseline metadata for runtime compatibility.',
        epilog='Example: tshunter merge --auto results/chrome.json --baseline tests/golden/hooks/chrome_143...json --version 143.0.7499.169 --out merged.json',
        runner=lambda args: _run_script(ROOT / 'tshunter' / 'merge.py', args.forward),
    )

    _add_forwarding_subparser(
        sub,
        'download',
        help_text='Download Chrome for Testing binaries',
        description='Download Chrome for Testing binaries and metadata for later analysis.',
        epilog='Example: tshunter download --milestones 142,143 --output-dir artifacts/chrome',
        runner=lambda args: _run_script(ROOT / 'tshunter' / 'downloader.py', args.forward),
    )

    _add_forwarding_subparser(
        sub,
        'batch',
        help_text='Batch analyze a milestone range or a binaries directory',
        description='Iterate browser versions, reuse DB hits / relocate baselines, fall back to full Ghidra analyze.',
        epilog='Example: tshunter batch --browser chrome --binaries-dir binaries/Chrome',
        runner=lambda args: batch_mod.main(args.forward),
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
