from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, '-m', 'tshunter.cli', *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


def test_root_help_succeeds():
    result = _run('--help')
    assert result.returncode == 0
    assert 'command' in result.stdout
    assert 'analyze' in result.stdout
    assert 'capture' in result.stdout


def test_all_subcommand_help_succeeds():
    commands = ['analyze', 'capture', 'ingest', 'query', 'relocate', 'merge', 'download', 'batch']
    for cmd in commands:
        result = _run(cmd, '--help')
        assert result.returncode == 0, f'{cmd} help failed: {result.stderr}'
        assert 'usage:' in result.stdout.lower()


def test_batch_help_shows_description():
    result = _run('batch', '--help')
    assert result.returncode == 0
    assert 'batch' in result.stdout.lower()


def test_forwarded_help_with_separator_succeeds():
    cases = [
        ('analyze', '--help'),
        ('ingest', '--help'),
        ('query', '--help'),
        ('batch', '--help'),
        ('download', '--help'),
        ('relocate', 'scan', '--help'),
    ]
    for case in cases:
        result = _run(case[0], '--', *case[1:])
        assert result.returncode == 0, f'{case} forwarded help failed: {result.stderr}'
        assert 'usage:' in result.stdout.lower()


def test_forwarded_options_without_separator_reach_download(monkeypatch):
    from tshunter import cli

    seen = {}

    def fake_download_runner(path, forward_args):
        seen['path'] = path
        seen['forward_args'] = forward_args

    monkeypatch.setattr(cli, '_run_script', fake_download_runner)

    rc = cli.main(['download', '--source', 'cft-all', '--milestones', '143', '--list'])

    assert rc is None
    assert seen['forward_args'] == ['--', '--source', 'cft-all', '--milestones', '143', '--list']


def test_batch_empty_binaries_dir_exits_nonzero(tmp_path):
    result = subprocess.run(
        [sys.executable, '-m', 'tshunter.cli', 'batch',
         '--browser', 'chrome', '--binaries-dir', str(tmp_path)],
        capture_output=True, text=True, cwd=str(ROOT),
    )
    assert result.returncode != 0


def test_installed_entrypoint_exists_after_editable_install():
    # This is a smoke assertion for environments where `pip install -e .` has already run.
    # We do not force installation inside the test itself; acceptance does that explicitly.
    maybe = shutil.which('tshunter')
    if maybe is not None:
        result = subprocess.run(['tshunter', '--help'], capture_output=True, text=True)
        assert result.returncode == 0
        assert 'analyze' in result.stdout


def test_no_args_errors_with_usage():
    result = _run()
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert 'usage:' in combined.lower()


def test_unknown_subcommand_errors():
    result = _run('not-a-real-cmd')
    assert result.returncode != 0
