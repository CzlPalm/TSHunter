from __future__ import annotations

import pytest

from tshunter import downloader


def test_cft_all_list_can_filter_one_milestone(monkeypatch, capsys):
    seen = {}

    def fake_known_good(milestone_filter=None):
        seen['filter'] = milestone_filter
        records = [
            {
                'milestone': '143',
                'version': '143.0.7499.169',
                'url': 'https://example.test/143.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
            {
                'milestone': '144',
                'version': '144.0.7559.1',
                'url': 'https://example.test/144.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
        ]
        if milestone_filter is None:
            return records
        return [item for item in records if item['milestone'] in milestone_filter]

    monkeypatch.setattr(downloader, '_fetch_cft_known_good', fake_known_good)

    rc = downloader.main(['--source', 'cft-all', '--milestones', '143', '--list'])

    out = capsys.readouterr().out
    assert rc == 0
    assert seen['filter'] == {'143'}
    assert '143.0.7499.169' in out
    assert '144.0.7559.1' not in out


def test_cft_all_list_can_filter_full_version_range(monkeypatch, capsys):
    def fake_known_good(milestone_filter=None):
        assert milestone_filter is None
        return [
            {
                'milestone': '143',
                'version': '143.0.7498.2',
                'url': 'https://example.test/143-old.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
            {
                'milestone': '143',
                'version': '143.0.7499.0',
                'url': 'https://example.test/143-start.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
            {
                'milestone': '143',
                'version': '143.0.7499.146',
                'url': 'https://example.test/143-end.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
            {
                'milestone': '143',
                'version': '143.0.7499.169',
                'url': 'https://example.test/143-after.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
        ]

    monkeypatch.setattr(downloader, '_fetch_cft_known_good', fake_known_good)

    rc = downloader.main([
        '--source', 'cft-all',
        '--version-range', '143.0.7499.0..143.0.7499.146',
        '--list',
    ])

    out = capsys.readouterr().out
    assert rc == 0
    assert '143.0.7498.2' not in out
    assert '143.0.7499.0' in out
    assert '143.0.7499.146' in out
    assert '143.0.7499.169' not in out


def test_cft_all_list_can_filter_explicit_versions(monkeypatch, capsys):
    def fake_known_good(milestone_filter=None):
        return [
            {
                'milestone': '143',
                'version': '143.0.7499.0',
                'url': 'https://example.test/143-a.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
            {
                'milestone': '143',
                'version': '143.0.7499.146',
                'url': 'https://example.test/143-b.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
            {
                'milestone': '143',
                'version': '143.0.7499.169',
                'url': 'https://example.test/143-c.zip',
                'platform': 'linux64',
                'binary': 'chrome',
            },
        ]

    monkeypatch.setattr(downloader, '_fetch_cft_known_good', fake_known_good)

    rc = downloader.main([
        '--source', 'cft-all',
        '--versions', '143.0.7499.0,143.0.7499.146',
        '--list',
    ])

    out = capsys.readouterr().out
    assert rc == 0
    assert '143.0.7499.0' in out
    assert '143.0.7499.146' in out
    assert '143.0.7499.169' not in out


def test_download_requires_selector_when_not_listing():
    with pytest.raises(SystemExit):
        downloader.parse_args(['--source', 'cft-all'])


def test_all_and_milestones_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        downloader.parse_args(['--all', '--milestones', '143'])
