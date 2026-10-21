from __future__ import annotations

from copy import deepcopy
import json
from typing import Any

import pytest

import dependency_compatibility_review as pair
import dependency_pair_watch as watch


def metadata(project: str, version: str, requirements: list[str] | None = None) -> dict[str, Any]:
    return dict(info=dict(name=project, version=version, requires_python='>=3.11',
        requires_dist=requirements), urls=[{'yanked': False}], vulnerabilities=[],
        releases={version: [{}]})


@pytest.mark.parametrize('version', ['3.13.9', '3.13.16'])
def test_patch_specific_marker_context_is_explicit(version: str) -> None:
    first = metadata('streamlit', '1.62.0', [
        'pillow<14; python_full_version >= "3.13.16"',
        'pillow<13; python_full_version < "3.13.16"'])
    before = deepcopy(pair.TARGETS)
    result = pair.assess_pair(first, metadata('pillow', '13.0.0'), python_version=version)
    assert result['pair_metadata_compatible'] == (version == '3.13.16')
    assert all(env['python_full_version'] == version for env in result['target_environments'].values())
    assert pair.TARGETS == before


def test_unknown_python_patch_is_not_invented() -> None:
    result = pair.assess_pair(metadata('streamlit', '1.62.0', ['pillow<14']),
        metadata('pillow', '13.0.0'), python_version='3.13.99')
    assert result['status'] == 'BLOCKED'


@pytest.mark.parametrize('case', ['blocked', 'compatible', 'backport', 'vulnerable', 'missing_advisories',
    'python_bound', 'malformed', 'network', 'prerelease', 'patch_marker'])
def test_watch_only_reports_fully_observed_pair_metadata(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    first = metadata('streamlit', '1.66.0', ['pillow<14' if case == 'compatible' else 'pillow<13'])
    pinned = metadata('streamlit', '1.62.0', ['pillow<13'])
    pillow = metadata('pillow', '13.0.0')
    if case == 'vulnerable':
        pillow['vulnerabilities'] = [{'id': 'public-advisory'}]
    if case == 'missing_advisories':
        del pillow['vulnerabilities']
    if case == 'python_bound':
        pillow['info']['requires_python'] = '>=3.14'
    if case == 'malformed':
        first = {}
    if case == 'prerelease':
        first['info']['version'] = '1.67.0rc1'
    if case == 'backport':
        pillow['releases']['12.3.1'] = [{}]
    if case == 'patch_marker':
        first['info']['requires_dist'] = ['pillow<14; python_full_version >= "3.13.16"',
            'pillow<13; python_full_version < "3.13.16"']
    calls: list[tuple[str, str | None]] = []
    def fetch(project: str, version: str | None) -> object:
        calls.append((project, version))
        if case == 'network':
            raise RuntimeError('private-sentinel')
        if project == 'streamlit':
            return pinned if version else first
        return metadata('pillow', '12.3.1') if version == '12.3.1' else pillow
    monkeypatch.setattr(watch, 'public_metadata', fetch)
    result = watch.watch_once()
    assert result['notify_candidate'] == (case in ('compatible', 'backport'))
    if case in ('missing_advisories', 'malformed', 'network', 'prerelease'):
        assert result['status'] == 'PUBLIC_PAIR_WATCH_UNVERIFIED'
    assert len(calls) <= 5
    assert result['install_authorised'] is result['full_audit_verified'] is False
    assert 'private-sentinel' not in json.dumps(result)


def test_preview_no_network_or_state(monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(watch, 'watch_once', lambda: pytest.fail('network called'))
    assert watch.main([]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'PREVIEW' and result['writes'] == result['network_calls'] == 0


def test_watch_public_targets_require_explicit_version_or_latest() -> None:
    with pytest.raises(ValueError, match='PUBLIC_METADATA_TARGET_REJECTED'):
        pair.public_metadata('private-sentinel', None)
