"""Opt-in bounded public metadata watch. No installation, state, credentials or tasks."""
from __future__ import annotations

import argparse
import json
import re
from typing import Any, NoReturn, Sequence

from packaging.version import Version

from dependency_compatibility_review import assess_pair, public_metadata


def stable(value: object) -> str:
    if type(value) is not str or re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', value) is None:
        raise ValueError('STABLE_PUBLIC_VERSION_REQUIRED')
    return value


def watch_once() -> dict[str, Any]:
    calls = 0
    def fetch(project: str, version: str | None) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls > 5:
            raise ValueError('PUBLIC_CALL_BOUND')
        value = public_metadata(project, version)
        if type(value) is not dict or type(value.get('info')) is not dict:
            raise ValueError('PUBLIC_METADATA_SHAPE_REQUIRED')
        return value
    result: dict[str, Any] = dict(status='PUBLIC_PAIR_WATCH_UNVERIFIED', notify_candidate=False,
        package_graph_verified=False, full_audit_verified=False, install_authorised=False,
        approval_authority=False, writes=0, credential_reads=0, capture_state_reads=0)
    try:
        first = fetch('streamlit', None)
        latest_streamlit = stable(first['info'].get('version'))
        pinned = first if latest_streamlit == '1.62.0' else fetch('streamlit', '1.62.0')
        latest = fetch('pillow', None)
        candidates = [(stable(latest['info'].get('version')), latest)]
        releases = latest.get('releases')
        if type(releases) is not dict or len(releases) > 1024:
            raise ValueError('PUBLIC_RELEASE_BOUND')
        backports = [name for name, files in releases.items() if type(name) is str
            and re.fullmatch(r'12\.[0-9]{1,3}\.[0-9]{1,3}', name) and files
            and Version(name) > Version('12.3.0')]
        if backports:
            backport = max(backports, key=Version)
            candidates.append((backport, fetch('pillow', backport)))
        # Always evaluate the reviewed fixed release if latest has moved further.
        if candidates[0][0] != '13.0.0':
            candidates.append(('13.0.0', fetch('pillow', '13.0.0')))
        pairs: list[dict[str, str]] = []
        for pillow_version, pillow in candidates:
            # Missing advisory data is UNKNOWN, not "no vulnerabilities".
            if type(pillow.get('vulnerabilities')) is not list:
                raise ValueError('PUBLIC_ADVISORY_COVERAGE_UNVERIFIED')
            if pillow['vulnerabilities']:
                continue
            for streamlit_version, streamlit in ((latest_streamlit, first), ('1.62.0', pinned)):
                reports = [assess_pair(streamlit, pillow, streamlit_version, 'both',
                    python_version, pillow_version) for python_version in ('3.13.9', '3.13.16')]
                if all(report.get('pair_metadata_compatible') is True for report in reports):
                    pair = dict(streamlit=streamlit_version, pillow=pillow_version)
                    if pair not in pairs:
                        pairs.append(pair)
        result.update(status='PUBLIC_PAIR_CANDIDATE_REQUIRES_FULL_REVIEW' if pairs else
            'PUBLIC_PAIR_WATCH_UNCHANGED_BLOCKED', notify_candidate=bool(pairs), candidates=pairs,
            tested_python_versions=['3.13.9', '3.13.16'],
            tested_platforms=['windows', 'linux'])
    except Exception:
        # Fixed classification only; no exception, URLs, response bytes or paths.
        pass
    result['network_calls_attempted'] = calls
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError('INVALID_ARGUMENTS')


def main(argv: Sequence[str] | None = None) -> int:
    try:
        parser = _Parser(description=__doc__)
        parser.add_argument('--confirm-public-network', action='store_true')
        args = parser.parse_args(argv)
        result = watch_once() if args.confirm_public_network else dict(status='PREVIEW',
            input_reads=0, network_calls=0, writes=0, credential_reads=0, install_authorised=False)
    except Exception:
        result = dict(status='PUBLIC_PAIR_WATCH_UNVERIFIED', notify_candidate=False,
            raw_error_printed=False, install_authorised=False, writes=0)
    print(json.dumps(result, sort_keys=True))
    return 2 if result['status'] == 'PUBLIC_PAIR_WATCH_UNVERIFIED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
