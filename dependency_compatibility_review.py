"""Inactive public-metadata pair review. Never installs or authorises a runtime."""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import re
import ssl
import sys
from typing import Any, NoReturn, Sequence
import urllib.request

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

MAX_METADATA_BYTES = 4 * 1024 * 1024
PYTHON_VERSION = '3.13.9'
PATCHED_PILLOW = '13.0.0'
REVIEWED_QUALITY_SHA256 = 'dbeedbe1f67ce1b8843de621477393f2844b0be4de874af5de0050dfa9033c79'
TARGETS = {
    'windows': dict(implementation_name='cpython', implementation_version=PYTHON_VERSION,
        os_name='nt', platform_machine='AMD64', platform_python_implementation='CPython',
        platform_release='', platform_system='Windows', platform_version='',
        python_version='3.13', python_full_version=PYTHON_VERSION, sys_platform='win32', extra=''),
    'linux': dict(implementation_name='cpython', implementation_version=PYTHON_VERSION,
        os_name='posix', platform_machine='x86_64', platform_python_implementation='CPython',
        platform_release='', platform_system='Linux', platform_version='',
        python_version='3.13', python_full_version=PYTHON_VERSION, sys_platform='linux', extra=''),
}


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('DUPLICATE_METADATA_KEY')
        result[key] = value
    return result


def quality_contract(text: str) -> bool:
    """One exact reviewed workflow, not a general-purpose YAML validator.

    Complete normalized bytes reject equivalent quoted keys/aliases and scope
    changes too. A legitimate workflow edit requires a new explicit review pin.
    """
    if hashlib.sha256(text.replace('\r\n', '\n').encode()).hexdigest() != REVIEWED_QUALITY_SHA256:
        return False
    audit = '      - run: python -m pip_audit -r requirements.txt'
    lines = text.replace('\r\n', '\n').splitlines()
    if (lines.count(audit) != 1 or text.count('pip_audit') != 1
            or any(token in text for token in ('continue-on-error', '--ignore-vuln',
                '--no-deps', '--disable-pip', 'shell:', 'defaults:', 'if:', 'PIP_AUDIT', 'PIP_NO_DEPS',
                'working-directory:', 'BASH_ENV', 'PYTHONPATH'))):
        return False
    try:
        indexes = [lines.index(line) for line in (
            '      - run: python -m pytest -q',
            '      - run: python resilience_acceptance.py --game-day', audit,
            '      - run: python deployment_canary.py', '      - run: python package_release.py')]
        return indexes == sorted(indexes) and len(set(indexes)) == len(indexes)
    except ValueError:
        return False


def _info(value: object, project: str, version: str, python_version: str = PYTHON_VERSION) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get('info'), dict):
        raise ValueError('METADATA_SHAPE_INVALID')
    info = value['info']
    if info.get('name', '').lower() != project or info.get('version') != version:
        raise ValueError('METADATA_IDENTITY_MISMATCH')
    python = info.get('requires_python')
    requirements = info.get('requires_dist')
    if (not isinstance(python, str) or len(python) > 256
            or not isinstance(requirements, (list, type(None)))
            or requirements is not None and (len(requirements) > 256 or any(
                not isinstance(item, str) or len(item) > 4096 for item in requirements))):
        raise ValueError('METADATA_REQUIREMENTS_INVALID')
    if not SpecifierSet(python).contains(python_version, prereleases=False):
        raise ValueError('PYTHON_REQUIREMENT_NOT_MET')
    files = value.get('urls')
    if not isinstance(files, list) or not files or len(files) > 512 or not any(
            isinstance(item, dict) and item.get('yanked') is False for item in files):
        raise ValueError('NON_YANKED_DISTRIBUTION_NOT_ESTABLISHED')
    return dict(info)


def assess_pair(streamlit: object, pillow: object, version: str = '1.62.0', target: str = 'both',
        python_version: str = PYTHON_VERSION, pillow_version: str = PATCHED_PILLOW) -> dict[str, Any]:
    report: dict[str, Any] = dict(status='BLOCKED', code='DEPENDENCY_COMPATIBILITY_REVIEW_REQUIRED',
        package_graph_verified=False, audit_verified=False, install_authorised=False,
        approval_authority=False, writes=0, credential_reads=0)
    try:
        if re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', version) is None:
            raise ValueError('REVIEWED_STABLE_VERSION_REQUIRED')
        if python_version not in ('3.13.9', '3.13.16') or re.fullmatch(
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', pillow_version) is None:
            raise ValueError('EXPLICIT_INTERPRETER_AND_CANDIDATE_REQUIRED')
        info = _info(streamlit, 'streamlit', version, python_version)
        _info(pillow, 'pillow', pillow_version, python_version)
        if target not in ('both', *TARGETS):
            raise ValueError('EXPLICIT_TARGET_REQUIRED')
        selected = tuple(TARGETS) if target == 'both' else (target,)
        environments = {name: {**TARGETS[name], 'python_full_version': python_version,
            'implementation_version': python_version} for name in selected}
        constraints: dict[str, list[str]] = {name: [] for name in selected}
        for raw in info['requires_dist'] or []:
            requirement = Requirement(raw)
            if requirement.url is not None:
                raise ValueError('DIRECT_URL_REQUIREMENT_REVIEW_REQUIRED')
            if requirement.name.lower() == 'pillow':
                if requirement.marker is not None and re.search(
                        r'\b(platform_release|platform_version|extras|dependency_groups)\b', str(requirement.marker)):
                    raise ValueError('TARGET_MARKER_CONTEXT_UNVERIFIED')
                for name in selected:
                    if requirement.marker is None or requirement.marker.evaluate(dict(environments[name])):
                        constraints[name].append(str(requirement.specifier))
        if any(not values for values in constraints.values()):
            raise ValueError('ACTIVE_PILLOW_REQUIREMENT_NOT_ESTABLISHED')
        target_results = {name: dict(pillow_specifiers=values,
            compatible=all(SpecifierSet(item).contains(pillow_version, prereleases=False) for item in values))
            for name, values in constraints.items()}
        compatible = all(value['compatible'] for value in target_results.values())
        report.update(status='PAIR_METADATA_COMPATIBLE_NOT_FULL_GRAPH' if compatible else 'BLOCKED',
            code='FULL_RESOLUTION_AND_AUDIT_STILL_REQUIRED' if compatible else 'STREAMLIT_PILLOW_REQUIREMENT_CONFLICT',
            streamlit_version=version, candidate_pillow_version=pillow_version,
            python_version=python_version, pillow_specifiers=sorted({item for values in constraints.values() for item in values}),
            target_results=target_results, target_environments=environments,
            pair_metadata_compatible=compatible,
            public_metadata_sha256=hashlib.sha256(json.dumps([streamlit, pillow],
                sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest())
    except Exception:
        # No raw metadata, exceptions, request/response headers, URLs or paths.
        pass
    return report


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
            headers: Any, newurl: str) -> None:
        raise ValueError('PUBLIC_METADATA_REDIRECT_REJECTED')


def public_metadata(project: str, version: str | None) -> object:
    if project not in ('streamlit', 'pillow') or (version is not None and re.fullmatch(
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', version) is None):
        raise ValueError('PUBLIC_METADATA_TARGET_REJECTED')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context), _NoRedirect())
    request = urllib.request.Request('https://pypi.org/pypi/' + project + ('/' + version if version else '') + '/json',
        headers={'Accept': 'application/json', 'User-Agent': 'InactiveDependencyPairReview/1'})
    with opener.open(request, timeout=20) as response:
        if response.status != 200:
            raise ValueError('PUBLIC_METADATA_STATUS_REJECTED')
        raw = response.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError('PUBLIC_METADATA_BYTE_BOUND')
    return json.loads(raw, object_pairs_hook=unique)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError('INVALID_ARGUMENTS')


def inspect_runtime() -> dict[str, Any]:
    versions: dict[str, str] = {}
    for project in ('certifi', 'pillow', 'streamlit'):
        try:
            parsed = Version(metadata.version(project))
            versions[project] = parsed.public if parsed.local is None else 'LOCAL_BUILD_REQUIRES_REVIEW'
        except metadata.PackageNotFoundError:
            versions[project] = 'ABSENT'
        except Exception:
            versions[project] = 'UNVERIFIED'
    return dict(status='INSTALLED_METADATA_ONLY_NOT_RUNTIME_ACCEPTANCE', versions=versions,
        python_version='.'.join(str(part) for part in sys.version_info[:3]),
        package_graph_verified=False, approval_authority=False, writes=0,
        credential_reads=0, network_calls=0, capture_state_reads=0, environment_identity_verified=False)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument('--probe-public-pair', action='store_true')
    parser.add_argument('--confirm-public-network', action='store_true')
    parser.add_argument('--streamlit-version', default='1.62.0')
    parser.add_argument('--target', choices=('windows', 'linux', 'both'), default='both')
    parser.add_argument('--python-version', choices=('3.13.9', '3.13.16'), default=PYTHON_VERSION)
    parser.add_argument('--inspect-runtime', action='store_true')
    parser.add_argument('--confirm-metadata-read', action='store_true')
    try:
        args = parser.parse_args(argv)
    except Exception:
        print(json.dumps(dict(status='BLOCKED', code='PUBLIC_PROBE_ARGUMENTS_REJECTED',
            network_calls=0, writes=0, credential_reads=0, install_authorised=False)))
        return 2
    if (args.inspect_runtime or args.confirm_metadata_read) and (args.probe_public_pair or args.confirm_public_network):
        print(json.dumps(dict(status='BLOCKED', code='ONE_EXPLICIT_OPERATION_REQUIRED', writes=0,
            network_calls=0, credential_reads=0)))
        return 2
    if args.inspect_runtime and args.confirm_metadata_read:
        print(json.dumps(inspect_runtime(), sort_keys=True))
        return 0
    if not (args.probe_public_pair and args.confirm_public_network):
        print(json.dumps(dict(status='PREVIEW', network_calls=0, input_reads=0,
            credential_reads=0, writes=0, install_authorised=False, approval_authority=False)))
        return 0
    calls = 0
    try:
        if re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', args.streamlit_version) is None:
            raise ValueError('REVIEWED_STABLE_VERSION_REQUIRED')
        calls += 1
        first = public_metadata('streamlit', args.streamlit_version)
        calls += 1
        second = public_metadata('pillow', PATCHED_PILLOW)
        result = assess_pair(first, second, args.streamlit_version, args.target, args.python_version)
    except Exception:
        result = dict(status='BLOCKED', code='PUBLIC_METADATA_UNVERIFIED',
            install_authorised=False, approval_authority=False, writes=0, credential_reads=0)
    result['network_calls_attempted'] = calls
    print(json.dumps(result, sort_keys=True))
    return 2 if result['status'] == 'BLOCKED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
