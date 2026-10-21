"""Inactive separate-distribution gate. No app-audit exception or backup admission."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, NoReturn, Sequence

SOURCE_BASE = '563665a32e5454633b0c27256072a7249503c520'
EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
SEED_README = b'# Standalone backup review seed\n\nNo executable tooling; no backup authority.\n'
SOURCE_MANIFEST = 'BACKUP_STANDALONE_UPLOAD.json'
MANIFEST = 'BACKUP_TOOL_DISTRIBUTION.json'
FORMAT = 'standalone-backup-distribution-v1'
MAP = {
    'live_database_backup.py': 'live_database_backup.py',
    'live_backup_conformance.py': 'live_backup_conformance.py',
    'archive_preservation_inventory.py': 'archive_preservation_inventory.py',
    'archive_preservation_witness.py': 'archive_preservation_witness.py',
    'programme_next_upload_check.py': 'programme_next_upload_check.py',
    'live_backup_upload_check.py': 'live_backup_upload_check.py',
    'standalone_backup_contract.py': 'standalone_backup_contract.py',
    'standalone_backup_launch.py': 'standalone_backup_launch.py',
    'dependency_compatibility_review.py': 'dependency_compatibility_review.py',
    'dependency_pair_watch.py': 'dependency_pair_watch.py',
    'dependency_pair_watch.ps1': 'dependency_pair_watch.ps1',
    'backup_artifact_contract.py': 'backup_artifact_contract.py',
    'capture_roots_preserve.py': 'capture_roots_preserve.py',
    'tests/test_capture_roots_preserve.py': 'tests/test_capture_roots_preserve.py',
    'backup_capacity_assessment.py': 'backup_capacity_assessment.py',
    'tests/test_backup_capacity_assessment.py': 'tests/test_backup_capacity_assessment.py',
    'sql/backup_capacity_sample_read_only.sql': 'sql/backup_capacity_sample_read_only.sql',
    'capture_preservation_upload_check.py': 'capture_preservation_upload_check.py',
    'tests/test_capture_preservation_upload_check.py': 'tests/test_capture_preservation_upload_check.py',
    'CAPTURE_PRESERVATION_2026-10-21.md': 'CAPTURE_PRESERVATION.md',
    'backup_delivery_templates/artifact-interface.json': 'BACKUP_ARTIFACT_INTERFACE.json',
    'tests/test_backup_artifact_contract.py': 'tests/test_backup_artifact_contract.py',
    'tests/test_live_database_backup.py': 'tests/test_live_database_backup.py',
    'tests/test_live_backup_conformance.py': 'tests/test_live_backup_conformance.py',
    'tests/test_archive_preservation_inventory.py': 'tests/test_archive_preservation_inventory.py',
    'tests/test_archive_preservation_witness.py': 'tests/test_archive_preservation_witness.py',
    'tests/test_standalone_backup_contract.py': 'tests/test_standalone_backup_contract.py',
    'tests/test_dependency_pair_watch.py': 'tests/test_dependency_pair_watch.py',
    'backup_delivery_templates/requirements-runtime.txt': 'requirements-runtime.txt',
    'backup_delivery_templates/requirements-test.txt': 'requirements-test.txt',
    'backup_delivery_templates/quality.yml': '.github/workflows/quality.yml',
    'backup_delivery_templates/codeql.yml': '.github/workflows/codeql.yml',
    'backup_delivery_templates/native.yml': '.github/workflows/live-backup-conformance.yml',
    'backup_delivery_templates/advisory.yml': '.github/workflows/advisory.yml',
    'BACKUP_DELIVERY_DECISION_2026-10-21.md': 'README.md',
    'STANDALONE_NATIVE_RUNBOOK_2026-10-21.md': 'NATIVE_EXPORT_RUNBOOK.md',
    'BACKUP_DELIVERY_VERIFICATION_2026-10-21.md': 'VERIFICATION.md',
}
FILES = frozenset((*MAP.values(), MANIFEST))
HASH = re.compile('[a-f0-9]{64}')
SAFE_CODES = frozenset(('PUBLIC_ALLOWLIST_REQUIRED', 'NONLINK_PUBLIC_TREE_REQUIRED',
    'BOUNDED_SINGLE_LINK_PUBLIC_FILE_REQUIRED', 'PUBLIC_FILE_CHANGED', 'PUBLIC_GIT_CHECK_REQUIRED',
    'EXACT_DISTRIBUTION_REQUIRED', 'REVIEWED_SOURCE_REQUIRED', 'EXACT_INERT_BOOTSTRAP_BASE_REQUIRED',
    'REGULAR_STAGE_ZERO_REQUIRED', 'DUPLICATE_TRACKED_FILE', 'DISTRIBUTION_HASH_REQUIRED',
    'EXACT_STAGED_TREE_REQUIRED', 'REVIEWED_IMPORT_CLOSURE_REQUIRED', 'SOURCE_MANIFEST_REQUIRED',
    'SOURCE_PAYLOAD_HASH_REQUIRED', 'NEW_LOCAL_PUBLIC_DESTINATION_REQUIRED',
    'NONLINK_PUBLIC_DESTINATION_REQUIRED', 'PUBLIC_EXPORT_INCOMPLETE', 'INVALID_ARGUMENTS',
    'ONE_EXPLICIT_OPERATION_REQUIRED', 'DUPLICATE_KEY', 'PERSONAL_HOME_PATH_IN_PUBLIC_PAYLOAD',
    'EXACT_REVIEWED_PRIOR_RELEASE_REQUIRED', 'PRIVATE_CREDENTIAL_NAME_REJECTED'))


def public_name(name: str) -> None:
    """Reject reserved private names before file metadata or contents are read.

    Exact distribution admission remains mandatory. This is defense in depth,
    not a guarantee that arbitrary renamed secrets can be detected without DLP.
    """
    if ':' in name:
        raise ValueError('PRIVATE_CREDENTIAL_NAME_REJECTED')
    for part in name.replace('\\', '/').casefold().split('/'):
        if (part.startswith(('client_secret', 'token.json', 'credentials.json', 'secrets.toml'))
                or part == '.env' or part.startswith('.env.')):
            raise ValueError('PRIVATE_CREDENTIAL_NAME_REJECTED')


def public_privacy(payloads: dict[str, bytes]) -> None:
    """Reject literal home-profile paths in ALL public payloads; not secret DLP.

    Fixed service identities, OS installation paths and synthetic fixtures still
    require human review. Do not print the matched value or inferred username.
    """
    for name in payloads:
        public_name(name)
    pattern = re.compile(rb'(?i)(?:[a-z]:[\\/]+users[\\/]+|/(?:home|users)/)[^\\/\s\x22\x27]+')
    if any(pattern.search(raw) for raw in payloads.values()):
        raise ValueError('PERSONAL_HOME_PATH_IN_PUBLIC_PAYLOAD')


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw.replace(b'\r\n', b'\n')).hexdigest()


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('DUPLICATE_KEY')
        result[key] = value
    return result


def read_public(root: Path, name: str) -> bytes:
    public_name(name)
    if name not in {*MAP, *FILES, SOURCE_MANIFEST}:
        raise ValueError('PUBLIC_ALLOWLIST_REQUIRED')
    path = root / name
    for item in (path, *path.parents):
        item_stat = item.lstat()
        if stat.S_ISLNK(item_stat.st_mode) or getattr(item_stat, 'st_file_attributes', 0) & 0x400:
            raise ValueError('NONLINK_PUBLIC_TREE_REQUIRED')
        if item == root:
            break
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 2**20:
        raise ValueError('BOUNDED_SINGLE_LINK_PUBLIC_FILE_REQUIRED')
    raw = path.read_bytes()
    after = path.stat()
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(raw) != before.st_size):
        raise ValueError('PUBLIC_FILE_CHANGED')
    return raw


def git(root: Path, *args: str, absent_head: bool = False) -> bytes:
    env = {key: value for key, value in os.environ.items() if key.upper() in
        ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull, GIT_GRAFT_FILE=os.devnull)
    result = subprocess.run(('git', '--no-replace-objects', '--no-optional-locks', '-c', 'core.fsmonitor=false',
        '-C', str(root), *args), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=15, check=False)
    if absent_head and result.returncode == 128:
        return b''
    if result.returncode or len(result.stdout) > 4 * 2**20:
        raise ValueError('PUBLIC_GIT_CHECK_REQUIRED')
    return result.stdout


def distribution(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'format', 'source_base', 'files'}
            or value['format'] != FORMAT or value['source_base'] != SOURCE_BASE
            or type(value['files']) is not dict or set(value['files']) != FILES
            or value['files'][MANIFEST] is not None
            or any(type(digest) is not str or HASH.fullmatch(digest) is None
                for name, digest in value['files'].items() if name != MANIFEST)):
        raise ValueError('EXACT_DISTRIBUTION_REQUIRED')
    return value


def verify_checkout(root: Path, expected_sha: str | None, staged: bool = False) -> None:
    if (type(expected_sha) is not str or re.fullmatch('[a-f0-9]{40}', expected_sha) is None
            or not staged and expected_sha == EMPTY_TREE):
        raise ValueError('REVIEWED_SOURCE_REQUIRED')
    if Path(git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != root.resolve():
        raise ValueError('REVIEWED_SOURCE_REQUIRED')
    head = git(root, 'rev-parse', '--verify', 'HEAD', absent_head=staged).decode().strip()
    _index_names(root)
    if staged:
        if expected_sha == EMPTY_TREE:
            if head:
                raise ValueError('REVIEWED_SOURCE_REQUIRED')
        elif (head != expected_sha or re.fullmatch(rb'100644 blob [a-f0-9]{40}\tREADME.md\n',
                git(root, 'ls-tree', '-r', expected_sha)) is None
                or git(root, 'show', expected_sha + ':README.md') != SEED_README):
            raise ValueError('EXACT_INERT_BOOTSTRAP_BASE_REQUIRED')
    elif head != expected_sha:
        raise ValueError('REVIEWED_SOURCE_REQUIRED')
    _verify_tree(root, expected_sha, staged)


def verify_update(root: Path, expected_base: str | None) -> None:
    """Separate maintenance admission; never widens the inert-seed gate.

    Owner supplies the previously approved release SHA, not arbitrary HEAD. Both
    prior committed distribution and candidate index/worktree must be complete.
    Scope/format migrations fail closed and need their own reviewed gate change.
    """
    if (type(expected_base) is not str or re.fullmatch('[a-f0-9]{40}', expected_base) is None
            or expected_base == EMPTY_TREE
            or Path(git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != root.resolve()
            or git(root, 'rev-parse', '--verify', 'HEAD').decode().strip() != expected_base):
        raise ValueError('EXACT_REVIEWED_PRIOR_RELEASE_REQUIRED')
    _index_names(root)  # admit ALL candidate names before predecessor payload reads
    previous = distribution(git(root, 'show', expected_base + ':' + MANIFEST))
    records = git(root, 'ls-tree', '-r', expected_base).splitlines()
    names: set[str] = set()
    for record in records:
        match = re.fullmatch(rb'100644 blob [a-f0-9]{40}\t(.+)', record)
        if match is None or match[1].decode() in names:
            raise ValueError('EXACT_REVIEWED_PRIOR_RELEASE_REQUIRED')
        names.add(match[1].decode())
    if names != FILES:
        raise ValueError('EXACT_REVIEWED_PRIOR_RELEASE_REQUIRED')
    for name, digest in previous['files'].items():
        if name != MANIFEST and sha(git(root, 'show', expected_base + ':' + name)) != digest:
            raise ValueError('EXACT_REVIEWED_PRIOR_RELEASE_REQUIRED')
    interface = 'BACKUP_ARTIFACT_INTERFACE.json'
    if interface in FILES and sha(git(root, 'show', expected_base + ':' + interface)) != sha(read_public(root, interface)):
        raise ValueError('EXACT_REVIEWED_PRIOR_RELEASE_REQUIRED')
    _verify_tree(root, expected_base, staged=True)


def _index_names(root: Path) -> set[str]:
    """Name/mode admission only; no payload metadata/content reads."""
    tracked = git(root, 'ls-files', '--stage', '-z').split(b'\0')
    names: set[str] = set()
    for line in filter(None, tracked):
        match = re.fullmatch(rb'100644 [a-f0-9]{40} 0\t(.+)', line)
        if match is None:
            raise ValueError('REGULAR_STAGE_ZERO_REQUIRED')
        name = match[1].decode('utf-8')
        public_name(name)
        if name in names:
            raise ValueError('DUPLICATE_TRACKED_FILE')
        names.add(name)
    if names != FILES:
        raise ValueError('EXACT_DISTRIBUTION_REQUIRED')
    return names


def _verify_tree(root: Path, expected_sha: str, staged: bool) -> None:
    if not staged and git(root, 'status', '--porcelain', '--untracked-files=all').strip():
        raise ValueError('REVIEWED_SOURCE_REQUIRED')
    # No --exclude-standard: ignored files/bytecode are not outside this gate.
    if git(root, 'ls-files', '--others').strip():
        raise ValueError('EXACT_STAGED_TREE_REQUIRED')
    _index_names(root)
    value = distribution(read_public(root, MANIFEST))
    public_privacy({name: read_public(root, name) for name in FILES})
    prefix = ':' if staged else expected_sha + ':'
    for name, digest in value['files'].items():
        current = read_public(root, name)
        indexed = git(root, 'show', prefix + name)
        if sha(current) != sha(indexed) or name != MANIFEST and sha(current) != digest:
            raise ValueError('DISTRIBUTION_HASH_REQUIRED')
    if staged and (git(root, 'diff', '--name-only').strip()
            or git(root, 'ls-files', '--others', '--exclude-standard').strip()):
        raise ValueError('EXACT_STAGED_TREE_REQUIRED')


def import_closure(payloads: dict[str, bytes]) -> list[str]:
    """Static import inventory, not a sandbox or dynamic-code safety proof."""
    modules = {Path(name).stem for name in payloads if '/' not in name and name.endswith('.py')}
    external: set[str] = set()
    for name, raw in payloads.items():
        if name.endswith('.py'):
            for node in ast.walk(ast.parse(raw, filename=name)):
                names = [item.name for item in node.names] if isinstance(node, ast.Import) else (
                    [node.module or ''] if isinstance(node, ast.ImportFrom) else [])
                for imported in names:
                    top = imported.split('.')[0]
                    if top and top not in modules and top not in sys.stdlib_module_names:
                        external.add(top)
    if external != {'cryptography', 'packaging', 'pytest'}:
        raise ValueError('REVIEWED_IMPORT_CLOSURE_REQUIRED')
    return sorted(external)


def export(root: Path, destination: Path) -> dict[str, Any]:
    value = json.loads(read_public(root, SOURCE_MANIFEST), object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'format', 'source_base', 'files', 'destinations'}
            or value['format'] != FORMAT or value['source_base'] != SOURCE_BASE
            or type(value['files']) is not dict or set(value['files']) != set(MAP)
            or value['destinations'] != MAP):
        raise ValueError('SOURCE_MANIFEST_REQUIRED')
    payloads: dict[str, bytes] = {}
    # Validate the complete path list before the first source payload read.
    for source, target in MAP.items():
        public_name(source)
        public_name(target)
    for source, target in MAP.items():
        raw = read_public(root, source).replace(b'\r\n', b'\n')
        if sha(raw) != value['files'][source]:
            raise ValueError('SOURCE_PAYLOAD_HASH_REQUIRED')
        payloads[target] = raw
    public_privacy(payloads)
    external = import_closure(payloads)
    if not destination.is_absolute() or str(destination).startswith(('\\\\', '//')):
        raise ValueError('NEW_LOCAL_PUBLIC_DESTINATION_REQUIRED')
    for parent in destination.parents:
        if parent.is_symlink() or getattr(parent.stat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('NONLINK_PUBLIC_DESTINATION_REQUIRED')
    destination.mkdir()  # exclusive; preserve partial output after any failure
    for name, raw in payloads.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as output:
            if output.write(raw) != len(raw):
                raise ValueError('PUBLIC_EXPORT_INCOMPLETE')
    manifest = dict(format=FORMAT, source_base=SOURCE_BASE,
        files={**{name: sha(raw) for name, raw in payloads.items()}, MANIFEST: None})
    with (destination / MANIFEST).open('xb') as output:
        output.write(json.dumps(manifest, indent=2, sort_keys=True).encode() + b'\n')
    return dict(status='PUBLIC_BACKUP_DISTRIBUTION_EXPORTED_NOT_ACCEPTED', files=len(FILES),
        static_external_imports=external, source_connections=0, credential_reads=0,
        app_audit_exception=False, backup_authorised=False, restore_verified=False)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError('INVALID_ARGUMENTS')


def main(argv: Sequence[str] | None = None) -> int:
    stage = 'ARGUMENTS'
    try:
        parser = _Parser(description=__doc__)
        parser.add_argument('--export-to')
        parser.add_argument('--confirm-public-export', action='store_true')
        parser.add_argument('--check-staged', action='store_true')
        parser.add_argument('--check-update', action='store_true')
        parser.add_argument('--verify-commit')
        parser.add_argument('--base')
        args = parser.parse_args(argv)
        if sum((bool(args.export_to or args.confirm_public_export), args.check_staged,
                args.check_update, bool(args.verify_commit))) > 1:
            raise ValueError('ONE_EXPLICIT_OPERATION_REQUIRED')
        root = Path(__file__).resolve().parent
        if args.check_staged or args.check_update or args.verify_commit:
            stage = 'PUBLIC_SOURCE_BINDING'
            if args.check_update:
                verify_update(root, args.base)
            else:
                verify_checkout(root, args.base if args.check_staged else args.verify_commit, args.check_staged)
            result = dict(status='BACKUP_SOURCE_BYTES_VERIFIED_REQUIRES_AUDIT_NATIVE_AND_EXACT_SHA_CI',
                backup_authorised=False, app_audit_exception=False, writes=0)
        elif args.export_to and args.confirm_public_export:
            stage = 'PUBLIC_DISTRIBUTION_EXPORT'
            result = export(root, Path(args.export_to))
        else:
            result = dict(status='PREVIEW', input_reads=0, writes=0, network_calls=0,
                credential_reads=0, backup_authorised=False)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        code = error.args[0] if (type(error) is ValueError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in SAFE_CODES) else 'STANDALONE_SOURCE_REVIEW_REQUIRED'
        print(json.dumps(dict(status='BLOCKED', code='STANDALONE_SOURCE_REVIEW_REQUIRED',
            stage=stage, blockers=[code],
            retry_authorised=False, raw_error_printed=False, backup_authorised=False)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
