"""One explicit 30-to-38 public-source migration, never private-copy admission."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, NoReturn, Sequence

import standalone_backup_contract as gate

BASE = '70629fcc2a98814d6e0d8ea760ba27b70e5c819b'
PRIOR_MANIFEST_SHA256 = 'ae48c936dd642db90f91f0e32e030f3802fa06124fe3ce96f58d1ffc6d9d50a1'
ADDED = frozenset(('capture_roots_preserve.py', 'tests/test_capture_roots_preserve.py',
    'backup_capacity_assessment.py', 'tests/test_backup_capacity_assessment.py',
    'sql/backup_capacity_sample_read_only.sql', 'capture_preservation_upload_check.py',
    'tests/test_capture_preservation_upload_check.py', 'CAPTURE_PRESERVATION.md'))
MODIFIED = frozenset(('standalone_backup_contract.py', 'standalone_backup_launch.py',
    'README.md', 'VERIFICATION.md', gate.MANIFEST))


def check(root: Path, base: str | None) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    try:
        if base != BASE or gate.git(root, 'rev-parse', '--verify', 'HEAD').decode().strip() != BASE:
            raise ValueError('EXACT_PRESERVATION_BASE_REQUIRED')
        if Path(gate.git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != root.resolve():
            raise ValueError('PRESERVATION_ROOT_REQUIRED')
        raw = gate.git(root, 'show', BASE + ':' + gate.MANIFEST)
        if gate.sha(raw) != PRIOR_MANIFEST_SHA256:
            raise ValueError('PRIOR_DISTRIBUTION_ANCHOR_REQUIRED')
        old = json.loads(raw, object_pairs_hook=gate.unique)
        old_names = set(old['files'])
        if (set(old) != {'format', 'source_base', 'files'} or old['format'] != gate.FORMAT
                or old['source_base'] != gate.SOURCE_BASE or old['files'][gate.MANIFEST] is not None
                or old_names | ADDED != gate.FILES or old_names & ADDED or not MODIFIED <= old_names):
            raise ValueError('EXACT_PRESERVATION_SCOPE_REQUIRED')
        tree: set[str] = set()
        for line in gate.git(root, 'ls-tree', '-r', BASE).splitlines():
            match = re.fullmatch(rb'100644 blob [a-f0-9]{40}\t(.+)', line)
            if match is None or match[1].decode() in tree:
                raise ValueError('PRIOR_REGULAR_TREE_REQUIRED')
            tree.add(match[1].decode())
        if tree != old_names:
            raise ValueError('EXACT_PRIOR_TREE_REQUIRED')
        for name, expected in old['files'].items():
            if name == gate.MANIFEST:
                continue
            actual = gate.sha(gate.git(root, 'show', BASE + ':' + name))
            if actual != expected:
                failures.append(dict(rule='PRIOR_PAYLOAD_HASH', path=name, expected=expected, actual=actual))
            if name not in MODIFIED:
                for where, value in (('index', gate.git(root, 'show', ':' + name)), ('worktree', gate.read_public(root, name))):
                    actual = gate.sha(value)
                    if actual != expected:
                        failures.append(dict(rule='UNCHANGED_PREREQUISITE_HASH', path=name,
                            location=where, expected=expected, actual=actual))
        changes = set(gate.git(root, 'diff', '--cached', '--name-status', BASE, '--').decode().splitlines())
        if changes != {'A\t' + name for name in ADDED} | {'M\t' + name for name in MODIFIED}:
            raise ValueError('EXACT_PRESERVATION_CHANGES_REQUIRED')
        gate._verify_tree(root, BASE, staged=True)
    except Exception as error:
        code = error.args[0] if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str else 'PRESERVATION_PACKAGE_READ_REQUIRED'
        allowed = {'EXACT_PRESERVATION_BASE_REQUIRED', 'PRESERVATION_ROOT_REQUIRED',
            'PRIOR_DISTRIBUTION_ANCHOR_REQUIRED', 'EXACT_PRESERVATION_SCOPE_REQUIRED',
            'PRIOR_REGULAR_TREE_REQUIRED', 'EXACT_PRIOR_TREE_REQUIRED', 'EXACT_PRESERVATION_CHANGES_REQUIRED',
            *gate.SAFE_CODES}
        failures.append(dict(rule=code if code in allowed else 'PRESERVATION_PACKAGE_READ_REQUIRED'))
    return dict(status='BLOCKED' if failures else 'CAPTURE_PRESERVATION_PACKAGE_VERIFIED_REQUIRES_EXACT_SHA_CI',
        failures=failures, source_base=BASE, hosted_changes=0, private_copy_authorized=False,
        native_acceptance_verified=False, custody_verified=False, restore_verified=False, deletion_authorised=False)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError('INVALID_ARGUMENTS')


def main(argv: Sequence[str] | None = None) -> int:
    try:
        parser = _Parser(allow_abbrev=False)
        parser.add_argument('--base', required=True)
        args = parser.parse_args(argv)
        result = check(Path.cwd(), args.base)
    except Exception:
        result = dict(status='BLOCKED', failures=[dict(rule='INVALID_ARGUMENTS')], private_copy_authorized=False)
    print(json.dumps(result, sort_keys=True))
    return 2 if result['status'] == 'BLOCKED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
