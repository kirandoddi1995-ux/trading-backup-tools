"""Synthetic exact-base transition tests; no public or private network writes."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import capture_preservation_upload_check as migration
import standalone_backup_contract as gate


@pytest.mark.parametrize('case', ['exact', 'base', 'head', 'old_manifest', 'prior_hash', 'unchanged',
    'mode', 'prior_scope', 'changes', 'candidate'])
def test_migration_keeps_fixed_predecessor_and_all_unchanged_pins(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    old = dict(format=gate.FORMAT, source_base=gate.SOURCE_BASE,
        files={gate.MANIFEST: None, 'fixed.py': gate.sha(b'fixed'), 'changed.py': gate.sha(b'previous')})
    raw = json.dumps(old).encode()
    monkeypatch.setattr(migration, 'PRIOR_MANIFEST_SHA256', gate.sha(raw))
    monkeypatch.setattr(migration, 'ADDED', frozenset(('new.py',)))
    monkeypatch.setattr(migration, 'MODIFIED', frozenset(('changed.py', gate.MANIFEST)))
    monkeypatch.setattr(gate, 'FILES', frozenset((*old['files'], 'new.py')))
    monkeypatch.setattr(gate, 'read_public', lambda root, name: b'changed' if case == 'unchanged' else b'fixed')
    def candidate(*a: Any, **k: Any) -> None:
        if case == 'candidate':
            raise ValueError('DISTRIBUTION_HASH_REQUIRED')
    monkeypatch.setattr(gate, '_verify_tree', candidate)
    def git(root: Path, *args: str, **kwargs: Any) -> bytes:
        if args == ('rev-parse', '--verify', 'HEAD'):
            return ('b' * 40 if case == 'head' else migration.BASE).encode()
        if args == ('rev-parse', '--show-toplevel'):
            return str(root).encode()
        if args == ('show', migration.BASE + ':' + gate.MANIFEST):
            return b'{}' if case == 'old_manifest' else raw
        if args[0] == 'show':
            if args[1].endswith('changed.py'):
                return b'previous'
            return b'tampered' if case in ('prior_hash', 'unchanged') else b'fixed'
        if args[0] == 'ls-tree':
            result = b''.join(b'100644 blob ' + b'a' * 40 + b'\t' + name.encode() + b'\n'
                for name in sorted(old['files']))
            if case == 'mode':
                result = result.replace(b'100644', b'120000', 1)
            return result + b'100644 blob ' + b'a' * 40 + b'\textra\n' if case == 'prior_scope' else result
        if args[0] == 'diff':
            return b'M\tchanged.py\nM\tBACKUP_TOOL_DISTRIBUTION.json\nA\tnew.py\n' if case != 'changes' else b''
        raise AssertionError('Unexpected synthetic Git operation')
    monkeypatch.setattr(gate, 'git', git)
    result = migration.check(tmp_path, 'b' * 40 if case == 'base' else migration.BASE)
    assert result['private_copy_authorized'] is False
    assert bool(result['failures']) is (case != 'exact')


def test_migration_cli_redacts_invalid_values(capsys: pytest.CaptureFixture[str]) -> None:
    assert migration.main(['--private-sentinel']) == 2
    assert 'private-sentinel' not in capsys.readouterr().out


def test_preserve_dispatch_keeps_source_admission_first(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace
    import capture_roots_preserve
    import standalone_backup_launch as launch
    calls: list[str] = []
    gate_module = SimpleNamespace(verify_checkout=lambda *a: calls.append('source'), read_public=lambda *a: b'lock')
    monkeypatch.setattr(launch.sys, 'flags', SimpleNamespace(isolated=1, no_site=1))
    monkeypatch.setattr(launch.sys, 'dont_write_bytecode', True)
    monkeypatch.setattr(launch.sys, 'version_info', (3, 13, 9))
    monkeypatch.setattr(launch, 'trusted_gate', lambda *a: gate_module)
    monkeypatch.setattr(launch, 'runtime_site', lambda *a: Path('unused'))
    monkeypatch.setattr(launch, 'admit_runtime', lambda *a: calls.append('runtime'))
    monkeypatch.setattr(launch.sys, 'path', list(launch.sys.path))
    monkeypatch.setitem(launch.sys.modules, 'standalone_backup_contract', gate_module)
    def product(args: list[str]) -> int:
        assert args[-3:] == ['--reviewed-source', 'a' * 40, '--confirm-run']
        calls.append('dispatch')
        return 0
    monkeypatch.setattr(capture_roots_preserve, 'main', product)
    assert launch.main(['--operation', 'preserve', '--reviewed-source', 'a' * 40, '--confirm-run']) == 0
    assert calls == ['source', 'runtime', 'dispatch']
