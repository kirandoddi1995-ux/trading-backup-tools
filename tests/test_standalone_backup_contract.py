"""Public source distribution only; no database or credential access."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

import live_database_backup as backup
import standalone_backup_contract as gate
import standalone_backup_launch as launch


def windows_source_job() -> str:
    text = (Path(__file__).resolve().parents[1] / '.github/workflows/quality.yml').read_text(encoding='utf-8')
    return text.split('  windows-directory-guard:', 1)[1]


def test_windows_checkout_selects_lf_before_materializing_source() -> None:
    job = windows_source_job()
    before, after = job.split('- uses: actions/checkout@v5', 1)
    assert 'git config --global core.autocrlf false' in before
    assert 'git config --global core.eol lf' in before
    assert before.count("if($LASTEXITCODE -ne 0)") == 2
    assert 'git config --system' not in job and 'safe.directory' not in job
    assert '--verify-commit "$env:REVIEWED_HEAD"' in after
    assert 'continue-on-error' not in job


@pytest.mark.parametrize('mismatch', ['none', 'root', 'head', 'dirty', 'git_error'])
def test_windows_source_diagnostic_is_fixed_redacted_and_not_acceptance(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mismatch: str) -> None:
    job = windows_source_job()
    match = re.search(r"          @'\n(.*?)\n          '@ \| python -B -", job, re.S)
    assert match is not None
    script = '\n'.join(line[10:] for line in match[1].splitlines())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('REVIEWED_HEAD', 'a' * 40)
    def synthetic_git(root: Path, *args: str) -> bytes:
        if mismatch == 'git_error':
            raise ValueError('private-error-must-not-print')
        if args == ('rev-parse', '--show-toplevel'):
            return str(tmp_path / 'other' if mismatch == 'root' else tmp_path).encode()
        if args == ('rev-parse', '--verify', 'HEAD'):
            return (('b' if mismatch == 'head' else 'a') * 40).encode()
        assert args == ('status', '--porcelain', '--untracked-files=all')
        return b' M private-name-must-not-print' if mismatch == 'dirty' else b''
    monkeypatch.setattr(gate, 'git', synthetic_git)
    if mismatch == 'git_error':
        with pytest.raises(SystemExit, match='1'):
            exec(compile(script, '<reviewed-workflow-diagnostic>', 'exec'), {})
    else:
        exec(compile(script, '<reviewed-workflow-diagnostic>', 'exec'), {})
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result['raw_values_printed'] is False
    if mismatch == 'git_error':
        assert result == dict(status='SOURCE_BINDING_DIAGNOSTIC_BLOCKED', raw_values_printed=False)
    else:
        assert result == dict(status='SOURCE_BINDING_DIAGNOSTIC_NOT_ACCEPTANCE',
            root_matches=mismatch != 'root', head_matches=mismatch != 'head',
            sanitized_checkout_clean=mismatch != 'dirty', raw_values_printed=False)
    for forbidden in (str(tmp_path), 'a' * 40, 'b' * 40, 'private-name', 'private-error'):
        assert forbidden not in output


def fixture(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, bytes], list[tuple[str, ...]]]:
    names = {'live_database_backup.py', gate.MANIFEST}
    monkeypatch.setattr(gate, 'FILES', frozenset(names))
    data = {'live_database_backup.py': b'# synthetic\n'}
    data[gate.MANIFEST] = json.dumps(dict(format=gate.FORMAT, source_base=gate.SOURCE_BASE,
        files={'live_database_backup.py': gate.sha(data['live_database_backup.py']), gate.MANIFEST: None})).encode()
    for name, raw in data.items():
        (root / name).write_bytes(raw)
    calls: list[tuple[str, ...]] = []
    def git(path: Path, *args: str, **kwargs: Any) -> bytes:
        calls.append(args)
        if args == ('rev-parse', '--show-toplevel'):
            return str(root).encode()
        if args == ('rev-parse', '--verify', 'HEAD'):
            return b'' if kwargs.get('absent_head') else b'a'*40
        if args[0] == 'ls-files' and '--stage' in args:
            return b''.join(b'100644 '+b'b'*40+b' 0\t'+name.encode()+b'\0' for name in sorted(data))
        if args[0] == 'show':
            return data[args[1].split(':', 1)[1]]
        return b''
    monkeypatch.setattr(gate, 'git', git)
    return data, calls


@pytest.mark.parametrize('staged', [True, False])
def test_exact_source_and_staging_do_not_grant_execution(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, staged: bool) -> None:
    _, calls = fixture(tmp_path, monkeypatch)
    gate.verify_checkout(tmp_path, gate.EMPTY_TREE if staged else 'a'*40, staged)
    assert any(args[0] == 'show' for args in calls)


@pytest.mark.parametrize('pin', [None, '', 'main', 'A'*40, 'a'*39, gate.EMPTY_TREE])
def test_no_implicit_head_or_empty_tree_runtime_admission(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, pin: str | None) -> None:
    monkeypatch.setattr(gate, 'git', lambda *a, **k: pytest.fail('unadmitted Git read'))
    with pytest.raises(ValueError, match='REVIEWED_SOURCE_REQUIRED'):
        gate.verify_checkout(tmp_path, pin)


@pytest.mark.parametrize('mutation', ['head', 'dirty', 'extra', 'stage', 'payload', 'manifest', 'index'])
def test_source_drift_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    data, _ = fixture(tmp_path, monkeypatch)
    original_git = gate.git
    def git(path: Path, *args: str, **kwargs: Any) -> bytes:
        if mutation == 'head' and args == ('rev-parse', '--verify', 'HEAD'):
            return b'b'*40
        if mutation == 'dirty' and args[0] == 'status':
            return b' M live_database_backup.py'
        result = original_git(path, *args, **kwargs)
        if args[0] == 'ls-files' and '--stage' in args:
            if mutation == 'extra':
                return result + b'100644 '+b'b'*40+b' 0\tprivate.env\0'
            if mutation == 'stage':
                return result.replace(b'100644', b'120000', 1)
        if mutation == 'index' and args[0] == 'show' and args[1].endswith('live_database_backup.py'):
            return b'# tampered'
        return result
    monkeypatch.setattr(gate, 'git', git)
    if mutation == 'payload':
        (tmp_path / 'live_database_backup.py').write_bytes(b'# changed')
    if mutation == 'manifest':
        value = json.loads(data[gate.MANIFEST])
        value['source_base'] = 'b'*40
        (tmp_path / gate.MANIFEST).write_text(json.dumps(value))
    with pytest.raises(ValueError):
        gate.verify_checkout(tmp_path, 'a'*40)


@pytest.mark.parametrize('raw', [b'{}', b'{"format":1,"format":2}', b'[]'])
def test_manifest_is_exact_not_a_user_selectable_scope(raw: bytes) -> None:
    with pytest.raises((ValueError, TypeError)):
        gate.distribution(raw)


def test_preview_is_zero_io(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(gate, 'read_public', lambda *a: pytest.fail('unexpected read'))
    monkeypatch.setattr(gate, 'git', lambda *a, **k: pytest.fail('unexpected Git'))
    assert gate.main([]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'PREVIEW' and result['input_reads'] == result['writes'] == 0


def test_explicit_profile_delegates_to_new_exact_gate_without_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str | None] = []
    monkeypatch.setattr(gate, 'verify_checkout', lambda root, pin: seen.append(pin))
    backup.reviewed_source('a'*40, 'standalone-backup-v1')
    assert seen == ['a'*40]
    with pytest.raises(ValueError, match='REVIEWED_SOURCE_REQUIRED'):
        backup.reviewed_source('a'*40, 'unknown-profile')


def test_static_import_inventory_rejects_ui_dependency() -> None:
    base = {'a.py': b'import cryptography, packaging, pytest\n'}
    assert gate.import_closure(base) == ['cryptography', 'packaging', 'pytest']
    with pytest.raises(ValueError, match='REVIEWED_IMPORT_CLOSURE_REQUIRED'):
        gate.import_closure({**base, 'bad.py': b'import PIL\n'})


def test_errors_never_print_private_argument(monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    assert gate.main(['--unknown', 'private-sentinel']) == 2
    assert 'private-sentinel' not in capsys.readouterr().out


def test_git_disables_replacements_and_ambient_configuration(monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path) -> None:
    seen: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    def run(argv: tuple[str, ...], **kwargs: Any) -> Any:
        from types import SimpleNamespace
        seen.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'synthetic', stderr=b'')
    monkeypatch.setattr(gate.subprocess, 'run', run)
    assert gate.git(tmp_path, 'show', 'a'*40 + ':README.md') == b'synthetic'
    command, options = seen[0]
    assert '--no-replace-objects' in command
    assert options['env']['GIT_NO_REPLACE_OBJECTS'] == '1'
    assert options['env']['GIT_CONFIG_GLOBAL'] == gate.os.devnull
    assert options['env']['GIT_GRAFT_FILE'] == gate.os.devnull


def test_ignored_import_payload_is_not_outside_source_closure(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    fixture(tmp_path, monkeypatch)
    original = gate.git
    monkeypatch.setattr(gate, 'git', lambda root, *args, **kwargs: b'__pycache__/injected.pyc' if
        args == ('ls-files', '--others') else original(root, *args, **kwargs))
    with pytest.raises(ValueError, match='EXACT_STAGED_TREE_REQUIRED'):
        gate.verify_checkout(tmp_path, 'a'*40)


def test_bootstrap_preview_loads_no_source_or_site(monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(launch, 'trusted_gate', lambda *a: pytest.fail('source load'))
    assert launch.main([]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'PREVIEW' and result['input_reads'] == 0


def test_confirmed_bootstrap_rejects_ordinary_nonisolated_test_process(
        capsys: pytest.CaptureFixture[str]) -> None:
    assert launch.main(['--confirm-run', '--reviewed-source', 'a'*40]) == 2
    assert json.loads(capsys.readouterr().out)['code'] == 'ISOLATED_BACKUP_BOOTSTRAP_REVIEW_REQUIRED'


@pytest.mark.parametrize('case', ['exact', 'extra', 'missing', 'wrong_version', 'duplicate'])
def test_runtime_metadata_is_complete_not_just_a_forbidden_name_list(
        monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    from importlib import metadata
    from types import SimpleNamespace
    versions = dict(cryptography='50.0.1', cffi='2.1.1', pycparser='3.0', packaging='26.3')
    requirements = '\n'.join(name+'=='+version for name, version in versions.items()).encode()
    if case == 'extra':
        versions['Pillow'] = '12.3.0'
    if case == 'missing':
        del versions['packaging']
    if case == 'wrong_version':
        versions['cryptography'] = '50.0.0'
    distributions = [SimpleNamespace(metadata={'Name': name}, version=version) for name, version in versions.items()]
    if case == 'duplicate':
        distributions.append(distributions[0])
    monkeypatch.setattr(metadata, 'distributions', lambda **kwargs: distributions)
    if case == 'exact':
        launch.admit_runtime(Path('synthetic-unused'), requirements)
    else:
        with pytest.raises(ValueError):
            launch.admit_runtime(Path('synthetic-unused'), requirements)


def test_substituted_gate_is_not_executed_before_authentication(tmp_path: Path) -> None:
    import subprocess
    import sys
    launch_source = Path(launch.__file__).read_bytes()
    (tmp_path / 'standalone_backup_launch.py').write_bytes(launch_source)
    marker = tmp_path / 'must-not-be-written'
    (tmp_path / 'standalone_backup_contract.py').write_text(
        'from pathlib import Path\nPath('+repr(str(marker))+').write_text("unsafe execution")\n')
    result = subprocess.run((sys.executable, '-I', '-S', '-B',
        str(tmp_path / 'standalone_backup_launch.py'), '--confirm-run', '--reviewed-source', 'a'*40),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    assert result.returncode == 2 and not marker.exists()
    expected_stage = 'SOURCE_BINDING' if sys.version_info[:3] == (3, 13, 9) else 'BOOTSTRAP_FLAGS'
    assert json.loads(result.stdout)['stage'] == expected_stage
    assert not result.stderr


def test_successful_bootstrap_orders_admission_before_dispatch(monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    from types import SimpleNamespace
    import dependency_pair_watch
    events: list[str] = []
    gate_module = SimpleNamespace(verify_checkout=lambda *a: events.append('source'),
        read_public=lambda *a: b'synthetic runtime')
    monkeypatch.setattr(launch.sys, 'flags', SimpleNamespace(isolated=1, no_site=1))
    monkeypatch.setattr(launch.sys, 'dont_write_bytecode', True)
    monkeypatch.setattr(launch.sys, 'version_info', (3, 13, 9))
    monkeypatch.setattr(launch, 'trusted_gate', lambda *a: gate_module)
    monkeypatch.setattr(launch, 'runtime_site', lambda *a: Path('synthetic-site'))
    monkeypatch.setattr(launch, 'admit_runtime', lambda *a: events.append('runtime'))
    monkeypatch.setattr(launch.sys, 'path', list(launch.sys.path))
    monkeypatch.setitem(launch.sys.modules, 'standalone_backup_contract', gate_module)
    monkeypatch.setattr(dependency_pair_watch, 'main', lambda args: events.append('dispatch') or 0)
    assert launch.main(['--confirm-run', '--reviewed-source', 'a'*40, '--operation', 'watch']) == 0
    assert events == ['source', 'runtime', 'dispatch']
    assert not capsys.readouterr().out


def source_fixture(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root.mkdir()
    monkeypatch.setattr(gate, 'MAP', {'a.py': 'a.py', 'b.py': 'b.py'})
    monkeypatch.setattr(gate, 'FILES', frozenset(('a.py', 'b.py', gate.MANIFEST)))
    monkeypatch.setattr(gate, 'import_closure', lambda _: ['synthetic'])
    for name in gate.MAP:
        (root / name).write_bytes(b'# public synthetic\n')
    (root / gate.SOURCE_MANIFEST).write_text(json.dumps(dict(format=gate.FORMAT,
        source_base=gate.SOURCE_BASE, destinations=gate.MAP,
        files={name: gate.sha((root/name).read_bytes()) for name in gate.MAP})))


def test_export_is_exact_and_existing_destination_is_preserved(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / 'source'
    source_fixture(source, monkeypatch)
    destination = tmp_path / 'new-output'
    result = gate.export(source, destination)
    assert result['backup_authorised'] is False
    assert set(path.name for path in destination.iterdir()) == set(gate.FILES)
    before = {path.name: path.read_bytes() for path in destination.iterdir()}
    with pytest.raises(FileExistsError):
        gate.export(source, destination)
    assert before == {path.name: path.read_bytes() for path in destination.iterdir()}


def test_export_rejects_tamper_before_destination_creation(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / 'source'
    source_fixture(source, monkeypatch)
    (source / 'b.py').write_bytes(b'# unreviewed')
    destination = tmp_path / 'must-not-exist'
    with pytest.raises(ValueError, match='SOURCE_PAYLOAD_HASH_REQUIRED'):
        gate.export(source, destination)
    assert not destination.exists()


def test_partial_public_export_is_retained_not_retried(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / 'source'
    source_fixture(source, monkeypatch)
    destination = tmp_path / 'partial'
    original_open = Path.open
    def open_path(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == destination / 'b.py':
            raise OSError('synthetic disk full')
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', open_path)
    with pytest.raises(OSError):
        gate.export(source, destination)
    assert (destination / 'a.py').read_bytes() == b'# public synthetic\n'
    assert not (destination / gate.MANIFEST).exists()


@pytest.mark.parametrize('mode', ['exact', 'wrong_head', 'wrong_readme', 'symlink_seed', 'extra_seed'])
def test_only_exact_external_inert_seed_base_is_accepted(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    fixture(tmp_path, monkeypatch)
    original = gate.git
    def git(root: Path, *args: str, **kwargs: Any) -> bytes:
        if args == ('rev-parse', '--verify', 'HEAD'):
            return b'b'*40 if mode == 'wrong_head' else b'a'*40
        if args == ('ls-tree', '-r', 'a'*40):
            raw = b'100644 blob '+b'c'*40+b'\tREADME.md\n'
            return raw.replace(b'100644', b'120000') if mode == 'symlink_seed' else (
                raw + b'100644 blob '+b'c'*40+b'\textra\n' if mode == 'extra_seed' else raw)
        if args == ('show', 'a'*40+':README.md'):
            return b'unapproved' if mode == 'wrong_readme' else gate.SEED_README
        return original(root, *args, **kwargs)
    monkeypatch.setattr(gate, 'git', git)
    if mode == 'exact':
        gate.verify_checkout(tmp_path, 'a'*40, staged=True)
    else:
        with pytest.raises(ValueError):
            gate.verify_checkout(tmp_path, 'a'*40, staged=True)


def test_hosted_templates_keep_audit_and_synthetic_acceptance_separate() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / 'backup_delivery_templates' / 'quality.yml'
    if not path.exists():
        path = root / '.github/workflows/quality.yml'
    text = path.read_text()
    assert 'python -m pip_audit -r requirements-runtime.txt' in text
    assert 'python -m pip_audit' in text and 'python -B -m pytest -q -p no:cacheprovider' in text
    assert '--require-hashes' in text and '--only-binary=:all:' in text
    assert 'continue-on-error' not in text and '--ignore-vuln' not in text
    assert '3.13.9' in text and '3.13.16' in text
    assert 'environment_preflight.py' not in text  # app gate not repurposed


@pytest.mark.parametrize('raw', [b'C:' + b'\\Users\\synthetic\\private',
    b'C:' + b'/' + b'Users/synthetic/private', b'/' + b'home/synthetic/private',
    b'/' + b'Users/synthetic/private'])
def test_all_public_file_types_reject_literal_personal_profile_paths(raw: bytes) -> None:
    for name in ('README.md', 'test.py', 'workflow.yml', 'manifest.json'):
        with pytest.raises(ValueError, match='PERSONAL_HOME_PATH_IN_PUBLIC_PAYLOAD'):
            gate.public_privacy({name: raw})


def test_public_privacy_does_not_weaken_fixed_target_or_os_installation() -> None:
    gate.public_privacy({'source.py': b'C:\\Program Files\\PostgreSQL\\17\\bin',
        'README.md': b'Join-Path $reviewedWorkspace .venv; $env:USERPROFILE'})


def test_export_privacy_rejection_precedes_all_destination_writes(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / 'source'
    source_fixture(source, monkeypatch)
    raw = b'# C:' + b'\\Users\\synthetic\\private\n'
    (source / 'a.py').write_bytes(raw)
    value = json.loads((source / gate.SOURCE_MANIFEST).read_bytes())
    value['files']['a.py'] = gate.sha(raw)
    (source / gate.SOURCE_MANIFEST).write_text(json.dumps(value))
    destination = tmp_path / 'must-not-be-created'
    with pytest.raises(ValueError, match='PERSONAL_HOME_PATH_IN_PUBLIC_PAYLOAD'):
        gate.export(source, destination)
    assert not destination.exists()


def test_complete_reviewed_public_mapping_passes_privacy_not_only_fixtures() -> None:
    root = Path(__file__).resolve().parents[1]
    source_tree = (root / gate.SOURCE_MANIFEST).is_file()
    gate.public_privacy({target: gate.read_public(root, source if source_tree else target)
        for source, target in gate.MAP.items()})


@pytest.mark.parametrize('case', ['exact', 'wrong_head', 'prior_hash', 'prior_scope', 'prior_mode',
    'prior_missing', 'prior_format', 'candidate_drift', 'wire_drift'])
def test_update_verifies_prior_release_and_candidate_not_arbitrary_new_main(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    data, _ = fixture(tmp_path, monkeypatch)
    interface = 'BACKUP_ARTIFACT_INTERFACE.json'
    wire = b'{"handoff_format":"synthetic-v1"}\n'
    monkeypatch.setattr(gate, 'FILES', gate.FILES | {interface})
    data[interface] = wire if case != 'wire_drift' else b'{"handoff_format":"synthetic-v2"}\n'
    candidate = json.loads(data[gate.MANIFEST])
    candidate['files'][interface] = gate.sha(data[interface])
    data[gate.MANIFEST] = json.dumps(candidate).encode()
    (tmp_path / interface).write_bytes(data[interface])
    (tmp_path / gate.MANIFEST).write_bytes(data[gate.MANIFEST])
    previous = {'live_database_backup.py': b'# previous approved release\n', interface: wire}
    manifest = json.loads(data[gate.MANIFEST])
    manifest['files']['live_database_backup.py'] = gate.sha(previous['live_database_backup.py'])
    manifest['files'][interface] = gate.sha(wire)
    if case == 'prior_format':
        manifest['format'] = 'unknown'
    previous[gate.MANIFEST] = json.dumps(manifest).encode()
    original = gate.git
    def git(root: Path, *args: str, **kwargs: Any) -> bytes:
        if args == ('rev-parse', '--verify', 'HEAD'):
            return b'b' * 40 if case == 'wrong_head' else b'a' * 40
        if args == ('ls-tree', '-r', 'a' * 40):
            raw = b''.join(b'100644 blob ' + b'c' * 40 + b'\t' + name.encode() + b'\n'
                for name in sorted(previous))
            if case == 'prior_mode':
                raw = raw.replace(b'100644', b'120000', 1)
            if case == 'prior_scope':
                raw += b'100644 blob ' + b'c' * 40 + b'\textra\n'
            if case == 'prior_missing':
                raw = raw.splitlines(keepends=True)[0]
            return raw
        if args[0] == 'show' and args[1].startswith('a' * 40 + ':'):
            name = args[1].split(':', 1)[1]
            return b'tampered' if case == 'prior_hash' and name.endswith('.py') else previous[name]
        if case == 'candidate_drift' and args == ('diff', '--name-only'):
            return b'live_database_backup.py'
        return original(root, *args, **kwargs)
    monkeypatch.setattr(gate, 'git', git)
    if case == 'exact':
        gate.verify_update(tmp_path, 'a' * 40)
        with pytest.raises(ValueError):  # initial seed rule remains distinct
            gate.verify_checkout(tmp_path, 'a' * 40, staged=True)
    else:
        with pytest.raises(ValueError):
            gate.verify_update(tmp_path, 'a' * 40)


@pytest.mark.parametrize('pin', [None, '', 'main', 'A' * 40, gate.EMPTY_TREE])
def test_update_requires_external_approved_release_before_git(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, pin: str | None) -> None:
    monkeypatch.setattr(gate, 'git', lambda *a, **k: pytest.fail('unadmitted Git query'))
    with pytest.raises(ValueError, match='EXACT_REVIEWED_PRIOR_RELEASE_REQUIRED'):
        gate.verify_update(tmp_path, pin)


def test_advisory_watch_is_opt_in_and_reuses_both_whole_profile_audits() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / 'backup_delivery_templates/advisory.yml'
    if not path.exists():
        path = root / '.github/workflows/advisory.yml'
    text = path.read_text()
    assert "vars.BACKUP_ADVISORY_WATCH_ENABLED == 'true'" in text
    assert 'uses: ./.github/workflows/quality.yml' in text
    assert 'contents: read' in text and 'schedule:' in text
    assert 'secrets' not in text and 'continue-on-error' not in text


@pytest.mark.parametrize('name', ['token.json', 'TOKEN.JSON', 'nested/Token.Json',
    'nested\\CLIENT_SECRET.json', 'client_secret_other.json', 'token.json.bak',
    '.env', 'private/.ENV.production', 'secrets.toml', 'Credentials.JSON',
    'token.json/renamed.txt', 'C:token.json', 'C:client_secret.json'])
def test_private_names_reject_before_metadata_or_contents(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setattr(Path, 'lstat', lambda *a, **k: pytest.fail('No metadata reads'))
    monkeypatch.setattr(Path, 'read_bytes', lambda *a, **k: pytest.fail('No content reads'))
    with pytest.raises(ValueError, match='PRIVATE_CREDENTIAL_NAME_REJECTED'):
        gate.read_public(tmp_path, name)


@pytest.mark.parametrize('name', ['tests/test_token_contract.py', 'BACKUP_ARTIFACT_INTERFACE.json',
    'requirements-runtime.txt', 'CAPTURE_PRESERVATION.md'])
def test_public_names_are_not_secret_content_detection(name: str) -> None:
    gate.public_name(name)


def test_private_payload_name_rejected_even_when_allowlist_widened(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, 'MAP', {'token.json': 'token.json'})
    with pytest.raises(ValueError, match='PRIVATE_CREDENTIAL_NAME_REJECTED'):
        gate.read_public(tmp_path, 'token.json')


def test_private_target_export_is_rejected_before_payload_read(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / 'source'
    source.mkdir()
    monkeypatch.setattr(gate, 'MAP', {'safe.py': 'nested/TOKEN.JSON'})
    manifest = dict(format=gate.FORMAT, source_base=gate.SOURCE_BASE,
        files={'safe.py': gate.sha(b'opaque')}, destinations=gate.MAP)
    def read(root: Path, name: str) -> bytes:
        assert name == gate.SOURCE_MANIFEST, 'No source payload may be read'
        return json.dumps(manifest).encode()
    monkeypatch.setattr(gate, 'read_public', read)
    with pytest.raises(ValueError, match='PRIVATE_CREDENTIAL_NAME_REJECTED'):
        gate.export(source, tmp_path / 'not-created')
    assert not (tmp_path / 'not-created').exists()


def test_entire_index_name_list_precedes_any_payload_read(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    names = ['allowed.py', 'nested/TOKEN.JSON']
    monkeypatch.setattr(gate, 'FILES', frozenset(names))
    def git(root: Path, *args: str, **kwargs: Any) -> bytes:
        if args[0] == 'ls-files' and '--stage' in args:
            return b''.join(b'100644 '+b'a'*40+b' 0\t'+name.encode()+b'\0' for name in names)
        return b''
    monkeypatch.setattr(gate, 'git', git)
    monkeypatch.setattr(gate, 'read_public', lambda *a: pytest.fail('No payload before names admission'))
    with pytest.raises(ValueError, match='PRIVATE_CREDENTIAL_NAME_REJECTED'):
        gate._verify_tree(tmp_path, 'a'*40, staged=True)


@pytest.mark.parametrize('entry', ['update', 'checkout'])
def test_actual_source_entry_points_preflight_index_before_prior_payloads(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, entry: str) -> None:
    def git(root: Path, *args: str, **kwargs: Any) -> bytes:
        if args == ('rev-parse', '--show-toplevel'):
            return str(tmp_path).encode()
        if args == ('rev-parse', '--verify', 'HEAD'):
            return b'a'*40
        if args[0] == 'ls-files':
            return b'100644 '+b'b'*40+b' 0\ttoken.json\0'
        pytest.fail('No predecessor or candidate payload read before names')
    monkeypatch.setattr(gate, 'git', git)
    with pytest.raises(ValueError, match='PRIVATE_CREDENTIAL_NAME_REJECTED'):
        if entry == 'update':
            gate.verify_update(tmp_path, 'a'*40)
        else:
            gate.verify_checkout(tmp_path, 'a'*40)
