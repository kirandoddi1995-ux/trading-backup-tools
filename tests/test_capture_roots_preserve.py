"""Synthetic two-root preservation; never inspect installed capture or credentials."""
from __future__ import annotations

from datetime import date
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

import capture_roots_preserve as copy

DAY = date(2001, 1, 2)


class SyntheticDirectory:
    """Portable adapter is NOT native Windows directory-lock acceptance."""
    def __init__(self, root: Path, expected: tuple[int, int]) -> None:
        self.root, self.expected = root, expected
    def __enter__(self) -> SyntheticDirectory:
        self.validate()
        return self
    def __exit__(self, *args: object) -> None:
        pass
    def validate(self) -> None:
        assert (self.root.stat().st_dev, self.root.stat().st_ino) == self.expected
    def open_new(self, name: str) -> Any:
        copy._name(name)
        return (self.root / name).open('xb')
    def publish(self, name: str, raw: bytes) -> None:
        with self.open_new(name) as stream:
            stream.write(raw)


@pytest.fixture
def forest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Path], Path]:
    # API fixtures are outside the module's source root, including in CI.
    roots = {role: tmp_path / role for role in copy.ROLES}
    for path in roots.values():
        path.mkdir(mode=0o700)
    (roots['Forward'] / '2001-01-02').mkdir()
    (roots['Forward'] / '2001-01-02' / 'observations.sqlite').write_bytes(b'opaque-not-opened-as-SQLite')
    (roots['Forward'] / '2001-01-02' / 'observations.sqlite-wal').write_bytes(b'opaque-sidecar')
    (roots['Forward'] / 'empty').mkdir()
    (roots['Forward'] / 'empty-file').write_bytes(b'')
    (roots['ForwardOps'] / 'audit.json').write_bytes(b'PRIVATE_SYNTHETIC_BYTES')
    (roots['ForwardOps'] / 'owner-lock').write_bytes(b'stale-or-active-not-established')
    monkeypatch.setattr(copy, 'Directory', SyntheticDirectory)
    monkeypatch.setattr(copy, '_check_binding', lambda *a: None)
    monkeypatch.setattr(copy, 'private_parent', lambda *a: None)
    # This portable adapter supplies capacity, not a native free-space claim.
    # Full-disk cases override it; native Windows tests use actual disk_usage.
    monkeypatch.setattr(copy.shutil, 'disk_usage',
        lambda path: type('SyntheticCapacity', (), {'free': 8 * 1024**3})())
    return roots, tmp_path / 'new-preservation'


def run(forest: tuple[dict[str, Path], Path], *, inspect: bool = False) -> dict[str, Any]:
    roots, destination = forest
    return copy.preserve(roots, destination, DAY, inspect_only=inspect, owner_quiescent=True)


def test_both_roots_all_default_bytes_empty_dirs_and_sidecars_preserved(forest: tuple[dict[str, Path], Path]) -> None:
    roots, destination = forest
    before = {str(p): p.read_bytes() for root in roots.values() for p in root.rglob('*') if p.is_file()}
    result = run(forest)
    assert result['status'] == 'CAPTURE_TWO_ROOTS_OPAQUE_COPY_VERIFIED_NOT_CUSTODY'
    assert (destination / 'Forward/empty').is_dir()
    assert (destination / 'Forward/empty-file').read_bytes() == b''
    assert (destination / 'Forward/2001-01-02/observations.sqlite-wal').read_bytes() == b'opaque-sidecar'
    assert before == {str(p): p.read_bytes() for root in roots.values() for p in root.rglob('*') if p.is_file()}
    verified = copy.verify(destination, result['manifest_sha256'])
    assert verified['source_reads'] == verified['writes'] == 0
    manifest = json.loads((destination / 'manifest.json').read_bytes())
    assert manifest['roots'] == ['Forward', 'ForwardOps']
    for field in ('atomic_snapshot', 'database_integrity_verified', 'authenticated',
        'independent_custody', 'restore_verified', 'deletion_authorised', 'acl_or_alternate_streams_copied'):
        assert manifest[field] is False


def test_inspection_is_readonly_and_reports_markers_not_live_status(forest: tuple[dict[str, Path], Path]) -> None:
    result = run(forest, inspect=True)
    assert result['status'] == 'CAPTURE_ROOTS_INSPECTED_NOT_PRESERVED'
    assert result['writes'] == result['source_writes'] == 0
    assert result['sqlite_sidecar_names'] == result['lock_named_files'] == 1
    assert not forest[1].exists()


def test_existing_destination_preserved_without_source_or_output_changes(forest: tuple[dict[str, Path], Path]) -> None:
    run(forest)
    raw = (forest[1] / 'manifest.json').read_bytes()
    with pytest.raises(ValueError, match='CAPTURE_NEW_DESTINATION_REQUIRED'):
        run(forest)
    assert (forest[1] / 'manifest.json').read_bytes() == raw


@pytest.mark.parametrize('change', ['missing_root', 'extra_root', 'overlap', 'inside_source', 'inside_code', 'no_attestation'])
def test_scope_unknown_or_overlap_blocks(forest: tuple[dict[str, Path], Path], change: str) -> None:
    roots, destination = forest
    roots = dict(roots)
    quiet = True
    if change == 'missing_root':
        del roots['ForwardOps']
    elif change == 'extra_root':
        roots['extra'] = roots['Forward']
    elif change == 'overlap':
        roots['ForwardOps'] = roots['Forward']
    elif change == 'inside_source':
        destination = roots['Forward'] / 'new'
    elif change == 'inside_code':
        destination = Path(copy.__file__).resolve().parent / 'must-not-exist'
    else:
        quiet = False
    with pytest.raises(ValueError):
        copy.preserve(roots, destination, DAY, inspect_only=False, owner_quiescent=quiet)


@pytest.mark.parametrize('limit', ['MAX_FILES', 'MAX_ENTRIES', 'MAX_FILE_BYTES', 'MAX_TOTAL_BYTES', 'MAX_DEPTH'])
def test_bounds_stop_not_subset_success(forest: tuple[dict[str, Path], Path],
        monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    monkeypatch.setattr(copy, limit, 1)
    with pytest.raises(ValueError):
        run(forest)
    assert not forest[1].exists()


@pytest.mark.parametrize('name', ['../bad', 'stream:ads', 'bad\\name', 'trailing.', 'trailing ', 'CON', 'LPT1.txt', '\x00'])
def test_unsafe_windows_names_rejected_portably(name: str) -> None:
    with pytest.raises(ValueError, match='CAPTURE_NAME_REVIEW_REQUIRED'):
        copy._name(name)


@pytest.mark.parametrize('mutation', ['add', 'same_size_change', 'delete'])
def test_source_changes_never_publish_success(forest: tuple[dict[str, Path], Path],
        monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    original = copy.inventory
    calls = 0
    def inventory(roots: dict[str, Path]) -> copy.Tree:
        nonlocal calls
        calls += 1
        if calls == 2:
            path = roots['ForwardOps'] / 'audit.json'
            if mutation == 'add':
                (roots['ForwardOps'] / 'new').write_bytes(b'added')
            elif mutation == 'same_size_change':
                path.write_bytes(b'x' * path.stat().st_size)
            else:
                path.unlink()
        return original(roots)
    monkeypatch.setattr(copy, 'inventory', inventory)
    with pytest.raises((ValueError, PermissionError)):
        run(forest)
    assert not (forest[1] / 'manifest.json').exists()


@pytest.mark.parametrize('failure', ['private_parent', 'full_disk', 'partial_copy'])
def test_io_failures_preserve_partials_never_success(forest: tuple[dict[str, Path], Path],
        monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    if failure == 'private_parent':
        def reject(*a: Any) -> None:
            raise ValueError('CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        monkeypatch.setattr(copy, 'private_parent', reject)
    elif failure == 'full_disk':
        from types import SimpleNamespace
        monkeypatch.setattr(copy.shutil, 'disk_usage', lambda *a: SimpleNamespace(free=0))
    else:
        original = copy._hash_fd
        def fail(fd: int, size: int, sink: Any = None) -> str:
            if sink is not None:
                sink.write(b'partial')
                raise OSError('private-path-sentinel')
            return original(fd, size, sink)
        monkeypatch.setattr(copy, '_hash_fd', fail)
    with pytest.raises((ValueError, OSError)):
        run(forest)
    assert not (forest[1] / 'manifest.json').exists()
    if failure == 'partial_copy':
        assert (forest[1] / 'attempt.json').exists()


@pytest.mark.parametrize('mutation', ['payload', 'extra_file', 'extra_root', 'missing_ops', 'manifest', 'attempt', 'anchor'])
def test_copy_verification_rejects_tampering_and_incomplete_scope(forest: tuple[dict[str, Path], Path], mutation: str) -> None:
    report = run(forest)
    root = forest[1]
    anchor = report['manifest_sha256']
    if mutation == 'payload':
        (root / 'ForwardOps/audit.json').write_bytes(b'changed')
    elif mutation == 'extra_file':
        (root / 'ForwardOps/extra').write_bytes(b'changed')
    elif mutation == 'extra_root':
        (root / 'extra').write_bytes(b'changed')
    elif mutation == 'missing_ops':
        (root / 'ForwardOps/audit.json').unlink()
    elif mutation == 'manifest':
        value = json.loads((root / 'manifest.json').read_bytes())
        value['restore_verified'] = True
        raw = json.dumps(value).encode()
        (root / 'manifest.json').write_bytes(raw)
        anchor = hashlib.sha256(raw).hexdigest()
    elif mutation == 'attempt':
        (root / 'attempt.json').write_bytes(b'{}')
    else:
        anchor = 'a' * 64
    with pytest.raises(ValueError):
        copy.verify(root, anchor)


def test_preview_no_sources_tasks_credentials_or_writes(monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(copy, 'preserve', lambda *a, **k: pytest.fail('preview private access'))
    monkeypatch.setattr(copy.native, 'reviewed_source', lambda *a: pytest.fail('preview source access'))
    monkeypatch.setattr(copy.native, '_console', lambda: pytest.fail('preview native access'))
    assert copy.main([]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['status'] == 'PREVIEW' and value['source_writes'] == value['writes'] == 0


def test_cli_rejects_before_private_access_and_redacts_exception(monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    def reject(*a: Any) -> None:
        raise ValueError({'private-sentinel': True})
    monkeypatch.setattr(copy.native, 'reviewed_source', reject)
    assert copy.main(['--mode', 'inspect', '--confirm-run', '--confirm-no-writers', '--session-date', '2001-01-02']) == 2
    raw = capsys.readouterr().out
    assert 'private-sentinel' not in raw and json.loads(raw)['stage'] == 'SOURCE_BINDING'


@pytest.mark.parametrize('owner,entries,directory,accepted', [
    ('synthetic-user', [(0, 3, 'synthetic-user')], True, True),
    ('synthetic-user', [(0, 0, 'synthetic-user')], True, False),
    ('synthetic-user', [(0, 0, 'synthetic-user')], False, True),
    ('synthetic-user', [(0, 3, 'world')], True, False),
    ('other-owner', [(0, 3, 'synthetic-user')], True, False),
    ('synthetic-user', [], True, False),
    ('synthetic-user', [(1, 3, 'synthetic-user')], True, False),
    ('synthetic-user', [(0, 0, 'synthetic-user'), (0, 11, 'S-1-3-0')], True, True),
    ('synthetic-user', [(0, 0, 'S-1-3-0')], False, False),
])
def test_privacy_policy_needs_known_principals_and_directory_inheritance(owner: str,
        entries: list[tuple[int, int, str]], directory: bool, accepted: bool) -> None:
    if accepted:
        copy._acl_policy(owner, 'synthetic-user', entries, directory=directory)
    else:
        with pytest.raises(ValueError, match='CAPTURE_PRIVATE_PARENT_UNVERIFIED'):
            copy._acl_policy(owner, 'synthetic-user', entries, directory=directory)


@pytest.mark.parametrize('change', ['source_late', 'extra_file', 'extra_directory'])
def test_readback_races_block_completion(forest: tuple[dict[str, Path], Path],
        monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    original = copy.open_read
    done = False
    def open_read(path: Path) -> int:
        nonlocal done
        if not done and any(path.is_relative_to(forest[1] / role) for role in copy.ROLES):
            done = True
            if change == 'source_late':
                (forest[0]['ForwardOps'] / 'late').write_bytes(b'new')
            elif change == 'extra_file':
                (forest[1] / 'ForwardOps/extra').write_bytes(b'new')
            else:
                (forest[1] / 'ForwardOps/extra').mkdir()
        return original(path)
    monkeypatch.setattr(copy, 'open_read', open_read)
    with pytest.raises(ValueError):
        run(forest)
    assert not (forest[1] / 'manifest.json').exists()


@pytest.mark.parametrize('change', ['marker_bytes', 'marker_replace', 'marker_link'])
def test_attempt_marker_must_remain_bound_until_completion(forest: tuple[dict[str, Path], Path],
        monkeypatch: pytest.MonkeyPatch, change: str) -> None:
    original = copy.open_read
    done = False
    def open_read(path: Path) -> int:
        nonlocal done
        if not done and any(path.is_relative_to(forest[1] / role) for role in copy.ROLES):
            done = True
            marker = forest[1] / 'attempt.json'
            if change == 'marker_bytes':
                marker.write_bytes(b'x' * len(copy.ATTEMPT))
            elif change == 'marker_replace':
                marker.rename(forest[1] / 'retained-attempt')
                marker.write_bytes(copy.ATTEMPT)
            else:
                os.link(marker, forest[1] / 'second-marker-name')
        return original(path)
    monkeypatch.setattr(copy, 'open_read', open_read)
    with pytest.raises((ValueError, OSError)):
        run(forest)
    assert not (forest[1] / 'manifest.json').exists()


def test_verifier_holds_manifest_during_payload_readback(forest: tuple[dict[str, Path], Path],
        monkeypatch: pytest.MonkeyPatch) -> None:
    report = run(forest)
    original = copy.open_read
    done = False
    def open_read(path: Path) -> int:
        nonlocal done
        if not done and any(path.is_relative_to(forest[1] / role) for role in copy.ROLES):
            done = True
            (forest[1] / 'manifest.json').write_bytes(b'changed-while-verifying')
        return original(path)
    monkeypatch.setattr(copy, 'open_read', open_read)
    with pytest.raises((ValueError, OSError)):
        copy.verify(forest[1], report['manifest_sha256'])


@pytest.mark.parametrize('case', ['exact', 'wrong_volume', 'same_volume', 'wrong_hash', 'wrong_size', 'binding_swap'])
def test_cipher_verification_binds_real_destination_not_drive_letter(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    source, destination = tmp_path / 'source.7z', tmp_path / 'destination.7z'
    for path in (source, destination):
        path.write_bytes(b'synthetic-ciphertext')
    monkeypatch.setattr(copy, '_cipher_path', lambda *a: None)
    def identity(fd: int) -> dict[str, Any]:
        return dict(file_id=os.fstat(fd).st_ino,
            volume='source' if os.fstat(fd).st_ino == source.stat().st_ino or case == 'same_volume' else 'destination')
    monkeypatch.setattr(copy, 'identity', identity)
    def measure(path: Path, maximum: int) -> dict[str, Any]:
        fd = os.open(path, os.O_RDONLY)
        try:
            binding = identity(fd)
        finally:
            os.close(fd)
        if case == 'binding_swap' and path == destination:
            binding['file_id'] += 1
        return dict(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), binding=binding)
    monkeypatch.setattr(copy, 'measure', measure)
    digest = hashlib.sha256(source.read_bytes()).hexdigest() if case != 'wrong_hash' else 'a' * 64
    volume = hashlib.sha256(b'destination' if case != 'wrong_volume' else b'other-disk').hexdigest()
    if case == 'exact':
        result = copy.verify_cipher(source, destination, source.stat().st_size, digest, volume)
        assert result['independent_custody'] is result['encryption_verified'] is False
    else:
        with pytest.raises(ValueError):
            copy.verify_cipher(source, destination, source.stat().st_size + (case == 'wrong_size'), digest, volume)


@pytest.mark.parametrize('error,code', [(ValueError('NATIVE_READ_HANDLE_UNAVAILABLE'), 'CAPTURE_SOURCE_HANDLE_UNAVAILABLE'),
    (PermissionError(13, 'private-sentinel'), 'CAPTURE_ACCESS_REVIEW_REQUIRED'),
    (OSError(28, 'private-sentinel'), 'CAPTURE_FREE_SPACE_REQUIRED'),
    (ValueError({'private-sentinel': True}), 'CAPTURE_ROOTS_IO_REVIEW_REQUIRED')])
def test_fixed_failure_projection_never_formats_raw_values(error: BaseException, code: str) -> None:
    assert copy._reason(error) == code


@pytest.mark.parametrize('relative', ['', 'Forward', 'ForwardOps', 'Forward/child'])
def test_verify_rejects_mutable_root_overlap_before_payload_reads(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch, relative: str) -> None:
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    def forbidden(*a: Any, **k: Any) -> Any:
        pytest.fail('No private file or inventory access permitted')
    monkeypatch.setattr(copy, '_control', forbidden)
    monkeypatch.setattr(copy, 'inventory', forbidden)
    monkeypatch.setattr(copy, 'private_parent', forbidden)
    with pytest.raises(ValueError, match='CAPTURE_SCOPE_OVERLAP'):
        copy.verify(tmp_path / 'KiranTrading' / relative, 'a' * 64)


def test_cipher_probe_opens_metadata_without_hashing_or_reading_content(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / 'opaque.7z'
    path.write_bytes(b'synthetic')
    def forbidden(*a: Any, **k: Any) -> Any:
        pytest.fail('Probe must not read content')
    monkeypatch.setattr(copy, 'measure', forbidden)
    monkeypatch.setattr(copy.os, 'read', forbidden)
    result = copy.probe_cipher(path)
    assert result['file_content_reads'] == 0 and result['writes'] == 0
    assert len(result['destination_volume_sha256']) == 64


def test_cipher_probe_rejects_multiple_links(tmp_path: Path) -> None:
    path, alias = tmp_path / 'opaque.7z', tmp_path / 'alias.7z'
    path.write_bytes(b'synthetic')
    os.link(path, alias)
    with pytest.raises(ValueError):
        copy.probe_cipher(alias)


def test_cipher_probe_rejects_link_shape_without_following(tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / 'opaque.7z'
    path.write_bytes(b'synthetic')
    actual = Path.lstat
    def linked(value: Path) -> Any:
        if value == path:
            record = actual(value)
            return type('SyntheticLink', (), dict(st_mode=0o120777, st_file_attributes=0x400,
                st_nlink=record.st_nlink))()
        return actual(value)
    monkeypatch.setattr(Path, 'lstat', linked)
    with pytest.raises(ValueError):
        copy.probe_cipher(path)


@pytest.mark.skipif(os.name != 'nt', reason='Native Windows directory/read-sharing acceptance; not a POSIX claim')
def test_native_windows_two_root_copy_and_readback(tmp_path: Path) -> None:
    roots = {role: tmp_path / role for role in copy.ROLES}
    for root in roots.values():
        root.mkdir(mode=0o700)
        (root / 'synthetic.json').write_bytes(b'opaque')
    result = copy.preserve(roots, tmp_path / 'new', DAY, inspect_only=False, owner_quiescent=True)
    assert copy.verify(tmp_path / 'new', result['manifest_sha256'])['files'] == 2


@pytest.mark.skipif(os.name != 'nt', reason='Native Windows sharing denial; not a POSIX claim')
def test_native_source_handle_denies_actual_write_access(tmp_path: Path) -> None:
    import ctypes
    source = tmp_path / 'opaque'
    source.write_bytes(b'synthetic')
    with copy.Directory(tmp_path, (tmp_path.stat().st_dev, tmp_path.stat().st_ino)) as guard:
        fd = copy.open_read(source)
        try:
            handle = guard.kernel.CreateFileW(str(source), 0x40000000, 3, None, 3, 0, None)
            if handle and handle != ctypes.c_void_p(-1).value:
                guard.kernel.CloseHandle(handle)
                pytest.fail('Source unexpectedly writable')
            assert ctypes.get_last_error() == 32
        finally:
            os.close(fd)
