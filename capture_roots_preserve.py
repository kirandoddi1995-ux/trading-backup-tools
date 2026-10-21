"""Inactive, opaque copy of BOTH capture roots; never a producer or SQLite reader.

Owner must keep ALL writers quiescent for inspection/copy. Existing source files
are held read-only with Windows write/delete sharing denied; directories are
pinned against deletion. Inventories and bytes must agree before/copy/after.
This is NOT an atomic volume snapshot, database integrity check or custody proof.
WAL/SHM/lock files are preserved as evidence, never removed, opened as databases
or treated as proof of consistency. Only default file streams are copied; ACLs,
ADS, task definitions and external credentials are NOT a full machine image.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import ctypes
from dataclasses import dataclass
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any, BinaryIO, NoReturn, Sequence

from archive_preservation_inventory import check_path, identity, measure, open_read
import live_database_backup as native

FORMAT = 'capture-two-roots-opaque-v1'
ROLES = ('Forward', 'ForwardOps')
MAX_FILES = 4096
MAX_ENTRIES = 8192
MAX_DEPTH = 24
MAX_FILE_BYTES = 256 * 1024**2
MAX_TOTAL_BYTES = 4 * 1024**3
MAX_MANIFEST_BYTES = 8 * 1024**2
MAX_CIPHER_BYTES = 5 * 1024**3
SAFE = frozenset(('CAPTURE_ROOTS_REQUIRED', 'CAPTURE_PATH_REVIEW_REQUIRED', 'CAPTURE_SCOPE_OVERLAP',
    'CAPTURE_ENTRY_BOUND', 'CAPTURE_NAME_REVIEW_REQUIRED', 'CAPTURE_FILE_SHAPE_REQUIRED',
    'CAPTURE_SOURCE_CHANGED', 'CAPTURE_NATIVE_BINDING_MISMATCH', 'CAPTURE_BYTES_BOUND',
    'CAPTURE_OWNER_QUIESCENCE_REQUIRED', 'CAPTURE_NEW_DESTINATION_REQUIRED',
    'CAPTURE_PRIVATE_PARENT_UNVERIFIED', 'CAPTURE_COPY_MISMATCH', 'CAPTURE_FREE_SPACE_REQUIRED',
    'CAPTURE_MANIFEST_INVALID', 'CAPTURE_MANIFEST_ANCHOR_REQUIRED', 'CAPTURE_INVALID_ARGUMENTS',
    'CAPTURE_NATIVE_PLATFORM_REQUIRED', 'CAPTURE_CIPHER_ANCHOR_REQUIRED',
    'CAPTURE_DESTINATION_VOLUME_REQUIRED', 'CAPTURE_SOURCE_HANDLE_UNAVAILABLE',
    'CAPTURE_ACCESS_REVIEW_REQUIRED', 'CAPTURE_SHARING_REVIEW_REQUIRED'))
ATTEMPT = b'{"attempt_consumed":true,"retry_authorised":false}\n'


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _name(value: str) -> None:
    require(bool(value) and len(value.encode('utf-8')) <= 240 and value not in ('.', '..')
        and value[-1] not in '. ' and not any(ord(c) < 32 or c in '/\\:' for c in value)
        and value.split('.')[0].upper() not in {'CON', 'PRN', 'AUX', 'NUL',
            *(f'COM{i}' for i in range(10)), *(f'LPT{i}' for i in range(10))}, 'CAPTURE_NAME_REVIEW_REQUIRED')


def _path(path: Path) -> None:
    require(path.is_absolute() and '..' not in path.parts, 'CAPTURE_PATH_REVIEW_REQUIRED')
    check_path(path)


def _stamp(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink


@dataclass(frozen=True)
class Tree:
    files: dict[str, tuple[int, int, int, int, int]]
    directories: dict[str, tuple[int, int]]


def inventory(roots: dict[str, Path]) -> Tree:
    require(set(roots) == set(ROLES), 'CAPTURE_ROOTS_REQUIRED')
    files: dict[str, tuple[int, int, int, int, int]] = {}
    directories: dict[str, tuple[int, int]] = {}
    total = 0
    def visit(path: Path, key: str, depth: int) -> None:
        nonlocal total
        require(depth <= MAX_DEPTH and len(files) + len(directories) < MAX_ENTRIES, 'CAPTURE_ENTRY_BOUND')
        _path(path)
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            directories[key] = info.st_dev, info.st_ino
            with os.scandir(path) as children:
                for child in children:
                    _name(child.name)
                    visit(path / child.name, key + '/' + child.name, depth + 1)
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'CAPTURE_FILE_SHAPE_REQUIRED')
            require(0 <= info.st_size <= MAX_FILE_BYTES and len(files) < MAX_FILES, 'CAPTURE_BYTES_BOUND')
            total += info.st_size
            require(total <= MAX_TOTAL_BYTES, 'CAPTURE_BYTES_BOUND')
            files[key] = _stamp(info)
    for role in ROLES:
        root = roots[role]
        require(root.is_dir(), 'CAPTURE_ROOTS_REQUIRED')
        visit(root, role, 0)
    require(bool(files), 'CAPTURE_ROOTS_REQUIRED')
    return Tree(files, directories)


def _acl_policy(owner: str, current: str, entries: list[tuple[int, int, str]], *, directory: bool) -> None:
    trusted = {current, 'S-1-5-18', 'S-1-5-32-544'}
    require(owner in trusted and 1 <= len(entries) <= 128, 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
    trusted.add('S-1-3-4')
    allowed, inherit_files, inherit_directories = False, False, False
    for kind, flags, principal in entries:
        require(kind in (0, 1) and not flags & ~0x1f, 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        require(principal in trusted or principal == 'S-1-3-0' and bool(flags & 8), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        allowed |= kind == 0 and not flags & 8 and principal in trusted
        if kind == 0 and (principal in trusted or principal == 'S-1-3-0'):
            inherit_files |= bool(flags & 1)
            inherit_directories |= bool(flags & 2)
    require(allowed and (not directory or inherit_files and inherit_directories), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')


def private_parent(path: Path) -> None:
    """Query existing DACL only. Unknown/exposed ACL blocks; never repair it."""
    _path(path)
    if os.name != 'nt':
        info = path.stat()
        uid = getattr(os, 'getuid')()
        require(info.st_uid == uid and stat.S_IMODE(info.st_mode) & 0o077 == 0,
            'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        return
    from ctypes import wintypes
    # Do not widen the existing native exporter's DLL allowlist.
    adv = getattr(ctypes, 'WinDLL')('advapi32', use_last_error=True)
    kernel = native.windows_library('kernel32')
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    adv.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    adv.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    adv.GetSecurityDescriptorOwner.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    token = wintypes.HANDLE()
    def sid(pointer: Any) -> str:
        result = wintypes.LPWSTR()
        try:
            require(bool(adv.ConvertSidToStringSidW(pointer, ctypes.byref(result))), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
            return str(result.value)
        finally:
            if result:
                kernel.LocalFree(ctypes.cast(result, ctypes.c_void_p))
    try:
        require(bool(adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token))), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        size = wintypes.DWORD()
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        require(0 < size.value <= 65536, 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        buf = ctypes.create_string_buffer(size.value)
        require(bool(adv.GetTokenInformation(token, 1, buf, size, ctypes.byref(size))), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        current = sid(ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0])
        size = wintypes.DWORD()
        adv.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(size))
        require(0 < size.value <= 65536, 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        descriptor = ctypes.create_string_buffer(size.value)
        require(bool(adv.GetFileSecurityW(str(path), 5, descriptor, size, ctypes.byref(size))), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        owner, acl, defaulted, present = ctypes.c_void_p(), ctypes.c_void_p(), wintypes.BOOL(), wintypes.BOOL()
        require(bool(adv.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted)))
            and bool(owner), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        owner_sid = sid(owner)
        require(bool(adv.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(acl),
            ctypes.byref(defaulted))) and bool(present.value) and bool(acl), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        count = int.from_bytes(ctypes.string_at(acl, 8)[4:6], 'little')
        require(1 <= count <= 128, 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
        entries: list[tuple[int, int, str]] = []
        for index in range(count):
            ace = ctypes.c_void_p()
            require(bool(adv.GetAce(acl, index, ctypes.byref(ace))), 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
            raw = ctypes.string_at(ace, 8)
            require(raw[0] in (0, 1) and int.from_bytes(raw[2:4], 'little') >= 16, 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
            address = ace.value
            require(address is not None, 'CAPTURE_PRIVATE_PARENT_UNVERIFIED')
            entries.append((raw[0], raw[1], sid(ctypes.c_void_p(int(address or 0) + 8))))
        _acl_policy(owner_sid, current, entries, directory=path.is_dir())
    finally:
        if token:
            kernel.CloseHandle(token)


class Directory(native.OutputDirectory):
    """Reuse reviewed native chain pinning; allow one safe basename, CREATE_NEW."""
    def open_new(self, name: str) -> BinaryIO:
        _name(name)
        self.validate()
        handle = self.kernel.CreateFileW(self.native_root + '\\' + name,
            0xc0000000, 1, None, 1, 0x00200000, None)
        require(bool(handle) and handle != ctypes.c_void_p(-1).value, 'CAPTURE_NEW_DESTINATION_REQUIRED')
        import msvcrt
        try:
            descriptor = getattr(msvcrt, 'open_osfhandle')(handle, os.O_RDWR | getattr(os, 'O_BINARY'))
            require(type(descriptor) is int, 'CAPTURE_NATIVE_BINDING_MISMATCH')
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise
        try:
            private_parent(self.root / name)  # Check ACTUAL file DACL before any data write.
            return os.fdopen(descriptor, 'wb')
        except BaseException:
            os.close(descriptor)
            raise


def _source_path(roots: dict[str, Path], key: str) -> Path:
    role, *parts = key.split('/')
    return roots[role].joinpath(*parts)


def _check_binding(directory: native.OutputDirectory, binding: dict[str, Any], parts: list[str]) -> None:
    if os.name == 'nt':
        expected = directory.native_root + '\\' + '\\'.join(parts)
        require(binding.get('final_path', '').casefold() == expected.casefold(), 'CAPTURE_NATIVE_BINDING_MISMATCH')


def _hash_fd(fd: int, size: int, sink: BinaryIO | None = None) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest, total = hashlib.sha256(), 0
    while True:
        raw = os.read(fd, min(1024**2, size + 1 - total))
        if not raw:
            break
        total += len(raw)
        require(total <= size, 'CAPTURE_SOURCE_CHANGED')
        digest.update(raw)
        if sink is not None:
            require(sink.write(raw) == len(raw), 'CAPTURE_COPY_MISMATCH')
    require(total == size, 'CAPTURE_SOURCE_CHANGED')
    return digest.hexdigest()


def _new_directory(path: Path) -> None:
    path.mkdir(mode=0o777 if os.name == 'nt' else 0o700)
    private_parent(path)


def _json(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, 'CAPTURE_MANIFEST_INVALID')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def _control(stack: ExitStack, path: Path, maximum: int, *, expected: bytes | None = None,
        expected_sha: str | None = None) -> tuple[int, tuple[int, int, int, int, int], bytes]:
    _path(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        and 0 < before.st_size <= maximum, 'CAPTURE_MANIFEST_INVALID')
    fd = open_read(path)
    stack.callback(os.close, fd)
    identity(fd)  # same-handle regular/single-link identity, not only pathname stat
    raw = bytearray()
    while len(raw) <= maximum:
        block = os.read(fd, min(65536, maximum + 1 - len(raw)))
        if not block:
            break
        raw.extend(block)
    require(len(raw) == before.st_size and len(raw) <= maximum
        and (expected is None or raw == expected)
        and (expected_sha is None or hashlib.sha256(raw).hexdigest() == expected_sha), 'CAPTURE_MANIFEST_ANCHOR_REQUIRED')
    result = bytes(raw)
    _control_unchanged(path, fd, _stamp(before), result)
    return fd, _stamp(before), result


def _control_unchanged(path: Path, fd: int, stamp: tuple[int, int, int, int, int], raw: bytes) -> None:
    _path(path)
    require(_stamp(path.stat()) == stamp and _stamp(os.fstat(fd)) == stamp,
        'CAPTURE_MANIFEST_INVALID')
    require(_hash_fd(fd, len(raw)) == hashlib.sha256(raw).hexdigest(), 'CAPTURE_MANIFEST_INVALID')


def preserve(roots: dict[str, Path], destination: Path | None, day: date, *,
        inspect_only: bool, owner_quiescent: bool) -> dict[str, Any]:
    require(owner_quiescent and type(day) is date, 'CAPTURE_OWNER_QUIESCENCE_REQUIRED')
    require(set(roots) == set(ROLES), 'CAPTURE_ROOTS_REQUIRED')
    code = Path(__file__).resolve().parent
    for root in roots.values():
        _path(root)
        require(not root.resolve().is_relative_to(code) and not code.is_relative_to(root.resolve()), 'CAPTURE_SCOPE_OVERLAP')
    first, second = (roots[role].resolve() for role in ROLES)
    require(not first.is_relative_to(second) and not second.is_relative_to(first), 'CAPTURE_SCOPE_OVERLAP')
    if not inspect_only:
        require(destination is not None, 'CAPTURE_NEW_DESTINATION_REQUIRED')
        assert destination is not None
        require(not os.path.lexists(destination), 'CAPTURE_NEW_DESTINATION_REQUIRED')
        _path(destination.parent)
        require(not destination.resolve().is_relative_to(code) and not code.is_relative_to(destination.resolve())
            and all(not destination.resolve().is_relative_to(r.resolve())
                and not r.resolve().is_relative_to(destination.resolve()) for r in roots.values()), 'CAPTURE_SCOPE_OVERLAP')
        _name(destination.name)
        private_parent(destination.parent)
    before = inventory(roots)
    require(len({before.directories[role] for role in ROLES}) == 2, 'CAPTURE_SCOPE_OVERLAP')
    total = sum(record[2] for record in before.files.values())
    if not inspect_only:
        assert destination is not None
        require(shutil.disk_usage(destination.parent).free >= total * 2 + 1024**3, 'CAPTURE_FREE_SPACE_REQUIRED')
    records: dict[str, dict[str, Any]] = {}
    with ExitStack() as stack:
        pinned: dict[str, native.OutputDirectory] = {}
        for key in sorted(before.directories, key=lambda k: (k.count('/'), k)):
            pinned[key] = stack.enter_context(Directory(_source_path(roots, key), before.directories[key]))
        opened: dict[str, int] = {}
        for key, stamp in sorted(before.files.items()):
            path = _source_path(roots, key)
            fd = open_read(path)
            stack.callback(os.close, fd)
            require(_stamp(os.fstat(fd)) == stamp, 'CAPTURE_SOURCE_CHANGED')
            binding = identity(fd)
            role, *parts = key.split('/')
            _check_binding(pinned[role], binding, parts)
            opened[key] = fd
            records[key] = dict(bytes=stamp[2], sha256=_hash_fd(fd, stamp[2]))
        require(inventory(roots) == before, 'CAPTURE_SOURCE_CHANGED')
        if not inspect_only:
            assert destination is not None
            _new_directory(destination)
            out = stack.enter_context(Directory(destination, (destination.stat().st_dev, destination.stat().st_ino)))
            out.publish('attempt.json', ATTEMPT)
            marker_fd, marker_stamp, marker_raw = _control(stack, destination / 'attempt.json', 256, expected=ATTEMPT)
            for key in sorted(before.directories, key=lambda k: (k.count('/'), k)):
                _new_directory(destination / key)
            for key, record in records.items():
                target = destination / key
                with Directory(target.parent, (target.parent.stat().st_dev, target.parent.stat().st_ino)) as directory:
                    with directory.open_new(target.name) as output:
                        require(_hash_fd(opened[key], record['bytes'], output) == record['sha256'], 'CAPTURE_SOURCE_CHANGED')
                        output.flush()
                        os.fsync(output.fileno())
        for key, fd in opened.items():
            require(_stamp(os.fstat(fd)) == before.files[key]
                and _hash_fd(fd, records[key]['bytes']) == records[key]['sha256'], 'CAPTURE_SOURCE_CHANGED')
        require(inventory(roots) == before, 'CAPTURE_SOURCE_CHANGED')
        for directory in pinned.values():
            directory.validate()
        base = dict(format=FORMAT, session_date=day.isoformat(), roots=list(ROLES),
            directories=sorted(before.directories), files=records,
            scope='BOTH_CAPTURE_ROOTS_DEFAULT_STREAMS', owner_quiescence_attested=True,
            atomic_snapshot=False, database_integrity_verified=False, authenticated=False,
            independent_custody=False, restore_verified=False, deletion_authorised=False,
            acl_or_alternate_streams_copied=False, scheduled_task_definitions_included=False)
        if inspect_only:
            return dict(status='CAPTURE_ROOTS_INSPECTED_NOT_PRESERVED', files=len(records), bytes=total,
                sqlite_sidecar_names=sum(k.endswith(('-wal', '-shm', '-journal')) for k in records),
                lock_named_files=sum(k.endswith(('.lock', '-lock')) for k in records),
                source_writes=0, writes=0, network_calls=0, approval_authority=False)
        assert destination is not None
        # Re-read destination independently, including zero-byte files, before
        # the completion manifest exists. Never trust only source stream hashes.
        for key, record in records.items():
            private_parent(destination / key)
            fd = open_read(destination / key)
            try:
                require(_hash_fd(fd, record['bytes']) == record['sha256'], 'CAPTURE_COPY_MISMATCH')
            finally:
                os.close(fd)
        retained = inventory({role: destination / role for role in ROLES})
        require(set(retained.files) == set(records) and set(retained.directories) == set(before.directories)
            and all(retained.files[key][2] == record['bytes'] for key, record in records.items()), 'CAPTURE_COPY_MISMATCH')
        _top_names(destination, {*ROLES, 'attempt.json'})
        require(inventory(roots) == before, 'CAPTURE_SOURCE_CHANGED')
        private_parent(destination / 'attempt.json')
        _control_unchanged(destination / 'attempt.json', marker_fd, marker_stamp, marker_raw)
        raw = json.dumps(base, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'
        require(len(raw) <= MAX_MANIFEST_BYTES, 'CAPTURE_BYTES_BOUND')
        out.publish('manifest.json', raw)
        _control(stack, destination / 'manifest.json', MAX_MANIFEST_BYTES, expected=raw)
        return dict(status='CAPTURE_TWO_ROOTS_OPAQUE_COPY_VERIFIED_NOT_CUSTODY', files=len(records),
            bytes=total, manifest_sha256=hashlib.sha256(raw).hexdigest(), source_writes=0,
            network_calls=0, credential_reads=0, approval_authority=False, retry_authorised=False,
            independent_custody=False, restore_verified=False)


def _top_names(root: Path, expected: set[str]) -> None:
    names: set[str] = set()
    with os.scandir(root) as entries:
        for entry in entries:
            require(len(names) < len(expected), 'CAPTURE_MANIFEST_INVALID')
            names.add(entry.name)
    require(names == expected, 'CAPTURE_MANIFEST_INVALID')


def verify(root: Path, expected_sha: str) -> dict[str, Any]:
    require(type(expected_sha) is str and re.fullmatch('[a-f0-9]{64}', expected_sha) is not None,
        'CAPTURE_MANIFEST_ANCHOR_REQUIRED')
    resolved = root.resolve()
    code = Path(__file__).resolve().parent
    mutable = Path(os.environ.get('LOCALAPPDATA', '')) / 'KiranTrading'
    require(not resolved.is_relative_to(code) and not code.is_relative_to(resolved)
        and all(not resolved.is_relative_to((mutable / role).resolve())
            and not (mutable / role).resolve().is_relative_to(resolved) for role in ROLES),
        'CAPTURE_SCOPE_OVERLAP')
    _path(root)
    private_parent(root)
    with ExitStack() as stack:
        guard = stack.enter_context(Directory(root, (root.stat().st_dev, root.stat().st_ino)))
        report = _verify_locked(root, expected_sha, stack)
        guard.validate()
        return report


def _verify_locked(root: Path, expected_sha: str, stack: ExitStack) -> dict[str, Any]:
    path = root / 'manifest.json'
    manifest_fd, manifest_stamp, raw = _control(stack, path, MAX_MANIFEST_BYTES, expected_sha=expected_sha)
    value = _json(raw)
    expected_keys = {'format', 'session_date', 'roots', 'directories', 'files', 'scope',
        'owner_quiescence_attested', 'atomic_snapshot', 'database_integrity_verified', 'authenticated',
        'independent_custody', 'restore_verified', 'deletion_authorised',
        'acl_or_alternate_streams_copied', 'scheduled_task_definitions_included'}
    require(type(value) is dict and set(value) == expected_keys and value['format'] == FORMAT
        and value['roots'] == list(ROLES) and value['scope'] == 'BOTH_CAPTURE_ROOTS_DEFAULT_STREAMS'
        and value['owner_quiescence_attested'] is True
        and all(value[k] is False for k in expected_keys - {'format', 'session_date', 'roots',
            'directories', 'files', 'scope', 'owner_quiescence_attested'}), 'CAPTURE_MANIFEST_INVALID')
    require(type(value['session_date']) is str and date.fromisoformat(value['session_date']).isoformat()
        == value['session_date'], 'CAPTURE_MANIFEST_INVALID')
    observed = inventory({role: root / role for role in ROLES})
    for directory in observed.directories:
        private_parent(root / directory)
    require(type(value['directories']) is list and value['directories'] == sorted(observed.directories)
        and type(value['files']) is dict and set(value['files']) == set(observed.files), 'CAPTURE_MANIFEST_INVALID')
    for key, record in value['files'].items():
        require(type(record) is dict and set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int
            and 0 <= record['bytes'] <= MAX_FILE_BYTES and type(record['sha256']) is str
            and re.fullmatch('[a-f0-9]{64}', record['sha256']) is not None, 'CAPTURE_MANIFEST_INVALID')
        private_parent(root / key)
        fd = open_read(root / key)
        try:
            require(_stamp(os.fstat(fd)) == observed.files[key]
                and record['bytes'] == observed.files[key][2]
                and _hash_fd(fd, record['bytes']) == record['sha256']
                and _stamp(os.fstat(fd)) == observed.files[key], 'CAPTURE_COPY_MISMATCH')
        finally:
            os.close(fd)
    require(inventory({role: root / role for role in ROLES}) == observed, 'CAPTURE_COPY_MISMATCH')
    _top_names(root, {*ROLES, 'attempt.json', 'manifest.json'})
    attempt = root / 'attempt.json'
    private_parent(path)
    private_parent(attempt)
    _control(stack, attempt, 256, expected=ATTEMPT)
    _control_unchanged(path, manifest_fd, manifest_stamp, raw)
    return dict(status='CAPTURE_COPY_BYTES_VERIFIED_NOT_CUSTODY', files=len(observed.files), writes=0,
        source_reads=0, network_calls=0, independent_custody=False, restore_verified=False, approval_authority=False)


def _cipher_path(path: Path) -> None:
    _path(path)
    code = Path(__file__).resolve().parent
    base = Path(os.environ.get('LOCALAPPDATA', '')) / 'KiranTrading'
    require(not path.resolve().is_relative_to(code)
        and all(not path.resolve().is_relative_to((base / role).resolve()) for role in ROLES),
        'CAPTURE_SCOPE_OVERLAP')


def probe_cipher(path: Path) -> dict[str, Any]:
    """Owner physically identifies disk FIRST; a digest is not physical attestation."""
    _cipher_path(path)
    fd = open_read(path)
    try:
        binding = identity(fd)
        require(_stamp(path.stat()) == _stamp(os.fstat(fd)), 'CAPTURE_NATIVE_BINDING_MISMATCH')
        volume = binding['volume']
        return dict(status='CAPTURE_CIPHER_VOLUME_OBSERVED_NOT_ENROLLED',
            destination_volume_sha256=hashlib.sha256(volume.encode()).hexdigest(),
            file_content_reads=0, writes=0, network_calls=0, raw_paths_printed=False,
            physical_disk_independence_verified=False, independent_custody=False, approval_authority=False)
    finally:
        os.close(fd)


def verify_cipher(source: Path, destination: Path, expected_bytes: int, expected_sha: str,
        expected_volume_sha: str) -> dict[str, Any]:
    require(type(expected_bytes) is int and 0 < expected_bytes <= MAX_CIPHER_BYTES
        and type(expected_sha) is str and re.fullmatch('[a-f0-9]{64}', expected_sha) is not None
        and type(expected_volume_sha) is str and re.fullmatch('[a-f0-9]{64}', expected_volume_sha) is not None,
        'CAPTURE_CIPHER_ANCHOR_REQUIRED')
    _cipher_path(source)
    _cipher_path(destination)
    with ExitStack() as stack:
        held: list[dict[str, Any]] = []
        for path in (source, destination):
            fd = open_read(path)
            stack.callback(os.close, fd)
            held.append(identity(fd))
        left, right = measure(source, expected_bytes), measure(destination, expected_bytes)
        require(all(record['bytes'] == expected_bytes and record['sha256'] == expected_sha for record in (left, right))
            and [left['binding'], right['binding']] == held, 'CAPTURE_CIPHER_ANCHOR_REQUIRED')
        require(left['binding']['volume'] != right['binding']['volume']
            and hashlib.sha256(right['binding']['volume'].encode()).hexdigest() == expected_volume_sha,
            'CAPTURE_DESTINATION_VOLUME_REQUIRED')
    return dict(status='CAPTURE_CIPHER_COPIES_BYTES_AND_DESTINATION_BOUND_NOT_CUSTODY',
        writes=0, network_calls=0, credential_reads=0, independent_custody=False,
        encryption_verified=False, physical_disk_independence_verified=False,
        restore_verified=False, deletion_authorised=False, approval_authority=False)


def _reason(error: BaseException) -> str:
    code = error.args[0] if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str else ''
    if code in SAFE:
        return code
    mapping = {'NATIVE_READ_HANDLE_UNAVAILABLE': 'CAPTURE_SOURCE_HANDLE_UNAVAILABLE',
        'NATIVE_HANDLE_VOLUME_UNVERIFIED': 'CAPTURE_NATIVE_BINDING_MISMATCH',
        'NATIVE_FILE_CHANGED': 'CAPTURE_NATIVE_BINDING_MISMATCH',
        'REVIEWED_NORMAL_WINDOWS_CONSOLE_REQUIRED': 'CAPTURE_NATIVE_PLATFORM_REQUIRED',
        'LOCAL_NATIVE_PATH_REQUIRED': 'CAPTURE_PATH_REVIEW_REQUIRED',
        'ABSOLUTE_NONLINK_PATH_REQUIRED': 'CAPTURE_PATH_REVIEW_REQUIRED',
        'SINGLE_LINK_REGULAR_FILE_REQUIRED': 'CAPTURE_FILE_SHAPE_REQUIRED',
        'FILE_SIZE_BOUND': 'CAPTURE_BYTES_BOUND', 'FILE_CHANGED': 'CAPTURE_SOURCE_CHANGED'}
    if code in mapping:
        return mapping[code]
    if isinstance(error, OSError):
        if getattr(error, 'winerror', None) == 32:
            return 'CAPTURE_SHARING_REVIEW_REQUIRED'
        if error.errno == 28:
            return 'CAPTURE_FREE_SPACE_REQUIRED'
        if error.errno == 13:
            return 'CAPTURE_ACCESS_REVIEW_REQUIRED'
    return 'CAPTURE_ROOTS_IO_REVIEW_REQUIRED'


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError('CAPTURE_INVALID_ARGUMENTS')


def main(argv: Sequence[str] | None = None) -> int:
    stage = 'ARGUMENTS'
    console: tuple[Any, int, int] | None = None
    result: dict[str, Any]
    status = 0
    try:
        parser = _Parser(description=__doc__, allow_abbrev=False)
        parser.add_argument('--mode', choices=('preview', 'inspect', 'preserve', 'verify', 'probe-cipher', 'verify-cipher'), default='preview')
        parser.add_argument('--destination', type=Path)
        parser.add_argument('--session-date', type=date.fromisoformat)
        parser.add_argument('--expected-manifest-sha256')
        parser.add_argument('--confirm-no-writers', action='store_true')
        parser.add_argument('--confirm-run', action='store_true')
        parser.add_argument('--reviewed-source')
        parser.add_argument('--cipher-source', type=Path)
        parser.add_argument('--cipher-destination', type=Path)
        parser.add_argument('--expected-cipher-bytes', type=int)
        parser.add_argument('--expected-cipher-sha256')
        parser.add_argument('--expected-destination-volume-sha256')
        args = parser.parse_args(argv)
        if args.mode == 'preview' or not args.confirm_run:
            print(json.dumps(dict(status='PREVIEW', input_reads=0, writes=0, credential_reads=0,
                network_calls=0, task_mutations=0, source_writes=0)))
            return 0
        stage = 'SOURCE_BINDING'
        native.reviewed_source(args.reviewed_source, 'standalone-backup-v1')
        stage = 'NATIVE_ADMISSION'
        require(sys.version_info[:3] == (3, 13, 9), 'CAPTURE_NATIVE_PLATFORM_REQUIRED')
        console = native._console()
        if args.mode in ('probe-cipher', 'verify-cipher'):
            stage = 'CIPHER_DESTINATION_BINDING'
            require(args.cipher_destination is not None, 'CAPTURE_CIPHER_ANCHOR_REQUIRED')
            if args.mode == 'probe-cipher':
                result = probe_cipher(args.cipher_destination)
            else:
                require(args.cipher_source is not None, 'CAPTURE_CIPHER_ANCHOR_REQUIRED')
                result = verify_cipher(args.cipher_source, args.cipher_destination, args.expected_cipher_bytes,
                    args.expected_cipher_sha256, args.expected_destination_volume_sha256)
        elif args.mode == 'verify':
            require(args.destination is not None, 'CAPTURE_NEW_DESTINATION_REQUIRED')
            stage = 'COPY_VERIFICATION'
            result = verify(args.destination, args.expected_manifest_sha256)
        else:
            require(args.confirm_no_writers and args.session_date is not None, 'CAPTURE_OWNER_QUIESCENCE_REQUIRED')
            parent = Path(os.environ.get('LOCALAPPDATA', '')) / 'KiranTrading'
            stage = 'TWO_ROOTS_OPAQUE_INSPECTION' if args.mode == 'inspect' else 'TWO_ROOTS_OPAQUE_COPY'
            result = preserve({role: parent / role for role in ROLES}, args.destination,
                args.session_date, inspect_only=args.mode == 'inspect', owner_quiescent=args.confirm_no_writers)
    except BaseException as error:
        result = dict(status='BLOCKED', code=_reason(error), stage=stage, raw_error_printed=False,
            retry_authorised=False, source_writes=0, partial_destination_retained=True, approval_authority=False)
        status = 2
    finally:
        if console is not None and not native.restore_console(console):
            result = dict(status='BLOCKED', code='CAPTURE_NATIVE_PLATFORM_REQUIRED', stage='CONSOLE_RESTORE',
                retry_authorised=False, raw_error_printed=False, approval_authority=False)
            status = 2
    print(json.dumps(result, sort_keys=True))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
