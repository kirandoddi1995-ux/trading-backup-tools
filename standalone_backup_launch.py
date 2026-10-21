"""Reviewed -I -S -B bootstrap, before any product/site import. Default is no IO."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types
from typing import NoReturn, Sequence


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError('INVALID_ARGUMENTS')


def trusted_gate(root: Path, expected_sha: str | None) -> types.ModuleType:
    """Trusted bootstrap authenticates source BEFORE executing the gate.

    Interpreter, Git binary and this reviewed entrypoint are the trust base.
    No claim of defending an already substituted bootstrap or compromised OS.
    Execute committed source explicitly, never a cached .pyc via importlib.
    """
    if type(expected_sha) is not str or re.fullmatch('[a-f0-9]{40}', expected_sha) is None:
        raise ValueError('EXTERNAL_SOURCE_PIN_REQUIRED')
    env = {key: value for key, value in os.environ.items() if key.upper() in
        ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull, GIT_GRAFT_FILE=os.devnull)
    def git(*args: str) -> bytes:
        child = subprocess.run(('git', '--no-replace-objects', '--no-optional-locks',
            '-c', 'core.fsmonitor=false', '-C', str(root), *args), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        if child.returncode or len(child.stdout) > 2**20:
            raise ValueError('EXTERNAL_SOURCE_PIN_REQUIRED')
        return child.stdout
    if (git('rev-parse', 'HEAD').decode().strip() != expected_sha or
            Path(git('rev-parse', '--show-toplevel').decode().strip()).resolve() != root):
        raise ValueError('EXTERNAL_SOURCE_PIN_REQUIRED')
    committed: dict[str, bytes] = {}
    for name in ('standalone_backup_launch.py', 'standalone_backup_contract.py'):
        path = root / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or getattr(info, 'st_file_attributes', 0) & 0x400 or not 0 < info.st_size <= 2**20):
            raise ValueError('AUTHENTICATED_BOOTSTRAP_REQUIRED')
        raw = git('show', expected_sha + ':' + name)
        if path.read_bytes().replace(b'\r\n', b'\n') != raw.replace(b'\r\n', b'\n'):
            raise ValueError('AUTHENTICATED_BOOTSTRAP_REQUIRED')
        committed[name] = raw
    gate = types.ModuleType('standalone_backup_contract')
    gate.__file__ = str(root / 'standalone_backup_contract.py')
    exec(compile(committed['standalone_backup_contract.py'], gate.__file__, 'exec'), gate.__dict__)
    return gate


def runtime_site(executable: Path, root: Path) -> Path:
    prefix = executable.parent.parent
    site = prefix / ('Lib/site-packages' if sys.platform == 'win32' else 'lib/python3.13/site-packages')
    if not (prefix / 'pyvenv.cfg').is_file() or not site.is_dir() or site.is_symlink():
        raise ValueError('DEDICATED_BACKUP_VENV_REQUIRED')
    if site == root or root in site.parents:
        raise ValueError('ENVIRONMENT_OUTSIDE_CHECKOUT_REQUIRED')
    for parent in (site, *site.parents):
        if parent.is_symlink() or getattr(parent.stat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('NONLINK_RUNTIME_REQUIRED')
    return site


def admit_runtime(site: Path, requirements: bytes) -> None:
    from importlib import metadata  # stdlib; site code and .pth are still not run
    expected: dict[str, str] = {}
    for line in requirements.decode().splitlines():
        match = re.match(r'^([A-Za-z0-9_-]+)==([0-9.]+)(?:\s|$)', line)
        if match:
            expected[match[1].lower().replace('_', '-')] = match[2]
    if set(expected) != {'cryptography', 'cffi', 'pycparser', 'packaging'}:
        raise ValueError('EXACT_BACKUP_RUNTIME_REQUIRED')
    observed: dict[str, str] = {}
    for item in metadata.distributions(path=[str(site)]):
        name = item.metadata['Name'].lower().replace('_', '-')
        if name in observed:
            raise ValueError('DUPLICATE_RUNTIME_DISTRIBUTION')
        observed[name] = item.version
    if observed != expected:
        raise ValueError('EXACT_BACKUP_RUNTIME_REQUIRED')


def main(argv: Sequence[str] | None = None) -> int:
    stage = 'ARGUMENTS'
    try:
        parser = _Parser(description=__doc__)
        parser.add_argument('--operation', choices=('backup', 'watch'), default='backup')
        parser.add_argument('--reviewed-source')
        parser.add_argument('--confirm-run', action='store_true')
        args, tail = parser.parse_known_args(argv)
        if not args.confirm_run:
            print(json.dumps(dict(status='PREVIEW', input_reads=0, writes=0,
                credential_reads=0, network_calls=0, source_connections=0)))
            return 0
        stage = 'BOOTSTRAP_FLAGS'
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                and sys.version_info[:3] == (3, 13, 9)):
            raise ValueError('REVIEWED_ISOLATED_3139_BOOTSTRAP_REQUIRED')
        stage = 'SOURCE_BINDING'
        root = Path(__file__).resolve().parent
        gate = trusted_gate(root, args.reviewed_source)
        gate.verify_checkout(root, args.reviewed_source)
        stage = 'RUNTIME_METADATA'
        site = runtime_site(Path(sys.executable), root)
        admit_runtime(site, gate.read_public(root, 'requirements-runtime.txt'))
        # -S means no .pth/sitecustomize/usercustomize execution; only these two
        # explicit paths are added AFTER source and metadata admission.
        sys.path[:0] = [str(root), str(site)]
        sys.modules['standalone_backup_contract'] = gate
        stage = 'PRODUCT_DISPATCH'
        if args.operation == 'watch':
            import dependency_pair_watch
            return dependency_pair_watch.main(tail)
        import live_database_backup
        return live_database_backup.main([*tail, '--reviewed-source', args.reviewed_source,
            '--source-profile', 'standalone-backup-v1', '--confirm-run'])
    except BaseException:
        print(json.dumps(dict(status='BLOCKED', code='ISOLATED_BACKUP_BOOTSTRAP_REVIEW_REQUIRED',
            stage=stage,
            raw_error_printed=False, retry_authorised=False, backup_authorised=False)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
