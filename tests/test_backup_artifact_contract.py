"""Synthetic data boundary only; no filesystem, backup or restore acceptance."""
from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

import backup_artifact_contract as contract


def fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    observed = {name: dict(bytes=10, sha256='a' * 64) for name in contract.LIMITS}
    manifest = dict(version='live-logical-backup-v1', status='OPAQUE_LOGICAL_EXPORT_NOT_RESTORE',
        tools={}, ca={}, native_acceptance_is_owner_attestation=True,
        **{key: False for key in contract.FALSE_FIELDS})
    manifest['artifacts'] = {name: dict(measured={**value, 'binding': {'final_path': 'private-sentinel'}},
        started_at='synthetic', finished_at='synthetic', native={**value, 'stderr_bytes': 0,
        'native_exit': 0, 'both_pipe_eof': True}) for name, value in observed.items()}
    return manifest, observed


def test_projection_retains_raw_hash_not_private_paths_or_authority() -> None:
    manifest, observed = fixture()
    raw = json.dumps(manifest).encode() + b'\r\n'
    result = contract.project(raw, 'b' * 40, observed)
    assert result['manifest']['sha256'] == hashlib.sha256(raw).hexdigest()
    assert 'private-sentinel' not in json.dumps(result)
    assert not any(result[key] for key in ('roles_same_snapshot', 'same_generation_verified',
        'authenticated_custody', 'restore_verified', 'deletion_authorised'))


@pytest.mark.parametrize('case', ['source', 'missing', 'extra', 'bool_size', 'big_size', 'hash',
    'disagreement', 'native_exit', 'native_bool', 'native_eof', 'restore_claim', 'version', 'duplicate', 'nan'])
def test_unknown_or_mismatched_data_never_admits(case: str) -> None:
    manifest, observed = fixture()
    source = 'b' * 40
    native = manifest['artifacts']['database.dump']['native']
    if case == 'source':
        source = 'main'
    elif case == 'missing':
        del observed['roles.sql']
    elif case == 'extra':
        observed['other.sql'] = observed['roles.sql']
    elif case == 'bool_size':
        observed['roles.sql']['bytes'] = True
    elif case == 'big_size':
        observed['roles.sql']['bytes'] = 16 * 1024**2 + 1
    elif case == 'hash':
        observed['roles.sql']['sha256'] = 'not-a-hash'
    elif case == 'disagreement':
        observed['roles.sql']['bytes'] = 11
    elif case == 'native_exit':
        native['native_exit'] = 1
    elif case == 'native_bool':
        native['native_exit'] = False
    elif case == 'native_eof':
        native['both_pipe_eof'] = False
    elif case == 'restore_claim':
        manifest['restore_verified'] = True
    elif case == 'version':
        manifest['version'] = 'unknown'
    raw = json.dumps(manifest).encode()
    if case == 'duplicate':
        raw = raw.replace(b'"tools": {}', b'"tools": {}, "tools": {}')
    if case == 'nan':
        raw = raw.replace(b'"tools": {}', b'"tools": NaN')
    with pytest.raises(ValueError):
        contract.project(raw, source, observed)


def test_interface_is_data_only_and_matches_bounds() -> None:
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    path = root / 'BACKUP_ARTIFACT_INTERFACE.json'
    if not path.exists():
        path = root / 'backup_delivery_templates/artifact-interface.json'
    value = json.loads(path.read_text())
    assert value['artifact_byte_limits'] == contract.LIMITS
    assert value['manifest_byte_limit'] == contract.MAX_MANIFEST
    assert value['cross_repository_code_imports_allowed'] is False
