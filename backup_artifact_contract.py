"""Pure data projection for an unsigned opaque backup; no files or DB imports.

The main restore repository owns its own consumer. It exchanges data, NEVER
imports this module from a sibling checkout. Equal hashes are not provenance.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

FORMAT = 'opaque-backup-handoff-v1'
LIMITS = {'database.dump': 4 * 1024**3, 'roles.sql': 16 * 1024**2, 'toc.list': 16 * 1024**2}
MAX_MANIFEST = 1024**2
FALSE_FIELDS = ('roles_same_snapshot', 'local_clock_verified', 'platform_complete',
    'independent_custody_verified', 'restore_verified', 'deletion_authorised', 'training_eligible')


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('BACKUP_DATA_DUPLICATE_KEY')
        result[key] = value
    return result


def _record(value: object, maximum: int) -> dict[str, Any]:
    if (type(value) is not dict or set(value) != {'bytes', 'sha256'}
            or type(value['bytes']) is not int or not 0 < value['bytes'] <= maximum
            or type(value['sha256']) is not str or re.fullmatch('[a-f0-9]{64}', value['sha256']) is None):
        raise ValueError('BACKUP_DATA_ARTIFACT_INVALID')
    return dict(value)


def project(raw_manifest: bytes, source_sha: str,
        observed: Mapping[str, object]) -> dict[str, Any]:
    """Caller supplies raw manifest and independently measured opaque records.

    This pure function cannot establish that supplied measurements were made.
    No path/volume identifier, role content or password enters its projection.
    Source commit is external approval, never discovered from a local HEAD.
    """
    if type(source_sha) is not str or re.fullmatch('[a-f0-9]{40}', source_sha) is None:
        raise ValueError('BACKUP_DATA_EXTERNAL_SOURCE_REQUIRED')
    if type(raw_manifest) is not bytes or not 0 < len(raw_manifest) <= MAX_MANIFEST:
        raise ValueError('BACKUP_DATA_MANIFEST_BOUND')
    manifest = json.loads(raw_manifest, object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('BACKUP_DATA_NONFINITE')))
    keys = {'version', 'status', 'artifacts', 'tools', 'ca', 'native_acceptance_is_owner_attestation', *FALSE_FIELDS}
    if (type(manifest) is not dict or set(manifest) != keys
            or manifest['version'] != 'live-logical-backup-v1'
            or manifest['status'] != 'OPAQUE_LOGICAL_EXPORT_NOT_RESTORE'
            or manifest['native_acceptance_is_owner_attestation'] is not True
            or any(manifest[name] is not False for name in FALSE_FIELDS)
            or type(manifest['artifacts']) is not dict or set(manifest['artifacts']) != set(LIMITS)
            or set(observed) != set(LIMITS)):
        raise ValueError('BACKUP_DATA_MANIFEST_INVALID')
    records: dict[str, Any] = {}
    for name, maximum in LIMITS.items():
        artifact = manifest['artifacts'][name]
        if type(artifact) is not dict or set(artifact) != {'measured', 'started_at', 'finished_at', 'native'}:
            raise ValueError('BACKUP_DATA_MANIFEST_INVALID')
        measured, native = artifact['measured'], artifact['native']
        if type(measured) is not dict or set(measured) != {'bytes', 'sha256', 'binding'}:
            raise ValueError('BACKUP_DATA_MANIFEST_INVALID')
        record = _record({key: measured[key] for key in ('bytes', 'sha256')}, maximum)
        if (_record(observed[name], maximum) != record or type(native) is not dict
                or set(native) != {'bytes', 'sha256', 'stderr_bytes', 'native_exit', 'both_pipe_eof'}
                or _record({key: native[key] for key in ('bytes', 'sha256')}, maximum) != record
                or type(native['native_exit']) is not int or native['native_exit'] != 0
                or type(native['stderr_bytes']) is not int or native['stderr_bytes'] != 0
                or native['both_pipe_eof'] is not True):
            raise ValueError('BACKUP_DATA_MEASUREMENT_MISMATCH')
        records[name] = record
    return dict(format=FORMAT, producer_source_sha=source_sha,
        manifest=dict(bytes=len(raw_manifest), sha256=hashlib.sha256(raw_manifest).hexdigest()),
        artifacts=records, measurements_supplied_not_authenticated=True,
        roles_same_snapshot=False, same_generation_verified=False,
        authenticated_custody=False, restore_verified=False, deletion_authorised=False)
