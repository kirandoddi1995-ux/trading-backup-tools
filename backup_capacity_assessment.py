"""Pure assessment of supplied capacity facts, never acquisition or write admission.

SQL companion: sql/backup_capacity_sample_read_only.sql. The caller supplies facts
and an aware clock; this module has no CLI, file IO, database, network, clock or
credential discovery. Source labels and samples are NOT authenticated here.
Cluster allocation excludes WAL/system disk usage. Physical sizes are not an
atomic MVCC snapshot, even when their catalog inventory is repeatable-read.
Local capture polls are not database writes and are never converted into growth.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fractions import Fraction
import re
from typing import Any, cast

FORMAT = 'backup-capacity-sample-v1'
METRIC = 'pg_database_size:all_databases:v1'
CURRENT_METRIC = 'pg_database_size:current_database:v1'
QUOTA_BYTES = 500_000_000
FLOOR_BYTES = 24_000_000
WARNING_BYTES = 64_000_000
MAX_DATABASES = 64
MAX_SAMPLES = 256
MAX_AGE = timedelta(hours=24)
MIN_TREND_SPAN = timedelta(hours=24)
MAX_SAMPLE_DURATION = timedelta(seconds=60)
MAX_BYTES = 2**63 - 1
TARGETS = (
    ('quant_app', 'mf_nav'), ('quant_app', 'market_quotes'),
    ('quant_app', 'universe_membership'), ('quant_app', 'universe_membership_versions'),
    ('quant_app', 'scanner_observations'), ('equity_research', 'outcomes'),
    ('quant_app', 'evidence_ledger_events'), ('quant_app', 'market_daily_volumes'),
)
SAMPLE_KEYS = frozenset(('format', 'metric', 'current_metric', 'source_id',
    'started_at', 'finished_at', 'server_major', 'database_name', 'database_oid',
    'database_count', 'databases', 'complete', 'current_database_bytes',
    'cluster_database_bytes', 'relations', 'business_rows_read'))
RELATION_KEYS = frozenset(('schema', 'name', 'present', 'kind', 'oid', 'relfilenode',
    'size_complete', 'total_bytes', 'table_bytes', 'indexes_bytes'))


class CapacityError(ValueError):
    """Only fixed public codes escape validation, never supplied data."""


def _require(condition: bool, code: str = 'SAMPLE_INVALID') -> None:
    if not condition:
        raise CapacityError(code)


def _text(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 256
        and not any(ord(char) < 32 for char in value))


def _integer(value: object, minimum: int = 0, maximum: int = MAX_BYTES) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _time(value: object) -> datetime:
    if type(value) is not str or len(value) > 64:
        raise CapacityError('SAMPLE_TIME_INVALID')
    try:
        instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
        _require(instant.utcoffset() is not None, 'SAMPLE_TIME_INVALID')
        return instant.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise CapacityError('SAMPLE_TIME_INVALID') from None


def _duration_us(delta: timedelta) -> int:
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def validate_sample(value: object) -> tuple[dict[str, Any], datetime, datetime]:
    """Validate exact JSON-compatible shape; partial facts never become complete."""
    _require(type(value) is dict and set(value) == SAMPLE_KEYS)
    value = cast(dict[str, Any], value)
    _require(value['format'] == FORMAT, 'SAMPLE_FORMAT_MISMATCH')
    _require(value['metric'] == METRIC and value['current_metric'] == CURRENT_METRIC,
             'SAMPLE_METRIC_MISMATCH')
    _require(type(value['complete']) is bool)
    source = value['source_id']
    _require(source is None or type(source) is str and
        re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', source) is not None)
    _require(not value['complete'] or source is not None)
    _require(type(value['server_major']) is int and value['server_major'] == 17)
    _require(_text(value['database_name']) and _integer(value['database_oid'], 1, 2**32 - 1))
    _require(_integer(value['database_count'], 1, 2**31 - 1))
    _require(type(value['business_rows_read']) is int and value['business_rows_read'] == 0)
    _require(_integer(value['current_database_bytes'], 1))
    start, end = _time(value['started_at']), _time(value['finished_at'])
    _require(timedelta(0) <= end - start <= MAX_SAMPLE_DURATION, 'SAMPLE_WINDOW_INVALID')
    databases = value['databases']
    if value['database_count'] > MAX_DATABASES:
        _require(databases is None and not value['complete'])
    else:
        _require(type(databases) is list and len(databases) == value['database_count'])
        oids: set[int] = set()
        names: set[str] = set()
        for row in databases:
            _require(type(row) is dict and set(row) == {'oid', 'name', 'bytes'})
            _require(_integer(row['oid'], 1, 2**32 - 1) and _text(row['name']))
            _require(row['oid'] not in oids and row['name'] not in names)
            oids.add(row['oid'])
            names.add(row['name'])
            _require(_integer(row['bytes']) if value['complete'] else row['bytes'] is None)
        current = [row for row in databases if row['oid'] == value['database_oid']]
        _require(len(current) == 1 and current[0]['name'] == value['database_name'])
    if value['complete']:
        _require(_integer(value['cluster_database_bytes'], 1))
        _require(sum(row['bytes'] for row in databases) == value['cluster_database_bytes'])
        _require(current[0]['bytes'] == value['current_database_bytes'])
    else:
        _require(value['cluster_database_bytes'] is None)
    relations = value['relations']
    _require(type(relations) is list and len(relations) == len(TARGETS))
    identities: set[tuple[str, str]] = set()
    for row in relations:
        _require(type(row) is dict and set(row) == RELATION_KEYS)
        _require(_text(row['schema']) and _text(row['name']))
        identity = (row['schema'], row['name'])
        _require(identity in TARGETS and identity not in identities)
        identities.add(identity)
        _require(type(row['present']) is bool and type(row['size_complete']) is bool)
        if row['present']:
            _require(row['kind'] in ('r', 'p') and _integer(row['oid'], 1, 2**32 - 1)
                and _integer(row['relfilenode'], 0, 2**32 - 1))
            _require(row['size_complete'] == (row['kind'] == 'r'))
        else:
            _require(not row['size_complete'] and all(row[k] is None
                for k in ('kind', 'oid', 'relfilenode')))
        for field in ('total_bytes', 'table_bytes', 'indexes_bytes'):
            _require(_integer(row[field]) if row['size_complete'] else row[field] is None)
        # File-size functions are live observations; no false exact component-sum invariant.
    return value, start, end


def _identity(sample: dict[str, Any]) -> tuple[object, ...]:
    inventory = sample['databases']
    return (sample['source_id'], sample['metric'], sample['current_metric'],
        sample['server_major'], sample['database_name'], sample['database_oid'],
        None if inventory is None else tuple(sorted((r['oid'], r['name']) for r in inventory)))


def _relation_deltas(before: dict[str, Any], after: dict[str, Any],
                     interval_us: int) -> list[dict[str, Any]]:
    old = {(r['schema'], r['name']): r for r in before['relations']}
    new = {(r['schema'], r['name']): r for r in after['relations']}
    results: list[dict[str, Any]] = []
    for identity in TARGETS:
        left, right = old[identity], new[identity]
        comparable = (left['size_complete'] and right['size_complete']
            and (left['oid'], left['relfilenode']) == (right['oid'], right['relfilenode']))
        delta = right['total_bytes'] - left['total_bytes'] if comparable else None
        rate = Fraction(delta * 86_400_000_000, interval_us) if delta is not None else None
        results.append(dict(schema=identity[0], name=identity[1], comparable=comparable,
            delta_bytes=delta, observed_bytes_per_day_ceiling=None if rate is None else
            -(-rate.numerator // rate.denominator)))
    return results


def assess(samples: object, *, now: datetime) -> dict[str, Any]:
    """Chronological supplied samples; no IO, automatic alarms or authorization.

    The newest sample must be <=24h old, measured from its START. Trend requires
    >=3 complete comparable samples spanning >=24h (finish to finish). Every
    adjacent window must be non-overlapping. Use the maximum positive interval
    rate, with exact rational arithmetic, only as an observed diagnostic. There
    is no extrapolation from a single point or an assertion of infinite runway.
    Relation deltas use the last comparable pair even before trend is eligible.
    """
    report: dict[str, Any] = dict(status='UNKNOWN', reasons=[], sample_count=0,
        quota_bytes=QUOTA_BYTES, floor_bytes=FLOOR_BYTES, warning_bytes=WARNING_BYTES,
        nominal_headroom_bytes=None, capacity_status='UNKNOWN', trend_status='UNAVAILABLE',
        observed_span_seconds=None, last_interval_microseconds=None, observed_delta_bytes=None,
        max_positive_observed_bytes_per_day_ceiling=None,
        diagnostic_seconds_to_floor=None, relation_growth=[],
        forecast_is_guaranteed=False, authenticated_inputs_verified=False,
        physical_disk_free_verified=False, backup_verified=False,
        write_admission_authorized=False, approval_authority=False,
        notifications_sent=0, writes=0, network_calls=0, credential_reads=0)
    try:
        _require(type(now) is datetime and now.utcoffset() is not None, 'CLOCK_INVALID')
        now = now.astimezone(timezone.utc)
        _require(type(samples) in (list, tuple), 'SAMPLE_INVENTORY_INVALID')
        sample_list = cast(list[object] | tuple[object, ...], samples)
        _require(1 <= len(sample_list) <= MAX_SAMPLES, 'SAMPLE_INVENTORY_INVALID')
        parsed = [validate_sample(sample) for sample in sample_list]
        report['sample_count'] = len(parsed)
        _require(all(end <= now for _, _, end in parsed), 'SAMPLE_FUTURE')
        for (_, _, previous_end), (_, start, end) in zip(parsed, parsed[1:]):
            _require(previous_end <= start and previous_end < end, 'SAMPLE_ORDER_OR_OVERLAP')
        current, started, finished = parsed[-1]
        _require(now - started <= MAX_AGE, 'CURRENT_SAMPLE_STALE')
        _require(current['complete'], 'CURRENT_SAMPLE_INCOMPLETE')
        headroom = QUOTA_BYTES - current['cluster_database_bytes']
        capacity = 'FLOOR_BREACHED' if headroom < FLOOR_BYTES else (
            'WARNING' if headroom <= WARNING_BYTES else 'OBSERVED')
        report.update(status=capacity, capacity_status=capacity, nominal_headroom_bytes=headroom)
        _require(all(sample['complete'] for sample, _, _ in parsed), 'HISTORY_INCOMPLETE')
        identity = _identity(current)
        _require(all(_identity(sample) == identity for sample, _, _ in parsed),
                 'SAMPLE_SOURCE_OR_INVENTORY_MISMATCH')
        if len(parsed) >= 2:
            before, _, before_end = parsed[-2]
            interval_us = _duration_us(finished - before_end)
            report['last_interval_microseconds'] = interval_us
            report['relation_growth'] = _relation_deltas(before, current, interval_us)
            report['observed_delta_bytes'] = current['cluster_database_bytes'] - before['cluster_database_bytes']
        span = finished - parsed[0][2]
        report['observed_span_seconds'] = _duration_us(span) // 1_000_000
        if len(parsed) < 3:
            report['trend_status'] = 'INSUFFICIENT_SAMPLES'
            return report
        if span < MIN_TREND_SPAN:
            report['trend_status'] = 'INSUFFICIENT_SPAN'
            return report
        rates = [Fraction((right['cluster_database_bytes'] - left['cluster_database_bytes'])
                    * 1_000_000, _duration_us(right_end - left_end))
            for (left, _, left_end), (right, _, right_end) in zip(parsed, parsed[1:])]
        positive = [rate for rate in rates if rate > 0]
        if not positive:
            report['trend_status'] = 'NO_POSITIVE_OBSERVED_GROWTH'
            return report
        rate = max(positive)
        daily = rate * 86400
        remaining = max(headroom - FLOOR_BYTES, 0)
        seconds = Fraction(remaining, 1) / rate
        report.update(trend_status='POSITIVE_OBSERVED_DIAGNOSTIC',
            max_positive_observed_bytes_per_day_ceiling=-(-daily.numerator // daily.denominator),
            diagnostic_seconds_to_floor=seconds.numerator // seconds.denominator)
    except (CapacityError, ValueError, OverflowError, TypeError, KeyError) as error:
        code = str(error) if isinstance(error, CapacityError) else 'SAMPLE_INVALID'
        report.update(status='UNKNOWN', reasons=[code], trend_status='UNAVAILABLE',
            max_positive_observed_bytes_per_day_ceiling=None, diagnostic_seconds_to_floor=None,
            relation_growth=[])
    return report
