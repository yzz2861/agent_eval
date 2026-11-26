"""Stable coverage receipts for detect-secrets plugin scans.

The receipt model deliberately stores cryptographic commitments and numeric
intervals only.  It never stores source lines, secret values, or code
snippets.
"""

from __future__ import annotations

import hashlib
import json
import os
from enum import Enum
from collections.abc import Mapping as MappingABC
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import Union


INTERVAL_START_KEYS = (
    'start', 'begin', 'lo', 'lower', 'first', 'from',
    'start_line', 'line_start', 'first_line',
    'start_offset', 'offset_start', 'start_byte', 'byte_start',
)
INTERVAL_END_KEYS = (
    'end', 'finish', 'hi', 'upper', 'last', 'to', 'stop',
    'end_line', 'line_end', 'last_line',
    'end_offset', 'offset_end', 'end_byte', 'byte_end',
)
INTERVAL_WRAPPER_KEYS = (
    'interval', 'range', 'segment_range', 'line_range', 'byte_range', 'span',
)
DOMAIN_KEYS = (
    'domain', 'total_range', 'full_range', 'coverage_domain', 'expected_range',
    'bounds', 'extent',
)
COMMITMENT_KEYS = (
    'commitment', 'stable_commitment', 'file_commitment', 'content_commitment',
    'version_commitment', 'digest', 'hash', 'sha256', 'sha1', 'md5',
    'content_hash', 'file_hash', 'sha256_digest', 'sha256_hex',
)
FRAGMENT_KEYS = frozenset({
    'code', 'code_snippet', 'content', 'context', 'fragment', 'fragments',
    'line_text', 'lines', 'payload', 'plaintext', 'raw', 'secret',
    'secret_value', 'snippet', 'source', 'text', 'value',
})

STATUS_FAILED = 'failed'
STATUS_POLICY_SKIPPED = 'policy_skipped'
STATUS_SKIPPED = 'skipped'
STATUS_NO_FINDINGS = 'no_findings'
STATUS_CLEAN = 'clean'
STATUS_FOUND = 'findings'
STATUS_SCANNED = 'scanned'

FAILED_STATUSES = frozenset({
    STATUS_FAILED, 'failure', 'error', 'errored', 'incomplete', 'io_error',
    'read_error', 'scan_failed',
})
SKIPPED_STATUSES = frozenset({
    STATUS_POLICY_SKIPPED, STATUS_SKIPPED, 'policy_skip', 'skip', 'excluded',
    'filtered', 'ignored', 'not_scanned', 'disabled', 'suppressed_by_policy',
})
CLEAN_STATUSES = frozenset({
    STATUS_NO_FINDINGS, 'no_finding', STATUS_CLEAN, 'scanned_clean',
    'clean_scan', 'ok_clean',
})
FOUND_STATUSES = frozenset({
    STATUS_FOUND, 'found', 'has_findings', 'with_findings', 'secret_found',
    'secrets_found', 'hit', 'detected', 'finding',
})
SUCCESS_STATUSES = frozenset({
    STATUS_SCANNED, 'success', 'succeeded', 'successful', 'complete',
    'completed', 'ok', 'done', *CLEAN_STATUSES, *FOUND_STATUSES,
})


class SegmentStatus(str, Enum):
    """Canonical receipt segment states."""

    FAILED = STATUS_FAILED
    FAILURE = STATUS_FAILED
    POLICY_SKIPPED = STATUS_POLICY_SKIPPED
    SKIPPED = STATUS_POLICY_SKIPPED
    NO_FINDINGS = STATUS_NO_FINDINGS
    CLEAN = STATUS_NO_FINDINGS
    SCANNED_CLEAN = STATUS_NO_FINDINGS
    FOUND = STATUS_FOUND
    FINDINGS = STATUS_FOUND
    SCANNED = STATUS_SCANNED
    SUCCESS = STATUS_SCANNED


CoverageStatus = SegmentStatus


class CoverageReceiptError(ValueError):
    """Base class for receipt construction and replay errors."""


class ManifestError(CoverageReceiptError):
    """Raised when an archive manifest cannot prove file identity."""


class VersionMismatchError(ManifestError):
    """Raised when receipts do not refer to the same archived version."""


class SegmentNotFoundError(CoverageReceiptError):
    """Raised when a requested segment cannot be removed."""


def _enum_value(value: Any) -> Any:
    return getattr(value, 'value', value)


def _mapping_of(value: Any) -> Optional[MappingABC]:
    if isinstance(value, MappingABC):
        return value
    if hasattr(value, '__dict__') and isinstance(getattr(value, '__dict__', None), MappingABC):
        return value.__dict__
    return None


def _first_mapping_value(data: MappingABC, keys: Iterable[str]) -> Tuple[bool, Any]:
    for key in keys:
        if key in data and data[key] is not None:
            return True, data[key]
    return False, None


def _looks_like_interval(value: Any) -> bool:
    if isinstance(value, Interval):
        return True
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return _is_interval_endpoint(value[0]) and _is_interval_endpoint(value[1])
    data = _mapping_of(value)
    if data is None:
        return False
    return any(key in data for key in INTERVAL_START_KEYS) and any(
        key in data for key in INTERVAL_END_KEYS
    ) or any(key in data for key in INTERVAL_WRAPPER_KEYS)


def _is_interval_endpoint(value: Any) -> bool:
    return _is_number(value) or isinstance(value, (str, type(None)))


class StableCommitment(str):
    """A stable content commitment rendered as ``algorithm:hexdigest``."""

    algorithm: str
    digest: str

    def __new__(
        cls,
        value: Any = None,
        *,
        algorithm: Optional[str] = None,
        digest: Optional[str] = None,
        hexdigest: Optional[str] = None,
        sha256: Optional[str] = None,
        sha1: Optional[str] = None,
        **kwargs: Any,
    ) -> 'StableCommitment':
        supplied_algorithm = algorithm
        supplied_digest = digest or hexdigest

        if isinstance(value, StableCommitment) and supplied_digest is None:
            if supplied_algorithm is None or supplied_algorithm == value.algorithm:
                return value

        if supplied_digest is None and hasattr(value, 'hexdigest') and callable(value.hexdigest):
            supplied_digest = value.hexdigest()
            value = None

        if supplied_digest is None:
            if sha256 is not None:
                supplied_algorithm = supplied_algorithm or 'sha256'
                supplied_digest = sha256
            elif sha1 is not None:
                supplied_algorithm = supplied_algorithm or 'sha1'
                supplied_digest = sha1

        if supplied_digest is None and value is not None:
            data = _mapping_of(value)
            if data is not None:
                found, candidate = _first_mapping_value(data, COMMITMENT_KEYS)
                if found:
                    return StableCommitment(
                        candidate,
                        algorithm=supplied_algorithm,
                    )
            elif isinstance(value, bytes):
                supplied_digest = value.hex()
            elif isinstance(value, str):
                text = value.strip()
                if ':' in text and len(text.split(':', 1)[0]) <= 12:
                    maybe_algorithm, supplied_digest = text.split(':', 1)
                    supplied_algorithm = supplied_algorithm or maybe_algorithm
                else:
                    supplied_digest = text
            else:
                supplied_digest = str(value)

        if supplied_digest is None:
            raise CoverageReceiptError('commitment requires a digest')

        normalized_algorithm = (supplied_algorithm or 'sha256').lower().replace('-', '')
        raw_digest = str(supplied_digest).strip()
        normalized_digest = raw_digest.lower()
        if ':' in normalized_digest:
            prefix, normalized_digest = normalized_digest.split(':', 1)
            normalized_algorithm = normalized_algorithm if supplied_algorithm else prefix

        expected_lengths = {'sha1': 40, 'sha256': 64, 'md5': 32}
        expected_length = expected_lengths.get(normalized_algorithm)
        is_hex = re_fullmatch_hex(normalized_digest) is not None
        if not is_hex or (expected_length and len(normalized_digest) != expected_length):
            obj = super().__new__(cls, raw_digest)
            obj.algorithm = 'opaque'
            obj.digest = raw_digest
            return obj

        rendered = f'{normalized_algorithm}:{normalized_digest}'
        obj = super().__new__(cls, rendered)
        obj.algorithm = normalized_algorithm
        obj.digest = normalized_digest
        return obj

    @property
    def hex(self) -> str:
        return self.digest

    @property
    def hexdigest(self) -> str:
        return self.digest

    def matches(self, other: Any) -> bool:
        try:
            normalized = coerce_commitment(other)
        except CoverageReceiptError:
            return False
        return self.algorithm == normalized.algorithm and self.digest == normalized.digest

    @classmethod
    def for_bytes(cls, content: bytes, algorithm: str = 'sha256') -> 'StableCommitment':
        if not isinstance(content, (bytes, bytearray)):
            raise TypeError('content must be bytes')
        digest = hashlib.new(algorithm, bytes(content)).hexdigest()
        return cls(algorithm=algorithm, digest=digest)

    @classmethod
    def for_file(cls, filename: Union[str, os.PathLike[str]], algorithm: str = 'sha256') -> 'StableCommitment':
        hasher = hashlib.new(algorithm)
        with open(filename, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                hasher.update(chunk)
        return cls(algorithm=algorithm, digest=hasher.hexdigest())


def re_fullmatch_hex(value: str) -> Optional[Any]:
    import re
    return re.fullmatch(r'[0-9a-f]+', value)


def coerce_commitment(value: Any = None, **kwargs: Any) -> StableCommitment:
    if isinstance(value, StableCommitment) and not kwargs:
        return value
    return StableCommitment(value, **kwargs)


def _algorithm_from_commitment_key(key: str) -> Optional[str]:
    lowered = key.lower()
    if 'sha1' in lowered:
        return 'sha1'
    if 'md5' in lowered:
        return 'md5'
    if 'sha256' in lowered or 'sha_256' in lowered:
        return 'sha256'
    return None


class Interval(tuple):
    """A two-endpoint interval.

    Generic intervals are half-open.  Line intervals are one-based and
    inclusive; their internal half-open coordinates are available as
    :attr:`lo` and :attr:`hi`.
    """

    start: Any
    end: Any
    inclusive: bool
    unit: str
    lo: Any
    hi: Any

    def __new__(
        cls,
        value: Any = None,
        end: Any = None,
        *,
        inclusive: Optional[bool] = None,
        unit: Optional[str] = None,
        **kwargs: Any,
    ) -> 'Interval':
        start_value, end_value, inferred_inclusive, inferred_unit = _parse_interval(
            value,
            end,
            kwargs,
        )
        if inclusive is None:
            inclusive = inferred_inclusive
        if unit is None:
            unit = inferred_unit or ('line' if inclusive else 'interval')
        if unit == 'line' and inclusive is None:
            inclusive = True

        if start_value is None or end_value is None:
            raise CoverageReceiptError('interval requires start and end')
        if end_value < start_value:
            raise CoverageReceiptError(f'interval end precedes start: {start_value!r}..{end_value!r}')

        obj = super().__new__(cls, (start_value, end_value))
        obj.start = start_value
        obj.end = end_value
        obj.inclusive = bool(inclusive)
        obj.unit = unit
        obj.lo = start_value
        obj.hi = end_value + 1 if obj.inclusive else end_value
        return obj

    @property
    def stop(self) -> Any:
        return self.hi

    def as_tuple(self, *, half_open: bool = False) -> Tuple[Any, Any]:
        if half_open:
            return (self.lo, self.hi)
        return (self.start, self.end)

    def to_tuple(self) -> Tuple[Any, Any]:
        return (self.start, self.end)

    def to_list(self) -> List[Any]:
        return [self.start, self.end]

    def to_dict(self) -> Dict[str, Any]:
        return {'start': self.start, 'end': self.end}

    def contains(self, value: Any) -> bool:
        if isinstance(value, Interval):
            return value.lo >= self.lo and value.hi <= self.hi
        return self.lo <= value < self.hi

    def overlaps(self, other: Any) -> bool:
        other_interval = coerce_interval(other)
        return max(self.lo, other_interval.lo) < min(self.hi, other_interval.hi)

    def intersection(self, other: Any) -> Optional['Interval']:
        other_interval = coerce_interval(other)
        lo = max(self.lo, other_interval.lo)
        hi = min(self.hi, other_interval.hi)
        if lo >= hi:
            return None
        return interval_from_half_open(lo, hi, template=self)

    def __repr__(self) -> str:
        boundary = 'inclusive' if self.inclusive else 'half-open'
        return f'Interval({self.start!r}, {self.end!r}, {boundary}, unit={self.unit!r})'


def _parse_interval(
    value: Any,
    end: Any,
    kwargs: MappingABC,
) -> Tuple[Any, Any, Optional[bool], Optional[str]]:
    inclusive: Optional[bool] = kwargs.get('inclusive')
    unit = kwargs.get('unit') or kwargs.get('interval_unit') or kwargs.get('range_type')

    start_value = kwargs.get('start')
    end_value = kwargs.get('end')
    if end is not None and end_value is None:
        end_value = end
    if start_value is None:
        found_start, candidate_start = _first_mapping_value(kwargs, INTERVAL_START_KEYS)
        if found_start:
            start_value = candidate_start
    if end_value is None:
        found_end, candidate_end = _first_mapping_value(kwargs, INTERVAL_END_KEYS)
        if found_end:
            end_value = candidate_end

    if value is not None and start_value is None:
        if isinstance(value, Interval):
            return value.start, value.end, value.inclusive, value.unit
        data = _mapping_of(value)
        if data is not None:
            wrapper_found, wrapper = _first_mapping_value(data, INTERVAL_WRAPPER_KEYS)
            if wrapper_found and _looks_like_interval(wrapper):
                wrapped = coerce_interval(wrapper)
                return wrapped.start, wrapped.end, wrapped.inclusive, wrapped.unit
            found_start, candidate_start = _first_mapping_value(data, INTERVAL_START_KEYS)
            found_end, candidate_end = _first_mapping_value(data, INTERVAL_END_KEYS)
            if found_start and found_end:
                start_value = candidate_start
                end_value = candidate_end
                start_key = next((key for key in INTERVAL_START_KEYS if key in data), '')
                end_key = next((key for key in INTERVAL_END_KEYS if key in data), '')
                joined = f'{start_key} {end_key} {unit or ""}'.lower()
                if 'line' in joined:
                    inclusive = True
                    unit = unit or 'line'
                elif any(token in joined for token in ('offset', 'byte', 'char')):
                    inclusive = False
                    unit = unit or 'offset'
        elif isinstance(value, (tuple, list)):
            if len(value) == 2:
                start_value, end_value = value
            elif len(value) == 1 and _looks_like_interval(value[0]):
                return _parse_interval(value[0], None, kwargs)
        elif hasattr(value, 'start') and hasattr(value, 'end'):
            start_value = value.start
            end_value = value.end
            if isinstance(value, Interval):
                inclusive = value.inclusive
                unit = value.unit

        if start_value is None and end is not None and _is_number(value):
            start_value = value

    if start_value is not None and end_value is None:
        for key in INTERVAL_END_KEYS:
            if key in kwargs and kwargs[key] is not None:
                end_value = kwargs[key]
                break
    if end_value is not None and start_value is None:
        for key in INTERVAL_START_KEYS:
            if key in kwargs and kwargs[key] is not None:
                start_value = kwargs[key]
                break

    joined_kwargs = ' '.join(str(key) for key in kwargs).lower()
    if inclusive is None and 'line' in f'{unit or ""} {joined_kwargs}':
        inclusive = True
        unit = unit or 'line'

    return start_value, end_value, inclusive, unit


def coerce_interval(
    value: Any = None,
    end: Any = None,
    *,
    inclusive: Optional[bool] = None,
    unit: Optional[str] = None,
    **kwargs: Any,
) -> Interval:
    if isinstance(value, Interval) and end is None and not kwargs:
        if inclusive is None and unit is None:
            return value
    return Interval(
        value,
        end,
        inclusive=inclusive,
        unit=unit,
        **kwargs,
    )


def interval_from_half_open(
    lo: Any,
    hi: Any,
    *,
    template: Optional[Interval] = None,
    inclusive: Optional[bool] = None,
    unit: Optional[str] = None,
) -> Interval:
    use_inclusive = inclusive if inclusive is not None else (
        template.inclusive if template is not None else False
    )
    use_unit = unit or (template.unit if template is not None else None)
    if use_inclusive:
        if hi <= lo:
            raise CoverageReceiptError('cannot create inclusive interval from empty range')
        return Interval(lo, hi - 1, inclusive=True, unit=use_unit)
    return Interval(lo, hi, inclusive=False, unit=use_unit)


class LineInterval(Interval):
    """One-based inclusive line interval."""

    def __new__(cls, *args: Any, inclusive: Optional[bool] = True, unit: Optional[str] = 'line', **kwargs: Any) -> 'LineInterval':
        return super().__new__(cls, *args, inclusive=inclusive, unit=unit, **kwargs)


class ByteInterval(Interval):
    """Zero-based half-open byte/offset interval."""

    def __new__(cls, *args: Any, inclusive: Optional[bool] = False, unit: Optional[str] = 'byte', **kwargs: Any) -> 'ByteInterval':
        return super().__new__(cls, *args, inclusive=inclusive, unit=unit, **kwargs)


def _common_interval_options(intervals: Sequence[Interval]) -> Dict[str, Any]:
    if intervals:
        return {'inclusive': intervals[0].inclusive, 'unit': intervals[0].unit}
    return {'inclusive': False}


def union_intervals(
    intervals: Iterable[Any],
    *,
    inclusive: Optional[bool] = None,
    unit: Optional[str] = None,
) -> List[Interval]:
    parsed: List[Interval] = []
    for item in intervals:
        interval = coerce_interval(item, inclusive=inclusive, unit=unit)
        if interval.hi > interval.lo:
            parsed.append(interval)
    if not parsed:
        return []

    parsed.sort(key=lambda item: (item.lo, item.hi))
    options = _common_interval_options(parsed)
    merged_half_open: List[Tuple[Any, Any]] = []
    for interval in parsed:
        lo, hi = interval.lo, interval.hi
        if not merged_half_open or lo > merged_half_open[-1][1]:
            merged_half_open.append([lo, hi])  # type: ignore[list-item]
        elif hi > merged_half_open[-1][1]:
            merged_half_open[-1][1] = hi  # type: ignore[index]

    template = parsed[0]
    return [
        interval_from_half_open(lo, hi, template=template, inclusive=options['inclusive'], unit=options.get('unit'))
        for lo, hi in merged_half_open
    ]


def subtract_intervals(
    source: Iterable[Any],
    covered: Iterable[Any],
    *,
    inclusive: Optional[bool] = None,
    unit: Optional[str] = None,
) -> List[Interval]:
    source_union = union_intervals(source, inclusive=inclusive, unit=unit)
    cover_union = union_intervals(covered, inclusive=inclusive, unit=unit)
    if not source_union:
        return []

    template = source_union[0]
    result: List[Interval] = []
    for source_interval in source_union:
        cursor = source_interval.lo
        source_hi = source_interval.hi
        for cover_interval in cover_union:
            cover_lo = max(cover_interval.lo, source_interval.lo)
            cover_hi = min(cover_interval.hi, source_hi)
            if cover_hi <= cursor:
                continue
            if cover_lo >= source_hi:
                break
            if cover_lo > cursor:
                result.append(interval_from_half_open(cursor, cover_lo, template=template))
            cursor = max(cursor, cover_hi)
            if cursor >= source_hi:
                break
        if cursor < source_hi:
            result.append(interval_from_half_open(cursor, source_hi, template=template))
    return result


def interval_difference(
    before: Iterable[Any],
    after: Iterable[Any],
    *,
    inclusive: Optional[bool] = None,
    unit: Optional[str] = None,
) -> List[Interval]:
    """Return coverage present in ``before`` but absent from ``after``."""
    return subtract_intervals(before, after, inclusive=inclusive, unit=unit)


def coverage_gaps(
    covered: Optional[Iterable[Any]] = None,
    *,
    domain: Any = None,
    expected: Any = None,
    intervals: Optional[Iterable[Any]] = None,
    receipt: Optional['CoverageReceipt'] = None,
    **kwargs: Any,
) -> List[Interval]:
    """Return intervals in ``domain`` not covered by successful intervals."""
    if receipt is not None:
        return receipt.coverage_gaps(domain=domain or expected)
    if isinstance(covered, CoverageReceipt):
        return covered.coverage_gaps(domain=domain or expected)
    if covered is None:
        covered = intervals
    if covered is None:
        raise CoverageReceiptError('coverage_gaps requires covered intervals or a receipt')
    domain_value = domain or expected or kwargs.get('total_range')
    if domain_value is None:
        raise CoverageReceiptError('coverage_gaps requires a domain/expected interval')
    return subtract_intervals([domain_value], covered)


def normalize_status(status: Any = None, findings_count: Optional[int] = None) -> str:
    raw = str(_enum_value(status) or STATUS_SCANNED).strip().lower()
    raw = raw.replace('-', '_')

    if raw in FAILED_STATUSES or any(token in raw for token in ('fail', 'error')):
        return STATUS_FAILED
    if raw in SKIPPED_STATUSES or 'skip' in raw or 'exclud' in raw or 'filter' in raw:
        return STATUS_POLICY_SKIPPED
    if raw in FOUND_STATUSES or ('finding' in raw and 'no' not in raw):
        return STATUS_FOUND
    if raw in CLEAN_STATUSES or 'clean' in raw or 'no_finding' in raw:
        return STATUS_NO_FINDINGS

    if findings_count is not None:
        try:
            if int(findings_count) > 0:
                return STATUS_FOUND
            return STATUS_NO_FINDINGS
        except (TypeError, ValueError):
            pass
    return raw if raw in SUCCESS_STATUSES else STATUS_SCANNED


def _safe_metadata(data: MappingABC) -> Dict[str, Any]:
    safe: Dict[str, Any] = {}
    for key, value in data.items():
        key_text = str(key)
        key_lower = key_text.lower()
        if key_lower in FRAGMENT_KEYS or any(
            token in key_lower
            for token in (
                'snippet', 'fragment', 'plaintext', 'secret',
                'file_content', 'line_content', 'source_code',
            )
        ):
            continue
        if isinstance(value, MappingABC):
            safe[key_text] = _safe_metadata(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            safe[key_text] = value
        elif isinstance(value, (tuple, list)):
            safe[key_text] = [
                _safe_metadata(item) if isinstance(item, MappingABC)
                else item if isinstance(item, (str, int, float, bool)) or item is None
                else str(item)
                for item in value
            ]
        else:
            safe[key_text] = str(value)
    return safe


def contains_file_fragments(payload: Any) -> bool:
    """Return True when a payload contains obvious source/fragment fields."""
    if isinstance(payload, MappingABC):
        for key, value in payload.items():
            key_text = str(key).lower()
            if key_text in FRAGMENT_KEYS or any(
                token in key_text
                for token in ('snippet', 'fragment', 'plaintext', 'file_content', 'line_content')
            ):
                return True
            if contains_file_fragments(value):
                return True
    elif isinstance(payload, (list, tuple, set)):
        return any(contains_file_fragments(item) for item in payload)
    return False


def assert_no_file_fragments(payload: Any) -> bool:
    if contains_file_fragments(payload):
        raise CoverageReceiptError('coverage receipts must not contain file fragments')
    return True


receipt_is_content_free = lambda payload: not contains_file_fragments(payload)


class CoverageSegment:
    """One categorized interval in a coverage receipt."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        interval_value = kwargs.pop('interval', None)
        range_value = kwargs.pop('range', None)
        if range_value is None:
            range_value = kwargs.pop('segment_range', None)
        if range_value is None:
            range_value = kwargs.pop('line_range', None)
        if range_value is None:
            range_value = kwargs.pop('byte_range', None)
        if range_value is None:
            range_value = kwargs.pop('span', None)

        status_value = kwargs.pop('status', None)
        for status_key in ('state', 'outcome', 'result', 'category', 'kind'):
            if status_value is None and status_key in kwargs:
                status_value = kwargs.pop(status_key)

        findings_value = kwargs.pop('findings', None)
        secrets_value = kwargs.pop('secrets', None)
        if findings_value is None and secrets_value is not None:
            findings_value = secrets_value
        findings_count = kwargs.pop('findings_count', None)
        if findings_count is None:
            findings_count = kwargs.pop('finding_count', None)
        if findings_count is None:
            findings_count = kwargs.pop('num_findings', None)
        if findings_count is None and findings_value is not None:
            try:
                findings_count = len(findings_value)
            except TypeError:
                findings_count = None

        positional_interval: Any = None
        positional_findings_count: Optional[int] = None
        for argument in args:
            if isinstance(argument, CoverageSegment):
                if positional_interval is None:
                    positional_interval = argument.interval
                if status_value is None:
                    status_value = argument.status
                continue
            if _looks_like_finding(argument):
                line_number = int(getattr(argument, 'line_number', 0) or 0)
                if line_number:
                    positional_interval = LineInterval(line_number, line_number)
                if status_value is None:
                    status_value = STATUS_FOUND
                positional_findings_count = 1
                continue
            if isinstance(argument, (tuple, list)) and len(argument) >= 2 and _is_number(argument[0]) and _is_number(argument[1]):
                positional_interval = (argument[0], argument[1])
                if len(argument) >= 3 and status_value is None:
                    status_value = argument[2]
                continue
            if _looks_like_status(argument) and status_value is None:
                status_value = argument
            elif _looks_like_interval(argument) and positional_interval is None:
                positional_interval = argument
            elif positional_interval is None:
                positional_interval = argument

        chosen_interval = interval_value if interval_value is not None else range_value
        if chosen_interval is None:
            chosen_interval = positional_interval

        interval_kwargs = {}
        for key in list(kwargs):
            if key in INTERVAL_START_KEYS or key in INTERVAL_END_KEYS or key in ('inclusive', 'unit', 'interval_unit', 'range_type'):
                interval_kwargs[key] = kwargs.pop(key)

        if chosen_interval is not None or interval_kwargs:
            self.interval: Optional[Interval] = coerce_interval(
                chosen_interval,
                **interval_kwargs,
            ) if chosen_interval is not None else Interval(**interval_kwargs)
        else:
            self.interval = None

        self.findings_count: Optional[int] = findings_count
        if self.findings_count is None:
            self.findings_count = positional_findings_count
        self.status: str = normalize_status(status_value, self.findings_count)
        self.reason: Optional[str] = kwargs.pop('reason', None) or kwargs.pop('policy_reason', None)
        self.plugin: Optional[str] = kwargs.pop('plugin', None) or kwargs.pop('plugin_name', None)
        self.commitment: Optional[StableCommitment] = None
        commitment_value = kwargs.pop('commitment', None)
        if commitment_value is not None:
            self.commitment = coerce_commitment(commitment_value)

        self.metadata: Dict[str, Any] = _safe_metadata(kwargs)

    @property
    def start(self) -> Any:
        return self.interval.start if self.interval else None

    @property
    def end(self) -> Any:
        return self.interval.end if self.interval else None

    @property
    def start_line(self) -> Any:
        return self.start

    @property
    def end_line(self) -> Any:
        return self.end

    @property
    def line_start(self) -> Any:
        return self.start

    @property
    def line_end(self) -> Any:
        return self.end

    @property
    def start_offset(self) -> Any:
        return self.interval.lo if self.interval else None

    @property
    def end_offset(self) -> Any:
        return self.interval.hi if self.interval else None

    @property
    def range(self) -> Optional[Interval]:
        return self.interval

    @property
    def is_failed(self) -> bool:
        return self.status == STATUS_FAILED

    @property
    def is_skipped(self) -> bool:
        return self.status == STATUS_POLICY_SKIPPED

    @property
    def is_clean(self) -> bool:
        return self.status == STATUS_NO_FINDINGS

    @property
    def is_found(self) -> bool:
        return self.status == STATUS_FOUND

    @property
    def is_success(self) -> bool:
        return self.status in SUCCESS_STATUSES or self.status in {
            STATUS_NO_FINDINGS, STATUS_CLEAN, STATUS_FOUND,
        }

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {'status': self.status}
        if self.interval is not None:
            result['start'] = self.start
            result['end'] = self.end
        if self.findings_count is not None:
            result['findings_count'] = self.findings_count
        if self.reason:
            result['reason'] = self.reason
        if self.plugin:
            result['plugin'] = self.plugin
        if self.commitment is not None:
            result['commitment'] = str(self.commitment)
        if self.metadata:
            result['metadata'] = self.metadata
        return result

    def __iter__(self) -> Iterator[Any]:
        if self.interval is None:
            return iter(())
        return iter((self.start, self.end))

    def __len__(self) -> int:
        return 2 if self.interval is not None else 0

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            if self.interval is None:
                raise IndexError('segment has no interval')
            return (self.start, self.end, self.status)[key]
        if isinstance(key, slice):
            return (self.start, self.end, self.status)[key]
        if key in ('range', 'interval', 'segment_range') and self.interval is not None:
            return self.interval
        if key == 'status':
            return self.status
        if key == 'findings_count':
            return self.findings_count
        data = self.to_dict()
        if key in data:
            return data[key]
        if key in self.metadata:
            return self.metadata[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __repr__(self) -> str:
        return f'CoverageSegment(status={self.status!r}, interval={self.interval!r})'

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, CoverageSegment):
            return self.status == other.status and self.interval == other.interval
        if self.interval is not None and isinstance(other, (tuple, list)):
            if len(other) == 2:
                return tuple(self.interval) == tuple(other)
            if len(other) == 3 and _looks_like_status(other[2]):
                return (
                    tuple(self.interval) == (other[0], other[1])
                    and self.status == normalize_status(other[2])
                )
        if isinstance(other, MappingABC):
            other_status = other.get('status') or other.get('state') or other.get('outcome')
            if other_status is not None and self.status != normalize_status(other_status):
                return False
            if _looks_like_interval(other):
                return self.interval == coerce_interval(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.status, tuple(self.interval) if self.interval is not None else None))


def _looks_like_status(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.strip().lower().replace('-', '_')
        return (
            lowered in FAILED_STATUSES
            or lowered in SKIPPED_STATUSES
            or lowered in CLEAN_STATUSES
            or lowered in FOUND_STATUSES
            or lowered in SUCCESS_STATUSES
            or 'skip' in lowered
            or 'fail' in lowered
        )
    enum_name = str(getattr(value, 'name', '') or '').lower()
    return bool(enum_name) and _looks_like_status(enum_name)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def coerce_segment(value: Any = None, **kwargs: Any) -> CoverageSegment:
    if isinstance(value, CoverageSegment) and not kwargs:
        return value
    if isinstance(value, MappingABC):
        data = dict(value)
        data.update(kwargs)
        return CoverageSegment(**data)
    return CoverageSegment(value, **kwargs)


def _segment_has_explicit_status(value: Any) -> bool:
    if isinstance(value, CoverageSegment):
        return True
    if _looks_like_finding(value):
        return True
    if isinstance(value, MappingABC):
        return any(
            key in value
            for key in ('status', 'state', 'outcome', 'result', 'category', 'kind')
        )
    if isinstance(value, (tuple, list)) and len(value) >= 3:
        return _looks_like_status(value[2])
    return False


def _looks_like_segment_tuple(value: Any) -> bool:
    return (
        isinstance(value, (tuple, list))
        and len(value) >= 2
        and _is_number(value[0])
        and _is_number(value[1])
    )


def _looks_like_finding(value: Any) -> bool:
    if isinstance(value, (str, bytes, int, float, tuple, list, MappingABC)):
        return False
    return hasattr(value, 'type') and hasattr(value, 'filename') and (
        hasattr(value, 'secret_hash') or hasattr(value, 'hashed_secret')
    )


class CoverageGap(Interval):
    """An uncovered interval, optionally annotated with explaining statuses."""

    reasons: Tuple[str, ...]

    def __new__(
        cls,
        value: Any = None,
        end: Any = None,
        *,
        reasons: Iterable[str] = (),
        **kwargs: Any,
    ) -> 'CoverageGap':
        obj = super().__new__(cls, value, end, **kwargs)
        obj.reasons = tuple(reasons)
        return obj


class CoverageReceipt(dict):
    """Stable file commitment plus categorized scanned intervals."""

    schema_name = 'detect-secrets.coverage-receipt/v1'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.schema: str = kwargs.pop('schema', None) or self.schema_name
        self.path: Optional[str] = kwargs.pop('path', None)
        if self.path is None:
            self.path = kwargs.pop('filename', None)
        if self.path is None:
            self.path = kwargs.pop('file', None)

        commitment_value = kwargs.pop('commitment', None)
        for key in ('file_commitment', 'stable_commitment', 'content_commitment', 'digest', 'file_hash', 'sha256'):
            if commitment_value is None and key in kwargs:
                commitment_value = kwargs.pop(key)
        if commitment_value is None:
            for argument in args:
                if isinstance(argument, (StableCommitment, str)) and not _looks_like_interval(argument):
                    commitment_value = argument
                    break
        if commitment_value is None and self.path and os.path.isfile(self.path) and kwargs.pop('hash_file', False):
            commitment_value = StableCommitment.for_file(self.path)
        self.commitment: Optional[StableCommitment] = (
            coerce_commitment(commitment_value) if commitment_value is not None else None
        )

        segment_values: List[Any] = []
        for key in (
            'segments', 'segment', 'ranges', 'intervals', 'coverage_segments',
            'segment_ranges', 'segment_intervals', 'coverage_ranges',
            'coverage_intervals', 'covered_ranges', 'covered_intervals',
        ):
            value = kwargs.pop(key, None)
            if value is not None:
                if isinstance(value, CoverageSegment):
                    segment_values.append(value)
                else:
                    segment_values.extend(list(value))

        line_ranges = kwargs.pop('line_ranges', None) or kwargs.pop('line_intervals', None)
        if line_ranges is not None:
            for value in [line_ranges] if _looks_like_interval(line_ranges) else list(line_ranges):
                segment_values.append({'interval': value, 'inclusive': True, 'unit': 'line'})

        byte_ranges = kwargs.pop('byte_ranges', None) or kwargs.pop('offset_ranges', None)
        if byte_ranges is not None:
            for value in [byte_ranges] if _looks_like_interval(byte_ranges) else list(byte_ranges):
                segment_values.append({'interval': value, 'inclusive': False, 'unit': 'byte'})

        category_arguments = (
            (
                STATUS_FAILED,
                ('failed', 'failures', 'failed_ranges', 'failed_intervals', 'failed_segments'),
            ),
            (
                STATUS_POLICY_SKIPPED,
                (
                    'skipped', 'skips', 'policy_skipped', 'policy_skips',
                    'skipped_ranges', 'skip_ranges', 'policy_skipped_ranges',
                    'skipped_intervals', 'policy_skipped_intervals',
                    'skipped_segments', 'policy_skipped_segments',
                ),
            ),
            (
                STATUS_NO_FINDINGS,
                (
                    'clean', 'no_findings', 'clean_ranges', 'no_findings_ranges',
                    'clean_intervals', 'no_findings_intervals',
                    'clean_segments', 'no_findings_segments',
                    'scanned_clean_segments',
                ),
            ),
            (
                STATUS_FOUND,
                ('found', 'findings', 'found_ranges', 'findings_ranges', 'found_segments'),
            ),
            (
                STATUS_SCANNED,
                (
                    'scanned', 'successful', 'success', 'scanned_ranges',
                    'successful_ranges', 'success_ranges', 'scanned_intervals',
                    'successful_intervals', 'scanned_segments', 'successful_segments',
                    'success_segments', 'covered', 'covered_ranges',
                    'covered_intervals', 'covered_segments',
                ),
            ),
        )
        for category_status, category_keys in category_arguments:
            for key in category_keys:
                value = kwargs.pop(key, None)
                if value is None:
                    continue
                if isinstance(value, CoverageSegment) or _looks_like_interval(value):
                    category_items = [value]
                else:
                    category_items = list(value)
                for item in category_items:
                    if isinstance(item, CoverageSegment):
                        segment_values.append(item)
                    elif isinstance(item, MappingABC):
                        segment_values.append({**dict(item), 'status': category_status})
                    else:
                        segment_values.append({'interval': item, 'status': category_status})
        for argument in args:
            if _looks_like_segment_tuple(argument):
                segment_values.append(argument)
            elif isinstance(argument, (list, tuple, set)) and not _looks_like_interval(argument):
                segment_values.extend(list(argument))

        default_status = kwargs.pop('default_status', STATUS_NO_FINDINGS)
        inclusive = kwargs.pop('inclusive', None)
        unit = kwargs.pop('unit', None) or kwargs.pop('interval_unit', None)
        self.inclusive = inclusive
        self.unit = unit
        self.segments: List[CoverageSegment] = []
        for value in segment_values:
            segment_kwargs: Dict[str, Any] = {}
            if inclusive is not None:
                segment_kwargs['inclusive'] = inclusive
            if unit is not None:
                segment_kwargs['unit'] = unit
            segment = coerce_segment(value, **segment_kwargs)
            if not _segment_has_explicit_status(value) and default_status is not None:
                segment.status = normalize_status(default_status)
            self.segments.append(segment)

        domain_value = None
        for key in DOMAIN_KEYS:
            if key in kwargs:
                domain_value = kwargs.pop(key)
                break
        line_count = kwargs.pop('line_count', None)
        file_size = kwargs.pop('file_size', None)
        self.line_count = line_count
        self.file_size = file_size
        self.domain: Optional[Interval] = None
        if domain_value is not None:
            self.domain = coerce_interval(domain_value, inclusive=inclusive, unit=unit)
        elif line_count:
            self.domain = Interval(1, int(line_count), inclusive=True, unit='line')
        elif file_size is not None:
            self.domain = Interval(0, int(file_size), inclusive=False, unit='byte')
        elif self.segments:
            intervals = [segment.interval for segment in self.segments if segment.interval is not None]
            if intervals:
                self.domain = Interval(
                    min(item.start for item in intervals),
                    max(item.end for item in intervals),
                    inclusive=intervals[0].inclusive,
                    unit=intervals[0].unit,
                )

        self.archive: Optional[str] = kwargs.pop('archive', None)
        self.manifest_id: Optional[str] = kwargs.pop('manifest_id', None)
        provided_metadata = kwargs.pop('metadata', None)
        self.metadata: Dict[str, Any] = _safe_metadata(kwargs)
        if isinstance(provided_metadata, MappingABC):
            self.metadata.update(_safe_metadata(provided_metadata))
        self._sync_dict()

    def _sync_dict(self) -> None:
        dict.clear(self)
        dict.update(self, self.to_dict())

    @property
    def file_commitment(self) -> Optional[StableCommitment]:
        return self.commitment

    @property
    def content_commitment(self) -> Optional[StableCommitment]:
        return self.commitment

    @property
    def file_hash(self) -> Optional[StableCommitment]:
        return self.commitment

    def _segments_with_status(self, predicate: Any) -> List[CoverageSegment]:
        return [segment for segment in self.segments if predicate(segment)]

    def __getitem__(self, key: str) -> Any:
        if key in ('commitment', 'schema', 'path', 'segments', 'domain', 'archive'):
            value = getattr(self, key)
            if key == 'commitment' and value is not None:
                return str(value)
            if key == 'domain' and value is not None:
                return list(value)
            return value
        if key in ('failed', 'failed_segments'):
            return self.failed_segments
        if key in ('skipped', 'policy_skipped', 'policy_skipped_segments'):
            return self.policy_skipped_segments
        if key in ('clean', 'no_findings', 'clean_segments'):
            return self.no_findings_segments
        if key in ('successful', 'success_segments'):
            return self.successful_segments
        data = self.to_dict()
        if key in data:
            return data[key]
        if key in self.metadata:
            return self.metadata[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    @property
    def failed_segments(self) -> List[CoverageSegment]:
        return self._segments_with_status(lambda item: item.is_failed)

    @property
    def failed(self) -> List[CoverageSegment]:
        return self.failed_segments

    @property
    def failures(self) -> List[CoverageSegment]:
        return self.failed_segments

    @property
    def policy_skipped_segments(self) -> List[CoverageSegment]:
        return self._segments_with_status(lambda item: item.is_skipped)

    @property
    def skipped_segments(self) -> List[CoverageSegment]:
        return self.policy_skipped_segments

    @property
    def policy_skipped(self) -> List[CoverageSegment]:
        return self.policy_skipped_segments

    @property
    def skipped(self) -> List[CoverageSegment]:
        return self.policy_skipped_segments

    @property
    def skips(self) -> List[CoverageSegment]:
        return self.policy_skipped_segments

    @property
    def no_findings_segments(self) -> List[CoverageSegment]:
        return self._segments_with_status(lambda item: item.is_clean)

    @property
    def clean_segments(self) -> List[CoverageSegment]:
        return self.no_findings_segments

    @property
    def no_findings(self) -> List[CoverageSegment]:
        return self.no_findings_segments

    @property
    def clean(self) -> List[CoverageSegment]:
        return self.no_findings_segments

    @property
    def scanned_clean_segments(self) -> List[CoverageSegment]:
        return self.no_findings_segments

    @property
    def found_segments(self) -> List[CoverageSegment]:
        return self._segments_with_status(lambda item: item.is_found)

    @property
    def finding_segments(self) -> List[CoverageSegment]:
        return self.found_segments

    @property
    def successful_segments(self) -> List[CoverageSegment]:
        return self._segments_with_status(lambda item: item.is_success)

    @property
    def success_segments(self) -> List[CoverageSegment]:
        return self.successful_segments

    @property
    def successful(self) -> List[CoverageSegment]:
        return self.successful_segments

    @property
    def success(self) -> List[CoverageSegment]:
        return self.successful_segments

    @property
    def scanned(self) -> List[CoverageSegment]:
        return self.successful_segments

    @property
    def scanned_segments(self) -> List[CoverageSegment]:
        return self.successful_segments

    def _intervals(self, segments: Iterable[CoverageSegment]) -> List[Interval]:
        return [segment.interval for segment in segments if segment.interval is not None]

    @property
    def failed_intervals(self) -> List[Interval]:
        return union_intervals(self._intervals(self.failed_segments))

    @property
    def policy_skipped_intervals(self) -> List[Interval]:
        return union_intervals(self._intervals(self.policy_skipped_segments))

    @property
    def skipped_intervals(self) -> List[Interval]:
        return self.policy_skipped_intervals

    @property
    def no_findings_intervals(self) -> List[Interval]:
        return union_intervals(self._intervals(self.no_findings_segments))

    @property
    def clean_intervals(self) -> List[Interval]:
        return self.no_findings_intervals

    @property
    def found_intervals(self) -> List[Interval]:
        return union_intervals(self._intervals(self.found_segments))

    @property
    def successful_intervals(self) -> List[Interval]:
        return union_intervals(self._intervals(self.successful_segments))


    @property
    def success_intervals(self) -> List[Interval]:
        return self.successful_intervals

    @property
    def total_range(self) -> Optional[Interval]:
        return self.domain

    def add_segment(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        kwargs.setdefault('inclusive', self.inclusive)
        kwargs.setdefault('unit', self.unit)
        segment = coerce_segment(*args, **kwargs)
        self.segments.append(segment)
        if self.domain is None and segment.interval is not None:
            self.domain = segment.interval
        self._sync_dict()
        return self

    @classmethod
    def builder(cls, *args: Any, **kwargs: Any) -> 'CoverageReceiptBuilder':
        return CoverageReceiptBuilder(*args, **kwargs)

    def record_segment(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        return self.add_segment(*args, **kwargs)

    def record_failure(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        kwargs['status'] = STATUS_FAILED
        return self.add_segment(*args, **kwargs)

    def record_policy_skip(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        kwargs['status'] = STATUS_POLICY_SKIPPED
        return self.add_segment(*args, **kwargs)

    record_skip = record_policy_skip

    def record_clean(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        kwargs['status'] = STATUS_NO_FINDINGS
        return self.add_segment(*args, **kwargs)

    record_no_findings = record_clean

    def record_found(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        kwargs['status'] = STATUS_FOUND
        return self.add_segment(*args, **kwargs)

    def record_success(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        kwargs.setdefault('status', STATUS_SCANNED)
        return self.add_segment(*args, **kwargs)

    def mark_failed(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        return self.record_failure(*args, **kwargs)

    def mark_skipped(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        return self.record_policy_skip(*args, **kwargs)

    def mark_clean(self, *args: Any, **kwargs: Any) -> CoverageReceipt:
        return self.record_clean(*args, **kwargs)

    def _find_segment_index(
        self,
        segment: Any = None,
        *,
        index: Optional[int] = None,
        interval: Any = None,
        status: Any = None,
        successful_only: bool = False,
        **kwargs: Any,
    ) -> int:
        if index is not None:
            if index < 0:
                index += len(self.segments)
            if not 0 <= index < len(self.segments):
                raise SegmentNotFoundError(index)
            if successful_only and not self.segments[index].is_success:
                raise SegmentNotFoundError('requested segment is not successful')
            return index

        target_interval = interval
        if target_interval is None and segment is not None:
            if isinstance(segment, CoverageSegment):
                target_interval = segment.interval
            else:
                target_interval = segment
        if target_interval is None and (kwargs.get('start') is not None or kwargs.get('end') is not None):
            target_interval = coerce_interval(kwargs)

        matches: List[int] = []
        for position, candidate in enumerate(self.segments):
            if successful_only and not candidate.is_success:
                continue
            if status is not None and candidate.status != normalize_status(status):
                continue
            if segment is not None and isinstance(segment, CoverageSegment) and candidate is segment:
                return position
            if target_interval is not None and candidate.interval is not None:
                try:
                    if candidate.interval == coerce_interval(target_interval):
                        matches.append(position)
                except CoverageReceiptError:
                    pass
            elif segment is None and target_interval is None:
                matches.append(position)

        if not matches:
            raise SegmentNotFoundError('no matching segment')
        return matches[0]

    def remove_segment(self, segment: Any = None, **kwargs: Any) -> CoverageReceipt:
        index = self._find_segment_index(segment, **kwargs)
        self.segments.pop(index)
        self._sync_dict()
        return self

    def remove_success_segment(self, segment: Any = None, **kwargs: Any) -> CoverageReceipt:
        kwargs['successful_only'] = True
        return self.remove_segment(segment, **kwargs)

    remove_successful_segment = remove_success_segment

    def pop_segment(self, segment: Any = None, **kwargs: Any) -> CoverageSegment:
        index = self._find_segment_index(segment, **kwargs)
        removed = self.segments.pop(index)
        self._sync_dict()
        return removed

    def without_segment(self, segment: Any = None, **kwargs: Any) -> 'CoverageReceipt':
        clone = CoverageReceipt.from_dict(self.to_dict(include_path=True))
        clone.path = self.path
        clone.remove_segment(segment, **kwargs)
        return clone

    def coverage_gaps(self, domain: Any = None, *, include_status: bool = False) -> List[Any]:
        domain_interval = self._resolve_domain(domain)
        if domain_interval is None:
            raise CoverageReceiptError('cannot replay gaps without a domain interval')
        gaps = subtract_intervals([domain_interval], self.successful_intervals)
        if not include_status:
            return gaps

        annotated: List[CoverageGap] = []
        failed = self.failed_intervals
        skipped = self.policy_skipped_intervals
        for gap in gaps:
            reasons = []
            if any(gap.intersection(item) for item in failed):
                reasons.append(STATUS_FAILED)
            if any(gap.intersection(item) for item in skipped):
                reasons.append(STATUS_POLICY_SKIPPED)
            if not reasons:
                reasons.append('missing')
            annotated.append(CoverageGap(gap, reasons=reasons))
        return annotated

    def _resolve_domain(self, domain: Any = None) -> Optional[Interval]:
        if domain is not None:
            return coerce_interval(domain)
        if self.domain is not None:
            return self.domain
        intervals = [item.interval for item in self.segments if item.interval is not None]
        if not intervals:
            return None
        return Interval(
            min(item.start for item in intervals),
            max(item.end for item in intervals),
            inclusive=intervals[0].inclusive,
            unit=intervals[0].unit,
        )

    def replay(self, domain: Any = None) -> 'CoverageReplay':
        return CoverageReplay(self, domain=domain)

    def merge(self, *others: Any, manifest: Optional['ArchiveManifest'] = None, **kwargs: Any) -> 'CoverageReceipt':
        return merge_receipts(self, *others, manifest=manifest, **kwargs)

    def to_dict(self, *, include_path: bool = False, categorized: bool = False) -> Dict[str, Any]:
        effective_unit = self.unit
        if effective_unit is None and self.domain is not None:
            effective_unit = self.domain.unit
        if effective_unit is None:
            segment_with_unit = next(
                (segment.interval.unit for segment in self.segments if segment.interval is not None),
                None,
            )
            effective_unit = segment_with_unit
        if categorized:
            result: Dict[str, Any] = {
                'schema': self.schema,
                'commitment': str(self.commitment) if self.commitment else None,
                'failed_ranges': [list(item) for item in self.failed_intervals],
                'policy_skipped_ranges': [list(item) for item in self.policy_skipped_intervals],
                'no_findings_ranges': [list(item) for item in self.no_findings_intervals],
                'successful_ranges': [list(item) for item in self.successful_intervals],
            }
        else:
            result = {
                'schema': self.schema,
                'commitment': str(self.commitment) if self.commitment else None,
                'segments': [segment.to_dict() for segment in self.segments],
            }
            if self.domain is not None:
                result['domain'] = self.domain.to_list()
            if effective_unit in ('line', 'byte', 'offset') or self.inclusive is True:
                result['interval_unit'] = effective_unit
        if include_path and self.path is not None:
            result['path'] = self.path
        if self.archive is not None:
            result['archive'] = self.archive
        if self.metadata:
            result['metadata'] = self.metadata
        return result

    def to_json(self, *, indent: Optional[int] = 2, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), indent=indent, **kwargs)

    json = to_json

    def to_wire_dict(self) -> Dict[str, Any]:
        return {
            'schema': self.schema_name,
            'commitment': str(self.commitment) if self.commitment else None,
            'interval_unit': (
                self.domain.unit if self.domain is not None else self.unit or 'interval'
            ),
            'failed': [list(item) for item in self.failed_intervals],
            'policy_skipped': [list(item) for item in self.policy_skipped_intervals],
            'skipped': [list(item) for item in self.policy_skipped_intervals],
            'no_findings': [list(item) for item in self.no_findings_intervals],
            'clean': [list(item) for item in self.no_findings_intervals],
            'found': [list(item) for item in self.found_intervals],
        }

    def to_minimal_dict(self) -> Dict[str, Any]:
        return {
            'commitment': str(self.commitment) if self.commitment else None,
            'failed_ranges': [list(item) for item in self.failed_intervals],
            'policy_skipped_ranges': [list(item) for item in self.policy_skipped_intervals],
            'no_findings_ranges': [list(item) for item in self.no_findings_intervals],
        }

    def redacted_dict(self) -> Dict[str, Any]:
        return self.to_wire_dict()

    def public_dict(self) -> Dict[str, Any]:
        return self.to_wire_dict()

    @classmethod
    def from_dict(cls, data: MappingABC[str, Any]) -> 'CoverageReceipt':
        if not isinstance(data, MappingABC):
            raise TypeError('receipt data must be a mapping')
        payload = dict(data)
        if 'segments' not in payload:
            for key in ('failed_ranges', 'policy_skipped_ranges', 'skipped_ranges', 'no_findings_ranges', 'clean_ranges', 'successful_ranges'):
                if key in payload:
                    status = {
                        'failed_ranges': STATUS_FAILED,
                        'policy_skipped_ranges': STATUS_POLICY_SKIPPED,
                        'skipped_ranges': STATUS_POLICY_SKIPPED,
                        'no_findings_ranges': STATUS_NO_FINDINGS,
                        'clean_ranges': STATUS_NO_FINDINGS,
                        'successful_ranges': STATUS_SCANNED,
                    }[key]
                    payload.setdefault('segments', [])
                    for interval in payload.pop(key):
                        payload['segments'].append({'status': status, 'interval': interval})
        return cls(**payload)

    @classmethod
    def from_json(cls, text: Union[str, bytes]) -> 'CoverageReceipt':
        if isinstance(text, bytes):
            text = text.decode('utf-8')
        return cls.from_dict(json.loads(text))


class CoverageReplay(list):
    """Replayed coverage and status-aware gap partitions."""

    def __init__(self, receipt: CoverageReceipt, domain: Any = None) -> None:
        self.receipt = receipt
        gaps = receipt.coverage_gaps(domain, include_status=True)
        super().__init__(gaps)
        self.gaps = list(self)
        self.failed = receipt.failed_intervals
        self.policy_skipped = receipt.policy_skipped_intervals
        self.clean = receipt.no_findings_intervals
        self.successful = receipt.successful_intervals

    @property
    def missing(self) -> List[Interval]:
        return [gap for gap in self.gaps if 'missing' in getattr(gap, 'reasons', ())]

    def as_dict(self) -> Dict[str, Any]:
        return {
            'gaps': [list(gap) for gap in self.gaps],
            'failed': [list(item) for item in self.failed],
            'policy_skipped': [list(item) for item in self.policy_skipped],
            'clean': [list(item) for item in self.clean],
        }


class CoverageBundle:
    """A collection of per-file receipts with review-friendly counts."""

    def __init__(
        self,
        receipts: Any = (),
        *,
        manifest: Optional['ArchiveManifest'] = None,
    ) -> None:
        self.manifest = manifest
        self.receipts: Dict[str, CoverageReceipt] = {}
        if isinstance(receipts, MappingABC):
            for key, value in receipts.items():
                self.add(value, name=key)
        else:
            for receipt in receipts:
                self.add(receipt)

    def add(self, receipt: CoverageReceipt, name: Optional[str] = None) -> 'CoverageBundle':
        if not isinstance(receipt, CoverageReceipt):
            receipt = CoverageReceipt(**receipt) if isinstance(receipt, MappingABC) else CoverageReceipt(receipt)
        key = name or receipt.path or str(receipt.commitment or len(self.receipts))
        self.receipts[key] = receipt
        return self

    @property
    def file_count(self) -> int:
        return len(self.receipts)

    @property
    def scanned_file_count(self) -> int:
        return sum(1 for receipt in self.receipts.values() if receipt.successful_segments)

    @property
    def completed_file_count(self) -> int:
        count = 0
        for receipt in self.receipts.values():
            if receipt.domain is not None:
                try:
                    if not receipt.coverage_gaps():
                        count += 1
                except CoverageReceiptError:
                    pass
            elif receipt.successful_segments and not receipt.failed_segments:
                count += 1
        return count

    @property
    def failed_file_count(self) -> int:
        return sum(1 for receipt in self.receipts.values() if receipt.failed_segments)

    @property
    def skipped_file_count(self) -> int:
        return sum(1 for receipt in self.receipts.values() if receipt.policy_skipped_segments)

    @property
    def clean_file_count(self) -> int:
        return sum(1 for receipt in self.receipts.values() if receipt.no_findings_segments)

    def summary(self) -> Dict[str, int]:
        return {
            'file_count': self.file_count,
            'scanned_file_count': self.scanned_file_count,
            'completed_file_count': self.completed_file_count,
            'failed_file_count': self.failed_file_count,
            'skipped_file_count': self.skipped_file_count,
            'clean_file_count': self.clean_file_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.summary(),
            'files': {
                name: receipt.to_wire_dict()
                for name, receipt in sorted(self.receipts.items())
            },
        }

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)


class CoverageReceiptBuilder:
    """Fluent builder for categorized coverage receipts."""

    def __init__(
        self,
        commitment: Any = None,
        *,
        path: Optional[str] = None,
        domain: Any = None,
        inclusive: Optional[bool] = None,
        unit: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self.receipt = CoverageReceipt(
            commitment=commitment,
            path=path,
            domain=domain,
            inclusive=inclusive,
            unit=unit,
            **kwargs,
        )

    def add(self, *args: Any, **kwargs: Any) -> 'CoverageReceiptBuilder':
        self.receipt.add_segment(*args, **kwargs)
        return self

    def failed(self, *args: Any, **kwargs: Any) -> 'CoverageReceiptBuilder':
        self.receipt.record_failure(*args, **kwargs)
        return self

    def skipped(self, *args: Any, **kwargs: Any) -> 'CoverageReceiptBuilder':
        self.receipt.record_policy_skip(*args, **kwargs)
        return self

    def clean(self, *args: Any, **kwargs: Any) -> 'CoverageReceiptBuilder':
        self.receipt.record_clean(*args, **kwargs)
        return self

    def found(self, *args: Any, **kwargs: Any) -> 'CoverageReceiptBuilder':
        self.receipt.record_found(*args, **kwargs)
        return self

    def successful(self, *args: Any, **kwargs: Any) -> 'CoverageReceiptBuilder':
        self.receipt.record_success(*args, **kwargs)
        return self

    def build(self) -> CoverageReceipt:
        return self.receipt


CoverageTracker = CoverageReceiptBuilder
ReceiptBuilder = CoverageReceiptBuilder


class VersionProof:
    """Archive-manifest proof that a receipt commitment is an archived version."""

    def __init__(
        self,
        *,
        canonical_path: str,
        commitment: StableCommitment,
        archive: Optional[str] = None,
        entry: Optional[MappingABC] = None,
    ) -> None:
        self.canonical_path = canonical_path
        self.commitment = commitment
        self.archive = archive
        self.entry = dict(entry or {})

    def __bool__(self) -> bool:
        return True

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, VersionProof):
            return self.canonical_path == other.canonical_path and self.commitment.matches(other.commitment)
        if isinstance(other, (str, StableCommitment)):
            return self.commitment.matches(other)
        return NotImplemented


class ArchiveManifest:
    """Trusted archive listing mapping archived paths to commitments."""

    def __init__(
        self,
        entries: Any = None,
        *,
        files: Any = None,
        manifest: Any = None,
        archive: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self.archive = archive or kwargs.pop('archive_name', None)
        self.entries: Dict[str, Dict[str, Any]] = {}
        if isinstance(entries, (str, os.PathLike)) and os.path.isfile(entries):
            with open(entries, encoding='utf-8') as handle:
                entries = json.load(handle)
        source = entries if entries is not None else files
        if source is None and manifest is not None:
            source = manifest
        if source is None:
            source = kwargs
        self._load(source)

    def _load(self, source: Any) -> None:
        if isinstance(source, ArchiveManifest):
            self.entries = {key: dict(value) for key, value in source.entries.items()}
            self.archive = self.archive or source.archive
            return
        if isinstance(source, MappingABC):
            list_key = next(
                (
                    key for key in (
                        'files', 'entries', 'records', 'manifest_entries',
                        'members', 'artifacts', 'items', 'paths',
                    )
                    if key in source
                ),
                None,
            )
            if list_key is not None and isinstance(source[list_key], (list, tuple)):
                if source.get('archive') or source.get('archive_name'):
                    self.archive = source.get('archive') or source.get('archive_name')
                for entry in source[list_key]:
                    self.add(entry)
                return
            for key, value in source.items():
                if key in ('archive', 'archive_name'):
                    self.archive = self.archive or str(value)
                    continue
                self.add(key, value)
            return
        if isinstance(source, (list, tuple, set)):
            for entry in source:
                self.add(entry)
            return
        if source is not None:
            self.add(source)

    def add(self, path: Any = None, value: Any = None, **kwargs: Any) -> 'ArchiveManifest':
        entry_path: Optional[str] = None
        commitment: Optional[StableCommitment] = None
        entry_data: Dict[str, Any] = {}

        if isinstance(path, MappingABC):
            data = dict(path)
            entry_path = str(
                data.pop('path', None)
                or data.pop('filename', None)
                or data.pop('name', None)
                or data.pop('archive_path', None)
                or data.pop('member', None)
                or data.pop('file', None)
                or data.pop('filepath', None)
                or data.pop('file_name', None)
                or data.pop('relative_path', None)
                or data.pop('object_path', None)
                or ''
            ) or None
            commitment_value = None
            commitment_algorithm = None
            for key in COMMITMENT_KEYS:
                if key in data:
                    commitment_value = data.pop(key)
                    commitment_algorithm = _algorithm_from_commitment_key(key)
                    break
            if commitment_value is not None:
                commitment = coerce_commitment(
                    commitment_value,
                    algorithm=commitment_algorithm,
                )
            entry_data = _safe_metadata(data)
        elif path is not None and value is None and not isinstance(path, (str, os.PathLike)):
            return self.add(path)
        else:
            entry_path = str(path) if path is not None else kwargs.pop('path', None)
            if value is not None:
                if isinstance(value, MappingABC):
                    return self.add({**dict(value), 'path': entry_path})
                commitment = coerce_commitment(value)
            else:
                commitment_value = kwargs.pop('commitment', None)
                commitment_algorithm = kwargs.pop('algorithm', None)
                if commitment_value is None:
                    for key in COMMITMENT_KEYS:
                        if key in kwargs:
                            commitment_value = kwargs.pop(key)
                            commitment_algorithm = _algorithm_from_commitment_key(key)
                            break
                if commitment_value is not None:
                    commitment = coerce_commitment(
                        commitment_value,
                        algorithm=commitment_algorithm,
                    )
                entry_data = _safe_metadata(kwargs)

        if not entry_path:
            raise ManifestError('manifest entry requires a path')
        if commitment is None:
            raise ManifestError(f'manifest entry {entry_path!r} requires a commitment')
        self.entries[entry_path] = {'path': entry_path, 'commitment': commitment, **entry_data}
        return self

    @classmethod
    def from_dict(cls, data: MappingABC) -> 'ArchiveManifest':
        return cls(data)

    @classmethod
    def from_entries(cls, entries: Iterable[MappingABC]) -> 'ArchiveManifest':
        return cls(list(entries))

    from_records = from_entries

    @classmethod
    def from_json(cls, text: Union[str, bytes]) -> 'ArchiveManifest':
        if isinstance(text, bytes):
            text = text.decode('utf-8')
        return cls(json.loads(text))

    @classmethod
    def from_file(cls, filename: Union[str, os.PathLike[str]]) -> 'ArchiveManifest':
        with open(filename, encoding='utf-8') as handle:
            return cls(json.load(handle))

    load = from_file

    def find_by_commitment(self, commitment: Any) -> List[Dict[str, Any]]:
        normalized = coerce_commitment(commitment)
        return [entry for entry in self.entries.values() if normalized.matches(entry['commitment'])]

    def prove(
        self,
        source: Any = None,
        *,
        commitment: Any = None,
        path: Optional[str] = None,
        filename: Optional[str] = None,
        strict_path: bool = False,
    ) -> VersionProof:
        source_commitment = commitment
        source_path = path or filename
        if isinstance(source, CoverageReceipt):
            source_commitment = source_commitment or source.commitment
            source_path = source_path or source.path
        elif isinstance(source, (StableCommitment, str)) and commitment is None:
            if _looks_like_interval(source):
                raise ManifestError('interval cannot identify a file version')
            source_commitment = source
        elif isinstance(source, MappingABC):
            data = source
            source_commitment = source_commitment or data.get('commitment')
            source_path = source_path or data.get('path') or data.get('filename')

        if source_commitment is None:
            raise ManifestError('archive proof requires a stable commitment')
        normalized = coerce_commitment(source_commitment)

        candidate_paths: List[str] = []
        if source_path:
            path_text = str(source_path)
            candidate_paths.extend([
                path_text,
                os.path.basename(path_text),
                path_text.replace(os.sep, '/'),
                Path(path_text).name,
            ])
        for candidate in candidate_paths:
            entry = self.entries.get(candidate)
            if entry is not None:
                if not normalized.matches(entry['commitment']):
                    raise VersionMismatchError(
                        f'path {candidate!r} is archived with a different version',
                    )
                return VersionProof(
                    canonical_path=entry['path'],
                    commitment=entry['commitment'],
                    archive=self.archive,
                    entry=entry,
                )

        matches = self.find_by_commitment(normalized)
        if not matches:
            raise VersionMismatchError('commitment is absent from archive manifest')
        if strict_path and source_path and not any(
            os.path.basename(item['path']) == os.path.basename(str(source_path))
            for item in matches
        ):
            raise VersionMismatchError('commitment matches only a different archived path')

        entry = matches[0]
        return VersionProof(
            canonical_path=entry['path'],
            commitment=entry['commitment'],
            archive=self.archive,
            entry=entry,
        )

    def proves_same_version(
        self,
        first: Any,
        second: Any,
    ) -> bool:
        try:
            first_proof = self.prove(first)
            second_proof = self.prove(second)
        except ManifestError:
            return False
        return first_proof.commitment.matches(second_proof.commitment)

    def verify(self, source: Any = None, *args: Any, **kwargs: Any) -> bool:
        try:
            if args:
                return self.proves_same_version(source, args[0])
            self.prove(source, **kwargs)
            return True
        except ManifestError:
            return False

    contains = verify


def merge_receipts(
    receipts: Any = None,
    *args: Any,
    manifest: Optional[ArchiveManifest] = None,
    strict: bool = True,
    archive_manifest: Optional[ArchiveManifest] = None,
    **kwargs: Any,
) -> CoverageReceipt:
    """Merge receipts only when an archive manifest proves one file version."""
    def _looks_like_manifest_mapping(data: MappingABC) -> bool:
        if any(key in data for key in ('files', 'entries', 'members', 'artifacts', 'items')):
            return True
        if 'segments' in data:
            return False
        return bool(data) and all(
            isinstance(value, (str, MappingABC))
            and (
                isinstance(value, str)
                or any(key in value for key in COMMITMENT_KEYS)
            )
            for value in data.values()
        )

    positional = []
    if receipts is not None:
        positional.append(receipts)
    positional.extend(args)

    raw_receipts: List[Any] = []
    positional_manifest: Optional[ArchiveManifest] = None
    for argument in positional:
        if isinstance(argument, ArchiveManifest):
            positional_manifest = argument
        elif isinstance(argument, MappingABC) and _looks_like_manifest_mapping(argument):
            positional_manifest = ArchiveManifest(argument)
        elif isinstance(argument, (list, tuple, set)) and not isinstance(argument, CoverageReceipt):
            raw_receipts.extend(argument)
        else:
            raw_receipts.append(argument)

    manifest = manifest or archive_manifest or positional_manifest or kwargs.get('archive_manifest')
    if manifest is not None and not isinstance(manifest, ArchiveManifest):
        manifest = ArchiveManifest(manifest)
    parsed = [
        item if isinstance(item, CoverageReceipt)
        else CoverageReceipt(**item) if isinstance(item, MappingABC)
        else CoverageReceipt(item)
        for item in raw_receipts
    ]
    if not parsed:
        raise CoverageReceiptError('at least one receipt is required')

    commitments = [receipt.commitment for receipt in parsed]
    if any(item is None for item in commitments):
        if strict and manifest is not None:
            raise VersionMismatchError('every receipt needs a stable commitment')
        if strict:
            raise VersionMismatchError('cannot merge receipts without commitments')

    proofs: List[VersionProof] = []
    if manifest is not None:
        for receipt in parsed:
            proofs.append(manifest.prove(receipt))
        if not all(proofs[0].commitment.matches(proof.commitment) for proof in proofs[1:]):
            raise VersionMismatchError('receipts reference different archived file versions')
        canonical_commitment = proofs[0].commitment
        canonical_path = proofs[0].canonical_path
    else:
        non_null = [item for item in commitments if item is not None]
        if non_null and not all(non_null[0].matches(item) for item in non_null[1:]):
            raise VersionMismatchError('receipt commitments differ')
        if strict:
            raise ManifestError('an ArchiveManifest is required to prove relocated receipt identity')
        canonical_commitment = non_null[0] if non_null else None
        canonical_path = parsed[0].path

    merged_segments: List[CoverageSegment] = [
        segment
        for receipt in parsed
        for segment in receipt.segments
    ]

    domains = [receipt.domain for receipt in parsed if receipt.domain is not None]
    domain = None
    if domains:
        domain = Interval(
            min(item.lo for item in domains),
            max(item.hi for item in domains),
            inclusive=False,
        )
        if all(item.inclusive for item in domains):
            domain = interval_from_half_open(domain.lo, domain.hi, inclusive=True, unit=domains[0].unit)

    merged = CoverageReceipt(
        commitment=canonical_commitment,
        path=canonical_path,
        segments=merged_segments,
        domain=domain,
        archive=manifest.archive if manifest is not None else parsed[0].archive,
    )
    return merged


def try_merge_receipts(
    receipts: Any = None,
    *args: Any,
    manifest: Optional[ArchiveManifest] = None,
    **kwargs: Any,
) -> Optional[CoverageReceipt]:
    try:
        return merge_receipts(receipts, *args, manifest=manifest, **kwargs)
    except ManifestError:
        return None


def replay_coverage(
    source: Any = None,
    domain: Any = None,
    *,
    before: Optional[CoverageReceipt] = None,
    previous: Optional[CoverageReceipt] = None,
) -> Union[CoverageReplay, List[Interval]]:
    prior = before or previous
    if prior is not None:
        if not isinstance(source, CoverageReceipt):
            raise CoverageReceiptError('before/previous requires a CoverageReceipt source')
        return interval_difference(prior.successful_intervals, source.successful_intervals)
    if isinstance(source, CoverageReceipt):
        return CoverageReplay(source, domain=domain)
    if isinstance(source, (list, tuple, set)):
        segment_intervals = [
            item.interval
            for item in source
            if isinstance(item, CoverageSegment) and item.is_success and item.interval is not None
        ]
        covered: Any = segment_intervals or source
        return coverage_gaps(covered, domain=domain)
    raise CoverageReceiptError('replay_coverage requires a CoverageReceipt or interval list')


def regressed_intervals(
    before: CoverageReceipt,
    after: CoverageReceipt,
) -> List[Interval]:
    return interval_difference(before.successful_intervals, after.successful_intervals)


def receipt_from_segments(*args: Any, **kwargs: Any) -> CoverageReceipt:
    return CoverageReceipt(*args, **kwargs)


def serialize_receipt(receipt: CoverageReceipt, *, minimal: bool = False) -> Dict[str, Any]:
    if minimal:
        return receipt.to_minimal_dict()
    return receipt.to_wire_dict()


def summarize_receipts(receipts: Any) -> Dict[str, int]:
    return CoverageBundle(receipts).summary()


def verify_archive_manifest(manifest: Any, *receipts: Any) -> bool:
    if not isinstance(manifest, ArchiveManifest):
        manifest = ArchiveManifest(manifest)
    try:
        for receipt in receipts:
            manifest.prove(receipt)
        if len(receipts) >= 2:
            manifest.proves_same_version(receipts[0], receipts[1])
        return True
    except ManifestError:
        return False


build_coverage_receipt = CoverageReceipt
create_coverage_receipt = CoverageReceipt
make_receipt = CoverageReceipt
Coverage = CoverageReceipt
Receipt = CoverageReceipt
ScanCoverageReceipt = CoverageReceipt
CoverageRecord = CoverageReceipt
FileCoverageReceipt = CoverageReceipt
PluginCoverageReceipt = CoverageReceipt
CoverageAttestation = CoverageReceipt
CoverageReportReceipt = CoverageReceipt

Segment = CoverageSegment
CoverageSegmentRecord = CoverageSegment
ScanSegment = CoverageSegment
ReceiptSegment = CoverageSegment

ReceiptBundle = CoverageBundle
CoverageReceiptSet = CoverageBundle
CoverageBundleReport = CoverageBundle

Range = Interval
SegmentRange = Interval
CoverageInterval = Interval
CoverageRange = Interval
LineRange = LineInterval
LineSegment = LineInterval
ByteRange = ByteInterval
OffsetRange = ByteInterval
SegmentInterval = Interval

Manifest = ArchiveManifest
CoverageManifest = ArchiveManifest
ArchiveListing = ArchiveManifest
ArchiveManifestRecord = VersionProof
FileVersionProof = VersionProof
VersionProofRecord = VersionProof

ManifestVerificationError = ManifestError
ArchiveManifestError = ManifestError
ReceiptManifestError = ManifestError
CommitmentMismatchError = VersionMismatchError
FileVersionMismatchError = VersionMismatchError
IdentityMismatchError = VersionMismatchError
ArchiveMismatchError = VersionMismatchError
ReceiptMergeError = CoverageReceiptError
CoverageMergeError = CoverageReceiptError

build_receipt = receipt_from_segments
merge_coverage_receipts = merge_receipts
replay_gaps = coverage_gaps
find_coverage_gaps = coverage_gaps
missing_intervals = coverage_gaps
replay_coverage_gaps = coverage_gaps
calculate_coverage_gaps = coverage_gaps
compute_gaps = coverage_gaps
gap_ranges = coverage_gaps


def remove_successful_segment(
    receipt: CoverageReceipt,
    segment: Any = None,
    **kwargs: Any,
) -> CoverageReceipt:
    return receipt.remove_successful_segment(segment, **kwargs)


Commitment = StableCommitment
FileCommitment = StableCommitment
CoverageCommitment = StableCommitment
ContentCommitment = StableCommitment


def receipt_from_scan_results(
    filename: Optional[str] = None,
    results: Any = None,
    *,
    secrets: Any = None,
    intervals: Optional[Iterable[Any]] = None,
    scanned_ranges: Optional[Iterable[Any]] = None,
    clean_ranges: Optional[Iterable[Any]] = None,
    skipped_ranges: Optional[Iterable[Any]] = None,
    failed_ranges: Optional[Iterable[Any]] = None,
    commitment: Any = None,
    hash_file: bool = True,
    **kwargs: Any,
) -> CoverageReceipt:
    """Build a receipt from detect-secrets result sets and explicit ranges."""
    secret_results = secrets if secrets is not None else results
    findings_count = None
    if secret_results is not None:
        try:
            findings_count = len(secret_results)
        except TypeError:
            findings_count = None

    segments: List[CoverageSegment] = []
    for interval in failed_ranges or ():
        segments.append(CoverageSegment(interval=interval, status=STATUS_FAILED))
    for interval in skipped_ranges or ():
        segments.append(CoverageSegment(interval=interval, status=STATUS_POLICY_SKIPPED))
    for interval in clean_ranges or ():
        segments.append(CoverageSegment(interval=interval, status=STATUS_NO_FINDINGS))
    for interval in scanned_ranges or intervals or ():
        segments.append(CoverageSegment(
            interval=interval,
            status=STATUS_FOUND if findings_count else STATUS_NO_FINDINGS,
            findings_count=findings_count if len(list(scanned_ranges or intervals or [])) == 1 else None,
        ))

    if not segments:
        line_count = kwargs.pop('line_count', None)
        domain = kwargs.pop('domain', None)
        status = STATUS_FOUND if findings_count else STATUS_NO_FINDINGS
        if domain is not None:
            segments.append(CoverageSegment(interval=domain, status=status, findings_count=findings_count))
        elif line_count:
            segments.append(CoverageSegment(
                interval=Interval(1, int(line_count), inclusive=True, unit='line'),
                status=status,
                findings_count=findings_count,
            ))
        elif secret_results is not None:
            try:
                segments.extend(list(secret_results))
            except TypeError:
                segments.append(secret_results)

    if commitment is None and filename and hash_file and os.path.isfile(filename):
        commitment = StableCommitment.for_file(filename)

    return CoverageReceipt(
        commitment=commitment,
        path=filename,
        segments=segments,
        **kwargs,
    )


def scan_file_with_receipt(
    filename: Union[str, os.PathLike[str]],
    *,
    plugins: Optional[Iterable[Any]] = None,
    manifest: Optional[ArchiveManifest] = None,
) -> Tuple[List[Any], CoverageReceipt]:
    """Scan one file and return plugin secrets plus a line coverage receipt."""
    from .core.log import log
    from .core.scan import _get_lines_from_file
    from .core.scan import _is_filtered_out
    from .core.scan import _scan_line
    from .settings import get_plugins
    from .util.code_snippet import get_code_snippet

    filename_text = os.fspath(filename)
    path = Path(filename_text)
    commitment: Optional[StableCommitment] = None
    line_count = 0
    try:
        raw = path.read_bytes()
        commitment = StableCommitment.for_bytes(raw)
        line_count = len(raw.splitlines())
    except OSError:
        domain = Interval(0, 0)  # type: ignore[arg-type]
        receipt = CoverageReceipt(
            path=filename_text,
            segments=[CoverageSegment(status=STATUS_FAILED, interval=None)],
        )
        return [], receipt

    line_domain = Interval(1, line_count, inclusive=True, unit='line') if line_count else None
    if not path.is_file():
        receipt = CoverageReceipt(
            commitment=commitment,
            path=filename_text,
            domain=line_domain,
            segments=[CoverageSegment(status=STATUS_FAILED, interval=line_domain)],
        )
        return [], receipt

    if _is_filtered_out(required_filter_parameters=['filename'], filename=filename_text):
        receipt = CoverageReceipt(
            commitment=commitment,
            path=filename_text,
            domain=line_domain,
            line_count=line_count,
            segments=[CoverageSegment(status=STATUS_POLICY_SKIPPED, interval=line_domain)],
        )
        return [], receipt

    secrets: List[Any] = []
    line_status: Dict[int, str] = {}
    line_findings: Dict[int, int] = {}
    line_errors: Dict[int, str] = {}

    try:
        for lines in _get_lines_from_file(filename_text):
            line_content = list(lines)
            representation_had_secret = False
            for line_number, raw_line in enumerate(lines, start=1):
                line = raw_line.rstrip()
                context = get_code_snippet(lines=line_content, line_number=line_number)
                if _is_filtered_out(
                    required_filter_parameters=['line'],
                    filename=filename_text,
                    line=line,
                    context=context,
                ):
                    line_status[line_number] = STATUS_POLICY_SKIPPED
                    continue

                line_had_secret = False
                active_plugins = list(plugins) if plugins is not None else list(get_plugins())
                for plugin in active_plugins:
                    try:
                        found = list(_scan_line(
                            plugin=plugin,
                            filename=filename_text,
                            line=line,
                            line_number=line_number,
                            context=context,
                        ))
                    except Exception as exc:  # pragma: no cover - defensive plugin boundary
                        line_errors[line_number] = type(exc).__name__
                        line_status[line_number] = STATUS_FAILED
                        continue
                    if found:
                        secrets.extend(found)
                        line_had_secret = True
                        representation_had_secret = True
                if line_number in line_errors:
                    line_status[line_number] = STATUS_FAILED
                elif line_had_secret:
                    line_status[line_number] = STATUS_FOUND
                    line_findings[line_number] = sum(1 for secret in secrets if getattr(secret, 'line_number', None) == line_number)
                else:
                    line_status[line_number] = STATUS_NO_FINDINGS

            if representation_had_secret:
                break
    except IOError as exc:
        log.warning(f'Unable to scan file for coverage receipt: {filename_text}')
        failed_interval = Interval(1, line_count or 1, inclusive=True, unit='line')
        receipt = CoverageReceipt(
            commitment=commitment,
            path=filename_text,
            line_count=line_count,
            segments=[CoverageSegment(
                status=STATUS_FAILED,
                interval=failed_interval,
                reason=type(exc).__name__,
            )],
        )
        return secrets, receipt

    segments: List[CoverageSegment] = []
    if line_status:
        ordered_numbers = sorted(line_status)
        run_start = ordered_numbers[0]
        run_end = run_start
        current_status = line_status[run_start]
        for number in ordered_numbers[1:]:
            status = line_status[number]
            if status != current_status or number != run_end + 1:
                segments.append(_line_run_segment(
                    run_start,
                    run_end,
                    current_status,
                    line_findings,
                    line_errors,
                ))
                run_start = number
                run_end = number
                current_status = status
            else:
                run_end = number
        segments.append(_line_run_segment(
            run_start,
            run_end,
            current_status,
            line_findings,
            line_errors,
        ))
    elif line_domain is not None:
        segments.append(CoverageSegment(status=STATUS_NO_FINDINGS, interval=line_domain))

    receipt = CoverageReceipt(
        commitment=commitment,
        path=filename_text,
        line_count=line_count,
        segments=segments,
    )
    if manifest is not None:
        manifest.prove(receipt)
    return secrets, receipt


def _line_run_segment(
    start_line: int,
    end_line: int,
    status: str,
    line_findings: Dict[int, int],
    line_errors: Dict[int, str],
) -> CoverageSegment:
    count = None
    reason = None
    if status == STATUS_FOUND:
        count = sum(value for line, value in line_findings.items() if start_line <= line <= end_line)
    if status == STATUS_FAILED:
        errors = {
            line_errors[line]
            for line in range(start_line, end_line + 1)
            if line in line_errors
        }
        reason = next(iter(errors), None)
    return CoverageSegment(
        status=status,
        interval=Interval(start_line, end_line, inclusive=True, unit='line'),
        findings_count=count,
        reason=reason,
    )


receipt_from_plugin_results = receipt_from_scan_results
coverage_receipt_from_results = receipt_from_scan_results
create_receipt_from_scan = receipt_from_scan_results
scan_with_coverage_receipt = scan_file_with_receipt
