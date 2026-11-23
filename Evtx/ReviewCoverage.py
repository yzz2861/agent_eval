"""Review coverage accounting for EVTX evidence.

The parser in :mod:`Evtx.Evtx` deliberately exposes the raw, read-only view of
an event log.  This module adds a small accounting layer on top of that view:
it records the physical location of every parsed record, reconciles review
receipts against those records, and reports which original records are actually
covered.

The important invariants are:

* coverage is keyed by evidence scope and the physical record location, never
  by a receipt's claimed count;
* receipts that overlap the same record do not increase the reviewed count;
* reviewed time is the union of covered intervals, not the sum of evidence
  intervals;
* a record that cannot be parsed is never counted as reviewed, and the parser
  error remains attached to the record as an unreviewed reason;
* fields from an earlier receipt revision are carried forward only when the
  earlier receipt's bindings still validate against the current record.

The public API is intentionally tolerant of plain dictionaries because receipts
are frequently exported as JSON by case-management tools.
"""

from __future__ import absolute_import

import datetime as _datetime
import hashlib
import json
import os
import re
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from .Evtx import Evtx as EvtxReader, InvalidRecordException, Record


UTC = _datetime.timezone.utc

STATUS_UNREVIEWED = "unreviewed"
STATUS_PARTIAL = "partial"
STATUS_HANDOVER_READY = "handover_ready"
STATUS_EMPTY = "empty"

REASON_NOT_COVERED = "not_covered"
REASON_RECORD_CONTENT_ERROR = "record_content_error"
REASON_INVALID_RECORD_STRUCTURE = "invalid_record_structure"
REASON_INVALID_TIMESTAMP = "invalid_timestamp"
REASON_MISSING_RECORD = "missing_record"
REASON_STALE_RECEIPT_BINDING = "stale_receipt_binding"
REASON_EVIDENCE_CHANGED = "evidence_changed"
REASON_RECEIPT_REJECTED = "receipt_rejected"

LEGACY_FIELD_PREFIX = "legacy_receipt."


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == () or value == [] or value == {}


def _unique(items: Iterable[Any]) -> List[Any]:
    seen = set()
    result = []
    for item in items:
        marker = item
        try:
            hash(marker)
        except TypeError:
            marker = repr(marker)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def _coerce_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            try:
                return int(text, 10)
            except ValueError:
                return None
    return None


def _coerce_datetime(value: Any) -> Optional[_datetime.datetime]:
    """Best-effort conversion of dates, ISO strings, and epoch values to UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, _datetime.datetime):
        when = value
        if when.tzinfo is None:
            return when.replace(tzinfo=UTC)
        return when.astimezone(UTC)
    if isinstance(value, _datetime.date):
        return _datetime.datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10**15:
            # Windows FILETIME, 100-nanosecond units since 1601-01-01.
            seconds = number / 10_000_000.0 - 11644473600.0
        elif number > 10**11:
            # Milliseconds since the Unix epoch.
            seconds = number / 1000.0
        elif number > 10**9:
            seconds = number
        else:
            seconds = number
        try:
            return _datetime.datetime.fromtimestamp(seconds, UTC)
        except (OverflowError, OSError, ValueError):
            return None

    text = str(value).strip()
    if not text:
        return None
    if text.startswith("{") and text.endswith("}"):
        # Some exporters wrap timestamps in JSON-ish braces.
        text = text[1:-1].strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        when = _datetime.datetime.fromisoformat(text)
    except ValueError:
        when = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                when = _datetime.datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        if when is None:
            # Last resort: numeric strings.
            try:
                return _coerce_datetime(float(text))
            except (TypeError, ValueError):
                return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.astimezone(UTC)


def _iso(value: Optional[_datetime.datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat()


def _ts(value: Optional[_datetime.datetime]) -> Optional[float]:
    if value is None:
        return None
    return value.astimezone(UTC).timestamp()


def _same_time(left: Any, right: Any) -> bool:
    a = _coerce_datetime(left)
    b = _coerce_datetime(right)
    if a is None or b is None:
        return False
    return abs((a - b).total_seconds()) <= 0.000001


def _same_value(expected: Any, actual: Any) -> bool:
    if expected is None:
        return True
    if isinstance(expected, (list, tuple, set, frozenset)):
        return actual in expected or str(actual) in {str(v) for v in expected}
    if isinstance(expected, _datetime.datetime) or isinstance(expected, _datetime.date):
        return _same_time(expected, actual)
    if isinstance(expected, str) and _coerce_datetime(expected) is not None and _coerce_datetime(actual) is not None:
        # Prefer timestamp comparison when both sides look like dates.
        if any(marker in expected for marker in ("-", ":", "T", "Z")) and any(
            marker in str(actual) for marker in ("-", ":", "T", "Z")
        ):
            return _same_time(expected, actual)
    if isinstance(expected, int) and not isinstance(expected, bool):
        number = _coerce_int(actual)
        return number == expected
    if isinstance(actual, int) and not isinstance(actual, bool):
        number = _coerce_int(expected)
        return number == actual
    left = str(expected)
    right = str(actual)
    if len(left) in (32, 40, 64) and len(right) in (32, 40, 64):
        return left.lower() == right.lower()
    return left == right


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    try:
        size = os.path.getsize(path)
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(path, "rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                sha256.update(block)
                md5.update(block)
        return sha256.hexdigest(), md5.hexdigest(), size
    except OSError:
        return None, None, None


def _merge_ranges(
    ranges: Iterable[Tuple[Optional[_datetime.datetime], Optional[_datetime.datetime]]]
) -> List[Tuple[_datetime.datetime, _datetime.datetime]]:
    prepared = [(start, end) for start, end in ranges if start is not None and end is not None and end >= start]
    prepared.sort(key=lambda item: item[0])
    merged: List[List[_datetime.datetime]] = []
    for start, end in prepared:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        elif end > merged[-1][1]:
            merged[-1][1] = end
    return [(start, end) for start, end in merged]


def _range_seconds(ranges: Iterable[Tuple[_datetime.datetime, _datetime.datetime]]) -> float:
    return sum((end - start).total_seconds() for start, end in ranges)


def _json_value(value: Any) -> Any:
    if isinstance(value, _datetime.datetime):
        return _iso(value)
    if isinstance(value, _datetime.date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


def _first(mapping: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return default


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _mapping_get_any(mapping: Mapping[str, Any], *names: str) -> Tuple[bool, Any]:
    for name in names:
        if name in mapping:
            return True, mapping[name]
    return False, None


_EVENT_ID_RE = re.compile(r"<EventID\b[^>]*>\s*(\d+)\s*</EventID>", re.IGNORECASE | re.DOTALL)
_PROVIDER_RE = re.compile(r'<Provider\b[^>]*\bName="([^"]+)"', re.IGNORECASE | re.DOTALL)
_COMPUTER_RE = re.compile(r"<Computer\b[^>]*>\s*([^<]+?)\s*</Computer>", re.IGNORECASE | re.DOTALL)
_CHANNEL_RE = re.compile(r"<Channel\b[^>]*>\s*([^<]+?)\s*</Channel>", re.IGNORECASE | re.DOTALL)
_EVENT_RECORD_ID_RE = re.compile(r"<EventRecordID\b[^>]*>\s*(\d+)\s*</EventRecordID>", re.IGNORECASE | re.DOTALL)
_DATA_RE = re.compile(r'<Data\b[^>]*\bName="([^"]+)"[^>]*>(.*?)</Data>', re.IGNORECASE | re.DOTALL)


def _extract_xml_fields(xml: Optional[str]) -> Dict[str, Any]:
    if not xml:
        return {}
    fields: Dict[str, Any] = {}
    match = _EVENT_ID_RE.search(xml)
    if match:
        fields["event_id"] = _coerce_int(match.group(1))
    match = _PROVIDER_RE.search(xml)
    if match:
        fields["provider"] = match.group(1)
    match = _COMPUTER_RE.search(xml)
    if match:
        fields["computer"] = match.group(1)
    match = _CHANNEL_RE.search(xml)
    if match:
        fields["channel"] = match.group(1)
    match = _EVENT_RECORD_ID_RE.search(xml)
    if match:
        fields["event_record_id"] = _coerce_int(match.group(1))
    for name, value in _DATA_RE.findall(xml):
        fields.setdefault(name, value)
        fields.setdefault("data." + name, value)
    return fields


@dataclass(frozen=True)
class RecordLocation:
    """A physical location in one evidence file.

    ``file_offset`` is the absolute offset of the record in the EVTX file,
    ``chunk_offset`` is the absolute offset of the containing chunk, and
    ``record_offset`` is the chunk-relative offset.
    """

    evidence_id: str = ""
    record_num: Optional[int] = None
    file_offset: Optional[int] = None
    chunk_offset: Optional[int] = None
    record_offset: Optional[int] = None
    timestamp: Any = None
    record_sha256: Optional[str] = None
    content_sha256: Optional[str] = None
    record_md5: Optional[str] = None
    content_md5: Optional[str] = None
    size: Optional[int] = None

    @classmethod
    def from_any(cls, value: Any, evidence_id: Optional[str] = None) -> "RecordLocation":
        if isinstance(value, cls):
            if evidence_id and not value.evidence_id:
                return cls(
                    evidence_id=evidence_id,
                    record_num=value.record_num,
                    file_offset=value.file_offset,
                    chunk_offset=value.chunk_offset,
                    record_offset=value.record_offset,
                    timestamp=value.timestamp,
                    record_sha256=value.record_sha256,
                    content_sha256=value.content_sha256,
                    record_md5=value.record_md5,
                    content_md5=value.content_md5,
                    size=value.size,
                )
            return value
        if isinstance(value, RecordSnapshot):
            return value.location
        if isinstance(value, int):
            return cls(evidence_id=evidence_id or "", record_num=value)
        if isinstance(value, str):
            text = value.strip()
            number = _coerce_int(text)
            if number is not None:
                return cls(evidence_id=evidence_id or "", record_num=number)
            return cls(evidence_id=evidence_id or text, record_num=None)
        if isinstance(value, Mapping):
            record_num = _coerce_int(
                _first(value, "record_num", "record_number", "record_no", "number", "id", "event_record_id")
            )
            file_offset = _coerce_int(_first(value, "file_offset", "absolute_offset", "offset"))
            chunk_offset = _coerce_int(_first(value, "chunk_offset", "chunk_start"))
            record_offset = _coerce_int(_first(value, "record_offset", "chunk_relative_offset", "relative_offset"))
            if record_offset is None and file_offset is not None and chunk_offset is not None:
                record_offset = file_offset - chunk_offset
            if file_offset is None and chunk_offset is not None and record_offset is not None:
                file_offset = chunk_offset + record_offset
            return cls(
                evidence_id=str(
                    _first(value, "evidence_id", "evidence_scope", "scope", "evidence", default=evidence_id or "")
                ),
                record_num=record_num,
                file_offset=file_offset,
                chunk_offset=chunk_offset,
                record_offset=record_offset,
                timestamp=_coerce_datetime(_first(value, "timestamp", "time", "system_time", "when")),
                record_sha256=_first(
                    value, "record_sha256", "sha256", "digest", "record_digest", "hash", "record_hash"
                ),
                content_sha256=_first(
                    value, "content_sha256", "xml_sha256", "content_digest", "content_hash", "xml_hash"
                ),
                record_md5=_first(value, "record_md5", "md5", "record_digest_md5"),
                content_md5=_first(value, "content_md5", "xml_md5", "content_digest_md5"),
                size=_coerce_int(_first(value, "size", "length", "record_size")),
            )
        raise TypeError("cannot make a RecordLocation from {!r}".format(value))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], evidence_id: Optional[str] = None) -> "RecordLocation":
        return cls.from_any(value, evidence_id=evidence_id)

    @property
    def key(self) -> Tuple[Any, ...]:
        if self.file_offset is not None:
            return (self.evidence_id, "offset", self.file_offset)
        return (self.evidence_id, "record", self.record_num)

    @property
    def key_string(self) -> str:
        if self.file_offset is not None:
            return "{}:offset:{}".format(self.evidence_id, self.file_offset)
        return "{}:record:{}".format(self.evidence_id, self.record_num)

    @property
    def offset(self) -> Optional[int]:
        return self.file_offset

    @property
    def record_number(self) -> Optional[int]:
        return self.record_num

    @property
    def digest(self) -> Optional[str]:
        return self.record_sha256 or self.record_md5

    @property
    def sha256(self) -> Optional[str]:
        return self.record_sha256

    @property
    def md5(self) -> Optional[str]:
        return self.record_md5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_scope": self.evidence_id,
            "record_num": self.record_num,
            "record_number": self.record_num,
            "file_offset": self.file_offset,
            "offset": self.file_offset,
            "chunk_offset": self.chunk_offset,
            "record_offset": self.record_offset,
            "key_string": self.key_string,
            "timestamp": _iso(_coerce_datetime(self.timestamp)),
            "record_sha256": self.record_sha256,
            "sha256": self.record_sha256,
            "content_sha256": self.content_sha256,
            "record_md5": self.record_md5,
            "md5": self.record_md5,
            "content_md5": self.content_md5,
            "size": self.size,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


@dataclass
class RecordSnapshot:
    """A record as it exists in the evidence at ledger-build time."""

    evidence_id: str
    record_num: Optional[int] = None
    file_offset: Optional[int] = None
    chunk_offset: Optional[int] = None
    record_offset: Optional[int] = None
    timestamp: Optional[_datetime.datetime] = None
    record_sha256: Optional[str] = None
    content_sha256: Optional[str] = None
    record_md5: Optional[str] = None
    content_md5: Optional[str] = None
    size: Optional[int] = None
    evidence_sha256: Optional[str] = None
    evidence_md5: Optional[str] = None
    valid: bool = True
    base_reasons: List[Dict[str, Any]] = field(default_factory=list)
    xml_fields: Dict[str, Any] = field(default_factory=dict)
    xml: Optional[str] = None
    source_record: Any = field(default=None, repr=False, compare=False)
    review_ids: List[str] = field(default_factory=list)
    claim_reasons: List[Dict[str, Any]] = field(default_factory=list)
    bound_fields: Dict[str, Any] = field(default_factory=dict)
    receipt_fields: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    _field_cache: Optional[Dict[str, Any]] = field(default=None, repr=False, compare=False)

    @property
    def location(self) -> RecordLocation:
        return RecordLocation(
            evidence_id=self.evidence_id,
            record_num=self.record_num,
            file_offset=self.file_offset,
            chunk_offset=self.chunk_offset,
            record_offset=self.record_offset,
            timestamp=self.timestamp,
            record_sha256=self.record_sha256,
            content_sha256=self.content_sha256,
            record_md5=self.record_md5,
            content_md5=self.content_md5,
            size=self.size,
        )

    @property
    def key(self) -> Tuple[Any, ...]:
        return self.location.key

    @property
    def key_string(self) -> str:
        return self.location.key_string

    @property
    def fingerprint(self) -> Tuple[Any, ...]:
        # Two copies of the same original record in overlapping evidence files
        # should not inflate an aggregate reviewed count.
        return (
            self.timestamp.astimezone(UTC).isoformat() if self.timestamp else None,
            self.record_num,
            self.record_sha256 or self.content_sha256 or self.record_md5 or self.content_md5,
        )

    @property
    def reviewed(self) -> bool:
        return bool(self.review_ids) and self.valid

    @property
    def receipt_ids(self) -> List[str]:
        """Receipts that successfully covered this physical record."""
        return list(self.review_ids)

    @property
    def reviewed_by(self) -> List[str]:
        return list(self.review_ids)

    @property
    def is_reviewed(self) -> bool:
        return self.reviewed

    @property
    def digest(self) -> Optional[str]:
        return self.record_sha256 or self.record_md5 or self.content_sha256 or self.content_md5

    @property
    def sha256(self) -> Optional[str]:
        return self.record_sha256

    @property
    def md5(self) -> Optional[str]:
        return self.record_md5

    @property
    def reason(self) -> Optional[str]:
        return self.unreviewed_reason

    @property
    def unreviewed_reasons(self) -> List[Dict[str, Any]]:
        return list(self.base_reasons) + list(self.claim_reasons)

    @property
    def reason_code(self) -> Optional[str]:
        if self.reviewed:
            return None
        reasons = list(self.base_reasons) + list(self.claim_reasons)
        codes = _unique(reason.get("reason_code") for reason in reasons if reason.get("reason_code"))
        if not codes:
            return REASON_NOT_COVERED
        return "+".join(codes)

    @property
    def unreviewed_reason(self) -> Optional[str]:
        if self.reviewed:
            return None
        reasons = list(self.base_reasons)
        reasons.extend(self.claim_reasons)
        if not reasons:
            return REASON_NOT_COVERED
        return "; ".join(str(reason.get("reason")) for reason in reasons if reason.get("reason"))

    @property
    def fields(self) -> Dict[str, Any]:
        if self._field_cache is None:
            fields: Dict[str, Any] = {
                "record_num": self.record_num,
                "record_number": self.record_num,
                "file_offset": self.file_offset,
                "offset": self.file_offset,
                "chunk_offset": self.chunk_offset,
                "record_offset": self.record_offset,
                "timestamp": self.timestamp,
                "time": self.timestamp,
                "record_sha256": self.record_sha256,
                "sha256": self.record_sha256,
                "content_sha256": self.content_sha256,
                "record_md5": self.record_md5,
                "md5": self.record_md5,
                "content_md5": self.content_md5,
                "size": self.size,
                "evidence_sha256": self.evidence_sha256,
                "file_sha256": self.evidence_sha256,
                "evidence_md5": self.evidence_md5,
                "file_md5": self.evidence_md5,
            }
            fields.update(self.xml_fields)
            self._field_cache = {key: value for key, value in fields.items() if value is not None}
        return self._field_cache

    def to_dict(self, include_bound_fields: bool = True) -> Dict[str, Any]:
        data = self.location.to_dict()
        data.update(
            {
                "key": list(self.key),
                "reviewed": self.reviewed,
                "receipt_ids": list(self.review_ids),
                "review_ids": list(self.review_ids),
                "unreviewed_reason": self.unreviewed_reason,
                "reason": self.unreviewed_reason,
                "reason_code": self.reason_code,
                "content_abnormal": not self.valid,
                "valid": self.valid,
                "evidence_sha256": self.evidence_sha256,
                "evidence_md5": self.evidence_md5,
                "reasons": _json_value(self.base_reasons),
                "claim_reasons": _json_value(self.claim_reasons),
                "xml_fields": _json_value(self.xml_fields),
                "xml": self.xml,
            }
        )
        if include_bound_fields:
            data["bound_fields"] = _json_value(self.bound_fields)
            data["receipt_fields"] = _json_value(self.receipt_fields)
        return data

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecordSnapshot":
        return _snapshot_from_mapping(value)

    # Mapping-like convenience for callers that work with receipt JSON.
    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def keys(self):
        return self.to_dict().keys()

    def items(self):
        return self.to_dict().items()


@dataclass
class EvidenceScope:
    """One exhibit / original evidence file and its parsed records."""

    evidence_id: str
    path: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    size: Optional[int] = None
    records: List[RecordSnapshot] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def scope(self) -> str:
        return self.evidence_id

    @property
    def id(self) -> str:
        return self.evidence_id

    @property
    def record_count(self) -> int:
        return len(self.records)

    @property
    def digest(self) -> Optional[str]:
        return self.sha256 or self.md5

    @property
    def start_time(self) -> Optional[_datetime.datetime]:
        times = [record.timestamp for record in self.records if record.timestamp is not None]
        return min(times) if times else None

    @property
    def end_time(self) -> Optional[_datetime.datetime]:
        times = [record.timestamp for record in self.records if record.timestamp is not None]
        return max(times) if times else None

    @property
    def all_aliases(self) -> List[str]:
        aliases = [self.evidence_id]
        if self.path:
            aliases.extend(
                [
                    self.path,
                    os.path.abspath(self.path),
                    os.path.normpath(self.path),
                    os.path.basename(self.path),
                ]
            )
        if self.sha256:
            aliases.append(self.sha256)
        aliases.extend(self.aliases)
        return _unique([str(alias) for alias in aliases if alias])

    def to_dict(self, include_records: bool = True) -> Dict[str, Any]:
        data = {
            "evidence_id": self.evidence_id,
            "scope": self.evidence_id,
            "path": self.path,
            "sha256": self.sha256,
            "md5": self.md5,
            "size": self.size,
            "record_count": len(self.records),
            "start_time": _iso(self.start_time),
            "end_time": _iso(self.end_time),
            "aliases": list(self.all_aliases),
            "metadata": _json_value(self.metadata),
        }
        if include_records:
            data["records"] = [record.to_dict() for record in self.records]
        return data

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceScope":
        scope_id = str(_first(value, "evidence_id", "scope", "id", "name", default=""))
        sha256 = _first(value, "sha256", "evidence_sha256", "file_sha256")
        md5 = _first(value, "md5", "evidence_md5", "file_md5")
        records: List[RecordSnapshot] = []
        for item in _as_list(_first(value, "records", "record_snapshots", default=[])):
            if isinstance(item, RecordSnapshot):
                records.append(item)
            elif isinstance(item, RecordLocation):
                records.append(_snapshot_from_mapping(item.to_dict()))
            elif isinstance(item, Mapping):
                records.append(_snapshot_from_mapping(item))
            else:
                number = _coerce_int(item)
                if number is None:
                    raise TypeError("cannot make a record from {!r}".format(item))
                records.append(
                    RecordSnapshot(
                        evidence_id=scope_id,
                        record_num=number,
                        evidence_sha256=sha256,
                        evidence_md5=md5,
                    )
                )
        return cls(
            evidence_id=scope_id,
            path=_first(value, "path", "file", "filename", "source"),
            sha256=sha256,
            md5=md5,
            size=_coerce_int(_first(value, "size", "length")),
            records=records,
            aliases=[str(alias) for alias in _as_list(_first(value, "aliases", default=[]))],
            metadata=dict(_first(value, "metadata", "extra", default={}) or {}),
        )


@dataclass
class ReviewReceipt:
    """A colleague's review receipt.

    A receipt can identify its records in any of the ways used by common
    evidence tools: record numbers, physical locations, snapshots with hashes,
    time windows, or segment identifiers.
    """

    receipt_id: str
    evidence_ids: List[str] = field(default_factory=list)
    evidence_sha256: Optional[str] = None
    evidence_md5: Optional[str] = None
    reviewer: Optional[str] = None
    reviewed_at: Optional[_datetime.datetime] = None
    start_time: Optional[_datetime.datetime] = None
    end_time: Optional[_datetime.datetime] = None
    intervals: List[Tuple[Optional[_datetime.datetime], Optional[_datetime.datetime]]] = field(default_factory=list)
    record_numbers: List[int] = field(default_factory=list)
    record_locations: List[RecordLocation] = field(default_factory=list)
    record_snapshots: List[RecordSnapshot] = field(default_factory=list)
    segment_ids: List[str] = field(default_factory=list)
    segment_specs: List[Dict[str, Any]] = field(default_factory=list)
    status: Optional[str] = None
    legacy: bool = False
    schema_version: Any = None
    required_fields: Dict[str, Any] = field(default_factory=dict)
    bound_fields: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    inherited_from: Dict[str, str] = field(default_factory=dict)
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def id(self) -> str:
        return self.receipt_id

    @property
    def evidence_scope(self) -> Optional[str]:
        return self.evidence_ids[0] if self.evidence_ids else None

    @property
    def scope(self) -> Optional[str]:
        return self.evidence_scope

    @property
    def record_nums(self) -> List[int]:
        return list(self.record_numbers)

    @property
    def locations(self) -> List[RecordLocation]:
        return list(self.record_locations)

    @property
    def snapshots(self) -> List[RecordSnapshot]:
        return list(self.record_snapshots)

    @property
    def interval(self) -> Optional[Tuple[Optional[_datetime.datetime], Optional[_datetime.datetime]]]:
        return self.intervals[0] if self.intervals else None

    @property
    def time_range(self) -> List[Optional[str]]:
        return [_iso(self.start_time), _iso(self.end_time)]

    @property
    def records(self) -> List[Any]:
        return list(self.record_snapshots) + list(self.record_locations)

    @property
    def has_selectors(self) -> bool:
        return bool(
            self.record_numbers
            or self.record_locations
            or self.record_snapshots
            or self.segment_ids
            or self.intervals
            or self.start_time
            or self.end_time
        )

    @classmethod
    def from_any(cls, value: Any) -> "ReviewReceipt":
        if isinstance(value, cls):
            return value
        if isinstance(value, (str, bytes, os.PathLike)):
            return cls.from_mapping(_load_json_mapping(value))
        if isinstance(value, Mapping):
            return cls.from_mapping(value)
        raise TypeError("cannot make a ReviewReceipt from {!r}".format(value))

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "ReviewReceipt":
        if not isinstance(mapping, Mapping):
            raise TypeError("receipt must be a mapping")
        receipt_id = _first(mapping, "receipt_id", "id", "receipt", "receipt_no")
        if receipt_id is None:
            receipt_id = "receipt-{}".format(uuid.uuid4().hex[:12])
        receipt_id = str(receipt_id)

        evidence_ids: List[str] = []
        evidence_hashes: Dict[str, str] = {}
        evidence_sha256 = _first(mapping, "evidence_sha256", "file_sha256", "evidence_hash")
        evidence_md5 = _first(mapping, "evidence_md5", "file_md5", "evidence_hash_md5")
        raw_hashes = _first(mapping, "evidence_hashes", "file_hashes")
        if isinstance(raw_hashes, Mapping):
            evidence_hashes.update({str(key): str(value) for key, value in raw_hashes.items() if value is not None})
        for key in ("evidence_ids", "evidence_id", "evidence_scope", "scope", "evidence", "evidence_scopes", "files"):
            if key not in mapping or mapping[key] is None:
                continue
            value = mapping[key]
            for item in _as_list(value):
                if isinstance(item, Mapping):
                    item_id = _first(item, "evidence_id", "id", "scope", "path", "file")
                    item_hash = _first(item, "sha256", "evidence_sha256", "file_sha256", "evidence_hash", "hash")
                    item_md5 = _first(item, "md5", "evidence_md5", "file_md5")
                    if item_id is not None:
                        evidence_ids.append(str(item_id))
                    if item_hash is not None:
                        if evidence_sha256 is None:
                            evidence_sha256 = item_hash
                        if item_id is not None:
                            evidence_hashes[str(item_id)] = str(item_hash)
                    if item_md5 is not None:
                        if evidence_md5 is None:
                            evidence_md5 = item_md5
                        if item_id is not None:
                            evidence_hashes.setdefault(str(item_id), str(item_md5))
                elif not _empty(item):
                    evidence_ids.append(str(item))

        record_numbers: List[int] = []
        for key in (
            "record_numbers",
            "record_nums",
            "record_nos",
            "record_number",
            "record_num",
            "record_ids",
            "covered_records",
            "reviewed_record_numbers",
        ):
            if key in mapping and mapping[key] is not None:
                for item in _as_list(mapping[key]):
                    number = _coerce_int(item)
                    if number is not None:
                        record_numbers.append(number)

        record_locations: List[RecordLocation] = []
        for key in ("record_locations", "locations", "record_refs", "location"):
            if key in mapping and mapping[key] is not None:
                for item in _as_list(mapping[key]):
                    record_locations.append(RecordLocation.from_any(item))
        for key in ("offsets", "record_offsets", "file_offsets"):
            if key in mapping and mapping[key] is not None:
                for item in _as_list(mapping[key]):
                    offset = _coerce_int(item)
                    if offset is not None:
                        record_locations.append(
                            RecordLocation(evidence_id=evidence_ids[0] if evidence_ids else "", file_offset=offset)
                        )

        record_snapshots: List[RecordSnapshot] = []
        if "records" in mapping and mapping["records"] is not None:
            raw_records = mapping["records"]
            if isinstance(raw_records, Mapping):
                for number, item in raw_records.items():
                    if isinstance(item, Mapping):
                        enriched = dict(item)
                        enriched.setdefault("record_num", number)
                        record_snapshots.append(_snapshot_from_mapping(enriched))
                    elif isinstance(item, str) and len(item.strip()) in (32, 40, 64):
                        record_snapshots.append(
                            _snapshot_from_mapping({"record_num": number, "sha256": item.strip()})
                        )
                    else:
                        record_snapshots.append(_snapshot_from_mapping({"record_num": number, "value": item}))
            else:
                for item in _as_list(raw_records):
                    if isinstance(item, RecordSnapshot):
                        record_snapshots.append(item)
                    elif isinstance(item, Mapping):
                        record_snapshots.append(_snapshot_from_mapping(item))
                    else:
                        number = _coerce_int(item)
                        if number is not None:
                            record_numbers.append(number)
        for key in ("record_snapshots", "record_bindings", "snapshots"):
            if key in mapping and mapping[key] is not None:
                for item in _as_list(mapping[key]):
                    if isinstance(item, RecordSnapshot):
                        record_snapshots.append(item)
                    else:
                        record_snapshots.append(_snapshot_from_mapping(item))

        start_time = _coerce_datetime(
            _first(mapping, "start_time", "start", "from", "coverage_start", "window_start")
        )
        end_time = _coerce_datetime(_first(mapping, "end_time", "end", "to", "coverage_end", "window_end"))
        intervals: List[Tuple[Optional[_datetime.datetime], Optional[_datetime.datetime]]] = []
        for key in ("intervals", "ranges", "windows", "periods"):
            if key in mapping and mapping[key] is not None:
                for item in _as_list(mapping[key]):
                    if isinstance(item, Mapping):
                        interval_start = _coerce_datetime(_first(item, "start_time", "start", "from"))
                        interval_end = _coerce_datetime(_first(item, "end_time", "end", "to"))
                    elif isinstance(item, (list, tuple)) and len(item) >= 2:
                        interval_start = _coerce_datetime(item[0])
                        interval_end = _coerce_datetime(item[1])
                    else:
                        continue
                    intervals.append((interval_start, interval_end))
        if "interval" in mapping and mapping["interval"] is not None:
            item = mapping["interval"]
            if isinstance(item, Mapping):
                intervals.append(
                    (
                        _coerce_datetime(_first(item, "start_time", "start", "from")),
                        _coerce_datetime(_first(item, "end_time", "end", "to")),
                    )
                )
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                intervals.append((_coerce_datetime(item[0]), _coerce_datetime(item[1])))
        if start_time is not None or end_time is not None:
            intervals.append((start_time, end_time))

        segment_ids: List[str] = []
        segment_specs: List[Dict[str, Any]] = []
        for key in ("segment_ids", "segment_id", "segment", "segments"):
            if key not in mapping or mapping[key] is None:
                continue
            for item in _as_list(mapping[key]):
                if isinstance(item, Mapping):
                    segment = dict(item)
                    segment_specs.append(segment)
                    segment_id = _first(segment, "segment_id", "id", "name")
                    if segment_id is not None:
                        segment_ids.append(str(segment_id))
                elif not _empty(item):
                    segment_ids.append(str(item))

        schema_version = _first(mapping, "schema_version", "format_version", "version", "receipt_version")
        legacy = bool(_first(mapping, "legacy", "is_legacy", default=False))
        if not legacy and schema_version is not None:
            try:
                legacy = int(str(schema_version).split(".")[0]) < 2
            except (TypeError, ValueError):
                legacy = str(schema_version).lower() in {"legacy", "v1", "1"}

        required_fields: Dict[str, Any] = {}
        raw_required = _first(mapping, "required_fields", "required", "binding_requirements")
        if isinstance(raw_required, Mapping):
            required_fields.update(raw_required)
        elif isinstance(raw_required, (list, tuple, set, frozenset)):
            for name in raw_required:
                required_fields[str(name)] = None

        bound_fields: Dict[str, Any] = {}
        raw_bound = _first(mapping, "bound_fields", "bindings", "binding")
        if isinstance(raw_bound, Mapping):
            nested_fields = _first(raw_bound, "fields", "values")
            if isinstance(nested_fields, Mapping):
                bound_fields.update(nested_fields)
            else:
                bound_fields.update(
                    {
                        key: value
                        for key, value in raw_bound.items()
                        if key not in {"required_fields", "required", "fields", "values"}
                    }
                )
            nested_required = _first(raw_bound, "required_fields", "required")
            if isinstance(nested_required, Mapping):
                required_fields.update(nested_required)
            elif isinstance(nested_required, (list, tuple, set, frozenset)):
                for name in nested_required:
                    required_fields[str(name)] = None

        # Legacy receipts commonly put their binding fields at the top level
        # instead of under a "bindings" object.  Such fields are only useful
        # when they still match the current record, so collect the ones that
        # can identify a record or its content.
        top_level_bindings = {
            "record_num": ("record_num", "record_number", "record_no", "number"),
            "file_offset": ("file_offset", "absolute_offset", "offset"),
            "chunk_offset": ("chunk_offset",),
            "record_offset": ("record_offset", "chunk_relative_offset", "relative_offset"),
            "timestamp": ("timestamp", "time", "system_time", "when"),
            "record_sha256": ("record_sha256", "sha256", "digest", "record_digest", "hash", "record_hash"),
            "content_sha256": ("content_sha256", "xml_sha256", "content_digest", "content_hash", "xml_hash"),
            "record_md5": ("record_md5", "md5", "record_digest_md5"),
            "content_md5": ("content_md5", "xml_md5", "content_digest_md5"),
            "size": ("size", "length", "record_size"),
            "event_id": ("event_id", "eventid"),
            "provider": ("provider",),
            "computer": ("computer",),
            "channel": ("channel",),
            "event_record_id": ("event_record_id", "event_recordid"),
        }
        for canonical, names in top_level_bindings.items():
            present, value = _mapping_get_any(mapping, *names)
            if present and value is not None and canonical not in bound_fields:
                bound_fields[canonical] = value

        # A legacy receipt may carry only binding fields.  Turn those
        # bindings into explicit selectors, otherwise they would be checked
        # against every record and produce spurious stale rejections.
        if not (record_numbers or record_locations or record_snapshots or segment_ids or intervals):
            if bound_fields.get("file_offset") is not None:
                for scope_id in evidence_ids or [""]:
                    record_locations.append(
                        RecordLocation(
                            evidence_id=str(scope_id),
                            record_num=_coerce_int(bound_fields.get("record_num")),
                            file_offset=_coerce_int(bound_fields.get("file_offset")),
                            timestamp=_coerce_datetime(bound_fields.get("timestamp")),
                        )
                    )
            elif bound_fields.get("record_num") is not None:
                number = _coerce_int(bound_fields.get("record_num"))
                if number is not None:
                    record_numbers.append(number)
            elif bound_fields.get("timestamp") is not None:
                when = _coerce_datetime(bound_fields.get("timestamp"))
                if when is not None:
                    intervals.append(
                        (
                            when - _datetime.timedelta(microseconds=1),
                            when + _datetime.timedelta(microseconds=1),
                        )
                    )

        metadata: Dict[str, Any] = {}
        for key in ("metadata", "extra"):
            if isinstance(mapping.get(key), Mapping):
                metadata.update(mapping[key])
        if evidence_hashes:
            metadata["evidence_hashes"] = dict(evidence_hashes)
        for key in ("notes", "note", "comment", "remarks", "tags", "label", "description"):
            if key in mapping:
                metadata[key] = mapping[key]

        reviewed_at = _coerce_datetime(_first(mapping, "reviewed_at", "reviewed_on", "review_time", "audited_at"))
        status = _first(mapping, "status", "result", "outcome", "review_status")
        reviewer = _first(mapping, "reviewer", "analyst", "examiner", "owner", "reviewed_by")

        return cls(
            receipt_id=receipt_id,
            evidence_ids=_unique(evidence_ids),
            evidence_sha256=evidence_sha256,
            evidence_md5=evidence_md5,
            reviewer=str(reviewer) if reviewer is not None else None,
            reviewed_at=reviewed_at,
            start_time=start_time,
            end_time=end_time,
            intervals=intervals,
            record_numbers=_unique(record_numbers),
            record_locations=record_locations,
            record_snapshots=record_snapshots,
            segment_ids=_unique(segment_ids),
            segment_specs=segment_specs,
            status=str(status) if status is not None else None,
            legacy=legacy,
            schema_version=schema_version,
            required_fields=required_fields,
            bound_fields=bound_fields,
            metadata=metadata,
            raw=dict(mapping),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReviewReceipt":
        return cls.from_mapping(value)

    @property
    def selectors(self) -> Dict[str, Any]:
        return {
            "evidence_ids": list(self.evidence_ids),
            "record_numbers": list(self.record_numbers),
            "record_locations": [item.to_dict() for item in self.record_locations],
            "record_snapshots": [item.to_dict() for item in self.record_snapshots],
            "records": [item.to_dict() for item in self.records],
            "segment_ids": list(self.segment_ids),
            "intervals": [(_iso(start), _iso(end)) for start, end in self.intervals],
        }

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "receipt_id": self.receipt_id,
            "id": self.receipt_id,
            "evidence_ids": list(self.evidence_ids),
            "evidence_scope": self.evidence_scope,
            "evidence_sha256": self.evidence_sha256,
            "evidence_md5": self.evidence_md5,
            "reviewer": self.reviewer,
            "reviewed_at": _iso(self.reviewed_at),
            "start_time": _iso(self.start_time),
            "end_time": _iso(self.end_time),
            "intervals": [(_iso(start), _iso(end)) for start, end in self.intervals],
            "record_numbers": list(self.record_numbers),
            "record_locations": [item.to_dict() for item in self.record_locations],
            "record_snapshots": [item.to_dict() for item in self.record_snapshots],
            "records": [item.to_dict() for item in self.records],
            "segment_ids": list(self.segment_ids),
            "segment_specs": _json_value(self.segment_specs),
            "status": self.status,
            "legacy": self.legacy,
            "schema_version": self.schema_version,
            "required_fields": _json_value(self.required_fields),
            "bound_fields": _json_value(self.bound_fields),
            "metadata": _json_value(self.metadata),
            "inherited_from": dict(self.inherited_from),
            "diagnostics": _json_value(self.diagnostics),
        }
        return data

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def keys(self):
        return self.to_dict().keys()

    def items(self):
        return self.to_dict().items()


def _snapshot_from_mapping(value: Mapping[str, Any]) -> RecordSnapshot:
    if isinstance(value, RecordSnapshot):
        return value
    location = RecordLocation.from_any(value)
    return RecordSnapshot(
        evidence_id=location.evidence_id,
        record_num=location.record_num,
        file_offset=location.file_offset,
        chunk_offset=location.chunk_offset,
        record_offset=location.record_offset,
        timestamp=location.timestamp,
        record_sha256=location.record_sha256,
        content_sha256=location.content_sha256,
        record_md5=location.record_md5,
        content_md5=location.content_md5,
        size=location.size,
        evidence_sha256=_first(value, "evidence_sha256", "file_sha256"),
        evidence_md5=_first(value, "evidence_md5", "file_md5"),
        xml_fields=dict(_first(value, "xml_fields", "fields", default={}) or {}),
    )


@dataclass
class UnreviewedRecord:
    snapshot: RecordSnapshot
    reason_code: str
    reason: str
    receipt_ids: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = self.snapshot.to_dict()
        data.update(
            {
                "reason_code": self.reason_code,
                "reason": self.reason,
                "receipt_ids": list(self.receipt_ids),
                "details": _json_value(self.details),
            }
        )
        return data

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


@dataclass
class CoverageSegment:
    segment_id: str
    evidence_id: Optional[str]
    start_time: Optional[_datetime.datetime]
    end_time: Optional[_datetime.datetime]
    records: List[RecordSnapshot] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_records(self) -> int:
        return len(self.records)

    @property
    def reviewed_records(self) -> List[RecordSnapshot]:
        return [record for record in self.records if record.reviewed]

    @property
    def reviewed_count(self) -> int:
        return len(self.reviewed_records)

    @property
    def unreviewed_count(self) -> int:
        return self.total_records - self.reviewed_count

    @property
    def receipt_ids(self) -> List[str]:
        ids: List[str] = []
        for record in self.records:
            ids.extend(record.review_ids)
        return _unique(ids)

    @property
    def status(self) -> str:
        if self.total_records == 0:
            return STATUS_EMPTY
        if self.reviewed_count == self.total_records:
            return STATUS_HANDOVER_READY
        if self.reviewed_count:
            return STATUS_PARTIAL
        return STATUS_UNREVIEWED

    @property
    def handover_ready(self) -> bool:
        return self.status == STATUS_HANDOVER_READY

    @property
    def ready(self) -> bool:
        return self.handover_ready

    @property
    def complete(self) -> bool:
        return self.handover_ready

    @property
    def partial(self) -> bool:
        return self.status == STATUS_PARTIAL

    @property
    def record_count(self) -> int:
        return self.total_records

    @property
    def coverage_ratio(self) -> float:
        return (float(self.reviewed_count) / self.total_records) if self.total_records else 0.0

    @property
    def coverage(self) -> float:
        return self.coverage_ratio

    def unreviewed(self) -> List[UnreviewedRecord]:
        result = []
        for record in self.records:
            item = _unreviewed_item(record)
            if item is not None:
                result.append(item)
        return result

    def to_dict(self, include_records: bool = True) -> Dict[str, Any]:
        data = {
            "segment_id": self.segment_id,
            "id": self.segment_id,
            "evidence_id": self.evidence_id,
            "start_time": _iso(self.start_time),
            "end_time": _iso(self.end_time),
            "total_records": self.total_records,
            "record_count": self.total_records,
            "reviewed_count": CountRows(self.reviewed_count, [record.to_dict() for record in self.reviewed_records]),
            "reviewed_records": CountRows(
                self.reviewed_count, [record.to_dict() for record in self.reviewed_records]
            ),
            "unreviewed_count": CountRows(self.unreviewed_count, [item.to_dict() for item in self.unreviewed()]),
            "unreviewed_records": CountRows(self.unreviewed_count, [item.to_dict() for item in self.unreviewed()]),
            "coverage_ratio": (float(self.reviewed_count) / self.total_records) if self.total_records else 0.0,
            "status": self.status,
            "status_aliases": (
                ["handover_ready", "complete", "ready"]
                if self.handover_ready
                else ([STATUS_PARTIAL] if self.partial else [self.status])
            ),
            "handover_ready": self.handover_ready,
            "ready": self.handover_ready,
            "complete": self.handover_ready,
            "partial": self.status == STATUS_PARTIAL,
            "coverage": (float(self.reviewed_count) / self.total_records) if self.total_records else 0.0,
            "receipt_ids": self.receipt_ids,
            "reviewed": [record.to_dict() for record in self.reviewed_records],
            "reviewed_rows": [record.to_dict() for record in self.reviewed_records],
            "unreviewed": [item.to_dict() for item in self.unreviewed()],
            "unreviewed_rows": [item.to_dict() for item in self.unreviewed()],
            "unreviewed_reasons": [item.to_dict() for item in self.unreviewed()],
            "metadata": _json_value(self.metadata),
        }
        if include_records:
            data["records"] = [record.to_dict() for record in self.records]
        return data

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


def _unreviewed_item(snapshot: RecordSnapshot) -> Optional[UnreviewedRecord]:
    if snapshot.reviewed:
        return None
    reasons = list(snapshot.base_reasons)
    reasons.extend(snapshot.claim_reasons)
    receipt_ids = _unique(reason.get("receipt_id") for reason in reasons if reason.get("receipt_id"))
    if not reasons:
        reasons = [
            {
                "reason_code": REASON_NOT_COVERED,
                "reason": REASON_NOT_COVERED,
            }
        ]
    reason_codes = _unique(reason.get("reason_code") for reason in reasons if reason.get("reason_code"))
    reason_text = "; ".join(str(reason.get("reason")) for reason in reasons if reason.get("reason"))
    return UnreviewedRecord(
        snapshot=snapshot,
        reason_code="+".join(reason_codes) if reason_codes else REASON_NOT_COVERED,
        reason=reason_text or REASON_NOT_COVERED,
        receipt_ids=receipt_ids,
        details={"reasons": _json_value(reasons)},
    )


class _CallableList(list):
    """A list that also supports ``collection()`` style access."""

    def __call__(self):
        return self


class SegmentCollection(_CallableList):
    def get(self, segment_id: str, default: Any = None) -> Any:
        for segment in self:
            if getattr(segment, "segment_id", None) == segment_id:
                return segment
        return default

    def __getitem__(self, key):
        if isinstance(key, str):
            found = self.get(key)
            if found is None:
                raise KeyError(key)
            return found
        return super().__getitem__(key)


class RecordCollection(_CallableList):
    def get(self, key: Any, default: Any = None) -> Any:
        for record in self:
            if record.key == key or str(record.key) == str(key) or record.key_string == str(key):
                return record
        return default

    def __getitem__(self, key):
        if isinstance(key, (str, tuple)):
            for record in self:
                if record.key == key or str(record.key) == str(key) or record.key_string == str(key):
                    return record
            raise KeyError(key)
        return super().__getitem__(key)


class RecordView(RecordCollection):
    """A record collection that can also be re-filtered by calling it."""

    def __init__(self, ledger: "ReviewCoverageLedger", records: Iterable[RecordSnapshot]):
        super().__init__(records)
        self._ledger = ledger

    def __call__(
        self,
        evidence_id: Optional[str] = None,
        reviewed: Optional[bool] = None,
        include_invalid: bool = True,
    ) -> RecordCollection:
        return self._ledger._select_records(
            evidence_id=evidence_id,
            reviewed=reviewed,
            include_invalid=include_invalid,
        )


class EvidenceCollection(_CallableList):
    def get(self, evidence_id: str, default: Any = None) -> Any:
        for item in self:
            if isinstance(item, Mapping):
                if item.get("evidence_id") == evidence_id or item.get("scope") == evidence_id:
                    return item
            elif getattr(item, "evidence_id", None) == evidence_id:
                return item
        return default

    def __getitem__(self, key):
        if isinstance(key, str):
            found = self.get(key)
            if found is None:
                raise KeyError(key)
            return found
        return super().__getitem__(key)

    def keys(self):
        return [item.get("evidence_id") if isinstance(item, Mapping) else item.evidence_id for item in self]

    def values(self):
        return list(self)

    def items(self):
        return [(key, value) for key, value in zip(self.keys(), self)]


class ReasonCollection(list):
    """A list of reason rows that also indexes counts by reason code."""

    def __init__(self, items: Iterable[Any] = (), counts: Optional[Mapping[str, int]] = None):
        super().__init__(items)
        self.counts = dict(counts or {})

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in self.counts:
                return self.counts[key]
            raise KeyError(key)
        return super().__getitem__(key)

    def get(self, key: Any, default: Any = None) -> Any:
        if isinstance(key, str):
            return self.counts.get(key, default)
        try:
            return self[key]
        except (IndexError, KeyError):
            return default

    def keys(self):
        return self.counts.keys()

    def values(self):
        return self.counts.values()

    def items(self):
        return self.counts.items()

    def __contains__(self, item):
        if isinstance(item, str) and item in self.counts:
            return True
        return super().__contains__(item)


class ReceiptCollection(_CallableList):
    def get(self, receipt_id: str, default: Any = None) -> Any:
        for receipt in self:
            if receipt.receipt_id == receipt_id:
                return receipt
        return default

    def __getitem__(self, key):
        if isinstance(key, str):
            found = self.get(key)
            if found is None:
                raise KeyError(key)
            return found
        return super().__getitem__(key)

    def keys(self):
        return [receipt.receipt_id for receipt in self]

    def values(self):
        return list(self)

    def items(self):
        return [(receipt.receipt_id, receipt) for receipt in self]


class CountRows(int):
    """An integer count that also behaves like its row list.

    Coverage summaries are consumed both by dashboards (which want counts)
    and by case tools (which want the underlying rows).  This keeps
    ``summary["reviewed_records"]`` useful in either style without changing
    its JSON representation, which remains a plain integer.
    """

    def __new__(cls, value: int, rows: Iterable[Any] = ()):
        instance = int.__new__(cls, value)
        instance.rows = list(rows)
        return instance

    def __iter__(self):
        return iter(self.rows)

    def __len__(self):
        return int(self)

    def __getitem__(self, index):
        return self.rows[index]

    def __eq__(self, other):
        if isinstance(other, (list, tuple)):
            return self.rows == list(other)
        return int.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    __hash__ = int.__hash__

    def to_list(self):
        return list(self.rows)


_SUMMARY_ALIASES = {
    "reviewed": "reviewed_records",
    "reviewed_count": "reviewed_record_count",
    "reviewed_records_count": "reviewed_record_count",
    "unreviewed": "unreviewed_records",
    "unreviewed_count": "unreviewed_record_count",
    "total": "total_records",
    "record_instances": "total_record_instances",
    "reviewed_instances": "reviewed_record_instances",
    "coverage": "coverage_ratio",
    "covered_duration": "covered_seconds",
    "covered_time": "covered_seconds",
    "handover": "handover_ready",
    "ready": "handover_ready",
    "complete": "handover_ready",
    "receipts_count": "receipt_count",
    "by_scope": "by_evidence",
    "coverage_by_evidence": "evidence",
    "coverage_by_scope": "by_evidence",
}


class CoverageSummary(dict):
    """Dictionary summary with attribute and alias access."""

    def __getattr__(self, name: str) -> Any:
        if name in self:
            return self[name]
        alias = _SUMMARY_ALIASES.get(name)
        if alias and alias in self:
            return self[alias]
        raise AttributeError(name)

    def __getitem__(self, key: str) -> Any:
        if key in self:
            return dict.__getitem__(self, key)
        alias = _SUMMARY_ALIASES.get(key)
        if alias:
            return dict.__getitem__(self, alias)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


class CoverageReport(CoverageSummary):
    def __init__(self, data: Mapping[str, Any], ledger: "ReviewCoverageLedger"):
        super().__init__(data)
        self.ledger = ledger

    def __call__(self):
        return self

    def summary(self):
        return self

    def to_dict(self, include_records: bool = True):
        if not include_records:
            return self.ledger.to_dict(include_records=False)
        return _json_value(dict(self))

    def to_json(self, indent: Optional[int] = 2, include_records: bool = True) -> str:
        return self.ledger.to_json(indent=indent, include_records=include_records)

    def dumps(self, indent: Optional[int] = 2, include_records: bool = True) -> str:
        return self.to_json(indent=indent, include_records=include_records)

    def trace_receipt(self, receipt_id: str, default: Any = None):
        return self.ledger.trace_receipt(receipt_id, default=default)

    def trace_receipts(self):
        return self.ledger.trace_receipts()

    def trace(self, receipt_id: str, default: Any = None):
        return self.trace_receipt(receipt_id, default=default)

    def unreviewed(self):
        return self["unreviewed_records"]


def _load_json_mapping(source: Any) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    if isinstance(source, (str, bytes, os.PathLike)):
        text = os.fspath(source)
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            data = json.loads(stripped)
        else:
            with open(text, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        if isinstance(data, Mapping):
            if "receipts" in data:
                return data
            return data
        raise TypeError("receipt JSON must contain an object")
    raise TypeError("cannot load receipt from {!r}".format(source))


def load_receipts(source: Any) -> List[ReviewReceipt]:
    """Load one or more receipts from a mapping, JSON text, or JSON file."""
    if source is None:
        return []
    if isinstance(source, ReviewReceipt):
        return [source]
    if isinstance(source, Mapping):
        if "receipts" in source:
            return [ReviewReceipt.from_any(item) for item in _as_list(source["receipts"])]
        return [ReviewReceipt.from_mapping(source)]
    if hasattr(source, "read"):
        return load_receipts(json.load(source))
    if isinstance(source, (str, bytes, os.PathLike)):
        text = os.fspath(source)
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            data = json.loads(stripped)
        else:
            with open(text, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        return load_receipts(data)
    if isinstance(source, Iterable):
        result = []
        for item in source:
            result.extend(load_receipts(item))
        return result
    raise TypeError("cannot load receipts from {!r}".format(source))


class ReviewCoverageLedger:
    """Reconcile review receipts against the read-only EVTX record view."""

    def __init__(
        self,
        evidence: Any = None,
        receipts: Any = None,
        segment_seconds: Optional[float] = None,
        segments: Optional[Sequence[Any]] = None,
        keep_xml: bool = False,
        validate_content: bool = True,
        **kwargs: Any,
    ):
        self._evidences: "OrderedDict[str, EvidenceScope]" = OrderedDict()
        self._receipts: "OrderedDict[str, ReviewReceipt]" = OrderedDict()
        self._receipt_history: List[Dict[str, Any]] = []
        self._receipt_results: Dict[str, Dict[str, Any]] = {}
        self._aliases: Dict[str, str] = {}
        self._ambiguous_aliases: set = set()
        self._segments_config: List[Dict[str, Any]] = []
        self._segment_cache: Optional[SegmentCollection] = None
        self._summary_cache: Optional[CoverageReport] = None
        if isinstance(segment_seconds, _datetime.timedelta):
            segment_seconds = segment_seconds.total_seconds()
        self.segment_seconds = segment_seconds
        self.keep_xml = keep_xml
        self.validate_content = validate_content
        self.metadata: Dict[str, Any] = dict(kwargs.pop("metadata", {}) or {})
        if kwargs:
            self.metadata.setdefault("options", {}).update(kwargs)
        if segments:
            self.add_segments(segments)
        if evidence is not None:
            self.add_evidences(evidence)
        if receipts is not None:
            self.add_receipts(receipts)

    # ------------------------------------------------------------------
    # Evidence ingestion
    # ------------------------------------------------------------------
    def add_evidence(self, evidence: Any, evidence_id: Optional[str] = None, **kwargs: Any) -> EvidenceScope:
        if isinstance(evidence, EvidenceScope):
            scope = evidence
            if evidence_id is not None:
                scope.evidence_id = str(evidence_id)
            if scope.records:
                converted: List[RecordSnapshot] = []
                for item in scope.records:
                    if isinstance(item, RecordSnapshot):
                        converted.append(item)
                    elif isinstance(item, RecordLocation):
                        converted.append(_snapshot_from_mapping(item.to_dict()))
                    elif isinstance(item, Mapping):
                        converted.append(_snapshot_from_mapping(item))
                    else:
                        number = _coerce_int(item)
                        if number is None:
                            raise TypeError("cannot make a record from {!r}".format(item))
                        converted.append(
                            RecordSnapshot(
                                evidence_id=scope.evidence_id,
                                record_num=number,
                                evidence_sha256=scope.sha256,
                                evidence_md5=scope.md5,
                            )
                        )
                scope.records = converted
            elif scope.path:
                scope = self._scan_path(scope.path, scope.evidence_id, scope)
            return self._register_evidence(scope)

        if isinstance(evidence, Mapping):
            mapping = dict(evidence)
            scope_id = evidence_id or _first(mapping, "evidence_id", "scope", "id", "name")
            path = _first(mapping, "path", "file", "filename", "source")
            records = _first(mapping, "records", "record_snapshots", "locations")
            if records is not None:
                return self.add_records(
                    str(scope_id or (path or "evidence-{}".format(uuid.uuid4().hex[:8]))),
                    records,
                    path=path,
                    sha256=_first(mapping, "sha256", "evidence_sha256", "file_sha256"),
                    md5=_first(mapping, "md5", "evidence_md5", "file_md5"),
                    aliases=_first(mapping, "aliases", default=[]),
                    metadata=_first(mapping, "metadata", "extra", default={}),
                )
            if path:
                return self._register_evidence(
                    self._scan_path(str(path), str(scope_id) if scope_id else None)
                )
            raise ValueError("evidence mapping requires a path or records")

        if isinstance(evidence, (str, bytes, os.PathLike)):
            return self._register_evidence(self._scan_path(os.fspath(evidence), evidence_id))

        if (
            isinstance(evidence, (tuple, list))
            and len(evidence) == 2
            and isinstance(evidence[1], (str, bytes, os.PathLike))
        ):
            return self._register_evidence(self._scan_path(os.fspath(evidence[1]), str(evidence[0])))

        # An already-open Evtx reader (or a FileHeader) is useful from code that
        # is already inside a read-only context manager.
        if hasattr(evidence, "chunks"):
            return self._register_evidence(self._scan_reader(evidence, evidence_id))

        raise TypeError("unsupported evidence value: {!r}".format(evidence))

    def add_evidences(self, evidence: Any) -> List[EvidenceScope]:
        if isinstance(evidence, Mapping) and not any(
            key in evidence for key in ("path", "records", "file", "filename", "evidence_id")
        ):
            scopes = []
            for scope_id, path in evidence.items():
                scopes.append(self.add_evidence(path, evidence_id=str(scope_id)))
            return scopes
        if (
            isinstance(evidence, tuple)
            and len(evidence) == 2
            and isinstance(evidence[1], (str, bytes, os.PathLike))
        ):
            return [self.add_evidence(evidence)]
        if isinstance(evidence, (list, tuple, set, frozenset)):
            return [self.add_evidence(item) for item in evidence]
        return [self.add_evidence(evidence)]

    def add_records(
        self,
        evidence_id: str,
        records: Iterable[Any],
        path: Optional[str] = None,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
        size: Optional[int] = None,
        aliases: Optional[Iterable[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> EvidenceScope:
        """Register synthetic or pre-scanned records for tests and adapters."""
        snapshots = []
        for item in records:
            if isinstance(item, RecordSnapshot):
                snapshot = item
                snapshot.evidence_id = str(evidence_id)
                if sha256 and snapshot.evidence_sha256 is None:
                    snapshot.evidence_sha256 = sha256
                if md5 and snapshot.evidence_md5 is None:
                    snapshot.evidence_md5 = md5
            elif isinstance(item, RecordLocation):
                snapshot = _snapshot_from_mapping(item.to_dict())
                snapshot.evidence_id = str(evidence_id)
                snapshot.evidence_sha256 = sha256
                snapshot.evidence_md5 = md5
            elif isinstance(item, Mapping):
                snapshot = _snapshot_from_mapping(item)
                snapshot.evidence_id = str(evidence_id)
                if snapshot.evidence_sha256 is None:
                    snapshot.evidence_sha256 = sha256
                if snapshot.evidence_md5 is None:
                    snapshot.evidence_md5 = md5
            else:
                number = _coerce_int(item)
                if number is None:
                    raise TypeError("cannot make a record from {!r}".format(item))
                snapshot = RecordSnapshot(
                    evidence_id=str(evidence_id),
                    record_num=number,
                    evidence_sha256=sha256,
                    evidence_md5=md5,
                )
            if snapshot._field_cache is None:
                if snapshot.evidence_sha256 is None:
                    snapshot.evidence_sha256 = sha256
                if snapshot.evidence_md5 is None:
                    snapshot.evidence_md5 = md5
            snapshots.append(snapshot)
        scope = EvidenceScope(
            evidence_id=str(evidence_id),
            path=str(path) if path else None,
            sha256=sha256,
            md5=md5,
            size=size,
            records=snapshots,
            aliases=list(_as_list(aliases or [])),
            metadata=dict(metadata or {}),
        )
        return self._register_evidence(scope)

    register_evidence = add_evidence
    add_evtx = add_evidence
    add_file = add_evidence
    add_log = add_evidence
    scan_evidence = add_evidence

    def _scan_path(
        self, path: str, evidence_id: Optional[str] = None, existing: Optional[EvidenceScope] = None
    ) -> EvidenceScope:
        path = os.fsdecode(os.fspath(path))
        scope_id = evidence_id or (existing.evidence_id if existing else path)
        with EvtxReader(path) as reader:
            scope = self._scan_reader(reader, scope_id, path=path)
        if existing is not None:
            scope.aliases = _unique(list(scope.aliases) + list(existing.aliases))
            scope.metadata.update(existing.metadata)
        return scope

    def _scan_reader(
        self, reader: Any, evidence_id: Optional[str] = None, path: Optional[str] = None
    ) -> EvidenceScope:
        if isinstance(reader, EvtxReader):
            if not reader._buf:
                raise TypeError("an Evtx reader must be used within its context")
            file_header = reader._fh
            if path is None:
                path = reader._filename
        elif hasattr(reader, "_fh") and reader._fh is not None:
            file_header = reader._fh
            if path is None:
                path = getattr(reader, "_filename", None)
        elif hasattr(reader, "chunks"):
            file_header = reader
        else:
            raise TypeError("unsupported EVTX reader: {!r}".format(reader))

        if path:
            path = os.fsdecode(os.fspath(path))
        scope_id = str(evidence_id or path or "evidence-{}".format(uuid.uuid4().hex[:8]))
        file_digest, file_md5, file_size = _hash_file(path) if path else (None, None, None)

        snapshots: List[RecordSnapshot] = []
        for chunk in file_header.chunks():
            snapshots.extend(self._scan_chunk(chunk, scope_id, file_digest, file_md5))

        return EvidenceScope(
            evidence_id=scope_id,
            path=path,
            sha256=file_digest,
            md5=file_md5,
            size=file_size,
            records=snapshots,
        )

    def _scan_chunk(
        self, chunk: Any, evidence_id: str, evidence_sha256: Optional[str], evidence_md5: Optional[str]
    ) -> List[RecordSnapshot]:
        snapshots: List[RecordSnapshot] = []
        chunk_offset = chunk.offset()
        buffer = chunk._buf
        try:
            next_record_offset = chunk.next_record_offset()
        except Exception:
            next_record_offset = 0

        parsed_numbers = set()
        if next_record_offset > 0x200:
            offset = chunk_offset + 0x200
            end_offset = min(chunk_offset + next_record_offset, len(buffer))
            while offset < end_offset:
                try:
                    record = Record(buffer, offset, chunk)
                    record_size = record.size()
                    if record_size <= 0:
                        raise InvalidRecordException()
                except Exception as exc:
                    snapshots.append(
                        self._synthetic_record(
                            evidence_id=evidence_id,
                            evidence_sha256=evidence_sha256,
                            evidence_md5=evidence_md5,
                            chunk_offset=chunk_offset,
                            file_offset=offset,
                            reason_code=REASON_INVALID_RECORD_STRUCTURE,
                            reason="invalid_record_structure: {}: {}".format(type(exc).__name__, exc),
                        )
                    )
                    break
                snapshot = self._snapshot_from_record(
                    record, evidence_id, evidence_sha256, evidence_md5, chunk_offset
                )
                snapshots.append(snapshot)
                if snapshot.record_num is not None:
                    parsed_numbers.add(snapshot.record_num)
                offset += record_size
        else:
            # Some malformed chunks do not advertise a next-record offset.
            # Fall back to the library iterator so we still see what it can parse.
            for record in chunk.records():
                snapshot = self._snapshot_from_record(
                    record, evidence_id, evidence_sha256, evidence_md5, chunk_offset
                )
                snapshots.append(snapshot)
                if snapshot.record_num is not None:
                    parsed_numbers.add(snapshot.record_num)

        # Keep a trace of record-number gaps that the chunk advertises but the
        # parser could not materialize.  This is deliberately bounded so a
        # corrupt header cannot create millions of synthetic rows.
        try:
            first = chunk.log_first_record_number()
            last = chunk.log_last_record_number()
        except Exception:
            first = last = None
        if first is not None and last is not None and first > 0 and 0 <= last - first <= 100000:
            missing = [number for number in range(first, last + 1) if number not in parsed_numbers]
            if len(missing) <= 4096:
                for number in missing:
                    snapshots.append(
                        self._synthetic_record(
                            evidence_id=evidence_id,
                            evidence_sha256=evidence_sha256,
                            evidence_md5=evidence_md5,
                            chunk_offset=chunk_offset,
                            file_offset=None,
                            record_num=number,
                            reason_code=REASON_MISSING_RECORD,
                            reason="missing_record: chunk advertises record {} but it was not parsed".format(number),
                        )
                    )
        return snapshots

    def _snapshot_from_record(
        self,
        record: Any,
        evidence_id: str,
        evidence_sha256: Optional[str],
        evidence_md5: Optional[str],
        chunk_offset: int,
    ) -> RecordSnapshot:
        reasons: List[Dict[str, Any]] = []
        try:
            record_num = record.record_num()
        except Exception:
            record_num = None
        try:
            size = record.size()
        except Exception:
            size = None
        try:
            file_offset = record.offset()
        except Exception:
            file_offset = None
        try:
            timestamp = _coerce_datetime(record.timestamp())
        except Exception:
            timestamp = None
        if timestamp is None or timestamp.year <= 1601:
            reasons.append(
                {
                    "reason_code": REASON_INVALID_TIMESTAMP,
                    "reason": "invalid_timestamp: record timestamp could not be decoded",
                }
            )
            # Do not let an undecodable FILETIME (0001-01-01) widen the
            # evidence's real time range or place the record in a window.
            timestamp = None

        try:
            magic = record.magic()
            if magic != 0x2A2A:
                reasons.append(
                    {
                        "reason_code": REASON_INVALID_RECORD_STRUCTURE,
                        "reason": "invalid_record_structure: unexpected record magic 0x{:x}".format(magic),
                    }
                )
        except Exception as exc:
            reasons.append(
                {
                    "reason_code": REASON_INVALID_RECORD_STRUCTURE,
                    "reason": "invalid_record_structure: {}: {}".format(type(exc).__name__, exc),
                }
            )

        try:
            if not record.verify():
                reasons.append(
                    {
                        "reason_code": REASON_INVALID_RECORD_STRUCTURE,
                        "reason": "invalid_record_structure: record size fields do not agree",
                    }
                )
        except Exception as exc:
            reasons.append(
                {
                    "reason_code": REASON_INVALID_RECORD_STRUCTURE,
                    "reason": "invalid_record_structure: {}: {}".format(type(exc).__name__, exc),
                }
            )

        record_sha256 = None
        record_md5 = None
        try:
            raw_record = bytes(record.data())
            record_sha256 = _sha256_bytes(raw_record)
            record_md5 = hashlib.md5(raw_record).hexdigest()
        except Exception:
            pass

        xml = None
        content_sha256 = None
        content_md5 = None
        xml_fields: Dict[str, Any] = {}
        if self.validate_content:
            try:
                xml = record.xml()
                if not str(xml).strip():
                    raise ValueError("empty record content")
                xml_bytes = str(xml).encode("utf-8")
                content_sha256 = _sha256_bytes(xml_bytes)
                content_md5 = hashlib.md5(xml_bytes).hexdigest()
                xml_fields = _extract_xml_fields(str(xml))
            except Exception as exc:
                reasons.append(
                    {
                        "reason_code": REASON_RECORD_CONTENT_ERROR,
                        "reason": "{}: {}: {}".format(REASON_RECORD_CONTENT_ERROR, type(exc).__name__, exc),
                        "exception": type(exc).__name__,
                        "message": str(exc),
                    }
                )
                xml = None

        relative_offset = None
        if file_offset is not None:
            relative_offset = file_offset - chunk_offset

        return RecordSnapshot(
            evidence_id=evidence_id,
            record_num=record_num,
            file_offset=file_offset,
            chunk_offset=chunk_offset,
            record_offset=relative_offset,
            timestamp=timestamp,
            record_sha256=record_sha256,
            content_sha256=content_sha256,
            record_md5=record_md5,
            content_md5=content_md5,
            size=size,
            evidence_sha256=evidence_sha256,
            evidence_md5=evidence_md5,
            valid=not reasons,
            base_reasons=reasons,
            xml_fields=xml_fields,
            xml=str(xml) if self.keep_xml and xml is not None else None,
            source_record=record if self.keep_xml else None,
        )

    def _synthetic_record(
        self,
        evidence_id: str,
        evidence_sha256: Optional[str],
        chunk_offset: Optional[int],
        file_offset: Optional[int],
        reason_code: str,
        reason: str,
        record_num: Optional[int] = None,
        evidence_md5: Optional[str] = None,
    ) -> RecordSnapshot:
        return RecordSnapshot(
            evidence_id=evidence_id,
            record_num=record_num,
            file_offset=file_offset,
            chunk_offset=chunk_offset,
            record_offset=(
                (file_offset - chunk_offset) if file_offset is not None and chunk_offset is not None else None
            ),
            evidence_sha256=evidence_sha256,
            evidence_md5=evidence_md5,
            valid=False,
            base_reasons=[{"reason_code": reason_code, "reason": reason}],
        )

    def _register_evidence(self, scope: EvidenceScope) -> EvidenceScope:
        scope.evidence_id = str(scope.evidence_id)
        for record in scope.records:
            record.evidence_id = scope.evidence_id
            record.timestamp = _coerce_datetime(record.timestamp)
            record._field_cache = None
            if record.evidence_sha256 is None:
                record.evidence_sha256 = scope.sha256
            if record.evidence_md5 is None:
                record.evidence_md5 = scope.md5
        # Keep the same physical order that ``Evtx.records()`` exposes.
        # Time coverage sorts a copy where chronology matters.
        scope.records.sort(
            key=lambda record: (
                record.file_offset if record.file_offset is not None else float("inf"),
                record.record_num if record.record_num is not None else float("inf"),
            )
        )
        self._evidences[scope.evidence_id] = scope
        for alias in scope.all_aliases:
            existing = self._aliases.get(alias)
            if existing and existing != scope.evidence_id:
                self._ambiguous_aliases.add(alias)
            else:
                self._aliases[alias] = scope.evidence_id
                self._aliases[os.path.normpath(alias) if os.path.sep in alias else alias] = scope.evidence_id
        self._retry_pending_receipts()
        self._invalidate()
        return scope

    # ------------------------------------------------------------------
    # Receipts
    # ------------------------------------------------------------------
    def add_receipt(self, receipt: Any, replace: bool = True) -> ReviewReceipt:
        parsed = ReviewReceipt.from_any(receipt)
        if parsed.segment_specs:
            self.add_segments(parsed.segment_specs)
        previous = self._receipts.get(parsed.receipt_id)
        if previous is not None:
            if not replace:
                suffix = 1
                while "{}-{}".format(parsed.receipt_id, suffix) in self._receipts:
                    suffix += 1
                parsed.receipt_id = "{}-{}".format(parsed.receipt_id, suffix)
            else:
                if self._evidences and self._merge_receipt_revision(previous, parsed):
                    pass
                else:
                    # Evidence may be attached later; defer the binding check
                    # until there is something real to validate against.
                    parsed._pending_previous = previous
                self._receipt_history.append({"replaced": previous.to_dict(), "replacement": parsed.receipt_id})
        self._receipts[parsed.receipt_id] = parsed
        self._invalidate()
        return parsed

    def add_receipts(self, receipts: Any) -> List[ReviewReceipt]:
        return [self.add_receipt(receipt) for receipt in load_receipts(receipts)]

    def upsert_receipt(self, receipt: Any) -> ReviewReceipt:
        return self.add_receipt(receipt, replace=True)

    @classmethod
    def from_evidence(cls, evidence: Any, receipts: Any = None, **kwargs: Any) -> "ReviewCoverageLedger":
        return cls(evidence=evidence, receipts=receipts, **kwargs)

    @classmethod
    def from_receipts(cls, receipts: Any, evidence: Any = None, **kwargs: Any) -> "ReviewCoverageLedger":
        return cls(evidence=evidence, receipts=receipts, **kwargs)

    def _retry_pending_receipts(self) -> None:
        if not self._evidences:
            return
        for receipt in self._receipts.values():
            previous = getattr(receipt, "_pending_previous", None)
            if previous is None:
                continue
            if self._merge_receipt_revision(previous, receipt):
                delattr(receipt, "_pending_previous")

    def _merge_receipt_revision(self, previous: ReviewReceipt, current: ReviewReceipt) -> bool:
        """Carry old metadata forward only when old bindings still validate."""
        ok, failures = self._validate_receipt_bindings(previous)
        if not ok:
            already_reported = any(
                diagnostic.get("source_receipt_id") == previous.receipt_id
                and diagnostic.get("reason_code") == REASON_STALE_RECEIPT_BINDING
                for diagnostic in current.diagnostics
            )
            if not already_reported:
                current.diagnostics.append(
                    {
                        "reason_code": REASON_STALE_RECEIPT_BINDING,
                        "reason": "legacy receipt fields were not reused",
                        "details": failures,
                        "source_receipt_id": previous.receipt_id,
                    }
                )
            return False

        inheritable = [
            "reviewer",
            "reviewed_at",
            "start_time",
            "end_time",
            "intervals",
            "record_numbers",
            "record_locations",
            "record_snapshots",
            "segment_ids",
            "segment_specs",
            "evidence_ids",
            "evidence_sha256",
            "evidence_md5",
            "status",
            "schema_version",
            "required_fields",
            "bound_fields",
        ]
        for name in inheritable:
            if _empty(getattr(current, name)) and not _empty(getattr(previous, name)):
                setattr(current, name, getattr(previous, name))
                current.inherited_from[name] = previous.receipt_id
        for key, value in previous.metadata.items():
            if key not in current.metadata:
                current.metadata[key] = value
                current.inherited_from["metadata." + key] = previous.receipt_id
        return True

    @staticmethod
    def _scope_hash_matches(scope: EvidenceScope, expected: Any) -> bool:
        value = str(expected).lower()
        return value in {str(scope.sha256 or "").lower(), str(scope.md5 or "").lower()}

    def _expected_evidence_hashes(self, receipt: ReviewReceipt, evidence_id: str) -> List[str]:
        expected: List[str] = []
        specific = False
        hashes = receipt.metadata.get("evidence_hashes")
        if isinstance(hashes, Mapping):
            scope = self._evidences.get(evidence_id)
            candidates = [evidence_id]
            if scope is not None and scope.path:
                candidates.extend([scope.path, os.path.abspath(scope.path), os.path.basename(scope.path)])
            for candidate in candidates:
                if candidate in hashes and hashes[candidate] is not None:
                    expected.append(str(hashes[candidate]))
                    specific = True
                    break
        if not specific:
            if receipt.evidence_sha256 is not None:
                expected.append(str(receipt.evidence_sha256))
            if receipt.evidence_md5 is not None:
                expected.append(str(receipt.evidence_md5))
        return _unique(expected)

    def _expected_evidence_hash(self, receipt: ReviewReceipt, evidence_id: str) -> Optional[str]:
        expected = self._expected_evidence_hashes(receipt, evidence_id)
        return expected[0] if expected else None

    def _validate_receipt_bindings(self, receipt: ReviewReceipt) -> Tuple[bool, List[Dict[str, Any]]]:
        failures: List[Dict[str, Any]] = []
        targets = self._resolve_evidence_ids(receipt)
        if receipt.evidence_ids and not targets:
            failures.append(
                {
                    "reason_code": REASON_EVIDENCE_CHANGED,
                    "reason": "receipt evidence scope is not present in this ledger",
                    "evidence_ids": receipt.evidence_ids,
                }
            )
        has_evidence_binding = (
            receipt.evidence_sha256 is not None
            or receipt.evidence_md5 is not None
            or isinstance(receipt.metadata.get("evidence_hashes"), Mapping)
        )
        if has_evidence_binding:
            if not targets:
                failures.append(
                    {
                        "reason_code": REASON_EVIDENCE_CHANGED,
                        "reason": "receipt binds an evidence hash but no evidence is available",
                    }
                )
            else:
                matched_any = False
                mismatched = {}
                for target in targets:
                    expected_values = self._expected_evidence_hashes(receipt, target)
                    if not expected_values or all(
                        self._scope_hash_matches(self._evidences[target], expected) for expected in expected_values
                    ):
                        matched_any = True
                    else:
                        mismatched[target] = {
                            "sha256": self._evidences[target].sha256,
                            "md5": self._evidences[target].md5,
                        }
                if not matched_any:
                    failures.append(
                        {
                            "reason_code": REASON_EVIDENCE_CHANGED,
                            "reason": "evidence hash does not match receipt binding",
                            "expected": receipt.evidence_sha256,
                            "actual": mismatched,
                        }
                    )
        if not receipt.has_selectors:
            if not receipt.bound_fields and not receipt.required_fields:
                return not failures, failures
            if not targets:
                targets = list(self._evidences)
            found = False
            for target in targets:
                for snapshot in self._evidences[target].records:
                    found = True
                    failures.extend(self._binding_failures(snapshot, receipt.bound_fields, receipt.required_fields))
            if not found:
                failures.append(
                    {
                        "reason_code": REASON_STALE_RECEIPT_BINDING,
                        "reason": "receipt no longer resolves to a current record",
                    }
                )
            return not failures, failures

        if not targets:
            targets = list(self._evidences)
        validations: List[Tuple[RecordSnapshot, Dict[str, Any]]] = []
        for claim in list(receipt.record_snapshots) + list(receipt.record_locations):
            claim_mapping = claim.to_dict() if hasattr(claim, "to_dict") else dict(claim)
            binding = dict(receipt.bound_fields)
            binding.update(self._binding_from_claim(claim_mapping))
            for snapshot in self._resolve_claim(claim, targets)[0]:
                validations.append((snapshot, binding))
        for number in receipt.record_numbers:
            for target in targets:
                for snapshot in self._records_by_number(target, number):
                    validations.append((snapshot, dict(receipt.bound_fields)))
        for interval in receipt.intervals:
            start, end = interval
            for snapshot in self._records_in_interval(targets, start, end):
                validations.append((snapshot, dict(receipt.bound_fields)))
        has_explicit_record_selectors = bool(
            receipt.record_numbers
            or receipt.record_locations
            or receipt.record_snapshots
            or receipt.intervals
        )
        if not has_explicit_record_selectors:
            for segment_id in receipt.segment_ids:
                for snapshot in self._segment_records(segment_id, targets):
                    validations.append((snapshot, dict(receipt.bound_fields)))
        if not validations:
            failures.append(
                {
                    "reason_code": REASON_STALE_RECEIPT_BINDING,
                    "reason": "receipt no longer resolves to a current record",
                }
            )
            return False, failures
        for snapshot, binding in validations:
            problems = self._binding_failures(snapshot, binding, receipt.required_fields)
            if problems:
                failures.extend(problems)
        return not failures, failures

    # ------------------------------------------------------------------
    # Reconciliation
    # ------------------------------------------------------------------
    def _invalidate(self) -> None:
        self._summary_cache = None
        self._segment_cache = None
        self._receipt_results = {}

    def _ensure_rebuilt(self) -> None:
        if self._summary_cache is not None:
            return
        for scope in self._evidences.values():
            for record in scope.records:
                record.review_ids = []
                record.claim_reasons = []
                record.bound_fields = {}
                record.receipt_fields = {}
        self._receipt_results = {}

        ordered_receipts = sorted(
            self._receipts.values(),
            key=lambda receipt: (
                _ts(receipt.reviewed_at) if receipt.reviewed_at is not None else float("inf"),
                receipt.receipt_id,
            ),
        )
        for receipt in ordered_receipts:
            self._receipt_results[receipt.receipt_id] = self._apply_receipt(receipt)

        self._summary_cache = CoverageReport(self._build_summary(), self)

    def _apply_receipt(self, receipt: ReviewReceipt) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "receipt_id": receipt.receipt_id,
            "status": "empty",
            "evidence_ids": [],
            "matched_records": [],
            "reviewed_records": [],
            "rejected_records": [],
            "unmatched_claims": [],
            "diagnostics": [],
        }
        targets = self._resolve_evidence_ids(receipt)
        if not targets and receipt.evidence_ids:
            result["status"] = "unresolved"
            result["diagnostics"].append(
                {
                    "reason_code": REASON_EVIDENCE_CHANGED,
                    "reason": "receipt evidence scope is not present in this ledger",
                    "evidence_ids": receipt.evidence_ids,
                }
            )
            return result
        if not targets and self._evidences:
            targets = list(self._evidences)
        result["evidence_ids"] = list(targets)

        rejected_evidence = []
        has_evidence_binding = (
            receipt.evidence_sha256 is not None
            or receipt.evidence_md5 is not None
            or isinstance(receipt.metadata.get("evidence_hashes"), Mapping)
        )
        if has_evidence_binding:
            filtered = []
            for target in targets:
                scope = self._evidences[target]
                expected_values = self._expected_evidence_hashes(receipt, target)
                if not expected_values or all(
                    self._scope_hash_matches(scope, expected) for expected in expected_values
                ):
                    filtered.append(target)
                else:
                    rejected_evidence.append(
                        {
                            "evidence_id": target,
                            "reason_code": REASON_EVIDENCE_CHANGED,
                            "reason": "evidence hash does not match receipt binding",
                            "expected": expected_values,
                            "actual": {"sha256": scope.sha256, "md5": scope.md5},
                        }
                    )
            targets = filtered
            result["diagnostics"].extend(rejected_evidence)
            for rejection in rejected_evidence:
                rejected_scope = self._evidences.get(rejection["evidence_id"])
                if rejected_scope is None:
                    continue
                for record in rejected_scope.records:
                    record.claim_reasons.append(
                        {
                            "reason_code": REASON_EVIDENCE_CHANGED,
                            "reason": "evidence_changed: evidence hash does not match receipt binding",
                            "expected": rejection.get("expected"),
                            "actual": rejection.get("actual"),
                            "receipt_id": receipt.receipt_id,
                        }
                    )
                    result["rejected_records"].append(record.to_dict(include_bound_fields=False))
            if not targets:
                result["status"] = "rejected"
                return result

        claims: "OrderedDict[Tuple[Any, ...], List[Tuple[RecordSnapshot, Dict[str, Any]]]]" = OrderedDict()

        def add_claim(snapshot: RecordSnapshot, claim: Mapping[str, Any]) -> None:
            claims.setdefault(snapshot.key, []).append((snapshot, dict(claim)))

        for claim in list(receipt.record_snapshots) + list(receipt.record_locations):
            resolved, failures = self._resolve_claim(claim, targets)
            claim_mapping = claim.to_dict() if hasattr(claim, "to_dict") else dict(claim)
            if not resolved:
                result["unmatched_claims"].append(
                    {"claim": _json_value(claim_mapping), "reason": "record not found", "details": failures}
                )
                continue
            for snapshot in resolved:
                add_claim(snapshot, claim_mapping)

        for number in receipt.record_numbers:
            found = []
            for target in targets:
                found.extend(self._records_by_number(target, number))
            if not found:
                result["unmatched_claims"].append({"record_num": number, "reason": "record not found"})
            for snapshot in found:
                add_claim(snapshot, {"record_num": number})

        has_explicit_record_selectors = bool(
            receipt.record_numbers
            or receipt.record_locations
            or receipt.record_snapshots
            or receipt.intervals
        )
        if not has_explicit_record_selectors:
            for segment_id in receipt.segment_ids:
                segment_records = self._segment_records(segment_id, targets)
                if not segment_records:
                    result["unmatched_claims"].append({"segment_id": segment_id, "reason": "segment not found"})
                for snapshot in segment_records:
                    add_claim(snapshot, {"segment_id": segment_id})

        intervals = list(receipt.intervals)
        for start, end in intervals:
            selected = self._records_in_interval(targets, start, end)
            if not selected:
                result["unmatched_claims"].append(
                    {
                        "interval": (_iso(start), _iso(end)),
                        "reason": "no records in interval",
                    }
                )
            for snapshot in selected:
                add_claim(snapshot, {"start_time": _iso(start), "end_time": _iso(end)})

        if not receipt.has_selectors:
            if not receipt.evidence_ids and not receipt.bound_fields and not receipt.required_fields:
                result["status"] = "empty"
                return result
            for target in targets:
                for snapshot in self._evidences[target].records:
                    add_claim(snapshot, {})

        if not claims:
            result["status"] = "empty"
            return result

        result["status"] = "accepted"
        for key, entries in claims.items():
            snapshot = entries[0][0]
            result["matched_records"].append(snapshot.to_dict(include_bound_fields=False))
            accepted = False
            for claimed_snapshot, claim in entries:
                snapshot = claimed_snapshot
                if self._claim_rejected(claim):
                    reason = self._claim_rejection_reason(claim)
                    self._reject_claim(result, snapshot, reason, receipt)
                    continue
                binding = dict(receipt.bound_fields)
                binding.update(self._binding_from_claim(claim))
                problems = self._binding_failures(snapshot, binding, receipt.required_fields)
                if problems:
                    for problem in problems:
                        self._reject_claim(result, snapshot, problem, receipt)
                    continue
                if not snapshot.valid:
                    for base_reason in snapshot.base_reasons:
                        self._reject_claim(result, snapshot, dict(base_reason), receipt)
                    if not snapshot.base_reasons:
                        self._reject_claim(
                            result,
                            snapshot,
                            {
                                "reason_code": REASON_RECORD_CONTENT_ERROR,
                                "reason": "record content is abnormal",
                            },
                            receipt,
                        )
                    continue

                if receipt.receipt_id not in snapshot.review_ids:
                    snapshot.review_ids.append(receipt.receipt_id)
                receipt_fields = self._record_fields_from_receipt(receipt)
                receipt_fields.update(self._record_fields_from_claim(claim))
                snapshot.receipt_fields[receipt.receipt_id] = receipt_fields
                snapshot.bound_fields.update(receipt_fields)
                accepted = True
            if accepted:
                result["reviewed_records"].append(snapshot.to_dict(include_bound_fields=False))
            else:
                result["rejected_records"].append(snapshot.to_dict(include_bound_fields=False))

        if result["rejected_records"] and result["reviewed_records"]:
            result["status"] = "partial"
        elif result["rejected_records"]:
            result["status"] = "rejected"
        else:
            result["status"] = "accepted"
        return result

    def _reject_claim(
        self,
        result: Dict[str, Any],
        snapshot: RecordSnapshot,
        problem: Mapping[str, Any],
        receipt: ReviewReceipt,
    ) -> None:
        reason = dict(problem)
        reason.setdefault("reason_code", REASON_RECEIPT_REJECTED)
        reason.setdefault("reason", str(reason["reason_code"]))
        reason["receipt_id"] = receipt.receipt_id
        snapshot.claim_reasons.append(reason)
        result["diagnostics"].append({"record": snapshot.to_dict(include_bound_fields=False), **reason})

    @staticmethod
    def _claim_rejected(claim: Mapping[str, Any]) -> bool:
        if "reviewed" in claim and not bool(claim["reviewed"]):
            return True
        status = str(_first(claim, "status", "result", "outcome", default="")).lower()
        return status in {"skipped", "rejected", "unreviewed", "failed", "exception", "not_reviewed"}

    @staticmethod
    def _claim_rejection_reason(claim: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "reason_code": REASON_RECEIPT_REJECTED,
            "reason": str(
                _first(
                    claim,
                    "unreviewed_reason",
                    "reason",
                    "error",
                    "message",
                    default=REASON_RECEIPT_REJECTED,
                )
            ),
        }

    def _resolve_evidence_ids(self, receipt: ReviewReceipt) -> List[str]:
        result: List[str] = []
        for token in receipt.evidence_ids:
            resolved = self._resolve_evidence(token)
            if resolved and resolved not in result:
                result.append(resolved)
        if not result and receipt.record_locations:
            for location in receipt.record_locations:
                resolved = self._resolve_evidence(location.evidence_id)
                if resolved and resolved not in result:
                    result.append(resolved)
        if not result and receipt.record_snapshots:
            for snapshot in receipt.record_snapshots:
                resolved = self._resolve_evidence(snapshot.evidence_id)
                if resolved and resolved not in result:
                    result.append(resolved)
        return result

    def _resolve_evidence(self, token: Any) -> Optional[str]:
        if token is None:
            return None
        text = str(token)
        if text in self._aliases and text not in self._ambiguous_aliases:
            return self._aliases[text]
        if text in self._evidences:
            return text
        normalized = os.path.normpath(text)
        if normalized in self._aliases and normalized not in self._ambiguous_aliases:
            return self._aliases[normalized]
        absolute = os.path.abspath(text)
        if absolute in self._aliases and absolute not in self._ambiguous_aliases:
            return self._aliases[absolute]
        basename = os.path.basename(normalized)
        if basename in self._aliases and basename not in self._ambiguous_aliases:
            return self._aliases[basename]
        # Allow evidence hashes as scope names.
        matches = [
            evidence_id
            for evidence_id, scope in self._evidences.items()
            if scope.sha256 and scope.sha256.lower() == text.lower()
        ]
        if len(matches) == 1:
            return matches[0]
        return None

    def _resolve_claim(
        self, claim: Any, targets: Sequence[str]
    ) -> Tuple[List[RecordSnapshot], List[Dict[str, Any]]]:
        failures: List[Dict[str, Any]] = []
        location = RecordLocation.from_any(claim)
        candidates = list(targets)
        if location.evidence_id:
            resolved = self._resolve_evidence(location.evidence_id)
            if resolved is None:
                failures.append(
                    {
                        "reason_code": REASON_EVIDENCE_CHANGED,
                        "reason": "claim evidence scope is not present",
                        "evidence_id": location.evidence_id,
                    }
                )
                return [], failures
            candidates = [resolved]
        found: List[RecordSnapshot] = []
        if location.file_offset is not None:
            for evidence_id in candidates:
                snapshot = self._records_by_offset(evidence_id, location.file_offset)
                if snapshot is not None:
                    found.append(snapshot)
        elif location.record_num is not None:
            for evidence_id in candidates:
                found.extend(self._records_by_number(evidence_id, location.record_num))
        elif location.timestamp is not None:
            start = location.timestamp - _datetime.timedelta(microseconds=1)
            end = location.timestamp + _datetime.timedelta(microseconds=1)
            found.extend(self._records_in_interval(candidates, start, end))
        if not found:
            failures.append(
                {
                    "reason_code": REASON_STALE_RECEIPT_BINDING,
                    "reason": "claim does not resolve to a current record",
                }
            )
        return found, failures

    def _records_by_offset(self, evidence_id: str, offset: int) -> Optional[RecordSnapshot]:
        scope = self._evidences.get(evidence_id)
        if scope is None:
            return None
        for record in scope.records:
            if record.file_offset == offset:
                return record
        return None

    def _records_by_number(self, evidence_id: str, number: int) -> List[RecordSnapshot]:
        scope = self._evidences.get(evidence_id)
        if scope is None:
            return []
        return [record for record in scope.records if record.record_num == number]

    def _records_in_interval(
        self,
        targets: Sequence[str],
        start: Optional[_datetime.datetime],
        end: Optional[_datetime.datetime],
    ) -> List[RecordSnapshot]:
        found = []
        for evidence_id in targets:
            scope = self._evidences.get(evidence_id)
            if scope is None:
                continue
            for record in scope.records:
                if record.timestamp is None:
                    continue
                if start is not None and record.timestamp < start:
                    continue
                if end is not None and record.timestamp > end:
                    continue
                found.append(record)
        return found

    @staticmethod
    def _binding_from_claim(claim: Mapping[str, Any]) -> Dict[str, Any]:
        mapping = dict(claim)
        result: Dict[str, Any] = {}
        aliases = {
            "record_num": ("record_num", "record_number", "record_no", "number"),
            "file_offset": ("file_offset", "absolute_offset", "offset"),
            "chunk_offset": ("chunk_offset",),
            "record_offset": ("record_offset", "chunk_relative_offset"),
            "timestamp": ("timestamp", "time", "system_time", "when"),
            "record_sha256": ("record_sha256", "sha256", "digest", "record_digest", "hash", "record_hash"),
            "content_sha256": ("content_sha256", "xml_sha256", "content_digest", "content_hash", "xml_hash"),
            "record_md5": ("record_md5", "md5", "record_digest_md5"),
            "content_md5": ("content_md5", "xml_md5", "content_digest_md5"),
            "size": ("size", "length", "record_size"),
            "evidence_sha256": ("evidence_sha256", "file_sha256"),
            "evidence_md5": ("evidence_md5", "file_md5"),
        }
        for canonical, names in aliases.items():
            present, value = _mapping_get_any(mapping, *names)
            if present and value is not None:
                result[canonical] = value
        return result

    def _binding_failures(
        self,
        snapshot: RecordSnapshot,
        binding: Mapping[str, Any],
        required_fields: Optional[Mapping[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        problems: List[Dict[str, Any]] = []
        for name, expected in binding.items():
            if expected is None:
                continue
            canonical = self._canonical_field_name(name)
            actual = snapshot.fields.get(canonical)
            if actual is None:
                problems.append(
                    {
                        "reason_code": REASON_STALE_RECEIPT_BINDING,
                        "reason": "receipt-bound field {!r} is missing from the current record".format(name),
                        "field": name,
                        "expected": _json_value(expected),
                    }
                )
                continue
            if canonical in {"timestamp", "time", "system_time"} or isinstance(
                expected, (_datetime.datetime, _datetime.date)
            ):
                matches = _same_time(expected, actual)
            elif canonical in {"record_sha256", "sha256", "digest", "record_digest"}:
                matches = any(
                    _same_value(expected, candidate)
                    for candidate in (
                        snapshot.record_sha256,
                        snapshot.content_sha256,
                        snapshot.record_md5,
                        snapshot.content_md5,
                    )
                    if candidate
                )
            elif canonical in {"content_sha256", "xml_sha256", "content_digest", "content_hash", "xml_hash"}:
                matches = any(
                    _same_value(expected, candidate)
                    for candidate in (snapshot.content_sha256, snapshot.content_md5)
                    if candidate
                )
            elif canonical in {"record_md5", "md5", "record_digest_md5"}:
                matches = any(
                    _same_value(expected, candidate)
                    for candidate in (snapshot.record_md5, snapshot.content_md5)
                    if candidate
                )
            elif canonical in {"content_md5", "xml_md5", "content_digest_md5"}:
                matches = snapshot.content_md5 is not None and _same_value(expected, snapshot.content_md5)
            else:
                matches = _same_value(expected, actual)
            if not matches:
                problems.append(
                    {
                        "reason_code": REASON_STALE_RECEIPT_BINDING,
                        "reason": "receipt-bound field {!r} no longer matches the current record".format(name),
                        "field": name,
                        "expected": _json_value(expected),
                        "actual": _json_value(actual),
                    }
                )

        for name, expected in (required_fields or {}).items():
            canonical = self._canonical_field_name(name)
            actual = snapshot.fields.get(canonical)
            if actual is None:
                problems.append(
                    {
                        "reason_code": REASON_STALE_RECEIPT_BINDING,
                        "reason": "required receipt field {!r} is missing from the current record".format(name),
                        "field": name,
                    }
                )
                continue
            if expected is not None and not _same_value(expected, actual):
                problems.append(
                    {
                        "reason_code": REASON_STALE_RECEIPT_BINDING,
                        "reason": "required receipt field {!r} no longer matches the current record".format(name),
                        "field": name,
                        "expected": _json_value(expected),
                        "actual": _json_value(actual),
                    }
                )
        return problems

    @staticmethod
    def _canonical_field_name(name: str) -> str:
        return {
            "record_number": "record_num",
            "record_no": "record_num",
            "number": "record_num",
            "offset": "file_offset",
            "absolute_offset": "file_offset",
            "chunk_relative_offset": "record_offset",
            "relative_offset": "record_offset",
            "time": "timestamp",
            "system_time": "timestamp",
            "when": "timestamp",
            "digest": "record_sha256",
            "hash": "record_sha256",
            "record_hash": "record_sha256",
            "record_digest": "record_sha256",
            "xml_sha256": "content_sha256",
            "content_digest": "content_sha256",
            "content_hash": "content_sha256",
            "xml_hash": "content_sha256",
            "md5": "record_md5",
            "record_digest_md5": "record_md5",
            "xml_md5": "content_md5",
            "content_digest_md5": "content_md5",
            "length": "size",
            "record_size": "size",
            "file_sha256": "evidence_sha256",
            "file_md5": "evidence_md5",
        }.get(str(name), str(name))

    @staticmethod
    def _record_fields_from_receipt(receipt: ReviewReceipt) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        for key in ("fields", "record_fields", "values"):
            value = receipt.metadata.get(key)
            if isinstance(value, Mapping):
                fields.update(value)
        if receipt.reviewer is not None:
            fields["reviewer"] = receipt.reviewer
        if receipt.reviewed_at is not None:
            fields["reviewed_at"] = _iso(receipt.reviewed_at)
        if receipt.status is not None:
            fields["receipt_status"] = receipt.status
        for key in ("notes", "note", "comment", "remarks", "label", "description"):
            if key in receipt.metadata:
                fields[key] = receipt.metadata[key]
        fields["last_receipt_id"] = receipt.receipt_id
        return fields

    @staticmethod
    def _record_fields_from_claim(claim: Mapping[str, Any]) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        for key in ("fields", "record_fields", "values"):
            value = claim.get(key)
            if isinstance(value, Mapping):
                fields.update(value)
        for key in ("reviewer", "reviewed_at", "notes", "note", "comment", "remarks"):
            if key in claim:
                fields[key] = claim[key]
        return fields

    # ------------------------------------------------------------------
    # Segments
    # ------------------------------------------------------------------
    def add_segments(self, segments: Sequence[Any]) -> None:
        if isinstance(segments, Mapping):
            segments = [segments]
        elif isinstance(segments, (str, bytes)) or not isinstance(segments, Iterable):
            segments = [segments]
        for item in segments:
            if isinstance(item, Mapping):
                spec = dict(item)
            elif isinstance(item, (list, tuple)) and len(item) >= 3:
                spec = {"segment_id": item[0], "start_time": item[1], "end_time": item[2]}
            else:
                spec = {"segment_id": str(item)}
            if "segment_id" not in spec:
                spec["segment_id"] = _first(spec, "id", "name")
            if spec.get("segment_id") is None:
                spec["segment_id"] = "segment-{}".format(uuid.uuid4().hex[:8])
            spec["segment_id"] = str(spec["segment_id"])
            self._segments_config = [old for old in self._segments_config if old["segment_id"] != spec["segment_id"]]
            self._segments_config.append(spec)
        self._invalidate()

    def _build_segments(self) -> SegmentCollection:
        segments: List[CoverageSegment] = []
        configured_ids = set()
        configured_evidence_ids = set()
        for spec in self._segments_config:
            segment_id = str(spec["segment_id"])
            configured_ids.add(segment_id)
            evidence_id = _first(spec, "evidence_id", "scope", "evidence")
            targets = [self._resolve_evidence(evidence_id)] if evidence_id else list(self._evidences)
            targets = [target for target in targets if target]
            configured_evidence_ids.update(targets)
            start = _coerce_datetime(_first(spec, "start_time", "start", "from"))
            end = _coerce_datetime(_first(spec, "end_time", "end", "to"))
            records: List[RecordSnapshot] = []
            if _first(spec, "record_numbers", "records", "record_nums") is not None:
                for item in _as_list(_first(spec, "record_numbers", "records", "record_nums")):
                    if isinstance(item, (int, str)):
                        number = _coerce_int(item)
                        if number is not None:
                            for target in targets:
                                records.extend(self._records_by_number(target, number))
                    else:
                        location = RecordLocation.from_any(item)
                        records.extend(self._resolve_claim(location, targets)[0])
            else:
                records.extend(self._records_in_interval(targets, start, end))
            segments.append(
                CoverageSegment(
                    segment_id=segment_id,
                    evidence_id=targets[0] if len(targets) == 1 else None,
                    start_time=start,
                    end_time=end,
                    records=records,
                    metadata={key: value for key, value in spec.items() if key not in {"segment_id"}},
                )
            )

        if self.segment_seconds:
            for scope in self._evidences.values():
                if scope.evidence_id in configured_evidence_ids:
                    continue
                for record in scope.records:
                    if record.timestamp is None:
                        continue
                    bucket = int(record.timestamp.timestamp() // self.segment_seconds)
                    segment_id = "{}:{}".format(scope.evidence_id, bucket)
                    existing = next((segment for segment in segments if segment.segment_id == segment_id), None)
                    if existing is None:
                        start = _datetime.datetime.fromtimestamp(bucket * self.segment_seconds, UTC)
                        end = _datetime.datetime.fromtimestamp((bucket + 1) * self.segment_seconds, UTC)
                        existing = CoverageSegment(
                            segment_id=segment_id,
                            evidence_id=scope.evidence_id,
                            start_time=start,
                            end_time=end,
                        )
                        segments.append(existing)
                    existing.records.append(record)

        for scope in self._evidences.values():
            if scope.evidence_id in configured_evidence_ids:
                continue
            if self.segment_seconds:
                continue
            segments.append(
                CoverageSegment(
                    segment_id=scope.evidence_id,
                    evidence_id=scope.evidence_id,
                    start_time=scope.start_time,
                    end_time=scope.end_time,
                    records=list(scope.records),
                )
            )
        segments.sort(
            key=lambda segment: (
                segment.evidence_id or "",
                segment.start_time or _datetime.datetime.min.replace(tzinfo=UTC),
            )
        )
        return SegmentCollection(segments)

    def _segment_records(self, segment_id: str, targets: Sequence[str]) -> List[RecordSnapshot]:
        if self._segment_cache is None:
            self._segment_cache = self._build_segments()
        segment = self._segment_cache.get(segment_id)
        if segment is None:
            return []
        if segment.evidence_id and segment.evidence_id not in targets:
            return []
        return list(segment.records)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def _build_summary(self) -> Dict[str, Any]:
        evidence_summaries = []
        all_records: List[RecordSnapshot] = []
        unreviewed_items: List[UnreviewedRecord] = []
        reason_counts: Dict[str, int] = {}
        covered_ranges_all: List[Tuple[_datetime.datetime, _datetime.datetime]] = []
        naive_covered_seconds = 0.0
        overlapping_pairs = []

        scopes = list(self._evidences.values())
        for index, scope in enumerate(scopes):
            for other in scopes[index + 1 :]:
                if (
                    scope.start_time is None
                    or scope.end_time is None
                    or other.start_time is None
                    or other.end_time is None
                ):
                    continue
                if scope.start_time <= other.end_time and other.start_time <= scope.end_time:
                    overlapping_pairs.append(
                        {
                            "left": scope.evidence_id,
                            "right": other.evidence_id,
                            "left_start": _iso(scope.start_time),
                            "left_end": _iso(scope.end_time),
                            "right_start": _iso(other.start_time),
                            "right_end": _iso(other.end_time),
                        }
                    )

        for scope in scopes:
            records = list(scope.records)
            reviewed = [record for record in records if record.reviewed]
            scope_unreviewed = []
            scope_reason_counts: Dict[str, int] = {}
            for record in records:
                item = _unreviewed_item(record)
                if item is not None:
                    scope_unreviewed.append(item.to_dict())
                    unreviewed_items.append(item)
                    for code in item.reason_code.split("+"):
                        reason_counts[code] = reason_counts.get(code, 0) + 1
                        scope_reason_counts[code] = scope_reason_counts.get(code, 0) + 1
            all_records.extend(records)

            status = self._status_for_records(records)
            covered_ranges = self._continuous_reviewed_ranges(records)
            covered_seconds = _range_seconds(covered_ranges)
            covered_ranges_all.extend(covered_ranges)
            naive_covered_seconds += covered_seconds
            evidence_summaries.append(
                {
                    "evidence_id": scope.evidence_id,
                    "scope": scope.evidence_id,
                    "path": scope.path,
                    "sha256": scope.sha256,
                    "size": scope.size,
                    "record_count": CountRows(len(records), [record.to_dict() for record in records]),
                    "total_records": CountRows(len(records), [record.to_dict() for record in records]),
                    "reviewed_record_count": CountRows(
                        len(reviewed), [record.to_dict() for record in reviewed]
                    ),
                    "reviewed_records": CountRows(len(reviewed), [record.to_dict() for record in reviewed]),
                    "reviewed_count": CountRows(len(reviewed), [record.to_dict() for record in reviewed]),
                    "unreviewed_record_count": CountRows(len(records) - len(reviewed), scope_unreviewed),
                    "unreviewed_count": CountRows(len(records) - len(reviewed), scope_unreviewed),
                    "invalid_record_count": len([record for record in records if not record.valid]),
                    "coverage_ratio": (float(len(reviewed)) / len(records)) if records else 0.0,
                    "coverage": (float(len(reviewed)) / len(records)) if records else 0.0,
                    "start_time": _iso(scope.start_time),
                    "end_time": _iso(scope.end_time),
                    "time_range": [_iso(scope.start_time), _iso(scope.end_time)],
                    "covered_seconds": covered_seconds,
                    "covered_time_ranges": [(_iso(start), _iso(end)) for start, end in covered_ranges],
                    "covered_ranges": [
                        {
                            "start": _iso(start),
                            "end": _iso(end),
                            "seconds": (end - start).total_seconds(),
                        }
                        for start, end in covered_ranges
                    ],
                    "status": status,
                    "status_aliases": (
                        ["handover_ready", "complete", "ready"]
                        if status == STATUS_HANDOVER_READY
                        else ([STATUS_PARTIAL] if status == STATUS_PARTIAL else [status])
                    ),
                    "handover_ready": status == STATUS_HANDOVER_READY,
                    "ready": status == STATUS_HANDOVER_READY,
                    "complete": status == STATUS_HANDOVER_READY,
                    "partial": status == STATUS_PARTIAL,
                    "receipt_ids": _unique(receipt_id for record in records for receipt_id in record.review_ids),
                    "unreviewed": scope_unreviewed,
                    "unreviewed_reasons": ReasonCollection(scope_unreviewed, scope_reason_counts),
                    "unreviewed_reason_counts": dict(scope_reason_counts),
                    "reviewed": [record.to_dict() for record in reviewed],
                    "reviewed_record_rows": [record.to_dict() for record in reviewed],
                    "records": [record.to_dict() for record in records],
                    "metadata": _json_value(scope.metadata),
                }
            )

        segments = self._build_segments()
        segment_dicts = [segment.to_dict(include_records=False) for segment in segments]
        for segment in segments:
            if segment.status == STATUS_HANDOVER_READY:
                continue
            for item in segment.unreviewed():
                if item.snapshot.key not in {other.snapshot.key for other in unreviewed_items}:
                    unreviewed_items.append(item)
                    for code in item.reason_code.split("+"):
                        reason_counts[code] = reason_counts.get(code, 0) + 1

        union_ranges = _merge_ranges(covered_ranges_all)
        union_seconds = _range_seconds(union_ranges)
        reviewed_instances = sum(1 for record in all_records if record.reviewed)
        total_instances = len(all_records)
        reviewed_fingerprints = {record.fingerprint for record in all_records if record.reviewed}
        total_fingerprints = {record.fingerprint for record in all_records}
        unreviewed_fingerprints = {record.fingerprint for record in all_records if not record.reviewed}
        seen_fingerprints = set()
        total_rows = []
        for record in all_records:
            if record.fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(record.fingerprint)
            total_rows.append(record.to_dict())
        reviewed_rows = [row for row in total_rows if row.get("reviewed")]
        seen_unreviewed = set()
        unreviewed_rows = []
        for item in unreviewed_items:
            fingerprint = item.snapshot.fingerprint
            if fingerprint in seen_unreviewed:
                continue
            seen_unreviewed.add(fingerprint)
            unreviewed_rows.append(item.to_dict())

        global_status = self._status_for_records(all_records)
        receipt_results = []
        for receipt in self._receipts.values():
            receipt_results.append(self._receipt_result(receipt))

        summary: Dict[str, Any] = {
            "evidence": EvidenceCollection(evidence_summaries),
            "by_evidence": {item["evidence_id"]: item for item in evidence_summaries},
            "segments": segment_dicts,
            "receipts": receipt_results,
            "receipt_count": len(receipt_results),
            "receipt_ids": [receipt.receipt_id for receipt in self._receipts.values()],
            "record_count": CountRows(total_instances, total_rows),
            "total_records": CountRows(len(total_fingerprints), total_rows),
            "total_record_instances": total_instances,
            "reviewed_record_count": CountRows(len(reviewed_fingerprints), reviewed_rows),
            "reviewed_records": CountRows(len(reviewed_fingerprints), reviewed_rows),
            "reviewed_count": CountRows(len(reviewed_fingerprints), reviewed_rows),
            "reviewed_record_rows": reviewed_rows,
            "reviewed_rows": reviewed_rows,
            "reviewed_record_instances": reviewed_instances,
            "reviewed_unique_records": len(reviewed_fingerprints),
            "unreviewed_record_count": CountRows(len(unreviewed_fingerprints), unreviewed_rows),
            "unreviewed_records": CountRows(len(unreviewed_fingerprints), unreviewed_rows),
            "unreviewed_count": CountRows(len(unreviewed_fingerprints), unreviewed_rows),
            "unreviewed_record_rows": unreviewed_rows,
            "unreviewed_rows": unreviewed_rows,
            "unreviewed_record_instances": total_instances - reviewed_instances,
            "invalid_record_count": len([record for record in all_records if not record.valid]),
            "coverage_ratio": (
                (float(len(reviewed_fingerprints)) / len(total_fingerprints)) if total_fingerprints else 0.0
            ),
            "coverage": (float(len(reviewed_fingerprints)) / len(total_fingerprints)) if total_fingerprints else 0.0,
            "covered_seconds": union_seconds,
            "covered_duration": union_seconds,
            "covered_time_ranges": [(_iso(start), _iso(end)) for start, end in union_ranges],
            "covered_intervals": [(_iso(start), _iso(end)) for start, end in union_ranges],
            "sum_evidence_covered_seconds": naive_covered_seconds,
            "overlap_saved_seconds": max(0.0, naive_covered_seconds - union_seconds),
            "overlap_seconds": max(0.0, naive_covered_seconds - union_seconds),
            "naive_covered_seconds": naive_covered_seconds,
            "union_covered_seconds": union_seconds,
            "overlapping_evidence": overlapping_pairs,
            "status": global_status,
            "status_aliases": (
                ["handover_ready", "complete", "ready"]
                if global_status == STATUS_HANDOVER_READY
                else ([STATUS_PARTIAL] if global_status == STATUS_PARTIAL else [global_status])
            ),
            "handover_ready": global_status == STATUS_HANDOVER_READY,
            "ready": global_status == STATUS_HANDOVER_READY,
            "complete": global_status == STATUS_HANDOVER_READY,
            "partial": global_status == STATUS_PARTIAL,
            "unreviewed": [item.to_dict() for item in unreviewed_items],
            "unreviewed_reasons": ReasonCollection(
                [item.to_dict() for item in unreviewed_items], reason_counts
            ),
            "unreviewed_reason_counts": dict(reason_counts),
            "unreviewed_by_reason": dict(reason_counts),
            "handover_ready_segments": [segment.segment_id for segment in segments if segment.handover_ready],
            "partial_segments": [segment.segment_id for segment in segments if segment.status == STATUS_PARTIAL],
            "metadata": _json_value(self.metadata),
        }
        start_times = [scope.start_time for scope in scopes if scope.start_time is not None]
        end_times = [scope.end_time for scope in scopes if scope.end_time is not None]
        summary["time_range"] = [
            _iso(min(start_times)) if start_times else None,
            _iso(max(end_times)) if end_times else None,
        ]
        summary["covered_ranges"] = [
            {"start": _iso(start), "end": _iso(end), "seconds": (end - start).total_seconds()}
            for start, end in union_ranges
        ]
        summary["totals"] = {
            "total_records": summary["total_records"],
            "total": summary["total_records"],
            "total_record_instances": summary["total_record_instances"],
            "reviewed_records": summary["reviewed_records"],
            "reviewed": summary["reviewed_records"],
            "reviewed_record_instances": summary["reviewed_record_instances"],
            "unreviewed_records": summary["unreviewed_records"],
            "unreviewed": summary["unreviewed_records"],
            "invalid_record_count": summary["invalid_record_count"],
            "coverage_ratio": summary["coverage_ratio"],
            "coverage": summary["coverage_ratio"],
            "covered_seconds": summary["covered_seconds"],
            "covered_duration": summary["covered_seconds"],
            "overlap_saved_seconds": summary["overlap_saved_seconds"],
        }
        summary["overall"] = summary["totals"]
        return summary

    @staticmethod
    def _status_for_records(records: Sequence[RecordSnapshot]) -> str:
        if not records:
            return STATUS_EMPTY
        reviewed = sum(1 for record in records if record.reviewed)
        if reviewed == len(records):
            return STATUS_HANDOVER_READY
        if reviewed:
            return STATUS_PARTIAL
        return STATUS_UNREVIEWED

    @staticmethod
    def _continuous_reviewed_ranges(
        records: Sequence[RecordSnapshot],
    ) -> List[Tuple[_datetime.datetime, _datetime.datetime]]:
        ranges: List[Tuple[_datetime.datetime, _datetime.datetime]] = []
        run_start = None
        run_end = None
        ordered = sorted(
            records,
            key=lambda record: (
                _ts(record.timestamp) if record.timestamp is not None else float("inf"),
                record.file_offset if record.file_offset is not None else float("inf"),
            ),
        )
        for record in ordered:
            if record.timestamp is None:
                continue
            if record.reviewed:
                if run_start is None:
                    run_start = record.timestamp
                run_end = record.timestamp
            elif run_start is not None and run_end is not None:
                ranges.append((run_start, run_end))
                run_start = None
                run_end = None
        if run_start is not None and run_end is not None:
            ranges.append((run_start, run_end))
        return ranges

    def _receipt_result(self, receipt: ReviewReceipt) -> Dict[str, Any]:
        result = dict(self._receipt_results.get(receipt.receipt_id, {}))
        result.setdefault("receipt_id", receipt.receipt_id)
        result["receipt"] = receipt.to_dict()
        # Keep the common header fields directly on the trace as well as in
        # the nested receipt document, so case tooling can index a trace
        # without knowing the full receipt schema.
        result.setdefault("reviewer", receipt.reviewer)
        result.setdefault("reviewed_at", _iso(receipt.reviewed_at))
        result.setdefault("legacy", receipt.legacy)
        result.setdefault("schema_version", receipt.schema_version)
        result.setdefault("evidence_ids", list(receipt.evidence_ids))
        result["inherited_from"] = dict(receipt.inherited_from)
        result["segment_ids"] = sorted(
            {
                segment.segment_id
                for segment in self._build_segments()
                if receipt.receipt_id in segment.receipt_ids
            }
        )
        result["reviewed_count"] = len(result.get("reviewed_records", []))
        result["rejected_count"] = len(result.get("rejected_records", []))
        result["handover_ready"] = result.get("status") == "accepted" and bool(
            result.get("reviewed_records")
        )
        if result["handover_ready"]:
            result["coverage_status"] = STATUS_HANDOVER_READY
        elif result.get("status") == "partial":
            result["coverage_status"] = STATUS_PARTIAL
        elif result.get("reviewed_records"):
            result["coverage_status"] = STATUS_PARTIAL
        else:
            result["coverage_status"] = STATUS_UNREVIEWED
        result["partial"] = result["coverage_status"] == STATUS_PARTIAL
        result.setdefault("records", list(result.get("matched_records", [])))
        result.setdefault("reviewed", list(result.get("reviewed_records", [])))
        result.setdefault("rejected", list(result.get("rejected_records", [])))
        result.setdefault("unmatched", list(result.get("unmatched_claims", [])))
        return result

    @property
    def summary(self) -> CoverageReport:
        self._ensure_rebuilt()
        assert self._summary_cache is not None
        return self._summary_cache

    def summarize(self) -> CoverageReport:
        return self.summary

    def report(self) -> CoverageReport:
        return self.summary

    def get_summary(self) -> CoverageReport:
        return self.summary

    def coverage_summary(self) -> CoverageReport:
        return self.summary

    @property
    def coverage(self) -> CoverageReport:
        return self.summary

    @property
    def status(self) -> str:
        return str(self.summary["status"])

    @property
    def handover_ready(self) -> bool:
        return bool(self.summary["handover_ready"])

    def is_handover_ready(self) -> bool:
        return self.handover_ready

    @property
    def coverage_ratio(self) -> float:
        return float(self.summary["coverage_ratio"])

    @property
    def reviewed_count(self) -> int:
        return int(self.summary["reviewed_record_count"])

    @property
    def unreviewed_count(self) -> int:
        return int(self.summary["unreviewed_record_count"])

    @property
    def by_evidence(self) -> Dict[str, Any]:
        return dict(self.summary["by_evidence"])

    @property
    def coverage_by_evidence(self) -> Dict[str, Any]:
        return self.by_evidence

    @property
    def totals(self) -> Dict[str, Any]:
        return dict(self.summary["totals"])

    def get_record(
        self,
        evidence_id: Optional[str] = None,
        record_num: Optional[int] = None,
        file_offset: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Optional[RecordSnapshot]:
        offset = file_offset if file_offset is not None else offset
        for scope in self._evidences.values():
            if evidence_id is not None and self._resolve_evidence(evidence_id) != scope.evidence_id:
                continue
            for record in scope.records:
                if offset is not None and record.file_offset != offset:
                    continue
                if record_num is not None and record.record_num != record_num:
                    continue
                if offset is None and record_num is None:
                    continue
                return record
        return None

    def to_dict(self, include_records: bool = True) -> Dict[str, Any]:
        data = _json_value(dict(self.summary))
        if not include_records:
            for item in data.get("evidence", []):
                for key in (
                    "records",
                    "reviewed",
                    "reviewed_record_rows",
                    "unreviewed",
                    "unreviewed_rows",
                    "unreviewed_reasons",
                ):
                    item.pop(key, None)
            for item in data.get("segments", []):
                for key in (
                    "records",
                    "reviewed",
                    "reviewed_rows",
                    "unreviewed",
                    "unreviewed_rows",
                    "unreviewed_reasons",
                ):
                    item.pop(key, None)
            for key in (
                "reviewed_rows",
                "reviewed_record_rows",
                "unreviewed",
                "unreviewed_rows",
                "unreviewed_record_rows",
                "unreviewed_reasons",
            ):
                data.pop(key, None)
            for receipt_result in data.get("receipts", []):
                for key in (
                    "matched_records",
                    "reviewed_records",
                    "rejected_records",
                    "unmatched_claims",
                    "diagnostics",
                ):
                    receipt_result.pop(key, None)
                nested = receipt_result.get("receipt")
                if isinstance(nested, dict):
                    nested.pop("record_locations", None)
                    nested.pop("record_snapshots", None)
        return data

    def as_dict(self, include_records: bool = True) -> Dict[str, Any]:
        return self.to_dict(include_records=include_records)

    def to_json(self, indent: Optional[int] = 2, include_records: bool = True) -> str:
        return json.dumps(self.to_dict(include_records=include_records), indent=indent, sort_keys=True)

    def dumps(self, indent: Optional[int] = 2, include_records: bool = True) -> str:
        return self.to_json(indent=indent, include_records=include_records)

    @property
    def receipts(self) -> ReceiptCollection:
        return ReceiptCollection(self._receipts.values())

    @property
    def receipt_ids(self) -> List[str]:
        return list(self._receipts)

    @property
    def receipt_history(self) -> List[Dict[str, Any]]:
        return list(self._receipt_history)

    @property
    def evidence(self) -> EvidenceCollection:
        return EvidenceCollection(self._evidences.values())

    @property
    def evidences(self) -> "_CallableList":
        return self.evidence

    @property
    def segments(self) -> SegmentCollection:
        self._ensure_rebuilt()
        if self._segment_cache is None:
            self._segment_cache = self._build_segments()
        return self._segment_cache

    @property
    def coverage_segments(self) -> SegmentCollection:
        return self.segments

    def get_receipt(self, receipt_id: str, default: Any = None) -> Any:
        return self._receipts.get(receipt_id, default)

    def trace_receipts(self) -> List[Any]:
        return [self.trace_receipt(receipt_id) for receipt_id in self.receipt_ids]

    def trace(self, receipt_id: str, default: Any = None) -> Any:
        return self.trace_receipt(receipt_id, default=default)

    @property
    def receipt_traces(self) -> List[Any]:
        return self.trace_receipts()

    @property
    def record_locations(self) -> List[RecordLocation]:
        return [record.location for record in self.records]

    @property
    def locations(self) -> List[RecordLocation]:
        return self.record_locations

    def trace_receipt(self, receipt_id: str, default: Any = None) -> Any:
        receipt = self._receipts.get(receipt_id)
        if receipt is None:
            return default
        self._ensure_rebuilt()
        result = self._receipt_result(receipt)
        result["found"] = True
        return CoverageSummary(result)

    def _select_records(
        self,
        evidence_id: Optional[str] = None,
        reviewed: Optional[bool] = None,
        include_invalid: bool = True,
    ) -> RecordCollection:
        self._ensure_rebuilt()
        result = RecordCollection()
        for scope in self._evidences.values():
            if evidence_id is not None and self._resolve_evidence(evidence_id) != scope.evidence_id:
                continue
            for record in scope.records:
                if reviewed is not None and record.reviewed != reviewed:
                    continue
                if not include_invalid and not record.valid:
                    continue
                result.append(record)
        return result

    @property
    def records(self) -> RecordView:
        """All records; callable for filtering, iterable without parentheses."""
        return RecordView(self, self._select_records())

    @property
    def reviewed_records(self) -> RecordView:
        return RecordView(self, self._select_records(reviewed=True))

    @property
    def unreviewed_records(self) -> RecordView:
        return RecordView(self, self._select_records(reviewed=False))

    def unreviewed(self, evidence_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = []
        for record in self._select_records(evidence_id=evidence_id, reviewed=False):
            item = _unreviewed_item(record)
            if item is not None:
                items.append(item.to_dict())
        return items

    def unreviewed_reasons(self, evidence_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.unreviewed(evidence_id=evidence_id)

    def handover_ready_segments(self) -> SegmentCollection:
        return SegmentCollection([segment for segment in self.segments if segment.handover_ready])

    def explain(self, record: Any) -> Dict[str, Any]:
        if isinstance(record, RecordSnapshot):
            snapshot = record
        else:
            location = RecordLocation.from_any(record)
            snapshot = None
            for scope in self._evidences.values():
                for candidate in scope.records:
                    if location.file_offset is not None and candidate.file_offset == location.file_offset:
                        if (
                            location.evidence_id
                            and self._resolve_evidence(location.evidence_id) != candidate.evidence_id
                        ):
                            continue
                        snapshot = candidate
                        break
                    if location.record_num is not None and candidate.record_num == location.record_num:
                        if (
                            location.evidence_id
                            and self._resolve_evidence(location.evidence_id) != candidate.evidence_id
                        ):
                            continue
                        snapshot = candidate
                        break
                if snapshot is not None:
                    break
            if snapshot is None:
                raise KeyError(record)
        self._ensure_rebuilt()
        data = snapshot.to_dict()
        data["receipt_traces"] = [
            self.trace_receipt(receipt_id, default={"receipt_id": receipt_id, "found": False})
            for receipt_id in snapshot.review_ids
        ]
        return data


CoverageLedger = ReviewCoverageLedger
ReviewLedger = ReviewCoverageLedger
Ledger = ReviewCoverageLedger
ReviewCoverage = ReviewCoverageLedger
Receipt = ReviewReceipt
Evidence = EvidenceScope
Location = RecordLocation
SegmentCoverage = CoverageSegment


def review_coverage(evidence: Any, receipts: Any = None, **kwargs: Any) -> CoverageReport:
    """Build a ledger and return its summary report."""
    return ReviewCoverageLedger(evidence=evidence, receipts=receipts, **kwargs).summary


def build_review_coverage_ledger(evidence: Any, receipts: Any = None, **kwargs: Any) -> ReviewCoverageLedger:
    return ReviewCoverageLedger(evidence=evidence, receipts=receipts, **kwargs)


def build_coverage_ledger(evidence: Any, receipts: Any = None, **kwargs: Any) -> ReviewCoverageLedger:
    return build_review_coverage_ledger(evidence, receipts=receipts, **kwargs)


def coverage_ledger(evidence: Any, receipts: Any = None, **kwargs: Any) -> ReviewCoverageLedger:
    return build_review_coverage_ledger(evidence, receipts=receipts, **kwargs)


def summarize_review_coverage(evidence: Any, receipts: Any = None, **kwargs: Any) -> CoverageReport:
    return review_coverage(evidence, receipts=receipts, **kwargs)


def summarize_coverage(evidence: Any, receipts: Any = None, **kwargs: Any) -> CoverageReport:
    return review_coverage(evidence, receipts=receipts, **kwargs)


def build_ledger(evidence: Any, receipts: Any = None, **kwargs: Any) -> ReviewCoverageLedger:
    return build_review_coverage_ledger(evidence, receipts=receipts, **kwargs)


def coverage_report(evidence: Any, receipts: Any = None, **kwargs: Any) -> CoverageReport:
    return review_coverage(evidence, receipts=receipts, **kwargs)


def review_ledger(evidence: Any, receipts: Any = None, **kwargs: Any) -> ReviewCoverageLedger:
    return build_review_coverage_ledger(evidence, receipts=receipts, **kwargs)


CoverageResult = CoverageReport
ReviewCoverageReport = CoverageReport


__all__ = [
    "CoverageLedger",
    "CoverageReport",
    "CoverageResult",
    "CoverageSegment",
    "CoverageSummary",
    "CountRows",
    "Evidence",
    "EvidenceCollection",
    "EvidenceScope",
    "Ledger",
    "Location",
    "REASON_EVIDENCE_CHANGED",
    "REASON_INVALID_RECORD_STRUCTURE",
    "REASON_INVALID_TIMESTAMP",
    "REASON_MISSING_RECORD",
    "REASON_NOT_COVERED",
    "REASON_RECEIPT_REJECTED",
    "REASON_RECORD_CONTENT_ERROR",
    "REASON_STALE_RECEIPT_BINDING",
    "ReasonCollection",
    "Receipt",
    "ReceiptCollection",
    "RecordCollection",
    "RecordLocation",
    "RecordSnapshot",
    "RecordView",
    "ReviewCoverage",
    "ReviewCoverageLedger",
    "ReviewCoverageReport",
    "ReviewLedger",
    "ReviewReceipt",
    "STATUS_EMPTY",
    "STATUS_HANDOVER_READY",
    "STATUS_PARTIAL",
    "STATUS_UNREVIEWED",
    "SegmentCollection",
    "SegmentCoverage",
    "UnreviewedRecord",
    "build_coverage_ledger",
    "build_ledger",
    "build_review_coverage_ledger",
    "coverage_ledger",
    "coverage_report",
    "load_receipts",
    "review_coverage",
    "review_ledger",
    "summarize_coverage",
    "summarize_review_coverage",
]
