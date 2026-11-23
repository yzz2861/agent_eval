#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Scoped, auditable event browsing.

An :class:`EventBrowser` exposes only a selected record-number range.  Every
cursor and every page receipt is bound to that browser's archive, range, role,
and policy generation, so two overlapping views of the same EVTX file cannot
consume one another's pagination state.

Records, fields, and summaries have separate visibility controls.  Source
provenance is kept outside the field projection so an investigator can map a
returned page back to the corresponding record numbers and byte offsets in the
original archive without being able to bypass field redaction.
"""

from __future__ import absolute_import

import base64
import binascii
import fnmatch
import hashlib
import hmac
import json
import mmap
import os
import secrets
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, Optional, Sequence, Tuple, Union

from .Evtx import Evtx

_MISSING = object()
_PROCESS_SIGNING_KEY = secrets.token_bytes(32)
_DEFAULT_SUMMARY_METRICS = (
    "total_count",
    "first_record_number",
    "last_record_number",
)


class BrowseError(Exception):
    """Base class for mistakes made while constructing or using a browse."""


class InvalidCursor(BrowseError, ValueError):
    """Raised when a cursor is malformed, expired, or belongs to another scope."""


class CursorError(InvalidCursor):
    """Backward-compatible alias for :class:`InvalidCursor`."""


class ScopeMismatch(InvalidCursor):
    """Raised when a cursor belongs to a different scope."""


class VisibilityError(BrowseError):
    """Raised when a value is deliberately hidden by the view policy."""


class ReceiptError(BrowseError):
    """Raised when a receipt is malformed or has an invalid signature."""


def _as_optional_int(value: Any, name: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("{} must be an integer or None".format(name))
    return value


@dataclass(frozen=True, init=False)
class RecordRange:
    """
    An inclusive range of EVTX record numbers.

    EVTX record numbers are source identifiers, not list indexes.  They may be
    sparse (for example, the bundled ``system.evtx`` starts at 12049).
    ``None`` means that the corresponding side is unbounded.

    The constructor also accepts ``start``/``start_record`` and
    ``end``/``end_record`` keyword aliases.
    """

    first_record: Optional[int] = None
    last_record: Optional[int] = None

    def __init__(self, first_record: Optional[int] = None, last_record: Optional[int] = None, **aliases: Any):
        first_aliases = ("start", "start_record", "first")
        last_aliases = ("end", "end_record", "last")
        for name in first_aliases:
            if name in aliases:
                if first_record is not None:
                    raise TypeError("first_record and {} cannot both be supplied".format(name))
                first_record = aliases.pop(name)
        for name in last_aliases:
            if name in aliases:
                if last_record is not None:
                    raise TypeError("last_record and {} cannot both be supplied".format(name))
                last_record = aliases.pop(name)
        if aliases:
            raise TypeError("unexpected range arguments: {}".format(", ".join(sorted(aliases))))
        object.__setattr__(self, "first_record", first_record)
        object.__setattr__(self, "last_record", last_record)
        self.__post_init__()

    def __post_init__(self):
        first_record = _as_optional_int(self.first_record, "first_record")
        last_record = _as_optional_int(self.last_record, "last_record")
        if first_record is not None and last_record is not None and first_record > last_record:
            raise ValueError("first_record must not be greater than last_record")
        object.__setattr__(self, "first_record", first_record)
        object.__setattr__(self, "last_record", last_record)

    @property
    def start(self) -> Optional[int]:
        return self.first_record

    @property
    def end(self) -> Optional[int]:
        return self.last_record

    @property
    def start_record(self) -> Optional[int]:
        return self.first_record

    @property
    def end_record(self) -> Optional[int]:
        return self.last_record

    @property
    def last(self) -> Optional[int]:
        return self.last_record

    def contains(self, record_number: int) -> bool:
        if self.first_record is not None and record_number < self.first_record:
            return False
        if self.last_record is not None and record_number > self.last_record:
            return False
        return True

    def __contains__(self, record_number: int) -> bool:
        return self.contains(record_number)

    def __iter__(self) -> Iterator[Optional[int]]:
        yield self.first_record
        yield self.last_record

    def __len__(self) -> int:
        return 2

    def __call__(self) -> "RecordRange":
        return self

    def to_dict(self) -> Dict[str, Optional[int]]:
        return {
            "first_record": self.first_record,
            "last_record": self.last_record,
        }


@dataclass(frozen=True)
class OrdinalRange:
    """An inclusive range of zero-based positions within an archive snapshot."""

    first_index: int
    last_index: int

    def __post_init__(self):
        if isinstance(self.first_index, bool) or not isinstance(self.first_index, int):
            raise TypeError("first_index must be an integer")
        if isinstance(self.last_index, bool) or not isinstance(self.last_index, int):
            raise TypeError("last_index must be an integer")
        if self.first_index < 0 or self.last_index < 0:
            raise ValueError("ordinal indexes must not be negative")
        if self.first_index > self.last_index:
            raise ValueError("first_index must not be greater than last_index")


@dataclass(frozen=True)
class Visibility:
    """
    Visibility for the three independently auditable parts of a page.

    ``records`` may be a boolean, an iterable of record numbers, a predicate
    receiving a :class:`SourceReference`, or ``None`` (visible).

    ``fields`` may be a boolean, a field name/pattern, an iterable of names or
    patterns, or a mapping of name/pattern to boolean.  ``None`` means all
    projected fields are visible.

    ``summary`` may be a boolean, an iterable of metric names, or a mapping of
    metric name to boolean.  ``None`` means all configured summary metrics are
    visible.
    """

    records: Any = True
    fields: Any = None
    summary: Any = True


@dataclass(frozen=True)
class SourceReference:
    """The location of one record in the unmodified archive."""

    ordinal: int
    record_number: int
    offset: int
    length: int
    content_digest: Optional[str] = None
    chunk_offset: Optional[int] = None

    @property
    def record_num(self) -> int:
        return self.record_number

    @property
    def record_id(self) -> int:
        return self.record_number

    @property
    def end_offset(self) -> int:
        return self.offset + self.length

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "ordinal": self.ordinal,
            "record_number": self.record_number,
            "record_num": self.record_number,
            "offset": self.offset,
            "length": self.length,
        }
        if self.chunk_offset is not None:
            result["chunk_offset"] = self.chunk_offset
        if self.content_digest is not None:
            result["content_digest"] = self.content_digest
        return result


@dataclass(frozen=True)
class Provenance:
    """
    A mapping between a browsed page and the original archive.

    Page-specific values describe the records in this response.  Scope values
    describe the complete signed range.  Both are supplied even when record
    fields or summary values are hidden.
    """

    archive: str
    archive_path: str
    archive_digest: str
    scope_id: str
    role: Optional[str]
    requested_range: RecordRange
    scope_first_record_number: Optional[int]
    scope_last_record_number: Optional[int]
    scope_first_offset: Optional[int]
    scope_last_offset: Optional[int]
    page_first_record_number: Optional[int]
    page_last_record_number: Optional[int]
    page_first_offset: Optional[int]
    page_last_offset: Optional[int]
    page_ordinal_start: int
    page_ordinal_end: int
    record_refs: Tuple[SourceReference, ...]
    source_digest: Optional[str]

    @property
    def path(self) -> str:
        return self.archive_path

    @property
    def first_record_number(self) -> Optional[int]:
        return self.page_first_record_number

    @property
    def last_record_number(self) -> Optional[int]:
        return self.page_last_record_number

    @property
    def first_offset(self) -> Optional[int]:
        return self.page_first_offset

    @property
    def last_offset(self) -> Optional[int]:
        return self.page_last_offset

    @property
    def record_numbers(self) -> Tuple[int, ...]:
        return tuple(ref.record_number for ref in self.record_refs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "archive": self.archive,
            "archive_path": self.archive_path,
            "archive_digest": self.archive_digest,
            "scope_id": self.scope_id,
            "role": self.role,
            "requested_range": self.requested_range.to_dict(),
            "scope_first_record_number": self.scope_first_record_number,
            "scope_last_record_number": self.scope_last_record_number,
            "scope_first_offset": self.scope_first_offset,
            "scope_last_offset": self.scope_last_offset,
            "page_first_record_number": self.page_first_record_number,
            "page_last_record_number": self.page_last_record_number,
            "page_first_offset": self.page_first_offset,
            "page_last_offset": self.page_last_offset,
            "page_ordinal_start": self.page_ordinal_start,
            "page_ordinal_end": self.page_ordinal_end,
            "record_refs": [ref.to_dict() for ref in self.record_refs],
            "source_digest": self.source_digest,
        }

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


class BrowseSummary(Mapping):
    """A read-only summary whose metrics are selected by the view policy."""

    def __init__(self, values: Dict[str, Any]):
        self._values = dict(values)

    def __getitem__(self, key: str) -> Any:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return "BrowseSummary({!r})".format(self._values)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._values)

    @property
    def total_count(self) -> Optional[int]:
        return self._values.get("total_count")

    @property
    def total(self) -> Optional[int]:
        return self.total_count

    @property
    def count(self) -> Optional[int]:
        return self.total_count


@dataclass(frozen=True)
class BrowsedRecord:
    """A source reference plus its field projection."""

    source: SourceReference
    fields: Mapping[str, Any]

    @property
    def record_number(self) -> int:
        return self.source.record_number

    @property
    def record_num(self) -> int:
        return self.source.record_number

    @property
    def record_id(self) -> int:
        return self.source.record_number

    @property
    def offset(self) -> int:
        return self.source.offset

    @property
    def length(self) -> int:
        return self.source.length

    @property
    def event_id(self) -> Any:
        return self.get("EventID")

    @property
    def provider(self) -> Any:
        return self.get("Provider.Name", self.get("Provider"))

    @property
    def timestamp(self) -> Any:
        return self.get("TimeCreated.SystemTime", self.get("TimeCreated"))

    @property
    def flat_fields(self) -> Mapping[str, Any]:
        return self.fields

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.fields:
            return self.fields[key]
        matches = [value for path, value in self.fields.items() if path.rsplit(".", 1)[-1] == key]
        if len(matches) == 1:
            return matches[0]
        return default

    def __getitem__(self, key: str) -> Any:
        if key == "source":
            return self.source.to_dict()
        if key in ("record_number", "record_num", "offset", "length"):
            return getattr(self, key)
        if key in self.fields:
            return self.fields[key]
        value = self.get(key, _MISSING)
        if value is _MISSING:
            raise KeyError(key)
        return value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "fields": dict(self.fields),
        }

    as_dict = to_dict


@dataclass(frozen=True)
class BrowsePage:
    """One paginated, signed view of a scoped event range."""

    records: Tuple[BrowsedRecord, ...]
    summary: Optional[BrowseSummary]
    provenance: Provenance
    next_cursor: Optional[str]
    receipt: str
    output_digest: str
    role: Optional[str]
    range: RecordRange
    _claims: Mapping[str, Any]

    def __iter__(self) -> Iterator[BrowsedRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    @property
    def count(self) -> int:
        """The number of records in this page."""
        return len(self.records)

    @property
    def returned_count(self) -> int:
        return len(self.records)

    @property
    def total_count(self) -> Optional[int]:
        if self.summary is None:
            return None
        return self.summary.total_count

    @property
    def record_numbers(self) -> Tuple[int, ...]:
        return self.provenance.record_numbers

    @property
    def claims(self) -> Mapping[str, Any]:
        """The signed claims that make up this page's output receipt."""
        return self._claims

    receipt_claims = claims

    @property
    def archive_digest(self) -> str:
        return self.provenance.archive_digest

    @property
    def records_count(self) -> int:
        return len(self.records)

    @property
    def size(self) -> int:
        return len(self.records)

    @property
    def total(self) -> Optional[int]:
        return self.total_count

    @property
    def source_range(self) -> Tuple[Optional[int], Optional[int]]:
        return (self.provenance.page_first_record_number, self.provenance.page_last_record_number)

    @property
    def has_more(self) -> bool:
        return self.next_cursor is not None

    @property
    def has_next(self) -> bool:
        return self.next_cursor is not None

    @property
    def cursor(self) -> Optional[str]:
        return self.next_cursor

    @property
    def signature(self) -> str:
        return self.receipt

    @property
    def range_receipt(self) -> str:
        return self.receipt

    def verify(self, browser: Optional["EventBrowser"] = None) -> bool:
        if browser is None:
            if not _verify_signed_document(self.receipt, self.receipt_key()):
                return False
            try:
                envelope = _unsign_payload(self.receipt, self.receipt_key())
                return envelope.get("digest") == self.output_digest and _page_matches_claims(self, envelope["claims"])
            except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError):
                return False
        return browser.verify(self)

    def receipt_key(self) -> bytes:
        # The key is never inserted into the claims, but the view keeps the
        # receipt token self-contained for callers that only retain the page.
        return getattr(self, "_receipt_key", b"")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "range": self.range.to_dict(),
            "records": [record.to_dict() for record in self.records],
            "summary": self.summary.to_dict() if self.summary is not None else None,
            "provenance": self.provenance.to_dict(),
            "next_cursor": self.next_cursor,
            "count": self.count,
            "total_count": self.total_count,
            "receipt": self.receipt,
            "output_digest": self.output_digest,
        }

    as_dict = to_dict


class EventBrowser:
    """
    Browse one authenticated, record-number-scoped view of an EVTX archive.

    Args:
      filename: Path to the EVTX file.
      first_record: Inclusive first source record number (may be ``None``).
      last_record: Inclusive last source record number (may be ``None``).
      role: Optional label for the person or process receiving this view.
      record_visibility: Boolean, record-number iterable, or predicate.
      field_visibility: Field allowlist or patterns.
      summary_visibility: Summary metric allowlist.
      page_size: Default maximum number of records returned per page.
      signing_key: Optional HMAC key.  Supplying the same key to two views does
        not merge their cursors because each view also receives a distinct
        ``scope_id``.
      scope_id: Optional explicit scope identifier for a deliberately shared
        capability.

    The browser keeps no process-global cache.  Counts are recomputed from the
    current signed selection, and cursors are stateless tokens whose signature
    binds them to the scope generation.
    """

    def __init__(
        self,
        filename: Any,
        first_record: Optional[int] = None,
        last_record: Optional[int] = None,
        role: Optional[str] = None,
        record_visibility: Any = True,
        field_visibility: Any = None,
        summary_visibility: Any = True,
        page_size: int = 100,
        signing_key: Optional[Union[bytes, str]] = None,
        scope_id: Optional[str] = None,
        range: Optional[Union[RecordRange, Tuple[Optional[int], Optional[int]], Mapping]] = None,
        start_record: Optional[int] = None,
        end_record: Optional[int] = None,
        start: Optional[int] = None,
        end: Optional[int] = None,
        ordinal_range: Optional[Union[OrdinalRange, Tuple[int, int]]] = None,
        record_numbers: Optional[Iterable[int]] = None,
        visibility: Optional[Visibility] = None,
        limit: Optional[int] = None,
        first_index: Optional[int] = None,
        last_index: Optional[int] = None,
        include_xml: bool = False,
        record_range: Optional[Union[RecordRange, Tuple[Optional[int], Optional[int]], Mapping]] = None,
        window: Optional[Union[RecordRange, Tuple[Optional[int], Optional[int]], Mapping]] = None,
        scope: Optional[Union[RecordRange, Tuple[Optional[int], Optional[int]], Mapping]] = None,
        first: Optional[int] = None,
        last: Optional[int] = None,
        records_visibility: Any = _MISSING,
        fields_visibility: Any = _MISSING,
        summaries_visibility: Any = _MISSING,
        index_range: Optional[Union[OrdinalRange, Tuple[int, int]]] = None,
    ):
        self._temporary_path: Optional[str] = None
        source_bytes = self._coerce_source_bytes(filename)
        if source_bytes is None:
            if not isinstance(filename, (str, bytes, os.PathLike)):
                raise TypeError("filename must be a path, bytes-like archive, or file object")
            self._filename = os.fspath(filename)
            self._archive_name = os.path.basename(self._filename)
            self._archive_path = self._filename
        else:
            temporary = tempfile.NamedTemporaryFile(prefix="evtx-scoped-", suffix=".evtx", delete=False)
            try:
                temporary.write(source_bytes)
                temporary.flush()
            finally:
                temporary.close()
            self._temporary_path = temporary.name
            self._filename = temporary.name
            self._archive_name = "<memory>"
            self._archive_path = "<memory>"
        if not isinstance(page_size, int) or isinstance(page_size, bool) or page_size <= 0:
            raise ValueError("page_size must be a positive integer")
        if limit is not None:
            if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
                raise ValueError("limit must be a positive integer")
            page_size = limit

        if visibility is not None:
            if not isinstance(visibility, Visibility):
                raise TypeError("visibility must be a Visibility instance")
            record_visibility = visibility.records
            field_visibility = visibility.fields
            summary_visibility = visibility.summary

        if records_visibility is not _MISSING:
            record_visibility = records_visibility
        if fields_visibility is not _MISSING:
            field_visibility = fields_visibility
        if summaries_visibility is not _MISSING:
            summary_visibility = summaries_visibility

        supplied_ranges = [value for value in (range, record_range, window, scope) if value is not None]
        if len(supplied_ranges) > 1:
            raise TypeError("only one range/window/scope argument may be supplied")
        if supplied_ranges:
            range = supplied_ranges[0]

        for alias, value in (
            ("start_record", start_record),
            ("end_record", end_record),
            ("start", start),
            ("end", end),
            ("first", first),
            ("last", last),
        ):
            if value is not None:
                if first_record is not None and alias.startswith("start"):
                    raise TypeError("first_record and {} cannot both be supplied".format(alias))
                if last_record is not None and alias.startswith("end"):
                    raise TypeError("last_record and {} cannot both be supplied".format(alias))

        if first_record is None:
            first_record = start_record if start_record is not None else start
        if first_record is None:
            first_record = first
        if last_record is None:
            last_record = end_record if end_record is not None else end
        if last_record is None:
            last_record = last

        if index_range is not None:
            if ordinal_range is not None:
                raise TypeError("index_range and ordinal_range cannot both be supplied")
            ordinal_range = index_range

        if first_record is not None and not isinstance(first_record, int):
            if last_record is not None or range is not None:
                raise TypeError("a positional range cannot be combined with other range boundaries")
            range = first_record
            first_record = None

        if range is not None:
            parsed_range = self._coerce_record_range(range)
            if first_record is not None or last_record is not None:
                raise TypeError("range and first_record/last_record cannot both be supplied")
            first_record = parsed_range.first_record
            last_record = parsed_range.last_record

        self._role = role
        self._record_visibility = record_visibility
        self._field_visibility = field_visibility
        self._summary_visibility = summary_visibility
        self._page_size = page_size
        self._include_xml = bool(include_xml)
        self._generation = 0
        self._key = self._normalise_key(signing_key)
        self._ordinal_selector = self._coerce_ordinal_selector(
            ordinal_range=ordinal_range,
            first_index=first_index,
            last_index=last_index,
        )
        self._explicit_record_numbers = self._coerce_record_numbers(record_numbers)
        self._requested_range = RecordRange(first_record, last_record)
        self._archive_digest = (
            hashlib.sha256(source_bytes).hexdigest() if source_bytes is not None else self._digest_file(self._filename)
        )

        try:
            self._snapshot = self._scan_snapshot()
        except Exception:
            self.close()
            raise

        # EVTX record numbers start at one.  A zero-based boundary is the
        # conventional way to request the first records of an archive, so treat
        # it as an explicit ordinal range.
        self._auto_ordinal = False
        if self._ordinal_selector is None and self._explicit_record_numbers is None and first_record == 0:
            last_index = last_record if last_record is not None else len(self._snapshot) - 1
            if last_index >= 0:
                self._ordinal_selector = OrdinalRange(0, last_index)
                self._auto_ordinal = True

        if scope_id is None:
            nonce = secrets.token_hex(12)
            scope_material = "{}|{}|{}|{}|{}".format(
                self._archive_digest,
                self._role or "",
                self._requested_range.to_dict(),
                self._ordinal_selector,
                nonce,
            ).encode("utf-8")
            scope_id = "scope-" + hmac.new(self._key, scope_material, hashlib.sha256).hexdigest()[:24]
        self._scope_id = str(scope_id)

        # Validate selectors and make the effective range visible immediately.
        self._scope_references()

    @staticmethod
    def _coerce_source_bytes(value: Any) -> Optional[bytes]:
        if isinstance(value, (bytearray, memoryview, mmap.mmap)):
            return bytes(value)
        if isinstance(value, bytes):
            return value if value.startswith(b"ElfFile") else None
        if hasattr(value, "read") and not isinstance(value, (str, bytes, os.PathLike)):
            position = None
            try:
                position = value.tell()
                value.seek(0)
            except (AttributeError, OSError):
                pass
            data = value.read()
            if position is not None:
                try:
                    value.seek(position)
                except (AttributeError, OSError):
                    pass
            if isinstance(data, str):
                raise TypeError("archive file objects must be opened in binary mode")
            return bytes(data)
        return None

    @classmethod
    def open(cls, filename: Any, *args: Any, **kwargs: Any) -> "EventBrowser":
        """Alias for construction, useful when a context manager is desired."""
        return cls(filename, *args, **kwargs)

    @classmethod
    def from_path(cls, filename: Any, *args: Any, **kwargs: Any) -> "EventBrowser":
        return cls(filename, *args, **kwargs)

    @staticmethod
    def _coerce_record_range(value: Union[RecordRange, Tuple[Optional[int], Optional[int]], Mapping]) -> RecordRange:
        if isinstance(value, RecordRange):
            return value
        if isinstance(value, Mapping):
            first = value.get("first_record", value.get("start", value.get("start_record")))
            last = value.get("last_record", value.get("end", value.get("end_record")))
            return RecordRange(first, last)
        if isinstance(value, (tuple, list)) and len(value) == 2:
            return RecordRange(value[0], value[1])
        raise TypeError("range must be a RecordRange, a (first, last) pair, or a mapping")

    @staticmethod
    def _coerce_ordinal_selector(
        ordinal_range: Optional[Union[OrdinalRange, Tuple[int, int]]],
        first_index: Optional[int],
        last_index: Optional[int],
    ) -> Optional[OrdinalRange]:
        if ordinal_range is not None:
            if first_index is not None or last_index is not None:
                raise TypeError("ordinal_range and first_index/last_index cannot both be supplied")
            if isinstance(ordinal_range, OrdinalRange):
                return ordinal_range
            if isinstance(ordinal_range, (tuple, list)) and len(ordinal_range) == 2:
                return OrdinalRange(ordinal_range[0], ordinal_range[1])
            raise TypeError("ordinal_range must be an OrdinalRange or a (first, last) pair")
        if first_index is None and last_index is None:
            return None
        if first_index is None or last_index is None:
            raise TypeError("first_index and last_index must be supplied together")
        return OrdinalRange(first_index, last_index)

    @staticmethod
    def _coerce_record_numbers(record_numbers: Optional[Iterable[int]]) -> Optional[Tuple[int, ...]]:
        if record_numbers is None:
            return None
        if isinstance(record_numbers, (str, bytes)):
            raise TypeError("record_numbers must be an iterable of integers")
        try:
            values = tuple(record_numbers)
        except TypeError:
            raise TypeError("record_numbers must be an iterable of integers")
        if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
            raise TypeError("record_numbers must contain only integers")
        return values

    @staticmethod
    def _normalise_key(signing_key: Optional[Union[bytes, str]]) -> bytes:
        if signing_key is None:
            return _PROCESS_SIGNING_KEY
        if isinstance(signing_key, str):
            return signing_key.encode("utf-8")
        if isinstance(signing_key, bytes):
            return signing_key
        raise TypeError("signing_key must be bytes, str, or None")

    @staticmethod
    def _digest_file(filename: str) -> str:
        digest = hashlib.sha256()
        with open(filename, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _scan_snapshot(self) -> Tuple[Tuple[int, int, int, int, int], ...]:
        records = []
        with Evtx(self._filename) as log:
            for ordinal, record in enumerate(log.records()):
                records.append(
                    (
                        ordinal,
                        record.record_num(),
                        record.offset(),
                        record.length(),
                        record._chunk.offset(),
                    )
                )
        return tuple(records)

    def __enter__(self) -> "EventBrowser":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        """Release a temporary in-memory archive, if one was created."""
        temporary_path = getattr(self, "_temporary_path", None)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            self._temporary_path = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __iter__(self) -> Iterator[BrowsedRecord]:
        return self.records()

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def role(self) -> Optional[str]:
        return self._role

    @property
    def scope_id(self) -> str:
        return self._scope_id

    @property
    def range(self) -> RecordRange:
        return self._requested_range

    @property
    def requested_range(self) -> RecordRange:
        return self._requested_range

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def archive_digest(self) -> str:
        return self._archive_digest

    @property
    def page_size(self) -> int:
        return self._page_size

    @property
    def scope(self) -> RecordRange:
        return self._requested_range

    @property
    def record_numbers(self) -> Tuple[int, ...]:
        return tuple(ref.record_number for ref in self._scope_references())

    def provenance(self) -> Provenance:
        """Return scope-level source provenance without revealing record fields."""
        refs = self._scope_references()
        return self._build_provenance(refs, refs, 0, len(refs))

    @property
    def field_visibility(self) -> Any:
        return self._field_visibility

    @property
    def summary_visibility(self) -> Any:
        return self._summary_visibility

    @property
    def record_visibility(self) -> Any:
        return self._record_visibility

    def _scope_references(self) -> Tuple[SourceReference, ...]:
        if self._ordinal_selector is not None:
            if self._requested_range != RecordRange(None, None) and not self._auto_ordinal:
                raise TypeError("record-number range and ordinal_range cannot both be supplied")
            first = self._ordinal_selector.first_index
            last = self._ordinal_selector.last_index
            refs = self._snapshot[first : last + 1]
        elif self._explicit_record_numbers is not None:
            if self._requested_range != RecordRange(None, None):
                raise TypeError("record-numbers and record-number range cannot both be supplied")
            wanted = set(self._explicit_record_numbers)
            refs = tuple(ref for ref in self._snapshot if ref[1] in wanted)
        else:
            refs = tuple(ref for ref in self._snapshot if self._requested_range.contains(ref[1]))
        return tuple(
            SourceReference(
                ordinal=ordinal,
                record_number=record_number,
                offset=offset,
                length=length,
                chunk_offset=chunk_offset,
            )
            for ordinal, record_number, offset, length, chunk_offset in refs
        )

    def _selection_digest(self, refs: Sequence[SourceReference]) -> str:
        material = json.dumps(
            [
                {
                    "ordinal": ref.ordinal,
                    "record_number": ref.record_number,
                    "offset": ref.offset,
                    "length": ref.length,
                    "chunk_offset": ref.chunk_offset,
                }
                for ref in refs
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()

    def _record_is_visible(self, ref: SourceReference) -> bool:
        visibility = self._record_visibility
        if visibility is None or visibility is True:
            return True
        if visibility is False:
            return False
        if callable(visibility):
            return bool(visibility(ref))
        if isinstance(visibility, slice):
            return False
        if isinstance(visibility, (set, frozenset, list, tuple, range)):
            return ref.record_number in visibility
        raise TypeError("record_visibility must be a boolean, iterable, predicate, or None")

    def _summary_allowed(self) -> bool:
        visibility = self._summary_visibility
        if visibility is None:
            return True
        if visibility is False:
            return False
        if isinstance(visibility, Mapping):
            return any(bool(value) for value in visibility.values())
        if isinstance(visibility, str):
            return bool(visibility)
        try:
            return bool(visibility)
        except TypeError:
            return True

    def _summary_metric_allowed(self, metric: str) -> bool:
        visibility = self._summary_visibility
        if visibility is None:
            return True
        if visibility is True:
            return metric in _DEFAULT_SUMMARY_METRICS
        if visibility is False:
            return False
        if isinstance(visibility, str):
            return metric == visibility
        if isinstance(visibility, Mapping):
            if any(bool(value) for value in visibility.values()):
                return bool(visibility.get(metric, False))
            return metric not in visibility and metric in _DEFAULT_SUMMARY_METRICS
        return metric in visibility

    def _field_policy(self) -> Any:
        return self._field_visibility

    def _page_size_for(self, limit: Optional[int]) -> int:
        if limit is None:
            return self._page_size
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        return limit

    def count(self) -> int:
        """Return the number of records in the current scope."""
        if not self._summary_allowed() or not self._summary_metric_allowed("total_count"):
            raise VisibilityError("total_count is hidden by summary_visibility")
        return len(self._scope_references())

    def total_count(self) -> int:
        return self.count()

    def summary(self) -> Optional[BrowseSummary]:
        """Return the configured summary for the current scope."""
        refs = self._scope_references()
        return self._build_summary(refs, refs, returned_count=len(refs))

    def records(self) -> Iterator[BrowsedRecord]:
        """Iterate all visible records in the current scope."""
        cursor = None
        while True:
            page = self.page(cursor=cursor, limit=self._page_size)
            for record in page.records:
                yield record
            if page.next_cursor is None:
                break
            cursor = page.next_cursor

    iter_records = records

    def page(
        self,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
        page_size: Optional[int] = None,
    ) -> BrowsePage:
        """
        Return one page.

        Cursors are opaque and valid only for this browser's current scope
        generation.  A cursor from another role's overlapping view, or from
        this view before a range/policy change, raises :class:`InvalidCursor`.
        """
        if page_size is not None:
            if limit is not None:
                raise TypeError("limit and page_size cannot both be supplied")
            limit = page_size
        size = self._page_size_for(limit)
        scope_refs = self._scope_references()
        selection_digest = self._selection_digest(scope_refs)

        if cursor is None:
            start = 0
        else:
            start = self._decode_cursor(cursor, scope_refs, selection_digest)

        end = min(start + size, len(scope_refs))
        page_refs = scope_refs[start:end]
        records = []
        for ref in page_refs:
            if not self._record_is_visible(ref):
                continue
            records.append(self._build_record(ref))

        next_cursor = None
        if end < len(scope_refs):
            next_cursor = self._encode_cursor(end, selection_digest)

        summary = self._build_summary(scope_refs, page_refs, returned_count=len(records))
        provenance = self._build_provenance(scope_refs, page_refs, start, end)
        claims = {
            "v": 1,
            "kind": "evtx.scoped-page",
            "archive_digest": self._archive_digest,
            "scope_id": self._scope_id,
            "role": self._role,
            "generation": self._generation,
            "requested_range": self._requested_range.to_dict(),
            "selection_digest": selection_digest,
            "provenance": provenance.to_dict(),
            "records": [record.to_dict() for record in records],
            "summary": summary.to_dict() if summary is not None else None,
            "next_cursor": next_cursor,
            "returned_count": len(records),
        }
        receipt, output_digest = self._sign_document(claims)

        page = BrowsePage(
            records=tuple(records),
            summary=summary,
            provenance=provenance,
            next_cursor=next_cursor,
            receipt=receipt,
            output_digest=output_digest,
            role=self._role,
            range=self._requested_range,
            _claims=claims,
        )
        # Keep receipt verification independently possible without exposing the
        # key in the signed document.
        object.__setattr__(page, "_receipt_key", self._key)
        return page

    browse = page
    fetch_page = page
    get_page = page
    next_page = page
    paginate = page
    events = records
    iter_events = records

    def set_range(
        self,
        first_record: Optional[int] = None,
        last_record: Optional[int] = None,
        range: Optional[Union[RecordRange, Tuple[Optional[int], Optional[int]], Mapping]] = None,
        start_record: Optional[int] = None,
        end_record: Optional[int] = None,
        start: Optional[int] = None,
        end: Optional[int] = None,
        record_range: Optional[Union[RecordRange, Tuple[Optional[int], Optional[int]], Mapping]] = None,
        window: Optional[Union[RecordRange, Tuple[Optional[int], Optional[int]], Mapping]] = None,
        first: Optional[int] = None,
        last: Optional[int] = None,
    ) -> "EventBrowser":
        """Change the scope and invalidate every cursor from the old generation."""
        supplied_ranges = [value for value in (range, record_range, window) if value is not None]
        if len(supplied_ranges) > 1:
            raise TypeError("only one range/window argument may be supplied")
        if supplied_ranges:
            range = supplied_ranges[0]
        if range is not None:
            if (
                first_record is not None
                or last_record is not None
                or start_record is not None
                or end_record is not None
                or start is not None
                or end is not None
                or first is not None
                or last is not None
            ):
                raise TypeError("range cannot be combined with record boundary arguments")
            parsed = self._coerce_record_range(range)
            first_record, last_record = parsed.first_record, parsed.last_record
        if start_record is not None:
            first_record = start_record
        if end_record is not None:
            last_record = end_record
        if start is not None:
            first_record = start
        if end is not None:
            last_record = end
        if first is not None:
            first_record = first
        if last is not None:
            last_record = last
        if self._explicit_record_numbers is not None:
            raise TypeError("set_range is only available for record-number ranges")
        if self._ordinal_selector is not None and not self._auto_ordinal:
            raise TypeError("set_range is only available for record-number ranges")
        self._requested_range = RecordRange(first_record, last_record)
        if first_record == 0:
            last_index = last_record if last_record is not None else len(self._snapshot) - 1
            self._ordinal_selector = OrdinalRange(0, last_index) if last_index >= 0 else None
            self._auto_ordinal = self._ordinal_selector is not None
        else:
            self._ordinal_selector = None
            self._auto_ordinal = False
        self._generation += 1
        self._scope_references()
        return self

    update_range = set_range
    change_range = set_range
    set_scope = set_range

    def set_visibility(
        self,
        record_visibility: Any = _MISSING,
        field_visibility: Any = _MISSING,
        summary_visibility: Any = _MISSING,
    ) -> "EventBrowser":
        """Change visibility policy and invalidate existing cursors."""
        if record_visibility is not _MISSING:
            self._record_visibility = record_visibility
        if field_visibility is not _MISSING:
            self._field_visibility = field_visibility
        if summary_visibility is not _MISSING:
            self._summary_visibility = summary_visibility
        self._generation += 1
        return self

    def _build_record(self, ref: SourceReference) -> BrowsedRecord:
        content_digest = None
        fields: Dict[str, Any] = {}
        xml = None
        with Evtx(self._filename) as log:
            record = log.get_record(ref.record_number)
            if record is None:
                raise BrowseError("record {} disappeared from the archive".format(ref.record_number))
            content_digest = hashlib.sha256(record.data()).hexdigest()
            if self._field_visibility is not False:
                try:
                    xml = record.xml()
                    fields = _project_fields(_flatten_xml_fields(xml), self._field_visibility)
                except Exception:
                    # A malformed event must not turn a scoped page into a
                    # different range.  No fields are revealed if projection
                    # cannot be performed.
                    fields = {}
            if self._include_xml and self._field_visibility is not False:
                fields = dict(fields)
                fields["_xml"] = xml
        source = SourceReference(
            ordinal=ref.ordinal,
            record_number=ref.record_number,
            offset=ref.offset,
            length=ref.length,
            chunk_offset=ref.chunk_offset,
            content_digest=content_digest,
        )
        return BrowsedRecord(source=source, fields=fields)

    def _build_summary(
        self,
        scope_refs: Sequence[SourceReference],
        page_refs: Sequence[SourceReference],
        returned_count: int,
    ) -> Optional[BrowseSummary]:
        if not self._summary_allowed():
            return None
        values: Dict[str, Any] = {}
        if self._summary_metric_allowed("total_count"):
            values["total_count"] = len(scope_refs)
        if self._summary_metric_allowed("first_record_number"):
            values["first_record_number"] = scope_refs[0].record_number if scope_refs else None
        if self._summary_metric_allowed("last_record_number"):
            values["last_record_number"] = scope_refs[-1].record_number if scope_refs else None
        if self._summary_metric_allowed("first_offset"):
            values["first_offset"] = scope_refs[0].offset if scope_refs else None
        if self._summary_metric_allowed("last_offset"):
            values["last_offset"] = scope_refs[-1].offset if scope_refs else None
        if self._summary_metric_allowed("page_count"):
            values["page_count"] = len(page_refs)
        if self._summary_metric_allowed("returned_count"):
            values["returned_count"] = returned_count
        if self._summary_metric_allowed("event_ids"):
            values["event_ids"] = self._summary_event_ids(scope_refs)
        if self._summary_metric_allowed("providers"):
            values["providers"] = self._summary_providers(scope_refs)
        return BrowseSummary(values)

    def _summary_event_ids(self, refs: Sequence[SourceReference]) -> Dict[str, int]:
        counts: Counter = Counter()
        for ref in refs:
            fields = self._read_fields(ref)
            if "EventID" in fields:
                counts[str(fields["EventID"])] += 1
        return dict(sorted(counts.items()))

    def _summary_providers(self, refs: Sequence[SourceReference]) -> Dict[str, int]:
        counts: Counter = Counter()
        for ref in refs:
            fields = self._read_fields(ref)
            provider = fields.get("Provider.Name", fields.get("Provider"))
            if provider is not None:
                counts[str(provider)] += 1
        return dict(sorted(counts.items()))

    def _read_fields(self, ref: SourceReference) -> Dict[str, Any]:
        with Evtx(self._filename) as log:
            record = log.get_record(ref.record_number)
            if record is None:
                return {}
            try:
                return _flatten_xml_fields(record.xml())
            except Exception:
                return {}

    def _build_provenance(
        self,
        scope_refs: Sequence[SourceReference],
        page_refs: Sequence[SourceReference],
        ordinal_start: int,
        ordinal_end: int,
    ) -> Provenance:
        page_first = page_refs[0] if page_refs else None
        page_last = page_refs[-1] if page_refs else None
        scope_first = scope_refs[0] if scope_refs else None
        scope_last = scope_refs[-1] if scope_refs else None
        source_material = json.dumps(
            [ref.to_dict() for ref in page_refs],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        source_digest = hashlib.sha256(source_material).hexdigest() if page_refs else None
        return Provenance(
            archive=self._archive_name,
            archive_path=self._archive_path,
            archive_digest=self._archive_digest,
            scope_id=self._scope_id,
            role=self._role,
            requested_range=self._requested_range,
            scope_first_record_number=scope_first.record_number if scope_first else None,
            scope_last_record_number=scope_last.record_number if scope_last else None,
            scope_first_offset=scope_first.offset if scope_first else None,
            scope_last_offset=scope_last.offset if scope_last else None,
            page_first_record_number=page_first.record_number if page_first else None,
            page_last_record_number=page_last.record_number if page_last else None,
            page_first_offset=page_first.offset if page_first else None,
            page_last_offset=page_last.offset if page_last else None,
            page_ordinal_start=ordinal_start,
            page_ordinal_end=ordinal_end,
            record_refs=tuple(page_refs),
            source_digest=source_digest,
        )

    def _encode_cursor(self, next_ordinal: int, selection_digest: str) -> str:
        payload = {
            "v": 1,
            "kind": "evtx.scoped-cursor",
            "archive_digest": self._archive_digest,
            "scope_id": self._scope_id,
            "generation": self._generation,
            "ordinal": next_ordinal,
            "selection_digest": selection_digest,
        }
        return _sign_payload(payload, self._key)

    def _decode_cursor(
        self,
        cursor: str,
        scope_refs: Sequence[SourceReference],
        selection_digest: str,
    ) -> int:
        if not isinstance(cursor, str) or not cursor:
            raise InvalidCursor("invalid cursor")
        try:
            payload = _unsign_payload(cursor, self._key)
            valid = (
                payload.get("v") == 1
                and payload.get("kind") == "evtx.scoped-cursor"
                and payload.get("archive_digest") == self._archive_digest
                and payload.get("scope_id") == self._scope_id
                and payload.get("generation") == self._generation
                and payload.get("selection_digest") == selection_digest
            )
            ordinal = payload.get("ordinal")
            if not valid or isinstance(ordinal, bool) or not isinstance(ordinal, int):
                raise InvalidCursor("invalid cursor")
            if ordinal < 0 or ordinal > len(scope_refs):
                raise InvalidCursor("invalid cursor")
            return ordinal
        except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError):
            raise InvalidCursor("invalid cursor")

    def _sign_document(self, claims: Mapping[str, Any]) -> Tuple[str, str]:
        digest = hashlib.sha256(_canonical_json(claims)).hexdigest()
        envelope = {
            "claims": claims,
            "digest": digest,
        }
        return _sign_payload(envelope, self._key), digest

    def verify(self, page_or_receipt: Union[BrowsePage, str]) -> bool:
        """
        Verify an old output after the browser has changed scope.

        This checks the receipt signature, its embedded output digest, and (when
        a page is supplied) the page's own digest.  It intentionally does not
        require the receipt's range to equal the browser's current range.
        """
        try:
            if isinstance(page_or_receipt, BrowsePage):
                receipt = page_or_receipt.receipt
                page = page_or_receipt
            elif isinstance(page_or_receipt, str):
                receipt = page_or_receipt
                page = None
            else:
                return False
            envelope = _unsign_payload(receipt, self._key)
            claims = envelope["claims"]
            if envelope.get("digest") != hashlib.sha256(_canonical_json(claims)).hexdigest():
                return False
            if page is not None:
                if page.output_digest != envelope.get("digest") or not _page_matches_claims(page, claims):
                    return False
            return True
        except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError):
            return False

    verify_receipt = verify
    check_receipt = verify
    verify_old_output = verify

    def read_receipt(self, receipt: str) -> Mapping[str, Any]:
        """Return verified claims from a receipt."""
        try:
            envelope = _unsign_payload(receipt, self._key)
            claims = envelope["claims"]
            if envelope.get("digest") != hashlib.sha256(_canonical_json(claims)).hexdigest():
                raise ReceiptError("receipt digest mismatch")
            return claims
        except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError) as exc:
            raise ReceiptError("invalid receipt") from exc

    def range_receipt(self) -> str:
        """Return a receipt for the current scope even before a page is read."""
        refs = self._scope_references()
        claims = {
            "v": 1,
            "kind": "evtx.scoped-range",
            "archive_digest": self._archive_digest,
            "scope_id": self._scope_id,
            "role": self._role,
            "generation": self._generation,
            "requested_range": self._requested_range.to_dict(),
            "selection_digest": self._selection_digest(refs),
            "first_record_number": refs[0].record_number if refs else None,
            "last_record_number": refs[-1].record_number if refs else None,
        }
        if self._summary_allowed() and self._summary_metric_allowed("total_count"):
            claims["total_count"] = len(refs)
        receipt, _ = self._sign_document(claims)
        return receipt

    def scope_receipt(self) -> str:
        return self.range_receipt()

    def range_claims(self) -> Mapping[str, Any]:
        """Return the verified claims for the current range receipt."""
        return self.read_receipt(self.range_receipt())


def _page_matches_claims(page: BrowsePage, claims: Mapping[str, Any]) -> bool:
    expected_output = {
        "records": [record.to_dict() for record in page.records],
        "summary": page.summary.to_dict() if page.summary is not None else None,
        "provenance": page.provenance.to_dict(),
        "next_cursor": page.next_cursor,
        "returned_count": len(page.records),
    }
    return not any(claims.get(key) != value for key, value in expected_output.items())


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _sign_payload(payload: Mapping[str, Any], key: bytes) -> str:
    body = _b64encode(_canonical_json(payload))
    signature = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
    return body + "." + signature


def _unsign_payload(token: str, key: bytes) -> Mapping[str, Any]:
    if not isinstance(token, str) or token.count(".") != 1:
        raise ValueError("invalid signed token")
    body, signature = token.split(".", 1)
    expected = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid signature")
    payload = json.loads(_b64decode(body).decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("invalid payload")
    return payload


def _verify_signed_document(token: str, key: bytes) -> bool:
    if not key:
        return False
    try:
        envelope = _unsign_payload(token, key)
        claims = envelope["claims"]
        return envelope.get("digest") == hashlib.sha256(_canonical_json(claims)).hexdigest()
    except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError):
        return False


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _flatten_xml_fields(xml: str) -> Dict[str, Any]:
    root = ET.fromstring(xml)
    fields: Dict[str, Any] = {}

    def put(path: str, value: Any) -> None:
        if path in fields:
            existing = fields[path]
            if isinstance(existing, list):
                existing.append(value)
            else:
                fields[path] = [existing, value]
        else:
            fields[path] = value

    def walk(element, prefix: str) -> None:
        name = _local_name(element.tag)
        path = "{}.{}".format(prefix, name) if prefix else name
        text = (element.text or "").strip()
        if text:
            put(path, text)
        for attr_name, attr_value in element.attrib.items():
            if _local_name(attr_name) == "xmlns":
                continue
            put("{}.{}".format(path, _local_name(attr_name)), attr_value)
        children = list(element)
        for child in children:
            child_name = _local_name(child.tag)
            if child_name == "Data" and "Name" in child.attrib:
                data_path = "{}.{}".format(path, child.attrib["Name"])
                data_text = (child.text or "").strip()
                if data_text:
                    put(data_path, data_text)
                for attr_name, attr_value in child.attrib.items():
                    if _local_name(attr_name) != "Name":
                        put("{}.{}".format(data_path, _local_name(attr_name)), attr_value)
            else:
                walk(child, path)

    root_name = _local_name(root.tag)
    for child in root:
        child_name = _local_name(child.tag)
        if child_name == "System":
            for system_child in child:
                name = _local_name(system_child.tag)
                text = (system_child.text or "").strip()
                if text:
                    put(name, text)
                for attr_name, attr_value in system_child.attrib.items():
                    if _local_name(attr_name) != "xmlns":
                        put("{}.{}".format(name, _local_name(attr_name)), attr_value)
                for nested in system_child:
                    walk(nested, name)
        elif child_name in ("EventData", "UserData", "RenderingInfo"):
            for item in child:
                item_name = _local_name(item.tag)
                if item_name == "Data" and "Name" in item.attrib and child_name == "EventData":
                    data_path = "EventData.{}".format(item.attrib["Name"])
                    data_text = (item.text or "").strip()
                    if data_text:
                        put(data_path, data_text)
                else:
                    walk(item, child_name)
        else:
            walk(child, root_name)
    return fields


def _field_matches(path: str, selector: str) -> bool:
    normalized = selector.replace("/", ".").replace("[", ".").replace("]", "")
    if normalized.startswith("Event."):
        normalized = normalized[len("Event.") :]
    if normalized.startswith("System."):
        normalized = normalized[len("System.") :]
    if fnmatch.fnmatchcase(path, normalized):
        return True
    if normalized.endswith(".*"):
        return path == normalized[:-2] or path.startswith(normalized[:-1])
    if path.endswith("." + normalized):
        return True
    return path == normalized


def _project_fields(fields: Mapping[str, Any], visibility: Any) -> Dict[str, Any]:
    if visibility is None or visibility is True:
        return dict(fields)
    if visibility is False:
        return {}
    if isinstance(visibility, str):
        selectors = (visibility,)
        denied = frozenset()
    elif isinstance(visibility, Mapping):
        selectors = tuple(str(key) for key, allowed in visibility.items() if allowed)
        denied = frozenset(str(key) for key, allowed in visibility.items() if not allowed)
        if not selectors and denied:
            selectors = ("*",)
    else:
        selectors = tuple(str(value) for value in visibility)
        denied = frozenset()
    if not selectors:
        return {}
    result = {}
    for path, value in fields.items():
        if any(_field_matches(path, selector) for selector in denied):
            continue
        if any(_field_matches(path, selector) for selector in selectors):
            result[path] = value
    return result


# Friendly aliases for callers that use "view" terminology.
ScopedEventView = EventBrowser
ScopedEventBrowser = EventBrowser
ScopedEVTXView = EventBrowser
ScopedView = EventBrowser
EventView = EventBrowser
Range = RecordRange
SignedRange = RecordRange
CursorExpired = InvalidCursor


def verify_receipt(receipt: str, signing_key: Optional[Union[bytes, str]] = None) -> bool:
    """Verify a receipt without constructing a browser."""
    key = EventBrowser._normalise_key(signing_key)
    return _verify_signed_document(receipt, key)


def read_receipt(receipt: str, signing_key: Optional[Union[bytes, str]] = None) -> Mapping[str, Any]:
    """Read verified receipt claims without constructing a browser."""
    key = EventBrowser._normalise_key(signing_key)
    try:
        envelope = _unsign_payload(receipt, key)
        claims = envelope["claims"]
        if envelope.get("digest") != hashlib.sha256(_canonical_json(claims)).hexdigest():
            raise ReceiptError("receipt digest mismatch")
        return claims
    except (ValueError, TypeError, KeyError, binascii.Error, json.JSONDecodeError) as exc:
        raise ReceiptError("invalid receipt") from exc


def scoped_view(
    filename: os.PathLike,
    first_record: Optional[int] = None,
    last_record: Optional[int] = None,
    **kwargs: Any,
) -> EventBrowser:
    """Convenience constructor for :class:`EventBrowser`."""
    return EventBrowser(filename, first_record=first_record, last_record=last_record, **kwargs)


scoped_event_view = scoped_view
evtx_scoped_event_view = scoped_view
evtx_event_browser_view = scoped_view
event_browser = scoped_view
browse_events = scoped_view


__all__ = [
    "BrowseError",
    "BrowsePage",
    "BrowseSummary",
    "BrowsedRecord",
    "CursorError",
    "CursorExpired",
    "EventBrowser",
    "EventView",
    "InvalidCursor",
    "OrdinalRange",
    "Provenance",
    "Range",
    "ReceiptError",
    "RecordRange",
    "ScopeMismatch",
    "ScopedEVTXView",
    "ScopedEventBrowser",
    "ScopedEventView",
    "ScopedView",
    "SignedRange",
    "SourceReference",
    "Visibility",
    "VisibilityError",
    "browse_events",
    "event_browser",
    "evtx_event_browser_view",
    "evtx_scoped_event_view",
    "read_receipt",
    "scoped_event_view",
    "scoped_view",
    "verify_receipt",
]
