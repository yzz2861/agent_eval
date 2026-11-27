# Resources:
#   https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/callouts/hookid.htm
#   https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw // For most of the header definitions
#   https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header // for timestamp calculation
#   https://docs.rs/winapi-ui-automation/0.3.9/winapi_ui_automation/um/evntcons/index.html
#   Windows Development Kit
#
# TMF parser:
#   https://searchcode.com/file/116783567/Tools/ETW/traceEvent/WPPTraceEventParser.cs
#
# Maybe interesting files to look at:
#   AppData\\Local\\Microsoft\\Windows\\Explorer\\ExplorerStartupLog.etl
#   Windows\\Performance\\WinSAT\\DataStore
#   Windows\\System32\\NDF\\*.etl
#   Windows\\System32\\LogFiles\\WMI
#   Windows\\System32\\SleepStudy
#   Windows\\Panther\\*.etl
#   Windows\\System32\\WDI\\LogFiles
from __future__ import annotations

import io
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cstruct import Structure
from dissect.util.compression.lzxpress import decompress as xpress_decompress
from dissect.util.sid import read_sid
from dissect.util.ts import wintimestamp

from dissect.etl import manifest
from dissect.etl.c_etl import BufferFlag, c_etl
from dissect.etl.exceptions import (
    InvalidBufferError,
    InvalidHeaderError,
    ManifestDigestNotAllowedError,
    ManifestNotFoundError,
    ManifestVersionNotFoundError,
    NoMoreEventsError,
)
from dissect.etl.headers.logfile import LogfileHeader
from dissect.etl.headers.utils import select_event_header
from dissect.etl.registry import ManifestArchivePolicy

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from types import ModuleType
    from uuid import UUID

    from dissect.etl.headers.headers import Header
    from dissect.etl.registry import ManifestDefinition, ManifestRegistry


class FieldStatus(str, Enum):
    """Whether a decoded field is fully backed by bytes from the event."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class ReviewItem:
    """Pointer to a raw event that needs human review.

    The offsets are absolute byte positions inside the parsed ETL file, together with the
    buffer index and the offset inside the buffer so the original bytes can be located
    without re-parsing the event.
    """

    reason: str
    provider_id: UUID | None
    descriptor_version: int | None
    buffer_index: int
    buffer_offset: int
    record_offset: int
    event_size: int

    @property
    def raw_offset(self) -> int:
        return self.buffer_offset + self.record_offset

    def describe(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "provider_id": str(self.provider_id) if self.provider_id else None,
            "descriptor_version": self.descriptor_version,
            "buffer_index": self.buffer_index,
            "buffer_offset": self.buffer_offset,
            "record_offset": self.record_offset,
            "raw_offset": self.raw_offset,
            "event_size": self.event_size,
        }


class ETL:
    """The main interface when controlling an ETL file."""

    def __init__(
        self,
        fh: BinaryIO,
        registry: ManifestRegistry | None = None,
        archive_policy: ManifestArchivePolicy | None = None,
    ):
        self.fh = fh
        self.manifest_registry = registry or manifest.REGISTRY
        self.archive_policy = archive_policy or ManifestArchivePolicy()
        self.review_items: list[ReviewItem] = []

        # Load the first buffer inside the file,
        # The first event of the buffer contains a logfile header
        first_buffer = Buffer(self, 0)
        self.buffer_header = first_buffer.header
        trace_header = first_buffer.read_record(0).header
        self.logfile_header = LogfileHeader(trace_header)

        # Lookup PointerSize
        self.pointer_size = self.logfile_header.pointer_size

        if self.pointer_size not in (4, 8):
            raise InvalidHeaderError(f"invalid pointer size: {self.pointer_size}")

        self.is_64bit = self.logfile_header.is_64bit

        self.start_time = self.logfile_header.start_time
        self.buffer_size = self.buffer_header.BufferSize
        self.start = wintimestamp(self.logfile_header.start_time)
        self.end = wintimestamp(self.logfile_header.end_time)

        self._buffer_cache = {0: first_buffer}

    def buffer(self, index: int) -> Buffer:
        """Reads a specific buffer into memory."""
        if index < 0 or index >= self.logfile_header.buffers_written:
            raise IndexError("buffer index out of range")

        try:
            buf = self._buffer_cache[index]
        except KeyError:
            prev_buf = self.buffer(index - 1)
            buf = Buffer(self, prev_buf.next_buffer, index)
            self._buffer_cache[index] = buf

        return buf

    def buffers(self) -> Iterator[Buffer]:
        for i in range(self.logfile_header.buffers_written):
            yield self.buffer(i)

    def __iter__(self) -> Iterator[Event]:
        for buffer in self.buffers():
            yield from buffer

    def add_review_item(
        self,
        reason: str,
        provider_id: UUID | None,
        descriptor_version: int | None,
        event_size: int,
        buffer_index: int,
        buffer_offset: int,
        record_offset: int,
    ) -> ReviewItem:
        """Record the location of a raw event that could not be fully decoded."""
        item = ReviewItem(
            reason=reason,
            provider_id=provider_id,
            descriptor_version=descriptor_version,
            buffer_index=buffer_index,
            buffer_offset=buffer_offset,
            record_offset=record_offset,
            event_size=event_size,
        )
        self.review_items.append(item)
        return item

    def calculate_timestamp(self, time_delta: int) -> datetime:
        return wintimestamp(self.get_filetime_for_event(time_delta))

    def get_filetime_for_event(self, time_delta: int) -> int:
        return self.logfile_header.timestamp_base + int(self._calculate_timescale_for_event(time_delta))

    def _calculate_timescale_for_event(self, time_delta: int) -> float:
        return self.logfile_header.timestamp_scale * time_delta


class Buffer:
    def __init__(self, etl: ETL, offset: int, index: int = 0):
        self.fh = etl.fh
        self.etl = etl
        self.offset = offset
        self.index = index

        self._header = None
        self._data = None

    @property
    def header(self) -> c_etl.BufferHeader:
        if not self._header:
            self.fh.seek(self.offset)
            self._header = c_etl.BufferHeader(self.fh)

        return self._header

    @property
    def size(self) -> int:
        return self.header.BufferSize

    @property
    def data(self) -> memoryview:
        if not self._data:
            data_len = min(self.size, self.filled_bytes) - len(c_etl.BufferHeader)
            if data_len < 0:
                raise InvalidBufferError("Invalid data length")
            self.fh.seek(self.data_offset)

            tmp_data = self.fh.read(data_len)

            if self.header.BufferFlag & BufferFlag.COMPRESSED:
                tmp_data = xpress_decompress(tmp_data)

            self._data = memoryview(tmp_data)
        return self._data

    @property
    def data_offset(self) -> int:
        return self.offset + len(c_etl.BufferHeader)

    @property
    def filled_bytes(self) -> int:
        return self.header.FilledBytes

    @property
    def next_buffer(self) -> int:
        return self.offset + self.size

    def __iter__(self) -> Iterator[EventRecord]:
        offset = 0
        try:
            while offset < self.filled_bytes:
                event = self.read_record(offset)
                offset += event.aligned_size
                yield event
        except (EOFError, NoMoreEventsError):
            pass

    def read_record(self, offset: int) -> EventRecord:
        """Parse a record from a given offset inside a buffer."""
        event_record = EventRecord()
        data = self.data[offset:]
        header = select_event_header(
            data=data,
            etl=self.etl,
        )

        event_record._header = header
        event_record._buffer = self
        event_record._record_offset = offset

        return event_record

    def open(self) -> BinaryIO:
        return io.BytesIO(self.data)


class EventRecord:
    __slots__ = (
        "_buffer",
        "_event",
        "_header",
        "_record_offset",
    )

    def __init__(self):
        self._buffer = None
        self._event = None
        self._header = None
        self._record_offset = 0

    @property
    def header(self) -> Header:
        """A header of the type Header."""
        return self._header

    @property
    def size(self) -> int:
        """Size of the whole record."""
        return self.header.size

    @property
    def event(self) -> Event:
        """Parse payload inside the event header."""
        if not self._event:
            self._event = parse_payload(
                self._header,
                self._buffer.etl if self._buffer else None,
                buffer=self._buffer,
                record_offset=self._record_offset,
            )

        return self._event

    @property
    def aligned_size(self) -> int:
        return (self.size + 7) & 0xFFFFFFF8

    def __repr__(self) -> str:
        return "<EventRecord>"


class Event:
    __slots__ = [
        "_definition",
        "_event",
        "_field_status",
        "_header",
        "_manifest",
        "_record",
        "_struct",
        "_unparsed_bytes",
    ]

    def __init__(
        self,
        header: Header,
        event_manifest: ModuleType | None,
        definition: ManifestDefinition | None = None,
    ):
        self._header = header
        self._manifest = event_manifest
        self._definition = definition
        self._event = None
        self._field_status: dict[str, FieldStatus] = {}
        self._unparsed_bytes: dict[str, tuple[int, int]] = {}

        # Not every header has an opcode and version, so check it like this.
        opcode = getattr(header, "opcode", None)
        version = getattr(header, "version", None)
        key = (opcode, version)

        if event_manifest and definition:
            try:
                self._event = event_manifest.EVENTS[key]
            except KeyError:
                self._event = None
                self._struct = None
            else:
                self._parse_struct()
        else:
            self._struct = None

    def _parse_struct(self) -> None:
        payload = bytes(self._header.payload)
        template = self._event.template
        try:
            self._struct = template(payload)
        except EOFError:
            # The payload does not contain enough bytes for every template field.
            self._struct = None
            self._field_status = dict.fromkeys(template.fields, FieldStatus.INCOMPLETE)
            self._unparsed_bytes = {"payload": (0, len(payload))}
            return

        consumed = len(self._struct)
        self._field_status = dict.fromkeys(self._struct.__class__.fields, FieldStatus.COMPLETE)
        if consumed < len(payload):
            # The manifest template is narrower than the delivered payload.
            self._field_status["unparsed"] = FieldStatus.INCOMPLETE
            self._unparsed_bytes["unparsed"] = (consumed, len(payload) - consumed)

    def __getattr__(self, attribute: str) -> Any:
        try:
            return getattr(self._struct, attribute)
        except AttributeError:
            return object.__getattribute__(self, attribute)

    def provider_name(self) -> str | None:
        """Returns the manifest provider name."""
        return self._manifest.PROVIDER_NAME if self._manifest else None

    def manifest_info(self) -> dict[str, Any] | None:
        """Returns which provider list, descriptor version and digest decoded this event."""
        return self._definition.describe() if self._definition else None

    def is_complete(self) -> bool:
        """True when every payload byte is covered by a manifest template field."""
        return self._struct is not None and not self._unparsed_bytes

    def field_status(self) -> dict[str, FieldStatus]:
        """Returns the completeness status of every decoded field."""
        return dict(self._field_status)

    def complete_fields(self) -> dict[str, Any]:
        """Returns only the fields that are fully backed by event bytes."""
        if not self._struct:
            return {}
        return {
            name: value
            for name, value in self._struct.__values__.items()
            if self._field_status.get(name) is FieldStatus.COMPLETE
        }

    def incomplete_fields(self) -> dict[str, Any]:
        """Returns fields and byte ranges that lack full byte support."""
        struct_values = self._struct.__values__.items() if self._struct else []
        incomplete = {
            name: value for name, value in struct_values if self._field_status.get(name) is FieldStatus.INCOMPLETE
        }
        if self._unparsed_bytes:
            incomplete["_unparsed_byte_ranges"] = dict(self._unparsed_bytes)
        return incomplete

    def ts(self) -> datetime:
        """Returns the event timestamp."""
        return self._header.timestamp

    def provider_id(self) -> UUID:
        """Returns the GUID of the provider from the header."""
        return self._header.provider_id

    def symbol(self) -> str | None:
        return self._event.symbol if self._event else None

    def event_values(self) -> dict[str, Any]:
        """Create an items view that holds event and header data.

        The header data is additional information provided from a specific header.
        The event data is from a specific manifest file if it exists.
        """
        event_values = self._header.additional_header_fields()
        struct_events = self._struct.__values__ if self._struct else {}

        # Pretty print Instance values.
        update_event = {}
        instance_values = ((key, value) for key, value in struct_events.items() if isinstance(value, Structure))
        for key, value in instance_values:
            if hasattr(value, "sid"):
                update_event[key] = read_sid(value.sid.dumps())

        event_values.update(struct_events)
        event_values.update(update_event)
        event_values["manifest"] = self.manifest_info()
        event_values["field_status"] = {name: status.value for name, status in self._field_status.items()}
        if self._unparsed_bytes:
            event_values["unparsed_byte_ranges"] = dict(self._unparsed_bytes)
        return event_values

    def __repr__(self) -> str:
        symbol = self._event.symbol if self._event else None
        return f"{self._header} <{symbol} {self._struct!r}>"


def parse_payload(
    header: Header,
    etl: ETL | None = None,
    buffer: Buffer | None = None,
    record_offset: int = 0,
) -> Event:
    """Parse the event payload using the archive-allowed manifest definition.

    The manifest definition is selected by provider GUID, descriptor version and the digest
    allowlist of the current archive. When no matching definition exists, a review item is
    recorded with the absolute location of the raw event.
    """
    if etl is None:
        # Backwards-compatible path for callers parsing a standalone header.
        return _parse_with_legacy_lookup(header)

    descriptor_version = getattr(header, "version", None)
    provider_id = getattr(header, "provider_id", None)
    try:
        definition = etl.manifest_registry.select(provider_id, descriptor_version, etl.archive_policy)
        mf = definition.module
        if header.is_64bit:
            mf.c_parser.EtwPointer.as_64bit()
            mf.c_parser.UserSID_blob.as_64bit()
        else:
            mf.c_parser.EtwPointer.as_32bit()
            mf.c_parser.UserSID_blob.as_32bit()
    except (
        ManifestNotFoundError,
        ManifestVersionNotFoundError,
        ManifestDigestNotAllowedError,
        AttributeError,
    ) as exc:
        if buffer is not None:
            etl.add_review_item(
                reason=str(exc),
                provider_id=provider_id,
                descriptor_version=descriptor_version,
                event_size=header.size,
                buffer_index=buffer.index,
                buffer_offset=buffer.offset,
                record_offset=record_offset,
            )
        mf = None
        definition = None

    event = Event(header, mf, definition)
    if event._struct is None and definition is not None and buffer is not None:
        etl.add_review_item(
            reason="Event payload could not be fully parsed with the selected manifest definition",
            provider_id=provider_id,
            descriptor_version=descriptor_version,
            event_size=header.size,
            buffer_index=buffer.index,
            buffer_offset=buffer.offset,
            record_offset=record_offset,
        )
    return event


def _parse_with_legacy_lookup(header: Header) -> Event:
    """Keep the old lookup behaviour for callers that do not provide an ETL object."""
    try:
        mf = manifest.lookup(header.provider_id)
        if header.is_64bit:
            mf.c_parser.EtwPointer.as_64bit()
            mf.c_parser.UserSID_blob.as_64bit()
        else:
            mf.c_parser.EtwPointer.as_32bit()
            mf.c_parser.UserSID_blob.as_32bit()
        definition = manifest.REGISTRY.select(header.provider_id, getattr(header, "version", None))
    except (ManifestNotFoundError, ManifestVersionNotFoundError, ManifestDigestNotAllowedError, AttributeError):
        return Event(header, None)
    return Event(header, mf, definition)
