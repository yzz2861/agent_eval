from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.eventlog.bxml import BxmlNameSource, BxmlSub, BxmlTemplateSource, BxmlValueSource
from dissect.eventlog.evtx.c_evtx import c_evtx
from dissect.eventlog.evtx.evtx import CHUNK_SIZE, ElfChnk
from dissect.eventlog.exceptions import MalformedElfChnkException

if TYPE_CHECKING:
    from typing_extensions import Self


@dataclass(frozen=True)
class ByteRange:
    offset: int
    length: int
    sha256: str

    @classmethod
    def from_data(cls, data: bytes, offset: int) -> Self:
        return cls(offset=offset, length=len(data), sha256=hashlib.sha256(data).hexdigest())


@dataclass(frozen=True)
class TemplateClaim:
    reference_offset: int
    offset: int
    length: int
    sha256: str


@dataclass(frozen=True)
class NameClaim:
    name: str
    offset: int
    length: int


@dataclass(frozen=True)
class ValueClaim:
    offset: int
    length: int
    type_id: int
    is_array: bool
    sha256: str


@dataclass(frozen=True)
class FieldSource:
    name: str
    value: Any
    value_range: ValueClaim | None
    template: TemplateClaim | None
    name_sources: tuple[NameClaim, ...]


@dataclass(frozen=True)
class EventProof:
    file_size: int
    chunk: ByteRange
    record: ByteRange
    record_id: int
    event: dict[str, Any]
    fields: tuple[FieldSource, ...]
    templates: tuple[TemplateClaim, ...]
    format: str = "dissect.eventlog.evtx.event-proof/v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        chunk = ByteRange(**data["chunk"])
        record = ByteRange(**data["record"])
        fields = tuple(
            FieldSource(
                name=item["name"],
                value=item["value"],
                value_range=ValueClaim(**item["value_range"]) if item["value_range"] else None,
                template=TemplateClaim(**item["template"]) if item["template"] else None,
                name_sources=tuple(NameClaim(**name) for name in item["name_sources"]),
            )
            for item in data["fields"]
        )
        return cls(
            format=data["format"],
            file_size=data["file_size"],
            chunk=chunk,
            record=record,
            record_id=data["record_id"],
            event=data["event"],
            fields=fields,
            templates=tuple(TemplateClaim(**item) for item in data["templates"]),
        )


@dataclass(frozen=True)
class VerificationMismatch:
    path: str
    expected: Any
    actual: Any


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    mismatches: tuple[VerificationMismatch, ...] = field(default_factory=tuple)
    read_ranges: tuple[ByteRange, ...] = field(default_factory=tuple)
    proof: EventProof | None = None


class _RangeCheckingReader:
    def __init__(self, fh: BinaryIO, allowed_ranges: tuple[tuple[int, int], ...]):
        self.fh = fh
        self.allowed_ranges = tuple(sorted(allowed_ranges))
        self.read_ranges: set[tuple[int, int]] = set()
        self._offset = 0

    def allow(self, offset: int, length: int) -> None:
        self.allowed_ranges = tuple(sorted((*self.allowed_ranges, (offset, length))))

    def read_range(self, offset: int, length: int) -> bytes:
        self.seek(offset)
        return self.read(length)

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence != 0:
            raise ValueError('Only absolute seeks are supported during proof verification')
        self._offset = offset
        self.fh.seek(offset)
        return offset

    def tell(self) -> int:
        return self._offset

    def read(self, length: int = -1) -> bytes:
        if length == -1:
            raise ValueError('Unbounded reads are not allowed during proof verification')
        end = self._offset + length
        if not any(
            start <= self._offset and end <= start + range_length for start, range_length in self.allowed_ranges
        ):
            raise ValueError(f'Read outside proof ranges: {self._offset}:{length}')
        self.fh.seek(self._offset)
        data = self.fh.read(length)
        if len(data) != length:
            raise EOFError('Short read while verifying EVTX proof')
        self.read_ranges.add((self._offset, length))
        self._offset = end
        return data


def normalize_value(value: Any) -> Any:
    if isinstance(value, BxmlSub):
        return normalize_value(value.get())
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [normalize_value(item) for item in value]
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {key: normalize_value(item) for key, item in value.items()}
    return value


def build_event_proofs(fh: BinaryIO, path: Path | None = None) -> tuple[EventProof, ...]:
    fh.seek(0, 2)
    file_size = fh.tell()
    fh.seek(0)
    header = c_evtx.EVTX_HEADER(fh)
    fh.read(header.header_block_size - len(c_evtx.EVTX_HEADER))
    proofs: list[EventProof] = []
    chunk_offset = header.header_block_size

    while True:
        chunk_data = fh.read(CHUNK_SIZE)
        if len(chunk_data) != CHUNK_SIZE:
            break
        try:
            chunk = ElfChnk(chunk_data, path, chunk_offset)
            for event, sources, record, record_chunk_offset in chunk.read_with_sources():
                record_offset = chunk_offset + record_chunk_offset
                record_data = chunk_data[record_chunk_offset : record_chunk_offset + record.size]
                template_claims = _collect_template_claims(chunk_data, sources)
                field_sources = tuple(
                    _build_field_source(chunk_data, event, field_name, sources) for field_name in event
                )
                proofs.append(
                    EventProof(
                        file_size=file_size,
                        chunk=ByteRange.from_data(chunk_data, chunk_offset),
                        record=ByteRange.from_data(record_data, record_offset),
                        record_id=record.record_id,
                        event={key: normalize_value(value) for key, value in event.items()},
                        fields=field_sources,
                        templates=template_claims,
                    )
                )
        except MalformedElfChnkException:
            pass
        chunk_offset += CHUNK_SIZE

    return tuple(proofs)


def verify_event_proof(fh: BinaryIO, proof_data: EventProof | dict[str, Any]) -> VerificationResult:
    proof = proof_data if isinstance(proof_data, EventProof) else EventProof.from_dict(proof_data)
    fh.seek(0, 2)
    actual_file_size = fh.tell()
    mismatches: list[VerificationMismatch] = []
    if actual_file_size != proof.file_size:
        mismatches.append(VerificationMismatch("file_size", proof.file_size, actual_file_size))

    ranges = _proof_ranges(proof)
    reader = _RangeCheckingReader(fh, ranges)
    chunk_hasher = hashlib.sha256()
    chunk_hash_step = 4096
    for chunk_part_offset in range(0, proof.chunk.length, chunk_hash_step):
        part_length = min(chunk_hash_step, proof.chunk.length - chunk_part_offset)
        reader.allow(proof.chunk.offset + chunk_part_offset, part_length)
        chunk_hasher.update(reader.read_range(proof.chunk.offset + chunk_part_offset, part_length))
    actual_chunk_hash = chunk_hasher.hexdigest()
    if actual_chunk_hash != proof.chunk.sha256:
        mismatches.append(VerificationMismatch("chunk.sha256", proof.chunk.sha256, actual_chunk_hash))

    actual = _rebuild_proof_from_chunk(proof, reader, actual_chunk_hash)
    mismatches.extend(_compare_proof(proof, actual))
    return VerificationResult(
        valid=not mismatches,
        mismatches=tuple(mismatches),
        read_ranges=tuple(_read_range_claims(reader)),
        proof=actual,
    )


def _rebuild_proof_from_chunk(
    proof: EventProof, reader: _RangeCheckingReader, actual_chunk_hash: str
) -> EventProof:
    record_start = proof.record.offset - proof.chunk.offset
    record_data = reader.read_range(proof.record.offset, proof.record.length)
    actual_record = ByteRange.from_data(record_data, proof.record.offset)
    chunk = ElfChnk(_GuardedChunkView(reader, proof.chunk.offset), None, proof.chunk.offset)
    event, sources, record, record_chunk_offset = next(chunk.read_with_sources_at(record_start))
    chunk_data = _GuardedChunkBytes(reader, proof.chunk.offset)
    template_claims = _collect_template_claims(chunk_data, sources)
    fields = tuple(_build_field_source(chunk_data, event, field_name, sources) for field_name in event)
    return EventProof(
        file_size=proof.file_size,
        chunk=ByteRange(proof.chunk.offset, proof.chunk.length, actual_chunk_hash),
        record=actual_record,
        record_id=record.record_id,
        event={key: normalize_value(value) for key, value in event.items()},
        fields=fields,
        templates=template_claims,
    )


class _GuardedChunkView:
    def __init__(self, reader: _RangeCheckingReader, chunk_offset: int):
        self.reader = reader
        self.chunk_offset = chunk_offset
        self.seek(0)

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence != 0:
            raise ValueError('Only absolute seeks are supported during proof verification')
        self.reader.seek(self.chunk_offset + offset)
        return offset

    def tell(self) -> int:
        return self.reader.tell() - self.chunk_offset

    def read(self, length: int = -1) -> bytes:
        return self.reader.read(length)


def _read_range_claims(reader: _RangeCheckingReader) -> tuple[ByteRange, ...]:
    return tuple(
        ByteRange(
            offset=offset,
            length=length,
            sha256=hashlib.sha256(reader.read_range(offset, length)).hexdigest(),
        )
        for offset, length in sorted(reader.read_ranges)
    )


class _GuardedChunkBytes:
    def __init__(self, reader: _RangeCheckingReader, chunk_offset: int):
        self.reader = reader
        self.chunk_offset = chunk_offset

    def __getitem__(self, item: slice) -> bytes:
        if item.step is not None:
            raise ValueError('Only contiguous byte slices are supported during proof verification')
        return self.reader.read_range(self.chunk_offset + item.start, item.stop - item.start)


def _proof_ranges(proof: EventProof) -> tuple[tuple[int, int], ...]:
    ranges = {
        (proof.record.offset, proof.record.length),
    }
    for template in proof.templates:
        ranges.add((proof.chunk.offset + template.offset, template.length))
    for field in proof.fields:
        if field.value_range:
            ranges.add((proof.chunk.offset + field.value_range.offset, field.value_range.length))
        for name in field.name_sources:
            ranges.add((proof.chunk.offset + name.offset, name.length))
    return tuple(ranges)


def _collect_template_claims(
    chunk_data: bytes | _GuardedChunkBytes, sources: dict[str, Any]
) -> tuple[TemplateClaim, ...]:
    claims: dict[int, TemplateClaim] = {}
    for source in sources.values():
        template_source = source["template"]
        if template_source is None or template_source.offset in claims:
            continue
        claims[template_source.offset] = _template_claim(chunk_data, template_source)
    return tuple(claims[offset] for offset in sorted(claims))


def _build_field_source(
    chunk_data: bytes | _GuardedChunkBytes, event: dict[str, Any], field_name: str, sources: dict[str, Any]
) -> FieldSource:
    source = sources[field_name]
    value_source: BxmlValueSource | None = source["value_source"]
    template_source: BxmlTemplateSource | None = source["template"]
    return FieldSource(
        name=field_name,
        value=normalize_value(event[field_name]),
        value_range=_value_claim(chunk_data, value_source) if value_source else None,
        template=_template_claim(chunk_data, template_source) if template_source else None,
        name_sources=tuple(_name_claim(item) for item in source["name_sources"]),
    )


def _name_claim(source: BxmlNameSource) -> NameClaim:
    return NameClaim(name=source.name, offset=source.offset, length=source.length)


def _template_claim(chunk_data: bytes | _GuardedChunkBytes, source: BxmlTemplateSource) -> TemplateClaim:
    data = chunk_data[source.offset : source.offset + source.length]
    return TemplateClaim(
        reference_offset=source.reference_offset,
        offset=source.offset,
        length=source.length,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _value_claim(chunk_data: bytes | _GuardedChunkBytes, source: BxmlValueSource) -> ValueClaim:
    data = chunk_data[source.offset : source.offset + source.length]
    return ValueClaim(
        offset=source.offset,
        length=source.length,
        type_id=source.type_id,
        is_array=source.is_array,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _compare_proof(expected: EventProof, actual: EventProof) -> tuple[VerificationMismatch, ...]:
    mismatches: list[VerificationMismatch] = []
    for path, expected_value, actual_value in _flatten_proof(expected, actual):
        if expected_value != actual_value:
            mismatches.append(VerificationMismatch(path, expected_value, actual_value))
    mismatches.extend(_compare_field_sources(expected.fields, actual.fields))
    return tuple(mismatches)


def _flatten_proof(expected: EventProof, actual: EventProof) -> tuple[tuple[str, Any, Any], ...]:
    items = [
        ("record_id", expected.record_id, actual.record_id),
        ("record.sha256", expected.record.sha256, actual.record.sha256),
        ("record.offset", expected.record.offset, actual.record.offset),
        ("record.length", expected.record.length, actual.record.length),
        ("event", expected.event, actual.event),
        ("templates", _claim_tuples(expected.templates), _claim_tuples(actual.templates)),
    ]
    return tuple(items)


def _claim_tuples(claims: tuple[TemplateClaim, ...]) -> tuple[tuple[Any, ...], ...]:
    return tuple((item.reference_offset, item.offset, item.length, item.sha256) for item in claims)


def _field_tuples(claims: tuple[FieldSource, ...]) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        (
            item.name,
            item.value,
            _value_tuple(item.value_range),
            _template_tuple(item.template),
            tuple((name.name, name.offset, name.length) for name in item.name_sources),
        )
        for item in claims
    )


def _compare_field_sources(
    expected: tuple[FieldSource, ...], actual: tuple[FieldSource, ...]
) -> list[VerificationMismatch]:
    actual_by_name = {field.name: field for field in actual}
    mismatches: list[VerificationMismatch] = []
    for expected_field in expected:
        actual_field = actual_by_name.get(expected_field.name)
        field_path = f"fields.{expected_field.name}"
        if actual_field is None:
            mismatches.append(VerificationMismatch(field_path, _field_tuple(expected_field), None))
            continue
        expected_tuple = _field_tuple(expected_field)
        actual_tuple = _field_tuple(actual_field)
        if expected_tuple != actual_tuple:
            mismatches.append(VerificationMismatch(field_path, expected_tuple, actual_tuple))
    return mismatches


def _field_tuple(field: FieldSource) -> tuple[Any, ...]:
    return _field_tuples((field,))[0]


def _value_tuple(claim: ValueClaim | None) -> tuple[Any, ...] | None:
    if claim is None:
        return None
    return (claim.offset, claim.length, claim.type_id, claim.is_array, claim.sha256)


def _template_tuple(claim: TemplateClaim | None) -> tuple[Any, ...] | None:
    if claim is None:
        return None
    return (claim.reference_offset, claim.offset, claim.length, claim.sha256)
