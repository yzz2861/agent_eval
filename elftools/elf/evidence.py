"""Forensic comparison helpers for parsed ELF evidence records.

The helpers in this module keep three kinds of equality separate:

* parsed numeric values can be equivalent even when their endian-specific
  raw encodings differ;
* raw records are occurrences at a concrete file range, so duplicate sections
  remain separate evidence;
* unknown or undecodable fields are reported as indeterminate rather than being
  coerced to an integer or compared by their raw bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..common.utils import stream_read
from .descriptions import describe_note, describe_note_gnu_properties, describe_sh_type
from .sections import NoteSection

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Literal

    from .elffile import ELFFile


INDETERMINATE: None = None


@dataclass(frozen=True)
class EvidenceRecord:
    """One independently locatable NOTE/property record.

    ``offset`` and ``size`` identify the complete raw note in the source ELF.
    """

    source: str
    section_name: str
    section_type: str | int
    section_description: str
    note_type: str | int
    record_type: str | int
    meaning: str
    offset: int
    size: int
    raw: bytes
    endian: Literal["big", "little"]
    numeric_value: int | None = None
    value_determinate: bool = False
    record_index: int = 0
    section_offset: int = 0
    section_size: int = 0

    @property
    def endianness(self) -> Literal["big", "little"]:
        return self.endian

    @property
    def file_range(self) -> tuple[int, int]:
        """Half-open ``(offset, offset + size)`` range in the source file."""
        return (self.offset, self.offset + self.size)

    @property
    def raw_range(self) -> tuple[int, int]:
        """Inclusive-style raw location as pyelftools' ``(n_offset, n_size)``."""
        return (self.offset, self.size)

    @property
    def identity(self) -> tuple[str, int, int, str | int, int]:
        return (self.source, self.offset, self.size, self.record_type,
                self.record_index)

    @property
    def key(self) -> tuple[str, int, int, str | int, int]:
        return self.identity

    def matches_numeric_value(self, value: int) -> bool:
        return self.value_determinate and self.numeric_value == value

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "section_name": self.section_name,
            "section_type": self.section_type,
            "section_description": self.section_description,
            "note_type": self.note_type,
            "record_type": self.record_type,
            "meaning": self.meaning,
            "offset": self.offset,
            "size": self.size,
            "file_range": self.file_range,
            "raw_range": self.raw_range,
            "raw": self.raw,
            "endian": self.endian,
            "numeric_value": self.numeric_value,
            "value_determinate": self.value_determinate,
            "record_index": self.record_index,
            "section_offset": self.section_offset,
            "section_size": self.section_size,
        }


@dataclass(frozen=True)
class EvidenceComparison:
    """Pairwise comparison without collapsing orthogonal distinctions."""

    left: EvidenceRecord
    right: EvidenceRecord
    same_identity: bool
    same_source: bool
    same_raw_range: bool
    raw_bytes_equal: bool
    values_equivalent: bool | None
    meanings_equal: bool

    @property
    def numeric_equivalent(self) -> bool:
        return self.values_equivalent is True

    @property
    def numeric_values_differ(self) -> bool:
        return self.values_equivalent is False

    @property
    def value_indeterminate(self) -> bool:
        return self.values_equivalent is None

    @property
    def raw_encoding_differs(self) -> bool:
        return not self.raw_bytes_equal

    @property
    def distinct_raw_record(self) -> bool:
        return not self.same_identity

    @property
    def labels(self) -> frozenset[str]:
        labels: set[str] = set()
        if self.same_identity:
            labels.add("same_evidence")
        else:
            labels.add("independent_evidence")
        if self.values_equivalent is True:
            labels.add("numeric_value_equivalent")
        elif self.values_equivalent is False:
            labels.add("numeric_value_different")
        else:
            labels.add("parsed_field_indeterminate")
        labels.add("raw_bytes_equal" if self.raw_bytes_equal
                   else "raw_bytes_different")
        labels.add("same_raw_range" if self.same_raw_range
                   else "different_raw_range")
        return frozenset(labels)


@dataclass
class EvidenceReport:
    records: list[EvidenceRecord] = field(default_factory=list)

    @property
    def independent_count(self) -> int:
        return count_independent_evidence(self.records)

    def __len__(self) -> int:
        return self.independent_count

    def meanings(self) -> list[str]:
        return [record.meaning for record in self.records]

    def numeric_groups(self) -> dict[tuple[str | int, int], list[EvidenceRecord]]:
        groups: dict[tuple[str | int, int], list[EvidenceRecord]] = {}
        for record in self.records:
            if not record.value_determinate or record.numeric_value is None:
                continue
            group_key = (record.record_type, record.numeric_value)
            groups.setdefault(group_key, []).append(record)
        return groups

    def indeterminate(self) -> list[EvidenceRecord]:
        return [record for record in self.records
                if not record.value_determinate]


def _as_elf(obj: ELFFile | Any) -> ELFFile:
    from io import BytesIO

    from .elffile import ELFFile

    if isinstance(obj, ELFFile):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return ELFFile(BytesIO(bytes(obj)))
    return ELFFile(obj)


def collect_evidence(
    obj: ELFFile | Any, source_id: str | None = None
) -> list[EvidenceRecord]:
    """Collect NOTE/GNU-property evidence from an ELF stream or ``ELFFile``."""
    elf = _as_elf(obj)
    if source_id is None:
        stream_name = getattr(elf.stream, "name", None)
        source_id = stream_name or f"<memory:{id(elf.stream):x}>"
    endian: Literal["big", "little"] = (
        "little" if elf.little_endian else "big"
    )
    records: list[EvidenceRecord] = []

    for section in elf.iter_sections():
        if not isinstance(section, NoteSection):
            continue

        section_type = section["sh_type"]
        section_description = describe_sh_type(section_type)

        for note in section.iter_notes():
            offset = int(note["n_offset"])
            size = int(note["n_size"])
            raw = stream_read(elf.stream, offset, size)
            note_type = note["n_type"]
            base: dict[str, Any] = {
                "source": source_id,
                "section_name": section.name,
                "section_type": section_type,
                "section_description": section_description,
                "note_type": note_type,
                "offset": offset,
                "size": size,
                "raw": raw,
                "endian": endian,
                "section_offset": int(section["sh_offset"]),
                "section_size": int(section["sh_size"]),
            }

            properties = note["n_desc"]
            if (note_type == "NT_GNU_PROPERTY_TYPE_0"
                    and isinstance(properties, list) and properties):
                for index, prop in enumerate(properties):
                    data = prop["pr_data"]
                    determinate = isinstance(data, int) and not isinstance(data, bool)
                    meaning = describe_note_gnu_properties(
                        [prop], elf["e_machine"]
                    ).strip()
                    records.append(EvidenceRecord(
                        **base,
                        record_type=prop["pr_type"],
                        meaning=meaning,
                        numeric_value=int(data) if determinate else None,
                        value_determinate=determinate,
                        record_index=index,
                    ))
            else:
                desc = note["n_desc"]
                determinate = isinstance(desc, int) and not isinstance(desc, bool)
                records.append(EvidenceRecord(
                    **base,
                    record_type=note_type,
                    meaning=describe_note(note, elf["e_machine"]).strip(),
                    numeric_value=int(desc) if determinate else None,
                    value_determinate=determinate,
                ))

    return records


def build_report(
    obj: ELFFile | Any, source_id: str | None = None
) -> EvidenceReport:
    return EvidenceReport(collect_evidence(obj, source_id))


def count_independent_evidence(records: Iterable[EvidenceRecord]) -> int:
    return len({record.key for record in records})


def compare_evidence(left: EvidenceRecord,
                      right: EvidenceRecord) -> EvidenceComparison:
    same_source = left.source == right.source
    same_raw_range = same_source and left.raw_range == right.raw_range
    same_identity = left.key == right.key
    raw_bytes_equal = left.raw == right.raw

    if left.value_determinate and right.value_determinate:
        values_equivalent: bool | None = (
            left.numeric_value == right.numeric_value
        )
    else:
        values_equivalent = INDETERMINATE

    return EvidenceComparison(
        left=left,
        right=right,
        same_identity=same_identity,
        same_source=same_source,
        same_raw_range=same_raw_range,
        raw_bytes_equal=raw_bytes_equal,
        values_equivalent=values_equivalent,
        meanings_equal=left.meaning == right.meaning,
    )


def compare_all(left: Iterable[EvidenceRecord],
                right: Iterable[EvidenceRecord]) -> list[EvidenceComparison]:
    """Compare records in order; fixture/test code is expected to align them."""
    left_records = list(left)
    right_records = list(right)
    if len(left_records) != len(right_records):
        raise ValueError("compare_all requires equally sized record lists")
    return [compare_evidence(a, b)
            for a, b in zip(left_records, right_records)]
