from __future__ import annotations

import io

import pytest

from dissect.cstruct import DeclarationSet, Presence, cstruct
from dissect.cstruct.declarative import Struct, field, uint16

DEFINITION = """
struct RecordV1 {
    uint16 serial;
    uint16 a;
    uint16 b;
    uint16 c;
    uint16 d;
};
struct RecordV2 {
    uint16 serial;
    uint16 a;
    uint16 b;
    uint16 c;
    uint16 d;
    uint16 extra;
};
"""

OLD_RECORD = bytes(10)
NEW_RECORD = bytes(12)


@pytest.fixture
def cs() -> cstruct:
    return cstruct(DEFINITION)


def test_same_zero_value_has_different_evidence(cs: cstruct) -> None:
    record, evidence = cs.RecordV2.read_with_evidence(OLD_RECORD)

    assert isinstance(record, cs.RecordV2)
    assert record.serial == 0
    assert record.extra == 0

    assert evidence["serial"].presence is Presence.READ
    assert evidence["serial"].is_read
    assert evidence["serial"].raw == b"\x00\x00"
    assert evidence["serial"].default_source is None

    assert evidence["extra"].presence is Presence.ABSENT
    assert evidence["extra"].defaulted
    assert evidence["extra"].raw == b""
    assert evidence["extra"].default_source == "absence"

    assert evidence.defaulted == {"extra": evidence["extra"]}
    assert evidence.defaults == ("extra",)


def test_truncated_field_is_distinct_from_absence(cs: cstruct) -> None:
    record, evidence = cs.RecordV2.read_with_evidence(NEW_RECORD[:-1])

    assert record.extra == 0
    assert evidence["extra"].presence is Presence.TRUNCATED
    assert evidence["extra"].is_truncated
    assert evidence["extra"].available == 1
    assert evidence["extra"].size == 2
    assert evidence["extra"].raw == b"\x00"
    assert evidence["extra"].default_source == "truncation"
    assert not evidence.complete


def test_known_generation_derives_default_without_consuming_bytes(cs: cstruct) -> None:
    record, evidence = cs.RecordV2.read_with_evidence(
        NEW_RECORD,
        generation=1,
        field_generations={"extra": 2},
        defaults={"extra": 9},
    )

    assert record.extra == 9
    assert evidence["extra"].presence is Presence.DERIVED
    assert evidence["extra"].is_derived
    assert evidence["extra"].value == 9
    assert evidence["extra"].default == 9
    assert evidence["extra"].default_source == "generation"
    assert evidence["extra"].consumed == 0
    assert "introduced in generation 2" in evidence["extra"].reason
    assert evidence.generation == 1


def test_declarative_field_generation_metadata() -> None:
    class Record(Struct, generation=2):
        serial: uint16
        extra: field(uint16, introduced=2, default=0xBEEF)

    record, evidence = Record.read_with_evidence(bytes(2), generation=1)

    assert record.serial == 0
    assert record.extra == 0xBEEF
    assert evidence["extra"].is_derived
    assert evidence["extra"].introduced == 2
    assert evidence["extra"].default_source == "generation"


def test_declaration_set_records_selection_basis(cs: cstruct) -> None:
    declarations = DeclarationSet("Record", {1: cs.RecordV1, 2: cs.RecordV2})

    old, old_evidence = declarations.read_with_evidence(OLD_RECORD)
    assert old.__class__ is cs.RecordV1
    assert old_evidence.declaration == "RecordV1"
    assert old_evidence.declaration_generation == 1
    assert old_evidence.selection == "size"
    assert "exactly matches declaration generation 1" in old_evidence.basis

    new, new_evidence = declarations.read_with_evidence(NEW_RECORD)
    assert new.__class__ is cs.RecordV2
    assert new_evidence.declaration == "RecordV2"
    assert new_evidence.declaration_generation == 2

    short, short_evidence = declarations.read_with_evidence(NEW_RECORD[:-1])
    assert short.__class__ is cs.RecordV2
    assert short_evidence.declaration == "RecordV2"
    assert short_evidence["extra"].is_truncated
    assert "best matches declaration generation 2" in short_evidence.basis

    explicit, explicit_evidence = declarations.read_with_evidence(OLD_RECORD, generation=1)
    assert explicit.__class__ is cs.RecordV1
    assert explicit_evidence.selection == "generation"
    assert explicit_evidence.basis == "explicitly requested generation 1"


def test_evidence_object_is_a_normal_structure(cs: cstruct) -> None:
    record, evidence = cs.RecordV2.read_with_evidence(OLD_RECORD)

    assert record.__evidence__ is evidence
    assert isinstance(record, cs.RecordV2)
    assert bytes(record) == NEW_RECORD
    assert record.a == 0
    assert record.d == 0
    assert list(record.__values__) == list(cs.RecordV2.__members__)


def test_evidence_through_other_read_interfaces(cs: cstruct) -> None:
    value, evidence = cs.RecordV2.reads(OLD_RECORD, evidence=True)
    assert value.extra == 0
    assert evidence["extra"].is_absent

    value, evidence = cs.RecordV2.read(io.BytesIO(OLD_RECORD), evidence=True)
    assert value.extra == 0
    assert evidence["extra"].is_absent

    value, evidence = cs.read("RecordV2", OLD_RECORD, evidence=True)
    assert value.extra == 0
    assert evidence["extra"].is_absent

    value, evidence = cs.read_with_evidence("RecordV2", OLD_RECORD)
    assert value.extra == 0
    assert evidence["extra"].is_absent


def test_normal_read_stays_strict_and_strict_evidence_raises(cs: cstruct) -> None:
    with pytest.raises(EOFError):
        cs.RecordV2(OLD_RECORD)

    with pytest.raises(EOFError):
        cs.RecordV2.read_with_evidence(OLD_RECORD, strict=True)


def test_nested_evidence(cs: cstruct) -> None:
    cs.load("""
    struct Inner {
        uint16 x;
        uint16 y;
    };
    struct Outer {
        uint16 a;
        Inner inner;
    };
    """)

    record, evidence = cs.Outer.read_with_evidence(bytes(5))

    assert record.a == 0
    assert record.inner.x == 0
    assert record.inner.y == 0
    assert evidence["inner"].is_truncated
    assert evidence["inner"].children["x"].is_read
    assert evidence["inner"].children["y"].is_truncated


def test_set_field_metadata_on_loaded_declaration(cs: cstruct) -> None:
    cs.RecordV2.set_field_metadata("extra", introduced=2, default={1: 0, 2: 7})

    record, evidence = cs.RecordV2.read_with_evidence(NEW_RECORD, generation=1)
    assert record.extra == 0
    assert evidence["extra"].is_derived
    assert evidence["extra"].introduced == 2

    record, evidence = cs.RecordV2.read_with_evidence(NEW_RECORD, generation=2)
    assert record.extra == 0
    assert evidence["extra"].is_read


def test_read_aliases_return_object_and_evidence(cs: cstruct) -> None:
    record, evidence = cs.RecordV2.read_audited(OLD_RECORD)
    assert record.extra == 0
    assert evidence["extra"].is_absent

    record, evidence = cs.RecordV2.read_with_presence(OLD_RECORD)
    assert record.extra == 0
    assert evidence["extra"].is_absent
    assert record.__presence__ is evidence


def test_newer_declaration_infers_generation_default_for_tail() -> None:
    class NewRecord(Struct, generation=2):
        a: uint16
        extra: uint16

    record, evidence = NewRecord.read_with_evidence(bytes(2), generation=1)

    assert record.a == 0
    assert record.extra == 0
    assert evidence["extra"].is_derived
    assert evidence["extra"].introduced == 2
    assert evidence["extra"].consumed == 0
