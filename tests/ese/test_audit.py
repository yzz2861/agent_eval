from __future__ import annotations

from types import SimpleNamespace

from dissect.database.ese.audit import FieldStatus
from dissect.database.ese.cursor import Cursor
from dissect.database.ese.c_ese import FIELDFLAG, PAGE_FLAG, JET_coltyp
from dissect.database.ese.record import Record
from dissect.database.ese.table import Column, Table


class FakeCatalogRecord:
    def __init__(self, version: bytes, default: bytes | None = None):
        self.version = version
        self.default = default

    def get(self, name: str, raw: bool = False) -> bytes | None:
        if name == "Version":
            return self.version
        if name == "DefaultValue":
            return self.default
        return None


class FakeNode:
    def __init__(self, key: bytes, data: bytes):
        self.key = key
        self.data = memoryview(data)
        self.tag = SimpleNamespace(page=SimpleNamespace(flags=PAGE_FLAG.NewRecordFormat))


class FakePage:
    is_branch = False

    def __init__(self, node: FakeNode):
        self.node_count = 1
        self._node = node

    def node(self, index: int) -> FakeNode:
        assert index == 0
        return self._node


def make_table(version: bytes, *, with_default: bool) -> Table:
    db = SimpleNamespace(has_small_pages=True, impacket_compat=False)
    default = b"\x07\x00" if with_default else None
    catalog_record = FakeCatalogRecord(version)
    current_record = FakeCatalogRecord(version, default)
    table = Table(db, f"table-{version.hex()}", 7, record=catalog_record)

    for column in [
        Column(1, "Id", JET_coltyp.Long, FIELDFLAG.NotNull),
        Column(2, "Current", JET_coltyp.Short, FIELDFLAG(0), record=current_record),
        Column(128, "EmptyVariable", JET_coltyp.Text, FIELDFLAG(0)),
        Column(256, "EmptyTagged", JET_coltyp.LongText, FIELDFLAG(0)),
    ]:
        table._add_column(column)

    return table


def make_explicit_null_record_data() -> bytes:
    fixed_data = (1).to_bytes(4, "little", signed=True)
    current_data = (0).to_bytes(2, "little", signed=True)
    null_bitmap = bytes([0b00000010])
    variable_offsets = (0x8000).to_bytes(2, "little")
    tagged_null = ((0x2008 << 16) | 256).to_bytes(4, "little")
    tagged_unknown = ((0x4009 << 16) | 259).to_bytes(4, "little")
    tagged_null_header = bytes([0x20])
    tagged_unknown_data = b"unknown tagged value"
    end_of_fixed_data = 4 + 4 + len(current_data) + len(null_bitmap)

    return (
        bytes([2, 128, *end_of_fixed_data.to_bytes(2, "little")])
        + fixed_data
        + current_data
        + null_bitmap
        + variable_offsets
        + tagged_null
        + tagged_unknown
        + tagged_null_header
        + tagged_unknown_data
    )


def make_undefined_dependencies_record_data() -> bytes:
    fixed_data = (1).to_bytes(4, "little", signed=True)
    current_data = (0).to_bytes(2, "little", signed=True)
    null_bitmap = bytes([0b00000010])
    variable_offsets = b"".join(
        [
            (0x8000).to_bytes(2, "little"),
            (0x8000).to_bytes(2, "little"),
            (0x8000).to_bytes(2, "little"),
        ]
    )
    tagged_unknown = ((0x4004 << 16) | 259).to_bytes(4, "little")
    tagged_unknown_header = bytes([0x00])
    tagged_unknown_data = b"unknown tagged value"
    end_of_fixed_data = 4 + 4 + len(current_data) + len(null_bitmap)

    return (
        bytes([2, 130, *end_of_fixed_data.to_bytes(2, "little")])
        + fixed_data
        + current_data
        + null_bitmap
        + variable_offsets
        + tagged_unknown
        + tagged_unknown_header
        + tagged_unknown_data
    )


def make_absent_record_data() -> bytes:
    fixed_data = (1).to_bytes(4, "little", signed=True)
    null_bitmap = bytes([0b00000000])
    variable_offsets = (0x8000).to_bytes(2, "little")
    tagged_unknown = ((0x4004 << 16) | 259).to_bytes(4, "little")
    tagged_unknown_header = bytes([0x00])
    tagged_unknown_data = b"unknown tagged value"
    end_of_fixed_data = 4 + 4 + len(null_bitmap)

    return (
        bytes([1, 128, *end_of_fixed_data.to_bytes(2, "little")])
        + fixed_data
        + null_bitmap
        + variable_offsets
        + tagged_unknown
        + tagged_unknown_header
        + tagged_unknown_data
    )


def test_record_audit_binds_status_to_catalog_and_visible_record() -> None:
    table = make_table(b"catalog-v1", with_default=False)
    record = Record(table, FakeNode(b"explicit-null-key", make_explicit_null_record_data()))

    audit = record.audit()

    assert audit.catalog_version == b"catalog-v1"
    assert audit.record is record
    assert [(entry.name, entry.identifier, entry.column_kind, entry.status) for entry in audit] == [
        ("Id", 1, "fixed", FieldStatus.PRESENT),
        ("Current", 2, "fixed", FieldStatus.NULL),
        ("EmptyVariable", 128, "variable", FieldStatus.NULL),
        ("EmptyTagged", 256, "tagged", FieldStatus.NULL),
        (None, 259, "tagged", FieldStatus.MISSING_DEFINITION),
    ]

    current = audit.get("Current")
    assert current.value is None
    assert current.raw_value is None
    assert current.default_value is None
    missing = next(entry for entry in audit if entry.status == FieldStatus.MISSING_DEFINITION)
    assert missing.missing_dependencies == ("column definition 259",)


def test_same_empty_field_demonstrates_absent_and_default_across_catalog_versions() -> None:
    v1_table = make_table(b"catalog-v1", with_default=False)
    v1_record = Record(v1_table, FakeNode(b"absent-key", make_absent_record_data()))
    v1_audit = v1_record.audit()

    v2_table = make_table(b"catalog-v2", with_default=True)
    v2_record = Record(v2_table, FakeNode(b"default-key", make_absent_record_data()))
    v2_audit = v2_record.audit()

    assert v1_audit.catalog_version == b"catalog-v1"
    assert v1_audit.get("Current").status == FieldStatus.ABSENT
    assert v1_audit.get("Current").value is None
    assert v1_record.get("Current") is None

    current = v2_audit.get("Current")
    assert v2_audit.catalog_version == b"catalog-v2"
    assert current.status == FieldStatus.DEFAULT
    assert current.raw_value is None
    assert current.value == 7
    assert current.default_value == b"\x07\x00"
    assert v2_record.get("Current") == 7


def test_table_audit_keeps_existing_read_result_compatible() -> None:
    table = make_table(b"catalog-v2", with_default=True)
    record = Record(table, FakeNode(b"record-key", make_absent_record_data()))
    table.records = lambda: iter([record])

    audits = list(table.audit_records())

    assert len(audits) == 1
    assert audits[0].record is record
    assert audits[0].get("Current").status == FieldStatus.DEFAULT
    assert record.get("Current") == 7


def test_record_audit_marks_user_defined_default_as_default() -> None:
    table = make_table(b"catalog-v2", with_default=False)
    current = table.column("Current")
    current.flags = FIELDFLAG.UserDefinedDefault
    record = Record(table, FakeNode(b"user-default-key", make_absent_record_data()))

    audit = record.audit().get("Current")

    assert audit.status == FieldStatus.DEFAULT
    assert audit.raw_value is None
    assert audit.value is None
    assert audit.default_value is None


def test_record_audit_reports_missing_dependency_columns_for_each_column_range() -> None:
    table = make_table(b"catalog-v1", with_default=False)
    record = Record(table, FakeNode(b"missing-definitions-key", make_undefined_dependencies_record_data()))

    missing = [entry for entry in record.audit() if entry.status == FieldStatus.MISSING_DEFINITION]

    assert [(entry.identifier, entry.column_kind, entry.missing_dependencies) for entry in missing] == [
        (129, "variable", ("column definition 129",)),
        (130, "variable", ("column definition 130",)),
        (259, "tagged", ("column definition 259",)),
    ]


def test_record_audit_reports_missing_fixed_dependency_column() -> None:
    table = make_table(b"catalog-v1", with_default=False)
    table._column_id_map.pop(2)
    table.columns = [column for column in table.columns if column.name != "Current"]
    table._column_name_map.pop("Current")
    record = Record(table, FakeNode(b"missing-fixed-key", make_explicit_null_record_data()))

    missing = [
        entry
        for entry in record.audit()
        if entry.status == FieldStatus.MISSING_DEFINITION and entry.column_kind == "fixed"
    ]

    assert [(entry.identifier, entry.column_kind, entry.missing_dependencies) for entry in missing] == [
        (2, "fixed", ("column definition 2",)),
    ]


def test_cursor_audit_uses_current_visible_record() -> None:
    table = make_table(b"catalog-v1", with_default=False)
    node = FakeNode(b"cursor-key", make_explicit_null_record_data())
    index = SimpleNamespace(root=FakePage(node), table=table, db=table.db, is_primary=True)
    cursor = Cursor(index)

    assert cursor.record_audit().record == cursor.record()
    assert cursor.record_audit().get("Current").status == FieldStatus.NULL
    assert [audit.record for audit in cursor.audit_records()] == [cursor.record()]
