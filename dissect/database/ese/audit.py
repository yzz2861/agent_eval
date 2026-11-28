from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from dissect.database.ese.c_ese import FIELDFLAG

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.record import Record, RecordData
    from dissect.database.ese.table import Column, Table


class FieldStatus(str, Enum):
    """Describes how an ESE record obtained the value for a column."""

    PRESENT = "present"
    NULL = "null"
    DEFAULT = "default"
    ABSENT = "absent"
    MISSING_DEFINITION = "missing_definition"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ColumnAudit:
    """Column-level evidence for one record field.

    Args:
        name: The approved column name, or ``None`` if the record references a column identifier that is not in the
            table definition.
        identifier: The ESE column identifier in the record or table definition.
        column_kind: The identifier range the column belongs to: ``fixed``, ``variable`` or ``tagged``.
        status: How the value for this column was represented in or derived for this record.
        value: The parsed value compatible with :meth:`Record.get`.
        raw_value: The raw stored bytes, without applying a column default.
        default_value: The parsed catalog default for this column.
        record: The record this audit is bound to.
        missing_dependencies: Catalog dependencies required to interpret this column, when they are unavailable.
    """

    name: str | None
    identifier: int
    column_kind: str
    status: FieldStatus
    value: Any
    raw_value: Any
    default_value: Any
    record: Record
    missing_dependencies: tuple[str, ...] = ()


class RecordAudit:
    """Audit all approved columns and every record identifier that requires a column definition."""

    def __init__(self, record: Record):
        self.record = record
        self.table = record._table
        self.catalog_version = record._table.catalog_version
        self.columns = tuple(audit_record(record))

    def __iter__(self) -> Iterator[ColumnAudit]:
        yield from self.columns

    def __len__(self) -> int:
        return len(self.columns)

    def get(self, column_name: str) -> ColumnAudit:
        """Return the audit entry for an approved column name."""
        for column_audit in self.columns:
            if column_audit.name == column_name:
                return column_audit

        raise KeyError(f"No column with this name in table {self.table.name}: {column_name}")

    def as_dict(self) -> dict[str, ColumnAudit]:
        """Return audit entries keyed by approved column name."""
        return {column_audit.name: column_audit for column_audit in self.columns if column_audit.name is not None}


def audit_record(record: Record) -> Iterator[ColumnAudit]:
    """Yield column-level evidence for one visible ESE record."""
    data = record._data
    table = record._table
    seen_tagged_identifiers = set()

    for column in table.columns:
        if column.is_fixed:
            yield _audit_fixed_column(record, data, column)
        elif column.is_variable:
            yield _audit_variable_column(record, data, column)
        else:
            yield _audit_tagged_column(record, data, column)
            seen_tagged_identifiers.add(column.identifier)

    yield from _audit_undefined_fixed_columns(record, data)
    yield from _audit_undefined_variable_columns(record, data)
    yield from _audit_undefined_tagged_columns(record, data, seen_tagged_identifiers)


def _audit_fixed_column(record: Record, data: RecordData, column: Column) -> ColumnAudit:
    if data.header is None:
        return _unavailable_column(record, column, ("record header",))

    if column.identifier > data._last_fixed_id:
        return _absent_or_default_column(record, data, column)

    bit_idx_identifier = column.identifier - 1
    bitmap_offset, bitmap_shift = divmod(bit_idx_identifier, 8)
    if bitmap_offset >= len(data._fixed_null_bitmap):
        return _unavailable_column(record, column, (f"fixed null bitmap byte {bitmap_offset}",))

    is_null = bool(data._fixed_null_bitmap[bitmap_offset] & (1 << bitmap_shift))
    raw_value = None if is_null else data._get_fixed(column)
    return _build_column_audit(record, data, column, raw_value, FieldStatus.NULL if is_null else FieldStatus.PRESENT)


def _audit_variable_column(record: Record, data: RecordData, column: Column) -> ColumnAudit:
    if data.header is None:
        return _unavailable_column(record, column, ("record header",))

    if column.identifier > data._last_variable_id:
        return _absent_or_default_column(record, data, column)

    identifier_idx = column.identifier - 128
    if identifier_idx >= len(data._variable_offsets):
        return _unavailable_column(record, column, (f"variable offset {identifier_idx}",))

    is_null = bool(data._variable_offsets[identifier_idx] & 0x8000)
    raw_value = None if is_null else data._get_variable(column)
    return _build_column_audit(record, data, column, raw_value, FieldStatus.NULL if is_null else FieldStatus.PRESENT)


def _audit_tagged_column(record: Record, data: RecordData, column: Column) -> ColumnAudit:
    if data.header is None:
        return _unavailable_column(record, column, ("record header",))

    tag_index = data._find_tag_field_idx(column.identifier)
    if tag_index is None:
        return _absent_or_default_column(record, data, column)

    tag_field = data._get_tag_field(tag_index)
    raw_value = None if tag_field.is_null else data._get_tagged(column)[1]
    status = FieldStatus.NULL if tag_field.is_null else FieldStatus.PRESENT
    return _build_column_audit(record, data, column, raw_value, status)


def _audit_undefined_fixed_columns(record: Record, data: RecordData) -> Iterator[ColumnAudit]:
    if data.header is None:
        return

    for identifier in range(1, data._last_fixed_id + 1):
        if identifier not in record._table._column_id_map:
            yield _missing_definition_column(record, identifier, "fixed", (f"column definition {identifier}",))


def _audit_undefined_variable_columns(record: Record, data: RecordData) -> Iterator[ColumnAudit]:
    if data.header is None:
        return

    for identifier in range(128, data._last_variable_id + 1):
        if identifier not in record._table._column_id_map:
            yield _missing_definition_column(record, identifier, "variable", (f"column definition {identifier}",))


def _audit_undefined_tagged_columns(
    record: Record, data: RecordData, seen_identifiers: set[int]
) -> Iterator[ColumnAudit]:
    for tag_index in range(data._tagged_data_count):
        identifier = data._get_tag_field(tag_index).identifier
        if identifier not in seen_identifiers and identifier not in record._table._column_id_map:
            yield _missing_definition_column(record, identifier, "tagged", (f"column definition {identifier}",))


def _absent_or_default_column(record: Record, data: RecordData, column: Column) -> ColumnAudit:
    has_inline_default = column.default is not None
    has_user_defined_default = bool(column.flags & FIELDFLAG.UserDefinedDefault)
    has_default = has_inline_default or has_user_defined_default
    status = FieldStatus.DEFAULT if has_default else FieldStatus.ABSENT
    value = data.get(column) if has_default else None
    return _build_column_audit(record, data, column, None, status, value=value)


def _unavailable_column(record: Record, column: Column, missing_dependencies: tuple[str, ...]) -> ColumnAudit:
    return ColumnAudit(
        name=column.name,
        identifier=column.identifier,
        column_kind=_column_kind(column),
        status=FieldStatus.UNAVAILABLE,
        value=None,
        raw_value=None,
        default_value=column.default,
        record=record,
        missing_dependencies=missing_dependencies,
    )


def _missing_definition_column(
    record: Record, identifier: int, column_kind: str, missing_dependencies: tuple[str, ...]
) -> ColumnAudit:
    return ColumnAudit(
        name=None,
        identifier=identifier,
        column_kind=column_kind,
        status=FieldStatus.MISSING_DEFINITION,
        value=None,
        raw_value=None,
        default_value=None,
        record=record,
        missing_dependencies=missing_dependencies,
    )


def _build_column_audit(
    record: Record,
    data: RecordData,
    column: Column,
    raw_value: Any,
    status: FieldStatus,
    value: Any = None,
) -> ColumnAudit:
    if value is None:
        value = data.get(column)

    if isinstance(raw_value, memoryview):
        raw_value = raw_value.tobytes()

    return ColumnAudit(
        name=column.name,
        identifier=column.identifier,
        column_kind=_column_kind(column),
        status=status,
        value=value,
        raw_value=raw_value,
        default_value=column.default,
        record=record,
    )


def _column_kind(column: Column) -> str:
    if column.is_fixed:
        return "fixed"
    if column.is_variable:
        return "variable"
    return "tagged"
