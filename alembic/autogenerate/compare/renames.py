# mypy: allow-untyped-calls

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from typing import TYPE_CHECKING

from ... import util

if TYPE_CHECKING:
    from sqlalchemy.engine.reflection import Inspector
    from sqlalchemy.sql.schema import Table


TableKey = tuple[str | None, str]
ColumnKey = tuple[str | None, str, str]


@dataclass(frozen=True)
class RenameHints:
    tables: Mapping[TableKey, TableKey]
    columns: Mapping[ColumnKey, ColumnKey]

    def table_key(self, key: TableKey) -> TableKey:
        return self.tables.get(key, key)

    def column_key(self, key: ColumnKey) -> ColumnKey:
        return self.columns.get(key, key)

    def column_names(self, key: TableKey) -> dict[str, str]:
        return {
            old_column: new_column
            for (
                old_schema,
                old_table,
                old_column,
            ), (
                new_schema,
                new_table,
                new_column,
            ) in self.columns.items()
            if (old_schema, old_table) == key
        }


def prepare_rename_hints(
    hints: Mapping[str, Any] | None,
    conn_table_names: set[TableKey],
    metadata_table_names: set[TableKey],
    metadata_tables: Mapping[TableKey, Table],
    inspector: Inspector,
    default_schema: str | None,
) -> RenameHints:
    if hints is None:
        return RenameHints(tables={}, columns={})

    table_hints = _normalize_table_hints(
        hints.get("tables", {}), default_schema
    )
    column_hints = _normalize_column_hints(
        hints.get("columns", {}), table_hints, default_schema
    )

    _assert_no_cycles(table_hints, "table")
    _assert_no_cycles(column_hints, "column")
    _assert_unique_targets(table_hints, "table")
    _assert_unique_targets(column_hints, "column")

    for old_key, new_key in table_hints.items():
        if old_key[0] != new_key[0]:
            raise util.CommandError(
                "Rename hints cannot move table %s to another schema; "
                "table schema changes are not renames"
                % (_format_table_key(old_key),)
            )
        if old_key not in conn_table_names:
            raise util.CommandError(
                "Rename hint refers to existing table %s, which was not "
                "found in the database" % (_format_table_key(old_key),)
            )
        if new_key not in metadata_table_names:
            raise util.CommandError(
                "Rename hint target table %s was not found in the target "
                "metadata" % (_format_table_key(new_key),)
            )
        if new_key in conn_table_names:
            raise util.CommandError(
                "Rename hint target table %s already exists in the "
                "database" % (_format_table_key(new_key),)
            )

    for old_key, new_key in column_hints.items():
        old_table_key = (old_key[0], old_key[1])
        new_table_key = (new_key[0], new_key[1])

        if old_table_key not in conn_table_names:
            raise util.CommandError(
                "Rename hint refers to existing table %s, which was not "
                "found in the database" % (_format_table_key(old_table_key),)
            )
        if new_table_key not in metadata_table_names:
            raise util.CommandError(
                "Rename hint target table %s was not found in the target "
                "metadata" % (_format_table_key(new_table_key),)
            )

        conn_columns = {
            column["name"]
            for column in inspector.get_columns(
                old_table_key[1], schema=old_table_key[0]
            )
        }
        metadata_columns = {
            column.name
            for column in metadata_tables[new_table_key].columns
            if not column.system
        }

        if old_key[2] not in conn_columns:
            raise util.CommandError(
                "Rename hint refers to existing column %s, which was not "
                "found in the database" % (_format_column_key(old_key),)
            )
        if new_key[2] not in metadata_columns:
            raise util.CommandError(
                "Rename hint target column %s was not found in the target "
                "metadata" % (_format_column_key(new_key),)
            )
        if new_key[2] in conn_columns:
            raise util.CommandError(
                "Rename hint target column %s already exists in the "
                "database" % (_format_column_key(new_key),)
            )

    return RenameHints(tables=table_hints, columns=column_hints)


def _normalize_table_hints(
    hints: Mapping[Any, Any], default_schema: str | None
) -> dict[TableKey, TableKey]:
    result = {}
    for old, new in hints.items():
        old_key = _normalize_table_key(old, default_schema)
        if isinstance(new, str):
            new_key = (old_key[0], new)
        else:
            new_key = _normalize_table_key(new, default_schema)
        result[old_key] = new_key
    return result


def _normalize_column_hints(
    hints: Mapping[Any, Any],
    table_hints: Mapping[TableKey, TableKey],
    default_schema: str | None,
) -> dict[ColumnKey, ColumnKey]:
    result = {}
    for old, new in hints.items():
        old_key = _normalize_column_key(old, default_schema)
        old_table_key = (old_key[0], old_key[1])
        target_table_key = table_hints.get(old_table_key, old_table_key)

        if isinstance(new, str):
            new_key = _normalize_column_key(new, default_schema)
            if len(new.split(".")) == 1:
                new_key = (
                    target_table_key[0],
                    target_table_key[1],
                    new,
                )
        else:
            new_key = _normalize_column_key(new, default_schema)
            new_table_key = (new_key[0], new_key[1])
            if new_table_key != target_table_key:
                raise util.CommandError(
                    "Column rename hint %s moves the column to table %s, but "
                    "no matching table rename was declared"
                    % (
                        _format_column_key(old_key),
                        _format_table_key(new_table_key),
                    )
                )

        result[old_key] = new_key
    return result


def _normalize_table_key(value: Any, default_schema: str | None) -> TableKey:
    if isinstance(value, str):
        value = (None, value)
    _validate_key_length(value, 2, "table")
    schema, table = value
    return (_normalize_schema(schema, default_schema), table)


def _normalize_column_key(value: Any, default_schema: str | None) -> ColumnKey:
    if isinstance(value, str):
        parts = value.split(".")
        if len(parts) == 2:
            value = (None, parts[0], parts[1])
        elif len(parts) == 3:
            value = (parts[0], parts[1], parts[2])
    _validate_key_length(value, 3, "column")
    schema, table, column = value
    return (_normalize_schema(schema, default_schema), table, column)


def _normalize_schema(schema: str | None, default_schema: str | None):
    return None if schema == default_schema else schema


def _validate_key_length(value: Any, length: int, kind: str) -> None:
    if not isinstance(value, tuple) or len(value) != length:
        raise util.CommandError(
            "Rename hints require %d values for each %s identifier"
            % (length, kind)
        )


def _assert_no_cycles(mapping: Mapping[Any, Any], kind: str) -> None:
    visiting = set()
    visited = set()

    def visit(key: Any) -> None:
        if key in visited:
            return
        if key in visiting:
            raise util.CommandError(
                "Cycle detected in %s rename hints at %s" % (kind, key)
            )
        visiting.add(key)
        if key in mapping:
            visit(mapping[key])
        visiting.remove(key)
        visited.add(key)

    for key in mapping:
        visit(key)


def _assert_unique_targets(mapping: Mapping[Any, Any], kind: str) -> None:
    targets = {}
    for old_key, new_key in mapping.items():
        if new_key in targets:
            raise util.CommandError(
                "Multiple %s rename hints map to %s: %s and %s"
                % (
                    kind,
                    new_key,
                    targets[new_key],
                    old_key,
                )
            )
        targets[new_key] = old_key


def _format_table_key(key: TableKey) -> str:
    return "%s.%s" % key if key[0] is not None else key[1]


def _format_column_key(key: ColumnKey) -> str:
    if key[0] is not None:
        return "%s.%s.%s" % key
    return "%s.%s" % (key[1], key[2])
