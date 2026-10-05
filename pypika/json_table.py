from __future__ import annotations

from enum import Enum
from typing import Any, Sequence

from pypika.enums import Dialects
from pypika.queries import Selectable
from pypika.terms import Term, ValueWrapper
from pypika.utils import (
    DialectNotSupported,
    QueryException,
    format_alias_sql,
    format_quotes,
)

__author__ = "Timothy Heys"
__email__ = "theys@kayak.com"


class JSONTableOnEmptyError(Enum):
    """
    Behavior for the "ON EMPTY" and "ON ERROR" clauses of a JSON_TABLE column. Use
    "JSONTableDefault" for the "DEFAULT" option.
    """

    NULL = "NULL"
    ERROR = "ERROR"


class JSONTableDefault:
    """
    A "DEFAULT '<json_string>'" option for the "ON EMPTY" and "ON ERROR" clauses of a JSON_TABLE
    column. The value is rendered as a quoted string literal containing JSON.
    """

    def __init__(self, json_string: str) -> None:
        if not isinstance(json_string, str) or not json_string:
            raise QueryException("JSON_TABLE DEFAULT requires a non-empty JSON string")
        self.json_string = json_string

    def get_sql(self, **kwargs: Any) -> str:
        secondary_quote_char = kwargs.get("secondary_quote_char") or "'"
        return "DEFAULT {}".format(format_quotes(self.json_string, secondary_quote_char))

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, JSONTableDefault) and self.json_string == other.json_string

    def __hash__(self) -> int:
        return hash(self.json_string)


def _validate_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise QueryException("JSON_TABLE column names must be non-empty strings")
    return name


def _validate_type(type_: str, name: str) -> str:
    if not isinstance(type_, str) or not type_.strip():
        raise QueryException("JSON_TABLE column '{}' requires a SQL type".format(name))
    return type_


def _validate_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise QueryException("JSON_TABLE paths must be non-empty strings")
    return path


def _validate_on_option(option: JSONTableOnEmptyError | JSONTableDefault | None, clause: str) -> Any:
    if option is None or isinstance(option, (JSONTableOnEmptyError, JSONTableDefault)):
        return option
    raise QueryException(
        "Invalid {clause} option for JSON_TABLE: expected JSONTableOnEmptyError or JSONTableDefault, "
        "got {option!r}".format(clause=clause, option=option)
    )


def _on_option_sql(option: JSONTableOnEmptyError | JSONTableDefault | None, clause: str, **kwargs: Any) -> str:
    if option is None:
        return ""
    if isinstance(option, JSONTableDefault):
        return " {option} ON {clause}".format(option=option.get_sql(**kwargs), clause=clause)
    return " {option} ON {clause}".format(option=option.value, clause=clause)


def _validate_columns(columns: Sequence[Any]) -> list:
    if not columns:
        raise QueryException("JSON_TABLE requires a COLUMNS clause with at least one column")
    for column in columns:
        if not isinstance(column, (JSONTableColumn, JSONTableNested)):
            raise QueryException(
                "JSON_TABLE columns must be JSONTableColumn or JSONTableNested instances, "
                "got {column!r}".format(column=column)
            )
    return list(columns)


def _validate_unique_column_names(columns: Sequence[Any]) -> None:
    seen = set()
    for column in columns:
        for name in column.column_names:
            key = name.lower()
            if key in seen:
                raise QueryException("Duplicate column name '{}' in JSON_TABLE COLUMNS clause".format(name))
            seen.add(key)


class JSONTableColumn:
    """
    Base class for a named column definition inside a JSON_TABLE "COLUMNS" clause. Do not instantiate
    directly; use one of the subclasses.
    """

    def __init__(self, name: str) -> None:
        self.name = _validate_name(name)

    @property
    def column_names(self) -> list[str]:
        return [self.name]

    def name_sql(self, **kwargs: Any) -> str:
        return format_quotes(self.name, kwargs.get("quote_char"))

    def get_sql(self, **kwargs: Any) -> str:
        raise NotImplementedError


class JSONTableOrdinalityColumn(JSONTableColumn):
    """A "name FOR ORDINALITY" column, numbering the rows produced by the JSON_TABLE expression."""

    def get_sql(self, **kwargs: Any) -> str:
        return "{name} FOR ORDINALITY".format(name=self.name_sql(**kwargs))


class JSONTablePathColumn(JSONTableColumn):
    """
    A "name type PATH 'path' [ON EMPTY] [ON ERROR]" column extracting a scalar value from the JSON document.
    """

    def __init__(
        self,
        name: str,
        type_: str,
        path: str,
        on_empty: JSONTableOnEmptyError | JSONTableDefault | None = None,
        on_error: JSONTableOnEmptyError | JSONTableDefault | None = None,
    ) -> None:
        super().__init__(name)
        self.type = _validate_type(type_, name)
        self.path = _validate_path(path)
        self.on_empty = _validate_on_option(on_empty, "ON EMPTY")
        self.on_error = _validate_on_option(on_error, "ON ERROR")

    def get_sql(self, **kwargs: Any) -> str:
        secondary_quote_char = kwargs.get("secondary_quote_char") or "'"
        sql = "{name} {type} PATH {path}".format(
            name=self.name_sql(**kwargs),
            type=self.type,
            path=format_quotes(self.path, secondary_quote_char),
        )
        sql += _on_option_sql(self.on_empty, "EMPTY", **kwargs)
        sql += _on_option_sql(self.on_error, "ERROR", **kwargs)
        return sql


class JSONTableExistsColumn(JSONTableColumn):
    """A "name type EXISTS PATH 'path'" column producing 1 or 0 depending on whether the path exists."""

    def __init__(self, name: str, type_: str, path: str) -> None:
        super().__init__(name)
        self.type = _validate_type(type_, name)
        self.path = _validate_path(path)

    def get_sql(self, **kwargs: Any) -> str:
        secondary_quote_char = kwargs.get("secondary_quote_char") or "'"
        return "{name} {type} EXISTS PATH {path}".format(
            name=self.name_sql(**kwargs),
            type=self.type,
            path=format_quotes(self.path, secondary_quote_char),
        )


class JSONTableNested:
    """
    A "NESTED PATH 'path' COLUMNS (...)" clause producing one row per array element at "path", relative
    to the enclosing (parent) path. May itself contain further nested clauses.
    """

    def __init__(self, path: str, columns: Sequence[Any]) -> None:
        self.path = _validate_path(path)
        self.columns = _validate_columns(columns)

    @property
    def column_names(self) -> list[str]:
        names = []
        for column in self.columns:
            names.extend(column.column_names)
        return names

    def get_sql(self, **kwargs: Any) -> str:
        secondary_quote_char = kwargs.get("secondary_quote_char") or "'"
        return "NESTED PATH {path} COLUMNS ({columns})".format(
            path=format_quotes(self.path, secondary_quote_char),
            columns=",".join(column.get_sql(**kwargs) for column in self.columns),
        )


class JSONTable(Selectable):
    """
    A MySQL 8.0 "JSON_TABLE" expression which turns a JSON document into a relational table. It can be used
    anywhere a table can be used in a query (FROM clause, JOINs) and its columns can be referenced via
    "json_table.field('name')" or attribute access. An alias is required.
    """

    def __init__(
        self,
        expr: str | Term,
        path: str,
        columns: Sequence[Any],
        alias: str | None = None,
    ) -> None:
        if not alias:
            raise QueryException("JSON_TABLE requires an alias")
        super().__init__(alias=alias)
        self._expr = expr if isinstance(expr, Term) else ValueWrapper(expr)
        self._path = _validate_path(path)
        self._columns = _validate_columns(columns)
        _validate_unique_column_names(self._columns)

    def get_sql(self, **kwargs: Any) -> str:
        dialect = kwargs.get("dialect")
        if dialect is not None and dialect != Dialects.MYSQL:
            raise DialectNotSupported("JSON_TABLE is only supported by the MySQL dialect")

        secondary_quote_char = kwargs.get("secondary_quote_char") or "'"
        sql = "JSON_TABLE({expr}, {path} COLUMNS ({columns}))".format(
            expr=self._expr.get_sql(**kwargs),
            path=format_quotes(self._path, secondary_quote_char),
            columns=",".join(column.get_sql(**kwargs) for column in self._columns),
        )
        return format_alias_sql(sql, self.alias, **kwargs)

    def __str__(self) -> str:
        return self.get_sql(quote_char='"')
