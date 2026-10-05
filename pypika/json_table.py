from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable

from pypika.enums import Dialects, SqlType, SqlTypeLength
from pypika.queries import Selectable
from pypika.terms import Node, Term
from pypika.utils import DialectNotSupported, QueryException, format_quotes

if TYPE_CHECKING:
    if sys.version_info >= (3, 11):
        from typing import Self
    else:
        from typing_extensions import Self


class JSONTableEmptyOption(Enum):
    null = "NULL"
    error = "ERROR"
    default = "DEFAULT"


class JSONTableErrorOption(Enum):
    null = "NULL"
    error = "ERROR"
    default = "DEFAULT"


class _SQLStringLiteral(Term):
    def __init__(self, value: str) -> None:
        super().__init__()
        self.value = value

    def get_sql(self, secondary_quote_char: str = "'", **_: Any) -> str:
        return format_quotes(self.value, secondary_quote_char)


def _reject_json_constant(constant: str) -> None:
    raise ValueError(constant)


def _sql_string(value: str) -> _SQLStringLiteral:
    if not isinstance(value, str) or not value:
        raise QueryException("JSON path must be a non-empty string.")
    if not value.startswith("$"):
        raise QueryException("JSON path must be relative to its parent and start with '$'.")
    return _SQLStringLiteral(value)


def _json_literal(value: Any, *, clause: str) -> Term:
    if isinstance(value, Term):
        return value
    if isinstance(value, str):
        try:
            json.loads(value, parse_constant=_reject_json_constant)
        except (TypeError, ValueError) as exc:
            raise QueryException(f"Invalid JSON default for {clause}.") from exc
        return _SQLStringLiteral(value)
    if value is None or isinstance(value, (dict, list, int, float, bool)):
        try:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise QueryException(f"Invalid JSON default for {clause}.") from exc
        return _SQLStringLiteral(encoded)
    raise QueryException(f"Invalid JSON default for {clause}.")


class JSONTableColumn(Node, ABC):
    is_output_column = True

    def __init__(self, name: str) -> None:
        if not isinstance(name, str) or not name:
            raise QueryException("JSON_TABLE output column name must be a non-empty string.")
        self.name = name

    def _output_name(self, quote_char: str | None = None) -> str:
        return format_quotes(self.name, quote_char)

    def output_names(self) -> set[str]:
        return {self.name}

    @abstractmethod
    def get_sql(self, quote_char: str | None = None, **kwargs: Any) -> str:
        raise NotImplementedError()


class JSONTableOrdinalityColumn(JSONTableColumn):
    def get_sql(self, quote_char: str | None = None, **_: Any) -> str:
        return f"{self._output_name(quote_char)} FOR ORDINALITY"


class JSONTableExistsPathColumn(JSONTableColumn):
    def __init__(self, name: str, path: str) -> None:
        super().__init__(name)
        self.path = _sql_string(path)

    def get_sql(self, quote_char: str | None = None, secondary_quote_char: str = "'", **kwargs: Any) -> str:
        return "{name} EXISTS PATH {path}".format(
            name=self._output_name(quote_char),
            path=self.path.get_sql(secondary_quote_char=secondary_quote_char, **kwargs),
        )


class JSONTablePathColumn(JSONTableColumn):
    ALLOWED_TYPES = frozenset(
        {
            "BOOLEAN",
            "INT",
            "INTEGER",
            "BIGINT",
            "SMALLINT",
            "TINYINT",
            "BIGINT UNSIGNED",
            "INTEGER UNSIGNED",
            "INT UNSIGNED",
            "MEDIUMINT UNSIGNED",
            "MEDIUMINT",
            "SMALLINT UNSIGNED",
            "TINYINT UNSIGNED",
            "FLOAT",
            "DOUBLE",
            "DECIMAL",
            "NUMERIC",
            "SIGNED",
            "UNSIGNED",
            "DATE",
            "TIME",
            "DATETIME",
            "TIMESTAMP",
            "YEAR",
            "CHAR",
            "VARCHAR",
            "BINARY",
            "VARBINARY",
            "JSON",
        }
    )

    @classmethod
    def _normalize_type(cls, type: str | SqlType | SqlTypeLength) -> SqlType | SqlTypeLength:
        if isinstance(type, str):
            if type not in cls.ALLOWED_TYPES:
                raise QueryException(f"Unsupported JSON_TABLE column data type: {type}.")
            return SqlType(type)
        if isinstance(type, SqlTypeLength) and (
            isinstance(type.length, bool) or not isinstance(type.length, int) or type.length < 0
        ):
            raise QueryException("JSON_TABLE column data type length must be a non-negative integer.")
        if not isinstance(type, (SqlType, SqlTypeLength)):
            raise QueryException("JSON_TABLE PATH column requires a SQL data type.")
        if type.name not in cls.ALLOWED_TYPES:
            raise QueryException(f"Unsupported JSON_TABLE column data type: {type.name}.")
        return type

    def __init__(
        self,
        name: str,
        path: str,
        type: str | SqlType | SqlTypeLength,
        *,
        on_empty: JSONTableEmptyOption | None = None,
        default_on_empty: Any = None,
        on_error: JSONTableErrorOption | None = None,
        default_on_error: Any = None,
    ) -> None:
        super().__init__(name)
        type = self._normalize_type(type)

        self.path = _sql_string(path)
        self.type = type
        self.on_empty = on_empty
        self.on_error = on_error
        self.default_on_empty = (
            _json_literal(default_on_empty, clause="ON EMPTY") if default_on_empty is not None else None
        )
        self.default_on_error = (
            _json_literal(default_on_error, clause="ON ERROR") if default_on_error is not None else None
        )
        self._validate_options()

    def _validate_options(self) -> None:
        if self.on_empty is not None and not isinstance(self.on_empty, JSONTableEmptyOption):
            raise QueryException("Invalid JSON_TABLE ON EMPTY option.")
        if self.on_error is not None and not isinstance(self.on_error, JSONTableErrorOption):
            raise QueryException("Invalid JSON_TABLE ON ERROR option.")
        if self.default_on_empty is not None and self.on_empty != JSONTableEmptyOption.default:
            raise QueryException("JSON default requires DEFAULT ON EMPTY.")
        if self.default_on_error is not None and self.on_error != JSONTableErrorOption.default:
            raise QueryException("JSON default requires DEFAULT ON ERROR.")
        if self.on_empty == JSONTableEmptyOption.error and self.default_on_empty is not None:
            raise QueryException("ERROR ON EMPTY cannot have a DEFAULT value.")
        if self.on_error == JSONTableErrorOption.error and self.default_on_error is not None:
            raise QueryException("ERROR ON ERROR cannot have a DEFAULT value.")
        if self.on_empty == JSONTableEmptyOption.default and self.default_on_empty is None:
            raise QueryException("DEFAULT ON EMPTY requires a JSON default value.")
        if self.on_error == JSONTableErrorOption.default and self.default_on_error is None:
            raise QueryException("DEFAULT ON ERROR requires a JSON default value.")

    def _option_sql(
        self,
        option: Enum | None,
        default: Term | None,
        clause: str,
        **kwargs: Any,
    ) -> str:
        if option is None and default is None:
            return ""
        if option == JSONTableEmptyOption.error or option == JSONTableErrorOption.error:
            return f" ERROR ON {clause}"
        if option == JSONTableEmptyOption.null or option == JSONTableErrorOption.null:
            return f" NULL ON {clause}"
        return " DEFAULT {default} ON {clause}".format(default=default.get_sql(**kwargs), clause=clause)

    def get_sql(self, quote_char: str | None = None, secondary_quote_char: str = "'", **kwargs: Any) -> str:
        sql = "{name} {type} PATH {path}{on_empty}{on_error}".format(
            name=self._output_name(quote_char),
            type=self.type.get_sql(**kwargs),
            path=self.path.get_sql(secondary_quote_char=secondary_quote_char, **kwargs),
            on_empty=self._option_sql(
                self.on_empty,
                self.default_on_empty,
                "EMPTY",
                secondary_quote_char=secondary_quote_char,
                **kwargs,
            ),
            on_error=self._option_sql(
                self.on_error,
                self.default_on_error,
                "ERROR",
                secondary_quote_char=secondary_quote_char,
                **kwargs,
            ),
        )
        return sql


class JSONTableNestedPath(Node):
    is_output_column = False

    def __init__(self, path: str, columns: Iterable[JSONTableColumn | JSONTableNestedPath]) -> None:
        self.path = _sql_string(path)
        self.columns = tuple(columns)
        if not self.columns:
            raise QueryException("NESTED PATH requires at least one column.")
        for column in self.columns:
            if not isinstance(column, (JSONTableColumn, JSONTableNestedPath)):
                raise QueryException("JSON_TABLE COLUMNS only accepts structured column definitions.")

    def output_names(self) -> set[str]:
        names: set[str] = set()
        for column in self.columns:
            output_names = column.output_names()
            duplicate_names = names.intersection(output_names)
            if duplicate_names:
                raise QueryException(
                    "Duplicate JSON_TABLE output column: {name}".format(name=next(iter(duplicate_names)))
                )
            names.update(output_names)
        return names

    def get_sql(self, quote_char: str | None = None, secondary_quote_char: str = "'", **kwargs: Any) -> str:
        return "NESTED PATH {path} COLUMNS ({columns})".format(
            path=self.path.get_sql(secondary_quote_char=secondary_quote_char, **kwargs),
            columns=",".join(
                column.get_sql(quote_char=quote_char, secondary_quote_char=secondary_quote_char, **kwargs)
                for column in self.columns
            ),
        )


class JSONTable(Selectable):
    def __init__(
        self,
        document: Term | str | int | bool | dict | list | None,
        path: str,
        columns: Iterable[JSONTableColumn | JSONTableNestedPath],
        alias: str | None = None,
    ) -> None:
        super().__init__(alias)
        self.document = self._wrap_document(document)
        self.path = _sql_string(path)
        self.columns = tuple(columns)
        if not self.columns:
            raise QueryException("JSON_TABLE requires at least one column.")
        for column in self.columns:
            if not isinstance(column, (JSONTableColumn, JSONTableNestedPath)):
                raise QueryException("JSON_TABLE COLUMNS only accepts structured column definitions.")
        self._validate_unique_output_columns()
        if self.alias is not None and (not isinstance(self.alias, str) or not self.alias):
            raise QueryException("JSON_TABLE alias must be a non-empty string.")

    @staticmethod
    def _wrap_document(document: Term | str | int | bool | dict | list | None) -> Term:
        if isinstance(document, Term):
            return document
        try:
            return _json_literal(document, clause="document")
        except QueryException:
            raise QueryException("Invalid JSON document.")

    def _validate_unique_output_columns(self) -> None:
        names: set[str] = set()
        for column in self.columns:
            output_names = column.output_names()
            duplicate_names = names.intersection(output_names)
            if duplicate_names:
                raise QueryException(
                    "Duplicate JSON_TABLE output column: {name}".format(name=next(iter(duplicate_names)))
                )
            names.update(output_names)

    def nodes_(self):
        yield self
        yield from self.document.nodes_()

    def replace_table(self, current_table, new_table) -> Self:
        document = self.document.replace_table(current_table, new_table)
        if document == self.document:
            return self
        return JSONTable(document, self.path.value, self.columns, self.alias)

    def get_sql(
        self,
        *,
        dialect: Dialects | None = None,
        quote_char: str | None = None,
        secondary_quote_char: str = "'",
        with_alias: bool = True,
        **kwargs: Any,
    ) -> str:
        if dialect is not None and dialect != Dialects.MYSQL:
            raise DialectNotSupported("JSON_TABLE is only supported by MySQL 8.0 and later.")
        if not self.alias:
            raise QueryException("JSON_TABLE requires an alias.")

        document_kwargs = dict(kwargs)
        document_kwargs["quote_char"] = quote_char
        document_kwargs["with_namespace"] = True
        document_kwargs["secondary_quote_char"] = secondary_quote_char
        document_kwargs.pop("with_alias", None)
        document_kwargs.pop("subquery", None)
        sql = "JSON_TABLE({document},{path} COLUMNS ({columns}))".format(
            document=self.document.get_sql(**document_kwargs),
            path=self.path.get_sql(secondary_quote_char=secondary_quote_char, **kwargs),
            columns=",".join(
                column.get_sql(quote_char=quote_char, secondary_quote_char=secondary_quote_char, **kwargs)
                for column in self.columns
            ),
        )
        return "{table} AS {alias}".format(table=sql, alias=format_quotes(self.alias, quote_char))
