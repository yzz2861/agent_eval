from __future__ import annotations

from copy import copy
from typing import Any, Iterable

from pypika.enums import Dialects
from pypika.queries import Query, Selectable, Table
from pypika.terms import Criterion, Field, Term, ValueWrapper
from pypika.utils import MergeException, builder, format_quotes

__author__ = "Timothy Heys"
__email__ = "theys@kayak.com"


class MergeWhenClause:
    """
    Represents a single WHEN clause of a MERGE statement. Instances are created through the
    when_matched_then_* / when_not_matched_then_* methods of :class:`MergeQueryBuilder` and should not be
    instantiated directly.
    """

    MATCHED = "MATCHED"
    NOT_MATCHED = "NOT MATCHED"
    NOT_MATCHED_BY_SOURCE = "NOT MATCHED BY SOURCE"

    UPDATE = "UPDATE"
    DELETE = "DELETE"
    INSERT = "INSERT"

    ALLOWED_ACTIONS = {
        MATCHED: (UPDATE, DELETE),
        NOT_MATCHED: (INSERT,),
        NOT_MATCHED_BY_SOURCE: (UPDATE, DELETE),
    }

    def __init__(
        self,
        match_type: str,
        action: str,
        condition: Criterion | None = None,
        updates: list[tuple[Field, Term]] | None = None,
        insert_columns: list[Field] | None = None,
        insert_values: list[Term] | None = None,
    ) -> None:
        if action not in self.ALLOWED_ACTIONS[match_type]:
            raise MergeException(
                "Cannot use {action} in a WHEN {match_type} clause".format(action=action, match_type=match_type)
            )
        self.match_type = match_type
        self.action = action
        self.condition = condition
        self.updates = updates or []
        self.insert_columns = insert_columns
        self.insert_values = insert_values or []

    def get_sql(self, **kwargs: Any) -> str:
        quote_char = kwargs.get("quote_char")

        clause_sql = "WHEN {match_type}".format(match_type=self.match_type)
        if self.condition is not None:
            clause_sql += " AND {condition}".format(condition=self.condition.get_sql(**kwargs))

        if self.action == self.UPDATE:
            sets = ", ".join(
                "{column}={value}".format(
                    column=format_quotes(field.name, quote_char),
                    value=value.get_sql(**kwargs),
                )
                for field, value in self.updates
            )
            clause_sql += " THEN UPDATE SET {sets}".format(sets=sets)
        elif self.action == self.DELETE:
            clause_sql += " THEN DELETE"
        else:
            clause_sql += " THEN INSERT"
            if self.insert_columns:
                columns = ", ".join(format_quotes(field.name, quote_char) for field in self.insert_columns)
                clause_sql += " ({columns})".format(columns=columns)
            values = ", ".join(value.get_sql(**kwargs) for value in self.insert_values)
            clause_sql += " VALUES ({values})".format(values=values)

        return clause_sql


class MergeQueryBuilder:
    """
    Query builder for MERGE statements. Created via Query.merge_into or the dialect specific query classes such
    as PostgreSQLQuery.merge_into and MSSQLQuery.merge_into.

    This class is immutable: every builder method returns a copy.
    """

    QUOTE_CHAR = '"'
    SECONDARY_QUOTE_CHAR = "'"
    ALIAS_QUOTE_CHAR = None
    QUERY_CLS = Query

    SUPPORTS_NOT_MATCHED_BY_SOURCE = True

    def __init__(
        self,
        dialect: Dialects | None = None,
        wrapper_cls: type[ValueWrapper] = ValueWrapper,
        immutable: bool = True,
    ) -> None:
        self._target = None
        self._source = None
        self._on = None
        self._when_clauses: list[MergeWhenClause] = []

        self.dialect = dialect
        self._wrapper_cls = wrapper_cls
        self.immutable = immutable

    def __copy__(self) -> MergeQueryBuilder:
        newone = type(self).__new__(type(self))
        newone.__dict__.update(self.__dict__)
        newone._when_clauses = copy(self._when_clauses)
        return newone

    @builder
    def merge_into(self, table: str | Table) -> None:
        """
        Sets the target table of the MERGE statement.

        :param table:
            An instance of a Table object or a string table name.
        """
        if self._target is not None:
            raise AttributeError("'MergeQueryBuilder' object already has attribute 'merge_into'")
        self._target = table if isinstance(table, Table) else Table(table)

    @builder
    def using(self, source: str | Selectable) -> None:
        """
        Sets the source of the MERGE statement. The source can be a table or a subquery. Subqueries must have an
        alias so that their fields can be referenced from the ON condition and the WHEN clauses.

        :param source:
            An instance of a Table object, an aliased subquery, or a string table name.
        """
        if self._source is not None:
            raise AttributeError("'MergeQueryBuilder' object already has attribute 'using'")

        if isinstance(source, str):
            source = Table(source)
        elif isinstance(source, Table):
            pass
        elif isinstance(source, Selectable):
            if source.alias is None:
                raise MergeException("Subquery sources in a MERGE statement must have an alias")
        else:
            raise MergeException("MERGE source must be a table or an aliased subquery, not %r" % type(source))

        self._source = source

    @builder
    def on(self, criterion: Criterion) -> None:
        """
        Sets the join condition of the MERGE statement. Calling this function multiple times combines the
        conditions with AND. Raw SQL strings are not accepted; build conditions from Field and Criterion objects.
        """
        criterion = self._validate_condition(criterion)
        self._on = criterion if self._on is None else self._on & criterion

    @builder
    def when_matched_then_update(
        self,
        updates: dict | Iterable[tuple] | None = None,
        condition: Criterion | None = None,
        **set_kwargs: Any,
    ) -> None:
        """
        Appends a WHEN MATCHED [AND condition] THEN UPDATE SET ... clause. updates accepts a dict or an iterable
        of (field, value) pairs; additional assignments can be passed as keyword arguments.
        """
        self._append_clause(
            MergeWhenClause(
                MergeWhenClause.MATCHED,
                MergeWhenClause.UPDATE,
                condition=self._validate_condition(condition),
                updates=self._normalize_updates(updates, set_kwargs),
            )
        )

    @builder
    def when_matched_then_delete(self, condition: Criterion | None = None) -> None:
        """
        Appends a WHEN MATCHED [AND condition] THEN DELETE clause.
        """
        self._append_clause(
            MergeWhenClause(
                MergeWhenClause.MATCHED,
                MergeWhenClause.DELETE,
                condition=self._validate_condition(condition),
            )
        )

    @builder
    def when_not_matched_then_insert(
        self,
        values: Iterable,
        columns: Iterable[str | Field] | None = None,
        condition: Criterion | None = None,
    ) -> None:
        """
        Appends a WHEN NOT MATCHED [AND condition] THEN INSERT [(columns)] VALUES (...) clause.
        """
        insert_columns = None
        if columns is not None:
            insert_columns = [self._target_field(column) for column in columns]
            self._validate_unique_columns(insert_columns, "INSERT")

        insert_values = [Term.wrap_constant(value, wrapper_cls=self._wrapper_cls) for value in values]
        if not insert_values:
            raise MergeException("MERGE INSERT requires at least one value")
        if insert_columns is not None and len(insert_columns) != len(insert_values):
            raise MergeException("MERGE INSERT column count does not match value count")

        self._append_clause(
            MergeWhenClause(
                MergeWhenClause.NOT_MATCHED,
                MergeWhenClause.INSERT,
                condition=self._validate_condition(condition),
                insert_columns=insert_columns,
                insert_values=insert_values,
            )
        )

    @builder
    def when_not_matched_by_source_then_update(
        self,
        updates: dict | Iterable[tuple] | None = None,
        condition: Criterion | None = None,
        **set_kwargs: Any,
    ) -> None:
        """
        Appends a WHEN NOT MATCHED BY SOURCE [AND condition] THEN UPDATE SET ... clause. Only supported by
        dialects that implement this clause (e.g. SQL Server).
        """
        self._validate_not_matched_by_source()
        self._append_clause(
            MergeWhenClause(
                MergeWhenClause.NOT_MATCHED_BY_SOURCE,
                MergeWhenClause.UPDATE,
                condition=self._validate_condition(condition),
                updates=self._normalize_updates(updates, set_kwargs),
            )
        )

    @builder
    def when_not_matched_by_source_then_delete(self, condition: Criterion | None = None) -> None:
        """
        Appends a WHEN NOT MATCHED BY SOURCE [AND condition] THEN DELETE clause. Only supported by dialects
        that implement this clause (e.g. SQL Server).
        """
        self._validate_not_matched_by_source()
        self._append_clause(
            MergeWhenClause(
                MergeWhenClause.NOT_MATCHED_BY_SOURCE,
                MergeWhenClause.DELETE,
                condition=self._validate_condition(condition),
            )
        )

    def get_sql(self, **kwargs: Any) -> str:
        kwargs.setdefault("quote_char", self.QUOTE_CHAR)
        kwargs.setdefault("secondary_quote_char", self.SECONDARY_QUOTE_CHAR)
        kwargs.setdefault("alias_quote_char", self.ALIAS_QUOTE_CHAR)
        kwargs.setdefault("dialect", self.dialect)

        self._validate()

        # Field references in the ON condition and WHEN clauses must be qualified with the target/source they
        # belong to, otherwise the statement would be ambiguous.
        kwargs["with_namespace"] = True

        querystring = "MERGE INTO {target}".format(target=self._target.get_sql(**kwargs))

        if isinstance(self._source, Table):
            source_sql = self._source.get_sql(**kwargs)
        else:
            source_sql = self._source.get_sql(with_alias=True, subquery=True, **kwargs)
        querystring += " USING {source}".format(source=source_sql)

        querystring += " ON {on}".format(on=self._on.get_sql(**kwargs))

        querystring += " " + " ".join(clause.get_sql(**kwargs) for clause in self._when_clauses)

        return querystring

    def __str__(self) -> str:
        return self.get_sql()

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, MergeQueryBuilder) and str(self) == str(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(str(self))

    def _validate(self) -> None:
        if self._target is None:
            raise MergeException("MERGE requires a target table")
        if self._source is None:
            raise MergeException("MERGE requires a source; call using() first")
        if self._on is None:
            raise MergeException("MERGE requires an ON condition; call on() first")
        if not self._when_clauses:
            raise MergeException("MERGE requires at least one WHEN clause")

    def _validate_condition(self, condition: Criterion | None) -> Criterion | None:
        if condition is not None and not isinstance(condition, Criterion):
            raise MergeException("MERGE conditions must be Criterion instances; raw SQL strings are not accepted")
        return condition

    def _validate_not_matched_by_source(self) -> None:
        if not self.SUPPORTS_NOT_MATCHED_BY_SOURCE:
            raise MergeException("WHEN NOT MATCHED BY SOURCE is not supported by this dialect")

    def _target_field(self, field: str | Field) -> Field:
        if isinstance(field, str):
            return Field(field, table=self._target)
        if isinstance(field, Field):
            if field.table is not None and self._target is not None and field.table != self._target:
                raise MergeException(
                    "MERGE target column {name!r} does not belong to the target table".format(name=field.name)
                )
            return field
        raise MergeException("MERGE target columns must be Field instances or column names")

    @staticmethod
    def _validate_unique_columns(fields: list[Field], context: str) -> None:
        seen = set()
        for field in fields:
            if field.name in seen:
                raise MergeException(
                    "Duplicate target column {name!r} in MERGE {context}".format(name=field.name, context=context)
                )
            seen.add(field.name)

    def _normalize_updates(self, updates: dict | Iterable[tuple] | None, set_kwargs: dict) -> list[tuple[Field, Term]]:
        pairs = []
        if updates is not None:
            pairs.extend(updates.items() if isinstance(updates, dict) else updates)
        pairs.extend(set_kwargs.items())

        if not pairs:
            raise MergeException("MERGE UPDATE requires at least one column assignment")

        normalized = [
            (self._target_field(field), Term.wrap_constant(value, wrapper_cls=self._wrapper_cls))
            for field, value in pairs
        ]
        self._validate_unique_columns([field for field, _ in normalized], "UPDATE SET")
        return normalized

    def _append_clause(self, clause: MergeWhenClause) -> None:
        if self._target is None or self._source is None or self._on is None:
            raise MergeException("Call merge_into(), using() and on() before adding WHEN clauses")

        group = [existing for existing in self._when_clauses if existing.match_type == clause.match_type]
        if any(existing.condition is None for existing in group):
            raise MergeException(
                "Unreachable WHEN {match_type} clause: an unconditional clause already exists in this group".format(
                    match_type=clause.match_type
                )
            )

        self._validate_group_rules(clause, group)
        self._when_clauses.append(clause)

    def _validate_group_rules(self, clause: MergeWhenClause, group: list[MergeWhenClause]) -> None:
        """
        Hook for dialect specific restrictions on the combination of clauses within a match group. The base
        implementation follows the SQL standard and applies no extra restrictions.
        """
