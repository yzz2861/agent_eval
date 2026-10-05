from __future__ import annotations

from copy import copy
from enum import Enum
from typing import Any

from pypika.enums import Dialects
from pypika.queries import QueryBuilder, Selectable, Table
from pypika.terms import Criterion, EmptyCriterion, Field, Term, ValueWrapper
from pypika.utils import QueryException, builder


class MergeMatch(Enum):
    matched = "matched"
    not_matched_by_target = "not_matched_by_target"
    not_matched_by_source = "not_matched_by_source"


class MergeWhenClause:
    immutable = True

    def __init__(self, match: MergeMatch, condition: Criterion | None = None) -> None:
        self.match = match
        self.condition = None if isinstance(condition, EmptyCriterion) else condition
        self._update = False
        self._delete = False
        self._insert = False
        self._updates: list[tuple[Field, Term]] = []
        self._columns: list[Field] = []
        self._values: list[Term] = []

    def __copy__(self) -> MergeWhenClause:
        newone = type(self).__new__(type(self))
        newone.__dict__.update(self.__dict__)
        newone._updates = copy(self._updates)
        newone._columns = copy(self._columns)
        newone._values = copy(self._values)
        return newone

    @builder
    def when(self, condition: Criterion) -> MergeWhenClause:
        if self.condition is not None:
            raise QueryException("A MERGE branch already has a condition")
        if not isinstance(condition, Criterion) or isinstance(condition, EmptyCriterion):
            raise QueryException("MERGE branch conditions must be criteria")
        self.condition = condition

    @builder
    def update(self) -> MergeWhenClause:
        self._require_no_action()
        self._update = True

    @builder
    def delete(self) -> MergeWhenClause:
        self._require_no_action()
        self._delete = True

    @builder
    def insert(self) -> MergeWhenClause:
        self._require_no_action()
        self._insert = True

    @builder
    def set(self, field: Field | str, value: Any) -> MergeWhenClause:
        if not self._update:
            raise QueryException("SET is only valid in a MERGE UPDATE action")
        if not isinstance(field, Field):
            field = Field(field)
        if not isinstance(value, Term):
            value = ValueWrapper(value)
        self._updates.append((field, value))

    @builder
    def columns(self, *fields: Field | str) -> MergeWhenClause:
        if not self._insert:
            raise QueryException("Columns are only valid in a MERGE INSERT action")
        for field in fields:
            if not isinstance(field, Field):
                field = Field(field)
            self._columns.append(field)

    @builder
    def values(self, *values: Any) -> MergeWhenClause:
        if not self._insert:
            raise QueryException("VALUES is only valid in a MERGE INSERT action")
        if self._values:
            raise QueryException("MERGE INSERT actions can only contain one VALUES row")
        if len(values) == 1 and isinstance(values[0], (list, tuple)):
            values = tuple(values[0])
        self._values = [value if isinstance(value, Term) else ValueWrapper(value) for value in values]

    def _require_no_action(self) -> None:
        if self._update or self._delete or self._insert:
            raise QueryException("A MERGE branch can only contain one action")

    def validate(self, merge: MergeQueryBuilder) -> None:
        actions = sum((self._update, self._delete, self._insert))
        if actions != 1:
            raise QueryException("A MERGE branch must contain exactly one UPDATE, DELETE, or INSERT action")

        if self.condition is not None and not isinstance(self.condition, Criterion):
            raise QueryException("MERGE branch conditions must be criteria")

        allowed_actions = merge.supported_actions[self.match]
        if self._update and "UPDATE" not in allowed_actions:
            raise QueryException(f"UPDATE is not supported for {self._match_label()}")
        if self._delete and "DELETE" not in allowed_actions:
            raise QueryException(f"DELETE is not supported for {self._match_label()}")
        if self._insert and "INSERT" not in allowed_actions:
            raise QueryException(f"INSERT is not supported for {self._match_label()}")

        if self._update and not self._updates:
            raise QueryException("MERGE UPDATE actions require at least one SET assignment")
        if self._insert and (not self._columns or not self._values):
            raise QueryException("MERGE INSERT actions require columns and values")
        if self._insert and len(self._columns) != len(self._values):
            raise QueryException("MERGE INSERT column and value counts must match")

        self._validate_target_columns([field for field, _ in self._updates], merge)
        self._validate_target_columns(self._columns, merge)

        for _, value in self._updates:
            self._validate_external_fields(value, merge, allow_target=True, allow_source=True)
        for value in self._values:
            self._validate_external_fields(value, merge, allow_target=False, allow_source=True)
        if self.condition is not None:
            self._validate_external_fields(self.condition, merge, allow_target=True, allow_source=True)

    def _validate_target_columns(self, fields: list[Field], merge: MergeQueryBuilder) -> None:
        names = set()
        for field in fields:
            if not isinstance(field, Field):
                raise QueryException("MERGE target columns must be fields")
            if field.alias is not None:
                raise QueryException("MERGE target columns cannot have aliases")
            if field.table is not None and field.table != merge.target:
                raise QueryException("MERGE target columns must belong to the target table")
            if field.name in names:
                raise QueryException(f"Duplicate MERGE target column: {field.name}")
            names.add(field.name)

    def _validate_external_fields(
        self,
        term: Term,
        merge: MergeQueryBuilder,
        allow_target: bool,
        allow_source: bool,
    ) -> None:
        for field in term.fields_():
            if field.table is None:
                raise QueryException(f"Field {field.name} must be qualified by the MERGE target or source")
            if field.table == merge.target:
                if not allow_target:
                    raise QueryException("Target fields are not allowed in MERGE INSERT values")
            elif field.table == merge.source:
                if not allow_source:
                    raise QueryException("Source fields are not allowed here")
            else:
                raise QueryException(f"Field {field.name} does not belong to the MERGE target or source")

    def _match_label(self) -> str:
        if self.match is MergeMatch.matched:
            return "WHEN MATCHED"
        if self.match is MergeMatch.not_matched_by_target:
            return "WHEN NOT MATCHED"
        return "WHEN NOT MATCHED BY SOURCE"

    def get_sql(self, merge: MergeQueryBuilder, by_target_keyword: bool = False, **kwargs: Any) -> str:
        if self.match is MergeMatch.matched:
            label = "WHEN MATCHED"
        elif self.match is MergeMatch.not_matched_by_target:
            label = "WHEN NOT MATCHED BY TARGET" if by_target_keyword else "WHEN NOT MATCHED"
        else:
            label = "WHEN NOT MATCHED BY SOURCE"

        if self.condition is not None:
            label += f" AND {self.condition.get_sql(subquery=True, **kwargs)}"

        if self._update:
            assignments = ",".join(
                "{}={}".format(
                    Field(field.name).get_sql(**{**kwargs, "with_alias": False, "with_namespace": False}),
                    value.get_sql(**{**kwargs, "with_alias": False}),
                )
                for field, value in self._updates
            )
            action = f"THEN UPDATE SET {assignments}"
        elif self._delete:
            action = "THEN DELETE"
        else:
            columns = ",".join(
                Field(field.name).get_sql(**{**kwargs, "with_alias": False, "with_namespace": False})
                for field in self._columns
            )
            values = ",".join(
                value.get_sql(**{**kwargs, "with_alias": False, "subquery": True}) for value in self._values
            )
            action = f"THEN INSERT ({columns}) VALUES ({values})"

        return f"{label} {action}"


class MergeWhenMatched(MergeWhenClause):
    def __init__(self, condition: Criterion | None = None) -> None:
        super().__init__(MergeMatch.matched, condition)


class MergeWhenNotMatched(MergeWhenClause):
    def __init__(self, condition: Criterion | None = None) -> None:
        super().__init__(MergeMatch.not_matched_by_target, condition)


class MergeWhenNotMatchedBySource(MergeWhenClause):
    def __init__(self, condition: Criterion | None = None) -> None:
        super().__init__(MergeMatch.not_matched_by_source, condition)


class MergeQueryBuilder:
    immutable = True
    QUOTE_CHAR = '"'
    SECONDARY_QUOTE_CHAR = "'"
    DIALECT: Dialects | None = None
    TERMINATE_WITH_SEMICOLON = False

    def __init__(self) -> None:
        self.target: Table | None = None
        self.source: Selectable | None = None
        self.on_criterion: Criterion | None = None
        self.branches: list[MergeWhenClause] = []

    @property
    def supported_actions(self) -> dict[MergeMatch, set[str]]:
        return {
            MergeMatch.matched: {"UPDATE", "DELETE"},
            MergeMatch.not_matched_by_target: {"INSERT"},
            MergeMatch.not_matched_by_source: {"UPDATE", "DELETE"},
        }

    @property
    def supported_matches(self) -> tuple[MergeMatch, ...]:
        return tuple(self.supported_actions)

    @property
    def match_order(self) -> tuple[MergeMatch, ...]:
        return self.supported_matches

    def __copy__(self) -> MergeQueryBuilder:
        newone = type(self).__new__(type(self))
        newone.__dict__.update(self.__dict__)
        newone.branches = copy(self.branches)
        return newone

    @builder
    def using(self, source: Selectable | str) -> MergeQueryBuilder:
        self._using(source)

    def _using(self, source: Selectable | str) -> None:
        if isinstance(source, str):
            source = Table(source)
        if not isinstance(source, Selectable):
            raise QueryException("MERGE source must be a table or aliased selectable")
        if isinstance(source, QueryBuilder) and source.alias is None:
            raise QueryException("MERGE subquery sources must have an alias")
        self.source = source

    @builder
    def on(self, on_criterion: Criterion) -> MergeQueryBuilder:
        self._on(on_criterion)

    def _on(self, on_criterion: Criterion) -> None:
        if not isinstance(on_criterion, Criterion) or isinstance(on_criterion, EmptyCriterion):
            raise QueryException("MERGE requires an ON criterion")
        self.on_criterion = on_criterion

    @builder
    def merge(
        self,
        target: Table | str,
        source: Selectable | str | None = None,
        on_criterion: Criterion | None = None,
    ) -> MergeQueryBuilder:
        self.target = target if isinstance(target, Table) else Table(target)
        if source is not None:
            if isinstance(source, str):
                source = Table(source)
            if not isinstance(source, Selectable):
                raise QueryException("MERGE source must be a table or aliased selectable")
            if isinstance(source, QueryBuilder) and source.alias is None:
                raise QueryException("MERGE subquery sources must have an alias")
            self.source = source
        if on_criterion is not None:
            if not isinstance(on_criterion, Criterion) or isinstance(on_criterion, EmptyCriterion):
                raise QueryException("MERGE requires an ON criterion")
            self.on_criterion = on_criterion

    @builder
    def when(self, branch: MergeWhenClause) -> MergeQueryBuilder:
        if not isinstance(branch, MergeWhenClause):
            raise QueryException("MERGE branches must be MergeWhenClause instances")
        self.branches.append(branch)

    def validate(self) -> None:
        if self.target is None or self.source is None or self.on_criterion is None:
            raise QueryException("MERGE requires target, source, and ON")
        if not self.branches:
            raise QueryException("MERGE requires at least one WHEN branch")

        for field in self.on_criterion.fields_():
            if field.table is None or (field.table != self.target and field.table != self.source):
                raise QueryException("MERGE ON fields must belong to the target or source")

        seen_unconditional: set[MergeMatch] = set()
        previous_index = -1
        for branch in self.branches:
            if branch.match not in self.supported_matches:
                raise QueryException(f"{branch._match_label()} is not supported by this dialect")

            branch.validate(self)

            current_index = self.match_order.index(branch.match)
            if current_index < previous_index:
                raise QueryException("MERGE WHEN branches must be grouped by match type")
            previous_index = current_index

            if branch.match in seen_unconditional:
                raise QueryException("Unconditional MERGE branch makes a later branch unreachable")

            if branch.condition is None:
                seen_unconditional.add(branch.match)

    def get_sql(self, **kwargs: Any) -> str:
        self.validate()
        kwargs.setdefault("quote_char", self.QUOTE_CHAR)
        kwargs.setdefault("secondary_quote_char", self.SECONDARY_QUOTE_CHAR)
        kwargs.setdefault("dialect", self.DIALECT)
        kwargs["with_namespace"] = True

        sql = "{keyword} {target} USING {source} ON {on} {branches}".format(
            keyword=self._merge_keyword(),
            target=self.target.get_sql(with_alias=True, **kwargs),
            source=self.source.get_sql(subquery=True, with_alias=True, **kwargs),
            on=self.on_criterion.get_sql(subquery=True, **kwargs),
            branches=" ".join(
                branch.get_sql(self, by_target_keyword=self._uses_by_target_keyword(), **kwargs)
                for branch in self.branches
            ),
        )
        return sql + ";" if self.TERMINATE_WITH_SEMICOLON else sql

    def _merge_keyword(self) -> str:
        return "MERGE"

    def _uses_by_target_keyword(self) -> bool:
        return False

    def __str__(self) -> str:
        return self.get_sql()


class PostgreSQLMergeQueryBuilder(MergeQueryBuilder):
    DIALECT = Dialects.POSTGRESQL

    @property
    def supported_matches(self) -> tuple[MergeMatch, ...]:
        return (MergeMatch.matched, MergeMatch.not_matched_by_target)

    def _merge_keyword(self) -> str:
        return "MERGE INTO"


class MSSQLMergeQueryBuilder(MergeQueryBuilder):
    DIALECT = Dialects.MSSQL
    TERMINATE_WITH_SEMICOLON = True

    def _uses_by_target_keyword(self) -> bool:
        return True
