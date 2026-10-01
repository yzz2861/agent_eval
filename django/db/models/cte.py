import re
from itertools import count

from django.core.exceptions import FieldError
from django.db.models.expressions import Col
from django.db.models.lookups import (
    Exact,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
)
from django.db.models.query import QuerySet, ValuesIterable
from django.db.models.query_utils import Q
from django.db.models.sql.datastructures import BaseTable
from django.db.models.sql.query import Query
from django.db.models.sql.where import WhereNode


IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_cte_counter = count()


class CTETable(BaseTable):
    def __init__(self, cte):
        self.cte = cte
        super().__init__(cte.sql_name, cte.sql_name)

    def relabeled_clone(self, change_map):
        clone = self.__class__(self.cte)
        clone.table_alias = change_map.get(self.table_alias, self.table_alias)
        return clone


class CTEJoin(CTETable):
    join_type = "INNER JOIN"
    nullable = False
    filtered_relation = None
    identity = None

    def __init__(self, cte, parent_alias, condition):
        super().__init__(cte)
        self.parent_alias = parent_alias
        self.condition = condition

    def as_sql(self, compiler, connection):
        condition, params = compiler.compile(self.condition)
        qn = compiler.quote_name
        return (
            f"INNER JOIN {qn(self.table_name)} {qn(self.table_alias)} ON ({condition})",
            params,
        )

    def relabeled_clone(self, change_map):
        condition = (
            self.condition.relabeled_clone(change_map)
            if self.condition is not None
            else None
        )
        clone = self.__class__(
            self.cte,
            change_map.get(self.parent_alias, self.parent_alias),
            condition,
        )
        clone.table_alias = change_map.get(self.table_alias, self.table_alias)
        return clone


class RecursiveCTEJoin(CTEJoin):
    def relabeled_clone(self, change_map):
        clone = super().relabeled_clone(change_map)
        recursive_alias = f"{self.cte.sql_name}_recursive"
        if recursive_alias in change_map:
            clone.condition = clone.condition.relabeled_clone(change_map)
        return clone


class CTEColumn(Col):
    def exact(self, value):
        return Exact(self, value)

    def gt(self, value):
        return GreaterThan(self, value)

    def gte(self, value):
        return GreaterThanOrEqual(self, value)

    def lt(self, value):
        return LessThan(self, value)

    def lte(self, value):
        return LessThanOrEqual(self, value)


class RecursiveCTE:
    def __init__(self, anchor, recursive=None, name=None):
        name = name or "recursive_cte"
        if not IDENTIFIER_RE.fullmatch(name):
            raise ValueError("CTE names must be valid SQL identifiers.")
        self.name = name
        self._id = next(_cte_counter)
        self.sql_name = f"{name}_{self._id}"
        self.anchor = self._get_query(anchor).clone()
        self.fields = self._get_fields()
        if callable(recursive):
            recursive = recursive(self)
        if recursive is None:
            raise ValueError("A recursive queryset is required.")
        self.recursive = self._get_query(recursive).clone()
        self.dependencies = tuple(
            dict.fromkeys((*self.anchor.ctes, *self.recursive.ctes))
        )

    @staticmethod
    def _get_query(queryset):
        if isinstance(queryset, QuerySet):
            return queryset.query
        if isinstance(queryset, Query):
            return queryset
        raise TypeError("CTE queries must be QuerySet or Query instances.")

    def _get_fields(self):
        query = self.anchor
        if query.selected is None:
            raise ValueError(
                "CTE queries must explicitly select fields with .values()."
            )
        fields = []
        for name, expression in query.selected.items():
            if isinstance(expression, str):
                expression = query.annotations[expression]
            elif isinstance(expression, int):
                opts = query.get_meta()
                if opts is None:
                    raise FieldError(f"Cannot resolve CTE column {name!r}.")
                target_field = opts.concrete_fields[expression].clone()
                target_field.model = None
                target_field.name = name
                target_field.attname = name
                target_field.column = name
                target_field.primary_key = False
                expression = CTEColumn(None, target_field)
            field = expression._output_field_or_none
            if field is None:
                raise FieldError(f"Cannot infer type for CTE column {name!r}.")
            field = field.clone()
            field.model = None
            field.name = name
            field.attname = name
            field.column = name
            field.primary_key = False
            fields.append((name, field))
        return tuple(fields)

    def _result_query(self):
        alias = self.sql_name
        query = Query(None)
        query.ctes = (self,)
        table = CTETable(self)
        query.alias_map[alias] = table
        query.alias_refcount[alias] = 1
        query.table_map[self.sql_name] = [alias]
        for name, field in self.fields:
            query.annotations[name] = CTEColumn(alias, field)
        names = tuple(name for name, field in self.fields)
        query.set_values(names)
        return query

    def queryset(self, using=None):
        queryset = QuerySet(
            model=None,
            query=self._result_query(),
            using=using,
        )
        queryset._fields = tuple(name for name, field in self.fields)
        queryset._iterable_class = ValuesIterable
        return queryset

    def __getitem__(self, name):
        return self.col(name)


    def col(self, name, alias=None):
        try:
            field = next(
                field
                for field_name, field in self.fields
                if field_name == name
            )
        except StopIteration:
            raise FieldError(f"CTE {self.name!r} has no column {name!r}.")
        return CTEColumn(alias or self.sql_name, field)

    def join(self, queryset, *on_conditions, on=None, **conditions):
        if not isinstance(queryset, QuerySet):
            raise TypeError("recursive must be called with a QuerySet.")
        clone = queryset._chain()
        query = clone.query
        query.get_initial_alias()
        parent_alias = query.base_table
        self_alias = f"{self.sql_name}_recursive"
        raw_conditions = []
        if on is not None:
            raw_conditions.append(on)
        raw_conditions.extend(on_conditions)
        for cte_name, value in conditions.items():
            comparison = self.col(cte_name, self_alias).exact(value)
            raw_conditions.append(comparison)
        if not raw_conditions:
            raise ValueError("A recursive join condition is required.")
        join = RecursiveCTEJoin(self, parent_alias, None)
        join.table_alias = self_alias
        query.alias_map[self_alias] = join
        query.alias_refcount[self_alias] = 1
        query.table_map.setdefault(self.sql_name, []).append(self_alias)
        resolved = None
        for raw_condition in raw_conditions:
            condition = raw_condition.resolve_expression(query)
            if type(condition) is Q:
                condition, _ = query._add_q(condition, None, split_subq=False)
            condition = condition.relabeled_clone({self.sql_name: self_alias})
            resolved = [condition] if resolved is None else [*resolved, condition]
        resolved = WhereNode(resolved)
        join.condition = resolved
        query.select = tuple(
            expression.relabeled_clone({self.sql_name: self_alias})
            for expression in query.select
        )
        query.annotations = {
            key: expression.relabeled_clone({self.sql_name: self_alias})
            for key, expression in query.annotations.items()
        }
        return clone

    def _attach_to(self, target, outer):
        if any(existing is self for existing in outer.ctes):
            target.ctes = tuple(cte for cte in target.ctes if cte is not self)
            return
        if any(existing.name == self.name for existing in outer.ctes):
            return
        target.ctes = tuple(cte for cte in target.ctes if cte is not self)
        outer.add_cte(self)
