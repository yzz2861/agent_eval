from __future__ import annotations

import copy
from typing import Any

from pypika.queries import AliasedQuery, JoinOn, JoinUsing, QueryBuilder, Selectable, Table, _SetOperation
from pypika.terms import Field, Node, Star
from pypika.utils import QueryException


class RelationRewriteException(QueryException):
    pass


class _Scope:
    def __init__(
        self,
        relations: list[Selectable],
        target: Selectable | None = None,
        replacement: Selectable | None = None,
        outer: _Scope | None = None,
        blocked_names: set[str] | None = None,
    ) -> None:
        self.outer = outer
        self.relations = tuple(relations)
        self.relation_ids = {id(relation) for relation in relations}
        self.current_replacements = {}
        if target is not None and replacement is not None:
            self.current_replacements[id(target)] = replacement
        self.visible_replacements = dict(outer.visible_replacements if outer else {})
        self.visible_replacements.update(self.current_replacements)
        self.target = target
        self.target_name = target.get_table_name() if target is not None else None
        self.blocked_names = set(outer.blocked_names if outer else set())
        if blocked_names:
            self.blocked_names.update(blocked_names)

        visible = list(relations)
        if outer:
            visible.extend(outer.visible_relations)
        self.visible_relations = tuple(visible)


class _RelationRewriter:
    def __init__(self, query: QueryBuilder | _SetOperation, target: Selectable, replacement: Selectable) -> None:
        self.original_query = query
        self.original_target = target
        self.original_replacement = replacement
        self.query: QueryBuilder | _SetOperation
        self.target: Selectable
        self.replacement_template: Selectable
        self.replacement_ids: set[int] = set()
        self.processed_scopes: dict[int, _Scope] = {}
        self.binding_count = 0
        self.referenced_columns: set[str] = set()
        self.references_star = False

    def rewrite(self) -> QueryBuilder | _SetOperation:
        self._validate_inputs()

        memo: dict[int, Any] = {}
        self.query = copy.deepcopy(self.original_query, memo)
        self.target = memo.get(id(self.original_target))
        self.replacement_template = self.original_replacement

        if isinstance(self.query, QueryBuilder):
            self._rewrite_query(self.query, None)
        else:
            self._rewrite_set_operation(self.query, None)

        if self.binding_count != 1:
            raise RelationRewriteException(
                "Expected exactly one binding for the target relation, found {}.".format(self.binding_count)
            )

        self._validate_replacement_columns()
        return self.query

    def _validate_inputs(self) -> None:
        if not isinstance(self.original_target, Selectable):
            raise RelationRewriteException("Target relation must be a Selectable.")
        if not isinstance(self.original_replacement, Selectable):
            raise RelationRewriteException("Replacement relation must be a Selectable.")
        if self.original_target is self.original_replacement:
            raise RelationRewriteException("Target and replacement relations must be different objects.")

    def _rewrite_query(self, query: QueryBuilder, outer: _Scope | None) -> _Scope:
        previous_outer = self.processed_scopes.get(id(query))
        if previous_outer is not None and previous_outer is not outer:
            raise RelationRewriteException("A reusable query node is referenced from different scopes.")
        self.processed_scopes[id(query)] = outer

        for cte in query._with:
            if isinstance(cte, AliasedQuery) and isinstance(cte.query, (QueryBuilder, _SetOperation)):
                if isinstance(cte.query, QueryBuilder):
                    self._rewrite_query(cte.query, None)
                else:
                    self._rewrite_set_operation(cte.query, None)

        relations = list(query._from) + [join.item for join in query._joins]
        target = next((relation for relation in relations if relation is self.target), None)
        replacement = None
        if target is not None:
            replacement = self._bind_target(relations, target)

        blocked_names = {relation.get_table_name() for relation in relations if relation is not target}
        scope = _Scope(relations, target, replacement, outer, blocked_names)

        for relation in relations:
            if relation is target:
                continue
            if isinstance(relation, QueryBuilder):
                self._rewrite_query(relation, scope)
            elif isinstance(relation, _SetOperation):
                self._rewrite_set_operation(relation, scope)

        if target is not None:
            query._from = [replacement if relation is target else relation for relation in query._from]
            for join in query._joins:
                if join.item is target:
                    join.item = replacement

            query._select_star_tables = {
                replacement if relation is target else relation for relation in query._select_star_tables
            }

        self._rewrite_query_terms(query, scope)
        return scope

    def _bind_target(self, relations: list[Selectable], target: Selectable) -> Selectable:
        if sum(relation is target for relation in relations) != 1:
            raise RelationRewriteException("Target relation is bound more than once in the same query scope.")

        self.binding_count += 1
        replacement = copy.deepcopy(self.replacement_template)
        if isinstance(replacement, (QueryBuilder, _SetOperation)) and not replacement.alias:
            raise RelationRewriteException("A subquery replacement must be used with an alias.")

        replacement_name = replacement.get_table_name()
        conflicting_names = {relation.get_table_name() for relation in relations if relation is not target}
        if replacement_name in conflicting_names:
            raise RelationRewriteException(
                "Replacement relation alias '{}' conflicts with another relation in the same scope.".format(
                    replacement_name
                )
            )

        self.replacement_ids.add(id(replacement))
        return replacement

    def _rewrite_query_terms(self, query: QueryBuilder, scope: _Scope) -> None:
        query._selects = [self._rewrite_node(term, scope) for term in query._selects]
        query._wheres = self._rewrite_node(query._wheres, scope)
        query._prewheres = self._rewrite_node(query._prewheres, scope)
        query._groupbys = [self._rewrite_node(term, scope) for term in query._groupbys]
        query._havings = self._rewrite_node(query._havings, scope)
        query._qualifys = self._rewrite_node(query._qualifys, scope)
        query._orderbys = [(self._rewrite_node(term, scope), direction) for term, direction in query._orderbys]

        for join in query._joins:
            if isinstance(join, JoinOn):
                join.criterion = self._rewrite_node(join.criterion, scope)
            elif isinstance(join, JoinUsing) and scope.target is not None:
                replacement = scope.current_replacements[id(scope.target)]
                for field in join.fields:
                    self._record_field_reference(field, replacement)

        if "_distinct_on" in query.__dict__:
            query._distinct_on = [self._rewrite_node(term, scope) for term in query._distinct_on]
        if "_limit_by" in query.__dict__ and query._limit_by is not None:
            limit, offset, terms = query._limit_by
            query._limit_by = (limit, offset, [self._rewrite_node(term, scope) for term in terms])

    def _rewrite_set_operation(self, operation: _SetOperation, outer: _Scope | None) -> _Scope | None:
        previous_outer = self.processed_scopes.get(id(operation))
        if previous_outer is not None and previous_outer is not outer:
            raise RelationRewriteException("A reusable set-operation node is referenced from different scopes.")
        self.processed_scopes[id(operation)] = outer

        base_scope = self._rewrite_query(operation.base_query, outer)
        for _, query in operation._set_operation:
            self._rewrite_query(query, outer)
        operation._orderbys = [
            (self._rewrite_node(term, base_scope), direction) for term, direction in operation._orderbys
        ]
        return base_scope

    def _rewrite_node(self, node: Any, scope: _Scope | None) -> Any:
        if node is None or isinstance(node, (str, int, float, bool, bytes)):
            return node
        if isinstance(node, QueryBuilder):
            self._rewrite_query(node, scope)
            return node
        if isinstance(node, _SetOperation):
            self._rewrite_set_operation(node, scope)
            return node
        if isinstance(node, AliasedQuery):
            return node
        if isinstance(node, Node):
            if id(node) in self.replacement_ids:
                return node
            if isinstance(node, Field):
                self._rebind_field(node, scope)
            for name, value in vars(node).items():
                if isinstance(node, Field) and name == "table":
                    continue
                setattr(node, name, self._rewrite_value(value, scope))
        return node

    def _rewrite_value(self, value: Any, scope: _Scope | None) -> Any:
        if isinstance(value, list):
            return [self._rewrite_node(item, scope) for item in value]
        if isinstance(value, tuple):
            return tuple(self._rewrite_node(item, scope) for item in value)
        if isinstance(value, set):
            return {self._rewrite_node(item, scope) for item in value}
        if isinstance(value, dict):
            return {key: self._rewrite_node(item, scope) for key, item in value.items()}
        return self._rewrite_node(value, scope)

    def _rebind_field(self, field: Field, scope: _Scope | None) -> None:
        if isinstance(field, Star) and field.table is None:
            return
        if scope is None:
            return

        if field.table is not None:
            if id(field.table) in scope.current_replacements:
                replacement = scope.current_replacements[id(field.table)]
                self._record_field_reference(field, replacement)
                field.table = replacement
                return

            replacement = scope.visible_replacements.get(id(field.table))
            if replacement is not None:
                if (
                    id(field.table) not in scope.current_replacements
                    and replacement.get_table_name() in scope.blocked_names
                ):
                    raise RelationRewriteException(
                        "Outer relation '{}' is shadowed by a relation in an inner scope.".format(
                            replacement.get_table_name()
                        )
                    )
                self._record_field_reference(field, replacement)
                field.table = replacement
                return

            local_matches = [
                relation for relation in scope.relations if relation.get_table_name() == field.table.get_table_name()
            ]
            if len(local_matches) > 1:
                raise RelationRewriteException(
                    "Field binding '{}' is ambiguous in the current query scope.".format(field.table.get_table_name())
                )
            if local_matches:
                relation = local_matches[0]
                replacement = scope.current_replacements.get(id(relation))
                if replacement is not None:
                    self._record_field_reference(field, replacement)
                    field.table = replacement
                return

            outer = scope.outer
            while outer is not None:
                outer_matches = [
                    relation
                    for relation in outer.relations
                    if relation.get_table_name() == field.table.get_table_name()
                ]
                if outer_matches:
                    if len(outer_matches) > 1:
                        raise RelationRewriteException(
                            "Field binding '{}' is ambiguous in an outer query scope.".format(
                                field.table.get_table_name()
                            )
                        )
                    relation = outer_matches[0]
                    replacement = outer.current_replacements.get(id(relation))
                    if replacement is not None:
                        self._record_field_reference(field, replacement)
                        field.table = replacement
                    return
                outer = outer.outer

            return

        if len(scope.relations) == 1:
            relation = scope.relations[0]
            replacement = scope.current_replacements.get(id(relation))
            if replacement is not None:
                self._record_field_reference(field, replacement)
                field.table = replacement
            return
        if len(scope.relations) > 1:
            raise RelationRewriteException(
                "Unqualified field '{}' is ambiguous in a multi-relation scope.".format(field.name)
            )
        if len(scope.visible_relations) == 1:
            relation = scope.visible_relations[0]
            replacement = scope.visible_replacements.get(id(relation))
            if replacement is not None:
                self._record_field_reference(field, replacement)
                field.table = replacement
            return
        if len(scope.visible_relations) > 1:
            raise RelationRewriteException(
                "Unqualified field '{}' is ambiguous in a correlated scope.".format(field.name)
            )

    def _record_field_reference(self, field: Field, replacement: Selectable) -> None:
        if isinstance(field, Star) or field.name == "*":
            self.references_star = True
        else:
            self.referenced_columns.add(field.name)

    def _validate_replacement_columns(self) -> None:
        if self.references_star or not self.referenced_columns:
            return

        columns = self._replacement_columns(self.replacement_template)
        if columns is None:
            return

        missing_columns = self.referenced_columns - columns
        if missing_columns:
            raise RelationRewriteException(
                "Replacement relation is missing required column(s): {}.".format(", ".join(sorted(missing_columns)))
            )

    def _replacement_columns(self, relation: Selectable) -> set[str] | None:
        if isinstance(relation, Table):
            return None
        if isinstance(relation, AliasedQuery):
            if relation.query is None:
                return None
            return self._query_columns(relation.query)
        if isinstance(relation, QueryBuilder):
            return self._query_columns(relation)
        if isinstance(relation, _SetOperation):
            return self._query_columns(relation.base_query)
        return None

    def _query_columns(self, query: QueryBuilder | _SetOperation) -> set[str] | None:
        if isinstance(query, _SetOperation):
            return self._query_columns(query.base_query)
        if any(isinstance(select, Star) for select in query._selects):
            return None
        if not query._selects:
            return set()

        columns = set()
        for select in query._selects:
            if getattr(select, "alias", None):
                columns.add(select.alias)
            elif isinstance(select, Field):
                columns.add(select.name)
        return columns


def replace_relation(
    query: QueryBuilder | _SetOperation,
    target: Selectable,
    replacement: Selectable,
) -> QueryBuilder | _SetOperation:
    return _RelationRewriter(query, target, replacement).rewrite()
