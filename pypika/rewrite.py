"""
Binding-aware relation rewriting for PyPika queries.

This module provides :func:`replace_relation`, a scope-resolving alternative
to `QueryBuilder.replace_table`.  Whereas `replace_table` compares tables by
value (name/schema/alias equality) and therefore rewrites *every* matching
table -- including unrelated occurrences in subqueries or self-joins that
happen to compare equal -- `replace_relation` targets exactly one relation
*occurrence* (a specific `FROM` or `JOIN` item inside a specific query
scope) and only rewrites:

* the relation itself, and
* the fields that actually bind to it, following SQL scoping rules:

  - a field binds to the nearest enclosing scope that exposes its namespace
    (table alias or name);
  - correlated subqueries see the relations of their outer scopes, so outer
    references inside them are rewritten together with the target;
  - an inner scope that re-binds the same name/alias shadows the outer
    relation, so fields inside it are left untouched;
  - derived tables (subqueries in `FROM`/`JOIN`) and CTE bodies open a
    fresh, non-correlated scope.

All clauses are traversed: `SELECT`, `JOIN` (items and `ON` criteria),
`WHERE`/`PREWHERE`, `GROUP BY`, `HAVING`, `QUALIFY`, `ORDER BY`, set
operations and `WITH` (CTE) definitions.

The replacement may be a plain table name, a `Table`, or an aliased subquery
(`QueryBuilder`/`_SetOperation`/`AliasedQuery`).  When the replacement is a
subquery its selected columns are checked for compatibility with the fields
that were bound to the replaced relation.

The input query is never mutated: the rewritten query is built by copying
only the nodes along changed paths, so the original object still compiles to
the exact same SQL afterwards.  Ambiguities that cannot be resolved (e.g. an
unqualified reference in a self-join without aliases) raise an error instead
of being guessed.
"""

from __future__ import annotations

from copy import copy
from typing import Any, Callable, Iterator, Union

from pypika.queries import (
    AliasedQuery,
    JoinOn,
    JoinUsing,
    QueryBuilder,
    Selectable,
    Table,
    _SetOperation,
)
from pypika.terms import Field, Node, Star
from pypika.utils import QueryException


class RelationRewriteError(QueryException):
    """Base class for errors raised while rewriting a relation."""


class RelationNotFoundError(RelationRewriteError):
    """Raised when the target relation cannot be found in the query."""


class AmbiguousRelationError(RelationRewriteError):
    """Raised when a reference cannot be bound to a single relation occurrence."""


class UnboundRelationError(RelationRewriteError):
    """Raised when a reference to the target namespace is not visible from its scope."""


class IncompatibleColumnsError(RelationRewriteError):
    """Raised when a subquery replacement does not expose the columns bound to the target."""


class RelationRef:
    """
    Identifies exactly one occurrence of a relation: a specific `FROM` or `JOIN` item owned by a
    specific query scope.  Two relations with the same table name or alias (self-joins, shadowing
    subqueries) are distinct `RelationRef` instances.

    Instances are obtained via :func:`iter_relations` or :func:`find_relation` and can be passed
    to :func:`replace_relation` as an unambiguous target.
    """

    __slots__ = ("scope", "kind", "index", "selectable")

    def __init__(self, scope: QueryBuilder, kind: str, index: int, selectable: Selectable) -> None:
        self.scope = scope
        self.kind = kind  # "from" or "join"
        self.index = index
        self.selectable = selectable

    @property
    def name(self) -> str:
        """The namespace (alias or table name) this relation exposes to its scope."""
        return self.selectable.get_table_name()

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, RelationRef)
            and self.scope is other.scope
            and self.kind == other.kind
            and self.index == other.index
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((id(self.scope), self.kind, self.index))

    def __repr__(self) -> str:
        return "RelationRef({name!r}, {kind}[{index}], scope={scope})".format(
            name=self.name, kind=self.kind, index=self.index, scope=hex(id(self.scope))
        )


class _ScopeEntry:
    """One relation visible inside a scope: its namespace, the selectable, and its occurrence."""

    __slots__ = ("name", "selectable", "ref")

    def __init__(self, name: str, selectable: Selectable, ref: RelationRef | None) -> None:
        self.name = name
        self.selectable = selectable
        self.ref = ref


class _ResolutionContext:
    """
    The chain of scopes visible from a point in the query.

    `scopes` holds relation entries per enclosing `QueryBuilder`, outermost first; resolution
    walks it in reverse so the innermost scope wins (shadowing).  `ctes` holds the CTE names
    visible at that point; they can never be the rewrite target but terminate resolution.
    """

    __slots__ = ("scopes", "ctes")

    def __init__(self, scopes: list | None = None, ctes: list | None = None) -> None:
        self.scopes = scopes if scopes is not None else []
        self.ctes = ctes if ctes is not None else []


def _scope_refs(query: QueryBuilder) -> list:
    """The relation occurrences owned directly by one query scope."""
    refs = [RelationRef(query, 'from', index, item) for index, item in enumerate(query._from)]
    refs += [RelationRef(query, 'join', index, join.item) for index, join in enumerate(query._joins)]
    return refs


def _walk_scopes(node: Any) -> Iterator:
    """Yields every QueryBuilder scope reachable from node, including CTE bodies."""
    if node is None:
        return
    if isinstance(node, (list, tuple, set, frozenset)):
        for value in node:
            yield from _walk_scopes(value)
        return
    if isinstance(node, QueryBuilder):
        yield node
        for clause in node._with:
            yield from _walk_scopes(clause.query)
        for item in node._from:
            yield from _walk_scopes(item)
        for join in node._joins:
            yield from _walk_scopes(join.item)
            yield from _walk_scopes(getattr(join, 'criterion', None))
            yield from _walk_scopes(getattr(join, 'fields', None))
        yield from _walk_scopes(node._selects)
        yield from _walk_scopes(node._columns)
        yield from _walk_scopes(node._values)
        yield from _walk_scopes(node._updates)
        yield from _walk_scopes(node._groupbys)
        yield from _walk_scopes(node._orderbys)
        yield from _walk_scopes(node._wheres)
        yield from _walk_scopes(node._prewheres)
        yield from _walk_scopes(node._havings)
        yield from _walk_scopes(node._qualifys)
        return
    if isinstance(node, _SetOperation):
        yield from _walk_scopes(node.base_query)
        for _, set_operation_query in node._set_operation:
            yield from _walk_scopes(set_operation_query)
        yield from _walk_scopes(node._orderbys)
        return
    if isinstance(node, Node):
        for value in vars(node).values():
            yield from _walk_scopes(value)


def iter_relations(query: QueryBuilder | _SetOperation) -> list:
    """
    Lists every relation occurrence (every FROM and JOIN item in every scope, including
    subqueries and CTE bodies) of `query`.  Two occurrences of the same table -- e.g. both sides
    of a self-join, or an outer relation and a same-named relation re-bound inside a subquery --
    appear as distinct `RelationRef` entries.

    :param query: The query to inspect.
    :return: A list of `RelationRef`, in traversal order.
    """
    return [ref for scope in _walk_scopes(query) for ref in _scope_refs(scope)]


def find_relation(query: QueryBuilder | _SetOperation, match: Union[Selectable, str, Callable]) -> RelationRef:
    """
    Finds the single relation occurrence in `query` identified by `match`:

    * a `Selectable` instance matches the occurrence using that exact object (identity, not
      equality -- a fresh Table('orders') will not match an existing Table('orders'));
    * a string matches occurrences whose namespace (alias) or table name equals it;
    * a callable receives each `RelationRef` and should return True for matches.

    :raises RelationNotFoundError: if nothing matches.
    :raises AmbiguousRelationError: if more than one occurrence matches; inspect
        :func:`iter_relations` and pass a `RelationRef` to disambiguate.
    """
    refs = iter_relations(query)
    if isinstance(match, Selectable):
        found = [ref for ref in refs if ref.selectable is match]
        description = repr(match)
    elif callable(match):
        found = [ref for ref in refs if match(ref)]
        description = getattr(match, '__name__', repr(match))
    else:
        name = str(match)
        found = [
            ref
            for ref in refs
            if ref.name == name or (isinstance(ref.selectable, Table) and ref.selectable._table_name == name)
        ]
        description = name

    if not found:
        raise RelationNotFoundError('No relation matching {match!r} was found in the query.'.format(match=description))
    if len(found) > 1:
        raise AmbiguousRelationError(
            '{match!r} matches {count} relation occurrences: {refs}. '.format(
                match=description, count=len(found), refs=', '.join(map(repr, found))
            )
            + 'Pass the RelationRef of the intended occurrence to replace_relation instead.'
        )
    return found[0]


class _RelationRewriter:
    """
    Rewrites one relation occurrence and every field bound to it.

    Only nodes along changed paths are copied; untouched subtrees are shared with the original
    query, which is therefore never mutated.
    """

    def __init__(self, target: RelationRef, replacement: Selectable) -> None:
        self.target = target
        self.replacement = replacement
        self.target_name = target.name
        self.bound_field_names = set()

    def run(self, root: Any) -> Any:
        return self._rewrite_node(root, _ResolutionContext())

    # -- query scopes ------------------------------------------------------

    def _rewrite_query(self, query: QueryBuilder, ctx: _ResolutionContext) -> QueryBuilder:
        # CTE bodies are non-correlated: they only see the CTEs defined before them.
        ctes = list(ctx.ctes)
        new_with = []
        for clause in query._with:
            new_clause = clause
            if clause.query is not None:
                new_body = self._rewrite_node(clause.query, _ResolutionContext(ctes=ctes))
                if new_body is not clause.query:
                    new_clause = copy(clause)
                    new_clause.query = new_body
            new_with.append(new_clause)
            ctes.append(_ScopeEntry(clause.name, new_clause, None))

        entries = [
            _ScopeEntry(item.get_table_name(), item, RelationRef(query, 'from', index, item))
            for index, item in enumerate(query._from)
        ]
        entries += [
            _ScopeEntry(join.item.get_table_name(), join.item, RelationRef(query, 'join', index, join.item))
            for index, join in enumerate(query._joins)
        ]

        # Expressions of this query (SELECT/WHERE/...) see its own relations plus all outer ones.
        inner = _ResolutionContext(scopes=ctx.scopes + [entries], ctes=ctes)
        # Derived tables in FROM/JOIN are non-correlated: they only see CTEs.
        detached = _ResolutionContext(ctes=ctes)

        changed = {}

        new_from = []
        for index, item in enumerate(query._from):
            if RelationRef(query, 'from', index, item) == self.target:
                new_from.append(self.replacement)
            else:
                new_from.append(self._rewrite_from_item(item, detached))
        self._collect(changed, '_from', new_from, query._from)

        new_joins = []
        for index, join in enumerate(query._joins):
            updates = {}
            if RelationRef(query, 'join', index, join.item) == self.target:
                updates['item'] = self.replacement
            else:
                new_item = self._rewrite_from_item(join.item, detached)
                if new_item is not join.item:
                    updates['item'] = new_item
            if isinstance(join, JoinOn):
                new_criterion = self._rewrite_node(join.criterion, inner)
                if new_criterion is not join.criterion:
                    updates['criterion'] = new_criterion
            elif isinstance(join, JoinUsing):
                new_fields = [self._rewrite_node(field, inner) for field in join.fields]
                if self._is_changed(new_fields, join.fields):
                    updates['fields'] = new_fields
            if updates:
                new_join = copy(join)
                for attr, value in updates.items():
                    setattr(new_join, attr, value)
                new_joins.append(new_join)
            else:
                new_joins.append(join)
        self._collect(changed, '_joins', new_joins, query._joins)

        self._collect(changed, '_with', new_with, query._with)

        for attr in (
            '_selects',
            '_columns',
            '_values',
            '_updates',
            '_groupbys',
            '_orderbys',
            '_wheres',
            '_prewheres',
            '_havings',
            '_qualifys',
        ):
            new_value = self._rewrite_value(getattr(query, attr), inner)
            if new_value is not getattr(query, attr):
                changed[attr] = new_value

        if any(table is self.target.selectable for table in query._select_star_tables):
            changed['_select_star_tables'] = {
                self.replacement if table is self.target.selectable else table for table in query._select_star_tables
            }

        if not changed:
            return query
        clone = copy(query)
        for attr, value in changed.items():
            setattr(clone, attr, value)
        return clone

    def _rewrite_set_operation(self, node: _SetOperation, ctx: _ResolutionContext) -> _SetOperation:
        changed = {}
        new_base = self._rewrite_query(node.base_query, ctx)
        if new_base is not node.base_query:
            changed['base_query'] = new_base

        new_operations = []
        for set_operation, set_operation_query in node._set_operation:
            new_query = self._rewrite_node(set_operation_query, ctx)
            new_operations.append((set_operation, new_query))
        self._collect(changed, '_set_operation', new_operations, node._set_operation)

        # ORDER BY of a set operation may reference the base query's relations.
        base_entries = [
            _ScopeEntry(item.get_table_name(), item, RelationRef(node.base_query, 'from', index, item))
            for index, item in enumerate(node.base_query._from)
        ]
        inner = _ResolutionContext(scopes=ctx.scopes + [base_entries], ctes=ctx.ctes)
        new_orderbys = self._rewrite_value(node._orderbys, inner)
        if new_orderbys is not node._orderbys:
            changed['_orderbys'] = new_orderbys

        if not changed:
            return node
        clone = copy(node)
        for attr, value in changed.items():
            setattr(clone, attr, value)
        return clone

    def _rewrite_from_item(self, item: Selectable, ctx: _ResolutionContext) -> Selectable:
        if isinstance(item, (QueryBuilder, _SetOperation)):
            return self._rewrite_node(item, ctx)
        if isinstance(item, AliasedQuery) and item.query is not None:
            new_query = self._rewrite_node(item.query, ctx)
            if new_query is not item.query:
                clone = copy(item)
                clone.query = new_query
                return clone
        return item

    # -- terms -------------------------------------------------------------

    def _rewrite_node(self, node: Any, ctx: _ResolutionContext) -> Any:
        if isinstance(node, QueryBuilder):
            return self._rewrite_query(node, ctx)
        if isinstance(node, _SetOperation):
            return self._rewrite_set_operation(node, ctx)
        if isinstance(node, Field):
            return self._rewrite_field(node, ctx)
        if isinstance(node, Node):
            return self._rewrite_generic(node, ctx)
        return node

    def _rewrite_generic(self, node: Node, ctx: _ResolutionContext) -> Node:
        updates = {}
        for attr, value in vars(node).items():
            new_value = self._rewrite_value(value, ctx)
            if new_value is not value:
                updates[attr] = new_value
        if not updates:
            return node
        clone = copy(node)
        for attr, value in updates.items():
            setattr(clone, attr, value)
        return clone

    def _rewrite_value(self, value: Any, ctx: _ResolutionContext) -> Any:
        if isinstance(value, Node):
            return self._rewrite_node(value, ctx)
        if isinstance(value, (list, tuple)):
            new_items = [self._rewrite_value(item, ctx) for item in value]
            if self._is_changed(new_items, value):
                return type(value)(new_items)
        return value

    def _rewrite_field(self, field: Field, ctx: _ResolutionContext) -> Field:
        table = field.table
        if table is None:
            return field
        entry = self._resolve(table, ctx)
        if entry is None or entry.ref != self.target:
            return field
        clone = copy(field)
        clone.table = self.replacement
        if field.name != '*':
            self.bound_field_names.add(field.name)
        return clone

    # -- name resolution ---------------------------------------------------

    def _resolve(self, table: Selectable, ctx: _ResolutionContext) -> _ScopeEntry | None:
        """
        Binds a field's table reference to a relation occurrence following SQL scoping rules:
        innermost scope first; identity match wins over name match; an inner scope that
        re-binds the same name shadows outer relations.
        """
        name = table.get_table_name()
        for scope in reversed(ctx.scopes):
            matches = [entry for entry in scope if entry.selectable is table or entry.name == name]
            if not matches:
                continue
            identity = [entry for entry in matches if entry.selectable is table]
            if len(identity) == 1:
                return identity[0]
            if len(matches) > 1:
                raise AmbiguousRelationError(
                    'Reference to {name!r} is ambiguous in this scope; it could bind to any of: {refs}. '.format(
                        name=name, refs=', '.join(repr(entry.ref) for entry in matches)
                    )
                    + 'Qualify the field with the exact table instance or use aliases.'
                )
            return matches[0]
        for entry in reversed(ctx.ctes):
            if entry.selectable is table or entry.name == name:
                return entry
        if name == self.target_name:
            raise UnboundRelationError(
                'Reference to {name!r} (the namespace of the relation being replaced) is not visible '.format(name=name)
                + 'from the scope it is used in; refusing to guess its binding.'
            )
        return None

    @staticmethod
    def _is_changed(new_items: list, old_items: Any) -> bool:
        return any(new is not old for new, old in zip(new_items, old_items))

    def _collect(self, changed: dict, attr: str, new_items: list, old_items: list) -> None:
        if self._is_changed(new_items, old_items):
            changed[attr] = new_items


def _output_columns(selectable: Selectable) -> set | None:
    """
    The column names a selectable exposes, or None when they cannot be determined statically
    (plain tables, `SELECT *`, unaliased expressions).
    """
    if isinstance(selectable, _SetOperation):
        return _output_columns(selectable.base_query)
    if isinstance(selectable, AliasedQuery):
        return _output_columns(selectable.query) if selectable.query is not None else None
    if isinstance(selectable, QueryBuilder):
        if selectable._select_star:
            return None
        columns = set()
        for term in selectable._selects:
            if isinstance(term, Star):
                return None
            if term.alias:
                columns.add(term.alias)
            elif isinstance(term, Field):
                columns.add(term.name)
            else:
                return None
        return columns
    return None


def _prepare_replacement(target: RelationRef, replacement: Any) -> Selectable:
    if isinstance(replacement, str):
        replacement = Table(replacement)
    if not isinstance(replacement, Selectable):
        raise TypeError(
            'replacement must be a table name, Table, or (aliased) subquery; got {kind}'.format(
                kind=type(replacement).__name__
            )
        )
    if getattr(replacement, 'alias', None) is None:
        # Inherit the replaced relation's alias so existing references stay valid; the user's
        # replacement object is copied by as_(), never mutated.
        alias = getattr(target.selectable, 'alias', None)
        if alias is not None:
            replacement = replacement.as_(alias)
        elif isinstance(replacement, (QueryBuilder, _SetOperation)):
            replacement = replacement.as_('sq0')
    return replacement


def replace_relation(
    query: QueryBuilder | _SetOperation,
    target: RelationRef | Selectable | str | Callable,
    replacement: Selectable | str,
) -> QueryBuilder | _SetOperation:
    """
    Returns a copy of `query` in which one relation occurrence -- and only the fields that bind
    to it -- is replaced by `replacement`.

    :param query:
        The query to rewrite.  It is never mutated; the returned query shares all untouched
        subtrees with it.
    :param target:
        Identifies the occurrence to replace: a `RelationRef` from :func:`iter_relations`/
        :func:`find_relation`, the exact `Selectable` instance used in the FROM/JOIN clause,
        a name (if unambiguous), or a predicate over `RelationRef`.
    :param replacement:
        A table name, `Table`, or (aliased) subquery.  If it carries no alias it inherits the
        replaced relation's alias.  A subquery replacement must expose every column that was
        selected through the replaced relation.
    :return:
        The rewritten query.
    :raises RelationNotFoundError:
        The target does not occur in the query.
    :raises AmbiguousRelationError:
        The target, or a field reference, cannot be bound to a single occurrence.
    :raises UnboundRelationError:
        A reference to the target's namespace is not visible from the scope it is used in.
    :raises IncompatibleColumnsError:
        A subquery replacement does not expose a column bound to the replaced relation.
    """
    ref = target if isinstance(target, RelationRef) else find_relation(query, target)
    replacement = _prepare_replacement(ref, replacement)

    rewriter = _RelationRewriter(ref, replacement)
    new_query = rewriter.run(query)

    columns = _output_columns(replacement)
    if columns is not None:
        missing = rewriter.bound_field_names - columns
        if missing:
            raise IncompatibleColumnsError(
                'Replacement subquery does not expose column(s) {missing} required by references to {name!r}.'.format(
                    missing=', '.join(sorted(missing)), name=ref.name
                )
            )
    return new_query
