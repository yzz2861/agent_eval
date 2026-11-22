"""Static pre-review of read-only report definitions.

This module offers a security-oriented, static pre-review entry point for
SELECT statements.  Given a caller-supplied manifest of approved views and
their columns, it traces every exported (projected) field back to the view
columns it originates from, following aliases, projections and subqueries.

No database statement is ever executed; the review is purely syntactic.

Only a small subset of SELECT syntax is supported:

* plain ``SELECT`` statements (no CTEs, no set operations, no DML/DDL),
* projections built from column references, literals, function calls and
  simple nested expressions,
* ``FROM`` clauses with views, aliases, joins and aliased subqueries.

Anything outside this subset raises :class:`UnsupportedStatementError`.
Referencing a view that is missing from the manifest raises
:class:`UnknownViewError`, i.e. the review stops immediately instead of
producing a partial result.

Columns whose origin can only be determined partially keep their known
sources together with "gaps" describing the missing evidence, so reviewers
can route them manually.  The approval queue of a column is derived from
its sources, therefore two exported columns that share the same name but
come from different views are routed to different queues.
"""

from collections.abc import Iterable, Mapping

from sqlparse import engine, sql
from sqlparse import tokens as T
from sqlparse.exceptions import SQLParseError
from sqlparse.utils import remove_quotes

__all__ = [
    "ColumnReview",
    "ReviewReport",
    "StaticReviewError",
    "UnknownViewError",
    "UnsupportedStatementError",
    "review",
]


class StaticReviewError(SQLParseError):
    """Base class for errors raised by the static pre-review."""


class UnsupportedStatementError(StaticReviewError):
    """The statement uses syntax outside the supported SELECT subset."""


class UnknownViewError(StaticReviewError):
    """A referenced view is missing from the approved view manifest."""


class ColumnReview:
    """Review result for a single exported column.

    :ivar name: Name under which the column is exported (alias or real
        name).
    :ivar queue: Approval queue key, derived from the resolved sources.
    :ivar sources: Tuple of ``(view, column)`` pairs the column
        originates from.
    :ivar gaps: Tuple of human-readable descriptions of evidence that
        could not be established statically.
    """

    __slots__ = ("gaps", "name", "queue", "sources")

    def __init__(self, name, sources, gaps=()):
        self.name = name
        self.sources = tuple(sorted(set(sources)))
        self.gaps = tuple(gaps)
        if self.sources:
            self.queue = "+".join(
                f"{view}.{col}" for view, col in self.sources
            )
        elif self.gaps:
            self.queue = "unresolved"
        else:
            self.queue = "constant"

    @property
    def complete(self):
        """``True`` if the origin of the column is fully established."""
        return not self.gaps

    def __repr__(self):
        return (
            f"<ColumnReview {self.name!r} queue={self.queue!r} "
            f"sources={self.sources!r} gaps={self.gaps!r}>"
        )

    def __eq__(self, other):
        if not isinstance(other, ColumnReview):
            return NotImplemented
        return (
            self.name == other.name
            and self.sources == other.sources
            and self.gaps == other.gaps
        )


class ReviewReport:
    """Aggregated result of a static pre-review.

    :ivar columns: Tuple of :class:`ColumnReview` items, one per exported
        column, in projection order.
    """

    __slots__ = ("columns",)

    def __init__(self, columns):
        self.columns = tuple(columns)

    @property
    def ok(self):
        """``True`` if every exported column has complete evidence."""
        return all(column.complete for column in self.columns)

    def queues(self):
        """Group exported column names by their approval queue."""
        grouped = {}
        for column in self.columns:
            grouped.setdefault(column.queue, []).append(column.name)
        return grouped

    def __iter__(self):
        return iter(self.columns)

    def __repr__(self):
        return f"<ReviewReport ok={self.ok} columns={len(self.columns)}>"


class _ViewSource:
    """A view from the approved manifest, usable as a column source."""

    __slots__ = ("columns", "view")

    def __init__(self, view, columns):
        self.view = view
        self.columns = tuple(columns)


class _DerivedSource:
    """An aliased subquery, usable as a column source.

    ``columns`` maps each exported name of the subquery to its
    ``(sources, gaps)`` pair.
    """

    __slots__ = ("columns",)

    def __init__(self, columns):
        self.columns = dict(columns)


def _lookup(mapping, key):
    """Return ``mapping[key]`` with a case-insensitive fallback."""
    if key in mapping:
        return mapping[key]
    lowered = key.lower()
    for candidate, value in mapping.items():
        if candidate.lower() == lowered:
            return value
    return None


def _lookup_name(names, key):
    """Return the declared spelling of *key* within *names*."""
    return _lookup({name: name for name in names}, key)


_CLAUSE_ENDERS = frozenset(
    [
        "GROUP BY",
        "ORDER BY",
        "HAVING",
        "LIMIT",
        "OFFSET",
        "WINDOW",
        "FOR",
    ]
)

_SET_OPERATIONS = frozenset(["UNION", "EXCEPT", "INTERSECT"])


class _Reviewer:
    def __init__(self, manifest):
        self._manifest = dict(manifest)

    def review_statement(self, stmt):
        first = stmt.token_first(skip_cm=True)
        if first is None:
            return []
        if first.ttype == T.Keyword.CTE:
            raise UnsupportedStatementError(
                "WITH (CTE) queries are not supported"
            )
        if stmt.get_type() != "SELECT":
            raise UnsupportedStatementError(
                "only plain SELECT statements are supported, "
                f"got {stmt.get_type()!r}"
            )
        for token in stmt.tokens:
            if (
                token.ttype in T.Keyword
                and token.normalized in _SET_OPERATIONS
            ):
                raise UnsupportedStatementError(
                    "set operations (UNION/EXCEPT/INTERSECT) "
                    "are not supported"
                )
        return self._review_select(stmt)

    def _review_select(self, stmt):
        projection, from_segment = self._split_select(stmt)
        scope = {}
        self._collect_sources(from_segment, scope)
        columns = []
        for item in projection:
            columns.extend(self._review_item(item, scope))
        return columns

    def _split_select(self, stmt):
        """Split a SELECT statement into projection and FROM tokens."""
        projection = []
        from_segment = []
        region = None
        for token in stmt.tokens:
            if region is None:
                if token.match(T.Keyword.DML, "SELECT"):
                    region = projection
                continue
            if region is projection:
                if token.match(T.Keyword, "FROM"):
                    region = from_segment
                    continue
                projection.append(token)
            else:
                if isinstance(token, sql.Where):
                    break
                if (
                    token.ttype in T.Keyword
                    and token.normalized in _CLAUSE_ENDERS
                ):
                    break
                from_segment.append(token)
        items = []
        for token in projection:
            if token.is_whitespace or token.ttype in T.Keyword:
                # skip whitespace and SELECT modifiers such as DISTINCT
                continue
            if isinstance(token, sql.IdentifierList):
                items.extend(token.get_identifiers())
            else:
                items.append(token)
        return items, from_segment

    def _collect_sources(self, segment, scope):
        skip_condition = False
        for token in segment:
            if token.is_whitespace:
                continue
            if token.ttype in T.Keyword:
                normalized = token.normalized
                if normalized == "ON":
                    skip_condition = True
                elif "JOIN" in normalized:
                    skip_condition = False
                continue
            if token.match(T.Punctuation, ","):
                skip_condition = False
                continue
            if skip_condition:
                continue
            if isinstance(token, sql.IdentifierList):
                for ident in token.get_identifiers():
                    self._add_source(ident, scope)
            elif isinstance(token, sql.Identifier):
                self._add_source(token, scope)
            elif isinstance(token, sql.Parenthesis):
                if self._is_subquery(token):
                    raise UnsupportedStatementError(
                        "derived tables require an alias"
                    )
                # anything else (e.g. JOIN ... USING (...)) is ignored

    def _add_source(self, ident, scope):
        parenthesis = next(
            (
                token
                for token in ident.tokens
                if isinstance(token, sql.Parenthesis)
            ),
            None,
        )
        if parenthesis is not None:
            if not self._is_subquery(parenthesis):
                raise UnsupportedStatementError(
                    "table functions are not supported: "
                    f"{ident.get_real_name()!r}"
                )
            alias = ident.get_alias()
            if alias is None:
                raise UnsupportedStatementError(
                    "derived tables require an alias"
                )
            subquery = sql.Statement(list(parenthesis.tokens[1:-1]))
            derived = {}
            for column in self._review_select(subquery):
                derived[column.name] = (column.sources, column.gaps)
            scope[alias] = _DerivedSource(derived)
            return
        real_name = ident.get_real_name()
        parent_name = ident.get_parent_name()
        view = None
        if parent_name is not None:
            view = _lookup_name(self._manifest, f"{parent_name}.{real_name}")
        if view is None:
            view = _lookup_name(self._manifest, real_name)
        if view is None:
            raise UnknownViewError(
                f"view {real_name!r} is not declared in the approved "
                "view manifest; review stopped"
            )
        scope[ident.get_alias() or real_name] = _ViewSource(
            view, self._manifest[view]
        )

    @staticmethod
    def _is_subquery(parenthesis):
        for token in parenthesis.tokens:
            if token.is_whitespace or token.match(T.Punctuation, "("):
                continue
            return token.match(T.Keyword.DML, "SELECT")
        return False

    def _review_item(self, item, scope):
        if item.ttype == T.Wildcard:
            return self._expand_wildcard(None, scope)
        if isinstance(item, sql.Identifier) and item.is_wildcard():
            return self._expand_wildcard(item.get_parent_name(), scope)
        if isinstance(item, sql.Identifier):
            name = (
                item.get_alias() or item.get_real_name() or item.value.strip()
            )
        else:
            name = item.value.strip()
        sources, gaps = self._trace(item, scope)
        return [ColumnReview(name, sources, gaps)]

    def _expand_wildcard(self, parent_name, scope):
        columns = []
        if parent_name is not None:
            source = _lookup(scope, parent_name)
            if source is None:
                return [
                    ColumnReview(
                        f"{parent_name}.*",
                        (),
                        (f"unknown table or alias {parent_name!r}",),
                    )
                ]
            entries = [(parent_name, source)]
        else:
            entries = list(scope.items())
        for _, source in entries:
            if isinstance(source, _ViewSource):
                for column in source.columns:
                    columns.append(
                        ColumnReview(column, ((source.view, column),))
                    )
            else:
                for name, (sources, gaps) in source.columns.items():
                    columns.append(ColumnReview(name, sources, gaps))
        return columns

    def _trace(self, token, scope):
        """Return ``(sources, gaps)`` for an expression token."""
        if isinstance(token, sql.Identifier):
            expression = self._expression_tokens(token)
            if self._is_plain_ref(expression):
                return self._resolve(
                    token.get_parent_name(), token.get_real_name(), scope
                )
            return self._trace_many(expression, scope)
        if isinstance(token, sql.Function):
            # only trace argument lists; skip the function name itself
            return self._trace_many(
                [
                    child
                    for child in token.tokens
                    if isinstance(child, sql.Parenthesis)
                ],
                scope,
            )
        if isinstance(token, sql.Parenthesis):
            if self._is_subquery(token):
                return set(), ["scalar subqueries are not supported"]
            return self._trace_many(token.tokens[1:-1], scope)
        if isinstance(token, sql.TokenList):
            return self._trace_many(token.tokens, scope)
        if token.ttype == T.Name:
            return self._resolve(None, remove_quotes(token.value), scope)
        return set(), []

    def _trace_many(self, tokens, scope):
        sources, gaps = set(), []
        for token in tokens:
            found, missing = self._trace(token, scope)
            sources |= found
            gaps.extend(missing)
        return sources, gaps

    @staticmethod
    def _expression_tokens(ident):
        """Return the tokens of *ident* without a trailing alias."""
        tokens = list(ident.tokens)
        as_idx, _ = ident.token_next_by(m=(T.Keyword, "AS"))
        if as_idx is not None:
            tokens = tokens[:as_idx]
        elif ident.get_alias() is not None:
            for idx in range(len(tokens) - 1, -1, -1):
                if not tokens[idx].is_whitespace:
                    if isinstance(tokens[idx], sql.Identifier):
                        tokens = tokens[:idx]
                    break
        return [token for token in tokens if not token.is_whitespace]

    @staticmethod
    def _is_plain_ref(tokens):
        return bool(tokens) and all(
            token.ttype in (T.Name, T.Punctuation, T.String.Symbol)
            for token in tokens
        )

    def _resolve(self, parent_name, column_name, scope):
        if parent_name is not None:
            source = _lookup(scope, parent_name)
            if source is None:
                return set(), [f"unknown table or alias {parent_name!r}"]
            return self._resolve_in(source, parent_name, column_name)
        sources, gaps, candidates = set(), [], []
        for scope_name, source in scope.items():
            found, missing = self._resolve_in(
                source, scope_name, column_name
            )
            if found:
                candidates.append((found, missing))
        if len(candidates) == 1:
            found, missing = candidates[0]
            return set(found), list(missing)
        if candidates:
            for found, _ in candidates:
                sources |= set(found)
            labels = ", ".join(
                f"{view}.{column}" for view, column in sorted(sources)
            )
            gaps.append(
                f"ambiguous column {column_name!r}; candidates: {labels}"
            )
            return sources, gaps
        if len(scope) == 1:
            # with a single source in scope its own diagnostic is
            # more precise than a generic "cannot resolve"
            scope_name, source = next(iter(scope.items()))
            return self._resolve_in(source, scope_name, column_name)
        return set(), [f"cannot resolve column {column_name!r}"]

    def _resolve_in(self, source, scope_name, column_name):
        if isinstance(source, _ViewSource):
            declared = _lookup_name(source.columns, column_name)
            if declared is None:
                return set(), [
                    f"column {column_name!r} is not declared in view "
                    f"{source.view!r}"
                ]
            return {(source.view, declared)}, []
        columns = _lookup(source.columns, column_name)
        if columns is None:
            return set(), [
                f"column {column_name!r} is not produced by subquery "
                f"{scope_name!r}"
            ]
        sources, gaps = columns
        return set(sources), list(gaps)


def review(sql_text, views, encoding=None):
    """Statically pre-review a read-only report definition.

    :param sql_text: A string containing one or more SELECT statements.
    :param views: Mapping of approved view names to their allowed column
        names, e.g. ``{"orders": ["id", "amount"]}``.
    :param encoding: The encoding of the statement (optional).
    :returns: A :class:`ReviewReport` describing every exported column.
    :raises UnsupportedStatementError: If the SQL uses syntax outside the
        supported SELECT subset.
    :raises UnknownViewError: If a referenced view is missing from
        *views*; the review stops immediately in this case.
    """
    if not isinstance(views, Mapping):
        raise TypeError("views must be a mapping of view name to columns")
    manifest = {}
    for view, columns in views.items():
        if isinstance(columns, str) or not isinstance(columns, Iterable):
            raise TypeError(
                f"columns of view {view!r} must be an iterable of names"
            )
        manifest[view] = tuple(columns)
    reviewer = _Reviewer(manifest)
    stack = engine.FilterStack()
    stack.enable_grouping()
    columns = []
    for stmt in stack.run(sql_text, encoding):
        columns.extend(reviewer.review_statement(stmt))
    return ReviewReport(columns)
