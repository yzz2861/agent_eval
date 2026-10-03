from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
import re
from typing import Any
from typing import TYPE_CHECKING

from sqlalchemy.sql import table as _table_clause
from sqlalchemy.sql.ddl import CreateView as _CreateView
from sqlalchemy.sql.elements import quoted_name
from sqlalchemy.sql.selectable import SelectBase

from ... import util

if TYPE_CHECKING:
    from sqlalchemy.engine import Dialect
    from sqlalchemy.sql.schema import MetaData
    from sqlalchemy.sql.schema import Table


ViewKey = tuple[str | None, str]
ViewDefinition = str | SelectBase


class ViewError(util.CommandError):
    """Base exception for view related errors."""


def _format_key(key: ViewKey) -> str:
    schema, name = key
    return f"${schema}.{name}" if schema else name


class ViewCycleError(ViewError):
    """Raised when the declared views contain a dependency cycle.

    The views participating in every cycle that was found are reported
    on the :attr:`.views` attribute in deterministic order.
    """

    def __init__(self, cycles: Sequence[Sequence[ViewKey]]) -> None:
        self.cycles = [list(cycle) for cycle in cycles]
        involved: set[ViewKey] = set()
        for cycle in self.cycles:
            involved.update(cycle)
        self.views = sorted(involved)

        rendered = "; ".join(
            " -> ".join(
                [*(_format_key(k) for k in cycle), _format_key(cycle[0])]
            )
            for cycle in self.cycles
        )
        super().__init__("Cycle(s) detected among views: %s" % rendered)


# ---------------------------------------------------------------------------
# Conservative SQL tokenizer
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[A-Za-z\u00a1-\uffff_][A-Za-z\u00a1-\uffff0-9_$#]*")
_NUMBER_RE = re.compile(r"(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
_MULTI_OPS = (
    "<=>",
    "::",
    "<>",
    "!=",
    "||",
    "->>",
    "->",
    "#>>",
    "#>",
    ">=",
    "<=",
    "||=",
    ":=",
    "@@",
)


class TokenizeError(ValueError):
    """Raised when SQL cannot be tokenized by the conservative scanner."""


def _scan_dollar_quote(text: str, pos: int) -> tuple[str, int]:
    rest = text[pos:]
    match = re.match(r"\$[A-Za-z_0-9]*\$", rest)
    if not match:
        raise TokenizeError("malformed dollar quote")
    tag = match.group(0)
    end = rest.find(tag, len(tag))
    if end < 0:
        raise TokenizeError("unterminated dollar quote")
    return rest[: end + len(tag)], pos + end + len(tag)


def _scan_quoted(text: str, pos: int, quote: str) -> tuple[str, int]:
    end = pos + 1
    length = len(text)
    while end < length:
        if text[end] == quote:
            if end + 1 < length and text[end + 1] == quote:
                end += 2
                continue
            break
        end += 1
    else:
        raise TokenizeError("unterminated quoted token")
    return text[pos : end + 1], end + 1


def tokenize_sql(sql: str) -> list[str]:
    r"""Tokenize *sql* into a list of conservative, comparable tokens.

    Comments and whitespace are dropped.  Unquoted words are case folded
    (unquoted SQL identifiers are case insensitive).  Quoted identifiers
    and string literals are retained verbatim including their quoting
    characters, so that differences inside literals and identifiers remain
    significant.  A single trailing semicolon, if present, is dropped.

    The tokenizer never removes optional keywords and never reorders
    anything.  Two definitions compare equal only when the sequence of
    meaningful tokens is identical, apart from whitespace, comments and
    unquoted identifier case.  Prefixed literals such as ``"E'...'"``
    retain their prefix, since the prefix is semantically significant.
    """

    tokens: list[str] = []
    length = len(sql)
    pos = 0

    while pos < length:
        char = sql[pos]

        if char in " \t\r\n\f":
            pos += 1
            continue

        if char == "-" and sql.startswith("--", pos):
            newline = sql.find("\n", pos)
            pos = length if newline < 0 else newline + 1
            continue

        if char == "/" and sql.startswith("/*", pos):
            depth = 0
            end = pos
            while end < length - 1:
                if sql.startswith("/*", end):
                    depth += 1
                    end += 2
                elif sql.startswith("*/", end):
                    depth -= 1
                    end += 2
                    if depth == 0:
                        break
                else:
                    end += 1
            if depth != 0:
                raise TokenizeError("unterminated block comment")
            pos = end
            continue

        if char == "$":
            token, pos = _scan_dollar_quote(sql, pos)
            tokens.append(token)
            continue

        if char in ("'", '"', "`"):
            token, pos = _scan_quoted(sql, pos, char)
            tokens.append(token)
            continue

        if char == "[":
            end = sql.find("]", pos + 1)
            if end < 0:
                raise TokenizeError("unterminated bracketed identifier")
            tokens.append(sql[pos : end + 1])
            pos = end + 1
            continue

        number = _NUMBER_RE.match(sql, pos)
        if number and (char.isdigit() or char == "."):
            tokens.append(number.group(0))
            pos = number.end()
            continue

        word = _WORD_RE.match(sql, pos)
        if word:
            end = word.end()
            token = word.group(0)
            if end < length and sql[end] in (chr(39), '"'):
                literal, new_pos = _scan_quoted(sql, end, sql[end])
                token = token + literal
                pos = new_pos
            else:
                pos = end
                token = token.lower()
            tokens.append(token)
            continue

        matched = False
        for operator in _MULTI_OPS:
            if sql.startswith(operator, pos):
                tokens.append(operator)
                pos += len(operator)
                matched = True
                break
        if not matched:
            tokens.append(char)
            pos += 1

    if tokens and tokens[-1] == ";":
        tokens.pop()
    return tokens


# ---------------------------------------------------------------------------
# Definition normalization
# ---------------------------------------------------------------------------

_CREATE_VIEW_RE = re.compile(
    r"^\s*create\s+"
    r"(?:or\s+replace\s+)?"
    r"(?:temporary\s+|temp\s+)?"
    r"(?:materialized\s+)?"
    r"view\s+"
    r"(?:if\s+not\s+exists\s+)?"
    r'(?:(?:"[^"]+"|`[^`]+`|\[[^]]+]|[\w$]+)\s*\.\s*)?'
    r'(?:"[^"]+"|`[^`]+`|\[[^]]+]|[\w$]+)'
    r"\s+as\s+",
    re.IGNORECASE | re.DOTALL,
)


def _select_body(definition: str) -> str:
    match = _CREATE_VIEW_RE.match(definition)
    if match:
        return definition[match.end() :]
    return definition


def normalize_view_definition(definition: str) -> tuple[str, ...]:
    """Return the conservative, comparable form of a view definition.

    A leading ``CREATE [OR REPLACE] [TEMP] VIEW [schema.]name AS`` clause
    (as stored by SQLite, or as supplied by the caller) is removed and the
    remaining SELECT body is run through :func:`.tokenize_sql`.  Whitespace
    and comments are therefore insignificant, but nothing else is
    collapsed: optional keywords, the quoting/qualification of the relation
    name itself, the contents of literals and quoted identifiers, and the
    order of keywords or columns all remain significant.
    """

    return tuple(tokenize_sql(_select_body(definition.strip())))


def definitions_equal(left: str, right: str) -> bool:
    """Compare two view definitions under the conservative specification."""

    try:
        return normalize_view_definition(left) == normalize_view_definition(
            right
        )
    except TokenizeError:
        # if either side cannot be safely tokenized, fall back to exact
        # textual equality rather than risk a false positive
        return left.strip() == right.strip()


# ---------------------------------------------------------------------------
# Dependency extraction
# ---------------------------------------------------------------------------

_TERMINATOR_KEYWORDS = frozenset(
    {
        "where",
        "group",
        "having",
        "order",
        "limit",
        "offset",
        "fetch",
        "window",
        "returning",
        "union",
        "except",
        "intersect",
        "for",
    }
)

_NON_RELATION_WORDS = frozenset(
    {
        "select",
        "lateral",
        "unnest",
        "values",
        "json_table",
        "generate_series",
        "only",
        "table",
        "with",
    }
)


def _unquote_ident(token: str) -> str | None:
    """Unquote a relation identifier token, or return None."""

    if not token:
        return None
    if token[0] in ("`", "'", '"'):
        if token[0] in ("`", '"') and token[-1] == token[0]:
            quote = token[0]
            return token[1:-1].replace(quote * 2, quote)
        return None
    if token[0] == "[" and token[-1] == "]":
        return token[1:-1]
    if token[0].isalpha() or token[0] == "_":
        # plain words are already case folded by the tokenizer
        return token
    return None


def _collect_cte_names(tokens: Sequence[str]) -> set[str]:
    names: set[str] = set()
    if not tokens or tokens[0] != "with":
        return names
    pos = 1
    if pos < len(tokens) and tokens[pos] == "recursive":
        pos += 1
    n = len(tokens)
    while pos < n:
        while pos < n and tokens[pos] in ("materialized", "not"):
            pos += 1
        if tokens[pos] == "(":
            depth = 0
            while pos < n:
                if tokens[pos] == "(":
                    depth += 1
                elif tokens[pos] == ")":
                    depth -= 1
                    if depth == 0:
                        pos += 1
                        break
                pos += 1
            continue
        name = _unquote_ident(tokens[pos])
        if name is not None:
            names.add(name.lower())
        while pos < n and tokens[pos] != "as":
            pos += 1
        if pos >= n:
            break
        pos += 1
        if pos >= n or tokens[pos] != "(":
            break
        depth = 0
        while pos < n:
            if tokens[pos] == "(":
                depth += 1
            elif tokens[pos] == ")":
                depth -= 1
                if depth == 0:
                    pos += 1
                    break
            pos += 1
        if pos < n and tokens[pos] == ",":
            pos += 1
            continue
        break
    return names


def extract_relation_names(definition: str) -> set[str]:
    """Return lower-cased relation names referenced in FROM/JOIN clauses.

    Parenthesized subqueries are descended into, but the bodies of a top
    level WITH clause (CTE definitions) are skipped; references to a CTE
    name in the outer statement are filtered out.  Relation aliases and
    column lists are ignored.  Callers intersect the result with the set
    of declared view names, so an alias resembling a view name cannot
    create a spurious dependency.
    """

    tokens = tokenize_sql(_select_body(definition.strip()))
    cte_names = _collect_cte_names(tokens)
    n = len(tokens)
    relations: set[str] = set()

    def matching_paren(pos: int) -> int:
        depth = 0
        while pos < n:
            if tokens[pos] == "(":
                depth += 1
            elif tokens[pos] == ")":
                depth -= 1
                if depth == 0:
                    return pos
            pos += 1
        return n - 1

    outer_start = 0
    if tokens and tokens[0] == "with":
        pos = 1
        if pos < n and tokens[pos] == "recursive":
            pos += 1
        while pos < n:
            if tokens[pos] == "as":
                pos += 1
                if pos < n and tokens[pos] == "(":
                    close = matching_paren(pos)
                    pos = close + 1
                    if pos < n and tokens[pos] == ",":
                        pos += 1
                        continue
                outer_start = pos
                break
            pos += 1
        else:
            outer_start = n

    def scan(start: int, end: int) -> None:
        i = start
        while i < end:
            token = tokens[i]
            if token == "(":
                close = matching_paren(i)
                inner_start = i + 1
                # a parenthesized WITH ... group: skip its CTE bodies and
                # only scan the outer statement of that subquery
                if inner_start < end and tokens[inner_start] == "with":
                    p = inner_start + 1
                    if p < end and tokens[p] == "recursive":
                        p += 1
                    while p < close:
                        if tokens[p] == "as":
                            p += 1
                            if p < close and tokens[p] == "(":
                                body_close = matching_paren(p)
                                p = body_close + 1
                                if p < close and tokens[p] == ",":
                                    p += 1
                                    continue
                            inner_start = p
                            break
                        p += 1
                scan(inner_start, close)
                i = close + 1
                continue
            if token != "from":
                i += 1
                continue
            i += 1
            while i < end:
                while i < end and tokens[i] in (
                    "left",
                    "right",
                    "full",
                    "inner",
                    "outer",
                    "cross",
                ):
                    i += 1
                if i < end and tokens[i] == "join":
                    i += 1
                if i >= end:
                    break
                if tokens[i] == "(":
                    close = matching_paren(i)
                    scan(i + 1, close)
                    i = close + 1
                else:
                    chain = [tokens[i]]
                    i += 1
                    while i + 1 < end and tokens[i] == ".":
                        chain.append(tokens[i + 1])
                        i += 2
                    ident = _unquote_ident(chain[-1])
                    if (
                        ident is not None
                        and ident not in _NON_RELATION_WORDS
                        and ident.lower() not in cte_names
                    ):
                        relations.add(ident.lower())
                while i < end:
                    tok = tokens[i]
                    if tok in (",", "join") or tok in _TERMINATOR_KEYWORDS:
                        break
                    if tok == "(":
                        close = matching_paren(i)
                        scan(i + 1, close)
                        i = close + 1
                    else:
                        i += 1
                if i < end and tokens[i] in (",", "join"):
                    if tokens[i] == ",":
                        i += 1
                    # else: outer while strips join qualifiers and the
                    # "join" keyword itself before parsing the next factor
                    continue
                break

    scan(outer_start, n)
    return relations


# ---------------------------------------------------------------------------
# Dependency graph and ordering
# ---------------------------------------------------------------------------


def view_dependency_edges(
    views: Iterable[View], default_schema: str | None = None
) -> dict[ViewKey, set[ViewKey]]:
    """Build a ``view -> set(dependency views)`` mapping.

    Relation names mentioned in a view body are intersected with the
    declared view set, so only edges between declared views remain. An
    unqualified relation name matches a view in the same schema or in the
    *default_schema*. Explicit :attr:`.View.depends_on` entries (given as
    unqualified names or dotted ``schema.name``) are also honored.
    """

    by_key: dict[ViewKey, View] = {view.key: view for view in views}
    unqualified: dict[str, list[ViewKey]] = {}
    for key in by_key:
        _, name = key
        unqualified.setdefault(name.lower(), []).append(key)

    edges: dict[ViewKey, set[ViewKey]] = {key: set() for key in by_key}
    for view in by_key.values():
        referenced: set[ViewKey] = set()
        definition = view.definition
        if isinstance(definition, str):
            for name in extract_relation_names(definition):
                for candidate in unqualified.get(name, ()):
                    candidate_schema, _ = candidate
                    if candidate_schema == view.key[0] or (
                        candidate_schema == default_schema
                        and view.key[0] in (None, default_schema)
                    ):
                        if candidate != view.key:
                            referenced.add(candidate)
        for explicit in view.depends_on:
            if "." in explicit:
                schema_name, _, dep_name = explicit.rpartition(".")
                candidate = (schema_name or None, dep_name)
            else:
                candidate = (view.key[0], explicit)
            if candidate in by_key and candidate != view.key:
                referenced.add(candidate)
        edges[view.key] = referenced
    return edges


def topological_order(edges: Mapping[ViewKey, set[ViewKey]]) -> list[ViewKey]:
    """Return view keys in dependency-first order.

    *edges* maps a view to the views it depends on. Raises
    :class:`.ViewCycleError` when a cycle is present.
    """

    nodes: set[ViewKey] = set(edges)
    for deps in edges.values():
        nodes.update(deps)
    indegree = {node: 0 for node in nodes}
    dependents: dict[ViewKey, set[ViewKey]] = {node: set() for node in nodes}
    for node, deps in edges.items():
        indegree[node] = len(deps)
        for dep in deps:
            dependents[dep].add(node)
    ready = sorted(n for n, deg in indegree.items() if deg == 0)
    ordered: list[ViewKey] = []
    while ready:
        node = ready.pop(0)
        ordered.append(node)
        for dependent in sorted(dependents[node]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
                ready.sort()
    if len(ordered) != len(nodes):
        raise ViewCycleError(_find_cycles(edges))
    return ordered


def _find_cycles(edges: Mapping[ViewKey, set[ViewKey]]) -> list[list[ViewKey]]:
    color: dict[ViewKey, int] = {}
    stack: list[ViewKey] = []
    cycles: list[list[ViewKey]] = []
    seen: set[tuple[str, ...]] = set()

    def visit(node: ViewKey) -> None:
        color[node] = 1
        stack.append(node)
        for dep in sorted(edges.get(node, ())):
            state = color.get(dep, 0)
            if state == 1:
                start = stack.index(dep)
                cycle = stack[start:]
                key = tuple(sorted(_format_key(k) for k in cycle))
                if key not in seen:
                    seen.add(key)
                    cycles.append(cycle)
            elif state == 0:
                visit(dep)
        stack.pop()
        color[node] = 2

    all_nodes = {*edges, *(d for ds in edges.values() for d in ds)}
    for node in sorted(all_nodes):
        if color.get(node, 0) == 0:
            visit(node)
    return cycles


# ---------------------------------------------------------------------------
# View declarations
# ---------------------------------------------------------------------------


def _normalize_schema(schema: str | quoted_name | None) -> str | None:
    if schema is None:
        return None
    return str(schema)


@dataclass(frozen=True)
class View:
    """A declarative description of a database view.

    :param name: view name. May be a :class:`.quoted_name` to force quoting.
    :param definition: the view body. Either a full ``CREATE VIEW ... AS``
     statement / bare ``SELECT`` as a string, or a SQLAlchemy
     :class:`.SelectBase` construct.
    :param schema: optional schema name (also may be :class:`.quoted_name`).
    :param materialized: when True the view is materialized. Currently only
     honored for metadata registration; create/drop of materialized views
     uses the appropriate DDL where the dialect supports it.
    """

    name: str | quoted_name
    definition: ViewDefinition
    schema: str | quoted_name | None = None
    materialized: bool = False
    depends_on: Sequence[str] = field(default_factory=tuple)

    @property
    def key(self) -> ViewKey:
        return (_normalize_schema(self.schema), str(self.name))

    def attach(self, metadata: MetaData) -> Table:
        """Register a lightweight ``is_view`` table on *metadata*.

        This lets autogenerate exclude the view from ordinary table
        comparison and provides a place to hang column information when
        the view is declared with a SQLAlchemy select construct.
        """

        from sqlalchemy import Table

        table = _view_table_for(self, metadata=metadata)
        if table is not None:
            return table
        return Table(
            str(self.name),
            metadata,
            schema=self.schema,
            keep_existing=True,
            extend_existing=True,
        )


def _view_table_for(
    view: View, *, metadata: MetaData | None = None
) -> Table | None:
    if isinstance(view.definition, SelectBase):
        create_view = _CreateView(
            view.definition,
            str(view.name),
            metadata=metadata,
            schema=view.schema,
            materialized=view.materialized,
        )
        return create_view.table
    return None


class ViewRegistry:
    """An explicit collection of :class:`.View` declarations.

    Pass an instance (or sequence of instances) as the
    :paramref:`.EnvironmentContext.configure.target_views` option, or
    attach one to :attr:`.MetaData.info` under the ``"views"`` key, to
    make the views participate in autogenerate.
    """

    def __init__(self, views: Iterable[View] = ()) -> None:
        self._views: dict[ViewKey, View] = {}
        for view in views:
            self.add(view)

    def add(self, view: View) -> View:
        key = view.key
        if key in self._views:
            raise ViewError(
                "Duplicate view declaration: %s" % _format_key(key)
            )
        self._views[key] = view
        return view

    def __iter__(self):
        return iter(self._views.values())

    def __len__(self) -> int:
        return len(self._views)

    def __contains__(self, key: object) -> bool:
        return key in self._views

    def get(self, key: ViewKey) -> View | None:
        return self._views.get(key)

    def keys(self) -> Iterable[ViewKey]:
        return self._views.keys()

    @classmethod
    def coerce(cls, value: Any) -> ViewRegistry | None:
        if value is None:
            return None
        if isinstance(value, ViewRegistry):
            return value
        return cls(value)


# ---------------------------------------------------------------------------
# DDL rendering
# ---------------------------------------------------------------------------


def _quoted_table(
    name: str | quoted_name, schema: str | quoted_name | None, dialect: Dialect
) -> str:
    table = _table_clause(str(name), schema=schema)
    return dialect.identifier_preparer.format_table(table)


def definition_sql(definition: ViewDefinition, dialect: Dialect) -> str:
    """Return a dialect specific SQL string for a view body.

    A string is returned verbatim (it may be a bare SELECT or a full
    CREATE VIEW statement - only the SELECT body is used by the
    ``CREATE VIEW`` renderers). A :class:`.SelectBase` is compiled with
    inlined literal binds so that the resulting SQL is both executable and
    usable in offline SQL output.
    """

    if isinstance(definition, str):
        return _select_body(definition.strip())
    return str(
        definition.compile(
            dialect=dialect,
            compile_kwargs={"literal_binds": True, "include_table": False},
        )
    )


def create_view_sql(
    name: str | quoted_name,
    definition: ViewDefinition,
    dialect: Dialect,
    *,
    schema: str | quoted_name | None = None,
    or_replace: bool = False,
    materialized: bool = False,
) -> str:
    """Render a ``CREATE [OR REPLACE] VIEW`` statement for *dialect*."""

    body = definition_sql(definition, dialect)
    kind = "MATERIALIZED VIEW" if materialized else "VIEW"
    replace_ = "OR REPLACE " if or_replace else ""
    return "CREATE %s%s %s AS %s" % (
        replace_,
        kind,
        _quoted_table(name, schema, dialect),
        body.strip(),
    )


def drop_view_sql(
    name: str | quoted_name,
    dialect: Dialect,
    *,
    schema: str | quoted_name | None = None,
    if_exists: bool = False,
    materialized: bool = False,
    cascade: bool = False,
) -> str:
    """Render a ``DROP VIEW`` statement for *dialect*."""

    kind = "MATERIALIZED VIEW" if materialized else "VIEW"
    exists = "IF EXISTS " if if_exists else ""
    tail = " CASCADE" if cascade and not materialized else ""
    return "DROP %s %s%s%s" % (
        kind,
        exists,
        _quoted_table(name, schema, dialect),
        tail,
    )
