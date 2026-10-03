"""First-class support for SQL views.

Provides the :class:`.View` declaration model, conservative view-body
comparison (:func:`.normalize_view_definition`), dependency extraction
(:func:`.view_dependencies`) and dependency ordering
(:func:`.topological_sort`).

.. versionadded:: 1.21
"""

from __future__ import annotations

from collections.abc import Collection
from collections.abc import Iterable
from collections.abc import Mapping
import re
from typing import Any
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union

from sqlalchemy.sql.elements import quoted_name
from sqlalchemy.sql.schema import MetaData

from .util.exc import CommandError

if TYPE_CHECKING:
    from sqlalchemy.sql.selectable import SelectBase

    ViewDefinition = Union[str, SelectBase]
else:  # pragma: no cover
    ViewDefinition = Any

ViewKey = tuple[Optional[str], str]

#: Key in MetaData.info holding declared views.
METADATA_VIEWS_KEY = "alembic_views"


class CircularViewDependencyError(CommandError):
    """Raised when a cycle is detected amongst view dependencies.

    The :attr:`.cycle` attribute lists the participating view keys in
    order, with the first key repeated at the end.

    .. versionadded:: 1.21
    """

    def __init__(self, cycle: Collection[ViewKey]) -> None:
        self.cycle = list(cycle)
        names = " -> ".join(
            format_view_name(name, schema) for schema, name in self.cycle
        )
        super().__init__(
            "Circular dependency detected among views: %s" % names
        )


def format_view_name(name: str, schema: Optional[str] = None) -> str:
    """Format a possibly schema-qualified view name."""

    if schema:
        return "%s.%s" % (schema, name)
    else:
        return name


class View:
    """Represent a SQL view definition.

    :param name: view name.  May be a
     :class:`~sqlalchemy.sql.elements.quoted_name` to force quoting.

    :param selectable: the view body as a raw SQL string (the SELECT,
     without the "CREATE VIEW ... AS" prefix) or a SQLAlchemy
     :class:`~sqlalchemy.sql.selectable.SelectBase`.

    :param metadata: optional :class:`~sqlalchemy.schema.MetaData` to
     register the view with so that it is considered by autogenerate.

    :param schema: optional schema name; a
     :class:`~sqlalchemy.sql.elements.quoted_name` may be used.

    :param depends_on: optional explicit dependencies.  Each entry is a
     view name or a "(schema, name)" tuple.  When omitted, view-to-view
     dependencies are inferred from the view body.

    :param materialized: when True the view is a materialized view.

    :param temporary: when True emit CREATE TEMPORARY VIEW.

    .. versionadded:: 1.21
    """

    __slots__ = (
        "name",
        "selectable",
        "schema",
        "materialized",
        "temporary",
        "_explicit_dependencies",
        "_metadata",
    )

    def __init__(
        self,
        name: Union[str, quoted_name],
        selectable: ViewDefinition,
        *,
        metadata: Optional[MetaData] = None,
        schema: Optional[Union[str, quoted_name]] = None,
        depends_on: Optional[Collection[Union[str, ViewKey]]] = None,
        materialized: bool = False,
        temporary: bool = False,
    ) -> None:
        self.name = name
        self.selectable = selectable
        self.schema = schema
        self.materialized = materialized
        self.temporary = temporary
        if depends_on is None:
            self._explicit_dependencies: Optional[frozenset[ViewKey]] = None
        else:
            current_schema = None if schema is None else str(schema)
            self._explicit_dependencies = frozenset(
                _coerce_dependency(dep, current_schema) for dep in depends_on
            )
        self._metadata: Optional[MetaData] = None
        if metadata is not None:
            self._attach(metadata)

    def _attach(self, metadata: MetaData) -> None:
        views = metadata.info.get(METADATA_VIEWS_KEY)
        if views is None:
            views = {}
            metadata.info[METADATA_VIEWS_KEY] = views
        elif isinstance(views, Mapping):
            views = dict(views)
            metadata.info[METADATA_VIEWS_KEY] = views
        else:
            views = {view_key(view): view for view in views}
            metadata.info[METADATA_VIEWS_KEY] = views
        key = self.key
        if key in views:
            raise ValueError(
                "View %r is already registered with this MetaData"
                % (format_view_name(key[1], key[0]),)
            )
        views[key] = self
        self._metadata = metadata

    @property
    def key(self) -> ViewKey:
        """The (schema, name) key of the view."""

        return view_key(self)

    def dependencies(self, dialect: Any = None) -> frozenset[ViewKey]:
        """Return the (schema, name) keys of views this view uses."""

        if self._explicit_dependencies is not None:
            return self._explicit_dependencies
        body = view_definition_text(self.selectable, dialect=dialect)
        current_schema = None if self.schema is None else str(self.schema)
        return frozenset(
            _coerce_dependency(dep, current_schema)
            for dep in view_dependencies(body, schema=current_schema)
        )

    def __repr__(self) -> str:
        return "View(%r, schema=%r)" % (self.name, self.schema)


def _coerce_dependency(
    dep: Union[str, ViewKey], default_schema: Optional[str]
) -> ViewKey:
    if isinstance(dep, tuple):
        schema, name = dep
        return (
            str(schema) if schema is not None else default_schema,
            str(name),
        )
    else:
        return default_schema, str(dep)


def view_key(view: View) -> ViewKey:
    return (
        None if view.schema is None else str(view.schema),
        str(view.name),
    )


def declared_views(
    metadata: Union[MetaData, Iterable[MetaData]],
) -> dict[ViewKey, View]:
    """Collect all :class:`.View` objects declared on metadata."""

    result: dict[ViewKey, View] = {}
    metadatas: Iterable[MetaData] = (
        (metadata,) if isinstance(metadata, MetaData) else list(metadata)
    )
    for md in metadatas:
        views = md.info.get(METADATA_VIEWS_KEY)
        if views is None:
            continue
        iterable: Iterable[View]
        if isinstance(views, Mapping):
            iterable = views.values()
        else:
            iterable = views
        for view in iterable:
            key = view_key(view)
            if key in result and result[key] is not view:
                raise ValueError(
                    "Duplicate view %r across multiple MetaData objects"
                    % (format_view_name(key[1], key[0]),)
                )
            result[key] = view
    return result


def view_definition_text(
    selectable: ViewDefinition, *, dialect: Any = None
) -> str:
    """Return the view body as a raw SQL string."""

    if isinstance(selectable, str):
        return selectable
    else:
        return str(
            selectable.compile(
                dialect=dialect, compile_kwargs={"literal_binds": True}
            )
        )


# ---------------------------------------------------------------------------
# SQL tokenizing, conservative normalization and dependency extraction
# ---------------------------------------------------------------------------

_SQL_TOKEN_RE = re.compile(
    r"(?P<ws>\s+|--[^\n]*(?:\n|$)|/\*.*?\*/)"
    r"|(?P<qident>\"(?:\"\"|[^\"])*\"|\[[^\]]*\]|`(?:``|[^`])*`)"
    r"|(?P<string>[eEnNxXbBrR]{0,2}'(?:''|[^'])*')"
    r"|(?P<number>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_$]*)"
    r"|(?P<punct>\.\.\.|<=|>=|<>|!=|::|\|\||\S)",
    re.DOTALL,
)

_PUNCT_NO_SPACE = frozenset({"(", ")", "[", "]", ",", ";", "."})
_PUNCT_OPEN = frozenset({"(", "["})
_PUNCT_CLOSE = frozenset({")", "]", ",", ";"})

_STOP_TOKENS = frozenset(
    {
        ")",
        "(",
        ",",
        ";",
        "where",
        "group",
        "having",
        "window",
        "union",
        "intersect",
        "except",
        "order",
        "limit",
        "offset",
        "returning",
    }
)


# Union of reserved words from the SQL standard, PostgreSQL and SQLite.
# Only these tokens are case-folded; identifiers and literals are
# preserved verbatim.
_SQL_KEYWORDS = frozenset(
    {
        "abort",
        "absent",
        "absolute",
        "access",
        "action",
        "add",
        "admin",
        "after",
        "all",
        "allocate",
        "also",
        "alter",
        "always",
        "analyse",
        "analyze",
        "and",
        "any",
        "are",
        "array",
        "as",
        "asc",
        "asensitive",
        "assertion",
        "assignment",
        "asymmetric",
        "at",
        "atomic",
        "attach",
        "attribute",
        "authorization",
        "auto_increment",
        "before",
        "begin",
        "between",
        "bigint",
        "binary",
        "bit",
        "blob",
        "boolean",
        "both",
        "breadth",
        "by",
        "cache",
        "call",
        "called",
        "cascade",
        "cascaded",
        "case",
        "cast",
        "catalog",
        "chain",
        "char",
        "character",
        "character_length",
        "check",
        "checkpoint",
        "class",
        "clob",
        "close",
        "cluster",
        "coalesce",
        "collate",
        "collation",
        "collect",
        "column",
        "columns",
        "comment",
        "commit",
        "committed",
        "complete",
        "condition",
        "configuration",
        "connect",
        "connection",
        "constraint",
        "constraints",
        "constructor",
        "contains",
        "continue",
        "convert",
        "corresponding",
        "cost",
        "count",
        "create",
        "cross",
        "cube",
        "current",
        "current_date",
        "current_default_transform_group",
        "current_path",
        "current_role",
        "current_time",
        "current_timestamp",
        "current_transform_group_for_type",
        "current_user",
        "cursor",
        "cycle",
        "data",
        "database",
        "date",
        "day",
        "deallocate",
        "dec",
        "decimal",
        "declare",
        "default",
        "defaults",
        "deferrable",
        "deferred",
        "definer",
        "delete",
        "depth",
        "deref",
        "desc",
        "describe",
        "descriptor",
        "detach",
        "deterministic",
        "diagnostics",
        "dictionary",
        "disable",
        "disconnect",
        "disk",
        "distinct",
        "do",
        "domain",
        "double",
        "drop",
        "dynamic",
        "each",
        "element",
        "else",
        "elseif",
        "empty",
        "enable",
        "end",
        "enclosed",
        "encoding",
        "enum",
        "equals",
        "escape",
        "event",
        "except",
        "exception",
        "excluding",
        "exclusive",
        "exec",
        "execute",
        "exists",
        "exit",
        "explain",
        "external",
        "extract",
        "false",
        "fetch",
        "filter",
        "final",
        "first",
        "float",
        "following",
        "for",
        "force",
        "foreign",
        "format",
        "found",
        "free",
        "from",
        "full",
        "fulltext",
        "function",
        "general",
        "generated",
        "get",
        "global",
        "go",
        "goto",
        "grant",
        "granted",
        "greatest",
        "group",
        "grouping",
        "groups",
        "having",
        "hierarchy",
        "hold",
        "hour",
        "identity",
        "if",
        "ignore",
        "immediate",
        "immediately",
        "immutable",
        "implementation",
        "import",
        "in",
        "include",
        "including",
        "increment",
        "index",
        "indexed",
        "indexes",
        "indicator",
        "infile",
        "inherit",
        "inherits",
        "initial",
        "initially",
        "inner",
        "inout",
        "input",
        "insensitive",
        "insert",
        "instance",
        "instantiable",
        "instead",
        "int",
        "integer",
        "intersect",
        "intersection",
        "interval",
        "into",
        "invoker",
        "is",
        "isnull",
        "isolation",
        "iterate",
        "join",
        "key",
        "keys",
        "language",
        "large",
        "last",
        "lateral",
        "leading",
        "leaf",
        "left",
        "less",
        "level",
        "like",
        "limit",
        "linear",
        "listen",
        "load",
        "local",
        "localtime",
        "localtimestamp",
        "locator",
        "lock",
        "map",
        "match",
        "matched",
        "materialized",
        "max",
        "member",
        "merge",
        "method",
        "minus",
        "minute",
        "minvalue",
        "modifies",
        "module",
        "month",
        "more",
        "multiset",
        "mumps",
        "national",
        "natural",
        "nchar",
        "nclob",
        "new",
        "next",
        "no",
        "none",
        "not",
        "nothing",
        "notify",
        "notnull",
        "nowait",
        "null",
        "nullif",
        "nulls",
        "numeric",
        "object",
        "octet_length",
        "of",
        "off",
        "offset",
        "oids",
        "old",
        "on",
        "only",
        "open",
        "operation",
        "operator",
        "option",
        "options",
        "or",
        "order",
        "ordering",
        "ordinality",
        "others",
        "out",
        "outer",
        "outfile",
        "output",
        "over",
        "overlaps",
        "overlay",
        "overriding",
        "pad",
        "parallel",
        "parameter",
        "parameters",
        "partial",
        "partition",
        "path",
        "percent",
        "pivot",
        "plan",
        "placing",
        "plpgql",
        "position",
        "postfix",
        "power",
        "preceding",
        "precision",
        "prefix",
        "preorder",
        "prepare",
        "preserve",
        "primary",
        "prior",
        "privileges",
        "procedure",
        "profile",
        "public",
        "raise",
        "range",
        "read",
        "reads",
        "real",
        "rebuild",
        "recursive",
        "ref",
        "references",
        "referencing",
        "refresh",
        "reindex",
        "relative",
        "release",
        "rename",
        "repeat",
        "repeatable",
        "replace",
        "replica",
        "reset",
        "restart",
        "restore",
        "restrict",
        "result",
        "return",
        "returned_length",
        "returned_octet_length",
        "returning",
        "returns",
        "revoke",
        "right",
        "role",
        "rollback",
        "rollup",
        "row",
        "rows",
        "rule",
        "savepoint",
        "scale",
        "schema",
        "scope",
        "scroll",
        "search",
        "second",
        "section",
        "security",
        "select",
        "self",
        "sensitive",
        "sequence",
        "serializable",
        "session",
        "session_user",
        "set",
        "sets",
        "share",
        "show",
        "similar",
        "simple",
        "size",
        "smallint",
        "snapshot",
        "some",
        "source",
        "space",
        "specific",
        "specifictype",
        "sql",
        "sqlcode",
        "sqlerror",
        "sqlexception",
        "sqlstate",
        "sqlwarning",
        "stable",
        "start",
        "state",
        "statement",
        "static",
        "statistics",
        "status",
        "stdin",
        "stdout",
        "storage",
        "strict",
        "structure",
        "style",
        "submultiset",
        "substring",
        "succeed",
        "sum",
        "symmetric",
        "system",
        "system_user",
        "table",
        "tables",
        "tablespace",
        "temporary",
        "terminate",
        "text",
        "than",
        "then",
        "time",
        "timestamp",
        "timezone_hour",
        "timezone_minute",
        "to",
        "token",
        "trailing",
        "transaction",
        "translate",
        "translation",
        "treat",
        "trigger",
        "trim",
        "true",
        "truncate",
        "trusted",
        "type",
        "uescape",
        "unbounded",
        "uncommitted",
        "under",
        "union",
        "unique",
        "unknown",
        "unlisten",
        "unlock",
        "unnamed",
        "unnest",
        "until",
        "update",
        "upper",
        "usage",
        "use",
        "user",
        "using",
        "vacuum",
        "value",
        "values",
        "varchar",
        "variable",
        "varying",
        "verbose",
        "version",
        "view",
        "views",
        "virtual",
        "visible",
        "when",
        "whenever",
        "where",
        "while",
        "window",
        "with",
        "within",
        "without",
        "work",
        "wrapper",
        "write",
        "xml",
        "xmlagg",
        "xmlattributes",
        "xmlbinary",
        "xmlcast",
        "xmlcomment",
        "xmlconcat",
        "xmldocument",
        "xmlelement",
        "xmlexists",
        "xmlforest",
        "xmliterate",
        "xmlnamespaces",
        "xmlparse",
        "xmlpi",
        "xmlquery",
        "xmlroot",
        "xmlserialize",
        "xmltable",
        "xmltext",
        "xmlvalidate",
        "year",
        "yes",
        "zone",
    }
)


def _tokenize(sql: str) -> list[tuple[str, str]]:
    """Split SQL into (kind, value) tokens.

    Whitespace and comments are returned as the "ws" kind so callers can
    choose to preserve or discard them.
    """

    tokens: list[tuple[str, str]] = []
    pos = 0
    length = len(sql)
    while pos < length:
        match = _SQL_TOKEN_RE.match(sql, pos)
        if match is None:
            tokens.append(("punct", sql[pos]))
            pos += 1
        else:
            kind = match.lastgroup or "punct"
            tokens.append((kind, match.group()))
            pos = match.end()
    return tokens


def _unquote_identifier(value: str) -> str:
    if value.startswith(('"', "`", "[")):
        inner = value[1:-1]
        if value.startswith("["):
            return inner.replace("]]", "]")
        elif value.startswith("`"):
            return inner.replace("``", "`")
        else:
            return inner.replace('""', '"')
    return value


def _strip_create_view_prefix(sql: str) -> str:
    """Strip a leading CREATE [..] VIEW [..] name AS clause if present.

    The comparison operates on the SELECT body.  Only an exact prefix of
    the documented shape is stripped; anything else is returned as-is so
    that comparison remains conservative.
    """

    stripped = sql.strip()
    if stripped.endswith(";"):
        stripped = stripped[:-1].rstrip()
    match = re.match(
        r"^create\s+"
        r"(?:(?:or\s+replace|temporary|temp|materialized)\s+)*"
        r"view\s+(?:if\s+not\s+exists\s+)?"
        r"[\w\"\.`\[\] ]+?\s+as\s+",
        stripped,
        re.IGNORECASE | re.DOTALL,
    )
    if match:
        return stripped[match.end() :]
    return stripped


def normalize_view_definition(sql: str) -> str:
    """Return a conservative canonical form of a view body.

    The canonical form ignores only:

    * leading/trailing whitespace and a single trailing semicolon;
    * a leading ``CREATE [..] VIEW name AS`` clause, allowing a stored
      full ``CREATE VIEW`` statement (as some dialects return from
      reflection) to be compared against a bare ``SELECT`` body;
    * SQL line (``--``) and block (``/* ... */``) comments;
    * whitespace between lexical tokens;
    * the letter case of reserved SQL keywords.

    Everything else is preserved exactly: the casing of identifiers
    (including unquoted ones), quoted identifiers, string and numeric
    literals, keyword operators occurring as identifiers, and all
    punctuation.  Whitespace inside quoted identifiers and string
    literals is never removed.  When in doubt, two definitions are
    considered different -- this is intentionally conservative and
    never strips all whitespace from the SQL text.
    """

    body = _strip_create_view_prefix(sql)
    output: list[str] = []
    previous = ""
    for kind, value in _tokenize(body):
        if kind == "ws":
            continue
        if kind == "ident" and value.lower() in _SQL_KEYWORDS:
            rendered = value.upper()
        else:
            rendered = value
        if output:
            if rendered in _PUNCT_CLOSE or rendered == "." or previous == "(":
                space = False
            elif previous in _PUNCT_OPEN or previous == "." or rendered == "(":
                space = False
            elif previous == ")":
                space = rendered not in (")", ",", ";", ".", "::")
            else:
                space = True
            if space:
                output.append(" ")
        output.append(rendered)
        previous = rendered
    return "".join(output)


def definitions_equal(left: str, right: str) -> bool:
    """Compare two view bodies using :func:`.normalize_view_definition`."""

    return normalize_view_definition(left) == normalize_view_definition(right)


def _statements(tokens: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    statements: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    for token in tokens:
        if token[0] != "ws" and token[1] == ";":
            if current:
                statements.append(current)
                current = []
        elif token[0] != "ws":
            current.append(token)
    if current:
        statements.append(current)
    return statements


def _split_top_level_commas(
    tokens: list[tuple[str, str]], start: int
) -> list[list[tuple[str, str]]]:
    groups: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    depth = 0
    pos = start
    while pos < len(tokens):
        kind, value = tokens[pos]
        if value == "(":
            depth += 1
            current.append(tokens[pos])
        elif value == ")":
            if depth == 0:
                break
            depth -= 1
            current.append(tokens[pos])
        elif value == "," and depth == 0:
            groups.append(current)
            current = []
        elif depth == 0 and kind == "ident" and value.lower() in _STOP_TOKENS:
            break
        elif depth == 0 and kind == "ident" and value.lower() in _JOIN_WORDS:
            break
        else:
            current.append(tokens[pos])
        pos += 1
    if current:
        groups.append(current)
    return groups


def _first_relation(
    tokens: list[tuple[str, str]],
) -> Optional[tuple[Optional[str], str]]:
    """Extract the first schema-qualified relation name from a FROM item.

    Returns None when the FROM item begins with "(" (a subquery or
    grouped join) or a join-keyword-only item.
    """

    if not tokens:
        return None
    kind, value = tokens[0]
    if kind == "punct":
        return None
    if kind == "ident" and value.lower() in _FROM_LEADING_KEYWORDS:
        return None
    parts: list[str] = []
    pos = 0
    while pos < len(tokens):
        kind, value = tokens[pos]
        if kind in ("ident", "qident"):
            parts.append(_unquote_identifier(value))
        elif kind == "punct" and value == "." and parts:
            pass
        else:
            break
        if pos + 1 < len(tokens) and tokens[pos + 1][1] == ".":
            pos += 2
            continue
        break
    if not parts:
        return None
    if len(parts) == 1:
        return None, parts[0]
    return parts[-2], parts[-1]


_JOIN_WORDS = frozenset(
    {"join", "inner", "left", "right", "full", "cross", "outer"}
)
_FROM_LEADING_KEYWORDS = frozenset(
    {"lateral", "json_table", "xmltable", "unnest", "generate_series"}
)


def _with_clause_end(tokens: list[tuple[str, str]]) -> int:
    """Return the index at which the main statement begins after WITH."""

    if not tokens or tokens[0][1].lower() != "with":
        return 0
    pos = 1
    if (
        pos < len(tokens)
        and tokens[pos][0] == "ident"
        and tokens[pos][1].lower() == "recursive"
    ):
        pos += 1
    depth = 0
    while pos < len(tokens):
        kind, value = tokens[pos]
        if value == "(":
            depth += 1
        elif value == ")":
            depth -= 1
            if depth == 0:
                # could be more CTEs separated by commas
                look = pos + 1
                while look < len(tokens) and tokens[look][0] == "ws":
                    look += 1
                if (
                    look < len(tokens)
                    and tokens[look][0] == "punct"
                    and tokens[look][1] == ","
                ):
                    pos = look + 1
                    continue
                return pos + 1
        pos += 1
    return len(tokens)


def _cte_names(tokens: list[tuple[str, str]]) -> set[str]:
    names: set[str] = set()
    if not tokens or tokens[0][1].lower() != "with":
        return names
    end = _with_clause_end(tokens)
    depth = 0
    for pos in range(1, end):
        kind, value = tokens[pos]
        if kind in ("ident", "qident") and depth == 0:
            # CTE name is followed (eventually) by AS (
            ahead = pos + 1
            while (
                ahead < end
                and tokens[ahead][0] == "ident"
                and tokens[ahead][1].lower() in ("as",)
            ):
                ahead += 1
            if (
                ahead < end
                and tokens[ahead][0] == "punct"
                and tokens[ahead][1] == "("
            ):
                names.add(_unquote_identifier(value))
        if value == "(":
            depth += 1
        elif value == ")":
            depth -= 1
    return names


def _join_item(
    tokens: list[tuple[str, str]], start: int
) -> list[tuple[str, str]]:
    """Return the single relation item on the right side of a JOIN."""

    item: list[tuple[str, str]] = []
    depth = 0
    pos = start
    while pos < len(tokens):
        kind, value = tokens[pos]
        if value == "(":
            depth += 1
        elif value == ")":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if kind == "ident" and value.lower() in _STOP_TOKENS:
                break
            if kind == "ident" and value.lower() in _JOIN_WORDS and (not item):
                break
            if kind == "ident" and value.lower() == "on":
                break
            if kind == "ident" and value.lower() == "using" and item:
                break
        item.append(tokens[pos])
        pos += 1
    return item


def view_dependencies(
    sql: str, *, schema: Optional[str] = None
) -> set[ViewKey]:
    """Infer schema-qualified relation references used by a view body.

    The scan is lexical and deliberately conservative: only relation
    names occurring directly after ``FROM``/``JOIN`` (or as additional
    comma-separated tables in a FROM clause) are collected.  String
    literals, quoted identifiers, subquery bodies and common-table
    expression names are handled so that ordinary view bodies parse
    correctly; exotic dynamic SQL is not parsed (and the explicit
    ``depends_on`` argument of :class:`.View` can be used instead).
    """

    references: set[ViewKey] = set()
    for statement in _statements(_tokenize(sql)):
        cte_names = _cte_names(statement)
        main_start = _with_clause_end(statement)
        pos = main_start
        while pos < len(statement):
            kind, value = statement[pos]
            keyword = value.lower() if kind == "ident" else None
            if keyword not in ("from", "join"):
                pos += 1
                continue

            relation_pos = pos + 1
            # skip join qualifier words such as LEFT OUTER, CROSS, ...
            while (
                relation_pos < len(statement)
                and statement[relation_pos][0] == "ident"
                and statement[relation_pos][1].lower() in _JOIN_WORDS
            ):
                relation_pos += 1

            if keyword == "from":
                groups = _split_top_level_commas(statement, relation_pos)
            else:
                groups = [_join_item(statement, relation_pos)]

            for group in groups:
                relation = _first_relation(group)
                if relation is None:
                    continue
                relation_schema, relation_name = relation
                if relation_name in cte_names:
                    continue
                references.add((relation_schema or schema, relation_name))
            pos += 1
    return references


# ---------------------------------------------------------------------------
# Dependency ordering
# ---------------------------------------------------------------------------

_WHITE = 0
_GRAY = 1
_BLACK = 2


def topological_sort(
    nodes: Collection[ViewKey],
    dependencies: Mapping[ViewKey, Collection[ViewKey]],
) -> list[ViewKey]:
    """Return ``nodes`` ordered so dependencies come first.

    Edges found in ``dependencies`` but not present in ``nodes`` are
    treated as external relations (e.g. base tables or views outside
    the plan) and ignored for ordering purposes.  A cycle raises
    :class:`.CircularViewDependencyError` naming the views involved.
    """

    present = set(nodes)
    color: dict[ViewKey, int] = {key: _WHITE for key in present}
    ordered: list[ViewKey] = []

    def visit(key: ViewKey, stack: list[ViewKey]) -> None:
        state = color.get(key, _BLACK)
        if state == _BLACK:
            return
        if state == _GRAY:
            cycle_start = stack.index(key)
            raise CircularViewDependencyError(stack[cycle_start:] + [key])
        color[key] = _GRAY
        stack.append(key)
        for dependency in sorted(set(dependencies.get(key, ()))):
            if dependency in present:
                visit(dependency, stack)
        stack.pop()
        color[key] = _BLACK
        ordered.append(key)

    for key in sorted(present):
        if color[key] == _WHITE:
            visit(key, [])
    return ordered


def reverse_topological_sort(
    nodes: Collection[ViewKey],
    dependencies: Mapping[ViewKey, Collection[ViewKey]],
) -> list[ViewKey]:
    """Return ``nodes`` in drop order (dependents first)."""

    return list(reversed(topological_sort(nodes, dependencies)))


def closure(
    roots: Collection[ViewKey],
    dependents: Mapping[ViewKey, Collection[ViewKey]],
) -> set[ViewKey]:
    """Return ``roots`` plus all transitive dependents."""

    result = set(roots)
    pending = list(roots)
    while pending:
        current = pending.pop()
        for dependent in dependents.get(current, ()):  # type: ignore[union-attr]
            if dependent not in result:
                result.add(dependent)
                pending.append(dependent)
    return result
