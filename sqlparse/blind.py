"""Create read-only blind review views for SQL migrations.

The view keeps the parts needed to review the effect of a statement:
statement flow, identifiers, operators, parentheses, boolean structure and
the number of values in a list.  String and numeric literals are replaced by
keyed markers, and comments are removed.  The markers are deliberately not
reversible without the key used to create the view.

Markers are scoped by their use.  For example, the same value used in a
``WHERE`` predicate and in an ``UPDATE ... SET`` assignment receives two
different roles, while repeated occurrences in the same kind of use share a
marker.  This preserves equality relationships without making unrelated uses
look identical.

A small set of columns is treated as containing credentials by default.
Predicates on those columns are replaced as a whole and marked as requiring
an internal review; callers can add columns or tables to that policy.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import re
import secrets
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlparse import sql
from sqlparse import tokens as T
from sqlparse.engine import FilterStack
from sqlparse.exceptions import SQLParseError


_DEFAULT_KEY = secrets.token_bytes(32)

_PRESERVED = (
    "statement flow, keywords and clause boundaries",
    "identifiers, operators, parentheses and boolean structure",
    "literal positions and list cardinality outside internal-only predicates",
)
_REDACTED = (
    "string literals",
    "numeric literals",
    "comments",
    "predicates governed by the internal-only policy",
)

_TYPE_FUNCTIONS = frozenset({
    "BINARY",
    "BIT",
    "CHAR",
    "DECIMAL",
    "DOUBLE",
    "FLOAT",
    "INTERVAL",
    "NCHAR",
    "NUMBER",
    "NUMERIC",
    "NVARCHAR",
    "REAL",
    "TIME",
    "TIMESTAMP",
    "VARBINARY",
    "VARCHAR",
})

_SENSITIVE_COLUMNS = frozenset({
    "access_key",
    "api_key",
    "apikey",
    "auth_token",
    "card_number",
    "client_secret",
    "credential",
    "credentials",
    "credit_card",
    "passwd",
    "password",
    "private_key",
    "pwd",
    "refresh_token",
    "secret",
    "session_token",
    "social_security_number",
    "ssn",
    "token",
})

_SENSITIVE_COLUMN_SUFFIXES = (
    "_access_key",
    "_api_key",
    "_auth_token",
    "_card_number",
    "_client_secret",
    "_credential",
    "_credentials",
    "_passwd",
    "_password",
    "_private_key",
    "_refresh_token",
    "_secret",
    "_session_token",
    "_token",
)

_MARKER_RE = re.compile(
    r"<(?P<kind>string|number):(?P<role>[a-z_]+):[0-9a-f]+>"
)
_COMMENT_MARKER_RE = re.compile(
    r"/\*\s*comment redacted\s*\*/", re.IGNORECASE
)
_INTERNAL_MARKER_RE = re.compile(
    r"/\*\s*INTERNAL REVIEW REQUIRED:\s*(?P<reason>[^*]+?)\s*\*/",
    re.IGNORECASE,
)
_UPDATE_TARGET_RE = re.compile(
    r"\bUPDATE\b.+?\bSET\b(?P<body>.+?)"
    r"(?=\bWHERE\b|\bRETURNING\b|;|$)",
    re.IGNORECASE | re.DOTALL,
)
_TARGET_ASSIGN_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?)\s*=(?!=|>)"
)
_INSERT_TARGET_RE = re.compile(
    r"\bINSERT\s+INTO\s+\S+\s*\((?P<body>[^)]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_ALTER_TARGET_RE = re.compile(
    r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?\S+\s+ADD\s+(?:COLUMN\s+)?"
    r"(?P<name>[A-Za-z_][\w$]*)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class LiteralRef:
    """A visible literal placeholder in a blind review view."""

    marker: str
    role: str
    kind: str
    statement: int
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class InternalPredicate:
    """A predicate withheld from the external view.

    The reason names the column or table that triggered the policy, but the
    predicate operator and literal are intentionally not retained.
    """

    reason: str
    column: str | None
    table: str | None
    statement: int


@dataclass(frozen=True, slots=True)
class BlindScope:
    """A value-independent description of a blind review view.

    ``structure`` replaces every visible literal marker with ``?``.  A change
    to a literal value therefore changes the review bindings but not the
    structure.  ``key`` is a digest of this structure and is used to compare
    two reviews without exposing any original value.
    """

    statements: tuple[str, ...]
    tables: tuple[str, ...]
    targets: tuple[str, ...]
    structure: tuple[str, ...]
    key: str


@dataclass(frozen=True, slots=True)
class BlindReviewDiff:
    """Compare the impact shape and visible bindings of two reviews."""

    before_scope: BlindScope
    after_scope: BlindScope
    scope_changes: tuple[str, ...]
    bindings_changed: bool
    binding_changes: tuple[str, ...]

    @property
    def scope_changed(self) -> bool:
        """Return whether the reviewed SQL structure changed."""

        return self.before_scope.key != self.after_scope.key

    @property
    def changed(self) -> bool:
        """Return whether the structure or a visible binding changed."""

        return self.scope_changed or self.bindings_changed

    def summary(self) -> str:
        """Return a short, value-free summary suitable for a review ticket."""

        lines = [
            f"Impact scope changed: {'yes' if self.scope_changed else 'no'}",
            "Visible literal bindings changed: "
            f"{'yes' if self.bindings_changed else 'no'}",
        ]
        if self.scope_changes:
            lines.append("Structure changes:")
            lines.extend(f"  {line}" for line in self.scope_changes)
        if self.binding_changes:
            lines.append("Binding changes:")
            lines.extend(f"  {line}" for line in self.binding_changes)
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class BlindReview:
    """A read-only, value-free view of one or more SQL statements."""

    sql: str
    occurrences: tuple[LiteralRef, ...]
    internal_only: tuple[InternalPredicate, ...]
    scope: BlindScope

    def __str__(self) -> str:
        return self.to_ticket()

    def diff(self, other: BlindReview) -> BlindReviewDiff:
        """Return a value-free comparison with *other*."""

        return _diff_reviews(self, other)

    def to_ticket(self) -> str:
        """Render the view with a short description for an external ticket."""

        header = (
            "-- BLIND REVIEW VIEW (read-only)\n"
            f"-- Preserved: {'; '.join(_PRESERVED)}.\n"
            f"-- Redacted: {'; '.join(_REDACTED)}.\n"
            "-- Markers are <kind:role:id>. The same role and id mean the "
            "same value in that use; a different role means a different use.\n"
            "-- INTERNAL REVIEW REQUIRED marks predicates that must be "
            "reviewed only by the trusted group.\n"
        )
        return header + self.sql


@dataclass(slots=True)
class _Leaf:
    token: Any
    ancestors: tuple[Any, ...]


class BlindReviewer:
    """Reusable blind-review factory.

    Reuse one instance, or pass the same ``key`` to the module-level helper,
    when comparing two versions of a migration.  With a stable key, the same
    value and role keep the same marker across both versions.
    """

    __slots__ = ("_key",)

    def __init__(self, key: str | bytes | None = None):
        self._key = _coerce_key(key)

    def review(
        self,
        sql: str,
        *,
        internal_only_columns: Iterable[str] = (),
        internal_only_tables: Iterable[str] = (),
    ) -> BlindReview:
        """Create a read-only blind review view."""

        return _review(
            sql,
            key=self._key,
            internal_only_columns=internal_only_columns,
            internal_only_tables=internal_only_tables,
        )


def blind_review(
    sql: str,
    *,
    key: str | bytes | None = None,
    internal_only_columns: Iterable[str] = (),
    internal_only_tables: Iterable[str] = (),
) -> BlindReview:
    """Return a read-only blind review view.

    String and numeric literals are replaced with keyed markers.  The same
    value in the same role shares a marker; the same value in a different
    role does not.  Comments are removed.

    ``internal_only_columns`` and ``internal_only_tables`` extend the default
    policy.  Predicates affected by that policy are withheld as a whole and
    reported in :attr:`BlindReview.internal_only`.

    :param sql: SQL migration text to review.
    :param key: Secret key used for marker generation.  Reuse a key when
        comparing versions.  If omitted, a process-local key is used.
    :param internal_only_columns: Additional column names that require an
        internal review.
    :param internal_only_tables: Tables whose predicates require an internal
        review.
    :returns: A frozen :class:`BlindReview` without the original values.
    :raises SQLParseError: If the input contains unparsed text, such as an
        unterminated string literal or block comment.
    """

    reviewer = _DEFAULT_REVIEWER if key is None else BlindReviewer(key)
    return reviewer.review(
        sql,
        internal_only_columns=internal_only_columns,
        internal_only_tables=internal_only_tables,
    )


def _coerce_key(key: str | bytes | None) -> bytes:
    if key is None:
        return _DEFAULT_KEY
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not isinstance(key, bytes):
        raise TypeError("key must be str, bytes or None")
    if not key:
        raise ValueError("key must not be empty")
    return key


_DEFAULT_REVIEWER = BlindReviewer(_DEFAULT_KEY)


def _review(
    sql_text: str,
    *,
    key: bytes,
    internal_only_columns: Iterable[str],
    internal_only_tables: Iterable[str],
) -> BlindReview:
    if not isinstance(sql_text, str):
        raise TypeError("sql must be a string")

    statements = _parse(sql_text)
    columns = _normalise_names(internal_only_columns)
    tables = _normalise_names(internal_only_tables)

    rendered_parts = []
    occurrences = []
    internal_predicates = []
    structures = []
    statement_types = []
    all_tables = []
    targets = []
    base_offset = 0

    for statement_index, statement in enumerate(statements):
        statement_text = str(statement)
        leaves = _leaves(statement)
        _validate_parse(leaves)
        modes = _modes(leaves)
        statement_tables = _extract_tables(leaves)
        statement_type = statement.get_type()

        internal_spans = _internal_spans(
            leaves,
            modes,
            statement_tables,
            columns,
            tables,
            statement_index,
        )
        rendered, statement_occurrences = _render(
            leaves,
            modes,
            internal_spans,
            key,
            statement_index,
            sql_text,
            base_offset,
        )
        rendered_parts.append(rendered)
        occurrences.extend(statement_occurrences)
        internal_predicates.extend(internal_spans.predicates)
        structure = _canonical_structure(rendered)
        structures.append(structure)
        statement_types.append(statement_type)
        all_tables.extend(statement_tables)
        targets.extend(_extract_targets(rendered))
        base_offset += len(statement_text)

    scope = BlindScope(
        statements=tuple(statement_types),
        tables=tuple(_dedupe(all_tables)),
        targets=tuple(_dedupe(targets)),
        structure=tuple(structures),
        key=_scope_key(structures),
    )
    return BlindReview(
        sql="".join(rendered_parts),
        occurrences=tuple(occurrences),
        internal_only=tuple(internal_predicates),
        scope=scope,
    )


def _parse(sql_text: str) -> tuple[Any, ...]:
    stack = FilterStack()
    stack.enable_grouping()
    return tuple(stack.run(sql_text))


def _validate_parse(leaves: tuple[_Leaf, ...]) -> None:
    for leaf in leaves:
        if leaf.token.ttype in T.Error:
            raise SQLParseError(
                "cannot create a blind review for unparsed SQL input"
            )

    for idx in range(len(leaves) - 1):
        if (
            leaves[idx].token.value == "/"
            and leaves[idx + 1].token.value == "*"
        ):
            raise SQLParseError(
                "cannot create a blind review for an unterminated comment"
            )


def _leaves(statement: Any) -> tuple[_Leaf, ...]:
    result = []
    for token in statement.flatten():
        ancestors = []
        parent = token.parent
        while parent is not None:
            ancestors.append(parent)
            parent = parent.parent
        result.append(_Leaf(token, tuple(ancestors)))
    return tuple(result)


def _modes(leaves: tuple[_Leaf, ...]) -> tuple[str, ...]:
    mode = "value"
    modes = []
    mode_stack = []
    case_stack = []

    for leaf in leaves:
        token = leaf.token
        value = token.value

        if token.is_keyword:
            keyword = token.normalized
            if keyword == "CASE":
                case_stack.append(mode)
            elif keyword in ("END", "END CASE") and case_stack:
                mode = case_stack.pop()
            elif keyword in ("WHERE", "HAVING", "ON", "WHEN"):
                mode = "predicate"
            elif keyword in ("SET", "UPDATE"):
                mode = "assignment"
            elif keyword == "VALUES":
                mode = "row"
            elif keyword == "DEFAULT":
                mode = "default"
            elif keyword in ("SELECT", "RETURNING", "THEN", "ELSE"):
                mode = "projection"
            elif keyword in ("LIMIT", "OFFSET"):
                mode = "value"

        if value == "(":
            mode_stack.append(mode)
        elif value == ")" and mode_stack:
            mode = mode_stack.pop()

        modes.append(mode)

    return tuple(modes)


def _render(
    leaves: tuple[_Leaf, ...],
    modes: tuple[str, ...],
    internal_spans: "_InternalSpans",
    key: bytes,
    statement_index: int,
    source: str,
    base_offset: int,
) -> tuple[str, list[LiteralRef]]:
    spans = {
        start: (end, replacement)
        for start, end, replacement in internal_spans.spans
    }
    comment_spans = _comment_spans(leaves)
    for start, end in comment_spans:
        newlines = sum(
            leaves[idx].token.value.count("\n")
            for idx in range(start, end + 1)
        )
        replacement = "/* comment redacted */" + "\n" * newlines
        spans.setdefault(start, (end, replacement))

    literals = {}
    occurrences = []
    offset = base_offset
    for idx, leaf in enumerate(leaves):
        token = leaf.token
        if _is_literal(token):
            role = _literal_role(leaf, modes[idx])
            kind = _literal_kind(token)
            marker = _marker(token.value, kind, role, key)
            literals[idx] = marker
            if not _covered(idx, internal_spans.spans):
                line, column = _position(source, offset)
                occurrences.append(
                    LiteralRef(
                        marker=marker,
                        role=role,
                        kind=kind,
                        statement=statement_index,
                        line=line,
                        column=column,
                    )
                )
        offset += len(token.value)

    rendered = []
    idx = 0
    while idx < len(leaves):
        if idx in spans:
            end, replacement = spans[idx]
            rendered.append(replacement)
            idx = end + 1
            continue
        if idx in literals:
            rendered.append(literals[idx])
        else:
            rendered.append(leaves[idx].token.value)
        idx += 1

    return "".join(rendered), occurrences


def _is_literal(token: Any) -> bool:
    """Return whether token is a value literal.

    Quoted identifiers are tokenized as ``T.String.Symbol``; they are
    structure and must stay visible.
    """

    return token.ttype in T.Literal and token.ttype is not T.String.Symbol


def _literal_kind(token: Any) -> str:
    if token.ttype in T.Number:
        return "number"
    return "string"


def _literal_role(leaf: _Leaf, mode: str) -> str:
    if _inside(leaf, sql.Values):
        return "row"
    if mode == "default":
        return "default"
    function = _nearest(leaf, sql.Function)
    if function is not None:
        if _function_name(function).upper() in _TYPE_FUNCTIONS:
            return "type_argument"
        return "value"
    return mode


def _marker(value: str, kind: str, role: str, key: bytes) -> str:
    payload = "\0".join((kind, role, value)).encode("utf-8")
    digest = hmac.new(key, payload, hashlib.sha256).hexdigest()[:10]
    return f"<{kind}:{role}:{digest}>"


@dataclass(frozen=True, slots=True)
class _InternalSpans:
    spans: tuple[tuple[int, int, str], ...]
    predicates: tuple[InternalPredicate, ...]


def _internal_spans(
    leaves: tuple[_Leaf, ...],
    modes: tuple[str, ...],
    statement_tables: list[str],
    extra_columns: frozenset[str],
    internal_tables: frozenset[str],
    statement_index: int,
) -> _InternalSpans:
    predicate_table = _matching_table(statement_tables, internal_tables)
    spans = {}
    predicates = []

    for idx, leaf in enumerate(leaves):
        if not _is_literal(leaf.token) or modes[idx] != "predicate":
            continue

        span = _predicate_span(leaves, idx)
        if span is None:
            continue
        start, end = span
        column = _predicate_column(leaves, start, end)
        reason = None
        if predicate_table is not None:
            reason = f"table {predicate_table}"
        elif column is not None and _is_internal_column(
            column, extra_columns
        ):
            reason = f"column {column}"
        if reason is None:
            continue

        spans[(start, end)] = (
            start,
            end,
            "/* INTERNAL REVIEW REQUIRED: "
            f"{_safe_comment_text(reason)} */",
        )
        predicates.append(
            InternalPredicate(
                reason=reason,
                column=column,
                table=predicate_table,
                statement=statement_index,
            )
        )

    return _InternalSpans(
        spans=tuple(spans.values()),
        predicates=tuple(_dedupe_predicates(predicates)),
    )


def _predicate_span(
    leaves: tuple[_Leaf, ...], literal_index: int
) -> tuple[int, int] | None:
    comparison = _nearest(leaves[literal_index], sql.Comparison)
    if comparison is not None:
        indices = _indices_of(leaves, comparison)
        if indices:
            return indices[0], indices[-1]

    clause_start = _clause_start(leaves, literal_index)
    clause_end = _clause_end(leaves, literal_index)
    predicates = _split_boolean_terms(leaves, clause_start, clause_end)
    for start, end in predicates:
        if start <= literal_index <= end:
            return _extend_balanced(leaves, start, end)
    return None


def _indices_of(leaves: tuple[_Leaf, ...], group: Any) -> list[int]:
    return [
        idx
        for idx, leaf in enumerate(leaves)
        if group in leaf.ancestors
    ]


def _clause_start(leaves: tuple[_Leaf, ...], index: int) -> int:
    for idx in range(index - 1, -1, -1):
        token = leaves[idx].token
        if token.is_keyword and token.normalized in (
            "WHERE",
            "HAVING",
            "ON",
            "WHEN",
        ):
            return idx + 1
        if token.value == ";" or (
            token.is_keyword
            and token.normalized in (
                "SELECT",
                "FROM",
                "GROUP BY",
                "ORDER BY",
                "LIMIT",
                "RETURNING",
            )
        ):
            return idx + 1
    return 0


def _clause_end(leaves: tuple[_Leaf, ...], index: int) -> int:
    depth = 0
    for idx in range(index, len(leaves)):
        token = leaves[idx].token
        if token.value == "(":
            depth += 1
        elif token.value == ")":
            if depth == 0:
                return idx - 1
            depth -= 1
        elif depth == 0 and (
            token.value == ";"
            or (
                token.is_keyword
                and token.normalized in (
                    "GROUP BY",
                    "ORDER BY",
                    "LIMIT",
                    "RETURNING",
                    "UNION",
                    "UNION ALL",
                    "EXCEPT",
                    "INTERSECT",
                    "THEN",
                    "ELSE",
                    "END",
                )
            )
        ):
            return idx - 1
    return len(leaves) - 1


def _split_boolean_terms(
    leaves: tuple[_Leaf, ...], start: int, end: int
) -> list[tuple[int, int]]:
    terms = []
    term_start = _skip_space(leaves, start, end, forward=True)
    if term_start is None:
        return terms

    depths = _depths(leaves)
    base_depth = depths[term_start]
    boundaries = []
    between = 0

    for idx in range(term_start, end + 1):
        if depths[idx] != base_depth:
            continue
        token = leaves[idx].token
        if token.is_keyword and token.normalized == "BETWEEN":
            between += 1
        elif token.is_keyword and token.normalized == "AND":
            if between:
                between -= 1
            else:
                boundaries.append(idx)
        elif token.is_keyword and token.normalized == "OR":
            boundaries.append(idx)

    for boundary in boundaries:
        term_end = _skip_space(
            leaves, boundary - 1, term_start, forward=False
        )
        if term_end is not None and term_start <= term_end:
            terms.append((term_start, term_end))
        next_start = _skip_space(
            leaves, boundary + 1, end, forward=True
        )
        if next_start is None:
            return terms
        term_start = next_start

    term_end = _skip_space(leaves, end, term_start, forward=False)
    if term_end is not None and term_start <= term_end:
        terms.append((term_start, term_end))
    return terms


def _depths(leaves: tuple[_Leaf, ...]) -> list[int]:
    depths = []
    depth = 0
    for leaf in leaves:
        value = leaf.token.value
        if value == ")":
            depth = max(depth - 1, 0)
        depths.append(depth)
        if value == "(":
            depth += 1
    return depths


def _extend_balanced(
    leaves: tuple[_Leaf, ...], start: int, end: int
) -> tuple[int, int]:
    depth = 0
    for idx in range(start, end + 1):
        value = leaves[idx].token.value
        if value == "(":
            depth += 1
        elif value == ")":
            depth = max(depth - 1, 0)

    while depth > 0 and end + 1 < len(leaves):
        value = leaves[end + 1].token.value
        if value == ")":
            depth -= 1
        elif not leaves[end + 1].token.is_whitespace:
            break
        end += 1
    return start, end


def _skip_space(
    leaves: tuple[_Leaf, ...],
    start: int,
    end: int,
    *,
    forward: bool,
) -> int | None:
    if forward:
        step = 1
        stop = end
    else:
        step = -1
        stop = end

    idx = start
    while (idx <= stop) if forward else (idx >= stop):
        if not leaves[idx].token.is_whitespace:
            return idx
        idx += step
    return None


def _predicate_column(
    leaves: tuple[_Leaf, ...], start: int, end: int
) -> str | None:
    names = []
    for idx in range(start, end + 1):
        token = leaves[idx].token
        if token.is_keyword and token.normalized in (
            "IN",
            "NOT",
            "BETWEEN",
            "LIKE",
            "ILIKE",
            "IS",
            "AND",
            "OR",
        ):
            break
        if token.ttype in (T.Name, T.String.Symbol):
            names.append(_unquote(token.value))
    return names[-1] if names else None


def _is_internal_column(
    column: str, extra_columns: frozenset[str]
) -> bool:
    name = _unquote(column).lower()
    simple = name.rsplit(".", 1)[-1]
    if name in extra_columns or simple in extra_columns:
        return True
    if any(
        configured.rsplit(".", 1)[-1] == simple
        for configured in extra_columns
    ):
        return True
    if simple in _SENSITIVE_COLUMNS:
        return True
    return any(simple.endswith(suffix) for suffix in _SENSITIVE_COLUMN_SUFFIXES)


def _matching_table(
    statement_tables: list[str], internal_tables: frozenset[str]
) -> str | None:
    for table in statement_tables:
        normalised = re.sub(r"[\"`\[\]]", "", table.lower())
        if (
            normalised in internal_tables
            or normalised.rsplit(".", 1)[-1] in internal_tables
        ):
            return table
    return None


def _normalise_names(names: Iterable[str]) -> frozenset[str]:
    if isinstance(names, str):
        names = (names,)
    result = set()
    for name in names:
        if not isinstance(name, str):
            raise TypeError("internal-only names must be strings")
        normalised = re.sub(r"[\"`\[\]]", "", name.lower())
        result.add(normalised)
    return frozenset(result)


def _unquote(value: str) -> str:
    if len(value) >= 2:
        pairs = {'"': '"', "`": "`", "[": "]", "'": "'"}
        if value[0] in pairs and value[-1] == pairs[value[0]]:
            return value[1:-1]
    return value


def _function_name(function: Any) -> str:
    for token in function.tokens:
        if isinstance(token, sql.Identifier):
            name = token.get_real_name()
            if name:
                return name
        elif token.ttype in (T.Name, T.String.Symbol):
            return _unquote(token.value)
    return ""


def _nearest(leaf: _Leaf, cls: type) -> Any | None:
    for ancestor in leaf.ancestors:
        if isinstance(ancestor, cls):
            return ancestor
    return None


def _inside(leaf: _Leaf, cls: type) -> bool:
    return any(isinstance(ancestor, cls) for ancestor in leaf.ancestors)


def _comment_spans(
    leaves: tuple[_Leaf, ...]
) -> tuple[tuple[int, int], ...]:
    spans = []
    seen = set()
    for idx, leaf in enumerate(leaves):
        comment = _nearest(leaf, sql.Comment)
        if comment is not None:
            if id(comment) in seen:
                continue
            seen.add(id(comment))
            indices = _indices_of(leaves, comment)
            if indices:
                spans.append((indices[0], indices[-1]))
        elif leaf.token.ttype in T.Comment:
            spans.append((idx, idx))
    return tuple(spans)


def _covered(
    idx: int, spans: tuple[tuple[int, int, str], ...]
) -> bool:
    return any(start <= idx <= end for start, end, _ in spans)


def _position(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    return line, offset - last_newline


def _extract_tables(leaves: tuple[_Leaf, ...]) -> list[str]:
    result = []
    for idx, leaf in enumerate(leaves):
        token = leaf.token
        if not token.is_keyword or token.normalized not in (
            "FROM", "JOIN", "UPDATE", "INTO", "TABLE", "USING"
        ):
            continue
        if _inside(leaf, sql.Function):
            continue
        if token.normalized == "UPDATE":
            prev_idx = _prev_significant(leaves, idx - 1)
            if prev_idx is not None:
                previous = leaves[prev_idx].token
                if previous.normalized in ("DO", "FOR", "KEY"):
                    continue
        name = _table_name_after(leaves, idx)
        if name is not None:
            result.append(name)
    return result


def _table_name_after(
    leaves: tuple[_Leaf, ...], index: int
) -> str | None:
    idx = _next_significant(leaves, index + 1)
    while idx is not None:
        token = leaves[idx].token
        if token.is_keyword and token.normalized in (
            "IF", "EXISTS", "LATERAL", "ONLY"
        ):
            idx = _next_significant(leaves, idx + 1)
            continue
        break
    if idx is None:
        return None

    token = leaves[idx].token
    if not _is_table_name(token):
        return None

    parts = [_unquote(token.value)]
    idx = _next_significant(leaves, idx + 1)
    while idx is not None and leaves[idx].token.value == ".":
        idx = _next_significant(leaves, idx + 1)
        if idx is None:
            break
        token = leaves[idx].token
        if not _is_table_name(token):
            break
        parts.append(_unquote(token.value))
        idx = _next_significant(leaves, idx + 1)
    return ".".join(parts)


_NON_TABLE_KEYWORDS = frozenset({
    "AS", "EXCEPT", "FETCH", "FOR", "FROM", "GROUP BY", "HAVING",
    "INTERSECT", "INTO", "JOIN", "LIMIT", "OFFSET", "ON", "ORDER BY",
    "QUALIFY", "RETURNING", "SELECT", "SET", "UNION", "UNION ALL",
    "USING", "VALUES", "WHERE", "WINDOW", "WITH",
})


def _is_table_name(token: Any) -> bool:
    if token.ttype in (T.Name, T.String.Symbol):
        return True
    return (
        token.is_keyword
        and token.normalized not in _NON_TABLE_KEYWORDS
    )


def _next_significant(
    leaves: tuple[_Leaf, ...], start: int
) -> int | None:
    for idx in range(start, len(leaves)):
        token = leaves[idx].token
        if token.is_whitespace or _inside(leaves[idx], sql.Comment):
            continue
        return idx
    return None


def _prev_significant(
    leaves: tuple[_Leaf, ...], start: int
) -> int | None:
    for idx in range(start, -1, -1):
        token = leaves[idx].token
        if token.is_whitespace or _inside(leaves[idx], sql.Comment):
            continue
        return idx
    return None


def _extract_targets(redacted_sql: str) -> list[str]:
    targets = []
    for match in _UPDATE_TARGET_RE.finditer(redacted_sql):
        body = match.group("body")
        for assignment in _split_top_level(body, ","):
            parsed = _TARGET_ASSIGN_RE.match(assignment)
            if parsed is not None:
                targets.append(parsed.group("name"))

    for match in _INSERT_TARGET_RE.finditer(redacted_sql):
        for name in match.group("body").split(","):
            name = name.strip()
            if name:
                targets.append(name)

    for match in _ALTER_TARGET_RE.finditer(redacted_sql):
        targets.append(match.group("name"))
    return targets


def _safe_comment_text(value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip())
    return re.sub(r"[^A-Za-z0-9_.$ -]", "_", value)


def _split_top_level(value: str, separator: str) -> list[str]:
    parts = []
    start = 0
    depth = 0
    quote = None

    for idx, char in enumerate(value):
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in ('"', '`'):
            quote = char
        elif char == "[":
            quote = "]"
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        elif char == separator and depth == 0:
            parts.append(value[start:idx])
            start = idx + 1

    parts.append(value[start:])
    return parts


def _canonical_structure(redacted_sql: str) -> str:
    structure = _MARKER_RE.sub("?", redacted_sql)
    structure = _COMMENT_MARKER_RE.sub("<comment>", structure)
    structure = _INTERNAL_MARKER_RE.sub(
        lambda match: f"<internal:{match.group('reason').strip()}>",
        structure,
    )
    return re.sub(r"\s+", " ", structure).strip()


def _scope_key(structures: list[str]) -> str:
    payload = "\n".join(structures).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _diff_reviews(
    before: BlindReview, after: BlindReview
) -> BlindReviewDiff:
    scope_changes = tuple(
        difflib.unified_diff(
            before.scope.structure,
            after.scope.structure,
            fromfile="before",
            tofile="after",
            lineterm="",
        )
    )
    before_bindings = _bindings(before)
    after_bindings = _bindings(after)
    changed_keys = sorted(
        set(before_bindings) ^ set(after_bindings)
        | {
            key
            for key in set(before_bindings) & set(after_bindings)
            if before_bindings[key] != after_bindings[key]
        }
    )
    binding_changes = tuple(
        f"statement {statement} role {role}: binding set changed"
        for statement, role, _kind, _marker in changed_keys
    )
    return BlindReviewDiff(
        before_scope=before.scope,
        after_scope=after.scope,
        scope_changes=scope_changes,
        bindings_changed=before_bindings != after_bindings,
        binding_changes=tuple(_dedupe(binding_changes)),
    )


def _bindings(review: BlindReview) -> Counter:
    return Counter(
        (item.statement, item.role, item.kind, item.marker)
        for item in review.occurrences
    )


def _dedupe(values: Iterable[Any]) -> list[Any]:
    result = []
    seen = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _dedupe_predicates(
    predicates: list[InternalPredicate],
) -> list[InternalPredicate]:
    return _dedupe(predicates)


__all__ = [
    "BlindReview",
    "BlindReviewDiff",
    "BlindReviewer",
    "BlindScope",
    "InternalPredicate",
    "LiteralRef",
    "blind_review",
]
