"""Structural SQL fingerprints."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from sqlparse import engine, sql
from sqlparse import tokens as T


@dataclass(frozen=True)
class SQLFingerprint:
    """A normalized SQL text and its stable structural digest.

    Equal fingerprints indicate that two SQL texts have the same parsed
    structure under the selected options. They are not proof that the SQL
    statements are semantically equivalent.
    """

    normalized: str
    digest: str


_TYPE_PARAMETER_TYPES = frozenset({
    "BIGDECIMAL",
    "BIGNUMERIC",
    "BINARY",
    "BIT",
    "BLOB",
    "BYTEINT",
    "CHAR",
    "CHARACTER",
    "CLOB",
    "DATETIME",
    "DAY",
    "DEC",
    "DECIMAL",
    "DOUBLE",
    "FLOAT",
    "HOUR",
    "INT",
    "INTEGER",
    "INTERVAL",
    "MINUTE",
    "MONTH",
    "NCHAR",
    "NUMBER",
    "NUMERIC",
    "NVARCHAR",
    "REAL",
    "SECOND",
    "SMALLINT",
    "TIME",
    "TIMESTAMP",
    "TINYINT",
    "VARBINARY",
    "VARCHAR",
    "VARCHAR2",
    "YEAR",
})

_POSITIONAL_CLAUSES = frozenset({"GROUP BY", "ORDER BY"})
_POSITIONAL_CLAUSE_END = frozenset({
    "EXCEPT",
    "FETCH",
    "FOR",
    "FROM",
    "HAVING",
    "INTERSECT",
    "INTO",
    "LIMIT",
    "OFFSET",
    "RETURNING",
    "UNION",
    "WHERE",
    "WINDOW",
})
_WHITESPACE = re.compile(r"\s+")
_DIGITS = re.compile(r"\d+")


def fingerprint(
    sql_text: str,
    encoding: str | None = None,
    *,
    fold_in_lists: bool = False,
) -> SQLFingerprint:
    """Return a normalized SQL text and its stable structural digest.

    Literal values are replaced with placeholders, insignificant whitespace
    is normalized, and keywords are upper-cased. Quoted identifiers and
    optimizer hints are retained.

    ``fold_in_lists`` folds flat scalar ``IN`` lists, regardless of their
    number of entries. Parenthesized rows, subqueries, and other non-scalar
    structures are never folded by this option.

    The fingerprint is intended for structural grouping, not as proof that
    two statements are semantically equivalent.
    """
    stack = engine.FilterStack()
    stack.enable_grouping()
    statements = tuple(stack.run(sql_text, encoding))
    normalized = "; ".join(
        _normalize_statement(statement, fold_in_lists)
        for statement in statements
    )
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return SQLFingerprint(normalized=normalized, digest=digest)


def _normalize_statement(
    statement: sql.Statement, fold_in_lists: bool
) -> str:
    positional_numbers = _positional_numbers(statement)
    positional_numbers |= _positional_parenthesized_numbers(statement)
    collapsed = _collapsed_in_parentheses(statement, fold_in_lists)
    atoms: list[tuple[str, str]] = []

    for token in statement.flatten():
        if token.ttype in T.Whitespace:
            continue
        if token.ttype in T.Comment:
            if _is_hint(token):
                atoms.append((_normalize_hint(token.value), "hint"))
            continue
        if token.ttype is T.Punctuation and token.value == ";":
            continue

        collapsed_parent = _collapsed_ancestor(token, collapsed)
        if collapsed_parent is not None:
            if token.value == "(":
                atoms.extend((
                    ("(", "punctuation"),
                    ("?", "placeholder"),
                    (")", "punctuation"),
                ))
            continue

        _append_token(token, id(token) in positional_numbers, atoms)

    return _join_atoms(atoms)


def _append_token(
    token: sql.Token,
    is_positional_number: bool,
    atoms: list[tuple[str, str]],
) -> None:
    if token.ttype in T.Name.Placeholder:
        atoms.append(("?", "placeholder"))
    elif token.ttype in T.String.Symbol:
        atoms.append((token.value, "name"))
    elif token.ttype in T.Number:
        if is_positional_number or _is_type_parameter(token):
            atoms.append((token.value, "literal"))
        else:
            _append_numeric_literal(token.value, atoms)
    elif token.ttype in T.Literal:
        atoms.append(("?", "placeholder"))
    elif token.is_keyword:
        atoms.append((token.normalized, "keyword"))
    elif token.ttype is T.Wildcard:
        atoms.append((token.value, "wildcard"))
    elif token.ttype in T.Punctuation:
        atoms.append((token.value, "punctuation"))
    elif token.ttype in (T.Operator, T.Operator.Comparison, T.Assignment):
        kind = (
            "unary_operator"
            if token.value == "-" and _is_unary_context(atoms)
            else "operator"
        )
        atoms.append((token.value, kind))
    elif token.ttype in T.Name and (
        _is_type_name(token) or _is_typed_literal_type(token)
    ):
        atoms.append((token.value.upper(), "name"))
    else:
        atoms.append((token.value, "name"))


def _append_numeric_literal(
    value: str, atoms: list[tuple[str, str]]
) -> None:
    if value[:1] == "-":
        kind = "unary_operator" if _is_unary_context(atoms) else "operator"
        atoms.append(("-", kind))
    atoms.append(("?", "placeholder"))


def _is_unary_context(atoms: list[tuple[str, str]]) -> bool:
    if not atoms:
        return True
    previous_text, previous_kind = atoms[-1]
    return (
        previous_kind in {"keyword", "operator", "wildcard"}
        or previous_text in "(,"
    )


def _positional_numbers(statement: sql.Statement) -> set[int]:
    positional_numbers: set[int] = set()
    in_positional_clause = False
    at_item_start = False
    parenthesis_depth = 0
    has_seen_item_token = False

    for token in statement.flatten():
        if token.ttype in T.Whitespace or token.ttype in T.Comment:
            continue

        if token.is_keyword:
            name = token.normalized
            if name in _POSITIONAL_CLAUSES:
                in_positional_clause = True
                at_item_start = True
            elif name in _POSITIONAL_CLAUSE_END or token.ttype in (
                T.DML,
                T.DDL,
                T.CTE,
            ):
                in_positional_clause = False
                at_item_start = False
                has_seen_item_token = False
            elif in_positional_clause and name not in {
                "ASC",
                "DESC",
                "FIRST",
                "LAST",
                "NULLS",
            }:
                at_item_start = False
                has_seen_item_token = True
        elif not in_positional_clause:
            continue
        elif token.ttype is T.Punctuation:
            if token.value == ",":
                if parenthesis_depth == 0:
                    at_item_start = True
                    has_seen_item_token = False
            elif token.value == "(":
                parenthesis_depth += 1
            elif token.value == ")":
                parenthesis_depth = max(0, parenthesis_depth - 1)
                if parenthesis_depth == 0 and at_item_start and (
                    not has_seen_item_token
                ):
                    at_item_start = False
            else:
                at_item_start = False
                has_seen_item_token = True
        elif token.ttype in T.Number:
            if (
                at_item_start
                and not has_seen_item_token
                and parenthesis_depth == 0
                and _DIGITS.fullmatch(token.value)
            ):
                positional_numbers.add(id(token))
            at_item_start = False
            has_seen_item_token = True
        elif token.ttype is not T.Punctuation:
            at_item_start = False
            has_seen_item_token = True

    return positional_numbers


def _positional_parenthesized_numbers(
    group: sql.TokenList,
) -> set[int]:
    positional_numbers: set[int] = set()

    def visit(node: sql.TokenList) -> None:
        for index, token in enumerate(node.tokens):
            if isinstance(token, sql.Parenthesis):
                previous = _previous_significant_token(node, index)
                if previous is not None and previous.match(
                    T.Keyword, ("ORDER BY", "GROUP BY")
                ):
                    leaves = [
                        leaf
                        for leaf in token.flatten()
                        if leaf.ttype not in T.Whitespace
                        and leaf.ttype not in T.Comment
                    ]
                    if (
                        len(leaves) == 3
                        and leaves[0].value == "("
                        and leaves[2].value == ")"
                        and leaves[1].ttype in T.Number
                        and _DIGITS.fullmatch(leaves[1].value)
                    ):
                        positional_numbers.add(id(leaves[1]))
                visit(token)
            elif token.is_group:
                visit(token)

    visit(group)
    return positional_numbers


def _previous_significant_token(
    group: sql.TokenList, index: int
) -> sql.Token | None:
    for token in reversed(group.tokens[:index]):
        if token.ttype in T.Whitespace or token.ttype in T.Comment:
            continue
        return token
    return None


def _is_type_parameter(token: sql.Token) -> bool:
    parent = token.parent
    while parent is not None and not isinstance(parent, sql.Parenthesis):
        if isinstance(parent, sql.Statement):
            return False
        parent = parent.parent

    if parent is None or not isinstance(parent.parent, sql.Function):
        return False

    function = parent.parent
    return _function_type_name(function) in _TYPE_PARAMETER_TYPES


def _is_type_name(token: sql.Token) -> bool:
    ancestor = token.parent
    crossed_parenthesis = False

    while ancestor is not None:
        if isinstance(ancestor, sql.TypedLiteral):
            return token.normalized.upper() in _TYPE_PARAMETER_TYPES
        if isinstance(ancestor, sql.Parenthesis):
            crossed_parenthesis = True
        if isinstance(ancestor, sql.Function) and not crossed_parenthesis:
            return _function_type_name(ancestor) in _TYPE_PARAMETER_TYPES
        ancestor = ancestor.parent

    return False


def _is_typed_literal_type(token: sql.Token) -> bool:
    ancestor = token.parent
    while ancestor is not None and not isinstance(
        ancestor, sql.TypedLiteral
    ):
        ancestor = ancestor.parent
    return ancestor is not None and token is ancestor.tokens[0]


def _function_type_name(function: sql.Function) -> str:
    name_parts: list[str] = []
    for token in function.tokens:
        if isinstance(token, sql.Parenthesis):
            break
        if token.is_group:
            for child in token.flatten():
                _append_type_name_part(child, name_parts)
        else:
            _append_type_name_part(token, name_parts)
    return " ".join(name_parts)


def _append_type_name_part(
    token: sql.Token, name_parts: list[str]
) -> None:
    if token.ttype in T.Whitespace or token.ttype in T.Comment:
        return
    if token.ttype is T.Punctuation and token.value == ".":
        name_parts.clear()
    elif token.is_keyword or token.ttype in T.Name:
        name_parts.append(token.normalized.upper())


def _collapsed_ancestor(
    token: sql.Token, collapsed: set[int]
) -> sql.Parenthesis | None:
    ancestor = token.parent
    while ancestor is not None:
        if isinstance(ancestor, sql.Parenthesis) and id(ancestor) in collapsed:
            return ancestor
        ancestor = ancestor.parent
    return None


def _collapsed_in_parentheses(
    group: sql.TokenList, enabled: bool
) -> set[int]:
    if not enabled:
        return set()

    collapsed: set[int] = set()

    def visit(node: sql.TokenList) -> None:
        for index, token in enumerate(node.tokens):
            if isinstance(token, sql.Parenthesis):
                if _is_in_parenthesis(node, index) and _is_flat_scalar_list(
                    token
                ):
                    collapsed.add(id(token))
                visit(token)
            elif token.is_group:
                visit(token)

    visit(group)
    return collapsed


def _is_in_parenthesis(parent: sql.TokenList, index: int) -> bool:
    for token in reversed(parent.tokens[:index]):
        if token.ttype in T.Whitespace or token.ttype in T.Comment:
            continue
        return token.match(T.Keyword, ("IN",))
    return False


def _is_flat_scalar_list(parenthesis: sql.Parenthesis) -> bool:
    for token in parenthesis.tokens[1:-1]:
        if token.is_group:
            if not _contains_only_scalar_groups(token):
                return False
        elif token.is_keyword and token.normalized in {"SELECT", "VALUES"}:
            return False
    return True


def _contains_only_scalar_groups(group: sql.Token) -> bool:
    if group.is_keyword and group.normalized == "SELECT":
        return False
    if isinstance(group, sql.Comment):
        return True
    if isinstance(group, (
        sql.Parenthesis,
        sql.SquareBrackets,
        sql.Function,
        sql.Case,
        sql.TypedLiteral,
        sql.Comparison,
        sql.Operation,
    )):
        return False
    if not group.is_group:
        return True
    return all(_contains_only_scalar_groups(token) for token in group.tokens)


def _is_hint(token: sql.Token) -> bool:
    return token.ttype in (
        T.Comment.Multiline.Hint,
        T.Comment.Single.Hint,
    ) or token.value.startswith(("/*+", "--+", "# +"))


def _normalize_hint(value: str) -> str:
    if value.startswith("/*+"):
        return (
            "/*+ "
            + _WHITESPACE.sub(
                " ", value.removeprefix("/*+").removesuffix("*/")
            ).strip()
            + " */"
        )
    if value.startswith("--+"):
        return (
            "--+ "
            + _WHITESPACE.sub(
                " ", value.removeprefix("--+")
            ).strip()
            + "\n"
        )
    return (
        "# + "
        + _WHITESPACE.sub(
            " ", value.removeprefix("# +")
        ).strip()
        + "\n"
    )


def _join_atoms(atoms: list[tuple[str, str]]) -> str:
    parts: list[str] = []
    previous: tuple[str, str] | None = None

    for current in atoms:
        text, kind = current
        if previous is not None and _needs_space(previous, current):
            parts.append(" ")
        parts.append(text)
        previous = current

    return "".join(parts).strip()


def _needs_space(
    previous: tuple[str, str], current: tuple[str, str]
) -> bool:
    previous_text, previous_kind = previous
    current_text, current_kind = current

    if current_text in ")].;,:":
        return False
    if current_kind == "unary_operator":
        return previous_text not in "(,"
    if previous_kind == "hint":
        return previous_text.endswith("*/")
    if previous_text in "([.:" or previous_kind == "unary_operator":
        return False
    if current_text == "(" and previous_kind in {"name", "wildcard"}:
        return False
    return not (
        current_text == "[" and previous_kind in {"name", "wildcard"}
    )
