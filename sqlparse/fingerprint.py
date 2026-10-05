#
# Copyright (C) 2026 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Structural SQL fingerprinting.

This module groups SQL statements by *shape*: value literals and
parameter placeholders are replaced by a canonical placeholder,
insignificant whitespace and keyword case are normalized, and a stable
digest is computed over the normalized text.

A fingerprint is a structural classification only.  Two statements
sharing a fingerprint are NOT guaranteed to be semantically equivalent,
and two semantically equivalent statements may have different
fingerprints.
"""

import hashlib
from typing import NamedTuple

from sqlparse import engine
from sqlparse import tokens as T

__all__ = ["Fingerprint", "fingerprint"]

#: Canonical replacement for value literals and placeholders.
_PLACEHOLDER = "?"

#: Token types that carry optimizer hints and are kept verbatim.
_HINT_TYPES = (T.Comment.Single.Hint, T.Comment.Multiline.Hint)

#: Keywords after which bare integers are column positions, not values.
_ORDINAL_KEYWORDS = ("ORDER BY", "GROUP BY")

#: Type names whose parenthesized numeric parameters are part of the
#: type declaration (e.g. DECIMAL(10, 2)) and must not be treated as
#: value literals.
_TYPE_NAMES = frozenset({
    "BIGINT", "BINARY", "BIT", "CHAR", "CHARACTER", "DATETIME", "DEC",
    "DECIMAL", "DOUBLE", "FIXED", "FLOAT", "INT", "INTEGER", "INTERVAL",
    "MEDIUMINT", "NCHAR", "NUMERIC", "NVARCHAR", "REAL", "SMALLINT",
    "TIME", "TIMESTAMP", "TINYINT", "VARBINARY", "VARCHAR", "VARYING",
})


class Fingerprint(NamedTuple):
    """Result of :func:`fingerprint`.

    :ivar normalized: The normalized statement text.  It is meant for
        grouping and display, not for execution.
    :ivar digest: A stable hexadecimal digest (SHA-256) of *normalized*.
    """

    normalized: str
    digest: str


def fingerprint(
    sql: str, encoding: str | None = None, *, collapse_in_lists: bool = False
) -> Fingerprint:
    """Compute a structural fingerprint for one or more SQL statements.

    Value literals (numbers, strings) and parameter placeholders are
    replaced by `?`, insignificant whitespace is collapsed, keywords
    are upper-cased and plain comments are removed.  Identifier quoting,
    optimizer hints, operator boundaries (including the sign of negative
    literals), type parameters such as `DECIMAL(10, 2)` and column
    positions in `ORDER BY`/`GROUP BY` are preserved, as are the
    number of statements and the nesting structure.

    :param sql: A string containing one or more SQL statements.
    :param encoding: The encoding of the statement (optional).
    :param collapse_in_lists: If True, a parenthesized list of values
        after `IN` is collapsed to a single placeholder regardless of
        its length (`IN (1, 2)` and `IN (1, 2, 3)` both become
        `IN (?)`).  If False (default), the number of elements is
        preserved.  Sublists containing subqueries or expressions are
        never collapsed.
    :returns: A :class:`Fingerprint` with the normalized text and a
        stable digest.

    .. note::
        This is a structural grouping aid, e.g. for aggregating slow
        query logs.  It does not prove semantic equivalence of
        statements.
    """
    stack = engine.FilterStack()
    normalized = "; ".join(
        part
        for part in (
            _normalize_statement(stmt, collapse_in_lists)
            for stmt in stack.run(sql, encoding)
        )
        if part
    )
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return Fingerprint(normalized=normalized, digest=digest)


def _is_significant(token):
    if token.is_whitespace:
        return False
    ttype = token.ttype
    return ttype not in T.Comment or ttype in _HINT_TYPES


def _is_value_token(token):
    ttype = token.ttype
    return (
        ttype in T.Number
        or ttype is T.String.Single
        or ttype is T.Literal
        or ttype is T.Name.Placeholder
    )


def _value_list_end(sig, open_idx):
    """Return index of the closing parenthesis of a pure value list.

    *sig* is the list of significant tokens and *open_idx* the index of
    the opening parenthesis.  Returns None if the parenthesis holds
    anything but literals, placeholders and commas (e.g. a subquery or
    nested parentheses).
    """
    depth = 0
    for idx in range(open_idx, len(sig)):
        token = sig[idx]
        value = token.value
        if value == "(":
            depth += 1
            if depth > 1:
                return None
        elif value == ")":
            depth -= 1
            if depth == 0:
                return idx
        elif not (
            _is_value_token(token)
            or (token.ttype is T.Punctuation and value == ",")
        ):
            return None
    return None


def _normalize_statement(stmt, collapse_in_lists):
    sig = [tok for tok in stmt.flatten() if _is_significant(tok)]
    # A trailing semicolon is statement syntax, not statement content.
    while sig and sig[-1].ttype is T.Punctuation and sig[-1].value == ";":
        sig.pop()

    parts = []
    ordinal_ctx = False
    idx = 0
    count = len(sig)
    while idx < count:
        token = sig[idx]
        ttype = token.ttype
        value = token.value

        if token.is_keyword:
            upper = " ".join(value.split()).upper()
            if (
                collapse_in_lists
                and upper == "IN"
                and idx + 1 < count
                and sig[idx + 1].value == "("
            ):
                end = _value_list_end(sig, idx + 1)
                if end is not None:
                    parts.append("IN (?)")
                    ordinal_ctx = False
                    idx = end + 1
                    continue
            parts.append(upper)
            if upper in _ORDINAL_KEYWORDS:
                ordinal_ctx = True
            elif ttype not in T.Keyword.Order:
                ordinal_ctx = False
            idx += 1
            continue

        if (
            value.upper() in _TYPE_NAMES
            and idx + 1 < count
            and sig[idx + 1].value == "("
        ):
            # Type declaration: keep parameters such as (10, 2) verbatim.
            parts.append(value)
            depth = 0
            idx += 1
            while idx < count:
                current = sig[idx].value
                parts.append(current)
                if current == "(":
                    depth += 1
                elif current == ")":
                    depth -= 1
                    if depth == 0:
                        break
                idx += 1
            ordinal_ctx = False
            idx += 1
            continue

        if ttype in T.Number:
            if ordinal_ctx and ttype is T.Number.Integer:
                parts.append(value)
            elif value[:1] in ("+", "-") and len(value) > 1:
                # The sign is an operator boundary, not part of the value.
                parts.append(value[0] + _PLACEHOLDER)
            else:
                parts.append(_PLACEHOLDER)
        elif (
            ttype is T.String.Single
            or ttype is T.Literal
            or ttype is T.Name.Placeholder
        ):
            parts.append(_PLACEHOLDER)
        else:
            parts.append(value)
        idx += 1

    return _join(parts)


def _join(parts):
    out = []
    for part in parts:
        if out and part not in (",", ")") and out[-1] != "(":
            out.append(" ")
        out.append(part)
    return "".join(out)
