#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Parse SQL statements."""

# Setup namespace
from collections.abc import Generator
from typing import IO, Any

from sqlparse import cli, engine, filters, formatter, sql, tokens
from sqlparse.exceptions import SQLParseError, SQLParseLimitError
from sqlparse.limits import ParseLimits, coerce_limits

__version__ = "0.6.1"
__all__ = [
    "ParseLimits",
    "SQLParseError",
    "SQLParseLimitError",
    "cli",
    "engine",
    "filters",
    "formatter",
    "sql",
    "tokens",
]


def parse(
    sql: str,
    encoding: str | None = None,
    *,
    limits: ParseLimits | None = None,
    max_tokens: int | None = None,
    max_nesting_depth: int | None = None,
    max_grouping_depth: int | None = None,
    max_grouping_calls: int | None = None,
    max_token_length: int | None = None,
    timeout: float | None = None,
) -> tuple[sql.Statement, ...]:
    """Parse sql and return a list of statements.

    :param sql: A string containing one or more SQL statements.
    :param encoding: The encoding of the statement (optional).
    :param limits: Optional :class:`~sqlparse.limits.ParseLimits` with the
        resource budget for this invocation only.
    :param max_tokens: Maximum number of lexer tokens in the input.
    :param max_nesting_depth: Maximum parenthesis/CASE nesting depth.
    :param max_grouping_depth: Maximum grouping recursion depth.
    :param max_grouping_calls: Maximum number of grouping function calls.
    :param max_token_length: Maximum length of a single lexer token.
    :param timeout: Wall-clock budget in seconds.
    :returns: A tuple of :class:`~sqlparse.sql.Statement` instances.
    """
    resource_limits = coerce_limits(
        limits,
        max_tokens=max_tokens,
        max_nesting_depth=max_nesting_depth,
        max_grouping_depth=max_grouping_depth,
        max_grouping_calls=max_grouping_calls,
        max_token_length=max_token_length,
        timeout=timeout,
    )
    return tuple(parsestream(sql, encoding, resource_limits))


def parsestream(
    stream: str | IO[str],
    encoding: str | None = None,
    limits: ParseLimits | None = None,
) -> Generator[sql.Statement, None, None]:
    """Parses sql statements from file-like object.

    :param stream: A file-like object.
    :param encoding: The encoding of the stream contents (optional).
    :returns: A generator of :class:`~sqlparse.sql.Statement` instances.
    """
    stack = engine.FilterStack(limits=limits)
    stack.enable_grouping()
    return stack.run(stream, encoding)


def format(sql: str, encoding: str | None = None, **options: Any) -> str:
    """Format *sql* according to *options*.

    Available options are documented in :ref:`formatting`.

    In addition to the formatting options this function accepts the
    keyword "encoding" which determines the encoding of the statement.

    :returns: The formatted SQL statement as string.
    """
    resource_limits = coerce_limits(
        options.pop('limits', None),
        max_tokens=options.pop('max_tokens', None),
        max_nesting_depth=options.pop('max_nesting_depth', None),
        max_grouping_depth=options.pop('max_grouping_depth', None),
        max_grouping_calls=options.pop('max_grouping_calls', None),
        max_token_length=options.pop('max_token_length', None),
        timeout=options.pop('timeout', None),
    )
    stack = engine.FilterStack(limits=resource_limits)
    options = formatter.validate_options(options)
    stack = formatter.build_filter_stack(stack, options)
    stack.postprocess.append(filters.SerializerUnicode())
    return "".join(stack.run(sql, encoding))


def split(
    sql: str,
    encoding: str | None = None,
    strip_semicolon: bool = False,
    *,
    limits: ParseLimits | None = None,
    max_tokens: int | None = None,
    max_nesting_depth: int | None = None,
    max_grouping_depth: int | None = None,
    max_grouping_calls: int | None = None,
    max_token_length: int | None = None,
    timeout: float | None = None,
) -> list[str]:
    """Split *sql* into single statements.

    :param sql: A string containing one or more SQL statements.
    :param encoding: The encoding of the statement (optional).
    :param strip_semicolon: If True, remove trailing semicolons
        (default: False).
    :returns: A list of strings.
    """
    resource_limits = coerce_limits(
        limits,
        max_tokens=max_tokens,
        max_nesting_depth=max_nesting_depth,
        max_grouping_depth=max_grouping_depth,
        max_grouping_calls=max_grouping_calls,
        max_token_length=max_token_length,
        timeout=timeout,
    )
    stack = engine.FilterStack(
        strip_semicolon=strip_semicolon, limits=resource_limits
    )
    return [str(stmt).strip() for stmt in stack.run(sql, encoding)]
