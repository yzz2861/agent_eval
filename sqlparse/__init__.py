#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Parse SQL statements."""

# Setup namespace
from collections.abc import Generator, Iterable
from typing import IO, Any

from sqlparse import cli, engine, filters, formatter, sql, tokens

__version__ = "0.6.1.dev0"
__all__ = ["cli", "engine", "filters", "formatter", "sql", "tokens"]


def parse(
    sql: str, encoding: str | None = None
) -> tuple[sql.Statement, ...]:
    """Parse sql and return a list of statements.

    :param sql: A string containing one or more SQL statements.
    :param encoding: The encoding of the statement (optional).
    :returns: A tuple of :class:`~sqlparse.sql.Statement` instances.
    """
    return tuple(parsestream(sql, encoding))


def parsestream(
    stream: str | IO[str], encoding: str | None = None
) -> Generator[sql.Statement, None, None]:
    """Parses sql statements from file-like object.

    :param stream: A file-like object.
    :param encoding: The encoding of the stream contents (optional).
    :returns: A generator of :class:`~sqlparse.sql.Statement` instances.
    """
    stack = engine.FilterStack()
    stack.enable_grouping()
    return stack.run(stream, encoding)


def parsechunks(
    chunks: Iterable[str],
    max_token_size: int | None = None,
    max_statement_size: int | None = None,
) -> Generator[sql.Statement, None, None]:
    """Parse SQL statements from an iterable of text chunks.

    This is a streaming variant of :func:`parse` for producers that
    yield the input in arbitrary pieces, e.g. an import tool reading
    from a non-seekable source.  Chunks are consumed lazily and at
    most once; empty chunks are skipped.  Unterminated tokens such as
    quoted strings, dollar-quoted literals, comments or identifiers
    may span arbitrary chunk boundaries; a chunk boundary is never
    mistaken for the end of the input.  A statement is yielded as soon
    as it is complete, without reading the remaining input first.

    When the input ends inside an unterminated quoted string,
    dollar-quoted literal or multiline comment,
    :class:`~sqlparse.exceptions.UnclosedTokenError` is raised.

    :param chunks: An iterable of text chunks.
    :param max_token_size: Maximum size (in characters) of the
        buffered input that cannot be tokenized yet.  When the buffer
        exceeds the limit,
        :class:`~sqlparse.exceptions.StreamLimitExceededError` is
        raised instead of accumulating more input without bounds.
    :param max_statement_size: Maximum size (in characters) of a
        single not yet completed statement.  When a statement exceeds
        the limit,
        :class:`~sqlparse.exceptions.StreamLimitExceededError` is
        raised.
    :returns: A generator of :class:`~sqlparse.sql.Statement`
        instances.
    """
    return engine.streaming.iter_statements(
        chunks, max_token_size, max_statement_size)


def format(sql: str, encoding: str | None = None, **options: Any) -> str:
    """Format *sql* according to *options*.

    Available options are documented in :ref:`formatting`.

    In addition to the formatting options this function accepts the
    keyword "encoding" which determines the encoding of the statement.

    :returns: The formatted SQL statement as string.
    """
    stack = engine.FilterStack()
    options = formatter.validate_options(options)
    stack = formatter.build_filter_stack(stack, options)
    stack.postprocess.append(filters.SerializerUnicode())
    return "".join(stack.run(sql, encoding))


def split(
    sql: str, encoding: str | None = None, strip_semicolon: bool = False
) -> list[str]:
    """Split *sql* into single statements.

    :param sql: A string containing one or more SQL statements.
    :param encoding: The encoding of the statement (optional).
    :param strip_semicolon: If True, remove trailing semicolons
        (default: False).
    :returns: A list of strings.
    """
    stack = engine.FilterStack(strip_semicolon=strip_semicolon)
    return [str(stmt).strip() for stmt in stack.run(sql, encoding)]
