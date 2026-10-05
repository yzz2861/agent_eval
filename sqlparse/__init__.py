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
from sqlparse.engine import streaming

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


def parse_chunks(
    chunks: Iterable[str],
    *,
    max_token_size: int | None = None,
    max_statement_size: int | None = None,
    strict_unclosed: bool = True,
    strip_semicolon: bool = False,
) -> Generator[sql.Statement, None, None]:
    """Parse complete statements from an iterable of text chunks.

    Chunks are consumed in order and must not be seekable or replayable.
    Quotes, dollar-quoted strings, comments and identifiers may span chunk
    boundaries. Unfinished input is reported as an error when
    *strict_unclosed* is true. The two size limits bound pending token and
    statement buffers.
    """
    return streaming.parse_chunks(
        chunks,
        max_token_size=max_token_size,
        max_statement_size=max_statement_size,
        strict_unclosed=strict_unclosed,
        strip_semicolon=strip_semicolon,
    )


def split_chunks(
    chunks: Iterable[str],
    *,
    max_token_size: int | None = None,
    max_statement_size: int | None = None,
    strict_unclosed: bool = True,
    strip_semicolon: bool = True,
) -> Generator[str, None, None]:
    """Yield complete statement strings from an iterable of text chunks."""
    return streaming.split_chunks(
        chunks,
        max_token_size=max_token_size,
        max_statement_size=max_statement_size,
        strict_unclosed=strict_unclosed,
        strip_semicolon=strip_semicolon,
    )


parsestream_chunks = parse_chunks


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
