#
# Copyright (C) 2009-2026 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Script-aware splitting that understands client-side batch commands.

Unlike :func:``sqlparse.split``, which only splits on
semicolons, this module implements an explicit *script mode* that honors
the batch commands used by interactive database clients:

* ``GO [count]`` on a line of its own (SQL Server: SSMS,
  sqlcmd, Azure Data Studio).
* ``DELIMITER <str>`` on a line of its own (MySQL /
  MariaDB client).

Both are client-side directives, not SQL.  They are stripped from the
returned batches and reported as metadata instead.
"""

import bisect
import dataclasses
import re

__all__ = ["ScriptBatch", "ScriptCommand", "ScriptResult", "split_script"]


@dataclasses.dataclass(frozen=True)
class ScriptCommand:
    """Metadata for a client-side batch command found in a script."""

    kind: str
    """The command kind: "go" or "delimiter"."""

    line: int
    """1-based line number of the command in the original script."""

    offset: int
    """0-based character offset of the command keyword."""

    end_offset: int
    """0-based character offset just past the end of the command line."""

    raw: str
    """The raw command line, without the trailing newline."""

    argument: "int | str | None"
    """Repeat count for GO (None if omitted) or the new delimiter
    for DELIMITER."""


@dataclasses.dataclass(frozen=True)
class ScriptBatch:
    """A single SQL batch plus its position in the original script."""

    sql: str
    """The batch text, stripped of surrounding whitespace."""

    offset: int
    """0-based character offset of the batch in the original script."""

    line: int
    """1-based line number where the batch starts."""

    def __str__(self):
        return self.sql


@dataclasses.dataclass(frozen=True)
class ScriptResult:
    """Result of :func:``split_script``."""

    batches: tuple
    """Tuple of :class:``ScriptBatch`` instances."""

    commands: tuple
    """Tuple of :class:``ScriptCommand`` instances."""

    def __iter__(self):
        return iter(self.batches)

    def __len__(self):
        return len(self.batches)


@dataclasses.dataclass(frozen=True)
class _Dialect:
    commands: str            # "go" or "delimiter"
    hash_comment: bool       # "#" starts a line comment
    backtick_quotes: bool    # backtick-quoted identifiers
    bracket_quotes: bool     # [...] quoted identifiers
    backslash_escapes: bool  # backslash escapes inside strings
    nested_comments: bool    # /* ... */ comments may nest
    dollar_quotes: bool      # $tag$ ... $tag$ quoting


_DIALECTS = {
    "tsql": _Dialect(
        commands="go", hash_comment=False, backtick_quotes=False,
        bracket_quotes=True, backslash_escapes=False,
        nested_comments=True, dollar_quotes=False),
    "mysql": _Dialect(
        commands="delimiter", hash_comment=True, backtick_quotes=True,
        bracket_quotes=False, backslash_escapes=True,
        nested_comments=False, dollar_quotes=True),
}

_DIALECT_ALIASES = {
    "tsql": "tsql",
    "mssql": "tsql",
    "sqlserver": "tsql",
    "mysql": "mysql",
    "mariadb": "mysql",
}

_GO_LINE_RE = re.compile(
    r"GO(?:[ \t]+(?P<arg>(?!--)\S+))?[ \t]*(?:--[^\n]*)?\Z",
    re.IGNORECASE,
)

_DOLLAR_OPEN_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")

_WORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _normalize_dialect(dialect):
    try:
        key = re.sub(r"[^a-z0-9]", "", dialect.lower())
    except AttributeError:
        raise ValueError(
            f"unknown dialect {dialect!r}; "
            f"expected one of: {', '.join(sorted(_DIALECT_ALIASES))}"
        )
    try:
        return _DIALECT_ALIASES[key]
    except KeyError:
        raise ValueError(
            f"unknown dialect {dialect!r}; "
            f"expected one of: {', '.join(sorted(_DIALECT_ALIASES))}"
        )


def _parse_go_line(content, line):
    """Parse a candidate GO line, return the repeat count or None."""
    match = _GO_LINE_RE.match(content)
    if match is None:
        raise ValueError(f"invalid GO command at line {line}: {content!r}")
    arg = match.group("arg")
    if arg is None:
        return None
    if not arg.isdigit() or int(arg) < 1:
        raise ValueError(
            f"invalid GO count {arg!r} at line {line}: "
            "expected a positive integer"
        )
    return int(arg)


def _parse_delimiter_line(content, line):
    """Parse a candidate DELIMITER line, return the new delimiter."""
    rest = content[len("DELIMITER"):].strip()
    if not rest:
        raise ValueError(
            f"invalid DELIMITER command at line {line}: "
            "missing delimiter argument"
        )
    return rest


def _scan_quoted(script, pos, quote, backslash_escapes):
    """Return the offset just past a quoted section starting at *pos*."""
    n = len(script)
    qlen = len(quote)
    j = pos + qlen
    while j < n:
        if backslash_escapes and script[j] == "\\":
            j += 2
            continue
        if script.startswith(quote, j):
            if script.startswith(quote, j + qlen):  # doubled quote = escape
                j += 2 * qlen
                continue
            return j + qlen
        j += 1
    return n  # unterminated: the rest of the script is quoted


def _scan_block_comment(script, pos, nested):
    """Return the offset just past a /* ... */ comment starting at *pos*."""
    n = len(script)
    depth = 1
    j = pos + 2
    while j < n and depth:
        close = script.find("*/", j)
        if close == -1:
            return n  # unterminated comment
        if nested:
            open_ = script.find("/*", j)
            if open_ != -1 and open_ < close:
                depth += 1
                j = open_ + 2
                continue
        depth -= 1
        j = close + 2
    return j


def split_script(script, dialect, keep_commands=False):
    """Split *script* into SQL batches using client batch commands.

    This is an explicit *script mode* splitter for operational scripts
    that contain client-side commands in addition to SQL:

    * With ``dialect="tsql"`` (aliases
      ``"mssql"``, ``"sqlserver"``)
      batches are separated by ``GO`` on a line of its
      own.  ``GO`` is matched case-insensitively and
      may be followed by a positive repeat count and/or a
      ``--`` comment.  The repeat count is returned
      as metadata only; batches are never duplicated.
    * With ``dialect="mysql"`` (alias
      ``"mariadb"``) batches are separated by the
      current delimiter, which starts as ``;`` and
      can be changed with a ``DELIMITER <str>``
      line.  The delimiter is only recognized outside strings,
      comments, quoted identifiers and dollar-quoted sections.  The
      ``DELIMITER`` directive itself is not part of
      the SQL body.

    Commands are only recognized at top level, as the first
    non-whitespace content of a line.  A command line with invalid
    arguments (e.g. ``GO abc`` or a bare
    ``DELIMITER``) raises :exc:``ValueError``.

    :param script: A string containing the script to split.
    :param dialect: The client dialect whose commands are honored.
    :param keep_commands: If True, command lines are kept verbatim at
        the end of the preceding batch (default: False, commands are
        stripped from the SQL body and only reported as metadata).
    :returns: A :class:``ScriptResult`` with the SQL
        batches and the command metadata (positions, raw text,
        arguments).
    """
    if not isinstance(script, str):
        raise TypeError(
            f"script must be a string, not {type(script).__name__}")
    dia = _DIALECTS[_normalize_dialect(dialect)]

    n = len(script)
    line_starts = [0]
    for match in re.finditer("\n", script):
        line_starts.append(match.end())

    def line_no(pos):
        return bisect.bisect_right(line_starts, pos)

    batches = []
    commands = []
    delimiter = ";"
    batch_start = 0
    line_blank = True  # only whitespace seen so far on the current line
    i = 0

    def flush(end):
        chunk = script[batch_start:end]
        stripped = chunk.strip()
        if stripped:
            offset = batch_start + (len(chunk) - len(chunk.lstrip()))
            batches.append(ScriptBatch(
                sql=stripped, offset=offset, line=line_no(offset)))

    while i < n:
        ch = script[i]

        if ch == "\n":
            line_blank = True
            i += 1
            continue

        # Client commands: first non-whitespace content of a line.
        if line_blank and ch in "gGdD":
            eol = script.find("\n", i)
            if eol == -1:
                eol = n
            content = script[i:eol]
            if content.endswith("\r"):
                content = content[:-1]
            argument = None
            if dia.commands == "go" and content[:2].upper() == "GO" \
                    and (len(content) == 2
                         or content[2] not in _WORD_CHARS):
                argument = _parse_go_line(content, line_no(i))
                kind = "go"
            elif dia.commands == "delimiter" \
                    and content[:9].upper() == "DELIMITER" \
                    and (len(content) == 9
                         or content[9] not in _WORD_CHARS):
                argument = _parse_delimiter_line(content, line_no(i))
                kind = "delimiter"
            else:
                kind = None
            if kind is not None:
                line_start = script.rfind("\n", 0, i) + 1
                next_line = eol + 1 if eol < n else n
                flush(next_line if keep_commands else line_start)
                commands.append(ScriptCommand(
                    kind=kind, line=line_no(i), offset=i,
                    end_offset=i + len(content), raw=content,
                    argument=argument))
                if kind == "delimiter":
                    delimiter = argument
                i = next_line
                batch_start = i
                line_blank = True
                continue

        # The current delimiter (MySQL mode) ends a batch.  It is
        # checked before quoting structures, so a delimiter that looks
        # like a quote opener (e.g. $$) still splits.
        if dia.commands == "delimiter" and script.startswith(delimiter, i):
            flush(i)
            i += len(delimiter)
            batch_start = i
            line_blank = False
            continue

        if ch == "-" and script.startswith("--", i):
            line_blank = False
            eol = script.find("\n", i)
            i = n if eol == -1 else eol
            continue

        if dia.hash_comment and ch == "#":
            line_blank = False
            eol = script.find("\n", i)
            i = n if eol == -1 else eol
            continue

        if ch == "/" and script.startswith("/*", i):
            line_blank = False
            i = _scan_block_comment(script, i, dia.nested_comments)
            continue

        if ch == "'" or ch == '"':
            line_blank = False
            i = _scan_quoted(script, i, ch, dia.backslash_escapes)
            continue

        if dia.backtick_quotes and ch == "\x60":
            line_blank = False
            i = _scan_quoted(script, i, "\x60", dia.backslash_escapes)
            continue

        if dia.bracket_quotes and ch == "[":
            line_blank = False
            i = _scan_quoted(script, i, "]", False)
            continue

        if dia.dollar_quotes and ch == "$":
            match = _DOLLAR_OPEN_RE.match(script, i)
            if match is not None:
                line_blank = False
                tag = match.group(0)
                close = script.find(tag, match.end())
                i = n if close == -1 else close + len(tag)
                continue

        if ch not in " \t\r\f\v":
            line_blank = False
        i += 1

    flush(n)

    return ScriptResult(batches=tuple(batches), commands=tuple(commands))
