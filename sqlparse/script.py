#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Explicit script mode for splitting SQL deployment scripts.

Operations and migration scripts routinely mix SQL with client-side
commands of the database tooling: SQL Server scripts use lines containing
GO (optionally with a repeat count) to separate batches, and MySQL
scripts use DELIMITER directives to redefine the statement terminator
around stored procedure bodies.  Naively cutting such scripts at every
semicolon breaks procedure bodies apart.

:func:`split_script` is an opt-in alternative to
:func:`sqlparse.split` that understands these commands for a chosen
dialect and reports them as metadata instead of returning them as SQL.
"""

import re
from dataclasses import dataclass

__all__ = [
    "ScriptBatch",
    "ScriptCommand",
    "ScriptError",
    "ScriptResult",
    "split_script",
]

_MSSQL_NAMES = frozenset(("mssql", "tsql", "sqlserver"))
_MYSQL_NAMES = frozenset(("mysql", "mariadb"))

# A GO command is a line containing nothing but the word GO, an optional
# repeat count and an optional trailing line comment (sqlcmd syntax).
_GO_LINE = re.compile(
    r"[ \t]*GO(?:[ \t]+([0-9]+))?[ \t]*(?:--[^\n]*)?$", re.IGNORECASE)
# Lines starting with the word GO that are not valid commands are
# reported as errors instead of being silently sent to the server.
_GO_PREFIX = re.compile(r"[ \t]*GO(?![\w$#])", re.IGNORECASE)

# A DELIMITER command is a line containing the word DELIMITER followed by
# a single delimiter token and an optional trailing line comment.
_DELIMITER_LINE = re.compile(
    r"[ \t]*DELIMITER[ \t]+(\S+)[ \t]*(?:(?:--|\#)[^\n]*)?$",
    re.IGNORECASE)
_DELIMITER_PREFIX = re.compile(r"[ \t]*DELIMITER(?![\w$#])", re.IGNORECASE)

# Same shapes as the dollar-quote patterns used by the lexer.
_DOLLAR_QUOTE = re.compile(
    r"\$(?:[_A-ZÀ-Ü]\w*)?\$", re.IGNORECASE | re.UNICODE)
_DOLLAR_QUOTE_OPENER_OK = re.compile(r'(?<![\w"$])', re.UNICODE)


@dataclass
class ScriptBatch:
    """A single executable batch of SQL from a script.

    `start` and `end` are the offsets of `sql` within the original
    script text.  `terminator` is the separator that ended the batch:
    "GO" for SQL Server scripts, the active delimiter for MySQL
    scripts, or None when the script ended without a terminator.
    """

    sql: str
    start: int
    end: int
    terminator: str | None


@dataclass
class ScriptCommand:
    """A client-side separator command found in a script.

    `kind` is "go" or "delimiter".  `start` and `end` are
    the offsets of the command line (without the trailing newline) within
    the original script text, `line` is its 1-based line number and
    `raw` is the command line itself, stripped of surrounding
    whitespace.  `repeat` holds the repeat count of a GO command
    (1 when omitted); it is metadata only and never executed.
    `delimiter` holds the new delimiter of a DELIMITER command.
    """

    kind: str
    start: int
    end: int
    line: int
    raw: str
    repeat: int | None = None
    delimiter: str | None = None


@dataclass
class ScriptError:
    """A malformed separator command found in a script.

    The offending line is treated as regular SQL text.
    """

    message: str
    start: int
    line: int


@dataclass
class ScriptResult:
    """The outcome of :func:`split_script`.

    `batches` are the executable SQL batches in source order,
    `commands` the separator commands that were consumed and `errors`
    the malformed directives that were left in the SQL text.  Iterating
    over the result iterates over the batches.
    """

    dialect: str
    batches: list[ScriptBatch]
    commands: list[ScriptCommand]
    errors: list[ScriptError]

    def __iter__(self):
        return iter(self.batches)

    def __len__(self):
        return len(self.batches)


class _ScriptScanner:
    """Character-level scanner that splits a script into batches.

    The scanner tracks strings, comments and quoted identifiers itself so
    that separators are only recognized outside of them; directives are
    only recognized at the start of a logical line in normal state.
    """

    def __init__(self, text, dialect):
        self.text = text
        self.is_mysql = dialect == "mysql"
        self.delimiter = ";" if self.is_mysql else None
        self.batches = []
        self.commands = []
        self.errors = []
        self.batch_start = 0
        self.pos = 0
        self.line = 1

    def scan(self):
        text = self.text
        n = len(text)
        at_line_start = True
        while self.pos < n:
            if at_line_start:
                at_line_start = False
                if self._check_directive():
                    at_line_start = True
                    continue
            ch = text[self.pos]
            nxt = text[self.pos + 1] if self.pos + 1 < n else ""
            if ch == "\n":
                self.line += 1
                at_line_start = True
                self.pos += 1
            elif self.is_mysql and text.startswith(self.delimiter, self.pos):
                self._emit(self.pos, self.delimiter)
                self.pos += len(self.delimiter)
                self.batch_start = self.pos
            elif (ch == "-" and nxt == "-") or (self.is_mysql and ch == "#"):
                self._skip_line_comment()
            elif ch == "/" and nxt == "*":
                self._skip_block_comment()
            elif ch == "'":
                self._skip_quoted("'", backslash=self.is_mysql)
            elif ch == '"':
                self._skip_quoted('"', backslash=self.is_mysql)
            elif self.is_mysql and ch == '`':
                self._skip_quoted('`', backslash=False)
            elif not self.is_mysql and ch == "[":
                self._skip_bracketed()
            elif ch == "$" and self._skip_dollar_quoted():
                pass
            else:
                self.pos += 1
        self._emit(n, None)
        return self

    def _emit(self, end, terminator):
        raw = self.text[self.batch_start:end]
        stripped = raw.strip()
        if stripped:
            offset = len(raw) - len(raw.lstrip())
            self.batches.append(ScriptBatch(
                sql=stripped,
                start=self.batch_start + offset,
                end=self.batch_start + offset + len(stripped),
                terminator=terminator,
            ))

    def _check_directive(self):
        """Consume a separator command at the current line start.

        Returns True when the line was a valid command and has been
        consumed.  Malformed commands are recorded as errors and the line
        is left to be scanned as regular SQL text.
        """
        text = self.text
        line_end = text.find("\n", self.pos)
        if line_end == -1:
            line_end = len(text)
        line_text = text[self.pos:line_end]
        if line_text.endswith("\r"):
            line_text = line_text[:-1]
        start = self.pos + (len(line_text) - len(line_text.lstrip(" \t")))
        if self.is_mysql:
            pattern, prefix, kind = (
                _DELIMITER_LINE, _DELIMITER_PREFIX, "delimiter")
        else:
            pattern, prefix, kind = _GO_LINE, _GO_PREFIX, "go"
        m = pattern.match(line_text)
        if m is None:
            if prefix.match(line_text):
                expected = ("DELIMITER <delimiter>" if self.is_mysql
                            else "GO [<count>]")
                self.errors.append(ScriptError(
                    f"invalid {kind.upper()} command, "
                    f"expected '{expected}'", start, self.line))
            return False
        argument = m.group(1)
        if self.is_mysql:
            if "\\" in argument:
                self.errors.append(ScriptError(
                    "delimiter must not contain a backslash",
                    start, self.line))
                return False
            self._emit(self.pos, self.delimiter)
            self.commands.append(ScriptCommand(
                kind="delimiter", start=start, end=self.pos + len(line_text),
                line=self.line, raw=line_text.strip(), delimiter=argument))
            self.delimiter = argument
        else:
            repeat = int(argument) if argument else 1
            if repeat < 1:
                self.errors.append(ScriptError(
                    "GO repeat count must be a positive integer",
                    start, self.line))
                return False
            self._emit(self.pos, "GO")
            self.commands.append(ScriptCommand(
                kind="go", start=start, end=self.pos + len(line_text),
                line=self.line, raw=line_text.strip(), repeat=repeat))
        # The newline after a command belongs to the command, not to the
        # following batch.
        if line_end < len(text):
            self.pos = line_end + 1
            self.line += 1
        else:
            self.pos = len(text)
        self.batch_start = self.pos
        return True

    def _skip_line_comment(self):
        nl = self.text.find("\n", self.pos)
        self.pos = len(self.text) if nl == -1 else nl

    def _skip_block_comment(self):
        end = self.text.find("*/", self.pos + 2)
        end = len(self.text) if end == -1 else end + 2
        self.line += self.text.count("\n", self.pos, end)
        self.pos = end

    def _skip_quoted(self, quote, backslash):
        text = self.text
        n = len(text)
        pos = self.pos + 1
        while pos < n:
            ch = text[pos]
            if backslash and ch == "\\":
                pos += 2
                continue
            if ch == quote:
                if pos + 1 < n and text[pos + 1] == quote:
                    pos += 2
                    continue
                pos += 1
                break
            pos += 1
        self.line += text.count("\n", self.pos, pos)
        self.pos = pos

    def _skip_bracketed(self):
        text = self.text
        n = len(text)
        pos = self.pos + 1
        while pos < n:
            if text[pos] == "]":
                if pos + 1 < n and text[pos + 1] == "]":
                    pos += 2
                    continue
                pos += 1
                break
            pos += 1
        self.line += text.count("\n", self.pos, pos)
        self.pos = pos

    def _skip_dollar_quoted(self):
        m = _DOLLAR_QUOTE.match(self.text, self.pos)
        if m is None or _DOLLAR_QUOTE_OPENER_OK.match(self.text, self.pos) \
                is None:
            return False
        tag = m.group(0)
        closer = self.text.find(tag, m.end())
        if closer == -1:
            return False
        end = closer + len(tag)
        self.line += self.text.count("\n", self.pos, end)
        self.pos = end
        return True


def split_script(sql, dialect, encoding=None):
    """Split *sql* into batches, honoring client-side script commands.

    This is an explicit script mode: unlike :func:`sqlparse.split`,
    which only splits at statement boundaries and is left unchanged, this
    function interprets the separator commands of the chosen *dialect*:

    * "mssql" (aliases "tsql", "sqlserver"): batches are
      separated by lines containing GO (case-insensitive, optional
      repeat count and trailing `--` comment).  The repeat count is
      reported as :attr:`ScriptCommand.repeat` metadata only and is
      never executed.  Semicolons stay inside the batch text.
    * "mysql" (alias "mariadb"): batches are separated by the
      active delimiter, initially ";" and redefined by DELIMITER
      directives.  The new delimiter is only recognized outside of
      strings, comments, quoted identifiers and dollar-quoted literals.

    Separator commands are never part of the returned SQL: GO lines
    and DELIMITER directives are consumed and reported in
    :attr:`ScriptResult.commands`, and terminators are excluded from
    :attr:`ScriptBatch.sql`.  Unlike :func:`sqlparse.split` there are
    no output options such as `strip_semicolon`; this behavior is
    fixed.  Malformed commands (e.g. GO 0, GO abc, DELIMITER without
    an argument) are reported in :attr:`ScriptResult.errors` and
    treated as regular SQL text.

    :param sql: A string (or bytes, see *encoding*) containing the script.
    :param dialect: The dialect whose client commands are recognized.
    :param encoding: The encoding of *sql* when given as bytes (optional).
    :returns: A :class:`ScriptResult` instance.
    """
    normalized = dialect.lower()
    if normalized in _MSSQL_NAMES:
        normalized = "mssql"
    elif normalized in _MYSQL_NAMES:
        normalized = "mysql"
    else:
        raise ValueError(
            f"unsupported dialect {dialect!r}, "
            f"expected one of {sorted(_MSSQL_NAMES | _MYSQL_NAMES)}")
    if isinstance(sql, bytes):
        sql = sql.decode(encoding) if encoding else sql.decode("utf-8")
    elif not isinstance(sql, str):
        raise TypeError(f"Expected str or bytes, got {type(sql)!r}")
    scanner = _ScriptScanner(sql, normalized).scan()
    return ScriptResult(
        dialect=normalized,
        batches=scanner.batches,
        commands=scanner.commands,
        errors=scanner.errors,
    )
