"""Streaming SQL lexing and statement parsing."""

import re
from collections.abc import Iterable, Iterator

from sqlparse import lexer, sql
from sqlparse import tokens as T
from sqlparse.engine import grouping
from sqlparse.engine.statement_splitter import StatementSplitter
from sqlparse.exceptions import SQLParseError
from sqlparse.filters import StripTrailingSemicolonFilter

NORMAL = 0
QUOTE = 1
BRACKET = 2
LINE_COMMENT = 3
BLOCK_COMMENT = 4
DOLLAR = 5

_WORD_RE = re.compile(r"[\w$#]+", re.UNICODE)
_DOLLAR_OPENER_RE = re.compile(
    r"(?<![\w\"$])\$(?:[_A-Za-zÀ-Üà-ü]\w*)?\$", re.UNICODE
)
_COMMENT_HINT_RE = re.compile(r"/\*\+")
_COMMENT_OPEN_RE = re.compile(r"/\*")
_DOLLAR_PENDING_RE = re.compile(
    r"(?<![\w\"$])\$(?:[_A-Za-zÀ-Üà-ü]\w*)?\$", re.UNICODE
)


def _check_limit(value, limit, description):
    if limit is not None and len(value) > limit:
        raise SQLParseError(
            f"Maximum {description} size exceeded ({limit})."
        )


def _positive_limit(value, name):
    if value is not None and (not isinstance(value, int) or value <= 0):
        raise ValueError(f"{name} must be a positive integer")
    return value


class StreamingLexer:
    """Tokenize an iterator of text chunks without concatenating them."""

    def __init__(self, max_token_size=None):
        self.max_token_size = _positive_limit(
            max_token_size, "max_token_size"
        )
        self.state = NORMAL
        self.buffer = ""
        self.delimiter = ""
        self.ttype = None
        self.dollar_tag = ""
        self.quote_closed = False
        self.escape_pending = False
        self.pending = ""
        self.pending_is_line_comment = False

    def _set_pending(self, value):
        _check_limit(value, self.max_token_size, "unfinished token")
        self.pending = value
        self.pending_is_line_comment = False

    def _complete_delimited(self, rest):
        value = self.buffer
        ttype = self.ttype
        self.state = NORMAL
        self.buffer = ""
        self.delimiter = ""
        self.ttype = None
        self.quote_closed = False
        self.escape_pending = False
        self.dollar_tag = ""
        return ttype, value, rest

    @staticmethod
    def _token_at(tokens, pos):
        offset = 0
        for ttype, value in tokens:
            if offset <= pos < offset + len(value):
                return ttype, value, offset
            offset += len(value)
        return None

    @staticmethod
    def _first_error_quote(tokens):
        offset = 0
        for ttype, value in tokens:
            if ttype is T.Error and len(value) == 1 and value in (
                "'", '"', "`", "´"
            ):
                return offset, value
            offset += len(value)
        return None

    @staticmethod
    def _open_line_comment(tokens):
        offset = 0
        for ttype, value in tokens:
            if ttype in (T.Comment.Single, T.Comment.Single.Hint):
                if not value.endswith(("\n", "\r")):
                    return offset, len(value), ttype
                return None
            offset += len(value)
        return None

    def _find_opener(self, text):
        tokens = list(lexer.tokenize(text))
        quote = self._first_error_quote(tokens)
        if quote is not None:
            quote_pos, delimiter = quote
            ttype = {
                "'": T.String.Single,
                '"': T.String.Symbol,
                "`": T.Name,
                "´": T.Name,
            }[delimiter]
            return quote_pos, QUOTE, ttype, delimiter

        line_comment = self._open_line_comment(tokens)
        if line_comment is not None:
            comment_pos, comment_end, comment_ttype = line_comment
            return comment_pos, LINE_COMMENT, comment_ttype, text[
                comment_pos:comment_end
            ]

        candidates = []
        for match in _DOLLAR_OPENER_RE.finditer(text):
            token = self._token_at(tokens, match.start())
            following = self._token_at(tokens, match.end() - 1)
            if token is None or (
                len(match.group()) == 2
                and token[0] is T.Error
                and token[1] == "$"
                and self._token_at(tokens, match.start() + 1) is not None
            ) or (
                token is not None
                and token[0] is T.Name.Placeholder
                and token[1] == match.group()[:-1]
                and following is not None
                and following[0] is T.Error
                and following[1] == "$"
            ):
                candidates.append(
                    (match.start(), DOLLAR, T.Literal, match.group())
                )
        hint_positions = {m.start() for m in _COMMENT_HINT_RE.finditer(text)}
        for match in _COMMENT_OPEN_RE.finditer(text):
            slash = self._token_at(tokens, match.start())
            star = self._token_at(tokens, match.start() + 1)
            if slash is None or star is None or (
                slash[0] is T.Operator and slash[1] == "/"
                and star[0] is T.Wildcard and star[1] == "*"
            ):
                ttype = (
                    T.Comment.Multiline.Hint
                    if match.start() in hint_positions
                    else T.Comment.Multiline
                )
                candidates.append((match.start(), BLOCK_COMMENT, ttype, "/*"))

        for match in re.finditer(r"\[", text):
            pos = match.start()
            if pos > 0 and re.match(r"[\w\])]", text[pos - 1]):
                continue
            end = text.find("]", pos + 1)
            if end == -1:
                candidates.append((pos, BRACKET, T.Name, "["))

        if not candidates:
            return None
        return min(candidates, key=lambda item: item[0])

    @staticmethod
    def _trailing_raw(tokens):
        if not tokens:
            return None
        ttype, value = tokens[-1]
        if ttype in (T.Comment.Single, T.Comment.Single.Hint):
            return value, True
        if ttype is T.Error and value == "$":
            return value, False
        if ttype in (T.Name, T.Keyword, T.Keyword.DML, T.Keyword.DDL,
                     T.Number, T.Number.Float, T.Number.Integer,
                     T.Name.Placeholder) and len(value) <= 64:
            return value, False
        if ttype in (T.Operator, T.Punctuation) and len(value) == 1 and (
            value in "-/:#"
        ):
            return value, False
        if len(tokens) >= 2:
            previous_ttype, previous_value = tokens[-2]
            if (
                ttype is T.Whitespace
                and previous_ttype in T.Keyword
                and len(previous_value) + len(value) <= 64
            ):
                return previous_value + value, False
        return None

    def _flush_pending(self):
        pending = self.pending
        self.pending = ""
        if not pending:
            return
        yield from lexer.tokenize(pending)

    def _consume_normal(self, chunk):
        while chunk:
            text = self.pending + chunk
            if self.max_token_size is not None and len(text) > self.max_token_size:
                self._scan_large_normal(text)
            opener = self._find_opener(text)
            if opener is None:
                tokens = list(lexer.tokenize(text))
                pending_match = _DOLLAR_PENDING_RE.search(text)
                pending_token = (
                    self._token_at(tokens, pending_match.start())
                    if pending_match is not None
                    else None
                )
                if pending_match is not None and (
                    pending_token is None
                    or (
                        pending_token[0] in (T.Error, T.Name.Placeholder)
                        and pending_token[1] == "$"
                    )
                    or (
                        pending_token[0] is T.Name.Placeholder
                        and pending_match.start() == pending_token[2]
                        and pending_match.group().endswith("$")
                        and (
                            pending_match.group()[:-1] == pending_token[1]
                            or pending_token[1] == "$"
                        )
                    )
                ):
                    yield from lexer.tokenize(text[:pending_match.start()])
                    self._set_pending(pending_match.group())
                    return
                trailing = self._trailing_raw(tokens)
                if trailing is None:
                    self.pending = ""
                    yield from tokens
                    return
                trailing_value, is_comment = trailing
                prefix_len = len(text) - len(trailing_value)
                yield from lexer.tokenize(text[:prefix_len])
                self._set_pending(trailing_value)
                self.pending_is_line_comment = is_comment
                return

            pos, state, ttype, delimiter = opener
            prefix = text[:pos]
            if prefix:
                yield from lexer.tokenize(prefix)
            self._set_pending("")
            chunk = self._enter_state(text, pos, state, ttype, delimiter)

    def _scan_large_normal(self, text):
        if not self.pending:
            return
        limit = self.max_token_size
        pos = 0
        while pos < len(text):
            char = text[pos]
            if re.match(r"[\w$#]", char):
                pos += 1
                continue
            if char.isspace():
                pos += 1
                continue
            if char in "'\"`´":
                quote_pos = pos + 1
                closed = False
                while quote_pos < len(text):
                    found = text.find(char, quote_pos)
                    if found == -1:
                        self._raise_token_limit(limit)
                    quote_pos = found + 1
                    run = 1
                    while quote_pos < len(text) and text[quote_pos] == char:
                        run += 1
                        quote_pos += 1
                    if quote_pos >= len(text) and run % 2 == 0:
                        self._raise_token_limit(limit)
                    if run % 2 == 1:
                        closed = True
                        pos = quote_pos - 1
                        break
                if closed:
                    pos += 1
                    continue
            if char == "[":
                if pos > 0 and not re.match(r"[\w\])]", text[pos - 1]):
                    self._raise_token_limit(limit)
            if char == "/" and pos + 1 < len(text) and text[pos + 1] == "*":
                end = text.find("*/", pos + 2)
                if end == -1:
                    self._raise_token_limit(limit)
                pos = end + 1
                continue
            if char == "$" and _DOLLAR_OPENER_RE.match(text, pos):
                match = _DOLLAR_OPENER_RE.match(text, pos)
                end = text.find(match.group(), match.end())
                if end == -1:
                    self._raise_token_limit(limit)
                pos = end + len(match.group())
                continue
            pos += 1

    @staticmethod
    def _raise_token_limit(limit):
        raise SQLParseError(
            f"Maximum unfinished token size exceeded ({limit})."
        )

    def _enter_state(self, text, pos, state, ttype, delimiter):
        self.state = state
        self.buffer = ""
        self.delimiter = delimiter
        self.ttype = ttype
        self.quote_closed = False
        self.escape_pending = False
        self.dollar_tag = ""
        if state == DOLLAR:
            self.dollar_tag = delimiter
            self.buffer = delimiter
        else:
            self.buffer = delimiter
        end = pos + len(delimiter)
        return text[end:]

    def _consume_pending_normal(self, chunk):
        if not self.pending:
            return False, chunk

        if self.pending.endswith(" "):
            match = _WORD_RE.match(chunk)
            if match and len(self.pending) + len(match.group()) <= 64:
                self.pending += match.group()
                return True, chunk[match.end():]
            return False, chunk

        match = _WORD_RE.match(chunk)
        if match and self.pending not in ("-", "/", ":", "#") and (
            not self.pending.startswith("$")
            or _DOLLAR_PENDING_RE.fullmatch(self.pending) is not None
        ):
            candidate = self.pending + match.group()
            if not self.pending.startswith("$") or (
                _DOLLAR_PENDING_RE.fullmatch(candidate) is not None
            ):
                self.pending = candidate
                return True, chunk[match.end():]
        return False, chunk

    def _consume_quote(self, chunk):
        projected = len(self.buffer) + len(chunk)
        if self.max_token_size is not None and projected > self.max_token_size:
            raise SQLParseError(
                f"Maximum unfinished token size exceeded "
                f"({self.max_token_size})."
            )
        supports_backslash = self.delimiter in ("'", '"')
        pos = 0
        while pos < len(chunk):
            if self.quote_closed:
                if chunk[pos] != self.delimiter:
                    ttype, value, rest = self._complete_delimited(
                        chunk[pos:]
                    )
                    yield ttype, value
                    yield from self._consume_normal(rest)
                    return
                self.buffer += self.delimiter
                self.quote_closed = False
                pos += 1
                continue

            char = chunk[pos]
            if self.escape_pending:
                self.buffer += char
                self.escape_pending = False
                pos += 1
                continue

            if char == "\\" and supports_backslash:
                if pos == len(chunk) - 1:
                    self.buffer += char
                    self.escape_pending = True
                    return
                self.buffer += chunk[pos:pos + 2]
                pos += 2
                continue

            if char != self.delimiter:
                self.buffer += char
                pos += 1
                continue

            run = 1
            while pos + run < len(chunk) and chunk[pos + run] == self.delimiter:
                run += 1

            if pos + run == len(chunk):
                self.buffer += chunk[pos:]
                self.quote_closed = run % 2 == 1
                return

            self.buffer += chunk[pos:pos + run]
            pos += run
            if run % 2 == 1:
                ttype, value, rest = self._complete_delimited(
                    chunk[pos + run:]
                )
                yield ttype, value
                yield from self._consume_normal(rest)
                return

            self.buffer += chunk[pos:pos + run]
            pos += run

    def _consume_bracket(self, chunk):
        pos = chunk.find("]")
        if self.max_token_size is not None and (
            len(self.buffer) + len(chunk[:pos]) > self.max_token_size
            if pos != -1
            else len(self.buffer) + len(chunk) > self.max_token_size
        ):
            raise SQLParseError(
                f"Maximum unfinished token size exceeded "
                f"({self.max_token_size})."
            )
        if pos == -1:
            self.buffer += chunk
            _check_limit(self.buffer, self.max_token_size, "unfinished token")
            return
        self.buffer += chunk[:pos + 1]
        rest = chunk[pos + 1:]
        ttype, value, rest = self._complete_delimited(rest)
        yield ttype, value
        yield from self._consume_normal(rest)

    def _consume_line_comment(self, chunk):
        for newline in ("\r\n", "\r", "\n"):
            pos = chunk.find(newline)
            if pos != -1:
                if self.max_token_size is not None and (
                    len(self.buffer) + pos > self.max_token_size
                ):
                    raise SQLParseError(
                        f"Maximum unfinished token size exceeded "
                        f"({self.max_token_size})."
                    )
                end = pos + len(newline)
                value = self.buffer + chunk[:pos]
                ttype = self.ttype
                self._complete_delimited(chunk[end:])
                yield ttype, value
                yield T.Newline, newline
                yield from self._consume_normal(chunk[end:])
                return
        if self.max_token_size is not None and (
            len(self.buffer) + len(chunk) > self.max_token_size
        ):
            raise SQLParseError(
                f"Maximum unfinished token size exceeded "
                f"({self.max_token_size})."
            )
        if chunk.endswith("\r"):
            self.buffer += chunk[:-1]
        else:
            self.buffer += chunk

    def _consume_block_comment(self, chunk):
        if self.buffer == "/*" and chunk.startswith("+"):
            self.ttype = T.Comment.Multiline.Hint
        carry = self.buffer[-1:] if self.buffer else ""
        searchable = carry + chunk
        pos = searchable.find("*/")
        close_at = None if pos == -1 else pos + 2 - len(carry)
        if self.max_token_size is not None and (
            len(self.buffer) + len(chunk if close_at is None else chunk[:close_at])
            > self.max_token_size
        ):
            raise SQLParseError(
                f"Maximum unfinished token size exceeded "
                f"({self.max_token_size})."
            )
        if close_at is None:
            self.buffer += chunk
            _check_limit(self.buffer, self.max_token_size, "unfinished token")
            return
        consumed = close_at
        value = self.buffer + chunk[:consumed]
        rest = chunk[consumed:]
        ttype = self.ttype
        self.state = NORMAL
        self.buffer = ""
        self.delimiter = ""
        self.ttype = None
        yield ttype, value
        yield from self._consume_normal(rest)

    def _consume_dollar(self, chunk):
        body = self.buffer[len(self.dollar_tag):]
        carry = body[-(len(self.dollar_tag) - 1):]
        searchable = carry + chunk
        pos = searchable.find(self.dollar_tag)
        close_at = None if pos == -1 else pos + len(self.dollar_tag) - len(carry)
        if self.max_token_size is not None and (
            len(self.buffer) + len(
                chunk if close_at is None else chunk[:close_at]
            ) > self.max_token_size
        ):
            raise SQLParseError(
                f"Maximum unfinished token size exceeded "
                f"({self.max_token_size})."
            )
        if close_at is None:
            self.buffer += chunk
            _check_limit(self.buffer, self.max_token_size, "unfinished token")
            return
        consumed = close_at
        value = self.buffer + chunk[:consumed]
        rest = chunk[consumed:]
        ttype = self.ttype
        self.state = NORMAL
        self.buffer = ""
        self.delimiter = ""
        self.dollar_tag = ""
        self.ttype = None
        yield ttype, value
        yield from self._consume_normal(rest)

    def feed(self, chunk):
        if not chunk:
            return
        if not isinstance(chunk, str):
            raise TypeError("chunks must be strings")

        if self.state == NORMAL:
            if self.pending.startswith("$") and chunk:
                yield from self._consume_normal(chunk)
                return
            if self.pending == "#" and not chunk.startswith((" ", "+")):
                yield from self._flush_pending()
                yield from self._consume_normal(chunk)
                return
            if self.pending_is_line_comment:
                text = self.pending + chunk
                comment_ttype = next(lexer.tokenize(self.pending))[0]
                self.pending = ""
                self.pending_is_line_comment = False
                self._enter_state(
                    text, 0, LINE_COMMENT, comment_ttype, text
                )
                return
            consumed, chunk = self._consume_pending_normal(chunk)
            if consumed:
                _check_limit(
                    self.pending, self.max_token_size, "unfinished token"
                )
            if not consumed and self.pending:
                if len(self.pending) == 1 and chunk and (
                    self.pending + chunk[0] in (
                        "--", "/*", "::", ":=", "# ", "#+"
                    )
                ):
                    pending = self.pending + chunk[0]
                    self.pending = ""
                    yield from self._consume_normal(pending + chunk[1:])
                    return
                if self.pending in ("--", "/*", "::", ":="):
                    pending = self.pending
                    self.pending = ""
                    yield from self._consume_normal(pending + chunk)
                    return
                if len(self.pending) == 1 and chunk:
                    if self.pending + chunk[0] in ("--", "/*", "::", ":=", "# ", "#+"):
                        pending = self.pending + chunk[0]
                        self.pending = ""
                        yield from self._consume_normal(pending + chunk[1:])
                    else:
                        yield from self._flush_pending()
                        yield from self._consume_normal(chunk)
                    return
                yield from self._flush_pending()
            yield from self._consume_normal(chunk)
        elif self.state in (QUOTE, BRACKET, LINE_COMMENT, BLOCK_COMMENT, DOLLAR):
            before = len(self.buffer)
            if self.state == QUOTE:
                yield from self._consume_quote(chunk)
            elif self.state == BRACKET:
                yield from self._consume_bracket(chunk)
            elif self.state == LINE_COMMENT:
                yield from self._consume_line_comment(chunk)
            elif self.state == BLOCK_COMMENT:
                yield from self._consume_block_comment(chunk)
            else:
                yield from self._consume_dollar(chunk)
            if self.state != NORMAL and self.max_token_size is not None and (
                len(self.buffer) > self.max_token_size and before <= self.max_token_size
            ):
                raise SQLParseError(
                    f"Maximum unfinished token size exceeded "
                    f"({self.max_token_size})."
                )

    def finish(self, strict=True):
        if self.state == NORMAL:
            _check_limit(
                self.pending, self.max_token_size, "unfinished token"
            )
            yield from self._flush_pending()
            return
        if self.state == QUOTE:
            if self.quote_closed:
                yield self.ttype, self.buffer + self.delimiter
                self.state = NORMAL
                self.buffer = ""
                self.delimiter = ""
                self.ttype = None
                self.quote_closed = False
                return
            if strict:
                raise SQLParseError("Unterminated quoted string.")
            yield self.ttype, self.buffer
            return
        if strict:
            names = {
                BRACKET: "bracketed identifier",
                BLOCK_COMMENT: "multiline comment",
                DOLLAR: "dollar-quoted string",
            }
            if self.state in names:
                raise SQLParseError(f"Unterminated {names[self.state]}.")
        if self.max_token_size is not None and (
            len(self.buffer) > self.max_token_size
        ):
            raise SQLParseError(
                f"Maximum token size exceeded ({self.max_token_size})."
            )
        yield self.ttype, self.buffer


def parse_chunks(
    chunks: Iterable[str],
    *,
    max_token_size: int | None = None,
    max_statement_size: int | None = None,
    strict_unclosed: bool = True,
    strip_semicolon: bool = False,
) -> Iterator[sql.Statement]:
    """Parse an iterator of non-seekable SQL text chunks.

    Completed statements are grouped and yielded as soon as the splitter
    reaches the beginning of the following statement. Pending lexer and
    statement data are bounded independently of the number of chunks.
    """
    _positive_limit(max_token_size, "max_token_size")
    _positive_limit(max_statement_size, "max_statement_size")

    stream_lexer = StreamingLexer(max_token_size=max_token_size)
    splitter = StatementSplitter()
    strip_filter = (
        StripTrailingSemicolonFilter() if strip_semicolon else None
    )
    statement_size = 0

    def emit(statement):
        grouped = grouping.group(statement)
        if strip_filter is not None:
            strip_filter.process(grouped)
        return grouped

    for chunk in chunks:
        if not chunk:
            continue
        if not isinstance(chunk, str):
            raise TypeError("chunks must be strings")

        for ttype, value in stream_lexer.feed(chunk):
            completed = splitter.process_token(ttype, value)
            if completed is not None:
                statement_size = 0
                yield emit(completed)

            if (
                max_statement_size is not None
                and statement_size + len(value) > max_statement_size
            ):
                raise SQLParseError(
                    f"Maximum unfinished statement size exceeded "
                    f"({max_statement_size})."
                )
            statement_size += len(value)

    pending_tokens = list(stream_lexer.finish(strict=strict_unclosed))
    for ttype, value in pending_tokens:
        completed = splitter.process_token(ttype, value)
        if completed is not None:
            statement_size = 0
            yield emit(completed)
        if (
            max_statement_size is not None
            and statement_size + len(value) > max_statement_size
        ):
            raise SQLParseError(
                f"Maximum unfinished statement size exceeded "
                f"({max_statement_size})."
            )
        statement_size += len(value)

    completed = splitter.finish()
    if completed is not None:
        yield emit(completed)


def split_chunks(
    chunks: Iterable[str],
    *,
    max_token_size: int | None = None,
    max_statement_size: int | None = None,
    strict_unclosed: bool = True,
    strip_semicolon: bool = True,
) -> Iterator[str]:
    """Yield complete statements from non-seekable text chunks."""
    for statement in parse_chunks(
        chunks,
        max_token_size=max_token_size,
        max_statement_size=max_statement_size,
        strict_unclosed=strict_unclosed,
        strip_semicolon=strip_semicolon,
    ):
        yield str(statement).strip()
