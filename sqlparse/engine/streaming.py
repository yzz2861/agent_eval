#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Streaming tokenization and statement parsing of chunked SQL input."""

import re
from collections.abc import Generator, Iterable

from sqlparse import keywords, tokens
from sqlparse.engine import grouping
from sqlparse.engine.statement_splitter import StatementSplitter
from sqlparse.exceptions import (
    SQLParseError,
    StreamLimitExceededError,
    UnclosedTokenError,
)
from sqlparse.lexer import Lexer

# Characters that open a string-like token.  Inside such a token a
# doubled quote is an escaped quote; single and double quotes
# additionally treat a backslash-escaped quote as content.  This
# mirrors the string patterns in keywords.SQL_REGEX.
_QUOTES = frozenset('\'"`\u00b4')
_BACKSLASH_ESCAPED_QUOTES = frozenset('\'"')

# A dollar-quoted literal opener (``$tag$``) that is still missing its
# closing ``$``; used to detect openers split across chunk boundaries.
_DOLLAR_OPENER_PREFIX = re.compile(
    r'\$(?:[_A-Z\u00c0-\u00dc]\w*)?\Z', re.IGNORECASE | re.UNICODE)

# A Python-style ``%(name)s`` placeholder that is still incomplete.
_PLACEHOLDER_PREFIX = re.compile(r'%\(\w*\)?\Z', re.UNICODE)

# A number (hexadecimal, scientific notation, ``-.5``) whose digits
# have not arrived yet.
_NUMBER_PREFIX = re.compile(
    r'-?(?:\d+(?:\.\d*)?|\.\d+)[eE]-?\Z'
    r'|-0[xX]?\Z'
    r'|-\.\Z',
    re.UNICODE)

# A name introduced by ``@`` or ``#`` (``@name``, ``##name``, ``#name``)
# that is still incomplete; the pattern in keywords.SQL_REGEX requires
# at least two word characters.
_AT_NAME_PREFIX = re.compile(
    r'(?:##|@|#)[A-Z\u00c0-\u00dc]?\Z', re.IGNORECASE | re.UNICODE)

# A keyword pattern containing a string literal (``AT TIME ZONE``)
# that is still incomplete.
_TZCAST_PREFIX = re.compile(
    r"(AT|WITH')\s+TIME\s+ZONE\s+'[^']*\Z",
    re.IGNORECASE | re.UNICODE)

# Mirrors the look-behind of the square bracket name pattern in
# keywords.SQL_REGEX.
_BRACKET_OPENER_OK = re.compile(r'(?<![\w\])])', re.UNICODE)

# Characters that can never be part of a word or whitespace; a word
# token followed only by word/whitespace characters may still merge
# with following input (multi-word keywords such as "GROUP BY").
_SPECIAL = re.compile(r'[^\w\s]', re.UNICODE)


def _last_special(ctx):
    """Return the last index of a non-word, non-whitespace character."""
    return max((m.start() for m in _SPECIAL.finditer(ctx)), default=-1)


def _next_non_ws(ctx):
    """Return for each position the index of the next non-whitespace
    character at or after it (len(ctx) if there is none)."""
    result = [0] * (len(ctx) + 1)
    nxt = len(ctx)
    for i in range(len(ctx) - 1, -1, -1):
        if not ctx[i].isspace():
            nxt = i
        result[i] = nxt
    return result


class IncrementalTokenizer:
    """Tokenizes SQL text that arrives in arbitrary chunks.

    Chunks are supplied via :meth:`feed`; the method returns the tokens
    that are known to be complete.  Tokens that may still grow with the
    next chunk (unfinished quotes, dollar-quoted literals, comments,
    identifiers, numbers, ...) are held back, so a chunk boundary is
    never mistaken for the end of the input.  :meth:`finish` flushes
    the remaining tokens once the input is exhausted and raises
    :class:`~sqlparse.exceptions.UnclosedTokenError` if a quoted
    string, a dollar-quoted literal or a multiline comment was never
    closed.

    ``max_token_size`` optionally limits the size (in characters) of
    the buffered input that cannot be tokenized yet.  When the buffer
    grows beyond the limit,
    :class:`~sqlparse.exceptions.StreamLimitExceededError` is raised
    instead of accumulating more input without bounds.
    """

    def __init__(self, max_token_size: int | None = None):
        self.max_token_size = max_token_size
        self._lexer = Lexer.get_default_instance()
        # Input that was fed but could not be tokenized yet.
        self._pending = ''
        # The last character that was emitted.  It provides look-behind
        # context for patterns matched at the start of the pending
        # buffer; a blank acts as "beginning of input".
        self._prev_char = ' '
        # None or (kind, data, resume) describing the unterminated
        # construct (string, comment, ...) that starts at the
        # beginning of self._pending; resume is the buffer-relative
        # offset at which the search for its end continues.
        self._awaiting = None

    def feed(self, chunk: str) -> list:
        """Feed a chunk of text and return newly completed tokens."""
        if not isinstance(chunk, str):
            raise TypeError(f'Expected str chunks, got {type(chunk)!r}')
        if not chunk:  # empty chunks carry no information
            return []
        self._pending += chunk
        return self._scan(final=False)

    def finish(self) -> list:
        """Flush the remaining tokens at the end of the input."""
        out = self._scan(final=True)
        if self._awaiting is not None:
            kind = self._awaiting[0]
            raise UnclosedTokenError(
                f'Input ended inside an unterminated {kind} '
                f'({len(self._pending)} characters buffered)')
        return out

    def iter_tokens(self, chunks: Iterable[str]) -> Generator:
        """Yield (token type, value) pairs for an iterable of chunks."""
        for chunk in chunks:
            yield from self.feed(chunk)
        yield from self.finish()

    def _scan(self, final):
        """Tokenize the safe prefix of the pending buffer."""
        out = []
        # self._prev_char provides one character of look-behind context
        # for patterns matched at the start of the buffer.
        ctx = self._prev_char + self._pending
        pos = 1
        next_non_ws = _next_non_ws(ctx)
        last_special = _last_special(ctx)
        while pos < len(ctx):
            result = self._token_at(ctx, pos, next_non_ws, last_special,
                                    final)
            if result is None:
                break
            end, ttype, value = result
            out.append((ttype, value))
            pos = end
        self._pending = ctx[pos:]
        if pos > 1:
            self._prev_char = ctx[pos - 1]
        if (self.max_token_size is not None
                and len(self._pending) > self.max_token_size):
            raise StreamLimitExceededError(
                'Unterminated token exceeds the configured maximum size '
                f'({self.max_token_size} characters)')
        return out

    def _token_at(self, ctx, pos, next_non_ws, last_special, final):
        """Return (end, ttype, value) for the token at pos in ctx.

        Returns None if more input is needed to decide where the token
        ends; unterminated constructs are tracked in self._awaiting.
        """
        if pos == 1 and self._awaiting is not None:
            return self._complete_awaiting(ctx, final)

        char = ctx[pos]
        if char in _QUOTES:
            end, resume = self._find_string_end(ctx, pos, final, pos + 1)
            if end is None:
                self._awaiting = ('string', char, resume)
                return None
            ttype, value = self._dispatch(ctx, pos)
            return pos + len(value), ttype, value

        if char == '/' and ctx[pos + 1:pos + 2] == '*':
            idx = ctx.find('*/', pos + 2)
            if idx == -1:
                self._awaiting = ('multiline comment', None,
                                  max(2, len(ctx) - pos - 1))
                return None
            end = idx + 2
            if ctx[pos + 2:pos + 3] == '+':
                ttype = tokens.Comment.Multiline.Hint
            else:
                ttype = tokens.Comment.Multiline
            return end, ttype, ctx[pos:end]

        if char == '$':
            opener = keywords._DOLLAR_QUOTE_DELIM.match(ctx, pos)
            if (opener is not None
                    and keywords._DOLLAR_QUOTE_OPENER_OK.match(ctx, pos)
                    is not None):
                tag = opener.group(1)
                idx = ctx.find(tag, pos + len(tag))
                if idx == -1:
                    self._awaiting = (
                        'dollar-quoted literal', tag,
                        max(len(tag), len(ctx) - pos - len(tag) + 1))
                    return None
                end = idx + len(tag)
                return end, tokens.Literal, ctx[pos:end]
            if (not final
                    and _DOLLAR_OPENER_PREFIX.match(ctx, pos) is not None
                    and keywords._DOLLAR_QUOTE_OPENER_OK.match(ctx, pos)
                    is not None):
                # A dollar-quote opener split across chunks, e.g.
                # "$ta" + "g$..."; wait for the rest of the opener.
                return None

        if char == '[' and _BRACKET_OPENER_OK.match(ctx, pos) is not None:
            idx_r = ctx.find(']', pos + 1)
            idx_l = ctx.find('[', pos + 1)
            if idx_r == -1 and idx_l == -1 and not final:
                # Possibly a [bracketed name] split across chunks.
                self._awaiting = ('square bracket name', None,
                                  len(ctx) - pos)
                return None

        if not final and char == '%' \
                and _PLACEHOLDER_PREFIX.match(ctx, pos) is not None:
            # A "%(name)s" placeholder split across chunks.
            return None

        if not final and (char == '-' or char.isdigit()) \
                and _NUMBER_PREFIX.match(ctx, pos) is not None:
            # A number split across chunks ("-0x" + "1F",
            # "1E" + "-3", "-." + "5").
            return None

        if not final and (char == '@' or char == '#') \
                and _AT_NAME_PREFIX.match(ctx, pos) is not None:
            # A "@name" or "#name" split across chunks; the pattern
            # requires at least two word characters.
            return None

        ttype, value = self._dispatch(ctx, pos)
        end = pos + len(value)
        if not final:
            if end == len(ctx):
                # The token touches the end of the buffered input and
                # may grow when the next chunk arrives.
                return None
            if value[0].isalpha() or value[0] == '_':
                if last_special < end:
                    # Only word and whitespace characters follow the
                    # token in the buffer; it may still merge with
                    # following input, e.g. into a multi-word keyword
                    # ("GROUP" + "BY").
                    return None
                if next_non_ws[end] >= len(ctx) - 1:
                    # The token is followed by at most one
                    # non-whitespace character; its type may still
                    # change through a look-ahead pattern ("name"
                    # followed by ".").
                    return None
            if _TZCAST_PREFIX.match(ctx, pos) is not None:
                # A keyword pattern containing a string literal
                # ("AT TIME ZONE '...'") may still be completed by
                # following input.
                return None
        return end, ttype, value

    def _complete_awaiting(self, ctx, final):
        """Try to finish the unterminated construct in self._awaiting.

        The construct starts at position 1 of ctx.
        """
        kind, data, resume = self._awaiting
        if kind == 'string':
            end, resume = self._find_string_end(ctx, 1, final, 1 + resume)
            if end is None:
                self._awaiting = (kind, data, resume)
                return None
            self._awaiting = None
            ttype, value = self._dispatch(ctx, 1)
            return 1 + len(value), ttype, value
        if kind == 'multiline comment':
            idx = ctx.find('*/', 1 + resume)
            if idx == -1:
                self._awaiting = (kind, data, max(2, len(ctx) - 2))
                return None
            self._awaiting = None
            end = idx + 2
            # Whether the comment is a hint ("/*+ ... */") can only
            # be decided once the opener is fully buffered.
            if ctx[3:4] == '+':
                ttype = tokens.Comment.Multiline.Hint
            else:
                ttype = tokens.Comment.Multiline
            return end, ttype, ctx[1:end]
        if kind == 'dollar-quoted literal':
            idx = ctx.find(data, 1 + resume)
            if idx == -1:
                self._awaiting = (
                    kind, data, max(len(data), len(ctx) - len(data)))
                return None
            self._awaiting = None
            end = idx + len(data)
            return end, tokens.Literal, ctx[1:end]
        # square bracket name
        idx_r = ctx.find(']', 1 + resume)
        idx_l = ctx.find('[', 1 + resume)
        if idx_r != -1 and (idx_l == -1 or idx_l > idx_r):
            self._awaiting = None
            ttype, value = self._dispatch(ctx, 1)
            return 1 + len(value), ttype, value
        if idx_l != -1 and (idx_r == -1 or idx_l < idx_r):
            # A second "[" invalidates the name; the first bracket is
            # plain punctuation.
            self._awaiting = None
            ttype, value = self._dispatch(ctx, 1)
            return 1 + len(value), ttype, value
        if final:
            self._awaiting = None
            ttype, value = self._dispatch(ctx, 1)
            return 1 + len(value), ttype, value
        self._awaiting = (kind, data, len(ctx) - 1)
        return None

    @staticmethod
    def _find_string_end(ctx, pos, final, start):
        """Find the end of the quoted string opening at pos.

        Returns (end, resume); end is None if the closing quote is not
        (yet) in the buffer.  resume is the offset relative to pos at
        which a later call may continue the search.
        """
        quote = ctx[pos]
        i = start
        while i < len(ctx):
            char = ctx[i]
            if char == '\\' and quote in _BACKSLASH_ESCAPED_QUOTES:
                if i + 1 >= len(ctx):
                    # The backslash may escape a quote in the next chunk.
                    return None, i - pos
                if ctx[i + 1] == quote:
                    i += 2
                    continue
                i += 1
                continue
            if char == quote:
                if i + 1 >= len(ctx):
                    if final:
                        return i + 1, i + 1 - pos
                    # A trailing quote may pair with a quote in the
                    # next chunk to form an escaped quote.
                    return None, i - pos
                if ctx[i + 1] == quote:
                    i += 2
                    continue
                return i + 1, i + 1 - pos
            i += 1
        return None, len(ctx) - pos

    def _dispatch(self, ctx, pos):
        """Match the token at pos with the lexer's regular expressions."""
        for rexmatch, action in self._lexer._SQL_REGEX:
            m = rexmatch(ctx, pos)
            if not m:
                continue
            if isinstance(action, tokens._TokenType):
                return action, m.group()
            if action is keywords.PROCESS_AS_KEYWORD:
                return self._lexer.is_keyword(m.group())
        return tokens.Error, ctx[pos]


def iter_statements(chunks, max_token_size=None, max_statement_size=None):
    """Yield grouped statements parsed from an iterable of text chunks.

    The chunks are consumed lazily and at most once; a statement is
    yielded as soon as it is complete, without reading the remaining
    input first.
    """
    tokenizer = IncrementalTokenizer(max_token_size=max_token_size)
    splitter = StatementSplitter(max_statement_size=max_statement_size)
    stream = tokenizer.iter_tokens(chunks)
    try:
        for stmt in splitter.process(stream):
            yield grouping.group(stmt)
    except RecursionError as err:
        raise SQLParseError('Maximum recursion depth exceeded') from err
