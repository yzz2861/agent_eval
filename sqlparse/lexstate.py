#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Recoverable lexical state machine for delimited SQL constructs.

Statement splitting is only as good as the lexical layer underneath it:
a semicolon may only end a statement when it appears outside of every
quoting and commenting construct.  This module scans raw SQL text in a
single left-to-right pass and records the exact character spans of

- single quoted ('...'), double quoted ("...") and backtick (`...`)
  strings, including PostgreSQL escape strings (E'...' is just a name
  token followed by a regular string),
- dollar-quoted literals ($tag$...$tag$),
- line comments (-- ... and # ...),
- block comments (/* ... */) with PostgreSQL-style nesting,
- MySQL executable comments (/*! ... */), which are block comments
  whose contents a MySQL server executes.

The scanner is *recoverable*: a string or block comment that is never
closed extends to the end of the input instead of raising, so a
semicolon that only a lexer error would expose can never split a
statement.  An unclosed dollar-quoted literal is *not* recovered as a
literal; the opening delimiter is treated as ordinary text (a dollar
quote without its closing tag is not a quote at all).  Everything the
scanner reports is a pure function of the input text -- no state is
shared between calls, so one statement's quotes can never leak into the
next statement and every call is independent.

One budget guards against pathological input: MAX_COMMENT_DEPTH caps
the nesting depth of block comments and raises SQLParseError when it is
exceeded.  The scan itself is a single left-to-right pass, so
adversarial input with many unclosed openers stays linear
(GHSA-prg7-hcfm-mfcr).
"""

import re
from bisect import bisect_left
from collections import defaultdict

from sqlparse import tokens as T
from sqlparse.exceptions import SQLParseError

# Maximum nesting depth of block comments (/* /* ... */ */).
# Set to None to disable the limit (not recommended for untrusted input).
MAX_COMMENT_DEPTH = 10000

# Characters that can start a delimited construct or a comment.  Jumping
# from one match to the next keeps the scan linear without iterating
# over every character in Python.
_SPECIAL = re.compile(r"'|\"|`|--|# |/\*|\$")

# End of a line comment; the newline itself belongs to the comment token.
_LINE_END = re.compile(r'\r\n|\r|\n')

# Open and close delimiters of a block comment.
_BLOCK_COMMENT_DELIM = re.compile(r'/\*|\*/')

# String patterns, identical to the corresponding entries in
# keywords.SQL_REGEX: a doubled quote or a backslash-escaped quote does
# not end a single or double quoted string, backticks only know the
# doubled-backtick escape.
_STRING_PATTERNS = {
    "'": (re.compile(r"'(''|\\'|[^'])*'"), T.String.Single),
    '"': (re.compile(r'"(""|\\"|[^"])*"'), T.String.Symbol),
    '`': (re.compile(r'`(``|[^`])*`'), T.Name),
}

# Dollar-quoted literals ($tag$...$tag$) used to be matched with a
# per-position regex using a lazy dot-all quantifier ([\s\S]*?)
# terminated by a backreference.  Applied at every text position, that
# shape is O(n^2) on adversarial input with many unclosed openers, since
# each failed attempt re-scans to the end of the remaining text
# (GHSA-prg7-hcfm-mfcr).  All delimiter positions are collected in a
# single pass instead, so an opener can be paired with a binary search
# when the scanner actually reaches it.
#
# The delimiter regex is wrapped in a lookahead so that overlapping
# occurrences are reported too: in '$$$$' the closing '$$' starts inside
# the match of the opening one, and a non-overlapping scan would miss it.
_DOLLAR_QUOTE_DELIM = re.compile(
    r'(?=(\$(?:[_A-ZÀ-Ü]\w*)?\$))', re.IGNORECASE | re.UNICODE)
# A delimiter can only open a literal if it is not glued to a word
# character, a double quote or another dollar sign on its left.
_DOLLAR_QUOTE_OPEN = re.compile(
    r'(?<![\w"$])(\$(?:[_A-ZÀ-Ü]\w*)?\$)', re.IGNORECASE | re.UNICODE)


def _find_dollar_closers(text):
    """Map every dollar-quote tag to its sorted delimiter positions."""
    closers = defaultdict(list)
    for m in _DOLLAR_QUOTE_DELIM.finditer(text):
        closers[m.group(1)].append(m.start())
    return closers


def _scan_block_comment(text, start, max_comment_depth):
    """Return the end offset of the block comment opening at `start`.

    Block comments nest (PostgreSQL); the comment ends when the nesting
    depth returns to zero.  An unclosed comment recovers by extending to
    the end of the input.  Raises SQLParseError when the nesting depth
    exceeds `max_comment_depth`.
    """
    depth = 1
    pos = start + 2
    while True:
        m = _BLOCK_COMMENT_DELIM.search(text, pos)
        if m is None:
            # Unclosed comment: recover by extending to end of input.
            return len(text)
        if m.group() == '/*':
            depth += 1
            if max_comment_depth is not None and depth > max_comment_depth:
                raise SQLParseError(
                    f'Maximum comment nesting depth exceeded '
                    f'({max_comment_depth}).'
                )
        else:
            depth -= 1
            if depth == 0:
                return m.end()
        pos = m.end()


def scan(text, max_comment_depth=None):
    """Scan `text` and return the spans of all delimited constructs.

    Returns a dict mapping the start offset of every string, dollar-quoted
    literal and block comment to a ``(end offset, token type)`` pair, so
    that ``text[start:end]`` is the exact source text of the construct.
    Line comments contain no statement separators and are only skipped,
    never reported.
    """
    if max_comment_depth is None:
        max_comment_depth = MAX_COMMENT_DEPTH
    spans = {}
    dollar_closers = _find_dollar_closers(text) if '$' in text else {}
    pos = 0
    while True:
        m = _SPECIAL.search(text, pos)
        if m is None:
            return spans
        marker = m.group()
        start = m.start()
        if marker in _STRING_PATTERNS:
            pattern, ttype = _STRING_PATTERNS[marker]
            match = pattern.match(text, start)
            if match is not None:
                end = match.end()
            else:
                # Unclosed string: recover by extending to end of input.
                end = len(text)
            spans[start] = (end, ttype)
            pos = end
        elif marker == '/*':
            end = _scan_block_comment(text, start, max_comment_depth)
            if text.startswith('/*+', start):
                ttype = T.Comment.Multiline.Hint
            else:
                # MySQL executable comments (/*! ... */) are preserved
                # verbatim as ordinary multiline comment tokens.
                ttype = T.Comment.Multiline
            spans[start] = (end, ttype)
            pos = end
        elif marker == '$':
            opener = _DOLLAR_QUOTE_OPEN.match(text, start)
            if opener is not None:
                tag = opener.group(1)
                closes = dollar_closers.get(tag, ())
                idx = bisect_left(closes, opener.end())
                if idx < len(closes):
                    end = closes[idx] + len(tag)
                    spans[start] = (end, T.Literal)
                    pos = end
                    continue
                pos = opener.end()
            else:
                # Not an opener: the dollar sign is ordinary text.
                pos = m.end()
        else:
            # A line comment (-- or # ): skip to the end of the line.
            nl = _LINE_END.search(text, m.end())
            pos = nl.end() if nl is not None else len(text)
