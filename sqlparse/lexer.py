#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""SQL Lexer"""
import re

# This code is based on the SqlLexer in pygments.
# http://pygments.org/
# It's separated from the rest of pygments to increase performance
# and to allow some customizations.
from collections.abc import Mapping
from io import TextIOBase
from threading import Lock

from sqlparse import keywords, tokens
from sqlparse.utils import consume


class Lexer:
    """The Lexer supports configurable syntax.
    To add support for additional keywords, use the `add_keywords` method.

    A lexer is a concrete set of lexing rules. For the legacy mutable
    singleton use :meth:`get_default_instance`; for independent rule sets
    that can coexist in one process use :class:`LexerConfig` and pass the
    frozen lexer it produces to the public entry points.
    """

    _default_instance = None
    _lock = Lock()

    # Development notes:
    # - Multiple independent rule sets are supported through
    #   :class:`LexerConfig`. A config is a mutable builder; freezing it
    #   produces a standalone lexer that shares no state with other lexers
    #   and is safe to use concurrently. The mutable default singleton is
    #   retained for backwards compatibility only.

    @classmethod
    def get_default_instance(cls):
        """Returns the lexer instance used internally
        by the sqlparse core functions."""
        with cls._lock:
            if cls._default_instance is None:
                cls._default_instance = cls()
                cls._default_instance.default_initialization()
        return cls._default_instance

    def __init__(self):
        self._frozen = False
        self._SQL_REGEX = []
        self._keywords = []

    def _ensure_mutable(self):
        if self._frozen:
            raise TypeError(
                'Cannot modify a frozen Lexer; build a new LexerConfig '
                'instead')

    def default_initialization(self):
        """Initialize the lexer with default dictionaries.
        Useful if you need to revert custom syntax settings."""
        self._ensure_mutable()
        self._init_from(
            sql_regex=list(keywords.SQL_REGEX),
            keyword_dicts=_default_keyword_dicts(),
            frozen=False,
        )

    def clear(self):
        """Clear all syntax configurations.
        Useful if you want to load a reduced set of syntax configurations.
        After this call, regexps and keyword dictionaries need to be loaded
        to make the lexer functional again."""
        self._ensure_mutable()
        self._SQL_REGEX = []
        self._keywords = []

    def set_SQL_REGEX(self, SQL_REGEX):
        """Set the list of regex that will parse the SQL."""
        self._ensure_mutable()
        FLAGS = re.IGNORECASE | re.UNICODE
        self._SQL_REGEX = [
            (re.compile(rx, FLAGS).match, tt)
            for rx, tt in SQL_REGEX
        ]

    def add_keywords(self, keywords):
        """Add keyword dictionaries. Keywords are looked up in the same order
        that dictionaries were added."""
        self._ensure_mutable()
        self._keywords.append(keywords)

    def _init_from(self, sql_regex, keyword_dicts, frozen=True):
        """Populate the lexer from already resolved rule collections.

        Used by the freezing machinery; bypasses the mutability check so
        that immutable lexers can be assembled during construction.
        """
        FLAGS = re.IGNORECASE | re.UNICODE
        self._SQL_REGEX = [
            (re.compile(rx, FLAGS).match, tt)
            for rx, tt in sql_regex
        ]
        # The keyword chain is copied so later changes to the builder (or
        # to a dictionary passed in by a caller) cannot reach this lexer.
        self._keywords = [dict(kwdict) for kwdict in keyword_dicts]
        self._frozen = frozen

    def is_keyword(self, value):
        """Checks for a keyword.

        If the given value is in one of the KEYWORDS_* dictionary
        it's considered a keyword. Otherwise, tokens.Name is returned.
        """
        val = value.upper()
        for kwdict in self._keywords:
            if val in kwdict:
                return kwdict[val], value
        else:
            return tokens.Name, value

    def get_tokens(self, text, encoding=None):
        """
        Return an iterable of (tokentype, value) pairs generated from
        `text`. If `unfiltered` is set to `True`, the filtering mechanism
        is bypassed even if filters are defined.

        Also preprocess the text, i.e. expand tabs and strip it if
        wanted and applies registered filters.

        Split ``text`` into (tokentype, text) pairs.

        ``stack`` is the initial stack (default: ``['root']``)
        """
        if isinstance(text, TextIOBase):
            text = text.read()

        if isinstance(text, str):
            pass
        elif isinstance(text, bytes):
            if encoding:
                text = text.decode(encoding)
            else:
                try:
                    text = text.decode('utf-8')
                except UnicodeDecodeError:
                    text = text.decode('unicode-escape')
        else:
            raise TypeError(f"Expected text or file-like object, got {type(text)!r}")

        delimited_spans = keywords.find_delimited_spans(text)
        span_openers = delimited_spans.openers

        iterable = enumerate(text)
        for pos, char in iterable:
            # Only positions the lexer actually reaches may open a
            # dollar-quoted literal or a multiline comment; a delimiter
            # inside a string literal or behind a "--" comment is skipped
            # along with its surrounding token and never resolved.
            if pos in span_openers:
                resolved = delimited_spans.resolve(pos)
                if resolved is not None:
                    end, ttype = resolved
                    yield ttype, text[pos:end]
                    consume(iterable, end - pos - 1)
                    continue

            for rexmatch, action in self._SQL_REGEX:
                m = rexmatch(text, pos)

                if not m:
                    continue
                elif isinstance(action, tokens._TokenType):
                    yield action, m.group()
                elif action is keywords.PROCESS_AS_KEYWORD:
                    yield self.is_keyword(m.group())

                consume(iterable, m.end() - pos - 1)
                break
            else:
                yield tokens.Error, char


def _default_keyword_dicts():
    return (
        keywords.KEYWORDS_COMMON,
        keywords.KEYWORDS_ORACLE,
        keywords.KEYWORDS_MYSQL,
        keywords.KEYWORDS_PLPGSQL,
        keywords.KEYWORDS_HQL,
        keywords.KEYWORDS_MSACCESS,
        keywords.KEYWORDS_SNOWFLAKE,
        keywords.KEYWORDS_BIGQUERY,
        keywords.KEYWORDS,
    )


class LexerConfig:
    """Mutable builder for an independent, immutable :class:`Lexer`.

    Rule collections (lexing regexes and keyword dictionaries) can be
    composed freely while the builder is being prepared. Calling
    :meth:`freeze` snapshots the current rules and returns a standalone
    lexer; subsequent changes to the builder never affect a lexer that
    was already frozen, so a parse, split or format in progress keeps
    using the rules it started with.

    Use :meth:`default` to start from the built-in SQL syntax or
    :meth:`empty` to build a reduced syntax from scratch. The resulting
    lexer can be passed as the ``lexer_config`` argument of
    :func:`sqlparse.parse`, :func:`sqlparse.parsestream`,
    :func:`sqlparse.split` and :func:`sqlparse.format`.
    """

    def __init__(self, sql_regex=None, keyword_dicts=None):
        self._sql_regex = list(sql_regex) if sql_regex is not None else []
        self._keyword_dicts = list(keyword_dicts) if keyword_dicts else []
        self._lock = Lock()

    @classmethod
    def default(cls):
        """Return a builder preloaded with the built-in SQL syntax."""
        return cls(
            sql_regex=list(keywords.SQL_REGEX),
            keyword_dicts=[dict(kw) for kw in _default_keyword_dicts()],
        )

    @classmethod
    def empty(cls):
        """Return a builder without any rules loaded."""
        return cls()

    def add_keywords(self, keyword_dict):
        """Add a keyword dictionary.

        Keyword dictionaries are consulted in the order they were added;
        the first matching dictionary decides a word's token type.
        """
        if not isinstance(keyword_dict, Mapping):
            raise TypeError(
                f'Expected a keyword mapping, got {type(keyword_dict)!r}')
        with self._lock:
            self._keyword_dicts.append(dict(keyword_dict))
        return self

    def set_SQL_REGEX(self, sql_regex):
        """Replace the lexing rules with `sql_regex`."""
        with self._lock:
            self._sql_regex = list(sql_regex)
        return self

    def add_sql_regex(self, sql_regex):
        """Append lexing rules, tried after the rules already present."""
        with self._lock:
            self._sql_regex.extend(sql_regex)
        return self

    def freeze(self):
        """Snapshot the current rules and return an immutable Lexer.

        The returned lexer is independent of this builder and of every
        other frozen lexer, so it can be used to parse concurrently with
        other configurations. Freezing the same builder again after it
        has been modified yields a fresh lexer reflecting the new rules.
        """
        with self._lock:
            sql_regex = list(self._sql_regex)
            keyword_dicts = list(self._keyword_dicts)
        lex = Lexer.__new__(Lexer)
        lex._init_from(
            sql_regex=sql_regex,
            keyword_dicts=keyword_dicts,
        )
        return lex


def resolve_lexer(lexer_config):
    """Return the concrete, ready-to-use lexer for one entry-point call.

    ``None`` selects the legacy default singleton, a :class:`LexerConfig`
    is frozen on the spot so the upcoming call owns an immutable rule
    snapshot, and an already frozen :class:`Lexer` is reused as-is.

    Freezing happens eagerly at the start of a call, before any token is
    read, so later builder mutations cannot change an in-flight parse.
    """
    if lexer_config is None:
        return Lexer.get_default_instance()
    if isinstance(lexer_config, LexerConfig):
        return lexer_config.freeze()
    if isinstance(lexer_config, Lexer):
        return lexer_config
    raise TypeError(
        'lexer_config must be a LexerConfig or Lexer instance, got '
        f'{type(lexer_config)!r}')


def tokenize(sql, encoding=None, lexer_config=None):
    """Tokenize sql.

    Tokenize *sql* using the :class:`Lexer` and return a 2-tuple stream
    of ``(token type, value)`` items. When *lexer_config* is omitted the
    legacy default lexer is used.
    """
    lex = resolve_lexer(lexer_config)
    return lex.get_tokens(sql, encoding)
