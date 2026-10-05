#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""SQL Lexer"""
import re
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from io import TextIOBase
from threading import Lock
from types import MappingProxyType
from typing import Any

# This code is based on the SqlLexer in pygments.
# http://pygments.org/
# It's separated from the rest of pygments to increase performance
# and to allow some customizations.
from sqlparse import keywords, tokens
from sqlparse.utils import consume

_DEFAULT_KEYWORDS = (
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

_active_lexer_config: ContextVar["LexerConfig | None"] = ContextVar(
    "sqlparse_lexer_config", default=None
)


class LexerConfig:
    """Immutable lexical rules used for one parsing operation."""

    __slots__ = ("_SQL_REGEX", "_keywords")

    def __delattr__(self, name):
        raise AttributeError("LexerConfig is immutable")

    def __setattr__(self, name, value):
        raise AttributeError("LexerConfig is immutable")

    def __init__(
        self,
        SQL_REGEX: Sequence[tuple[str, Any]],
        keyword_dicts: Sequence[Mapping[str, Any]],
    ):
        flags = re.IGNORECASE | re.UNICODE
        object.__setattr__(
            self,
            "_SQL_REGEX",
            tuple(
                (re.compile(rx, flags).match, action)
                for rx, action in SQL_REGEX
            ),
        )
        object.__setattr__(
            self,
            "_keywords",
            tuple(MappingProxyType(dict(kwdict)) for kwdict in keyword_dicts),
        )

    @property
    def SQL_REGEX(self) -> tuple[tuple[Any, Any], ...]:
        return self._SQL_REGEX

    @property
    def keywords(self) -> tuple[Mapping[str, Any], ...]:
        return self._keywords

    @classmethod
    def builder(cls) -> "LexerConfigBuilder":
        return LexerConfigBuilder()


class LexerConfigBuilder:
    """Build an immutable :class:`LexerConfig` from lexical rules."""

    def __init__(self) -> None:
        self.use_defaults()

    @classmethod
    def empty(cls) -> "LexerConfigBuilder":
        builder = cls.__new__(cls)
        builder.clear()
        return builder

    @classmethod
    def default(cls) -> "LexerConfigBuilder":
        return cls()

    def clear(self) -> "LexerConfigBuilder":
        self._SQL_REGEX = []
        self._keywords = []
        return self

    def use_defaults(self) -> "LexerConfigBuilder":
        self._SQL_REGEX = list(keywords.SQL_REGEX)
        self._keywords = [dict(kwdict) for kwdict in _DEFAULT_KEYWORDS]
        return self

    def set_SQL_REGEX(self, SQL_REGEX) -> "LexerConfigBuilder":
        """Replace the configured regular expressions."""
        self._SQL_REGEX = list(SQL_REGEX)
        return self

    set_sql_regex = set_SQL_REGEX

    def add_regex(
        self,
        pattern: "str | tuple[str, Any]",
        token_type: Any = None,
        *,
        index: int | None = None,
    ) -> "LexerConfigBuilder":
        """Add a lexical regular expression before keyword fallback."""
        if isinstance(pattern, tuple):
            pattern, token_type = pattern
        rule = (pattern, token_type)
        if index is None:
            index = next(
                (
                    position
                    for position, (_, action) in enumerate(self._SQL_REGEX)
                    if action is keywords.PROCESS_AS_KEYWORD
                ),
                len(self._SQL_REGEX),
            )
            self._SQL_REGEX.insert(index, rule)
        else:
            self._SQL_REGEX.insert(index, rule)
        return self

    def add_keywords(self, keyword_dict) -> "LexerConfigBuilder":
        """Append a keyword dictionary. Later dictionaries take precedence."""
        self._keywords.append(dict(keyword_dict))
        return self

    def add_keyword(self, keyword: str, token_type: Any) -> "LexerConfigBuilder":
        """Add or override one keyword for this configuration."""
        self._keywords.append({keyword.upper(): token_type})
        return self

    def add_rules(self, rules) -> "LexerConfigBuilder":
        """Add multiple lexical regular expressions."""
        for rule in rules:
            self.add_regex(rule)
        return self

    def build(self) -> LexerConfig:
        merged_keywords = {}
        for keyword_dict in self._keywords:
            merged_keywords.update(keyword_dict)
        return LexerConfig(self._SQL_REGEX, [merged_keywords])

    freeze = build

    add_lexical_rule = add_regex
    add_rule = add_regex
    add_lexical_rules = add_rules


def prepare_lexer_config(config) -> "LexerConfig | None":
    """Return the immutable config to use for a public API call."""
    if config is None:
        return _active_lexer_config.get()
    if isinstance(config, LexerConfig):
        return config
    if isinstance(config, LexerConfigBuilder):
        return config.build()
    if isinstance(config, Lexer):
        if config._config is not None:
            return config._config
        return LexerConfig(config._SQL_REGEX_SOURCE, config._keywords_source)
    raise TypeError(f"Unsupported lexer configuration: {type(config)!r}")


class Lexer:
    """The Lexer supports configurable syntax.
    To add support for additional keywords, use the `add_keywords` method."""

    _default_instance = None
    _lock = Lock()

    # Development notes:
    # - This class is prepared to be able to support additional SQL dialects
    #   in the future by adding additional functions that take the place of
    #   the function default_initialization().
    # - get_default_instance() preserves the mutable singleton API. Calls that
    #   receive a LexerConfig build an independent Lexer, while a ContextVar
    #   propagates that frozen configuration through nested parsing calls.

    @classmethod
    def get_default_instance(cls):
        """Returns the lexer instance used internally
        by the sqlparse core functions."""
        with cls._lock:
            if cls._default_instance is None:
                cls._default_instance = cls()
                cls._default_instance.default_initialization()
        return cls._default_instance

    def __init__(self, config: LexerConfig | None = None):
        if config is None:
            self.clear()
        else:
            self._config = config
            self._SQL_REGEX = list(config.SQL_REGEX)
            self._keywords = list(config.keywords)
            self._SQL_REGEX_SOURCE = None
            self._keywords_source = None

    def default_initialization(self):
        """Initialize the lexer with default dictionaries.
        Useful if you need to revert custom syntax settings."""
        self.clear()
        self.set_SQL_REGEX(keywords.SQL_REGEX)
        for keyword_dict in _DEFAULT_KEYWORDS:
            self.add_keywords(keyword_dict)

    def clear(self):
        """Clear all syntax configurations.
        Useful if you want to load a reduced set of syntax configurations.
        After this call, regexps and keyword dictionaries need to be loaded
        to make the lexer functional again."""
        self._config = None
        self._SQL_REGEX = []
        self._keywords = []
        self._SQL_REGEX_SOURCE = []
        self._keywords_source = []

    def set_SQL_REGEX(self, SQL_REGEX):
        """Set the list of regex that will parse the SQL."""
        FLAGS = re.IGNORECASE | re.UNICODE
        self._SQL_REGEX_SOURCE = list(SQL_REGEX)
        self._SQL_REGEX = [
            (re.compile(rx, FLAGS).match, tt)
            for rx, tt in SQL_REGEX
        ]

    def add_keywords(self, keywords):
        """Add keyword dictionaries. Keywords are looked up in the same order
        that dictionaries were added."""
        self._keywords.append(keywords)
        self._keywords_source.append(keywords)

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


def tokenize(sql, encoding=None, lexer_config: "LexerConfig | None" = None):
    """Tokenize sql.

    Tokenize *sql* using the :class:`Lexer` and return a 2-tuple stream
    of ``(token type, value)`` items.
    """
    lexer_config = prepare_lexer_config(lexer_config)
    if lexer_config is None:
        lexer = Lexer.get_default_instance()
    else:
        lexer = Lexer(lexer_config)
    return lexer.get_tokens(sql, encoding)
