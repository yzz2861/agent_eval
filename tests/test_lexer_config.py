"""Tests for independent, concurrently usable lexer configurations."""

from concurrent.futures import ThreadPoolExecutor

import pytest

import sqlparse
from sqlparse import keywords, tokens as T
from sqlparse.lexer import Lexer, LexerConfig


WORD = "bacon"
SQL = f"select {WORD} from t"


def _config(ttype):
    config = LexerConfig.default()
    config.add_keywords({WORD.upper(): ttype})
    return config


def _word_ttype(config_or_lexer):
    statement = sqlparse.parse(SQL, lexer_config=config_or_lexer)[0]
    return next(
        token.ttype for token in statement.flatten() if token.value == WORD
    )


def test_distinct_configs_tokenize_same_word_differently():
    assert _word_ttype(_config(T.Keyword)) is T.Keyword
    assert _word_ttype(_config(T.Name.Builtin)) is T.Name.Builtin
    # The default singleton never saw the custom keyword.
    statement = sqlparse.parse(SQL)[0]
    assert next(
        token.ttype for token in statement.flatten() if token.value == WORD
    ) is T.Name


def test_concurrent_configs_do_not_crosstalk():
    keyword_lexer = _config(T.Keyword).freeze()
    builtin_lexer = _config(T.Name.Builtin).freeze()
    iterations = 200

    def work(lexer, expected):
        for _ in range(iterations):
            assert _word_ttype(lexer) is expected

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(work, keyword_lexer, T.Keyword),
            executor.submit(work, builtin_lexer, T.Name.Builtin),
        ]
        for future in futures:
            future.result()


def test_concurrent_parse_split_format_use_same_rules():
    lexer = _config(T.Keyword).freeze()

    def use_entry_points():
        assert _word_ttype(lexer) is T.Keyword
        assert sqlparse.split(SQL, lexer_config=lexer) == [SQL]
        formatted = sqlparse.format(
            SQL, keyword_case="upper", lexer_config=lexer)
        assert "SELECT BACON FROM t" == formatted

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(use_entry_points) for _ in range(8)]
        for future in futures:
            future.result()


def test_mutating_builder_during_iteration_does_not_affect_run():
    config = _config(T.Keyword)
    statements = sqlparse.parsestream(
        f"{WORD}; " * 6 + WORD, lexer_config=config
    )

    # The run already froze its own snapshot: rules added while the
    # caller is still consuming the generator cannot reach it.
    first = next(statements)
    config.add_keywords({"eggs": T.Keyword})
    config.add_keywords({WORD.upper(): T.Name.Builtin})
    seen = [first] + list(statements)

    assert len(seen) == 7
    for statement in seen:
        token = next(
            token for token in statement.flatten() if token.value == WORD
        )
        assert token.ttype is T.Keyword


def test_freeze_reflects_later_builder_changes_in_new_lexer_only():
    config = _config(T.Keyword)
    before = config.freeze()

    config.set_SQL_REGEX(
        keywords.SQL_REGEX[:38]
        + [(r"ZORDER\s+BY\b", T.Keyword)]
        + keywords.SQL_REGEX[38:]
    )
    after = config.freeze()

    statement_after = sqlparse.parse(
        "select * from t zorder by c", lexer_config=after)[0]
    assert (
        T.Keyword,
        "zorder by",
    ) in [(token.ttype, token.value) for token in statement_after.flatten()]

    statement_before = sqlparse.parse(
        "select * from t zorder by c", lexer_config=before)[0]
    assert (
        T.Keyword,
        "zorder by",
    ) not in [
        (token.ttype, token.value) for token in statement_before.flatten()
    ]


def test_frozen_lexer_is_immutable():
    frozen = _config(T.Keyword).freeze()
    with pytest.raises(TypeError):
        frozen.add_keywords({"spam": T.Keyword})
    with pytest.raises(TypeError):
        frozen.clear()
    with pytest.raises(TypeError):
        frozen.set_SQL_REGEX(keywords.SQL_REGEX)
    with pytest.raises(TypeError):
        frozen.default_initialization()


def test_freeze_copies_keyword_mapping():
    keywords_map = {WORD.upper(): T.Keyword}
    config = LexerConfig.default()
    config.add_keywords(keywords_map)
    frozen = config.freeze()

    # Mutating the caller's mapping after freezing must not leak in.
    keywords_map[WORD.upper()] = T.Name.Builtin
    assert _word_ttype(frozen) is T.Keyword


def test_legacy_default_instance_remains_mutable():
    default = Lexer.get_default_instance()
    try:
        default.add_keywords({"LEGACYBACON": T.Name.Builtin})
        ttype = next(
            ttype
            for ttype, value in sqlparse.lexer.tokenize("legacybacon")
            if ttype not in T.Whitespace
        )
        assert ttype is T.Name.Builtin
    finally:
        default.default_initialization()


def test_add_keywords_requires_mapping():
    with pytest.raises(TypeError):
        LexerConfig.default().add_keywords([("spam", T.Keyword)])


def test_invalid_lexer_config_type():
    with pytest.raises(TypeError):
        sqlparse.parse("select 1", lexer_config=object())
