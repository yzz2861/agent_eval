from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

import sqlparse
from sqlparse import engine, keywords, lexer
from sqlparse import tokens as T
from sqlparse.lexer import LexerConfigBuilder


def _bacon_token(config_name):
    token_type = {
        "keyword": T.Keyword,
        "builtin": T.Name.Builtin,
    }[config_name]
    return (
        LexerConfigBuilder()
        .add_keyword("BACON", token_type)
        .build()
    )


def _first_bacon(stmt):
    return next(token for token in stmt.flatten() if token.value == "bacon")


def test_parse_uses_independent_lexer_configs():
    sql = "select bacon"

    keyword_stmt = sqlparse.parse(
        sql, lexer_config=_bacon_token("keyword")
    )[0]
    builtin_stmt = sqlparse.parse(
        sql, lexer_config=_bacon_token("builtin")
    )[0]

    assert _first_bacon(keyword_stmt).ttype is T.Keyword
    assert _first_bacon(builtin_stmt).ttype is T.Name.Builtin
    assert _first_bacon(sqlparse.parse(sql)[0]).ttype is T.Name


def test_format_uses_independent_lexer_configs():
    sql = "bacon from eggs"

    keyword_result = sqlparse.format(
        sql,
        lexer_config=_bacon_token("keyword"),
        keyword_case="upper",
    )
    builtin_result = sqlparse.format(
        sql,
        lexer_config=_bacon_token("builtin"),
        keyword_case="upper",
    )

    assert keyword_result == "BACON FROM eggs"
    assert builtin_result == "bacon FROM eggs"


def test_split_uses_independent_lexer_rules():
    sql = "select 1 GO select 2"
    rules = [
        (pattern, action)
        for pattern, action in keywords.SQL_REGEX
        if pattern != r"GO(\s\d+)\b"
    ]
    config = (
        LexerConfigBuilder()
        .set_SQL_REGEX(rules)
        .add_keyword("GO", T.Name)
        .build()
    )

    assert len(sqlparse.split(sql)) == 2
    assert len(sqlparse.split(sql, lexer_config=config)) == 1


def test_lexer_config_is_deeply_frozen():
    keyword_dict = {"BACON": T.Keyword}
    rules = [(r"BACON\b", T.Name.Builtin)]
    config = (
        LexerConfigBuilder.empty()
        .add_keywords(keyword_dict)
        .add_rules(rules)
        .build()
    )

    with pytest.raises(AttributeError):
        config.SQL_REGEX = ()
    with pytest.raises(TypeError):
        config.SQL_REGEX[0] = None
    with pytest.raises(TypeError):
        config.keywords[0]["BACON"] = T.Name


def test_builder_modification_does_not_affect_built_config():
    builder = LexerConfigBuilder().add_keyword("BACON", T.Keyword)
    config = builder.build()
    builder.add_keyword("BACON", T.Name.Builtin)

    assert _first_bacon(
        sqlparse.parse("bacon", lexer_config=config)[0]
    ).ttype is T.Keyword
    assert (
        sqlparse.parse("bacon", lexer_config=builder)[0].tokens[0].ttype
        is T.Name.Builtin
    )


def test_builder_is_frozen_when_generator_starts():
    builder = LexerConfigBuilder().add_keyword("BACON", T.Keyword)
    statements = sqlparse.parsestream(
        "bacon; bacon", lexer_config=builder
    )
    builder.add_keyword("BACON", T.Name.Builtin)

    assert all(stmt.tokens[0].ttype is T.Keyword for stmt in statements)


def test_builder_change_during_iteration_does_not_affect_statements():
    builder = LexerConfigBuilder().add_keyword("BACON", T.Keyword)
    statements = sqlparse.parsestream("bacon; bacon", lexer_config=builder)

    assert next(statements).tokens[0].ttype is T.Keyword
    builder.add_keyword("BACON", T.Name.Builtin)
    assert next(statements).tokens[0].ttype is T.Keyword

    assert (
        sqlparse.parse("bacon", lexer_config=builder)[0].tokens[0].ttype
        is T.Name.Builtin
    )


def test_paused_generator_does_not_leak_lexer_config():
    statements = sqlparse.parsestream(
        "bacon; bacon", lexer_config=_bacon_token("keyword")
    )
    first = next(statements)

    assert first.tokens[0].ttype is T.Keyword
    assert _first_bacon(sqlparse.parse("bacon")[0]).ttype is T.Name

    second = next(statements)
    assert second.tokens[0].ttype is T.Keyword


def test_mutated_input_dictionary_does_not_affect_config():
    keyword_dict = {"BACON": T.Keyword}
    config = LexerConfigBuilder().add_keywords(keyword_dict).build()
    keyword_dict["BACON"] = T.Name.Builtin

    assert (
        sqlparse.parse("bacon", lexer_config=config)[0].tokens[0].ttype
        is T.Keyword
    )


def test_concurrent_configs_do_not_interfere():
    keyword_config = _bacon_token("keyword")
    builtin_config = _bacon_token("builtin")
    barrier = Barrier(2)

    def check(config, expected):
        barrier.wait()
        for _ in range(100):
            stmt = sqlparse.parse("bacon", lexer_config=config)[0]
            assert stmt.tokens[0].ttype is expected

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(check, keyword_config, T.Keyword),
            executor.submit(check, builtin_config, T.Name.Builtin),
        ]
        for future in futures:
            future.result()


class _RecursiveParseFilter:
    def process(self, stmt):
        parsed = sqlparse.parse("bacon")
        assert parsed[0].tokens[0].ttype is T.Name.Builtin
        return stmt


class _RecursiveFormatFilter:
    def process(self, stmt):
        stmt._recursive = sqlparse.format(
            "bacon", keyword_case="upper"
        )
        return stmt


class _RecursiveSerializer:
    def process(self, stmt):
        return stmt._recursive


def test_recursive_filters_use_active_lexer_config():
    stack = engine.FilterStack(lexer_config=_bacon_token("builtin"))
    stack.stmtprocess.append(_RecursiveParseFilter())

    result = list(stack.run("bacon"))

    assert result[0].tokens[0].ttype is T.Name.Builtin


def test_recursive_formatting_uses_active_lexer_config():
    stack = engine.FilterStack(lexer_config=_bacon_token("keyword"))
    stack.postprocess.extend(
        [_RecursiveFormatFilter(), _RecursiveSerializer()]
    )

    assert "".join(stack.run("eggs")) == "BACON"


def test_default_instance_remains_mutable():
    instance = lexer.Lexer.get_default_instance()
    instance.add_keywords({"BACON": T.Keyword})

    try:
        assert sqlparse.parse("bacon")[0].tokens[0].ttype is T.Keyword
    finally:
        instance.default_initialization()

    assert _first_bacon(sqlparse.parse("bacon")[0]).ttype is T.Name
