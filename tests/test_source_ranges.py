import pytest

import sqlparse
from sqlparse import engine, formatter, lexer, sql
from sqlparse.source import SourceRange


def walk_groups(token):
    yield token
    if token.is_group:
        for child in token.tokens:
            yield from walk_groups(child)


def test_source_ranges_are_disabled_by_default():
    statement = sqlparse.parse("select a from t")[0]

    assert statement.get_source_range() is None
    assert all(token.get_source_range() is None
               for token in walk_groups(statement))

    stream = lexer.tokenize("select a from t")
    assert all(len(item) == 2 for item in stream)


def test_leaf_and_group_ranges_match_source_slices():
    source = "select a -- comment\r\nfrom t"
    statement = sqlparse.parse(source, source_ranges=True)[0]

    for token in walk_groups(statement):
        start, end = token.get_source_range()
        assert source[start:end] == str(token)


def test_source_range_object_and_explicit_bytes():
    statement = sqlparse.parse("select '😀'", source_ranges=True)[0]
    leaf = statement.flatten().__next__()

    assert isinstance(leaf.source_range, SourceRange)
    assert tuple(leaf.source_range) == (0, 6)
    assert leaf.source_range.source == "select '😀'"
    assert statement.source_range == SourceRange(0, 10)
    assert statement.get_byte_range("utf-8") == (0, 13)


def test_duplicate_fragments_have_absolute_ranges():
    source = "select a from a; select a"
    statements = sqlparse.parse(source, source_ranges=True)

    assert [statement.get_source_range() for statement in statements] == [
        (0, 17), (17, 25)]

    first_where = statements[0].token_next_by(i=sql.Identifier, idx=2)[1]
    second_select = statements[1].tokens[0]
    assert source[slice(*first_where.get_source_range())] == "a"
    assert source[slice(*second_select.get_source_range())] == "select"


@pytest.mark.parametrize(("source", "encoding"), [
    ("select '😀' from 表", "utf-8"),
    ("select '😀' from 表", "utf-16-le"),
    ("select '名称' from 表", "gbk"),
])
def test_byte_ranges_use_requested_encoding(source, encoding):
    statement = sqlparse.parse(
        source, encoding=encoding, source_ranges=True)[0]

    for token in statement.flatten():
        start, end = token.get_source_range()
        assert token.get_byte_range(encoding=encoding) == (
            len(source[:start].encode(encoding)),
            len(source[:end].encode(encoding)),
        )


def test_formatting_does_not_invent_ranges_for_generated_tokens():
    source = "select a -- remove\r\nfrom t where a = 1"
    stack = engine.FilterStack()
    options = formatter.validate_options({
        "keyword_case": "upper",
        "reindent": True,
        "strip_comments": True,
    })
    formatter.build_filter_stack(stack, options)
    statement = next(stack.run(source, source_ranges=True))

    for token in statement.flatten():
        source_range = token.get_source_range()
        if source_range is None:
            continue
        assert source[slice(*source_range)] == token.value

    values_by_range = {
        token.get_source_range(): token.value
        for token in statement.flatten()
        if token.get_source_range() is not None
    }
    assert (0, 6) not in values_by_range
    assert values_by_range[(7, 8)] == "a"
    assert all(token.get_source_range() is None
               for token in statement.flatten()
               if token.is_whitespace)


def test_changed_keyword_and_unchanged_identifier_ranges():
    source = "select a"
    stack = engine.FilterStack()
    options = formatter.validate_options({"keyword_case": "upper"})
    formatter.build_filter_stack(stack, options)
    statement = next(stack.run(source, source_ranges=True))

    keyword = statement.tokens[0]
    identifier = next(token for token in statement.flatten()
                       if token.value == "a")
    assert keyword.value == "SELECT"
    assert keyword.get_source_range() is None
    assert source[slice(*identifier.get_source_range())] == "a"
