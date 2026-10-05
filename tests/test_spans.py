"""Tests for optional source span tracking."""

import io

import pytest
import itertools

import sqlparse
from sqlparse import engine, formatter, sql
from sqlparse import tokens as T


def _walk_groups(tlist):
    """Recursively yield all groups (including tlist itself)."""
    yield tlist
    for token in tlist.tokens:
        if token.is_group:
            yield from _walk_groups(token)


def _assert_leaf_spans(source, stmt):
    """Every leaf span must slice the exact token text from source."""
    leaves = list(stmt.flatten())
    assert leaves
    for token in leaves:
        assert token.source_span is not None
        start, end = token.source_span
        assert source[start:end] == token.value
    # Leaves cover the statement contiguously, nothing lost in between.
    pos = leaves[0].source_span[0]
    for token in leaves:
        assert token.source_span[0] == pos
        pos = token.source_span[1]
    return pos


def _assert_group_spans(source, stmt):
    """Every group span must slice the exact group text from source."""
    for group in _walk_groups(stmt):
        start, end = group.source_span
        assert source[start:end] == str(group)


def test_spans_disabled_by_default():
    stmt = sqlparse.parse('select 1')[0]
    assert stmt.source_span is None
    for token in stmt.flatten():
        assert token.source_span is None
        assert token.source_text('select 1') is None
        assert token.byte_span('select 1') is None


def test_leaf_spans_match_source_slices():
    source = 'select a, b from foo where a > 10'
    stmt = sqlparse.parse(source, with_spans=True)[0]
    end = _assert_leaf_spans(source, stmt)
    assert stmt.source_span == (0, end)
    assert source[0:end] == str(stmt)


def test_group_spans_come_from_children():
    source = 'select a, f(b, c) from foo where a > 1'
    stmt = sqlparse.parse(source, with_spans=True)[0]
    _assert_leaf_spans(source, stmt)
    _assert_group_spans(source, stmt)
    # The WHERE group must line up with the source text, not a search.
    where = stmt.token_next_by(i=sql.Where)[1]
    start, end = where.source_span
    assert source[start:end] == 'where a > 1'
    assert start == source.index('where')


def test_duplicate_fragments_get_distinct_spans():
    source = 'select a from t1 where a = 1 and a = 2'
    stmt = sqlparse.parse(source, with_spans=True)[0]
    names = [t for t in stmt.flatten() if t.value == 'a']
    assert len(names) == 3
    spans = [t.source_span for t in names]
    assert len(set(spans)) == 3
    for token in names:
        start, end = token.source_span
        assert source[start:end] == 'a'


def test_whitespace_comments_and_crlf():
    source = (
        'select  a,\r\n'
        '  -- a comment\r\n'
        '  /* multi\r\n line */ b\r\n'
        'from  t;\r\n'
    )
    stmt = sqlparse.parse(source, with_spans=True)[0]
    end = _assert_leaf_spans(source, stmt)
    _assert_group_spans(source, stmt)
    assert source[:end] == str(stmt)
    stmt = sqlparse.parse(source, with_spans=True)[0]
    end = _assert_leaf_spans(source, stmt)
    _assert_group_spans(source, stmt)
    assert source[:end] == str(stmt)
    # The trailing whitespace-only remnant is not part of any statement.
    assert source[end:] == '\r\n'


def test_supplementary_plane_unicode():
    source = ('-- ' + chr(0x1F600) * 2 + ' comment' + chr(10)
            + 'select ' + chr(39) + chr(0x1D4B3) + chr(39) + ' as x;'
            + chr(10))
    stmt = sqlparse.parse(source, with_spans=True)[0]
    _assert_leaf_spans(source, stmt)
    _assert_group_spans(source, stmt)
    _assert_leaf_spans(source, stmt)
    _assert_group_spans(source, stmt)
    comment = next(t for t in stmt.flatten()
                   if t.ttype == T.Comment.Single)
    start, end = comment.source_span
    assert source[start:end] == comment.value
    assert start == 0


def test_multiple_statements_keep_offsets():
    source = 'select 1;\nselect 2; -- tail\nselect 3'
    stmts = sqlparse.parse(source, with_spans=True)
    assert len(stmts) == 3
    for stmt in stmts:
        _assert_leaf_spans(source, stmt)
        start, end = stmt.source_span
        assert source[start:end] == str(stmt)
    # Statement spans appear in source order and do not overlap.
    spans = [stmt.source_span for stmt in stmts]
    assert spans == sorted(spans)
    for (_, prev_end), (next_start, _) in itertools.pairwise(spans):
        assert prev_end <= next_start
    # The second statement head starts at its own text, not the first
    # occurrence of the same fragment.
    head = stmts[1].token_first()
    assert head.source_span[0] == source.index('select 2')


def test_parsestream_with_spans():
    source = 'select 1; select 2'
    stmts = list(sqlparse.parsestream(io.StringIO(source), with_spans=True))
    assert len(stmts) == 2
    for stmt in stmts:
        _assert_leaf_spans(source, stmt)


def test_source_text_helper():
    source = 'select abc from foo'
    stmt = sqlparse.parse(source, with_spans=True)[0]
    for token in stmt.flatten():
        assert token.source_text(source) == token.value
    assert stmt.source_text(source) == str(stmt)


@pytest.mark.parametrize('encoding', ['utf-8', 'utf-16-le', 'latin-1'])
def test_byte_spans(encoding):
    source = ('select ' + chr(39) + chr(0x1F600) + chr(39)
            + ' as x -- ' + chr(0xFC) + chr(10))
    if encoding == 'latin-1':
        # latin-1 cannot encode the emoji; use an encodable source.
        source = 'select a -- ' + chr(0xFC) + chr(10)
    stmt = sqlparse.parse(source, with_spans=True)[0]
    encoded = source.encode(encoding)
    for token in stmt.flatten():
        bstart, bend = token.byte_span(source, encoding)
        assert encoded[bstart:bend] == token.value.encode(encoding)
    # Group byte spans work too.
    bstart, bend = stmt.byte_span(source, encoding)
    assert encoded[bstart:bend] == str(stmt).encode(encoding)


def test_byte_span_without_span_is_none():
    token = sql.Token(T.Name, 'x')
    assert token.source_span is None
    assert token.byte_span('x') is None


def test_tokens_created_by_filters_have_no_span():
    source = 'select a from foo'
    stack = engine.FilterStack(with_spans=True)
    stack.enable_grouping()
    options = formatter.validate_options({'reindent': True})
    stack = formatter.build_filter_stack(stack, options)
    stmt = next(iter(stack.run(source)))
    leaves = list(stmt.flatten())
    # Reindenting inserted new whitespace tokens without spans...
    assert any(t.source_span is None for t in leaves)
    # ...while untouched tokens keep valid source positions.
    keywords = [t for t in leaves if t.is_keyword]
    assert keywords
    for token in keywords:
        assert token.source_span is not None
        start, end = token.source_span
        assert source[start:end] == token.value
    # Every token that still has a span must slice correctly.
    for token in leaves:
        if token.source_span is not None:
            start, end = token.source_span
            assert source[start:end] == token.value


def test_group_without_original_children_has_no_span():
    token = sql.Token(T.Whitespace, ' ')
    group = sql.Parenthesis([token])
    assert token.source_span is None
    assert group.source_span is None


def test_group_span_ignores_spanless_children():
    source = 'select a'
    stmt = sqlparse.parse(source, with_spans=True)[0]
    leaves = list(stmt.flatten())
    first, last = leaves[0], leaves[-1]
    # A group mixing original tokens with synthesized ones derives its
    # span from the original children only.
    group = sql.Identifier([
        sql.Token(T.Whitespace, ''),
        first,
        sql.Token(T.Whitespace, '  '),
        last,
    ])
    assert group.source_span == (first.source_span[0], last.source_span[1])
    start, end = group.source_span
    assert source[start:end] == 'select a'
