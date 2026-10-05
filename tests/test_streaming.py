#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

import os
import random

import pytest

import sqlparse
from sqlparse.engine.streaming import IncrementalTokenizer
from sqlparse.exceptions import (
    StreamLimitExceededError,
    UnclosedTokenError,
)

SQL_SAMPLE = (
    "SELECT a, b.c, [my col] FROM tbl\n"
    "WHERE x = 'it''s' AND y = $$dollar quoted$$ AND z = $tag$v$tag$;\n"
    'SELECT "double ""quoted""", `back``tick` FROM t2;\n'
    "-- a single line comment\n"
    "SELECT /* multi\nline */ /*+ hint */ 1;\n"
    "SELECT 0x1F, 1.5, .5, 1E3, -2 FROM t3 GROUP BY a ORDER BY b;\n"
    "SELECT %s, %(name)s, :1, :name, ? FROM t4;\n"
    "CREATE OR REPLACE FUNCTION f() RETURNS void AS $$\n"
    "BEGIN\n"
    "  RAISE NOTICE 'semi;colon';\n"
    "END;\n"
    "$$ LANGUAGE plpgsql;\n"
    "SELECT 'at ''end''';\n"
    "SELECT * FROM t5 WHERE a = 'back\\'slash';\n"
    "SELECT CASE WHEN a THEN 1 ELSE 2 END FROM t6;\n"
    "SELECT 1 UNION ALL SELECT 2;\n"
    "UPDATE t SET a = 1 WHERE b IN (1, 2, (SELECT 3));\n"
)


def _flatten(statements):
    return [(t.ttype, t.value) for stmt in statements
            for t in stmt.flatten()]


def _random_chunks(sql, seed):
    rng = random.Random(seed)
    chunks = []
    pos = 0
    while pos < len(sql):
        n = rng.randint(1, 17)
        chunks.append(sql[pos:pos + n])
        pos += n
    return chunks


@pytest.mark.parametrize('chunks', [
    [SQL_SAMPLE],
    list(SQL_SAMPLE),
    _random_chunks(SQL_SAMPLE, 42),
    _random_chunks(SQL_SAMPLE, 7),
])
def test_equivalent_to_batch_parse(chunks):
    expected = sqlparse.parse(SQL_SAMPLE)
    result = list(sqlparse.parsechunks(iter(chunks)))
    assert [str(s) for s in result] == [str(s) for s in expected]
    assert _flatten(result) == _flatten(expected)


@pytest.mark.parametrize('filename', [
    'function_psql.sql',
    'casewhen_procedure.sql',
    'dashcomment.sql',
    'multiple_case_in_begin.sql',
])
def test_equivalent_to_batch_parse_for_files(filename):
    path = os.path.join(os.path.dirname(__file__), 'files', filename)
    with open(path, encoding='utf-8') as f:
        sql = f.read()
    expected = sqlparse.parse(sql)
    # one chunk, character by character and random chunk sizes
    for chunks in ([sql], list(sql), _random_chunks(sql, 1)):
        result = list(sqlparse.parsechunks(iter(chunks)))
        assert [str(s) for s in result] == [str(s) for s in expected]
        assert _flatten(result) == _flatten(expected)


@pytest.mark.parametrize('sql', [
    'SELECT a FROM t ORDER BY a ASC NULLS FIRST;',
    'SELECT a FROM t ORDER BY a DESC NULLS LAST;',
    "SELECT 'at ''end''';",
    "SELECT 'a\\'b';",
    'SELECT "dq ""x""" FROM t;',
    'SELECT `bt``x` FROM t;',
    'SELECT [my col] FROM t;',
    'SELECT $tag$body$tag$, $$x$$;',
    'SELECT /*+ hint */ /* c */ 1;',
    'SELECT 1 -- trailing comment',
    'SELECT %s, %(name)s, :1, ?;',
    'SELECT 0x1F, 1.5, .5, 1E3, -2;',
    'SELECT CASE WHEN a THEN 1 ELSE 2 END FROM t;',
    'SELECT 1 UNION ALL SELECT 2;',
    'CREATE OR REPLACE VIEW v AS SELECT 1;',
    'SELECT * FROM t WHERE ts AT TIME ZONE \'utc\' = 1;',
    'SELECT a . b FROM t;',
    'PREPARE stmt FROM \'SELECT 1\';',
    'SELECT 1 GO SELECT 2 GO',
])
def test_all_two_way_splits(sql):
    expected = sqlparse.parse(sql)
    expected_str = None
    for i in range(len(sql) + 1):
        result = list(sqlparse.parsechunks(iter([sql[:i], sql[i:]])))
        if expected_str is None:
            expected_str = [str(s) for s in expected]
        assert [str(s) for s in result] == expected_str, i
        assert _flatten(result) == _flatten(expected), i


def test_input_is_consumed_only_once():
    class OneShot:
        def __init__(self):
            self.iterated = False

        def __iter__(self):
            assert not self.iterated, 'input was iterated twice'
            self.iterated = True
            return iter(['SELECT 1;', 'SELECT 2;'])

    result = list(sqlparse.parsechunks(OneShot()))
    assert [str(s) for s in result] == ['SELECT 1;', 'SELECT 2;']


def test_empty_chunks_are_skipped():
    chunks = ['', 'SELECT ', '', '1;', '', '', 'SELECT 2;', '']
    result = list(sqlparse.parsechunks(iter(chunks)))
    assert [str(s) for s in result] == ['SELECT 1;', 'SELECT 2;']


def test_non_string_chunk_raises():
    with pytest.raises(TypeError):
        list(sqlparse.parsechunks([b'SELECT 1;']))


def test_chunk_end_is_not_statement_end():
    # A statement is only produced once it is really closed; the end
    # of a chunk must not be mistaken for the end of the input.
    chunks = ['SELECT 1', '; SELECT 2;']
    result = list(sqlparse.parsechunks(iter(chunks)))
    assert [str(s).strip() for s in result] == ['SELECT 1;', 'SELECT 2;']


def test_trailing_statement_without_semicolon():
    result = list(sqlparse.parsechunks(['SELECT 1']))
    assert [str(s) for s in result] == ['SELECT 1']


def test_string_escape_at_chunk_boundary():
    # 'ab''cd' is a single string literal with an escaped quote.
    chunks = ["SELECT 'ab", "'", "'cd';"]
    result = list(sqlparse.parsechunks(iter(chunks)))
    assert [str(s) for s in result] == ["SELECT 'ab''cd';"]


def test_backslash_escape_at_chunk_boundary():
    chunks = ["SELECT 'ab\\", "'", "';"]
    result = list(sqlparse.parsechunks(iter(chunks)))
    assert [str(s) for s in result] == ["SELECT 'ab\\'';"]


def test_dollar_quote_opener_split_across_chunks():
    chunks = ['SELECT $ta', 'g$body$ta', 'g$;']
    result = list(sqlparse.parsechunks(iter(chunks)))
    assert [str(s) for s in result] == ['SELECT $tag$body$tag$;']


def test_comment_split_across_chunks():
    chunks = ['SELECT 1 /* com', 'ment */', ' /*+ hi', 'nt */;']
    result = list(sqlparse.parsechunks(iter(chunks)))
    assert [str(s) for s in result] == ['SELECT 1 /* comment */ /*+ hint */;']


def test_multiword_keyword_split_across_chunks():
    chunks = ['SELECT a FROM t GROUP', ' ', 'BY a', ';']
    result = list(sqlparse.parsechunks(iter(chunks)))
    expected = sqlparse.parse('SELECT a FROM t GROUP BY a;')
    assert _flatten(result) == _flatten(expected)


def test_procedure_body_matches_split():
    sql = (
        'CREATE OR REPLACE FUNCTION f() RETURNS void AS $$\n'
        'BEGIN\n'
        "  RAISE NOTICE 'semi;colon';\n"
        'END;\n'
        '$$ LANGUAGE plpgsql;\n'
        'SELECT 1;'
    )
    result = list(sqlparse.parsechunks(iter(list(sql))))
    assert len(result) == 2
    assert [str(s).strip() for s in result] == sqlparse.split(sql)


def test_statements_are_produced_before_input_is_exhausted():
    pulled = 0
    total = 500

    def source():
        nonlocal pulled
        for i in range(total):
            pulled += 1
            yield f'SELECT {i};\n'

    statements = sqlparse.parsechunks(source())
    first = next(statements)
    assert str(first).strip() == 'SELECT 0;'
    # the first statement is produced long before the input ends
    assert pulled < total
    count = 1 + sum(1 for _ in statements)
    assert count == total
    assert pulled == total


def test_buffer_stays_bounded_for_many_small_statements():
    tokenizer = IncrementalTokenizer()
    emitted = 0
    for i in range(2000):
        emitted += len(tokenizer.feed(f'SELECT {i};'))
        assert len(tokenizer._pending) <= 1
    emitted += len(tokenizer.finish())
    assert emitted > 0


@pytest.mark.parametrize('sql', [
    "SELECT 'abc",
    'SELECT "abc',
    'SELECT `abc',
    'SELECT $$abc',
    'SELECT $tag$abc',
    'SELECT /* abc',
    'SELECT /*+ abc',
])
def test_unclosed_constructs_raise(sql):
    with pytest.raises(UnclosedTokenError):
        list(sqlparse.parsechunks([sql]))


def test_unclosed_construct_raises_after_complete_statements():
    statements = sqlparse.parsechunks(['SELECT 1;', "SELECT 'abc"])
    assert str(next(statements)).strip() == 'SELECT 1;'
    with pytest.raises(UnclosedTokenError):
        next(statements)


def test_max_token_size_stops_unterminated_token():
    def source():
        yield "SELECT '"
        while True:
            yield 'x' * 100

    with pytest.raises(StreamLimitExceededError):
        list(sqlparse.parsechunks(source(), max_token_size=500))


def test_max_statement_size_stops_long_statement():
    def source():
        yield 'SELECT '
        while True:
            yield 'x, '

    with pytest.raises(StreamLimitExceededError):
        list(sqlparse.parsechunks(source(), max_statement_size=100))


def test_max_statement_size():
    with pytest.raises(StreamLimitExceededError):
        list(sqlparse.parsechunks(['SELECT ' + 'x' * 100 + ';'],
                                  max_statement_size=50))
