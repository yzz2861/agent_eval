"""Tests for sqlparse.fingerprint."""

import hashlib

import pytest

import sqlparse
from sqlparse import fingerprint


def _grouped(*sqls, **options):
    """Assert that all statements share one fingerprint."""
    prints = [fingerprint(sql, **options) for sql in sqls]
    first = prints[0]
    for other in prints[1:]:
        assert other.normalized == first.normalized
        assert other.digest == first.digest
    return first


def _separated(*sqls, **options):
    """Assert that no two statements share a fingerprint."""
    prints = [fingerprint(sql, **options) for sql in sqls]
    digests = [fp.digest for fp in prints]
    assert len(set(digests)) == len(digests)
    return prints


def test_result_fields():
    fp = fingerprint("SELECT 1")
    assert isinstance(fp, sqlparse.Fingerprint)
    assert fp.digest == hashlib.sha256(fp.normalized.encode("utf-8")).hexdigest()


def test_digest_is_stable():
    assert fingerprint("SELECT a FROM t WHERE b = 1").digest == \
        fingerprint("SELECT a FROM t WHERE b = 1").digest


def test_normalized_text():
    fp = fingerprint("select  a, 'x'  from t where b=-5 and c in (1,2)")
    assert fp.normalized == \
        "SELECT a, ? FROM t WHERE b = -? AND c IN (?, ?)"


@pytest.mark.parametrize("sqls", [
    # value literals of every flavor collapse to the placeholder
    ("SELECT * FROM t WHERE a = 5", "SELECT * FROM t WHERE a = 97"),
    ("SELECT * FROM t WHERE a = 1.5", "SELECT * FROM t WHERE a = 2e3"),
    ("SELECT * FROM t WHERE a = 'x'", "SELECT * FROM t WHERE a = 'y y'"),
    # keyword case and insignificant whitespace are normalized
    ("select a from t where b = 1", "SELECT  a\nFROM   t WHERE b = 2"),
    # placeholders and literals are all value slots
    ("SELECT * FROM t WHERE a = ?", "SELECT * FROM t WHERE a = %s"),
    ("SELECT * FROM t WHERE a = :name", "SELECT * FROM t WHERE a = 42"),
    # the sign is preserved, the magnitude is not
    ("SELECT * FROM t WHERE a = -1", "SELECT * FROM t WHERE a = -99"),
    # plain comments carry no meaning
    ("SELECT a /* note */ FROM t", "SELECT a FROM t -- tail"),
    # comment markers inside strings are string content
    ("SELECT * FROM t WHERE s = 'a -- b'", "SELECT * FROM t WHERE s = 'x /* y'"),
    # a trailing semicolon is statement syntax, not content
    ("SELECT 1", "SELECT 1;"),
    # same shape in multiple statements
    ("SELECT 1; SELECT 2", "SELECT 3; SELECT 4"),
])
def test_should_group(sqls):
    _grouped(*sqls)


@pytest.mark.parametrize("sqls", [
    # type parameters are part of the declaration, not values
    ("CREATE TABLE t (a DECIMAL(10, 2))", "CREATE TABLE t (a DECIMAL(12, 4))"),
    ("SELECT CAST(x AS DECIMAL(10, 2))", "SELECT CAST(x AS DECIMAL(10, 3))"),
    # column positions in ORDER BY / GROUP BY are not values
    ("SELECT a, b FROM t ORDER BY 1", "SELECT a, b FROM t ORDER BY 2"),
    ("SELECT a FROM t GROUP BY 1", "SELECT a FROM t GROUP BY 2"),
    # a negative literal is not a positive literal
    ("SELECT * FROM t WHERE a = -1", "SELECT * FROM t WHERE a = 1"),
    # a binary minus is not a sign on a literal
    ("SELECT * FROM t WHERE a = b - 1", "SELECT * FROM t WHERE a = -1"),
    # quoted identifiers are kept verbatim
    ('SELECT "a" FROM t', 'SELECT "b" FROM t'),
    ("SELECT `a` FROM t", "SELECT `b` FROM t"),
    # optimizer hints are significant
    ("SELECT /*+ INDEX(t i) */ a FROM t", "SELECT /*+ FULL(t) */ a FROM t"),
    ("SELECT /*+ INDEX(t i) */ a FROM t", "SELECT a FROM t"),
    # different nesting structure
    ("SELECT (a + b) FROM t", "SELECT a + b FROM t"),
    # different statement counts
    ("SELECT 1", "SELECT 1; SELECT 2"),
    ("SELECT 1; SELECT 2", "SELECT 1; SELECT 2; SELECT 3"),
    # different placeholder counts
    ("SELECT * FROM t WHERE a = ?", "SELECT * FROM t WHERE a = ? AND b = ?"),
])
def test_must_separate(sqls):
    _separated(*sqls)


def test_in_list_arity_preserved_by_default():
    _separated(
        "SELECT * FROM t WHERE a IN (1, 2)",
        "SELECT * FROM t WHERE a IN (1, 2, 3)",
    )


def test_in_list_collapse_option():
    fp = _grouped(
        "SELECT * FROM t WHERE a IN (1, 2)",
        "SELECT * FROM t WHERE a IN (1, 2, 3)",
        "SELECT * FROM t WHERE a IN ('x', 'y', 'z', ?)",
        collapse_in_lists=True,
    )
    assert "IN (?)" in fp.normalized
    fp_not = fingerprint(
        "SELECT * FROM t WHERE a NOT IN (1, 2)", collapse_in_lists=True)
    assert "NOT IN (?)" in fp_not.normalized


def test_in_list_collapse_keeps_subqueries_and_expressions():
    _separated(
        "SELECT * FROM t WHERE a IN (1, 2)",
        "SELECT * FROM t WHERE a IN (SELECT b FROM u)",
        "SELECT * FROM t WHERE a IN (1 + 2, 3)",
        collapse_in_lists=True,
    )


def test_multi_statement_normalization():
    fp = fingerprint("select 1; select 'x'")
    assert fp.normalized == "SELECT ?; SELECT ?"


def test_empty_input():
    fp = fingerprint("")
    assert fp.normalized == ""
    assert fp.digest == hashlib.sha256(b"").hexdigest()


def test_encoding_parameter():
    fp = fingerprint("SELECT '\\xe4\\xf6\\xfc'", encoding="latin-1")
    assert fp.normalized == "SELECT ?"
