"""Tests for structural SQL fingerprints."""

import pytest

import sqlparse


def digest(sql, **options):
    return sqlparse.fingerprint(sql, **options).digest


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (
            "select a,b from t where id=42 and nm='alice'",
            "SELECT a, b\nFROM t\nWHERE id = 7 AND nm = 'bob'",
            "SELECT a, b FROM t WHERE id = ? AND nm = ?",
        ),
        (
            "select * from t where x in (?, :id, 42)",
            "select * from t where x in ($id, %s, 9)",
            "SELECT * FROM t WHERE x IN (?, ?, ?)",
        ),
        (
            "select * from t where x = -3",
            "select * from t where x = -03",
            "SELECT * FROM t WHERE x = -?",
        ),
        (
            "select * from t where x = -3",
            "select * from t where x = -?",
            "SELECT * FROM t WHERE x = -?",
        ),
        (
            "select /*+ INDEX(t idx) */ * from t",
            "select /*+  INDEX(t   idx) */\n*\nfrom t",
            "SELECT /*+ INDEX(t idx) */ * FROM t",
        ),
        (
            "select --+ index(t idx)\n* from t",
            "select --+  index(t   idx)\n* from t",
            "SELECT --+ index(t idx)\n* FROM t",
        ),
    ],
)
def test_fingerprint_groups_equivalent_structure(left, right, expected):
    left_fingerprint = sqlparse.fingerprint(left)
    right_fingerprint = sqlparse.fingerprint(right)

    assert left_fingerprint.normalized == expected
    assert right_fingerprint.normalized == expected
    assert left_fingerprint.digest == right_fingerprint.digest


@pytest.mark.parametrize(
    ("left", "right", "options"),
    [
        (
            "create table t (x decimal(10,2))",
            "create table t (x decimal(10,3))",
            {},
        ),
        (
            "select a from t order by 1",
            "select a from t order by 2",
            {},
        ),
        (
            'select "Col1" from t',
            'select "col1" from t',
            {},
        ),
        (
            "select * from t where x in (1, 2)",
            "select * from t where x in (1, 2, 3)",
            {},
        ),
        (
            "select * from t where x in ((1, 2), (3, 4))",
            "select * from t where x in ((1, 2, 3), (4, 5, 6))",
            {"fold_in_lists": True},
        ),
        (
            "select * from t where x in ((1, 2), (3, 4))",
            "select * from t where x in (1, 2, 3, 4)",
            {"fold_in_lists": True},
        ),
        (
            "select * from t where x in (select id from s)",
            "select * from t where x in (1, 2)",
            {"fold_in_lists": True},
        ),
        (
            "select * from t where x in (abs(1), 2)",
            "select * from t where x in (1, 2)",
            {"fold_in_lists": True},
        ),
        (
            "select * from t where x in (date '2020-01-01', 1)",
            "select * from t where x in (1, 2)",
            {"fold_in_lists": True},
        ),
        (
            "select a",
            "select a; select b",
            {},
        ),
    ],
)
def test_fingerprint_keeps_structural_differences(left, right, options):
    assert digest(left, **options) != digest(right, **options)


def test_fold_in_lists_is_explicit():
    left = "select * from t where x in (1, 2)"
    right = "select * from t where x in (1, 2, 3)"

    assert digest(left) != digest(right)
    assert digest(left, fold_in_lists=True) == digest(
        right, fold_in_lists=True
    )
    assert sqlparse.fingerprint(
        right, fold_in_lists=True
    ).normalized == "SELECT * FROM t WHERE x IN (?)"


def test_single_item_in_list_can_fold():
    result = sqlparse.fingerprint(
        "select * from t where x in (1)", fold_in_lists=True
    )
    assert result.normalized == "SELECT * FROM t WHERE x IN (?)"


def test_type_parameters_are_retained():
    result = sqlparse.fingerprint(
        "create table t (x decimal(10,2), y varchar(255))"
    )
    assert result.normalized == (
        "CREATE TABLE t(x DECIMAL(10, 2), y VARCHAR(255))"
    )


def test_order_by_position_is_retained():
    result = sqlparse.fingerprint(
        "select a, b from t order by 1, 2 desc, x"
    )
    assert result.normalized == (
        "SELECT a, b FROM t ORDER BY 1, 2 DESC, x"
    )


def test_parenthesized_order_by_position_is_retained():
    result = sqlparse.fingerprint("select a, b from t order by (1)")
    assert result.normalized == "SELECT a, b FROM t ORDER BY (1)"


def test_comment_markers_inside_strings_are_literals():
    result = sqlparse.fingerprint(
        "select '-- not a comment', '/* also not */' from dual"
    )
    assert result.normalized == "SELECT ?, ? FROM dual"


def test_quoted_identifiers_are_retained():
    result = sqlparse.fingerprint('select "Mixed Case" from t')
    assert result.normalized == 'SELECT "Mixed Case" FROM t'


def test_multiple_statements_keep_statement_count():
    result = sqlparse.fingerprint(
        "select a from t;; select b from t;"
    )
    assert result.normalized == (
        "SELECT a FROM t; ; SELECT b FROM t"
    )
    assert digest("select a from t") != result.digest


def test_digest_is_stable_sha256():
    sql = "select * from t where id = 1"
    result = sqlparse.fingerprint(sql)

    assert result.digest == sqlparse.fingerprint(sql).digest
    assert len(result.digest) == 64
    assert all(char in "0123456789abcdef" for char in result.digest)


def test_fingerprint_is_structural_not_semantic_equivalence():
    assert "not proof" in sqlparse.SQLFingerprint.__doc__
    assert "semantically equivalent" in sqlparse.SQLFingerprint.__doc__
