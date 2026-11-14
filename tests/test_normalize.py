import pytest

import sqlparse
from sqlparse.filters.others import normalize_for_matching
from sqlparse.sql import NormalizedView


def test_comment_glues_keyword_and_maps_back():
    view = normalize_for_matching('UN/**/ION SEL/**/ECT')
    assert view.text == 'UNION SELECT'
    # the hit in the normalized text maps back to the original range
    assert view.original_span(0, 5) == (0, 9)
    assert view.original_span(6, 12) == (10, 20)
    assert list(view.find_all('UNION')) == [(0, 9)]


def test_string_contents_are_kept_verbatim():
    view = normalize_for_matching("SELECT 'a--b'")
    assert view.text == "SELECT 'a--b'"
    # the '--' inside the string is not treated as a comment
    assert view.original_span(7, 13) == (7, 13)


def test_quoted_identifier_and_dollar_quote_untouched():
    view = normalize_for_matching(
        'select $$a--b$$, "Quoted Id" from t')
    assert view.text == 'SELECT $$a--b$$, "Quoted Id" FROM t'


def test_whitespace_is_collapsed():
    view = normalize_for_matching('SELECT   a ,\n\t b')
    assert view.text == 'SELECT a , b'


def test_line_comment_separates_tokens():
    view = normalize_for_matching('a--x\nFROM t')
    assert view.text == 'a FROM t'


def test_unclosed_block_comment_swallows_rest():
    view = normalize_for_matching('SELECT /* unclosed')
    assert view.text == 'SELECT'


def test_postgres_nested_comments():
    view = normalize_for_matching(
        '/* a /* b */ c */ SELECT 1', dialect='postgres')
    assert view.text == 'SELECT 1'
    # without nesting the tail of the comment stays visible
    view = normalize_for_matching('/* a /* b */ c */ SELECT 1')
    assert view.text == 'c */ SELECT 1'


def test_postgresql_alias():
    view = normalize_for_matching(
        '/* a /* b */ c */ SELECT 1', dialect='postgresql')
    assert view.text == 'SELECT 1'


def test_mysql_hash_comment_without_space():
    view = normalize_for_matching('SELECT 1 #c\nFROM t', dialect='mysql')
    assert view.text == 'SELECT 1 FROM t'


def test_mysql_executable_comment_is_unwrapped():
    view = normalize_for_matching(
        'SELECT /*!50000 UNION */ 1', dialect='mysql')
    assert view.text == 'SELECT UNION 1'
    assert list(view.find_all('UNION')) == [(16, 21)]
    # other dialects treat it as a plain comment
    view = normalize_for_matching('SELECT /*!50000 UNION */ 1')
    assert view.text == 'SELECT 1'


def test_postgres_escape_string_keeps_comment_chars():
    view = normalize_for_matching("SELECT E'a\\'--b'")
    assert view.text == "SELECT E'a\\'--b'"


@pytest.mark.parametrize('sql_text, dialect', [
    ('UN/**/ION SEL/**/ECT', None),
    ('sel/**/ect a', None),  # joined names form a keyword on pass two
    ("SELECT 'a--b'", None),
    ('SELECT /* unclosed', None),
    ('/* a /* b */ c */ SELECT 1', 'postgres'),
    ('SELECT 1 #c\nFROM t', 'mysql'),
    ('SELECT /*!50000 UNION */ 1', 'mysql'),
    ('select 1 /**/ union /**/ select 2', None),
])
def test_normalization_is_idempotent(sql_text, dialect):
    view = normalize_for_matching(sql_text, dialect=dialect)
    again = normalize_for_matching(view.text, dialect=dialect)
    assert again.text == view.text


def test_unknown_dialect_rejected():
    with pytest.raises(ValueError):
        normalize_for_matching('SELECT 1', dialect='oracle')


def test_statement_hook():
    stmt = sqlparse.parse('UN/**/ION SEL/**/ECT')[0]
    view = stmt.get_normalized_view()
    assert isinstance(view, NormalizedView)
    assert view.text == 'UNION SELECT'


def test_parse_and_format_output_unchanged():
    sql_text = "UN/**/ION SEL/**/ECT 'a--b'"
    stmt, = sqlparse.parse(sql_text)
    assert str(stmt) == sql_text
    assert [t.value for t in stmt.flatten()] == [
        'UN', '/**/', 'ION', ' ', 'SEL', '/**/', 'ECT', ' ', "'a--b'"]
    assert sqlparse.format("select 'a--b'", keyword_case='upper') \
        == "SELECT 'a--b'"
