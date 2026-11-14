# Tests splitting functions.

import types
from io import StringIO

import pytest

import sqlparse
from sqlparse import lexstate
from sqlparse import tokens as T
from sqlparse.exceptions import SQLParseError


def test_split_semicolon():
    sql1 = 'select * from foo;'
    sql2 = "select * from foo where bar = 'foo;bar';"
    stmts = sqlparse.parse(''.join([sql1, sql2]))
    assert len(stmts) == 2
    assert str(stmts[0]) == sql1
    assert str(stmts[1]) == sql2


def test_split_backslash():
    stmts = sqlparse.parse("select '\'; select '\'';")
    assert len(stmts) == 2


@pytest.mark.parametrize('fn', ['function.sql',
                                'function_psql.sql',
                                'function_psql2.sql',
                                'function_psql3.sql',
                                'function_psql4.sql'])
def test_split_create_function(load_file, fn):
    sql = load_file(fn)
    stmts = sqlparse.parse(sql)
    assert len(stmts) == 1
    assert str(stmts[0]) == sql


def test_split_dashcomments(load_file):
    sql = load_file('dashcomment.sql')
    stmts = sqlparse.parse(sql)
    assert len(stmts) == 3
    assert ''.join(str(q) for q in stmts) == sql


@pytest.mark.parametrize('s', ['select foo; -- comment\n',
                               'select foo; -- comment\r',
                               'select foo; -- comment\r\n',
                               'select foo; -- comment'])
def test_split_dashcomments_eol(s):
    stmts = sqlparse.parse(s)
    assert len(stmts) == 1


def test_split_begintag(load_file):
    sql = load_file('begintag.sql')
    stmts = sqlparse.parse(sql)
    assert len(stmts) == 3
    assert ''.join(str(q) for q in stmts) == sql


def test_split_begintag_2(load_file):
    sql = load_file('begintag_2.sql')
    stmts = sqlparse.parse(sql)
    assert len(stmts) == 1
    assert ''.join(str(q) for q in stmts) == sql


def test_split_dropif():
    sql = 'DROP TABLE IF EXISTS FOO;\n\nSELECT * FROM BAR;'
    stmts = sqlparse.parse(sql)
    assert len(stmts) == 2
    assert ''.join(str(q) for q in stmts) == sql


def test_split_comment_with_umlaut():
    sql = ('select * from foo;\n'
           '-- Testing an umlaut: ä\n'
           'select * from bar;')
    stmts = sqlparse.parse(sql)
    assert len(stmts) == 2
    assert ''.join(str(q) for q in stmts) == sql


def test_split_comment_end_of_line():
    sql = ('select * from foo; -- foo\n'
           'select * from bar;')
    stmts = sqlparse.parse(sql)
    assert len(stmts) == 2
    assert ''.join(str(q) for q in stmts) == sql
    # make sure the comment belongs to first query
    assert str(stmts[0]) == 'select * from foo; -- foo\n'


def test_split_casewhen():
    sql = ("SELECT case when val = 1 then 2 else null end as foo;\n"
           "comment on table actor is 'The actor table.';")
    stmts = sqlparse.split(sql)
    assert len(stmts) == 2


def test_split_casewhen_procedure(load_file):
    # see issue580
    stmts = sqlparse.split(load_file('casewhen_procedure.sql'))
    assert len(stmts) == 2


def test_split_cursor_declare():
    sql = ('DECLARE CURSOR "foo" AS SELECT 1;\n'
           'SELECT 2;')
    stmts = sqlparse.split(sql)
    assert len(stmts) == 2


def test_split_if_function():  # see issue 33
    # don't let IF as a function confuse the splitter
    sql = ('CREATE TEMPORARY TABLE tmp '
           'SELECT IF(a=1, a, b) AS o FROM one; '
           'SELECT t FROM two')
    stmts = sqlparse.split(sql)
    assert len(stmts) == 2


def test_split_stream():
    stream = StringIO("SELECT 1; SELECT 2;")
    stmts = sqlparse.parsestream(stream)
    assert isinstance(stmts, types.GeneratorType)
    assert len(list(stmts)) == 2


def test_split_encoding_parsestream():
    stream = StringIO("SELECT 1; SELECT 2;")
    stmts = list(sqlparse.parsestream(stream))
    assert isinstance(stmts[0].tokens[0].value, str)


def test_split_unicode_parsestream():
    stream = StringIO('SELECT ö')
    stmts = list(sqlparse.parsestream(stream))
    assert str(stmts[0]) == 'SELECT ö'


def test_split_simple():
    stmts = sqlparse.split('select * from foo; select * from bar;')
    assert len(stmts) == 2
    assert stmts[0] == 'select * from foo;'
    assert stmts[1] == 'select * from bar;'


def test_split_ignores_empty_newlines():
    stmts = sqlparse.split('select foo;\nselect bar;\n')
    assert len(stmts) == 2
    assert stmts[0] == 'select foo;'
    assert stmts[1] == 'select bar;'


def test_split_quotes_with_new_line():
    stmts = sqlparse.split('select "foo\nbar"')
    assert len(stmts) == 1
    assert stmts[0] == 'select "foo\nbar"'

    stmts = sqlparse.split("select 'foo\n\bar'")
    assert len(stmts) == 1
    assert stmts[0] == "select 'foo\n\bar'"


def test_split_mysql_handler_for(load_file):
    # see issue581
    stmts = sqlparse.split(load_file('mysql_handler.sql'))
    assert len(stmts) == 2


@pytest.mark.parametrize('sql, expected', [
    ('select * from foo;', ['select * from foo']),
    ('select * from foo', ['select * from foo']),
    ('select * from foo; select * from bar;', [
        'select * from foo',
        'select * from bar',
    ]),
    ('  select * from foo;\n\nselect * from bar;\n\n\n\n', [
        'select * from foo',
        'select * from bar',
    ]),
    ('select * from foo\n\n;  bar', ['select * from foo', 'bar']),
])
def test_split_strip_semicolon(sql, expected):
    stmts = sqlparse.split(sql, strip_semicolon=True)
    assert len(stmts) == len(expected)
    for idx, expectation in enumerate(expected):
        assert stmts[idx] == expectation


def test_split_strip_semicolon_procedure(load_file):
    stmts = sqlparse.split(load_file('mysql_handler.sql'),
                           strip_semicolon=True)
    assert len(stmts) == 2
    assert stmts[0].endswith('end')
    assert stmts[1].endswith('end')

@pytest.mark.parametrize('sql, num', [
    ('USE foo;\nGO\nSELECT 1;\nGO', 4),
    ('SELECT * FROM foo;\nGO', 2),
    ('USE foo;\nGO 2\nSELECT 1;', 3)
])
def test_split_go(sql, num):  # issue762
    stmts = sqlparse.split(sql)
    assert len(stmts) == num


def test_split_multiple_case_in_begin(load_file):  # issue784
    stmts = sqlparse.split(load_file('multiple_case_in_begin.sql'))
    assert len(stmts) == 1


def test_split_if_exists_in_begin_end():  # issue812
    # IF EXISTS should not be confused with control flow IF
    sql = """CREATE TASK t1 AS
BEGIN
    CREATE OR REPLACE TABLE temp1;
    DROP TABLE IF EXISTS temp1;
END;
EXECUTE TASK t1;"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 2
    assert 'CREATE TASK' in stmts[0]
    assert 'EXECUTE TASK' in stmts[1]


def test_split_begin_end_semicolons():  # issue809
    # Semicolons inside BEGIN...END blocks should not split statements
    sql = """WITH
FUNCTION meaning_of_life()
  RETURNS tinyint
  BEGIN
    DECLARE a tinyint DEFAULT CAST(6 as tinyint);
    DECLARE b tinyint DEFAULT CAST(7 as tinyint);
    RETURN a * b;
  END
SELECT meaning_of_life();"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 1
    assert 'WITH' in stmts[0]
    assert 'SELECT meaning_of_life()' in stmts[0]


def test_split_begin_end_procedure():  # issue809
    # Test with CREATE PROCEDURE (BigQuery style)
    sql = """CREATE OR REPLACE PROCEDURE mydataset.create_customer()
BEGIN
  DECLARE id STRING;
  SET id = GENERATE_UUID();
  INSERT INTO mydataset.customers (customer_id)
    VALUES(id);
  SELECT FORMAT("Created customer %s", id);
END;"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 1
    assert 'CREATE OR REPLACE PROCEDURE' in stmts[0]


def test_split_begin_transaction():  # issue826
    # BEGIN TRANSACTION should not be treated as a block start
    sql = """BEGIN TRANSACTION;
DELETE FROM "schema"."table_a" USING "table_a_temp" WHERE "schema"."table_a"."id" = "table_a_temp"."id";
INSERT INTO "schema"."table_a" SELECT * FROM "table_a_temp";
END TRANSACTION;"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 4
    assert stmts[0] == 'BEGIN TRANSACTION;'
    assert stmts[1].startswith('DELETE')
    assert stmts[2].startswith('INSERT')
    assert stmts[3] == 'END TRANSACTION;'


def test_split_begin_transaction_formatted():  # issue826
    # Test with formatted SQL (newlines between BEGIN and TRANSACTION)
    sql = """BEGIN
TRANSACTION;
DELETE FROM "schema"."table_a" USING "table_a_temp" WHERE "schema"."table_a"."id" = "table_a_temp"."id";
INSERT INTO "schema"."table_a" SELECT * FROM "table_a_temp";
END
TRANSACTION;"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 4
    assert stmts[0] == 'BEGIN\nTRANSACTION;'
    assert stmts[1].startswith('DELETE')
    assert stmts[2].startswith('INSERT')
    assert stmts[3] == 'END\nTRANSACTION;'


def test_split_anonymous_begin_end_for():  # issue845 Case 1
    sql = """
BEGIN
    SELECT 1;
    FOR R DO
        SELECT 1;
    END FOR;
END;
"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 1
    assert "END FOR;" in stmts[0]


def test_split_anonymous_begin_end_case_inline():  # issue845 Case 2
    sql = """
BEGIN
    SELECT 1;
    IF 1 THEN
        SELECT CASE WHEN 1 THEN 2 ELSE 3 END AS COUNT;
    ELSE
        SELECT 2;
    END IF;
END;
"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 1
    assert "END AS COUNT;" in stmts[0]


def test_split_for_update_in_begin_end():
    # Verify that FOR UPDATE / FOR SHARE inside a BEGIN ... END block do not break level balancing
    sql = """
BEGIN
    SELECT * FROM foo FOR UPDATE;
    SELECT * FROM bar FOR SHARE;
END;
SELECT 3;
"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 2
    assert "SELECT 3;" in stmts[1]


def test_split_multiple_for_loops_in_begin_end():
    # Verify that multiple sequential loops inside a BEGIN ... END block balance correctly
    sql = """
BEGIN
    FOR x IN select_query LOOP
        SELECT 1;
    END LOOP;
    FOR y IN select_query LOOP
        SELECT 2;
    END LOOP;
END;
SELECT 3;
"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 2
    assert "SELECT 3;" in stmts[1]


def test_split_procedural_case_end_case():
    # Verify that CASE closed by END CASE inside a BEGIN block balances correctly
    sql = """
BEGIN
    CASE val
        WHEN 1 THEN SELECT 'one';
        WHEN 2 THEN SELECT 'two';
        ELSE SELECT 'other';
    END CASE;
END;
SELECT 3;
"""
    stmts = sqlparse.split(sql)
    assert len(stmts) == 2
    assert "SELECT 3;" in stmts[1]


def test_split_standalone_for_update():
    # Verify that standalone FOR UPDATE statements split correctly
    sql = "SELECT * FROM foo FOR UPDATE; SELECT 3;"
    stmts = sqlparse.split(sql)
    assert len(stmts) == 2
    assert stmts[0] == "SELECT * FROM foo FOR UPDATE;"
    assert stmts[1] == "SELECT 3;"


def test_split_dollar_quoted_function_body():
    # Semicolons inside a dollar-quoted function body must not split.
    sql = ("CREATE FUNCTION f() RETURNS void AS $$\n"
           "BEGIN\n"
           "  RAISE NOTICE 'one;';\n"
           "  RAISE NOTICE 'two;';\n"
           "END;\n"
           "$$ LANGUAGE plpgsql;\n"
           "SELECT 1;")
    stmts = sqlparse.split(sql)
    assert stmts == [
        ("CREATE FUNCTION f() RETURNS void AS $$\n"
         "BEGIN\n"
         "  RAISE NOTICE 'one;';\n"
         "  RAISE NOTICE 'two;';\n"
         "END;\n"
         "$$ LANGUAGE plpgsql;"),
        "SELECT 1;",
    ]


def test_split_dollar_quoted_tagged_body():
    sql = ("CREATE FUNCTION f() RETURNS void AS $body$\n"
           "  SELECT 1;\n"
           "  SELECT 2;\n"
           "$body$ LANGUAGE sql;\n"
           "SELECT 3;")
    stmts = sqlparse.split(sql)
    assert stmts == [
        ("CREATE FUNCTION f() RETURNS void AS $body$\n"
         "  SELECT 1;\n"
         "  SELECT 2;\n"
         "$body$ LANGUAGE sql;"),
        "SELECT 3;",
    ]


def test_split_nested_block_comment():
    # Semicolons inside nested block comments must not split.
    sql = 'SELECT 1 /* outer /* inner ; */ still ; comment */; SELECT 2;'
    stmts = sqlparse.split(sql)
    assert stmts == [
        'SELECT 1 /* outer /* inner ; */ still ; comment */;',
        'SELECT 2;',
    ]


def test_split_mysql_executable_comment():
    # MySQL executable comments are kept as statements of their own.
    sql = 'SELECT 1;\n/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE */;\nSELECT 2;'
    stmts = sqlparse.split(sql)
    assert stmts == [
        'SELECT 1;',
        '/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE */;',
        'SELECT 2;',
    ]


def test_split_mysql_executable_comment_multiline():
    sql = '/*!40101 SET\n  @OLD_SQL_MODE=@@SQL_MODE */;\nSELECT 1;'
    stmts = sqlparse.split(sql)
    assert stmts == [
        '/*!40101 SET\n  @OLD_SQL_MODE=@@SQL_MODE */;',
        'SELECT 1;',
    ]


def test_mysql_executable_comment_survives_strip_comments():
    sql = 'SELECT 1 /* gone */, /*!40101 KEEP_ME */ 2'
    res = sqlparse.format(sql, strip_comments=True)
    assert '/* gone */' not in res
    assert '/*!40101 KEEP_ME */' in res


@pytest.mark.parametrize('sql, expected', [
    ("SELECT 'a\n;b'; SELECT 2;", ["SELECT 'a\n;b';", 'SELECT 2;']),
    ('SELECT "a\n;b"; SELECT 2;', ['SELECT "a\n;b";', 'SELECT 2;']),
    ('SELECT `a\n;b`; SELECT 2;', ['SELECT `a\n;b`;', 'SELECT 2;']),
    ("SELECT E'a\\';b'; SELECT 2;", ["SELECT E'a\\';b';", 'SELECT 2;']),
    ('SELECT $$a\n;b$$; SELECT 2;', ['SELECT $$a\n;b$$;', 'SELECT 2;']),
    ('SELECT /* a\n;b */ 1; SELECT 2;',
     ['SELECT /* a\n;b */ 1;', 'SELECT 2;']),
    ('SELECT /*! a\n;b */ 1; SELECT 2;',
     ['SELECT /*! a\n;b */ 1;', 'SELECT 2;']),
])
def test_split_constructs_span_newlines(sql, expected):
    # Quoting and commenting constructs correctly cross line boundaries.
    assert sqlparse.split(sql) == expected


@pytest.mark.parametrize('sql, expected', [
    # comment markers inside strings are not comments
    ("SELECT '/* ; */'; SELECT 2;", ["SELECT '/* ; */';", 'SELECT 2;']),
    ('SELECT "/* ; */"; SELECT 2;', ['SELECT "/* ; */";', 'SELECT 2;']),
    ('SELECT `/* ; */`; SELECT 2;', ['SELECT `/* ; */`;', 'SELECT 2;']),
    # quote markers inside comments are not strings
    ("SELECT /* ' ; */ 1; SELECT 2;", ["SELECT /* ' ; */ 1;", 'SELECT 2;']),
    ('SELECT /* " ; */ 1; SELECT 2;', ['SELECT /* " ; */ 1;', 'SELECT 2;']),
    # dollar quotes and comments do not interfere
    ('SELECT $$ /* ; */ $$; SELECT 2;', ['SELECT $$ /* ; */ $$;', 'SELECT 2;']),
    ('SELECT /* $$ ; */ 1; SELECT 2;', ['SELECT /* $$ ; */ 1;', 'SELECT 2;']),
    ("SELECT $$ ' ; ' $$; SELECT 2;", ["SELECT $$ ' ; ' $$;", 'SELECT 2;']),
    # the other quote character does not end a string
    ("SELECT 'a\";b'; SELECT 2;", ["SELECT 'a\";b';", 'SELECT 2;']),
    ('SELECT "a\';b"; SELECT 2;', ['SELECT "a\';b";', 'SELECT 2;']),
])
def test_split_interleaved_constructs(sql, expected):
    assert sqlparse.split(sql) == expected


@pytest.mark.parametrize('sql', [
    "SELECT 'unclosed; SELECT 2",
    'SELECT "unclosed; SELECT 2',
    'SELECT `unclosed; SELECT 2',
    'SELECT /* unclosed; SELECT 2',
    'SELECT /*! unclosed; SELECT 2',
])
def test_split_unclosed_constructs_recover_to_eof(sql):
    # An unclosed quote or comment swallows the rest of the script;
    # no semicolon inside it may split.
    assert sqlparse.split(sql) == [sql]


def test_split_unclosed_dollar_quote_is_not_a_quote():
    # A dollar quote without its closing tag is not a quote at all;
    # semicolons after it split normally (stable fallback).
    stmts = sqlparse.split('SELECT $x$unclosed; SELECT 2')
    assert stmts == ['SELECT $x$unclosed;', 'SELECT 2']


def test_split_comment_nesting_budget():
    with pytest.raises(SQLParseError,
                       match='Maximum comment nesting depth exceeded'):
        sqlparse.parse('/*' * (lexstate.MAX_COMMENT_DEPTH + 1))


def test_split_comment_nesting_within_budget():
    comment = '/*' * 50 + ' x; ' + '*/' * 50
    sql = comment + '; SELECT 1;'
    assert sqlparse.split(sql) == [comment + ';', 'SELECT 1;']


def test_split_statement_length_budget(monkeypatch):
    from sqlparse.engine import statement_splitter
    monkeypatch.setattr(statement_splitter, 'MAX_STATEMENT_LENGTH', 100)
    with pytest.raises(SQLParseError,
                       match='Maximum statement length exceeded'):
        sqlparse.split('SELECT ' + 'a' * 200)


def test_split_statement_length_budget_is_per_statement(monkeypatch):
    from sqlparse.engine import statement_splitter
    monkeypatch.setattr(statement_splitter, 'MAX_STATEMENT_LENGTH', 100)
    sql = '; '.join('SELECT ' + 'a' * 50 for _ in range(5))
    assert len(sqlparse.split(sql)) == 5


def test_split_quote_state_does_not_leak_between_statements():
    sql = "SELECT 'a'; SELECT 'b'; SELECT 'c'"
    assert sqlparse.split(sql) == ["SELECT 'a';", "SELECT 'b';", "SELECT 'c'"]


def test_split_calls_are_independent():
    # The scanner keeps no state between calls.
    sql = "SELECT $$x$$, 'y'; SELECT 2"
    first = sqlparse.split(sql)
    second = sqlparse.split(sql)
    assert first == second == ["SELECT $$x$$, 'y';", 'SELECT 2']


def test_split_empty_statements_convention():
    # Existing convention: bare semicolons are kept, whitespace-only
    # scripts yield nothing.
    assert sqlparse.split('SELECT 1;; SELECT 2;') == [
        'SELECT 1;', ';', 'SELECT 2;']
    assert sqlparse.split('; ; ;') == [';', ';', ';']
    assert sqlparse.split('   \n  ') == []


def test_split_preserves_statement_offsets():
    # Statements keep their original start and end characters.
    sql = ("SELECT 1; /* c;\n*/ SELECT 'x;y';\n"
           "-- tail\n"
           "SELECT $$z;$$;")
    stmts = sqlparse.parse(sql)
    assert ''.join(str(stmt) for stmt in stmts) == sql
    assert str(stmts[0]) == 'SELECT 1; '
    assert str(stmts[1]) == "/* c;\n*/ SELECT 'x;y';"
    assert str(stmts[2]) == '\n-- tail\nSELECT $$z;$$;'


def test_lexstate_scan_reports_exact_positions():
    sql = "SELECT 'a;b' /* c /* d */ e */ $$x;y$$"
    spans = lexstate.scan(sql)
    assert spans == {
        7: (12, T.String.Single),
        13: (30, T.Comment.Multiline),
        31: (38, T.Literal),
    }
    assert sql[7:12] == "'a;b'"
    assert sql[13:30] == '/* c /* d */ e */'
    assert sql[31:38] == '$$x;y$$'


def test_lexstate_scan_skips_constructs_inside_strings():
    sql = "SELECT '/*', \"$$\", '`' /* c */"
    spans = lexstate.scan(sql)
    comments = [start for start, (end, ttype) in spans.items()
                if ttype in T.Comment]
    assert comments == [sql.index('/* c */')]
