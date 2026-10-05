# Tests for the script mode splitter (GO / DELIMITER client commands).

import pytest

import sqlparse
from sqlparse.script import ScriptBatch, ScriptCommand


def sqls(result):
    return [batch.sql for batch in result.batches]


# --- T-SQL: GO ------------------------------------------------------------

def test_tsql_basic_go():
    script = "SELECT 1\nGO\nSELECT 2\nGO\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT 1", "SELECT 2"]
    assert [cmd.kind for cmd in result.commands] == ["go", "go"]
    assert [cmd.argument for cmd in result.commands] == [None, None]


@pytest.mark.parametrize("go", ["GO", "go", "Go", "gO"])
def test_tsql_go_case_insensitive(go):
    script = f"SELECT 1\n{go}\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT 1"]
    assert len(result.commands) == 1


@pytest.mark.parametrize("dialect", ["tsql", "mssql", "sqlserver",
                                     "T-SQL", "SQL_Server"])
def test_tsql_dialect_aliases(dialect):
    result = sqlparse.split_script("SELECT 1\nGO\n", dialect)
    assert sqls(result) == ["SELECT 1"]


def test_tsql_go_count_is_metadata_only():
    script = "SELECT 1\nGO 3\n"
    result = sqlparse.split_script(script, "tsql")
    # The repeat count is reported, not executed: one batch only.
    assert sqls(result) == ["SELECT 1"]
    assert result.commands[0].argument == 3
    assert result.commands[0].raw == "GO 3"


def test_tsql_go_trailing_comment():
    script = "SELECT 1\nGO -- end of batch\nSELECT 2\nGO 2 -- twice\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT 1", "SELECT 2"]
    assert [cmd.argument for cmd in result.commands] == [None, 2]
    assert result.commands[0].raw == "GO -- end of batch"


def test_tsql_go_with_tab_and_crlf():
    script = "SELECT 1\r\nGO\t2\r\nSELECT 2\r\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT 1", "SELECT 2"]
    assert result.commands[0].argument == 2
    assert result.commands[0].raw == "GO\t2"


def test_tsql_procedure_semicolons_not_split():
    script = (
        "CREATE PROCEDURE p\n"
        "AS\n"
        "BEGIN\n"
        "    SELECT 1;\n"
        "    SELECT 2;\n"
        "END\n"
        "GO\n"
    )
    result = sqlparse.split_script(script, "tsql")
    assert len(result.batches) == 1
    assert "SELECT 1;" in result.batches[0].sql
    assert "SELECT 2;" in result.batches[0].sql


def test_tsql_go_inside_string_not_recognized():
    script = "SELECT '\nGO\n' AS x\nGO\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT '\nGO\n' AS x"]
    assert len(result.commands) == 1


def test_tsql_go_inside_comments_not_recognized():
    script = "/* outer /* nested */\nGO\n*/\nSELECT 1 -- GO\nGO\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["/* outer /* nested */\nGO\n*/\nSELECT 1 -- GO"]
    assert len(result.commands) == 1


def test_tsql_go_inside_bracket_identifier_not_recognized():
    script = "SELECT [weird\nGO\nname]\nGO\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT [weird\nGO\nname]"]


def test_tsql_go_not_at_line_start():
    script = "SELECT GO\nFROM t\nGO\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT GO\nFROM t"]


def test_tsql_goto_is_not_go():
    script = "GOTO\nGO\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["GOTO"]


def test_tsql_missing_terminator_at_end():
    script = "SELECT 1\nGO\nSELECT 2"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT 1", "SELECT 2"]


def test_tsql_unterminated_string_hides_go():
    script = "SELECT 'abc\nGO\n"
    result = sqlparse.split_script(script, "tsql")
    assert sqls(result) == ["SELECT 'abc\nGO"]
    assert result.commands == ()


@pytest.mark.parametrize("go", ["GO abc", "GO 0", "GO -1", "GO 2.5",
                                "GO 2 3", "GO;", "GO 1x"])
def test_tsql_invalid_go_arguments(go):
    with pytest.raises(ValueError):
        sqlparse.split_script(f"SELECT 1\n{go}\n", "tsql")


def test_tsql_positions():
    script = "SELECT 1\nGO\nSELECT 2\ngo 3\n"
    result = sqlparse.split_script(script, "tsql")
    assert [(b.sql, b.offset, b.line) for b in result.batches] == [
        ("SELECT 1", 0, 1), ("SELECT 2", 12, 3)]
    cmd1, cmd2 = result.commands
    assert (cmd1.line, cmd1.offset, cmd1.end_offset, cmd1.raw) == \
        (2, 9, 11, "GO")
    assert (cmd2.line, cmd2.offset, cmd2.end_offset, cmd2.raw) == \
        (4, 21, 25, "go 3")
    assert cmd2.argument == 3


def test_tsql_keep_commands():
    script = "SELECT 1\nGO 2\nSELECT 2\nGO\n"
    result = sqlparse.split_script(script, "tsql", keep_commands=True)
    assert sqls(result) == ["SELECT 1\nGO 2", "SELECT 2\nGO"]
    assert len(result.commands) == 2  # metadata is always reported


# --- MySQL: DELIMITER -----------------------------------------------------

def test_mysql_default_semicolon():
    result = sqlparse.split_script("SELECT 1;\nSELECT 2;", "mysql")
    assert sqls(result) == ["SELECT 1", "SELECT 2"]
    assert result.commands == ()


def test_mysql_delimiter_procedure():
    script = (
        "DELIMITER //\n"
        "CREATE PROCEDURE p()\n"
        "BEGIN\n"
        "    SELECT 1;\n"
        "    SELECT 2;\n"
        "END//\n"
        "DELIMITER ;\n"
        "SELECT 3;\n"
    )
    result = sqlparse.split_script(script, "mysql")
    assert sqls(result) == [
        "CREATE PROCEDURE p()\nBEGIN\n    SELECT 1;\n    SELECT 2;\nEND",
        "SELECT 3",
    ]
    assert [(cmd.kind, cmd.argument) for cmd in result.commands] == [
        ("delimiter", "//"), ("delimiter", ";")]
    # The DELIMITER directive itself is not part of the SQL body.
    assert all("DELIMITER" not in batch.sql for batch in result.batches)


@pytest.mark.parametrize("directive", ["DELIMITER", "delimiter", "Delimiter"])
def test_mysql_delimiter_case_insensitive(directive):
    script = f"{directive} $$\nSELECT 1$$\n"
    result = sqlparse.split_script(script, "mysql")
    assert sqls(result) == ["SELECT 1"]
    assert result.commands[0].argument == "$$"


def test_mysql_mariadb_alias():
    result = sqlparse.split_script("SELECT 1;\n", "mariadb")
    assert sqls(result) == ["SELECT 1"]


def test_mysql_multi_char_delimiter():
    script = "DELIMITER ;;\nSELECT 1;;\nDELIMITER ;\nSELECT 2;"
    result = sqlparse.split_script(script, "mysql")
    assert sqls(result) == ["SELECT 1", "SELECT 2"]


def test_mysql_delimiter_not_matched_in_strings_and_comments():
    script = (
        "DELIMITER //\n"
        "CREATE PROCEDURE p()\n"
        "BEGIN\n"
        "    SELECT 'a//b';\n"
        "    SELECT \"c//d\";\n"
        "    SELECT \x60e//f\x60;\n"
        "    SELECT 1 -- // line comment\n"
        "    /* // block comment */\n"
        "    SELECT 2 # // hash comment\n"
        "END//\n"
        "DELIMITER ;\n"
    )
    result = sqlparse.split_script(script, "mysql")
    assert len(result.batches) == 1
    body = result.batches[0].sql
    assert "'a//b'" in body
    assert "\"c//d\"" in body
    assert "\x60e//f\x60" in body


def test_mysql_backslash_escape_hides_delimiter():
    script = "DELIMITER //\nSELECT 'it\\'s // here'//\n"
    result = sqlparse.split_script(script, "mysql")
    assert sqls(result) == ["SELECT 'it\\'s // here'"]


def test_mysql_dollar_quoted_section_hides_delimiter():
    script = (
        "DELIMITER $$\n"
        "CREATE FUNCTION f() RETURNS TEXT\n"
        "BEGIN\n"
        "    RETURN $q$has $$ and ; inside$q$;\n"
        "END$$\n"
        "DELIMITER ;\n"
        "SELECT 1;\n"
    )
    result = sqlparse.split_script(script, "mysql")
    assert len(result.batches) == 2
    assert "$q$has $$ and ; inside$q$" in result.batches[0].sql
    assert result.batches[1].sql == "SELECT 1"


def test_mysql_dollar_amount_is_not_a_quote():
    result = sqlparse.split_script("SELECT $100;\nSELECT 2;", "mysql")
    assert sqls(result) == ["SELECT $100", "SELECT 2"]


def test_mysql_missing_terminator_at_end():
    script = "DELIMITER //\nSELECT 1//\nSELECT 2"
    result = sqlparse.split_script(script, "mysql")
    assert sqls(result) == ["SELECT 1", "SELECT 2"]


def test_mysql_delimiter_without_argument():
    with pytest.raises(ValueError):
        sqlparse.split_script("SELECT 1;\nDELIMITER\n", "mysql")
    with pytest.raises(ValueError):
        sqlparse.split_script("SELECT 1;\nDELIMITER   \n", "mysql")


def test_mysql_delimiter_word_prefix_is_not_a_command():
    script = "DELIMITERS\nSELECT 1;"
    result = sqlparse.split_script(script, "mysql")
    assert sqls(result) == ["DELIMITERS\nSELECT 1"]
    assert result.commands == ()


def test_mysql_go_is_plain_sql():
    result = sqlparse.split_script("SELECT 1;\nGO\nSELECT 2;", "mysql")
    assert sqls(result) == ["SELECT 1", "GO\nSELECT 2"]


def test_mysql_positions():
    script = "DELIMITER //\nSELECT 1//\nDELIMITER ;\nSELECT 2;"
    result = sqlparse.split_script(script, "mysql")
    assert [(b.sql, b.offset, b.line) for b in result.batches] == [
        ("SELECT 1", 13, 2), ("SELECT 2", 36, 4)]
    cmd1, cmd2 = result.commands
    assert (cmd1.line, cmd1.offset, cmd1.end_offset, cmd1.raw) == \
        (1, 0, 12, "DELIMITER //")
    assert (cmd2.line, cmd2.offset, cmd2.end_offset, cmd2.raw) == \
        (3, 24, 35, "DELIMITER ;")


def test_mysql_keep_commands():
    script = "SELECT 1;\nDELIMITER //\nSELECT 2//\n"
    result = sqlparse.split_script(script, "mysql", keep_commands=True)
    assert sqls(result) == ["SELECT 1", "DELIMITER //", "SELECT 2"]
    assert len(result.commands) == 1


# --- general behavior -----------------------------------------------------

def test_unknown_dialect():
    with pytest.raises(ValueError):
        sqlparse.split_script("SELECT 1", "oracle")


def test_non_string_script():
    with pytest.raises(TypeError):
        sqlparse.split_script(None, "tsql")


@pytest.mark.parametrize("script", ["", "  \n\t\n"])
def test_no_batches(script):
    result = sqlparse.split_script(script, "tsql")
    assert result.batches == ()
    assert result.commands == ()
    assert len(result) == 0


def test_comment_only_script_is_a_batch():
    # Comments are SQL text and are kept as batch content.
    result = sqlparse.split_script("-- only a comment\n", "tsql")
    assert sqls(result) == ["-- only a comment"]


def test_only_commands():
    result = sqlparse.split_script("GO\nGO 2\n", "tsql")
    assert result.batches == ()
    assert len(result.commands) == 2


def test_result_types():
    result = sqlparse.split_script("SELECT 1\nGO\n", "tsql")
    assert isinstance(result.batches[0], ScriptBatch)
    assert isinstance(result.commands[0], ScriptCommand)
    assert str(result.batches[0]) == "SELECT 1"
    assert list(result) == list(result.batches)


def test_default_split_unchanged():
    # sqlparse.split() keeps its semicolon-only behavior and treats
    # client commands as ordinary SQL tokens.
    stmts = sqlparse.split("SELECT 1;\nGO\nSELECT 2;")
    assert stmts == ["SELECT 1;", "GO", "SELECT 2;"]
