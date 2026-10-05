#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

import pytest

import sqlparse
from sqlparse.script import split_script


def sql_batches(result):
    return [batch.sql for batch in result.batches]


# --------------------------- SQL Server (GO) ---------------------------

def test_mssql_basic_go():
    result = split_script("SELECT 1\nGO\nSELECT 2\nGO\n", "mssql")
    assert sql_batches(result) == ["SELECT 1", "SELECT 2"]
    assert [b.terminator for b in result.batches] == ["GO", "GO"]
    assert [c.kind for c in result.commands] == ["go", "go"]
    assert result.errors == []


@pytest.mark.parametrize("go", ["GO", "go", "Go", "gO"])
def test_mssql_go_case_insensitive(go):
    result = split_script(f"SELECT 1\n{go}\n", "mssql")
    assert sql_batches(result) == ["SELECT 1"]
    assert len(result.commands) == 1


def test_mssql_go_repeat_count_is_metadata_only():
    result = split_script("SELECT 1\nGO 3\n", "mssql")
    # The repeat count must not multiply the batch.
    assert sql_batches(result) == ["SELECT 1"]
    assert result.commands[0].repeat == 3


def test_mssql_go_default_repeat_count():
    result = split_script("SELECT 1\nGO\n", "mssql")
    assert result.commands[0].repeat == 1


def test_mssql_go_trailing_comment():
    result = split_script("SELECT 1\nGO 2 -- run twice\n", "mssql")
    assert sql_batches(result) == ["SELECT 1"]
    command = result.commands[0]
    assert command.repeat == 2
    assert command.raw == "GO 2 -- run twice"


def test_mssql_go_not_at_line_start():
    result = split_script("SELECT 1 GO\n", "mssql")
    assert sql_batches(result) == ["SELECT 1 GO"]
    assert result.commands == []


def test_mssql_go_word_prefix_is_no_command():
    result = split_script("SELECT 1\nGO2\n", "mssql")
    assert sql_batches(result) == ["SELECT 1\nGO2"]
    assert result.commands == []


def test_mssql_go_inside_string():
    result = split_script("SELECT 'a\nGO\nb'\nGO\n", "mssql")
    assert sql_batches(result) == ["SELECT 'a\nGO\nb'"]
    assert len(result.commands) == 1


def test_mssql_go_inside_block_comment():
    result = split_script("/*\nGO\n*/\nSELECT 1\nGO\n", "mssql")
    assert sql_batches(result) == ["/*\nGO\n*/\nSELECT 1"]
    assert len(result.commands) == 1


def test_mssql_go_inside_bracketed_identifier():
    result = split_script("SELECT [a\nGO\nb] FROM t\nGO\n", "mssql")
    assert sql_batches(result) == ["SELECT [a\nGO\nb] FROM t"]
    assert len(result.commands) == 1


def test_mssql_procedure_body_with_semicolons():
    script = (
        "CREATE PROCEDURE p AS\n"
        "BEGIN\n"
        "    SELECT 1;\n"
        "    SELECT 2;\n"
        "END\n"
        "GO\n"
    )
    result = split_script(script, "mssql")
    assert sql_batches(result) == [script.split("GO")[0].strip()]
    assert ";" in result.batches[0].sql


def test_mssql_trailing_batch_without_go():
    result = split_script("SELECT 1\nGO\nSELECT 2", "mssql")
    assert sql_batches(result) == ["SELECT 1", "SELECT 2"]
    assert result.batches[-1].terminator is None


def test_mssql_empty_batches_are_skipped():
    result = split_script("GO\nGO\nSELECT 1\nGO\nGO\n", "mssql")
    assert sql_batches(result) == ["SELECT 1"]
    assert len(result.commands) == 4


@pytest.mark.parametrize("argument", ["0", "-1", "2.5", "abc", "1 2"])
def test_mssql_go_invalid_argument(argument):
    result = split_script(f"SELECT 1\nGO {argument}\nGO\n", "mssql")
    assert len(result.errors) == 1
    assert result.errors[0].line == 2
    # The malformed line stays in the SQL text, only the valid GO splits.
    assert sql_batches(result) == [f"SELECT 1\nGO {argument}"]
    assert len(result.commands) == 1


def test_mssql_command_positions():
    script = "SELECT 1\nGO 3\nSELECT 2\n"
    result = split_script(script, "mssql")
    command = result.commands[0]
    assert script[command.start:command.end] == "GO 3"
    assert command.line == 2
    batch = result.batches[0]
    assert script[batch.start:batch.end] == batch.sql == "SELECT 1"


def test_mssql_crlf_line_endings():
    result = split_script("SELECT 1\r\nGO\r\nSELECT 2\r\n", "mssql")
    assert sql_batches(result) == ["SELECT 1", "SELECT 2"]
    assert result.commands[0].raw == "GO"


def test_mssql_delimiter_directive_is_plain_sql():
    result = split_script("DELIMITER //\nSELECT 1\nGO\n", "mssql")
    assert sql_batches(result) == ["DELIMITER //\nSELECT 1"]
    assert result.commands[0].kind == "go"


# ----------------------------- MySQL ---------------------------------

def test_mysql_basic_semicolon():
    result = split_script("SELECT 1; SELECT 2;", "mysql")
    assert sql_batches(result) == ["SELECT 1", "SELECT 2"]
    assert [b.terminator for b in result.batches] == [";", ";"]
    assert result.commands == []


def test_mysql_delimiter_procedure():
    script = (
        "DELIMITER //\n"
        "CREATE PROCEDURE p()\n"
        "BEGIN\n"
        "    SELECT 1;\n"
        "    SELECT 2;\n"
        "END //\n"
        "DELIMITER ;\n"
        "SELECT 3;\n"
    )
    result = split_script(script, "mysql")
    assert sql_batches(result) == [
        "CREATE PROCEDURE p()\nBEGIN\n    SELECT 1;\n    SELECT 2;\nEND",
        "SELECT 3",
    ]
    assert [b.terminator for b in result.batches] == ["//", ";"]
    assert [c.delimiter for c in result.commands] == ["//", ";"]
    # DELIMITER directives are not part of the SQL text.
    assert all("DELIMITER" not in batch.upper() for batch in sql_batches(result))


@pytest.mark.parametrize("directive", ["DELIMITER", "delimiter", "Delimiter"])
def test_mysql_delimiter_case_insensitive(directive):
    result = split_script(f"{directive} //\nSELECT 1//\n", "mysql")
    assert sql_batches(result) == ["SELECT 1"]
    assert result.commands[0].delimiter == "//"


def test_mysql_delimiter_inside_string():
    result = split_script("DELIMITER //\nSELECT '//';\n//\n", "mysql")
    assert sql_batches(result) == ["SELECT '//';"]


def test_mysql_delimiter_inside_backtick_identifier():
    result = split_script(
        "DELIMITER //\nSELECT `a//b` FROM t//\n", "mysql")
    assert sql_batches(result) == ["SELECT `a//b` FROM t"]


def test_mysql_delimiter_inside_line_comment():
    result = split_script("DELIMITER //\n-- //\nSELECT 1//\n", "mysql")
    assert sql_batches(result) == ["-- //\nSELECT 1"]


def test_mysql_delimiter_inside_block_comment():
    result = split_script("DELIMITER //\n/* // */\nSELECT 1//\n", "mysql")
    assert sql_batches(result) == ["/* // */\nSELECT 1"]


def test_mysql_delimiter_inside_dollar_quoted_literal():
    result = split_script(
        "DELIMITER //\nSELECT $body$a // b$body$//\n", "mysql")
    assert sql_batches(result) == ["SELECT $body$a // b$body$"]


def test_mysql_delimiter_trailing_comment():
    result = split_script("DELIMITER // -- switch\nSELECT 1//\n", "mysql")
    assert result.commands[0].delimiter == "//"
    assert sql_batches(result) == ["SELECT 1"]


def test_mysql_delimiter_change_back_and_forth():
    script = (
        "DELIMITER $$\n"
        "CREATE PROCEDURE p() BEGIN SELECT 1; END$$\n"
        "DELIMITER ;\n"
        "SELECT 2;\n"
    )
    result = split_script(script, "mysql")
    assert sql_batches(result) == [
        "CREATE PROCEDURE p() BEGIN SELECT 1; END", "SELECT 2"]
    assert [b.terminator for b in result.batches] == ["$$", ";"]


def test_mysql_trailing_batch_without_terminator():
    result = split_script("SELECT 1;\nSELECT 2", "mysql")
    assert sql_batches(result) == ["SELECT 1", "SELECT 2"]
    assert result.batches[-1].terminator is None


def test_mysql_delimiter_missing_argument():
    result = split_script("DELIMITER\nSELECT 1;\n", "mysql")
    assert len(result.errors) == 1
    assert result.errors[0].line == 1
    assert sql_batches(result) == ["DELIMITER\nSELECT 1"]
    assert result.commands == []


def test_mysql_delimiter_backslash_rejected():
    result = split_script("DELIMITER " + chr(92) + "\nSELECT 1;\n", "mysql")
    assert len(result.errors) == 1
    assert "backslash" in result.errors[0].message


def test_mysql_delimiter_extra_junk():
    result = split_script("DELIMITER // junk\nSELECT 1;\n", "mysql")
    assert len(result.errors) == 1
    assert result.commands == []


def test_mysql_directive_not_at_line_start():
    result = split_script("SELECT 1; DELIMITER //\nSELECT 2;\n", "mysql")
    assert result.commands == []
    assert sql_batches(result) == ["SELECT 1", "DELIMITER //\nSELECT 2"]


def test_mysql_go_is_plain_sql():
    result = split_script("SELECT 1;\nGO\nSELECT 2;\n", "mysql")
    assert result.commands == []
    assert sql_batches(result) == ["SELECT 1", "GO\nSELECT 2"]


def test_mysql_command_positions():
    script = "DELIMITER //\nSELECT 1//\n"
    result = split_script(script, "mysql")
    command = result.commands[0]
    assert script[command.start:command.end] == "DELIMITER //"
    assert command.line == 1
    batch = result.batches[0]
    assert script[batch.start:batch.end] == batch.sql == "SELECT 1"


# ----------------------------- general -------------------------------

def test_unknown_dialect():
    with pytest.raises(ValueError, match="unsupported dialect"):
        split_script("SELECT 1", "oracle")


@pytest.mark.parametrize("dialect", ["mssql", "tsql", "sqlserver"])
def test_mssql_dialect_aliases(dialect):
    assert split_script("SELECT 1\nGO\n", dialect).commands[0].kind == "go"


@pytest.mark.parametrize("dialect", ["mysql", "mariadb"])
def test_mysql_dialect_aliases(dialect):
    result = split_script("DELIMITER //\nSELECT 1//\n", dialect)
    assert result.dialect == "mysql"
    assert sql_batches(result) == ["SELECT 1"]


def test_bytes_input_with_encoding():
    result = split_script(b"SELECT 1\nGO\n", "mssql", encoding="utf-8")
    assert sql_batches(result) == ["SELECT 1"]


def test_result_iteration_and_length():
    result = split_script("SELECT 1\nGO\nSELECT 2\nGO\n", "mssql")
    assert len(result) == 2
    assert [batch.sql for batch in result] == ["SELECT 1", "SELECT 2"]


def test_default_split_is_unchanged():
    # sqlparse.split() knows nothing about DELIMITER directives.
    script = "DELIMITER //\nSELECT 1; SELECT 2;\n"
    assert sqlparse.split(script) == [
        "DELIMITER //\nSELECT 1;", "SELECT 2;"]
