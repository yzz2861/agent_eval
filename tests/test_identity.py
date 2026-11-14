import pytest

import sqlparse
from sqlparse import sql


def identifier(sql_text):
    parsed = sqlparse.parse(sql_text)[0]
    token = parsed.tokens[0]
    if isinstance(token, sql.IdentifierList):
        token = token.tokens[0]
    return token


def test_unquoted_names_fold_to_same_key():
    lower = identifier("public.orders").get_object_identity()
    upper = identifier("PUBLIC.ORDERS").get_object_identity()

    assert lower.key == upper.key
    assert lower.key_string == upper.key_string == "public.orders"
    assert lower.schema.raw == "public"
    assert lower.table.raw == "orders"
    assert upper.schema.normalized == "public"
    assert upper.table.normalized == "orders"


def test_casefold_strategy_can_be_customized():
    identity = identifier("Orders").get_object_identity(casefold=str.upper)

    assert identity.table.normalized == "ORDERS"
    assert identity.key == (("unquoted", "ORDERS"),)


def test_dialect_folds_unquoted_names_but_preserves_quoted_names():
    identity = identifier('orders."Mixed"').get_object_identity(
        dialect="oracle")

    assert identity.schema.normalized == "ORDERS"
    assert identity.table.normalized == "Mixed"
    assert identity.table.quoted is True


def test_dialect_and_casefold_are_mutually_exclusive():
    with pytest.raises(ValueError):
        identifier("orders").get_object_identity(
            casefold=str.lower, dialect="mysql")


def test_quoted_names_preserve_case_and_quote_type():
    identity = identifier('"Public"."Orders"').get_object_identity()

    assert identity.schema.normalized == "Public"
    assert identity.table.normalized == "Orders"
    assert identity.schema.quote_char == '"'
    assert identity.table.quote_char == '"'
    assert identity.key != identifier("public.orders").get_object_identity().key


@pytest.mark.parametrize("sql_text, quote_char", [
    ('`public`.`orders`', '`'),
    ('[public].[orders]', '['),
    ('´public´.´orders´', '´'),
])
def test_database_specific_quote_types_are_distinct(sql_text, quote_char):
    identity = identifier(sql_text).get_object_identity()

    assert identity.schema.quoted is True
    assert identity.schema.quote_char == quote_char
    assert identity.table.quote_char == quote_char
    assert identity.key != identifier("public.orders").get_object_identity().key


def test_escaped_quote_content_and_escape_are_available():
    identity = identifier('"bad""quote"').get_object_identity()

    assert identity.table.raw == '"bad""quote"'
    assert identity.table.value == 'bad""quote'
    assert identity.table.normalized == 'bad"quote'
    assert identity.table.escaped is True
    assert identity.table.escape_sequence == '""'
    assert identity.table.key == ('quoted', '"', 'bad""quote')


def test_escaped_and_unescaped_quoted_names_have_distinct_keys():
    unescaped = identifier('"a"').get_object_identity()
    escaped = identifier('"a"""').get_object_identity()

    assert unescaped.table.normalized == "a"
    assert escaped.table.normalized == 'a"'
    assert escaped.table.escaped is True
    assert unescaped.key != escaped.key


def test_original_parts_are_traceable_by_position():
    sql_text = "PUBLIC . ORDERS"
    identity = identifier(sql_text).get_object_identity()

    assert isinstance(identity, sql.ObjectIdentity)
    for part in identity.parts:
        assert isinstance(part, sql.ObjectNamePart)
        assert sql_text[part.start_position:part.end_position] == part.raw


def test_raw_parts_and_key_string_round_trip():
    identity = identifier('PUBLIC."Orders"').get_object_identity()

    assert ".".join(part.raw for part in identity.parts) == 'PUBLIC."Orders"'
    assert identity.key_string == 'public."Orders"'


def test_alias_is_not_part_of_object_key():
    identity = identifier("public.orders AS o").get_object_identity()

    assert identity.alias == "o"
    assert identity.key == identifier("public.orders").get_object_identity().key


def test_schema_alias_keeps_real_object_identity():
    identity = identifier("db.schema.table AS t").get_object_identity()

    assert identity.alias == "t"
    assert identity.catalog.normalized == "db"
    assert identity.schema.normalized == "schema"
    assert identity.table.normalized == "table"


def test_three_part_and_four_part_names_map_to_object_levels():
    table = identifier("db.schema.table").get_object_identity()
    column = identifier("db.schema.table.col").get_object_identity()

    assert (table.catalog.raw, table.schema.raw, table.table.raw) == (
        "db", "schema", "table")
    assert table.column is None
    assert (column.catalog.raw, column.schema.raw, column.table.raw,
            column.column.raw) == ("db", "schema", "table", "col")


def test_column_kind_maps_short_names_to_table_and_column():
    identity = identifier("t.id").get_object_identity(kind="column")

    assert identity.kind == "column"
    assert identity.table.raw == "t"
    assert identity.column.raw == "id"
    assert identity.schema is None
    assert identity != identifier("t.id").get_object_identity(kind="table")


def test_more_than_four_name_parts_are_invalid_in_strict_mode():
    invalid = identifier("a.b.c.d.e").get_object_identity()

    assert len(invalid.parts) == 4
    assert invalid.valid is False
    assert invalid.errors
    with pytest.raises(ValueError):
        identifier("a.b.c.d.e").get_object_identity(strict=True)


def test_identity_result_rejects_more_than_four_direct_parts():
    part = sql.ObjectNamePart(
        raw="a",
        value="a",
        normalized="a",
        quoted=False,
        quote_char=None,
        escaped=False,
        escape_sequence=None,
        start_position=0,
        end_position=1,
    )

    with pytest.raises(ValueError):
        sql.ObjectIdentity(parts=[part] * 5)


def test_function_call_is_marked_and_not_confused_with_table():
    function = identifier("db.schema.func(x)").get_object_identity()
    table = identifier("db.schema.func").get_object_identity()
    quoted_function = identifier("db.schema.`func`(x)").get_object_identity()

    assert function.is_function is True
    assert function.key == (
        ("unquoted", "db"),
        ("unquoted", "schema"),
        ("unquoted", "func"),
    )
    assert table.is_function is False
    assert table.key == function.key
    assert table != function
    assert quoted_function.is_function is True
    assert quoted_function.table.quote_char == '`'


def test_table_and_function_allowlists_are_separate_decision_sets():
    table_entries = {
        identifier("db.schema.func").get_object_identity().key,
    }
    function = identifier("db.schema.func(x)").get_object_identity()

    assert function.key in table_entries
    assert function.is_function is True
    assert not (function.key in table_entries and not function.is_function)


def test_allowlist_matches_unquoted_case_variants_only():
    allowlist = {identifier("public.orders").get_object_identity().key}

    assert identifier("PUBLIC.ORDERS").get_object_identity().key in allowlist
    assert identifier('"public"."orders"').get_object_identity().key \
        not in allowlist
    assert identifier('"Public"."Orders"').get_object_identity().key \
        not in allowlist
    assert identifier('`public`.`orders`').get_object_identity().key \
        not in allowlist


def test_statement_identities_support_allowlist_decisions():
    allowlist = {identifier("public.orders").get_object_identity().key}
    statement = sqlparse.parse(
        "SELECT * FROM PUBLIC.ORDERS, \"Public\".\"Orders\""
    )[0]
    identities = list(statement.get_object_identities())
    keys = {identity.key for identity in identities}

    assert identifier("PUBLIC.ORDERS").get_object_identity().key in keys
    assert allowlist.intersection(keys) == allowlist
    assert identifier(
        '"Public"."Orders"').get_object_identity().key in keys
    assert identifier(
        '"Public"."Orders"').get_object_identity().key not in allowlist


@pytest.mark.parametrize("sql_text", [
    'select "bad"quote"',
    'select `bad`quote`',
    'select [bad]quote]',
    '"unterminated',
    '[unterminated',
])
def test_strict_mode_rejects_bad_quotes(sql_text):
    parsed = sqlparse.parse(sql_text)[0]
    assert list(parsed.get_object_identities())
    with pytest.raises(ValueError):
        list(parsed.get_object_identities(strict=True))

    assert str(parsed) == sql_text


def test_strict_mode_allows_array_indices():
    statement = sqlparse.parse("select col[1] from t")[0]

    identities = list(statement.get_object_identities(strict=True))

    assert any(identity.key == (("unquoted", "col"),)
               for identity in identities)


def test_existing_identifier_behavior_is_unchanged():
    sql_text = 'SELECT "Public"."Orders" AS o FROM PUBLIC.ORDERS'
    parsed = sqlparse.parse(sql_text)[0]

    assert str(parsed) == sql_text
    assert sqlparse.format(sql_text) == sql_text
    aliased = identifier('"Public"."Orders" AS o')
    assert aliased.get_name() == "o"
    assert aliased.get_real_name() == "Orders"
